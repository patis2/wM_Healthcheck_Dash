"""Unit tests for the agent's parsing and tailing. Run:  python -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))
import wm_agent as A  # noqa: E402

DEFAULTS = dict(A.DEFAULTS, first_run="beginning", multiline_timeout_s=0.0, default_tz="+00:00")


def make_tailer(path, profile="is_server", state=None, **over):
    prof = A.Profile(profile, A.BUILTIN_PROFILES[profile])
    d = dict(DEFAULTS, **over)
    return A.Tailer({"name": "t", "path": path}, prof, "agent-1", A.Redactor([], True, True), d, state)


class Parsing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "server.log")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, text, mode="a"):
        with open(self.log, mode) as fh:
            fh.write(text)

    def test_documented_sample_line(self):
        self.write("2022-01-07 15:58:49 GMT-03:00 [ISS.0053.0002C] (tid=793) Access denied for user renan on port 5200\n")
        ev = make_tailer(self.log).poll(final=True)
        self.assertEqual(len(ev), 1)
        e = ev[0]
        self.assertEqual((e["level"], e["code"], e["tid"]), ("FATAL", "ISS.0053.0002", "793"))
        self.assertEqual(e["ts"], "2022-01-07T18:58:49.000Z")  # GMT-03:00 -> UTC
        self.assertEqual(e["msg"], "Access denied for user renan on port 5200")

    def test_all_level_letters(self):
        for letter, name in {"C": "FATAL", "E": "ERROR", "W": "WARN", "I": "INFO", "D": "DEBUG", "T": "TRACE"}.items():
            self.write(f"2026-01-01 00:00:00 UTC [ISS.0001.0001{letter}] m\n")
        self.assertEqual([e["level"] for e in make_tailer(self.log).poll(final=True)], ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"])

    def test_level_letter_with_or_without_a_dot(self):
        # the product documentation writes the bracket as product.facility.number.level; real files attach the letter to the number
        self.write("2026-01-01 00:00:00 UTC [ISS.0001.0001.E] dotted form\n2026-01-01 00:00:01 UTC [ISS.0001.0001E] attached form\n")
        evs = make_tailer(self.log).poll(final=True)
        self.assertEqual([(e["level"], e["code"], e["msg"]) for e in evs],
                         [("ERROR", "ISS.0001.0001", "dotted form"), ("ERROR", "ISS.0001.0001", "attached form")])

    def test_timezone_forms(self):
        for tz, expect in [("UTC", "10:00"), ("IST", "04:30"), ("CEST", "08:00"), ("GMT+05:30", "04:30"), ("+0200", "08:00")]:
            self.assertEqual(A.parse_ts("2026-01-01 10:00:00", tz, A.TZ_ABBREV, 0)[11:16], expect, tz)

    def test_stack_trace_is_one_event(self):
        self.write("2026-01-01 00:00:00 UTC [ISP.0090.0003E] (tid=1) Exception --> boom\n\tat a.B.c(B.java:1)\nCaused by: x\n"
                   "2026-01-01 00:00:01 UTC [ISS.0001.0001I] next\n")
        ev = make_tailer(self.log).poll(final=True)
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[0]["detail"].count("\n"), 1)
        self.assertIn("Caused by: x", ev[0]["detail"])

    def test_partial_line_waits_for_newline(self):
        self.write("2026-01-01 00:00:00 UTC [ISS.0001.0001I] complete\n2026-01-01 00:00:01 UTC [ISS.0001.0001I] half")
        t = make_tailer(self.log, multiline_timeout_s=60)
        self.assertEqual([e["msg"] for e in t.poll()], [])  # 'complete' is held for stack-trace lines, 'half' is unterminated
        self.write(" done\n")
        evs = t.poll(final=True)
        self.assertEqual([e["msg"] for e in evs], ["complete", "half done"])

    def test_secrets_are_masked_before_leaving_the_host(self):
        self.write("2026-01-01 00:00:00 UTC [ISS.0001.0001E] login password=hunter2 token: abc123 Authorization: Bearer eyJhbGciOi.x.y card 4111 1111 1111 1111 ok order 1234567890123456\n")
        e = make_tailer(self.log).poll(final=True)[0]
        for secret in ("hunter2", "abc123", "eyJhbGciOi", "4111 1111 1111 1111"):
            self.assertNotIn(secret, e["msg"])
        j = make_tailer(self.log)
        self.write('2026-01-01 00:00:01 UTC [ISS.0001.0001E] body {"password":"p@ss w0rd","user":"bob"} done\n')
        self.assertNotIn("p@ss", [x for x in j.poll(final=True) if "body" in x["msg"]][0]["msg"])
        self.assertIn("1234567890123456", e["msg"])  # fails Luhn, so it is an id, not a card
        self.assertIn(" ok ", e["msg"])  # separator after the masked card is preserved

    def test_wrapper_profile_and_continuations(self):
        p = os.path.join(self.dir.name, "wrapper.log")
        with open(p, "w") as fh:
            fh.write("ERROR  | jvm 1    | 2026/01/01 10:00:00 | Exception in thread \"main\" java.lang.OutOfMemoryError\n"
                     "ERROR  | jvm 1    | 2026/01/01 10:00:00 |     at a.B.c(B.java:1)\n"
                     "STATUS | wrapper  | 2026/01/01 10:00:05 | --> Wrapper Stopped\n")
        ev = make_tailer(p, "wrapper").poll(final=True)
        self.assertEqual([e["level"] for e in ev], ["ERROR", "INFO"])
        self.assertIn("at a.B.c", ev[0]["detail"])

    def test_event_ids_are_stable_across_reads(self):
        self.write("2026-01-01 00:00:00 UTC [ISS.0001.0001I] a\n2026-01-01 00:00:01 UTC [ISS.0001.0001I] b\n")
        one = [e["eid"] for e in make_tailer(self.log).poll(final=True)]
        two = [e["eid"] for e in make_tailer(self.log).poll(final=True)]
        self.assertEqual(one, two)
        self.assertEqual(len(set(one)), 2)


class Rotation(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "server.log")

    def tearDown(self):
        self.dir.cleanup()

    def line(self, n):
        return f"2026-01-01 00:00:{n % 60:02d} UTC [ISS.0001.0001I] line-{n}\n"

    def append(self, a, b, path=None):
        with open(path or self.log, "a") as fh:
            fh.writelines(self.line(i) for i in range(a, b))

    def msgs(self, evs):
        return [e["msg"] for e in evs]

    def test_rename_rotation_loses_nothing(self):
        self.append(0, 5)
        t = make_tailer(self.log)
        got = self.msgs(t.poll())
        self.append(5, 8)                       # written, not yet read...
        os.rename(self.log, self.log + ".1")    # ...then the server rotates the file
        self.append(8, 10)                      # and keeps logging into a fresh file
        got += self.msgs(t.poll(final=True))
        self.assertEqual(got, [f"line-{i}" for i in range(10)])

    def test_copy_truncate_rotation(self):
        self.append(0, 5)
        t = make_tailer(self.log)
        got = self.msgs(t.poll())
        self.append(5, 7)
        import shutil
        shutil.copy(self.log, self.log + ".1")  # copy, then truncate in place (same inode)
        open(self.log, "w").close()
        self.append(7, 9)
        got += self.msgs(t.poll(final=True))
        self.assertEqual(got, [f"line-{i}" for i in range(9)])

    def test_resume_after_restart_from_saved_state(self):
        self.append(0, 4)
        t1 = make_tailer(self.log)
        first = self.msgs(t1.poll(final=True))
        saved = dict(t1.state)
        self.append(4, 7)
        t2 = make_tailer(self.log, state=saved)  # a new process resuming from agent_state.json
        self.assertEqual(first + self.msgs(t2.poll(final=True)), [f"line-{i}" for i in range(7)])

    def test_restart_after_rotation_while_agent_was_down(self):
        self.append(0, 4)
        t1 = make_tailer(self.log)
        first = self.msgs(t1.poll(final=True))
        saved = dict(t1.state)
        self.append(4, 6)
        os.rename(self.log, self.log + ".1")
        self.append(6, 8)
        t2 = make_tailer(self.log, state=saved)
        self.assertEqual(first + self.msgs(t2.poll(final=True)), [f"line-{i}" for i in range(8)])

    def test_first_run_end_skips_history(self):
        self.append(0, 5)
        t = make_tailer(self.log, first_run="end")
        self.assertEqual(t.poll(final=True), [])
        self.append(5, 6)
        self.assertEqual(self.msgs(t.poll(final=True)), ["line-5"])

    def test_pending_event_is_not_committed_until_complete(self):
        self.append(0, 2)
        t = make_tailer(self.log, multiline_timeout_s=60)
        t.poll()  # line-1 stays pending (it might still get stack-trace lines)
        self.assertLess(t.state["commit"], os.path.getsize(self.log))


# /proc/mounts lines for the df -h of a Dev IS host: what is monitored is /opt*, /var*, /wMNfs and /wMShared
MOUNTS = """devtmpfs /dev devtmpfs rw 0 0
tmpfs /dev/shm tmpfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/nvme0n1p2 / xfs rw 0 0
/dev/mapper/WmVg-VarOptDataInt /var/opt/DataIntegration xfs rw 0 0
/dev/mapper/WmVg-DataIntegration /opt/WM12/DataIntegration xfs rw 0 0
/dev/mapper/WmVg-DataIntVol /opt/DataIntegration xfs rw 0 0
/dev/mapper/WmVg-DataIntLogVol /opt/DataIntegration/logs xfs rw 0 0
/dev/mapper/WmVg-OptToolsVol /opt/tools xfs rw 0 0
/dev/mapper/WmVg-Odd /opt/with\\040space xfs rw 0 0
nas.example.com:/wmnfs /wMNfs nfs4 rw 0 0
nas.example.com:/wmshared /wMShared nfs4 rw 0 0
tmpfs /var/tmpcache tmpfs rw 0 0
tmpfs /run/user/10581 tmpfs rw 0 0
"""


class DiskMounts(unittest.TestCase):
    def test_mount_patterns_pick_monitored_file_systems_only(self):
        with tempfile.NamedTemporaryFile("w", suffix=".mounts", delete=False) as fh:
            fh.write(MOUNTS)
        try:
            got = A.disk_targets([], ["/opt*", "/var*", "/wMNfs", "/wMShared"], fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(got, ["/opt/WM12/DataIntegration", "/opt/DataIntegration", "/opt/DataIntegration/logs", "/opt/tools",
                               "/opt/with space", "/var/opt/DataIntegration", "/wMNfs", "/wMShared"])
        self.assertNotIn("/", got)                      # root and tmpfs (even under /var) are not monitored

    def test_without_a_mount_table_literal_paths_still_count(self):
        got = A.disk_targets(["/data"], ["/opt*", "/wMNfs", "/data"], os.path.join(tempfile.gettempdir(), "no-such-mounts"))
        self.assertEqual(got, ["/data", "/wMNfs"])

    def test_missing_mount_points_are_reported(self):
        pats = ["/opt*", "/var*", "/wMNfs", "/wMShared"]
        mounted = ["/", "/opt/DataIntegration", "/opt/DataIntegration/logs", "/wMShared"]
        seen = set()
        m = A.mount_presence(pats, mounted, seen)
        self.assertEqual(m, {"mount_present:/opt/DataIntegration": 1, "mount_present:/opt/DataIntegration/logs": 1,
                             "mount_present:/var*": 0, "mount_present:/wMNfs": 0, "mount_present:/wMShared": 1})
        self.assertNotIn("/wMNfs", A.disk_targets([], pats, mounted=mounted))   # not measured: would report the / disk
        m = A.mount_presence(pats, ["/", "/opt/DataIntegration", "/wMNfs"], seen)  # logs volume and NAS dropped
        self.assertEqual((m["mount_present:/opt/DataIntegration/logs"], m["mount_present:/wMShared"], m["mount_present:/wMNfs"]),
                         (0, 0, 1))

    def test_hung_mount_does_not_block_the_heartbeat(self):
        gate = threading.Event()
        real, old = A.shutil.disk_usage, A.DISK_TIMEOUT_S
        A.shutil.disk_usage = lambda p: gate.wait(10) or real(".")
        try:
            A._disk_usage.__defaults__ = (0.2,)
            m = A.host_metrics(["/hung"])
            self.assertEqual(m["disk_used_pct:/hung"], -1)      # reported as unreadable instead of hanging
            m = A.host_metrics(["/hung"])                         # still blocked: skipped without a new thread
            self.assertEqual(m["disk_used_pct:/hung"], -1)
        finally:
            gate.set()
            A.shutil.disk_usage = real
            A._disk_usage.__defaults__ = (old,)
            A._disk_inflight.clear()


if __name__ == "__main__":
    unittest.main()
