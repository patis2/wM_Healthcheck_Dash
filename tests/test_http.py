"""End-to-end tests over real HTTP: the ingest contract, request limits, token scoping, dashboard auth,
and an agent riding out a collector outage without losing or duplicating events.
Run:  python -m unittest discover -s tests -v
"""
import base64
import gzip
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "collector"))
sys.path.insert(0, os.path.join(HERE, "..", "agent"))
sys.path.insert(0, os.path.join(HERE, "..", "sim"))
from hub import config as cfgmod  # noqa: E402
from hub import server as srv  # noqa: E402
from hub.notify import hook_label  # noqa: E402
import wm_agent as A  # noqa: E402

TOKEN, OTHER = "wmh_test_token_one", "wmh_test_token_two"


def make_cfg(tmp, **over):
    cfg = cfgmod._merge(cfgmod.DEFAULTS, {
        "db_path": os.path.join(tmp, "hub.db"),
        "rules_file": os.path.join(HERE, "..", "collector", "rules.json"),
        "agents": [{"name": "one", "token_sha256": cfgmod.sha256_hex(TOKEN), "servers": ["IS-PRD-01"]},
                   {"name": "uat", "token_sha256": cfgmod.sha256_hex(OTHER), "servers": ["*-UAT-*"]}],
        "notifications": {"dry_run": True, "outbox_dir": os.path.join(tmp, "outbox")},
    })
    return cfgmod._merge(cfg, over)


class Collector:
    """A collector on an ephemeral loopback port, without the background alert/notifier threads."""

    def __init__(self, cfg, port=0):
        self.hub = srv.Hub(cfg)
        srv.Handler.hub = self.hub
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), srv.Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.hub.store.close()


def call(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read()
        e.close()
        try:
            return e.code, json.loads(body or b"{}")
        except ValueError:
            return e.code, {}


def batch(server="IS-PRD-01", events=None, heartbeat=None):
    b = {"server": {"name": server, "environment": "PROD", "host": "h1", "agent_version": "t"}, "events": events or []}
    if heartbeat is not None:
        b["heartbeat"] = heartbeat
    return b


def ev(eid, ts="2026-10-30T10:00:00.000Z", level="ERROR", msg="boom"):
    return {"eid": eid, "ts": ts, "source": "server.log", "level": level, "code": "ISS.0001.0001", "msg": msg}


class Ingest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.c = Collector(make_cfg(self.tmp.name))
        self.ingest_url = self.c.url + "/api/v1/ingest"

    def tearDown(self):
        self.c.close()
        self.tmp.cleanup()

    def post(self, payload, token=TOKEN, gz=True, raw=None, headers=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        if gz:
            body = gzip.compress(body) if raw is None else body
            h["Content-Encoding"] = "gzip"
        h.update(headers or {})
        return call(self.ingest_url, body, h, "POST")

    def test_healthz_needs_no_auth(self):
        self.assertEqual(call(self.c.url + "/healthz"), (200, {"ok": True}))

    def test_gzip_batch_is_stored_with_event_time_and_duplicates_ignored(self):
        st, body = self.post(batch(events=[ev("a1"), ev("a2")]))
        self.assertEqual((st, body), (200, {"accepted": 2, "duplicates": 0}))
        st, body = self.post(batch(events=[ev("a1"), ev("a3")]))  # a retried batch overlapping the first
        self.assertEqual(body, {"accepted": 1, "duplicates": 1})
        rows = self.c.hub.store.q("SELECT eid, ts, recv FROM events ORDER BY eid")
        self.assertEqual([r["eid"] for r in rows], ["a1", "a2", "a3"])
        want = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(rows[0]["ts"], want)                    # event time, in UTC ...
        self.assertGreater(abs(rows[0]["recv"] - rows[0]["ts"]), 1)  # ... kept apart from the receive time

    def test_far_future_event_time_is_clamped_to_arrival(self):
        future = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
        self.post(batch(events=[ev("f1", ts=future)]))
        r = self.c.hub.store.one("SELECT ts, recv FROM events WHERE eid='f1'")
        self.assertEqual(r["ts"], r["recv"])

    def test_auth_and_token_to_server_scoping(self):
        self.assertEqual(self.post(batch(), token="wrong")[0], 401)
        self.assertEqual(call(self.ingest_url, b"{}", {"Content-Type": "application/json"}, "POST")[0], 401)
        st, body = self.post(batch(server="IS-PRD-02"))         # token one is issued for IS-PRD-01 only
        self.assertEqual(st, 403)
        self.assertEqual(self.post(batch(server="IS-UAT-07"), token=OTHER)[0], 200)
        self.assertEqual(self.post(batch(server="IS-PRD-01"), token=OTHER)[0], 403)

    def test_token_entry_without_servers_list_may_report_as_nobody(self):
        self.c.hub.agent_index[cfgmod.sha256_hex("wmh_loose")] = {"name": "loose", "token_sha256": "x"}
        self.assertEqual(self.post(batch(), token="wmh_loose")[0], 403)

    def test_malformed_and_oversized_requests(self):
        self.assertEqual(self.post(None, raw=b"not gzip at all")[0], 400)
        self.assertEqual(self.post(None, raw=b"[1,2]", gz=False)[0], 400)            # JSON, but not an object
        self.assertEqual(self.post(batch(events=[{"eid": ""}]))[0], 422)
        self.assertEqual(self.post(batch(events=[{"eid": "bad id with spaces"}]))[0], 422)
        self.assertEqual(self.post(batch(heartbeat=[1]))[0], 422)
        self.assertEqual(self.post(batch(), headers={"Content-Encoding": "br"})[0], 415)
        bomb = gzip.compress(b'{"events":[' + b" " * (40 * 1024 * 1024) + b"]}")  # 40 MB of spaces > 4 x 8 MB
        self.assertEqual(self.post(None, raw=bomb)[0], 413)
        self.c.hub.cfg["max_events_per_batch"] = 3
        self.assertEqual(self.post(batch(events=[ev(f"e{i}") for i in range(4)]))[0], 422)

    def test_long_fields_are_cut(self):
        self.post(batch(events=[dict(ev("long"), msg="x" * 9000, detail="y" * 20000)]))
        r = self.c.hub.store.one("SELECT length(msg) AS m, length(detail) AS d FROM events WHERE eid='long'")
        self.assertEqual((r["m"], r["d"]), (4000, 12000))

    def test_heartbeat_metrics_and_clock_skew(self):
        hb = {"ts": (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat(),
              "metrics": {"load_per_cpu": 0.5, "nan": float("nan"), "flag": True}}
        self.assertEqual(self.post(batch(heartbeat=hb))[0], 200)
        latest = {m["name"]: m["value"] for m in self.c.hub.store.metric_latest("IS-PRD-01")}
        self.assertEqual(latest["load_per_cpu"], 0.5)
        self.assertNotIn("nan", latest)
        self.assertNotIn("flag", latest)
        self.assertAlmostEqual(latest["agent_clock_skew_s"], 300, delta=5)

    def test_bad_query_parameters_are_400_not_500(self):
        self.assertEqual(call(self.c.url + "/api/v1/overview?hours=abc")[0], 400)
        self.assertEqual(call(self.c.url + "/api/v1/events?limit=x")[0], 400)


class DashboardAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.c = Collector(make_cfg(self.tmp.name, ui_auth={"mode": "basic", "users": {"ops": cfgmod.hash_password("pw")}}))

    def tearDown(self):
        self.c.close()
        self.tmp.cleanup()

    def test_basic_auth_csrf_header_and_audit(self):
        url = self.c.url + "/api/v1/maintenance"
        self.assertEqual(call(url)[0], 401)
        auth = {"Authorization": "Basic " + base64.b64encode(b"ops:wrong").decode()}
        self.assertEqual(call(url, headers=auth)[0], 401)
        auth = {"Authorization": "Basic " + base64.b64encode(b"ops:pw").decode(), "Content-Type": "application/json"}
        self.assertEqual(call(url, headers=auth)[0], 200)
        body = json.dumps({"server": "IS-PRD-*", "minutes": 30, "reason": "patching"}).encode()
        self.assertEqual(call(url, body, auth, "POST")[0], 403)                    # no X-WM-Hub header: CSRF guard
        st, res = call(url, body, dict(auth, **{"X-WM-Hub": "1"}), "POST")
        self.assertEqual(st, 200)
        self.assertEqual(self.c.hub.store.q("SELECT actor, action FROM audit"), [{"actor": "ops", "action": "maintenance.add"}])
        self.assertEqual(call(self.c.url + "/healthz")[0], 200)                    # still open for load balancers

    def test_security_headers_on_the_dashboard_page(self):
        auth = {"Authorization": "Basic " + base64.b64encode(b"ops:pw").decode()}
        with urllib.request.urlopen(urllib.request.Request(self.c.url + "/", headers=auth), timeout=10) as r:
            h = r.headers
            self.assertIn("default-src 'self'", h["Content-Security-Policy"])
            self.assertEqual(h["X-Frame-Options"], "DENY")
            self.assertEqual(h["X-Content-Type-Options"], "nosniff")
            self.assertNotIn("http://", r.read().decode().split("<script", 1)[0].lower().replace("http://www.w3.org", ""))


class ConfigGuards(unittest.TestCase):
    def cfg(self, **over):
        return cfgmod._merge(cfgmod.DEFAULTS, over)

    def test_default_is_loopback_and_valid(self):
        self.assertEqual(cfgmod.DEFAULTS["listen"]["host"], "127.0.0.1")
        self.assertEqual(cfgmod.validate(self.cfg()), [])

    def test_anonymous_dashboard_on_a_public_interface_is_refused(self):
        errs = cfgmod.validate(self.cfg(listen={"host": "0.0.0.0", "port": 8080}))
        self.assertTrue(any("unauthenticated dashboard" in e for e in errs))
        with self.assertRaises(SystemExit):
            srv.serve(self.cfg(listen={"host": "0.0.0.0", "port": 0}))
        ok = self.cfg(listen={"host": "0.0.0.0", "port": 8080}, ui_auth={"mode": "basic", "users": {"a": "h"}})
        self.assertEqual(cfgmod.validate(ok), [])

    def test_agent_tokens_must_be_scoped_and_hashed(self):
        errs = cfgmod.validate(self.cfg(agents=[{"name": "x", "token_sha256": "0" * 64},
                                                {"name": "y", "token_sha256": "plain", "servers": ["Y"]}]))
        self.assertEqual(len(errs), 2)

    def test_teams_webhook_url_is_not_logged(self):
        url = "https://prod-00.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=SECRET"
        self.assertNotIn("SECRET", hook_label(url))
        self.assertEqual(hook_label("WM_HUB_TEAMS_PROD"), "WM_HUB_TEAMS_PROD")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class AgentOutage(unittest.TestCase):
    """Agent spools while the collector is down, then delivers everything exactly once."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.log = os.path.join(d, "server.log")
        self.port = free_port()
        self.agent_cfg = dict(A.DEFAULTS, collector_url=f"http://127.0.0.1:{self.port}", server_name="IS-PRD-01",
                              agent_id="IS-PRD-01", environment="PROD", first_run="beginning", default_tz="+00:00",
                              multiline_timeout_s=0.0, http_timeout_s=3, spool_dir=os.path.join(d, "spool"),
                              state_file=os.path.join(d, "state.json"),
                              sources=[{"name": "server.log", "path": self.log, "profile": "is_server"}])
        self.c = None

    def tearDown(self):
        if self.c:
            self.c.close()
        self.tmp.cleanup()

    def write(self, a, b):
        with open(self.log, "a") as fh:
            for i in range(a, b):
                fh.write(f"2026-10-30 10:00:{i % 60:02d} UTC [ISS.0001.0001E] (tid=1) failure password=hunter{i} seq={i}\n")

    def run_once(self):
        """One pass of a fresh agent process: resume from saved offsets, spool, try to deliver."""
        agent = A.Agent(dict(self.agent_cfg), TOKEN)
        agent.buffer += agent.collect_once(final=True)
        agent.spool_buffer(force=True)
        agent._save_state()
        agent._flush_spool_on_exit(10)
        return agent

    def test_outage_then_recovery_loses_and_duplicates_nothing(self):
        self.write(0, 10)
        agent = self.run_once()                               # collector is down: the batch must stay spooled
        self.assertEqual(len(agent.spool.files()), 1)
        self.write(10, 15)
        agent = self.run_once()                               # still down, agent "restarted": a second batch
        self.assertEqual(len(agent.spool.files()), 2)
        self.c = Collector(make_cfg(self.tmp.name), port=self.port)
        agent._flush_spool_on_exit(10)                        # collector back: spool drains in order
        self.assertEqual(agent.spool.files(), [])
        agent = self.run_once()                               # nothing new: no re-sending of old lines
        rows = self.c.hub.store.q("SELECT msg FROM events ORDER BY ts")
        self.assertEqual(sorted(int(r["msg"].rsplit("seq=", 1)[1]) for r in rows), list(range(15)))
        self.assertFalse(any("hunter" in r["msg"] for r in rows))      # redacted before it reached the spool
        with open(self.agent_cfg["state_file"]) as fh:
            self.assertEqual(json.load(fh)["server.log"]["commit"], os.path.getsize(self.log))

    def test_rejected_batch_is_quarantined_and_counted(self):
        self.c = Collector(make_cfg(self.tmp.name), port=self.port)
        agent = A.Agent(dict(self.agent_cfg, server_name="NOT-MINE"), TOKEN)
        agent.spool.put({"server": {"name": "IS-PRD-01"}, "events": [{"eid": "has spaces"}]})  # 422 from the collector
        threading.Thread(target=agent._sender_loop, daemon=True).start()
        deadline = time.time() + 10
        while agent.spool.files() and time.time() < deadline:
            time.sleep(0.1)
        agent.stop.set()
        self.assertEqual(agent.spool.files(), [])
        self.assertEqual(agent.spool.stats()["rejected_batches"], 1)
        self.assertEqual(agent.metrics()["agent_batches_rejected"], 1)


class DemoSafety(unittest.TestCase):
    def test_existing_directory_is_refused_and_left_untouched(self):
        import run_demo
        with tempfile.TemporaryDirectory() as d:
            keep = os.path.join(d, "precious.txt")
            with open(keep, "w") as fh:
                fh.write("user data")
            with self.assertRaises(SystemExit):
                run_demo.fresh_dir(d)
            with open(keep) as fh:
                self.assertEqual(fh.read(), "user data")
            self.assertEqual(os.listdir(d), ["precious.txt"])

    def test_default_directory_is_new_each_time(self):
        import run_demo
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                a, b = run_demo.fresh_dir(None), run_demo.fresh_dir(None)
            finally:
                os.chdir(cwd)
            self.assertNotEqual(a, b)
            self.assertTrue(a.startswith(os.path.join(d, "demo_runs")))
            self.assertEqual(os.listdir(a), [])

    def test_demo_has_no_recursive_delete(self):
        with open(os.path.join(HERE, "..", "sim", "run_demo.py")) as fh:
            src = fh.read()
        self.assertNotIn("rmtree", src)


if __name__ == "__main__":
    unittest.main()
