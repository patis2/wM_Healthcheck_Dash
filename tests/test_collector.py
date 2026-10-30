"""Collector tests: rule engine behaviour and real SMTP / Teams-webhook delivery against local sinks.
Run:  python -m unittest discover -s tests -v
"""
import itertools
import json
import os
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "collector"))
from hub import config as cfgmod  # noqa: E402
from hub.alerts import Engine  # noqa: E402
from hub.notify import Notifier  # noqa: E402
from hub.store import Store, fingerprint  # noqa: E402

EID = itertools.count()  # unique event ids; time.time_ns() repeats within ~15 ms on Windows

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "collector", "rules.json")


class SmtpSink(socketserver.StreamRequestHandler):
    """Just enough SMTP to receive one message."""
    inbox = []

    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())  # noqa: E731
        w("220 sink ready")
        data_mode, buf = False, []
        for raw in self.rfile:
            line = raw.decode().rstrip("\r\n")
            if data_mode:
                if line == ".":
                    SmtpSink.inbox.append("\n".join(buf))
                    data_mode, buf = False, []
                    w("250 queued")
                else:
                    buf.append(line[1:] if line.startswith("..") else line)
                continue
            cmd = line.upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                w("250 sink")
            elif cmd.startswith(("MAIL", "RCPT")):
                w("250 ok")
            elif cmd == "DATA":
                data_mode = True
                w("354 go")
            elif cmd == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")


class TeamsSink(BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        TeamsSink.got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(202)
        self.end_headers()

    def log_message(self, *a):
        pass


def sample_alert(**kw):
    a = {"id": 7, "rule_id": "WM-002", "rule_name": "Error burst", "server": "IS-PRD-01", "environment": "PROD", "severity": "critical",
         "title": "120 errors in 5 min on IS-PRD-01", "detail": "Most recent message: <b>boom</b> & more", "first_seen": time.time() - 60,
         "last_seen": time.time(), "runbook": "https://wiki.example.com/rb", "notify_count": 1}
    a.update(kw)
    return a


class Delivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SmtpSink)
        cls.http = HTTPServer(("127.0.0.1", 0), TeamsSink)
        for s in (cls.smtp, cls.http):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for s in (cls.smtp, cls.http):
            s.shutdown()
            s.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        os.environ["TEST_TEAMS_HOOK"] = f"http://127.0.0.1:{self.http.server_address[1]}/hook"
        self.cfg = {"notifications": {"dry_run": False, "dashboard_url": "https://hub.example.com",
                                      "email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": self.smtp.server_address[1],
                                                "security": "none", "from": "hub@example.com"},
                                      "teams": {"enabled": True},
                                      "routes": [{"match": {"severity": ["critical"]}, "email": ["oncall@example.com"], "teams": ["TEST_TEAMS_HOOK"]},
                                                 {"match": {"severity": ["info"]}, "email": ["nobody@example.com"]}]}}
        SmtpSink.inbox.clear()
        TeamsSink.got.clear()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_email_and_teams_are_really_sent_and_routed(self):
        aid = self.store.create_alert({**sample_alert(), "dedup_key": "k", "value": 1, "now": time.time()})
        n = Notifier(self.cfg, self.store)
        n._dispatch("firing", sample_alert(id=aid))
        self.assertEqual(len(SmtpSink.inbox), 1)
        mail = SmtpSink.inbox[0]
        self.assertIn("Subject: [FIRING][CRITICAL][PROD] IS-PRD-01", mail.replace("\n ", " "))
        self.assertIn("oncall@example.com", mail)
        self.assertNotIn("nobody@example.com", mail)            # info-only route must not match a critical alert
        self.assertIn("&lt;b&gt;boom&lt;/b&gt;", mail.replace("=\n", ""))  # HTML part is escaped
        card = TeamsSink.got[0]
        self.assertEqual(card["type"], "message")
        att = card["attachments"][0]
        self.assertEqual(att["contentType"], "application/vnd.microsoft.card.adaptive")
        self.assertEqual(att["content"]["type"], "AdaptiveCard")
        self.assertTrue(any(f["title"] == "Server" and f["value"] == "IS-PRD-01" for f in att["content"]["body"][1]["facts"]))
        self.assertEqual(att["content"]["actions"][0]["url"], f"https://hub.example.com/#/alerts/{aid}")
        rows = self.store.notifications()
        self.assertEqual(sorted((r["channel"], r["status"]) for r in rows), [("email", "sent"), ("teams", "sent")])

    def test_failed_delivery_is_recorded_not_raised(self):
        self.cfg["notifications"]["email"]["smtp_port"] = 1  # nothing listens here
        self.cfg["notifications"]["teams"]["enabled"] = False
        aid = self.store.create_alert({**sample_alert(), "dedup_key": "k", "value": 1, "now": time.time()})
        n = Notifier(self.cfg, self.store)
        import hub.notify as hn
        orig, hn.time.sleep = hn.time.sleep, lambda s: None
        try:
            n._dispatch("firing", sample_alert(id=aid))
        finally:
            hn.time.sleep = orig
        self.assertEqual(self.store.notifications()[0]["status"], "failed")


class Engine_(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.sent = []

        class Cap:
            def submit(_, kind, alert):
                self.sent.append((kind, alert["rule_id"], alert["severity"], alert["server"]))
        self.cfg = {"rules_file": RULES, "expected_heartbeat_s": 30, "eval_interval_s": 15}
        self.eng = Engine(self.cfg, self.store, Cap())
        self.eng.load_rules(force=True)
        self.now = time.time()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def ingest(self, server="IS-PRD-01", env="PROD", n=0, level="ERROR", msg="boom", metrics=None, age=0):
        evs = [{"eid": f"{server}-{next(EID)}", "ts_epoch": self.now - age, "source": "server.log", "level": level, "code": "ISS.1.1",
                "tid": "", "msg": msg, "detail": ""} for i in range(n)]
        hb = {"ts_epoch": self.now, "metrics": metrics} if metrics is not None else None
        self.store.ingest({"name": server, "environment": env, "host": "h", "tags": {}, "agent_version": "t", "os": "t"}, evs, hb, self.now)

    def alerts(self, rule):
        return [a for a in self.store.open_alerts() if a["rule_id"] == rule]

    def test_severity_levels_escalate_in_place_and_dedupe(self):
        self.ingest(n=30)
        self.eng.evaluate(self.now)
        a = self.alerts("WM-002")
        self.assertEqual([x["severity"] for x in a], ["warning"])
        self.ingest(n=80)  # 110 in window -> critical
        self.eng.evaluate(self.now + 15)
        a = self.alerts("WM-002")
        self.assertEqual(len(a), 1)                      # same alert, not a second one
        self.assertEqual(a[0]["severity"], "critical")
        self.assertIn(("severity_change", "WM-002", "critical", "IS-PRD-01"), self.sent)

    def test_auto_resolve_after_condition_clears(self):
        self.ingest(n=30)
        self.eng.evaluate(self.now)
        self.eng.evaluate(self.now + 600)                # window passed, events no longer counted
        self.assertEqual(self.alerts("WM-002"), [])
        self.assertIn("resolved", [s[0] for s in self.sent])

    def test_heartbeat_missing_and_maintenance_suppression(self):
        self.ingest(n=0, metrics={"load_per_cpu": 0.1})
        self.eng.evaluate(self.now + 400)
        self.assertEqual(len(self.alerts("WM-001")), 1)
        self.store.add_maintenance("IS-PRD-*", self.now, self.now + 3600, "patching", "t")
        self.store.update_alert(self.alerts("WM-001")[0]["id"], state="resolved", resolved_at=self.now)
        self.eng.evaluate(self.now + 420)
        self.assertEqual(self.alerts("WM-001"), [])      # in maintenance: not evaluated

    def test_scope_limits_rule_to_environment(self):
        self.ingest(server="IS-DEV-01", env="DEV", n=0, metrics={})
        self.eng.evaluate(self.now + 400)                # WM-001 is scoped to PROD and UAT
        self.assertEqual(self.alerts("WM-001"), [])

    def test_metric_threshold_levels(self):
        self.ingest(metrics={"disk_used_pct:/sag": 85.0})
        self.eng.evaluate(self.now)
        self.assertEqual([a["severity"] for a in self.alerts("WM-008")], ["warning"])
        self.assertIn("/sag", self.alerts("WM-008")[0]["title"])

    def test_fingerprint_ignores_ids_and_numbers(self):
        a = fingerprint("ISP.1", "Order 123 not found for customer 'ACME-9' at 10.0.0.5:8080")
        b = fingerprint("ISP.1", "Order 98765 not found for customer 'ZED-1' at 10.1.2.3:9090")
        self.assertEqual(a, b)
        self.assertNotEqual(a, fingerprint("ISP.2", "Order 123 not found for customer 'ACME-9' at 10.0.0.5:8080"))

    def test_replayed_history_is_not_a_new_error(self):
        self.ingest(n=1, msg="ancient failure", age=3 * 86400)   # event time 3 days ago, delivered now
        self.eng.evaluate(self.now)
        self.assertEqual(self.alerts("WM-007"), [])
        self.ingest(n=1, msg="brand new failure")                # happening now
        self.eng.evaluate(self.now + 1)
        self.assertEqual(len(self.alerts("WM-007")), 1)

    def test_recurring_error_is_not_renewed_by_retention_purge(self):
        # an error that began 20 days ago and is still happening must survive the 14-day purge
        self.ingest(n=1, msg="long running failure", age=20 * 86400)
        self.ingest(n=1, msg="long running failure", age=3600)
        self.ingest(n=1, msg="abandoned failure", age=20 * 86400)    # nothing recent: should be forgotten
        self.store.purge(14, 7, 180)
        fps = {r["sample"] for r in self.store.q("SELECT sample FROM fp_seen")}
        self.assertIn("long running failure", fps)
        self.assertNotIn("abandoned failure", fps)
        self.ingest(n=1, msg="long running failure")
        self.eng.evaluate(self.now + 1)
        self.assertEqual(self.alerts("WM-007"), [])              # still not "new"

    def test_rollups_match_a_direct_count_and_ignore_duplicates(self):
        srv = {"name": "IS-PRD-01", "environment": "PROD", "host": "h", "tags": {}, "agent_version": "t", "os": "t"}
        base = int(self.now // 3600) * 3600 - 7200            # an hour boundary two hours ago
        evs = [{"eid": f"e{i}", "ts_epoch": base + i * 7, "source": "s", "level": ["INFO", "WARN", "ERROR", "FATAL"][i % 4], "code": "C.1",
                "tid": "", "msg": f"failure number {i}", "detail": ""} for i in range(400)]
        self.store.ingest(srv, evs, None, self.now)
        again = self.store.ingest(srv, evs[:100], None, self.now)      # a retried batch
        self.assertEqual(again, (0, 100))
        direct = self.store.q("SELECT CAST(ts/300 AS INTEGER)*300 AS b, SUM(rank>=4) AS errors, SUM(rank=3) AS warns, COUNT(*) AS total "
                              "FROM events GROUP BY b ORDER BY b")
        self.assertEqual(self.store.trend(base, 300), direct)
        ec = self.store.event_counts(base)[0]
        self.assertEqual((ec["errors"], ec["warns"], ec["total"]), (200, 100, 400))
        self.assertEqual(ec["last_ts"], base + 399 * 7)

    def test_rollups_are_rebuilt_for_a_database_created_without_them(self):
        self.ingest(n=5)
        self.store.conn().execute("DELETE FROM event_rollup")
        self.store.conn().commit()
        reopened = Store(self.store.path)
        try:
            self.assertEqual(reopened.event_counts(self.now - 3600)[0]["total"], 5)
        finally:
            reopened.close()

    def test_top_errors_groups_by_pattern_with_a_sample(self):
        for i in range(30):
            self.ingest(n=1, msg=f"Order {1000 + i} not found")
        self.ingest(n=2, msg="disk quota exceeded")
        top = self.store.top_errors(self.now - 3600, 8)
        self.assertEqual([t["n"] for t in top], [30, 2])
        self.assertTrue(top[0]["sample"].startswith("Order "))
        self.assertEqual(top[0]["servers"], 1)

    def test_password_hashing(self):
        h = cfgmod.hash_password("s3cret")
        self.assertTrue(cfgmod.verify_password("s3cret", h))
        self.assertFalse(cfgmod.verify_password("S3cret", h))
        self.assertFalse(cfgmod.verify_password("s3cret", "garbage"))


if __name__ == "__main__":
    unittest.main()
