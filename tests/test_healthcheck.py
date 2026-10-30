"""Health-check tests: server-list import, inventory matching, landscape/cluster grouping, shared NAS storage
counted (and alerted) once, the CSV report, and the demo estate plan.
Run:  python -m unittest discover -s tests -v
"""
import base64
import csv
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "collector"))
sys.path.insert(0, os.path.join(HERE, "..", "sim"))
sys.path.insert(0, HERE)
import import_inventory as imp  # noqa: E402
import simulate  # noqa: E402
from hub import config as cfgmod  # noqa: E402
from hub import inventory as invmod  # noqa: E402
from hub.alerts import FLEET  # noqa: E402
from test_http import Collector, call, make_cfg  # noqa: E402

TOKEN = "wmh_health_token"
# the layout of the team's Server List.xlsx: landscape rows (code or nothing in column B) followed by role / host rows
SHEET = [["Dev", "CON"], ["Broker", "SITE1WMASD009"], ["SBX", "site1wmasd010"], ["SBX", "site1wmasd013"],
         ["Optimize", "SITE1WMASD012"], ["CCE", "SITE1WMASD012"],
         ["Test", "TST"], ["Broker1", "SITE1WMAST393"], ["Broker2", "SITE1WMAST109"], ["CIS01_TEST", "site2wmast100"],
         ["CIS02_TEST", "site2wmast111"], ["Optimize & CCE", "site1wmast007", "", "site1wmast007"],
         ["PROD"], ["MWS01_PROD", "SITE1WMASP010"], ["MWS02_PROD", "SITE1WMASP013"], ["PRD_UM1", "SITE1WMASP434"],
         ["PRD_UM2", "SITE1WMASP436"], ["PRD_BAT_PPI_01", "site2wmasp119"], ["PRD_CIS1", "site2wmasp104", "CIS cluster"],
         [], ["DR"], ["DR_BR", "SITE4WMASR203"]]


def write_xlsx(path, rows):
    """Minimal workbook with shared strings, as Excel writes it."""
    strings, xml_rows = [], []
    for r, row in enumerate(rows, 1):
        cells = []
        for c, v in enumerate(row):
            if v == "":
                continue
            if v not in strings:
                strings.append(v)
            cells.append(f'<c r="{"ABCD"[c]}{r}" t="s"><v>{strings.index(v)}</v></c>')
        xml_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    m = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/workbook.xml", f'<workbook {m} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                                      '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                                 '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/sharedStrings.xml", f'<sst {m}>' + "".join(f"<si><t>{s.replace('&', '&amp;')}</t></si>" for s in strings) + "</sst>")
        z.writestr("xl/worksheets/sheet1.xml", f'<worksheet {m}><sheetData>{"".join(xml_rows)}</sheetData></worksheet>')


class ImportServerList(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.xlsx = os.path.join(self.tmp.name, "Server List.xlsx")
        write_xlsx(self.xlsx, SHEET)

    def tearDown(self):
        self.tmp.cleanup()

    def test_xlsx_is_read_with_the_standard_library(self):
        rows = imp.read_xlsx(self.xlsx)
        self.assertEqual(rows[0], ["Dev", "CON"])
        self.assertEqual(rows[11], ["Optimize & CCE", "site1wmast007", "", "site1wmast007"])

    def test_landscapes_clusters_and_roles(self):
        inv, warnings = imp.build(imp.read_xlsx(self.xlsx))
        self.assertEqual(warnings, [])
        self.assertEqual([(ls["name"], ls["code"]) for ls in inv["landscapes"]], [("Dev", "CON"), ("Test", "TST"), ("PROD", ""), ("DR", "")])
        by = {s["host"]: s for ls in inv["landscapes"] for s in ls["servers"]}
        self.assertEqual(by["SITE1WMAST393"]["cluster"], "Broker")          # Broker1 + Broker2 -> one cluster
        self.assertEqual(by["SITE1WMAST109"]["cluster"], "Broker")
        self.assertEqual(by["site2wmast100"]["cluster"], "CIS")             # CIS01_TEST
        self.assertEqual(by["SITE1WMASP010"]["cluster"], "MWS")             # MWS01_PROD
        self.assertEqual(by["SITE1WMASP434"]["cluster"], "UM")              # PRD_UM1
        self.assertEqual(by["site2wmasp119"]["cluster"], "BAT PPI")         # PRD_BAT_PPI_01
        self.assertEqual(by["site2wmasp104"]["cluster"], "CIS cluster")     # explicit column C wins
        self.assertEqual(by["SITE4WMASR203"]["cluster"], "BR")              # DR_BR
        self.assertEqual(by["site1wmast007"]["cluster"], "Optimize & CCE")
        dev = inv["landscapes"][0]["servers"]
        self.assertEqual(len(dev), 4)                                         # SITE1WMASD012 listed twice -> one host
        self.assertEqual(by["SITE1WMASD012"]["roles"], ["Optimize", "CCE"])
        self.assertEqual(by["SITE1WMASD012"]["cluster"], "Optimize & CCE")
        self.assertEqual([s["cluster"] for s in dev].count("SBX"), 2)

    def test_output_parses_cleanly_and_cli_will_not_overwrite(self):
        out = os.path.join(self.tmp.name, "inventory.json")
        sys_argv = sys.argv
        try:
            sys.argv = ["import_inventory.py", self.xlsx, "-o", out, "--shared", "PROD NAS=/nas/wm_shared@PROD"]
            self.assertEqual(imp.main(), 0)
            with open(out) as fh:
                inv, errors = invmod.parse(json.load(fh))
            self.assertEqual(errors, [])
            self.assertEqual(inv["shared_storage"], [{"name": "PROD NAS", "path": "/nas/wm_shared", "landscapes": ["PROD"]}])
            with self.assertRaises(SystemExit):
                imp.main()                                                    # exists, no --force
        finally:
            sys.argv = sys_argv

    def test_csv_source_and_server_before_landscape(self):
        p = os.path.join(self.tmp.name, "list.csv")
        with open(p, "w", newline="") as fh:
            csv.writer(fh).writerows([["Orphan", "host0001"], ["UAT", ""], ["IS1", "uat0001"]])
        inv, warnings = imp.build(imp.read_csv(p))
        self.assertEqual([s["host"] for s in inv["landscapes"][0]["servers"]], ["uat0001"])
        self.assertEqual(len(warnings), 1)


class InventoryParse(unittest.TestCase):
    def test_bad_entries_are_reported_and_skipped(self):
        inv, errors = invmod.parse({"landscapes": [{"name": "PROD", "servers": [{"host": "a1"}, {"host": "bad host"}, {"host": "A1.corp.example"}]},
                                                   {"servers": []}], "shared_storage": [{"name": "x"}]})
        self.assertEqual([s["host"] for s in inv["landscapes"][0]["servers"]], ["a1"])
        self.assertEqual(len(errors), 4)
        self.assertEqual(invmod.parse([])[1], ["inventory must be an object with a 'landscapes' list"])

    def test_lookup_by_name_or_host_with_or_without_domain(self):
        inv = invmod.Inventory()
        inv._set(invmod.parse({"landscapes": [{"name": "PROD", "servers": [{"host": "SITE2WMASP104", "cluster": "CIS"}]}]})[0])
        self.assertEqual(inv.lookup("site2wmasp104")["cluster"], "CIS")
        self.assertEqual(inv.lookup("IS-PRD-01", "site2wmasp104.corp.example.com")["landscape"], "PROD")
        self.assertIsNone(inv.lookup("IS-PRD-02", "other.corp"))

    def test_broken_file_keeps_last_good_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "inventory.json")
            with open(p, "w") as fh:
                json.dump({"landscapes": [{"name": "PROD", "servers": [{"host": "h1"}]}]}, fh)
            inv = invmod.Inventory(p).refresh()
            self.assertTrue(inv.loaded)
            with open(p, "w") as fh:
                fh.write("{not json")
            os.utime(p, (time.time() + 5, time.time() + 5))
            inv.refresh()
            self.assertIsNotNone(inv.lookup("h1"))
            self.assertIn("cannot parse", inv.errors[0])


INVENTORY = {
    "landscapes": [
        {"name": "Dev", "code": "CON", "servers": [{"host": "devhost01", "cluster": "CIS & B2B", "roles": ["CIS & B2B"]}]},
        {"name": "PROD", "code": "", "servers": [
            {"host": "prdhost01", "cluster": "CIS", "roles": ["PRD_CIS1"]},
            {"host": "prdhost02", "cluster": "CIS", "roles": ["PRD_CIS2"]},
            {"host": "prdhost03", "cluster": "UM", "roles": ["=HYPERLINK(\"x\")"]}]}],
    "shared_storage": [{"name": "PROD NAS", "path": "/nas/wm_shared", "landscapes": ["PROD"]}]}


class HealthCheckApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = os.path.join(self.tmp.name, "inventory.json")
        with open(p, "w") as fh:
            json.dump(INVENTORY, fh)
        self.cfg = make_cfg(self.tmp.name, inventory_file=p,
                            agents=[{"name": "all", "token_sha256": cfgmod.sha256_hex(TOKEN), "servers": ["*"]}])
        self.c = Collector(self.cfg)

    def tearDown(self):
        self.c.close()
        self.tmp.cleanup()

    def report(self, name, host, env, metrics):
        body = json.dumps({"server": {"name": name, "environment": env, "host": host, "agent_version": "t"}, "events": [],
                           "heartbeat": {"metrics": metrics}}).encode()
        st, _ = call(self.c.url + "/api/v1/ingest", body, {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}, "POST")
        self.assertEqual(st, 200)

    def seed(self):
        nas = "disk_used_pct:/nas/wm_shared"
        self.report("IS-PRD-01", "prdhost01.corp.example", "PROD", {nas: 91.0, "disk_used_pct:/sag": 40.0})  # matched by host
        self.report("prdhost02", "prdhost02", "PROD", {nas: 90.5, "disk_used_pct:/sag": 50.0})
        self.report("devhost01", "devhost01", "Dev", {nas: 99.0})                    # Dev has no shared storage entry
        self.report("IS-UAT-09", "uat09", "UAT", {"disk_used_pct:/sag": 10.0})       # reports but is not in the list

    def test_landscapes_clusters_no_data_and_unlisted(self):
        self.seed()
        st, hc = call(self.c.url + "/api/v1/healthcheck")
        self.assertEqual(st, 200)
        self.assertTrue(hc["inventory"]["loaded"])
        self.assertEqual([L["name"] for L in hc["landscapes"]], ["Dev", "PROD", "UAT"])   # list order, then unlisted environments
        prod = hc["landscapes"][1]
        self.assertEqual([c["name"] for c in prod["clusters"]], ["CIS", "UM"])
        cis = prod["clusters"][0]
        self.assertEqual((cis["up"], cis["total"]), (2, 2))
        self.assertEqual([n["server"] for n in cis["nodes"]], ["IS-PRD-01", "prdhost02"])
        um = prod["clusters"][1]["nodes"][0]
        self.assertEqual((um["status"], um["server"], um["listed"]), ("NODATA", None, True))   # listed, never reported
        self.assertEqual(prod["status"], "NODATA")
        uat = hc["landscapes"][2]
        self.assertFalse(uat["listed"])
        self.assertEqual(uat["clusters"][0]["name"], "Not in server list")
        self.assertIn("prdhost03", [n["host"] for n in hc["attention"]])

    def test_shared_storage_is_counted_once_and_kept_out_of_server_disk(self):
        self.seed()
        _, hc = call(self.c.url + "/api/v1/healthcheck")
        self.assertEqual(len(hc["shared_storage"]), 1)
        nas = hc["shared_storage"][0]
        self.assertEqual((nas["used_pct"], nas["servers"], nas["status"], nas["spread_pct"]), (91.0, 2, "CRITICAL", 0.5))
        att = [n for n in hc["attention"] if n.get("shared")]
        self.assertEqual(len(att), 1)                                    # one entry for the share, not one per server
        nodes = {n["server"]: n for L in hc["landscapes"] for c in L["clusters"] for n in c["nodes"]}
        self.assertEqual(nodes["IS-PRD-01"]["disk_max_pct"], 40.0)      # the NAS is not this server's disk
        self.assertEqual(nodes["IS-PRD-01"]["disk_max_path"], "/sag")
        self.assertEqual(nodes["devhost01"]["disk_max_pct"], 99.0)       # same path, but Dev lists no shared storage

    def test_missing_mount_and_75_percent_threshold(self):
        self.seed()
        self.report("prdhost02", "prdhost02", "PROD", {"mount_present:/nas/wm_shared": 0, "mount_present:/sag": 1,
                                                      "disk_used_pct:/sag": 75.0, "disk_used_pct:/opt/tools": 74.9})
        _, hc = call(self.c.url + "/api/v1/healthcheck")
        self.assertEqual(hc["thresholds"], {"disk_warning": 75.0, "disk_critical": 90.0})
        node = next(n for L in hc["landscapes"] for c in L["clusters"] for n in c["nodes"] if n["server"] == "prdhost02")
        self.assertEqual(node["mounts_missing"], ["/nas/wm_shared"])
        self.assertIn("Mount point /nas/wm_shared is not mounted", node["reasons"])
        self.assertIn("Disk /sag 75% used (limit 75%)", node["reasons"])  # 75% is not "under 75%"
        self.assertEqual(hc["shared_storage"][0]["missing_on"], ["prdhost02"])
        self.assertEqual(hc["shared_storage"][0]["servers"], 1)          # its last NAS reading no longer counts
        eng = self.c.hub.engine
        eng.load_rules(force=True)
        eng.evaluate()
        al = {(a["rule_id"], a["dedup_key"]): a["severity"] for a in self.c.hub.store.open_alerts()}
        self.assertEqual(al[("WM-018", "prdhost02|mount_present:/nas/wm_shared")], "critical")
        self.assertEqual(al[("WM-008", "prdhost02|disk_used_pct:/sag")], "warning")
        self.assertNotIn(("WM-008", "prdhost02|disk_used_pct:/opt/tools"), al)
        self.assertNotIn(("WM-018", "prdhost02|mount_present:/sag"), al)

    def test_opt_limits_per_landscape(self):
        # Dev (CON, CN1) 90%, UAT (Test, PSS) 85%, PROD and DR 75% for /opt*; everything else stays at 75%.
        # devhost01's agent reports environment "UNSET": its landscape comes from the server list.
        self.report("devhost01", "devhost01", "UNSET", {"disk_used_pct:/opt/DataIntegration": 88.0, "disk_used_pct:/var/opt/x": 76.0})
        self.report("IS-UAT-09", "uat09", "UAT", {"disk_used_pct:/opt/DataIntegration": 88.0})
        self.report("prdhost01", "prdhost01", "PROD", {"disk_used_pct:/opt/DataIntegration": 76.0})
        self.report("prdhost02", "prdhost02", "PROD", {"disk_used_pct:/opt/tools": 74.0})
        eng = self.c.hub.engine
        eng.load_rules(force=True)
        eng.evaluate()
        al = {a["dedup_key"]: (a["rule_id"], a["severity"]) for a in self.c.hub.store.open_alerts()}
        self.assertNotIn("devhost01|disk_used_pct:/opt/DataIntegration", al)           # 88% < 90% on Dev
        self.assertEqual(al["devhost01|disk_used_pct:/var/opt/x"], ("WM-008", "warning"))   # /var* keeps 75%
        self.assertEqual(al["IS-UAT-09|disk_used_pct:/opt/DataIntegration"], ("WM-020", "warning"))
        self.assertEqual(al["prdhost01|disk_used_pct:/opt/DataIntegration"], ("WM-021", "warning"))
        self.assertNotIn("prdhost02|disk_used_pct:/opt/tools", al)
        self.assertEqual(sum(1 for k in al if "|disk_used_pct:/opt" in k), 2)                      # no double alert from WM-008
        _, hc = call(self.c.url + "/api/v1/healthcheck")
        nodes = {n["server"]: n for L in hc["landscapes"] for c in L["clusters"] for n in c["nodes"] if n["server"]}
        dev = nodes["devhost01"]
        self.assertEqual([d["path"] for d in dev["disks_over"]], ["/var/opt/x"])
        self.assertEqual((dev["disk_max_path"], dev["disk_warn"]), ("/var/opt/x", 75.0))   # the disk that is over its limit
        self.assertIn("Disk /opt/DataIntegration 88% used (limit 85%)", nodes["IS-UAT-09"]["reasons"])
        self.assertEqual(eng.levels_for("disk_used_pct:/opt/x", {"CN1"}), (90.0, 95.0))
        self.assertEqual(eng.levels_for("disk_used_pct:/opt/x", {"PSS"}), (85.0, 95.0))
        self.assertEqual(eng.levels_for("disk_used_pct:/opt/x", {"DR"}), (75.0, 90.0))
        self.assertEqual(eng.levels_for("disk_used_pct:/opt/x", {"NEWLANDSCAPE"}), (75.0, 90.0))
        self.assertEqual(eng.levels_for("disk_used_pct:/wMNfs", {"Dev"}), (75.0, 90.0))

    def test_overview_filters_by_landscape(self):
        self.seed()
        _, d = call(self.c.url + "/api/v1/overview?env=PROD")
        self.assertEqual(sorted(s["name"] for s in d["servers"]), ["IS-PRD-01", "prdhost02"])
        self.assertEqual(d["environments"][:2], ["Dev", "PROD"])

    def test_csv_report(self):
        self.seed()
        with urllib.request.urlopen(self.c.url + "/api/report.csv", timeout=10) as r:
            self.assertIn("attachment", r.headers["Content-Disposition"])
            self.assertTrue(r.headers["Content-Type"].startswith("text/csv"))
            text = r.read().decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 6)                                   # 5 servers + 1 shared storage row
        self.assertIn("mounts_missing", rows[0])
        um = next(r for r in rows if r["host"] == "prdhost03")
        self.assertEqual(um["status"], "NODATA")
        self.assertTrue(um["roles"].startswith("'="))                    # no formula injection when opened in Excel
        nas = next(r for r in rows if r["cluster"] == "Shared storage")
        self.assertEqual((nas["landscape"], nas["disk_max_pct"]), ("PROD", "91.0"))
        with urllib.request.urlopen(self.c.url + "/api/report.csv?problems=1", timeout=10) as r:
            problems = list(csv.DictReader(io.StringIO(r.read().decode("utf-8-sig"))))
        self.assertEqual({r["status"] for r in problems}, {"NODATA", "CRITICAL"})

    def test_report_needs_dashboard_login_when_auth_is_on(self):
        self.c.hub.cfg["ui_auth"] = {"mode": "basic", "users": {"ops": cfgmod.hash_password("pw")}}
        self.assertEqual(call(self.c.url + "/api/report.csv")[0], 401)
        self.assertEqual(call(self.c.url + "/api/v1/healthcheck")[0], 401)
        auth = {"Authorization": "Basic " + base64.b64encode(b"ops:pw").decode()}
        with urllib.request.urlopen(urllib.request.Request(self.c.url + "/api/report.csv", headers=auth), timeout=10) as r:
            self.assertEqual(r.status, 200)

    def test_without_a_server_list_servers_group_by_reported_environment(self):
        self.c.hub.inventory = invmod.Inventory()
        self.seed()
        _, hc = call(self.c.url + "/api/v1/healthcheck")
        self.assertFalse(hc["inventory"]["loaded"])
        self.assertEqual(sorted(L["name"] for L in hc["landscapes"]), ["Dev", "PROD", "UAT"])
        self.assertEqual(hc["shared_storage"], [])

    def test_shared_nas_alerts_once_local_disk_alerts_per_server(self):
        self.seed()
        self.report("prdhost02", "prdhost02", "PROD", {"disk_used_pct:/nas/wm_shared": 90.5, "disk_used_pct:/sag": 95.0})
        eng = self.c.hub.engine
        eng.load_rules(force=True)
        eng.evaluate()
        disk = [a for a in self.c.hub.store.open_alerts() if a["rule_id"] == "WM-008"]
        shared = [a for a in disk if a["server"] == FLEET]
        self.assertEqual(len(shared), 1)
        self.assertEqual((shared[0]["severity"], shared[0]["environment"], shared[0]["value"]), ("critical", "PROD", 91.0))
        self.assertIn("PROD NAS", shared[0]["title"])
        local = sorted((a["server"], a["dedup_key"]) for a in disk if a["server"] != FLEET)
        self.assertEqual(local, [("devhost01", "devhost01|disk_used_pct:/nas/wm_shared"),   # Dev path is not declared shared
                                 ("prdhost02", "prdhost02|disk_used_pct:/sag")])


class DemoEstate(unittest.TestCase):
    def test_demo_inventory_follows_the_server_list(self):
        hosts = simulate.load_hosts()
        self.assertEqual([ls for ls in dict.fromkeys(h["landscape"] for h in hosts)], ["Dev", "Test", "PROD", "CN1", "PSS", "DR"])
        self.assertEqual(len(hosts), len({h["name"] for h in hosts}))
        with open(simulate.DEFAULT_INVENTORY) as fh:
            self.assertEqual(invmod.parse(json.load(fh))[1], [])

    def test_plan_maps_scenario_to_listed_hosts(self):
        hosts = simulate.load_hosts()
        real, light, quiet, parts = simulate.plan(hosts)
        self.assertEqual(len(real), 5)
        self.assertEqual(len(real) + len(light) + len(quiet), len(hosts))
        by = {h["name"]: h for h in hosts}
        self.assertIn("PRD_CIS1", by[parts["IS-PRD-01"]]["roles"])
        self.assertEqual(by[parts["IS-UAT-01"]]["landscape"], "Test")
        self.assertEqual([by[q]["roles"] for q in quiet], [["DR_DMZ_RI"]])
        real_all, light_all, _, _ = simulate.plan(hosts, all_real=True)
        self.assertEqual((len(real_all), len(light_all)), (len(hosts) - 1, 0))

    def test_light_host_payload_matches_the_ingest_contract(self):
        from hub import server as srv
        h = simulate.Light({"name": "site1wmasd009", "landscape": "Dev", "cluster": "Broker", "roles": ["Broker"]},
                           "http://127.0.0.1:1", "t")
        p = h.payload()
        self.assertEqual(srv.clean_server(p["server"])["environment"], "Dev")
        for e in p["events"]:
            srv.clean_event(e, time.time())
        self.assertIn("disk_used_pct:" + simulate.NAS_PATH, srv.clean_heartbeat(p["heartbeat"], time.time())["metrics"])


if __name__ == "__main__":
    unittest.main()
