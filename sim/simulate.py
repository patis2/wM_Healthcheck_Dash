#!/usr/bin/env python3
"""Simulated webMethods estate for demos and tests.

The estate follows a server list (inventory.json; default: inventory.demo.json, generated from the
team's Server List.xlsx): one simulated host per listed host, named after its host name and
reporting the landscape it is listed under.

Five hosts used by the scenario are "real": each gets webMethods-style server.log / wrapper.log files,
a probe endpoint and a REAL agent process (agent/wm_agent.py) shipping to the collector. The scenario
injects error bursts, an out-of-memory event, log rotation, a dead agent, a failing probe and a filling
NAS share (/wMShared) so the alert engine, dedup, auto-resolve and the notification payloads can be seen working.
Every other host is "light": one thread posts its heartbeat metrics and a few log events through the
same ingest API and per-host token, which keeps a 75-host demo to a few processes. Pass
--all-real-agents to run a real agent for every host instead (roughly 20 MB of memory per agent).
One host per --silent entry never reports, to show how a listed host without an agent looks.

    WM_SIM_TOKENS='{"site2wmasp104": "wmh_...", ...}' python simulate.py --workdir ./wmsim --collector http://127.0.0.1:8080

Each simulated host gets its own agent token (JSON map in WM_SIM_TOKENS, one entry per server name),
because the collector only lets a token report as the server names it was issued for.
"""
import argparse
import json
import os
import random
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(os.path.dirname(HERE), "agent", "wm_agent.py")

# inventory.local.json (gitignored) holds a real server list on the operator's PC; the committed
# inventory.demo.json uses placeholder host names (siteNwm...) with the same shape.
_LOCAL_INVENTORY = os.path.join(HERE, "inventory.local.json")
DEFAULT_INVENTORY = _LOCAL_INVENTORY if os.path.exists(_LOCAL_INVENTORY) else os.path.join(HERE, "inventory.demo.json")
# File systems as on a real host (df -h of a Dev IS server): mount -> (size GB, typical used %).
# Monitored are /opt*, /var* (local to each server) and the NAS mounts /wMNfs and /wMShared (shared).
MAIN_DISK = "/opt/DataIntegration"
LOCAL_DISKS = {"/opt/DataIntegration": (60, 75), "/opt/DataIntegration/logs": (29, 4), "/opt/DataIntegration/dropbox": (25, 1),
               "/opt/WM12/DataIntegration": (60, 64), "/opt/WM12/DataIntegration/logs": (30, 28),
               "/opt/WM12/DataIntegration/dropbox": (25, 1), "/var/opt/DataIntegration": (30, 27),
               "/var/opt/WM12/DataIntegration": (30, 28), "/opt/tools": (16, 34)}
NAS_DISKS = {"/wMNfs": (195, 70), "/wMShared": (249, 65)}
NAS_PATH = "/wMShared"  # the share the scenario fills
# scenario part -> (landscape, role in the server list, tz label written in the log, tz offset minutes)
SCENARIO_ROLES = {
    "IS-PRD-01": ("PROD", "PRD_CIS1", "UTC", 0),
    "IS-PRD-02": ("PROD", "PRD_A2A1", "UTC", 0),
    "MWS-PRD-01": ("PROD", "MWS01_PROD", "UTC", 0),
    "IS-UAT-01": ("Test", "CIS01_TEST", "IST", 330),
    "IS-DEV-01": ("Dev", "CIS & B2B", "GMT-03:00", -180),
}
DEFAULT_SILENT = ["DR_DMZ_RI"]  # listed but never reports: shows as "No data"
NAS = {}  # (landscape, mount) -> used % of that landscape's NAS share, moved by the scenario, read by its hosts


def load_hosts(path=DEFAULT_INVENTORY):
    """[{name, landscape, cluster, roles}] in server-list order; name is the lower-case host name."""
    with open(path, encoding="utf-8") as fh:
        inv = json.load(fh)
    return [{"name": s["host"].lower(), "landscape": ls["name"], "cluster": s.get("cluster", ""), "roles": s.get("roles") or []}
            for ls in inv["landscapes"] for s in ls["servers"]]


def plan(hosts, all_real=False, silent=DEFAULT_SILENT):
    """Pick the host behind each scenario part. Returns (real, light, silent_names, part -> host name)."""
    def pick(ls, role):
        return (next((h for h in hosts if h["landscape"] == ls and role in h["roles"]), None)
                or next((h for h in hosts if h["landscape"] == ls), None))
    parts, used = {}, set()
    for part, (ls, role, *_x) in SCENARIO_ROLES.items():
        h = pick(ls, role)
        h = h if h and h["name"] not in used else next(x for x in hosts if x["name"] not in used)
        parts[part] = h["name"]
        used.add(h["name"])
    quiet = {h["name"] for h in hosts if h["name"] not in used and (h["name"] in silent or set(h["roles"]) & set(silent))}
    real = [h for h in hosts if h["name"] in used or (all_real and h["name"] not in quiet)]
    light = [h for h in hosts if h not in real and h["name"] not in quiet]
    return real, light, sorted(quiet), parts


def nas_used(landscape, path=NAS_PATH):
    return NAS.setdefault((landscape, path), min(72.0, NAS_DISKS[path][1] + random.uniform(-15, 5)))


def local_disks():
    """Per-host starting point for each local file system, scattered around the reference host's values."""
    return {p: min(72.0, max(0.5, used + random.uniform(-15, 5))) for p, (_, used) in LOCAL_DISKS.items()}


def disk_metrics(host):
    """mount_present / disk_used_pct / disk_free_gb for every monitored mount, as the agent reports them.
    A mount point in host.missing is reported as not mounted and has no usage figures."""
    m = {}
    for p, (size, _) in {**LOCAL_DISKS, **NAS_DISKS}.items():
        m["mount_present:" + p] = 0 if p in host.missing else 1
        if p in host.missing:
            continue
        v = host.disk if p == MAIN_DISK else host.local[p] if p in LOCAL_DISKS else nas_used(host.env, p)
        m["disk_used_pct:" + p], m["disk_free_gb:" + p] = round(v, 1), round(size * (100 - v) / 100, 2)
    return m


DEMO_MISSING = {"UM3": {"/wMShared"}}  # role -> mount points never mounted on that host (a static "missing" example)
# role -> fixed /opt/DataIntegration used %: the same 87-88% is healthy on Dev (limit 90%) and a warning on UAT (85%)
DEMO_OPT = {"Broker": 88.0, "UM1": 87.0}

INFO = ["Service acme.orders:createOrder completed in {n} ms", "Adapter connection ACME.DB:conn1 validated", "Package AcmeOrders loaded",
        "Invoked wm.server:ping by Administrator", "Scheduler task cleanupSessions ran, removed {n} sessions", "Trigger acme.events:onOrder processed document {n}"]
WARN = ["Retry 2 of 3 for service acme.billing:postInvoice", "Slow service acme.orders:search took {n} ms", "Session pool at {n}% capacity",
        "Document {n} routed to dead-letter queue", "Certificate for partner ACME-EDI expires in {n} days"]
ERR = ["Exception --> com.wm.app.b2b.server.ServiceException: acme.orders:createOrder failed: order {n} not found",
       "Exception --> java.net.SocketTimeoutException: Read timed out calling https://partner.example.com/api/v2/orders/{n}"]
DB = "Exception --> java.sql.SQLException: Connection refused (Connection refused) while acquiring connection from pool ACME.DB:conn1 [attempt {n}]"
TRACE = ["\tat com.wm.app.b2b.server.ns.NSService.invoke(NSService.java:{n})", "\tat com.wm.app.b2b.server.invoke.InvokeManager.process(InvokeManager.java:{n})",
         "\tat com.wm.app.b2b.server.ServerThread.run(ServerThread.java:{n})"]


class Probe:
    def __init__(self, port):
        self.up = True
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if outer.up else 503)
                self.end_headers()
                self.wfile.write(b"OK" if outer.up else b"DOWN")

            def log_message(self, *a):
                pass
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


class Srv:
    def __init__(self, workdir, name, env, tz, off, port, collector, token, tags=None):
        self.name, self.env, self.tz, self.off, self.port = name, env, tz, off, port
        self.dir = os.path.join(workdir, name)
        os.makedirs(os.path.join(self.dir, "logs"), exist_ok=True)
        self.log = os.path.join(self.dir, "logs", "server.log")
        self.wrap = os.path.join(self.dir, "logs", "wrapper.log")
        self.extra = os.path.join(self.dir, "extra_metrics.json")
        self.seq = 0
        self.expected = set()
        self.lock = threading.Lock()
        self.probe = Probe(port)
        self.agent = None
        self.collector, self.token = collector, token
        self.local = local_disks()
        self.disk = self.local[MAIN_DISK]
        self.missing = set()
        self.cfg_path = os.path.join(self.dir, "agent.json")
        with open(self.cfg_path, "w") as fh:
            json.dump({
                "collector_url": collector, "server_name": name, "environment": env,
                "tags": tags or {"instance": "default"},
                "sources": [{"name": "server.log", "path": self.log, "profile": "is_server"},
                            {"name": "wrapper.log", "path": self.wrap, "profile": "wrapper"}],
                "disk_paths": [], "default_tz": "+00:00", "first_run": "beginning",
                "spool_dir": os.path.join(self.dir, "spool"), "state_file": os.path.join(self.dir, "state.json"),
                "poll_interval_s": 1, "flush_interval_s": 2, "heartbeat_interval_s": 5, "multiline_timeout_s": 1.5,
                "extra_metrics_file": self.extra,
                "probes": [{"name": "is-ping", "url": f"http://127.0.0.1:{port}/invoke/wm.server/ping", "timeout_s": 2}],
                "log_file": os.path.join(self.dir, "agent.log")}, fh, indent=2)

    # -- logging ----------------------------------------------------------------
    def stamp(self, t):
        d = datetime.fromtimestamp(t, timezone.utc) + timedelta(minutes=self.off)
        return d.strftime("%Y-%m-%d %H:%M:%S") + f" {self.tz}"

    def emit(self, level, code, msg, t=None, trace=0, path=None, fh=None):
        t = t or time.time()
        with self.lock:
            self.seq += 1
            n = self.seq
            self.expected.add(n)
        text = f"{msg} [seq={n}]"
        lines = [f"{self.stamp(t)} [{code}{level}] (tid={random.randint(10, 900)}) {text}"]
        lines += [random.choice(TRACE).format(n=random.randint(10, 900)) for _ in range(trace)]
        return "\n".join(lines) + "\n"

    def write(self, text, path=None):
        with self.lock:  # rotation renames the file under this lock; Windows cannot rename a file that is open
            with open(path or self.log, "a") as fh:
                fh.write(text)

    def rand_event(self, t=None):
        r = random.random()
        if r < 0.80:
            return self.emit("I", "ISS.0014.0004", random.choice(INFO).format(n=random.randint(5, 900)), t)
        if r < 0.96:
            return self.emit("W", "ISS.0033.0100", random.choice(WARN).format(n=random.randint(5, 9000)), t)
        return self.emit("E", "ISP.0090.0003", random.choice(ERR).format(n=random.randint(100, 99999)), t, trace=3)

    def backfill(self, hours):
        now = time.time()
        bursts = [now - random.uniform(0.5, hours) * 3600 for _ in range(2)]
        out = []
        t = now - hours * 3600
        while t < now - 20:
            rate = 5 + 3 * random.random()  # events per minute baseline
            for b in bursts:
                if b <= t < b + 360:
                    rate = 28
            for _ in range(int(rate * (60 / 60))):
                out.append((t + random.uniform(0, 60), None))
            t += 60
        out.sort()
        with open(self.log, "w") as fh:
            for ts, _ in out:
                fh.write(self.rand_event(ts))
        with open(self.wrap, "w") as fh:
            fh.write(f"STATUS | wrapper  | {datetime.fromtimestamp(now - hours * 3600, timezone.utc):%Y/%m/%d %H:%M:%S} | --> Wrapper Started as Service\n")

    # -- agent ----------------------------------------------------------------------
    def start_agent(self, *extra):
        env = dict(os.environ, WM_AGENT_TOKEN=self.token)
        env.pop("WM_SIM_TOKENS", None)  # each agent sees only its own token
        with open(os.path.join(self.dir, "agent.stderr"), "a") as err:
            self.agent = subprocess.Popen([sys.executable, AGENT, "--config", self.cfg_path, *extra], env=env,
                                          stdout=subprocess.DEVNULL, stderr=err)

    def drain(self):
        """Restart the agent once with --once: it resumes from its saved offsets and delivers what is left."""
        self.stop_agent()
        self.start_agent("--once")
        self.agent.wait(timeout=90)

    def stop_agent(self, kill=False):
        if self.agent and self.agent.poll() is None:
            self.agent.kill() if kill else self.agent.terminate()
            self.agent.wait(timeout=15)

    def metrics_loop(self, stop):
        while not stop.is_set():
            self.disk += random.uniform(-0.05, 0.08)
            with open(self.extra, "w") as fh:
                json.dump(dict(disk_metrics(self), jvm_heap_used_pct=round(random.uniform(40, 72), 1)), fh)
            stop.wait(5)

    def traffic_loop(self, stop):
        while not stop.is_set():
            self.write("".join(self.rand_event() for _ in range(random.choice([0, 0, 1, 1, 2, 3]))))
            if random.random() < 0.02:
                self.write(f"INFO   | jvm 1    | {datetime.now(timezone.utc):%Y/%m/%d %H:%M:%S} | Heartbeat check {random.randint(1, 99)}\n", self.wrap)
            stop.wait(1)


class Light:
    """A host simulated without an agent process: heartbeats and a few events through the ingest API."""

    def __init__(self, h, collector, token):
        self.name, self.env, self.token = h["name"], h["landscape"], token
        self.url = collector.rstrip("/") + "/api/v1/ingest"
        self.server = {"name": self.name, "environment": self.env, "host": self.name, "agent_version": "sim-light",
                       "os": "Linux (simulated)", "tags": {"cluster": h["cluster"][:80], "simulated": "light"}}
        self.local = local_disks()
        self.disk = self.local[MAIN_DISK]
        self.missing = set().union(*(DEMO_MISSING.get(r, set()) for r in h["roles"]))
        self.disk = next((DEMO_OPT[r] for r in h["roles"] if r in DEMO_OPT), self.disk)
        self.load, self.mem = random.uniform(0.1, 0.8), random.uniform(45, 75)
        self.seq, self.run = 0, f"{int(time.time()):x}"
        self.failures = 0

    def payload(self):
        now = datetime.now(timezone.utc)
        events = []
        for _ in range(random.choice([0, 0, 1, 1, 2])):
            self.seq += 1
            r = random.random()
            lvl, code, msg = (("INFO", "ISS.0014.0004", random.choice(INFO)) if r < 0.85 else
                              ("WARN", "ISS.0033.0100", random.choice(WARN)) if r < 0.98 else ("ERROR", "ISP.0090.0003", random.choice(ERR)))
            events.append({"eid": f"sim-{self.name}-{self.run}-{self.seq}", "ts": now.isoformat(timespec="milliseconds"), "level": lvl,
                           "code": code, "source": "server.log", "msg": msg.format(n=random.randint(5, 9000))})
        self.disk += random.uniform(-0.03, 0.05)
        m = {"load_per_cpu": round(max(0.02, self.load + random.uniform(-0.1, 0.15)), 2), "mem_used_pct": round(self.mem + random.uniform(-2, 2), 1),
             **disk_metrics(self),
             "probe_ok:is-ping": 1, "probe_ms:is-ping": round(10 + 25 * random.random(), 1), "agent_spool_files": 0}
        return {"agent_id": self.name, "server": self.server, "events": events,
                "heartbeat": {"ts": now.isoformat(timespec="seconds"), "metrics": m}}

    def send(self):
        req = urllib.request.Request(self.url, data=json.dumps(self.payload()).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            self.failures = 0
        except (urllib.error.URLError, OSError) as exc:
            self.failures += 1
            if self.failures in (1, 10, 100):
                print(f"light host {self.name}: send failed ({exc}); retrying", flush=True)


def light_loop(hosts, stop, interval=5):
    while not stop.is_set():
        t = time.time()
        for h in hosts:
            if stop.is_set():
                return
            h.send()
        stop.wait(max(0.5, interval - (time.time() - t)))


def seed_metrics(db, servers, hours):
    """Backfill metric history so sparklines are populated on first look (demo only)."""
    con = sqlite3.connect(db)
    now = time.time()
    rows = []
    for s in servers:
        base_load, base_mem = random.uniform(0.2, 0.9), random.uniform(48, 70)
        t = now - hours * 3600
        i = 0
        while t < now - 30:
            i += 1
            rows += [(s.name, t, "load_per_cpu", max(0.02, base_load + 0.25 * random.random() + (0.6 if i % 90 < 6 else 0))),
                     (s.name, t, "mem_used_pct", min(99, base_mem + 5 * random.random() + i * 0.004)),
                     (s.name, t, "disk_used_pct:" + MAIN_DISK, s.disk - (now - t) / 3600 * 0.15 + random.uniform(-.1, .1)),
                     (s.name, t, "disk_used_pct:/wMNfs", nas_used(s.env, "/wMNfs") - (now - t) / 3600 * 0.2),
                     (s.name, t, "disk_used_pct:/wMShared", nas_used(s.env, "/wMShared") - (now - t) / 3600 * 0.3),
                     (s.name, t, "probe_ms:is-ping", 12 + 30 * random.random() + (150 if i % 120 < 3 else 0))]
            t += 120
    con.executemany("INSERT INTO metrics(server, ts, name, value) VALUES(?,?,?,?)", rows)
    con.commit()
    con.close()


def scenario(srvs, stop, t0, parts):
    by = {part: next(s for s in srvs if s.name == host) for part, host in parts.items()}
    steps = []

    def at(sec, fn, label):
        steps.append((sec, fn, label))

    def db_burst():
        s = by["IS-PRD-02"]
        for i in range(70):
            s.write(s.emit("E", "ISP.0090.0003", DB.format(n=i), trace=2))
            time.sleep(0.25)

    def oom():
        s = by["IS-PRD-01"]
        s.write(s.emit("E", "ISC.0075.0006", "Exception --> java.lang.OutOfMemoryError: Java heap space", trace=2))
        s.write(f"ERROR  | jvm 1    | {datetime.now(timezone.utc):%Y/%m/%d %H:%M:%S} | Exception in thread \"pool-3\" java.lang.OutOfMemoryError: Java heap space\n", s.wrap)

    def new_pattern():
        s = by["IS-UAT-01"]
        s.write(s.emit("E", "ISP.0090.0099", "Exception --> com.acme.NewFeatureException: mapping 'CustomerV3' is missing field 'taxId'", trace=3))

    def rotate():
        s = by["IS-PRD-01"]
        for attempt in range(50):  # on Windows the agent may hold the file open for a moment while reading
            try:
                with s.lock:
                    os.rename(s.log, s.log + ".1")
                    open(s.log, "w").close()
                break
            except PermissionError:
                time.sleep(0.1)
        else:
            raise RuntimeError("could not rotate server.log")
        for _ in range(40):
            s.write(s.rand_event())
            time.sleep(0.1)

    def auth_storm():
        for i in range(25):
            s = by[random.choice(["IS-PRD-01", "IS-PRD-02"])]
            s.write(s.emit("C", "ISS.0053.0002", f"Access denied for user svc_edi{i % 3} on port 5555"))
            time.sleep(0.2)

    at(15, lambda: threading.Thread(target=db_burst, daemon=True).start(), "DB burst on IS-PRD-02")
    at(25, oom, "OOM on IS-PRD-01")
    at(30, new_pattern, "new error pattern on IS-UAT-01")
    at(35, lambda: setattr(by["IS-PRD-02"].probe, "up", False), "probe down on IS-PRD-02")
    at(40, lambda: by["IS-PRD-01"].__setattr__("disk", 93.5), "/opt/DataIntegration 93% on IS-PRD-01")
    at(45, lambda: by["MWS-PRD-01"].stop_agent(kill=True), "agent killed on MWS-PRD-01")
    at(50, rotate, "log rotation on IS-PRD-01")
    at(55, lambda: threading.Thread(target=auth_storm, daemon=True).start(), "auth failure storm")
    at(110, lambda: setattr(by["IS-PRD-02"].probe, "up", True), "probe recovers")
    at(120, lambda: by["MWS-PRD-01"].start_agent(), "agent restarted on MWS-PRD-01")
    at(125, lambda: by["IS-PRD-01"].__setattr__("disk", 61.0), "disk back to normal")
    at(60, lambda: NAS.__setitem__(("PROD", "/wMShared"), 91.5), "PROD /wMShared NAS 91% full (one alert, not one per server)")
    at(150, lambda: NAS.__setitem__(("PROD", "/wMShared"), 66.0), "PROD /wMShared cleaned up")
    at(70, lambda: by["IS-PRD-02"].missing.add("/wMNfs"), "/wMNfs NFS mount dropped on IS-PRD-02")
    at(140, lambda: by["IS-PRD-02"].missing.discard("/wMNfs"), "/wMNfs mounted again on IS-PRD-02")
    for sec, fn, label in sorted(steps, key=lambda x: x[0]):
        while time.time() - t0 < sec:
            if stop.wait(0.5):
                return
        label = label.replace("IS-PRD-01", parts["IS-PRD-01"]).replace("IS-PRD-02", parts["IS-PRD-02"]) \
            .replace("MWS-PRD-01", parts["MWS-PRD-01"]).replace("IS-UAT-01", parts["IS-UAT-01"])
        print(f"[scenario +{sec:>3}s] {label}", flush=True)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            print("scenario step failed:", exc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--collector", default="http://127.0.0.1:8080")
    ap.add_argument("--inventory", default=DEFAULT_INVENTORY, help="server list to simulate (inventory.json format)")
    ap.add_argument("--all-real-agents", action="store_true", help="run a real agent process for every host (heavy)")
    ap.add_argument("--silent", action="append", help="host or role that never reports (repeatable; default %s)" % DEFAULT_SILENT)
    ap.add_argument("--token", help="one token for every server (only works if the collector allows it); "
                                     "prefer WM_SIM_TOKENS with one token per server")
    ap.add_argument("--db", help="collector sqlite file, used only to seed metric history for the demo")
    ap.add_argument("--history-hours", type=float, default=6)
    ap.add_argument("--run-seconds", type=int, default=0, help="0 = run until Ctrl-C")
    ap.add_argument("--no-scenario", action="store_true")
    a = ap.parse_args()

    tokens = json.loads(os.environ.get("WM_SIM_TOKENS") or "{}")
    if not tokens and not a.token:
        ap.error("set WM_SIM_TOKENS (JSON map of server name -> token) or pass --token")
    os.makedirs(a.workdir, exist_ok=True)
    real, light, quiet, parts = plan(load_hosts(a.inventory), a.all_real_agents, a.silent or DEFAULT_SILENT)
    tz = {host: SCENARIO_ROLES[part][2:] for part, host in parts.items()}
    srvs = [Srv(a.workdir, h["name"], h["landscape"], *tz.get(h["name"], ("UTC", 0)), 18101 + i, a.collector,
                tokens.get(h["name"]) or a.token, {"instance": "default", "cluster": h["cluster"][:80]}) for i, h in enumerate(real)]
    lights = [Light(h, a.collector, tokens.get(h["name"]) or a.token) for h in light]
    for s in srvs:
        s.backfill(a.history_hours)
    if a.db:
        seed_metrics(a.db, srvs + lights, a.history_hours)
    for s in srvs:
        s.start_agent()
    stop = threading.Event()
    for s in srvs:
        threading.Thread(target=s.metrics_loop, args=(stop,), daemon=True).start()
        threading.Thread(target=s.traffic_loop, args=(stop,), daemon=True).start()
    if lights:
        threading.Thread(target=light_loop, args=(lights, stop), daemon=True).start()
    t0 = time.time()
    if not a.no_scenario:
        threading.Thread(target=scenario, args=(srvs, stop, t0, parts), daemon=True).start()
    print(f"simulating {len(srvs) + len(lights)} hosts ({len(srvs)} with a real agent, {len(lights)} light); "
          f"never reporting: {', '.join(quiet) or 'none'}. Ctrl-C to stop", flush=True)
    try:
        while not stop.wait(1):
            if a.run_seconds and time.time() - t0 > a.run_seconds:
                break
    except KeyboardInterrupt:
        pass
    stop.set()
    time.sleep(3)  # let the last lines be picked up
    for s in srvs:
        s.drain()
    with open(os.path.join(a.workdir, "expected.json"), "w") as fh:
        json.dump({s.name: sorted(s.expected) for s in srvs}, fh)
    print("done; expected sequence numbers written to expected.json")


if __name__ == "__main__":
    main()
