"""HTTP server: agent ingest endpoint, dashboard API and the static dashboard page."""
from __future__ import annotations

import base64
import csv
import fnmatch
import io
import json
import logging
import math
import os
import re
import ssl
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config as cfgmod
from .alerts import Engine
from .inventory import Inventory
from .notify import Notifier
from .store import RANK, Store, iso_to_epoch

log = logging.getLogger("hub.server")
NAME_RX = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")
EID_RX = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


class HttpError(Exception):
    def __init__(self, code, msg, headers=None):
        super().__init__(msg)
        self.code, self.msg, self.headers = code, msg, headers or {}


class Hub:
    """Shared application state handed to every request handler."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.store = Store(cfg["db_path"], cfg.get("sqlite_synchronous", "NORMAL"))
        self.notifier = Notifier(cfg, self.store)
        self.engine = Engine(cfg, self.store, self.notifier)
        self.inventory = Inventory(cfg.get("inventory_file")).refresh()
        self.engine.inventory = self.inventory
        self.agent_index = {a["token_sha256"]: a for a in cfg["agents"]}
        self.stats = {"started": time.time(), "ingest_requests": 0, "events_accepted": 0, "events_duplicate": 0,
                      "ingest_rejected": 0, "last_ingest": 0.0}
        self.stop = threading.Event()

    def start_background(self):
        self.notifier.start()
        self.engine.start()
        threading.Thread(target=self._janitor, daemon=True, name="janitor").start()

    def _janitor(self):
        delay = 60  # first purge shortly after start, then hourly
        while not self.stop.wait(delay):
            delay = 3600
            try:
                r = self.cfg["retention_days"]
                n = self.store.purge(r["events"], r["metrics"], r["alerts"])
                log.info("retention purge: %d events, %d metric rows, %d alerts", *n)
            except Exception:  # noqa: BLE001
                log.exception("purge failed")


# -- helpers ----------------------------------------------------------------------------------
def clean_event(e, recv, max_msg=4000, max_detail=12000):
    """Validate one event. Event time (UTC epoch) is kept separate from the collector's receive time."""
    if not isinstance(e, dict):
        raise ValueError("event must be an object")
    eid = str(e.get("eid") or "")
    if not EID_RX.match(eid):
        raise ValueError("event.eid missing, too long or has invalid characters")
    ts = iso_to_epoch(e.get("ts"), recv)
    if not math.isfinite(ts) or ts > recv + 86400:  # more than a day in the future: clamp to arrival time
        ts = recv
    level = str(e.get("level", "INFO")).upper()
    return {"eid": eid, "ts_epoch": ts, "source": str(e.get("source", ""))[:128], "level": level if level in RANK else "INFO",
            "code": str(e.get("code", ""))[:40], "tid": str(e.get("tid", ""))[:20], "msg": str(e.get("msg", ""))[:max_msg],
            "detail": str(e.get("detail", ""))[:max_detail]}


def clean_server(s):
    if not isinstance(s, dict) or not NAME_RX.match(str(s.get("name", ""))):
        raise ValueError("server.name missing or invalid")
    tags = s.get("tags") if isinstance(s.get("tags"), dict) else {}
    return {"name": s["name"], "environment": str(s.get("environment", "UNSET"))[:30], "host": str(s.get("host", ""))[:200],
            "tags": {str(k)[:40]: str(v)[:80] for k, v in list(tags.items())[:20]},
            "agent_version": str(s.get("agent_version", ""))[:20], "os": str(s.get("os", ""))[:80]}


def clean_heartbeat(h, recv):
    if not h:
        return None
    if not isinstance(h, dict) or not isinstance(h.get("metrics") or {}, dict):
        raise ValueError("heartbeat must be an object with a metrics map")
    metrics = {}
    for k, v in list((h.get("metrics") or {}).items())[:500]:
        if isinstance(v, (int, float)) and not isinstance(v, bool) and len(str(k)) <= 200 and math.isfinite(v):
            metrics[str(k)] = float(v)
    return {"ts_epoch": iso_to_epoch(h.get("ts"), recv), "metrics": metrics}


def status_of(s, now, alerts, down_after, maint):
    if s["state"] == "retired":
        return "RETIRED"
    if any(fnmatch.fnmatch(s["name"], m["server_glob"]) for m in maint):
        return "MAINT"
    if now - s["last_seen"] > down_after:
        return "DOWN"
    sev = {a["severity"] for a in alerts}
    return "CRITICAL" if "critical" in sev else "WARNING" if "warning" in sev else "OK"


class Handler(BaseHTTPRequestHandler):
    server_version = "WmHub/0.1"
    protocol_version = "HTTP/1.1"
    timeout = 30  # seconds a client may stall a request before the socket is dropped
    hub: Hub = None  # injected

    # -- plumbing ---------------------------------------------------------------------
    def log_message(self, fmt, *args):  # quiet access log, errors are logged explicitly
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, code, body, ctype="application/json", headers=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, default=str, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method):
        try:
            u = urlparse(self.path)
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            path = u.path.rstrip("/") or "/"
            for m, rx, fn, kind in ROUTES:
                if m != method:
                    continue
                mt = rx.match(path)
                if mt:
                    if kind == "agent":
                        return fn(self, mt, qs)
                    actor = self._ui_auth()
                    if method != "GET" and self.headers.get("X-WM-Hub") != "1":
                        raise HttpError(403, "missing X-WM-Hub header (CSRF protection)")
                    self.actor = actor
                    return fn(self, mt, qs)
            raise HttpError(404, "not found")
        except HttpError as e:
            if e.code >= 400:
                self.close_connection = True  # an unread request body must not be parsed as the next request
            self._send(e.code, {"error": e.msg}, headers=e.headers)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("unhandled error for %s %s", method, self.path)
            self._send(500, {"error": "internal error"})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise HttpError(400, "invalid Content-Length")
        cap = int(self.hub.cfg["max_body_mb"] * 1024 * 1024)
        if n <= 0:
            return b""
        if n > cap:
            raise HttpError(413, "body too large")
        return self.rfile.read(n)

    def _json_body(self):
        raw = self._body()
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise HttpError(400, "invalid JSON")

    # -- auth ---------------------------------------------------------------------------------
    def _ui_auth(self):
        a = self.hub.cfg["ui_auth"]
        if a.get("mode", "none") == "none":
            return "anonymous"
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                stored = a["users"].get(user)
                if stored and cfgmod.verify_password(pw, stored):
                    return user
            except (ValueError, UnicodeDecodeError):
                pass
        raise HttpError(401, "authentication required", {"WWW-Authenticate": 'Basic realm="webMethods Hub", charset="UTF-8"'})

    def _agent_auth(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise HttpError(401, "bearer token required")
        agent = self.hub.agent_index.get(cfgmod.sha256_hex(h[7:].strip()))
        if not agent:
            time.sleep(0.5)  # blunt brute-force guessing a little
            raise HttpError(401, "invalid token")
        return agent


# =============================================================================================
# Agent endpoint
# =============================================================================================
def h_ingest(self: Handler, mt, qs):
    hub = self.hub
    agent = self._agent_auth()
    enc = self.headers.get("Content-Encoding", "").strip().lower()
    if enc not in ("", "identity", "gzip"):
        raise HttpError(415, "Content-Encoding must be gzip")
    raw = self._body()
    cap = int(hub.cfg["max_body_mb"] * 1024 * 1024) * 4
    try:
        if enc == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, cap)
            if d.unconsumed_tail:
                raise HttpError(413, "decompressed body too large")
        payload = json.loads(raw)
    except (zlib.error, ValueError, EOFError, OSError):
        hub.stats["ingest_rejected"] += 1
        raise HttpError(400, "body is not valid (gzip) JSON")
    if not isinstance(payload, dict):
        hub.stats["ingest_rejected"] += 1
        raise HttpError(400, "body must be a JSON object")
    recv = time.time()
    try:
        server = clean_server(payload.get("server"))
        # a token entry without a 'servers' list may report as nobody (config validation also rejects it)
        if not any(fnmatch.fnmatchcase(server["name"], g) for g in agent.get("servers") or []):
            raise HttpError(403, f"token '{agent.get('name')}' may not report as '{server['name']}'")
        evs = payload.get("events") or []
        if not isinstance(evs, list) or len(evs) > hub.cfg["max_events_per_batch"]:
            raise ValueError("events must be a list of at most %d" % hub.cfg["max_events_per_batch"])
        events = [clean_event(e, recv, hub.cfg["max_message_chars"], hub.cfg["max_detail_chars"]) for e in evs]
        hb = clean_heartbeat(payload.get("heartbeat"), recv)
    except ValueError as exc:
        hub.stats["ingest_rejected"] += 1
        raise HttpError(422, str(exc))
    accepted, dup = hub.store.ingest(server, events, hb, recv)
    s = hub.stats
    s["ingest_requests"] += 1
    s["events_accepted"] += accepted
    s["events_duplicate"] += dup
    s["last_ingest"] = recv
    self._send(200, {"accepted": accepted, "duplicates": dup})


# =============================================================================================
# Dashboard API
# =============================================================================================
def _int(qs, key, default, lo, hi):
    try:
        v = int(qs.get(key, default))
    except (TypeError, ValueError):
        raise HttpError(400, f"{key} must be an integer")
    return min(max(v, lo), hi)


def _down_after(hub):
    return max(4 * hub.cfg["expected_heartbeat_s"], 120)


DEFAULT_DISK_LEVELS = (75.0, 90.0)  # used when no rule covers a disk


def _finite(v):
    return None if v == float("inf") else v


def _server_rows(hub, now):
    store = hub.store
    inv = hub.inventory.refresh()
    alerts_by = {}
    for a in store.open_alerts():
        alerts_by.setdefault(a["server"], []).append(a)
    counts = {r["server"]: r for r in store.event_counts(now - 3600)}
    metrics = {}
    for m in store.metric_latest():
        metrics.setdefault(m["server"], {})[m["name"]] = m
    maint = store.active_maintenance(now)
    rows = []
    for s in store.servers():
        al = alerts_by.get(s["name"], [])
        c = counts.get(s["name"], {})
        mm = {k: v["value"] for k, v in metrics.get(s["name"], {}).items() if now - v["ts"] < 3 * _down_after(hub)}
        entry = inv.lookup(s["name"], s["host"])
        landscape = entry["landscape"] if entry else s["environment"]
        shared = inv.shared_metric_names(landscape)  # NAS shares are reported once under Shared storage, not per server
        gone = {"disk_used_pct:" + k.split(":", 1)[1] for k, v in mm.items() if k.startswith("mount_present:") and v == 0}
        envs = {s["environment"], landscape}
        disks = []  # (level rank, used %, path, warning limit, critical limit) per file system, each judged by its own rule
        for k, v in mm.items():
            if k.startswith("disk_used_pct:") and v >= 0 and k not in shared | gone:
                warn, crit = hub.engine.levels_for(k, envs) or (DEFAULT_DISK_LEVELS if k.startswith("disk_used_pct:/opt") else (None, None))
                warn, crit = warn if warn is not None else float("inf"), crit if crit is not None else float("inf")
                disks.append((2 if v >= crit else 1 if v >= warn else 0, v, k.split(":", 1)[1], warn, crit))
        worst = max(disks) if disks else None
        tags = json.loads(s["tags"] or "{}")
        rows.append({
            "name": s["name"], "environment": s["environment"], "host": s["host"], "tags": tags,
            "landscape": landscape, "listed": entry is not None,
            "cluster": entry["cluster"] if entry else (tags.get("cluster") or None),
            "roles": entry["roles"] if entry else [],
            "agent_version": s["agent_version"], "os": s["os"], "state": s["state"], "last_seen": s["last_seen"],
            "silent_s": round(now - s["last_seen"]), "first_seen": s["first_seen"],
            "status": status_of(s, now, al, _down_after(hub), maint),
            "errors_1h": c.get("errors") or 0, "warns_1h": c.get("warns") or 0, "events_1h": c.get("total") or 0,
            "alerts": {sev: sum(1 for a in al if a["severity"] == sev) for sev in ("critical", "warning", "info")},
            "alerts_acked": sum(1 for a in al if a["state"] == "acked"),
            "mounts_missing": sorted(k.split(":", 1)[1] for k, v in mm.items() if k.startswith("mount_present:") and v == 0),
            "disk_max_pct": worst[1] if worst else None, "disk_max_path": worst[2] if worst else None,
            "disk_warn": _finite(worst[3]) if worst else None, "disk_crit": _finite(worst[4]) if worst else None,
            "disks_over": [{"path": d[2], "used_pct": d[1], "limit": d[3], "level": "critical" if d[0] == 2 else "warning"}
                           for d in sorted(disks, reverse=True) if d[0]], "load_per_cpu": mm.get("load_per_cpu"),
            "mem_used_pct": mm.get("mem_used_pct"),
            "probes_failed": sum(1 for k, v in mm.items() if k.startswith("probe_ok:") and v == 0),
            "probes_total": sum(1 for k in mm if k.startswith("probe_ok:")),
            "spool_files": mm.get("agent_spool_files"),
        })
    return rows


def _fill(rows, since, now, bucket):
    by = {int(r["b"]): r for r in rows}
    out, b = [], int(since // bucket) * bucket
    while b <= now:
        r = by.get(b, {})
        out.append({"t": b, "errors": r.get("errors") or 0, "warns": r.get("warns") or 0, "total": r.get("total") or 0})
        b += bucket
    return out


def _environments(hub):
    """Landscapes in server-list order, then any other environment an agent reports."""
    names = [ls["name"] for ls in hub.inventory.refresh().data["landscapes"]]
    return names + sorted({s["environment"] for s in hub.store.servers()} - set(names))


def h_overview(self: Handler, mt, qs):
    hub, now = self.hub, time.time()
    hours = _int(qs, "hours", 6, 1, 72)
    env = qs.get("env") if qs.get("env") not in (None, "", "ALL") else None
    rows = [r for r in _server_rows(hub, now) if env is None or env in (r["environment"], r["landscape"])]
    names = [r["name"] for r in rows]
    bucket = 300 if hours <= 12 else 1800
    since = now - hours * 3600
    status_counts = {}
    for r in rows:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    open_al = [a for a in hub.store.alerts(["open", "acked"], limit=500) if env is None or a["server"] in names or
               (a["server"] == "*FLEET*")]
    self._send(200, {
        "now": now, "hours": hours, "servers": rows, "status_counts": status_counts,
        "alerts_open": {sev: sum(1 for a in open_al if a["severity"] == sev and a["state"] == "open") for sev in ("critical", "warning", "info")},
        "alerts_acked": sum(1 for a in open_al if a["state"] == "acked"),
        "alerts": open_al[:15],
        "trend": _fill(hub.store.trend(since, bucket, servers=names), since, now, bucket), "bucket_s": bucket,
        "top_errors": hub.store.top_errors(since, 8, servers=names),
        "environments": _environments(hub),
        "events_1h": sum(r["events_1h"] for r in rows), "errors_1h": sum(r["errors_1h"] for r in rows),
    })



# -- health check: landscapes -> clusters -> nodes ------------------------------------------
SEVERITY_ORDER = ["DOWN", "CRITICAL", "WARNING", "NODATA", "MAINT", "OK", "RETIRED"]
ATTENTION = ("DOWN", "CRITICAL", "WARNING", "NODATA")
NODE_FIELDS = ("last_seen", "silent_s", "errors_1h", "warns_1h", "alerts", "disk_max_pct", "load_per_cpu", "mem_used_pct",
               "probes_failed", "probes_total", "agent_version", "disk_max_path", "mounts_missing", "disk_warn", "disk_crit",
               "disks_over")


def _worst(statuses, default="OK"):
    statuses = [s for s in statuses if s != "RETIRED"] or list(statuses)
    return min(statuses, key=SEVERITY_ORDER.index) if statuses else default


def _dur(sec):
    sec = int(sec)
    return f"{sec} s" if sec < 120 else f"{sec // 60} min" if sec < 7200 else f"{sec // 3600} h" if sec < 172800 else f"{sec // 86400} days"


def _reasons(r):
    if r is None:
        return ["Listed in the server list but has never reported (agent not installed or not configured?)"]
    out = []
    if r["status"] == "DOWN":
        out.append(f"No heartbeat for {_dur(r['silent_s'])}")
    elif r["status"] == "MAINT":
        out.append("In a maintenance window")
    for sev in ("critical", "warning"):
        n = r["alerts"].get(sev, 0)
        if n:
            out.append(f"{n} {sev} alert{'s' if n > 1 else ''}")
    for p in r["mounts_missing"]:
        out.append(f"Mount point {p} is not mounted")
    if r["probes_failed"]:
        out.append(f"{r['probes_failed']} of {r['probes_total']} probe(s) failing")
    for d in r["disks_over"]:
        out.append(f"Disk {d['path']} {d['used_pct']:.0f}% used (limit {d['limit']:g}%)")
    if r["errors_1h"]:
        out.append(f"{r['errors_1h']} error(s) in the last hour")
    return out


def _disk_levels(hub, path="/", envs=()):
    """Warning/critical percentages the disk rules apply to this path, so shared storage is judged like any other disk."""
    return hub.engine.levels_for("disk_used_pct:" + path, set(envs)) or DEFAULT_DISK_LEVELS


def health_check(hub, now):
    inv = hub.inventory.refresh()
    rows = _server_rows(hub, now)
    warn, crit = _disk_levels(hub)
    by_host = {}
    for r in rows:
        e = inv.lookup(r["name"], r["host"])
        if e:
            by_host.setdefault(e["host"].lower(), []).append(r)
    landscapes, lmap = [], {}

    def node(ls_name, cluster, r, entry=None):
        n = {"landscape": ls_name, "cluster": cluster, "roles": entry["roles"] if entry else r["roles"],
             "host": entry["host"] if entry else (r["host"] or r["name"]), "server": r["name"] if r else None,
             "status": r["status"] if r else "NODATA", "listed": entry is not None, "reasons": _reasons(r)}
        for k in NODE_FIELDS:
            n[k] = r[k] if r else None
        return n

    def landscape(name, code=""):
        if name not in lmap:
            lmap[name] = {"name": name, "code": code, "listed": False, "clusters": {}}
            landscapes.append(lmap[name])
        return lmap[name]

    for ls in inv.data["landscapes"]:
        L = landscape(ls["name"], ls["code"])
        L["listed"] = True
        for e in ls["servers"]:
            for r in by_host.get(e["host"].lower()) or [None]:
                L["clusters"].setdefault(e["cluster"], []).append(node(ls["name"], e["cluster"], r, e))
    listed = {id(r) for rs in by_host.values() for r in rs}
    for r in rows:  # reporting servers that are not in the server list: grouped by the environment their agent reports
        if id(r) in listed or r["status"] == "RETIRED":
            continue
        cl = r["cluster"] or ("Not in server list" if inv.loaded else (r["tags"].get("product") or "Servers"))
        landscape(r["environment"])["clusters"].setdefault(cl, []).append(node(r["environment"], cl, r))
    for L in landscapes:
        clusters = []
        for name, nodes in L["clusters"].items():
            st = [n["status"] for n in nodes]
            clusters.append({"name": name, "status": _worst(st), "nodes": nodes, "total": len(nodes),
                             "up": sum(1 for s in st if s in ("OK", "WARNING", "CRITICAL", "MAINT"))})
        L["clusters"] = clusters
        L["counts"] = {}
        for c in clusters:
            for n in c["nodes"]:
                L["counts"][n["status"]] = L["counts"].get(n["status"], 0) + 1
        L["status"] = _worst([c["status"] for c in clusters])
        L["total"] = sum(c["total"] for c in clusters)

    # shared storage: one row per share, using the fullest value any server in scope reports
    latest = {}
    for m in hub.store.metric_latest():
        if m["name"].startswith(("disk_used_pct:", "disk_free_gb:", "mount_present:")) and now - m["ts"] < 3 * _down_after(hub):
            latest.setdefault(m["name"], []).append(m)
    ls_of = {r["name"]: r["landscape"] for r in rows if r["status"] != "RETIRED"}
    shared = []
    for sh in inv.data["shared_storage"]:
        scope = sh["landscapes"]
        missing = sorted(m["server"] for m in latest.get("mount_present:" + sh["path"], []) if m["value"] == 0 and
                         m["server"] in ls_of and (scope is None or ls_of[m["server"]] in scope))
        vals = [m for m in latest.get("disk_used_pct:" + sh["path"], []) if m["server"] in ls_of and m["value"] >= 0 and
                (scope is None or ls_of[m["server"]] in scope) and m["server"] not in missing]  # stale value of a dropped mount
        free = [m["value"] for m in latest.get("disk_free_gb:" + sh["path"], []) if m["server"] in {v["server"] for v in vals}]
        used = max((v["value"] for v in vals), default=None)
        swarn, scrit = _disk_levels(hub, sh["path"], scope or ())
        status = "NODATA" if used is None else "CRITICAL" if used >= scrit else "WARNING" if used >= swarn else "OK"
        shared.append({"name": sh["name"], "path": sh["path"], "landscapes": scope, "used_pct": used,
                       "free_gb": min(free) if free else None, "servers": len(vals), "status": status, "missing_on": missing,
                       "limit": swarn, "critical": scrit,
                       "spread_pct": round(max(v["value"] for v in vals) - min(v["value"] for v in vals), 1) if vals else None,
                       "last_ts": max((v["ts"] for v in vals), default=None)})

    attention = [n for L in landscapes for c in L["clusters"] for n in c["nodes"] if n["status"] in ATTENTION]
    attention += [{"landscape": ", ".join(s["landscapes"] or ["all"]), "cluster": "Shared storage", "roles": [], "host": s["path"],
                   "server": None, "shared": s["name"], "status": s["status"],
                   "reasons": [f"{s['name']} {s['used_pct']:.1f}% used (seen by {s['servers']} server(s))"]}
                  for s in shared if s["status"] in ("CRITICAL", "WARNING")]
    attention.sort(key=lambda n: (SEVERITY_ORDER.index(n["status"]), n["landscape"], n["cluster"], n["host"]))
    totals = {}
    for L in landscapes:
        for k, v in L["counts"].items():
            totals[k] = totals.get(k, 0) + v
    return {"now": now, "landscapes": landscapes, "attention": attention, "shared_storage": shared, "totals": totals,
            "inventory": {"loaded": inv.loaded, "path": os.path.basename(inv.path or ""), "errors": inv.errors[:20]},
            "thresholds": {"disk_warning": warn, "disk_critical": crit}}


def h_healthcheck(self: Handler, mt, qs):
    self._send(200, health_check(self.hub, time.time()))


def _cell(v):
    """CSV cell that a spreadsheet will not run as a formula."""
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.1f}"
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def h_report_csv(self: Handler, mt, qs):
    now = time.time()
    hc = health_check(self.hub, now)
    problems = qs.get("problems") in ("1", "true", "yes")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["landscape", "cluster", "roles", "host", "server", "status", "reasons", "last_seen_utc", "errors_1h", "warnings_1h",
                "critical_alerts", "warning_alerts", "disk_max_pct", "disk_max_path", "mounts_missing", "load_per_cpu", "mem_used_pct",
                "probes_failed"])
    for L in hc["landscapes"]:
        for c in L["clusters"]:
            for n in c["nodes"]:
                if problems and n["status"] not in ATTENTION:
                    continue
                al = n["alerts"] or {}
                seen = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(n["last_seen"])) if n["last_seen"] else ""
                w.writerow([_cell(x) for x in (L["name"], c["name"], " / ".join(n["roles"]), n["host"], n["server"], n["status"],
                            "; ".join(n["reasons"]), seen, n["errors_1h"], n["warns_1h"], al.get("critical"), al.get("warning"),
                            n["disk_max_pct"], n["disk_max_path"], " ".join(n["mounts_missing"] or []), n["load_per_cpu"],
                            n["mem_used_pct"], n["probes_failed"])])
    for s in hc["shared_storage"]:
        if problems and s["status"] not in ATTENTION:
            continue
        w.writerow([_cell(x) for x in (", ".join(s["landscapes"] or ["all"]), "Shared storage", s["name"], s["path"], "", s["status"],
                    f"seen by {s['servers']} server(s)", "", "", "", "", "", s["used_pct"], s["path"],
                    " ".join(s["missing_on"]), "", "", "")])
    name = time.strftime("wm-health-check-%Y%m%d-%H%M.csv", time.gmtime(now))
    self._send(200, ("﻿" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
               {"Content-Disposition": f'attachment; filename="{name}"'})


SERIES_PREFIX = ("load_per_cpu", "mem_used_pct", "disk_used_pct:", "probe_ms:", "log_age_s:", "agent_spool_files")


def h_server(self: Handler, mt, qs):
    hub, now = self.hub, time.time()
    name = mt.group(1)
    if not hub.store.server(name):
        raise HttpError(404, "unknown server")
    hours = _int(qs, "hours", 6, 1, 72)
    since, bucket = now - hours * 3600, (300 if hours <= 12 else 1800)
    row = next(r for r in _server_rows(hub, now) if r["name"] == name)
    latest = {m["name"]: {"value": m["value"], "ts": m["ts"]} for m in hub.store.metric_latest(name)}
    series = {n: [[p["ts"], p["value"]] for p in hub.store.metric_series(name, n, since, 160)]
              for n in sorted(latest) if n.startswith(SERIES_PREFIX)}
    sources = sorted({n.split(":", 1)[1] for n in latest if n.startswith("log_age_s:")})
    self._send(200, {
        "now": now, "hours": hours, "server": row, "metrics": latest, "series": series, "sources": sources,
        "trend": _fill(hub.store.trend(since, bucket, name), since, now, bucket), "bucket_s": bucket,
        "top_errors": hub.store.top_errors(since, 8, name),
        "alerts": hub.store.alerts(["open", "acked"], 100, name) + hub.store.alerts(["resolved"], 10, name),
        "events": hub.store.search_events({"server": name, "min_level": "WARN", "since": since}, 40),
    })


def h_events(self: Handler, mt, qs):
    f = {k: qs[k] for k in ("server", "min_level", "level", "source", "code", "fp", "since", "until", "q") if qs.get(k)}
    if f.get("since") and not re.fullmatch(r"\d+(\.\d+)?", f["since"]) or f.get("until") and not re.fullmatch(r"\d+(\.\d+)?", f["until"]):
        raise HttpError(400, "since/until must be epoch seconds")
    rows = self.hub.store.search_events(f, _int(qs, "limit", 200, 1, 1000))
    self._send(200, {"events": rows, "count": len(rows)})


def h_alerts(self: Handler, mt, qs):
    states = [s for s in qs.get("state", "open,acked").split(",") if s in ("open", "acked", "resolved")] or ["open", "acked"]
    self._send(200, {"alerts": self.hub.store.alerts(states, _int(qs, "limit", 200, 1, 500), qs.get("server") or None)})


def h_alert_one(self: Handler, mt, qs):
    a = self.hub.store.alert(int(mt.group(1)))
    if not a:
        raise HttpError(404, "no such alert")
    notes = [n for n in self.hub.store.notifications(500) if n["alert_id"] == a["id"]]
    ev = self.hub.store.search_events({"server": a["server"], "min_level": "WARN", "since": a["first_seen"] - 600}, 30) \
        if a["server"] != "*FLEET*" else []
    self._send(200, {"alert": a, "notifications": notes, "events": ev})


def _alert_action(action):
    def fn(self: Handler, mt, qs):
        store, aid, now = self.hub.store, int(mt.group(1)), time.time()
        a = store.alert(aid)
        if not a:
            raise HttpError(404, "no such alert")
        body = self._json_body()
        note = str(body.get("note", "") if isinstance(body, dict) else "")[:500]
        if action == "ack" and a["state"] == "open":
            store.update_alert(aid, state="acked", ack_by=self.actor, ack_at=now, ack_note=note)
        elif action == "unack" and a["state"] == "acked":
            store.update_alert(aid, state="open", ack_by=None, ack_at=None)
        elif action == "resolve" and a["state"] != "resolved":
            store.update_alert(aid, state="resolved", resolved_at=now, resolved_by=self.actor)
        else:
            raise HttpError(409, f"cannot {action} an alert that is {a['state']}")
        store.audit(self.actor, f"alert.{action}", f"#{aid} {a['title'][:100]} {note}")
        self._send(200, {"alert": store.alert(aid)})
    return fn


def h_rules(self: Handler, mt, qs):
    eng = self.hub.engine
    firing = {}
    for a in self.hub.store.open_alerts():
        firing[a["rule_id"]] = firing.get(a["rule_id"], 0) + 1
    rules = [{k: v for k, v in r.items() if not k.startswith("_")} | {"firing": firing.get(r["id"], 0)} for r in eng.rules]
    self._send(200, {"rules": rules, "errors": eng.rule_errors, "last_eval": eng.last_eval, "last_eval_ms": eng.last_eval_ms})


def h_maint_list(self: Handler, mt, qs):
    self._send(200, {"maintenance": self.hub.store.maintenance_list(time.time())})


def h_maint_add(self: Handler, mt, qs):
    b = self._json_body()
    if not isinstance(b, dict):
        raise HttpError(400, "expected a JSON object")
    glob_ = str(b.get("server", "")).strip()
    try:
        minutes = int(b.get("minutes", 60))
    except (TypeError, ValueError):
        raise HttpError(400, "minutes must be an integer")
    if not glob_ or not re.fullmatch(r"[A-Za-z0-9_.\-*?\[\]]{1,100}", glob_) or not 1 <= minutes <= 60 * 24 * 14:
        raise HttpError(400, "server (glob) required; minutes must be 1..20160")
    now = time.time()
    mid = self.hub.store.add_maintenance(glob_, now, now + minutes * 60, str(b.get("reason", ""))[:200], self.actor)
    self.hub.store.audit(self.actor, "maintenance.add", f"{glob_} {minutes}min {b.get('reason', '')}")
    self._send(200, {"id": mid})


def h_maint_del(self: Handler, mt, qs):
    self.hub.store.end_maintenance(int(mt.group(1)), time.time())
    self.hub.store.audit(self.actor, "maintenance.end", mt.group(1))
    self._send(200, {"ok": True})


def h_server_state(state):
    def fn(self: Handler, mt, qs):
        if not self.hub.store.server(mt.group(1)):
            raise HttpError(404, "unknown server")
        self.hub.store.set_server_state(mt.group(1), state)
        self.hub.store.audit(self.actor, f"server.{state}", mt.group(1))
        self._send(200, {"ok": True})
    return fn


def h_notifications(self: Handler, mt, qs):
    self._send(200, {"notifications": self.hub.store.notifications(_int(qs, "limit", 100, 1, 1000))})


def h_status(self: Handler, mt, qs):
    hub = self.hub
    try:
        size = os.path.getsize(hub.cfg["db_path"])
    except OSError:
        size = 0
    self._send(200, {"stats": hub.stats, "db_bytes": size, "notify_queue": hub.notifier.q.qsize(),
                     "dry_run": hub.cfg["notifications"].get("dry_run", False),
                     "rules_loaded": len(hub.engine.rules), "last_eval": hub.engine.last_eval, "now": time.time()})


def h_index(self: Handler, mt, qs):
    p = os.path.join(WEB_DIR, "index.html")
    try:
        with open(p, "rb") as fh:
            self._send(200, fh.read(), "text/html; charset=utf-8")
    except OSError:
        raise HttpError(404, "dashboard files not found")


def h_health(self: Handler, mt, qs):
    self._send(200, {"ok": True})


def h_noicon(self: Handler, mt, qs):
    self._send(204, b"", "image/x-icon")


def _r(pattern):
    return re.compile("^" + pattern + "$")


ROUTES = [
    ("GET", _r("/healthz"), h_health, "agent"),
    ("POST", _r("/api/v1/ingest"), h_ingest, "agent"),
    ("GET", _r("/"), h_index, "ui"),
    ("GET", _r("/favicon.ico"), h_noicon, "ui"),
    ("GET", _r("/api/v1/overview"), h_overview, "ui"),
    ("GET", _r("/api/v1/healthcheck"), h_healthcheck, "ui"),
    ("GET", _r("/api/report.csv"), h_report_csv, "ui"),
    ("GET", _r("/api/v1/report.csv"), h_report_csv, "ui"),
    ("GET", _r("/api/v1/servers/([A-Za-z0-9_.\\-]{1,100})"), h_server, "ui"),
    ("POST", _r("/api/v1/servers/([A-Za-z0-9_.\\-]{1,100})/retire"), h_server_state("retired"), "ui"),
    ("POST", _r("/api/v1/servers/([A-Za-z0-9_.\\-]{1,100})/activate"), h_server_state("active"), "ui"),
    ("GET", _r("/api/v1/events"), h_events, "ui"),
    ("GET", _r("/api/v1/alerts"), h_alerts, "ui"),
    ("GET", _r("/api/v1/alerts/(\\d+)"), h_alert_one, "ui"),
    ("POST", _r("/api/v1/alerts/(\\d+)/ack"), _alert_action("ack"), "ui"),
    ("POST", _r("/api/v1/alerts/(\\d+)/unack"), _alert_action("unack"), "ui"),
    ("POST", _r("/api/v1/alerts/(\\d+)/resolve"), _alert_action("resolve"), "ui"),
    ("GET", _r("/api/v1/rules"), h_rules, "ui"),
    ("GET", _r("/api/v1/maintenance"), h_maint_list, "ui"),
    ("POST", _r("/api/v1/maintenance"), h_maint_add, "ui"),
    ("DELETE", _r("/api/v1/maintenance/(\\d+)"), h_maint_del, "ui"),
    ("GET", _r("/api/v1/notifications"), h_notifications, "ui"),
    ("GET", _r("/api/v1/status"), h_status, "ui"),
]


def serve(cfg):
    errors = cfgmod.validate(cfg)
    if errors:
        for e in errors:
            log.error("config error: %s", e)
        raise SystemExit("collector not started: fix the configuration errors above")
    if cfg["ui_auth"].get("mode", "none") == "none":
        if cfgmod.is_loopback(cfg["listen"]["host"]):
            log.warning("dashboard authentication is OFF (ui_auth.mode=none); acceptable only on this loopback address")
        else:
            log.warning("INSECURE: anonymous dashboard on %s because ui_auth.insecure_allow_anonymous_remote is set",
                        cfg["listen"]["host"])
    hub = Hub(cfg)
    Handler.hub = hub
    hub.start_background()
    ls = cfg["listen"]
    ThreadingHTTPServer.request_queue_size = 256  # the default (5) resets connections when many agents flush at once
    httpd = ThreadingHTTPServer((ls["host"], ls["port"]), Handler)
    httpd.daemon_threads = True
    tls = cfg["tls"]
    scheme = "http"
    if tls.get("cert") and tls.get("key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls["cert"], tls["key"])
        if tls.get("client_ca"):
            ctx.load_verify_locations(tls["client_ca"])
            ctx.verify_mode = ssl.CERT_OPTIONAL
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        log.warning("TLS is not configured - serving plain HTTP. Put a TLS-terminating proxy in front or set tls.cert/tls.key.")
    log.info("collector listening on %s://%s:%s  (db %s)", scheme, ls["host"], ls["port"], cfg["db_path"])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        hub.stop.set()
        hub.engine.stop.set()
        hub.notifier.stop.set()
        httpd.server_close()
        hub.store.close()
