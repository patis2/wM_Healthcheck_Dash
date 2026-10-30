"""Alert engine: evaluates rules on a timer, de-duplicates into alerts, drives notifications.

Alert lifecycle:  open -> (acked) -> resolved.
An alert is identified by (rule_id, dedup_key). While the condition holds the same alert is
updated, never duplicated. It resolves automatically after `resolve_after_s` without the
condition being seen again, which also protects against flapping.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import operator
import os
import re
import threading
import time

from .store import RANK, Store

log = logging.getLogger("hub.alerts")

SEV_RANK = {"info": 0, "warning": 1, "critical": 2}
OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq, "!=": operator.ne,
       "abs>": lambda v, t: abs(v) > t}
FLEET = "*FLEET*"


class _Safe(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def normalise(rule: dict) -> dict:
    r = dict(rule)
    for k in ("id", "name", "type"):
        if k not in r:
            raise ValueError(f"rule is missing '{k}': {rule}")
    r.setdefault("severity", "warning")
    r.setdefault("enabled", True)
    r.setdefault("window_s", 300)
    r.setdefault("group_by", "server")
    r.setdefault("notify", True)
    r.setdefault("notify_resolved", True)
    r.setdefault("resolve_after_s", max(int(r["window_s"]), 120))
    if r["type"] not in ("event_count", "metric_threshold", "heartbeat_missing", "new_error"):
        raise ValueError(f"unknown rule type '{r['type']}'")
    if "levels" in r:
        lv = [(x["severity"], float(x.get("threshold", x.get("value")))) for x in r["levels"]]
    elif r["type"] == "event_count":
        lv = [(r["severity"], float(r.get("threshold", 1)))]
    elif r["type"] == "metric_threshold":
        lv = [(r["severity"], float(r["value"]))]
    else:
        lv = [(r["severity"], 0.0)]
    for s, _ in lv:
        if s not in SEV_RANK:
            raise ValueError(f"rule {r['id']}: unknown severity '{s}'")
    r["_levels"] = sorted(lv, key=lambda x: -SEV_RANK[x[0]])  # most severe first
    if r["type"] == "metric_threshold" and r.get("op", ">") not in OPS:
        raise ValueError(f"rule {r['id']}: unknown op")
    for k in ("code", "message", "exclude_message"):
        if r.get("match", {}).get(k):
            re.compile(r["match"][k])
    return r


class Engine:
    def __init__(self, cfg: dict, store: Store, notifier):
        self.cfg, self.store, self.notifier = cfg, store, notifier
        self.rules: list = []
        self.rule_errors: list = []
        self._mtime = 0.0
        self.stop = threading.Event()
        self.last_eval = 0.0
        self.last_eval_ms = 0
        self._fetched = {}
        self.inventory = None  # hub.inventory.Inventory, set by the Hub; lets shared NAS paths alert once

    # -- rules -----------------------------------------------------------------
    def load_rules(self, force=False):
        path = self.cfg["rules_file"]
        try:
            mt = os.path.getmtime(path)
        except OSError:
            if not self.rules:
                log.error("rules file %s not found", path)
            return
        if not force and mt == self._mtime:
            return
        try:
            with open(path) as fh:
                raw = json.load(fh)
            rules, errors = [], []
            for r in raw["rules"] if isinstance(raw, dict) else raw:
                try:
                    rules.append(normalise(r))
                except (ValueError, KeyError, re.error, TypeError) as exc:
                    errors.append(f"{r.get('id', '?')}: {exc}")
            ids = [r["id"] for r in rules]
            if len(ids) != len(set(ids)):
                errors.append("duplicate rule ids")
            self.rules, self.rule_errors, self._mtime = rules, errors, mt
            log.info("loaded %d rule(s) from %s (%d error(s))", len(rules), path, len(errors))
            for e in errors:
                log.error("rule error: %s", e)
        except (OSError, ValueError) as exc:
            self.rule_errors = [f"cannot parse {path}: {exc}"]
            log.error("cannot load rules: %s (keeping previous set)", exc)

    # -- scope -------------------------------------------------------------------
    def _in_scope(self, rule, servers, now):
        sc = rule.get("scope", {})
        maint = self.store.active_maintenance(now)
        out = []
        for s in servers:
            if s.get("state") == "retired":
                continue
            if not self.env_in_scope(sc, self._envs(s)):
                continue
            if sc.get("server") and not any(fnmatch.fnmatch(s["name"], g) for g in ([sc["server"]] if isinstance(sc["server"], str) else sc["server"])):
                continue
            if sc.get("tags"):
                tags = json.loads(s.get("tags") or "{}")
                if any(tags.get(k) != v for k, v in sc["tags"].items()):
                    continue
            if any(fnmatch.fnmatch(s["name"], m["server_glob"]) for m in maint):
                continue
            out.append(s)
        return out

    def _envs(self, s):
        """The names a server can be scoped by: its reported environment and its landscape in the server list."""
        envs = {s["environment"]}
        if self.inventory is not None:
            e = self.inventory.refresh().lookup(s["name"], s.get("host"))
            if e:
                envs.add(e["landscape"])
        return envs

    @staticmethod
    def env_in_scope(sc, envs):
        if sc.get("environment") and not envs & set(sc["environment"]):
            return False
        if sc.get("not_environment") and envs & set(sc["not_environment"]):
            return False
        return True

    def levels_for(self, metric, envs):
        """(warning, critical) of the first enabled threshold rule that would judge this metric for a server with these
        environment/landscape names, or None. Lets the dashboard use the same per-landscape limits as the alerts."""
        self.load_rules()
        for r in self.rules:
            if (r["enabled"] and r["type"] == "metric_threshold" and fnmatch.fnmatchcase(metric, r["metric"])
                    and not (r.get("exclude_metric") and fnmatch.fnmatchcase(metric, r["exclude_metric"]))
                    and self.env_in_scope(r.get("scope", {}), set(envs))):
                lv = dict(r["_levels"])
                return lv.get("warning", lv.get("critical")), lv.get("critical", float("inf"))
        return None

    def _in_maintenance(self, server, now):
        return any(fnmatch.fnmatch(server, m["server_glob"]) for m in self.store.active_maintenance(now))

    # -- evaluation -----------------------------------------------------------------
    def evaluate(self, now=None):
        now = now or time.time()
        t0 = time.time()
        self.load_rules()
        servers = self.store.servers()
        env_of = {s["name"]: s["environment"] for s in servers}
        active, ok_rules = {}, set()
        self._fetched = {}
        for rule in self.rules:
            if not rule["enabled"]:
                ok_rules.add(rule["id"])  # disabled rules let their alerts age out
                continue
            try:
                scoped = self._in_scope(rule, servers, now)
                fn = {"event_count": self._event_count, "metric_threshold": self._metric, "heartbeat_missing": self._heartbeat,
                      "new_error": self._new_error}[rule["type"]]
                for c in fn(rule, scoped, now):
                    c.setdefault("environment", env_of.get(c["server"], "-"))
                    active[(rule["id"], c["key"])] = (rule, c)
                ok_rules.add(rule["id"])
            except Exception:  # noqa: BLE001 - one broken rule must not stop the others
                log.exception("rule %s failed", rule["id"])
        self._reconcile(active, ok_rules, now)
        self._fetched = {}  # release the row lists
        self.last_eval, self.last_eval_ms = now, int((time.time() - t0) * 1000)

    @staticmethod
    def _pick(levels, value, op="ge"):
        """Most severe level whose threshold the value reaches. op: callable(value, threshold)."""
        for sev, thr in levels:
            if op(value, thr):
                return sev
        return None

    @staticmethod
    def _title(_rule, default, **kw):
        return (_rule.get("title") or default).format_map(_Safe(**kw))

    # event_count --------------------------------------------------------------------
    def _event_count(self, rule, servers, now):
        m = rule.get("match", {})
        names = [s["name"] for s in servers]
        min_rank = RANK[m["min_level"].upper()] if m.get("min_level") else 0
        ck = (rule["window_s"], min_rank, tuple(names))  # rules with the same window and scope share one fetch per evaluation
        rows = self._fetched.get(ck)
        if rows is None:
            rows = self._fetched[ck] = self.store.fetch_events(now - rule["window_s"], min_rank, names)
        code_rx = re.compile(m["code"]) if m.get("code") else None
        msg_rx = re.compile(m["message"]) if m.get("message") else None
        ex_rx = re.compile(m["exclude_message"]) if m.get("exclude_message") else None
        sources = set(m.get("sources") or [])
        exact = {x.upper() for x in m.get("levels", [])}
        groups = {}
        for r in rows:
            if sources and r["source"] not in sources:
                continue
            if exact and r["level"] not in exact:
                continue
            if code_rx and not code_rx.search(r["code"] or ""):
                continue
            text = r["msg"] or ""
            if msg_rx and not msg_rx.search(text):
                continue
            if ex_rx and ex_rx.search(text):
                continue
            gb = rule["group_by"]
            key = FLEET if gb == "fleet" else (f"{r['server']}|{r['fp']}" if gb == "server+fp" else r["server"])
            g = groups.setdefault(key, {"n": 0, "server": FLEET if gb == "fleet" else r["server"], "sample": text, "servers": set()})
            g["n"] += 1
            g["servers"].add(r["server"])
        out = []
        for key, g in groups.items():
            sev = self._pick(rule["_levels"], g["n"], operator.ge)
            if not sev:
                continue
            wm = max(1, rule["window_s"] // 60)
            title = self._title(rule, "{rule}: {count} matching event(s) in {window_min} min", rule=rule["name"], count=g["n"],
                                window_min=wm, server=g["server"], sample=g["sample"][:100])
            detail = f"{g['n']} matching event(s) in the last {wm} min" + (f" across {len(g['servers'])} servers" if len(g["servers"]) > 1 else "")
            detail += f".\nMost recent message: {g['sample'][:500]}"
            out.append({"key": key, "server": g["server"], "severity": sev, "title": title, "detail": detail, "value": g["n"]})
        return out

    # metric_threshold -----------------------------------------------------------------
    def _metric(self, rule, servers, now):
        names = {s["name"] for s in servers}
        op = OPS[rule.get("op", ">")]
        hb = self.cfg["expected_heartbeat_s"]
        stale = max(3 * hb, 120)
        levels = rule["_levels"]
        inv = self.inventory.refresh() if self.inventory is not None else None
        landscape = {}
        if inv is not None and inv.data["shared_storage"]:
            for s in servers:
                e = inv.lookup(s["name"], s.get("host"))
                landscape[s["name"]] = e["landscape"] if e else s["environment"]
        shared = {}  # share name -> (fullest row, share): a NAS mounted on many servers alerts once, not once per server
        out = []
        for row in self.store.metric_latest():
            if row["server"] not in names or not fnmatch.fnmatch(row["name"], rule["metric"]):
                continue
            if rule.get("exclude_metric") and fnmatch.fnmatch(row["name"], rule["exclude_metric"]):
                continue
            if now - row["ts"] > stale or row["value"] < rule.get("ignore_below", float("-inf")):
                continue
            if landscape and row["name"].startswith("disk_used_pct:"):
                share = next((sh for sh in inv.shared_for(landscape[row["server"]]) if "disk_used_pct:" + sh["path"] == row["name"]), None)
                if share:
                    if share["name"] not in shared or row["value"] > shared[share["name"]][0]["value"]:
                        shared[share["name"]] = (row, share)
                    continue
            c = self._metric_row(rule, row, op, levels, hb, now)
            if c:
                out.append(c)
        for name, (row, share) in shared.items():
            c = self._metric_row(rule, row, op, levels, hb, now, label=name, where="shared storage")
            if c:
                c.update(key=f"shared|{name}", server=FLEET, environment=",".join(share["landscapes"] or ["*"])[:30])
                out.append(c)
        return out

    def _metric_row(self, rule, row, op, levels, hb, now, label=None, where=None):
        sev = self._pick(levels, row["value"], op)
        if not sev:
            return None
        if rule.get("for_s"):
            grace = 2 * hb
            series = self.store.q("SELECT ts, value FROM metrics WHERE server=? AND name=? AND ts>=? ORDER BY ts",
                                  (row["server"], row["name"], now - rule["for_s"] - grace))
            if len(series) < 2 or series[0]["ts"] > now - rule["for_s"] + grace:
                return None
            sevs = [self._pick(levels, p["value"], op) for p in series]
            if any(s is None for s in sevs):
                return None
            sev = min(sevs, key=lambda s: SEV_RANK[s])
        thr = dict(levels)[sev]
        v = row["value"]
        vtxt = f"{v:g}"
        title = self._title(rule, "{metric} is {value} (threshold {op} {threshold:g})", metric=row["name"], value=vtxt,
                            threshold=thr, op=rule.get("op", ">"), server=where or row["server"], rule=rule["name"],
                            label=label or (row["name"].split(":", 1)[1] if ":" in row["name"] else row["name"]))
        detail = f"{row['name']} = {vtxt} on {row['server']}; rule fires when value {rule.get('op', '>')} {thr:g}" + \
                 (f" for {rule['for_s']}s" if rule.get("for_s") else "")
        if where:
            detail += f".\n{label} is shared storage: it is alerted once, using the fullest value any server reports."
        return {"key": f"{row['server']}|{row['name']}", "server": row["server"], "severity": sev, "title": title,
                "detail": detail, "value": v}

    # heartbeat_missing ----------------------------------------------------------------
    def _heartbeat(self, rule, servers, now):
        limit = rule.get("max_silence_s", 4 * self.cfg["expected_heartbeat_s"])
        out = []
        for s in servers:
            silent = now - s["last_seen"]
            if silent > limit:
                mins = silent / 60
                out.append({"key": s["name"], "server": s["name"], "severity": rule["_levels"][0][0],
                            "title": self._title(rule, "No heartbeat from {server} for {minutes:.0f} min", server=s["name"], minutes=mins),
                            "detail": f"The agent on {s['name']} has not reported for {mins:.1f} min (limit {limit}s). "
                                      f"Host, agent or network may be down. Last contact: "
                                      f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(s['last_seen']))}.",
                            "value": round(silent)})
        return out

    # new_error ----------------------------------------------------------------------------
    def _new_error(self, rule, servers, now):
        names = {s["name"] for s in servers}
        min_rank = RANK[rule.get("match", {}).get("min_level", "ERROR").upper()]
        out = []
        for r in self.store.new_fingerprints(now - rule["window_s"], min_rank):
            if r["server"] in names:
                out.append({"key": r["fp"], "server": r["server"], "severity": rule["_levels"][0][0],
                            "title": self._title(rule, "New error pattern {code}: {sample}", code=r["code"] or "-", sample=r["sample"][:90],
                                                 server=r["server"]),
                            "detail": f"First time this error pattern was seen anywhere in the fleet (fingerprint {r['fp']}).\n{r['sample']}",
                            "value": 1})
        return out

    # -- lifecycle -----------------------------------------------------------------------------
    def _reconcile(self, active, ok_rules, now):
        existing = {(a["rule_id"], a["dedup_key"]): a for a in self.store.open_alerts()}
        rules = {r["id"]: r for r in self.rules}
        for k, (rule, c) in active.items():
            a = existing.get(k)
            if a is None:
                aid = self.store.create_alert({"rule_id": rule["id"], "rule_name": rule["name"], "server": c["server"],
                                               "environment": c["environment"], "dedup_key": c["key"], "severity": c["severity"],
                                               "title": c["title"], "detail": c["detail"], "value": c["value"], "now": now,
                                               "runbook": rule.get("runbook")})
                self._notify(rule, "firing", aid, now)
                continue
            upgraded = SEV_RANK[c["severity"]] > SEV_RANK[a["severity"]]
            self.store.touch_alert(a["id"], now, severity=c["severity"], title=c["title"], detail=c["detail"], value=c["value"])
            if upgraded and a["state"] == "open":
                self._notify(rule, "severity_change", a["id"], now)
            elif a["state"] == "open":
                if rule.get("repeat_s") and now - a["last_notified"] >= rule["repeat_s"]:
                    self._notify(rule, "reminder", a["id"], now)
                elif (rule.get("escalate_after_s") and not a["escalated"] and now - a["first_seen"] >= rule["escalate_after_s"]):
                    self.store.update_alert(a["id"], escalated=1)
                    self._notify(rule, "escalation", a["id"], now)
        for k, a in existing.items():
            rule = rules.get(a["rule_id"])
            if k in active or (rule is not None and a["rule_id"] not in ok_rules):
                continue
            quiet = now - a["last_seen"]
            limit = rule["resolve_after_s"] if rule else 300
            if quiet >= limit:
                self.store.update_alert(a["id"], state="resolved", resolved_at=now, resolved_by="auto")
                self.store.audit("engine", "alert.auto_resolved", f"#{a['id']} {a['title'][:120]}")
                if rule and rule["notify_resolved"] and not self._in_maintenance(a["server"], now) and a["notify_count"]:
                    self._notify(rule, "resolved", a["id"], now)

    def _notify(self, rule, kind, aid, now):
        if not rule["notify"]:
            return
        a = self.store.alert(aid)
        self.store.update_alert(aid, last_notified=now, notify_count=a["notify_count"] + 1)
        a["notify_count"] += 1
        self.notifier.submit(kind, a)

    # -- thread --------------------------------------------------------------------------------------
    def run(self):
        self.load_rules(force=True)
        while not self.stop.is_set():
            try:
                self.evaluate()
            except Exception:  # noqa: BLE001
                log.exception("evaluation failed")
            self.stop.wait(self.cfg["eval_interval_s"])

    def start(self):
        threading.Thread(target=self.run, daemon=True, name="alert-engine").start()
