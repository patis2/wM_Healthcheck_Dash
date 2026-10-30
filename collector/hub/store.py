"""SQLite store for the Observability Hub.

SQLite (WAL mode) keeps the prototype dependency-free. Everything that touches SQL lives in
this file, so moving to PostgreSQL/TimescaleDB or OpenSearch means re-implementing one class.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone

RANK = {"TRACE": 0, "DEBUG": 1, "UNKNOWN": 2, "INFO": 2, "WARN": 3, "ERROR": 4, "FATAL": 5}

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers(
  name TEXT PRIMARY KEY, environment TEXT, host TEXT, tags TEXT, agent_version TEXT, os TEXT,
  first_seen REAL, last_seen REAL, state TEXT DEFAULT 'active', maintenance_until REAL DEFAULT 0, maint_reason TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, eid TEXT UNIQUE, server TEXT NOT NULL, ts REAL NOT NULL, recv REAL NOT NULL,
  source TEXT, level TEXT, rank INTEGER, code TEXT, tid TEXT, msg TEXT, detail TEXT, fp TEXT);
CREATE INDEX IF NOT EXISTS ev_server_ts ON events(server, ts);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_rank_cover ON events(rank, ts, fp, server);
CREATE INDEX IF NOT EXISTS ev_fp ON events(fp, ts);
CREATE TABLE IF NOT EXISTS event_rollup(
  server TEXT NOT NULL, bucket INTEGER NOT NULL, errors INTEGER NOT NULL, warns INTEGER NOT NULL, total INTEGER NOT NULL, last_ts REAL NOT NULL,
  PRIMARY KEY(server, bucket)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fp_seen(fp TEXT PRIMARY KEY, first_seen REAL, server TEXT, code TEXT, sample TEXT, rank INTEGER);
CREATE TABLE IF NOT EXISTS metrics(server TEXT, ts REAL, name TEXT, value REAL);
CREATE INDEX IF NOT EXISTS m_idx ON metrics(server, name, ts);
CREATE TABLE IF NOT EXISTS metric_latest(server TEXT, name TEXT, ts REAL, value REAL, PRIMARY KEY(server, name));
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, rule_name TEXT, server TEXT, environment TEXT, dedup_key TEXT,
  severity TEXT, state TEXT, title TEXT, detail TEXT, value REAL, first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 1,
  ack_by TEXT, ack_at REAL, ack_note TEXT, resolved_at REAL, resolved_by TEXT, last_notified REAL DEFAULT 0, notify_count INTEGER DEFAULT 0,
  escalated INTEGER DEFAULT 0, runbook TEXT);
CREATE INDEX IF NOT EXISTS al_state ON alerts(state, last_seen);
CREATE INDEX IF NOT EXISTS al_key ON alerts(rule_id, dedup_key, state);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, alert_id INTEGER, kind TEXT, channel TEXT, target TEXT, status TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS maintenance(
  id INTEGER PRIMARY KEY AUTOINCREMENT, server_glob TEXT, start_ts REAL, end_ts REAL, reason TEXT, created_by TEXT);
"""

_NORM = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\"[^\"]{0,200}\"|'[^']{0,200}'"), "<str>"),
    (re.compile(r"\d+"), "<n>"),
]


def fingerprint(code: str, msg: str) -> str:
    """Group 'the same error' regardless of ids, counts, addresses and quoted values."""
    t = (msg or "")[:300]
    for rx, rep in _NORM:
        t = rx.sub(rep, t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    return hashlib.sha1(f"{code}|{t}".encode()).hexdigest()[:12]


def iso_to_epoch(s, default):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except (ValueError, TypeError):
        return default


class Store:
    def __init__(self, path, synchronous="NORMAL"):
        self.path = path
        if str(synchronous).upper() not in ("NORMAL", "FULL"):
            raise ValueError("sqlite synchronous must be NORMAL or FULL")
        self.synchronous = str(synchronous).upper()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self._all = []  # every per-thread connection, so close() can release the file (Windows keeps it locked)
        self.wlock = threading.RLock()
        with self.wlock:
            c = self.conn()
            c.executescript(SCHEMA)
            c.execute("DROP INDEX IF EXISTS ev_rank_ts")  # superseded by ev_rank_cover
            if not c.execute("SELECT 1 FROM event_rollup LIMIT 1").fetchone():  # database created before rollups existed
                c.execute("INSERT INTO event_rollup SELECT server, CAST(ts/60 AS INTEGER)*60, SUM(rank>=4), SUM(rank=3), COUNT(*), MAX(ts) "
                          "FROM events GROUP BY 1, 2")
            c.commit()

    # -- connections --------------------------------------------------------
    def conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            # one connection per thread; check_same_thread=False only so close() may release it from another thread
            c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(f"PRAGMA synchronous={self.synchronous}")  # validated to NORMAL|FULL in __init__
            c.execute("PRAGMA busy_timeout=30000")
            self._local.c = c
            with self.wlock:
                self._all.append(c)
        return c

    def close(self):
        """Close every connection this store opened (all threads)."""
        with self.wlock:
            for c in self._all:
                try:
                    c.close()
                except sqlite3.Error:
                    pass
            self._all = []
        self._local = threading.local()

    def q(self, sql, args=()):
        return [dict(r) for r in self.conn().execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.conn().execute(sql, args).fetchone()
        return dict(r) if r else None

    # -- ingest ---------------------------------------------------------------
    def ingest(self, server, events, heartbeat, recv):
        """Store one agent payload. Returns (accepted, duplicates)."""
        name = server["name"]
        accepted = dup = 0
        with self.wlock:
            c = self.conn()
            c.execute("BEGIN")
            try:
                row = c.execute("SELECT name FROM servers WHERE name=?", (name,)).fetchone()
                tags = json.dumps(server.get("tags") or {}, sort_keys=True)
                if row is None:
                    c.execute("INSERT INTO servers(name, environment, host, tags, agent_version, os, first_seen, last_seen) "
                              "VALUES(?,?,?,?,?,?,?,?)",
                              (name, server.get("environment", "UNSET"), server.get("host"), tags,
                               server.get("agent_version"), server.get("os"), recv, recv))
                else:
                    c.execute("UPDATE servers SET environment=?, host=?, tags=?, agent_version=?, os=?, last_seen=? WHERE name=?",
                              (server.get("environment", "UNSET"), server.get("host"), tags,
                               server.get("agent_version"), server.get("os"), recv, name))
                agg = {}  # (minute bucket) -> [errors, warns, total, newest event time], for accepted events only
                for e in events:
                    rank = RANK.get(e["level"], 2)
                    fp = fingerprint(e["code"], e["msg"])
                    cur = c.execute(
                        "INSERT OR IGNORE INTO events(eid, server, ts, recv, source, level, rank, code, tid, msg, detail, fp) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (e["eid"], name, e["ts_epoch"], recv, e["source"], e["level"], rank, e["code"], e["tid"],
                         e["msg"], e["detail"], fp))
                    if cur.rowcount:
                        accepted += 1
                        a = agg.setdefault(int(e["ts_epoch"] // 60) * 60, [0, 0, 0, 0.0])
                        a[0] += rank >= 4
                        a[1] += rank == 3
                        a[2] += 1
                        a[3] = max(a[3], e["ts_epoch"])
                        if rank >= 3:
                            # first_seen = the EVENT time, kept as the minimum, so replayed history never looks "new"
                            c.execute(
                                "INSERT INTO fp_seen(fp, first_seen, server, code, sample, rank) VALUES(?,?,?,?,?,?) "
                                "ON CONFLICT(fp) DO UPDATE SET "
                                "server=CASE WHEN excluded.first_seen<first_seen THEN excluded.server ELSE server END, "
                                "sample=CASE WHEN excluded.first_seen<first_seen THEN excluded.sample ELSE sample END, "
                                "first_seen=MIN(first_seen, excluded.first_seen)",
                                (fp, e["ts_epoch"], name, e["code"], e["msg"][:300], rank))
                    else:
                        dup += 1
                if agg:
                    c.executemany(
                        "INSERT INTO event_rollup(server, bucket, errors, warns, total, last_ts) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(server, bucket) DO UPDATE SET errors=errors+excluded.errors, warns=warns+excluded.warns, "
                        "total=total+excluded.total, last_ts=MAX(last_ts, excluded.last_ts)",
                        [(name, b, v[0], v[1], v[2], v[3]) for b, v in agg.items()])
                if heartbeat:
                    hts = heartbeat["ts_epoch"]
                    for mname, val in heartbeat["metrics"].items():
                        c.execute("INSERT INTO metrics(server, ts, name, value) VALUES(?,?,?,?)", (name, recv, mname, val))
                        c.execute("INSERT OR REPLACE INTO metric_latest(server, name, ts, value) VALUES(?,?,?,?)", (name, mname, recv, val))
                    skew = round(recv - hts, 1)
                    c.execute("INSERT INTO metrics(server, ts, name, value) VALUES(?,?,?,?)", (name, recv, "agent_clock_skew_s", skew))
                    c.execute("INSERT OR REPLACE INTO metric_latest(server, name, ts, value) VALUES(?,?,?,?)",
                              (name, "agent_clock_skew_s", recv, skew))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return accepted, dup

    # -- servers ---------------------------------------------------------------
    def servers(self):
        return self.q("SELECT * FROM servers ORDER BY environment, name")

    def server(self, name):
        return self.one("SELECT * FROM servers WHERE name=?", (name,))

    def active_maintenance(self, now):
        return self.q("SELECT * FROM maintenance WHERE start_ts<=? AND end_ts>?", (now, now))

    # -- events ------------------------------------------------------------------
    def fetch_events(self, since, min_rank=0, servers=None, limit=200000):
        sql = "SELECT id, server, ts, source, level, rank, code, msg, fp FROM events WHERE ts>=? AND rank>=?"
        args = [since, min_rank]
        if servers is not None:
            if not servers:
                return []
            sql += " AND server IN (%s)" % ",".join("?" * len(servers))
            args += list(servers)
        sql += " ORDER BY ts DESC LIMIT ?"
        return self.q(sql, args + [limit])

    def search_events(self, f, limit=200):
        sql, args = ["SELECT id, server, ts, source, level, code, tid, msg, detail, fp FROM events WHERE 1=1"], []
        if f.get("server"):
            sql.append("AND server=?"); args.append(f["server"])
        if f.get("min_level"):
            sql.append("AND rank>=?"); args.append(RANK.get(f["min_level"].upper(), 0))
        if f.get("level"):
            sql.append("AND level=?"); args.append(f["level"].upper())
        if f.get("source"):
            sql.append("AND source=?"); args.append(f["source"])
        if f.get("code"):
            sql.append("AND code LIKE ?"); args.append(f["code"] + "%")
        if f.get("fp"):
            sql.append("AND fp=?"); args.append(f["fp"])
        if f.get("since"):
            sql.append("AND ts>=?"); args.append(float(f["since"]))
        if f.get("until"):
            sql.append("AND ts<=?"); args.append(float(f["until"]))
        if f.get("q"):
            like = "%" + f["q"].replace("%", r"\%").replace("_", r"\_") + "%"
            sql.append("AND (msg LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); args += [like, like]
        sql.append("ORDER BY ts DESC, id DESC LIMIT ?")
        return self.q(" ".join(sql), args + [min(int(limit), 1000)])

    @staticmethod
    def _in(servers):
        """SQL fragment + args restricting to a list of server names (None = no restriction)."""
        if servers is None:
            return "", []
        if not servers:
            return " AND 0", []
        return " AND server IN (%s)" % ",".join("?" * len(servers)), list(servers)

    def trend(self, since, bucket_s, server=None, servers=None):
        frag, fa = self._in(servers)
        # Reads the per-minute rollup, so the cost depends on the time range, not on how many events were logged.
        # bucket_s must be a multiple of 60; the first bucket may include up to a minute before `since`.
        sql = ("SELECT CAST(bucket/? AS INTEGER)*? AS b, SUM(errors) AS errors, SUM(warns) AS warns, SUM(total) AS total "
               "FROM event_rollup WHERE bucket>=?" + frag)
        args = [bucket_s, bucket_s, int(since // 60) * 60] + fa
        if server:
            sql += " AND server=?"; args.append(server)
        sql += " GROUP BY b ORDER BY b"
        return self.q(sql, args)

    def top_errors(self, since, limit=8, server=None, servers=None):
        frag, fa = self._in(servers)
        # Step 1 is answered from the covering index ev_rank_cover alone (rank IN (...) lets SQLite seek by time per level).
        sql = ("SELECT fp, COUNT(*) AS n, COUNT(DISTINCT server) AS servers, MAX(ts) AS last_ts "
               "FROM events WHERE rank IN (4, 5) AND ts>=?" + frag)
        args = [since] + fa
        if server:
            sql += " AND server=?"; args.append(server)
        sql += " GROUP BY fp ORDER BY n DESC LIMIT ?"
        rows = self.q(sql, args + [limit])
        for r in rows:  # Step 2: one sample message per pattern, only for the few that are shown
            s = self.one("SELECT code, msg FROM events WHERE fp=? AND ts>=? ORDER BY ts DESC LIMIT 1", (r["fp"], since))
            r["code"], r["sample"] = (s["code"], s["msg"]) if s else ("", "")
        return rows

    def event_counts(self, since):
        return self.q("SELECT server, SUM(errors) AS errors, SUM(warns) AS warns, SUM(total) AS total, MAX(last_ts) AS last_ts "
                      "FROM event_rollup WHERE bucket>=? GROUP BY server", (int(since // 60) * 60,))

    def new_fingerprints(self, since, min_rank):
        return self.q("SELECT fp, first_seen, server, code, sample, rank FROM fp_seen WHERE first_seen>=? AND rank>=?", (since, min_rank))

    # -- metrics ------------------------------------------------------------------
    def metric_latest(self, server=None):
        if server:
            return self.q("SELECT * FROM metric_latest WHERE server=?", (server,))
        return self.q("SELECT * FROM metric_latest")

    def metric_series(self, server, name, since, max_points=240):
        rows = self.q("SELECT ts, value FROM metrics WHERE server=? AND name=? AND ts>=? ORDER BY ts", (server, name, since))
        if len(rows) > max_points:
            step = len(rows) / max_points
            rows = [rows[int(i * step)] for i in range(max_points)]
        return rows

    def metric_names(self, server):
        return [r["name"] for r in self.q("SELECT DISTINCT name FROM metric_latest WHERE server=? ORDER BY name", (server,))]

    # -- alerts -------------------------------------------------------------------
    def open_alerts(self):
        return self.q("SELECT * FROM alerts WHERE state IN ('open','acked')")

    def alerts(self, states, limit=200, server=None):
        sql, args = "SELECT * FROM alerts WHERE state IN (%s)" % ",".join("?" * len(states)), list(states)
        if server:
            sql += " AND server=?"; args.append(server)
        sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_seen DESC LIMIT ?"
        return self.q(sql, args + [limit])

    def alert(self, aid):
        return self.one("SELECT * FROM alerts WHERE id=?", (aid,))

    def create_alert(self, a):
        with self.wlock:
            c = self.conn()
            cur = c.execute(
                "INSERT INTO alerts(rule_id, rule_name, server, environment, dedup_key, severity, state, title, detail, value, "
                "first_seen, last_seen, runbook) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["rule_id"], a["rule_name"], a["server"], a["environment"], a["dedup_key"], a["severity"], "open",
                 a["title"], a["detail"], a["value"], a["now"], a["now"], a.get("runbook")))
            c.commit()
            return cur.lastrowid

    def update_alert(self, aid, **fields):
        if not fields:
            return
        with self.wlock:
            c = self.conn()
            c.execute("UPDATE alerts SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?", list(fields.values()) + [aid])
            c.commit()

    def touch_alert(self, aid, now, **fields):
        fields["last_seen"] = now
        with self.wlock:
            c = self.conn()
            sets = ", ".join(f"{k}=?" for k in fields) + ", hits=hits+1"
            c.execute(f"UPDATE alerts SET {sets} WHERE id=?", list(fields.values()) + [aid])
            c.commit()

    # -- notifications / audit / maintenance --------------------------------------------
    def record_notification(self, alert_id, kind, channel, target, status, detail=""):
        with self.wlock:
            c = self.conn()
            c.execute("INSERT INTO notifications(ts, alert_id, kind, channel, target, status, detail) VALUES(?,?,?,?,?,?,?)",
                      (time.time(), alert_id, kind, channel, target, status, detail[:500]))
            c.commit()

    def notifications(self, limit=100):
        return self.q("SELECT n.*, a.title, a.server FROM notifications n LEFT JOIN alerts a ON a.id=n.alert_id "
                      "ORDER BY n.id DESC LIMIT ?", (limit,))

    def audit(self, actor, action, detail=""):
        with self.wlock:
            c = self.conn()
            c.execute("INSERT INTO audit(ts, actor, action, detail) VALUES(?,?,?,?)", (time.time(), actor, action, detail[:500]))
            c.commit()

    def add_maintenance(self, server_glob, start, end, reason, who):
        with self.wlock:
            c = self.conn()
            cur = c.execute("INSERT INTO maintenance(server_glob, start_ts, end_ts, reason, created_by) VALUES(?,?,?,?,?)",
                            (server_glob, start, end, reason, who))
            c.commit()
            return cur.lastrowid

    def end_maintenance(self, mid, now):
        with self.wlock:
            c = self.conn()
            c.execute("UPDATE maintenance SET end_ts=? WHERE id=? AND end_ts>?", (now, mid, now))
            c.commit()

    def maintenance_list(self, now):
        return self.q("SELECT * FROM maintenance WHERE end_ts>? ORDER BY start_ts", (now - 86400,))

    def set_server_state(self, name, state):
        with self.wlock:
            c = self.conn()
            c.execute("UPDATE servers SET state=? WHERE name=?", (state, name))
            c.commit()

    # -- housekeeping ----------------------------------------------------------------------
    def purge(self, ev_days, metric_days, alert_days):
        now = time.time()
        with self.wlock:
            c = self.conn()
            n1 = c.execute("DELETE FROM events WHERE ts<?", (now - ev_days * 86400,)).rowcount
            c.execute("DELETE FROM event_rollup WHERE bucket<?", (now - ev_days * 86400,))
            n2 = c.execute("DELETE FROM metrics WHERE ts<?", (now - metric_days * 86400,)).rowcount
            n3 = c.execute("DELETE FROM alerts WHERE state='resolved' AND resolved_at<?", (now - alert_days * 86400,)).rowcount
            c.execute("DELETE FROM notifications WHERE ts<?", (now - alert_days * 86400,))
            # Forget an error pattern only once none of its events remain. Purging on first_seen alone would
            # re-announce a pattern that has been recurring for months as "new" every retention period.
            c.execute("DELETE FROM fp_seen WHERE first_seen<? AND NOT EXISTS (SELECT 1 FROM events e WHERE e.fp=fp_seen.fp)",
                      (now - ev_days * 86400,))
            c.commit()
        return n1, n2, n3
