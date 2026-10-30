#!/usr/bin/env python3
"""
wm_agent.py - webMethods Observability Hub : local log agent
==============================================================
Runs on each webMethods host. Tails log files, turns them into structured
events, redacts secrets, stores batches in a local spool and pushes them
OUTBOUND over HTTPS to the central collector. Python 3.8+, standard library only.

    python wm_agent.py --config agent.json            # run as a daemon
    python wm_agent.py --config agent.json --check    # validate config, files, collector link
    python wm_agent.py --config agent.json --dry-run --once --from-beginning
                                                      # show how YOUR logs parse; sends nothing

Delivery guarantee: at-least-once. A batch is written to the spool BEFORE the
read offsets move forward, and every event carries a deterministic id, so the
collector can drop duplicates after a crash or a retry.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import gzip
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import random
import re
import shutil
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

AGENT_VERSION = "0.1.0"
log = logging.getLogger("wm_agent")

# --------------------------------------------------------------------------
# Parsing profiles
# --------------------------------------------------------------------------
LEVEL_LETTER = {"C": "FATAL", "E": "ERROR", "W": "WARN", "I": "INFO", "D": "DEBUG", "T": "TRACE"}
LEVEL_WORD = {
    "FATAL": "FATAL", "SEVERE": "ERROR", "ERROR": "ERROR", "ERR": "ERROR",
    "WARN": "WARN", "WARNING": "WARN", "ADVICE": "WARN",
    "STATUS": "INFO", "INFO": "INFO", "NOTICE": "INFO",
    "DEBUG": "DEBUG", "TRACE": "TRACE",
}
_TS = r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?"
_TZ = r"GMT[+-]\d{1,2}(?::?\d{2})?|UTC[+-]\d{1,2}(?::?\d{2})?|UTC|GMT|Z|[+-]\d{2}:?\d{2}|[A-Z]{2,5}"

# Built-in profiles. Each needs a 'start' regex with named groups ts, msg and
# (level | level_word). Optional groups: tz, code, tid. 'cont' marks lines that
# belong to the previous event even though they match 'start' (stack frames).
# Override or add profiles in the config file under "profiles".
BUILTIN_PROFILES = {
    # 2022-01-07 15:58:49 GMT-03:00 [ISS.0053.0002C] (tid=793) Access denied ...
    "is_server": {
        "start": rf"^(?P<ts>{_TS})\s*(?P<tz>{_TZ})?\s+\[(?P<code>[A-Z]{{2,6}}\.\d{{1,5}}\.\d{{1,6}})\.?(?P<level>[CEWIDT])\]\s*(?:\(tid=(?P<tid>\d+)\)\s*)?(?P<msg>.*)$",
    },
    # STATUS | wrapper  | 2022/01/07 15:58:49 | --> Wrapper Started as Service
    "wrapper": {
        "start": rf"^(?P<level_word>[A-Za-z]+)\s*\|\s*(?P<src>[\w .-]+?)\s*\|\s*(?P<ts>{_TS})\s*\|\s?(?P<msg>.*)$",
        "cont": r"^\s+at\s|^Caused by:|^\s+\.\.\.\s\d+\smore|^\s*$",
    },
    # 2026-10-29 10:00:01,123 ERROR [thread] message   (log4j / OSGi style)
    "generic": {
        "start": rf"^\[?(?P<ts>{_TS})(?:\s*(?P<tz>{_TZ}))?\]?\s+\[?(?P<level_word>TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|SEVERE|FATAL)\]?\s*[-:]?\s*(?P<msg>.*)$",
    },
}

TZ_ABBREV = {  # abbreviations are ambiguous; override with "tz_abbrev" in the config
    "UTC": 0, "GMT": 0, "Z": 0, "BST": 60, "CET": 60, "CEST": 120, "EET": 120, "EEST": 180,
    "IST": 330, "JST": 540, "SGT": 480, "AEST": 600, "AEDT": 660,
    "EST": -300, "EDT": -240, "CST": -360, "CDT": -300, "MST": -420, "MDT": -360, "PST": -480, "PDT": -420,
}


def tz_offset_minutes(tz, abbrev):
    if not tz:
        return None
    t = tz.strip()
    m = re.fullmatch(r"(?:GMT|UTC)?([+-])(\d{1,2})(?::?(\d{2}))?", t)
    if m:
        mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
        return -mins if m.group(1) == "-" else mins
    return abbrev.get(t.upper())


def parse_ts(ts, tz, abbrev, default_offset_min):
    """Return an ISO-8601 UTC string. default_offset_min=None means 'host local time'."""
    s = ts.replace("T", " ").replace("/", "-").replace(",", ".")
    m = re.match(r"(.*\.)(\d{1,6})$", s)
    if m:
        s = m.group(1) + m.group(2).ljust(6, "0")
    naive = datetime.fromisoformat(s)
    off = tz_offset_minutes(tz, abbrev)
    if off is None:
        off = default_offset_min
    if off is None:
        aware = naive.astimezone()  # naive -> host local zone (handles DST)
    else:
        aware = naive.replace(tzinfo=timezone(timedelta(minutes=off)))
    return aware.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{aware.microsecond // 1000:03d}Z"


class Profile:
    def __init__(self, name, spec):
        self.name = name
        self.start = re.compile(spec["start"])
        self.cont = re.compile(spec["cont"]) if spec.get("cont") else None


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------
DEFAULT_REDACT = [
    # key=value / key: value / "key":"value"; the value may carry a scheme word ("Authorization: Bearer xyz")
    (r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b([\"']?\s*[=:]\s*)((?:Bearer|Basic|Digest|Negotiate|NTLM)\s+\S+|\"[^\"]*\"|'[^']*'|\S+)", r"\1\2***"),
    (r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer ***"),
    (r"(?i)\bBasic\s+[A-Za-z0-9+/]{12,}=*", "Basic ***"),
]
_PAN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class Redactor:
    def __init__(self, extra, defaults=True, mask_cards=True):
        pairs = (DEFAULT_REDACT if defaults else []) + [(e["pattern"], e.get("replace", "***")) for e in extra]
        self.rules = [(re.compile(p), r) for p, r in pairs]
        self.mask_cards = mask_cards

    def __call__(self, text):
        if not text:
            return text
        for rx, rep in self.rules:
            text = rx.sub(rep, text)
        if self.mask_cards:
            def card(m):
                raw = m.group(0)
                body = raw.rstrip(" -")  # the regex may swallow a trailing separator; give it back
                digits = re.sub(r"\D", "", body)
                if 13 <= len(digits) <= 19 and _luhn(digits):
                    return "[REDACTED-CARD]" + raw[len(body):]
                return raw
            text = _PAN.sub(card, text)
        return text


# --------------------------------------------------------------------------
# Tailing
# --------------------------------------------------------------------------
class Tailer:
    """Reads one logical log (a path or a glob), survives rotation, joins multi-line events."""

    def __init__(self, cfg, profile, agent_id, redact, defaults, state):
        self.name = cfg["name"]
        self.pattern = cfg["path"]
        self.is_glob = any(c in self.pattern for c in "*?[")
        self.profile = profile
        self.agent_id = agent_id
        self.redact = redact
        self.first_run = cfg.get("first_run", defaults["first_run"])
        self.max_msg = defaults["max_message_chars"]
        self.max_detail_lines = defaults["max_detail_lines"]
        self.max_detail_chars = defaults["max_detail_chars"]
        self.read_chunk = defaults["read_chunk_bytes"]
        self.ml_timeout = defaults["multiline_timeout_s"]
        self.abbrev = {**TZ_ABBREV, **{k.upper(): v for k, v in defaults.get("tz_abbrev", {}).items()}}
        d = cfg.get("default_tz", defaults.get("default_tz", "local"))
        self.default_off = None if d == "local" else tz_offset_minutes(d, self.abbrev)
        self.min_level = cfg.get("min_level")
        self.state = state  # {ino, commit, sig_len, sig} or None
        self.pos = state["commit"] if state else None
        self.pending = None
        self.pending_touch = 0.0
        self.last_size = 0
        self.last_mtime = None
        self.exists = False
        self.current_path = None

    # -- file discovery ---------------------------------------------------
    def _current(self):
        if self.is_glob:
            matches = [p for p in glob.glob(self.pattern) if os.path.isfile(p)]
            return max(matches, key=lambda p: os.stat(p).st_mtime) if matches else None
        return self.pattern if os.path.isfile(self.pattern) else None

    def _siblings(self):
        found = set(glob.glob(self.pattern if self.is_glob else self.pattern + "*"))
        found.update(glob.glob(self.pattern + "*"))
        return [p for p in found if os.path.isfile(p)]

    @staticmethod
    def _sig(path, n):
        with open(path, "rb") as fh:
            return zlib.crc32(fh.read(n))

    def _same_file(self, path, st):
        s = self.state
        if s["ino"] != st.st_ino:
            return False
        if st.st_size < s["sig_len"]:
            return False
        return self._sig(path, s["sig_len"]) == s["sig"] if s["sig_len"] else True

    def _find_old(self, current):
        """Locate the previous incarnation of the log: renamed (same inode) or copy-truncated (same head bytes)."""
        s = self.state
        for p in self._siblings():
            if p == current:
                continue
            try:
                st = os.stat(p)
                if st.st_size < s["commit"]:
                    continue
                if st.st_ino == s["ino"]:
                    return p
                if s["sig_len"] and st.st_size >= s["sig_len"] and self._sig(p, s["sig_len"]) == s["sig"]:
                    return p
            except OSError:
                continue
        return None

    def _refresh_sig(self, path, size):
        n = min(size, 128)
        if self.state and (self.state["sig_len"] < n):
            self.state["sig_len"] = n
            self.state["sig"] = self._sig(path, n)

    # -- main entry --------------------------------------------------------
    def poll(self, final=False):
        out = []
        path = self._current()
        if not path:
            self.exists = False
            if final:
                out += self._flush(force=True)
            return out
        st = os.stat(path)
        self.exists, self.last_size, self.last_mtime, self.current_path = True, st.st_size, st.st_mtime, path

        if self.state is None:
            start = st.st_size if self.first_run == "end" else 0
            n = min(st.st_size, 128)
            self.state = {"ino": st.st_ino, "commit": start, "sig_len": n, "sig": self._sig(path, n) if n else 0}
            self.pos = start
        elif not self._same_file(path, st):
            # rotated / replaced / truncated-and-regrown: drain the old file if we can still find it
            old = self._find_old(path)
            if old:
                log.info("%s: rotation detected, draining %s", self.name, old)
                out += self._read(old, self.pos, final=True)
            out += self._flush(force=True)
            n = min(st.st_size, 128)
            self.state = {"ino": st.st_ino, "commit": 0, "sig_len": n, "sig": self._sig(path, n) if n else 0}
            self.pos = 0
        elif st.st_size < self.pos:
            log.info("%s: file truncated in place, restarting at 0", self.name)
            out += self._flush(force=True)
            self.pos = 0
            self.state["commit"] = 0

        out += self._read(path, self.pos, final=final)
        self._refresh_sig(path, st.st_size)
        out += self._flush(force=final)
        self._update_commit()
        return out

    def _update_commit(self):
        if self.state is not None:
            self.state["commit"] = self.pending["start_off"] if self.pending else self.pos

    # -- reading -----------------------------------------------------------
    def _read(self, path, off, final):
        out = []
        with open(path, "rb") as fh:
            fh.seek(off)
            chunk = fh.read(self.read_chunk)
        if not chunk:
            return out
        cut = chunk.rfind(b"\n") + 1
        if cut == 0:
            if not final and len(chunk) < 1_000_000:
                return out  # partial line, wait for the newline
            cut = len(chunk)
        data = chunk[:cut]
        pieces = data.split(b"\n")
        if data.endswith(b"\n"):
            pieces.pop()  # split leaves one empty tail piece after the final newline
        line_off = off
        for raw in pieces:
            consumed = len(raw) + 1
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            ev = self._feed(raw.decode("utf-8", errors="replace"), line_off)
            if ev:
                out.append(ev)
            line_off += consumed
        self.pos = off + len(data)
        return out

    def _feed(self, line, line_off):
        if line == "" and self.pending is None:
            return None
        m = self.profile.start.match(line)
        if m and self.profile.cont and self.profile.cont.match(m.groupdict().get("msg") or line):
            m = None
        emitted = None
        if m:
            emitted = self._take_pending()
            self.pending = self._new_event(m, line_off)
            self.pending_touch = time.time()
        elif self.pending is not None:
            p = self.pending
            if len(p["_detail"]) < self.max_detail_lines:
                p["_detail"].append(line)
            else:
                p["_cut"] = True
            self.pending_touch = time.time()
        else:
            # text before the first recognised line (banner, partial stack): keep as unparsed
            self.pending = {"start_off": line_off, "ts": None, "level": "UNKNOWN", "code": "", "tid": "",
                            "msg": line[: self.max_msg], "_detail": [], "_cut": False}
            self.pending_touch = time.time()
        return emitted

    def _new_event(self, m, line_off):
        g = m.groupdict()
        level = LEVEL_LETTER.get(g.get("level") or "") or LEVEL_WORD.get((g.get("level_word") or "").upper(), "INFO")
        try:
            ts = parse_ts(g["ts"], g.get("tz"), self.abbrev, self.default_off)
        except ValueError:
            ts = None
        return {"start_off": line_off, "ts": ts, "level": level, "code": g.get("code") or "",
                "tid": g.get("tid") or "", "msg": (g.get("msg") or "")[: self.max_msg],
                "_detail": [], "_cut": False}

    def _take_pending(self):
        p, self.pending = self.pending, None
        if p is None:
            return None
        if p["ts"] is None:
            p["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
        detail = "\n".join(p["_detail"])[: self.max_detail_chars]
        if p["_cut"]:
            detail += "\n... [truncated by agent]"
        ev = {
            "eid": hashlib.sha1(f"{self.agent_id}|{self.name}|{self.state['ino']}|{p['start_off']}".encode()).hexdigest()[:24],
            "ts": p["ts"], "source": self.name, "level": p["level"], "code": p["code"], "tid": p["tid"],
            "msg": self.redact(p["msg"]), "detail": self.redact(detail),
        }
        if self.min_level and RANK.get(ev["level"], 2) < RANK.get(self.min_level, 0):
            return None
        return ev

    def _flush(self, force=False):
        if self.pending is None:
            return []
        if not force and time.time() - self.pending_touch < self.ml_timeout:
            return []
        ev = self._take_pending()
        return [ev] if ev else []


RANK = {"TRACE": 0, "DEBUG": 1, "UNKNOWN": 2, "INFO": 2, "WARN": 3, "ERROR": 4, "FATAL": 5}

# --------------------------------------------------------------------------
# Host metrics and probes
# --------------------------------------------------------------------------

# Kernel and in-memory file systems: never "disk" space worth alerting on.
PSEUDO_FS = {"tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs",
             "securityfs", "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "rpc_pipefs",
             "overlay", "squashfs", "nsfs", "ramfs", "efivarfs", "selinuxfs"}
DISK_TIMEOUT_S = 5.0
_disk_inflight = {}  # path -> thread still blocked in statvfs (a hung NFS mount); not retried until it returns


def read_mounts(mounts_file="/proc/mounts"):
    """Mount points of real file systems (pseudo file systems such as tmpfs left out), or None without a mount table."""
    try:
        with open(mounts_file) as fh:
            out = []
            for ln in fh:
                f = ln.split()
                if len(f) >= 3 and f[2] not in PSEUDO_FS:
                    out.append(re.sub(r"\\([0-7]{3})", lambda x: chr(int(x.group(1), 8)), f[1]))  # \040 = space
            return out
    except OSError:
        return None


def _is_glob(p):
    return any(ch in p for ch in "*?[")


def disk_targets(disk_paths, disk_mounts, mounts_file="/proc/mounts", mounted=False):
    """Paths to measure: the explicit disk_paths, plus every mounted file system whose mount point matches a
    disk_mounts pattern (for example "/opt*", "/var*", "/wMNfs"). Pseudo file systems such as tmpfs are skipped,
    and a listed mount point that is not mounted is not measured (that would report the parent disk).
    Without a mount table (Windows, macOS) patterns without wildcards are measured as plain paths."""
    out = list(disk_paths)
    if disk_mounts:
        if mounted is False:
            mounted = read_mounts(mounts_file)
        for pat in disk_mounts:
            if mounted is None:
                if not _is_glob(pat):
                    out.append(pat)
                continue
            out += [mp for mp in mounted if fnmatch.fnmatchcase(mp, pat)]
    return list(dict.fromkeys(out))


def mount_presence(disk_mounts, mounted, seen):
    """mount_present:<path> = 1 / 0 for each monitored mount point.
    A plain entry (/wMNfs) is checked directly; a pattern (/opt*) reports 0 when nothing matches it; and a mount
    point that matched earlier in this agent's life but has gone (an NFS share dropped) reports 0. `seen` is updated."""
    m = {}
    if not disk_mounts:
        return m
    for pat in disk_mounts:
        if _is_glob(pat):
            if mounted is None:
                continue
            hits = [mp for mp in mounted if fnmatch.fnmatchcase(mp, pat)]
            seen.update(hits)
            m.update({f"mount_present:{mp}": 1 for mp in hits})
            if not hits:
                m[f"mount_present:{pat}"] = 0
        else:
            ok = pat in mounted if mounted is not None else os.path.ismount(pat)
            m[f"mount_present:{pat}"] = 1 if ok else 0
            if ok:
                seen.add(pat)
    if mounted is not None:
        for mp in seen:
            if mp not in mounted:
                m[f"mount_present:{mp}"] = 0
    return m


def _disk_usage(path, timeout=DISK_TIMEOUT_S):
    """shutil.disk_usage that cannot hang the agent on an unresponsive NFS share."""
    if path in _disk_inflight:
        if _disk_inflight[path].is_alive():
            raise OSError(f"{path}: previous check still blocked")
        del _disk_inflight[path]
    box = {}

    def run():
        try:
            box["du"] = shutil.disk_usage(path)
        except OSError as exc:
            box["err"] = exc
    t = threading.Thread(target=run, daemon=True, name=f"disk {path}")
    t.start()
    t.join(timeout)
    if t.is_alive():
        _disk_inflight[path] = t
        raise OSError(f"{path}: no answer within {timeout:g} s (hung network mount?)")
    if "err" in box:
        raise box["err"]
    return box["du"]


def host_metrics(disk_paths):
    m = {}
    try:
        load1 = os.getloadavg()[0]
        m["load_per_cpu"] = round(load1 / (os.cpu_count() or 1), 3)
    except (AttributeError, OSError):
        pass
    try:
        with open("/proc/meminfo") as fh:
            info = {ln.split(":")[0]: int(ln.split()[1]) for ln in fh if ":" in ln}
        if info.get("MemTotal"):
            m["mem_used_pct"] = round(100.0 * (1 - info.get("MemAvailable", info.get("MemFree", 0)) / info["MemTotal"]), 1)
    except (OSError, ValueError, KeyError):
        pass
    if os.name == "nt" and "mem_used_pct" not in m:
        m.update(_windows_memory())  # Windows has no load average, so load_per_cpu is not reported there
    for p in disk_paths:
        try:
            du = _disk_usage(p)
            m[f"disk_used_pct:{p}"] = round(100.0 * du.used / du.total, 1)
            m[f"disk_free_gb:{p}"] = round(du.free / 1e9, 2)
        except OSError:
            m[f"disk_used_pct:{p}"] = -1
    return m


def _windows_memory():
    """Physical memory in use via GlobalMemoryStatusEx (standard-library ctypes, no extra packages)."""
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)) and st.ullTotalPhys:
            return {"mem_used_pct": round(100.0 * (1 - st.ullAvailPhys / st.ullTotalPhys), 1)}
    except (AttributeError, OSError, ImportError):
        pass
    return {}


def read_extra_metrics(path):
    """Plug-in point: any other script (JMX poller, IS stats service export...) can drop a flat
    {"metric_name": number} JSON file; it is merged into every heartbeat while it stays fresh (< 5 min)."""
    if not path:
        return {}
    try:
        if time.time() - os.path.getmtime(path) > 300:
            return {}
        with open(path) as fh:
            raw = json.load(fh)
        return {str(k): float(v) for k, v in raw.items() if isinstance(v, (int, float))}
    except (OSError, ValueError):
        return {}


def run_probe(p, ssl_ctx):
    name, t0, ok = p["name"], time.time(), 0
    timeout = p.get("timeout_s", 5)
    try:
        if p.get("tcp"):
            host, port = p["tcp"].rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=timeout):
                ok = 1
        else:
            req = urllib.request.Request(p["url"])
            user = p.get("user") or os.environ.get(p.get("user_env", ""), "")
            pwd = p.get("password") or os.environ.get(p.get("password_env", ""), "")
            if user:
                import base64
                req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode())
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as r:
                body = r.read(65536).decode("utf-8", "replace") if p.get("expect_text") else ""
                ok = int(r.status == p.get("expect_status", 200) and (not p.get("expect_text") or p["expect_text"] in body))
    except Exception as exc:  # noqa: BLE001 - a failed probe is data, not an error
        log.debug("probe %s failed: %s", name, exc)
    return {f"probe_ok:{name}": ok, f"probe_ms:{name}": round((time.time() - t0) * 1000)}


# --------------------------------------------------------------------------
# Spool + transport
# --------------------------------------------------------------------------
class Spool:
    def __init__(self, directory, max_mb):
        self.dir = directory
        self.max_bytes = max_mb * 1024 * 1024
        self.dropped = 0
        os.makedirs(self.dir, exist_ok=True)
        os.makedirs(os.path.join(self.dir, "rejected"), exist_ok=True)
        self.seq = int(time.time() * 1000)
        self.lock = threading.Lock()

    def files(self):
        return sorted(f for f in os.listdir(self.dir) if f.endswith(".json.gz"))

    def put(self, batch):
        with self.lock:
            self.seq += 1
            name = f"{self.seq:016d}_n{len(batch['events'])}.json.gz"
            tmp = os.path.join(self.dir, name + ".tmp")
            with open(tmp, "wb") as fh:
                fh.write(gzip.compress(json.dumps(batch, separators=(",", ":")).encode()))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, os.path.join(self.dir, name))
            self._enforce_cap()

    def _enforce_cap(self):
        fl = self.files()
        sizes = {f: os.path.getsize(os.path.join(self.dir, f)) for f in fl}
        total = sum(sizes.values())
        while total > self.max_bytes and len(fl) > 1:
            victim = fl.pop(0)
            m = re.search(r"_n(\d+)\.", victim)
            self.dropped += int(m.group(1)) if m else 0
            total -= sizes[victim]
            os.remove(os.path.join(self.dir, victim))
            log.warning("spool over cap, dropped %s", victim)

    def stats(self):
        fl = self.files()
        try:
            rejected = sum(1 for f in os.listdir(os.path.join(self.dir, "rejected")) if f.endswith(".json.gz"))
        except OSError:
            rejected = 0
        return {"files": len(fl), "bytes": sum(os.path.getsize(os.path.join(self.dir, f)) for f in fl),
                "dropped_events": self.dropped, "rejected_batches": rejected}


class Transport:
    def __init__(self, cfg, token):
        self.url = cfg["collector_url"].rstrip("/") + "/api/v1/ingest"
        self.token = token
        self.agent_id = cfg["agent_id"]
        self.ctx = None
        if self.url.startswith("https"):
            if cfg.get("verify_tls", True):
                self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file"))
            else:
                log.warning("verify_tls is OFF - do not use outside a lab")
                self.ctx = ssl._create_unverified_context()  # noqa: SLF001
            if cfg.get("client_cert"):
                self.ctx.load_cert_chain(cfg["client_cert"], cfg.get("client_key"))
        handlers = [urllib.request.HTTPSHandler(context=self.ctx)] if self.ctx else []
        if cfg.get("proxy"):
            handlers.append(urllib.request.ProxyHandler({"http": cfg["proxy"], "https": cfg["proxy"]}))
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout = cfg.get("http_timeout_s", 20)

    def post(self, gz_bytes):
        """Return (status, retry_after_s, body). status 0 = network error."""
        req = urllib.request.Request(self.url, data=gz_bytes, method="POST", headers={
            "Content-Type": "application/json", "Content-Encoding": "gzip",
            "Authorization": f"Bearer {self.token}", "X-Agent-Id": self.agent_id,
            "X-Agent-Version": AGENT_VERSION, "User-Agent": f"wm-agent/{AGENT_VERSION}"})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, 0, r.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            ra = e.headers.get("Retry-After")
            try:
                body = e.read(512).decode("utf-8", "replace")
            finally:
                e.close()
            return e.code, int(ra) if ra and ra.isdigit() else 0, body
        except Exception as e:  # noqa: BLE001
            return 0, 0, str(e)


# --------------------------------------------------------------------------
# Agent
# --------------------------------------------------------------------------
DEFAULTS = {
    "poll_interval_s": 1.0, "flush_interval_s": 5.0, "heartbeat_interval_s": 30.0,
    "batch_max_events": 500, "spool_dir": "./spool", "spool_max_mb": 200, "state_file": "./agent_state.json",
    "first_run": "end", "max_message_chars": 4000, "max_detail_lines": 80, "max_detail_chars": 12000,
    "read_chunk_bytes": 8 * 1024 * 1024, "multiline_timeout_s": 3.0, "default_tz": "local",
    "redact_defaults": True, "mask_card_numbers": True, "redact": [], "disk_paths": [], "disk_mounts": [], "probes": [],
    "tags": {}, "environment": "UNSET", "profiles": {}, "tz_abbrev": {},
}


def load_config(path):
    with open(path) as fh:
        cfg = json.load(fh)
    for k, v in DEFAULTS.items():
        cfg.setdefault(k, v)
    cfg.setdefault("server_name", socket.gethostname())
    cfg.setdefault("agent_id", cfg["server_name"])
    for key in ("collector_url", "sources"):
        if key not in cfg:
            raise SystemExit(f"config error: '{key}' is required")
    names = [s["name"] for s in cfg["sources"]]
    if len(names) != len(set(names)):
        raise SystemExit("config error: source names must be unique")
    return cfg


class Agent:
    def __init__(self, cfg, token, dry_run=False, from_beginning=False):
        self.cfg, self.dry_run = cfg, dry_run
        if from_beginning:
            cfg["first_run"] = "beginning"
        self.stop = threading.Event()
        self.seen_mounts = set()  # monitored mount points seen so far; one that disappears is reported as missing
        self.profiles = {k: Profile(k, v) for k, v in {**BUILTIN_PROFILES, **cfg["profiles"]}.items()}
        self.redact = Redactor(cfg["redact"], cfg["redact_defaults"], cfg["mask_card_numbers"])
        self.state = {} if dry_run else self._load_state()
        self.tailers = []
        for s in cfg["sources"]:
            prof = self.profiles.get(s.get("profile", "generic"))
            if prof is None:
                raise SystemExit(f"config error: unknown profile '{s.get('profile')}' for source {s['name']}")
            self.tailers.append(Tailer(s, prof, cfg["agent_id"], self.redact, cfg, self.state.get(s["name"])))
        self.spool = None if dry_run else Spool(cfg["spool_dir"], cfg["spool_max_mb"])
        self.transport = None if dry_run else Transport(cfg, token)
        self.buffer = []
        self.sent_total = 0
        self.last_send_ok = 0.0
        self.last_flush = time.time()
        self.started = time.time()
        self.probe_ctx = ssl.create_default_context() if any(str(p.get("url", "")).startswith("https") for p in cfg["probes"]) else None

    # -- state -------------------------------------------------------------
    def _load_state(self):
        try:
            with open(self.cfg["state_file"]) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        """Persist read offsets. Only call when every event read so far is already in the spool."""
        if self.dry_run:
            return
        snap = json.dumps({t.name: t.state for t in self.tailers if t.state is not None}, sort_keys=True)
        if snap == getattr(self, "_last_snap", None):
            return
        tmp = self.cfg["state_file"] + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(snap)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.cfg["state_file"])
        self._last_snap = snap

    # -- identity ------------------------------------------------------------
    def server_info(self):
        c = self.cfg
        return {"name": c["server_name"], "environment": c["environment"], "host": socket.getfqdn(),
                "tags": c["tags"], "agent_version": AGENT_VERSION,
                "os": f"{platform.system()} {platform.release()}", "python": platform.python_version()}

    # -- loop ---------------------------------------------------------------
    def collect_once(self, final=False):
        events = []
        for t in self.tailers:
            try:
                events += t.poll(final=final)
            except OSError as exc:
                log.warning("%s: read error: %s", t.name, exc)
        return events

    def spool_buffer(self, force=False):
        max_n = self.cfg["batch_max_events"]
        due = force or len(self.buffer) >= max_n or (self.buffer and time.time() - self.last_flush >= self.cfg["flush_interval_s"])
        if not due and self.buffer:
            return
        while self.buffer:
            chunk, self.buffer = self.buffer[:max_n], self.buffer[max_n:]
            batch = {"agent_id": self.cfg["agent_id"], "server": self.server_info(),
                     "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "events": chunk}
            if self.dry_run:
                for e in chunk:
                    print(json.dumps(e, ensure_ascii=False))
            else:
                try:
                    self.spool.put(batch)
                except OSError as exc:
                    log.error("cannot write spool (%s) - keeping events in memory", exc)
                    self.buffer = chunk + self.buffer
                    return
        self.last_flush = time.time()

    def run(self):
        threading.Thread(target=self._sender_loop, daemon=True, name="sender").start()
        log.info("agent %s started, %d source(s), collector %s", self.cfg["agent_id"], len(self.tailers), self.cfg["collector_url"])
        while not self.stop.is_set():
            self.buffer += self.collect_once()
            self.spool_buffer()
            if not self.buffer:  # offsets may only advance once their events are durable in the spool
                self._save_state()
            self.stop.wait(self.cfg["poll_interval_s"])
        # graceful shutdown: flush multi-line leftovers, spool, persist offsets
        self.buffer += self.collect_once(final=True)
        self.spool_buffer(force=True)
        self._save_state()
        self._flush_spool_on_exit(self.cfg.get("shutdown_flush_s", 10))
        log.info("agent stopped (%d batch(es) left in the spool for the next start)", len(self.spool.files()))

    def _flush_spool_on_exit(self, seconds):
        """Best-effort synchronous delivery so a planned restart leaves nothing behind."""
        deadline = time.time() + seconds
        for name in self.spool.files():
            if time.time() > deadline:
                return
            path = os.path.join(self.spool.dir, name)
            try:
                with open(path, "rb") as fh:
                    status, _, _ = self.transport.post(fh.read())
            except OSError:
                continue
            if status not in (200, 202):
                return
            self._discard(path)

    # -- metrics + heartbeat ---------------------------------------------------
    def metrics(self):
        c = self.cfg
        mounted = read_mounts() if c["disk_mounts"] else None
        m = host_metrics(disk_targets(c["disk_paths"], c["disk_mounts"], mounted=mounted))
        m.update(mount_presence(c["disk_mounts"], mounted, self.seen_mounts))
        now = time.time()
        for t in self.tailers:
            m[f"log_missing:{t.name}"] = 0 if t.exists else 1
            if t.exists:
                m[f"log_age_s:{t.name}"] = round(now - t.last_mtime)
                m[f"log_size_bytes:{t.name}"] = t.last_size
        for p in c["probes"]:
            m.update(run_probe(p, self.probe_ctx))
        m.update(read_extra_metrics(c.get("extra_metrics_file")))
        if self.spool:
            s = self.spool.stats()
            m.update({"agent_spool_files": s["files"], "agent_spool_bytes": s["bytes"], "agent_events_dropped": s["dropped_events"],
                      "agent_batches_rejected": s["rejected_batches"]})
        m["agent_uptime_s"] = round(now - self.started)
        m["agent_last_send_age_s"] = round(now - self.last_send_ok) if self.last_send_ok else -1
        return m

    def heartbeat(self):
        hb = {"agent_id": self.cfg["agent_id"], "server": self.server_info(), "events": [],
              "heartbeat": {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "metrics": self.metrics()}}
        if self.dry_run:
            return hb
        status, _, body = self.transport.post(gzip.compress(json.dumps(hb).encode()))
        if status in (200, 202):
            self.last_send_ok = time.time()
        else:
            log.warning("heartbeat failed: %s %s", status, body[:120])
        return hb

    @staticmethod
    def _discard(path):
        try:
            os.remove(path)
        except FileNotFoundError:  # spool cap may have evicted it while it was in flight
            pass

    def _sender_loop(self):
        backoff, next_hb = 1.0, 0.0
        while not self.stop.is_set():
            if time.time() >= next_hb:
                self.heartbeat()
                next_hb = time.time() + self.cfg["heartbeat_interval_s"]
            files = self.spool.files()
            if not files:
                self.stop.wait(0.5)
                continue
            path = os.path.join(self.spool.dir, files[0])
            with open(path, "rb") as fh:
                payload = fh.read()
            status, retry_after, body = self.transport.post(payload)
            if status in (200, 202):
                self._discard(path)
                self.last_send_ok = time.time()
                self.sent_total += int(re.search(r"_n(\d+)\.", files[0]).group(1))
                backoff = 1.0
            elif status in (400, 413, 415, 422):
                log.error("collector rejected %s (%s %s) - quarantined", files[0], status, body[:120])
                try:
                    os.replace(path, os.path.join(self.spool.dir, "rejected", files[0]))
                except OSError:
                    pass
            else:
                wait = max(retry_after, backoff) * random.uniform(0.8, 1.2)
                if status in (401, 403):
                    log.error("collector refused credentials (%s) - check agent token; retrying in %.0fs", status, wait)
                else:
                    log.warning("send failed (%s %s); %d batch(es) spooled; retry in %.0fs", status, body[:80], len(files), wait)
                backoff = min(backoff * 2, 300.0)
                self.stop.wait(wait)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def check(cfg, token):
    ok = True
    print(f"agent_id={cfg['agent_id']} server_name={cfg['server_name']} env={cfg['environment']}")
    for s in cfg["sources"]:
        t = Tailer(s, Profile("p", {"start": "x^"}), "x", lambda x: x, cfg, None)
        cur = t._current()
        print(f"  source {s['name']:<18} profile={s.get('profile', 'generic'):<8} ->", cur or "NOT FOUND")
        ok &= bool(cur)
    mounted = read_mounts() if cfg["disk_mounts"] else None
    for k, v in mount_presence(cfg["disk_mounts"], mounted, set()).items():
        if not v:
            print(f"  mount  {k.split(':', 1)[1]:<34} NOT MOUNTED")
    for p in disk_targets(cfg["disk_paths"], cfg["disk_mounts"], mounted=mounted):
        try:
            du = _disk_usage(p)
            print(f"  disk   {p:<34} {100.0 * du.used / du.total:5.1f}% used")
        except OSError as exc:
            print(f"  disk   {p:<34} NOT READABLE ({exc})")
    for d in [cfg["spool_dir"], os.path.dirname(os.path.abspath(cfg["state_file"]))]:
        os.makedirs(d, exist_ok=True)
        print(f"  writable: {d}", os.access(d, os.W_OK))
    tr = Transport(cfg, token)
    hb = {"agent_id": cfg["agent_id"], "server": {"name": cfg["server_name"], "environment": cfg["environment"],
          "tags": cfg["tags"], "agent_version": AGENT_VERSION}, "events": [], "heartbeat": {"metrics": {"check": 1}}}
    status, _, body = tr.post(gzip.compress(json.dumps(hb).encode()))
    print(f"  collector {cfg['collector_url']} -> HTTP {status} {body[:100]}")
    return ok and status in (200, 202)


def main(argv=None):
    if sys.version_info < (3, 8):
        raise SystemExit("wm_agent.py needs Python 3.8 or later")
    ap = argparse.ArgumentParser(description="webMethods Observability Hub agent")
    ap.add_argument("--config", required=True)
    ap.add_argument("--check", action="store_true", help="validate config, files and collector connectivity")
    ap.add_argument("--dry-run", action="store_true", help="print parsed events, send and save nothing")
    ap.add_argument("--once", action="store_true", help="one pass (then try to deliver the spool) and exit")
    ap.add_argument("--from-beginning", action="store_true", help="ignore first_run and read files from the start")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)

    cfg = load_config(a.config)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if cfg.get("log_file"):
        fh = logging.handlers.RotatingFileHandler(cfg["log_file"], maxBytes=5_000_000, backupCount=3)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logging.getLogger().addHandler(fh)
    token = os.environ.get("WM_AGENT_TOKEN") or cfg.get("agent_token", "")
    if not token and not a.dry_run:
        raise SystemExit("no agent token: set WM_AGENT_TOKEN or agent_token in the config")
    if a.check:
        return 0 if check(cfg, token) else 2

    agent = Agent(cfg, token, dry_run=a.dry_run, from_beginning=a.from_beginning)
    if a.once:
        agent.buffer += agent.collect_once(final=True)
        agent.spool_buffer(force=True)
        agent._save_state()
        if a.dry_run:
            print(json.dumps(agent.heartbeat()["heartbeat"]["metrics"]), file=sys.stderr)
            return 0
        deadline = time.time() + 60
        threading.Thread(target=agent._sender_loop, daemon=True).start()
        while agent.spool.files() and time.time() < deadline:
            time.sleep(0.3)
        agent.stop.set()
        return 0 if not agent.spool.files() else 3

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: agent.stop.set())
    agent.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
