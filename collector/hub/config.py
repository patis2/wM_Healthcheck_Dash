"""Configuration loading and credential helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets

DEFAULTS = {
    "listen": {"host": "127.0.0.1", "port": 8080},  # loopback unless the config says otherwise
    "tls": {"cert": None, "key": None, "client_ca": None},
    "db_path": "./data/hub.db",
    "rules_file": "./rules.json",
    "inventory_file": None,  # landscapes, clusters and shared NAS paths (see import_inventory.py); optional
    "retention_days": {"events": 14, "metrics": 7, "alerts": 180},
    "expected_heartbeat_s": 30,
    "eval_interval_s": 15,
    "max_body_mb": 8,
    "max_events_per_batch": 5000,
    "max_message_chars": 4000,
    "max_detail_chars": 12000,
    "sqlite_synchronous": "NORMAL",  # FULL also survives host power loss, at an unmeasured ingest cost
    "agents": [],
    # mode none = anonymous dashboard; only allowed on a loopback listen address unless the
    # insecure flag below is set on purpose (never do that outside an isolated lab)
    "ui_auth": {"mode": "none", "users": {}, "insecure_allow_anonymous_remote": False},
    "notifications": {"dry_run": True, "outbox_dir": "./data/outbox", "dashboard_url": "http://localhost:8080",
                      "email": {"enabled": False}, "teams": {"enabled": False}, "routes": []},
}


def _merge(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load(path):
    with open(path) as fh:
        cfg = _merge(DEFAULTS, json.load(fh))
    base = os.path.dirname(os.path.abspath(path))
    for key in ("db_path", "rules_file", "inventory_file"):
        if cfg.get(key) and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.normpath(os.path.join(base, cfg[key]))
    ob = cfg["notifications"].get("outbox_dir")
    if ob and not os.path.isabs(ob):
        cfg["notifications"]["outbox_dir"] = os.path.normpath(os.path.join(base, ob))
    return cfg


def is_loopback(host: str) -> bool:
    if str(host).lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate(cfg: dict) -> list:
    """Return a list of configuration errors that must stop the collector from starting."""
    errs = []
    names = set()
    for i, a in enumerate(cfg.get("agents") or []):
        label = a.get("name") or f"agents[{i}]"
        if not a.get("name"):
            errs.append(f"{label}: 'name' is required")
        elif a["name"] in names:
            errs.append(f"{label}: duplicate agent name")
        names.add(a.get("name"))
        if not re.fullmatch(r"[0-9a-f]{64}", str(a.get("token_sha256", ""))):
            errs.append(f"{label}: token_sha256 must be the 64-character hex hash printed by --new-agent-token")
        sv = a.get("servers")
        if not isinstance(sv, list) or not sv or not all(isinstance(x, str) and x for x in sv):
            errs.append(f"{label}: 'servers' must list the server names (or globs) this token may report as")
    ua = cfg.get("ui_auth") or {}
    mode = ua.get("mode", "none")
    if mode not in ("none", "basic"):
        errs.append("ui_auth.mode must be 'none' or 'basic'")
    if mode == "basic" and not ua.get("users"):
        errs.append("ui_auth.mode is 'basic' but no users are configured (create hashes with --hash-password)")
    host = (cfg.get("listen") or {}).get("host", "")
    if mode == "none" and not is_loopback(host) and not ua.get("insecure_allow_anonymous_remote"):
        errs.append(f"refusing to serve an unauthenticated dashboard on non-loopback address '{host}': "
                    "set ui_auth.mode to 'basic' (or listen on 127.0.0.1)")
    if str(cfg.get("sqlite_synchronous", "NORMAL")).upper() not in ("NORMAL", "FULL"):
        errs.append("sqlite_synchronous must be NORMAL or FULL")
    return errs


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_token() -> str:
    return "wmh_" + secrets.token_urlsafe(32)


def hash_password(pw: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iters, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def secret(cfg_block: dict, key: str) -> str:
    """Read a secret from <key>_env (preferred) or <key>; keeps passwords out of config files."""
    env_name = cfg_block.get(key + "_env")
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    return cfg_block.get(key, "") or ""
