"""Server inventory: which landscape (environment) and cluster each host belongs to, and which
disk paths are shared NAS storage.

The inventory is the collector's view of what *should* exist, so the dashboard can group servers
by landscape and cluster and can show a listed host that has never reported ("no data"). It is a
JSON file, usually generated from the team's server list with import_inventory.py:

    {"landscapes": [{"name": "PROD", "code": "PRD", "servers": [
        {"host": "site2wmasp104", "cluster": "CIS", "roles": ["PRD_CIS1"]}, ...]}],
     "shared_storage": [{"name": "PROD NAS", "path": "/nas/wm_shared", "landscapes": ["PROD"]}]}

A reporting server is matched to an inventory entry by server name or host name (case-insensitive,
with or without the domain part). The file is re-read when it changes, like rules.json.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading

log = logging.getLogger("hub.inventory")
HOST_RX = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")


def _short(h):
    return str(h or "").strip().lower().split(".", 1)[0]


def parse(raw):
    """Validate an inventory document. Returns (inventory, errors); bad entries are skipped, not fatal."""
    errors = []
    if not isinstance(raw, dict) or not isinstance(raw.get("landscapes"), list):
        return {"landscapes": [], "shared_storage": []}, ["inventory must be an object with a 'landscapes' list"]
    seen, landscapes = {}, []
    for i, ls in enumerate(raw["landscapes"][:100]):
        if not isinstance(ls, dict) or not str(ls.get("name", "")).strip():
            errors.append(f"landscapes[{i}]: 'name' is required")
            continue
        name = str(ls["name"]).strip()[:40]
        servers = []
        for j, s in enumerate((ls.get("servers") or [])[:2000]):
            host = str(s.get("host", "")).strip() if isinstance(s, dict) else ""
            if not HOST_RX.match(host):
                errors.append(f"{name}: servers[{j}] has a missing or invalid 'host'")
                continue
            key = _short(host)
            if key in seen:
                errors.append(f"{name}: host '{host}' is already listed under {seen[key]}; second entry ignored")
                continue
            seen[key] = name
            roles = [str(r)[:60] for r in (s.get("roles") or []) if str(r).strip()][:10]
            servers.append({"host": host, "cluster": str(s.get("cluster") or (roles[0] if roles else host))[:60], "roles": roles})
        landscapes.append({"name": name, "code": str(ls.get("code") or "")[:20], "servers": servers})
    shared = []
    for i, sh in enumerate((raw.get("shared_storage") or [])[:200]):
        if not isinstance(sh, dict) or not str(sh.get("path", "")).strip():
            errors.append(f"shared_storage[{i}]: 'path' is required")
            continue
        lss = sh.get("landscapes")
        shared.append({"name": str(sh.get("name") or sh["path"])[:80], "path": str(sh["path"]).strip()[:200],
                       "landscapes": [str(x) for x in lss] if isinstance(lss, list) and lss else None})
    return {"landscapes": landscapes, "shared_storage": shared}, errors


class Inventory:
    def __init__(self, path=None):
        self.path = path
        self.errors: list = []
        self._mtime = None
        self._lock = threading.Lock()
        self._set({"landscapes": [], "shared_storage": []})

    def _set(self, inv):
        self.data = inv
        self.index = {}
        for ls in inv["landscapes"]:
            for s in ls["servers"]:
                self.index[_short(s["host"])] = {"landscape": ls["name"], "code": ls["code"], **s}

    @property
    def loaded(self):
        return bool(self.data["landscapes"])

    def refresh(self):
        """Re-read the file if it changed. A broken file keeps the previous good copy."""
        if not self.path:
            return self
        try:
            mt = os.path.getmtime(self.path)
        except OSError:
            if self._mtime is not False:
                log.error("inventory file %s not found; servers are grouped by their reported environment", self.path)
                self.errors, self._mtime = [f"inventory file not found: {self.path}"], False
            return self
        with self._lock:
            if mt == self._mtime:
                return self
            try:
                with open(self.path, encoding="utf-8") as fh:
                    inv, errs = parse(json.load(fh))
                self._set(inv)
                self.errors = errs
                log.info("inventory: %d landscape(s), %d host(s), %d shared path(s), %d warning(s)",
                         len(inv["landscapes"]), len(self.index), len(inv["shared_storage"]), len(errs))
            except (OSError, ValueError) as exc:
                self.errors = [f"cannot parse {self.path}: {exc}"]
                log.error("cannot load inventory: %s (keeping previous copy)", exc)
            self._mtime = mt
        return self

    def lookup(self, name, host=None):
        """Inventory entry for a reporting server, or None."""
        for k in (_short(name), _short(host)):
            if k and k in self.index:
                return self.index[k]
        return None

    def shared_for(self, landscape):
        """Shared-storage entries that apply to servers in this landscape."""
        return [s for s in self.data["shared_storage"] if s["landscapes"] is None or landscape in s["landscapes"]]

    def shared_metric_names(self, landscape):
        return {"disk_used_pct:" + s["path"] for s in self.shared_for(landscape)}
