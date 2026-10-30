#!/usr/bin/env python3
"""One-command demo: collector + a simulated webMethods estate that follows the server list.

    python sim/run_demo.py                      # then open http://127.0.0.1:8080
    python sim/run_demo.py --port 9000 --dir ./my_demo --run-seconds 180
    python sim/run_demo.py --inventory my_inventory.json

The estate comes from sim/inventory.demo.json (generated from Server List.xlsx with
collector/import_inventory.py): every listed host appears under its landscape and cluster. Five hosts
run a real agent and carry the alert scenario; the rest send light simulated heartbeats, and one DR
host never reports so the "No data" state is visible. See sim/simulate.py for the details.

Alert timers are shortened so a two-minute run shows firing, escalation and auto-resolve.
Notifications run in dry-run mode: emails (.eml) and Teams cards (.json) land in <dir>/data/outbox.

Safety: the demo never deletes anything. Without --dir it creates a new, timestamped folder under
./demo_runs. If the folder you name already exists, it stops instead of reusing or removing it.
Everything listens on 127.0.0.1 only.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "collector"))
from hub import config as c  # noqa: E402
import simulate  # noqa: E402

HOST = "127.0.0.1"  # demo services are loopback-only by design


def fresh_dir(requested):
    """Return a directory that did not exist before this call. Never touches an existing one."""
    if requested:
        path = os.path.abspath(requested)
        if os.path.exists(path):
            sys.exit(f"demo: '{path}' already exists. Choose a new --dir (the demo never reuses or deletes a folder).")
        os.makedirs(path)
        return path
    base = os.path.join(os.getcwd(), "demo_runs")
    os.makedirs(base, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for i in range(100):
        path = os.path.join(base, stamp if i == 0 else f"{stamp}-{i}")
        try:
            os.mkdir(path)  # atomic: fails if someone else created it first
            return path
        except FileExistsError:
            continue
    sys.exit("demo: could not create a fresh run directory")


def demo_rules(dst, landscapes=()):
    with open(os.path.join(ROOT, "collector", "rules.json")) as fh:
        rules = json.load(fh)
    for r in rules["rules"]:
        if "for_s" in r:
            r["for_s"] = min(r["for_s"], 20)
        if "max_silence_s" in r:
            r["max_silence_s"] = 25
        if r["id"] == "WM-001":
            r["escalate_after_s"] = 40
            if landscapes:  # the shipped rule watches PROD/UAT; the demo uses the server list's landscape names
                r["scope"] = {"environment": [x for x in landscapes if x.lower() != "dev"]}
        if r["id"] == "WM-007":
            r["window_s"] = 120
        r["resolve_after_s"] = min(r.get("resolve_after_s", 60), 30)
    with open(dst, "w") as fh:
        json.dump(rules, fh, indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--dir", help="new folder for this run (must not exist); default ./demo_runs/<timestamp>")
    ap.add_argument("--run-seconds", type=int, default=0, help="stop after this many seconds (0 = until Ctrl-C)")
    ap.add_argument("--inventory", default=simulate.DEFAULT_INVENTORY, help="server list to simulate (inventory.json format)")
    ap.add_argument("--all-real-agents", action="store_true", help="run a real agent process for every host (heavy)")
    a = ap.parse_args()
    with open(a.inventory, encoding="utf-8") as fh:
        inventory = json.load(fh)
    hosts = simulate.load_hosts(a.inventory)
    run_dir = fresh_dir(a.dir)
    print(f"demo files: {run_dir}", flush=True)

    # one token per simulated host, each allowed to report only as its own server name
    tokens = {h["name"]: c.new_token() for h in hosts}
    demo_rules(os.path.join(run_dir, "rules.json"), [ls["name"] for ls in inventory["landscapes"]])
    with open(os.path.join(run_dir, "inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=1)
    cfg = {"listen": {"host": HOST, "port": a.port}, "db_path": "./data/hub.db", "rules_file": "./rules.json",
           "inventory_file": "./inventory.json",
           "eval_interval_s": 3, "expected_heartbeat_s": 5,
           "agents": [{"name": n, "token_sha256": c.sha256_hex(t), "servers": [n]} for n, t in tokens.items()],
           "ui_auth": {"mode": "none"},  # anonymous is allowed only because HOST is loopback
           "notifications": {"dry_run": True, "outbox_dir": "./data/outbox", "dashboard_url": f"http://{HOST}:{a.port}",
                             "email": {"enabled": True, "from": "webMethods Hub <hub@demo.local>"}, "teams": {"enabled": True},
                             "routes": [{"match": {"severity": ["critical"]}, "email": ["oncall@demo.local"], "teams": ["WM_TEAMS_PROD"]},
                                        {"match": {"severity": ["warning", "info"]}, "email": ["ops@demo.local"], "teams": ["WM_TEAMS_PROD"]}]}}
    cfg_path = os.path.join(run_dir, "collector.json")
    with open(cfg_path, "w") as fh:
        json.dump(cfg, fh, indent=1)

    procs = [subprocess.Popen([sys.executable, os.path.join(ROOT, "collector", "run_collector.py"), "--config", cfg_path])]
    try:
        for _ in range(30):
            if procs[0].poll() is not None:
                sys.exit("demo: the collector exited during start-up (is the port already in use?)")
            try:
                urllib.request.urlopen(f"http://{HOST}:{a.port}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        # tokens travel by environment variable, not on the command line where other users could read them
        env = dict(os.environ, WM_SIM_TOKENS=json.dumps(tokens))
        cmd = [sys.executable, os.path.join(HERE, "simulate.py"), "--workdir", os.path.join(run_dir, "sim"),
               "--collector", f"http://{HOST}:{a.port}", "--db", os.path.join(run_dir, "data", "hub.db"), "--inventory", a.inventory]
        if a.all_real_agents:
            cmd.append("--all-real-agents")
        if a.run_seconds:
            cmd += ["--run-seconds", str(a.run_seconds)]
        procs.append(subprocess.Popen(cmd, env=env))
        print(f"\nDashboard: http://{HOST}:{a.port}   (Ctrl-C to stop)\n", flush=True)
        procs[-1].wait()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
    print(f"demo stopped; its files are kept in {run_dir}")


if __name__ == "__main__":
    main()
