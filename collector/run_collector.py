#!/usr/bin/env python3
"""Entry point for the webMethods Observability Hub collector.

    python run_collector.py --config collector.json
    python run_collector.py --new-agent-token IS-PRD-01     # mint a token, print the config entry
    python run_collector.py --hash-password                 # hash a dashboard password
    python run_collector.py --config collector.json --check-rules
"""
import argparse
import getpass
import json
import logging
import os
import sys

if sys.version_info < (3, 9):
    sys.exit("the collector needs Python 3.9 or later")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hub import config as cfgmod  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--new-agent-token", metavar="NAME_OR_SERVER_GLOB")
    ap.add_argument("--hash-password", action="store_true")
    ap.add_argument("--check-rules", action="store_true")
    ap.add_argument("--check-config", action="store_true", help="validate tokens, dashboard auth and listen address")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if a.new_agent_token:
        tok = cfgmod.new_token()
        print("Give this token to the agent (WM_AGENT_TOKEN). It is shown once and not stored by the collector:\n  ", tok)
        print("\nAdd this entry to \"agents\" in collector.json:")
        print(json.dumps({"name": a.new_agent_token, "token_sha256": cfgmod.sha256_hex(tok), "servers": [a.new_agent_token]}, indent=2))
        return 0
    if a.hash_password:
        pw = getpass.getpass("Password: ")
        print(cfgmod.hash_password(pw))
        return 0
    if not a.config:
        ap.error("--config is required")

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = cfgmod.load(a.config)
    if a.check_config:
        errs = cfgmod.validate(cfg)
        for e in errs:
            print("ERROR:", e)
        print("configuration OK" if not errs else f"{len(errs)} configuration error(s)")
        return 1 if errs else 0
    if a.check_rules:
        from hub.alerts import Engine
        eng = Engine(cfg, None, None)
        eng.load_rules(force=True)
        print(f"{len(eng.rules)} rule(s) OK")
        for e in eng.rule_errors:
            print("ERROR:", e)
        return 1 if eng.rule_errors else 0
    from hub.server import serve
    serve(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
