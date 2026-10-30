#!/usr/bin/env python3
"""Turn the team's server list (.xlsx or .csv) into the collector's inventory.json.

    python import_inventory.py "Server List.xlsx" -o inventory.json
    python import_inventory.py servers.csv -o inventory.json --shared "PROD NAS=/nas/prod_shared@PROD"

Expected layout (first sheet, no header row), as in the current server list:

    A: landscape name or role name   B: landscape code or host name   C: cluster (optional)
    Dev      | CON                      <- landscape row: column B empty or has no digits
    Broker   | SITE1WMASD009           <- server row
    Broker1  | SITE1WMAST393 | Broker  <- optional explicit cluster in column C

When column C is empty the cluster is derived from the role name: landscape words (PRD, PROD,
TEST, TST, DR, AWS, the landscape name/code) and node numbers are dropped, so Broker1 and Broker2
form cluster "Broker" and PRD_UM1..PRD_UM3 form cluster "UM". Review the output before using it.
A host listed twice in one landscape becomes one server with several roles. Other columns are ignored.
Standard library only (an .xlsx file is a zip of XML parts).
"""
import argparse
import csv
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
LANDSCAPE_WORDS = {"PRD", "PROD", "TST", "TEST", "DEV", "DR", "AWS", "UAT", "SIT", "QA"}


def _col(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def read_xlsx(path):
    """Rows of the first worksheet as lists of strings (values, not formulas)."""
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
                shared.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        first = wb.find("m:sheets/m:sheet", NS)
        rid = first.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        target = next(r.get("Target") for r in rels if r.get("Id") == rid)
        target = target.lstrip("/") if target.startswith("/") else "xl/" + target
        sheet = ET.fromstring(z.read(target))
    rows = []
    for r in sheet.iter("{%s}row" % NS["m"]):
        row = []
        for c in r.findall("m:c", NS):
            i = _col(c.get("r"))
            t = c.get("t")
            if t == "inlineStr":
                v = "".join(x.text or "" for x in c.iter("{%s}t" % NS["m"]))
            else:
                ve = c.find("m:v", NS)
                v = "" if ve is None else (shared[int(ve.text)] if t == "s" else ve.text or "")
            row += [""] * (i + 1 - len(row))
            row[i] = v.strip()
        rows.append(row)
    return rows


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [[c.strip() for c in r] for r in csv.reader(fh)]


def derive_cluster(role, landscape, code):
    drop = LANDSCAPE_WORDS | {landscape.upper(), code.upper()}
    out = []
    for tok in re.split(r"[_\s]+", role):
        if not tok or tok.upper() in drop or tok.isdigit():
            continue
        tok = re.sub(r"(?<=[A-Za-z])\d+$", "", tok)  # Broker1 -> Broker, MWS01 -> MWS, B2B1 -> B2B
        if tok:
            out.append(tok)
    return " ".join(out) or role


def is_host(v):
    return bool(v) and any(ch.isdigit() for ch in v) and re.fullmatch(r"[A-Za-z0-9_.\-]{3,200}", v) is not None


def build(rows, shared=()):
    landscapes, cur, warnings = [], None, []
    for n, row in enumerate(rows, 1):
        a, b, c = (row + ["", "", ""])[:3]
        if not a and not b:
            continue
        if a and not is_host(b):
            cur = {"name": a, "code": b, "servers": [], "_by": {}}
            landscapes.append(cur)
            continue
        if cur is None:
            warnings.append(f"row {n}: server '{b}' appears before any landscape row; skipped")
            continue
        if not is_host(b):
            warnings.append(f"row {n}: '{b}' does not look like a host name; skipped")
            continue
        role = a or b
        cluster = c or derive_cluster(role, cur["name"], cur["code"])
        key = b.lower()
        if key in cur["_by"]:  # same host listed again (for example Optimize and CCE on one box)
            s = cur["_by"][key]
            s["roles"].append(role)
            if cluster not in s["cluster"].split(" & "):
                s["cluster"] += " & " + cluster
            continue
        s = {"host": b, "cluster": cluster, "roles": [role]}
        cur["_by"][key] = s
        cur["servers"].append(s)
    for ls in landscapes:
        del ls["_by"]
    seen = {}
    for ls in landscapes:
        for s in ls["servers"]:
            k = s["host"].lower()
            if k in seen:
                warnings.append(f"host {s['host']} is listed in both {seen[k]} and {ls['name']}; the collector keeps the first")
            seen.setdefault(k, ls["name"])
    return {"landscapes": landscapes, "shared_storage": list(shared)}, warnings


def parse_shared(spec):
    """'NAME=/path@LS1,LS2' (landscapes optional)."""
    name, _, rest = spec.partition("=")
    path, _, lss = rest.partition("@")
    if not name or not path:
        raise argparse.ArgumentTypeError("use NAME=/path or NAME=/path@LANDSCAPE[,LANDSCAPE]")
    out = {"name": name.strip(), "path": path.strip()}
    if lss:
        out["landscapes"] = [x.strip() for x in lss.split(",") if x.strip()]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("source", help=".xlsx or .csv server list")
    ap.add_argument("-o", "--output", default="-", help="inventory.json to write (default: print)")
    ap.add_argument("--shared", action="append", type=parse_shared, default=[], metavar="NAME=/path[@LANDSCAPE,...]",
                    help="a shared NAS mount (repeatable); counted once on the dashboard instead of once per server")
    ap.add_argument("--force", action="store_true", help="overwrite an existing output file")
    a = ap.parse_args()
    rows = read_xlsx(a.source) if a.source.lower().endswith((".xlsx", ".xlsm")) else read_csv(a.source)
    inv, warnings = build(rows, a.shared)
    for w in warnings:
        print("warning:", w, file=sys.stderr)
    text = json.dumps(inv, indent=1)
    if a.output == "-":
        print(text)
    else:
        if os.path.exists(a.output) and not a.force:
            sys.exit(f"{a.output} exists; pass --force to overwrite it")
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    n = sum(len(ls["servers"]) for ls in inv["landscapes"])
    print(f"{len(inv['landscapes'])} landscape(s), {n} host(s)", file=sys.stderr)
    for ls in inv["landscapes"]:
        cl = {}
        for s in ls["servers"]:
            cl[s["cluster"]] = cl.get(s["cluster"], 0) + 1
        print(f"  {ls['name']:<6} " + ", ".join(f"{k} x{v}" if v > 1 else k for k, v in cl.items()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
