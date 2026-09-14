#!/usr/bin/env python3
"""
asm_events.py — turn an ASM support ID into violation detail.

run_matrix.py already extracts the support ID from ASM's blocking page, which
is the authoritative, synchronous signal that the WAF blocked a request. This
tool is the ENRICHMENT step: given an ID, it reports which violation and which
signature fired, so a block can be attributed to the right cause rather than
merely counted.

  --support-id 1844674407370955161     look up one request
  --recent 20                          list recent blocked requests
  --raw                                dump the JSON as returned

NOTE ON ENDPOINTS: the ASM request-log REST surface has moved between TMOS
versions. Several candidates are tried and the one that answers is reported.
If none does, the GUI path is printed instead — an honest fallback beats a
confident wrong answer. Nothing here needs "Trigger ASM iRule Events": that
setting is only for ASM_REQUEST_* iRule events, which this lab does not use.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ilx_deploy import BigIP, load_dotenv  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CANDIDATES = [
    "/mgmt/tm/asm/events/requests",
    "/mgmt/tm/asm/events",
]


def query(b: BigIP, path: str, params: dict) -> dict | None:
    import requests
    try:
        r = requests.get(f"{b.host}{path}", headers=b.headers, params=params,
                         verify=False, timeout=60)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def summarise(item: dict) -> str:
    viols = item.get("violations") or item.get("violationRefs") or []
    names = [v.get("name", str(v)) if isinstance(v, dict) else str(v) for v in viols]
    sigs = [s.get("name", "") for s in (item.get("signatures") or []) if isinstance(s, dict)]
    return (
        f"  support_id : {item.get('supportId')}\n"
        f"  time       : {item.get('requestDatetime') or item.get('datetime')}\n"
        f"  method/uri : {item.get('method')} {item.get('uri')}\n"
        f"  client     : {item.get('clientIp')}\n"
        f"  action      : {item.get('requestStatus') or item.get('action')}\n"
        f"  violations : {', '.join(names) or '(none reported)'}\n"
        f"  signatures : {', '.join(s for s in sigs if s) or '(none reported)'}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--support-id")
    g.add_argument("--recent", type=int, metavar="N")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    load_dotenv(os.path.join(REPO, ".env"))
    host = os.environ.get("BIGIP_HOST", "").rstrip("/")
    pwd = os.environ.get("BIGIP_PASSWORD", "")
    if not host or not pwd:
        sys.exit("Set BIGIP_HOST and BIGIP_PASSWORD (see .env.example)")

    b = BigIP(host, os.environ.get("BIGIP_USERNAME", "admin"), pwd)

    if args.support_id:
        params = {"$filter": f"supportId eq {args.support_id}"}
        label = f"support ID {args.support_id}"
    else:
        params = {"$top": args.recent, "$orderby": "requestDatetime desc"}
        label = f"{args.recent} most recent requests"

    for path in CANDIDATES:
        doc = query(b, path, params)
        if doc is None:
            continue
        items = doc.get("items", []) if isinstance(doc, dict) else []
        print(f"endpoint: {path}  ({len(items)} item(s) for {label})\n")
        if args.raw:
            json.dump(doc, sys.stdout, indent=2)
            return 0
        if not items:
            print("  no matching requests. ASM logging can lag a few seconds —")
            print("  and a request rejected by the iRule never reaches ASM at all,")
            print("  which is exactly why run_matrix distinguishes reject from block.")
            return 0
        for item in items:
            print(summarise(item))
            print()
        return 0

    print("None of the candidate ASM REST endpoints answered:", file=sys.stderr)
    for c in CANDIDATES:
        print(f"  {c}", file=sys.stderr)
    print("\nFall back to the GUI: Security > Event Logs > Application > Requests,"
          "\nthen filter by support ID. Record the working path in docs/FINDINGS.md.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
