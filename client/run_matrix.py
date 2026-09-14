#!/usr/bin/env python3
"""
run_matrix.py — fire client/cases.yaml at every virtual server and assert the
outcomes. This is the deliverable: the lab's claims either hold here or they do
not.

Exit code is 0 only when every asserted cell matches. `measure` cells are
recorded and never asserted, because the single-VS experiment exists to answer
a question rather than confirm one.

CLASSIFICATION — the distinction that carries the whole result
    block   403 carrying an ASM support ID   -> the WAF made the decision
    reject  4xx/5xx with no support ID       -> the DECRYPTOR made the decision
    allow   2xx                              -> reached the backend
Collapsing block and reject into "it failed" would hide which control fired,
and a 403 for the wrong reason would read as success.

The support ID comes from ASM's own blocking page rather than the event log:
it is synchronous, needs no extra permissions, and cannot be confused with a
neighbouring request. tools/asm_events.py turns an ID into violation detail.

Usage:
  python3 client/run_matrix.py --all
  python3 client/run_matrix.py --case sqli --verbose
  python3 client/run_matrix.py --target chain,blind
  python3 client/run_matrix.py --all --profile B        # old ILX runtime
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import warnings

try:
    import requests
    import yaml
    from tabulate import tabulate
except ImportError as e:
    sys.exit(
        f"Missing dependency: {e.name}\n"
        "\nThe project venv is probably not active — the system python3 cannot see\n"
        "the packages. Either activate it:\n"
        "    source .venv/bin/activate\n"
        "or run without activating:\n"
        f"    ./.venv/bin/python {sys.argv[0]}\n"
        "\nIf .venv does not exist yet:\n"
        "    python3 -m venv .venv\n"
        "    ./.venv/bin/python -m pip install -r requirements.txt"
    )

warnings.filterwarnings("ignore")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "client"))

from jwe_builder import ATTACK_PAYLOADS, JweBuilder  # noqa: E402

# ASM's default blocking page carries the ID; wording varies by version.
SUPPORT_ID = re.compile(r"support\s*ID\s*(?:is)?\s*[:=]?\s*(\d{6,})", re.I)


def load_dotenv(path: str) -> None:
    """
    Minimal .env loader. A real environment variable still wins, but WITHIN the
    file the LAST occurrence of a key wins and an empty value is ignored.

    Both rules exist because of a real failure: applying setdefault line by line
    made the FIRST occurrence win, so an earlier `KEY=` with no value silently
    masked a real value appended later in the same file. It presents as
    "variable not set" no matter how carefully you edit it.
    """
    if not os.path.exists(path):
        return
    values = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            if v:                          # an empty value is not a value
                values[k.strip()] = v      # later lines override earlier ones
    for k, v in values.items():
        os.environ.setdefault(k, v)


def classify(resp: requests.Response) -> tuple[str, str | None]:
    """-> (outcome, support_id)."""
    text = resp.text or ""
    m = SUPPORT_ID.search(text)
    sid = m.group(1) if m else None

    if 200 <= resp.status_code < 300:
        return "allow", None
    if sid:
        # ASM decided. Status is usually 403 but the blocking page is the signal.
        return "block", sid
    return "reject", None


def backend_view(resp: requests.Response) -> str:
    """
    What the origin actually received. On an allow, this is what makes the
    blind spot visible: 'ciphertext' means the WAF was inspecting a JWE.
    """
    try:
        body = resp.json()
    except ValueError:
        return ""
    recv = body.get("received") or {}
    if not recv:
        return ""
    if recv.get("looks_like_undecrypted_jwe"):
        return "ciphertext"
    if recv.get("jwe_decrypted_header") == "true":
        return f"plaintext ({recv.get('jwe_kid') or 'no kid'})"
    return "plaintext"


def build_body(builder: JweBuilder, case: dict, as_jwe: bool, profile: str):
    """-> (body, content_type)."""
    if not as_jwe:
        payload = ATTACK_PAYLOADS[case.get("payload", "clean")]
        return json.dumps(payload), "application/json"

    if "case" in case:
        return builder.build_case(case["case"], profile=profile), "application/jose"
    return builder.build(ATTACK_PAYLOADS[case["payload"]], profile=profile), "application/jose"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--case", help="comma-separated case names")
    ap.add_argument("--target", help="comma-separated target names")
    ap.add_argument("--profile", default="C", choices=["A", "B", "C"],
                    help="JWE algorithm profile (B for an old ILX runtime)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not (args.all or args.case):
        ap.error("give --all or --case")

    load_dotenv(os.path.join(REPO, ".env"))
    spec = yaml.safe_load(open(os.path.join(REPO, "client", "cases.yaml")))
    builder = JweBuilder(os.environ.get("JWE_KEYS_DIR", os.path.join(REPO, "keys")))

    targets = spec["targets"]
    if args.target:
        want = {t.strip() for t in args.target.split(",")}
        targets = {k: v for k, v in targets.items() if k in want}

    # Skip targets whose address is not configured rather than reporting them
    # as failures — a partially built lab should still be testable.
    resolved, skipped = {}, []
    for name, t in targets.items():
        addr = os.environ.get(t["env"], "").strip()
        if addr:
            resolved[name] = {**t, "addr": addr}
        else:
            skipped.append(f"{name} ({t['env']} unset)")

    if not resolved:
        sys.exit("no targets resolved — set VS_* in .env (see .env.example)")
    if skipped:
        print(f"skipping targets: {', '.join(skipped)}\n")

    cases = spec["cases"]
    if args.case:
        want = {c.strip() for c in args.case.split(",")}
        cases = [c for c in cases if c["name"] in want]
        missing = want - {c["name"] for c in cases}
        if missing:
            sys.exit(f"unknown case(s): {sorted(missing)}")

    path = spec.get("path", "/api/v1/orders")
    rows, failures, measured = [], [], []

    for case in cases:
        row = [case["name"]]
        for tname, t in resolved.items():
            expected = case["expect"].get(tname, "n/a")
            if expected == "n/a":
                row.append("–")
                continue

            try:
                body, ctype = build_body(builder, case, t["jwe"], args.profile)
            except Exception as e:                      # noqa: BLE001
                row.append("BUILD-ERR")
                failures.append(f"{case['name']}/{tname}: cannot build: {e}")
                continue

            url = f"https://{t['addr']}{path}"
            try:
                resp = requests.post(url, data=body.encode(),
                                     headers={"Content-Type": ctype},
                                     verify=False, timeout=args.timeout)
            except requests.RequestException as e:
                row.append("NET-ERR")
                failures.append(f"{case['name']}/{tname}: {type(e).__name__}: {e}")
                continue

            got, sid = classify(resp)
            view = backend_view(resp)

            cell = got
            if sid:
                cell += f" #{sid[:10]}"
            elif view == "ciphertext":
                # The blind spot, made explicit in the table.
                cell += " (cipher)"

            if expected == "measure":
                row.append(f"? {cell}")
                measured.append(
                    f"{case['name']}/{tname}: {got} http={resp.status_code} "
                    f"backend_saw={view or 'n/a'}" + (f" support_id={sid}" if sid else "")
                )
            elif got == expected:
                row.append(f"✓ {cell}")
            else:
                row.append(f"✗ {cell}")
                failures.append(
                    f"{case['name']}/{tname}: expected {expected}, got {got} "
                    f"(http {resp.status_code}, backend saw {view or 'n/a'})"
                )

            if args.verbose:
                print(f"  {case['name']:20} {tname:8} http={resp.status_code} "
                      f"-> {got:6} backend_saw={view or '-'} "
                      f"{'sid=' + sid if sid else ''}")

        rows.append(row)

    print()
    print(tabulate(rows, headers=["case"] + list(resolved), tablefmt="simple"))
    print("\ntargets:")
    for name, t in resolved.items():
        print(f"  {name:8} {t['addr']:15} {t['label']}")

    if measured:
        print("\nMEASURED (not asserted — record these in docs/FINDINGS.md):")
        for m in measured:
            print("  " + m)

    # The one row that matters, called out explicitly.
    sqli = next((c for c in cases if c["name"] == "sqli"), None)
    if sqli and {"chain", "blind"} <= set(resolved):
        i = list(resolved).index("chain") + 1
        j = list(resolved).index("blind") + 1
        r = next(x for x in rows if x[0] == "sqli")
        holds = r[i].startswith("✓") and r[j].startswith("✓")
        print(f"\nCENTRAL CLAIM (same JWE, opposite outcomes): "
              f"{'HOLDS' if holds else 'DOES NOT HOLD'}")
        print(f"  chain={r[i]}   blind={r[j]}")

    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print("  " + f)
        return 1

    print(f"\nall asserted cells matched ({len(rows)} cases x {len(resolved)} targets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
