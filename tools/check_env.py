#!/usr/bin/env python3
"""
check_env.py — show what the tools actually resolved, and test the BIG-IP login.

Exists because `.env` is not the only source of truth: every tool here loads it
with os.environ.setdefault, so a variable ALREADY SET IN YOUR SHELL silently
wins — including an empty or stale one. That failure looks like a wrong
password, which sends you to the wrong place.

Passwords are never printed. What IS printed is length, and whether the value
carries surrounding quotes or stray whitespace, which are the usual culprits.

  python3 tools/check_env.py              # show resolved config
  python3 tools/check_env.py --login      # also attempt a real login
"""

from __future__ import annotations

import argparse
import os
import sys
import warnings

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VARS = [
    ("BIGIP_HOST", True), ("BIGIP_USERNAME", False), ("BIGIP_PASSWORD", True),
    ("VS_JWE_INGRESS", False), ("VS_JWE_BLIND", False), ("VS_PLAIN_WAF", False),
    ("VS_JWE_SINGLE", False), ("BACKEND_IP", False), ("BACKEND_PORT", False),
    ("JWE_KEYS_DIR", False), ("BIGIP_KEYS_DIR", False),
    ("JWE_FAIL_MODE", False), ("JWE_MAX_PAYLOAD", False),
]
SECRET = {"BIGIP_PASSWORD"}


def parse_env_file(path: str):
    """
    Returns (values, duplicates). MUST mirror load_dotenv's precedence exactly:
    last occurrence wins, empty values ignored. A diagnostic that models
    different precedence than the tools it diagnoses is worse than none — this
    one previously reported a password the tools could not see.
    """
    values, seen, dupes = {}, set(), []
    if not os.path.exists(path):
        return values, dupes
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k in seen:
                dupes.append(k)
            seen.add(k)
            if v:
                values[k] = v
    return values, dupes


def describe(name: str, value: str | None) -> str:
    if value is None:
        return "(unset)"
    if value == "":
        return "(EMPTY STRING — this is not the same as unset)"
    notes = []
    if value != value.strip():
        notes.append("HAS LEADING/TRAILING WHITESPACE")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        notes.append("STILL QUOTED")
    if name in SECRET:
        shown = f"<{len(value)} chars>"
    else:
        shown = value
    return shown + ("   <-- " + ", ".join(notes) if notes else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--login", action="store_true",
                    help="attempt a real iControl REST login and print the response")
    args = ap.parse_args()

    env_path = os.path.join(REPO, ".env")
    from_file, dupes = parse_env_file(env_path)

    print(f".env : {env_path}" + ("" if from_file else "   <-- MISSING or empty!"))
    if not os.path.exists(env_path):
        print("\n  cp .env.example .env    # then edit the BIGIP_* lines")
        return 1

    print(f"       {len(from_file)} key(s) parsed")
    if dupes:
        print(f"\n⚠️  duplicate key(s) in .env: {', '.join(sorted(set(dupes)))}")
        print("   The LAST occurrence wins. Delete the earlier lines — an earlier")
        print("   `KEY=` with no value is the classic cause of 'variable not set'.")
    print()
    print(f"{'variable':18} {'effective value':38} source")
    print("-" * 78)

    shadowed = []
    problems = []
    for name, required in VARS:
        shell_val = os.environ.get(name)
        file_val = from_file.get(name)

        # Mirror the tools' own precedence: setdefault means shell wins.
        if shell_val is not None:
            effective, source = shell_val, "SHELL"
            if file_val is not None and file_val != shell_val:
                shadowed.append(name)
                source = "SHELL (shadows .env!)"
        elif file_val is not None:
            effective, source = file_val, ".env"
        else:
            effective, source = None, "-"

        print(f"{name:18} {describe(name, effective):38} {source}")

        if required and not (effective or "").strip():
            problems.append(f"{name} is required and not usably set")
        if effective and effective != effective.strip():
            problems.append(f"{name} has surrounding whitespace")
        if name == "BIGIP_HOST" and effective and not effective.startswith("http"):
            problems.append("BIGIP_HOST needs an https:// scheme")

    if shadowed:
        print(f"\n⚠️  Shell variables override .env: {', '.join(shadowed)}")
        print("   Every tool loads .env with os.environ.setdefault, so the SHELL value")
        print("   wins. Clear them and re-run:")
        print("     unset " + " ".join(shadowed))

    if problems:
        print("\nPROBLEMS")
        for p in dict.fromkeys(problems):
            print("  - " + p)

    if not args.login:
        print("\nRun with --login to test the credential against the BIG-IP.")
        return 1 if problems else 0

    # ── live login ──────────────────────────────────────────────────────────
    try:
        import requests
    except ImportError as e:
        sys.exit(f"Missing dependency: {e.name} — activate the venv "
                 "(source .venv/bin/activate)")
    warnings.filterwarnings("ignore")

    host = (os.environ.get("BIGIP_HOST") or from_file.get("BIGIP_HOST") or "").rstrip("/")
    user = os.environ.get("BIGIP_USERNAME") or from_file.get("BIGIP_USERNAME") or "admin"
    pwd = os.environ.get("BIGIP_PASSWORD") or from_file.get("BIGIP_PASSWORD") or ""
    if not host or not pwd:
        print("\ncannot test login: BIGIP_HOST or BIGIP_PASSWORD not set")
        return 1

    print(f"\n=== login test: {user}@{host} ===")
    try:
        r = requests.post(
            f"{host}/mgmt/shared/authn/login",
            json={"username": user, "password": pwd, "loginProviderName": "tmos"},
            verify=False, timeout=30,
        )
    except requests.exceptions.ConnectTimeout:
        print("  CONNECT TIMEOUT — is the deployment Running, and are you reachable")
        print("  from this network? UDF management IPs are only routable via the")
        print("  deployment's access methods, not from your laptop directly.")
        return 1
    except requests.exceptions.SSLError as e:
        print(f"  TLS error: {e}")
        return 1
    except requests.RequestException as e:
        print(f"  {type(e).__name__}: {e}")
        return 1

    print(f"  HTTP {r.status_code}")
    if r.status_code == 200:
        tok = r.json().get("token", {}).get("token", "")
        print(f"  LOGIN OK — token {tok[:12]}... ({len(tok)} chars)")
        return 0

    head = r.text[:400].lower()
    if "<html" in head or "<!doctype html" in head:
        print("  body: HTML (not JSON)")
        print("\n  *** This response came from UDF, not BIG-IP. ***")
        print("  UDF HTTPS access methods authenticate with the browser session")
        print("  cookie, so they cannot carry scripted iControl REST calls. Use an")
        print("  SSH tunnel, or run these tools inside the deployment:")
        print("\n    ssh -p <sshPort> -N -L 8443:<bigip-mgmt-ip>:443 \\")
        print("        <user>@<dnsKey>.access.udf.f5.com")
        print("    # then  BIGIP_HOST=https://127.0.0.1:8443")
        print("\n  See docs/RUNBOOK.md - Reaching the BIG-IP management plane.")
        return 1

    print(f"  body: {r.text[:400]}")
    if r.status_code == 401:
        print("\n  401 means the credential was rejected. Check, in this order:")
        print("   1. The password in UDF: bigip-waf component -> Credentials tab.")
        print("      UDF templates ship their own credential; it is not admin/admin.")
        print("   2. Whether a SHELL variable is shadowing .env (see the table above).")
        print("   3. Special characters: if you exported it in the shell, $ ! and `")
        print("      get expanded by zsh. Put it in .env instead, which is not expanded.")
        print("   4. Whether the account is locked after repeated failures.")
    elif r.status_code == 404:
        print("\n  404 on the login endpoint usually means the management plane is")
        print("  still starting. Wait for the component to reach Running and retry.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
