#!/usr/bin/env python3
"""
as3_submit.py — inject the iRules and WAF policy into the AS3 declaration, then
submit it to BIG-IP.

Adapted from the resilient-dns-demo tool of the same name, with one addition
that matters: the declaration on disk carries __PLACEHOLDER__ tokens and the
real content is injected HERE, at submit time, from

    bigip/irules/jwe_decrypt.tcl
    bigip/irules/jwe_single.tcl
    bigip/waf/jwe-demo-policy.json

so the .tcl and policy files stay the single source of truth. Pasting base64
into the JSON by hand guarantees it goes stale the first time someone edits an
iRule and forgets to re-encode.

Usage:
  python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json
  python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json --dry-run
  python3 tools/as3_submit.py --render-only > /tmp/rendered.json

Environment (.env is the project's normal mechanism):
  BIGIP_HOST      https://<management-ip>
  BIGIP_USERNAME  default: admin
  BIGIP_PASSWORD  admin password
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import warnings

try:
    import requests
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
DEFAULT_DECL = os.path.join(REPO, "bigip", "as3", "waf-jwe-declaration.json")

UDF_PROXY_HELP = """
That 401 came from UDF's access-method proxy, NOT from BIG-IP: the body is UDF's
HTML login page. UDF HTTPS access methods are authenticated by the browser
session cookie (HttpOnly), so they cannot carry scripted iControl REST calls.

Two ways round it:

  A. SSH tunnel (keeps these tools on your laptop). Take the SSH port from the
     bigip-waf component's Access Methods tab:

       ssh -p <sshPort> -N -L 8443:<bigip-mgmt-ip>:443 <user>@<dnsKey>.access.udf.f5.com

     then set  BIGIP_HOST=https://127.0.0.1:8443

  B. Run these tools INSIDE the deployment (api-backend or test-desktop). Every
     component sits on the 10.1.1.0/24 management subnet, so
     BIGIP_HOST=https://10.1.1.<bigip> works there directly.

See docs/RUNBOOK.md - "Reaching the BIG-IP management plane".
"""


def looks_like_udf_proxy(body: str) -> bool:
    """UDF's proxy answers with HTML; BIG-IP answers with JSON."""
    head = (body or "")[:400].lower()
    return "<html" in head or "<!doctype html" in head or "<title>udf</title>" in head


INJECTIONS = {
    "__IRULE_JWE_DECRYPT_B64__": ("bigip/irules/jwe_decrypt.tcl", "b64"),
    "__IRULE_JWE_SINGLE_B64__": ("bigip/irules/jwe_single.tcl", "b64"),
    "__WAF_POLICY__": ("bigip/waf/jwe-demo-policy.json", "json"),
}


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


def render(decl_path: str) -> dict:
    """Substitute every placeholder, failing loudly if any survives."""
    with open(decl_path) as fh:
        raw = fh.read()

    for token, (rel, mode) in INJECTIONS.items():
        if token not in raw:
            continue
        src = os.path.join(REPO, rel)
        if not os.path.exists(src):
            sys.exit(f"cannot inject {token}: {rel} not found")

        with open(src) as fh:
            content = fh.read()

        if mode == "b64":
            value = base64.b64encode(content.encode("utf-8")).decode("ascii")
            raw = raw.replace(f'"{token}"', json.dumps(value))
        else:
            # The WAF policy is an object, so the QUOTED placeholder is replaced
            # by raw JSON — otherwise it would land as a string and AS3 would
            # reject it with an unhelpful schema error.
            policy = json.loads(content)
            raw = raw.replace(f'"{token}"', json.dumps(policy["policy"]))

    doc = json.loads(raw)   # also validates the substitution produced valid JSON

    leftover = [t for t in INJECTIONS if t in json.dumps(doc)]
    if leftover:
        sys.exit(f"placeholders not substituted: {leftover}")
    return doc


def login(host: str, username: str, password: str) -> str:
    r = requests.post(
        f"{host}/mgmt/shared/authn/login",
        json={"username": username, "password": password, "loginProviderName": "tmos"},
        verify=False, timeout=30,
    )
    if r.status_code != 200:
        if looks_like_udf_proxy(r.text):
            sys.exit(f"Login failed ({r.status_code}) — reached UDF, not BIG-IP."
                     + UDF_PROXY_HELP)
        sys.exit(f"Login failed ({r.status_code}): {r.text[:300]}")
    return r.json()["token"]["token"]


def submit(host: str, token: str, declaration: dict) -> int:
    headers = {"X-F5-Auth-Token": token, "Content-Type": "application/json"}
    print(f"POST {host}/mgmt/shared/appsvcs/declare")
    r = requests.post(f"{host}/mgmt/shared/appsvcs/declare",
                      headers=headers, json=declaration, verify=False, timeout=180)

    if r.status_code == 202:
        task = r.json().get("id")
        print(f"accepted as task {task}; polling...")
        for _ in range(60):
            time.sleep(5)
            t = requests.get(f"{host}/mgmt/shared/appsvcs/task/{task}",
                             headers=headers, verify=False, timeout=30)
            results = t.json().get("results", [])
            if results and all(x.get("message") != "in progress" for x in results):
                r = t
                break

    body = r.json() if r.content else {}
    results = body.get("results", [body])

    ok = True
    for item in results:
        code = item.get("code")
        msg = item.get("message", "")
        tenant = item.get("tenant", "")
        marker = "OK " if code in (200, 0) else "ERR"
        if code not in (200, 0):
            ok = False
        print(f"  [{marker}] {tenant or '-'}: code={code} {msg}")
        if item.get("response"):
            print(f"         {item['response']}")

    if not ok:
        print("\nIf the WAF_Policy inline `policy` field was rejected, that field name "
              "differs across AS3 versions — see docs/LIMITATIONS.md for the "
              "import-policy fallback.", file=sys.stderr)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("declaration", nargs="?", default=DEFAULT_DECL)
    ap.add_argument("--dry-run", action="store_true",
                    help="render and validate, contact nothing")
    ap.add_argument("--render-only", action="store_true",
                    help="print the fully rendered declaration to stdout")
    args = ap.parse_args()

    load_dotenv(os.path.join(REPO, ".env"))
    doc = render(args.declaration)

    if args.render_only:
        json.dump(doc, sys.stdout, indent=2)
        return 0

    app = doc["declaration"]["jwe_lab"]["jwe_app"]
    vs = {k: v for k, v in app.items()
          if isinstance(v, dict) and str(v.get("class", "")).startswith("Service_")}
    print(f"rendered {args.declaration}")
    print(f"  virtual servers : {len(vs)}")
    for name, v in vs.items():
        waf = "WAF" if "policyWAF" in v else "no-WAF"
        print(f"    {name:18} {v['virtualAddresses'][0]}:{v['virtualPort']:<5} {waf}")
    print(f"  irules injected : "
          f"{sum(1 for v in app.values() if isinstance(v, dict) and v.get('class') == 'iRule')}")

    if args.dry_run:
        print("\n--dry-run: nothing submitted")
        return 0

    host = os.environ.get("BIGIP_HOST", "").rstrip("/")
    user = os.environ.get("BIGIP_USERNAME", "admin")
    pwd = os.environ.get("BIGIP_PASSWORD", "")
    if not host or not pwd:
        sys.exit("Set BIGIP_HOST and BIGIP_PASSWORD (see .env.example)")

    print(f"\nlogging in to {host} ...")
    return submit(host, login(host, user, pwd), doc)


if __name__ == "__main__":
    sys.exit(main())
