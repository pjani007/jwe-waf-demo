#!/usr/bin/env python3
"""
ilx_deploy.py — install the ILX workspace, the keyring, and then PROVE the
plugin can actually read the keys.

That last part is the reason this script exists rather than a few tmsh lines.
A root-owned 0600 private key is unreadable if the ILX Node process runs as
some other user, and the failure surfaces as a decryption error rather than a
permissions error — so it gets misdiagnosed as a crypto bug. Here the owner is
DISCOVERED, the keys are chowned to match, and a selftest reads them back.

Steps
  1. login, confirm ASM + ILX are provisioned
  2. create /config/jwe/keys (0700) and upload keyring.json + key material
  3. create the ILX workspace and copy in index.js + package.json
  4. create the ILX plugin from the workspace
  5. discover the plugin's Node binary and process owner; chown the keys
  6. run `index.js --selftest` under that runtime and print what it found

Usage:
  python3 tools/ilx_deploy.py
  python3 tools/ilx_deploy.py --keys-only     # rotate keys, leave the plugin
  python3 tools/ilx_deploy.py --selftest-only # diagnose without changing anything
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
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
EXT_SRC = os.path.join(REPO, "bigip", "ilx", "jwe_decrypt_ws",
                       "extensions", "jwe_decrypt")

WORKSPACE = "jwe_decrypt_ws"
EXTENSION = "jwe_decrypt"
PLUGIN = "jwe_decrypt_plugin"

# Candidate paths for the ILX Node binary. TMOS has moved this between
# releases, so it is probed rather than assumed.
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


NODE_CANDIDATES = [
    "/usr/lib/ilx/bin/node",
    "/usr/lib/ilx/node/bin/node",
    "/var/service/ilx/node/bin/node",
    "/usr/bin/f5-rest-node",
]


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


class BigIP:
    """Token-auth iControl REST client with a bash escape hatch."""

    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip("/")
        r = requests.post(
            f"{self.host}/mgmt/shared/authn/login",
            json={"username": username, "password": password,
                  "loginProviderName": "tmos"},
            verify=False, timeout=30,
        )
        if r.status_code != 200:
            if looks_like_udf_proxy(r.text):
                sys.exit(f"login failed ({r.status_code}) — reached UDF, not BIG-IP."
                         + UDF_PROXY_HELP)
            sys.exit(f"login failed ({r.status_code}): {r.text[:300]}")
        try:
            self.token = r.json()["token"]["token"]
        except (ValueError, KeyError):
            sys.exit("login returned 200 but no token; body was not iControl REST JSON:\n"
                     + r.text[:300]
                     + (UDF_PROXY_HELP if looks_like_udf_proxy(r.text) else ""))

    @property
    def headers(self) -> dict:
        return {"X-F5-Auth-Token": self.token, "Content-Type": "application/json"}

    def bash(self, cmd: str) -> str:
        """Run a shell command via /mgmt/tm/util/bash."""
        r = requests.post(
            f"{self.host}/mgmt/tm/util/bash", headers=self.headers,
            json={"command": "run", "utilCmdArgs": f"-c '{cmd}'"},
            verify=False, timeout=180,
        )
        if r.status_code != 200:
            raise RuntimeError(f"bash failed ({r.status_code}): {r.text[:300]}")
        return r.json().get("commandResult", "")

    def put_file(self, remote: str, content: str) -> None:
        """
        Write a file by streaming base64 through bash. Avoids the
        file-transfer API's staging-directory rules, and keeps arbitrary
        content (PEM newlines, JSON quotes) intact.
        """
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        self.bash(f"mkdir -p $(dirname {remote})")
        self.bash(f"rm -f {remote}.b64")
        # Chunked so a long single command line cannot be truncated.
        for i in range(0, len(b64), 2000):
            self.bash(f"printf %s {b64[i:i + 2000]} >> {remote}.b64")
        self.bash(f"base64 -d {remote}.b64 > {remote} && rm -f {remote}.b64")


def check_provisioning(b: BigIP) -> None:
    out = b.bash("tmsh list sys provision one-line")
    need = {"asm": "Advanced WAF", "ilx": "iRules LX"}
    missing = [f"{m} ({label})" for m, label in need.items()
               if f"sys provision {m} " not in out or "level none" in
               next((l for l in out.splitlines() if f"provision {m} " in l), "level none")]
    print("provisioning:")
    for line in out.splitlines():
        for m in need:
            if f"provision {m} " in line:
                print("  " + line.strip())
    if missing:
        print(f"\n  WARNING: not provisioned: {', '.join(missing)}")
        print("  Run bigip/provision.sh first — ILX and ASM are both required.")


def upload_keys(b: BigIP, keys_dir: str, remote_dir: str) -> list[str]:
    keyring_path = os.path.join(keys_dir, "keyring.json")
    if not os.path.exists(keyring_path):
        sys.exit(f"{keyring_path} not found — run tools/keygen.py first")

    with open(keyring_path) as fh:
        keyring = json.load(fh)

    b.bash(f"mkdir -p {remote_dir} && chmod 700 {remote_dir}")
    b.put_file(f"{remote_dir}/keyring.json", json.dumps(keyring, indent=2))

    installed = []
    for entry in keyring["keys"]:
        local = os.path.join(keys_dir, entry["file"])
        if not os.path.exists(local):
            sys.exit(f"keyring references {entry['file']} but it is not in {keys_dir}")
        with open(local) as fh:
            b.put_file(f"{remote_dir}/{entry['file']}", fh.read())
        b.bash(f"chmod 600 {remote_dir}/{entry['file']}")
        installed.append(entry["kid"])
        print(f"  installed {entry['kid']:16} ({entry['alg']})")

    # The decoy must never reach the BIG-IP, or the wrong-key test is void.
    b.bash(f"rm -f {remote_dir}/decoy-*")
    return installed


def deploy_workspace(b: BigIP) -> None:
    existing = b.bash(f"tmsh list ilx workspace {WORKSPACE} 2>&1 || true")
    if "was not found" in existing or "Syntax Error" in existing:
        print(f"  creating workspace {WORKSPACE}")
        b.bash(f"tmsh create ilx workspace {WORKSPACE}")
        b.bash(f"tmsh modify ilx workspace {WORKSPACE} extensions add {{ {EXTENSION} }}")
    else:
        print(f"  workspace {WORKSPACE} exists — updating extension files")

    ws_dir = f"/var/ilx/workspaces/Common/{WORKSPACE}/extensions/{EXTENSION}"
    b.bash(f"mkdir -p {ws_dir}")
    for fname in ("index.js", "package.json"):
        with open(os.path.join(EXT_SRC, fname)) as fh:
            b.put_file(f"{ws_dir}/{fname}", fh.read())
        print(f"  uploaded {fname}")

    plugins = b.bash(f"tmsh list ilx plugin {PLUGIN} 2>&1 || true")
    if "was not found" in plugins or "Syntax Error" in plugins:
        print(f"  creating plugin {PLUGIN}")
        b.bash(f"tmsh create ilx plugin {PLUGIN} from-workspace {WORKSPACE} "
               f"extensions {{ {EXTENSION} {{ concurrency-mode dedicated }} }}")
    else:
        print(f"  plugin {PLUGIN} exists — reloading from workspace")
        b.bash(f"tmsh modify ilx plugin {PLUGIN} from-workspace {WORKSPACE}")
    b.bash("tmsh save sys config")


def find_node(b: BigIP) -> str | None:
    for path in NODE_CANDIDATES:
        if "No such file" not in b.bash(f"ls {path} 2>&1"):
            return path
    found = b.bash("find /usr/lib/ilx /var/service -name node -type f 2>/dev/null | head -3")
    return found.strip().splitlines()[0] if found.strip() else None


def selftest(b: BigIP, remote_dir: str) -> int:
    ws_dir = f"/var/ilx/workspaces/Common/{WORKSPACE}/extensions/{EXTENSION}"

    print("\nruntime discovery:")
    node = find_node(b)
    if not node:
        print("  could not locate the ILX node binary; probed:")
        for c in NODE_CANDIDATES:
            print(f"    {c}")
        print("  Find it with:  find / -name node -path '*ilx*' 2>/dev/null")
        return 1
    print(f"  node binary : {node}")
    print(f"  version     : {b.bash(f'{node} --version 2>&1').strip()}")

    # Which user do the plugin's processes actually run as?
    owner = b.bash(
        "ps -eo user,args | grep -i 'ilx' | grep -v grep | awk '{print $1}' "
        "| sort -u | head -3"
    ).strip()
    print(f"  ilx proc user: {owner or '(no ILX processes running yet)'}")

    if owner and "root" not in owner:
        user = owner.splitlines()[0].strip()
        print(f"  chowning {remote_dir} to {user} so the plugin can read the keys")
        b.bash(f"chown -R {user} {remote_dir}")

    print("\nselftest (reads the keyring as the runtime sees it):")
    out = b.bash(f"cd {ws_dir} && JWE_KEYS_DIR={remote_dir} {node} index.js --selftest 2>&1")
    for line in out.strip().splitlines():
        print("  " + line)

    if "keyring err" in out or "(none)" in out:
        print("\n  SELFTEST FAILED — the plugin cannot read the keyring.")
        print("  Check ownership/permissions on", remote_dir)
        return 1

    caps = b.bash(f"cd {ws_dir} && {node} index.js --capabilities 2>&1")
    try:
        c = json.loads(caps)
        print(f"\n  profile C (RSA-OAEP-256) available: {c['profileC_rsa_oaep_sha256']}")
        if not c["profileC_rsa_oaep_sha256"]:
            print("  -> this runtime predates Node 12. Run the matrix with --profile B.")
    except ValueError:
        print("\n  could not parse --capabilities output:", caps[:200])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys-only", action="store_true")
    ap.add_argument("--selftest-only", action="store_true")
    args = ap.parse_args()

    load_dotenv(os.path.join(REPO, ".env"))
    host = os.environ.get("BIGIP_HOST", "").rstrip("/")
    pwd = os.environ.get("BIGIP_PASSWORD", "")
    if not host or not pwd:
        sys.exit("Set BIGIP_HOST and BIGIP_PASSWORD (see .env.example)")

    keys_dir = os.path.abspath(os.environ.get("JWE_KEYS_DIR", os.path.join(REPO, "keys")))
    remote_dir = os.environ.get("BIGIP_KEYS_DIR", "/config/jwe/keys")

    print(f"connecting to {host} ...")
    b = BigIP(host, os.environ.get("BIGIP_USERNAME", "admin"), pwd)

    if args.selftest_only:
        return selftest(b, remote_dir)

    check_provisioning(b)

    print(f"\ninstalling keyring -> {remote_dir}")
    kids = upload_keys(b, keys_dir, remote_dir)

    if not args.keys_only:
        print("\ndeploying ILX workspace")
        deploy_workspace(b)

    rc = selftest(b, remote_dir)

    print(f"\n{len(kids)} kid(s) installed: {', '.join(kids)}")
    if rc == 0:
        print("\nNEXT: python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json")
    return rc


if __name__ == "__main__":
    sys.exit(main())
