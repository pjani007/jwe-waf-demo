#!/usr/bin/env python3
"""
keyring_push.py — manage which kids the BIG-IP trusts, without touching AS3,
the iRule, or the plugin.

This is what makes rotation a live demo rather than a slide. The decryptor
re-reads keyring.json on a 30-second mtime poll, so adding or removing a kid
needs no plugin restart and no VS bounce.

  --list                      show local vs installed kids
  --add <kid>                 promote a kid from keyring.available.json
  --retire <kid>              mark retiring (still accepted; stops being advertised)
  --remove <kid>              drop from the keyring and delete the key file
  --push                      re-upload the current local keyring

Rotation runbook (docs/RUNBOOK.md has the full narrative):
  keyring_push.py --add jwe-oaep256-b        # overlap: both kids accepted
  run_matrix.py --case clean                 # still passing
  keyring_push.py --retire jwe-oaep256-a
  keyring_push.py --remove jwe-oaep256-a     # old kid now rejected
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ilx_deploy import BigIP, load_dotenv  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def write(path: str, doc: dict) -> None:
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--add", metavar="KID")
    g.add_argument("--retire", metavar="KID")
    g.add_argument("--remove", metavar="KID")
    g.add_argument("--push", action="store_true")
    args = ap.parse_args()

    load_dotenv(os.path.join(REPO, ".env"))
    keys_dir = os.path.abspath(os.environ.get("JWE_KEYS_DIR", os.path.join(REPO, "keys")))
    remote_dir = os.environ.get("BIGIP_KEYS_DIR", "/config/jwe/keys")

    kr_path = os.path.join(keys_dir, "keyring.json")
    av_path = os.path.join(keys_dir, "keyring.available.json")
    keyring = read(kr_path)
    available = read(av_path)["keys"]
    by_kid = {e["kid"]: e for e in keyring["keys"]}

    def connect() -> BigIP:
        host = os.environ.get("BIGIP_HOST", "").rstrip("/")
        pwd = os.environ.get("BIGIP_PASSWORD", "")
        if not host or not pwd:
            sys.exit("Set BIGIP_HOST and BIGIP_PASSWORD (see .env.example)")
        return BigIP(host, os.environ.get("BIGIP_USERNAME", "admin"), pwd)

    if args.list:
        print(f"local keyring ({kr_path}):")
        for e in keyring["keys"]:
            print(f"  {e['kid']:16} {e['alg']:14} [{e['status']}]")
        print("\navailable but NOT in the keyring:")
        for e in available:
            if e["kid"] not in by_kid:
                tag = " (decoy — must never be installed)" if e["kid"].startswith("decoy-") else ""
                print(f"  {e['kid']:16} {e['alg']:14}{tag}")
        try:
            b = connect()
            print(f"\ninstalled on BIG-IP ({remote_dir}):")
            print("  " + (b.bash(f"ls -1 {remote_dir} 2>&1").strip().replace("\n", "\n  ")))
        except SystemExit:
            print("\n(BIG-IP not configured; local view only)")
        return 0

    if args.add:
        if args.add.startswith("decoy-"):
            sys.exit("refusing to install a decoy key — it exists to be UNtrusted")
        if args.add in by_kid:
            print(f"{args.add} already in the keyring")
            return 0
        entry = next((e for e in available if e["kid"] == args.add), None)
        if not entry:
            sys.exit(f"{args.add} not in keyring.available.json — run tools/keygen.py")
        keyring["keys"].append({**entry, "status": "active"})
        write(kr_path, keyring)
        print(f"added {args.add} locally; pushing...")

    elif args.retire:
        if args.retire not in by_kid:
            sys.exit(f"{args.retire} is not in the keyring")
        by_kid[args.retire]["status"] = "retiring"
        write(kr_path, keyring)
        print(f"{args.retire} -> retiring (still accepted, no longer advertised)")

    elif args.remove:
        if args.remove not in by_kid:
            sys.exit(f"{args.remove} is not in the keyring")
        fname = by_kid[args.remove]["file"]
        keyring["keys"] = [e for e in keyring["keys"] if e["kid"] != args.remove]
        write(kr_path, keyring)
        b = connect()
        b.bash(f"rm -f {remote_dir}/{fname}")
        print(f"removed {args.remove} and deleted {fname} from the BIG-IP")

    b = connect()
    b.bash(f"mkdir -p {remote_dir} && chmod 700 {remote_dir}")
    b.put_file(f"{remote_dir}/keyring.json", json.dumps(keyring, indent=2))

    # Any newly-referenced key file must be present before the poll picks it up,
    # or the kid resolves to a 'key file unreadable' entry.
    for e in keyring["keys"]:
        local = os.path.join(keys_dir, e["file"])
        if os.path.exists(local):
            with open(local) as fh:
                b.put_file(f"{remote_dir}/{e['file']}", fh.read())
            b.bash(f"chmod 600 {remote_dir}/{e['file']}")

    print(f"pushed {len(keyring['keys'])} kid(s): "
          f"{', '.join(e['kid'] for e in keyring['keys'])}")
    print("the plugin re-reads keyring.json within 30s — no restart needed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
