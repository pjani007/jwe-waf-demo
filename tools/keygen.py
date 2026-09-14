#!/usr/bin/env python3
"""
keygen.py — generate the JWE recipient keyring for the lab.

The BIG-IP is the JWE *recipient*, so it holds the PRIVATE keys; the test client
encrypts with the public halves. That direction is the reverse of TLS server-cert
intuition and of JWS, so the filenames say `recipient` throughout.

Emits, into --keys-dir (default ./keys):

  <kid>.pem / <kid>.key   private key material, mode 0600
  keyring.json            what ilx_deploy.py installs on the BIG-IP
  keyring.available.json  every generated kid, so keyring_push.py can promote one
  jwks.json               PUBLIC RSA keys — what a legitimate client fetches
  decoy-jwks.json         public half of keys deliberately NOT in the keyring
  shared-secrets.json     symmetric `dir` keys — NOT publishable, see note below

On `dir` and public-key distribution
------------------------------------
Profile A (alg=dir) is a *pre-shared symmetric secret*. It cannot be distributed
via a public JWKS, because publishing it would hand every client the decryption
key. It lives in shared-secrets.json for the lab client only. Profiles B and C
are asymmetric, so their public halves go in jwks.json and are safe to serve.
That asymmetry is the point worth showing, not an inconsistency.

Idempotent: existing key material is left alone unless --force is given, so
re-running never silently invalidates a keyring the BIG-IP already trusts.

Usage:
  python3 tools/keygen.py
  python3 tools/keygen.py --keys-dir ./keys --rsa-bits 3072
  python3 tools/keygen.py --force            # regenerate everything
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import stat
import sys
from datetime import datetime, timedelta, timezone

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
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


# kid -> spec. `in_keyring` False means the material exists on disk but the
# BIG-IP is never told about it — that is what makes the negative tests real.
KEY_SPECS = [
    # Profile A — works on every Node runtime, so the demo always has a path.
    {"kid": "jwe-dir-a",      "alg": "dir",          "enc": "A256GCM", "kind": "oct",
     "in_keyring": True,  "note": "profile A baseline; pre-shared secret"},

    # Profile B — default OAEP padding (SHA-1), works on old ILX Node.
    {"kid": "jwe-oaep-a",     "alg": "RSA-OAEP",     "enc": "A256GCM", "kind": "rsa",
     "in_keyring": True,  "note": "profile B; RSA-OAEP with SHA-1"},

    # Profile C — needs oaepHash, Node >= 12. Primary key for the demo.
    {"kid": "jwe-oaep256-a",  "alg": "RSA-OAEP-256", "enc": "A256GCM", "kind": "rsa",
     "in_keyring": True,  "note": "profile C primary"},

    # Rotation target. Generated now, promoted into the keyring by
    # keyring_push.py during the rotation runbook step.
    {"kid": "jwe-oaep256-b",  "alg": "RSA-OAEP-256", "enc": "A256GCM", "kind": "rsa",
     "in_keyring": False, "note": "rotation successor; promote with keyring_push.py"},

    # Decoy: the client can encrypt to this while CLAIMING a trusted kid, which
    # exercises the 'right kid, wrong key material' rejection path.
    {"kid": "decoy-oaep256",  "alg": "RSA-OAEP-256", "enc": "A256GCM", "kind": "rsa",
     "in_keyring": False, "note": "decoy; must never appear in keyring.json"},
]

VALIDITY_DAYS = 180


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_uint(n: int) -> str:
    """base64url of a big-endian unsigned int, per RFC 7518 §6.3."""
    length = (n.bit_length() + 7) // 8
    return b64u(n.to_bytes(length, "big"))


def write_private(path: str, data: str, force: bool) -> bool:
    """Write key material 0600. Returns True if written, False if kept."""
    if os.path.exists(path) and not force:
        return False
    with open(path, "w") as fh:
        fh.write(data)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return True


def key_filename(spec: dict) -> str:
    return f"{spec['kid']}.pem" if spec["kind"] == "rsa" else f"{spec['kid']}.key"


def load_or_create(spec: dict, keys_dir: str, rsa_bits: int, force: bool):
    """Returns (created: bool, public_jwk: dict | None, secret_b64u: str | None)."""
    path = os.path.join(keys_dir, key_filename(spec))

    if spec["kind"] == "oct":
        if os.path.exists(path) and not force:
            with open(path) as fh:
                return False, None, fh.read().strip()
        secret = b64u(secrets.token_bytes(32))          # 32 bytes = A256GCM CEK
        write_private(path, secret + "\n", force=True)
        return True, None, secret

    # RSA
    if os.path.exists(path) and not force:
        with open(path, "rb") as fh:
            priv = serialization.load_pem_private_key(fh.read(), password=None)
        created = False
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        write_private(path, pem, force=True)
        created = True

    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": spec["kid"],
        "use": "enc",
        "alg": spec["alg"],
        "n": b64u_uint(nums.n),
        "e": b64u_uint(nums.e),
    }
    return created, jwk, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys-dir", default=os.environ.get("JWE_KEYS_DIR", "./keys"))
    ap.add_argument("--rsa-bits", type=int, default=3072,
                    help="RSA modulus size (default 3072; 2048 is the floor)")
    ap.add_argument("--force", action="store_true",
                    help="regenerate existing key material (invalidates the deployed keyring)")
    args = ap.parse_args()

    if args.rsa_bits < 2048:
        return _fail("--rsa-bits must be at least 2048")

    keys_dir = os.path.abspath(args.keys_dir)
    os.makedirs(keys_dir, exist_ok=True)
    os.chmod(keys_dir, stat.S_IRWXU)  # 0700

    now = datetime.now(timezone.utc).replace(microsecond=0)
    generated = now.isoformat().replace("+00:00", "Z")
    not_after = (now + timedelta(days=VALIDITY_DAYS)).isoformat().replace("+00:00", "Z")

    keyring, available, jwks, decoy_jwks, secrets_out = [], [], [], [], {}
    created_count = kept_count = 0

    for spec in KEY_SPECS:
        created, jwk, secret = load_or_create(spec, keys_dir, args.rsa_bits, args.force)
        created_count += int(created)
        kept_count += int(not created)

        entry = {
            "kid": spec["kid"],
            "alg": spec["alg"],
            "enc": spec["enc"],
            "file": key_filename(spec),
            "status": "active",
            "not_after": not_after,
            "note": spec["note"],
        }
        available.append(entry)
        if spec["in_keyring"]:
            keyring.append(entry)

        if jwk is not None:
            target = decoy_jwks if spec["kid"].startswith("decoy-") else jwks
            target.append(jwk)
        if secret is not None:
            secrets_out[spec["kid"]] = {"alg": spec["alg"], "enc": spec["enc"], "k": secret}

        flag = "created" if created else "kept"
        print(f"  {flag:8} {spec['kid']:16} {spec['alg']:14} {spec['note']}")

    def dump(name: str, doc) -> None:
        p = os.path.join(keys_dir, name)
        with open(p, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        # keyring.json names key files but holds no secrets; shared-secrets.json does.
        if name == "shared-secrets.json":
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)

    dump("keyring.json", {"version": 1, "generated": generated, "keys": keyring})
    dump("keyring.available.json", {"version": 1, "keys": available})
    dump("jwks.json", {"keys": jwks})
    dump("decoy-jwks.json", {"keys": decoy_jwks})
    dump("shared-secrets.json", {
        "_warning": "Symmetric dir keys. NOT publishable — never serve these from JWKS.",
        "keys": secrets_out,
    })

    print(f"\n{created_count} created, {kept_count} kept  ->  {keys_dir}")
    print(f"keyring.json      : {len(keyring)} kid(s) for the BIG-IP: "
          f"{', '.join(k['kid'] for k in keyring)}")
    print(f"jwks.json         : {len(jwks)} public RSA key(s), safe to serve")
    print(f"decoy-jwks.json   : {len(decoy_jwks)} key(s) deliberately NOT trusted")
    print(f"shared-secrets.json: {len(secrets_out)} symmetric key(s), lab-only")
    if not args.force and kept_count:
        print("\n(existing material kept; --force to regenerate)")
    return 0


def _fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
