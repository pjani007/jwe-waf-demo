#!/usr/bin/env python3
"""
jwe_builder.py — construct RFC 7516 compact JWE tokens for the test matrix.

Uses jwcrypto rather than hand-rolling the sender side. That is deliberate: the
BIG-IP decryptor (bigip/ilx/.../index.js) is hand-written against the RFC with
zero dependencies, so pairing it with an INDEPENDENT implementation on the
sender side means agreement is real evidence of conformance rather than two
copies of the same misreading.

Key sources (produced by tools/keygen.py):
  keys/jwks.json           public RSA keys — profiles B and C
  keys/shared-secrets.json symmetric dir key — profile A (never publishable)
  keys/decoy-jwks.json     public key deliberately absent from the BIG-IP keyring
  keys/keyring.json        which kids the BIG-IP actually trusts

Usage as a CLI (handy for curl-driven runbook steps):
  python3 client/jwe_builder.py --profile C --payload '{"note":"hello"}'
  python3 client/jwe_builder.py --profile C --case sqli
  python3 client/jwe_builder.py --list-cases
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

try:
    from jwcrypto import jwe, jwk
    from jwcrypto.common import json_encode
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


DEFAULT_KEYS_DIR = os.environ.get("JWE_KEYS_DIR", "./keys")

# Profile -> the `alg` it exercises. The kid is resolved from the keyring by
# alg, so renaming kids in keygen.py does not break the builder.
PROFILE_ALG = {
    "A": "dir",
    "B": "RSA-OAEP",
    "C": "RSA-OAEP-256",
}

# Attack strings live here so cases.yaml and the CLI share one definition.
# These are the payloads whose visibility to the WAF the whole lab is about.
ATTACK_PAYLOADS = {
    "clean":     {"note": "ordinary order note", "qty": 2},
    "sqli":      {"note": "' OR 1=1--", "qty": 1},
    "sqli_union": {"note": "1' UNION SELECT username,password FROM users--", "qty": 1},
    "xss":       {"note": "<script>alert(document.cookie)</script>", "qty": 1},
    "cmdi":      {"note": "; cat /etc/passwd", "qty": 1},
    "traversal": {"note": "../../../../etc/passwd", "qty": 1},
}


def _read_json(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


class JweBuilder:
    """Builds compact JWE tokens against the lab's generated key material."""

    def __init__(self, keys_dir: str = DEFAULT_KEYS_DIR):
        self.keys_dir = os.path.abspath(keys_dir)
        missing = [
            n for n in ("keyring.json", "jwks.json", "shared-secrets.json", "decoy-jwks.json")
            if not os.path.exists(os.path.join(self.keys_dir, n))
        ]
        if missing:
            raise FileNotFoundError(
                f"missing {', '.join(missing)} in {self.keys_dir} — run tools/keygen.py first"
            )

        self.keyring = _read_json(os.path.join(self.keys_dir, "keyring.json"))["keys"]
        self.jwks = _read_json(os.path.join(self.keys_dir, "jwks.json"))["keys"]
        self.decoy = _read_json(os.path.join(self.keys_dir, "decoy-jwks.json"))["keys"]
        self.secrets = _read_json(os.path.join(self.keys_dir, "shared-secrets.json"))["keys"]

    # ── key lookup ──────────────────────────────────────────────────────────

    def trusted_kid_for(self, alg: str) -> str:
        for entry in self.keyring:
            if entry["alg"] == alg:
                return entry["kid"]
        raise KeyError(f"no trusted kid in keyring.json with alg={alg}")

    def _encryption_key(self, kid: str, alg: str) -> jwk.JWK:
        """The key the SENDER encrypts with: public RSA, or the shared dir secret."""
        if alg == "dir":
            sec = self.secrets.get(kid)
            if sec is None:
                raise KeyError(f"no shared secret for kid {kid}")
            return jwk.JWK(kty="oct", k=sec["k"])

        for candidate in (self.jwks, self.decoy):
            for j in candidate:
                if j["kid"] == kid:
                    return jwk.JWK(**j)
        raise KeyError(f"no public key for kid {kid}")

    # ── construction ────────────────────────────────────────────────────────

    def build(
        self,
        payload: dict | str,
        profile: str = "C",
        kid: str | None = None,
        encrypt_to_kid: str | None = None,
        header_overrides: dict | None = None,
    ) -> str:
        """
        payload         dict (JSON-encoded) or a raw string
        profile         A | B | C  — selects alg
        kid             kid ADVERTISED in the protected header (default: trusted kid)
        encrypt_to_kid  kid whose key is actually USED (default: same as `kid`).
                        Differing from `kid` is how the 'right kid, wrong key
                        material' rejection path gets exercised.
        header_overrides merged last, so any field can be corrupted on purpose
        """
        if profile not in PROFILE_ALG:
            raise ValueError(f"unknown profile {profile!r}; expected one of {sorted(PROFILE_ALG)}")

        alg = PROFILE_ALG[profile]
        advertised_kid = kid or self.trusted_kid_for(alg)
        using_kid = encrypt_to_kid or advertised_kid

        header = {"alg": alg, "enc": "A256GCM", "kid": advertised_kid}
        if header_overrides:
            header.update(header_overrides)

        plaintext = payload if isinstance(payload, str) else json.dumps(payload)
        key = self._encryption_key(using_kid, header["alg"])

        token = jwe.JWE(plaintext.encode("utf-8"), json_encode(header))
        token.add_recipient(key)
        return token.serialize(compact=True)

    # ── negative-case constructors ──────────────────────────────────────────

    def build_case(self, case: str, profile: str = "C") -> str:
        """Build one named test case. See --list-cases for the catalogue."""
        alg = PROFILE_ALG[profile]

        if case in ATTACK_PAYLOADS:
            return self.build(ATTACK_PAYLOADS[case], profile=profile)

        if case == "unknown_kid":
            # Encrypt to a real key but ADVERTISE a kid the BIG-IP has never
            # heard of. Encrypting *to* the bogus kid is impossible (no such
            # key) and would only test the builder, not the decryptor.
            return self.build(ATTACK_PAYLOADS["clean"], profile=profile,
                              kid="jwe-does-not-exist",
                              encrypt_to_kid=self.trusted_kid_for(alg))

        if case == "wrong_key_material":
            # Claim a kid the BIG-IP trusts, but encrypt to the decoy key.
            # Must be an RSA profile — `dir` has no decoy counterpart.
            if alg == "dir":
                raise ValueError("wrong_key_material needs profile B or C")
            return self.build(ATTACK_PAYLOADS["clean"], profile=profile,
                              kid=self.trusted_kid_for(alg),
                              encrypt_to_kid=self.decoy[0]["kid"])

        if case == "alg_mismatch":
            # Encrypt with the symmetric dir key but advertise an RSA kid, so
            # header alg and the kid's bound alg disagree.
            rsa_kid = self.trusted_kid_for("RSA-OAEP-256")
            dir_kid = self.trusted_kid_for("dir")
            return self.build(ATTACK_PAYLOADS["clean"], profile="A",
                              kid=rsa_kid, encrypt_to_kid=dir_kid)

        if case == "tampered_tag":
            return tamper_tag(self.build(ATTACK_PAYLOADS["clean"], profile=profile))

        if case == "tampered_ciphertext":
            return tamper_ciphertext(self.build(ATTACK_PAYLOADS["clean"], profile=profile))

        if case == "malformed_jwe":
            return ".".join(self.build(ATTACK_PAYLOADS["clean"], profile=profile).split(".")[:4])

        if case == "oversize":
            # Just over the ILX::call 65 536-byte ceiling.
            filler = "A" * 70000
            return self.build({"note": "oversize probe", "blob": filler}, profile=profile)

        raise ValueError(f"unknown case {case!r}")


# ── token mutators ──────────────────────────────────────────────────────────
# Operate on the compact serialisation so the corruption is byte-exact and
# does not depend on jwcrypto internals.

def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _flip_last_byte(segment: str) -> str:
    raw = bytearray(_b64u_decode(segment))
    raw[-1] ^= 0x01
    return _b64u_encode(bytes(raw))


def tamper_tag(token: str) -> str:
    """Flip one bit of the GCM auth tag — must fail authentication."""
    p = token.split(".")
    p[4] = _flip_last_byte(p[4])
    return ".".join(p)


def tamper_ciphertext(token: str) -> str:
    """Flip one bit of the ciphertext — must fail authentication, not decrypt."""
    p = token.split(".")
    p[3] = _flip_last_byte(p[3])
    return ".".join(p)


ALL_CASES = (
    list(ATTACK_PAYLOADS)
    + ["unknown_kid", "wrong_key_material", "alg_mismatch", "tampered_tag",
       "tampered_ciphertext", "malformed_jwe", "oversize"]
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR)
    ap.add_argument("--profile", default="C", choices=sorted(PROFILE_ALG))
    ap.add_argument("--payload", help="raw JSON string to encrypt")
    ap.add_argument("--case", help="named test case (see --list-cases)")
    ap.add_argument("--list-cases", action="store_true")
    args = ap.parse_args()

    if args.list_cases:
        print("cases:")
        for c in ALL_CASES:
            kind = "payload" if c in ATTACK_PAYLOADS else "negative"
            print(f"  {c:22} ({kind})")
        return 0

    b = JweBuilder(args.keys_dir)

    if args.case:
        print(b.build_case(args.case, profile=args.profile))
    elif args.payload:
        print(b.build(json.loads(args.payload), profile=args.profile))
    else:
        print(b.build(ATTACK_PAYLOADS["clean"], profile=args.profile))
    return 0


if __name__ == "__main__":
    sys.exit(main())
