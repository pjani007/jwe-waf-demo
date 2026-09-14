#!/usr/bin/env python3
"""
Offline conformance tests — no BIG-IP, no lab, no network.

Two independent implementations are pitted against each other:

  sender    client/jwe_builder.py           -> jwcrypto (third-party)
  recipient bigip/ilx/.../index.js          -> hand-rolled, zero-dependency Node

Agreement between them is meaningful evidence of RFC 7516 conformance. If both
were mine, a shared misreading would pass silently.

The Node half needs a runtime. Resolution order:
  1. `node` on PATH
  2. `docker run node:<tag>`  (also lets us test OLD Node, which is the point —
     the TMOS ILX runtime version is unverified, see docs/LIMITATIONS.md)
Neither available -> those tests SKIP with a message. They never silently pass.

  pytest tests/ -v
  NODE_IMAGE=node:8-alpine pytest tests/ -v      # prove the old-runtime path
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "client"))

from jwe_builder import (  # noqa: E402
    ATTACK_PAYLOADS,
    JweBuilder,
    PROFILE_ALG,
    tamper_ciphertext,
    tamper_tag,
)

KEYS_DIR = os.path.join(REPO, "keys")
EXT_DIR = os.path.join(REPO, "bigip", "ilx", "jwe_decrypt_ws", "extensions", "jwe_decrypt")
INDEX_JS = os.path.join(EXT_DIR, "index.js")
NODE_IMAGE = os.environ.get("NODE_IMAGE", "node:18-alpine")


# ── Node runtime discovery ──────────────────────────────────────────────────

def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _runner():
    """Returns (kind, callable(args) -> CompletedProcess) or (None, None)."""
    if shutil.which("node"):
        def run_local(args):
            return subprocess.run(
                ["node", INDEX_JS] + args,
                capture_output=True, text=True, timeout=60,
                env={**os.environ, "JWE_KEYS_DIR": KEYS_DIR},
            )
        return "local node", run_local

    if _docker_usable():
        def run_docker(args):
            return subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{EXT_DIR}:/app:ro",
                 "-v", f"{KEYS_DIR}:/keys:ro",
                 "-e", "JWE_KEYS_DIR=/keys",
                 NODE_IMAGE, "node", "/app/index.js"] + args,
                capture_output=True, text=True, timeout=180,
            )
        return f"docker {NODE_IMAGE}", run_docker

    return None, None


RUNNER_KIND, RUN_NODE = _runner()

needs_node = pytest.mark.skipif(
    RUN_NODE is None,
    reason="no Node runtime: install node, or start Docker "
           "(`! open -a Docker`) so the ILX decryptor can be executed",
)


@pytest.fixture(scope="session")
def builder():
    if not os.path.exists(os.path.join(KEYS_DIR, "keyring.json")):
        pytest.skip("run tools/keygen.py first")
    return JweBuilder(KEYS_DIR)


@pytest.fixture(scope="session")
def best_profile():
    """
    The strongest asymmetric profile THIS runtime can actually decrypt.

    Tests about rejection logic or payload fidelity are not tests about
    RSA-OAEP-256, so pinning them to profile C would make them fail on an old
    ILX runtime for a reason unrelated to what they assert. Profile C where
    available, otherwise B.
    """
    if RUN_NODE is None:
        return "C"
    try:
        caps = json.loads(RUN_NODE(["--capabilities"]).stdout)
    except (ValueError, OSError):
        return "C"
    return "C" if caps.get("profileC_rsa_oaep_sha256") else "B"


def decrypt_via_node(token: str):
    """Returns (status, field2, field3) from the pipe-delimited ILX wire format."""
    proc = RUN_NODE(["--decrypt", token])
    out = (proc.stdout or "").strip()
    if not out:
        raise AssertionError(f"no stdout from node; stderr={proc.stderr!r}")
    parts = out.split("|", 2)
    while len(parts) < 3:
        parts.append("")
    return parts[0], parts[1], parts[2]


# ── Sender-side tests (always run) ──────────────────────────────────────────

@pytest.mark.parametrize("profile", sorted(PROFILE_ALG))
def test_builder_emits_five_segment_compact_jwe(builder, profile):
    token = builder.build(ATTACK_PAYLOADS["clean"], profile=profile)
    assert token.count(".") == 4, "compact JWE must have exactly 5 segments"


@pytest.mark.parametrize("profile", sorted(PROFILE_ALG))
def test_protected_header_binds_alg_enc_kid(builder, profile):
    token = builder.build(ATTACK_PAYLOADS["clean"], profile=profile)
    seg = token.split(".")[0]
    hdr = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    assert hdr["alg"] == PROFILE_ALG[profile]
    assert hdr["enc"] == "A256GCM"
    assert hdr["kid"] == builder.trusted_kid_for(PROFILE_ALG[profile])


def test_dir_key_is_absent_from_public_jwks(builder):
    """A symmetric dir key in a published JWKS would leak the secret."""
    published = {j["kid"] for j in builder.jwks}
    assert "jwe-dir-a" not in published
    assert all(j["kty"] == "RSA" for j in builder.jwks)


def test_decoy_key_is_not_in_the_trusted_keyring(builder):
    """Otherwise the wrong-key-material case would spuriously succeed."""
    trusted = {e["kid"] for e in builder.keyring}
    for j in builder.decoy:
        assert j["kid"] not in trusted


def test_tamper_helpers_change_exactly_one_segment(builder):
    orig = builder.build(ATTACK_PAYLOADS["clean"], profile="C")
    for mutate, idx in ((tamper_tag, 4), (tamper_ciphertext, 3)):
        got = mutate(orig).split(".")
        want = orig.split(".")
        differing = [i for i in range(5) if got[i] != want[i]]
        assert differing == [idx], f"{mutate.__name__} touched segments {differing}"


# ── Cross-implementation tests (need Node) ──────────────────────────────────

@needs_node
@pytest.mark.parametrize("profile", sorted(PROFILE_ALG))
def test_node_decrypts_every_profile(builder, profile):
    """The core claim: jwcrypto's output is readable by the ILX decryptor."""
    payload = ATTACK_PAYLOADS["clean"]
    token = builder.build(payload, profile=profile)
    status, kid, b64 = decrypt_via_node(token)

    if status == "ERR" and kid == "alg_unsupported_on_runtime":
        pytest.skip(f"profile {profile} unsupported on this runtime ({RUNNER_KIND}): {b64}")

    assert status == "OK", f"profile {profile} failed: {kid} {b64}"
    assert kid == builder.trusted_kid_for(PROFILE_ALG[profile])
    assert json.loads(base64.b64decode(b64).decode()) == payload


@needs_node
@pytest.mark.parametrize("case", sorted(ATTACK_PAYLOADS))
def test_attack_payloads_decrypt_intact(builder, best_profile, case):
    """
    Attack strings must survive decryption BYTE-EXACT. If the decryptor mangled
    them, the WAF would inspect something other than what the attacker sent —
    and the demo would prove nothing.
    """
    token = builder.build(ATTACK_PAYLOADS[case], profile=best_profile)
    status, _kid, b64 = decrypt_via_node(token)
    assert status == "OK", f"{case}: {b64}"
    assert json.loads(base64.b64decode(b64).decode()) == ATTACK_PAYLOADS[case]


@needs_node
@pytest.mark.parametrize("case,expected_err", [
    ("unknown_kid",         "unknown_kid"),
    ("wrong_key_material",  "unwrap_failed"),
    ("alg_mismatch",        "alg_mismatch"),
    ("tampered_tag",        "auth_failed"),
    ("tampered_ciphertext", "auth_failed"),
    ("malformed_jwe",       "malformed_jwe"),
])
def test_negative_cases_are_rejected_for_the_right_reason(builder, best_profile, case, expected_err):
    """A rejection for the wrong reason is a failing test, not a pass."""
    token = builder.build_case(case, profile=best_profile)
    status, err, detail = decrypt_via_node(token)
    assert status == "ERR", f"{case} should have been rejected, got {status}"
    assert err == expected_err, f"{case}: expected {expected_err}, got {err} ({detail})"


@needs_node
def test_empty_and_garbage_input_fail_closed(builder):
    for bad in ("", "not-a-jwe", "a.b.c", "....."):
        status, err, _ = decrypt_via_node(bad)
        assert status == "ERR", f"{bad!r} must be rejected"
        assert err in {"empty_token", "malformed_jwe", "bad_header"}, f"{bad!r} -> {err}"


@needs_node
def test_oversize_decrypts_here_because_the_cap_lives_in_the_irule(builder, best_profile):
    """
    Documents an enforcement boundary that is easy to misplace. Node has no
    payload ceiling; the 65 536-byte limit is the ILX::call transport cap and is
    enforced in bigip/irules/jwe_decrypt.tcl BEFORE the call is made. So the
    oversize case must be asserted against the VS, not here.
    """
    token = builder.build_case("oversize", profile=best_profile)
    assert len(token) > 65536
    status, _kid, b64 = decrypt_via_node(token)
    assert status == "OK", "Node itself imposes no size limit"
    assert json.loads(base64.b64decode(b64).decode())["note"] == "oversize probe"


@needs_node
def test_runtime_capabilities_are_reported(builder):
    proc = RUN_NODE(["--capabilities"])
    caps = json.loads(proc.stdout)
    assert caps["profileA_dir"] is True
    assert caps["profileB_rsa_oaep_sha1"] is True
    assert isinstance(caps["profileC_rsa_oaep_sha256"], bool)
    print(f"\nruntime: {RUNNER_KIND}, node {caps['node']}, "
          f"profile C available: {caps['profileC_rsa_oaep_sha256']}")
