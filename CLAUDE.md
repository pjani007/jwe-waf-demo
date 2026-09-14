# JWE Decryption for WAF Inspection — project instructions

## Goal
A runnable F5 UDF lab proving that Advanced WAF cannot inspect JWE-encrypted
request bodies, then closing that gap by decrypting on the BIG-IP before the
WAF policy evaluates the payload. It is a **test framework**, not slideware:
every claim is asserted by a case with an expected outcome.

## Non-negotiables

- **Separate verified from assumed.** `docs/FINDINGS.md` has ✅ VERIFIED and
  OPEN sections. Never move something to VERIFIED without having executed it.
  A plausible answer is not a finding.
- **`reject` ≠ `block`.** 4xx from the decryptor and 403-with-support-ID from
  ASM are different controls. Never collapse them.
- **Fail closed by default.** Anything that cannot be decrypted cannot be
  inspected. `JWE_FAIL_MODE=open` exists only to demonstrate the bypass, and
  logs `JWE BYPASS` at `local0.crit`.
- **Zero npm dependencies in the ILX extension.** Node built-ins only. If a
  dependency seems necessary, say why rather than adding it quietly.
- **Cross-validate the crypto.** The sender uses `jwcrypto`; the recipient is
  hand-rolled. Two independent implementations agreeing is the evidence. Never
  make both sides share an implementation.
- **Run the tests on two Node versions.** `pytest tests/ -q` and
  `NODE_IMAGE=node:8-alpine pytest tests/ -q`. The old-runtime path is a real
  supported configuration, not a curiosity.
- **Single source of truth for BIG-IP config.** iRules live in `bigip/irules/*.tcl`
  and the WAF policy in `bigip/waf/*.json`; `as3_submit.py` injects them. Never
  paste base64 into the AS3 declaration.
- **Idempotency.** `keygen.py` must not silently invalidate a deployed keyring;
  re-running any tool must not churn.

## Coupled values — change together or the chain breaks silently
- `static::JWE_WAF_VS` in `jwe_decrypt.tcl` **must** match the AS3
  tenant/application path (`/jwe_lab/jwe_app/vs_waf_internal`).
- `JWE_MAX_PAYLOAD` (65536) is the `ILX::call` transport cap. Not tunable upward.
- Keyring `alg` per kid is binding: a header advertising a different `alg` is
  rejected as `alg_mismatch`, deliberately.

## UDF specifics
- No REST API. Control plane is JSON-RPC over a Primus WebSocket, gated by an
  **HttpOnly** session cookie — it only works from an authenticated browser tab.
- `autostopDuration` is **MINUTES** despite the UI saying hours.
  `ExtendDeployment` is denied to ordinary users over RPC.
- `StartDeployment` requires `HV3InstanceType` even though it is stored.
- `DeleteDeployment` takes `id`, not `deploymentId`. No confirm, no undo.
- Binding an interface does **not** configure it in the guest OS; there is no
  DHCP on traffic subnets.
- Resolve component templates by **pattern with fallbacks** — names drift, and
  Ubuntu Desktop images are 18.04/20.04 only.

## Quality bar
- No hand-waving on crypto. Every algorithm choice has a documented reason and
  a test.
- Every rejection path asserts its specific reason, not just "it failed".
- Where a claim is uncertain, build the thing that measures it (`vs_jwe_single`)
  rather than asserting either answer.
- Attack payloads must survive decryption byte-exact, or the WAF is inspecting
  something other than what was sent.
