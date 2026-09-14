# Limitations and known gaps

Written to be believed, so it includes the things that are inconvenient.

## Protocol and algorithm coverage

- **`enc` is A256GCM only.** No `A128CBC-HS256`, `A192GCM`, or `A128GCM`. Adding
  one means a branch in `decryptContent()`; AES-CBC-HMAC also needs the
  MAC-then-decrypt ordering of RFC 7518 §5.2, which is not implemented.
- **`alg` is `dir`, `RSA-OAEP`, `RSA-OAEP-256`.** No `ECDH-ES` (increasingly the
  modern default), no `A128KW`/`A256KW`, no `PBES2`.
- **Compact serialisation only.** JSON and flattened JSON serialisations are
  rejected as `malformed_jwe`.
- **Single recipient.** Multi-recipient JWE is out of scope.
- **No JWS verification.** A nested JWT (JWS inside JWE) is decrypted but its
  signature is not checked. Payload inspection is the goal here, not token
  authentication — that is APM's job.
- **`x5t#S256` is parsed, never validated.** No chain building, no CA. This is
  the deliberate PKI choice, not an oversight.

## Transport and size

- **65 536-byte ceiling**, imposed by `ILX::call`. Not tunable. Larger bodies are
  rejected (fail-closed) or forwarded undecrypted (fail-open, logged as
  `JWE BYPASS`). ILX *streaming* would lift this and is a genuine future
  direction; it is a different programming model, not a config change.
- **Chunked bodies are rejected** with 411. Without `Content-Length` the size
  guard cannot run, and collecting an unbounded body is precisely how this
  becomes a bypass.
- **`Content-Length` after replace** is computed with TCL `string length`, which
  counts characters. Multi-byte UTF-8 in a decrypted payload could produce a
  length mismatch. Not observed; not proven absent.

## Key management

- **Private keys live in `/config/jwe/keys` as plain PEM.** Persistent across
  reboots and trivially readable from Node, but **not** in the secure vault,
  **not** in a UCS archive unless you add a custom file list, and **not**
  HA-synced. Fine for a single-device lab; production belongs in the BIG-IP
  crypto store or an external KMS/HSM.
- **No revocation beyond removal.** `status: revoked` is honoured, but there is
  no CRL/OCSP concept — JWE has none.
- **Rotation has a 30-second window.** A kid added to `keyring.json` is not live
  until the mtime poll fires. Adding a key file *after* the keyring references it
  yields `key_unusable` until the next poll.
- **`not_after` is enforced by this decryptor**, not by the JWE spec. Do not
  expect other JWE implementations to reject an expired kid.

## Lab and platform

- **Single BIG-IP.** No HA, no config-sync. The ILX workspace and
  `/config/jwe/keys` would both need attention in a pair.
- **Default `/Common/clientssl`** is used for TLS, so clients see a self-signed
  certificate and every tool runs with verification disabled. Deliberate: a lab
  TLS PKI would obscure the JWE PKI, which is the actual subject.
- **UDF autostop is in MINUTES** despite the UI saying hours, and
  `ExtendDeployment` is denied to ordinary users over RPC. Use the UI's EXTEND
  button.
- **`Ubuntu 22.04 Desktop` does not exist** in the UDF catalogue — Desktop images
  are 18.04/20.04, 22.04+ is Server-only. `build-deployment.js` resolves
  templates by pattern with fallbacks and prints candidates on a miss.
- **iRules LX is deprecated in BIG-IP Next (v20.0.1+).** It is supported on the
  TMOS line this lab targets, including 17.5 and 21.x. If this ever needs to run
  on BIG-IP Next, the decryption approach must change.

## Things that could invalidate a result

- **AS3 `WAF_Policy.policy` inline** — the field name for an inline declarative
  policy has varied across AS3 versions. If submission fails on schema, the
  fallback is to import the policy via
  `/mgmt/tm/asm/tasks/import-policy` and reference it by name with `bigip:`.
  `as3_submit.py` prints a pointer here on failure.
- **`TRAFFIC_IF=1.1`** in `provision.sh` is an assumption about which NIC TMOS
  presents. Verify with `tmsh show net interface`.
- **ILX Node binary path** is probed across four candidates; if none matches,
  `ilx_deploy.py` says so rather than guessing.
- **ASM request-log REST endpoint** has moved between versions.
  `asm_events.py` tries candidates and falls back to naming the GUI path.
  Support-ID extraction in `run_matrix.py` does not depend on it — that comes
  from ASM's blocking page, which is synchronous and version-stable.
- **"Trigger ASM iRule Events" is NOT required.** It gates `ASM_REQUEST_*` iRule
  events, which this lab does not use. An earlier draft listed it as a
  prerequisite; that was wrong.

## Out of scope

- Re-encrypting to the origin (backend receives plaintext).
- Response-body JWE encryption.
- APM / OAuth / OIDC token handling.
- DoS resistance. Decryption is CPU work on the data path and this lab does no
  rate limiting; a flood of large JWEs is an amplification vector worth testing
  before anything like this goes near production.
