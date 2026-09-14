# JWE Decryption for WAF Inspection — F5 UDF Demo Framework

A runnable F5 lab that **proves an Advanced WAF blind spot exists**, then closes
it — with a test matrix that fails loudly if either half regresses.

## The problem in one paragraph

Advanced WAF inspects HTTP after TLS termination, so transport encryption is not
an obstacle. **Application-layer** encryption is. When an API accepts
JWE-encrypted request bodies, the payload is ciphertext inside an otherwise
normal HTTPS request: attack signatures have nothing to match, and SQLi or XSS
inside a JWE reaches the application while the WAF logs nothing. The fix is to
decrypt the JWE on the BIG-IP *before* the WAF policy evaluates the body.

## The central claim

One row of the matrix carries the whole thing:

```
case    chain (decrypt→WAF)          blind (WAF only)
sqli    ✓ block #1844674407          ✓ allow (cipher)
```

**Identical ciphertext. Identical policy. Opposite outcomes.** `(cipher)` is the
backend reporting that it received an undecrypted JWE — the blind spot stated by
the origin, not inferred from a status code.

## Topology

| VS | Address | WAF | Decrypt | Proves |
|---|---|---|---|---|
| `vs_jwe_ingress` → `vs_waf_internal` | `.40` → `.241` | ✅ | ✅ | **The fix** |
| `vs_jwe_blind` | `.41` | ✅ | ❌ | **The blind spot** |
| `vs_plain_waf` | `.42` | ✅ | n/a | **The policy is armed** |
| `vs_jwe_single` | `.43` | ✅ | ✅ same VS | Measures [K000158872](https://my.f5.com/manage/s/article/K000158872) |

`.41` and `.42` are what make the result falsifiable. Without `.41`, a block on
`.40` proves only that a WAF exists. Without `.42`, a 200 on `.41` could be a
dead policy rather than a blind spot.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate                   # <- every command below assumes this
python3 -m pip install -r requirements.txt   # `pip` alone is often not on PATH
cp .env.example .env

python3 tools/keygen.py                      # keyring, PEMs, JWKS
pytest tests/ -q                             # 27 passed — no BIG-IP needed
```

> **`Missing dependency: pip install -r requirements.txt`** means the venv is not
> active, so the system `python3` cannot see the packages. Either
> `source .venv/bin/activate`, or skip activation and call the interpreter
> directly: `./.venv/bin/python tools/keygen.py`.

Then follow [docs/RUNBOOK.md](docs/RUNBOOK.md) to build the UDF lab and run
`client/run_matrix.py --all`.

## What is verified vs assumed

Verification is separated from intent on purpose — see
[docs/FINDINGS.md](docs/FINDINGS.md).

**✅ Verified by execution:** JWE conformance cross-checked against `jwcrypto` on
Node 18 (27 passed) and Node 8.17 (26 passed, 1 skipped); every rejection
asserted for its specific reason; key hygiene (no symmetric key in JWKS, decoy
provably untrusted); backend correctly distinguishing plaintext from ciphertext.

**⏳ Open until the lab runs:** whether ASM deep-inspects after the Content-Type
rewrite; the K000158872 single-VS behaviour; the real TMOS ILX Node version; and
the central claim itself.

## Design decisions worth knowing

- **Zero npm dependencies.** `index.js` implements RFC 7516 with Node built-ins.
  The usual advice is `node-jose`, but that means `npm install` on an appliance
  and a dependency tree to audit. Cross-validated against `jwcrypto` instead.
- **Two-VS chain, not one.** Keeps `HTTP::collect` out of ASM's flow, sidestepping
  K000158872 rather than betting on it. `.43` measures it anyway.
- **`reject` ≠ `block`.** A 4xx from the decryptor and a 403 from ASM are
  different controls; collapsing them hides which one fired.
- **iRules and WAF policy are injected at submit time** from `.tcl`/`.json`
  sources, so no stale base64 can drift out of sync.
- **The BIG-IP holds the private keys** — it is the JWE *recipient*. Reverse of
  TLS server-cert intuition, and the most common JWE implementation error.

## Layout

```
udf/          build-deployment.js, teardown.js, userdata/     (JSON-RPC, no REST API)
bigip/
  irules/     jwe_decrypt.tcl (production), jwe_single.tcl (experiment)
  ilx/        zero-dependency RFC 7516 decryptor
  as3/        AS3 declaration with __PLACEHOLDER__ injection
  waf/        declarative WAF policy
  provision.sh
backend/      FastAPI origin — deliberately trusting, and the proof instrument
client/       jwe_builder.py, cases.yaml, run_matrix.py
tools/        keygen, ilx_deploy, as3_submit, keyring_push, asm_events
tests/        offline conformance, no lab required
docs/         ARCHITECTURE, RUNBOOK, FINDINGS, LIMITATIONS
```

## Honest limits

The `enc` is A256GCM only; `ECDH-ES` is not implemented; payloads are capped at
65 536 bytes by `ILX::call`; private keys sit in `/config` outside the secure
vault; there is no rate limiting, so JWE decryption on the data path is an
untested amplification vector. Full list in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md).
