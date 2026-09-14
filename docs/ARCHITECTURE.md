# Architecture

## The problem

Advanced WAF inspects HTTP after TLS termination, which gives it full visibility
into transport-encrypted traffic. **Application-layer** encryption is different.
When the request body is a JWE, the payload is ciphertext *inside* an otherwise
ordinary HTTPS request. Attack signatures have nothing to match. SQLi or XSS
inside a JWE reaches the application untouched, and the WAF logs nothing —
because from its point of view nothing happened.

That is a blind spot, not a misconfiguration. Closing it means decrypting the
JWE on the BIG-IP *before* the WAF policy evaluates the payload.

## Why iRules LX and not native iRules

Native `CRYPTO::decrypt` / `CRYPTO::sign` / `CRYPTO::verify` do not implement
JWE. There is no TCL path to RSA-OAEP key unwrap plus AES-GCM content
decryption with the protected header as AAD. The documented approach is iRules
LX: a TCL iRule collects the body and hands it to a Node extension over
`ILX::call`.

**This build has zero npm dependencies.** `index.js` implements RFC 7516
compact decryption using only Node's built-in `crypto`. The usual advice is
`node-jose`, but that means an `npm install` on an appliance that may have no
route to the registry, and a dependency tree to audit. Roughly 120 lines of
hand-written crypto, cross-validated against `jwcrypto` on every commit, is the
better trade here.

## The two-VS chain

```
                    ┌──────────────────────────────────────────────┐
 JWE request        │ vs_jwe_ingress   10.1.10.40:443              │
 Content-Type:      │   clientssl, NO ASM policy                   │
 application/jose   │   irule_jwe_decrypt:                         │
───────────────────▶│     size guard  (65536 cap, BEFORE collect)  │
                    │     HTTP::collect                            │
                    │     ILX::call decrypt                        │
                    │     HTTP::payload replace  <plaintext>       │
                    │     Content-Type := application/json         │
                    │     virtual /jwe_lab/jwe_app/vs_waf_internal │
                    └───────────────────────┬──────────────────────┘
                                            ▼
                    ┌──────────────────────────────────────────────┐
                    │ vs_waf_internal  10.1.10.241:8080            │
                    │   ASM policy jwe-demo-policy                 │
                    │   sees an ordinary plaintext JSON POST       │
                    │   pool_api -> 10.1.10.20:8080                │
                    └──────────────────────────────────────────────┘
```

ASM could have gone on the ingress VS directly. It did not, for one reason:
[K000158872](https://my.f5.com/manage/s/article/K000158872) (Dec 2025) documents
an interaction between iRules using `HTTP::collect` and ASM payload inspection,
and the article is behind MyF5 auth. Rather than bet on which way it goes, the
chain keeps `HTTP::collect` out of ASM's flow entirely — ASM evaluates a clean
request on its own VS with no payload manipulation in sight.

Chaining uses the `virtual` iRule command, which is valid during ALL_EVENTS.
That is internal — no hairpin through the network, no SNAT or loopback
complications that a pool-member-pointing-at-a-VS arrangement would bring.

## Why four virtual servers

A single VS could demonstrate decryption. It could not demonstrate that
decryption *matters*, and it could not distinguish "the WAF blocked it" from
"the policy blocks everything".

| VS | Address | WAF | Decrypt | What it proves |
|---|---|---|---|---|
| `vs_jwe_ingress` → `vs_waf_internal` | `.40` → `.241` | ✅ | ✅ | **The fix.** Attack inside a JWE is blocked |
| `vs_jwe_blind` | `.41` | ✅ | ❌ | **The blind spot.** Same JWE, reaches the backend |
| `vs_plain_waf` | `.42` | ✅ | n/a | **The policy is armed.** Plaintext attack is blocked |
| `vs_jwe_single` | `.43` | ✅ | ✅ same VS | **Measures K000158872** |

`.41` and `.42` are what make the result falsifiable. Without `.41` the block on
`.40` proves only that a WAF exists. Without `.42`, a 200 on `.41` could be
explained by a dead policy rather than a blind spot.

## Content-Type rewriting — what it does and does not do

After decryption the iRule sets `Content-Type: application/json`, preserving the
original in `X-Original-Content-Type`.

Being precise about why, because it is easy to overstate: ASM attack signatures
scan the request body regardless of Content-Type, so raw signature matching can
fire on a plaintext body even under `application/jose`. The rewrite is required
for the **JSON content profile** to be selected, because profile selection is
header-based (matching e.g. `*json*`). Without it there is no JSON parsing, so
no parameter extraction, no parameter-level enforcement, and no JSON-specific
defences (max array length, structure depth). Leaving `application/jose` mapped
to a JSON profile instead produces *Malformed JSON data* — a block for the
wrong reason, which looks like success.

Which of these actually happens on 17.5 is an **OPEN** item in
[FINDINGS.md](FINDINGS.md); the lab is built to measure it.

## Failure modes are security decisions

`JWE_FAIL_MODE` governs what happens when a body cannot be decrypted:

- **`closed`** (default) — reject. Something that cannot be decrypted cannot be
  inspected, so forwarding it would defeat the control.
- **`open`** — forward undecrypted, logged at `local0.crit` as `JWE BYPASS`.
  Exists only so the matrix can demonstrate the difference.

The `65536`-byte ceiling is part of this. `ILX::call` cannot carry more, so the
size check runs **before** `HTTP::collect` — the decision is made deliberately
rather than discovered mid-call. Fail open on oversize and you have rebuilt the
bypass the whole design exists to close.

`reject` and `block` are reported separately throughout, because they are
different controls: `reject` is the decryptor refusing a request the WAF never
saw; `block` is ASM acting on inspected plaintext, evidenced by a support ID.

## PKI

RFC 7517 key management, no CA. See [the PKI section of the plan](../README.md#pki)
and `tools/keygen.py` for the reasoning; in short:

- The **BIG-IP is the recipient**, so it holds the private keys. The client
  encrypts with the public halves. This is the reverse of TLS server-cert
  intuition and of JWS, and is the most common JWE implementation error.
- A **keyring** keyed by `kid`, not a single key — which buys rotation with an
  overlap window, a genuine unknown-`kid` rejection path, and per-kid algorithm
  binding so a header cannot talk a key into an algorithm it was not issued for.
- Symmetric (profile A, `dir`) keys are **never** published in JWKS. Only the
  asymmetric public halves are servable.
- Reload is a 30-second mtime poll, so adding a kid needs no plugin restart.

## Algorithm profiles

| Profile | `alg` / `enc` | Requirement |
|---|---|---|
| A | `dir` / A256GCM | Any Node. Pre-shared secret, always works |
| B | `RSA-OAEP` / A256GCM | Default OAEP padding (SHA-1) |
| C | `RSA-OAEP-256` / A256GCM | `oaepHash`, Node ≥ 12 |

Three rather than one because the TMOS ILX Node version was unknown at design
time. Verified on Node 8.17 (A, B) and Node 18 (A, B, C) — see
[FINDINGS.md](FINDINGS.md). Profile C degrades with an explicit
`alg_unsupported_on_runtime`, never as a generic decryption failure.
