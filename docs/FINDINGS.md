# Findings

Observed facts only. Anything not yet executed is marked **OPEN** and stays that
way until something is run against it — a plausible answer is not a finding.

---

## ✅ VERIFIED — JWE decryptor conformance (2026-09-10)

Cross-implementation: sender is `jwcrypto` (third-party, via
`client/jwe_builder.py`), recipient is the hand-rolled zero-dependency
`bigip/ilx/.../index.js`. Agreement across two independent implementations is
the evidence; a single implementation agreeing with itself is not.

| Runtime | Result |
|---|---|
| Node 18.x (`node:18-alpine`) | **27 passed** |
| Node 8.17.0 (`node:8-alpine`) | **26 passed, 1 skipped** |

Reproduce:
```bash
pytest tests/ -q                                # modern runtime
NODE_IMAGE=node:8-alpine pytest tests/ -q       # old-runtime path
```

### Algorithm profile availability by runtime — RISK RETIRED

The plan flagged "TMOS ILX Node version is unverified" as a risk. It is now
bounded on both sides rather than guessed:

| Profile | `alg` / `enc` | Node 8.17.0 | Node 18.x |
|---|---|---|---|
| A | `dir` / A256GCM | ✅ | ✅ |
| B | `RSA-OAEP` / A256GCM | ✅ | ✅ |
| C | `RSA-OAEP-256` / A256GCM | ❌ | ✅ |

Node 8 reports `{"profileC_rsa_oaep_sha256": false}` from `--capabilities` and
returns `ERR|alg_unsupported_on_runtime|...` naming the required version —
**not** a generic decryption failure. So whatever TMOS 17.5's ILX runtime turns
out to be, the demo has a working path (A and B) and profile C fails
diagnostically rather than opaquely. Confirm the real version with
`tools/ilx_deploy.py`, which prints `process.version` from the actual plugin.

OpenSSL on Node 8 is 1.0.2s; AES-256-GCM and RSA-OAEP(SHA-1) are both present.

### Rejection reasons are asserted individually

Every negative case must fail for the *right* reason — a 400 from the wrong
cause would let a broken decryptor look correct:

| Case | Reason returned |
|---|---|
| unknown `kid` | `unknown_kid` |
| trusted `kid`, decoy key material | `unwrap_failed` |
| header `alg` ≠ the kid's bound alg | `alg_mismatch` |
| flipped GCM auth tag | `auth_failed` |
| flipped ciphertext bit | `auth_failed` |
| 4-segment token | `malformed_jwe` |
| empty / garbage input | `empty_token` / `malformed_jwe` / `bad_header` |

`unknown_kid` and `malformed_jwe` are resolved **before** any crypto runs, which
is why they pass even on a runtime that cannot do the token's algorithm.

---

## ✅ VERIFIED — UDF RPC corrections (2026-09-14)

Observed live against udf.f5.com. Both contradict the reference material, so
they are recorded here rather than trusted from docs.

**`CreateDeployment.purpose` enum is not what the reference says.** The server
returned:

```
ValidationError-child "purpose" fails because
  ["purpose" must be one of [customer, development, other, personaluse]]
```

Actual: `customer` `development` `other` `personaluse`.
Reference material claims: `solution` `customer` `education` `application` `other`.
`scheme: "solution"` was accepted in the same call, so the two fields do **not**
share an enum. `udf/build-deployment.js` now parses the allowed list out of a Joi
validation error and retries, preferring `other` (present in every observed
variant) — so a future drift self-corrects instead of halting the build.

**BIG-IP templates are named `BIGIP`, not `BIG-IP`.** The live HV3 catalogue
(100 templates) uses no hyphen and appends a build number:

```
BIGIP 15.1.10.8-0.0.30   BIGIP 16.1.6.1-0.0.11   BIGIP 17.1.3-0.0.11
BIGIP 17.5.1.3-0.0.19    BIGIP 21.0.0-0.0.10
```

Reference material writes these "BIG-IP 17.5.1.3", which matches nothing. The
resolver now uses `/^BIG-?IP\s+17\.5/i` — tolerant of both spellings, and
verified NOT to match `BIG-IQ 7.1.0.3-0.0.41`, which a looser pattern would.
`BIGIP 21.0.0` is deliberately excluded from the fallback chain: changing major
release should be an explicit decision, not something a regex does quietly.

Ubuntu names were correct as assumed: `Ubuntu 24.04 LTS Server` and
`Ubuntu 20.04 LTS Desktop`. Desktop exists only in 18.04 and 20.04 — confirming
that 22.04 Desktop, which the original plan specified, does not exist.

**`Search` requires a `target` parameter.** Calling `Search {query}` fails with
`child "target" fails because ["target" is required]`, and the accepted values
for `target` are unknown. The duplicate-name check uses `GetUserDeployments`
instead, which has verified parameters. Confirmed working: it listed 9 existing
deployments for the account.

Bug this exposed in our own script, worth noting because the failure direction
was backwards: the duplicate check threw on ANY error, so a guard whose only job
was to prevent accidental double-spend became the reason the lab would not build
at all. Convenience checks must warn and continue; only a genuine name clash
aborts.

## ✅ VERIFIED — UDF access methods do NOT proxy iControl REST (2026-09-14)

A scripted `POST /mgmt/shared/authn/login` to
`https://<dnsKey>.access.udf.f5.com` returns **401 with UDF's HTML login page**,
not BIG-IP JSON. UDF HTTPS access methods authenticate with the browser session
cookie (HttpOnly), so they cannot carry API calls from a script.

**Retraction.** An earlier entry here claimed the opposite. That conclusion came
from a `curl` that printed only `%{http_code}` and discarded the body: a bare
`401` was read as "BIG-IP rejected the password" when it actually meant "UDF
rejected the request". **A status code alone does not identify which hop
answered** — check the body, or the content type.

Working approaches:
- **SSH tunnel** — `ssh -p <sshPort> -N -L 8443:<mgmt-ip>:443 …`, then
  `BIGIP_HOST=https://127.0.0.1:8443`. SSH access methods are key-based and do
  work programmatically.
- **Run inside the deployment** — components share `10.1.1.0/24`, so the
  management plane is directly reachable there. Required anyway for
  `run_matrix.py`, because the `10.1.10.0/24` traffic subnet is not routable
  from outside.

All three tools now detect an HTML body and print both options instead of
dumping markup.

## ✅ VERIFIED — key hygiene

- Symmetric profile-A (`dir`) key is **absent** from `jwks.json`. Asserted in the
  suite and re-checked against the live `/.well-known/jwks.json` endpoint.
  Publishing it would hand every client the decryption key.
- Decoy key is provably **not** in `keyring.json`, so `wrong_key_material`
  cannot spuriously succeed.
- `keygen.py` is idempotent: a second run reports `0 created, 5 kept` and does
  not invalidate a keyring the BIG-IP already trusts.
- Private material lands `0600` in a `0700` directory.

## ✅ VERIFIED — backend as proof instrument

`POST /api/v1/echo` distinguishes the two states the whole lab turns on:

| Posted | `content_type` | `looks_like_undecrypted_jwe` | `body_parsed` |
|---|---|---|---|
| compact JWE (`application/jose`) | `application/jose` | `true` | `null` |
| decrypted JSON + iRule headers | `application/json` | `false` | parsed object |

`' OR 1=1--` arrives byte-exact after the round trip, so an attack the WAF is
meant to catch is not being mangled en route.

---

## Bugs found and fixed during verification

Recorded because each was silent, and two would have been expensive later.

1. **stdout truncated at exactly 65536 bytes.** `process.exit()` discards
   pending async writes to a pipe. Large plaintexts came back cut at the 64 KiB
   pipe buffer and failed base64 decoding as "Incorrect padding" — which reads
   as a base64 bug, not an exit bug. The 64 KiB buffer coincidentally matching
   the ILX 65 536-byte cap made it look like a transport limit. Fixed by setting
   `process.exitCode` and letting Node flush. CLI-only; ILX mode uses
   `res.reply()` and was never affected.
2. **Empty token fell through to usage text.** `argv[i+1]` is falsy for `''`, so
   an empty token — a legitimate input that must be rejected — was treated as a
   missing argument. Fixed with `!== undefined`.
3. **`unknown_kid` case was unbuildable.** It tried to *encrypt to* a
   nonexistent kid rather than encrypting to a real key while *advertising* a
   bogus one. The latter is also the realistic attack shape.
4. **Tests pinned to profile C** failed on Node 8 for a reason unrelated to
   what they assert. Added a `best_profile` fixture so rejection-logic and
   payload-fidelity tests use whatever the runtime supports.

---

## OPEN — requires the lab

Nothing below has been executed. No claims either way.

- **K000158872** (`HTTP::collect` + ASM payload inspection). The production path
  chains to a WAF-only VS to sidestep it; `vs_jwe_single` (`.43`) measures it.
  Record here: does an attack inside a JWE get blocked on the single VS?
- **Does ASM deep-inspect after the Content-Type rewrite?** Evidence says the
  JSON profile is selected by header value, so `application/jose` must be
  rewritten to `application/json`. Confirm a *parameter-level* violation, not
  just a generic one.
- **Real TMOS ILX Node version** on BIG-IP 17.5.1.3.
- **ILX plugin process owner** vs `0600` root-owned keys.
- **The blind spot itself** — the same attack must return 200 on `.41` and be
  blocked with a support ID on `.40`. This is the demo's central claim and is
  still unproven.
- **Oversize enforcement** lives in the iRule, not Node. Must be asserted
  against the VS.
