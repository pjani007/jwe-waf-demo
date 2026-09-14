# Runbook

## 0. Prerequisites

```bash
python3 -m venv .venv
source .venv/bin/activate                    # <- EVERY command in this runbook assumes this
python3 -m pip install -r requirements.txt    # `pip` alone is often not on PATH
cp .env.example .env                          # then edit
```

**If you see `Missing dependency: pip install -r requirements.txt`**, the venv is
not active and the system `python3` cannot see the packages. Either re-run
`source .venv/bin/activate`, or drop activation entirely and call the
interpreter directly — every command below also works as:

```bash
./.venv/bin/python tools/keygen.py
./.venv/bin/python -m pytest tests/ -q
```

A Node runtime is needed only for the offline tests. Docker is enough:
`open -a Docker`.

## 1. Offline first — never build a lab to find a crypto bug

```bash
python3 tools/keygen.py
pytest tests/ -q                              # expect: 27 passed
NODE_IMAGE=node:8-alpine pytest tests/ -q     # expect: 26 passed, 1 skipped
```

The Node 8 run matters: it proves profiles A and B work on an old ILX runtime
and that profile C degrades with an explicit reason. If you skip it and the real
BIG-IP turns out to run old Node, you will debug it as a key problem.

## 2. Build the UDF lab

1. Log in to <https://udf.f5.com> in **Chrome**.
2. DevTools → Console → paste `udf/build-deployment.js`.
3. `await buildJweLab()`

It prints the deployment id, the `dnsKey` (the access hostname — **not** the
id), and the access methods. Autostop is 480 **minutes**.

Then put the BIG-IP management address in `.env` as `BIGIP_HOST`.

## 3. Prepare the guests

**BIG-IP** — in the component's Web Shell:

```bash
bash provision.sh          # paste bigip/provision.sh
```

Provisioning ASM restarts services; give it a few minutes. Verify
`tmsh show net interface` agrees with `TRAFFIC_IF` before trusting the VLAN.

**Backend** — set `udf/userdata/backend.sh` as Custom Userdata, or paste it.
Then copy the app across and start it:

```bash
scp -P <sshPort> backend/app.py keys/jwks.json ubuntu@<dnsKey>.access.udf.f5.com:/tmp/
# on the backend:
sudo mv /tmp/app.py /tmp/jwks.json /opt/jwe-lab/
sudo systemctl start jwe-backend
curl -s localhost:8080/healthz
```

Only `jwks.json` goes to the backend. The private keyring and
`shared-secrets.json` belong on the BIG-IP and the client respectively — never
on the origin.

## 3b. Reaching the BIG-IP management plane

**The UDF HTTPS access-method hostname will not work for these tools.** It is
authenticated by the browser session cookie (HttpOnly), so a scripted iControl
REST call receives UDF's HTML login page with a 401 — BIG-IP never sees it. The
giveaway is `<!doctype html>` / `<title>UDF</title>` in the body; a real BIG-IP
401 is JSON. `check_env.py --login` and both deploy tools now detect this and
say so.

**Option A — SSH tunnel (recommended).** SSH access methods are key-based and
work from outside. Take the port from the `bigip-waf` component's Access
Methods tab:

```bash
ssh -p <sshPort> -N -L 8443:<bigip-mgmt-ip>:443 <user>@<dnsKey>.access.udf.f5.com
# leave it running; then in .env:
#   BIGIP_HOST=https://127.0.0.1:8443
python3 tools/check_env.py --login      # expect LOGIN OK
```

`-N` means no remote command, just the forward. If SSH refuses, confirm your
public key is registered in UDF (Settings → SSH Keys) — UDF SSH is key-only and
never accepts a password.

**Option B — run the tools inside the deployment.** Every component has an
interface on the `10.1.1.0/24` management subnet, so from `api-backend` or
`test-desktop` the BIG-IP is directly reachable:

```bash
# on test-desktop (see udf/userdata/desktop.sh)
BIGIP_HOST=https://10.1.1.<bigip>
```

This is the better choice for `run_matrix.py` anyway, since the traffic subnet
`10.1.10.0/24` is only reachable from inside the deployment — the virtual
servers are not routable from your laptop at all.

**Do NOT** create an unauthenticated HTTPS access method pointing at TMUI or the
management interface to work around this. It bypasses the protection that makes
UDF safe to expose.

## 4. Deploy the decryptor and the policy

```bash
python3 tools/ilx_deploy.py     # keys + workspace + plugin + SELFTEST
```

Read the selftest output. It reports the real ILX Node version, the process
owner, and whether the plugin can actually read the keyring. If it says profile
C is unavailable, run the matrix with `--profile B`.

```bash
python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json --dry-run
python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json
```

## 5. Run the matrix — the deliverable

```bash
python3 client/run_matrix.py --all
```

Exit 0 means every asserted cell matched. The line to read is:

```
CENTRAL CLAIM (same JWE, opposite outcomes): HOLDS
  chain=✓ block #1844674407   blind=✓ allow (cipher)
```

Identical ciphertext, identical policy, opposite outcomes. `(cipher)` is the
backend confirming it received an undecrypted JWE — the blind spot, stated by
the origin rather than inferred.

Enrich a block:

```bash
python3 tools/asm_events.py --support-id 1844674407370955161
```

Record the `MEASURED` rows (the `single` target) in
[FINDINGS.md](FINDINGS.md) — those answer K000158872.

## 6. Demo script (~10 minutes)

1. **Show the policy works.** `run_matrix.py --case sqli --target plain` → blocked.
2. **Show the blind spot.** `--case sqli --target blind` → 200, backend saw
   `ciphertext`. Same attack, same policy, invisible.
3. **Close it.** `--case sqli --target chain` → blocked, with a support ID.
4. **Attribute the block.** `asm_events.py --support-id <id>` → the signature.
5. **Show it fails safe.** `--case tampered_tag,unknown_kid --target chain` →
   `reject`, not `block`: refused before the WAF, and the log says why.

## 7. Rotation demo

```bash
python3 tools/keyring_push.py --list
python3 tools/keyring_push.py --add jwe-oaep256-b     # overlap window
sleep 35                                              # 30s mtime poll
python3 client/run_matrix.py --case clean             # both kids accepted
python3 tools/keyring_push.py --retire jwe-oaep256-a
python3 tools/keyring_push.py --remove jwe-oaep256-a  # old kid now rejected
```

No plugin restart, no VS bounce, no AS3 resubmit.

## Troubleshooting

| Symptom | Cause to check first |
|---|---|
| `Missing dependency: pip install -r requirements.txt` | venv not active. `source .venv/bin/activate`, or use `./.venv/bin/python` |
| `zsh: command not found: pip` | Use `python3 -m pip`, or activate the venv (which provides `pip`) |
| Everything returns `reject` | Selftest: can the plugin read the keyring? `ilx_deploy.py --selftest-only` |
| `reject` with `alg_unsupported_on_runtime` | Old ILX Node. Use `--profile B` |
| `reject` with `key_unusable` | Keyring references a file that is not on the box, or wrong ownership |
| Nothing ever blocks, even on `plain` | Signature staging. Must be `signatureStaging: false` — staged signatures alarm without blocking |
| `block` where you expect `allow` | *Malformed JSON data*: Content-Type rewrite missing, or a JSON profile bound to `application/jose` |
| `411` on every JWE | Client sent chunked; `Content-Length` is required |
| `413` on a small body | `JWE_MAX_PAYLOAD` or a proxy adding transfer encoding |
| `502 decrypt_unavailable` | Plugin not running: `tmsh show ilx plugin jwe_decrypt_plugin` |
| Chain returns 200 with no inspection | `static::JWE_WAF_VS` does not match the AS3 tenant/app path |
| AS3 rejects `waf_policy` | Inline `policy` field name varies by AS3 version — see LIMITATIONS.md |

Logs: `tail -f /var/log/ltm | grep -E 'JWE (reject|BYPASS|ok)'`.
`JWE BYPASS` at `local0.crit` means fail-open forwarded something uninspectable.

## Teardown

```
# DevTools, after build-deployment.js is loaded (it defines udf()):
await teardownJweLab('<deploymentId>', { force: true })
```

No confirm, no undo. Stopping the deployment instead costs almost nothing and
keeps the work.
