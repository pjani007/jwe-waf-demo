/*
 * jwe_decrypt — RFC 7516 JWE compact decryption for BIG-IP iRules LX.
 *
 * Runs in two modes:
 *   ILX plugin  — `server.addMethod('decrypt', ...)`, called from jwe_decrypt.tcl
 *   standalone  — `node index.js --selftest` / `--decrypt <token>` for CI and CI-less labs
 *
 * DELIBERATELY DEPENDENCY-FREE. Uses only Node's built-in `crypto`, so the workspace
 * needs no `npm install` and survives an offline BIG-IP and a flaky registry. That rules
 * out node-jose, which is why the algorithm support below is hand-rolled.
 *
 * Wire format back to TCL is pipe-delimited, not JSON — iRules TCL has no JSON parser:
 *   OK|<kid>|<base64 plaintext>
 *   ERR|<machine_reason>|<human detail>
 *
 * Supported (see docs/ARCHITECTURE.md for why three profiles):
 *   dir           + A256GCM   profile A — any Node version
 *   RSA-OAEP      + A256GCM   profile B — default OAEP padding (SHA-1)
 *   RSA-OAEP-256  + A256GCM   profile C — needs oaepHash, Node >= 12
 */

'use strict';

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

// ── Configuration ────────────────────────────────────────────────────────────

var KEYS_DIR = process.env.JWE_KEYS_DIR || '/config/jwe/keys';
var KEYRING_FILE = 'keyring.json';
var RELOAD_INTERVAL_MS = 30000;

// A256GCM fixed parameters (RFC 7518 §5.3)
var A256GCM = { keyBytes: 32, ivBytes: 12, tagBytes: 16, cipher: 'aes-256-gcm' };

// ── Node capability detection ────────────────────────────────────────────────
// `oaepHash` landed in Node 12. On older ILX runtimes RSA-OAEP-256 is simply
// unavailable, and we say so explicitly rather than failing as a "bad token".

var NODE_MAJOR = parseInt(String(process.versions.node).split('.')[0], 10) || 0;
var SUPPORTS_OAEP_SHA256 = NODE_MAJOR >= 12;

function capabilities() {
  return {
    node: process.versions.node,
    openssl: process.versions.openssl,
    profileA_dir: true,
    profileB_rsa_oaep_sha1: true,
    profileC_rsa_oaep_sha256: SUPPORTS_OAEP_SHA256
  };
}

// ── base64url ────────────────────────────────────────────────────────────────
// Buffer's native 'base64url' encoding arrived in Node 15.7, too new to rely on
// here, so both directions are done by hand.

function b64uToBuf(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) { s += '='; }
  return Buffer.from(s, 'base64');
}

function bufToB64u(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Keyring ──────────────────────────────────────────────────────────────────
// A keyring rather than a single key, which buys three things: rotation with an
// overlap window, a genuine unknown-kid rejection path, and per-kid algorithm
// binding so a header cannot talk a key into an algorithm it was not issued for.

var _keyring = null;
var _keyringMtime = 0;
var _keyringLoadError = null;

function keyringPath() { return path.join(KEYS_DIR, KEYRING_FILE); }

function loadKeyring(force) {
  var p = keyringPath();
  var st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    _keyringLoadError = 'keyring not readable at ' + p + ': ' + e.message;
    _keyring = null;
    return null;
  }

  var mtime = st.mtime.getTime();
  if (!force && _keyring && mtime === _keyringMtime) { return _keyring; }

  try {
    var raw = fs.readFileSync(p, 'utf8');
    var doc = JSON.parse(raw);
    var byKid = {};

    (doc.keys || []).forEach(function (k) {
      if (!k.kid || !k.alg || !k.enc || !k.file) { return; }
      var material;
      var kf = path.join(KEYS_DIR, k.file);
      try {
        material = fs.readFileSync(kf, 'utf8');
      } catch (e) {
        // One unreadable key must not take the whole keyring down — the other
        // kids keep working and this one reports its own precise failure.
        byKid[k.kid] = { kid: k.kid, broken: 'key file unreadable: ' + e.message };
        return;
      }
      byKid[k.kid] = {
        kid: k.kid,
        alg: k.alg,
        enc: k.enc,
        status: k.status || 'active',
        not_after: k.not_after || null,
        material: material.trim()
      };
    });

    _keyring = byKid;
    _keyringMtime = mtime;
    _keyringLoadError = null;
    return _keyring;
  } catch (e) {
    _keyringLoadError = 'keyring parse failed: ' + e.message;
    _keyring = null;
    return null;
  }
}

// mtime poll, not fs.watch — fs.watch is unreliable on older Node and on some
// filesystems fires no event at all. 30s means a new kid is live without a
// plugin restart or a VS bounce.
function startKeyringWatcher() {
  loadKeyring(true);
  var t = setInterval(function () { loadKeyring(false); }, RELOAD_INTERVAL_MS);
  if (t.unref) { t.unref(); }
  return t;
}

function resolveKid(kid) {
  var ring = loadKeyring(false);
  if (!ring) { return { err: 'keyring_unavailable', detail: _keyringLoadError || 'unknown' }; }
  if (!kid) { return { err: 'missing_kid', detail: 'protected header has no kid' }; }

  var entry = ring[kid];
  if (!entry) {
    return { err: 'unknown_kid', detail: 'kid ' + kid + ' not in keyring' };
  }
  if (entry.broken) {
    return { err: 'key_unusable', detail: entry.broken };
  }
  if (entry.status === 'revoked') {
    return { err: 'revoked_kid', detail: 'kid ' + kid + ' is revoked' };
  }
  if (entry.not_after && Date.parse(entry.not_after) < Date.now()) {
    return { err: 'expired_kid', detail: 'kid ' + kid + ' expired at ' + entry.not_after };
  }
  return { entry: entry };
}

// ── Content encryption ───────────────────────────────────────────────────────

function decryptContent(cek, ivB, ctB, tagB, aadAscii) {
  if (cek.length !== A256GCM.keyBytes) {
    return { err: 'bad_cek_length', detail: 'CEK is ' + cek.length + 'B, need ' + A256GCM.keyBytes };
  }
  if (ivB.length !== A256GCM.ivBytes) {
    return { err: 'bad_iv_length', detail: 'IV is ' + ivB.length + 'B, need ' + A256GCM.ivBytes };
  }
  if (tagB.length !== A256GCM.tagBytes) {
    return { err: 'bad_tag_length', detail: 'tag is ' + tagB.length + 'B, need ' + A256GCM.tagBytes };
  }

  try {
    var d = crypto.createDecipheriv(A256GCM.cipher, cek, ivB);
    // AAD is the protected header EXACTLY as it appeared on the wire (RFC 7516
    // §5.1 step 14) — never a re-serialisation, which would change the bytes
    // and fail authentication for reasons that look like a key problem.
    d.setAAD(Buffer.from(aadAscii, 'ascii'));
    d.setAuthTag(tagB);
    var pt = Buffer.concat([d.update(ctB), d.final()]);   // final() throws on tag mismatch
    return { plaintext: pt };
  } catch (e) {
    return { err: 'auth_failed', detail: 'GCM authentication failed (tampered or wrong key)' };
  }
}

// ── Key unwrap ───────────────────────────────────────────────────────────────

function unwrapCek(alg, entry, encryptedKeyB) {
  if (alg === 'dir') {
    if (encryptedKeyB.length !== 0) {
      return { err: 'dir_with_encrypted_key', detail: 'alg=dir must carry an empty encrypted key' };
    }
    return { cek: b64uToBuf(entry.material) };
  }

  if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
    if (encryptedKeyB.length === 0) {
      return { err: 'missing_encrypted_key', detail: alg + ' requires an encrypted key' };
    }
    if (alg === 'RSA-OAEP-256' && !SUPPORTS_OAEP_SHA256) {
      return {
        err: 'alg_unsupported_on_runtime',
        detail: 'RSA-OAEP-256 needs oaepHash (Node >= 12); this runtime is Node ' +
                process.versions.node + '. Use profile A or B.'
      };
    }
    var opts = { key: entry.material, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING };
    if (alg === 'RSA-OAEP-256') { opts.oaepHash = 'sha256'; }
    try {
      return { cek: crypto.privateDecrypt(opts, encryptedKeyB) };
    } catch (e) {
      return { err: 'unwrap_failed', detail: 'RSA unwrap failed (wrong key for this kid)' };
    }
  }

  return { err: 'unsupported_alg', detail: 'alg ' + alg + ' is not implemented' };
}

// ── Main entry point ─────────────────────────────────────────────────────────

function decryptCompact(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, err: 'empty_token', detail: 'no token supplied' };
  }

  var parts = token.split('.');
  if (parts.length !== 5) {
    return {
      ok: false, err: 'malformed_jwe',
      detail: 'compact JWE needs 5 segments, got ' + parts.length
    };
  }

  var protectedB64 = parts[0];
  var hdr;
  try {
    hdr = JSON.parse(b64uToBuf(protectedB64).toString('utf8'));
  } catch (e) {
    return { ok: false, err: 'bad_header', detail: 'protected header is not valid JSON' };
  }

  // x5t#S256 is parsed but NOT validated — this build is RFC 7517 key
  // management with no CA (see the plan's PKI decision). Keeping the field
  // visible in the log keeps an X.509-backed variant a bolt-on.
  var x5t = hdr['x5t#S256'] || null;

  var r = resolveKid(hdr.kid);
  if (r.err) { return { ok: false, err: r.err, detail: r.detail, kid: hdr.kid || null }; }
  var entry = r.entry;

  // Algorithm binding. Without this a token could nominate `dir` against an RSA
  // kid and steer the decryptor down a path the key was never issued for.
  if (hdr.alg !== entry.alg) {
    return {
      ok: false, err: 'alg_mismatch', kid: entry.kid,
      detail: 'header alg=' + hdr.alg + ' but kid ' + entry.kid + ' is bound to ' + entry.alg
    };
  }
  if (hdr.enc !== entry.enc) {
    return {
      ok: false, err: 'enc_mismatch', kid: entry.kid,
      detail: 'header enc=' + hdr.enc + ' but kid ' + entry.kid + ' is bound to ' + entry.enc
    };
  }
  if (hdr.enc !== 'A256GCM') {
    return { ok: false, err: 'unsupported_enc', kid: entry.kid, detail: 'enc ' + hdr.enc + ' not implemented' };
  }

  var u = unwrapCek(hdr.alg, entry, b64uToBuf(parts[1]));
  if (u.err) { return { ok: false, err: u.err, detail: u.detail, kid: entry.kid }; }

  var c = decryptContent(u.cek, b64uToBuf(parts[2]), b64uToBuf(parts[3]),
                         b64uToBuf(parts[4]), protectedB64);
  if (c.err) { return { ok: false, err: c.err, detail: c.detail, kid: entry.kid }; }

  return {
    ok: true, kid: entry.kid, alg: hdr.alg, enc: hdr.enc,
    status: entry.status, x5t: x5t, plaintext: c.plaintext
  };
}

// Pipe-delimited because iRules TCL has no JSON parser. Detail is stripped of
// pipes and newlines so the TCL split is unambiguous.
function toWire(res) {
  if (res.ok) {
    return 'OK|' + res.kid + '|' + res.plaintext.toString('base64');
  }
  var detail = String(res.detail || '').replace(/[|\r\n]+/g, ' ');
  return 'ERR|' + res.err + '|' + detail;
}

// ── ILX plugin mode ──────────────────────────────────────────────────────────

function startIlxServer() {
  var ilx;
  try {
    ilx = require('f5-nodejs');
  } catch (e) {
    return false;   // not on a BIG-IP
  }

  startKeyringWatcher();

  var server = new ilx.ILXServer();

  server.addMethod('decrypt', function (req, res) {
    var token = req.params()[0];
    var out;
    try {
      out = toWire(decryptCompact(token));
    } catch (e) {
      // Never leak a stack trace into the data path; fail closed and let the
      // iRule decide what that means.
      out = 'ERR|internal_error|' + String(e.message).replace(/[|\r\n]+/g, ' ');
    }
    res.reply(out);
  });

  // Lets ilx_deploy.py verify key readability under the real plugin user
  // instead of us assuming which user that is.
  server.addMethod('selftest', function (req, res) {
    var caps = capabilities();
    var ring = loadKeyring(true);
    var kids = ring ? Object.keys(ring) : [];
    res.reply(JSON.stringify({
      ok: !!ring,
      keyring_path: keyringPath(),
      keyring_error: _keyringLoadError,
      kids: kids,
      uid: typeof process.getuid === 'function' ? process.getuid() : null,
      capabilities: caps
    }));
  });

  server.listen();
  return true;
}

// ── CLI ──────────────────────────────────────────────────────────────────────

function cli(argv) {
  if (argv.indexOf('--capabilities') !== -1) {
    process.stdout.write(JSON.stringify(capabilities(), null, 2) + '\n');
    return 0;
  }

  if (argv.indexOf('--selftest') !== -1) {
    var caps = capabilities();
    process.stdout.write('node        : ' + caps.node + '\n');
    process.stdout.write('openssl     : ' + caps.openssl + '\n');
    process.stdout.write('profile A   : dir+A256GCM          ' + (caps.profileA_dir ? 'yes' : 'no') + '\n');
    process.stdout.write('profile B   : RSA-OAEP+A256GCM     ' + (caps.profileB_rsa_oaep_sha1 ? 'yes' : 'no') + '\n');
    process.stdout.write('profile C   : RSA-OAEP-256+A256GCM ' + (caps.profileC_rsa_oaep_sha256 ? 'yes' : 'no') + '\n');
    var ring = loadKeyring(true);
    process.stdout.write('keyring     : ' + keyringPath() + '\n');
    if (!ring) {
      process.stdout.write('keyring err : ' + _keyringLoadError + '\n');
      return 1;
    }
    var kids = Object.keys(ring);
    process.stdout.write('kids        : ' + (kids.length ? kids.join(', ') : '(none)') + '\n');
    kids.forEach(function (k) {
      var e = ring[k];
      process.stdout.write('  - ' + k + ': ' +
        (e.broken ? 'BROKEN ' + e.broken : e.alg + '/' + e.enc + ' [' + e.status + ']') + '\n');
    });
    return 0;
  }

  var i = argv.indexOf('--decrypt');
  // `!== undefined`, not truthiness: an EMPTY token is a legitimate input that
  // must be rejected as empty_token, and '' is falsy in JS.
  if (i !== -1 && argv[i + 1] !== undefined) {
    var res = decryptCompact(argv[i + 1]);
    process.stdout.write(toWire(res) + '\n');
    return res.ok ? 0 : 1;
  }

  process.stderr.write(
    'usage: node index.js [--selftest | --capabilities | --decrypt <compact-jwe>]\n' +
    '       JWE_KEYS_DIR overrides the key directory (default ' + KEYS_DIR + ')\n');
  return 2;
}

module.exports = {
  decryptCompact: decryptCompact,
  toWire: toWire,
  loadKeyring: loadKeyring,
  capabilities: capabilities,
  b64uToBuf: b64uToBuf,
  bufToB64u: bufToB64u
};

if (require.main === module) {
  var args = process.argv.slice(2);
  // NEVER process.exit() here. It discards pending asynchronous writes to a
  // pipe, silently truncating output at the OS pipe buffer (64 KiB) — which
  // decoded as "Incorrect padding" on large plaintexts and looked like a
  // base64 bug. Setting exitCode lets Node flush, then exit on its own.
  if (args.length > 0) {
    process.exitCode = cli(args);
  } else if (!startIlxServer()) {
    process.exitCode = cli([]);   // print usage off-box
  }
}
