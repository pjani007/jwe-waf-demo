/*
 * build-deployment.js — create the JWE-WAF lab in UDF over the JSON-RPC WebSocket.
 *
 * HOW TO RUN
 *   1. Log in to https://udf.f5.com in Chrome (only Chrome is supported).
 *   2. Open DevTools -> Console on any udf.f5.com page.
 *   3. Paste this whole file, then call:  await buildJweLab()
 *
 * WHY DEVTOOLS AND NOT curl/node
 *   UDF has no REST API. The control plane is JSON-RPC over a Primus WebSocket
 *   gated by the session cookie, which is HttpOnly — it is not in
 *   document.cookie and cannot be replayed from outside the browser. Running
 *   from an authenticated page is the path of least resistance.
 *
 * WHAT IT BUILDS
 *   subnet   10.1.10.0/24 (traffic; Management 10.1.1.0/24 is auto-created)
 *   bigip-waf     BIG-IP 17.5.x   8 vCPU / 16 GB   .30 + secondaries .40 .41 .42 .43 .241
 *   api-backend   Ubuntu Server   2 vCPU /  4 GB   .20
 *   test-desktop  Ubuntu Desktop  2 vCPU /  4 GB   .10
 *
 * THREE TRAPS THIS SCRIPT HANDLES FOR YOU
 *   - autostopDuration is in MINUTES even though the UI says hours. 480 = 8h.
 *     ExtendDeployment is denied to ordinary users over RPC, so a too-short
 *     value can only be rescued from the UI's EXTEND button.
 *   - StartDeployment requires HV3InstanceType even though the deployment
 *     already stores one; omitting it fails with "Invalid HV3 instance type".
 *   - Binding an interface does NOT configure it in the guest OS. There is no
 *     DHCP on traffic subnets. The Linux hosts get netplan from customUserdata;
 *     the BIG-IP gets its VLAN/self-IP from bigip/provision.sh.
 */

'use strict';

const CONFIG = {
  name: 'jwe-waf-lab',
  region: 'europe-west2',          // GCP region for the UDF Hypervisor
  instanceType: 'n1-standard-16',  // MEDIUM — fits 12 vCPU / 24 GB of guests
  autostopMinutes: 480,            // MINUTES. 480 = 8 hours.
  trafficCidr: '10.1.10.0/24',
  groupId: null,                   // null = auto-resolve from your memberships

  // Undocumented, drifting enums — verified live 2026-09-14:
  //   purpose ∈ [customer, development, other, personaluse]
  // `scheme` accepted 'solution' in the same call. If either is rejected, the
  // script reads the allowed list out of the validation error and retries.
  scheme: 'solution',
  purpose: 'development',          // building/testing a lab, not a customer demo

  addresses: {
    desktop: '10.1.10.10',
    backend: '10.1.10.20',
    bigipSelf: '10.1.10.30',
    // Virtual server addresses, bound as secondaries on the BIG-IP interface.
    bigipSecondary: [
      '10.1.10.40',   // vs_jwe_ingress   decrypt -> chain to WAF   (the fix)
      '10.1.10.41',   // vs_jwe_blind     WAF only, no decrypt      (the blind spot)
      '10.1.10.42',   // vs_plain_waf     plaintext + WAF           (policy is armed)
      '10.1.10.43',   // vs_jwe_single    decrypt + WAF, same VS    (measures K000158872)
      '10.1.10.241',  // vs_waf_internal  inner WAF VS for the chain
    ],
  },

  // Resolved by pattern, in priority order, because exact template names drift
  // between UDF releases. The script prints candidates if nothing matches.
  // Verified against the live HV3 catalogue 2026-09-14. The BIG-IP templates are
  // named "BIGIP <version>-<build>" — NO hyphen in BIGIP, despite the reference
  // material writing it "BIG-IP". `BIG-?IP` tolerates either spelling.
  // Real names: BIGIP 15.1.10.8-0.0.30 / 16.1.6.1-0.0.11 / 17.1.3-0.0.11 /
  //             17.5.1.3-0.0.19 / 21.0.0-0.0.10
  // 21.0.0 is deliberately NOT a fallback: dropping to a different major
  // release should be an explicit choice, not something a regex does quietly.
  templates: {
    bigip:   { patterns: [/^BIG-?IP\s+17\.5/i, /^BIG-?IP\s+17\./i], disk: 81, cpus: 8, memMiB: 16384 },
    // Desktop images are 18.04/20.04 only — 22.04+ is Server-only.
    desktop: { patterns: [/Ubuntu\s*20\.04.*Desktop/i, /Ubuntu.*Desktop/i], disk: 24, cpus: 2, memMiB: 4096 },
    backend: { patterns: [/Ubuntu\s*24\.04.*Server/i, /Ubuntu\s*22\.04.*Server/i], disk: 16, cpus: 2, memMiB: 4096 },
  },
};

// ── Minimal RPC client ───────────────────────────────────────────────────────

async function udf() {
  const ws = new WebSocket('wss://us-west-2.udf.f5.com/primus?_primuscb=' +
                           Date.now().toString(36));
  let id = 0;
  const pending = new Map();

  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
    setTimeout(() => rej(new Error('WebSocket open timeout')), 10000);
  });

  ws.onmessage = e => {
    const raw = typeof e.data === 'string' ? e.data : '';

    // PRIMUS HEARTBEAT. The server pings periodically and closes the socket if
    // nothing pongs back — which is why a long poll died with "WebSocket is
    // already in CLOSING or CLOSED state". The ping may arrive raw
    // (primus::ping::123) or JSON-encoded ("primus::ping::123"); mirror
    // whichever form was used.
    const ping = raw.match(/^"?primus::ping::(\d+)"?$/);
    if (ping) {
      ws.send(raw.charAt(0) === '"'
        ? JSON.stringify('primus::pong::' + ping[1])
        : 'primus::pong::' + ping[1]);
      return;
    }

    let m;
    try { m = JSON.parse(raw); } catch { return; }
    // Responses arrive OUT OF ORDER — always correlate by id.
    if (m?.type === 1 && pending.has(m.id)) {
      pending.get(m.id)(m.data);
      pending.delete(m.id);
    }
  };

  const handshake = await new Promise(res => {
    const h = e => { ws.removeEventListener('message', h); res(JSON.parse(e.data)); };
    ws.addEventListener('message', h);
    ws.send('{}');
  });
  if (!handshake.authorized) {
    throw new Error('not authorized — re-login to udf.f5.com and retry');
  }

  const call = (method, params) => new Promise((res, rej) => {
    const myId = ++id;
    pending.set(myId, ([err, result]) => {
      // A failed call returns the JSON-RPC error IN PLACE OF the result, so
      // checking only the tuple's error slot reads failures as successes.
      const e = err?.error || (err && err.jsonrpc ? err : null);
      e ? rej(new Error(`${method}: ${e.data ?? JSON.stringify(e)}`)) : res(result);
    });
    ws.send(JSON.stringify({
      type: 0,
      data: ['msg', { jsonrpc: '2.0', region: 'us-west-2', method, params }],
      id: myId,
    }));
  });

  return { call, close: () => ws.close() };
}

const log = (...a) => console.log('[jwe-lab]', ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

/*
 * rowsOf — pull a list out of an RPC result without assuming its wrapper.
 * Response shapes are not stable across methods/versions: some return
 * {deployments:[...]}, some a bare array. Guessing one and indexing blind is
 * how a status call crashes on a lab that is perfectly healthy.
 */
function rowsOf(r, key) {
  if (!r) return [];
  if (Array.isArray(r)) return r;
  if (key && Array.isArray(r[key])) return r[key];
  for (const v of Object.values(r)) if (Array.isArray(v)) return v;
  return [];
}

function resolveTemplate(templates, spec, label) {
  const hv3 = templates.filter(t => t.provider === 'HV3');
  for (const pattern of spec.patterns) {
    const hit = hv3.find(t => pattern.test(t.name));
    if (hit) return hit;
  }
  const names = hv3.map(t => t.name).sort();
  console.error(`[jwe-lab] no HV3 template matched ${label}:`, spec.patterns);
  console.error('[jwe-lab] available HV3 templates:', names);
  throw new Error(`no template for ${label} — pick one from the list above and ` +
                  `add its pattern to CONFIG.templates.${label}.patterns`);
}

// ── Build ────────────────────────────────────────────────────────────────────

async function buildJweLab(overrides = {}) {
  const cfg = { ...CONFIG, ...overrides };
  // A single socket has to survive several minutes of polling. Heartbeats are
  // answered above, but a reconnecting wrapper means a dropped socket costs a
  // retry instead of the whole build.
  let conn = await udf();
  const call = async (method, params) => {
    try {
      return await conn.call(method, params);
    } catch (e) {
      if (!/CLOSING|CLOSED|not open|closed/i.test(String(e && e.message))) throw e;
      log('socket dropped — reconnecting');
      conn = await udf();
      return conn.call(method, params);
    }
  };
  const close = () => { try { conn.close(); } catch {} };

  try {
    const { user } = await call('GetActiveUser');
    log('user:', user.email || user.id);

    let groupId = cfg.groupId;
    if (!groupId) {
      const memberships = await call('GetUserGroupMemberships', { userId: user.id });
      const first = (memberships?.groupMemberships || memberships || [])[0];
      groupId = first?.groupId || first?.group?.id;
      if (!groupId) {
        throw new Error('could not resolve a groupId — set CONFIG.groupId explicitly');
      }
    }
    log('group:', groupId, '(this group is CHARGED for the deployment)');

    // Warn if a lab of this name already exists, so re-running does not quietly
    // double your spend.
    //
    // Uses GetUserDeployments, not Search: `Search` requires a `target` param
    // whose accepted values are undocumented, and it rejected
    // {query} with ValidationError-child "target" fails because ["target" is
    // required]. GetUserDeployments is a verified read.
    //
    // This is a CONVENIENCE CHECK, so it must never block the build. An earlier
    // version threw on any failure here, which meant a guard against
    // overspending became the reason the lab would not build at all.
    try {
      let rows = [];
      try {
        const mine = await call('GetUserDeployments', { userId: user.id });
        rows = mine?.deployments || mine || [];
      } catch {
        const mine = await call('GetUserDeployments');   // some builds take no params
        rows = mine?.deployments || mine || [];
      }
      const clash = (Array.isArray(rows) ? rows : [])
        .find(d => String(d?.name || '').toLowerCase() === cfg.name.toLowerCase());
      if (clash) {
        throw new Error(
          `a deployment named "${cfg.name}" already exists (id ${clash.id}, ` +
          `state ${clash.state}). Delete it, or change CONFIG.name, or call ` +
          `buildJweLab({name: 'jwe-waf-lab-2'}).`);
      }
      log(`duplicate check: ${Array.isArray(rows) ? rows.length : 0} existing ` +
          `deployment(s), no name clash`);
    } catch (e) {
      if (/already exists/.test(e.message)) throw e;    // a real clash, not an API problem
      log('duplicate check skipped (could not list deployments):', e.message);
    }

    log('creating deployment...');

    // `scheme` and `purpose` are undocumented enums that DRIFT between UDF
    // releases. Observed live 2026-09-14:
    //   purpose ∈ [customer, development, other, personaluse]
    // which does NOT match the values published in the reference material
    // (solution / education / application). Rather than hardcode a guess,
    // a Joi validation error carries the accepted list — so parse it, retry
    // with a value that is actually allowed, and say so out loud.
    const params = {
      name: cfg.name,
      groupId,
      provider: 'HV3',
      HV3Region: cfg.region,
      scheme: cfg.scheme,
      purpose: cfg.purpose,
    };

    let deployment;
    for (let attempt = 1; ; attempt++) {
      try {
        ({ deployment } = await call('CreateDeployment', params));
        break;
      } catch (e) {
        // e.g. child "purpose" fails because ["purpose" must be one of [a, b, c]]
        const m = /child "(\w+)" fails because \["\1" must be one of \[([^\]]+)\]\]/
          .exec(e.message);
        if (!m || attempt > 3) throw e;

        const field = m[1];
        const allowed = m[2].split(',').map(s => s.trim()).filter(Boolean);
        // Prefer 'other' — it has appeared in every observed variant of both
        // enums — else take the first value the server will accept.
        const pick = allowed.includes('other') ? 'other' : allowed[0];
        log(`CreateDeployment rejected ${field}="${params[field]}"; ` +
            `server allows [${allowed.join(', ')}] -> retrying with "${pick}"`);
        params[field] = pick;
      }
    }
    const DEP = deployment.id;
    log('deployment:', DEP);

    log('creating traffic subnet', cfg.trafficCidr);
    await call('CreateSubnet', { deploymentId: DEP, awsCidrBlock: cfg.trafficCidr });

    const templates = await call('ListTemplates');
    const tB = resolveTemplate(templates, cfg.templates.bigip, 'bigip');
    const tD = resolveTemplate(templates, cfg.templates.desktop, 'desktop');
    const tA = resolveTemplate(templates, cfg.templates.backend, 'backend');
    log('templates:', { bigip: tB.name, desktop: tD.name, backend: tA.name });

    const mk = async (name, tpl, spec) => {
      const r = await call('CreateInstance', {
        deploymentId: DEP,
        templateId: tpl.id,
        name,
        // Honour the template's own floor — a smaller disk fails validation.
        diskSize: Math.max(spec.disk, tpl.minDiskSize || 0),
        cpus: spec.cpus,
        memory: spec.memMiB,       // MiB, not GB
      });
      log('  component:', name, r.instance.id);
      return r.instance;
    };

    log('creating components...');
    const bigip   = await mk('bigip-waf',    tB, cfg.templates.bigip);
    const backend = await mk('api-backend',  tA, cfg.templates.backend);
    const desktop = await mk('test-desktop', tD, cfg.templates.desktop);

    // Re-read to learn the traffic subnet's id.
    const comps = await call('GetDeploymentComponents', { deploymentIds: [DEP] });
    const list = comps?.components || comps || [];
    const traffic = list.find(c => c.awsCidrBlock === cfg.trafficCidr);
    if (!traffic) throw new Error(`traffic subnet ${cfg.trafficCidr} not found after create`);

    log('binding interfaces (deployment is Stopped — required for F5 templates)...');
    const bind = async (inst, addr, label) => {
      await call('CreateInterface', {
        deploymentId: DEP, instanceId: inst.id,
        subnetId: traffic.id, primaryAddress: addr,
      });
      log('  bound', label, '->', addr);
    };
    await bind(bigip,   cfg.addresses.bigipSelf, 'bigip-waf');
    await bind(backend, cfg.addresses.backend,   'api-backend');
    await bind(desktop, cfg.addresses.desktop,   'test-desktop');

    log('adding VS addresses as secondaries...');
    await call('UpdateInterface', {
      deploymentId: DEP, instanceId: bigip.id,
      subnetId: traffic.id, primaryAddress: cfg.addresses.bigipSelf,
      // Change-set form, not a plain list.
      secondaryAddresses: cfg.addresses.bigipSecondary.map(v => ({ action: 'add', value: v })),
    });
    cfg.addresses.bigipSecondary.forEach(a => log('  secondary', a));

    log(`starting (${cfg.instanceType}, autostop ${cfg.autostopMinutes} MINUTES)...`);
    await call('StartDeployment', {
      deploymentId: DEP,
      groupId,
      userId: user.id,
      HV3InstanceType: cfg.instanceType,   // required even though it is stored
      autostopDuration: cfg.autostopMinutes,
    });

    log('waiting for Running (hypervisor ~1 min, components a few more)...');
    for (let i = 0; i < 40; i++) {
      await sleep(15000);
      const r = await call('GetDeployments', { deploymentIds: [DEP] });
      // GetDeployments can transiently return no rows during transitions.
      const d = r?.deployments?.[0];
      if (!d) { log('  (no rows yet)'); continue; }
      log('  state:', d.state);
      if (d.state === 'Running') break;
      if (d.state === 'Error') throw new Error('deployment entered Error state');
    }

    const methods = await call('GetAccessMethods', { deploymentIds: [DEP] });
    const final = await call('GetDeployments', { deploymentIds: [DEP] });
    const dnsKey = final?.deployments?.[0]?.dnsKey;

    console.log('\n=== JWE-WAF lab ready ===');
    console.log('deploymentId :', DEP);
    console.log('dnsKey       :', dnsKey, '(this, NOT the id, is the access hostname)');
    console.log('\naccess methods:');
    (methods?.accessMethods || methods || []).forEach(m => {
      console.log(`  ${(m.label || m.type || '?').padEnd(14)} ${m.host || ''} ${m.sshPort || ''}`);
    });
    console.log('\nNEXT STEPS');
    console.log('  1. Put the BIG-IP management IP in .env as BIGIP_HOST');
    console.log('  2. bash bigip/provision.sh                  (VLAN, self-IP, provision ASM+ILX)');
    console.log('  3. python3 tools/ilx_deploy.py              (workspace + keys + selftest)');
    console.log('  4. python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json');
    console.log('  5. python3 client/run_matrix.py --all');
    console.log('\nAutostop is', cfg.autostopMinutes, 'minutes. ExtendDeployment is DENIED over');
    console.log('RPC for ordinary users — use the UI EXTEND button if you need longer.');

    return { deploymentId: DEP, dnsKey };
  } finally {
    close();
  }
}

// ── Status ───────────────────────────────────────────────────────────────────

/*
 * statusJweLab — report an existing lab's state, components and access methods.
 *
 * Separate from the build on purpose: a build that dies in the wait loop has
 * still created everything, so recovering the details must not require
 * re-running (and re-paying for) the build.
 *
 *   await statusJweLab()             // finds it by CONFIG.name
 *   await statusJweLab('<id>')       // or pass the id
 */
async function statusJweLab(deploymentId) {
  const conn = await udf();
  try {
    // Always list first: the row it returns is a complete deployment record,
    // and it is the fallback when GetDeployments comes back empty.
    const { user } = await conn.call('GetActiveUser');
    let mine = [];
    try {
      mine = rowsOf(await conn.call('GetUserDeployments', { userId: user.id }), 'deployments');
    } catch {
      mine = rowsOf(await conn.call('GetUserDeployments'), 'deployments');
    }

    let base = deploymentId
      ? mine.find(x => x?.id === deploymentId)
      : mine.find(x => String(x?.name || '').toLowerCase() === CONFIG.name.toLowerCase());

    if (!base && deploymentId) base = { id: deploymentId };
    if (!base) {
      console.log(`no deployment named "${CONFIG.name}". Yours:`);
      for (const x of mine) console.log(`  ${x.id}  ${String(x.state).padEnd(10)} ${x.name}`);
      throw new Error('pass an id from the list above');
    }

    const id = base.id;

    // GetDeployments is documented to transiently return NO ROWS for a valid id
    // during state transitions. Treat it as enrichment, never as the source of
    // truth, or a healthy lab looks like a missing one.
    let d = base;
    try {
      const fresh = rowsOf(await conn.call('GetDeployments', { deploymentIds: [id] }),
                           'deployments')[0];
      if (fresh) d = { ...base, ...fresh };
      else log('GetDeployments returned no rows (normal mid-transition) — using the list row');
    } catch (e) {
      log('GetDeployments failed, using the list row:', e.message);
    }

    console.log('\n=== ' + d.name + ' ===');
    console.log('deploymentId :', d.id);
    console.log('state        :', d.state);
    console.log('dnsKey       :', d.dnsKey, '(access hostname — NOT the id)');
    console.log('region       :', d.HV3Region || d.providerRegion || '?');

    let list = [];
    try {
      list = rowsOf(await conn.call('GetDeploymentComponents', { deploymentIds: [id] }),
                    'components');
    } catch (e) { log('GetDeploymentComponents failed:', e.message); }

    console.log('\ncomponents:');
    let mgmtHint = null;
    for (const c of list) {
      if (c.componentType === 'Subnet' || c.awsCidrBlock) {
        console.log(`  [subnet] ${c.awsCidrBlock}`);
        continue;
      }
      const traffic = (c.interfaces || [])
        .map(i => i.primaryAddress).filter(Boolean).join(', ');
      console.log(`  ${String(c.name).padEnd(14)} ${String(c.state).padEnd(10)} ` +
                  `mgmt=${c.mgmtIp || '?'}  traffic=${traffic || '-'}`);
      if (/bigip/i.test(c.name || '') && c.mgmtIp) mgmtHint = c.mgmtIp;
    }

    let ams = [];
    try {
      ams = rowsOf(await conn.call('GetAccessMethods', { deploymentIds: [id] }),
                   'accessMethods');
    } catch (e) { log('GetAccessMethods failed:', e.message); }
    console.log('\naccess methods:');
    for (const m of ams) {
      const host = m.host || (m.dnsKey ? m.dnsKey + '.access.udf.f5.com' : '');
      console.log(`  ${String(m.label || m.type || '?').padEnd(16)} ` +
                  `${String(m.protocol || '').padEnd(6)} ${host} ${m.sshPort || ''}`);
    }

    if (d.state === 'Running') {
      console.log('\nNEXT STEPS');
      if (mgmtHint) console.log(`  .env  ->  BIGIP_HOST=https://${mgmtHint}`);
      console.log('  1. BIG-IP web shell: run bigip/provision.sh');
      console.log('  2. python3 tools/ilx_deploy.py');
      console.log('  3. python3 tools/as3_submit.py bigip/as3/waf-jwe-declaration.json');
      console.log('  4. python3 client/run_matrix.py --all');
    } else {
      console.log(`\nstill ${d.state} — re-run  await statusJweLab('${d.id}')  in a minute.`);
      console.log('Deployment "Running" only means the hypervisor is up; components');
      console.log('stay Starting for a few minutes after that.');
    }

    return { deploymentId: d.id, state: d.state, dnsKey: d.dnsKey, mgmtIp: mgmtHint };
  } finally {
    try { conn.close(); } catch {}
  }
}

if (typeof window !== 'undefined') {
  window.buildJweLab = buildJweLab;
  window.statusJweLab = statusJweLab;
  console.log('[jwe-lab] loaded. Run:  await buildJweLab()  |  await statusJweLab()');
}
