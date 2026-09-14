/*
 * teardown.js — delete the lab.
 *
 * Paste into DevTools on an authenticated udf.f5.com page, then:
 *   await teardownJweLab('<deploymentId>')
 *
 * DeleteDeployment takes `id`, NOT `deploymentId`, and there is NO confirm,
 * NO dry-run and NO undo. The UI's two-click CONFIRM is client-side only.
 * The id is printed here before deletion so you can abort.
 */

'use strict';

async function teardownJweLab(deploymentId, { force = false } = {}) {
  if (!deploymentId) throw new Error('pass the deploymentId');
  if (typeof udf !== 'function') throw new Error('paste build-deployment.js first (it defines udf())');

  const { call, close } = await udf();
  try {
    const r = await call('GetDeployments', { deploymentIds: [deploymentId] });
    const d = r?.deployments?.[0];
    if (!d) throw new Error(`no deployment ${deploymentId} — already gone?`);

    console.log('about to DELETE:', d.name, '| state:', d.state, '| id:', d.id);
    if (!force) {
      console.log('This is irreversible. Re-run with { force: true } to proceed.');
      return { deleted: false };
    }

    await call('DeleteDeployment', { id: deploymentId });   // `id`, not deploymentId
    console.log('delete issued; state moves to Deleting and the row vanishes in ~1 min');
    return { deleted: true };
  } finally {
    close();
  }
}

if (typeof window !== 'undefined') {
  window.teardownJweLab = teardownJweLab;
  console.log('[jwe-lab] teardown loaded. Run: await teardownJweLab("<id>", {force:true})');
}
