'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { recoverKillSwitch } = require('../src/lifecycle/killswitch-startup');

function makeLog() {
  const entries = [];
  const log = {};
  for (const lvl of ['info', 'warn', 'error', 'debug']) log[lvl] = (...a) => entries.push([lvl, a.join(' ')]);
  return { log, entries };
}

const storeWith = (killSwitch) => ({ get: (k, d) => (k === 'tunnel.killSwitch' ? killSwitch : d) });

describe('recoverKillSwitch (core with recoverStaleState)', () => {
  it('cleans up when the tunnel is down even if the setting is on', async () => {
    let opts;
    const ks = { recoverStaleState: async (o) => { opts = o; return 'cleaned'; } };
    const { log } = makeLog();
    const res = await recoverKillSwitch({
      killSwitch: ks, store: storeWith(true), wgService: { isConnected: async () => false }, log,
    });
    assert.equal(res, 'cleaned');
    assert.deepEqual(opts, { keepActive: false });
  });

  it('keeps the kill-switch only if the setting is on and the tunnel is up', async () => {
    const seen = [];
    const ks = { recoverStaleState: async (o) => { seen.push(o.keepActive); return 'none'; } };
    const { log } = makeLog();
    await recoverKillSwitch({ killSwitch: ks, store: storeWith(true), wgService: { isConnected: async () => true }, log });
    await recoverKillSwitch({ killSwitch: ks, store: storeWith(false), wgService: { isConnected: async () => true }, log });
    await recoverKillSwitch({ killSwitch: ks, store: storeWith(true), wgService: { isConnected: async () => { throw new Error('x'); } }, log });
    await recoverKillSwitch({ killSwitch: ks, store: storeWith(true), log });
    assert.deepEqual(seen, [true, false, false, false]);
  });

  it('logs cleanup errors instead of swallowing them silently', async () => {
    const ks = { recoverStaleState: async () => { throw new Error('netsh failed: access denied'); } };
    const { log, entries } = makeLog();
    const res = await recoverKillSwitch({ killSwitch: ks, store: storeWith(false), log });
    assert.equal(res, 'failed');
    assert.ok(entries.some(([lvl, msg]) => lvl === 'error' && msg.includes('access denied')));
  });
});

describe('recoverKillSwitch (KillSwitch without recoverStaleState)', () => {
  it('disables leftover rules when the tunnel is down', async () => {
    let disabled = false;
    const ks = { enabled: false, isActive: async () => true, disable: async () => { disabled = true; } };
    const { log } = makeLog();
    assert.equal(await recoverKillSwitch({ killSwitch: ks, store: storeWith(true), log }), 'cleaned');
    assert.equal(disabled, true);
  });

  it('does nothing without leftovers', async () => {
    const ks = { isActive: async () => false, disable: async () => { throw new Error('must not be called'); } };
    const { log } = makeLog();
    assert.equal(await recoverKillSwitch({ killSwitch: ks, store: storeWith(false), log }), 'none');
  });
});
