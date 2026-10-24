'use strict';

// "Update installieren" (utils/update-install.js): the VPN is only torn down
// once the installer re-hashed fine, a failed start reconnects it and comes
// back with a reason, only a running installer ends the app.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { createUpdateInstaller, installErrorText } = require('../src/utils/update-install');

const t = (k) => ({
  'update.installError.not_ready': 'nicht bereit',
  'update.installError.busy': 'läuft schon',
  'update.installError.verify_failed': 'Datei beschädigt',
  'update.installError.launch_failed': 'Installer startet nicht',
  'update.installError.exited': 'Installer sofort beendet',
  'update.installVpnRestored': 'VPN wieder verbunden.',
}[k] || k);

function harness({ ready = true, prepare = { ok: true, version: '1.2.0' }, launch = { ok: true, via: 'spawn' }, connected = true, reconnectFails = false } = {}) {
  const events = [];
  const updater = {
    isUpdateReady: () => ready,
    prepareInstall: async () => { events.push('prepare'); return prepare; },
    launchInstaller: async () => { events.push('launch'); return launch; },
    check: async () => { events.push('check'); return null; },
  };
  let isConnected = connected;
  const install = createUpdateInstaller({
    getUpdater: () => updater,
    log: { info() {}, warn() {}, error() {}, debug() {} },
    isConnected: () => isConnected,
    disconnect: async () => { events.push('disconnect'); isConnected = false; },
    reconnect: async () => { events.push('reconnect'); if (reconnectFails) throw new Error('no handshake'); isConnected = true; },
    liftFirewall: async () => { events.push('firewall'); },
    quit: () => { events.push('quit'); },
    quitDelayMs: 5,
  });
  return { install, events, updater };
}

const settle = (ms = 20) => new Promise((r) => setTimeout(r, ms));

describe('createUpdateInstaller', () => {
  it('verifies first, then tunnel down, installer start, quit', async () => {
    const h = harness();
    assert.deepEqual(await h.install(), { ok: true, via: 'spawn' });
    await settle();
    assert.deepEqual(h.events, ['prepare', 'disconnect', 'firewall', 'launch', 'quit']);
  });

  it('nothing ready: the VPN is not touched', async () => {
    const h = harness({ ready: false });
    assert.deepEqual(await h.install(), { ok: false, code: 'not_ready' });
    assert.deepEqual(h.events, []);
  });

  it('a broken installer keeps the VPN and is downloaded again', async () => {
    const h = harness({ prepare: { ok: false, code: 'verify_failed', message: 'changed' } });
    const r = await h.install();
    assert.equal(r.code, 'verify_failed');
    await settle();
    assert.deepEqual(h.events, ['prepare', 'check']);
  });

  it('a failed start reconnects the VPN, reports why and does not quit', async () => {
    const h = harness({ launch: { ok: false, code: 'launch_failed', message: 'UNKNOWN: spawn UNKNOWN' } });
    const r = await h.install();
    assert.deepEqual(r, { ok: false, code: 'launch_failed', message: 'UNKNOWN: spawn UNKNOWN', vpnRestored: true });
    await settle();
    assert.deepEqual(h.events, ['prepare', 'disconnect', 'firewall', 'launch', 'reconnect']);
  });

  it('reconnect failing is reported, not thrown', async () => {
    const h = harness({ launch: { ok: false, code: 'exited', message: 'Exit-Code 2' }, reconnectFails: true });
    assert.deepEqual(await h.install(), { ok: false, code: 'exited', message: 'Exit-Code 2', vpnRestored: false });
  });

  it('without a tunnel nothing is disconnected or reconnected', async () => {
    const h = harness({ connected: false, launch: { ok: false, code: 'exited', message: 'x' } });
    const r = await h.install();
    assert.equal(r.vpnRestored, undefined);
    assert.deepEqual(h.events, ['prepare', 'firewall', 'launch']);
  });

  it('a second click while it runs is refused', async () => {
    const h = harness();
    const a = h.install();
    assert.deepEqual(await h.install(), { ok: false, code: 'busy' });
    assert.equal((await a).ok, true);
  });

  it('an exception becomes a result', async () => {
    const h = harness();
    h.updater.prepareInstall = async () => { throw new Error('boom'); };
    assert.deepEqual(await h.install(), { ok: false, code: 'launch_failed', message: 'boom' });
  });
});

describe('installErrorText', () => {
  it('success → null, failures → reason, detail, VPN note', () => {
    assert.equal(installErrorText({ ok: true }, t), null);
    assert.equal(installErrorText(true, t), null);
    assert.equal(installErrorText({ ok: false, code: 'verify_failed', message: 'hash' }, t), 'Datei beschädigt');
    assert.equal(installErrorText({ ok: false, code: 'launch_failed', message: 'UNKNOWN', vpnRestored: true }, t), 'Installer startet nicht (UNKNOWN) VPN wieder verbunden.');
    assert.equal(installErrorText({ ok: false, code: 'weird' }, t), 'Installer startet nicht');
    assert.equal(installErrorText(false, t), 'Installer startet nicht');
  });
});
