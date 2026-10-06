'use strict';

// The renderer bridge shared by the Pro and Community preloads: channel names
// must stay exactly as before, and every invoked channel must be served by
// the core IPC handlers (locale:* is registered by the apps themselves).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { createBridgeApi, createSubscriber } = require('../src/preload/bridge');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const i18n = require('../src/i18n');

function fakeIpcRenderer() {
  const calls = { invoke: [], send: [], on: [], off: [] };
  return {
    calls,
    invoke: (ch, ...args) => { calls.invoke.push([ch, ...args]); return Promise.resolve(); },
    send: (ch, ...args) => { calls.send.push([ch, ...args]); },
    on: (ch, fn) => { calls.on.push([ch, fn]); },
    removeListener: (ch, fn) => { calls.off.push([ch, fn]); },
  };
}

// Call every function of the bridge once (callbacks get a no-op).
function exercise(api) {
  const walk = (obj) => {
    for (const v of Object.values(obj)) {
      if (typeof v === 'function') {
        const r = v(() => {});
        if (typeof r === 'function') r();
      } else if (v && typeof v === 'object') walk(v);
    }
  };
  walk(api);
}

describe('createBridgeApi', () => {
  it('uses the same channels as the former app preloads', () => {
    const ipc = fakeIpcRenderer();
    exercise(createBridgeApi(ipc, i18n));
    const invoked = [...new Set(ipc.calls.invoke.map((c) => c[0]))].sort();
    assert.deepEqual(invoked, [
      'app:version', 'autostart:set', 'config:get', 'config:getAll', 'config:import-file',
      'config:import-qr', 'config:set', 'dns:leak-test', 'killswitch:toggle', 'locale:get',
      'locale:set', 'logs:export', 'logs:get', 'logs:show', 'permissions:get', 'policy:get', 'policy:refresh', 'portal:open', 'rdp-allow:toggle',
      'server:setup', 'server:test', 'services:list', 'shell:open-external', 'support:send', 'traffic:stats',
      'tunnel:connect', 'tunnel:disconnect', 'tunnel:reconnect', 'tunnel:status', 'update:check', 'update:install',
      'update:policy', 'wireguard:check',
    ]);
    assert.deepEqual(ipc.calls.send.map((c) => c[0]).sort(), ['window:close', 'window:minimize']);
    const events = [...new Set(ipc.calls.on.map((c) => c[0]))].sort();
    assert.deepEqual(events, ['locale:changed', 'navigate', 'peer-expiry', 'policy:changed', 'portal-url', 'tunnel-state', 'update-ready', 'update:policy']);
  });

  it('subscriptions pass the payload and unsubscribe the same handler', () => {
    const ipc = fakeIpcRenderer();
    const api = createBridgeApi(ipc, i18n);
    let got;
    const off = api.tunnel.onState((s) => { got = s; });
    const [ch, handler] = ipc.calls.on[0];
    assert.equal(ch, 'tunnel-state');
    handler({}, { connected: true });
    assert.deepEqual(got, { connected: true });
    off();
    assert.deepEqual(ipc.calls.off[0], ['tunnel-state', handler]);
  });

  it('announces updates on the edition-specific channel', () => {
    const ipc = fakeIpcRenderer();
    createBridgeApi(ipc, i18n, { updateReadyChannel: 'update:ready' }).update.onReady(() => {});
    assert.equal(ipc.calls.on[0][0], 'update:ready');
  });

  it('createSubscriber returns an unsubscribe for edition-specific events', () => {
    const ipc = fakeIpcRenderer();
    const seen = [];
    const off = createSubscriber(ipc)('rdp:progress', (d) => seen.push(d));
    ipc.calls.on[0][1]({}, 42);
    off();
    assert.deepEqual(seen, [42]);
    assert.equal(ipc.calls.off[0][0], 'rdp:progress');
  });

  it('every invoked channel is served by the core handlers (locale:* by the apps)', () => {
    const ipc = fakeIpcRenderer();
    exercise(createBridgeApi(ipc, i18n));
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
      dialog: {},
      getMainWindow: () => null,
      store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {},
      log: { info() {}, warn() {}, error() {}, debug() {} },
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, toggleRdpAllow() {},
      openPortal() {},
      installUpdate() {}, getTunnelState: () => ({}),
      wgConfigFile: 'wg.conf',
    });
    for (const [ch] of ipc.calls.invoke) {
      if (ch.startsWith('locale:')) continue;
      assert.ok(handlers[ch], `no core handler for ${ch}`);
    }
  });
});
