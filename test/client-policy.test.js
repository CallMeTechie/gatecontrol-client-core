'use strict';

// Client policies from the server: pure helpers (normalisation, Windows split
// modes, locks, forced values, config:set rules), the caching service
// (fail-safe semantics, ETag, version hints) and the IPC guards.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const cp = require('../src/utils/client-policy');
const ClientPolicyService = require('../src/services/client-policy');
const { registerBaseHandlers, applyPolicyToStore } = require('../src/ipc/base-handlers');
const ApiClient = require('../src/services/api-client');

const silent = { info() {}, warn() {}, error() {}, debug() {} };

function memStore(initial = {}) {
  const data = { ...initial };
  return {
    data,
    get: (k, d) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : d),
    set: (k, v) => { data[k] = v; },
    delete: (k) => { delete data[k]; },
    get store() { return data; },
  };
}

describe('utils/client-policy', () => {
  it('normalizePolicy: missing/invalid fields fall back to unrestricted', () => {
    assert.deepEqual(cp.normalizePolicy(null), cp.unrestricted());
    const p = cp.normalizePolicy({ killSwitch: 'required', autoConnect: 'sometimes', splitTunnelModes: ['include', 'bogus', 'off'], lockSettings: 'yes', lockServer: true });
    assert.equal(p.killSwitch, 'required');
    assert.equal(p.autoConnect, 'user');
    assert.deepEqual(p.splitTunnelModes, ['off', 'include']);
    assert.equal(p.lockSettings, false);
    assert.equal(p.lockServer, true);
    assert.deepEqual(cp.normalizePolicy({ splitTunnelModes: [] }).splitTunnelModes, ['off', 'exclude', 'include']);
    assert.equal(cp.isManaged(null), false);
    assert.equal(cp.isManaged({ lockServer: true }), true);
  });

  it('windowsSplitModes: intersection with off/include, full tunnel as fallback', () => {
    assert.deepEqual(cp.windowsSplitModes(null), ['off', 'include']);
    assert.deepEqual(cp.windowsSplitModes({ splitTunnelModes: ['off', 'exclude'] }), ['off']);
    assert.deepEqual(cp.windowsSplitModes({ splitTunnelModes: ['exclude'] }), ['off']);
    assert.deepEqual(cp.windowsSplitModes({ splitTunnelModes: ['include'] }), ['include']);
  });

  it('forcedValues and locks', () => {
    const p = { killSwitch: 'required', autoConnect: 'always_on', autostart: 'forbidden', splitTunnelModes: ['off'] };
    assert.deepEqual(cp.forcedValues(p, { splitTunnelEnabled: true }), {
      'tunnel.killSwitch': true,
      'tunnel.autoConnect': true,
      'app.startWithWindows': false,
      'tunnel.splitTunnel': false,
    });
    assert.deepEqual(cp.forcedValues({ splitTunnelModes: ['include'] }, { splitTunnelEnabled: false }), { 'tunnel.splitTunnel': true });
    assert.deepEqual(cp.forcedValues(null), {});
    const l = cp.locks(p);
    assert.equal(l.killSwitch, true);
    assert.equal(l.autoConnect, true);
    assert.equal(l.autostart, true);
    assert.equal(l.splitMode, true);
    assert.equal(l.splitRoutes, false);
    assert.equal(l.settings, false);
    assert.equal(l.disconnect, true);
    assert.equal(cp.canDisconnect({ autoConnect: 'required' }), true);
    const all = cp.locks({ lockSettings: true });
    assert.ok(all.killSwitch && all.autoConnect && all.autostart && all.splitMode && all.splitRoutes && all.settings);
    assert.equal(all.server, false);
  });

  it('canWriteConfig follows the locks; theme/locale stay free', () => {
    const p = { killSwitch: 'required', autostart: 'forbidden', splitTunnelModes: ['off', 'include'] };
    assert.equal(cp.canWriteConfig(p, 'tunnel.killSwitch', false), false);
    assert.equal(cp.canWriteConfig(p, 'tunnel.killSwitch', true), true);
    assert.equal(cp.canWriteConfig(p, 'app.startWithWindows', true), false);
    assert.equal(cp.canWriteConfig(p, 'app.startWithWindows', false), true);
    assert.equal(cp.canWriteConfig(p, 'tunnel.splitTunnel', true), true);
    assert.equal(cp.canWriteConfig({ splitTunnelModes: ['off'] }, 'tunnel.splitTunnel', true), false);
    assert.equal(cp.canWriteConfig({ splitTunnelModes: ['include'], splitTunnelLocked: true }, 'tunnel.splitRoutes', 'x'), false);
    const locked = { lockSettings: true };
    assert.equal(cp.canWriteConfig(locked, 'app.checkInterval', 10), false);
    assert.equal(cp.canWriteConfig(locked, 'tunnel.autoConnect', false), false);
    assert.equal(cp.canWriteConfig(locked, 'app.theme', 'light'), true);
    assert.equal(cp.canWriteConfig(null, 'app.checkInterval', 10), true);
  });
});

describe('ClientPolicyService', () => {
  function api(responses) {
    const calls = [];
    return {
      calls,
      async getClientPolicy(v) {
        calls.push(v);
        const r = responses.shift();
        if (r instanceof Error) throw r;
        return r;
      },
    };
  }
  const answer = (policy, version = 'aaaa1111') => ({ notModified: false, data: { ok: true, version, managed: true, policy } });

  it('never fetched → unrestricted, fetched → persisted and applied', async () => {
    const store = memStore();
    const svc = new ClientPolicyService({ apiClient: api([answer({ killSwitch: 'required' })]), store, log: silent, interval: 0 });
    assert.equal(svc.getState().fetched, false);
    assert.equal(svc.getState().managed, false);
    let changes = 0;
    svc.onChange(() => { changes++; });
    assert.equal(await svc.refresh(), 'updated');
    assert.equal(svc.getPolicy().killSwitch, 'required');
    assert.equal(changes, 1);
    assert.equal(store.data.policy.version, 'aaaa1111');

    // a new instance (app restart, server offline) keeps the last known policy
    const offline = new ClientPolicyService({ apiClient: api([new Error('ECONNREFUSED')]), store, log: silent, interval: 0 });
    assert.equal(offline.getPolicy().killSwitch, 'required');
    assert.equal(await offline.refresh(), 'unavailable');
    assert.equal(offline.getPolicy().killSwitch, 'required');
    assert.equal(offline.getState().fetched, true);
  });

  it('sends the cached version (ETag) and handles 304 / malformed answers', async () => {
    const store = memStore();
    const a = api([answer({ lockServer: true }, 'bbbb'), { notModified: true }, { notModified: false, data: { ok: false } }]);
    const svc = new ClientPolicyService({ apiClient: a, store, log: silent, interval: 0 });
    await svc.refresh();
    assert.equal(await svc.refresh(), 'unchanged');
    assert.equal(await svc.refresh(), 'unavailable');
    assert.deepEqual(a.calls, [null, 'bbbb', 'bbbb']);
    assert.equal(svc.getPolicy().lockServer, true);
  });

  it('noteVersion refreshes only on a different version; reset drops the cache', async () => {
    const store = memStore();
    const a = api([answer({}, 'cccc'), answer({ autostart: 'required' }, 'dddd')]);
    const svc = new ClientPolicyService({ apiClient: a, store, log: silent, interval: 0 });
    await svc.refresh();
    assert.equal(await svc.noteVersion('cccc'), 'unchanged');
    assert.equal(await svc.noteVersion('not a version!'), 'unchanged');
    assert.equal(a.calls.length, 1);
    assert.equal(await svc.noteVersion('dddd'), 'updated');
    assert.equal(svc.getPolicy().autostart, 'required');
    let emitted = null;
    svc.onChange((s) => { emitted = s; });
    svc.reset();
    assert.equal(emitted.fetched, false);
    assert.equal(store.data.policy, undefined);
    assert.equal(svc.getPolicy().autostart, 'user');
  });

  it('a damaged cache counts as never fetched', () => {
    const svc = new ClientPolicyService({ apiClient: api([]), store: memStore({ policy: 'garbage' }), log: silent, interval: 0 });
    assert.equal(svc.getState().fetched, false);
  });
});

describe('ApiClient policy plumbing', () => {
  it('getClientPolicy sends If-None-Match and maps 304', async () => {
    const c = new ApiClient('https://gc.example', 'tok', silent, '1');
    let seen;
    c.client.get = async (url, opts) => {
      seen = { url, opts };
      return { status: 304, data: '' };
    };
    assert.deepEqual(await c.getClientPolicy('abcd'), { notModified: true, data: null });
    assert.equal(seen.url, '/api/v1/client/policy');
    assert.equal(seen.opts.headers['If-None-Match'], '"abcd"');
    assert.equal(seen.opts.validateStatus(304), true);
    assert.equal(seen.opts.validateStatus(500), false);
  });

  it('heartbeat/permissions answers report policyVersion', async () => {
    const c = new ApiClient('https://gc.example', 'tok', silent, '1');
    const seen = [];
    c.onPolicyVersion = (v) => seen.push(v);
    c.client.get = async () => ({ data: { permissions: {}, policyVersion: 'ab12' } });
    c.client.post = async () => ({ data: { ok: true, policyVersion: 'cd34' } });
    await c.getPermissions();
    await c.sendHeartbeat({});
    assert.deepEqual(seen, ['ab12', 'cd34']);
    assert.equal(c.policyVersion, 'cd34');
  });
});

describe('IPC policy guards', () => {
  function setup(policy, overrides = {}) {
    const handlers = {};
    const store = memStore({ 'tunnel.splitTunnel': false });
    const calls = [];
    const clientPolicy = { getPolicy: () => cp.normalizePolicy(policy), getState: () => cp.uiState(policy, { fetched: true }), refresh: async () => 'unchanged' };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1', setLoginItemSettings() { calls.push('login'); } },
      dialog: {}, getMainWindow: () => null, store,
      wgService: {}, apiClient: { configure() {} }, killSwitch: {},
      log: silent,
      connectTunnel() {}, disconnectTunnel() { calls.push('disconnect'); return 'done'; },
      toggleKillSwitch(v) { calls.push(['ks', v]); },
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
      clientPolicy, overrides,
    });
    return { handlers, store, calls };
  }

  it('refuses locked writes, kill-switch off, disconnect, server setup', async () => {
    const { handlers, store, calls } = setup({ killSwitch: 'required', autoConnect: 'always_on', lockServer: true, lockSettings: true });
    assert.equal(handlers['config:set']({}, 'app.checkInterval', 5), false);
    assert.equal(store.data['app.checkInterval'], undefined);
    handlers['config:set']({}, 'app.theme', 'light');
    assert.equal(store.data['app.theme'], 'light');
    assert.deepEqual(handlers['killswitch:toggle']({}, false), { blocked: true, policyLocked: true });
    handlers['killswitch:toggle']({}, true);
    assert.deepEqual(calls, [['ks', true]]);
    assert.deepEqual(handlers['tunnel:disconnect'](), { blocked: true, policyLocked: true });
    const setupRes = await handlers['server:setup']({}, { url: 'https://x', apiKey: 'k' });
    assert.equal(setupRes.success, false);
    assert.equal(setupRes.policyLocked, true);
    const qr = await handlers['config:import-qr']({}, {});
    assert.equal(qr.policyLocked, true);
    assert.equal(handlers['policy:get']().managed, true);
  });

  it('guards wrap client overrides too (autostart)', () => {
    const seen = [];
    const { handlers, store } = setup({ autostart: 'forbidden' }, { 'autostart:set': (_, v) => { seen.push(v); return v; } });
    store.set('app.startWithWindows', false);
    assert.equal(handlers['autostart:set']({}, true), false);
    assert.deepEqual(seen, []);
    assert.equal(handlers['autostart:set']({}, false), false);
    assert.deepEqual(seen, [false]);
  });

  it('unmanaged client: everything passes, policy:get is unrestricted', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: {}, dialog: {}, getMainWindow: () => null, store: memStore(), wgService: {}, apiClient: {}, killSwitch: {},
      log: silent, connectTunnel() {}, disconnectTunnel: () => 'x', toggleKillSwitch() {}, installUpdate() {},
      getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.equal(handlers['tunnel:disconnect'](), 'x');
    assert.deepEqual(handlers['policy:get']().fetched, false);
    assert.deepEqual(handlers['policy:get']().managed, false);
  });

  it('tunnel:reconnect is allowed under always-on; a new server drops the old policy', async () => {
    const order = [];
    const handlers = {};
    let resets = 0;
    let refreshes = 0;
    const svc = {
      getPolicy: () => cp.normalizePolicy({ autoConnect: 'always_on' }),
      getState: () => cp.uiState({ autoConnect: 'always_on' }),
      reset: () => { resets++; },
      refresh: async () => { refreshes++; return 'updated'; },
    };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: {}, dialog: {}, getMainWindow: () => null, store: memStore(), wgService: {},
      apiClient: { configure() {}, ping: async () => ({}), register: async () => ({ peerId: 3 }), setPeerId() {} },
      killSwitch: {}, log: silent,
      connectTunnel: async () => order.push('connect'), disconnectTunnel: async () => order.push('disconnect'),
      toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
      clientPolicy: svc,
    });
    assert.deepEqual(handlers['tunnel:disconnect'](), { blocked: true, policyLocked: true });
    await handlers['tunnel:reconnect']();
    assert.deepEqual(order, ['disconnect', 'connect']);
    const r = await handlers['server:setup']({}, { url: 'https://gc.example', apiKey: 'tok' });
    assert.equal(r.success, true);
    assert.equal(resets, 1);
    assert.equal(refreshes, 1);
  });

  it('applyPolicyToStore sets forced values and reports changes', () => {
    const store = memStore({ 'tunnel.killSwitch': false, 'tunnel.splitTunnel': true, 'app.startWithWindows': true });
    const changed = applyPolicyToStore(store, { killSwitch: 'required', autostart: 'forbidden', splitTunnelModes: ['off'] }, silent);
    assert.deepEqual(changed, { 'tunnel.killSwitch': true, 'app.startWithWindows': false, 'tunnel.splitTunnel': false });
    assert.deepEqual(applyPolicyToStore(store, { killSwitch: 'required' }, silent), {});
  });
});
