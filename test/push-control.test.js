'use strict';

// Phase 5 of the notification center: control events and hello.state
// (PushClient), the coordinator (services/push-control.js) with the real
// ClientPolicyService and ConnectionMonitor, and polling as the fallback —
// against a local HTTP server that plays the push endpoint of servers with
// and without control events.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const PushClient = require('../src/services/push-client');
const PushControl = require('../src/services/push-control');
const ClientPolicyService = require('../src/services/client-policy');
const ConnectionMonitor = require('../src/services/connection-monitor');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = {
  initialDelayMs: 20, maxDelayMs: 160, disabledRetryMs: 300, rateLimitMs: 400,
  connectTimeoutMs: 1000, defaultKeepaliveS: 25, stableAfterMs: 60000, ackDelayMs: 5, networkDebounceMs: 5,
};
const MIN = 60 * 1000;

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pushServer(handler) {
  const requests = [];
  const open = new Set();
  const server = http.createServer((req, res) => {
    const n = requests.length;
    requests.push({ url: req.url, headers: req.headers });
    open.add(res);
    res.on('close', () => open.delete(res));
    handler(req, res, n);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((r) => {
    for (const res of open) res.destroy();
    server.close(() => r());
  });
  cleanups.push(close);
  return { url, requests, open, close, write: (chunk) => { for (const res of open) res.write(chunk); } };
}

const ev = (event, data, id) => `${id != null ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
const HELLO_OLD = { server_time: '2026-10-11T08:00:00.000Z', keepalive_s: 25, retention_h: 72, via: 'direct', unread: 0,
  topics: [{ id: 'devices', label: 'Geräte & Gateways' }] };
const QUIET = { from: '22:00', to: '07:00', tz: 'Europe/Berlin', critical_bypass: true };
const V1 = '3f9a0c1d22b4e7a8'; // policy versions: opaque 16-hex strings (server contract)
const V2 = '0b7e5d2c91a4f360';
const STATE = { policy_version: V1, peer_enabled: true, support_bundle_requested: false, support_bundle_requested_at: null, config_hash: 'h1' };
const HELLO_NEW = { ...HELLO_OLD, quiet: QUIET, state: STATE };

function sse(res, chunks = []) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
  for (const c of chunks) res.write(c);
}

/** ApiClient double: push routes, policy (ETag), peer info, config hash. */
function fakeApi(url) {
  const calls = { acks: [], prefs: [], policy: [], peerInfo: 0 };
  const api = {
    calls,
    serverPolicyVersion: V1,
    peerId: 7,
    serverUrl: url,
    apiKey: 'gc_token',
    configHash: 'h1',
    supportBundleRequest: null,
    buildHeaders: () => ({ 'X-API-Token': 'gc_token', 'X-Client-Platform': 'windows', 'X-Client-Type': 'pro' }),
    pushAck: async (b) => { calls.acks.push(b); return { ok: true }; },
    pushPrefs: async (p) => { calls.prefs.push(p); return { ok: true }; },
    pushInbox: async () => ({ ok: true, items: [], unread: 0 }),
    getClientPolicy: async (known) => {
      calls.policy.push(known);
      const version = api.serverPolicyVersion;
      return known === version ? { notModified: true, data: null } : { notModified: false, data: { ok: true, version, policy: {} } };
    },
    getPeerInfo: async () => { calls.peerInfo++; return { id: 7, enabled: true }; },
  };
  return api;
}

function setup(url, { monitorRunning = true, interval = 300000, onConfigChanged } = {}) {
  const store = createMemoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
  const api = fakeApi(url);
  const pushClient = new PushClient({ apiClient: api, store, log, allowHttp: true, random: () => 1, timing: FAST });
  const clientPolicy = new ClientPolicyService({ apiClient: api, store, log, interval });
  const seen = { disabled: [], support: [], config: 0 };
  const monitor = new ConnectionMonitor({
    interval: 30000, apiClient: api, log,
    wgService: { getStats: async () => ({ connected: true }) },
    onPeerDisabled: (info) => { seen.disabled.push(info); },
    onSupportBundleRequest: (req) => { seen.support.push(req); },
  });
  if (monitorRunning) monitor.running = true; // tunnel up, without the timer
  const control = new PushControl({
    pushClient, clientPolicy, connectionMonitor: monitor, apiClient: api, log,
    onConfigChanged: onConfigChanged || (async () => { seen.config++; }),
  });
  const modes = [];
  control.on('mode', (m) => modes.push(m.relaxed));
  control.start();
  cleanups.push(async () => { control.stop(); pushClient.stop(); clientPolicy.stop(); monitor.stop(); });
  return { api, pushClient, clientPolicy, monitor, control, seen, modes, store };
}

describe('PushClient control events and hello.state', () => {
  it('emits normalized state and control events; controlSupported only with hello.state', async () => {
    const srv = await pushServer((req, res) => sse(res, [
      ev('hello', HELLO_NEW),
      ev('control', { type: 'policy_changed', policy_version: V2 }),
      ev('control', { type: 'support_bundle_requested', requested_at: '2026-10-11 08:01:00' }),
      ev('control', { type: 'peer_state', enabled: false }),
      ev('control', { type: 'config_changed' }),
      ev('control', { type: 'something_new' }),
      ev('control', { type: 'peer_state' }),
      'event: control\ndata: not json\n\n',
    ]));
    const store = createMemoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
    const api = fakeApi(srv.url);
    const client = new PushClient({ apiClient: api, store, log, allowHttp: true, timing: FAST });
    cleanups.push(async () => client.stop());
    const got = { state: [], control: [], hello: [], event: [] };
    for (const k of Object.keys(got)) client.on(k, (x) => got[k].push(x));
    assert.equal(client.controlSupported(), false);
    client.start();
    await waitFor(() => got.control.length === 4, 3000, 'control events');
    await sleep(30);

    assert.equal(client.controlSupported(), true);
    assert.equal(client.status().control, true);
    assert.deepEqual(got.state, [{
      policyVersion: V1, peerEnabled: true, supportBundleRequested: false, supportBundleRequestedAt: null, configHash: 'h1',
    }]);
    assert.deepEqual(got.hello[0].quiet, { from: '22:00', to: '07:00', tz: 'Europe/Berlin', criticalBypass: true });
    assert.deepEqual(got.control, [
      { type: 'policy_changed', policyVersion: V2 },
      { type: 'support_bundle_requested', requestedAt: '2026-10-11 08:01:00' },
      { type: 'peer_state', enabled: false },
      { type: 'config_changed' },
    ]);
    assert.equal(got.event.length, 0, 'control events never surface as generic events');
    assert.equal(api.calls.acks.length, 0, 'control events carry no id and are never acked');
    assert.equal(store.get('notifications.lastSeq'), 0, 'control events do not move the resume position');

    srv.close();
    await waitFor(() => !client.controlSupported(), 3000, 'disconnect');
    assert.equal(client.status().control, false);
  });

  it('older server (no hello.state, no hello.quiet): no control, quiet unknown', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_OLD)]));
    const store = createMemoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
    const client = new PushClient({ apiClient: fakeApi(srv.url), store, log, allowHttp: true, timing: FAST });
    cleanups.push(async () => client.stop());
    const hellos = [];
    const states = [];
    client.on('hello', (h) => hellos.push(h));
    client.on('state', (s) => states.push(s));
    client.start();
    await waitFor(() => hellos.length, 3000, 'hello');
    assert.equal(client.controlSupported(), false);
    assert.equal(client.status().control, false);
    assert.equal(hellos[0].quiet, undefined);
    assert.equal(hellos[0].state, null);
    assert.equal(states.length, 0);
  });

  it('normalizers reject malformed values', () => {
    const { normalizeQuiet, normalizeState, normalizeControl } = PushClient;
    assert.equal(normalizeQuiet(null), null);
    assert.equal(normalizeQuiet({ from: '22:00', to: '22:00', tz: 'UTC' }), null, 'from = to means none');
    assert.equal(normalizeQuiet({ from: '25:00', to: '07:00' }), null);
    assert.deepEqual(normalizeQuiet({ from: '22:00', to: '07:00', tz: 'bad tz!' }), { from: '22:00', to: '07:00', tz: null, criticalBypass: false });
    assert.equal(normalizeState(undefined), null);
    assert.deepEqual(normalizeState({ policy_version: 'zz', peer_enabled: 'no', config_hash: 5, support_bundle_requested_at: 'x' }), {
      policyVersion: null, peerEnabled: null, supportBundleRequested: null, supportBundleRequestedAt: null, configHash: null,
    });
    assert.deepEqual(normalizeState({ policy_version: 'a1b2' }).policyVersion, 'a1b2');
    assert.equal(normalizeState({ policy_version: 7 }).policyVersion, null, 'never a number');
    assert.equal(normalizeState({ support_bundle_requested_at: '2026-10-11 08:15:02' }).supportBundleRequestedAt, '2026-10-11 08:15:02', 'SQLite format (UTC) kept verbatim');
    assert.equal(normalizeState({ support_bundle_requested_at: '2026-10-11T08:15:02Z' }).supportBundleRequestedAt, '2026-10-11T08:15:02Z');
    assert.equal(normalizeControl({ type: 'support_bundle_requested', requested_at: 'yesterday' }).requestedAt, null);
    assert.equal(normalizeControl({ type: 'policy_changed', policy_version: 8 }).policyVersion, null);
    assert.equal(normalizeControl({ type: 'peer_state', enabled: 'false' }), null);
    assert.equal(normalizeControl({ type: '__proto__' }), null);
    assert.equal(normalizeControl([]), null);
    assert.deepEqual(normalizeControl({ type: 'support_bundle_requested' }), { type: 'support_bundle_requested', requestedAt: null });
  });

  it('fetchPrefs reads the quiet hours (GET prefs) and maps errors', async () => {
    const store = createMemoryStore({ notifications: {} });
    const mk = (getPushPrefs) => new PushClient({ apiClient: { getPushPrefs }, store, log });
    assert.deepEqual(await mk(async () => ({ ok: true, enabled: true, quiet: QUIET })).fetchPrefs(),
      { ok: true, quiet: { from: '22:00', to: '07:00', tz: 'Europe/Berlin', criticalBypass: true }, hasQuiet: true });
    assert.deepEqual(await mk(async () => ({ ok: true, enabled: true })).fetchPrefs(), { ok: true, quiet: null, hasQuiet: false });
    const e404 = Object.assign(new Error('nf'), { response: { status: 404, data: {} } });
    assert.deepEqual(await mk(async () => { throw e404; }).fetchPrefs(), { ok: false, error: 'http_404' });
    assert.deepEqual(await new PushClient({ apiClient: {}, store, log }).fetchPrefs(), { ok: false, error: 'unsupported' });
  });
});

describe('PushControl: polling as the fallback', () => {
  it('stretches policy and peer-info polling while the stream has control, reverts on disconnect', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_NEW)]));
    const { pushClient, clientPolicy, monitor, control, modes } = setup(srv.url);
    clientPolicy.start();
    assert.equal(clientPolicy.pollInterval(), 300000);
    assert.deepEqual(monitor.peerCheckMode(), { mode: 'cycles', every: 2, ms: 60000 });

    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    assert.equal(clientPolicy.pollInterval(), 30 * MIN);
    assert.deepEqual(monitor.peerCheckMode(), { mode: 'interval', ms: 15 * MIN });
    assert.equal(monitor.interval, 30000, 'the WireGuard stats check keeps its interval');

    srv.close();
    await waitFor(() => !control.relaxed, 3000, 'revert');
    assert.equal(clientPolicy.pollInterval(), 300000);
    assert.deepEqual(monitor.peerCheckMode(), { mode: 'cycles', every: 2, ms: 60000 });
    assert.deepEqual(modes, [true, false]);
  });

  it('older server: nothing changes', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_OLD), ev('control', { type: 'config_changed' })]));
    const { pushClient, clientPolicy, monitor, control, modes, seen } = setup(srv.url);
    clientPolicy.start();
    const hello = new Promise((r) => pushClient.once('hello', r));
    pushClient.start();
    await hello;
    await sleep(30);
    assert.equal(control.relaxed, false);
    assert.equal(clientPolicy.pollInterval(), 300000);
    assert.deepEqual(monitor.peerCheckMode().mode, 'cycles');
    assert.deepEqual(modes, []);
    assert.equal(seen.config, 1, 'a control event is still honoured');
  });

  it('push disabled on the server (404): normal polling', async () => {
    const srv = await pushServer((req, res) => { res.writeHead(404); res.end(); });
    const { pushClient, control } = setup(srv.url);
    pushClient.start();
    await waitFor(() => pushClient.status().reason === 'unsupported', 3000, '404');
    assert.equal(control.relaxed, false);
  });

  it('never polls more often than configured (long user interval stays)', () => {
    const p = new ClientPolicyService({ apiClient: null, store: createMemoryStore({}), log, interval: 2 * 60 * MIN });
    p.setPollInterval(30 * MIN);
    assert.equal(p.pollInterval(), 2 * 60 * MIN);
    p.setPollInterval(null);
    assert.equal(p.pollInterval(), 2 * 60 * MIN);
    const off = new ClientPolicyService({ apiClient: null, store: createMemoryStore({}), log, interval: 0 });
    off.setPollInterval(30 * MIN);
    assert.equal(off.pollInterval(), 0);
  });

  it('relaxedInterval() stretches the apps\' own polls (Community config/check)', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_NEW)]));
    const { pushClient, control } = setup(srv.url);
    assert.equal(control.relaxedInterval('config', 300000), 300000);
    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    assert.equal(control.relaxedInterval('config', 300000), 30 * MIN);
    assert.equal(control.relaxedInterval('config', 60 * MIN), 60 * MIN);
    assert.equal(control.relaxedInterval('unknown', 300000), 300000);
  });
});

describe('PushControl: reactions', () => {
  it('control events: policy refresh, support bundle, peer disabled, config check', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_NEW)]));
    const { pushClient, api, seen, monitor, control } = setup(srv.url);
    const handled = [];
    control.on('control', (c) => handled.push(c.type));
    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    await waitFor(() => api.calls.policy.length === 1, 3000, 'policy refresh on first hello (nothing cached)');

    // same version as cached → nothing to fetch
    srv.write(ev('control', { type: 'policy_changed', policy_version: V1 }));
    await sleep(40);
    assert.equal(api.calls.policy.length, 1);

    api.serverPolicyVersion = V2;
    srv.write(ev('control', { type: 'policy_changed', policy_version: V2 }));
    await waitFor(() => api.calls.policy.length === 2, 3000, 'policy refresh on control');
    assert.deepEqual(api.calls.policy, [null, V1], 'If-None-Match with the cached version');

    srv.write(ev('control', { type: 'support_bundle_requested', requested_at: '2026-10-11 08:05:00' }));
    await waitFor(() => seen.support.includes('2026-10-11 08:05:00'), 3000, 'support request');
    assert.equal(api.supportBundleRequest, '2026-10-11 08:05:00', 'same value as peer-info supportBundleRequestedAt');

    srv.write(ev('control', { type: 'config_changed' }));
    await waitFor(() => seen.config === 1, 3000, 'config check');

    srv.write(ev('control', { type: 'peer_state', enabled: true }));
    srv.write(ev('control', { type: 'peer_state', enabled: false }));
    await waitFor(() => seen.disabled.length === 1, 3000, 'peer disabled');
    assert.deepEqual(seen.disabled[0], { enabled: false, source: 'push' });
    assert.equal(monitor.running, false, 'monitor stopped like on a peer-info answer');
    srv.write(ev('control', { type: 'peer_state', enabled: false }));
    await sleep(40);
    assert.equal(seen.disabled.length, 1, 'only once while the tunnel is down');
    assert.deepEqual(handled, ['policy_changed', 'policy_changed', 'support_bundle_requested', 'config_changed', 'peer_state', 'peer_state', 'peer_state']);
    assert.equal(api.calls.peerInfo, 0, 'no peer-info polling needed');
  });

  it('hello.state catches up after reconnect: support request, disabled peer, changed config hash', async () => {
    const states = [
      { ...STATE },
      { ...STATE, support_bundle_requested: true, support_bundle_requested_at: '2026-10-11 09:00:00', peer_enabled: false, config_hash: 'h2' },
    ];
    const srv = await pushServer((req, res, n) => {
      sse(res, [ev('hello', { ...HELLO_NEW, state: states[Math.min(n, 1)] })]);
      if (n === 0) setTimeout(() => res.destroy(), 30);
    });
    const { pushClient, api, seen } = setup(srv.url);
    pushClient.start();
    await waitFor(() => srv.requests.length >= 2 && seen.disabled.length === 1, 3000, 'second hello');
    await waitFor(() => seen.config === 1, 3000, 'config check');
    assert.deepEqual(seen.support, [null, '2026-10-11 09:00:00'], 'first hello clears, second requests (same handler as peer-info)');
    assert.equal(api.supportBundleRequest, '2026-10-11 09:00:00');
    assert.deepEqual(seen.disabled, [{ enabled: false, source: 'hello' }]);
    assert.equal(api.calls.policy.length, 1, 'same policy_version on reconnect → no second refresh');
  });

  it('hello.state with a hash version uses noteVersion (no refresh when cached)', () => {
    const api = fakeApi('http://x');
    const policy = { noted: [], refreshed: 0, noteVersion(v) { this.noted.push(v); }, refresh() { this.refreshed++; return Promise.resolve(); } };
    const push = new (require('node:events'))();
    push.controlSupported = () => false;
    const control = new PushControl({ pushClient: push, clientPolicy: policy, apiClient: api, log });
    control.start();
    control.handleState(PushClient.normalizeState({ policy_version: 'abc123', config_hash: 'h1' }));
    assert.deepEqual(policy.noted, ['abc123']);
    assert.equal(policy.refreshed, 0);
    control.handleState(PushClient.normalizeState({ policy_version: 'abc123', config_hash: null }));
    assert.deepEqual(policy.noted, ['abc123', 'abc123']);
    control.stop();
  });

  it('a token without a peer (peer_enabled:false, config_hash null) disables nothing', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', { ...HELLO_NEW,
      state: { policy_version: V1, peer_enabled: false, support_bundle_requested: false, support_bundle_requested_at: null, config_hash: null } })]));
    const { pushClient, api, seen, monitor, control } = setup(srv.url);
    api.peerId = null;
    api.configHash = null;
    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    srv.write(ev('control', { type: 'peer_state', enabled: false }));
    await sleep(40);
    assert.equal(seen.disabled.length, 0);
    assert.equal(monitor.running, true);
    assert.equal(seen.config, 0);
  });

  it('peer disabled while the tunnel is down: nothing to disconnect', () => {
    const push = new (require('node:events'))();
    push.controlSupported = () => false;
    const seen = [];
    const monitor = new ConnectionMonitor({ apiClient: {}, log, wgService: {}, onPeerDisabled: (i) => seen.push(i) });
    const control = new PushControl({ pushClient: push, connectionMonitor: monitor, log });
    control.start();
    control.handleControl({ type: 'peer_state', enabled: false });
    control.handleState({ peerEnabled: false });
    assert.equal(seen.length, 0);
  });

  it('config checks are coalesced while one runs; errors are contained', async () => {
    const push = new (require('node:events'))();
    push.controlSupported = () => false;
    let runs = 0;
    let release;
    const control = new PushControl({
      pushClient: push, log,
      onConfigChanged: async () => { runs++; if (runs === 1) await new Promise((r) => { release = r; }); else throw new Error('boom'); },
    });
    control.start();
    control.handleControl({ type: 'config_changed' });
    control.handleControl({ type: 'config_changed' });
    control.handleControl({ type: 'config_changed' });
    await waitFor(() => release, 1000, 'first run');
    release();
    await control.idle();
    assert.equal(runs, 2);
  });

  it('a throwing reaction does not break the push client', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_NEW), ev('control', { type: 'support_bundle_requested' })]));
    const store = createMemoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
    const api = fakeApi(srv.url);
    const pushClient = new PushClient({ apiClient: api, store, log, allowHttp: true, timing: FAST });
    const monitor = { supportBundleRequest() { throw new Error('boom'); }, setPeerCheckInterval() {} };
    const control = new PushControl({ pushClient, connectionMonitor: monitor, apiClient: api, log });
    control.start();
    cleanups.push(async () => { control.stop(); pushClient.stop(); });
    const notes = [];
    pushClient.on('notification', (n) => notes.push(n));
    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    srv.write(ev('notification', { seq: 9, id: 19, title: 't', priority: 'info', topic: 'devices' }, 9));
    await waitFor(() => notes.length === 1, 3000, 'notification after a failing reaction');
  });

  it('stop() unsubscribes and restores normal polling', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO_NEW)]));
    const { pushClient, clientPolicy, control, seen } = setup(srv.url);
    pushClient.start();
    await waitFor(() => control.relaxed, 3000, 'relaxed');
    control.stop();
    assert.equal(control.relaxed, false);
    assert.equal(clientPolicy.pollInterval(), 300000);
    srv.write(ev('control', { type: 'config_changed' }));
    await sleep(40);
    assert.equal(seen.config, 0);
  });
});

describe('ConnectionMonitor peer-info cadence', () => {
  function monitorWith({ interval = 15 } = {}) {
    let peerInfo = 0;
    const support = [];
    const m = new ConnectionMonitor({
      interval, log,
      apiClient: { getPeerInfo: async () => { peerInfo++; return { enabled: true }; }, supportBundleRequest: null },
      wgService: { getStats: async () => ({ connected: true }) },
      onPeerDisabled() {},
      onSupportBundleRequest: (r) => support.push(r),
    });
    cleanups.push(async () => m.stop());
    return { m, count: () => peerInfo, support };
  }

  it('every 2nd cycle normally; time-based while push delivers; back immediately', async () => {
    const { m, count } = monitorWith({ interval: 15 });
    m.start();
    await sleep(110);
    const normal = count();
    assert.ok(normal >= 2, `peer-info polled every 2nd cycle (got ${normal})`);

    m.setPeerCheckInterval(10 * MIN);
    const before = count();
    await sleep(110);
    assert.equal(count(), before, 'no peer-info within the stretched interval');

    m.setPeerCheckInterval(null);
    await waitFor(() => count() > before, 1000, 'peer-info right after reverting');
  });

  it('peerDisabled() and supportBundleRequest() are safe handlers', () => {
    const { m, support } = monitorWith();
    assert.equal(m.peerDisabled({}), false, 'not running → no handler');
    m.running = true;
    m.onPeerDisabled = () => { throw new Error('boom'); };
    assert.equal(m.peerDisabled({}), true);
    assert.equal(m.running, false);
    m.supportBundleRequest('2026-10-11T10:00:00Z');
    m.supportBundleRequest(false);
    assert.deepEqual(support, ['2026-10-11T10:00:00Z', null]);
  });
});
