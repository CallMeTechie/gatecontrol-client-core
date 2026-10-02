'use strict';

// Support bundle: collector (content + redaction), sender (confirmation,
// error mapping, admin request dedupe), ApiClient upload (gzip, peerId,
// headers) and the support:send IPC channel.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const zlib = require('node:zlib');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { collectSupportBundle, readTail, MAX_LOG_LINES } = require('../src/support/collector');
const { createSupportBundleSender } = require('../src/support/sender');
const ApiClient = require('../src/services/api-client');
const ConnectionMonitor = require('../src/services/connection-monitor');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const i18n = require('../src/i18n');

const WG_KEY = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=';
const PSK = 'FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=';
const TOKEN = 'gc_' + 'f00dfeed'.repeat(6);
const log = { info() {}, warn() {}, error() {}, debug() {} };

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gc-support-'));
}

function fixture() {
  const dir = tmpDir();
  const wgConfigFile = path.join(dir, 'gatecontrol0.conf');
  fs.writeFileSync(wgConfigFile, `[Interface]\nPrivateKey = ${WG_KEY}\nAddress = 10.8.0.7/32\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = abc\nPresharedKey = ${PSK}\nEndpoint = gate.example.com:51820\nAllowedIPs = 10.8.0.0/24\n`);
  const logFile = path.join(dir, 'main.log');
  const lines = [];
  for (let i = 0; i < MAX_LOG_LINES + 500; i++) lines.push(`[2026-10-02 10:00:00.000] [info] line ${i}`);
  lines.push(`[2026-10-02 10:00:01.000] [warn] API 401: /api/v1/client/ping X-API-Token: ${TOKEN}`);
  lines.push('[2026-10-02 10:00:02.000] [error] Tunnel failed: no handshake');
  fs.writeFileSync(logFile, lines.join('\n') + '\n');
  const storeData = {
    server: { url: 'https://gate.example.com', apiKey: TOKEN, peerId: '7' },
    tunnel: { killSwitch: true, splitTunnel: false, splitRoutes: '10.0.0.0/8' },
    app: { theme: 'dark', locale: 'de' },
    rdp: { savedPassword: 'hunter2' },
  };
  const store = {
    store: storeData,
    get: (k, d) => k.split('.').reduce((o, p) => (o && p in o ? o[p] : undefined), storeData) ?? d,
  };
  const execFile = (cmd, args, opts, cb) => cb(null, `Network Destination  Netmask  Gateway  Interface\n0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.20\n`);
  const ctx = {
    app: { getVersion: () => '1.24.0' },
    store,
    log: { ...log, transports: { file: { getFile: () => ({ path: logFile }) } } },
    getTunnelState: () => ({ connected: true, connectedSince: new Date('2026-10-02T09:00:00Z'), handshakeTimestamp: 1790000000 - 42, endpoint: 'gate.example.com:51820', rxBytes: 1000, txBytes: 2000 }),
    wgConfigFile,
    apiClient: { clientType: 'pro', clientVersion: '1.24.0', clientPlatform: 'windows' },
    locale: 'de',
  };
  const deps = { execFile, now: () => 1790000000 * 1000, platform: 'win32' };
  return { ctx, deps, dir };
}

describe('collectSupportBundle', () => {
  it('collects all sections and leaks no secret', async () => {
    const { ctx, deps } = fixture();
    const b = await collectSupportBundle(ctx, { deps });
    assert.equal(b.schema, 1);
    assert.equal(b.reason, 'user');
    assert.equal(b.client.product, 'pro');
    assert.equal(b.client.version, '1.24.0');
    assert.equal(b.client.coreVersion, require('../package.json').version);
    assert.equal(b.client.platform, 'windows');
    assert.equal(b.client.locale, 'de');
    assert.ok(b.client.os);
    assert.equal(b.tunnel.connected, true);
    assert.equal(b.tunnel.lastHandshakeAgeSec, 42);
    assert.equal(b.tunnel.killSwitch, true);
    assert.equal(b.tunnel.connectedSince, '2026-10-02T09:00:00.000Z');
    assert.equal(b.settings.server.url, 'https://gate.example.com');
    assert.equal(b.settings.server.apiKey, '[REDACTED]');
    assert.equal(b.settings.rdp.savedPassword, '[REDACTED]');
    assert.equal(b.settings.tunnel.splitRoutes, '10.0.0.0/8');
    assert.match(b.wireguardConfig, /PrivateKey = \[REDACTED\]/);
    assert.match(b.wireguardConfig, /Address = 10\.8\.0\.7\/32/);
    assert.ok(Array.isArray(b.network.interfaces));
    assert.ok(Array.isArray(b.network.dnsServers));
    assert.match(b.network.routes, /192\.168\.1\.1/);
    for (const i of b.network.interfaces) for (const a of i.addresses) assert.equal(a.mac, undefined);
    assert.equal(b.logs.lines.length, MAX_LOG_LINES);
    assert.equal(b.logs.truncated, true);
    assert.match(b.logs.lines[b.logs.lines.length - 1], /Tunnel failed/);
    assert.ok(b.errors.some((l) => /Tunnel failed/.test(l)));
    assert.ok(b.errors.some((l) => /API 401/.test(l)));

    const json = JSON.stringify(b);
    for (const secret of [WG_KEY, PSK, TOKEN, 'hunter2']) assert.ok(!json.includes(secret), `leak: ${secret}`);
  });

  it('survives missing files, store and tunnel state', async () => {
    const b = await collectSupportBundle({ wgConfigFile: path.join(tmpDir(), 'nope.conf') }, {
      reason: 'admin_request',
      deps: { execFile: (c, a, o, cb) => cb(new Error('no route')), logFile: path.join(tmpDir(), 'none.log') },
    });
    assert.equal(b.schema, 1);
    assert.equal(b.reason, 'admin_request');
    assert.equal(b.wireguardConfig, null);
    assert.equal(b.network.routes, null);
    assert.deepEqual(b.logs.lines, []);
    assert.ok(b.notes.some((n) => /wireguardConfig/.test(n)));
  });

  it('readTail returns the last lines only', async () => {
    const f = path.join(tmpDir(), 'x.log');
    fs.writeFileSync(f, 'a\nb\nc\nd\n');
    const r = await readTail(f, 2);
    assert.deepEqual(r.lines, ['c', 'd']);
    assert.equal(r.totalLines, 4);
  });
});

function fakeDialog(response) {
  const calls = [];
  return { calls, showMessageBox: async (...args) => { calls.push(args[args.length - 1]); return { response }; } };
}

describe('createSupportBundleSender', () => {
  const okClient = (uploads, fail) => ({
    client: {}, peerId: 7,
    uploadSupportBundle: async (b) => { uploads.push(b); if (fail) throw fail; return { ok: true, bundle: { id: 12 } }; },
  });
  const baseCtx = (extra) => ({ store: { get: () => 'https://gate.example.com:8443' }, getMainWindow: () => ({}), log, ...extra });
  const collect = async (ctx, opts) => ({ schema: 1, reason: opts.reason });

  it('asks first (host + contents) and uploads on confirm', async () => {
    i18n.setLocale('de');
    const uploads = [];
    const dialog = fakeDialog(0);
    const sender = createSupportBundleSender(baseCtx({ dialog, apiClient: okClient(uploads) }), { collect });
    const res = await sender.send();
    assert.deepEqual(res, { success: true, id: 12 });
    assert.equal(uploads.length, 1);
    assert.equal(dialog.calls.length, 1);
    assert.equal(dialog.calls[0].message, 'Diagnosedaten an gate.example.com:8443 senden?');
    assert.match(dialog.calls[0].detail, /Enthalten:/);
    assert.match(dialog.calls[0].detail, /Nicht enthalten: private Schlüssel/);
  });

  it('sends nothing when the user cancels', async () => {
    const uploads = [];
    const sender = createSupportBundleSender(baseCtx({ dialog: fakeDialog(1), apiClient: okClient(uploads) }), { collect });
    assert.deepEqual(await sender.send(), { success: false, cancelled: true });
    assert.equal(uploads.length, 0);
  });

  it('refuses without server/peer, without asking', async () => {
    const dialog = fakeDialog(0);
    const sender = createSupportBundleSender(baseCtx({ dialog, apiClient: { client: null, peerId: null } }), { collect });
    const res = await sender.send();
    assert.equal(res.success, false);
    assert.equal(res.error, i18n.t('support.notConfigured'));
    assert.equal(dialog.calls.length, 0);
  });

  it('maps server errors (429, 413, other)', async () => {
    i18n.setLocale('en');
    const err = (status, error) => Object.assign(new Error('x'), { response: { status, data: { error } } });
    for (const [e, expected] of [
      [err(429, 'rate_limited'), i18n.t('support.rateLimited')],
      [err(413, 'too_large'), i18n.t('support.tooLarge')],
      [err(500, 'upload_failed'), i18n.t('support.failed', { error: 'upload_failed' })],
    ]) {
      const sender = createSupportBundleSender(baseCtx({ dialog: fakeDialog(0), apiClient: okClient([], e) }), { collect });
      const res = await sender.send();
      assert.equal(res.success, false);
      assert.equal(res.error, expected);
    }
  });

  it('admin request: prompts once per request timestamp, mentions the admin', async () => {
    i18n.setLocale('en');
    const uploads = [];
    const dialog = fakeDialog(1); // user declines
    const results = [];
    const sender = createSupportBundleSender(baseCtx({ dialog, apiClient: okClient(uploads), onSupportResult: (r) => results.push(r) }), { collect });
    await sender.onServerRequest('2026-10-02 10:00:00');
    await sender.onServerRequest('2026-10-02 10:00:00');
    assert.equal(dialog.calls.length, 1);
    assert.match(dialog.calls[0].detail, /administrator requested/i);
    await sender.onServerRequest('2026-10-02 11:00:00'); // asked again
    assert.equal(dialog.calls.length, 2);
    await sender.onServerRequest(null);
    await sender.onServerRequest(true);
    assert.equal(dialog.calls.length, 3);
    assert.equal(uploads.length, 0);
    assert.equal(results.length, 3);
  });
});

describe('ApiClient.uploadSupportBundle', () => {
  it('POSTs gzip JSON with peerId and auth headers', async () => {
    let seen;
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        seen = { url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, bundle: { id: 5, created_at: 'x', size_bytes: 10 } }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const c = new ApiClient(`http://127.0.0.1:${server.address().port}`, 'gc_tok', log, 7, { clientType: 'community' });
      c.supportBundleRequest = '2026-10-02 10:00:00';
      const data = await c.uploadSupportBundle({ schema: 1, hello: 'world' });
      assert.equal(data.bundle.id, 5);
      assert.equal(seen.url, '/api/v1/client/support-bundle?peerId=7');
      assert.equal(seen.headers['content-type'], 'application/gzip');
      assert.equal(seen.headers['x-api-token'], 'gc_tok');
      assert.equal(seen.headers['x-client-type'], 'community');
      assert.deepEqual(JSON.parse(zlib.gunzipSync(seen.body).toString()), { schema: 1, hello: 'world' });
      assert.equal(c.supportBundleRequest, null);
    } finally {
      server.close();
    }
  });

  it('refuses without peer', async () => {
    const c = new ApiClient('https://gate.example.com', 'gc_tok', log, null);
    await assert.rejects(c.uploadSupportBundle({ schema: 1 }));
  });

  it('remembers the server request flag from peer-info / heartbeat answers', () => {
    const c = new ApiClient('https://gate.example.com', 'gc_tok', log, 7);
    c._rememberSupportRequest({ ok: true, supportBundleRequested: true, supportBundleRequestedAt: '2026-10-02 10:00:00' });
    assert.equal(c.supportBundleRequest, '2026-10-02 10:00:00');
    c._rememberSupportRequest({ ok: true, supportBundleRequested: true });
    assert.equal(c.supportBundleRequest, true);
    c._rememberSupportRequest({ ok: true }); // older server: unchanged
    assert.equal(c.supportBundleRequest, true);
    c._rememberSupportRequest({ ok: true, supportBundleRequested: false });
    assert.equal(c.supportBundleRequest, null);
  });
});

describe('ConnectionMonitor → onSupportBundleRequest', () => {
  it('passes the request flag after each peer-info check', async () => {
    const seen = [];
    const apiClient = { supportBundleRequest: '2026-10-02 10:00:00', getPeerInfo: async () => ({ enabled: true }) };
    const m = new ConnectionMonitor({ apiClient, log, wgService: {}, onSupportBundleRequest: (r) => seen.push(r) });
    m._peerCheckEveryN = 1;
    await m._checkPeerStatus();
    apiClient.supportBundleRequest = null;
    await m._checkPeerStatus();
    assert.deepEqual(seen, ['2026-10-02 10:00:00', null]);
  });
});

describe('support:send IPC', () => {
  it('is registered and runs the shared sender', async () => {
    const handlers = {};
    const ipcMain = { handle: (ch, fn) => { handlers[ch] = fn; }, on() {} };
    let sent = 0;
    registerBaseHandlers(ipcMain, {
      app: { getVersion: () => '1' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {} },
      wgService: {}, apiClient: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState() {}, wgConfigFile: 'x',
      supportBundle: { send: async (o) => { sent++; return { success: true, id: 1, reason: o.reason }; } },
    });
    assert.ok(handlers['support:send']);
    assert.deepEqual(await handlers['support:send'](), { success: true, id: 1, reason: 'user' });
    assert.equal(sent, 1);
  });
});
