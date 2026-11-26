'use strict';

// The home cache of the gateways (phase 3b) in the Windows apps: the PC's LAN addresses (X-GC-Local), the `lan` hint
// of the server checked, the download from the gateway with the certificate pinned (a certificate exactly as the
// gateway makes it: self-signed, no name) and the bytes' SHA-256 checked, a quiet fall back to the server on any
// error — Drive's content (open, save as, vault, folder backup) and the app update —, and Drive 1.20 "offline
// verfügbar" (API, service, IPC).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'electron') return require.resolve('./fixtures/electron-stub');
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const electron = require('electron');
const axios = require('axios');
const HC = require('../src/utils/home-cache');
const { fetchLan, PinnedAgent } = require('../src/services/home-cache');
const DriveApi = require('../src/services/drive-api');
const DriveService = require('../src/services/drive');
const ApiClient = require('../src/services/api-client');
const Updater = require('../src/services/updater');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');
const { makeSelfSigned } = require('./fixtures/self-signed');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const loopback = (h) => h === '127.0.0.1';
const IFACES = {
  WLAN: [{ address: '192.168.1.23', family: 'IPv4', internal: false }, { address: 'fe80::1', family: 'IPv6', internal: false }],
  Ethernet: [{ address: '10.0.0.5', family: 'IPv4', internal: false }],
  gatecontrol0: [{ address: '10.8.0.2', family: 'IPv4', internal: false }],
  'vEthernet (WSL)': [{ address: '172.20.0.1', family: 'IPv4', internal: false }],
  'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
  Mobilfunk: [{ address: '100.70.1.2', family: 'IPv4', internal: false }],
};

/** The gateway's LAN endpoint: GET /blob/<sha256>?exp&sig → the blob (or what `srv.answer` says). */
async function gateway(blobs = {}) {
  const cert = makeSelfSigned();
  const srv = { hits: [], answer: null, tlsSha256: cert.sha256 };
  const server = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
    srv.hits.push(req.url);
    const m = /^\/blob\/([0-9a-f]{64})\?exp=\d+&sig=[0-9a-f]+$/.exec(req.url);
    if (srv.answer) return srv.answer(req, res);
    if (!m || !blobs[m[1]]) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not_cached"}'); }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': blobs[m[1]].length });
    return res.end(blobs[m[1]]);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  cleanup.push(() => new Promise((r) => server.close(r)));
  srv.base = `https://127.0.0.1:${server.address().port}`;
  srv.lan = (hash, over = {}) => ({ url: `${srv.base}/blob/${hash}?exp=1999999999&sig=${'ab'.repeat(32)}`, sha256: hash, tlsSha256: cert.sha256, exp: 1999999999, ...over });
  return srv;
}

// ── Helpers ──────────────────────────────────────────────

describe('home cache: helpers', () => {
  it('X-GC-Local: private IPv4 of the real adapters only, at most four', () => {
    assert.deepEqual(HC.localAddresses(IFACES), ['192.168.1.23', '10.0.0.5']);
    assert.equal(HC.localHeader(IFACES), '192.168.1.23,10.0.0.5');
    assert.equal(HC.localHeader({ WLAN: [{ address: '100.64.0.1', family: 'IPv4' }] }), null);
    assert.equal(HC.localHeader(null), null);
    const many = { Ethernet: ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'].map((address) => ({ address, family: 'IPv4' })) };
    assert.equal(HC.localAddresses(many).length, 4);
    assert.equal(HC.isPrivateV4('172.31.255.255'), true);
    assert.equal(HC.isPrivateV4('172.32.0.1'), false);
    assert.equal(HC.isPrivateV4('192.168.01.1'), false);
    assert.equal(HC.isPrivateV4('8.8.8.8'), false);
  });

  it('a lan hint: https to a private IPv4, /blob/<sha256>, a fingerprint, exp', () => {
    const h = 'a'.repeat(64);
    const ok = { url: `https://192.168.1.23:8443/blob/${h}?exp=1700000600&sig=${'0f'.repeat(32)}`, sha256: h.toUpperCase(), tlsSha256: 'AB:'.repeat(31) + 'AB', exp: 1700000600 };
    assert.deepEqual(HC.normalizeLan(ok), { url: ok.url, sha256: h, tlsSha256: 'ab'.repeat(32), exp: 1700000600 });
    assert.equal(HC.normalizeLan({ ...ok, url: ok.url.replace('https:', 'http:') }), null);
    assert.equal(HC.normalizeLan({ ...ok, url: ok.url.replace('192.168.1.23', '203.0.113.5') }), null);
    assert.equal(HC.normalizeLan({ ...ok, url: ok.url.replace('192.168.1.23', 'nas.local') }), null);
    assert.equal(HC.normalizeLan({ ...ok, url: ok.url.replace('https://', 'https://u:p@') }), null);
    assert.equal(HC.normalizeLan({ ...ok, url: ok.url.replace('/blob/', '/other/') }), null);
    assert.equal(HC.normalizeLan({ ...ok, sha256: 'b'.repeat(64) }), null);
    assert.equal(HC.normalizeLan({ ...ok, tlsSha256: 'nope' }), null);
    assert.equal(HC.normalizeLan({ ...ok, exp: '1700000600' }), null);
    assert.equal(HC.normalizeLan(ok, { expectSha256: 'c'.repeat(64) }), null);
    assert.ok(HC.normalizeLan(ok, { expectSha256: h }));
    assert.equal(HC.normalizeLan(null), null);
    assert.equal(HC.lanWhere(ok), '192.168.1.23:8443');
  });
});

// ── The download from the gateway ────────────────────────

describe('home cache: fetchLan (pinned)', () => {
  const blob = Buffer.from('Urlaubsfoto '.repeat(5000));
  const h = sha(blob);

  it('loads the blob when the certificate has the pin and the bytes their SHA-256', async () => {
    const gw = await gateway({ [h]: blob });
    const file = path.join(tmpDir('hc-'), 'x.part');
    const seen = [];
    const r = await fetchLan(gw.lan(h), file, { size: blob.length, onProgress: (got) => seen.push(got) });
    assert.deepEqual(r, { bytes: blob.length, sha256: h });
    assert.deepEqual(fs.readFileSync(file), blob);
    assert.equal(gw.hits.length, 1);
    assert.equal(seen.at(-1), blob.length);
  });

  it('another certificate: refused before a single byte of the request is sent', async () => {
    const gw = await gateway({ [h]: blob });
    const file = path.join(tmpDir('hc-'), 'x.part');
    await assert.rejects(fetchLan(gw.lan(h, { tlsSha256: 'cd'.repeat(32) }), file), (e) => e.code === 'tls_pin');
    assert.equal(gw.hits.length, 0);
    assert.equal(fs.existsSync(file), false);
    assert.throws(() => new PinnedAgent({ pin: 'kein pin' }), (e) => e.code === 'tls_pin');
  });

  it('other bytes, a refusal, the wrong size, too large: an error and no file', async () => {
    const gw = await gateway({ [h]: blob });
    const dir = tmpDir('hc-');
    await assert.rejects(fetchLan(gw.lan('e'.repeat(64)), path.join(dir, 'a')), (e) => e.code === 'http_404');
    gw.answer = (_q, res) => { res.writeHead(200, { 'Content-Length': 5 }); res.end('fremd'); };
    await assert.rejects(fetchLan(gw.lan(h), path.join(dir, 'b')), (e) => e.code === 'sha256_mismatch');
    await assert.rejects(fetchLan(gw.lan(h), path.join(dir, 'c'), { size: blob.length }), (e) => e.code === 'size_mismatch');
    gw.answer = (_q, res) => { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end('{"error":"expired"}'); };
    await assert.rejects(fetchLan(gw.lan(h), path.join(dir, 'd')), (e) => e.code === 'http_403');
    gw.answer = (_q, res) => { res.writeHead(200); res.end(blob); };
    await assert.rejects(fetchLan(gw.lan(h), path.join(dir, 'e'), { maxBytes: 100 }), (e) => e.code === 'too_large');
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it('nobody answers: a network error, quickly', async () => {
    const file = path.join(tmpDir('hc-'), 'x');
    const lan = { url: `https://127.0.0.1:1/blob/${h}?exp=1&sig=00`, sha256: h, tlsSha256: 'ab'.repeat(32), exp: 1 };
    await assert.rejects(fetchLan(lan, file), (e) => e.code === 'network');
  });
});

// ── Drive ────────────────────────────────────────────────

async function driveSetup(features = ['offline'], { getInterfaces = () => IFACES, shell = null } = {}) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {}, getInterfaces, lanHostOk: loopback });
  const temp = tmpDir('hc-drive-');
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => temp, shell });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api, temp };
}

const mediaHits = (srv) => srv.state.requests.filter((r) => r.method === 'GET' && /\/gatecontrol-drive\/media\/[^/]+$/.test(r.path));

describe('home cache: Drive content', () => {
  it('content() sends X-GC-Local (not for a version, not without LAN addresses) and keeps a valid lan', async () => {
    const { srv, api } = await driveSetup();
    const n = srv.state.nodes.get(12);
    const data = srv.state.media.get(n.mediaId).data;
    srv.lan = (node, local) => (local ? { url: `https://127.0.0.1:9/blob/${sha(data)}?exp=1999999999&sig=00`, sha256: sha(data), tlsSha256: 'ab'.repeat(32), exp: 1999999999 } : null);
    const c = await api.content(12);
    assert.equal(c.lan.sha256, sha(data));
    assert.deepEqual(srv.state.local, [{ method: 'GET', route: 'nodes/12/content', value: '192.168.1.23,10.0.0.5' }]);
    const v = await api.content(11, 501);
    assert.equal(v.lan, null);
    assert.equal(srv.state.local.length, 1);
    // a hint the app may not use (public address) is dropped
    srv.lan = () => ({ url: `https://203.0.113.9/blob/${sha(data)}?exp=1&sig=00`, sha256: sha(data), tlsSha256: 'ab'.repeat(32), exp: 1 });
    assert.equal((await api.content(12)).lan, null);
    const none = await driveSetup(['offline'], { getInterfaces: () => ({ gatecontrol0: [{ address: '10.8.0.2', family: 'IPv4' }] }) });
    await none.api.content(12);
    assert.deepEqual(none.srv.state.local, []);
  });

  it('opens a file from the home gateway; another certificate or a failure there: from the server', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; } };
    const { srv, svc } = await driveSetup(['offline'], { shell });
    const n = srv.state.nodes.get(12);
    const data = srv.state.media.get(n.mediaId).data;
    const gw = await gateway({ [sha(data)]: data });
    srv.lan = () => gw.lan(sha(data));
    const r = await svc.open(12);
    assert.equal(r.ok, true);
    assert.equal(fs.readFileSync(r.path, 'utf8'), '%PDF-1.4 brief');
    assert.equal(gw.hits.length, 1);
    assert.equal(mediaHits(srv).length, 0);
    // the pin does not match: not a byte to the gateway, the server's copy
    srv.lan = () => gw.lan(sha(data), { tlsSha256: 'cd'.repeat(32) });
    fs.rmSync(path.dirname(r.path), { recursive: true, force: true });
    const r2 = await svc.open(12);
    assert.equal(fs.readFileSync(r2.path, 'utf8'), '%PDF-1.4 brief');
    assert.equal(gw.hits.length, 1);
    assert.equal(mediaHits(srv).length, 1);
    // the gateway sends other bytes: the server's copy, no .part left
    gw.answer = (_q, res) => { res.writeHead(200); res.end('%PDF-1.4 falsch'); };
    srv.lan = () => gw.lan(sha(data));
    fs.rmSync(path.dirname(r.path), { recursive: true, force: true });
    const r3 = await svc.open(12);
    assert.equal(fs.readFileSync(r3.path, 'utf8'), '%PDF-1.4 brief');
    assert.equal(mediaHits(srv).length, 2);
    assert.deepEqual(fs.readdirSync(path.dirname(r3.path)), ['Brief.pdf']);
  });

  it('downloadTo without lan: from the server as before', async () => {
    const { srv, api } = await driveSetup();
    const c = await api.content(12);
    assert.equal(c.lan, null);
    const file = path.join(tmpDir('hc-'), 'b.pdf');
    const r = await api.downloadTo(c, file);
    assert.equal(r.via, 'server');
    assert.equal(fs.readFileSync(file, 'utf8'), '%PDF-1.4 brief');
    assert.equal(mediaHits(srv).length, 1);
  });
});

describe('home cache: previews (Drive 1.24)', () => {
  const jpeg = (t) => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from(t)]);
  const previewHits = (srv) => srv.state.requests.filter((r) => r.method === 'GET' && /\/gatecontrol-drive\/media\/[^/]+\/preview/.test(r.path));

  it('lists go out with X-GC-Local; a preview the list names on the gateway comes from there, pinned and checked', async () => {
    const { srv, api } = await driveSetup(['offline', 'homeCache', 'homeCachePreviews']);
    const p = srv.mutate.photo(1, 'Strand.jpg');
    const small = jpeg('klein');
    const large = jpeg('gross');
    const gw = await gateway({ [sha(small)]: small, [sha(large)]: large });
    srv.previewLan = (n, local, size) => (local && n.id === p.id ? gw.lan(sha(size === 'small' ? small : large)) : null);
    await api.me();
    await api.folder(1);
    assert.ok(srv.state.local.some((x) => x.route === 'nodes/1/children' && x.value === '192.168.1.23,10.0.0.5'));
    const r = await api.preview(p.mediaId);
    assert.equal(r.mime, 'image/jpeg');
    assert.ok(Buffer.compare(r.data, small) === 0);
    const l = await api.preview(p.mediaId, { large: true });
    assert.ok(Buffer.compare(l.data, large) === 0);
    assert.equal(gw.hits.length, 2);
    assert.equal(previewHits(srv).length, 0);
    // a file the list named no hint for: from the server
    const other = srv.mutate.photo(1, 'Wald.jpg');
    assert.ok((await api.preview(other.mediaId)).data.length > 0);
    assert.equal(previewHits(srv).length, 1);
  });

  it('other bytes or no answer at the gateway: the server\'s preview, and for a minute no gateway', async () => {
    const { srv, api } = await driveSetup(['offline', 'homeCache', 'homeCachePreviews']);
    const a = srv.mutate.photo(1, 'A.jpg');
    const b = srv.mutate.photo(1, 'B.jpg');
    const gw = await gateway({});
    gw.answer = (_q, res) => { res.writeHead(200); res.end('falsch'); };
    srv.previewLan = (n, local) => (local ? gw.lan(sha(jpeg(n.name))) : null);
    await api.me();
    await api.folder(1);
    const ra = await api.preview(a.mediaId);
    assert.equal(ra.mime, 'image/jpeg');
    assert.equal(gw.hits.length, 1);
    assert.equal(previewHits(srv).length, 1);
    // paused: B goes to the server without asking the gateway
    await api.preview(b.mediaId);
    assert.equal(gw.hits.length, 1);
    assert.equal(previewHits(srv).length, 2);
  });

  it('without the feature: lists without X-GC-Local, hints not used', async () => {
    const { srv, api } = await driveSetup(['offline', 'homeCache']);
    const p = srv.mutate.photo(1, 'C.jpg');
    const gw = await gateway({});
    srv.previewLan = () => gw.lan('e'.repeat(64));
    await api.me();
    await api.folder(1);
    assert.equal(srv.state.local.filter((x) => x.route === 'nodes/1/children').length, 0);
    await api.preview(p.mediaId);
    assert.equal(gw.hits.length, 0);
    assert.equal(previewHits(srv).length, 1);
  });
});

describe('Drive 1.20: offline verfügbar', () => {
  it('mark, list, unmark — API, service and IPC', async () => {
    const { srv, svc } = await driveSetup(['offline']);
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc });
    const on = await handlers['drive:offline:set'](null, { id: 12, on: true });
    assert.equal(on.ok, true);
    assert.equal(on.offline, true);
    assert.equal(on.node.offline, true);
    assert.equal(typeof on.node.offlineAt, 'number');
    assert.ok(srv.state.offline.has(12));
    const list = await handlers['drive:offline'](null, {});
    assert.deepEqual(list.ids, [12]);
    assert.equal(list.items[0].name, 'Brief.pdf');
    const off = await handlers['drive:offline:set'](null, { id: 12, on: false });
    assert.deepEqual({ ok: off.ok, id: off.id, offline: off.offline }, { ok: true, id: 12, offline: false });
    assert.deepEqual((await svc.offlineList()).ids, []);
    const bad = await handlers['drive:offline:set'](null, { id: 12, on: 'ja' });
    assert.equal(bad.ok, false);
    assert.equal(bad.code, 'invalid');
    srv.offlineMax = 0;
    const full = await handlers['drive:offline:set'](null, { id: 12, on: true });
    assert.equal(full.ok, false);
    assert.equal(full.code, 'invalid');
  });

  it('an older Drive: unsupported', async () => {
    const { svc } = await driveSetup(['devices']);
    await assert.rejects(svc.offlineList(), (e) => e.code === 'unsupported');
    await assert.rejects(svc.setOffline(12, true), (e) => e.code === 'unsupported');
  });
});

// ── The app update ───────────────────────────────────────

describe('home cache: app update', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const PUB = publicKey.export({ type: 'spki', format: 'pem' });
  const INSTALLER = Buffer.from('MZ installer '.repeat(2000));
  const H = sha(INSTALLER);
  const FILE = 'GateControl.Pro.Client.Setup.1.1.0.exe';
  const manifest = JSON.stringify({ schema: 1, product: 'pro', version: '1.1.0', fileName: FILE, sha256: H, size: INSTALLER.length });
  const signature = crypto.sign(null, Buffer.from(manifest), privateKey).toString('base64');

  function run({ lan, fetch = undefined, ifaces = IFACES }) {
    electron.__state.version = '1.0.0';
    const calls = [];
    const realGet = axios.get;
    axios.get = async (url, opts = {}) => {
      calls.push({ url, opts });
      if (url.endsWith('/api/v1/client/update/check')) {
        return { data: { ok: true, available: true, version: '1.1.0', downloadUrl: `https://github.com/x/releases/download/v1.1.0/${FILE}`, fileName: FILE, fileSize: INSTALLER.length, manifest, signature, ...(lan ? { lan } : {}) } };
      }
      return { data: Readable.from([INSTALLER]) };
    };
    cleanup.push(() => { axios.get = realGet; });
    const dir = tmpDir('hc-upd-');
    const lines = [];
    const ulog = { info: (m) => lines.push(m), warn: (m) => lines.push(m), error: (m) => lines.push(m), debug() {} };
    const u = new Updater({
      serverUrl: 'https://gate.example.com', apiKey: 't', log: ulog, product: 'pro', publicKey: PUB, downloadDir: dir,
      getInterfaces: () => ifaces, lanHostOk: loopback, ...(fetch ? { fetchLan: fetch } : {}),
    });
    return { u, calls, dir, lines };
  }

  it('the check sends X-GC-Local; with a valid lan the installer comes from the gateway', async () => {
    const gw = await gateway({ [H]: INSTALLER });
    const { u, calls } = run({ lan: gw.lan(H) });
    const info = await u.check();
    assert.equal(info.version, '1.1.0');
    assert.equal(calls[0].opts.headers['X-GC-Local'], '192.168.1.23,10.0.0.5');
    assert.equal(calls.length, 1); // no download from the server
    assert.equal(gw.hits.length, 1);
    assert.deepEqual(fs.readFileSync(u.downloadPath), INSTALLER);
    assert.equal((await u.prepareInstall()).ok, true);
  });

  it('the gateway fails (pin, bytes, not there): the installer from downloadUrl', async () => {
    const gw = await gateway({ [H]: INSTALLER });
    const cases = [
      [gw.lan(H, { tlsSha256: 'cd'.repeat(32) }), null],
      [gw.lan(H), (_q, res) => { res.writeHead(200); res.end(Buffer.from('MZ evil')); }],
      [gw.lan(H), (_q, res) => { res.writeHead(404); res.end('{"error":"not_cached"}'); }],
    ];
    for (const [lan, answer] of cases) {
      gw.answer = answer;
      const { u, calls } = run({ lan });
      await u.check();
      assert.equal(calls.length, 2);
      assert.deepEqual(fs.readFileSync(u.downloadPath), INSTALLER);
      assert.deepEqual(fs.readdirSync(path.dirname(u.downloadPath)), [FILE]);
    }
  });

  it('a hint for another file than the signed manifest, or none: the server, the gateway is never asked', async () => {
    let asked = 0;
    const fetch = async () => { asked++; throw new Error('no'); };
    const other = { url: `https://127.0.0.1:9/blob/${'f'.repeat(64)}?exp=1&sig=00`, sha256: 'f'.repeat(64), tlsSha256: 'ab'.repeat(32), exp: 1 };
    const a = run({ lan: other, fetch });
    await a.u.check();
    assert.equal(a.calls.length, 2);
    assert.ok(a.lines.some((l) => /Heimnetz ungültig/.test(l)));
    const b = run({ lan: null, fetch, ifaces: {} });
    await b.u.check();
    assert.equal(b.calls[0].opts.headers['X-GC-Local'], undefined);
    assert.equal(b.calls.length, 2);
    assert.equal(asked, 0);
  });
});
