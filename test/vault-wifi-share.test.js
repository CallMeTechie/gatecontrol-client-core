'use strict';

// Vault Wi-Fi shares (plugin gatecontrol-vault 1.4.0, README "WLAN-Freigaben"): the QR code's text and the copy of a
// Wi-Fi entry (utils/vault.js wifiOf / wifiText / wifiSame / parseShares — the same rules as the portal tab and
// Android), and VaultService.wifiShares / wifiShare / wifiShareEnd with the vault:wifi-* IPC against the in-memory
// plugin (fixtures/vault-server.js): main builds the copy from the decrypted entry, the renderer never gets the password.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const VaultService = require('../src/services/vault');
const v = require('../src/utils/vault');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { vaultServer } = require('./fixtures/vault-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const KDF = { m: 19456, t: 2 };
const PW = 'Sonnenblume-Kanu-Turm-47';
const BS = '\\';

const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

function device(srv, uid, name = 'pc') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-vault-wifi-'));
  dirs.push(dir);
  const s = new VaultService({ api: srv.transport(uid, name), dir, kdf: KDF, deviceName: name, log, timing: { recheckMs: 1e9, retryMinMs: 1e9, syncMs: 1e9 } });
  s.dir = dir;
  return s;
}

async function setUp(s) {
  await s.check();
  await s.setup({ password: PW });
  await s.confirmSetup();
  await s.sync();
}

function register(s) {
  const handlers = {};
  registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
    app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
    wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
    installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', vault: s,
  });
  return (ch, arg) => handlers[ch](null, arg);
}

const wifiEntry = (fields) => ({ type: 'wifi', title: 'Gäste', fields: { ssid: 'Gäste;WLAN', password: 'Korrekt:Pferd', security: 'WPA2', ...fields } });

describe('utils/vault: Wi-Fi QR code and share copy', () => {
  it('wifiOf: the security rules of every app; hidden from the field', () => {
    const of = (fields) => v.wifiOf({ type: 'wifi', fields });
    assert.deepEqual(of({ ssid: 'S', password: 'p', security: 'WPA2' }), { ssid: 'S', security: 'WPA', password: 'p', hidden: false });
    assert.equal(of({ ssid: 'S', password: 'p', security: 'WPA3' }).security, 'SAE');
    assert.equal(of({ ssid: 'S', password: 'p', security: 'WPA2/WPA3' }).security, 'WPA');
    assert.equal(of({ ssid: 'S', password: 'p', security: 'WEP' }).security, 'WEP');
    assert.deepEqual(of({ ssid: 'S', password: 'p', security: 'Offen' }), { ssid: 'S', security: 'nopass', password: '', hidden: false });
    assert.equal(of({ ssid: 'S' }).security, 'nopass');
    assert.equal(of({ ssid: 'S', password: 'p', hidden: 'ja' }).hidden, true);
    assert.equal(of({ password: 'p' }), null, 'no network name');
    assert.equal(v.wifiOf(null), null);
  });

  it('wifiText: WIFI:T:…;S:…;P:…;H:true;; with \\ ; , : " escaped', () => {
    assert.equal(v.wifiText({ ssid: 'Gäste;WLAN', security: 'WPA', password: 'Korrekt:Pferd', hidden: false }), 'WIFI:T:WPA;S:Gäste' + BS + ';WLAN;P:Korrekt' + BS + ':Pferd;;');
    assert.equal(v.wifiText({ ssid: 'a"b,c' + BS, security: 'nopass', password: '', hidden: true }), 'WIFI:T:nopass;S:a' + BS + '"b' + BS + ',c' + BS + BS + ';H:true;;');
  });

  it('wifiSame and parseShares', () => {
    const d = wifiEntry();
    const share = { id: 'a'.repeat(24), itemId: 'Aa1111111111111111111a', target: 'wall', ssid: 'Gäste;WLAN', security: 'WPA', password: 'Korrekt:Pferd', hidden: false, expiresAt: null, canEnd: true, createdBy: { id: 2, name: 'Anna' } };
    assert.equal(v.wifiSame(d, share), true);
    assert.equal(v.wifiSame(wifiEntry({ password: 'neu' }), share), false);
    const p = v.parseShares({ shares: [share, { ...share, id: 'x' }, { ...share, target: 'tv' }], targets: { wall: true } });
    assert.equal(p.shares.length, 1);
    assert.deepEqual([p.shares[0].createdBy, p.targets], ['Anna', { wall: true, portal: true }]);
    assert.equal(v.parseShares({}), null);
  });
});

/** An SVG of utils/qr-image.js → the text jsQR reads from it (the path's modules painted 4 px each). */
function readSvg(svg) {
  const jsQR = require('jsqr');
  const n = Number(/viewBox="0 0 (\d+) /.exec(svg)[1]);
  const s = 4;
  const px = new Uint8ClampedArray(n * s * n * s * 4).fill(255);
  for (const m of svg.matchAll(/M(\d+) (\d+)h1v1h-1z/g)) {
    const x = Number(m[1]);
    const y = Number(m[2]);
    for (let dy = 0; dy < s; dy++) for (let dx = 0; dx < s; dx++) {
      const i = (((y * s + dy) * n * s) + x * s + dx) * 4;
      px[i] = px[i + 1] = px[i + 2] = 0;
    }
  }
  const r = jsQR(px, n * s, n * s);
  return r && r.data;
}

describe('utils/qr-image: the QR code as a picture', () => {
  const qr = require('../src/utils/qr-image');
  it('an SVG with fixed markup only, black on white with a quiet zone; reads back as the text', () => {
    const text = v.wifiText({ ssid: 'Gäste;WLAN', security: 'WPA', password: 'Korrekt:Pferd', hidden: true });
    const svg = qr.qrSvg(text);
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 \d+ \d+" shape-rendering="crispEdges"><rect width="\d+" height="\d+" fill="#ffffff"\/><path d="[Mhvz0-9 -]+" fill="#000000"\/><\/svg>$/);
    assert.ok(!svg.includes('Korrekt'), 'never the text');
    assert.equal(readSvg(svg), text);
    const url = qr.qrDataUrl(text);
    assert.match(url, /^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/);
    assert.equal(Buffer.from(url.split(',')[1], 'base64').toString('utf8'), svg);
    assert.equal(qr.qrSvg('x'.repeat(5000)), null, 'too long for a QR code');
  });
});

describe('VaultService: Wi-Fi shares', () => {
  it('share, list, keep after a change, end — the copy built in main; the renderer never gets the password', async () => {
    const srv = vaultServer();
    const s = device(srv, 2);
    const call = register(s);
    await setUp(s);
    const vaultId = s._state.vaults.find((x) => x.kind === 'personal').id;
    const { id } = await s.save({ vaultId, data: wifiEntry() });
    const login = (await s.save({ vaultId, data: { type: 'login', title: 'Bank', fields: { username: 'a', password: 'b' } } })).id;

    assert.equal((await call('vault:wifi-share', { id, target: 'tv', duration: '1h' })).code, 'invalid');
    assert.equal((await call('vault:wifi-share', { id, target: 'wall', duration: '2h' })).code, 'invalid');
    assert.equal((await call('vault:wifi-share', { id: login, target: 'wall', duration: '1h' })).code, 'invalid', 'only Wi-Fi entries');
    const r = await call('vault:wifi-share', { id, target: 'wall', duration: '1h' });
    assert.equal(r.ok, true, JSON.stringify(r));
    const post = srv.calls.filter((c) => c.method === 'POST' && c.path.endsWith('wifi-shares')).pop();
    assert.deepEqual(post.body, { itemId: id, target: 'wall', duration: '1h', ssid: 'Gäste;WLAN', security: 'WPA', password: 'Korrekt:Pferd', hidden: false });

    let list = await call('vault:wifi-shares', { id });
    assert.equal(list.ok, true);
    assert.deepEqual(list.targets, { wall: true, portal: true });
    assert.deepEqual(list.shares.map((x) => [x.target, x.canEnd, x.current, x.createdBy]), [['wall', true, true, 'Anna']]);
    assert.ok(!JSON.stringify(list).includes('Korrekt'), 'no password to the renderer');
    assert.ok(Date.parse(list.shares[0].expiresAt) > Date.now());

    // the entry changes: the share is an older copy → keep sends the new one with the same end
    await s.save({ id, vaultId, data: wifiEntry({ password: 'Neues:Passwort' }) });
    list = await call('vault:wifi-shares', { id });
    assert.equal(list.shares[0].current, false);
    const end = list.shares[0].expiresAt;
    assert.equal((await call('vault:wifi-share', { id, target: 'wall', duration: 'keep' })).ok, true);
    list = await call('vault:wifi-shares', { id });
    assert.deepEqual([list.shares[0].current, list.shares[0].expiresAt], [true, end]);

    // no wall tablet: the plugin's code passes through
    srv.wall = false;
    assert.equal((await call('vault:wifi-share', { id, target: 'wall', duration: '5m' })).code, 'no_wall');
    assert.equal((await call('vault:wifi-share', { id, target: 'portal', duration: 'forever' })).ok, true);

    const shareId = list.shares[0].id;
    assert.equal((await call('vault:wifi-share-end', { shareId: 'nope' })).code, 'invalid');
    assert.equal((await call('vault:wifi-share-end', { shareId })).ok, true);
    list = await call('vault:wifi-shares', { id });
    assert.deepEqual(list.shares.map((x) => x.target), ['portal']);

    // the QR code as a picture built in main: no text (with the password) for the page
    const q = await call('vault:wifi-qr', { id });
    assert.equal(q.ok, true, JSON.stringify(q));
    assert.deepEqual([q.ssid, q.hidden], ['Gäste;WLAN', false]);
    assert.match(q.image, /^data:image\/svg\+xml;base64,/);
    assert.ok(!JSON.stringify(q).includes('Neues:Passwort'));
    assert.equal(readSvg(Buffer.from(q.image.split(',')[1], 'base64').toString('utf8')), 'WIFI:T:WPA;S:Gäste' + BS + ';WLAN;P:Neues' + BS + ':Passwort;;');
    await s.save({ id, vaultId, data: wifiEntry({ password: 'Neues:Passwort', hidden: 'true' }) });
    assert.equal((await call('vault:wifi-qr', { id })).hidden, true);
    assert.equal((await call('vault:wifi-qr', { id: login })).code, 'invalid', 'only Wi-Fi entries');
    assert.equal((await call('vault:wifi-qr', { id: 'x' })).code, 'invalid');

    s.lock('manual');
    assert.equal((await call('vault:wifi-qr', { id })).code, 'locked');
    assert.equal((await call('vault:wifi-shares', { id })).code, 'locked');
    assert.equal((await call('vault:wifi-share', { id, target: 'portal', duration: '1h' })).code, 'locked');
  });
});
