'use strict';

// Medien-Plugin (W1): MediaServerSources with MediaService against a fake plugin API and a fake Jellyfin — the list
// merged and kept encrypted, the entry "Medien" only with the plugin's tab, a share's password per secretRev, the
// invisible sign-in (Quick Connect with the plugin's device id, URL-encoded header, the code to the plugin, again after
// a 401), the network rule (away only through the VPN: started on opening, without it nothing sent; the admin's
// exception; home by GateControl's home-network detection, never by the plugin's probes), SMB error 1219 → WebDAV, media.revoke, no_access, the plugin
// gone for 24 h, 30 / 90 days offline, sources of this PC taken over, DELETE v1/jellyfin/device?sourceId=… before an
// access the plugin made is discarded here.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { createMemoryStore } = require('./fixtures/memory-store');
const MediaStore = require('../src/services/media-store');
const MediaService = require('../src/services/media');
const MediaServerSources = require('../src/services/media-server-sources');
const MSV = require('../src/utils/media-server');
const { MessengerError } = require('../src/services/messenger-api');

const protect = {
  available: () => true,
  encrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
  decrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
};
const DAY = 24 * 60 * 60 * 1000;
const DEVICE = 'gc-7Hq2mXk4Rb9tLp0sVw3N';

/** A fake Jellyfin routed by "METHOD /path"; every request recorded. */
async function fakeJellyfin() {
  const requests = [];
  const state = { confirmed: true, token: 'jf-access-1', resume401: 0 };
  const routes = {
    'POST /QuickConnect/Initiate': () => ({ body: { Secret: 'qc-secret', Code: '482913' } }),
    'GET /QuickConnect/Connect': () => ({ body: { Authenticated: state.confirmed } }),
    'POST /Users/AuthenticateWithQuickConnect': () => ({ body: { AccessToken: state.token, ServerId: '4f1ca9', User: { Id: 'a71e', Name: 'mila' } } }),
    'GET /UserItems/Resume': () => (state.resume401-- > 0 ? { status: 401, body: {} } : { body: { Items: [{ Id: 'm1', Name: 'Kobaltnacht', Type: 'Movie' }] } }),
    'GET /Playback/BitrateTest': () => ({ raw: Buffer.alloc(2000) }),
    'POST /Sessions/Logout': () => ({ status: 204 }),
  };
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    requests.push({ method: req.method, path: u.pathname, headers: req.headers });
    const r = routes[`${req.method} ${u.pathname}`];
    const a = r ? r() : { status: 404, body: {} };
    res.writeHead(a.status || 200, { 'Content-Type': 'application/json' });
    res.end(a.raw || (a.body !== undefined ? JSON.stringify(a.body) : ''));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    requests, state, routes, base: `http://localhost:${port}`,
    paths: () => requests.map((x) => `${x.method} ${x.path}`),
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}

/** The plugin's app API as MessengerApi._call answers it (refusals thrown as MessengerError). */
function fakeApi(handlers) {
  const calls = [];
  return {
    calls,
    async _call(method, path, opts = {}) {
      calls.push({ method, path, opts });
      const h = handlers[`${method} ${path}`] || handlers[`${method} ${path.replace(/\/v1\/sources\/[^/]+\//, '/v1/sources/:id/').replace(/\/v1\/shares\/[^/]+\//, '/v1/shares/:id/')}`];
      if (!h) throw new MessengerError('not found', { status: 404, code: 'not_found' });
      const r = await h(opts, path);
      if (r instanceof MessengerError) throw r;
      return r;
    },
  };
}

const refusal = (status, code, body = {}) => new MessengerError(code, { status, code, body: { ok: false, code, ...body } });
const P = (x) => `/api/v1/client/plugins/gatecontrol-medien/api/${x}`;
const HN = '/api/v1/client/home-network';
const HOME = { [`GET ${HN}`]: () => ({ ok: true, same_lan: true, via: 'tunnel', site: { type: 'server' } }) };

function listOf(jfBase, over = {}) {
  return {
    v: 1, rev: 'r1', at: '2026-11-25T19:02:11.000Z', media: true, maxOfflineDays: 90, offlineHintDays: 30,
    network: { rule: 'home_direct_away_vpn', vpnRequiredAway: true, home: { probes: [{ kind: 'jellyfin', url: 'http://192.168.1.20:8096/System/Info/Public', serverId: '4f1ca9' }] } },
    sources: [
      {
        id: 'jf-1', kind: 'jellyfin', name: 'DS918+', serverId: '4f1ca9', version: '10.10.7', address: jfBase, home: { address: jfBase },
        away: { mode: 'vpn' }, user: { id: 'a71e', name: 'mila' }, problem: null, device: { id: DEVICE, name: 'GateControl · Büro-PC' },
        paired: false, quickConnect: true, downloads: true, alwaysOriginal: false,
      },
      {
        id: 'sh-1', kind: 'share', name: 'Filme', folder: 'filme', smb: { address: 'smb://192.168.1.20/filme' },
        webdav: { address: 'https://192.168.1.20:5006/filme' }, user: 'medien-lesen', secretRev: 3, away: { mode: 'vpn' },
      },
    ],
    ...over,
  };
}

function setup({ jf, handlers = {}, tunnel = null, now = () => clock.t, mem = createMemoryStore(), net = null, ifaces = () => ({}), shares = null }) {
  const store = new MediaStore({ store: mem, protect });
  const media = new MediaService({
    store, client: 'GateControl Pro', version: '1.10.0', deviceName: () => 'Büro-PC', networkInterfaces: ifaces, now,
    lanRoute: { supported: false, removeHostRoutes: async () => {} }, tunnel, ...(net ? { net } : {}), ...(shares ? { shares } : {}),
  });
  const api = fakeApi({
    'GET /api/v1/client/plugins': () => ({ ok: true, plugins: [{ id: MSV.PLUGIN_ID, version: '1.0.0', tab: { label: 'Medien' } }] }),
    [`GET ${P('v1/sources')}`]: () => listOf(jf.base),
    [`GET ${P('v1/sources/:id/secret')}`]: () => ({ v: 1, user: 'medien-lesen', password: 'nas-pw', rev: 3 }),
    [`POST ${P('v1/jellyfin/pair')}`]: () => ({ v: 1, userId: 'a71e', userName: 'mila', deviceId: DEVICE }),
    [`POST ${P('v1/jellyfin/paired')}`]: () => ({ v: 1 }),
    [`POST ${P('v1/sources/:id/report')}`]: () => ({ v: 1 }),
    [`POST ${P('v1/shares/:id/checked')}`]: () => ({ v: 1 }),
    [`DELETE ${P('v1/jellyfin/device')}`]: () => ({ v: 1, sources: [] }),
    ...handlers,
  });
  const nc = { handlers: [], addPushHandler(h) { this.handlers.push(h); return () => {}; } };
  const ss = new MediaServerSources({ media, api, now, notificationCenter: nc, sleep: async () => {}, timing: { pairRetryMs: 0 } });
  return { store, media, api, ss, nc, mem };
}

const clock = { t: Date.parse('2026-11-25T19:00:00Z') };
const tunnelUp = () => ({ isUp: true, connects: 0, up() { return this.isUp; }, async connect() { this.connects++; this.isUp = true; return true; } });

describe('MediaServerSources', () => {
  let jf;
  beforeEach(async () => { jf = await fakeJellyfin(); clock.t = Date.parse('2026-11-25T19:00:00Z'); });
  afterEach(async () => { await jf.close(); });

  it('the list from the server: merged, kept encrypted, the tab, the password per secretRev, since=rev next time', async () => {
    const { ss, store, api, mem, media } = setup({ jf, tunnel: tunnelUp() });
    const st = await ss.refresh();
    assert.equal(st.state, 'available');
    assert.equal(st.visible, true);
    assert.deepEqual(store.sources().map((x) => [x.id, x.kind, x.managed]), [['jf-1', 'jellyfin', true], ['sh-1', 'smb', true], ['sh-1_w', 'webdav', true]]);
    assert.equal(store.source('sh-1').password, 'nas-pw');
    assert.equal(store.source('sh-1_w').password, 'nas-pw', 'both halves');
    assert.equal(store.source('sh-1').pwRev, 3);
    const dump = JSON.stringify(mem.store);
    assert.ok(!dump.includes('nas-pw') && !dump.includes('192.168.1.20'), 'list and password only encrypted');
    const pub = media.status();
    assert.deepEqual(pub.sources.map((s) => s.id), ['jf-1', 'sh-1'], 'a pair once');
    assert.ok(!JSON.stringify(pub).includes('nas-pw'));
    assert.equal(pub.server.visible, true);

    api.calls.length = 0;
    await ss.refresh();
    const get = api.calls.find((c) => c.path === P('v1/sources'));
    assert.deepEqual(get.opts.params, { since: 'r1' });
    assert.ok(!api.calls.some((c) => c.path.endsWith('/secret')), 'the same secretRev: not asked again');
    // a new secretRev → asked again
    api.calls.length = 0;
    const l = listOf(jf.base, { rev: 'r2' });
    l.sources[1].secretRev = 4;
    api._handlers = null;
    const orig = api._call.bind(api);
    api._call = (m, p, o) => (p === P('v1/sources') ? Promise.resolve(l) : orig(m, p, o));
    await ss.refresh();
    assert.ok(api.calls.some((c) => c.path === P('v1/sources/sh-1/secret')));
  });

  it('no tab → hidden; 404 plugin_unavailable: hidden at once, deleted after 24 h; license_required likewise', async () => {
    const { ss, store, api } = setup({ jf, tunnel: tunnelUp() });
    await ss.refresh();
    assert.equal(store.sources().length, 3);
    const orig = api._call.bind(api);
    let answer = refusal(404, 'not_found', { reason: 'plugin_unavailable' });
    api._call = (m, p, o) => (p === P('v1/sources') ? Promise.reject(answer) : orig(m, p, o));
    let st = await ss.refresh();
    assert.equal(st.visible, false);
    assert.equal(st.state, 'unavailable');
    assert.equal(store.sources().length, 3, 'kept for 24 h (decision 37 a)');
    clock.t += DAY - 1000;
    await ss.refresh();
    assert.equal(store.sources().length, 3);
    clock.t += 2000;
    answer = refusal(403, 'license_required', { reason: 'missing' });
    st = await ss.refresh();
    assert.equal(store.sources().length, 0, 'after 24 h: the sources and their access are deleted');
    assert.equal(st.reason, 'license_required');

    const hidden = setup({ jf, handlers: { 'GET /api/v1/client/plugins': () => ({ plugins: [{ id: MSV.PLUGIN_ID, tab: null }] }) } });
    assert.equal((await hidden.ss.refresh()).visible, false, 'the plugin gives no tab: no "Medien"');
  });

  it('signs in by itself: Quick Connect with the plugin\'s device id, URL-encoded header, the code to the plugin, paired; a 401 again', async () => {
    const { ss, store, api, media } = setup({ jf, tunnel: tunnelUp() });
    await ss.refresh();
    const rows = await media.resume('jf-1');
    assert.equal(rows.ok, true, JSON.stringify(rows));
    assert.equal(rows.items[0].name, 'Kobaltnacht');
    const init = jf.requests.find((r) => r.path === '/QuickConnect/Initiate');
    const auth = init.headers.authorization;
    assert.ok(auth.includes(`DeviceId="${DEVICE}"`), auth);
    assert.ok(auth.includes('Device="GateControl%20%C2%B7%20B%C3%BCro-PC"'), auth);
    assert.ok(auth.includes('Client="GateControl"'));
    const pair = api.calls.find((c) => c.path === P('v1/jellyfin/pair'));
    assert.deepEqual(pair.opts.body, { sourceId: 'jf-1', code: '482913' });
    assert.deepEqual(api.calls.find((c) => c.path === P('v1/jellyfin/paired')).opts.body, { sourceId: 'jf-1', jellyfinDeviceId: DEVICE });
    assert.equal(store.source('jf-1').token, 'jf-access-1');
    assert.ok(!JSON.stringify(media.status()).includes('jf-access-1'));
    assert.ok(!JSON.stringify(api.calls).includes('jf-access-1'), 'the server never sees the access');

    // Jellyfin signed this PC out: again without asking
    jf.state.token = 'jf-access-2';
    jf.state.resume401 = 1;
    const again = await media.resume('jf-1');
    assert.equal(again.ok, true);
    assert.equal(store.source('jf-1').token, 'jf-access-2');
    assert.equal(jf.requests.filter((r) => r.path === '/QuickConnect/Initiate').length, 2);
  });

  it('code_invalid: a new code once; no_mapping: the admin\'s matter, no sign-in; no_access: the source goes', async () => {
    let n = 0;
    const a = setup({ jf, tunnel: tunnelUp(), handlers: { [`POST ${P('v1/jellyfin/pair')}`]: () => (n++ === 0 ? refusal(422, 'code_invalid') : { v: 1 }) } });
    await a.ss.refresh();
    assert.equal((await a.media.resume('jf-1')).ok, true);
    assert.equal(n, 2);

    const b = setup({ jf, tunnel: tunnelUp(), handlers: { [`POST ${P('v1/jellyfin/pair')}`]: () => refusal(409, 'no_mapping') } });
    await b.ss.refresh();
    const r = await b.media.resume('jf-1');
    assert.equal(r.code, 'no_mapping');
    assert.equal(b.store.source('jf-1').problem, 'no_mapping');
    assert.equal(b.media.status().sources[0].problem, 'no_mapping');

    const c = setup({ jf, tunnel: tunnelUp(), handlers: { [`GET ${P('v1/sources/:id/secret')}`]: () => refusal(403, 'no_access') } });
    await c.ss.refresh();
    assert.deepEqual(c.store.sources().map((x) => x.id), ['jf-1'], 'the share is not the person\'s any more');
  });

  it('the network rule: away only through the VPN — started on opening; without it nothing is sent', async () => {
    const tunnel = { isUp: false, connects: 0, up() { return this.isUp; }, async connect() { this.connects++; this.isUp = true; return true; } };
    const { ss, media, store } = setup({ jf, tunnel });
    const vpn = [];
    media.on('vpn', (e) => vpn.push(e.state));
    await ss.refresh();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(jf.requests.length, 0, 'the background sign-in does not start the VPN, nothing sent');
    // opening Medien: the list, the VPN started, signed in
    const opened = await media.serverRefresh();
    assert.equal(opened.server.visible, true);
    assert.equal(tunnel.connects, 1);
    assert.ok(store.source('jf-1').token);
    const rows = await media.resume('jf-1');
    assert.equal(rows.ok, true);
    assert.equal(tunnel.connects, 1);
    assert.deepEqual(vpn, ['connecting', 'up']);
    assert.equal(media.status().sources[0].link.way, 'vpn');

    // the VPN cannot be started: blocked, not one request
    const t2 = { up: () => false, connect: async () => false };
    const jf2 = await fakeJellyfin();
    try {
      const b = setup({ jf: jf2, tunnel: t2 });
      await b.ss.refresh();
      const r = await b.media.resume('jf-1');
      assert.equal(r.code, 'vpn_required');
      assert.equal((await b.media.shareList({ sourceId: 'sh-1' })).code, 'vpn_required');
      assert.equal(jf2.requests.length, 0);
      assert.equal(b.media.status().sources[0].link.way, 'blocked');
      // the stream addresses are refused as well (MediaNet blocked)
      b.store.update('jf-1', { token: 't' });
      const c = b.media._client('jf-1');
      assert.equal((await c.get('Items')).code, 'vpn_required');
    } finally { await jf2.close(); }
  });

  it('the admin\'s exception: away without VPN over the https:// address; at home by the plugin\'s probe, bound to the LAN', async () => {
    const lan = () => ({ Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }] });
    const asked = [];
    const net = {
      reset() {},
      async request(o) {
        asked.push(o);
        if (o.blocked) throw Object.assign(new Error('x'), { code: 'vpn_required' });
        if (o.url.includes('/System/Info/Public')) return { status: 200, data: JSON.stringify({ Id: '4F1CA9' }) };
        return { status: 200, data: JSON.stringify({ Items: [] }) };
      },
    };
    const homeNet = { [`GET ${HN}`]: () => ({ ok: true, lan: ['192.168.1.2'], same_lan: true, via: 'tunnel', site: { type: 'server' } }) };
    const home = setup({ jf, tunnel: { up: () => true, connect: async () => true }, net, ifaces: lan, handlers: homeNet });
    await home.ss.refresh();
    home.store.update('jf-1', { token: 't', pairedUserId: 'a71e' });
    const c = await home.media.check('jf-1');
    assert.equal(c.link.atHome, true);
    assert.equal(c.link.localAddress, '192.168.1.37', 'bound to the LAN, also with the VPN on');
    const q = home.api.calls.filter((x) => x.path === HN);
    assert.equal(q.length, 1);
    assert.deepEqual(q[0].opts.params, { local: '192.168.1.37' }, 'the LAN addresses of this PC, never the tunnel\'s');
    assert.equal(home.media.status().sources[0].link.way, 'home');
    await home.media.check('jf-1');
    assert.equal(home.api.calls.filter((x) => x.path === HN).length, 1, 'kept until the network changes');
    home.media.networkChanged();
    await home.media.check('jf-1');
    assert.equal(home.api.calls.filter((x) => x.path === HN).length, 2);

    // the plugin's probe answers (a hotel's 192.168.1.20 with the same server id) but GateControl says no: away
    const hotelNet = net;
    const direct = listOf(jf.base);
    direct.sources[0].away = { mode: 'direct', address: 'https://jellyfin.example.test' };
    const hotel = setup({ jf, net: hotelNet, ifaces: lan, tunnel: { up: () => false, connect: async () => false }, handlers: { [`GET ${P('v1/sources')}`]: () => direct } });
    await hotel.ss.refresh();
    hotel.store.update('jf-1', { token: 't', pairedUserId: 'a71e' });
    asked.length = 0;
    const away = await hotel.media.check('jf-1');
    assert.equal(away.link.atHome, false);
    assert.equal(away.link.via, 'direct');
    assert.equal(hotel.media._client('jf-1').base, 'https://jellyfin.example.test');
    assert.equal(hotel.media.status().sources[0].link.way, 'direct');

    // a share with SMB alone: the exception is a WebDAV address — away only through the VPN (none here: blocked)
    const smbOnly = listOf(jf.base);
    smbOnly.sources = [{ ...smbOnly.sources[1], webdav: null, away: { mode: 'direct', address: 'https://nas.example.test/filme' } }];
    const s2 = setup({ jf, net: hotelNet, ifaces: lan, tunnel: { up: () => false, connect: async () => false }, handlers: { [`GET ${P('v1/sources')}`]: () => smbOnly } });
    await s2.ss.refresh();
    assert.equal((await s2.media.check('sh-1')).link.blocked, true);
  });

  it('at home only by GateControl\'s home-network detection: a tcp probe alone never; VPN off only a gateway site', async () => {
    const lan = () => ({ 'WLAN': [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }], 'GateControl': [{ address: '10.8.0.5', family: 'IPv4', internal: false, cidr: '10.8.0.5/32' }] });
    const net = { reset() {}, reachable: async () => true, certificate: async () => null, request: async () => ({ status: 200, data: JSON.stringify({ Id: '4f1ca9', Items: [] }) }) };
    const tcpOnly = listOf(jf.base);
    tcpOnly.network = { ...tcpOnly.network, home: { probes: [
      { kind: 'tcp', host: '192.168.1.20', port: 445, sourceId: 'sh-1', unique: false },
      { kind: 'tcp', host: '192.168.1.20', port: 8096, sourceId: 'jf-1', unique: false },
    ] } };
    const off = () => ({ up: () => false, connect: async () => false });

    // a foreign network with the same addresses: every tcp probe would connect, the server says no → away (blocked)
    const a = setup({ jf, net, ifaces: lan, tunnel: off(), handlers: {
      [`GET ${P('v1/sources')}`]: () => tcpOnly,
      [`GET ${HN}`]: () => ({ ok: true, lan: [], same_lan: false, via: 'direct', site: null }),
    } });
    await a.ss.refresh();
    const r = await a.media.check('sh-1');
    assert.equal(r.link.atHome, false);
    assert.equal(r.link.blocked, true);
    assert.equal((await a.media.shareList({ sourceId: 'sh-1' })).code, 'vpn_required', 'no password to a foreign device');
    assert.deepEqual(a.api.calls.find((x) => x.path === HN).opts.params, { local: '192.168.1.37' });

    // the server cannot be asked (old server, offline): away as well
    const b = setup({ jf, net, ifaces: lan, tunnel: off(), handlers: { [`GET ${P('v1/sources')}`]: () => tcpOnly } });
    await b.ss.refresh();
    assert.equal((await b.media.check('sh-1')).link.atHome, false);

    // VPN off: a direct "own LAN" answer is not taken (a reverse proxy in between) …
    const c = setup({ jf, net, ifaces: lan, tunnel: off(), handlers: { [`GET ${HN}`]: () => ({ ok: true, same_lan: true, via: 'direct', site: { type: 'server' } }) } });
    await c.ss.refresh();
    assert.equal((await c.media.check('sh-1')).link.atHome, false);
    // … a gateway site is (the server compared the public address and the gateway's LAN)
    const d = setup({ jf, net, ifaces: lan, tunnel: off(), handlers: { [`GET ${HN}`]: () => ({ ok: true, same_lan: true, via: 'direct', site: { type: 'gateway', gatewayId: 7, name: 'NAS' } }) } });
    await d.ss.refresh();
    const dl = await d.media.check('sh-1');
    assert.equal(dl.link.atHome, true);
    assert.equal(dl.link.localAddress, '192.168.1.37');
  });

  it('VPN off at home without a gateway: away first, the VPN started, asked again through it → home, bound to the LAN', async () => {
    const lan = () => ({ Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }] });
    const net = { reset() {}, request: async () => ({ status: 200, data: JSON.stringify({ Items: [] }) }) };
    const tunnel = { isUp: false, connects: 0, up() { return this.isUp; }, async connect() { this.connects++; this.isUp = true; return true; } };
    const seen = [];
    const s = setup({ jf, net, ifaces: lan, tunnel, handlers: {
      [`GET ${HN}`]: () => { seen.push(tunnel.isUp); return tunnel.isUp ? { ok: true, same_lan: true, via: 'tunnel', site: { type: 'server' } } : { ok: true, same_lan: false, via: 'direct', site: null }; },
    } });
    await s.ss.refresh();
    s.store.update('jf-1', { token: 't', pairedUserId: 'a71e' });
    const rows = await s.media.resume('jf-1');
    assert.equal(rows.ok, true, JSON.stringify(rows));
    assert.equal(tunnel.connects, 1);
    assert.deepEqual(seen, [false, true]);
    const l = s.media.link('jf-1');
    assert.equal(l.atHome, true);
    assert.equal(l.localAddress, '192.168.1.37');
    assert.equal(s.media.status().sources[0].link.way, 'home');
  });

  it('SMB error 1219 → WebDAV at once (no question); "SMB geprüft" told once', async () => {
    const lan = () => ({ Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }] });
    const net = { reset() {}, request: async () => ({ status: 200, data: JSON.stringify({ Id: '4f1ca9' }) }), certificate: async () => null };
    const used = [];
    const fake = (kind, answer) => (source) => ({ kind, source, list: async () => { used.push(kind); return answer(); }, close: async () => {}, stat: async () => ({ ok: false, code: 'not_found' }) });
    let smb = () => ({ ok: false, code: 'smb_conflict', winError: 1219 });
    const shares = { smb: fake('smb', () => smb()), webdav: fake('webdav', () => ({ ok: true, value: [] })) };
    const s = setup({ jf, net, ifaces: lan, shares, tunnel: { up: () => true, connect: async () => true }, handlers: HOME });
    await s.ss.refresh();
    const r = await s.media.shareList({ sourceId: 'sh-1' });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.via, 'webdav');
    assert.deepEqual(used, ['smb', 'webdav']);
    const checked = s.api.calls.filter((c) => c.path === P('v1/shares/sh-1/checked'));
    assert.deepEqual(checked.map((c) => c.opts.body), [{ protocol: 'smb', ok: false, problem: 'smb_conflict' }]);
    assert.equal(s.media.status().sources[1].link.smbConflict, true);

    // another PC without the conflict: SMB, checked once
    const t = setup({ jf, net, ifaces: lan, shares: { ...shares, smb: fake('smb', () => ({ ok: true, value: [] })) }, tunnel: { up: () => true, connect: async () => true }, handlers: HOME });
    await t.ss.refresh();
    await t.media.shareList({ sourceId: 'sh-1' });
    await t.media.shareList({ sourceId: 'sh-1' });
    assert.deepEqual(t.api.calls.filter((c) => c.path === P('v1/shares/sh-1/checked')).map((c) => c.opts.body), [{ protocol: 'smb', ok: true }]);
    assert.equal(t.media.status().sources[1].smbChecked, true);
  });

  it('media.revoke: access and passwords go, the list again; null = all', async () => {
    const { ss, store, api, nc } = setup({ jf, tunnel: tunnelUp() });
    await ss.refresh();
    assert.equal((await ss.pair('jf-1')).ok, true);
    api.calls.length = 0;
    const handled = nc.handlers[0];
    assert.equal(handled, undefined, 'only after start()');
    ss.start();
    ss.stop();
    const r = nc.handlers[0].notification({ topic: MSV.SIGNAL_TOPIC, kind: 'data', silent: true, data: { kind: 'media.revoke', sourceIds: ['sh-1'], reason: 'right' } });
    assert.equal(r, 'consumed');
    await new Promise((x) => setTimeout(x, 20));
    await ss.refresh();
    assert.equal(store.source('jf-1').token, 'jf-access-1', 'another source keeps its access');
    assert.equal(nc.handlers[0].notification({ topic: 'plugin:gatecontrol-familie:internet', data: {} }), false, 'not ours');
    await ss.revoke({ sourceIds: null, reason: 'device_removed' });
    assert.equal(store.source('jf-1').token, null);
    const full = api.calls.filter((c) => c.path === P('v1/sources')).pop();
    assert.equal(full.opts.params, undefined, 'the whole list, no since');
    assert.equal(store.source('sh-1').password, 'nas-pw', 'still allowed: fetched anew');
  });

  it('30 days a note, 90 days the NAS passwords are deleted (without the server the last list counts)', async () => {
    const mem = createMemoryStore();
    const a = setup({ jf, mem, tunnel: tunnelUp() });
    await a.ss.refresh();
    const offlineApi = { _call: async () => { throw new MessengerError('network', { code: 'network' }); } };
    clock.t += 31 * DAY;
    const b = setup({ jf, mem, tunnel: tunnelUp() });
    b.ss.api = offlineApi;
    const st = await b.ss.refresh();
    assert.equal(st.state, 'error');
    assert.equal(st.offline.hint, true);
    assert.equal(st.visible, true, 'the last list counts');
    assert.equal(b.store.source('sh-1').password, 'nas-pw');
    clock.t += 60 * DAY;
    await b.ss.refresh();
    assert.equal(b.store.source('sh-1').password, null, 'after 90 days');
    assert.equal(b.store.source('jf-1').managed, true, 'the list stays');
  });

  it('sources of this PC taken over (33 a): progress kept under the server\'s id, the rest removed, a note; old access signed out', async () => {
    const mem = createMemoryStore();
    const store = new MediaStore({ store: mem, protect });
    const oldJf = store.save({ kind: 'jellyfin', name: 'DS918+', address: jf.base, serverId: '4F1CA9', userId: 'u0', token: 'old-tok' });
    const oldSmb = store.save({ kind: 'smb', name: 'nas', address: 'smb://192.168.1.20/filme' });
    store.save({ kind: 'webdav', name: 'anders', address: 'https://192.168.1.30/x' });
    store.setProgress(`${oldSmb.id}|Kobaltnacht.mkv`, { positionMs: 60000, durationMs: 100000 });
    const { ss, store: st2 } = setup({ jf, mem, tunnel: tunnelUp() });
    const s = await ss.refresh();
    assert.deepEqual(s.notice.adopted.map((x) => x.id), ['jf-1', 'sh-1']);
    assert.deepEqual(s.notice.dropped.map((x) => x.name), ['anders']);
    assert.deepEqual(st2.sources().map((x) => x.id), ['jf-1', 'sh-1', 'sh-1_w']);
    assert.equal(st2.progress('sh-1|Kobaltnacht.mkv').positionMs, 60000);
    assert.equal(st2.progress(`${oldSmb.id}|Kobaltnacht.mkv`), null);
    await new Promise((r) => setTimeout(r, 50));
    const logout = jf.requests.find((r) => r.path === '/Sessions/Logout');
    assert.ok(logout && logout.headers.authorization.includes('Token="old-tok"'), 'the old access signed out');
    assert.ok(oldJf.id);
  });

  describe('DELETE v1/jellyfin/device?sourceId=… before the access goes here (best effort)', () => {
    const deletes = (api) => api.calls.filter((c) => c.method === 'DELETE');
    const signedIn = async (opts = {}) => {
      const c = setup({ jf, tunnel: tunnelUp(), ...opts });
      await c.ss.refresh();
      assert.equal((await c.ss.pair('jf-1')).ok, true);
      c.api.calls.length = 0;
      return c;
    };

    it('media.revoke: asked before the list again (a new sign-in is not deleted by it); a share alone: nothing', async () => {
      const { ss, api, store } = await signedIn();
      await ss.revoke({ sourceIds: ['sh-1'], reason: 'right' });
      assert.equal(deletes(api).length, 0, 'no Jellyfin source withdrawn');
      api.calls.length = 0;
      await ss.revoke({ sourceIds: ['jf-1'], reason: 'mapping' });
      const d = deletes(api);
      assert.equal(d.length, 1);
      assert.equal(d[0].path, P('v1/jellyfin/device'));
      assert.deepEqual(d[0].opts.params, { sourceId: 'jf-1' });
      assert.ok(d[0].opts.timeout > 0, 'never waits long');
      const iDel = api.calls.indexOf(d[0]);
      const iList = api.calls.findIndex((c) => c.path === P('v1/sources'));
      assert.ok(iDel >= 0 && iList > iDel, 'the list only after it');
      assert.equal(store.source('jf-1').token, null);
    });

    it('a failure is only logged: the revoke, the removal and the 24 h still happen', async () => {
      const warned = [];
      const { ss, api, store } = await signedIn({ handlers: { [`DELETE ${P('v1/jellyfin/device')}`]: () => refusal(503, 'unavailable') } });
      ss.log = { info() {}, debug() {}, error() {}, warn: (m) => warned.push(m) };
      const st = await ss.revoke({ sourceIds: null, reason: 'device_removed' });
      assert.equal(st.state, 'available');
      assert.equal(deletes(api).length, 1);
      assert.ok(warned.some((m) => m.includes('jf-1')), warned.join('\n'));
      assert.equal((await ss.signOutDevice('jf-1')).ok, false, 'never throws');
      assert.ok(store.source('jf-1'));
    });

    it('no_access and a source gone from the list: asked for that source only', async () => {
      const a = await signedIn();
      a.ss.dropSource('jf-1');
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(deletes(a.api).map((c) => c.opts.params), [{ sourceId: 'jf-1' }]);
      assert.equal(a.store.source('jf-1'), null);

      const b = await signedIn();
      const l = listOf(jf.base, { rev: 'r2' });
      l.sources = l.sources.filter((x) => x.id !== 'jf-1');
      const orig = b.api._call.bind(b.api);
      b.api._call = (m, p, o) => (p === P('v1/sources') ? (b.api.calls.push({ method: m, path: p, opts: o }), Promise.resolve(l)) : orig(m, p, o));
      await b.ss.refresh();
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(deletes(b.api).map((c) => c.opts.params), [{ sourceId: 'jf-1' }]);
      assert.equal(b.store.source('jf-1'), null);
      assert.ok(b.store.source('sh-1'), 'the share stays');
    });

    it('the plugin gone for 24 h: asked once more before its sources go; never signed in: nothing asked', async () => {
      const { ss, api, store } = await signedIn();
      const orig = api._call.bind(api);
      api._call = (m, p, o) => (p === P('v1/sources') ? Promise.reject(refusal(404, 'not_found', { reason: 'plugin_unavailable' })) : orig(m, p, o));
      await ss.refresh();
      assert.equal(deletes(api).length, 0, 'within the 24 h nothing');
      clock.t += DAY + 1000;
      await ss.refresh();
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(deletes(api).map((c) => c.opts.params), [{ sourceId: 'jf-1' }]);
      assert.equal(store.sources().length, 0);

      const fresh = setup({ jf, tunnel: tunnelUp() });
      await fresh.ss.refresh();
      fresh.ss.dropSource('jf-1');
      await fresh.ss.revoke({ sourceIds: null, reason: 'admin' });
      assert.equal(deletes(fresh.api).length, 0, 'no access made: nothing to delete');
    });

    it('another server: the plugin of the server signed in before is asked (serverChanging), not the new one', async () => {
      const { ss, api, media, store } = await signedIn();
      media.serverChanging();
      const newApi = fakeApi({});
      ss.api = newApi; // apiClient.configure(): the new server
      media.serverChanging(); // a second setup before the reset: the first server still counts
      await media.forgetAll();
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(deletes(api).map((c) => c.opts.params), [{ sourceId: 'jf-1' }]);
      assert.equal(deletes(newApi).length, 0);
      assert.equal(store.sources().length, 0);
      // forgotten without serverChanging (the transport may point elsewhere): nothing sent
      api.calls.length = 0;
      await media.forgetAll();
      assert.equal(deletes(api).length + deletes(newApi).length, 0);
    });

    it('serverChanging keeps the old axios client of the ApiClient (configure() makes a new one)', () => {
      const { media } = setup({ jf });
      const oldClient = { request: async () => ({ status: 200, data: { ok: true } }) };
      const apiClient = { client: oldClient };
      const ss = new MediaServerSources({ media, apiClient, now: () => clock.t });
      ss.serverChanging();
      apiClient.client = { request: async () => { throw new Error('the new server'); } };
      assert.equal(ss._leaving.apiClient.client, oldClient);
    });
  });
});
