'use strict';

// "Kameras im Heimnetz" (plugin gatecontrol-door 1.6.0): the pure helpers
// (utils/cameras.js — media addresses, cleaned answers, push context), the
// service (services/cameras.js — availability, cache, live / still / clips,
// the gccam: media scheme against a real HTTP server, camera pushes, the
// toast picture), the notification center's toast pictures, the IPC
// (cameras:*) and the cameras.* texts.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const axios = require('axios');
const cam = require('../src/utils/cameras');
const CamerasService = require('../src/services/cameras');
const MessengerApi = require('../src/services/messenger-api');
const NotificationCenter = require('../src/services/notification-center');
const { buildToastXml } = require('../src/utils/toast-xml');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const { MessengerError } = MessengerApi;
const tick = () => new Promise((r) => setImmediate(r));

const TOK = `${'a'.repeat(40)}.${'B'.repeat(43)}`;
const TOK2 = `${'c'.repeat(40)}.${'D'.repeat(43)}`;
const media = (file, tok = TOK) => `/camera-media/${tok}/${file}`;
const CAM1 = 'c0123456789abcde';
const CAM2 = 'cfedcba987654321';
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4, 0xff, 0xd9]);

const LIST = {
  ok: true, supported: true, minGatecontrol: '1.240.0', every: 10,
  cameras: [
    {
      id: CAM1, kind: 'home', name: 'Einfahrt\u0007', gateway: 'DS918 Gateway', gatewayId: 4, host: '192.168.1.73', model: 'Reolink RLC-510A', source: 'onvif',
      state: 'ok', online: true, codec: 'h264', events: { supported: true, state: 'pullpoint', kinds: ['person', 'vehicle', 'rocket'] },
      settings: { record: 'motion', events: ['person', 'vehicle'], retentionDays: 14, stream: 'main', audio: true }, push: true,
      snapshotUrl: media('snapshot.jpg'), snapshotAt: '2026-11-07T13:59:56Z', lastEventAt: '2026-11-07T13:02:00Z', user: 'admin', password: 'secret',
    },
    { id: CAM2, name: 'Garten', online: false, state: 'unreachable', snapshotUrl: 'https://evil.example/x.jpg', settings: { record: 'away', stream: 'sub' } },
    { id: 'not-a-camera', name: 'Bad' },
    { id: CAM1, name: 'Duplicate' },
  ],
};

const LIVE = { ok: true, live: { mode: 'live', via: 'vpn', ready: true, hls: media('index.m3u8'), mp4: media('live.mp4'), snapshot: media('snapshot.jpg'), codec: 'avc1.640028', audio: true, every: 10, expiresAt: '2026-11-07T14:10:00Z' } };
const SNAP = { ok: true, live: { mode: 'snapshot', snapshot: media('snapshot.jpg'), every: 10, reason: 'vpn_required', via: 'internet' } };
const CLIPS = {
  ok: true, day: '2026-11-07',
  clips: [
    { id: 'e000000000000001', cameraId: CAM1, camera: 'Einfahrt', kind: 'animal', kinds: ['animal'], startedAt: '2026-11-07T05:15:00Z', endedAt: '2026-11-07T05:15:08Z', nobodyHome: false, ms: 8000, thumbUrl: media('thumb.jpg', TOK2), clipUrl: media('clip.mp4', TOK2) },
    { id: 'e000000000000002', cameraId: CAM1, camera: 'Einfahrt', kind: 'person', kinds: ['motion', 'person'], startedAt: '2026-11-07T13:02:00Z', endedAt: '2026-11-07T13:02:24Z', nobodyHome: true, ms: 24000, thumbUrl: media('thumb.jpg'), clipUrl: media('clip.mp4') },
    { id: 'e000000000000003', cameraId: CAM1, kind: 'vehicle', startedAt: '2026-11-07T11:47:00Z', ms: null, thumbUrl: null, clipUrl: null },
    { id: 'x', kind: 'person', startedAt: '2026-11-07T10:00:00Z' },
  ],
};

describe('utils/cameras', () => {
  it('media addresses: only /camera-media/<token>/<file> of the own server, back and forth', () => {
    assert.equal(cam.mediaUrl(media('live.mp4')), `gccam://media/${TOK}/live.mp4`);
    assert.equal(cam.mediaUrl(media('s42.m4s')), `gccam://media/${TOK}/s42.m4s`);
    for (const bad of ['https://evil.example/camera-media/x/live.mp4', media('../etc/passwd'), media('live.exe'), '/camera-media/short.x/live.mp4', `${media('live.mp4')}?x=1`, null, 5]) {
      assert.equal(cam.mediaUrl(bad), null, String(bad));
    }
    assert.deepEqual(cam.parseMediaUrl(`gccam://media/${TOK}/clip.mp4`), { path: media('clip.mp4'), file: 'clip.mp4', ext: 'mp4', type: 'video/mp4' });
    // ?t=<n> against caching is dropped
    assert.equal(cam.parseMediaUrl(`gccam://media/${TOK}/snapshot.jpg?t=17`).path, media('snapshot.jpg'));
    for (const bad of [`gccam://other/${TOK}/clip.mp4`, `gccam://media/${TOK}/../x`, `http://media/${TOK}/clip.mp4`, `gccam://u:p@media/${TOK}/clip.mp4`, 'gccam://media/x/clip.mp4']) {
      assert.equal(cam.parseMediaUrl(bad), null, bad);
    }
    assert.equal(cam.rangeOf('bytes=0-'), 'bytes=0-');
    assert.equal(cam.rangeOf('bytes=100-200'), 'bytes=100-200');
    assert.equal(cam.rangeOf('bytes=0-1,5-6'), null);
    assert.equal(cam.rangeOf('bytes=-'), null);
  });

  it('GET cameras/home: known fields only, never the address or the camera account', () => {
    const l = cam.normalizeList(LIST);
    assert.equal(l.supported, true);
    assert.equal(l.every, 10);
    assert.equal(l.cameras.length, 2);
    const [a, b] = l.cameras;
    assert.equal(a.name, 'Einfahrt');
    assert.equal(a.snapshotUrl, `gccam://media/${TOK}/snapshot.jpg`);
    assert.deepEqual(a.events.kinds, ['person', 'vehicle']);
    assert.deepEqual(a.settings, { record: 'motion', events: ['person', 'vehicle'], retentionDays: 14, stream: 'main', audio: true });
    assert.equal(a.snapshotAt, Date.parse('2026-11-07T13:59:56Z'));
    for (const k of ['host', 'user', 'password', 'gatewayId']) assert.ok(!(k in a), k);
    assert.equal(b.snapshotUrl, null);
    assert.equal(b.online, false);
    assert.equal(b.state, 'unreachable');
    assert.equal(b.settings.stream, 'sub');
    // older GateControl (no gc.cameras): nothing
    assert.deepEqual(cam.normalizeList({ supported: false, minGatecontrol: '1.240.0', cameras: LIST.cameras }), { supported: false, minGatecontrol: '1.240.0', every: 10, cameras: [] });
  });

  it('live: video in the VPN, a still every 10 s otherwise', () => {
    const l = cam.normalizeLive(LIVE);
    assert.equal(l.mode, 'live');
    assert.equal(l.mp4, `gccam://media/${TOK}/live.mp4`);
    assert.equal(l.hls, `gccam://media/${TOK}/index.m3u8`);
    assert.equal(l.audio, true);
    assert.equal(l.via, 'vpn');
    assert.equal(l.expiresAt, Date.parse('2026-11-07T14:10:00Z'));
    assert.deepEqual(cam.normalizeLive(SNAP), { mode: 'snapshot', snapshot: `gccam://media/${TOK}/snapshot.jpg`, every: 10, reason: 'vpn_required', via: 'internet' });
    // live without a playable address → the still
    assert.equal(cam.normalizeLive({ live: { mode: 'live', mp4: 'https://x/live.mp4', snapshot: media('snapshot.jpg') } }).mode, 'snapshot');
    assert.equal(cam.normalizeLive({ live: { mode: 'live' } }), null);
    assert.equal(cam.normalizeLive({ live: { mode: 'snapshot', snapshot: media('snapshot.jpg'), every: 1 } }).every, 10);
  });

  it('still: base64 JPEG only', () => {
    const s = cam.normalizeStill({ still: { data: JPEG.toString('base64'), mime: 'image/jpeg', at: '2026-11-07T14:00:00Z' } });
    assert.deepEqual(s.data, JPEG);
    assert.equal(s.at, Date.parse('2026-11-07T14:00:00Z'));
    assert.equal(cam.normalizeStill({ still: { data: Buffer.from('<svg/>').toString('base64') } }), null);
    assert.equal(cam.normalizeStill({ still: { data: 'not base64!' } }), null);
    assert.equal(cam.normalizeStill({}), null);
  });

  it('clips: newest first, kinds checked, media addresses converted', () => {
    const c = cam.normalizeClips(CLIPS);
    assert.equal(c.day, '2026-11-07');
    assert.deepEqual(c.clips.map((x) => x.id), ['e000000000000002', 'e000000000000003', 'e000000000000001']);
    assert.equal(c.clips[0].kind, 'person');
    assert.deepEqual(c.clips[0].kinds, ['motion', 'person']);
    assert.equal(c.clips[0].nobodyHome, true);
    assert.equal(c.clips[0].ms, 24000);
    assert.equal(c.clips[0].clipUrl, `gccam://media/${TOK}/clip.mp4`);
    assert.equal(c.clips[1].clipUrl, null);
    assert.deepEqual(c.clips[1].kinds, ['vehicle']);
    assert.equal(c.clips[2].thumbUrl, `gccam://media/${TOK2}/thumb.jpg`);
    assert.equal(cam.dayArg('2026-11-07'), '2026-11-07');
    assert.equal(cam.dayArg(undefined), undefined);
    assert.equal(cam.dayArg('2026-02-30'), null);
  });

  it('push context: camera pushes only (Ring and the locks stay as they are)', () => {
    const p = { topic: 'plugin:gatecontrol-door:kamera', data: { route: 'plg-gatecontrol-door', door: { type: 'home_camera_event', cameraId: CAM1, eventId: 'e000000000000002' } } };
    assert.deepEqual(cam.pushContext(p), { cameraId: CAM1, eventId: 'e000000000000002' });
    assert.deepEqual(cam.pushContext({ ...p, topic: null }), { cameraId: CAM1, eventId: 'e000000000000002' });
    assert.equal(cam.pushContext({ topic: 'plugin:gatecontrol-door:doorbell', data: { door: { type: 'ding', eventId: 4, cameraId: 4, lockId: 1 } } }), null);
    assert.equal(cam.pushContext({ topic: 'plugin:gatecontrol-door:doorbell', data: p.data }), null);
    assert.equal(cam.pushContext({ topic: p.topic, data: { door: { type: 'home_camera_event', cameraId: 'x' } } }), null);
    assert.equal(cam.homeSupported('1.6.0'), true);
    assert.equal(cam.homeSupported('1.5.9'), false);
    assert.equal(cam.homeSupported(null), null);
  });

  it('file name of a saved still', () => {
    const at = new Date(2026, 10, 7, 14, 2, 31).getTime();
    assert.equal(cam.stillFileName('Einfahrt', at), 'Einfahrt 2026-11-07 14-02-31.jpg');
    assert.equal(cam.stillFileName('a/b:c', at), 'a_b_c 2026-11-07 14-02-31.jpg');
  });
});

function fakeApi(routes = {}) {
  const api = { calls: [], routes, scopeValue: 'https://gc\nkey' };
  api.scope = () => api.scopeValue;
  api._call = async (method, p, opts = {}) => {
    api.calls.push([method, p, opts.params || null]);
    const key = p.replace(cam.API_BASE, '');
    let r = api.routes[key];
    if (typeof r === 'function') r = r(opts.params);
    if (r instanceof Error) throw r;
    if (r === undefined) throw new MessengerError('HTTP 404', { status: 404, code: 'not_found' });
    return JSON.parse(JSON.stringify(r));
  };
  api.noticeImage = async (url) => {
    api.calls.push(['NOTICE', url]);
    if (api.noticeFails) throw new MessengerError('HTTP 404', { status: 404 });
    return { mime: 'image/jpeg', data: JPEG };
  };
  return api;
}

const plugins = (version = '1.6.0') => ({ ok: true, plugins: [{ id: 'gatecontrol-messenger', version: '1.11.0' }, { id: 'gatecontrol-door', name: 'Tür & Kamera', version }] });
const STILL = { ok: true, still: { data: JPEG.toString('base64'), mime: 'image/jpeg', at: '2026-11-07T14:00:00Z' } };

function service(routes, opts = {}) {
  let now = opts.now || Date.parse('2026-11-07T14:00:00Z');
  const api = fakeApi({
    '/api/v1/client/plugins': plugins(), 'cameras/home': LIST, [`cameras/home/${CAM1}/live`]: LIVE,
    [`cameras/home/${CAM1}/clips`]: CLIPS, [`cameras/home/${CAM1}/still`]: STILL, ...routes,
  });
  const s = new CamerasService({ api, log, timing: { recheckMs: 1e9, retryMinMs: 1e9 }, now: () => now, ...opts.extra });
  const states = [];
  const pushes = [];
  s.on('state', (x) => states.push(x));
  s.on('push', (x) => pushes.push(x));
  return { s, api, states, pushes, setNow: (v) => { now = v; } };
}

describe('CamerasService', () => {
  it('is available while the plugin is there, the server has cameras and the person sees one', async () => {
    const { s, api, states } = service();
    assert.equal(s.status().state, 'unknown');
    const st = await s.check();
    assert.deepEqual([st.state, st.version, st.count, st.minGatecontrol], ['available', '1.6.0', 2, '1.240.0']);
    assert.equal(states.length, 1);

    api.routes['cameras/home'] = { ok: true, supported: true, cameras: [] };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'no_cameras']);
    api.routes['cameras/home'] = { ok: true, supported: false, minGatecontrol: '1.240.0', cameras: [] };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason, x.minGatecontrol]), ['unavailable', 'needs_gatecontrol', '1.240.0']);
    api.routes['/api/v1/client/plugins'] = plugins('1.5.2');
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'unsupported']);
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [{ id: 'gatecontrol-messenger' }] };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'not_installed']);
    // a plugin without the route (older, unknown version) → unsupported
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [{ id: 'gatecontrol-door' }] };
    delete api.routes['cameras/home'];
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'unsupported']);
  });

  it('network errors keep the page, auth errors close it', async () => {
    const { s, api } = service();
    await s.check();
    api.routes['/api/v1/client/plugins'] = new MessengerError('network', { code: 'network' });
    assert.equal((await s.check()).state, 'available');
    api.routes['/api/v1/client/plugins'] = new MessengerError('HTTP 401', { status: 401, code: 'http_401' });
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'auth']);
  });

  it('list is cached briefly, served stale on network errors', async () => {
    const { s, api, setNow } = service();
    const a = await s.list();
    assert.equal(a.cameras.length, 2);
    const n = api.calls.length;
    await s.list();
    assert.equal(api.calls.length, n, 'from the cache');
    setNow(Date.parse('2026-11-07T14:00:20Z'));
    api.routes['cameras/home'] = new MessengerError('network', { code: 'network' });
    const b = await s.list();
    assert.equal(b.stale, true);
    assert.equal(b.cameras.length, 2);
    assert.equal(s.nameOf(CAM1), 'Einfahrt');
    assert.equal(s.nameOf('c1111111111111111'.slice(0, 16)), 'c111111111111111');
  });

  it('live, still and clips; a camera the person does not see is not found', async () => {
    const { s, api } = service({ [`cameras/home/${CAM2}/live`]: new MessengerError('no right', { status: 404, code: 'not_found' }) });
    assert.equal((await s.live(CAM1)).live.mode, 'live');
    api.routes[`cameras/home/${CAM1}/live`] = SNAP;
    assert.equal((await s.live(CAM1)).live.reason, 'vpn_required');
    await assert.rejects(s.live(CAM2), (e) => e.code === 'not_found');
    await assert.rejects(s.live('../x'), (e) => e.code === 'invalid');
    assert.deepEqual((await s.still(CAM1)).data, JPEG);
    const c = await s.clips(CAM1);
    assert.equal(c.clips.length, 3);
    await s.clips(CAM1);
    assert.equal(api.calls.filter((x) => String(x[1]).endsWith('/clips')).length, 1, 'cached');
    await s.clips(CAM1, { day: '2026-11-06' });
    assert.deepEqual(api.calls.at(-1)[2], { day: '2026-11-06' });
    await assert.rejects(s.clips(CAM1, { day: 'gestern' }), (e) => e.code === 'invalid');
  });

  it('a new server drops everything', async () => {
    const { s, api } = service();
    s.start();
    await tick();
    await s.clips(CAM1);
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    const st = await s.resetForNewServer();
    assert.equal(st.state, 'unavailable');
    const n = api.calls.filter((x) => String(x[1]).endsWith('/clips')).length;
    await s.clips(CAM1);
    assert.equal(api.calls.filter((x) => String(x[1]).endsWith('/clips')).length, n + 1);
    s.stop();
  });
});

// ── The media scheme against a real server ─────────────────

describe('CamerasService.handleProtocol (gccam:)', () => {
  let server;
  let base;
  const seen = [];
  let liveClosed = null;
  before(async () => {
    server = http.createServer((req, res) => {
      seen.push({ url: req.url, range: req.headers.range || null, token: req.headers['x-api-token'] || null });
      if (req.url === media('snapshot.jpg')) { res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'x=1' }); res.end(JPEG); return; }
      if (req.url === media('clip.mp4')) {
        const body = Buffer.alloc(100, 7);
        if (req.headers.range === 'bytes=10-19') {
          res.writeHead(206, { 'Content-Type': 'video/mp4', 'Content-Range': 'bytes 10-19/100', 'Content-Length': '10', 'Accept-Ranges': 'bytes' });
          res.end(body.subarray(10, 20));
        } else {
          res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '100', 'Accept-Ranges': 'bytes' });
          res.end(body);
        }
        return;
      }
      if (req.url === media('live.mp4')) {
        res.writeHead(200, { 'Content-Type': 'video/mp4' });
        let i = 0;
        const t = setInterval(() => { res.write(Buffer.from(`frag${i++}`)); }, 10);
        liveClosed = new Promise((resolve) => res.on('close', () => { clearInterval(t); resolve(true); }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  const svc = () => {
    const apiClient = { serverUrl: base, apiKey: 'device-token', client: axios.create({ baseURL: base, headers: { 'X-API-Token': 'device-token' } }) };
    return new CamerasService({ apiClient, log });
  };
  const req = (url, headers = {}, method = 'GET') => ({ url, method, headers: new Headers(headers) });

  it('a still: fetched from /camera-media/ of the own server, type from the file name, no cookies', async () => {
    const r = await svc().handleProtocol(req(`gccam://media/${TOK}/snapshot.jpg?t=3`));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'image/jpeg');
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.equal(r.headers.get('set-cookie'), null);
    assert.deepEqual(Buffer.from(await r.arrayBuffer()), JPEG);
    assert.equal(seen.at(-1).url, media('snapshot.jpg'));
  });

  it('a clip with Range', async () => {
    const r = await svc().handleProtocol(req(`gccam://media/${TOK}/clip.mp4`, { Range: 'bytes=10-19' }));
    assert.equal(r.status, 206);
    assert.equal(r.headers.get('content-range'), 'bytes 10-19/100');
    assert.equal(r.headers.get('accept-ranges'), 'bytes');
    assert.equal((await r.arrayBuffer()).byteLength, 10);
    // Range only for clips
    await (await svc().handleProtocol(req(`gccam://media/${TOK}/snapshot.jpg`, { Range: 'bytes=0-1' }))).arrayBuffer();
    assert.equal(seen.at(-1).range, null);
  });

  it('live.mp4 streams until the page stops reading', async () => {
    const r = await svc().handleProtocol(req(`gccam://media/${TOK}/live.mp4`));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'video/mp4');
    const reader = r.body.getReader();
    const first = await reader.read();
    assert.ok(Buffer.from(first.value).toString().startsWith('frag'));
    await reader.cancel();
    assert.equal(await liveClosed, true, 'upstream closed');
  });

  it('anything else is refused', async () => {
    assert.equal((await svc().handleProtocol(req(`gccam://media/${TOK2}/clip.mp4`))).status, 404, 'upstream 404');
    assert.equal((await svc().handleProtocol(req('gccam://media/x/../../api/v1/client/peer'))).status, 404);
    assert.equal((await svc().handleProtocol(req(`gccam://evil/${TOK}/live.mp4`))).status, 404);
    assert.equal((await svc().handleProtocol(req(`gccam://media/${TOK}/live.mp4`, {}, 'POST'))).status, 405);
    const none = new CamerasService({ apiClient: {}, log });
    assert.equal((await none.handleProtocol(req(`gccam://media/${TOK}/live.mp4`))).status, 503);
  });
});

// ── Pushes, toast pictures ─────────────────────────────────

function center() {
  class N extends EventEmitter { constructor(o) { super(); this.opts = o; N.created.push(this); } show() {} close() {} static isSupported() { return true; } }
  N.created = [];
  const push = new EventEmitter();
  Object.assign(push, { ack: async () => ({ ok: true }), fetchInbox: async () => ({ ok: true, items: [], unread: 0 }), start() {}, stop() {}, restart() {}, applySettings() {}, status: () => ({ state: 'connected' }) });
  const store = createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } });
  const nc = new NotificationCenter({ store, log, pushClient: push, Notification: N, platform: 'win32', protocol: 'gatecontrol-pro', showWindow() {}, now: () => Date.parse('2026-11-07T14:02:10Z') });
  const navigate = [];
  nc.on('navigate', (x) => navigate.push(x));
  return { nc, N, push, navigate };
}

const camPush = (seq, extra = {}) => ({
  seq, id: seq + 700, topic: 'plugin:gatecontrol-door:kamera', priority: 'high', title: 'Person an der Einfahrt', body: 'Niemand ist zu Hause · 14:02',
  created_at: '2026-11-07T14:02:05Z', expires_at: '2026-11-07T20:02:05Z', silent: false, collapse_key: `homecam:${CAM1}`,
  data: { route: 'plg-gatecontrol-door', door: { type: 'home_camera_event', cameraId: CAM1, eventId: 'e000000000000002' } },
  imageUrl: '/notify-media/abcdef0123456789.jpg', ...extra,
});
const ringPush = (seq) => ({
  seq, id: seq + 700, topic: 'plugin:gatecontrol-door:doorbell', priority: 'high', title: 'Klingel · Haustür', body: 'Haustür · 14:02',
  created_at: '2026-11-07T14:02:05Z', silent: false, data: { route: 'plg-gatecontrol-door', door: { type: 'ding', eventId: 9, cameraId: 4, lockId: 1 } },
  imageUrl: '/notify-media/ring000000000001.jpg',
});
const waitFor = async (fn) => { for (let i = 0; i < 100 && !fn(); i++) await new Promise((r) => setTimeout(r, 5)); };

describe('CamerasService and the notification center', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-cams-'));
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('a camera toast carries the push picture; Ring toasts stay as they were', async () => {
    const { nc, N, navigate } = center();
    const { s, api, pushes } = service({}, { extra: { notificationCenter: nc, tempDir: () => tmp } });
    s.start();
    await tick();
    await s.clips(CAM1);

    nc.handleNotification(ringPush(1));
    assert.equal(N.created.length, 1, 'Ring: toast at once');
    assert.ok(!N.created[0].opts.toastXml.includes('<image src='), 'Ring: no picture');

    nc.handleNotification(camPush(2));
    assert.deepEqual(pushes, [{ cameraId: CAM1, eventId: 'e000000000000002', notificationId: 702 }]);
    await waitFor(() => N.created.length === 2);
    const xml = N.created[1].opts.toastXml;
    const file = path.join(tmp, 'toast-702.jpg');
    assert.ok(xml.includes(`<image src="${file}"/>`), xml);
    assert.deepEqual(fs.readFileSync(file), JPEG);
    assert.deepEqual(api.calls.find((c) => c[0] === 'NOTICE'), ['NOTICE', '/notify-media/abcdef0123456789.jpg']);
    // the clips were dropped by the push
    const n = api.calls.length;
    await s.clips(CAM1);
    assert.equal(api.calls.length, n + 1);

    // click → the page on that camera; Ring → the inbox
    N.created[1].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'plg-gatecontrol-door', id: 702, context: { cameraId: CAM1, eventId: 'e000000000000002' } });
    N.created[0].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 701 });
    s.stop();
  });

  it('without the push picture a fresh still; without any picture the plain toast', async () => {
    const { nc, N } = center();
    const { s, api } = service({}, { extra: { notificationCenter: nc, tempDir: () => tmp } });
    s.start();
    await tick();
    api.noticeFails = true;
    nc.handleNotification(camPush(3));
    await waitFor(() => N.created.length === 1);
    assert.ok(N.created[0].opts.toastXml.includes('toast-703.jpg'));
    assert.ok(api.calls.some((c) => String(c[1]).endsWith(`${CAM1}/still`)));

    api.routes[`cameras/home/${CAM1}/still`] = new MessengerError('offline', { status: 502, code: 'cam_offline' });
    nc.handleNotification(camPush(4, { imageUrl: null }));
    await waitFor(() => N.created.length === 2);
    assert.ok(!N.created[1].opts.toastXml.includes('<image src='));
    s.stop();
  });

  it('a toast waits for its picture only so long, and not at all when read meanwhile', async () => {
    const { nc, N } = center();
    nc.toastImageWaitMs = 20;
    let release;
    const off = nc.addToastImage(() => new Promise((r) => { release = r; }));
    nc.handleNotification(camPush(5));
    assert.equal(N.created.length, 0);
    await waitFor(() => N.created.length === 1);
    assert.ok(!N.created[0].opts.toastXml.includes('<image src='), 'shown without it');
    release('/tmp/late.jpg');

    nc.toastImageWaitMs = 5000;
    let release2;
    nc._toastImages = [];
    nc.addToastImage(() => new Promise((r) => { release2 = r; }));
    nc.handleNotification(camPush(6));
    nc._markLocal([706], 'read', 'read');
    release2(path.join(tmp, 'x.jpg'));
    await tick();
    await tick();
    assert.equal(N.created.length, 1, 'read elsewhere: no banner');
    off();
    assert.throws(() => nc.addToastImage('x'), TypeError);
  });

  it('the inbox entry keeps the push picture path (notify-media only)', () => {
    const { nc } = center();
    nc.handleNotification(camPush(7));
    assert.equal(nc.get(707).image_url, '/notify-media/abcdef0123456789.jpg');
    nc.handleNotification(camPush(8, { imageUrl: 'https://evil.example/x.jpg' }));
    assert.ok(!('image_url' in nc.get(708)));
  });

  it('toast XML: a picture below the text, escaped', () => {
    const xml = buildToastXml({ title: 'Person an der Einfahrt', inlineImagePath: 'C:\\Temp\\a&b.jpg' });
    assert.ok(xml.includes('<image src="C:\\Temp\\a&amp;b.jpg"/>'));
    assert.ok(!buildToastXml({ title: 'x' }).includes('<image'));
  });
});

// ── IPC ────────────────────────────────────────────────────

describe('cameras:* IPC', () => {
  function register(s, dialog = {}) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', getPath: () => os.tmpdir() }, dialog, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', cameras: s,
      userFolders: { userPath: () => os.tmpdir(), dialogPath: (k, n) => path.join('C:\\Users\\marc\\Pictures', n), info: () => ({}), checked: () => Promise.resolve() },
    });
    return { handlers, sent };
  }

  it('channels, argument checks and events', async () => {
    const { s } = service();
    const { handlers, sent } = register(s);
    for (const ch of ['cameras:status', 'cameras:check', 'cameras:list', 'cameras:live', 'cameras:clips', 'cameras:still:save']) assert.ok(handlers[ch], ch);
    assert.equal((await handlers['cameras:check']()).state, 'available');
    assert.equal(sent.at(-1)[0], 'cameras:state');
    assert.equal((await handlers['cameras:list'](null, {})).cameras.length, 2);
    assert.deepEqual(await handlers['cameras:live'](null, { id: '../../x' }), { ok: false, code: 'invalid', error: 'invalid argument', status: null });
    assert.equal((await handlers['cameras:live'](null, { id: CAM1 })).live.mode, 'live');
    assert.equal((await handlers['cameras:clips'](null, { id: CAM1, day: 'morgen' })).code, 'invalid');
    assert.equal((await handlers['cameras:clips'](null, { id: CAM1 })).clips.length, 3);
    const nf = await handlers['cameras:live'](null, { id: CAM2 });
    assert.deepEqual([nf.ok, nf.code, nf.status], [false, 'not_found', 404]);
    s.emit('push', { cameraId: CAM1 });
    assert.deepEqual(sent.at(-1), ['cameras:push', { cameraId: CAM1 }]);
  });

  it('Standbild speichern: a fresh still into the file the person picks (Pictures)', async () => {
    const { s } = service();
    await s.list();
    const written = [];
    let opts = null;
    const dialog = { showSaveDialog: async (_w, o) => { opts = o; return { canceled: false, filePath: 'C:\\Users\\marc\\Pictures\\x.jpg' }; } };
    const { handlers } = register(s, dialog);
    const fsp = require('fs').promises;
    const orig = fsp.writeFile;
    fsp.writeFile = async (p, d) => { written.push([p, d]); };
    try {
      const r = await handlers['cameras:still:save'](null, { id: CAM1 });
      assert.deepEqual(r, { ok: true, path: 'C:\\Users\\marc\\Pictures\\x.jpg' });
    } finally {
      fsp.writeFile = orig;
    }
    assert.match(opts.defaultPath, /Pictures.Einfahrt \d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}\.jpg$/);
    assert.deepEqual(written, [['C:\\Users\\marc\\Pictures\\x.jpg', JPEG]]);
    dialog.showSaveDialog = async () => ({ canceled: true });
    assert.deepEqual(await handlers['cameras:still:save'](null, { id: CAM1 }), { ok: false, cancelled: true });
    assert.equal((await register(s, {}).handlers['cameras:still:save'](null, { id: CAM1 })).code, 'unsupported');
  });

  it('no cameras service → no cameras:* channels', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.ok(!Object.keys(handlers).some((c) => c.startsWith('cameras:')));
  });
});

describe('i18n cameras.* (de / en)', () => {
  const keys = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? keys(v, `${p}${k}.`) : [`${p}${k}`]));
  it('same keys in both languages, same placeholders', () => {
    assert.deepEqual(keys(de.cameras).sort(), keys(en.cameras).sort());
    const get = (o, k) => k.split('.').reduce((a, x) => a[x], o);
    for (const k of keys(de.cameras)) {
      const ph = (s) => (String(s).match(/\{\{\w+\}\}/g) || []).sort();
      assert.deepEqual(ph(get(de.cameras, k)), ph(get(en.cameras, k)), k);
    }
    assert.equal(de.cameras.clips.title, 'Clips heute');
    assert.equal(de.cameras.saveStill, 'Standbild speichern');
  });
});
