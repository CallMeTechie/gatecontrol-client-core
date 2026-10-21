'use strict';

// The chat as the place for all notifications (core 1.191, Messenger 1.6):
// push routes (GET/PUT /api/v1/client/push/routes) through ApiClient →
// PushClient → NotificationCenter → IPC, a notice card's link opening what a
// click on its notification would (openTarget / notify:open), notice card
// pictures (/notify-media/…) and the messenger helpers that know the 1.6 fields.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');
const EventEmitter = require('node:events');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const NotificationCenter = require('../src/services/notification-center');
const MessengerApi = require('../src/services/messenger-api');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createBridgeApi } = require('../src/preload/bridge');
const i18n = require('../src/i18n');
const notifyRoutes = require('../src/utils/notify-routes');
const messenger = require('../src/utils/messenger');
const school = require('../src/utils/school');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, error() {}, debug() {} };

const ROUTES = {
  ok: true,
  sink: true,
  canFamily: false,
  groups: [
    { source: 'core', label: 'GateControl', topics: [
      { id: 'security', label: 'Sicherheit', dest: 'own', locked: false, familySetBy: null },
      { id: 'devices', label: 'Geräte', dest: 'inbox', locked: false, familySetBy: null },
    ] },
    { source: 'plugin:gatecontrol-schule', label: 'Schule', topics: [
      { id: 'plugin:gatecontrol-schule:messages', label: 'Nachrichten der Schule', dest: 'family', locked: false, familySetBy: 'Marc' },
      { id: 'plugin:gatecontrol-schule:changes', label: 'Vertretungen\n', dest: 'bogus', locked: 0 },
      { id: 'plugin:gatecontrol-schule:changes', label: 'doppelt', dest: 'own' },
      { id: '../etc', label: 'x', dest: 'own' },
    ] },
    { source: 'http://evil', label: 'x', topics: [{ id: 'devices', dest: 'own' }] },
    { source: 'plugin:empty', label: 'Leer', topics: [] },
  ],
};

describe('notify-routes helpers', () => {
  it('normalizes the answer: known dests, locked core topics, plain labels, no duplicates or bad ids', () => {
    const r = notifyRoutes.normalizeRoutes(ROUTES);
    assert.equal(r.sink, true);
    assert.equal(r.canFamily, false);
    assert.deepEqual(r.groups.map((g) => g.source), ['core', 'plugin:gatecontrol-schule']);
    const [sec, dev] = r.groups[0].topics;
    // security always stays in GateControl, whatever the server says
    assert.deepEqual([sec.dest, sec.locked], ['inbox', true]);
    assert.deepEqual([dev.dest, dev.locked], ['inbox', false]);
    const schule = r.groups[1].topics;
    assert.deepEqual(schule.map((tp) => tp.id), ['plugin:gatecontrol-schule:messages', 'plugin:gatecontrol-schule:changes']);
    assert.deepEqual([schule[0].dest, schule[0].familySetBy], ['family', 'Marc']);
    assert.deepEqual([schule[1].dest, schule[1].label, schule[1].familySetBy], ['inbox', 'Vertretungen', null]);
  });

  it('refuses what is not an answer and reads refusal codes', () => {
    assert.equal(notifyRoutes.normalizeRoutes(null), null);
    assert.equal(notifyRoutes.normalizeRoutes({ ok: true }), null);
    assert.equal(notifyRoutes.normalizeRoutes([]), null);
    assert.deepEqual(notifyRoutes.normalizeRoutes({ groups: [] }), { sink: false, canFamily: false, groups: [] });
    assert.equal(notifyRoutes.errorCode({ error: 'Family_Not_Allowed' }), 'family_not_allowed');
    assert.equal(notifyRoutes.errorCode({ code: 'locked' }), 'locked');
    assert.equal(notifyRoutes.errorCode({ error: 'Not found <b>' }), null);
    assert.equal(notifyRoutes.errorCode('x'), null);
  });

  it('normalizes the own chat of a PUT answer (GateControl 1.192); anything else → null', () => {
    assert.deepEqual(notifyRoutes.normalizeChat({ source: 'plugin:gatecontrol-schule', label: 'Schule', conversationId: '42', created: true }),
      { source: 'plugin:gatecontrol-schule', label: 'Schule', conversationId: '42', created: true });
    assert.deepEqual(notifyRoutes.normalizeChat({ source: 'core', label: ' \n', conversationId: 7, created: false }),
      { source: 'core', label: 'GateControl', conversationId: '7', created: false });
    // the label falls back to the plugin id; a bad id is dropped, not the chat
    assert.deepEqual(notifyRoutes.normalizeChat({ source: 'plugin:gatecontrol-schule', conversationId: '../1', created: 'yes' }),
      { source: 'plugin:gatecontrol-schule', label: 'gatecontrol-schule', conversationId: null, created: false });
    for (const bad of [null, undefined, 'x', [], {}, { source: 'http://evil', label: 'x' }, { source: 7 }]) assert.equal(notifyRoutes.normalizeChat(bad), null);
  });
});

/** A core stub: GET/PUT /api/v1/client/push/routes as `routes` says. */
function routesServer() {
  const state = { mode: 'ok', puts: [], chats: new Set(), routes: JSON.parse(JSON.stringify(ROUTES)) };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
      if (req.url !== '/api/v1/client/push/routes' || req.headers['x-api-token'] !== 'tok') return send(404, { error: 'Not found' });
      if (state.mode === 'old') return send(404, { error: 'Not found' });
      if (state.mode === 'disabled') return send(503, { ok: false, error: 'push_disabled' });
      if (req.method === 'GET') return send(200, state.routes);
      const b = JSON.parse(body || '{}');
      state.puts.push(b);
      if (b.topic === 'plugin:gone:x') return send(404, { ok: false, error: 'unknown_topic' });
      if (b.dest === 'family' && !state.routes.canFamily) return send(403, { ok: false, error: 'family_not_allowed' });
      if (b.topic === 'devices' && b.dest === 'own' && state.mode === 'nosink') return send(409, { ok: false, error: 'no_sink' });
      for (const g of state.routes.groups) for (const tp of g.topics || []) if (tp.id === b.topic) tp.dest = b.dest;
      // GateControl 1.192: on "own" the source's own chat (created or the existing one)
      if (b.dest === 'own' && state.mode !== 'nochat') {
        const g = state.routes.groups.find((x) => (x.topics || []).some((tp) => tp.id === b.topic));
        const created = !state.chats.has(g.source);
        state.chats.add(g.source);
        return send(200, { ...state.routes, chat: { source: g.source, label: g.label, conversationId: '42', created } });
      }
      return send(200, state.mode === 'nochat' ? state.routes : { ...state.routes, chat: null }); // nochat: a server before 1.192
    });
  });
  return { server, state };
}

describe('push routes over the device token', () => {
  let srv;
  let push;
  before(async () => {
    srv = routesServer();
    await new Promise((r) => srv.server.listen(0, '127.0.0.1', r));
    const api = new ApiClient(`http://127.0.0.1:${srv.server.address().port}`, 'tok', log);
    push = new PushClient({ apiClient: api, store: createMemoryStore(), log, allowHttp: true });
  });
  after(() => srv.server.close());

  it('GET → normalized routes; PUT → the new answer', async () => {
    srv.state.mode = 'ok';
    const r = await push.fetchRoutes();
    assert.equal(r.ok, true);
    assert.equal(r.routes.groups[1].label, 'Schule');
    const s = await push.setRoute('devices', 'own');
    assert.equal(s.ok, true);
    assert.equal(s.routes.groups[0].topics[1].dest, 'own');
    assert.deepEqual(srv.state.puts.at(-1), { topic: 'devices', dest: 'own' });
  });

  it('PUT own → the own chat (created, then the existing one); inbox / older servers → null', async () => {
    srv.state.mode = 'ok';
    srv.state.chats.clear();
    const a = await push.setRoute('plugin:gatecontrol-schule:changes', 'own');
    assert.equal(a.ok, true);
    assert.deepEqual(a.chat, { source: 'plugin:gatecontrol-schule', label: 'Schule', conversationId: '42', created: true });
    const b = await push.setRoute('plugin:gatecontrol-schule:changes', 'own');
    assert.equal(b.chat.created, false);
    assert.equal((await push.setRoute('plugin:gatecontrol-schule:changes', 'inbox')).chat, null);
    srv.state.mode = 'nochat'; // a server before 1.192: no chat field
    const c = await push.setRoute('plugin:gatecontrol-schule:changes', 'own');
    assert.deepEqual([c.ok, c.chat], [true, null]);
    srv.state.mode = 'ok';
  });

  it('server refusals come back as their codes; older servers as unsupported', async () => {
    srv.state.mode = 'ok';
    assert.deepEqual(await push.setRoute('plugin:gatecontrol-schule:messages', 'family'), { ok: false, error: 'family_not_allowed' });
    assert.deepEqual(await push.setRoute('plugin:gone:x', 'own'), { ok: false, error: 'unknown_topic' });
    srv.state.mode = 'nosink';
    assert.deepEqual(await push.setRoute('devices', 'own'), { ok: false, error: 'no_sink' });
    srv.state.mode = 'disabled';
    assert.deepEqual(await push.fetchRoutes(), { ok: false, error: 'push_disabled' });
    srv.state.mode = 'old';
    assert.deepEqual(await push.fetchRoutes(), { ok: false, error: 'unsupported' });
    assert.deepEqual(await push.setRoute('devices', 'inbox'), { ok: false, error: 'unsupported' });
  });

  it('checks its arguments before asking the server', async () => {
    const before = srv.state.puts.length;
    assert.deepEqual(await push.setRoute('../x', 'own'), { ok: false, error: 'invalid_topic' });
    assert.deepEqual(await push.setRoute('devices', 'chat'), { ok: false, error: 'invalid_dest' });
    assert.deepEqual(await push.setRoute('admin_notice', 'own'), { ok: false, error: 'locked' });
    assert.equal(srv.state.puts.length, before);
  });

  it('without a server: an error, no exception', async () => {
    const none = new PushClient({ apiClient: new ApiClient('', '', log), store: createMemoryStore(), log });
    const r = await none.fetchRoutes();
    assert.equal(r.ok, false);
    const legacy = new PushClient({ apiClient: {}, store: createMemoryStore(), log });
    assert.deepEqual(await legacy.fetchRoutes(), { ok: false, error: 'unsupported' });
  });
});

function center(pushClient = null) {
  const push = pushClient || Object.assign(new EventEmitter(), { status: () => ({ state: 'connected' }), applySettings() {}, start() {}, stop() {} });
  return new NotificationCenter({
    store: createMemoryStore({ notifications: {} }), log, pushClient: push, platform: 'win32',
    Notification: class { on() {} show() {} close() {} static isSupported() { return true; } },
  });
}

describe('NotificationCenter.openTarget (notice card links)', () => {
  it('a page that claims the notification opens like on a toast click', () => {
    const nc = center();
    nc.addClickRoute(school.APP_ROUTE, (entry) => school.pushContext(entry));
    const nav = [];
    nc.on('navigate', (e) => nav.push(e));
    const r = nc.openTarget({
      route: 'plg-gatecontrol-schule/messages/4711',
      topic: 'plugin:gatecontrol-schule:messages',
      data: { schule: { studentId: 3, messageId: '4711' } },
    });
    assert.deepEqual(r, { ok: true, route: 'plg-gatecontrol-schule' });
    assert.equal(nav.length, 1);
    assert.equal(nav[0].route, 'plg-gatecontrol-schule');
    assert.equal(nav[0].id, null);
    assert.equal(nav[0].context.kind, 'messages');
    assert.equal(nav[0].context.studentId, 3);
  });

  it('the link route alone is enough for the plugin page (data.route)', () => {
    const nc = center();
    nc.addClickRoute(school.APP_ROUTE, (entry) => school.pushContext(entry));
    const nav = [];
    nc.on('navigate', (e) => nav.push(e));
    assert.equal(nc.openTarget({ route: 'plg-gatecontrol-schule' }).ok, true);
    assert.equal(nav[0].route, 'plg-gatecontrol-schule');
  });

  it('nothing claims it → ok false and no navigation (the app opens the route itself)', () => {
    const nc = center();
    const nav = [];
    nc.on('navigate', (e) => nav.push(e));
    assert.deepEqual(nc.openTarget({ route: 'plg-gatecontrol-door', topic: 'plugin:gatecontrol-door:ring', data: {} }), { ok: false });
    assert.deepEqual(nc.openTarget({ route: 'javascript:alert(1)' }), { ok: false });
    assert.deepEqual(nc.openTarget(), { ok: false });
    nc.addClickRoute('plg-gatecontrol-schule', () => null);
    assert.deepEqual(nc.openTarget({ route: 'plg-gatecontrol-schule/messages/1' }), { ok: false });
    assert.equal(nav.length, 0);
  });

  it('routes / setRoute pass through to the push client; not attached → error', async () => {
    const calls = [];
    const fake = Object.assign(new EventEmitter(), {
      status: () => ({ state: 'connected' }), applySettings() {}, start() {}, stop() {},
      fetchRoutes: async () => ({ ok: true, routes: { sink: false, canFamily: false, groups: [] } }),
      setRoute: async (topic, dest) => { calls.push([topic, dest]); return { ok: false, error: 'no_sink' }; },
    });
    const nc = center(fake);
    assert.equal((await nc.routes()).ok, true);
    assert.deepEqual(await nc.setRoute('devices', 'own'), { ok: false, error: 'no_sink' });
    assert.deepEqual(calls, [['devices', 'own']]);
    // the own chat of the answer reaches the app unchanged
    const chat = { source: 'plugin:gatecontrol-schule', label: 'Schule', conversationId: '42', created: true };
    fake.setRoute = async () => ({ ok: true, routes: { sink: true, canFamily: false, groups: [] }, chat });
    assert.deepEqual((await nc.setRoute('plugin:gatecontrol-schule:messages', 'own')).chat, chat);
    const lone = new NotificationCenter({ store: createMemoryStore({ notifications: {} }), log, platform: 'win32' });
    assert.deepEqual(await lone.routes(), { ok: false, error: 'not_attached' });
    assert.deepEqual(await lone.setRoute('devices', 'own'), { ok: false, error: 'not_attached' });
  });
});

describe('notify IPC and bridge for routes and card links', () => {
  function handlersWith(nc) {
    const handlers = {};
    registerBaseHandlers({ handle: (ch, fn) => { handlers[ch] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
      dialog: {}, getMainWindow: () => null, store: createMemoryStore({ notifications: {} }),
      wgService: {}, apiClient: {}, log,
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
      wgConfigFile: 'wg.conf', notificationCenter: nc,
    });
    return handlers;
  }

  it('notify:routes / notify:routes:set / notify:open check their arguments', async () => {
    const seen = [];
    const nc = {
      on() {},
      routes: async () => ({ ok: true, routes: { sink: true, canFamily: true, groups: [] } }),
      setRoute: async (topic, dest) => { seen.push(['set', topic, dest]); return { ok: true, routes: null }; },
      openTarget: (t) => { seen.push(['open', t]); return { ok: false }; },
    };
    const h = handlersWith(nc);
    assert.equal((await h['notify:routes']({})).ok, true);
    assert.deepEqual(await h['notify:routes:set']({}, null), { ok: false, error: 'invalid' });
    assert.deepEqual(await h['notify:routes:set']({}, { topic: 'devices', dest: 7 }), { ok: false, error: 'invalid' });
    const chat = { source: 'core', label: 'GateControl', conversationId: '9', created: false };
    nc.setRoute = async (topic, dest) => { seen.push(['set', topic, dest]); return { ok: true, routes: null, chat }; };
    assert.deepEqual((await h['notify:routes:set']({}, { topic: 'devices', dest: 'own' })).chat, chat);
    await h['notify:open']({}, { route: 'plg-x/y', topic: 'plugin:x:y', data: { a: 1 } });
    await h['notify:open']({}, { route: 5, data: [1] });
    await h['notify:open']({}, { route: 'plg-x', data: { big: 'x'.repeat(20000) } });
    assert.deepEqual(seen, [
      ['set', 'devices', 'own'],
      ['open', { route: 'plg-x/y', topic: 'plugin:x:y', data: { a: 1 } }],
      ['open', { route: null, topic: null, data: null }],
      ['open', { route: 'plg-x', topic: null, data: null }],
    ]);
  });

  it('the bridge sends routes, setRoute, open and noticeImage on their channels', () => {
    const calls = [];
    const ipc = { invoke: (...a) => { calls.push(a); return Promise.resolve(); }, send() {}, on() {}, removeListener() {} };
    const api = createBridgeApi(ipc, i18n);
    api.notify.routes();
    api.notify.setRoute('devices', 'family');
    api.notify.open({ route: 'plg-gatecontrol-schule', topic: null, data: null });
    api.chat.noticeImage('/notify-media/abcdefgh12.jpg');
    assert.deepEqual(calls, [
      ['notify:routes'],
      ['notify:routes:set', { topic: 'devices', dest: 'family' }],
      ['notify:open', { route: 'plg-gatecontrol-schule', topic: null, data: null }],
      ['chat:notice:image', { path: '/notify-media/abcdefgh12.jpg' }],
    ]);
  });
});

describe('messenger helpers for Messenger 1.6', () => {
  it('knows the notice features (no update hint)', () => {
    assert.deepEqual(messenger.unknownFeatures({ notices: true, notice_routes: true, story_duration: true }), []);
    assert.equal(messenger.FEATURES_14.notices, 'notices');
  });

  it('card routes may name a plugin screen after a slash, nothing else', () => {
    assert.equal(messenger.cardRoute({ route: 'plg-gatecontrol-door' }), 'plg-gatecontrol-door');
    assert.equal(messenger.cardRoute({ route: 'plg-gatecontrol-schule/messages/4711' }), 'plg-gatecontrol-schule/messages/4711');
    for (const bad of ['vpn', 'plg-x/../y', 'plg-x/..', 'plg-x//y', 'plg-x/a/b/c/d', 'plg-x/a?b', 'https://x', 'plg-x/' + 'a'.repeat(81)]) {
      assert.equal(messenger.cardRoute({ route: bad }), null, bad);
    }
  });

  it('notice pictures: only /notify-media/ of the own server', () => {
    assert.equal(messenger.isNotifyMediaPath('/notify-media/abcdefgh12.webp'), true);
    for (const bad of ['/notify-media/short.jpg', '/notify-media/../x.jpg', 'https://evil/notify-media/abcdefgh12.jpg', '/notify-media/abcdefgh12.svg', '/avatars/abcdefghijklmnop.png']) {
      assert.equal(messenger.isNotifyMediaPath(bad), false, bad);
    }
  });
});

describe('notice card pictures over the device token', () => {
  let server;
  let api;
  const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
  before(async () => {
    server = http.createServer((req, res) => {
      if (req.headers['x-api-token'] !== 'tok') { res.writeHead(401); res.end(); return; }
      if (req.url === '/notify-media/doorbell0001.png') { res.writeHead(200, { 'Content-Type': 'image/png' }); res.end(PNG); return; }
      if (req.url === '/notify-media/htmlpage0001.png') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<b>x</b>'); return; }
      if (req.url === '/notify-media/hugefile0001.png') { res.writeHead(200, { 'Content-Type': 'image/png' }); res.end(Buffer.alloc(1024 * 1024 + 10)); return; }
      res.writeHead(404); res.end();
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    api = new MessengerApi({ apiClient: new ApiClient(`http://127.0.0.1:${server.address().port}`, 'tok', log), log });
  });
  after(() => server.close());

  it('loads pictures, refuses other types, sizes and paths', async () => {
    const r = await api.noticeImage('/notify-media/doorbell0001.png');
    assert.equal(r.mime, 'image/png');
    assert.deepEqual(r.data, PNG);
    await assert.rejects(api.noticeImage('/notify-media/htmlpage0001.png'), (e) => e.code === 'bad_response');
    await assert.rejects(api.noticeImage('/notify-media/hugefile0001.png'));
    await assert.rejects(api.noticeImage('/etc/passwd'), (e) => e.code === 'invalid');
  });
});
