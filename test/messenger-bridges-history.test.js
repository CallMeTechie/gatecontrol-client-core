'use strict';

// Messenger 1.17 (Stufe 5 der Brücken): „Älteren Verlauf laden“ in „Verknüpfte Dienste“ (GET bridges → history,
// PUT bridges/history), files of the history on request (placeholder on_request → POST messages/:id/fetch), the
// older messages filed in at night (conversation.update { reason: history }), the phone warning (networks[].phone,
// the push of the topic `bridge`) and „Brücke veraltet“ also by clientOutdated. Detected only by the feature word
// bridge_history — an older plugin keeps everything as it was.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('events');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerService = require('../src/services/messenger');
const ChatNotifier = require('../src/services/chat-notifier');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };
const STAGE4 = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_new_chat: true };
const STAGE5 = { ...STAGE4, bridge_history: true };

const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function waitFor(fn, ms = 4000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function setup({ features = STAGE5, push = false } = {}) {
  const srv = await messengerServer({ features });
  srv.state.bridge.media = true;
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const store = createMemoryStore();
  let pushClient = null;
  if (push) {
    pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: PUSH_FAST });
    cleanups.push(() => pushClient.stop());
    pushClient.start();
  }
  const m = new MessengerService({ apiClient, pushClient, store, log, timing: FAST });
  cleanups.push(() => m.stop());
  const events = [];
  for (const ev of ['conversations', 'messages']) m.on(ev, (p) => events.push({ ev, p }));
  return { srv, m, events };
}
const bridgeCalls = (srv) => srv.state.requests.filter((r) => r.path.startsWith(`${API}bridges/`));
const msgGets = (srv, id) => srv.state.requests.filter((r) => r.method === 'GET' && r.path === `${API}conversations/${id}/messages`);

describe('bridges stage 5 – helpers', () => {
  it('knows the new feature word (no update hint for it)', () => {
    assert.deepEqual(U.unknownFeatures({ bridge_chats: true, bridge_media: true, bridge_new_chat: true, bridge_history: true }), []);
  });

  it('GET bridges: history, the phone warning and clientOutdated; an older plugin has none of them', () => {
    const b = U.normalizeBridges({ available: true, location: 'server', history: { available: true, days: -1, default: 30, options: [0, 30, -1, 7, 'x'], pending: 412 }, networks: [
      { id: 'whatsapp', state: 'running', allowed: true, outdated: false, clientOutdated: true, phone: { offline: true, days: 12, leftDays: 2 }, logins: [] },
    ] });
    assert.deepEqual(b.history, { available: true, days: -1, default: 30, options: [0, 30, -1], pending: 412 });
    assert.equal(b.networks[0].clientOutdated, true);
    assert.deepEqual(b.networks[0].phone, { offline: true, days: 12, leftDays: 2 });
    const old = U.normalizeBridges({ available: true, location: 'server', networks: [{ id: 'whatsapp', state: 'running', allowed: true, logins: [] }] });
    assert.equal(old.history, null);
    assert.equal(old.networks[0].clientOutdated, false);
    assert.deepEqual(old.networks[0].phone, { offline: false, days: null, leftDays: null });
    assert.equal(U.normalizeBridges({ available: false, history: { available: true } }).history, null);
  });

  it('history: switched off by the administrator, odd values fall back to the default', () => {
    assert.deepEqual(U.normalizeBridgeHistory({ available: false, days: 30, default: 30, options: [0, 30, -1], pending: 0 }), { available: false, days: 30, default: 30, options: [0, 30, -1], pending: 0 });
    assert.deepEqual(U.normalizeBridgeHistory({ available: true, days: 14, default: 0, options: [], pending: -3 }), { available: true, days: 0, default: 0, options: [0, 30, -1], pending: 0 });
    assert.equal(U.normalizeBridgeHistory(null), null);
    assert.equal(U.normalizeBridgeHistory([]), null);
    assert.deepEqual(U.normalizePhone({ offline: true, days: 15, leftDays: 0 }), { offline: true, days: 15, leftDays: 0 });
    assert.deepEqual(U.normalizePhone({ offline: 'yes', days: 15 }), { offline: false, days: null, leftDays: null });
  });

  it('the push of „Verknüpfte Dienste“ (topic bridge, deepLink bridges) opens them; others are not ours', () => {
    assert.deepEqual(U.bridgePushContext({ topic: 'plugin:gatecontrol-messenger:bridge', data: { deepLink: 'bridges', bridge: 'whatsapp' } }), { type: 'bridges', bridge: 'whatsapp' });
    assert.deepEqual(U.bridgePushContext({ topic: 'plugin:gatecontrol-messenger:bridge', data: null }), { type: 'bridges', bridge: null });
    assert.deepEqual(U.bridgePushContext({ topic: 'plugin:gatecontrol-messenger:other', data: { deepLink: 'bridges', bridge: 'Bad Net' } }), { type: 'bridges', bridge: null });
    assert.equal(U.bridgePushContext({ topic: 'plugin:gatecontrol-messenger:message', data: { deepLink: 'chat' } }), null);
    assert.equal(U.bridgePushContext({ topic: 'plugin:gatecontrol-familie:internet', data: { deepLink: 'bridges' } }), null);
    assert.equal(U.bridgePushContext(null), null);
  });
});

describe('bridges stage 5 – MessengerService', () => {
  it('„Älteren Verlauf laden“: GET bridges carries the choice, PUT bridges/history changes it; days are checked first', async () => {
    const { srv, m } = await setup();
    m.start();
    await waitFor(() => m.supports('bridge_history'));
    srv.state.bridge.history.pending = 120;
    srv.state.bridge.networks[0].phone = { offline: true, days: 13, leftDays: 1 };
    srv.state.bridge.networks[0].clientOutdated = true;
    const b = await m.bridges();
    assert.deepEqual(b.history, { available: true, days: 30, default: 30, options: [0, 30, -1], pending: 120 });
    assert.deepEqual(b.networks[0].phone, { offline: true, days: 13, leftDays: 1 });
    assert.equal(b.networks[0].clientOutdated, true);
    assert.deepEqual(await m.setBridgeHistory(-1), { available: true, days: -1, default: 30, options: [0, 30, -1], pending: 120 });
    assert.deepEqual(await m.setBridgeHistory(0), { available: true, days: 0, default: 30, options: [0, 30, -1], pending: 0 });
    const before = srv.state.requests.length;
    for (const bad of [7, '30', null, undefined]) await assert.rejects(m.setBridgeHistory(bad), (e) => e.code === 'invalid');
    assert.equal(srv.state.requests.length, before, 'nothing asked for invalid days');
    const put = srv.state.requests.filter((r) => r.method === 'PUT' && r.path === `${API}bridges/history`);
    assert.deepEqual(put.map((r) => r.body), [{ days: -1 }, { days: 0 }]);
  });

  it('a file of the history: on_request → POST messages/:id/fetch?bridged=1 → loading; nothing to fetch → invalid', async () => {
    const { srv, m } = await setup();
    const id = srv.addBridgeConv({ title: 'Kim Muster' });
    const old = srv.addBridgeMsg(id, { text: '', placeholder: { kind: 'image', name: 'IMG-2041.jpg', state: 'on_request' } });
    const other = srv.addBridgeMsg(id, { text: 'Hallo' });
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await m.getMessages(id);
    const got = await m.fetchBridgeFile(old.id);
    assert.equal(got.bridge.placeholder.state, 'loading');
    assert.equal(m.messagesView(id).messages.find((x) => x.id === old.id).bridge.placeholder.state, 'loading');
    const post = srv.state.requests.find((r) => r.method === 'POST' && r.path === `${API}messages/${old.id}/fetch`);
    assert.equal(post.query.bridged, '1');
    assert.deepEqual(post.body, {});
    assert.deepEqual(srv.state.bridge.fetches, [old.id]);
    await assert.rejects(m.fetchBridgeFile(other.id), (e) => e.code === 'invalid' && e.status === 400);
    await assert.rejects(m.fetchBridgeFile('x'), (e) => e.code === 'invalid');
  });

  it('older messages at night (conversation.update reason history): the open chat loads again, another drops its cache', async () => {
    const { srv, m, events } = await setup({ push: true });
    const open = srv.addBridgeConv({ title: 'Kim Muster' });
    srv.addBridgeMsg(open, { text: 'Neu' });
    const closed = srv.addBridgeConv({ title: 'Elternrunde', kind: 'group' });
    srv.addBridgeMsg(closed, { text: 'Gestern' });
    m.start();
    await waitFor(() => m.listConversations().length === 2);
    await m.getMessages(open);
    await m.getMessages(closed);
    m.setOpen({ id: open, visible: true });
    await waitFor(() => srv.streams.size > 0, 4000, 'push stream');
    const before = msgGets(srv, open).length;
    srv.addBridgeMsg(open, { text: 'Alt aus dem Verlauf' });
    srv.event('conversation.update', { conversationId: open, reason: 'history' });
    await waitFor(() => events.some((e) => e.ev === 'messages' && e.p.conversationId === open && e.p.reason === 'history'), 4000, 'history reload');
    assert.ok(msgGets(srv, open).length > before, 'the open chat asked again');
    assert.ok(m.messagesView(open).messages.some((x) => x.text === 'Alt aus dem Verlauf'));
    // not open: the cache goes, the next look loads the newest page
    srv.addBridgeMsg(closed, { text: 'Vorgestern' });
    srv.event('conversation.update', { conversationId: closed, reason: 'history' });
    await waitFor(() => m.messagesView(closed).messages.length === 0, 4000, 'cache dropped');
    const v = await m.getMessages(closed);
    assert.deepEqual(v.messages.map((x) => x.text), ['Gestern', 'Vorgestern']);
  });

  it('an older plugin (1.16): no history, no fetch, no phone — nothing asked', async () => {
    const { srv, m } = await setup({ features: STAGE4 });
    m.start();
    await waitFor(() => m.supports('bridge_chats'));
    const b = await m.bridges();
    assert.equal(b.history, null);
    assert.equal(b.networks[0].clientOutdated, false);
    assert.equal(b.networks[0].phone.offline, false);
    await assert.rejects(m.setBridgeHistory(30), (e) => e.code === 'unsupported');
    await assert.rejects(m.fetchBridgeFile(5), (e) => e.code === 'unsupported');
    assert.equal(bridgeCalls(srv).length, 0);
    assert.equal(srv.state.requests.filter((r) => r.path.includes('/fetch')).length, 0);
  });
});

describe('bridges stage 5 – ChatNotifier', () => {
  it('claims a click on the push of „Verknüpfte Dienste“ for the chats (context type bridges), nothing else', () => {
    const routes = new Map();
    const nc = Object.assign(new EventEmitter(), {
      setChatHandler() {},
      addClickRoute(route, fn) { routes.set(route, fn); return () => routes.delete(route); },
    });
    const n = new ChatNotifier({ messenger: new EventEmitter(), notificationCenter: nc, log, platform: 'linux' });
    n.start();
    const resolve = routes.get('plg-gatecontrol-messenger');
    assert.equal(typeof resolve, 'function');
    assert.deepEqual(resolve({ topic: 'plugin:gatecontrol-messenger:bridge', data: { deepLink: 'bridges', bridge: 'whatsapp' } }), { type: 'bridges', bridge: 'whatsapp' });
    assert.equal(resolve({ topic: 'plugin:gatecontrol-schule:message', data: {} }), null);
    n.stop();
    assert.equal(routes.size, 0, 'removed again on stop');
  });
});
