'use strict';

// Messenger 1.25 in the core: the contacts' WhatsApp status updates (`GET status/feed` → `bridged`, feature
// `bridge_status`) — kept in the cached feed, watched (POST status/bridged/:id/seen), answered or reacted to as a message
// into the WhatsApp chat (POST status/bridged/:id/reply), the switch prefs.privacy.bridgedStatusSeen, the live event
// story.bridged, the IPC and the preload. Names are made up.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
const { messengerServer, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');
const U = require('../src/utils/messenger');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, feedDebounceMs: 5 };
const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function setup(features) {
  const srv = await messengerServer({ features });
  cleanups.push(() => srv.close());
  const m = new MessengerService({ apiClient: new ApiClient(srv.url, 'gc_token', log), pushClient: null, store: createMemoryStore(), log, timing: FAST });
  cleanups.push(() => m.stop());
  const handlers = new Map();
  const win = { isDestroyed: () => false, webContents: { send: () => {} } };
  registerMessengerHandlers((ch, fn) => handlers.set(ch, fn), { messenger: m, getMainWindow: () => win, log, platform: 'linux' });
  const ipc = (ch, arg) => handlers.get(ch)({}, arg);
  m.start();
  await waitFor(() => m.status().state === 'available', 3000, 'available');
  return { srv, m, ipc };
}

const ALEX = (chatId) => ({ network: 'whatsapp', contact: { id: 21, name: 'Alex Beispiel' }, chatId, canReply: true,
  stories: [{ id: 101, kind: 'image', text: 'Abendrunde am See', mediaId: '0123456789abcdef0123456789abcdef', createdAt: new Date().toISOString(), seen: false }] });

describe('Messenger 1.25 – WhatsApp status in the status row', () => {
  it('the feed keeps `bridged`; seen marks it here; a reply and a reaction go into the WhatsApp chat', async () => {
    const { srv, m, ipc } = await setup({ ...FEATURES_14, bridge_status: true });
    const chat = srv.addConv();
    srv.state.bridged.push(ALEX(chat));
    assert.equal(m.status().updateHint, null, 'bridge_status is known');
    const feed = await ipc('chat:status:feed', { refresh: true });
    assert.equal(feed.bridged.length, 1);
    assert.deepEqual([feed.bridged[0].contact.name, feed.bridged[0].unseen, feed.bridged[0].stories[0].kind], ['Alex Beispiel', true, 'image']);
    const feeds = [];
    m.on('feed', (f) => feeds.push(f));
    assert.equal((await ipc('chat:story:bridged:seen', { id: 101 })).ok, true);
    assert.equal(feeds.at(-1).bridged[0].unseen, false, 'the ring turns grey');
    const reply = await ipc('chat:story:bridged:reply', { id: 101, text: 'Schön!' });
    assert.equal(reply.ok, true);
    assert.equal(reply.message.text, 'Schön!');
    const react = await ipc('chat:story:bridged:reply', { id: 101, emoji: '❤️' });
    assert.equal(react.message.text, '❤️ auf deinen Status');
    const bodies = srv.state.requests.filter((x) => /\/status\/bridged\/101\/reply$/.test(x.path)).map((x) => x.body);
    assert.deepEqual(bodies.map((b) => [b.text || null, b.emoji || null, typeof b.clientId]), [['Schön!', null, 'string'], [null, '❤️', 'string']]);
    assert.equal((await ipc('chat:story:bridged:reply', { id: 101, text: 'x', emoji: '❤️' })).code, 'invalid', 'one or the other');
    assert.equal((await ipc('chat:story:bridged:reply', { id: 101 })).code, 'invalid');
  });

  it('the switch goes out with PUT prefs; an older server: no `bridged`, the calls are refused', async () => {
    const { srv, ipc } = await setup({ ...FEATURES_14, bridge_status: true });
    await ipc('chat:prefs', { privacy: { bridgedStatusSeen: true } });
    assert.deepEqual(srv.state.requests.filter((x) => x.path.endsWith('/prefs')).at(-1).body, { privacy: { bridgedStatusSeen: true } });
    const old = await setup(FEATURES_14);
    old.srv.state.bridged.push(ALEX(null));
    assert.deepEqual((await old.ipc('chat:status:feed', { refresh: true })).bridged, []);
    assert.equal((await old.ipc('chat:story:bridged:seen', { id: 101 })).code, 'unsupported');
  });

  it('bridgedFeedOf checks and caps what the server sends', () => {
    const out = U.bridgedFeedOf([
      ALEX(44), { ...ALEX(44) }, { network: 'Whats App', contact: { id: 2 }, stories: [{ id: 1, kind: 'text' }] },
      { network: 'whatsapp', contact: { id: 3 }, stories: [{ id: 'x', kind: 'text' }, { id: 4, kind: 'poll' }] }, null,
    ]);
    assert.equal(out.length, 1, 'the same contact once, a bad network, no usable story, null — dropped');
    assert.equal(out[0].chatId, 44);
    assert.deepEqual(U.prefsBody({ privacy: { bridgedStatusSeen: 'yes' } }), {}, 'only a boolean');
  });
});
