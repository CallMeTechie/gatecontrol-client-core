'use strict';

// Messenger 1.20 (Chats v2, Teil A): WhatsApp channels on a page of their own (GET channels, ?channels=1 — they leave
// GET conversations, its unread and the badge; `channels` { count, unread } for the entry „Kanäle“), groups where only
// admins write (can.sendReason), format and link previews passed through, the push of a channel, the retry of a file
// that failed (POST messages/:id/fetch, `retry: true`). Detected only by the feature word bridge_channels — without it
// everything stays as it was.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerService = require('../src/services/messenger');
const MessengerApi = require('../src/services/messenger-api');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };
const STAGE4C = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_new_chat: true, bridge_history: true, bridge_contacts: true };
const V2A = { ...STAGE4C, bridge_channels: true };

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

async function setup({ features = V2A, push = false, store = createMemoryStore() } = {}) {
  const srv = await messengerServer({ features });
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  let pushClient = null;
  if (push) {
    pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: PUSH_FAST });
    cleanups.push(() => pushClient.stop());
    pushClient.start();
  }
  const m = new MessengerService({ apiClient, pushClient, store, log, timing: FAST });
  cleanups.push(() => m.stop());
  return { srv, m, store };
}
/** A chat with Kim, a channel with two posts (one unread), a group where only admins write. */
function fill(srv) {
  const kim = srv.addBridgeConv({ title: 'Kim Muster' });
  srv.addBridgeMsg(kim, { text: 'Hallo' });
  const chan = srv.addBridgeConv({ title: 'Sicherheit kompakt', channel: true });
  srv.addBridgeMsg(chan, { post: true, text: 'Erster Beitrag' });
  srv.addBridgeMsg(chan, { post: true, text: 'Jetzt patchen: X200\nhttps://sicherheit-kompakt.example/news/x200', marks: [{ type: 'bold', start: 0, end: 14 }], preview: { url: 'https://sicherheit-kompakt.example/news/x200', title: 'Kritische Lücke', description: null, site: 'sicherheit-kompakt.example', image: null } });
  const admins = srv.addBridgeConv({ kind: 'group', title: 'Elternbeirat', readOnly: true });
  srv.addBridgeMsg(admins, { text: 'Treffen am Montag', contact: { contactId: 21, name: 'Frau Berg' } });
  return { kim, chan, admins };
}
const calls = (srv, path) => srv.state.requests.filter((r) => r.path === `${API}${path}`);

describe('channels (Messenger 1.20) – helpers', () => {
  it('knows the feature word (no update hint for it)', () => {
    assert.deepEqual(U.unknownFeatures(V2A), []);
    assert.ok(U.KNOWN_FEATURES.includes('bridge_channels'));
  });

  it('isChannel and the summary of GET conversations', () => {
    assert.equal(U.isChannel({ bridge: { network: 'whatsapp', channel: true } }), true);
    assert.equal(U.isChannel({ bridge: { network: 'whatsapp', channel: false, readOnly: true } }), false);
    assert.equal(U.isChannel({ bridge: null }), false);
    assert.equal(U.isChannel(null), false);
    assert.deepEqual(U.normalizeChannelSummary({ count: 3, unread: 7 }), { count: 3, unread: 7 });
    assert.deepEqual(U.normalizeChannelSummary({ count: -1, unread: 'x' }), { count: 0, unread: 0 });
    assert.equal(U.normalizeChannelSummary(null), null);
    assert.equal(U.normalizeChannelSummary([1]), null);
  });

  it('the push of a channel’s post', () => {
    const base = { kind: 'message', seq: 5, id: 9, title: 'Sicherheit kompakt · Kanal über WhatsApp', body: 'Jetzt patchen', data: { conversation: { id: '14', isGroup: true, title: 'Sicherheit kompakt' }, conversationId: 14, messageId: 40, bridge: 'whatsapp', channel: true, actions: [{ type: 'mark_read', label: 'Gelesen', path: 'conversations/14/read', body: { upTo: 40, bridged: true } }] } };
    const p = U.parseChatNotification(base);
    assert.equal(p.channel, true);
    assert.equal(p.reply, null);
    assert.deepEqual(p.markRead.body, { upTo: 40, bridged: true });
    assert.equal(U.parseChatNotification({ ...base, data: { ...base.data, channel: undefined } }).channel, false);
    // `channel` only with a bridge
    assert.equal(U.parseChatNotification({ ...base, data: { ...base.data, bridge: undefined } }).channel, false);
  });

  it('the API: ?channels=1 next to ?bridged=1 only with both marks; a bridged push button says it in its body too', async () => {
    const seen = [];
    const client = { request: async (o) => { seen.push(o); return { status: 200, data: { ok: true } }; } };
    const api = new MessengerApi({ apiClient: { client, serverUrl: 'https://gc.example', apiKey: 'k' } });
    await api.conversations();
    assert.equal(seen.pop().params, undefined);
    await assert.rejects(api.channelList(), (e) => e.code === 'unsupported');
    api.bridged = true;
    await api.conversations();
    assert.deepEqual(seen.pop().params, { bridged: 1 });
    api.channels = true;
    await api.conversations({ since: '2026-11-15T10:00:00.000Z' });
    assert.deepEqual(seen.pop().params, { since: '2026-11-15T10:00:00.000Z', bridged: 1, channels: 1 });
    await api.channelList();
    const ch = seen.pop();
    assert.match(ch.url, /\/api\/channels$/);
    assert.deepEqual(ch.params, { bridged: 1, channels: 1 });
    await api.messages(5, { limit: 20 });
    assert.deepEqual(seen.pop().params, { limit: 20, bridged: 1, channels: 1 });
    // other routes stay unmarked
    await api.me();
    assert.equal(seen.pop().params, undefined);
    await api.postPath('conversations/14/read', { upTo: 40, bridged: true });
    assert.deepEqual(seen.pop().data, { upTo: 40, bridged: true, channels: true });
    await api.postPath('conversations/3/read', { upTo: 2 });
    assert.deepEqual(seen.pop().data, { upTo: 2 });
  });
});

describe('channels (Messenger 1.20) – the service', () => {
  it('channels leave the chat list and its unread; GET channels holds them, the summary counts them', async () => {
    const { srv, m } = await setup();
    const { kim, chan, admins } = fill(srv);
    await m.check();
    await waitFor(() => m.listChannels().length === 1, 4000, 'channels');
    assert.deepEqual(m.listConversations().map((c) => c.id).sort(), [kim, admins].sort());
    const ch = m.listChannels()[0];
    assert.equal(ch.id, chan);
    assert.equal(ch.bridge.channel, true);
    assert.equal(ch.muted, true);
    assert.equal(ch.can.sendReason, 'channel');
    assert.deepEqual(m.channelSummary(), { count: 1, unread: 2 });
    assert.deepEqual(m.status().channels, { count: 1, unread: 2 });
    // the badge: Kim (1) and the group (1) — never the channel
    assert.equal(m.unreadTotal(), 2);
    const conv = calls(srv, 'conversations')[0];
    assert.equal(conv.query.bridged, '1');
    assert.equal(conv.query.channels, '1');
    assert.equal(calls(srv, 'channels').length, 1);
    // the group where only admins write stays a chat
    const g = m.listConversations().find((c) => c.id === admins);
    assert.equal(g.can.send, false);
    assert.equal(g.can.sendReason, 'admins_only');
    assert.equal(g.can.react, true);
    // format and preview pass through as they are
    const msgs = await m.getMessages(chan);
    const post = msgs.messages[msgs.messages.length - 1];
    assert.deepEqual(post.marks, [{ type: 'bold', start: 0, end: 14 }]);
    assert.equal(post.preview.title, 'Kritische Lücke');
    assert.equal(post.bridge.channel, true);
    // read: the summary follows
    await m.markRead(chan);
    assert.deepEqual(m.channelSummary(), { count: 1, unread: 0 });
  });

  it('a full read of the list keeps the channels; the summary asks GET channels again only when it differs', async () => {
    const { srv, m } = await setup();
    const { chan } = fill(srv);
    await m.check();
    await waitFor(() => m.listChannels().length === 1);
    await m.refreshConversations({ full: true });
    assert.equal(m.listChannels().length, 1);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(calls(srv, 'channels').length, 1, 'same summary: not read again');
    srv.addBridgeMsg(chan, { post: true, text: 'Noch einer' });
    await m.refreshConversations({ full: true });
    await waitFor(() => m.channelSummary().unread === 3, 4000, 'new post');
    assert.equal(calls(srv, 'channels').length, 2);
    // no channel any more: they go
    srv.state.convs.delete(chan);
    await m.refreshConversations({ full: true });
    assert.deepEqual(m.listChannels(), []);
    assert.deepEqual(m.channelSummary(), { count: 0, unread: 0 });
  });

  it('a post of a channel not known yet (live event): fetched and filed under the channels', async () => {
    const { srv, m } = await setup({ push: true });
    srv.addBridgeMsg(srv.addBridgeConv({ title: 'Kim Muster' }), { text: 'Hallo' });
    m.start();
    await waitFor(() => m.listConversations().length === 1, 4000, 'list');
    await waitFor(() => srv.streams.size > 0, 4000, 'push stream');
    assert.deepEqual(m.listChannels(), []);
    const chan = srv.addBridgeConv({ title: 'Neuer Kanal', channel: true });
    const post = srv.addBridgeMsg(chan, { post: true, text: 'Hallo Welt' });
    srv.event('message.new', { conversationId: chan, messageId: post.id, senderId: null, clientId: null, kind: 'text', createdAt: new Date().toISOString(), bridge: 'whatsapp' });
    await waitFor(() => m.listChannels().length === 1, 4000, 'channel filed');
    assert.equal(m.listConversations().some((c) => c.id === chan), false);
    assert.deepEqual(m.channelSummary(), { count: 1, unread: 1 });
    assert.equal(m.unreadTotal(), 1);
  });

  it('the bell: PATCH notify; sending into a channel is refused with its reason', async () => {
    const { srv, m } = await setup();
    const { chan, admins } = fill(srv);
    await m.check();
    await waitFor(() => m.listChannels().length === 1);
    const r = await m.updateConversation(chan, { notify: 'all' });
    assert.equal(r.conversation.muted, false);
    const patch = srv.state.requests.find((x) => x.method === 'PATCH' && x.path === `${API}conversations/${chan}`);
    assert.deepEqual(patch.body, { notify: 'all' });
    assert.equal(patch.query.channels, '1');
    assert.equal(m.listChannels()[0].muted, false);
    await assert.rejects(m.api.send(admins, { kind: 'text', text: 'Hallo', clientId: 'abcdefgh1234' }), (e) => e.code === 'bridge_read_only' && e.body.reason === 'admins_only');
  });

  it('without the word: channels stay in the list (read only), no ?channels=1, no GET channels', async () => {
    const { srv, m } = await setup({ features: STAGE4C });
    const { chan } = fill(srv);
    await m.check();
    assert.ok(m.listConversations().some((c) => c.id === chan));
    assert.deepEqual(m.listChannels(), []);
    assert.equal(m.channelSummary(), null);
    assert.equal(m.status().channels, null);
    assert.equal(calls(srv, 'conversations')[0].query.channels, undefined);
    assert.equal(calls(srv, 'channels').length, 0);
    assert.deepEqual(await m.refreshChannels(), []);
  });

  it('the cache keeps the channels and their summary for the next start', async () => {
    const store = createMemoryStore();
    const a = await setup({ store });
    fill(a.srv);
    await a.m.check();
    await waitFor(() => a.m.listChannels().length === 1);
    a.m.stop();
    const m2 = new MessengerService({ apiClient: new ApiClient(a.srv.url, 'gc_token', log), store, log, timing: FAST });
    cleanups.push(() => m2.stop());
    assert.equal(m2.listChannels().length, 1);
    assert.equal(m2.listConversations().some((c) => c.bridge && c.bridge.channel), false);
    assert.deepEqual(m2.channelSummary(), { count: 1, unread: 2 });
  });
});

describe('retry of a bridged file that failed (Messenger 1.19)', () => {
  it('POST messages/:id/fetch for a placeholder failed with retry — also without bridge_history', async () => {
    const { srv, m } = await setup({ features: { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true } });
    const kim = srv.addBridgeConv({ title: 'Kim Muster' });
    const msg = srv.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'IMG.jpg', state: 'failed', reason: 'unavailable', retry: true } });
    await m.check();
    await m.getMessages(kim);
    const out = await m.fetchBridgeFile(msg.id);
    assert.equal(out.bridge.placeholder.state, 'loading');
    const req = calls(srv, `messages/${msg.id}/fetch`)[0];
    assert.equal(req.method, 'POST');
    assert.equal(req.query.bridged, '1');
    const view = m.messagesView(kim);
    assert.equal(view.messages.find((x) => x.id === msg.id).bridge.placeholder.state, 'loading');
  });
});
