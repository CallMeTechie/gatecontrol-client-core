'use strict';

// MessengerService (services/messenger.js) with the real ApiClient and
// PushClient against the in-memory messenger server: availability, the chat
// list, messages, live plugin events on the push stream, catching up after a
// reconnect, sending through the outbox, read marks, "active", typing,
// cache for offline reading, server change.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerService = require('../src/services/messenger');
const { messengerServer, API } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };

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

async function setup({ push = true, store = createMemoryStore(), srvOpts = {}, visible = () => true } = {}) {
  const srv = await messengerServer(srvOpts);
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  let pushClient = null;
  if (push) {
    pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: PUSH_FAST });
    cleanups.push(() => pushClient.stop());
  }
  const m = new MessengerService({ apiClient, pushClient, store, log, timing: FAST, isWindowVisible: visible });
  cleanups.push(() => m.stop());
  const events = [];
  for (const ev of ['state', 'conversations', 'messages', 'typing', 'unread', 'read-local', 'read-self', 'send-failed']) m.on(ev, (p) => events.push({ ev, p }));
  return { srv, apiClient, pushClient, m, store, events };
}

describe('MessengerService – availability', () => {
  it('available with the plugin: loads me and the chat list', async () => {
    const { srv, m } = await setup({ push: false });
    const id = srv.addConv();
    srv.addMsg(id, { text: 'Hi' });
    m.start();
    await waitFor(() => m.status().state === 'available' && m.listConversations().length === 1);
    const st = m.status();
    assert.equal(st.me.user.id, 7);
    assert.equal(st.me.limits.typingEveryS, 3);
    assert.equal(st.unread, 1);
    assert.equal(m.listConversations()[0].lastMessage.text, 'Hi');
  });

  it('unavailable on servers without the plugin, without the app tab, or not configured', async () => {
    const { m } = await setup({ push: false, srvOpts: { plugin: false } });
    m.start();
    await waitFor(() => m.status().state === 'unavailable');
    assert.equal(m.status().reason, 'not_installed');

    const b = await setup({ push: false, srvOpts: { tab: false } });
    b.m.start();
    await waitFor(() => b.m.status().state === 'unavailable');
    assert.equal(b.m.status().reason, 'hidden');

    const none = new MessengerService({ apiClient: { client: null, serverUrl: '', apiKey: '' }, store: createMemoryStore(), log, timing: FAST });
    cleanups.push(() => none.stop());
    none.start();
    await waitFor(() => none.status().state === 'unavailable');
    assert.equal(none.status().reason, 'not_configured');
  });

  it('a network error is retried; cached chats stay usable (stale)', async () => {
    const store = createMemoryStore();
    const a = await setup({ push: false, store });
    const id = a.srv.addConv();
    a.srv.addMsg(id, { text: 'cached' });
    a.m.start();
    await waitFor(() => a.m.listConversations().length === 1);
    await a.m.getMessages(id);
    a.m.stop();

    // Same server + token, server down now.
    a.srv.fail('/api/v1/client/plugins', 0, 'drop');
    const b = new MessengerService({ apiClient: a.apiClient, store, log, timing: FAST });
    cleanups.push(() => b.stop());
    assert.equal(b.status().state, 'available');
    assert.equal(b.status().stale, true);
    b.start();
    await waitFor(() => b.status().reason === 'network');
    assert.equal(b.status().state, 'available');
    const view = await b.getMessages(id);
    assert.equal(view.offline, true);
    assert.equal(view.messages[0].text, 'cached');
    a.srv.heal();
    await waitFor(() => b.status().stale === false, 3000, 'fresh after the retry');
  });
});

describe('MessengerService – messages and live events', () => {
  it('loads messages, merges sent ones, marks read and reports "active"', async () => {
    const { srv, m, events } = await setup({ push: false });
    const id = srv.addConv();
    for (let i = 0; i < 3; i++) srv.addMsg(id, { text: `m${i}` });
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    const view = await m.getMessages(id);
    assert.deepEqual(view.messages.map((x) => x.text), ['m0', 'm1', 'm2']);
    m.setOpen({ id, visible: true });
    await waitFor(() => srv.state.reads.length === 1 && srv.state.actives.length >= 2, 3000, 'read + active pings');
    assert.equal(srv.state.reads[0].upTo, view.messages[2].id);
    await waitFor(() => m.unreadTotal() === 0);
    assert.ok(events.some((e) => e.ev === 'read-local' && e.p.conversationId === id));

    const pending = await m.send({ conversationId: id, text: 'Antwort' });
    assert.equal(pending.pending, true);
    assert.equal(m.messagesView(id).pending.length + m.messagesView(id).messages.filter((x) => x.clientId === pending.clientId).length, 1);
    await waitFor(() => m.messagesView(id).messages.some((x) => x.text === 'Antwort'));
    assert.equal(m.messagesView(id).pending.length, 0);
    assert.equal(m.listConversations()[0].lastMessage.text, 'Antwort');
    m.setOpen({ id: null });
    await waitFor(() => srv.state.actives.some((x) => x.body && x.body.active === false));
  });

  it('live events on the push stream update the cache', async () => {
    const { srv, m, events, pushClient } = await setup();
    const id = srv.addConv();
    srv.addMsg(id, { text: 'erste' });
    pushClient.start();
    m.start();
    await waitFor(() => m.listConversations().length === 1 && pushClient.status().state === 'connected');
    await m.getMessages(id);

    // message.new → messages?after=
    const m2 = srv.addMsg(id, { text: 'neu' });
    srv.event('message.new', { conversationId: id, messageId: m2.id, senderId: 8, clientId: null, kind: 'text', createdAt: m2.createdAt });
    await waitFor(() => m.messagesView(id).messages.some((x) => x.text === 'neu'));
    await waitFor(() => m.unreadTotal() === 2, 3000, 'unread from the refreshed conversation');

    // typing
    srv.event('typing', { conversationId: id, userId: 8, until: new Date(Date.now() + 6000).toISOString() });
    await waitFor(() => events.some((e) => e.ev === 'typing' && e.p.userIds.includes(8)));
    assert.deepEqual(m.listConversations()[0].typing, [8]);
    srv.event('typing', { conversationId: id, userId: 8, until: null });
    await waitFor(() => m.listConversations()[0].typing.length === 0);

    // reaction
    srv.event('reaction', { conversationId: id, messageId: m2.id, userId: 8, emoji: '👍', reactions: [{ emoji: '👍', count: 1, userIds: [8] }] });
    await waitFor(() => m.messagesView(id).messages.find((x) => x.id === m2.id).reactions.length === 1);

    // edit → changedSince
    const msg = srv.state.msgs.get(id).find((x) => x.id === m2.id);
    msg.text = 'neu (bearbeitet)';
    msg.editedAt = Date.now();
    msg.changedAt = Date.now();
    srv.event('message.update', { conversationId: id, messageId: m2.id, editedAt: new Date(msg.editedAt).toISOString() });
    await waitFor(() => m.messagesView(id).messages.find((x) => x.id === m2.id).text === 'neu (bearbeitet)');

    // delete for everyone → tombstone; hidden → removed
    srv.event('message.delete', { conversationId: id, messageIds: [m2.id], reason: 'deleted' });
    await waitFor(() => m.messagesView(id).messages.find((x) => x.id === m2.id).deleted === true);
    const first = m.messagesView(id).messages[0].id;
    srv.event('message.delete', { conversationId: id, messageIds: [first], reason: 'hidden' });
    await waitFor(() => !m.messagesView(id).messages.some((x) => x.id === first));

    // read on another own device
    srv.state.convs.get(id).members.find((x) => x.id === 7).lastRead = m2.id;
    srv.event('read', { conversationId: id, userId: 7, lastReadId: m2.id, lastDeliveredId: m2.id, self: true, unread: 0 });
    await waitFor(() => events.some((e) => e.ev === 'read-self' && e.p.conversationId === id));
    await waitFor(() => m.unreadTotal() === 0, 3000, 'unread 0 after reading elsewhere');

    // removed from the chat
    srv.state.convs.delete(id);
    srv.event('conversation.remove', { conversationId: id });
    await waitFor(() => m.listConversations().length === 0);
  });

  it('catches up after a reconnect (no replay of plugin events)', async () => {
    const { srv, m, pushClient } = await setup();
    const id = srv.addConv();
    srv.addMsg(id, { text: 'a' });
    pushClient.start();
    m.start();
    await waitFor(() => m.listConversations().length === 1 && pushClient.status().state === 'connected');
    await m.getMessages(id);
    srv.dropStreams();
    srv.addMsg(id, { text: 'verpasst' });
    await waitFor(() => m.messagesView(id).messages.some((x) => x.text === 'verpasst'), 4000, 'missed message after reconnect');
    const since = srv.state.requests.filter((r) => r.path === `${API}conversations` && r.query.since);
    assert.ok(since.length >= 1, 'asked conversations?since=');
  });

  it('polls without the push stream', async () => {
    const { srv, m } = await setup({ push: false });
    srv.addConv();
    m.start();
    m.setViewOpen(true);
    await waitFor(() => m.listConversations().length === 1);
    srv.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    await waitFor(() => m.listConversations().length === 2, 3000, 'second chat by polling');
  });

  it('edit, delete, react, older pages, search, people, groups, prefs', async () => {
    const { srv, m } = await setup({ push: false });
    const id = srv.addConv();
    for (let i = 0; i < 60; i++) srv.addMsg(id, { text: `n${i}`, senderId: i % 2 ? 7 : 8 });
    m.start();
    await waitFor(() => m.available() && m.listConversations().length === 1);
    let view = await m.getMessages(id);
    assert.equal(view.messages.length, 50);
    assert.equal(view.hasMore, true);
    view = await m.getMessages(id, { before: view.messages[0].id });
    assert.equal(view.messages.length, 60);
    assert.equal(view.hasMore, false);
    const mine = view.messages.find((x) => x.mine);
    assert.equal((await m.edit(mine.id, 'geändert')).text, 'geändert');
    assert.equal(m.messagesView(id).messages.find((x) => x.id === mine.id).text, 'geändert');
    assert.equal((await m.react(mine.id, '❤️'))[0].emoji, '❤️');
    const del = await m.remove(mine.id, 'all');
    assert.equal(del.forAll, true);
    assert.equal(m.messagesView(id).messages.find((x) => x.id === mine.id).deleted, true);
    const other = view.messages.find((x) => !x.mine);
    await m.remove(other.id, 'me');
    assert.ok(!m.messagesView(id).messages.some((x) => x.id === other.id));
    assert.equal((await m.search(id, 'n5')).results.length > 0, true);
    await assert.rejects(m.search(id, 'n'), (e) => e.code === 'invalid');
    assert.deepEqual((await m.people()).map((p) => p.name), ['Anna', 'Lena']);
    const g = await m.createConversation({ kind: 'group', userIds: [8, 9], title: 'Familie' });
    assert.equal(g.created, true);
    assert.equal(g.conversation.title, 'Familie');
    const renamed = await m.updateConversation(g.conversation.id, { title: 'Family' });
    assert.equal(renamed.conversation.title, 'Family');
    const left = await m.updateConversation(g.conversation.id, { remove: [7] });
    assert.equal(left.left, true);
    assert.ok(!m.listConversations().some((c) => c.id === g.conversation.id));
    const d = await m.createConversation({ kind: 'direct', userIds: [8] });
    assert.equal(d.created, false);
    assert.equal((await m.setPrefs({ typing: false })).typing, false);
    assert.equal(await m.typing(id), false, 'typing switched off: nothing sent');
  });

  it('typing is throttled to one call per 3 s, stop only after typing', async () => {
    let now = 1_000_000;
    const { srv, m } = await setup({ push: false });
    m.now = () => now;
    const id = srv.addConv();
    m.start();
    await waitFor(() => m.available());
    assert.equal(await m.typing(id, { stop: true }), false);
    assert.equal(await m.typing(id), true);
    assert.equal(await m.typing(id), false);
    now += 3100;
    assert.equal(await m.typing(id), true);
    assert.equal(await m.typing(id, { stop: true }), true);
    assert.deepEqual(srv.state.typings.map((x) => x.body), [{}, {}, { stop: true }]);
  });

  it('files: size and type limits from GET me, the file name of documents', async () => {
    const { srv, m } = await setup({ push: false });
    const id = srv.addConv();
    m.start();
    await waitFor(() => m.available());
    await assert.rejects(m.send({ conversationId: id, kind: 'file', file: { data: Buffer.alloc(2 * 1024 * 1024), mime: 'application/pdf', name: 'big.pdf' } }), (e) => e.code === 'too_large');
    await assert.rejects(m.send({ conversationId: id, kind: 'file', file: { data: Buffer.from('MZ'), mime: 'application/x-msdownload', name: 'a.exe' } }), (e) => e.code === 'unsupported_type');
    const p = await m.send({ conversationId: id, kind: 'file', file: { data: Buffer.from('%PDF'), mime: 'application/pdf', name: 'Brief.pdf' } });
    assert.equal(p.meta.fileName, 'Brief.pdf');
    await waitFor(() => srv.state.msgs.get(id).length === 1);
    const stored = srv.state.msgs.get(id)[0];
    const media = await m.media(stored.mediaId);
    assert.deepEqual(media.data, Buffer.from('%PDF'));
  });

  it('server change: cache, outbox and availability are reset', async () => {
    const { srv, m, apiClient, store } = await setup({ push: false });
    srv.addConv();
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    m._persistNow();
    assert.ok(store.get(MessengerService.CACHE_KEY));
    apiClient.configure(srv.url, 'other-token');
    await m.resetForNewServer();
    assert.equal(m.listConversations().length, 0);
    assert.equal(store.get(MessengerService.CACHE_KEY), undefined);
    await waitFor(() => m.listConversations().length === 1, 3000, 'reloaded from the new setup');
  });
});
