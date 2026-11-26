'use strict';

// Messenger 1.21 (Chats v2, Teil B): persons — the chat with a GateControl account and the WhatsApp chat of the same
// human as ONE entry (?people=1: `person`, `folded`), the shared history by time through persons/:id/messages (`way` on
// each message, the source filter), sending without a choice of way (POST persons/:id/messages), read marks, live
// events of a way, suggestions, merging, „Trennen“, the name, the push „Name · über WhatsApp“, the question after
// linking WhatsApp. Detected only by the feature word chat_people — without it everything stays as it was.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
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
const V2A = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_new_chat: true, bridge_history: true, bridge_contacts: true, bridge_channels: true };
const V2B = { ...V2A, chat_people: true };

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

async function setup({ features = V2B, push = false, store = createMemoryStore() } = {}) {
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

const T0 = Date.parse('2026-11-15T10:00:00.000Z');
/** Anna (account 8) in GateControl and as „Schatzimausi 💕“ on WhatsApp — their messages mixed in time; Kim apart. */
function fill(srv, { person = true } = {}) {
  const gc = srv.addConv({ kind: 'direct', members: [7, 8] });
  const wa = srv.addBridgeConv({ title: 'Schatzimausi 💕' });
  const kim = srv.addBridgeConv({ title: 'Kim Muster' });
  const at = (msg, min) => { msg.createdAt = T0 + min * 60000; return msg; };
  const g1 = at(srv.addMsg(gc, { senderId: 8, text: 'GC eins' }), 1);
  const w1 = at(srv.addBridgeMsg(wa, { text: 'WA eins', contact: { contactId: 31, name: 'Schatzimausi 💕' } }), 2);
  const g2 = at(srv.addMsg(gc, { senderId: 7, text: 'GC zwei' }), 3);
  const w2 = at(srv.addBridgeMsg(wa, { text: 'WA zwei', contact: { contactId: 31, name: 'Schatzimausi 💕' } }), 4);
  at(srv.addBridgeMsg(kim, { text: 'Hallo' }), 5);
  const pid = person ? srv.addPerson({ convIds: [gc, wa], userId: 8 }) : null;
  return { gc, wa, kim, pid, g1, w1, g2, w2 };
}
const calls = (srv, path) => srv.state.requests.filter((r) => r.path === `${API}${path}`);

describe('persons (Messenger 1.21) – helpers', () => {
  it('knows the feature word (no update hint for it)', () => {
    assert.deepEqual(U.unknownFeatures(V2B), []);
    assert.ok(U.KNOWN_FEATURES.includes('chat_people'));
  });

  it('a person, its ways, the way of an answer, a message’s way', () => {
    const e = { id: 12, person: { id: 1, conversationId: 12, ways: [{ way: 'gatecontrol', conversationId: 12 }, { way: 'whatsapp', conversationId: 13, bridge: { network: 'whatsapp' } }], reply: { way: 'whatsapp', conversationId: 13 } } };
    assert.equal(U.isPerson(e), true);
    assert.equal(U.isPerson({ id: 12, person: null }), false);
    assert.equal(U.isPerson({ id: 12, person: { id: 1, ways: [] } }), false);
    assert.deepEqual(U.personWayIds(e), [12, 13]);
    assert.deepEqual(U.personWayIds({ id: 5 }), [5]);
    assert.equal(U.personReplyWay(e).conversationId, 13);
    assert.equal(U.wayOf({ way: 'whatsapp' }), 'whatsapp');
    assert.equal(U.wayOf({ way: '<b>' }), null);
  });

  it('the shared history by time, a tie by id', () => {
    const list = U.mergeMessages([{ id: 9, createdAt: '2026-11-15T10:03:00.000Z' }], [{ id: 20, createdAt: '2026-11-15T10:01:00.000Z' }, { id: 4, createdAt: '2026-11-15T10:03:00.000Z' }], { byTime: true });
    assert.deepEqual(list.map((x) => x.id), [20, 4, 9]);
    assert.deepEqual(U.mergeMessages([{ id: 9 }], [{ id: 4 }]).map((x) => x.id), [4, 9]);
  });

  it('the body of a merge, a suggestion id, the consent', () => {
    assert.deepEqual(U.mergeBody({ conversationIds: [17, 17, 'x'], userId: 3, name: 'account' }), { conversationIds: [17], userId: 3, name: 'account' });
    assert.deepEqual(U.mergeBody({ conversationIds: [17, 41], name: 41 }), { conversationIds: [17, 41], name: 41 });
    assert.equal(U.mergeBody({ conversationIds: [] }), null);
    assert.equal(U.mergeBody({ conversationIds: [1], userId: 'x' }), null);
    assert.equal(U.isSuggestionId('17-3'), true);
    assert.equal(U.isSuggestionId('../x'), false);
    assert.deepEqual(U.normalizeRecognition({ available: true, network: 'whatsapp', asked: false, allowed: false }), { available: true, network: 'whatsapp', asked: false, allowed: false });
    assert.equal(U.normalizeRecognition(null), null);
    const b = U.normalizeBridges({ available: true, networks: [], recognition: { available: true, asked: true, allowed: true } });
    assert.equal(b.recognition.allowed, true);
    assert.equal('recognition' in U.normalizeBridges({ available: true, networks: [] }), false);
  });

  it('the push of a way of a person: data.person', () => {
    const p = U.parseChatNotification({ kind: 'message', seq: 3, id: 9, title: 'Anna · über WhatsApp', body: 'Hi', data: { conversationId: 13, messageId: 40, bridge: 'whatsapp', person: { id: 1, conversationId: 12 } } });
    assert.deepEqual(p.person, { id: 1, conversationId: 12 });
    assert.equal(p.conversationId, 13);
    assert.equal(U.parseChatNotification({ kind: 'message', seq: 3, id: 9, data: { conversationId: 13, person: { id: 'x' } } }).person, null);
  });
});

describe('persons (Messenger 1.21) – MessengerService', () => {
  it('without the word: the ways stay separate chats, no ?people=1, no persons/…', async () => {
    const { srv, m } = await setup({ features: V2A });
    const { gc, wa } = fill(srv);
    await m.check();
    const ids = m.listConversations().map((c) => c.id);
    assert.ok(ids.includes(gc) && ids.includes(wa));
    assert.equal(calls(srv, 'conversations')[0].query.people, undefined);
    assert.deepEqual(await m.suggestions(), []);
    await assert.rejects(m.mergePersons({ conversationIds: [wa], userId: 8 }), (e) => e.code === 'unsupported');
  });

  it('one entry per person: the lead’s id, the ways folded out, the unread of all ways, found by every name', async () => {
    const { srv, m } = await setup();
    const { gc, wa, kim } = fill(srv);
    await m.check();
    const list = m.listConversations();
    assert.deepEqual(list.map((c) => c.id).sort(), [gc, kim].sort());
    const e = list.find((c) => c.id === gc);
    assert.equal(U.isPerson(e), true);
    assert.equal(e.title, 'Anna');
    assert.deepEqual(e.person.names, ['Anna', 'Schatzimausi 💕']);
    assert.equal(e.unread, 2);
    assert.equal(e.person.reply.way, 'whatsapp');
    assert.equal(m.unreadTotal(), 3);
    const q = calls(srv, 'conversations')[0].query;
    assert.equal(q.people, '1');
    assert.equal(q.bridged, '1');
    // a way asked for by its own id is shown as the person
    assert.equal(m.entryIdOf(wa), gc);
    const c = await m.getConversation(wa);
    assert.equal(c.id, gc);
    assert.ok(calls(srv, `persons/${e.person.id}`).length >= 1);
  });

  it('the shared history by time with each message’s way; the source chips (way=) and back to all', async () => {
    const { srv, m } = await setup();
    const { gc, pid, g1, w1, g2, w2 } = fill(srv);
    await m.check();
    const v = await m.getMessages(gc);
    assert.deepEqual(v.messages.map((x) => x.id), [g1.id, w1.id, g2.id, w2.id]);
    assert.deepEqual(v.messages.map((x) => x.way), ['gatecontrol', 'whatsapp', 'gatecontrol', 'whatsapp']);
    assert.equal(v.way, null);
    assert.equal(calls(srv, `persons/${pid}/messages`).length, 1);
    assert.equal(calls(srv, `conversations/${gc}/messages`).length, 0);
    const f = await m.setWay(gc, 'whatsapp');
    assert.deepEqual(f.messages.map((x) => x.id), [w1.id, w2.id]);
    assert.equal(f.way, 'whatsapp');
    assert.equal(calls(srv, `persons/${pid}/messages`).pop().query.way, 'whatsapp');
    await assert.rejects(m.setWay(gc, 'signal'), (e) => e.code === 'invalid');
    const all = await m.setWay(gc, null);
    assert.equal(all.messages.length, 4);
    assert.equal(calls(srv, `persons/${pid}/messages`).pop().query.way, undefined);
    // the GateControl way's marks are the ticks of the messages inside GateControl
    assert.equal(m.getCachedConversation(gc).readUpTo, 0);
  });

  it('older and newer pages use message ids of any way as cursors (by time)', async () => {
    const { srv, m } = await setup();
    const { gc, wa, pid, g1, w1 } = fill(srv);
    await m.check();
    await m.getMessages(gc);
    const before = await m.getMessages(gc, { before: w1.id });
    assert.equal(calls(srv, `persons/${pid}/messages`).pop().query.before, String(w1.id));
    assert.equal(before.messages[0].id, g1.id);
    const w3 = srv.addBridgeMsg(wa, { text: 'WA drei' });
    w3.createdAt = T0 + 10 * 60000;
    const newer = await m.getMessages(gc);
    assert.equal(newer.messages[newer.messages.length - 1].id, w3.id);
  });

  it('sending goes through persons/:id/messages — the server picks the way; the composer checks that way', async () => {
    const { srv, m } = await setup();
    const { gc, wa, pid } = fill(srv);
    m.start();
    await m.check();
    await m.getMessages(gc);
    assert.equal(m.replyWay(gc).way, 'whatsapp');
    assert.equal(m.replyWay(wa), null);
    // the answer goes over WhatsApp (1.27: a location WhatsApp cannot send goes to the GateControl way —
    // messenger-versandweg.test.js)
    await m.send({ conversationId: gc, kind: 'text', text: 'Hallo Schatz' });
    await waitFor(() => calls(srv, `persons/${pid}/messages`).some((r) => r.method === 'POST'), 4000, 'person send');
    const sent = srv.state.msgs.get(wa).find((x) => x.text === 'Hallo Schatz');
    assert.ok(sent, 'went over WhatsApp');
    const view = await waitFor(() => { const x = m.messagesView(gc); return x.messages.some((y) => y.id === sent.id) && !x.pending.length && x; }, 4000, 'sent in view');
    assert.equal(view.messages.find((y) => y.id === sent.id).way, 'whatsapp');
  });

  it('read: POST persons/:id/read up to the newest message shown (by time) — never under a source filter', async () => {
    const { srv, m } = await setup();
    const { gc, pid, w2 } = fill(srv);
    await m.check();
    await m.getMessages(gc);
    const r = await m.markRead(gc);
    assert.equal(r.unread, 0);
    assert.deepEqual(srv.state.personReads.pop(), { personId: pid, upTo: w2.id });
    assert.equal(m.getCachedConversation(gc).unread, 0);
    await m.setWay(gc, 'gatecontrol');
    srv.state.personReads.length = 0;
    m.getCachedConversation(gc);
    m._convs.get(gc).unread = 2;
    assert.equal(await m.markRead(gc), null);
    assert.equal(srv.state.personReads.length, 0);
  });

  it('active on every way while the person is open; „schreibt …“ to the way of the answer; a way counts as open', async () => {
    const { srv, m } = await setup();
    const { gc, wa } = fill(srv);
    await m.check();
    m.setOpen({ id: gc, visible: true });
    await waitFor(() => srv.state.actives.some((x) => x.conversationId === wa) && srv.state.actives.some((x) => x.conversationId === gc), 2000, 'actives');
    assert.equal(m.isOpenAndVisible(wa), true);
    await m.typing(gc);
    assert.equal(srv.state.typings.pop().conversationId, wa);
    m.setOpen({ id: null });
    await waitFor(() => srv.state.actives.some((x) => x.conversationId === wa && x.body && x.body.active === false), 2000, 'inactive');
  });

  it('live: a message of a way loads the person’s newer messages; typing of a way shows on the entry', async () => {
    const { srv, m } = await setup({ push: true });
    const { gc, wa, pid } = fill(srv);
    m.start();
    await m.check();
    await m.getMessages(gc);
    await waitFor(() => srv.streams.size > 0, 2000, 'stream');
    const w3 = srv.addBridgeMsg(wa, { text: 'Neu über WhatsApp' });
    srv.event('message.new', { conversationId: wa, messageId: w3.id, senderId: null, bridge: 'whatsapp', createdAt: new Date().toISOString() });
    await waitFor(() => m.messagesView(gc).messages.some((x) => x.id === w3.id), 3000, 'new message');
    assert.ok(calls(srv, `persons/${pid}/messages`).some((r) => r.query.after));
    srv.event('typing', { conversationId: wa, userId: null, contacts: [{ contactId: 31, name: 'Schatzimausi 💕' }], until: new Date(Date.now() + 4000).toISOString() });
    await waitFor(() => (m.getCachedConversation(gc).typingContacts || []).length === 1, 2000, 'typing');
  });

  it('conversation.update { reason: person } reads the list again; a person split shows its ways apart', async () => {
    const { srv, m } = await setup({ push: true });
    const { gc, wa, pid } = fill(srv);
    m.start();
    await m.check();
    await waitFor(() => srv.streams.size > 0, 2000, 'stream');
    srv.state.persons.delete(pid);
    srv.event('conversation.update', { conversationId: gc, reason: 'person', personId: null });
    await waitFor(() => m.listConversations().some((c) => c.id === wa), 3000, 'split shown');
    assert.equal(U.isPerson(m.getCachedConversation(gc)), false);
  });

  it('„Trennen“: DELETE persons/:id/ways/:conversationId, the list again; mute and archive for every way; the name', async () => {
    const { srv, m } = await setup();
    const { gc, wa, pid } = fill(srv);
    await m.check();
    const r1 = await m.updateConversation(gc, { notify: 'none' });
    assert.equal(r1.conversation.id, gc);
    assert.equal(calls(srv, `persons/${pid}`).find((x) => x.method === 'PATCH').body.notify, 'none');
    assert.equal(srv.state.convs.get(wa).notify, 'none');
    const a = await m.archive(gc, true);
    assert.equal(a.archived, true);
    assert.equal(calls(srv, `persons/${pid}/archive`).length, 1);
    const n = await m.renamePerson(gc, wa);
    assert.equal(n.title, 'Schatzimausi 💕');
    const s = await m.splitPerson(gc, wa);
    assert.equal(s.person, null);
    assert.deepEqual(s.conversationIds.sort(), [gc, wa].sort());
    assert.ok(m.listConversations().some((c) => c.id === wa));
    assert.equal(U.isPerson(m.getCachedConversation(gc)), false);
  });

  it('suggestions: asked at most every 15 minutes; „Nicht jetzt“; „Zusammenführen“ with the name chosen', async () => {
    const { srv, m } = await setup();
    const { wa, kim } = fill(srv, { person: false });
    srv.state.suggestions = [
      { id: `${kim}-9`, conversationId: kim, userId: 9, network: 'whatsapp', label: 'WhatsApp', strength: 'medium', via: 'profile_phone', contact: { name: 'Kim Muster', avatarUrl: null, avatarMediaId: null }, account: { name: 'Lena', avatarUrl: null, initials: 'LE', colorHex: '#F2B91B' }, text: '„Kim Muster“ bei WhatsApp ist vielleicht Lena.', reason: 'x' },
      { id: `${wa}-8`, conversationId: wa, userId: 8, network: 'whatsapp', label: 'WhatsApp', strength: 'strong', via: 'own_whatsapp', contact: { name: 'Schatzimausi 💕', avatarUrl: null, avatarMediaId: null }, account: { name: 'Anna', avatarUrl: null, initials: 'AN', colorHex: '#F97316' }, text: '„Schatzimausi 💕“ bei WhatsApp ist vielleicht Anna.', reason: 'y' },
      { id: '../x', conversationId: 1, userId: 2, contact: {}, account: {} },
    ];
    await m.check();
    let seen = null;
    m.on('suggestions', (l) => { seen = l; });
    const list = await m.suggestions();
    assert.equal(list.length, 2);
    await m.suggestions();
    assert.equal(calls(srv, 'persons/suggestions').length, 1);
    await m.answerSuggestion(`${kim}-9`, 'later');
    assert.deepEqual(srv.state.answers, [{ id: `${kim}-9`, action: 'later' }]);
    assert.equal(seen.length, 1);
    await assert.rejects(m.answerSuggestion(`${kim}-9`, 'maybe'), (e) => e.code === 'invalid');
    const e = await m.mergePersons({ conversationIds: [wa], userId: 8, name: 'account' });
    assert.equal(U.isPerson(e), true);
    assert.equal(e.title, 'Anna');
    assert.deepEqual(calls(srv, 'persons').find((x) => x.method === 'POST').body, { conversationIds: [wa], userId: 8, name: 'account' });
    assert.equal(m.listConversations().some((c) => c.id === wa), false);
    assert.equal(seen.length, 0);
  });

  it('„Mit Person zusammenführen …“: the candidates of a chat; a group is refused (cannot_merge)', async () => {
    const { srv, m } = await setup();
    const { wa, kim } = fill(srv, { person: false });
    const grp = srv.addBridgeConv({ kind: 'group', title: 'Elternbeirat' });
    srv.addBridgeMsg(grp, { text: 'Hallo' });
    await m.check();
    const c = await m.personCandidates(wa);
    assert.ok(c.accounts.some((a) => a.userId === 8));
    assert.ok(c.chats.some((x) => x.conversationId === kim && x.network === 'whatsapp'));
    assert.equal(calls(srv, 'persons/candidates')[0].query.conversationId, String(wa));
    await assert.rejects(m.mergePersons({ conversationIds: [wa, grp] }), (e) => e.code === 'cannot_merge' && e.body.reason === 'group');
  });

  it('the question after linking WhatsApp: GET bridges › recognition, PUT bridges/recognition', async () => {
    const { srv, m } = await setup();
    srv.state.recognition = { asked: false, allowed: false };
    await m.check();
    const b = await m.bridges();
    assert.deepEqual(b.recognition, { available: true, network: 'whatsapp', asked: false, allowed: false });
    const r = await m.setRecognition(true);
    assert.deepEqual(r, { available: true, network: 'whatsapp', asked: true, allowed: true });
    srv.state.recognition = null;
    assert.equal((await m.bridges()).recognition, undefined);
    await assert.rejects(m.setRecognition(true), (e) => e.code === 'feature_off');
  });

  it('the cache keeps the person and its history; the next start shows them before the server answers', async () => {
    const store = createMemoryStore();
    const a = await setup({ store });
    const { gc } = fill(a.srv);
    await a.m.check();
    await a.m.getMessages(gc);
    a.m._persistNow();
    a.m.stop();
    const m2 = new MessengerService({ apiClient: new ApiClient(a.srv.url, 'gc_token', log), store, log, timing: FAST });
    cleanups.push(() => m2.stop());
    assert.equal(U.isPerson(m2.getCachedConversation(gc)), true);
    assert.equal(m2.messagesView(gc).messages.length, 4);
  });
});

describe('persons (Messenger 1.21) – push', () => {
  it('a click on the push of a way opens the person’s entry; the person open → no toast', async () => {
    const shown = [];
    class FakeN { constructor(o) { this.o = o; this.h = {}; shown.push(this); } on(k, f) { this.h[k] = f; } show() {} close() {} static isSupported() { return true; } }
    const messenger = { isOpenAndVisible: () => false, entryIdOf: (id) => id, on() {}, removeListener() {}, off() {} };
    const n = new ChatNotifier({ messenger, Notification: FakeN, platform: 'linux', log });
    const nav = [];
    n.on('navigate', (e) => nav.push(e.conversationId));
    n.handle({ kind: 'message', seq: 1, id: 1, title: 'Anna · über WhatsApp', body: 'Hi', data: { conversationId: 13, messageId: 40, bridge: 'whatsapp', person: { id: 1, conversationId: 12 } } });
    await waitFor(() => shown.length === 1, 2000, 'toast');
    assert.equal(shown[0].o.title, 'Anna · über WhatsApp');
    shown[0].h.click();
    assert.deepEqual(nav, [12]);
    messenger.isOpenAndVisible = (id) => id === 12;
    n.handle({ kind: 'message', seq: 2, id: 2, title: 'Anna · über WhatsApp', body: 'Noch was', data: { conversationId: 13, messageId: 41, bridge: 'whatsapp', person: { id: 1, conversationId: 12 } } });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(shown.length, 1);
  });
});

describe('persons (Messenger 1.21) – IPC', () => {
  it('checks the arguments before the service sees them', async () => {
    const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
    const h = new Map();
    const seen = [];
    const m = new Proxy({ on() {} }, { get: (t, k) => (k in t ? t[k] : (...args) => { seen.push([k, ...args]); return Promise.resolve(k === 'setWay' ? { messages: [] } : null); }) });
    registerMessengerHandlers((ch, fn) => h.set(ch, fn), { messenger: m, getMainWindow: () => null, log });
    const call = (ch, a) => h.get(ch)(null, a);
    assert.equal((await call('chat:person:way', { id: 12, way: '<x>' })).code, 'invalid');
    assert.equal((await call('chat:person:way', { id: 12, way: 'whatsapp' })).ok, true);
    assert.equal((await call('chat:person:split', { id: 12, conversationId: 'x' })).code, 'invalid');
    assert.equal((await call('chat:person:name', { id: 12, name: 'nobody' })).code, 'invalid');
    assert.equal((await call('chat:bridge:recognition', { allowed: 'yes' })).code, 'invalid');
    await call('chat:person:split', { id: 12, conversationId: 13 });
    await call('chat:suggestions', { refresh: true });
    assert.deepEqual(seen, [['setWay', 12, 'whatsapp'], ['splitPerson', 12, 13], ['suggestions', { refresh: true }]]);
  });
});
