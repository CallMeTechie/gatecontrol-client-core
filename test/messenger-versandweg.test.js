'use strict';

// Messenger 1.27: „Nachrichten senden über“ per person (person.replyPref, PUT persons/:id { replyPref }, reply.fallback),
// the plus menu with everything a person can get (what only GateControl carries goes to the person's GateControl way
// while the text goes over a bridge), a location over a bridge that sends one (`bridge.supports` names location), an
// incoming location of a bridge as a location message, the line „Ortsnachricht · <Ort>“ (message.placeMessage).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const V2B = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_new_chat: true, bridge_history: true, bridge_contacts: true, bridge_channels: true, chat_people: true };
const V127 = { ...V2B, placeMessages: true };

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

async function setup({ features = V127, location = false } = {}) {
  const srv = await messengerServer({ features });
  cleanups.push(() => srv.close());
  srv.state.bridge.location = location;
  const m = new MessengerService({ apiClient: new ApiClient(srv.url, 'gc_token', log), store: createMemoryStore(), log, timing: FAST });
  cleanups.push(() => m.stop());
  return { srv, m };
}

/** Kim Muster in GateControl (account 8) and on WhatsApp; the newest incoming message came over WhatsApp. */
function fill(srv) {
  const gc = srv.addConv({ kind: 'direct', members: [7, 8] });
  const wa = srv.addBridgeConv({ title: 'Kim M.' });
  const T0 = Date.parse('2026-11-17T10:00:00.000Z');
  const g1 = srv.addMsg(gc, { senderId: 8, text: 'Kommst du heute zum Essen?' });
  g1.createdAt = T0;
  const w1 = srv.addBridgeMsg(wa, { text: 'Bringst du Brot mit?', contact: { contactId: 31, name: 'Kim M.' } });
  w1.createdAt = T0 + 60000;
  const pid = srv.addPerson({ convIds: [gc, wa], userId: 8 });
  return { gc, wa, pid, g1, w1 };
}
const calls = (srv, path) => srv.state.requests.filter((r) => r.path === `${API}${path}` && r.method === 'POST');

describe('Versandweg (Messenger 1.27) – helpers', () => {
  const e = {
    id: 12,
    person: {
      id: 1, conversationId: 12, replyPref: 'whatsapp',
      ways: [{ way: 'gatecontrol', conversationId: 12, bridge: null, can: { send: true } }, { way: 'whatsapp', conversationId: 13, bridge: { network: 'whatsapp', supports: ['text'] }, can: { send: false } }],
      reply: { way: 'gatecontrol', label: 'GateControl', conversationId: 12, fallback: true },
    },
  };

  it('knows the feature word (no update hint for it)', () => {
    assert.ok(U.KNOWN_FEATURES.includes('placeMessages'));
    assert.deepEqual(U.unknownFeatures(V127), []);
  });

  it('the choice, its body, the GateControl way', () => {
    assert.equal(U.personReplyPref(e), 'whatsapp');
    assert.equal(U.personReplyPref({ id: 12, person: { ...e.person, replyPref: undefined } }), 'auto');
    assert.equal(U.personReplyPref({ id: 12, person: { ...e.person, replyPref: '<x>' } }), 'auto');
    assert.deepEqual(U.replyPrefBody(e, 'gatecontrol'), { replyPref: 'gatecontrol' });
    assert.deepEqual(U.replyPrefBody(e, null), { replyPref: 'auto' });
    assert.equal(U.replyPrefBody(e, 'signal'), null, 'a way the person does not have');
    assert.equal(U.replyPrefBody(e, 3), null);
    assert.equal(U.replyPrefBody({ id: 5 }, 'auto'), null, 'no person');
    assert.equal(U.personGcWay(e).conversationId, 12);
    assert.equal(U.personGcWay({ id: 13, person: { id: 2, ways: [e.person.ways[1]] } }), null);
  });

  it('a location over a bridge only where `supports` names it; what needs the GateControl way', () => {
    assert.equal(U.bridgeTakesLocation({ supports: ['text', 'location'] }), true);
    assert.equal(U.bridgeTakesLocation({ supports: ['text'] }), false);
    assert.equal(U.bridgeTakesLocation(null), false);
    const wa = { supports: ['text', 'location'] };
    const sig = { supports: ['text'] };
    assert.equal(U.needsGcWay({ kind: 'poll' }, wa), true);
    assert.equal(U.needsGcWay({ kind: 'event' }, wa), true);
    assert.equal(U.needsGcWay({ kind: 'action' }, wa), true);
    assert.equal(U.needsGcWay({ kind: 'location' }, wa), false);
    assert.equal(U.needsGcWay({ kind: 'location' }, sig), true);
    assert.equal(U.needsGcWay({ kind: 'text', replyStory: { storyId: 3 } }, wa), true);
    assert.equal(U.needsGcWay({ kind: 'text' }, sig), false);
    assert.equal(U.needsGcWay({ kind: 'poll' }, null), false, 'the text goes inside GateControl anyway');
  });
});

describe('Versandweg (Messenger 1.27) – MessengerService', () => {
  it('„Immer GateControl“: PUT persons/:id { replyPref }, the entry follows; back to „Automatisch“', async () => {
    const { srv, m } = await setup();
    const { gc, pid } = fill(srv);
    m.start();
    await m.check();
    await m.getMessages(gc);
    assert.equal(m.replyWay(gc).way, 'whatsapp');
    assert.equal(m.replyWay(gc).pref, 'auto');
    assert.equal(m.replyWay(gc).fallback, false);
    const c = await m.setReplyPref(gc, 'gatecontrol');
    assert.equal(c.person.replyPref, 'gatecontrol');
    assert.deepEqual(srv.state.replyPrefs.pop(), { personId: pid, method: 'PUT', replyPref: 'gatecontrol' });
    assert.equal(m.replyWay(gc).way, 'gatecontrol');
    assert.equal(m.replyWay(gc).pref, 'gatecontrol');
    await m.send({ conversationId: gc, kind: 'text', text: 'Mach ich.' });
    await waitFor(() => srv.state.msgs.get(gc).some((x) => x.text === 'Mach ich.'), 4000, 'sent over GateControl');
    await m.setReplyPref(gc, null);
    assert.equal(srv.state.replyPrefs.pop().replyPref, 'auto');
    assert.equal(m.replyWay(gc).way, 'whatsapp');
  });

  it('„Immer WhatsApp“ while WhatsApp cannot send: GateControl with fallback', async () => {
    const { srv, m } = await setup();
    const { gc, wa } = fill(srv);
    await m.check();
    await m.setReplyPref(gc, 'whatsapp');
    assert.equal(m.replyWay(gc).way, 'whatsapp');
    srv.state.convs.get(wa).bridge.state = 'logged_out';
    await m.refreshConversations({ full: true });
    const rw = m.replyWay(gc);
    assert.equal(rw.way, 'gatecontrol');
    assert.equal(rw.pref, 'whatsapp');
    assert.equal(rw.fallback, true);
  });

  it('refuses a way the person does not have, and a server before 1.27', async () => {
    const { srv, m } = await setup();
    const { gc, wa } = fill(srv);
    await m.check();
    await assert.rejects(m.setReplyPref(gc, 'signal'), (e) => e.code === 'invalid');
    await assert.rejects(m.setReplyPref(wa, 'gatecontrol'), (e) => e.code === 'invalid', 'a way is no entry of its own');
    assert.equal((srv.state.replyPrefs || []).length, 0);
    const old = await setup({ features: V2B });
    const f = fill(old.srv);
    await old.m.check();
    await assert.rejects(old.m.setReplyPref(f.gc, 'gatecontrol'), (e) => e.code === 'unsupported');
  });

  it('the text over WhatsApp: a poll goes to the GateControl way (POST conversations/<gc>/messages), shown in the person', async () => {
    const { srv, m } = await setup();
    const { gc, wa, pid } = fill(srv);
    m.start();
    await m.check();
    await m.getMessages(gc);
    assert.equal(m.replyWay(gc).way, 'whatsapp');
    await m.send({ conversationId: gc, kind: 'poll', poll: { question: 'Pizza oder Pasta?', options: ['Pizza', 'Pasta'] } });
    await waitFor(() => calls(srv, `conversations/${gc}/messages`).length, 4000, 'poll to the GateControl chat');
    assert.equal(calls(srv, `persons/${pid}/messages`).length, 0);
    assert.equal(srv.state.msgs.get(wa).filter((x) => x.kind === 'poll').length, 0);
    const sent = srv.state.msgs.get(gc).find((x) => x.kind === 'poll');
    assert.ok(sent);
    await waitFor(() => { const v = m.messagesView(gc); return v.messages.some((y) => y.id === sent.id) && !v.pending.length; }, 4000, 'poll in the person');
  });

  it('a location: over WhatsApp when its bridge sends one (no accuracy), else to the GateControl way; an answer to a WhatsApp message is not quoted there', async () => {
    const { srv, m } = await setup({ location: true });
    const { gc, wa, pid, w1 } = fill(srv);
    m.start();
    await m.check();
    await m.getMessages(gc);
    await m.send({ conversationId: gc, kind: 'location', location: { lat: 51.5, lon: 7.25, label: 'Marktplatz', accuracy: 12 }, replyTo: w1.id });
    await waitFor(() => calls(srv, `persons/${pid}/messages`).length, 4000, 'location over the person');
    const loc = await waitFor(() => srv.state.msgs.get(wa).find((x) => x.kind === 'location'), 4000, 'location over WhatsApp');
    assert.deepEqual(loc.location, { lat: 51.5, lon: 7.25, label: 'Marktplatz' });
    assert.equal(srv.state.lastSendBody.replyTo, w1.id);

    // Signal-like: the bridge sends no location
    srv.state.bridge.location = false;
    await m.refreshConversations({ full: true });
    await m.send({ conversationId: gc, kind: 'location', location: { lat: 51.6, lon: 7.3 }, replyTo: w1.id });
    await waitFor(() => calls(srv, `conversations/${gc}/messages`).length, 4000, 'location to the GateControl chat');
    const gl = srv.state.msgs.get(gc).find((x) => x.kind === 'location');
    assert.deepEqual(gl.location, { lat: 51.6, lon: 7.3 });
    assert.equal(srv.state.lastSendBody.replyTo, undefined, 'the WhatsApp message is not in the GateControl chat');
  });

  it('a chat over a bridge alone: a location when it sends one, else bridge_text_only; a poll never', async () => {
    const { srv, m } = await setup({ location: true });
    const kim = srv.addBridgeConv({ title: 'Kim Muster' });
    srv.addBridgeMsg(kim, { text: 'Hallo' });
    m.start();
    await m.check();
    await m.getMessages(kim);
    await m.send({ conversationId: kim, kind: 'location', location: { lat: 50, lon: 7 } });
    await waitFor(() => srv.state.msgs.get(kim).some((x) => x.kind === 'location'), 4000, 'location over the bridge');
    await assert.rejects(m.send({ conversationId: kim, kind: 'poll', poll: { question: 'Ja?', options: ['Ja', 'Nein'] } }), (e) => e.code === 'bridge_text_only');
    srv.state.bridge.location = false;
    await m.refreshConversations({ full: true });
    await assert.rejects(m.send({ conversationId: kim, kind: 'location', location: { lat: 50, lon: 7 } }), (e) => e.code === 'bridge_text_only');
  });

  it('a person without a GateControl way: what only GateControl carries stays refused', async () => {
    const { srv, m } = await setup();
    const a = srv.addBridgeConv({ title: 'Jo Test' });
    const b = srv.addBridgeConv({ title: 'Jo T.', network: 'signal' });
    srv.addBridgeMsg(a, { text: 'Hi' });
    srv.addPerson({ convIds: [a, b] });
    await m.check();
    const id = m.listConversations().find((c) => U.isPerson(c)).id;
    await m.getMessages(id);
    await assert.rejects(m.send({ conversationId: id, kind: 'poll', poll: { question: 'Ja?', options: ['Ja', 'Nein'] } }), (e) => e.code === 'bridge_text_only');
    await assert.rejects(m.send({ conversationId: id, kind: 'location', location: { lat: 50, lon: 7 } }), (e) => e.code === 'bridge_text_only');
  });

  it('an incoming location of a bridge is a location message; an own message keeps placeMessage', async () => {
    const { srv, m } = await setup();
    const kim = srv.addBridgeConv({ title: 'Kim Muster' });
    const inc = srv.addBridgeMsg(kim, { text: null });
    inc.kind = 'location';
    inc.location = { lat: 51.31, lon: 7.41, label: 'Schwimmbad Nord' };
    const gc = srv.addConv({ kind: 'direct', members: [7, 8] });
    const own = srv.addMsg(gc, { senderId: 7, text: 'Bin da, Tür ist offen.' });
    own.placeMessage = { name: 'Zuhause', trigger: 'enter' };
    await m.check();
    const v1 = await m.getMessages(kim);
    const loc = v1.messages.find((x) => x.id === inc.id);
    assert.equal(loc.kind, 'location');
    assert.deepEqual(loc.location, { lat: 51.31, lon: 7.41, label: 'Schwimmbad Nord' });
    const v2 = await m.getMessages(gc);
    assert.deepEqual(v2.messages.find((x) => x.id === own.id).placeMessage, { name: 'Zuhause', trigger: 'enter' });
  });
});

describe('Versandweg (Messenger 1.27) – IPC', () => {
  it('chat:person:reply-pref checks the arguments before the service sees them', async () => {
    const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
    const h = new Map();
    const seen = [];
    const m = new Proxy({ on() {} }, { get: (t, k) => (k in t ? t[k] : (...args) => { seen.push([k, ...args]); return Promise.resolve({ id: 12 }); }) });
    registerMessengerHandlers((ch, fn) => h.set(ch, fn), { messenger: m, getMainWindow: () => null, log });
    const call = (ch, a) => h.get(ch)(null, a);
    assert.equal((await call('chat:person:reply-pref', { id: 12, pref: '<x>' })).code, 'invalid');
    assert.equal((await call('chat:person:reply-pref', { id: 'x', pref: 'auto' })).code, 'invalid');
    assert.deepEqual(await call('chat:person:reply-pref', { id: 12, pref: 'whatsapp' }), { ok: true, conversation: { id: 12 } });
    await call('chat:person:reply-pref', { id: 12, pref: null });
    assert.deepEqual(seen, [['setReplyPref', 12, 'whatsapp'], ['setReplyPref', 12, 'auto']]);
  });
});
