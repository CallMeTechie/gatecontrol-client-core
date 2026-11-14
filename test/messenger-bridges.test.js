'use strict';

// Messenger 1.13 „Verknüpfte Dienste“ and 1.14 chats over a bridge: the pure helpers, the routes of MessengerApi
// (the mark ?bridged=1 only where the server names the feature), and MessengerService against the in-memory
// messenger server — linking with a code and a QR code, unlinking, a bridged chat's list, sending (text only, no
// queue), „Nicht gesendet“ + resend, typing contacts, and an older plugin that knows none of it.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerApi = require('../src/services/messenger-api');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };
const LINKED = { ...FEATURES_14, linked_services: true };
const BRIDGED = { ...LINKED, bridge_chats: true };

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

async function setup({ features = LINKED, push = false, store = createMemoryStore() } = {}) {
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
  const events = [];
  for (const ev of ['state', 'conversations', 'messages', 'typing', 'send-failed']) m.on(ev, (p) => events.push({ ev, p }));
  return { srv, m, apiClient, pushClient, events, store };
}
const apiCalls = (srv) => srv.state.requests.filter((r) => r.path.startsWith(API));
const marked = (srv) => apiCalls(srv).filter((r) => r.query.bridged === '1');

describe('bridges – helpers', () => {
  it('knows the feature words (no update hint for them)', () => {
    assert.deepEqual(U.unknownFeatures({ linked_services: true, bridge_chats: true, bridges: false }), []);
    assert.deepEqual(U.unknownFeatures({ linked_services: true, something_new: true }), ['something_new']);
  });

  it('checks a phone number: country code, 6–15 digits', () => {
    assert.equal(U.bridgePhone('+49 1512 0000000'), '+4915120000000');
    assert.equal(U.bridgePhone('0049 (1512) 000-00.00'), '+4915120000000');
    for (const bad of ['', '01512 0000000', '+49', '+49 1512 00000000000000', '+49 15a2', null]) assert.equal(U.bridgePhone(bad), null, String(bad));
  });

  it('normalizes GET bridges and drops what it cannot name', () => {
    const b = U.normalizeBridges({ available: true, location: 'server', networks: [
      { id: 'whatsapp', state: 'running', allowed: true, lock: null, consent: '2026-11-01T10:00:00.000Z', outdated: true, version: '0.1', wantVersion: '0.2', logins: [{ id: 'l1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' }, { id: 'bad id' }, { id: 'l2', state: 'weird' }] },
      { id: 'Bad Net' }, null,
    ] });
    assert.equal(b.available, true);
    assert.equal(b.networks.length, 1);
    assert.deepEqual(b.networks[0].logins.map((l) => [l.id, l.state]), [['l1', 'connected'], ['l2', 'unknown']]);
    assert.equal(b.networks[0].consent, true);
    assert.equal(b.networks[0].outdated, true);
    assert.deepEqual(U.normalizeBridges({ available: false, networks: [{ id: 'whatsapp' }] }), { available: false, location: 'server', networks: [] });
    assert.deepEqual(U.normalizeBridges(null).networks, []);
  });

  it('normalizes a login step: number, code, QR modules, complete, waiting, unsupported', () => {
    const L = U.normalizeBridgeLogin;
    assert.deepEqual(L({ processId: 'p1', waiting: true }), { processId: 'p1', waiting: true });
    assert.deepEqual(L({ processId: 'p1', step: { id: 's1', type: 'user_input', fields: [{ id: 'phone_number', type: 'phone_number' }] } }).step, { id: 's1', type: 'phone', fieldId: 'phone_number' });
    assert.deepEqual(L({ processId: 'p1', step: { id: 's2', type: 'display_and_wait', display: { type: 'code', data: 'K7P2-M4X9' } } }).step, { id: 's2', type: 'code', code: 'K7P2-M4X9' });
    const rows = Array.from({ length: 21 }, () => '1'.repeat(21));
    assert.deepEqual(L({ processId: 'p1', step: { id: 's3', type: 'display_and_wait', display: { type: 'qr', data: 'x', matrix: { size: 21, rows } } } }).step, { id: 's3', type: 'qr', matrix: { size: 21, rows } });
    assert.equal(L({ processId: 'p1', step: { id: 'd', type: 'complete', loginId: 'l1' } }).step.type, 'complete');
    // a QR step without usable modules, a picture address, an unknown step: not shown
    assert.equal(L({ processId: 'p1', step: { id: 's3', type: 'display_and_wait', display: { type: 'qr', data: 'x', matrix: { size: 21, rows: rows.slice(1) } } } }).step.type, 'unsupported');
    assert.equal(L({ processId: 'p1', step: { id: 's3', type: 'display_and_wait', display: { type: 'qr', data: 'x', matrix: { size: 21, rows: rows.map(() => 'x'.repeat(21)) } } } }).step.type, 'unsupported');
    assert.equal(L({ processId: 'p1', step: { id: 's4', type: 'cookies' } }).step.type, 'unsupported');
    assert.equal(L({ processId: 'p1', step: { id: 's2', type: 'display_and_wait', display: { type: 'code', data: '<b>x</b>' } } }).step.type, 'unsupported');
    assert.equal(L({ step: { id: 's', type: 'complete' } }), null);
    assert.equal(L({ processId: 'bad id', waiting: true }), null);
  });

  it('messageStatus: the bridge’s word on an own message', () => {
    const c = { readUpTo: null, deliveredUpTo: 5 };
    assert.equal(U.messageStatus({ id: 5, mine: true, status: 'failed', bridge: { state: 'failed' } }, c), 'failed');
    assert.equal(U.messageStatus({ id: 6, mine: true, status: 'sending', bridge: { state: 'pending' } }, c), 'pending');
    assert.equal(U.messageStatus({ id: 5, mine: true, status: 'delivered', bridge: { state: 'delivered' } }, c), 'delivered');
    assert.equal(U.messageStatus({ id: 7, mine: true, status: 'sent', bridge: { state: 'sent' } }, c), 'sent');
    assert.equal(U.messageStatus({ id: 7, mine: false, bridge: { sender: { contactId: 1 } } }, c), null);
  });

  it('a chat push names its bridge and keeps the actions’ bodies', () => {
    const p = U.parseChatNotification({ seq: 3, id: 9, kind: 'message', title: 'Kim Muster · WhatsApp', body: 'Hi', data: { messageId: 4, conversationId: 12, bridge: 'whatsapp', conversation: { id: '12', title: null, isGroup: false }, sender: { id: 'ext-12', name: 'Kim Muster', avatarUrl: null },
      actions: [{ type: 'reply', label: 'Antworten', path: 'conversations/12/messages', body: { bridged: true } }, { type: 'mark_read', label: 'Gelesen', path: 'conversations/12/read', body: { upTo: 4, bridged: true } }] } });
    assert.equal(p.bridge, 'whatsapp');
    assert.equal(p.sender.id, 'ext-12');
    assert.deepEqual(p.reply.body, { bridged: true });
    assert.deepEqual(p.markRead.body, { upTo: 4, bridged: true });
    assert.equal(U.parseChatNotification({ seq: 3, id: 9, kind: 'message', data: { conversationId: 12, bridge: 'What?' } }).bridge, null);
    assert.equal(U.bridgeLabel('whatsapp'), 'WhatsApp');
    assert.equal(U.bridgeLabel('signal'), 'Signal');
  });
});

describe('bridges – MessengerApi', () => {
  async function api(features = LINKED) {
    const srv = await messengerServer({ features });
    cleanups.push(() => srv.close());
    return { srv, api: new MessengerApi({ apiClient: new ApiClient(srv.url, 'gc_token', log), log }) };
  }

  it('marks conversation and message routes with ?bridged=1 only when told to', async () => {
    const { srv, api: a } = await api(BRIDGED);
    const id = srv.addBridgeConv();
    srv.addBridgeMsg(id);
    assert.equal((await a.conversations()).conversations.length, 0, 'without the mark the chat does not exist');
    await assert.rejects(a.conversation(id), (e) => e.code === 'not_found' && e.status === 404);
    assert.equal(marked(srv).length, 0);
    a.bridged = true;
    assert.equal((await a.conversations({ since: '2020-01-01T00:00:00.000Z' })).conversations.length, 1);
    assert.deepEqual(srv.state.requests.at(-1).query, { since: '2020-01-01T00:00:00.000Z', bridged: '1' });
    assert.equal((await a.conversation(id)).conversation.bridge.network, 'whatsapp');
    const page = await a.messages(id, { limit: 10 });
    assert.deepEqual(srv.state.requests.at(-1).query, { limit: '10', bridged: '1' });
    assert.equal(page.messages[0].bridge.sender.name, 'Kim Muster');
    await a.remove(page.messages[0].id, 'me');
    assert.deepEqual(srv.state.requests.at(-1).query, { for: 'me', bridged: '1' });
    await a.me();
    await a.people();
    await a.bridges();
    assert.deepEqual(srv.state.requests.slice(-3).map((r) => r.query), [{}, {}, {}], 'other routes stay as they are');
  });

  it('calls the routes of „Verknüpfte Dienste“', async () => {
    const { srv, api: a } = await api();
    assert.equal((await a.bridges()).bridges.networks[0].id, 'whatsapp');
    await assert.rejects(a.bridgeLogin('whatsapp', 'phone'), (e) => e.code === 'consent_required' && e.status === 409);
    assert.ok((await a.bridgeConsent('whatsapp')).consent);
    assert.deepEqual(srv.state.requests.at(-1).body, { accept: true });
    const start = await a.bridgeLogin('whatsapp', 'phone');
    assert.deepEqual(srv.state.requests.at(-1).body, { flow: 'phone' });
    const pid = start.login.processId;
    const code = await a.bridgeStep('whatsapp', pid, start.login.step.id, { phone_number: '+4915120000000' });
    assert.equal(srv.state.requests.at(-1).path, `${API}bridges/whatsapp/login/${pid}/phone1`);
    assert.equal(code.login.step.display.data, 'K7P2-M4X9');
    assert.equal((await a.bridgeStep('whatsapp', pid, 'code1')).login.waiting, true);
    assert.deepEqual(srv.state.requests.at(-1).body, {});
    assert.equal((await a.bridgeStep('whatsapp', pid, 'code1')).login.step.type, 'complete');
    await a.bridgeUnlink('whatsapp', 'login1');
    assert.equal(srv.state.requests.at(-1).method, 'DELETE');
    assert.equal(srv.state.requests.at(-1).path, `${API}bridges/whatsapp/logins/login1`);
    const again = await a.bridgeLogin('whatsapp', 'qr');
    await a.bridgeCancel('whatsapp', again.login.processId);
    assert.deepEqual(srv.state.bridge.calls.at(-1), { op: 'cancel', process: again.login.processId });
    for (const bad of [() => a.bridgeLogin('Whats App', 'qr'), () => a.bridgeLogin('whatsapp', 'sms'), () => a.bridgeStep('whatsapp', '../x', 's'), () => a.bridgeUnlink('whatsapp', 'a/b'), () => a.bridgeCancel('whatsapp', '')]) {
      const n = srv.state.requests.length;
      await assert.rejects(bad(), (e) => e.code === 'invalid');
      assert.equal(srv.state.requests.length, n, 'nothing sent');
    }
  });
});

describe('bridges – MessengerService', () => {
  it('an older plugin: nothing changes — no mark on any call, no bridges', async () => {
    const { srv, m } = await setup({ features: FEATURES_14 });
    const id = srv.addConv();
    srv.addMsg(id, { text: 'Hi' });
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await m.getMessages(id);
    await m.send({ conversationId: id, kind: 'text', text: 'Hallo' });
    await waitFor(() => srv.state.lastSendBody);
    await m.markRead(id);
    assert.equal(marked(srv).length, 0);
    assert.equal(m.api.bridged, false);
    assert.equal(m.status().updateHint, null);
    assert.equal('bridge' in m.listConversations()[0], false);
    await assert.rejects(m.bridges(), (e) => e.code === 'unsupported');
    await assert.rejects(m.bridgeLogin('whatsapp', 'qr'), (e) => e.code === 'unsupported');
    assert.equal(apiCalls(srv).some((r) => r.path.includes('/bridges')), false);
  });

  it('links with a pairing code: notes, number (checked, sent once), code, waiting, linked', async () => {
    const { srv, m } = await setup();
    m.start();
    await waitFor(() => m.status().state === 'available');
    assert.equal(m.api.bridged, true, 'the server offers a bridge: its chats are asked for');
    assert.equal(m.status().updateHint, null);
    let b = await m.bridges();
    assert.deepEqual(b.networks.map((n) => [n.id, n.state, n.consent, n.logins.length]), [['whatsapp', 'running', false, 0]]);
    await assert.rejects(m.bridgeLogin('whatsapp', 'phone'), (e) => e.code === 'consent_required');
    assert.deepEqual(await m.bridgeConsent('whatsapp'), { consent: true });
    const start = await m.bridgeLogin('whatsapp', 'phone');
    assert.deepEqual(start.step, { id: 'phone1', type: 'phone', fieldId: 'phone_number' });
    const n = srv.state.requests.length;
    await assert.rejects(m.bridgeStep('whatsapp', start.processId, start.step.id, { phone: '01512 0000000', fieldId: 'phone_number' }), (e) => e.code === 'phone_invalid');
    assert.equal(srv.state.requests.length, n, 'a number without country code is not sent');
    const code = await m.bridgeStep('whatsapp', start.processId, start.step.id, { phone: '0049 1512 0000000', fieldId: 'phone_number' });
    assert.deepEqual(srv.state.requests.at(-1).body, { input: { phone_number: '+4915120000000' } });
    assert.deepEqual(code.step, { id: 'code1', type: 'code', code: 'K7P2-M4X9' });
    assert.deepEqual(await m.bridgeStep('whatsapp', code.processId, code.step.id), { processId: code.processId, waiting: true });
    assert.equal((await m.bridgeStep('whatsapp', code.processId, code.step.id)).step.type, 'complete');
    b = await m.bridges();
    assert.deepEqual(b.networks[0].logins.map((l) => [l.state, l.name]), [['connected', '+49 1512 0000000']]);
    // the service refuses the number: the page stays on the field
    srv.state.bridge.phoneRefused = true;
    const s2 = await m.bridgeLogin('whatsapp', 'phone');
    await assert.rejects(m.bridgeStep('whatsapp', s2.processId, s2.step.id, { phone: '+49 1512 0000000' }), (e) => e.code === 'bridge_failed' && e.body.reason === 'bad_number');
  });

  it('links with a QR code (renewed while waiting), reports an expired code, cancels, unlinks', async () => {
    const { srv, m } = await setup();
    srv.state.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
    srv.state.bridge.qrRenewAt = 1;
    srv.state.bridge.confirmAfter = 3;
    m.start();
    await waitFor(() => m.status().state === 'available');
    const qr = await m.bridgeLogin('whatsapp', 'qr');
    assert.equal(qr.step.type, 'qr');
    assert.equal(qr.step.matrix.size, 25);
    const next = await m.bridgeStep('whatsapp', qr.processId, qr.step.id);
    assert.equal(next.step.type, 'qr');
    assert.notEqual(next.step.id, qr.step.id, 'a new code is a new step');
    assert.notDeepEqual(next.step.matrix.rows, qr.step.matrix.rows);
    assert.equal((await m.bridgeStep('whatsapp', qr.processId, next.step.id)).waiting, true);
    srv.state.bridge.loginFails = { status: 502, code: 'bridge_failed', reason: 'timeout' };
    await assert.rejects(m.bridgeStep('whatsapp', qr.processId, next.step.id), (e) => e.code === 'bridge_failed' && e.body.reason === 'timeout');
    const again = await m.bridgeLogin('whatsapp', 'qr');
    assert.equal(await m.bridgeCancel('whatsapp', again.processId), true);
    assert.equal(srv.state.bridge.process, null);
    assert.equal(await m.bridgeCancel('whatsapp', 'bad id'), false);
    // unlink: the chats of the service say so afterwards
    srv.state.bridge.networks[0].logins = [{ id: 'login1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' }];
    const id = srv.addBridgeConv();
    srv.addBridgeMsg(id);
    await m.refreshConversations({ full: true });
    assert.equal(m.listConversations()[0].bridge.state, 'ok');
    assert.equal(await m.bridgeUnlink('whatsapp', 'login1'), true);
    await waitFor(() => m.listConversations()[0].bridge.state === 'unlinked');
    assert.equal(m.listConversations()[0].can.send, false);
    // locked for a child, switched off
    srv.state.bridge.networks[0].allowed = false;
    await assert.rejects(m.bridgeLogin('whatsapp', 'qr'), (e) => e.code === 'bridge_locked' && e.status === 403);
    srv.state.bridge.available = false;
    assert.deepEqual(await m.bridges(), { available: false, location: 'server', networks: [] });
  });

  it('a chat over a bridge: listed with the mark, text out, contacts typing', async () => {
    const { srv, m, events } = await setup({ features: BRIDGED, push: true });
    const id = srv.addBridgeConv({ title: 'Kim Muster' });
    const first = srv.addBridgeMsg(id, { text: 'Kommst du?' });
    srv.addBridgeMsg(id, { text: 'Am Handy geschrieben', remote: true });
    srv.addBridgeMsg(id, { text: null, placeholder: { kind: 'image', name: 'grill.jpg' } });
    const normal = srv.addConv();
    srv.addMsg(normal, { text: 'Hi' });
    m.start();
    await waitFor(() => m.listConversations().length === 2 && m.status().live);
    const c = m.listConversations().find((x) => x.id === id);
    assert.deepEqual([c.bridge.network, c.bridge.label, c.bridge.state, c.peer, c.title, c.members.length], ['whatsapp', 'WhatsApp', 'ok', null, 'Kim Muster', 1]);
    assert.deepEqual(c.typingContacts, []);
    assert.equal(m.listConversations().find((x) => x.id === normal).bridge, null);
    assert.equal('typingContacts' in m.listConversations().find((x) => x.id === normal), false);
    assert.ok(apiCalls(srv).filter((r) => /\/(conversations|messages)(\/|$)/.test(r.path)).every((r) => r.query.bridged === '1'));
    const v = await m.getMessages(id);
    assert.deepEqual(v.messages.map((x) => [x.mine, x.bridge.remote, x.bridge.sender && x.bridge.sender.name, x.bridge.placeholder && x.bridge.placeholder.kind]),
      [[false, false, 'Kim Muster', null], [true, true, null, null], [false, false, 'Kim Muster', 'image']]);
    // only a text crosses: refused before anything is queued
    await assert.rejects(m.send({ conversationId: id, kind: 'location', location: { lat: 50, lon: 7 } }), (e) => e.code === 'bridge_text_only');
    await assert.rejects(m.send({ conversationId: id, kind: 'image', file: { data: Buffer.from('x'), mime: 'image/png', name: 'a.png' } }), (e) => e.code === 'bridge_text_only');
    assert.equal(m.outbox.size(), 0);
    await m.send({ conversationId: id, kind: 'text', text: 'Bin gleich da', replyTo: first.id });
    await waitFor(() => srv.state.lastSendBody);
    assert.equal(srv.state.lastSendBody.replyTo, first.id);
    assert.equal(srv.state.requests.find((r) => r.method === 'POST' && r.path.endsWith(`/conversations/${id}/messages`)).query.bridged, '1');
    await waitFor(() => m.messagesView(id).messages.length === 4);
    assert.equal(m.messagesView(id).messages.at(-1).bridge.state, 'sent');
    // contacts typing (userId null), until it stops
    srv.event('typing', { conversationId: id, userId: null, contacts: [{ contactId: 12, name: 'Kim Muster' }], until: new Date(Date.now() + 5000).toISOString() });
    await waitFor(() => m.listConversations().find((x) => x.id === id).typingContacts.length === 1);
    assert.deepEqual(m.getCachedConversation(id).typingContacts, [{ contactId: 12, name: 'Kim Muster' }]);
    assert.deepEqual(events.filter((e) => e.ev === 'typing').at(-1).p.contacts, [{ contactId: 12, name: 'Kim Muster' }]);
    srv.event('typing', { conversationId: id, userId: null, contacts: [], until: null });
    await waitFor(() => m.listConversations().find((x) => x.id === id).typingContacts.length === 0);
  });

  it('„Nicht gesendet“: the bridge did not take it — shown with its reason, sent again on request; no queue while it is away', async () => {
    const { srv, m, events } = await setup({ features: BRIDGED });
    const id = srv.addBridgeConv();
    srv.addBridgeMsg(id);
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await m.getMessages(id);
    srv.state.bridge.sendFails = 'not_running';
    await m.send({ conversationId: id, kind: 'text', text: 'Hallo?' });
    await waitFor(() => m.messagesView(id).messages.length === 2);
    const failed = m.messagesView(id).messages.at(-1);
    assert.deepEqual([failed.status, failed.bridge.state, failed.bridge.reason], ['failed', 'failed', 'not_running']);
    assert.equal(U.messageStatus(failed, m.getCachedConversation(id)), 'failed');
    assert.equal(m.outbox.size(), 0, 'stored at the server: not in the outbox');
    srv.state.bridge.sendFails = null;
    const again = await m.resend(failed.id);
    assert.equal(again.bridge.state, 'sent');
    assert.equal(srv.state.requests.at(-1).query.bridged, '1');
    assert.equal(m.messagesView(id).messages.at(-1).status, 'sent');
    // the bridge is away: the server takes nothing (503) — the message fails at once instead of waiting
    srv.state.convs.get(id).bridge.state = 'unreachable';
    await m.send({ conversationId: id, kind: 'text', text: 'Noch da?' });
    await waitFor(() => events.some((e) => e.ev === 'send-failed'));
    assert.equal(events.find((e) => e.ev === 'send-failed').p.error, 'bridge_unreachable');
    const p = m.messagesView(id).pending;
    assert.deepEqual([p.length, p[0].failed, p[0].error], [1, true, 'bridge_unreachable']);
    await assert.rejects(m.resend('x'), (e) => e.code === 'invalid');
  });

  it('the first chat over a bridge arrives: the mark is set and GET me is read again', async () => {
    const features = { ...FEATURES_14 };
    const { srv, m } = await setup({ features, push: true });
    const id = srv.addBridgeConv();
    m.start();
    await waitFor(() => m.status().state === 'available' && m.status().live);
    assert.equal(m.api.bridged, false);
    assert.equal(m.listConversations().length, 0);
    // the server now has a chat for this person (features.bridge_chats appears with it)
    features.bridge_chats = true;
    const msg = srv.addBridgeMsg(id, { text: 'Erste Nachricht' });
    srv.event('message.new', { conversationId: id, messageId: msg.id, senderId: null, clientId: null, kind: 'text', createdAt: new Date().toISOString(), bridge: 'whatsapp' });
    await waitFor(() => m.listConversations().length === 1);
    assert.equal(m.api.bridged, true);
    await waitFor(() => m.supports('bridge_chats'));
    assert.equal(m.status().me.features.bridge_chats, true);
  });
});
