'use strict';

// Messenger 1.15 (Stufe 4 der Brücken): files in chats over a bridge (`bridge.supports` / `bridge.mediaTypes`, 423
// scan_pending sent again, 409 bridge_media_type), the contact's picture, and a new chat by phone number
// (`bridge_new_chat`: POST bridges/:network/resolve, …/chats). Detected only by the feature words — an older plugin
// keeps everything as it was.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const BRIDGED = { ...FEATURES_14, linked_services: true, bridge_chats: true };
const STAGE4 = { ...BRIDGED, bridge_media: true, bridge_new_chat: true };
const WA = { network: 'whatsapp', supports: ['text', 'image', 'video', 'voice', 'file'], mediaTypes: { image: ['image/jpeg', 'image/png', 'image/webp'], video: ['video/mp4'], voice: ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg'], file: null } };

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

async function setup({ features = STAGE4, media = true } = {}) {
  const srv = await messengerServer({ features });
  srv.state.bridge.media = media;
  cleanups.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const lines = [];
  const spy = { info: (s) => lines.push(String(s)), warn: (s) => lines.push(String(s)), debug: (s) => lines.push(String(s)), error: (s) => lines.push(String(s)) };
  const m = new MessengerService({ apiClient, store: createMemoryStore(), log: spy, timing: FAST });
  m.outbox.backoffMs = [20, 40];
  cleanups.push(() => m.stop());
  const events = [];
  for (const ev of ['conversations', 'messages', 'send-failed']) m.on(ev, (p) => events.push({ ev, p }));
  return { srv, m, events, lines };
}
const bridgeCalls = (srv) => srv.state.requests.filter((r) => r.path.startsWith(`${API}bridges/`));

describe('bridges stage 4 – helpers', () => {
  it('knows the new feature words (no update hint for them)', () => {
    assert.deepEqual(U.unknownFeatures({ bridge_chats: true, bridge_media: true, bridge_new_chat: true }), []);
  });

  it('normalizes a number of the dialog: +49 by default, a leading 0 goes, + and 00 keep their country', () => {
    assert.equal(U.bridgeNumber('0151 23456789'), '+4915123456789');
    assert.equal(U.bridgeNumber('151-234 567 89'), '+4915123456789');
    assert.equal(U.bridgeNumber('(0151) 2345/6789'), '+4915123456789');
    assert.equal(U.bridgeNumber('+43 664 1234567'), '+436641234567');
    assert.equal(U.bridgeNumber('0043 664 1234567'), '+436641234567');
    assert.equal(U.bridgeNumber('0664 1234567', '+43'), '+436641234567');
    assert.equal(U.bridgeNumber('0151 23456789', 'xx'), '+4915123456789');
    for (const bad of ['', null, '0151 234', 'abc', '+0151 23456789', '+49 151 2345678901234', '1'.repeat(30)]) assert.equal(U.bridgeNumber(bad), null, String(bad));
  });

  it('a file into a chat over a bridge: kind in supports, type in mediaTypes (null = any)', () => {
    assert.equal(U.bridgeMediaRefusal(WA, 'image', 'image/webp'), null);
    assert.equal(U.bridgeMediaRefusal(WA, 'image', 'image/gif'), 'image');
    assert.equal(U.bridgeMediaRefusal(WA, 'voice', 'audio/webm'), 'voice');
    assert.equal(U.bridgeMediaRefusal(WA, 'voice', 'audio/ogg; codecs=opus'), null);
    assert.equal(U.bridgeMediaRefusal(WA, 'file', 'video/mp4'), null);
    assert.equal(U.bridgeMediaRefusal(WA, 'file', 'video/webm'), 'video');
    assert.equal(U.bridgeMediaRefusal(WA, 'file', 'application/x-weird'), null);
    assert.equal(U.bridgeMediaRefusal({ network: 'whatsapp', supports: ['text', 'reply'] }, 'image', 'image/jpeg'), 'text_only');
    assert.equal(U.bridgeMediaRefusal({ supports: ['image'] }, 'image', 'image/gif'), null, 'no mediaTypes: the server decides');
  });

  it('GET bridges: newChat per service, null from an older plugin', () => {
    const b = U.normalizeBridges({ available: true, networks: [
      { id: 'whatsapp', state: 'running', allowed: true, logins: [], newChat: { available: false, reason: 'logged_out', limit: { perHour: 10, left: 7, retryAfterS: 0 } } },
      { id: 'signal', state: 'running', allowed: true, logins: [] },
    ] });
    assert.deepEqual(b.networks[0].newChat, { available: false, reason: 'logged_out', limit: { perHour: 10, left: 7, retryAfterS: 0 } });
    assert.equal(b.networks[1].newChat, null);
    assert.deepEqual(U.normalizeNewChat({ available: true, reason: 'off', limit: { perHour: -1 } }), { available: true, reason: null, limit: { perHour: null, left: null, retryAfterS: 0 } });
  });

  it('normalizes the answer of resolve', () => {
    assert.deepEqual(U.normalizeResolve({ ok: true, found: true, name: ' Lena\u0007 Berger ', avatarUrl: 'https://x/y', existing: { conversationId: 12 } }), { found: true, name: 'Lena  Berger', avatarMediaId: null, existing: { conversationId: 12 } });
    assert.deepEqual(U.normalizeResolve({ found: false, name: 'x', existing: { conversationId: 3 } }), { found: false, name: null, avatarMediaId: null, existing: null });
  });
});

describe('bridges stage 4 – MessengerService', () => {
  it('files out: picture and voice message cross, the type is checked first, 423 scan_pending is sent again', async () => {
    const { srv, m, events } = await setup();
    const id = srv.addBridgeConv({ title: 'Kim Muster' });
    srv.addBridgeMsg(id);
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await m.getMessages(id);
    const c = m.getCachedConversation(id);
    assert.ok(c.bridge.supports.includes('voice'));
    assert.deepEqual(c.bridge.mediaTypes.voice, ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg']);
    // refused before anything is queued: a WebM recording, a WebM video, a location
    await assert.rejects(m.send({ conversationId: id, kind: 'voice', meta: { durationMs: 2000 }, file: { data: Buffer.from('webm'), mime: 'audio/webm', name: 'a' } }), (e) => e.code === 'bridge_media_type' && e.body.reason === 'voice');
    await assert.rejects(m.send({ conversationId: id, kind: 'file', meta: { fileName: 'v.webm' }, file: { data: Buffer.from('v'), mime: 'video/webm', name: 'v.webm' } }), (e) => e.code === 'bridge_media_type' && e.body.reason === 'video');
    await assert.rejects(m.send({ conversationId: id, kind: 'location', location: { lat: 50, lon: 7 } }), (e) => e.code === 'bridge_text_only');
    assert.equal(m.outbox.size(), 0);
    // the virus scan is not done twice: the same entry goes again after Retry-After
    srv.state.bridge.scanPending = 2;
    await m.send({ conversationId: id, kind: 'image', text: 'Grill', meta: { w: 4, h: 3 }, file: { data: Buffer.from('jpeg'), mime: 'image/jpeg', name: 'grill.jpg' } });
    await waitFor(() => m.outbox.size() === 0, 8000, 'image sent');
    assert.equal(srv.state.bridge.scanPending, 0);
    assert.equal(events.filter((e) => e.ev === 'send-failed').length, 0);
    const posts = srv.state.requests.filter((r) => r.method === 'POST' && r.path.endsWith(`/conversations/${id}/messages`));
    assert.equal(posts.length, 3);
    assert.equal(new Set(posts.map((r) => r.body.clientId)).size, 1, 'same clientId');
    assert.equal(srv.state.requests.filter((r) => r.method === 'PUT' && r.path.includes('/media')).length, 1, 'uploaded once');
    assert.ok(posts.every((r) => r.query.bridged === '1'));
    await m.send({ conversationId: id, kind: 'voice', meta: { durationMs: 2000 }, file: { data: Buffer.from('ogg'), mime: 'audio/ogg', name: 'sprachnachricht' } });
    await waitFor(() => m.messagesView(id).messages.filter((x) => x.kind === 'voice').length === 1);
    assert.equal(srv.state.lastSendBody.kind, 'voice');
  });

  it('a type the server refuses after all (409 bridge_media_type): „Nicht gesendet“ with the kind, no retry', async () => {
    const { srv, m, events } = await setup();
    const id = srv.addBridgeConv();
    srv.addBridgeMsg(id);
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await m.getMessages(id);
    // the app's list says yes (no types named for voice), the server's says no
    m._convs.get(id).bridge = { ...m._convs.get(id).bridge, mediaTypes: { ...m._convs.get(id).bridge.mediaTypes, voice: null } };
    await m.send({ conversationId: id, kind: 'voice', meta: { durationMs: 1500 }, file: { data: Buffer.from('webm'), mime: 'audio/webm', name: 'a' } });
    await waitFor(() => events.some((e) => e.ev === 'send-failed'));
    const p = m.messagesView(id).pending[0];
    assert.deepEqual([p.failed, p.error, p.reason], [true, 'bridge_media_type', 'voice']);
    assert.equal(srv.state.requests.filter((r) => r.method === 'POST' && r.path.endsWith(`/conversations/${id}/messages`)).length, 1, 'not sent again by itself');
  });

  it('an older plugin (Messenger 1.14): no files offered, no new chat', async () => {
    const { srv, m } = await setup({ features: BRIDGED, media: false });
    const id = srv.addBridgeConv();
    srv.addBridgeMsg(id);
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    const c = m.getCachedConversation(id);
    assert.equal(c.bridge.supports.includes('image'), false);
    assert.equal('mediaTypes' in c.bridge, false);
    await assert.rejects(m.send({ conversationId: id, kind: 'image', file: { data: Buffer.from('x'), mime: 'image/jpeg', name: 'a.jpg' } }), (e) => e.code === 'bridge_text_only');
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'unsupported');
    await assert.rejects(m.bridgeStartChat('whatsapp', '0151 23456789'), (e) => e.code === 'unsupported');
    assert.equal(bridgeCalls(srv).length, 0);
  });

  it('a new chat by number: checked on request, started, kept in the list until it is listed, the number never logged', async () => {
    const { srv, m, lines } = await setup();
    srv.state.bridge.networks[0].logins = [{ id: 'login1', name: '+49 1512 0000000', state: 'connected', since: new Date().toISOString() }];
    srv.state.bridge.numbers.set('+4915123456789', 'Lena Berger');
    const old = srv.addBridgeConv({ title: 'Kim Muster' });
    srv.addBridgeMsg(old);
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 234'), (e) => e.code === 'invalid_number');
    assert.equal(bridgeCalls(srv).length, 0, 'an incomplete number is not sent');
    const r = await m.bridgeResolve('whatsapp', '0151 23456789', '+49');
    assert.deepEqual(r, { found: true, name: 'Lena Berger', avatarMediaId: null, existing: null });
    assert.equal(bridgeCalls(srv).at(-1).body.number, '+4915123456789');
    const none = await m.bridgeResolve('whatsapp', '+49 160 0000000');
    assert.equal(none.found, false);
    const started = await m.bridgeStartChat('whatsapp', '0151 23456789');
    assert.equal(started.created, true);
    const nid = started.conversation.id;
    assert.equal(started.conversation.bridge.network, 'whatsapp');
    assert.ok(m.listConversations().some((x) => x.id === nid));
    // GET conversations does not list it yet: a full read keeps it
    await m.refreshConversations({ full: true });
    assert.ok(m.listConversations().some((x) => x.id === nid), 'kept');
    assert.deepEqual((await m.getMessages(nid)).messages, []);
    // the same number once more: the same chat; resolve names it
    assert.deepEqual(await m.bridgeResolve('whatsapp', '015123456789'), { found: true, name: 'Lena Berger', avatarMediaId: null, existing: { conversationId: nid } });
    assert.equal((await m.bridgeStartChat('whatsapp', '+49 151 23456789')).created, false);
    // not at WhatsApp
    await assert.rejects(m.bridgeStartChat('whatsapp', '+49 160 0000000'), (e) => e.code === 'not_found' && e.body.reason === 'not_on_network');
    // the plugin's brake
    srv.state.bridge.lookupMax = 0;
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'rate_limited' && e.status === 429 && e.body.retryAfterS === 840);
    assert.ok(lines.every((l) => !/151\s*2?3?456|4915123456789/.test(l)), 'the number is never logged');
  });

  it('a new chat: refusals of the link (logged out, locked, not reachable)', async () => {
    const { srv, m } = await setup();
    const net = srv.state.bridge.networks[0];
    m.start();
    await waitFor(() => m.status().state === 'available');
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'bridge_unlinked' && e.body.reason === 'unlinked');
    net.logins = [{ id: 'l1', name: 'x', state: 'logged_out', since: null }];
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'bridge_unlinked' && e.body.reason === 'logged_out');
    net.logins = [{ id: 'l1', name: 'x', state: 'connected', since: null }];
    net.state = 'unreachable';
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'bridge_unreachable');
    net.allowed = false;
    await assert.rejects(m.bridgeResolve('whatsapp', '0151 23456789'), (e) => e.code === 'bridge_locked');
    await assert.rejects(m.bridgeResolve('Bad Net', '0151 23456789'), (e) => e.code === 'invalid');
  });

  it('a contact’s picture: avatarMediaId of the chat is loaded like a group picture', async () => {
    const { srv, m } = await setup();
    const id = srv.addBridgeConv({ title: 'Kim Muster' });
    srv.addBridgeMsg(id);
    const mediaId = 'a'.repeat(32);
    srv.state.media.set(mediaId, { mime: 'image/jpeg', data: Buffer.from('jpeg-bytes') });
    srv.state.convs.get(id).avatarMediaId = mediaId;
    m.start();
    await waitFor(() => m.listConversations().length === 1);
    assert.equal(m.getCachedConversation(id).avatarMediaId, mediaId);
    const pic = await m.media(mediaId);
    assert.equal(Buffer.from(pic.data).toString(), 'jpeg-bytes');
  });
});
