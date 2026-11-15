'use strict';

// Messenger 1.18 (Stufe 4c der Brücken): „Neuer Chat“ with contacts — GET contacts/new-chat (GateControl, the WhatsApp
// contacts of the bridge, the address book of Mail) and POST bridges/:network/chats { ref } | { contactId, phoneKind }.
// Detected only by the feature word `bridge_contacts`; without it the new chat by number (1.15 / 1.16) stays as it was.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const STAGE4 = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_new_chat: true };
const STAGE4C = { ...STAGE4, bridge_contacts: true };
const REF = (n) => `k${String(n).repeat(44).slice(0, 44)}`;

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

async function setup({ features = STAGE4C } = {}) {
  const srv = await messengerServer({ features });
  cleanups.push(() => srv.close());
  const B = srv.state.bridge;
  B.networks[0].logins = [{ id: 'login1', name: '+49 1512 0000000', state: 'connected', since: new Date().toISOString() }];
  B.contacts = [
    { ref: REF('a'), name: 'Lena Berger', alsoInAddressBook: true, addressBookId: 13 },
    { ref: REF('b'), name: 'Anna Albers' },
  ];
  B.book = [
    { contactId: 12, name: 'Sabine Wolf', phones: [
      { key: 'home', kind: 'home', number: '+49 30 12345678', e164: '+493012345678', landline: true, notOnNetwork: false },
      { key: 'mobile', kind: 'mobile', number: '+49 151 23456780', e164: '+4915123456780', landline: false, notOnNetwork: false },
    ] },
    { contactId: 14, name: 'Tom Klein', phones: [{ key: 'mobile', kind: 'mobile', number: '+49 160 0000000', e164: '+491600000000', landline: false, notOnNetwork: false }] },
  ];
  B.numbers.set('+4915123456780', 'Sabine');
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const lines = [];
  const spy = { info: (s) => lines.push(String(s)), warn: (s) => lines.push(String(s)), debug: (s) => lines.push(String(s)), error: (s) => lines.push(String(s)) };
  const m = new MessengerService({ apiClient, store: createMemoryStore(), log: spy, timing: FAST });
  cleanups.push(() => m.stop());
  m.start();
  await waitFor(() => m.supports('bridge_new_chat'), 4000, 'GET me');
  return { srv, m, lines };
}

describe('bridges stage 4c – helpers', () => {
  it('knows the feature word (no update hint for it)', () => {
    assert.deepEqual(U.unknownFeatures({ bridge_new_chat: true, bridge_contacts: true }), []);
  });

  it('normalizes GET contacts/new-chat: sections, phones sorted, no WhatsApp → no address book and no number entry', () => {
    const r = U.normalizeNewChatContacts({
      network: 'whatsapp', query: 'ber',
      gatecontrol: [{ userId: 3, name: 'Marc', avatarUrl: '/avatars/3.webp', initials: 'MA', colorHex: '#84CC16', conversationId: 12 }, { userId: 'x' }],
      whatsapp: { state: 'ok', total: 86, items: [{ ref: REF('a'), name: 'Lena\u0007 Berger', avatarMediaId: null, conversationId: null, alsoInAddressBook: true, addressBookId: 13, number: '+49…' }, { ref: 'bad' }] },
      addressBook: { state: 'ok', total: 41, items: [{ contactId: 12, name: 'Sabine Wolf', conversationId: null, phones: [
        { key: 'other', kind: 'other', number: '+49 89 1', e164: '+49891', landline: true },
        { key: 'home', kind: 'home', number: '+49 30 12345678', e164: '+493012345678', landline: true },
        { key: 'mobile-2', kind: 'mobile', number: '+49 151 2', e164: '+491512' },
        { key: 'fax', number: '1' },
      ] }, { contactId: 15, name: 'Ohne Nummer', phones: [] }] },
      addressBookReason: null, number: { e164: '+4917155501230', show: '+49 171 5550123', conversationId: null }, numberEntry: true,
      limit: { perHour: 10, left: 7, retryAfterS: 0 },
    });
    assert.deepEqual(r.gatecontrol, [{ id: 3, userId: 3, name: 'Marc', avatarUrl: '/avatars/3.webp', initials: 'MA', colorHex: '#84CC16', conversationId: 12 }]);
    assert.deepEqual(r.whatsapp, { state: 'ok', total: 86, items: [{ ref: REF('a'), name: 'Lena  Berger', avatarMediaId: null, avatarUrl: null, conversationId: null, alsoInAddressBook: true, addressBookId: 13 }] });
    assert.deepEqual(r.addressBook.items.map((x) => [x.contactId, x.phones.map((p) => p.key)]), [[12, ['mobile-2', 'home', 'other']]]);
    assert.equal(r.addressBook.total, 41);
    assert.deepEqual(r.number, { e164: '+4917155501230', show: '+49 171 5550123', conversationId: null });
    assert.equal(r.numberEntry, true);
    assert.deepEqual(r.limit, { perHour: 10, left: 7, retryAfterS: 0 });
    const none = U.normalizeNewChatContacts({ gatecontrol: [], whatsapp: null, addressBook: { state: 'ok', items: [] }, number: { e164: '+4917155501230' }, numberEntry: true });
    assert.deepEqual([none.whatsapp, none.addressBook, none.number, none.numberEntry], [null, null, null, false]);
    assert.equal(U.normalizeNewChatContacts({ whatsapp: { state: 'weird', items: [{ ref: REF('a') }] } }).whatsapp.state, 'unreachable');
    // the server's initials: whole characters, never half an emoji
    assert.equal(U.normalizeNewChatContacts({ gatecontrol: [{ userId: 4, name: 'Mama', initials: 'MAM💕' }] }).gatecontrol[0].initials, 'MAM💕');
    assert.equal(U.normalizeNewChatContacts({ gatecontrol: [{ userId: 4, name: 'Mama', initials: 'M💕💕💕' }] }).gatecontrol[0].initials, 'M💕💕💕');
    assert.deepEqual(U.normalizeNewChatContacts({ whatsapp: { state: 'logged_out', total: 3, items: [{ ref: REF('a') }] } }).whatsapp, { state: 'logged_out', total: 3, items: [] });
  });

  it('a contact for POST …/chats: { ref } or { contactId, phoneKind }, nothing else', () => {
    assert.deepEqual(U.contactChatBody({ ref: REF('a'), contactId: 3 }), { ref: REF('a') });
    assert.deepEqual(U.contactChatBody({ contactId: 12, phoneKind: 'work-2', number: '+49…' }), { contactId: 12, phoneKind: 'work-2' });
    for (const bad of [null, {}, { ref: 'k1' }, { contactId: 0, phoneKind: 'mobile' }, { contactId: 12, phoneKind: 'fax' }, { contactId: 12 }]) assert.equal(U.contactChatBody(bad), null, JSON.stringify(bad));
  });
});

describe('bridges stage 4c – MessengerService', () => {
  it('an older plugin (Messenger 1.17): no contacts, the new chat by number stays', async () => {
    const { m } = await setup({ features: STAGE4 });
    await assert.rejects(m.newChatContacts('whatsapp', ''), (e) => e.code === 'unsupported');
    await assert.rejects(m.bridgeContactChat('whatsapp', { ref: REF('a') }), (e) => e.code === 'unsupported');
    assert.equal(typeof (await m.bridgeResolve('whatsapp', '0151 23456780')).found, 'boolean');
  });

  it('lists the three sections; the search goes as q, a number-like search gets the row „… bei WhatsApp prüfen“', async () => {
    const { srv, m, lines } = await setup();
    const r = await m.newChatContacts('whatsapp', '');
    assert.deepEqual(r.whatsapp.items.map((c) => c.name), ['Anna Albers', 'Lena Berger']);
    assert.equal(r.whatsapp.items[1].alsoInAddressBook, true);
    assert.deepEqual(r.addressBook.items[0].phones.map((p) => p.key), ['mobile', 'home'], 'mobile first');
    assert.equal(r.numberEntry, true);
    const q = await m.newChatContacts('whatsapp', '  berg ');
    assert.deepEqual(q.whatsapp.items.map((c) => c.name), ['Lena Berger']);
    const calls = srv.state.requests.filter((x) => x.path === `${API}contacts/new-chat`);
    assert.deepEqual(calls.map((x) => x.query), [{ network: 'whatsapp' }, { network: 'whatsapp', q: 'berg' }]);
    assert.equal((await m.newChatContacts('whatsapp', '0171 5550123')).number.e164, '+491715550123');
    assert.equal(srv.state.bridge.lookups, 0, 'listing and searching check nothing');
    assert.ok(!lines.some((l) => /berg|Lena|Sabine|5550123/.test(l)), 'neither the search nor a name is logged');
    await assert.rejects(m.newChatContacts('Bad Net', ''), (e) => e.code === 'invalid');
  });

  it('a WhatsApp contact starts its chat at once (nothing counted), kept in the list; contact_expired comes through', async () => {
    const { srv, m } = await setup();
    const r = await m.bridgeContactChat('whatsapp', { ref: REF('a') });
    assert.equal(r.created, true);
    assert.equal(r.conversation.title, 'Lena Berger');
    assert.equal(srv.state.bridge.lookups, 0);
    const posted = srv.state.requests.filter((x) => x.method === 'POST' && x.path === `${API}bridges/whatsapp/chats`);
    assert.deepEqual(posted.map((x) => x.body), [{ ref: REF('a') }]);
    await m.refreshConversations({ full: true });
    assert.ok(m.getCachedConversation(r.conversation.id), 'not listed by the server yet, kept');
    assert.equal((await m.bridgeContactChat('whatsapp', { ref: REF('a') })).created, false);
    srv.state.bridge.expired.add(REF('b'));
    await assert.rejects(m.bridgeContactChat('whatsapp', { ref: REF('b') }), (e) => e.code === 'contact_expired' && e.status === 409);
    await assert.rejects(m.bridgeContactChat('whatsapp', { ref: 'nope' }), (e) => e.code === 'invalid');
  });

  it('an address book number is checked on tap: found → chat, not at WhatsApp (then remembered), too many checks', async () => {
    const { srv, m, lines } = await setup();
    const r = await m.bridgeContactChat('whatsapp', { contactId: 12, phoneKind: 'mobile' });
    assert.deepEqual([r.created, r.conversation.title], [true, 'Sabine Wolf']);
    assert.equal(srv.state.bridge.lookups, 1);
    await assert.rejects(m.bridgeContactChat('whatsapp', { contactId: 14, phoneKind: 'mobile' }), (e) => e.code === 'not_found' && e.body.reason === 'not_on_network' && !e.body.remembered);
    await assert.rejects(m.bridgeContactChat('whatsapp', { contactId: 14, phoneKind: 'mobile' }), (e) => e.code === 'not_found' && e.body.remembered === true);
    assert.equal(srv.state.bridge.lookups, 2, 'a remembered „no“ asks nobody');
    assert.equal((await m.newChatContacts('whatsapp', '')).addressBook.items.find((x) => x.contactId === 14).phones[0].notOnNetwork, true);
    await assert.rejects(m.bridgeContactChat('whatsapp', { contactId: 99, phoneKind: 'mobile' }), (e) => e.code === 'not_found' && e.body.reason === 'contact_gone');
    srv.state.bridge.lookupMax = 2;
    await assert.rejects(m.bridgeContactChat('whatsapp', { contactId: 12, phoneKind: 'home' }), (e) => e.code === 'rate_limited' && e.body.retryAfterS === 840 && e.body.perHour === 2);
    srv.state.bridge.book = null;
    await assert.rejects(m.bridgeContactChat('whatsapp', { contactId: 12, phoneKind: 'mobile' }), (e) => e.code === 'mail_missing');
    assert.ok(!lines.some((l) => /Sabine|Tom|151 2345|160 0000/.test(l)), 'neither a name nor a number is logged');
  });

  it('the WhatsApp section says why it is empty; no link → no WhatsApp, no address book, no number entry', async () => {
    const { srv, m } = await setup();
    srv.state.bridge.listState = 'unreachable';
    const down = await m.newChatContacts('whatsapp', '');
    assert.deepEqual([down.whatsapp.state, down.whatsapp.items.length, down.addressBook.state], ['unreachable', 0, 'unreachable']);
    srv.state.bridge.listState = 'ok';
    srv.state.bridge.networks[0].logins[0].state = 'logged_out';
    const out = await m.newChatContacts('whatsapp', '');
    assert.equal(out.whatsapp.state, 'logged_out');
    await assert.rejects(m.bridgeContactChat('whatsapp', { ref: REF('a') }), (e) => e.code === 'bridge_logged_out');
    srv.state.bridge.networks[0].logins = [];
    const none = await m.newChatContacts('whatsapp', '');
    assert.deepEqual([none.whatsapp, none.addressBook, none.numberEntry, none.gatecontrol.length > 0], [null, null, false, true]);
  });
});
