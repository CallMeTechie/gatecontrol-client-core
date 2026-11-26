'use strict';

// Mail 1.4.0 — contacts with the GC contact as the master, favourites and the calendar widget of the start page:
// the pure helpers (utils/mail-pim.js — summaries and cards with their sources and conflicts, the preview of a merge,
// the protocol, favourites, upcoming events, bodies, live events), the API and the service (services/mail.js —
// duplicates with details, merge without a primary, "Rückgängig", "Verknüpfung lösen", conflicts taken over or
// dismissed, writeBack, deleting with the linked cards, favourites and the widget offline from the cache) and the IPC
// against the fake server (fixtures/mail-pim-server.js with contactsMaster). A server before 1.4.0 (the fake without
// it) answers the new paths with 404: the service says `unsupported`, the new fields are null.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const mail = require('../src/utils/mail');
const MailService = require('../src/services/mail');
const ApiClient = require('../src/services/api-client');
const { registerMailHandlers } = require('../src/ipc/mail-handlers');
const { mailServer } = require('./fixtures/mail-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const DAY = 24 * 60 * 60 * 1000;

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

const fakeProtect = () => ({
  available: () => true,
  encrypt: (b) => Buffer.concat([Buffer.from('ENC1'), Buffer.from(b).map((x) => x ^ 0x5a)]),
  decrypt: (b) => Buffer.from(b.subarray(4)).map((x) => x ^ 0x5a),
});

async function setup(opts = {}, extra = {}) {
  const srv = await mailServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const svc = new MailService({
    apiClient, log, getLang: () => 'de', timing: { retryMinMs: 10, retryMaxMs: 20 }, timeZone: () => 'Europe/Berlin',
    tempDir: () => tmpDir('mail-tmp-'), ...extra,
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}

const ymd = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

describe('utils/mail-pim – Mail 1.4.0', () => {
  it('summaries and cards: favourite, main number, conflicts, sources; null from servers before', () => {
    const s = mail.normalizeCardSummary({ id: 5, name: 'Sabine', favorite: true, mainPhone: '0170 1', conflicts: 2, masterId: 'x', sources: [{ addressbookId: 1, source: 'local' }, { addressbookId: 2, source: 'graph', accountId: 2 }, { source: 'evil' }] });
    assert.deepEqual([s.favorite, s.mainPhone, s.conflicts, s.masterId, s.sources], [true, '0170 1', 2, null, [{ addressbookId: 1, source: 'local', accountId: null }, { addressbookId: 2, source: 'graph', accountId: 2 }]]);
    const old = mail.normalizeCardSummary({ id: 5, name: 'Sabine' });
    assert.deepEqual([old.favorite, old.conflicts, old.sources, old.masterId], [null, null, null, null], 'a server before 1.4.0: the new parts stay hidden');
    const c = mail.normalizeCard({
      id: 5, favorite: false, mainPhone: { value: '0170 1', type: 'cell' }, mainPhoneChosen: true,
      sources: [{ id: 5, addressbookId: 1, addressbook: 'Meine Kontakte', source: 'local' }, { id: 7, addressbookId: 2, addressbook: 'Kontakte', source: 'graph', accountId: 2, account: 'max@firma.de' }, { id: 0 }],
      conflicts: [
        { id: 9, field: 'phones', type: 'mobile', value: { value: '0171 2', type: 'mobile' }, replaces: { value: '0170 1', type: 'mobile' }, source: { id: 7, addressbookId: 2, source: 'graph' }, at: 5 },
        { id: 10, field: 'company', value: 'Keller AG', replaces: 'Keller GmbH', source: { id: 7 } },
        { id: 11, field: 'birthday', value: '14.03.1981' },
        { id: 12, field: 'name', value: 'X' },
      ],
    });
    assert.deepEqual([c.favorite, c.mainPhone, c.mainPhoneChosen], [false, { value: '0170 1', type: 'other' }, true]);
    assert.deepEqual(c.sources.map((x) => [x.id, x.source, x.account]), [[5, 'local', null], [7, 'graph', 'max@firma.de']]);
    assert.deepEqual(c.conflicts.map((x) => [x.id, x.field, x.type]), [[9, 'phones', 'mobile'], [10, 'company', null]], 'unknown fields and bad values dropped');
    assert.equal(c.conflicts[0].replaces.value, '0170 1');
    assert.deepEqual([mail.normalizeCard({ id: 5 }).conflicts, mail.normalizeCard({ id: 5 }).sources, mail.normalizeCard({ id: 5 }).favorite], [null, null, null]);
  });

  it('duplicates with details and the preview, the protocol, favourites, upcoming events', () => {
    const d = mail.normalizeDuplicates({ items: [{ key: '1-2', reason: 'phone', certain: false, cards: [{ id: 1, name: 'A' }, { id: 2, name: 'B' }],
      details: [{ card: { id: 1, phones: [{ value: '0172 3', type: 'mobile' }] }, source: { id: 1, addressbookId: 1, source: 'local' } }, { card: { id: 0 } }],
      preview: { id: null, name: { display: 'Schatzimausi 💞' }, phones: [{ value: '0172 3', type: 'mobile' }], photoFrom: 2, sources: [{ id: 1 }, { id: 2, source: 'graph' }], conflicts: [{ field: 'company', value: 'X', source: { id: 2 } }, { field: 'evil', value: 1 }] } }] });
    const it0 = d.items[0];
    assert.deepEqual([it0.certain, it0.details.length, it0.preview.name.display, it0.preview.photoFrom, it0.preview.sources.length, it0.preview.conflicts.length], [false, 1, 'Schatzimausi 💞', 2, 2, 1]);
    const old = mail.normalizeDuplicates({ items: [{ key: '1-2', reason: 'email', cards: [{ id: 1 }, { id: 2 }] }] }).items[0];
    assert.deepEqual([old.certain, old.details, old.preview], [null, null, null]);
    const mg = mail.normalizeMerges({ items: [{ id: 3, masterId: 5, mode: 'auto', created: true, reason: 'email', at: 9, cards: [{ id: 5, name: 'S', source: 'local' }, { id: 7, name: 'S', source: 'graph', removed: true }] }, { id: 'x' }] });
    assert.deepEqual([mg.items.length, mg.items[0].mode, mg.items[0].created, mg.items[0].undoneAt, mg.items[0].cards[1].removed], [1, 'auto', true, null, true]);
    assert.equal(mail.normalizeMerge({ id: 3, mode: 'evil', reason: 'evil' }).mode, 'manual');
    const f = mail.normalizeFavorites({ items: [{ id: 2, name: 'Tim', phone: { value: '0170 1', type: 'mobile' }, photo: true, photoEtag: 'p1' }, { id: 3, name: '', email: 'anna@x.de' }, { id: -1 }] });
    assert.deepEqual(f.items.map((x) => [x.id, x.name, x.phone && x.phone.value, x.email]), [[2, 'Tim', '0170 1', null], [3, 'anna@x.de', null, 'anna@x.de']]);
    const u = mail.normalizeUpcoming({ timeZone: 'Europe/Berlin', today: '2026-10-31', more: 3, items: [
      { key: '301', eventId: 301, calendarId: 3, color: '#b79cff', title: 'Projekt', start: 1, end: 2, allDay: false, day: '2026-10-31', online: 'https://teams.microsoft.com/x', myResponse: 'organizer' },
      { key: 'bday:403:2026', overlayId: 'birthdays', title: 'Anna', start: 1, end: 2, allDay: true, startDate: '2026-11-01', endDate: '2026-11-01', day: '2026-11-01', online: 'javascript:x' },
      { key: '../x', start: 1, end: 2 }, { key: 'y', title: 'no times' },
    ] });
    assert.deepEqual([u.timeZone, u.today, u.more, u.items.length], ['Europe/Berlin', '2026-10-31', 3, 2]);
    assert.deepEqual([u.items[0].color, u.items[0].online, u.items[1].overlayId, u.items[1].startDate, u.items[1].online], ['#B79CFF', 'https://teams.microsoft.com/x', 'birthdays', '2026-11-01', null]);
    assert.deepEqual([u.items[0].occurrence, mail.normalizeUpcoming({ items: [{ key: '304:1730800800000', eventId: 304, start: 1, end: 2 }] }).items[0].occurrence], [null, '1730800800000'], 'a series\' occurrence from its key');
    assert.deepEqual([mail.upcomingQuery({}), mail.upcomingQuery({ days: 7, limit: 20 }), mail.upcomingQuery({ days: 8 }), mail.upcomingQuery({ limit: '5' })], [{ days: 2, limit: 8 }, { days: 7, limit: 20 }, null, null]);
    assert.deepEqual(mail.normalizeWriteBack([{ id: 7, addressbookId: 2, ok: true }, { id: 8, addressbookId: 3, ok: false, code: 'read_only' }, { id: 9, ok: 'yes' }, { id: 0 }]),
      [{ id: 7, addressbookId: 2, ok: true, code: null }, { id: 8, addressbookId: 3, ok: false, code: 'read_only' }, { id: 9, addressbookId: null, ok: false, code: 'error' }]);
  });

  it('bodies, live events and the offline list', () => {
    assert.deepEqual(mail.mergeBody({ ids: [1, 2] }), { ids: [1, 2] }, 'primaryId only a hint since 1.4.0');
    assert.equal(mail.mergeBody({ ids: [1, 2], primaryId: 3 }), null);
    assert.deepEqual(mail.cardBody({ favorite: true }, { patch: true }), { favorite: true });
    assert.deepEqual(mail.cardBody({ mainPhone: ' 0170 1 ' }, { patch: true }), { mainPhone: '0170 1' });
    assert.deepEqual(mail.cardBody({ mainPhone: null }, { patch: true }), { mainPhone: null });
    assert.equal(mail.cardBody({ mainPhone: 'abc' }, { patch: true }), null);
    assert.equal(mail.cardBody({ favorite: 'ja' }, { patch: true }), null);
    assert.equal(mail.cardBody({ favorite: true }), null, 'not for a new contact');
    assert.deepEqual([mail.previewBody({ ids: [1, 2] }), mail.previewBody({ ids: [1] }), mail.previewBody({ ids: [1, 'x'] })], [{ ids: [1, 2] }, null, null]);
    assert.deepEqual([mail.unmergeBody({ ids: [7] }), mail.unmergeBody({}), mail.unmergeBody({ ids: [] }), mail.unmergeBody({ keepMaster: 'yes' }), mail.unmergeBody({ ids: [7], keepMaster: true }, { withIds: false })],
      [{ ids: [7] }, {}, null, null, { keepMaster: true }]);
    assert.deepEqual([mail.acceptBody({}), mail.acceptBody({ mode: 'add' }), mail.acceptBody({ mode: 'merge' })], [{}, { mode: 'add' }, null]);
    assert.deepEqual([mail.favoritesBody({ ids: [3, 2] }), mail.favoritesBody({ ids: [] }), mail.favoritesBody({ ids: Array.from({ length: 51 }, (_, i) => i + 1) }), mail.favoritesBody({ ids: [1, 'x'] })],
      [{ ids: [3, 2] }, { ids: [] }, null, null]);
    assert.deepEqual([mail.deleteCardQuery({}), mail.deleteCardQuery({ linked: 'delete' }), mail.deleteCardQuery({ linked: 'all' })], [{}, { linked: 'delete' }, null]);
    assert.deepEqual(mail.normalizeContactsLive({ kind: 'merged', masterId: 5, contactIds: [5, 7], auto: true }), { kind: 'merged', masterId: 5, contactIds: [5, 7], auto: true });
    assert.deepEqual(mail.normalizeContactsLive({ kind: 'conflicts', contactIds: [5] }), { kind: 'conflicts', contactIds: [5] });
    assert.deepEqual(mail.normalizeContactsLive({ kind: 'favorites', x: 1 }), { kind: 'favorites' });
    assert.equal(mail.normalizeContactsLive({ kind: 'later' }), null);
    const items = [{ id: 1, name: 'A', sortKey: 'A', linked: [], masterId: null }, { id: 2, name: 'A', sortKey: 'A', linked: [], masterId: 1, addressbookId: 2 }];
    assert.deepEqual(mail.filterCards(items, {}).map((x) => x.id), [1], 'a linked card not in the list of all contacts');
    assert.deepEqual(mail.filterCards(items, { book: 2 }).map((x) => x.id), [2], 'but in its address book');
  });
});

describe('MailService – contacts with the GC contact as the master (Mail 1.4.0)', () => {
  it('the list: only masters, sources and the hint dot; a conflict taken over or dismissed', async () => {
    const { svc, srv } = await setup({ contactsMaster: true });
    const seen = [];
    svc.on('contacts', (x) => seen.push(x));
    const all = await svc.cards({});
    assert.ok(!all.items.some((c) => c.id === 401), 'the linked Outlook card is not listed');
    const s = all.items.find((c) => c.id === 405);
    assert.deepEqual([s.conflicts, s.sources.map((x) => x.source), s.favorite, s.phone], [1, ['local', 'graph'], false, '0170 1234567']);
    assert.deepEqual(all.items.filter((c) => c.favorite).map((c) => c.id).sort(), [402, 403]);
    const card = (await svc.card(405)).card;
    assert.deepEqual(card.sources.map((x) => [x.id, x.addressbook, x.account]), [[405, 'Meine Kontakte', null], [401, 'Firma · M365', 'max@firma.de']]);
    assert.deepEqual([card.conflicts.length, card.conflicts[0].value.value, card.conflicts[0].replaces.value], [1, '0171 2345678', '0170 1234567']);
    // "Übernehmen" replaces the number of the master
    const acc = await svc.acceptConflict(405, card.conflicts[0].id);
    assert.deepEqual([acc.ok, acc.card.conflicts.length, acc.card.phones.map((p) => p.value)], [true, 0, ['0171 2345678', '0221 3004012']]);
    assert.equal(srv.state.pim.lastAccept.mode, 'replace');
    assert.deepEqual(seen.at(-1), { kind: 'changed', addressbookId: 1, contactIds: [405] });
    await assert.rejects(svc.acceptConflict(405, card.conflicts[0].id), { code: 'not_found' }, 'done already');
    // "Verwerfen"
    srv.state.pim.conflicts.push({ id: 952, cardId: 405, sourceId: 401, field: 'company', type: null, value: 'Keller AG', replaces: 'Keller GmbH', at: Date.now() });
    const dis = await svc.dismissConflict(405, 952);
    assert.deepEqual([dis.card.company, dis.card.conflicts.length, srv.state.pim.dismissed.length], ['Keller GmbH', 0, 1]);
    assert.deepEqual((await svc.conflicts()).items, []);
  });

  it('duplicates with details: the uncertain case with its cards and the preview; merge, the protocol, undo', async () => {
    const { svc, srv } = await setup({ contactsMaster: true });
    const d = await svc.duplicates({ details: true });
    assert.equal(srv.state.requests.at(-1).query.details, '1');
    assert.equal(d.items.length, 1);
    const x = d.items[0];
    assert.deepEqual([x.reason, x.certain, x.cards.map((c) => c.id).sort()], ['phone', false, [407, 408]]);
    assert.deepEqual(x.details.map((e) => [e.card.id, e.source.source]).sort(), [[407, 'graph'], [408, 'local']]);
    assert.deepEqual([x.preview.name.display, x.preview.id, x.preview.photoFrom, x.preview.phones.length, x.preview.emails[0].value],
      ['Schatzimausi 💞', 408, 407, 2, 'sabrina@example.com'], 'the GC card stays, the name with the emoji wins');
    const pv = await svc.mergePreview([407, 408]);
    assert.equal(pv.preview.name.display, 'Schatzimausi 💞');
    await svc.cards({});
    const mg = await svc.merge({ ids: [407, 408] });
    assert.deepEqual([mg.card.id, mg.card.sources.length, typeof mg.mergeId], [408, 2, 'number']);
    assert.equal(srv.state.pim.lastMerge.primaryId, undefined, 'no primary needed');
    assert.ok(!(await svc.cards({})).items.some((c) => c.id === 407), 'the account card is linked');
    const prot = await svc.merges();
    assert.deepEqual(prot.items.map((m) => [m.mode, m.masterId]), [['manual', 408], ['auto', 405]]);
    // "Rückgängig" of the automatic merge: the Outlook card on its own again
    const seen = [];
    svc.on('contacts', (e) => seen.push(e));
    const un = await svc.undoMerge(901);
    assert.deepEqual([un.ok, un.card.id, un.unlinked], [true, 405, [401]]);
    assert.equal(seen.at(-1).kind, 'merged');
    assert.ok((await svc.cards({})).items.some((c) => c.id === 401), 'shown again');
    await assert.rejects(svc.undoMerge(901), { code: 'not_found' });
    // "Verknüpfung lösen" of one source
    const lo = await svc.unmerge(408, { ids: [407] });
    assert.deepEqual([lo.unlinked, lo.card.sources.length, srv.state.pim.lastUnmerge.ids], [[407], 1, [407]]);
    // the certain duplicates now
    srv.state.pim.cards.get(406).emails.push({ value: 'tim@firma.de', type: 'work', primary: false });
    srv.state.pim.cards.get(406).name = { ...srv.state.pim.cards.get(406).name, display: '', given: '', family: '' };
    const auto = await svc.autoMerge();
    assert.equal(auto.merged, 1);
    assert.equal(auto.items[0].mode, 'auto');
  });

  it('editing: writeBack, favourite and main number, deleting with the linked cards', async () => {
    const { svc, srv } = await setup({ contactsMaster: true });
    const seen = [];
    svc.on('contacts', (x) => seen.push(x));
    const c = (await svc.card(405)).card;
    const up = await svc.updateCard(405, { emails: [c.emails[0]], etag: c.etag });
    assert.deepEqual(up.writeBack, [{ id: 401, addressbookId: 2, ok: true, code: null }], 'a value taken over from Outlook goes back there');
    srv.state.pim.books[1].writable = false;
    const up2 = await svc.updateCard(405, { phones: [{ value: '0170 1234567', type: 'mobile' }] });
    assert.deepEqual(up2.writeBack, [{ id: 401, addressbookId: 2, ok: false, code: 'read_only' }], '"Nicht bei <Konto> geändert"');
    const plain = await svc.updateCard(402, { company: 'X' });
    assert.deepEqual(plain.writeBack, []);
    const fav = await svc.setFavorite(405, true);
    assert.equal(fav.card.favorite, true);
    assert.deepEqual(srv.state.pim.lastCardBody, { favorite: true });
    assert.equal(seen.at(-1).kind, 'favorites');
    assert.deepEqual((await svc.favorites()).items.map((x) => x.id), [402, 403, 405]);
    const main = await svc.setMainPhone(408, '0221 777888');
    assert.deepEqual([main.card.mainPhone.value, main.card.mainPhoneChosen], ['0221 777888', true]);
    await assert.rejects(svc.setMainPhone(408, '0999 1'), { code: 'invalid' });
    assert.equal((await svc.cards({})).items.find((x) => x.id === 408).phone, '0221 777888', 'the list shows the main number');
    assert.equal((await svc.setMainPhone(408, null)).card.mainPhoneChosen, false);
    const order = await svc.setFavorites([403, 402]);
    assert.deepEqual(order.items.map((x) => x.id), [403, 402]);
    // a read-only account card: only the favourite (GateControl's own)
    assert.equal((await svc.setFavorite(404, true)).card.favorite, true);
    // deleting a master: its linked cards at their providers too
    srv.state.pim.books[1].writable = true;
    assert.equal((await svc.deleteCard(405, { linked: 'delete' })).ok, true);
    assert.deepEqual(srv.state.pim.lastDelete, { id: 405, linked: 'delete' });
    assert.ok(!srv.state.pim.cards.has(401));
    await assert.rejects(svc.deleteCard(402, { linked: 'all' }), { code: 'invalid' });
  });

  it('favourites and the calendar widget: offline from the cache', async () => {
    const cacheDir = tmpDir('mail-master-');
    const { svc, srv } = await setup({ contactsMaster: true }, { cacheDir: () => cacheDir, protect: fakeProtect() });
    const fav = await svc.favorites();
    assert.deepEqual(fav.items.map((x) => [x.id, x.name, x.phone && x.phone.value]), [[402, 'Tim Brandt', '0170 1112223'], [403, 'Anna Lang', null]]);
    const up = await svc.upcoming({});
    assert.deepEqual(srv.state.requests.at(-1).query, { days: '2', limit: '8', lang: 'de' });
    const tomorrow = ymd(Date.now() + DAY);
    const t2 = up.items.filter((x) => x.day === tomorrow);
    assert.deepEqual(t2.map((x) => x.title), ['Anna Lang (40)', 'Zahnarzt'], 'tomorrow: the birthday (all day) first');
    assert.equal(t2[0].overlayId, 'birthdays');
    assert.equal(up.today, ymd(Date.now()));
    const few = await svc.upcoming({ days: 2, limit: 1 });
    assert.equal(few.items.length, 1);
    assert.ok(few.more >= 1);
    await assert.rejects(svc.upcoming({ days: 9 }), { code: 'invalid' });
    await svc.cache.flush();
    srv.down = true;
    const off = await svc.upcoming({});
    assert.deepEqual([off.offline, off.items.length], [true, up.items.length]);
    const offFav = await svc.favorites();
    assert.deepEqual([offFav.offline, offFav.items.length], [true, 2]);
  });

  it('a server before 1.4.0: the new paths are unsupported, the new fields null', async () => {
    const { svc } = await setup();
    assert.deepEqual(await svc.favorites(), { ok: true, unsupported: true, items: [] });
    assert.deepEqual((await svc.upcoming({})).unsupported, true);
    assert.deepEqual(await svc.merges(), { ok: true, unsupported: true, items: [] });
    assert.deepEqual(await svc.conflicts(), { ok: true, unsupported: true, items: [] });
    const all = await svc.cards({});
    assert.deepEqual([all.items[0].favorite, all.items[0].sources, all.items[0].conflicts], [null, null, null]);
    const card = (await svc.card(401)).card;
    assert.deepEqual([card.conflicts, card.sources, card.favorite], [null, null, null]);
    const d = await svc.duplicates({ details: true });
    assert.deepEqual([d.items[0].certain, d.items[0].details, d.items[0].preview], [null, null, null]);
    const up = await svc.updateCard(402, { company: 'X' });
    assert.deepEqual(up.writeBack, []);
  });
});

describe('mail IPC – Mail 1.4.0', () => {
  it('checks the arguments of the new channels', async () => {
    const { svc } = await setup({ contactsMaster: true });
    const handlers = {};
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('mail:card:merge', { ids: [407, 408] })).ok, true, 'without primaryId');
    assert.equal((await call('mail:card:merge', { ids: [1, 2], primaryId: 'x' })).code, 'invalid');
    assert.equal((await call('mail:card:preview', { ids: [1] })).code, 'invalid');
    assert.equal((await call('mail:card:duplicates', { details: true })).ok, true);
    assert.equal((await call('mail:card:merges', { limit: 999 })).code, 'invalid');
    assert.equal((await call('mail:card:merges', {})).items.length, 2);
    assert.equal((await call('mail:card:merge:undo', { id: 901, keepMaster: 'ja' })).code, 'invalid');
    assert.equal((await call('mail:card:unmerge', { id: 405, ids: ['x'] })).code, 'invalid');
    assert.equal((await call('mail:card:conflict:accept', { id: 405, conflictId: 951, mode: 'all' })).code, 'invalid');
    assert.equal((await call('mail:card:conflict:accept', { id: 405, conflictId: 951, mode: 'add' })).card.phones.length, 3, '"Zusätzlich"');
    assert.equal((await call('mail:card:conflict:dismiss', { id: 405 })).code, 'invalid');
    assert.equal((await call('mail:card:favorite', { id: 405, on: 1 })).code, 'invalid');
    assert.equal((await call('mail:card:favorite', { id: 405, on: true })).card.favorite, true);
    assert.equal((await call('mail:card:main-phone', { id: 405, value: 5 })).code, 'invalid');
    assert.equal((await call('mail:card:main-phone', { id: 405, value: '0221 3004012' })).card.mainPhone.value, '0221 3004012');
    assert.equal((await call('mail:favorites:set', { ids: [1, 'x'] })).code, 'invalid');
    assert.deepEqual((await call('mail:favorites:set', { ids: [405] })).items.map((x) => x.id), [405]);
    assert.deepEqual((await call('mail:favorites')).items.map((x) => x.id), [405]);
    assert.equal((await call('mail:upcoming', { days: 0 })).code, 'invalid');
    assert.equal((await call('mail:upcoming', { days: 1, limit: 3 })).ok, true);
    assert.equal((await call('mail:card:delete', { id: 402, linked: 'everything' })).code, 'invalid');
    assert.equal((await call('mail:card:delete', { id: 402, linked: 'keep' })).ok, true);
  });
});
