'use strict';

// Mail Phase 2 (calendar and contacts in the plugin gatecontrol-mail, client API "C3"): the pure helpers
// (utils/mail-pim.js — cleaned answers, request bodies, live events, the offline search of contacts), the API and the
// service (services/mail.js — the device's time zone, ranges and events with the offline cache, conflicts, invitations,
// contacts kept current with `since`, photos, vCard files through the dialogs, groups, calls, live events, push
// clicks) and the IPC (mail:cal:*, mail:event:*, mail:card:*, …) against the fake server (fixtures/mail-pim-server.js).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
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
const { mailServer, PNG } = require('./fixtures/mail-server');

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

const week = () => { const d = new Date(); d.setHours(0, 0, 0, 0); const from = d.getTime() - DAY; return { from, to: from + 8 * DAY }; };

describe('utils/mail-pim', () => {
  it('calendars, overlays and settings are cleaned', () => {
    const c = mail.normalizeCalendars({
      calendars: [{ id: 1, source: 'graph', accountId: '2', name: 'Kalender', color: '#abcdef', kind: 'business', writable: true, maxReminders: 1, state: 'consent_required', error: { code: 'consent_required', at: 5 } }, { id: 0 }, { id: 3, source: 'evil', color: 'red' }],
      overlays: [{ id: 'familie', name: 'Familie', visible: true }, { id: 'alltag:7', name: 'Abfuhr' }, { id: '../x' }],
      prefs: { view: 'year', weekStart: 0, defaultReminder: null, timeZone: 'Europe/Berlin; rm -rf' },
      consent: [{ accountId: 2, missing: ['Calendars.ReadWrite'] }, { accountId: 'x' }],
    });
    assert.equal(c.calendars.length, 2);
    assert.deepEqual([c.calendars[0].color, c.calendars[0].accountId, c.calendars[0].maxReminders, c.calendars[0].state, c.calendars[0].error.code], ['#ABCDEF', 2, 1, 'consent_required', 'consent_required']);
    assert.deepEqual([c.calendars[1].source, c.calendars[1].color, c.calendars[1].visible], ['local', '#46E0A0', true]);
    assert.deepEqual(c.overlays.map((o) => [o.id, o.source]), [['familie', 'familie'], ['alltag:7', 'alltag']]);
    assert.deepEqual([c.prefs.view, c.prefs.weekStart, c.prefs.defaultReminder, c.prefs.timeZone, c.prefs.allDayReminder], ['week', 0, null, null, 1080]);
    assert.deepEqual(c.consent, [{ accountId: 2, missing: ['Calendars.ReadWrite'] }]);
  });

  it('occurrences: the key from id and occurrence, all-day dates inclusive, enums', () => {
    const o = mail.normalizeOccurrence({ key: 'evil', eventId: 7, occurrence: '1730800800000', start: 1730800800000, end: 1730804400000, status: 'x', myResponse: 'needs_action', attendees: '4', online: { url: 'javascript:alert(1)' } });
    assert.deepEqual([o.key, o.status, o.myResponse, o.attendees, o.online], ['7:1730800800000', 'confirmed', 'needs_action', 4, null]);
    const a = mail.normalizeOccurrence({ eventId: 8, occurrence: '2026-11-04', start: 1, end: 2, allDay: true, startDate: '2026-11-04', endDate: '2026-11-03' });
    assert.deepEqual([a.key, a.startDate, a.endDate], ['8:2026-11-04', '2026-11-04', '2026-11-04']);
    assert.equal(mail.normalizeOccurrence({ eventId: 9, occurrence: '../1', start: 5 }).occurrence, null);
    const e = mail.normalizeEvents({ items: [{ eventId: 1, start: 5 }, { eventId: 0, start: 5 }], overlays: [{ key: 'bday:4:2026', overlayId: 'birthdays', start: 5 }, { key: 'x', overlayId: 'nope', start: 5 }], pending: [3, 'x', 3] });
    assert.deepEqual([e.items.length, e.overlays.length, e.overlays[0].readOnly, e.pending], [1, 1, true, [3]]);
  });

  it('an event and an invitation keep their known fields', () => {
    const ev = mail.normalizeEvent({
      eventId: 3, start: 10, end: 20, description: 'a\u0007b', organizer: { name: 'S', email: 's@x.de' }, attendees: [{ email: 'a@b.de', response: 'maybe', role: 'chair' }, { email: 'no' }],
      reminders: [15, -1, 99999999], recurrence: { rrule: 'FREQ=WEEKLY;BYDAY=TU', freq: 'weekly', byDay: ['TU', 'XX'], interval: 0, until: '2026-13-40' }, etag: '"5-1"', canEdit: true,
    });
    assert.equal(ev.description, 'ab');
    assert.deepEqual(ev.attendees, [{ name: '', email: 'a@b.de', role: 'required', response: 'needs_action', self: false, contactId: null }]);
    assert.deepEqual(ev.reminders, [15]);
    assert.deepEqual([ev.recurrence.byDay, ev.recurrence.interval, ev.recurrence.until, ev.recurrence.editable], [['TU'], 1, null, true]);
    assert.deepEqual([ev.etag, ev.canEdit, ev.readOnly], ['"5-1"', true, false]);
    assert.equal(ev.series, null, 'Mail 1.2.0: no series field');
    assert.deepEqual(mail.normalizeEvent({ eventId: 3, start: 10, series: { start: 5, end: 8, allDay: 'x' } }).series, { start: 5, end: 8, allDay: false });
    assert.equal(mail.normalizeEvent({ eventId: 3, start: 10, series: { start: 'x' } }).series, null);
    assert.deepEqual(mail.normalizeEvent({ eventId: 3, start: 10, series: { start: 5, end: 8, allDay: true, startDate: '2026-09-01', endDate: '2026-09-02' } }).series, { start: 5, end: 8, allDay: true, startDate: '2026-09-01', endDate: '2026-09-02' });
    const inv = mail.normalizeInvitation({ id: 4, start: 10, method: 'counter', state: 'weird', counts: { accepted: 3 }, proposed: { start: 30, end: 40 }, recurrence: { summary: { de: 'jeden Dienstag' } }, calendarChoices: [1, 1, 'x', 2] });
    assert.deepEqual([inv.method, inv.state, inv.counts.accepted, inv.counts.declined, inv.proposed.end, inv.recurrence.summary.en, inv.calendarChoices], ['counter', 'open', 3, 0, 40, 'jeden Dienstag', [1, 2]]);
    assert.equal(mail.normalizeInvitation({ id: 4 }), null, 'a start is needed');
  });

  it('request bodies: a new event needs its calendar, title and times; changes only what is given', () => {
    assert.equal(mail.eventBody({ title: 'X', allDay: false, start: 1, end: 2 }), null, 'no calendar');
    assert.equal(mail.eventBody({ calendarId: 1, title: ' ', allDay: false, start: 1, end: 2 }), null);
    assert.equal(mail.eventBody({ calendarId: 1, title: 'X', allDay: false, start: 3, end: 2 }), null);
    assert.equal(mail.eventBody({ calendarId: 1, title: 'X', allDay: true }), null, 'all-day needs a date');
    const b = mail.eventBody({
      calendarId: 1, title: ' Treffen\n', allDay: false, start: 1, end: 2, location: 'Raum 1', reminders: [15, 15, 60],
      recurrence: { freq: 'weekly', byDay: ['TU', 'TH'], until: '2026-12-31' }, attendees: [{ email: 'a@b.de', name: 'A' }, { email: 'A@b.de' }], online: { create: 'teams' }, bogus: 1,
    });
    assert.deepEqual(b, { calendarId: 1, title: 'Treffen', allDay: false, start: 1, end: 2, location: 'Raum 1', reminders: [15, 60], recurrence: { freq: 'weekly', interval: 1, byDay: ['TU', 'TH'], until: '2026-12-31' }, attendees: [{ email: 'a@b.de', name: 'A' }], online: { create: 'teams' } });
    assert.equal(mail.eventBody({ calendarId: 1, title: 'X', allDay: false, start: 1, end: 2, recurrence: { freq: 'weekly', until: '2026-12-31', count: 3 } }), null, 'until or count');
    assert.equal(mail.eventBody({ calendarId: 1, title: 'X', allDay: false, start: 1, end: 2, reminders: [1, 2, 3, 4] }), null);
    assert.deepEqual(mail.eventBody({ title: 'Neu', scope: 'occurrence', occurrence: '1730800800000', etag: '"1-0"' }, { patch: true }), { title: 'Neu', scope: 'occurrence', occurrence: '1730800800000', etag: '"1-0"' });
    assert.equal(mail.eventBody({ scope: 'occurrence', etag: '"1-0"' }, { patch: true }), null, 'nothing to change');
    assert.equal(mail.eventBody({ title: 'X', scope: 'occurrence' }, { patch: true }), null, 'which occurrence');
    assert.deepEqual(mail.eventBody({ recurrence: null }, { patch: true }), { recurrence: null }, 'the rule removed');
    assert.deepEqual(mail.deleteEventQuery({ scope: 'occurrence', occurrence: '2026-11-04', notify: true, comment: 'Krank' }), { scope: 'occurrence', occurrence: '2026-11-04', notify: 1, comment: 'Krank' });
    assert.equal(mail.deleteEventQuery({ scope: 'occurrence' }), null);
    assert.deepEqual(mail.respondBody({ response: 'tentative', comment: ' Später ', proposeStart: 5, proposeEnd: 9 }), { response: 'tentative', comment: 'Später', proposeStart: 5, proposeEnd: 9 });
    assert.equal(mail.respondBody({ response: 'maybe' }), null);
    assert.equal(mail.respondBody({ response: 'accepted', proposeStart: 9, proposeEnd: 5 }), null);
    assert.deepEqual(mail.respondBody({ response: 'accepted', calendarId: 3, send: false }, { invitation: true }), { response: 'accepted', calendarId: 3 });
    const q = mail.eventsQuery({ from: 1000, to: 1000 + 7 * DAY, calendars: [1, '2', 'familie', 'alltag:7'] });
    assert.deepEqual(q, { from: 1000, to: 1000 + 7 * DAY, calendars: '1,2,familie,alltag:7' });
    assert.equal(mail.eventsQuery({ from: 1000, to: 1000 + 63 * DAY }), null, '≤ 62 days');
    assert.equal(mail.eventsQuery({ from: 1000, to: 2000, calendars: ['x;y'] }), null);
    assert.deepEqual(mail.subscribeBody({ url: 'webcal://calendar.google.com/x/basic.ics', name: 'Gmail' }), { url: 'https://calendar.google.com/x/basic.ics', name: 'Gmail' });
    assert.equal(mail.subscribeBody({ url: 'http://x.de/a.ics' }), null);
    assert.equal(mail.calSettingsPatch({ view: 'year' }), null);
    assert.deepEqual(mail.calSettingsPatch({ timeZone: 'America/New_York', defaultReminder: null }), { timeZone: 'America/New_York', defaultReminder: null });
  });

  it('contacts: summaries, a card, bodies, the offline search', () => {
    const l = mail.normalizeCardList({ items: [{ id: 1, name: 'Äbel', letter: 'Ä', emails: ['a@b.de', 'bad'], groups: [3, 3] }, { id: 0 }], next: 'abc_-', version: '12', deleted: [5] });
    assert.deepEqual([l.items.length, l.items[0].letter, l.items[0].emails, l.items[0].groups, l.next, l.version, l.deleted], [1, '#', ['a@b.de'], [3], 'abc_-', 12, [5]]);
    const c = mail.normalizeCard({ id: 2, source: 'graph', readOnly: true, etag: '"v3"', name: { given: 'Sabine' }, emails: [{ value: 's@x.de', type: 'boss' }], phones: [{ value: '0171', type: 'cell' }], birthday: '--03-14', addresses: [{ street: '' }, { city: 'Köln', type: 'work' }] });
    assert.deepEqual([c.emails[0].type, c.phones[0].type, c.birthday, c.addresses.length, c.addresses[0].city, c.readOnly], ['other', 'other', '--03-14', 1, 'Köln', true]);
    assert.equal(mail.cardBody({}), null);
    assert.equal(mail.cardBody({ note: 'x' }), null, 'a new contact needs a name, a company or an address');
    assert.deepEqual(mail.cardBody({ name: { given: 'Tim ', family: '' }, emails: [{ value: 'a@b.de', type: 'work' }, { value: 'A@b.de' }], phones: [{ value: '0170 1' }], birthday: '1990-01-02' }),
      { name: { given: 'Tim' }, emails: [{ value: 'a@b.de', type: 'work', primary: false }], phones: [{ value: '0170 1', type: 'other' }], birthday: '1990-01-02' });
    assert.equal(mail.cardBody({ phones: [{ value: 'abc' }] }, { patch: true }), null);
    assert.deepEqual(mail.cardBody({ company: 'X', etag: '"v1"', addressbookId: 3 }, { patch: true }), { company: 'X', etag: '"v1"' }, 'the address book only for a new one');
    assert.deepEqual(mail.mergeBody({ ids: [1, 2], primaryId: 2, pick: { name: 1, note: 'join', photo: 9 } }), null, 'pick only among the ids');
    assert.deepEqual(mail.mergeBody({ ids: [1, 2], primaryId: 2, pick: { name: 1, note: 'join' } }), { ids: [1, 2], primaryId: 2, pick: { name: 1, note: 'join' } });
    assert.deepEqual(mail.membersBody({ add: [{ contactId: 4 }, { email: 'o@x.de', name: 'Oma' }], remove: [7] }), { add: [{ contactId: 4 }, { email: 'o@x.de', name: 'Oma' }], remove: [7] });
    assert.equal(mail.membersBody({ add: [{ email: 'no' }] }), null);
    const items = [
      { id: 1, name: 'Älbert Ötzi', sortKey: 'OTZI ALBERT', emails: [], phone: null, groups: [], linked: [3], addressbookId: 1 },
      { id: 2, name: 'Tim Brandt', sortKey: 'BRANDT TIM', company: 'Firma', emails: ['tim@firma.de'], phone: '0170 1112223', groups: [9], linked: [], addressbookId: 1 },
      { id: 3, name: 'Albert Oetzi', sortKey: 'OETZI ALBERT', emails: [], phone: null, groups: [], linked: [], addressbookId: 2 },
    ];
    assert.deepEqual(mail.filterCards(items, { q: 'ötzi' }).map((x) => x.id), [1], 'umlauts folded, a linked one only under its primary');
    assert.deepEqual(mail.filterCards(items, { q: 'otzi', book: 2 }).map((x) => x.id), [], 'in its own book by its own name');
    assert.deepEqual(mail.filterCards(items, { q: '1112' }).map((x) => x.id), [2], 'digits of the number');
    assert.deepEqual(mail.filterCards(items, { group: 9 }).map((x) => x.id), [2]);
    assert.deepEqual(mail.filterCards(items, {}).map((x) => x.id), [2, 1]);
  });

  it('accounts, me, suggestions, live events and push clicks of Phase 2', () => {
    const me = mail.normalizeMe({
      features: ['calendar', 'contacts', 'dav', 'familyOverlay', 'teleport'], microsoft: { adminConsentUrl: 'http://evil' },
      accounts: [{ id: 2, email: 'a@b.de', calendar: { sync: true, state: 'consent_required', server: 'caldav.gmx.net' }, missingScopes: ['Calendars.ReadWrite', 'bad scope'] }],
    });
    assert.deepEqual(me.features, ['mail', 'calendar', 'contacts', 'dav', 'familyOverlay']);
    assert.equal(me.microsoft.adminConsentUrl, null);
    assert.deepEqual(me.accounts[0].calendar, { sync: true, state: 'consent_required', readOnly: false, server: 'caldav.gmx.net' });
    assert.deepEqual(me.accounts[0].contacts, { sync: false, state: 'none', readOnly: false, server: null });
    assert.deepEqual(me.accounts[0].missingScopes, ['Calendars.ReadWrite']);
    const s = mail.normalizeContacts({ items: [
      { name: 'Familie', email: null, source: 'group', groupId: 5, members: [{ name: 'Oma', email: 'o@x.de' }, { name: 'X' }] },
      { name: 'Leer', source: 'group', members: [] },
      { name: 'Tim', email: 'tim@firma.de', source: 'contact', contactId: 4, photo: true },
      { name: 'Alt', email: 'alt@x.de' },
    ] });
    assert.deepEqual(s.items.map((x) => [x.source, x.email, x.members && x.members.length]), [['group', null, 1], ['contact', 'tim@firma.de', null], ['recent', 'alt@x.de', null]]);
    assert.deepEqual(mail.normalizeCalendarLive({ kind: 'changed', calendarId: '3', from: 5 }), { kind: 'changed', calendarId: 3, accountId: null, from: 5, to: null });
    assert.equal(mail.normalizeCalendarLive({ kind: 'boom' }), null);
    assert.deepEqual(mail.normalizeContactsLive({ kind: 'changed', addressbookId: 1, contactIds: [4, 'x', 4] }), { kind: 'changed', addressbookId: 1, contactIds: [4] });
    assert.deepEqual(mail.pushTarget(mail.REMINDER_TOPIC, { calendar: { eventId: 7, occurrence: '1730800800000' } }), { kind: 'event', eventId: 7, occurrence: '1730800800000' });
    assert.deepEqual(mail.pushTarget(mail.REMINDER_TOPIC, { calendar: { eventId: 7, occurrence: '../x' } }), { kind: 'event', eventId: 7, occurrence: null });
    assert.deepEqual(mail.pushTarget(mail.INVITE_TOPIC, { calendar: { invitationId: 9 } }), { kind: 'invitation', invitationId: 9 });
    assert.equal(mail.pushTarget(mail.MAIL_TOPIC, { calendar: { eventId: 7 } }), null);
    const sum = mail.normalizeSummary({ id: 1, accountId: 1, invite: 'request' });
    assert.equal(sum.invite, 'request');
    assert.equal(mail.normalizeSummary({ id: 1, accountId: 1, invite: 'party' }).invite, null);
  });
});

describe('MailService – calendar', () => {
  it('the calendars: the device\'s time zone is set when it differs; the offline window is filled', async () => {
    const { svc, srv } = await setup({}, { timeZone: () => 'America/New_York' });
    const r = await svc.calendars();
    assert.equal(r.ok, true);
    assert.deepEqual(r.calendars.map((c) => c.name), ['Privat', 'Firma', 'Kalender', 'Feiertage']);
    assert.deepEqual(srv.state.pim.lastCalSettings, { timeZone: 'America/New_York' });
    assert.equal(r.prefs.timeZone, 'America/New_York');
    srv.state.pim.lastCalSettings = null;
    await svc.calendars();
    assert.equal(srv.state.pim.lastCalSettings, null, 'once');
    // −30 … +90 days in two ranges of the visible calendars and overlays
    const asked = () => srv.state.requests.filter((x) => x.path.endsWith('/api/events'));
    for (let i = 0; i < 100 && asked().length < 2; i += 1) await new Promise((res) => setTimeout(res, 10));
    assert.equal(asked().length, 2);
    assert.equal(asked()[0].query.calendars, '1,2,3,familie,birthdays');
    assert.ok(Number(asked()[0].query.to) - Number(asked()[0].query.from) <= 62 * DAY);
  });

  it('events of a range, an event with its description as a frame document, offline from the cache', async () => {
    const cacheDir = tmpDir('mail-pim-cache-');
    const { svc, srv } = await setup({}, { cacheDir: () => cacheDir, protect: fakeProtect() });
    const w = week();
    const r = await svc.events({ ...w, calendars: [1, 2, 3, 'familie', 'birthdays'] });
    const titles = r.items.map((x) => x.title);
    for (const t of ['Projektbesprechung', 'Zahnarzt', 'Sprint-Review', 'Training', 'Messe']) assert.ok(titles.includes(t), t);
    assert.ok(r.items.find((x) => x.title === 'Training').occurrence, 'a series: one occurrence');
    assert.deepEqual(r.overlays.map((x) => x.title).sort(), ['Anna Lang (40)', 'Tim abholen']);
    await assert.rejects(svc.events({ from: w.from, to: w.from + 70 * DAY }), { code: 'invalid' });
    const e = await svc.event(301);
    assert.equal(e.event.title, 'Projektbesprechung');
    assert.equal(e.event.attendees.find((a) => a.email === 'sabine@firma.de').contactId, 401);
    assert.ok(e.doc.includes('<b>Agenda</b>') && e.docDark.includes('Agenda'));
    assert.ok(e.doc.includes("default-src 'none'"), 'the frame\'s own CSP');
    const tr = r.items.find((x) => x.title === 'Training');
    const occ = await svc.event(tr.eventId, tr.occurrence);
    assert.equal(occ.event.occurrence, tr.occurrence);
    await svc.cache.flush();
    // offline: the range and the event come from the cache, marked offline
    srv.down = true;
    const off = await svc.events({ ...w, calendars: [1, 2, 3, 'familie', 'birthdays'] });
    assert.equal(off.offline, true);
    assert.equal(off.items.length, r.items.length);
    const part = await svc.events({ from: w.from, to: w.from + 2 * DAY, calendars: [1] });
    assert.ok(part.offline && part.items.every((x) => x.calendarId === 1 && x.start < w.from + 2 * DAY), 'a part of a cached range');
    assert.equal((await svc.event(301)).offline, true);
    await assert.rejects(svc.event(302));
    // on disk only encrypted
    const files = fs.readdirSync(path.join(cacheDir, fs.readdirSync(cacheDir)[0]));
    assert.ok(files.includes('pim.bin'));
    assert.ok(!fs.readFileSync(path.join(cacheDir, fs.readdirSync(cacheDir)[0], 'pim.bin')).includes(Buffer.from('Projektbesprechung')));
  });

  it('new, changed (conflict → current), one occurrence deleted, an answer; live events after each', async () => {
    const { svc, srv } = await setup();
    const seen = [];
    svc.on('calendar', (c) => seen.push(c));
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() + 1); d.setHours(9);
    const made = await svc.createEvent({ calendarId: 1, title: 'Neu', allDay: false, start: d.getTime(), end: d.getTime() + 3600000, attendees: [{ email: 'tim@firma.de', name: 'Tim' }], reminders: [15] });
    assert.deepEqual([made.ok, made.event.title, made.sent.mail], [true, 'Neu', 1]);
    assert.deepEqual(srv.state.pim.lastEventBody.attendees, [{ email: 'tim@firma.de', name: 'Tim' }]);
    assert.deepEqual(seen.at(-1), { kind: 'changed', calendarId: 1, accountId: null, from: null, to: null });
    const ev = (await svc.event(made.event.eventId)).event;
    const ok = await svc.updateEvent(ev.eventId, { title: 'Neuer Titel', etag: ev.etag });
    assert.equal(ok.event.title, 'Neuer Titel');
    const stale = await svc.updateEvent(ev.eventId, { title: 'Meins', etag: ev.etag });
    assert.deepEqual([stale.ok, stale.code, stale.current.title], [false, 'conflict', 'Neuer Titel']);
    const again = await svc.updateEvent(ev.eventId, { title: 'Meins', etag: stale.current.etag });
    assert.equal(again.event.title, 'Meins', '"Meine Änderung erneut anwenden"');
    const series = (await svc.events({ ...week(), calendars: [1] })).items.find((x) => x.title === 'Training');
    const del = await svc.deleteEvent(series.eventId, { scope: 'occurrence', occurrence: series.occurrence });
    assert.equal(del.ok, true);
    assert.deepEqual(srv.state.pim.lastDelete, { scope: 'occurrence', occurrence: series.occurrence, lang: 'de' });
    assert.ok(!(await svc.events({ ...week(), calendars: [1] })).items.some((x) => x.key === series.key));
    const resp = await svc.respondEvent(303, { response: 'tentative', comment: 'Später' });
    assert.equal(resp.event.myResponse, 'tentative');
    await assert.rejects(svc.createEvent({ calendarId: 4, title: 'X', allDay: false, start: 1, end: 2 }), { code: 'read_only' });
    await assert.rejects(svc.createEvent({ calendarId: 1, title: 'X', allDay: false, start: 1, end: 2, online: { create: 'teams' } }), (e) => e.code === 'not_supported' && e.detail.what === 'teams');
    // calendars: own, subscription, overlay, settings
    const cal = await svc.createCalendar({ name: 'Sport', color: '#5FD3E0' });
    assert.equal(cal.calendar.name, 'Sport');
    assert.equal((await svc.updateCalendar(cal.calendar.id, { visible: false })).calendar.visible, false);
    const sub = await svc.subscribe({ url: 'webcal://calendar.google.com/x/basic.ics', name: 'Gmail' });
    assert.equal(srv.state.pim.lastSubscribe.url, 'https://calendar.google.com/x/basic.ics');
    assert.equal(sub.calendar.writable, false);
    await assert.rejects(svc.deleteCalendar(3), (e) => e.code === 'not_supported');
    assert.equal((await svc.updateOverlay('familie', { visible: false })).overlay.visible, false);
    assert.equal((await svc.calSettings({ view: 'month' })).prefs.view, 'month');
    assert.equal(seen.filter((x) => x.kind === 'calendars').length >= 4, true);
  });

  it('an invitation in a mail: the card, an answer into a chosen calendar, the AI to-do into the own calendar', async () => {
    const { svc, srv } = await setup({ invite: true });
    const list = await svc.list({ box: 2 });
    assert.equal(list.items.find((x) => x.id === 106).invite, 'request');
    const m = await svc.message(106);
    const inv = m.message.invite;
    assert.deepEqual([inv.id, inv.title, inv.organizer.email, inv.calendarChoices, inv.counts.accepted, inv.comment], [701, 'Sprint-Review', 'sabine@firma.de', [1, 2, 3], 1, 'Bitte die Zahlen mitbringen.']);
    const r = await svc.respondInvitation(701, { response: 'accepted', comment: 'Gern', calendarId: 1 });
    assert.deepEqual([r.ok, r.invitation.state, r.invitation.myResponse, r.event.calendarId], [true, 'answered', 'accepted', 1]);
    assert.deepEqual(srv.state.pim.lastInviteRespond, { response: 'accepted', comment: 'Gern', calendarId: 1 });
    assert.equal((await svc.invitations('all')).items.length, 1);
    assert.equal((await svc.dismissInvitation(701, { decline: true })).ok, true);
    assert.deepEqual(srv.state.pim.lastDismiss, { decline: true });
    const todo = await svc.todo(101, 0, { action: 'calendar', calendarId: 1 });
    assert.deepEqual([todo.where, todo.eventId], ['Privat · 28.11.', 999]);
    assert.deepEqual(srv.state.todos.at(-1).body, { action: 'calendar', calendarId: 1 });
    // without the calendar right of Microsoft: no card, the list still says "Einladung"
    srv.state.features = srv.state.features.filter((f) => f !== 'calendar');
    assert.equal((await svc.message(106)).message.invite, null);
    await assert.rejects(svc.calendars(), (e) => e.code === 'feature_off' && e.status === 403);
  });

  it('live events and push clicks', async () => {
    const pushClient = new EventEmitter();
    const nc = new EventEmitter();
    let resolver = null;
    nc.addClickRoute = (route, fn) => { resolver = fn; return () => { resolver = null; }; };
    const { svc } = await setup({}, { pushClient, notificationCenter: nc });
    const cal = [];
    const con = [];
    svc.on('calendar', (x) => cal.push(x));
    svc.on('contacts', (x) => con.push(x));
    const send = (type, data) => pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-mail', type, data } });
    send('calendar', { kind: 'changed', calendarId: 3, accountId: 2, from: 1, to: 2 });
    send('calendar', { kind: 'invitation', invitationId: 701, messageId: 106 });
    send('calendar', { kind: 'nonsense' });
    send('contacts', { kind: 'changed', addressbookId: 1, contactIds: [402] });
    send('contacts', { kind: 'groups' });
    assert.deepEqual(cal, [{ kind: 'changed', calendarId: 3, accountId: 2, from: 1, to: 2 }, { kind: 'invitation', invitationId: 701, messageId: 106 }]);
    assert.deepEqual(con, [{ kind: 'changed', addressbookId: 1, contactIds: [402] }, { kind: 'groups' }]);
    pushClient.emit('hello');
    assert.deepEqual([cal.at(-1), con.at(-1)], [{ kind: 'calendars' }, { kind: 'addressbooks' }], 'after a reconnect everything loads again');
    assert.deepEqual(resolver({ topic: mail.REMINDER_TOPIC, data: { calendar: { eventId: 301, occurrence: null } } }), { kind: 'event', eventId: 301, occurrence: null });
    assert.deepEqual(resolver({ topic: mail.INVITE_TOPIC, data: { calendar: { invitationId: 701 } } }), { kind: 'invitation', invitationId: 701 });
  });
});

describe('MailService – contacts', () => {
  it('all summaries once, then only the changes (since); searched on this PC; offline from the cache', async () => {
    const cacheDir = tmpDir('mail-pim-cards-');
    const { svc, srv } = await setup({}, { cacheDir: () => cacheDir, protect: fakeProtect() });
    const books = await svc.addressbooks();
    assert.deepEqual(books.items.map((b) => [b.name, b.count, b.writable]), [['Meine Kontakte', 4, true], ['Firma · M365', 1, true], ['Privat · GMX', 1, false]]);
    assert.deepEqual(books.groups.map((g) => [g.name, g.count]), [['Team Vertrieb', 2], ['Familie', 2]]);
    const all = await svc.cards({});
    assert.deepEqual(all.items.map((c) => c.name), ['Bernd Albers', 'Tim Brandt', 'Sabine Keller', 'Sabine Keller', 'Anna Lang', 'Älbert Ötzi']);
    assert.equal(all.items[0].letter, 'A');
    const asked = () => srv.state.requests.filter((x) => x.path.endsWith('/api/cards'));
    assert.equal(asked().length, 1);
    assert.equal(asked()[0].query.since, undefined, 'the whole list first');
    assert.deepEqual((await svc.cards({ q: 'otzi' })).items.map((c) => c.id), [406]);
    assert.deepEqual((await svc.cards({ q: 'keller', book: 2 })).items.map((c) => c.id), [401]);
    assert.deepEqual((await svc.cards({ group: 502 })).items.map((c) => c.id), [402]);
    assert.equal(asked().length, 1, 'searched on this PC');
    // a change elsewhere (live event): only the changes are asked for
    srv.state.pim.cards.get(403).company = 'Lang & Co';
    srv.state.pim.cards.get(403).version = (srv.state.pim.version += 1);
    srv.state.pim.cards.delete(404);
    srv.state.pim.tombstones.push({ id: 404, version: (srv.state.pim.version += 1) });
    svc._cardsStale = true;
    const after = await svc.cards({});
    assert.equal(asked().at(-1).query.since, String(all.version));
    assert.ok(!after.items.some((c) => c.id === 404), 'deleted');
    assert.equal(after.items.find((c) => c.id === 403).company, 'Lang & Co');
    const card = await svc.card(401);
    assert.deepEqual([card.card.name.given, card.card.phones.length, card.card.groups, card.card.source], ['Sabine', 2, [501], 'graph']);
    const ph = await svc.cardPhoto(401, 'ph401');
    assert.equal(ph.url, `data:image/png;base64,${PNG.toString('base64')}`);
    await svc.cardPhoto(401, 'ph401');
    assert.equal(srv.state.requests.filter((x) => x.path.endsWith('/cards/401/photo')).length, 1, 'kept by its etag');
    await svc.cache.flush();
    srv.down = true;
    svc._cardSyncAt = 0;   // asked again after a while: no server
    const off = await svc.cards({ q: 'brandt' });
    assert.deepEqual([off.offline, off.items.map((c) => c.id)], [true, [402]]);
    assert.equal((await svc.card(401)).offline, true);
    assert.ok((await svc.cardPhoto(401, 'ph401')).url.startsWith('data:image/png'));
  });

  it('new, edited (conflict → current), deleted; read only; lookup, activity, draft, duplicates and merge; groups', async () => {
    const { svc, srv } = await setup();
    const seen = [];
    svc.on('contacts', (x) => seen.push(x));
    const made = await svc.createCard({ name: { given: 'Nina', family: 'Neu' }, emails: [{ value: 'nina@x.de', type: 'home' }], groups: [502] });
    assert.deepEqual([made.card.name.display, made.card.addressbookId, made.card.groups], ['Nina Neu', 1, [502]]);
    assert.deepEqual(seen.at(-1), { kind: 'changed', addressbookId: 1, contactIds: [made.card.id] });
    assert.ok((await svc.cards({ q: 'nina' })).items.length === 1, 'the list knows it at once');
    const edited = await svc.updateCard(made.card.id, { company: 'Neu GmbH', etag: made.card.etag });
    assert.equal(edited.card.company, 'Neu GmbH');
    const stale = await svc.updateCard(made.card.id, { company: 'Alt', etag: made.card.etag });
    assert.deepEqual([stale.ok, stale.code, stale.current.company], [false, 'conflict', 'Neu GmbH']);
    await assert.rejects(svc.updateCard(404, { company: 'X' }), { code: 'read_only' });
    assert.equal((await svc.deleteCard(made.card.id)).ok, true);
    assert.ok(!(await svc.cards({ q: 'nina' })).items.length);
    const look = await svc.lookup('Sabine@Firma.de');
    assert.equal(look.card.id, 401);
    assert.equal(srv.state.requests.at(-1).query.email, 'sabine@firma.de');
    assert.deepEqual((await svc.lookup('tim@firma.de')).person, { userId: 7, name: 'Tim Brandt' });
    assert.equal((await svc.lookup('nobody@x.de')).card, null);
    const act = await svc.activity(401);
    assert.ok(act.mails.some((x) => x.id === 102));
    assert.ok(act.events.some((x) => x.title === 'Projektbesprechung'));
    const draft = await svc.cardDraft({ email: 'rechnung@stadtwerke.de', messageId: 101 });
    assert.deepEqual([draft.draft.name.given, draft.draft.company, draft.draft.phones[0].value, draft.existing], ['Stadtwerke', 'Stadtwerke', '0221 555 12 34', null]);
    assert.equal((await svc.cardDraft({ email: 'tim@firma.de' })).existing.id, 402);
    const dups = await svc.duplicates();
    assert.deepEqual(dups.items.map((x) => [x.reason, x.cards.map((c) => c.id).sort()]), [['email', [401, 405]]]);
    await svc.cards({});
    const merged = await svc.merge({ ids: [401, 405], primaryId: 401, pick: { note: 'join' } });
    assert.equal(merged.card.linked[0].id, 405, 'different address books: linked');
    assert.equal((await svc.cards({ q: 'keller' })).items.length, 1, 'shown once');
    assert.equal((await svc.duplicates()).items.length, 0);
    assert.equal((await svc.ignoreDuplicates([402, 403])).ok, true);
    const g = await svc.createGroup({ name: 'Elternbeirat' });
    const gm = await svc.groupMembers(g.group.id, { add: [{ contactId: 403 }, { email: 'kita@x.de', name: 'Kita' }] });
    assert.deepEqual(gm.members.map((x) => x.email), ['anna.lang@example.com', 'kita@x.de']);
    const gm2 = await svc.groupMembers(g.group.id, { remove: [gm.members[1].id] });
    assert.equal(gm2.group.count, 1);
    assert.equal((await svc.group(501)).members.length, 2);
    assert.equal((await svc.updateGroup(g.group.id, { name: 'Elternrat' })).group.name, 'Elternrat');
    assert.equal((await svc.deleteGroup(g.group.id)).ok, true);
    assert.ok(seen.some((x) => x.kind === 'groups'));
    // suggestions while writing: contacts and groups (the group's addresses go in)
    const sug = await svc.contacts('famil');
    assert.deepEqual(sug.items.map((x) => [x.source, x.name, (x.members || []).map((y) => y.email)]), [['group', 'Familie', ['tim@firma.de', 'oma@example.com']]]);
  });

  it('files: vCard import and export through the dialogs, a photo of this PC, a call', async () => {
    const dir = tmpDir('mail-pim-files-');
    const vcf = path.join(dir, 'google.vcf');
    fs.writeFileSync(vcf, '﻿BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:3.0\r\nFN:B\r\nEND:VCARD\r\n');
    const png = path.join(dir, 'foto.png');
    fs.writeFileSync(png, PNG);
    const out = path.join(dir, 'export.vcf');
    let open = [vcf];
    const dialog = {
      showOpenDialog: async () => (open ? { canceled: false, filePaths: open } : { canceled: true, filePaths: [] }),
      showSaveDialog: async () => ({ canceled: false, filePath: out }),
    };
    const opened = [];
    const shell = { openExternal: async (u) => { opened.push(u); } };
    const { svc, srv } = await setup({}, { dialog, shell });
    const imp = await svc.importVcf({ addressbookId: 1 });
    assert.deepEqual([imp.ok, imp.imported], [true, 2]);
    assert.ok(srv.state.pim.imports[0].vcf.startsWith('BEGIN:VCARD'), 'without the BOM');
    assert.equal(srv.state.pim.imports[0].addressbookId, 1);
    fs.writeFileSync(path.join(dir, 'kein.vcf'), 'hallo');
    open = [path.join(dir, 'kein.vcf')];
    await assert.rejects(svc.importVcf({}), { code: 'invalid_vcard' });
    open = null;
    assert.equal((await svc.importVcf({})).code, 'cancelled');
    const exp = await svc.exportVcf({ book: 'all' });
    assert.equal(exp.path, out);
    assert.ok(fs.readFileSync(out, 'utf8').includes('FN:Sabine Keller'));
    open = [png];
    const ph = await svc.setCardPhoto(402);
    assert.ok(ph.card.photo);
    assert.equal(srv.state.pim.photos.get(402).mime, 'image/png');
    // with nativeImage the picture becomes a 512 px JPEG
    let resized = null;
    svc.nativeImage = { createFromBuffer: () => ({ isEmpty: () => false, getSize: () => ({ width: 2000, height: 1000 }), resize: (o) => { resized = o; return { toJPEG: () => Buffer.from([0xFF, 0xD8, 1, 2]) }; }, toJPEG: () => Buffer.alloc(0) }) };
    await svc.setCardPhoto(403);
    assert.deepEqual(resized, { width: 512, quality: 'good' });
    assert.equal(srv.state.pim.photos.get(403).mime, 'image/jpeg');
    assert.equal((await svc.deleteCardPhoto(403)).card.photo, null);
    assert.deepEqual(await svc.call('+49 171 / 234-5678'), { ok: true });
    assert.deepEqual(opened, ['tel:+491712345678']);
    await assert.rejects(svc.call('javascript:alert(1)'), { code: 'invalid' });
    await assert.rejects(svc.call('12'), { code: 'invalid' });
  });

  it('Microsoft "Neu anmelden": the scopes of me and the account\'s address as login hint', async () => {
    const urls = [];
    const listener = { redirectUri: 'http://localhost:5555', result: null, close() {} };
    const { svc, srv } = await setup({}, {
      openExternal: async (u) => { urls.push(u); const q = new URL(u).searchParams; listener.resolve({ code: srv.issueCode(q.get('code_challenge')) }); return true; },
      startListener: async () => { listener.result = new Promise((r) => { listener.resolve = r; }); return listener; },
    });
    srv.state.accounts[1].missingScopes = ['Calendars.ReadWrite', 'Contacts.ReadWrite'];
    assert.deepEqual((await svc.me()).accounts[1].missingScopes, ['Calendars.ReadWrite', 'Contacts.ReadWrite']);
    const r = await svc.signInMicrosoft({ accountId: 2 });
    assert.equal(r.ok, true);
    const q = new URL(urls[0]).searchParams;
    assert.equal(q.get('login_hint'), 'max@firma.de');
    assert.ok(q.get('scope').split(' ').includes('Calendars.ReadWrite') && q.get('scope').split(' ').includes('Contacts.ReadWrite'));
    assert.deepEqual((await svc.me()).accounts[1].missingScopes, []);
    assert.equal((await svc.me()).microsoft.adminConsentUrl, 'https://login.microsoftonline.com/common/adminconsent?client_id=abcd-1234-efgh-5678');
  });
});

describe('mail IPC – calendar and contacts', () => {
  it('checks arguments and forwards the live events', async () => {
    const { svc, srv } = await setup();
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => win, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('mail:cal:list')).calendars.length, 4);
    assert.equal((await call('mail:events', { from: 'x', to: 5 })).code, 'invalid');
    assert.equal((await call('mail:events', { ...week(), calendars: ['1;DROP'] })).code, 'invalid');
    assert.equal((await call('mail:event:get', { id: 301, occurrence: '../x' })).code, 'invalid');
    assert.equal((await call('mail:event:get', { id: 301 })).event.title, 'Projektbesprechung');
    assert.equal((await call('mail:event:create', { calendarId: 1, title: 'X' })).code, 'invalid');
    assert.equal((await call('mail:event:respond', { id: 303, response: 'maybe' })).code, 'invalid');
    const conflict = await call('mail:event:update', { id: 301, title: 'Y', etag: '"0-0"' });
    assert.deepEqual([conflict.ok, conflict.code, conflict.current.title], [false, 'conflict', 'Projektbesprechung']);
    assert.equal((await call('mail:cards', { book: '../1' })).code, 'invalid');
    assert.equal((await call('mail:cards', { q: 'tim' })).items[0].name, 'Tim Brandt');
    assert.equal((await call('mail:card:lookup', {})).code, 'invalid');
    assert.equal((await call('mail:card:merge', { ids: [1], primaryId: 'x' })).code, 'invalid');
    assert.equal((await call('mail:call', { number: 5 })).code, 'invalid');
    assert.equal((await call('mail:card:update', { id: 404, company: 'X' })).code, 'read_only');
    // Mail 1.3.0: a shift of a series the server refuses → its reason reaches the page
    const tr = (await call('mail:event:get', { id: 304 })).event;
    assert.deepEqual(tr.series && [tr.series.allDay, typeof tr.series.start], [false, 'number'], 'a series carries its master\'s times');
    srv.state.fail['PATCH events/:id'] = { status: 400, code: 'invalid', extra: { field: 'start', reason: 'series_shift' } };
    const shift = await call('mail:event:update', { id: 304, start: tr.start + 3600000, end: tr.end + 3600000, scope: 'series' });
    assert.deepEqual([shift.ok, shift.code, shift.detail.field, shift.detail.reason], [false, 'invalid', 'start', 'series_shift']);
    delete srv.state.fail['PATCH events/:id'];
    assert.equal((await call('mail:overlay:update', { id: 'birthdays', visible: false })).overlay.visible, false);
    svc.emit('calendar', { kind: 'calendars' });
    svc.emit('contacts', { kind: 'groups' });
    assert.deepEqual(sent.slice(-2), [['mail:calendar', { kind: 'calendars' }], ['mail:contacts', { kind: 'groups' }]]);
  });
});
