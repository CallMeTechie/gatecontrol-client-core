'use strict';

// Notizen & Aufgaben, plugin 1.9.0 (the word calendarEvents of me.features — never a version): „Termin“ in the quick
// entry. The pure helpers (utils/notes-events.js: the calendars, why no event can be made, what the renderer may send,
// what becomes of a refused waiting event, the waiting row in „Mein Tag“, the form of „Mehr Angaben …“; utils/notes.js:
// Item.event, me.events, the parsed fields, the group choice 'show'), NotesService against the fake server (an older
// plugin offers nothing; an event made, made again without its calendar, refused for good; without a connection it
// waits with a clientId, leaves the queue after the first 200 and is never sent twice; Mail gone while it waited: a
// task with its day and time) and the IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const N = require('../src/utils/notes');
const E = require('../src/utils/notes-events');
const NotesService = require('../src/services/notes');
const ApiClient = require('../src/services/api-client');
const { registerNotesHandlers } = require('../src/ipc/notes-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer, FEATURES, STAGE1, STAGE2, STAGE3, STAGE4, STAGE5, STAGE6, STAGE7 } = require('./fixtures/notes-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const OLD = [...FEATURES, 'offlineEdits', ...STAGE1, ...STAGE2, ...STAGE3, ...STAGE4, ...STAGE5, ...STAGE6];
const ALL = [...OLD, ...STAGE7];

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(opts = {}, store = createMemoryStore()) {
  const srv = await notesServer({ features: ALL, ...opts });
  cleanup.push(() => srv.close());
  const svc = new NotesService({
    apiClient: new ApiClient(srv.url, 'gc_token', log), log, store, protect: null, getLang: () => 'de',
    pushClient: null, notificationCenter: null, dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, store };
}

const asked = (srv, re) => srv.state.requests.filter((r) => re.test(`${r.method} ${r.path}`));
const why = async (p) => { try { await p; return null; } catch (err) { return [err.code, err.status, (err.body && (err.body.reason || err.body.field)) || null]; } };
const section = (view, id) => view.sections.find((s) => s.id === id) || { items: [] };

describe('utils/notes-events: plugin 1.9.0', () => {
  it('cleans the calendars: only writable ones of their own kind are targets, „Aufgaben“ never, the default is one of them', () => {
    const c = E.normalizeCalendars({
      state: 'ok', reason: null, defaultId: 10, reminders: { timed: 15, allDay: 360 }, timeZone: 'Europe/Berlin',
      calendars: [
        { id: 7, key: 'cal:7', name: 'Privat', color: '#4F8DF5', kind: 'own', writable: true, target: true, isDefault: false, shown: true },
        { id: 10, key: 'cal:10', name: 'Aufgaben', color: '#999999', kind: 'tasks', writable: true, target: true, isDefault: true, shown: false },
        { id: null, key: 'overlay:familie', name: 'Familie', color: 'red', kind: 'family', writable: false, target: true, shown: true },
        { id: 3, key: 'bad key!', name: 'x' }, 'x',
      ],
    });
    assert.deepEqual(c.targets, [7]);
    assert.equal(c.defaultId, 7);
    assert.deepEqual(c.calendars.map((x) => [x.key, x.target, x.isDefault, x.color]), [['cal:7', true, true, '#4F8DF5'], ['cal:10', false, false, '#999999'], ['overlay:familie', false, false, null]]);
    assert.deepEqual(c.reminders, { timed: 15, allDay: 360 });
    // ok without a target reads as none / no_calendar; an unknown answer too
    assert.deepEqual([E.normalizeCalendars({ state: 'ok', calendars: [] }).state, E.normalizeCalendars({ state: 'ok', calendars: [] }).reason], ['none', 'no_calendar']);
    assert.deepEqual([E.normalizeCalendars({ state: 'none', reason: 'no_mail' }).reason, E.normalizeCalendars(null).reason], ['no_mail', 'no_calendar']);
  });

  it('why no event can be made, and which reason passes by itself', () => {
    assert.deepEqual(['no_mail', 'mail_old', 'feature_off', 'not_allowed', 'not_licensed', 'no_seat', 'no_calendar', 'unreachable', 'auth_failed'].map(E.why),
      ['mail', 'mail', 'off', 'off', 'off', 'off', 'none', 'unreachable', 'unreachable']);
    assert.deepEqual(['no_mail', 'no_calendar', 'unreachable', 'auth_failed', null].map(E.permanent), [true, true, false, false, false]);
    const ok = E.normalizeCalendars({ state: 'ok', calendars: [{ id: 7, key: 'cal:7', name: 'P', kind: 'own', writable: true, target: true }] });
    // the calendars are the newer word; without them me.events; unreachable is no block
    assert.equal(E.blocked({ events: { available: false, reason: 'no_mail' } }, ok), null);
    assert.equal(E.blocked({ events: { available: false, reason: 'no_mail' } }, null), 'no_mail');
    assert.equal(E.blocked(null, E.normalizeCalendars({ state: 'none', reason: 'unreachable' })), null);
    assert.equal(E.blocked(null, E.normalizeCalendars({ state: 'none', reason: 'feature_off' })), 'feature_off');
    assert.deepEqual([E.defaultReminder(E.normalizeCalendars({ reminders: { timed: 15, allDay: 360 } }), false), E.defaultReminder(E.normalizeCalendars({ reminders: { timed: 15, allDay: 360 } }), true), E.defaultReminder(null, true)], [15, 360, null]);
    assert.deepEqual(['14:00', '23:30', '09:15'].map(E.plusHour), ['15:00', '00:30', '10:15']);
  });

  it('checks what the renderer sends for POST events and PATCH events/<id>', () => {
    assert.deepEqual(E.eventCreate({ title: ' Fashion Outlet ', date: '2026-12-04', time: '14:00', endTime: '15:00', location: 'Fashion Outlet', calendarId: 7, reminder: 15, repeat: { type: 'weekly', interval: 1, days: [5] }, clientId: 'x', extra: 1 }),
      { title: 'Fashion Outlet', date: '2026-12-04', time: '14:00', endTime: '15:00', location: 'Fashion Outlet', calendarId: 7, reminder: 15, repeat: { type: 'weekly', interval: 1, days: [5] } });
    // no time: all day; reminder false: none; left out: the calendar's (nothing is sent)
    assert.deepEqual(E.eventCreate({ title: 'Einkaufen', date: '2026-12-04', reminder: false }), { title: 'Einkaufen', date: '2026-12-04', reminder: false });
    assert.deepEqual(E.eventCreate({ title: 'Urlaub', date: '2026-12-04', endDate: '2026-12-06', allDay: true }), { title: 'Urlaub', date: '2026-12-04', allDay: true, endDate: '2026-12-06' });
    for (const bad of [{ date: '2026-12-04' }, { title: 'x' }, { title: 'x', date: '4.12.' }, { title: 'x', date: '2026-12-04', time: '25:00' }, { title: 'x', date: '2026-12-04', endTime: '15:00' },
      { title: 'x', date: '2026-12-04', allDay: true, time: '14:00' }, { title: 'x', date: '2026-12-04', allDay: false }, { title: 'x', date: '2026-12-04', reminder: 40321 },
      { title: 'x', date: '2026-12-04', calendarId: 0 }, { title: 'x', date: '2026-12-04', repeat: { type: 'after', interval: 3 } }, { title: 'x'.repeat(256), date: '2026-12-04' },
      { title: 'x', date: '2026-12-04', endDate: '2026-12-20' }, { title: 'x', date: '2026-12-04', location: 'y'.repeat(256) }, null]) {
      assert.equal(E.eventCreate(bad), null, JSON.stringify(bad));
    }
    // a change: only what is sent; null takes the place off and ends the series; no calendarId
    assert.deepEqual(E.eventPatch({ location: null, repeat: null, calendarId: 8 }), { location: null, repeat: null });
    assert.deepEqual(E.eventPatch({ date: '2026-12-05', time: '10:00' }), { date: '2026-12-05', time: '10:00' });
    assert.equal(E.eventPatch({ time: '10:00' }), null);
  });

  it('a refused waiting event: it stays, goes again without its calendar, becomes a task, or is dropped', () => {
    const op = { what: 'event', clientId: 'aaaaaaaa-1', body: { title: 'Zahnarzt', date: '2026-12-04', time: '14:00', location: 'Praxis am Markt', calendarId: 9, repeat: { type: 'weekly', interval: 1, days: [5] }, clientId: 'aaaaaaaa-1' }, at: 1 };
    let n = 0;
    const cid = () => `bbbbbbbb-${++n}`;
    assert.equal(E.refused(op, { status: null }, cid), 'keep');
    assert.equal(E.refused(op, { status: 502 }, cid), 'keep');
    assert.equal(E.refused(op, { status: 503, body: { reason: 'unreachable' } }, cid), 'keep');
    assert.equal(E.refused(op, { status: 503, body: { reason: 'auth_failed' } }, cid), 'keep');
    const again = E.refused(op, { status: 404, body: { code: 'not_found', field: 'calendarId' } }, cid).op;
    assert.equal(again.body.calendarId, undefined);
    assert.equal(again.clientId, 'bbbbbbbb-1');
    assert.equal(again.body.clientId, 'bbbbbbbb-1');
    const task = E.refused(op, { status: 503, body: { reason: 'no_mail' } }, cid).op;
    assert.deepEqual([task.what, task.clientId, task.reason], ['task', 'bbbbbbbb-2', 'no_mail']);
    assert.deepEqual(task.body, { title: 'Zahnarzt', due: { date: '2026-12-04', time: '14:00' }, remindAt: { date: '2026-12-04', time: '14:00' }, note: 'Praxis am Markt', repeat: { type: 'weekly', interval: 1, days: [5] }, clientId: 'bbbbbbbb-2' });
    assert.equal(E.refused(op, { status: 400, body: { field: 'title' } }, cid), 'drop');
    assert.equal(E.refused({ ...op, body: { ...op.body, calendarId: undefined } }, { status: 404, body: { field: 'calendarId' } }, cid), 'drop');
    // a waiting task keeps the rules of a task: 503 waits, a 4xx drops it
    assert.equal(E.refused(task, { status: 503, body: { reason: 'no_mail' } }, cid), 'keep');
    assert.equal(E.refused(task, { status: 400 }, cid), 'drop');
    // only what is stored right comes back from the store, and only for this server and person
    const stored = { scope: 's1', ops: [op, task, { what: 'event', clientId: 'short', body: op.body }, { what: 'x', clientId: 'cccccccc', body: {} }] };
    assert.deepEqual(E.storedQueue(stored, 's1').map((o) => [o.what, o.clientId]), [['event', 'aaaaaaaa-1'], ['task', 'bbbbbbbb-2']]);
    assert.deepEqual(E.storedQueue(stored, 's2'), []);
  });

  it('a waiting event in „Mein Tag“: today under „Termine heute“, later ones under „Demnächst“, no tick box', () => {
    const view = { view: 'myday', date: '2026-11-08', sections: [
      { id: 'events', title: 'Termine heute', count: 1, items: [{ uid: 's:1', show: { date: '2026-11-08', time: '19:30' } }] },
      { id: 'today', title: 'Heute', count: 0, items: [] }, { id: 'done', title: 'Erledigt', count: 0, items: [] }] };
    const ops = [
      { what: 'event', clientId: 'aaaaaaaa-1', body: { title: 'Zahnarzt', date: '2026-11-08', time: '16:30', location: 'Praxis' } },
      { what: 'event', clientId: 'aaaaaaaa-2', body: { title: 'Outlet', date: '2026-11-13' } },
      { what: 'event', clientId: 'aaaaaaaa-3', body: { title: 'Später', date: '2026-12-31' } },
      { what: 'task', clientId: 'aaaaaaaa-4', body: { title: 'Aufgabe' } },
    ];
    const v = E.overlay(view, ops);
    assert.deepEqual(section(v, 'events').items.map((x) => x.uid), ['q:aaaaaaaa-1', 's:1']);
    assert.equal(section(v, 'events').count, 2);
    assert.deepEqual(v.sections.map((s) => s.id), ['events', 'today', 'upcoming', 'done']);
    const row = section(v, 'upcoming').items[0];
    assert.deepEqual([row.pending, row.canComplete, row.overdue, row.allDay, row.event.end, row.kind], [true, false, false, true, null, 'event']);
    const timed = section(v, 'events').items[0];
    assert.deepEqual([timed.subtitle, timed.event.end, timed.event.location], ['Praxis', { date: '2026-11-08', time: '17:30' }, 'Praxis']);
    // another view stays as it is
    assert.equal(E.overlay({ ...view, view: 'planned' }, ops).sections.length, 3);
    assert.equal(E.addDays('2026-12-30', 3), '2027-01-02');
  });

  it('„Mehr Angaben …“: the form gets what the chips show — the calendar\'s default reminder too', () => {
    const cals = E.normalizeCalendars({ state: 'ok', defaultId: 7, reminders: { timed: 15, allDay: 360 }, calendars: [{ id: 7, key: 'cal:7', name: 'Privat', kind: 'own', writable: true, target: true }] });
    assert.deepEqual(E.formPrefill({ title: 'Zahnarzt', date: '2026-12-04', time: '14:00', location: 'Praxis' }, cals),
      { title: 'Zahnarzt', date: '2026-12-04', time: '14:00', endTime: '15:00', allDay: false, location: 'Praxis', calendarId: 7, reminder: 15, repeat: null });
    assert.deepEqual(E.formPrefill({ title: 'Outlet', date: '2026-12-04', reminder: false, calendarId: 8 }, cals),
      { title: 'Outlet', date: '2026-12-04', time: null, endTime: null, allDay: true, location: null, calendarId: 8, reminder: null, repeat: null });
    assert.equal(E.formPrefill({ title: 'x', date: '2026-12-04' }, cals).reminder, 360);
  });

  it('utils/notes: Item.event (no tick box, never overdue), me.events, the parsed fields, the choice „show“', () => {
    const i = N.normalizeItem({ id: 318, type: 'source', kind: 'event', title: 'Zahnarzt', subtitle: 'Praxis am Markt', canComplete: true, overdue: true,
      source: { plugin: 'gatecontrol-mail', label: 'Mail', open: { plugin: 'gatecontrol-mail', route: 'event/912' } }, due: { date: '2026-11-27', time: '16:30' },
      event: { end: { date: '2026-11-27', time: '17:15' }, location: 'Praxis am Markt', calendar: { key: 'cal:7', name: 'Privat', color: '#4F8DF5', kind: 'own' }, eventId: 912, recurring: false, writable: true } });
    assert.deepEqual([i.canComplete, i.overdue, i.event.calendar.color, i.event.eventId, i.event.end, i.source.open.route], [false, false, '#4F8DF5', 912, { date: '2026-11-27', time: '17:15' }, 'event/912']);
    // Schule, Alltag: kind event without `event`, as before
    const school = N.normalizeItem({ id: 2, kind: 'event', canComplete: false, source: { plugin: 'gatecontrol-schule' } });
    assert.equal(school.event, null);
    assert.deepEqual(N.normalizeMe({ events: { available: true, reason: 'x' } }).events, { available: true, reason: null });
    assert.deepEqual(N.normalizeMe({ events: { available: false, reason: 'no_mail' } }).events, { available: false, reason: 'no_mail' });
    assert.equal(N.normalizeMe({}).events, null);
    const p = N.normalizeParsed({ title: 'Flohmarkt', date: '2026-11-14', time: '14:00', endTime: '16:00', allDay: false, location: 'Oma', looksLikeEvent: true });
    assert.deepEqual([p.endTime, p.allDay, p.location, p.looksLikeEvent], ['16:00', false, 'Oma', true]);
    assert.deepEqual(N.normalizePrefs({ groups: { 'gatecontrol-mail|cal:9': 'show', 'gatecontrol-mail|cal:7': 'hide', 'x|y': 'nope' } }).groups, { 'gatecontrol-mail|cal:9': 'show', 'gatecontrol-mail|cal:7': 'hide' });
    assert.deepEqual(N.groupsArg({ 'gatecontrol-mail|cal:9': null, 'gatecontrol-mail|cal:7': 'show', 'gatecontrol-mail|cal:8': 'maybe' }), { 'gatecontrol-mail|cal:9': null, 'gatecontrol-mail|cal:7': 'show' });
    assert.equal(N.groupsArg({ 'bad key': 'show' }), null);
  });
});

describe('NotesService: plugin 1.9.0 „Termin“', () => {
  it('an older plugin: no calendars, no event, no event mode — the server is not asked', async () => {
    const { srv, svc } = await setup({ features: OLD });
    assert.equal((await svc.me()).me.events, null);
    assert.deepEqual(await why(svc.eventCalendars()), ['unsupported', null, null]);
    assert.deepEqual(await why(svc.createEvent({ title: 'x', date: '2026-11-09' })), ['unsupported', null, null]);
    assert.deepEqual(await why(svc.parse({ text: 'Sa 14–16 Uhr Flohmarkt bei Oma', mode: 'event' })), ['unsupported', null, null]);
    assert.equal(asked(srv, /events/).length, 0);
  });

  it('the calendars, an event made (calendar and reminder only when chosen), its row, the event mode of POST parse', async () => {
    const { srv, svc } = await setup();
    assert.deepEqual((await svc.me()).me.events, { available: true, reason: null });
    const c = (await svc.eventCalendars()).calendars;
    assert.deepEqual([c.state, c.defaultId, c.targets, c.reminders], ['ok', 7, [7, 8], { timed: 15, allDay: 360 }]);
    assert.deepEqual(c.calendars.filter((x) => x.shown).map((x) => x.key), ['cal:7', 'cal:8', 'overlay:familie']);
    const p = (await svc.parse({ text: 'Sa 14–16 Uhr Flohmarkt bei Oma', mode: 'event' })).parsed;
    assert.deepEqual([p.title, p.time, p.endTime, p.location, p.allDay], ['Flohmarkt', '14:00', '16:00', 'Oma', false]);
    assert.equal(asked(srv, /POST .*\/parse$/).at(-1).body.mode, 'event');
    const r = await svc.createEvent({ title: 'Zahnarzt', date: '2026-11-08', time: '16:30', location: 'Praxis am Markt' });
    assert.equal(r.queued, false);
    assert.equal(r.items[0].event.eventId, r.event.id);
    const sent = asked(srv, /^POST .*\/events$/).at(-1).body;
    assert.match(sent.clientId, /^[0-9a-f-]{36}$/);
    assert.deepEqual(Object.keys(sent).sort(), ['clientId', 'date', 'location', 'time', 'title']);
    const v = (await svc.view({ name: 'myday' })).view;
    const row = section(v, 'events').items.find((x) => x.event);
    assert.deepEqual([row.title, row.subtitle, row.canComplete, row.event.calendar.name, row.source.open.route], ['Zahnarzt', 'Praxis am Markt', false, 'Privat', `event/${r.event.id}`]);
    // PATCH / DELETE: only what the hub made; another event: removed false
    const u = await svc.updateEvent(r.event.id, { location: null });
    assert.equal(u.items[0].event.location, null);
    const other = srv.addEvent({ title: 'Elternabend', date: '2026-11-10', time: '19:00' });
    assert.deepEqual(await svc.deleteEvent(other.id), { ok: true, removed: false });
    assert.deepEqual(await why(svc.updateEvent(other.id, { title: 'x' })), ['not_found', 404, null]);
    assert.deepEqual(await svc.deleteEvent(r.event.id), { ok: true, removed: true });
  });

  it('„Demnächst“ and „Geplant“ carry the events of the next days; the choice per calendar („Quellen“)', async () => {
    const { svc, srv } = await setup();
    srv.addEvent({ title: 'Outlet', date: '2026-11-13', time: '14:00', location: 'Fashion Outlet' });
    srv.addEvent({ calendarId: 9, title: 'Feiertag', date: '2026-11-11' });
    let v = (await svc.view({ name: 'myday' })).view;
    assert.deepEqual(section(v, 'upcoming').items.filter((x) => x.event).map((x) => x.title), ['Outlet']);
    assert.ok(!section(v, 'overdue').items.some((x) => x.event));
    const pl = (await svc.view({ name: 'planned' })).view;
    assert.deepEqual(section(pl, 'week').items.filter((x) => x.event).map((x) => x.title), ['Outlet']);
    // Feiertage on, Privat off — and back to the default
    await svc.setPrefs({ groups: N.groupsArg({ 'gatecontrol-mail|cal:9': 'show', 'gatecontrol-mail|cal:7': 'hide' }) });
    v = (await svc.view({ name: 'myday' })).view;
    assert.deepEqual(section(v, 'upcoming').items.filter((x) => x.event).map((x) => x.title), ['Feiertag']);
    const c = (await svc.eventCalendars()).calendars;
    assert.deepEqual(c.calendars.filter((x) => x.shown).map((x) => x.key), ['cal:8', 'cal:9', 'overlay:familie']);
    await svc.setPrefs({ groups: N.groupsArg({ 'gatecontrol-mail|cal:9': null, 'gatecontrol-mail|cal:7': null }) });
    assert.deepEqual(srv.state.prefs.groups, {});
  });

  it('a calendar that is gone: once more without it; no event possible for good: the reason, nothing queued', async () => {
    const { srv, svc } = await setup();
    const r = await svc.createEvent({ title: 'Zahnarzt', date: '2026-11-09', time: '09:00', calendarId: 9 });
    assert.equal(r.event.calendarId, 7);
    const two = asked(srv, /^POST .*\/events$/).slice(-2).map((x) => x.body);
    assert.deepEqual([two[0].calendarId, two[1].calendarId], [9, undefined]);
    assert.notEqual(two[0].clientId, two[1].clientId);
    srv.state.eventsReason = 'no_mail';
    assert.deepEqual(await why(svc.createEvent({ title: 'Outlet', date: '2026-11-13' })), ['unavailable', 503, 'no_mail']);
    assert.equal((await svc.pendingEvents()).items.length, 0);
    // 400: shown, never queued
    srv.state.eventsReason = null;
    srv.state.fail['POST events'] = { status: 400, code: 'invalid', extra: { field: 'title' } };
    assert.deepEqual(await why(svc.createEvent({ title: 'x', date: '2026-11-13' })), ['invalid', 400, 'title']);
    assert.equal((await svc.pendingEvents()).items.length, 0);
  });

  it('without a connection: the event waits with its clientId, shows in „Mein Tag“, goes once and leaves the queue', async () => {
    const store = createMemoryStore();
    const { srv, svc } = await setup({}, store);
    await svc.eventCalendars();
    srv.down = true;
    const r = await svc.createEvent({ title: 'Zahnarzt', date: '2026-11-08', time: '16:30', location: 'Praxis' });
    assert.deepEqual([r.queued, r.offline, r.pending.pending, r.pending.title], [true, true, true, 'Zahnarzt']);
    // the calendars: the last answer
    assert.equal((await svc.eventCalendars()).stale, true);
    const r2 = await svc.createEvent({ title: 'Outlet', date: '2026-11-13' });
    assert.equal(r2.queued, true);
    assert.deepEqual(store.get('notesEventQueue').ops.map((o) => o.body.title), ['Zahnarzt', 'Outlet']);
    srv.down = false;
    // Mail does not answer: it stays
    srv.state.eventsReason = 'unreachable';
    let v = (await svc.view({ name: 'myday' })).view;
    assert.deepEqual(section(v, 'events').items.filter((x) => x.pending).map((x) => x.title), ['Zahnarzt']);
    assert.deepEqual(section(v, 'upcoming').items.filter((x) => x.pending).map((x) => x.title), ['Outlet']);
    assert.equal((await svc._eventFlush()).sent, 0);
    assert.equal((await svc.pendingEvents()).items.length, 2);
    // Mail is back: each goes once, with its own clientId, and leaves the queue after the first 200
    srv.state.eventsReason = null;
    const before = asked(srv, /^POST .*\/events$/).length;
    const sent = await svc._eventFlush();
    assert.equal(sent.sent, 2);
    const posts = asked(srv, /^POST .*\/events$/).slice(before).filter((x) => !x.body || true);
    const ok = posts.filter((x) => srv.state.eventKeys.has(x.body.clientId));
    assert.deepEqual(ok.map((x) => x.body.clientId), [r.clientId, r2.clientId]);
    assert.deepEqual(store.get('notesEventQueue').ops, []);
    assert.equal((await svc._eventFlush()).sent, 0);
    assert.equal(srv.state.events.size, 2);
    v = (await svc.view({ name: 'myday' })).view;
    assert.ok(!section(v, 'events').items.some((x) => x.pending));
    assert.deepEqual(section(v, 'events').items.filter((x) => x.event).map((x) => x.title), ['Zahnarzt']);
  });

  it('sent twice (the answer lost): the server makes one event; „Rückgängig“ before sending; another person sends nothing', async () => {
    const store = createMemoryStore();
    const { srv, svc } = await setup({}, store);
    srv.down = true;
    const r = await svc.createEvent({ title: 'Zahnarzt', date: '2026-11-09', time: '09:00' });
    const r2 = await svc.createEvent({ title: 'Weg damit', date: '2026-11-09' });
    assert.deepEqual(await svc.unqueueEvent(r2.clientId), { ok: true, removed: true });
    assert.deepEqual(await svc.unqueueEvent(r2.clientId), { ok: true, removed: false });
    srv.down = false;
    // the same body with the same clientId twice: one event (replayed)
    const body = store.get('notesEventQueue').ops[0].body;
    const api = svc.api;
    const a = await api.createEvent(body);
    const b = await api.createEvent(body);
    assert.deepEqual([a.event.id === b.event.id, b.replayed], [true, true]);
    await svc._eventFlush();
    assert.equal(srv.state.events.size, 1);
    assert.equal(srv.state.eventKeys.get(r.clientId), a.event.id);
    // the store of another server and person: nothing of it goes out
    srv.down = true;
    await svc.createEvent({ title: 'Nur hier', date: '2026-11-09' });
    srv.down = false;
    const other = await setup({}, createMemoryStore());
    other.store.set('notesEventQueue', { ...store.get('notesEventQueue'), scope: 'another' });
    assert.equal((await other.svc._eventFlush()).sent, 0);
    assert.equal(other.srv.state.events.size, 0);
  });

  it('Mail gone while the event waited: it becomes a task with its day, time and place; the calendar gone: without it', async () => {
    const { srv, svc } = await setup();
    await svc.eventCalendars();
    srv.down = true;
    await svc.createEvent({ title: 'Zahnarzt', date: '2026-11-09', time: '09:00', location: 'Praxis am Markt', calendarId: 8 });
    await svc.createEvent({ title: 'Outlet', date: '2026-11-13', time: '14:00', location: 'Fashion Outlet' });
    srv.down = false;
    // the first: its calendar is gone → the default one
    srv.state.calendars = srv.state.calendars.filter((c) => c.id !== 8);
    srv.state.fail['POST events'] = undefined;
    const first = await svc._eventFlush();
    assert.equal(first.sent, 2);
    assert.deepEqual([...srv.state.events.values()].map((e) => [e.title, e.calendarId]), [['Zahnarzt', 7], ['Outlet', 7]]);
    // Mail gone: the waiting one is made a task
    srv.down = true;
    await svc.createEvent({ title: 'Flohmarkt', date: '2026-11-14', time: '14:00', location: 'Oma' });
    srv.down = false;
    srv.state.eventsReason = 'no_mail';
    const r = await svc._eventFlush();
    assert.equal(r.asTask.length, 1);
    const t = [...srv.state.tasks.values()].find((x) => x.title === 'Flohmarkt');
    assert.deepEqual([t.due, t.note], [{ date: '2026-11-14', time: '14:00' }, 'Oma']);
    assert.equal((await svc.pendingEvents()).items.length, 0);
    // … and the last word of the calendars says so: a new event is refused at once, without a connection too
    srv.down = true;
    assert.deepEqual(await why(svc.createEvent({ title: 'x', date: '2026-11-14' })), ['unavailable', 503, 'no_mail']);
  });
});

describe('ipc/notes-handlers: plugin 1.9.0', () => {
  it('checks the event, the patch, the clientId, the mode and the group choices; the clientId is made here', async () => {
    const { srv, svc } = await setup();
    const h = {};
    registerNotesHandlers((ch, fn) => { h[ch] = fn; }, { notes: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => h[ch]({}, arg);
    assert.equal((await call('notes:events:calendars')).calendars.defaultId, 7);
    assert.deepEqual(await call('notes:event:create', { event: { title: '', date: '2026-11-09' } }), { ok: false, code: 'invalid', error: 'invalid argument', status: null, field: 'event' });
    const r = await call('notes:event:create', { event: { title: 'Zahnarzt', date: '2026-11-09', time: '09:00', clientId: 'mine-mine-mine' } });
    assert.equal(r.ok, true);
    assert.notEqual(asked(srv, /^POST .*\/events$/).at(-1).body.clientId, 'mine-mine-mine');
    assert.equal((await call('notes:event:update', { id: r.event.id, patch: {} })).field, 'patch');
    assert.equal((await call('notes:event:update', { id: r.event.id, patch: { title: 'Zahnarzt Dr. Muster' } })).ok, true);
    assert.equal((await call('notes:event:delete', { id: 'x' })).field, 'id');
    assert.equal((await call('notes:event:unqueue', { clientId: 'no' })).field, 'clientId');
    assert.deepEqual((await call('notes:events:pending')).items, []);
    assert.equal((await call('notes:parse', { text: 'x', mode: 'other' })).field, 'mode');
    assert.equal((await call('notes:parse', { text: 'Freitag 14 Uhr Outlet im Zentrum', mode: 'event' })).parsed.location, 'Zentrum');
    assert.equal((await call('notes:prefs:set', { patch: { groups: { 'gatecontrol-mail|cal:9': 'show' } } })).ok, true);
    assert.equal((await call('notes:prefs:set', { patch: { groups: { 'gatecontrol-mail|cal:9': null } } })).ok, true);
    assert.equal((await call('notes:prefs:set', { patch: { groups: { 'gatecontrol-mail|cal:9': 'perhaps' } } })).field, 'groups');
    // refused for good: the reason comes along for the card
    srv.state.eventsReason = 'feature_off';
    const no = await call('notes:event:create', { event: { title: 'x', date: '2026-11-09' } });
    assert.deepEqual([no.ok, no.code, no.reason, no.status], [false, 'unavailable', 'feature_off', 503]);
  });
});
