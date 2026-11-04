'use strict';

// Mail Phase 3 (Mail 1.9.0 — free/busy, shared calendars, resources in the plugin gatecontrol-mail): the pure helpers
// (utils/mail-plan.js and the additions to utils/mail-pim.js / utils/mail.js — features, rows, suggestions, shares,
// „Mit mir geteilt“, resources, bookings, the refusals' details, live events, push clicks), the API and the service
// (services/mail.js — never kept offline, the shared calendars in the offline window, live events) and the IPC
// (mail:freebusy, mail:share:*, mail:shared*, mail:resources, mail:booking:*) against the fake server
// (fixtures/mail-plan-server.js, `mailServer({ plan: true })`).

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
const { mailServer } = require('./fixtures/mail-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

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
  const srv = await mailServer({ plan: true, ...opts });
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

const day0 = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime(); };
const at = (days, h, mi = 0) => { const d = new Date(day0()); d.setDate(d.getDate() + days); d.setHours(h, mi, 0, 0); return d.getTime(); };

describe('utils/mail-plan', () => {
  it('the features of 1.9.0 are known (no "newer version" for them); older servers have none', () => {
    const me = mail.normalizeMe({ features: ['calendar', 'freeBusy', 'calendarSharing', 'resources', 'bookingRequests', 'teleport'] });
    assert.deepEqual(me.features, ['mail', 'calendar', 'freeBusy', 'calendarSharing', 'resources', 'bookingRequests']);
    for (const f of ['freeBusy', 'calendarSharing', 'resources', 'bookingRequests']) assert.ok(mail.FEATURES.includes(f), f);
    assert.deepEqual(mail.normalizeMe({ features: ['calendar'] }).features, ['mail', 'calendar']);
  });

  it('calendars: sharedBy, the shared ones, free/busy and the working hours of the settings (defaults for older servers)', () => {
    const c = mail.normalizeCalendars({
      calendars: [{ id: 5, source: 'graph', accountId: 2, name: 'Team', sharedBy: { email: 'team@firma.de' } }, { id: 6, sharedBy: { email: 'nope' } }],
      shared: [
        { id: 50, name: 'Urlaube', color: '#f28cc2', owner: { userId: 7, name: 'Sabine' }, level: 'read', via: 'user', group: 'egal', visible: true, accepted: true, writable: true },
        { id: 51, owner: { userId: 8 }, level: 'admin', via: 'group', group: 'Vertrieb' }, { id: 'x' },
      ],
      prefs: { freeBusy: false, workHours: { days: [5, 1, 1, 9], from: '07:30', to: '24:00' } },
    });
    assert.deepEqual([c.calendars[0].sharedBy, c.calendars[1].sharedBy], [{ email: 'team@firma.de' }, null]);
    assert.deepEqual(c.shared.map((x) => [x.id, x.color, x.level, x.group, x.writable, x.visible]), [[50, '#F28CC2', 'read', null, false, true], [51, '#8C96A5', 'freebusy', 'Vertrieb', false, false]]);
    assert.deepEqual([c.prefs.freeBusy, c.prefs.workHours], [false, { days: [1, 5], from: '07:30', to: '24:00' }]);
    const old = mail.normalizeCalendars({ calendars: [], prefs: { workHours: { days: [1], from: '18:00', to: '08:00' } } });
    assert.deepEqual([old.shared, old.prefs.freeBusy, old.prefs.workHours], [[], true, { days: [1, 2, 3, 4, 5], from: '08:00', to: '18:00' }]);
    assert.deepEqual(mail.calSettingsPatch({ freeBusy: false, workHours: { days: [1, 2], from: '09:00', to: '17:30' } }), { freeBusy: false, workHours: { days: [1, 2], from: '09:00', to: '17:30' } });
    for (const workHours of [{ days: [1, 1], from: '09:00', to: '10:00' }, { days: [8], from: '09:00', to: '10:00' }, { days: [1], from: '10:00', to: '09:00' }, { days: [1], from: '9:00', to: '10:00' }, { days: [], from: '09:00', to: '10:00' }]) {
      assert.equal(mail.calSettingsPatch({ workHours }), null, JSON.stringify(workHours));
    }
    assert.equal(mail.calSettingsPatch({ freeBusy: 'yes' }), null);
  });

  it('items of shared calendars: `shared`, free/busy ones without eventId under the server\'s key, private', () => {
    const e = mail.normalizeEvents({ items: [
      { key: 's:51:1:1730800800000', eventId: null, calendarId: 51, title: 'Gebucht', start: 5, end: 9, busy: 'tentative', shared: 'freebusy', location: 'x' },
      { key: 'evil key', eventId: null, calendarId: 51, start: 5, shared: 'freebusy' },
      { key: 's:51:2:3', eventId: null, calendarId: 51, start: 5 },
      { eventId: 950, calendarId: 50, start: 5, shared: 'read' },
      { eventId: 951, calendarId: 50, start: 5, shared: 'owner' },
    ] });
    assert.deepEqual(e.items.map((x) => [x.key, x.eventId, x.shared, x.private]), [['s:51:1:1730800800000', null, 'freebusy', true], ['950', 950, 'read', false], ['951', 951, null, false]]);
    assert.equal(e.items[0].busy, 'tentative');
    assert.equal(mail.normalizeEvent({ eventId: null, key: 's:1:1:1', start: 5, shared: 'freebusy' }).eventId, null, 'never opened: no id');
  });

  it('free/busy: rows without titles, the asker first, unknown ones without blocks; bodies checked', () => {
    const fb = mail.normalizeFreeBusy({ from: 1, to: 2, items: [
      { key: 'tim@firma.de', kind: 'person', email: 'tim@firma.de', name: 'Tom', state: 'ok', blocks: [{ start: 20, end: 30, status: 'busy', title: 'Geheim' }, { start: 5, end: 4 }, { start: 10, end: 15, status: 'oof' }] },
      { key: 'self', kind: 'self', name: 'Max', state: 'ok', blocks: [] },
      { key: 'kunde@mueller.de', kind: 'external', email: 'kunde@mueller.de', state: 'unknown', blocks: [{ start: 1, end: 2 }] },
      { key: 'resource:12', kind: 'room', resourceId: 12, state: 'ok' }, { kind: 'self' },
    ] });
    assert.deepEqual(fb.items.map((r) => [r.key, r.kind, r.state, r.blocks.length]), [['self', 'self', 'ok', 0], ['tim@firma.de', 'person', 'ok', 2], ['kunde@mueller.de', 'external', 'unknown', 0], ['resource:12', 'external', 'ok', 0]]);
    assert.deepEqual(fb.items[1].blocks, [{ start: 10, end: 15, status: 'busy' }, { start: 20, end: 30, status: 'busy' }], 'never a title');
    assert.deepEqual(mail.freeBusyBody({ from: 1, to: 2, attendees: ['A@x.de', 'a@x.de', { email: 'b@x.de' }], resources: [12, '12'] }), { from: 1, to: 2, attendees: ['A@x.de', 'b@x.de'], resources: [12] });
    assert.equal(mail.freeBusyBody({ from: 1, to: 1 + 32 * DAY, attendees: [] }), null, '≤ 31 days');
    assert.equal(mail.freeBusyBody({ from: 1, to: 2, attendees: ['no address'] }), null);
    assert.equal(mail.freeBusyBody({ from: 1, to: 2, attendees: Array.from({ length: 51 }, (_, i) => `p${i}@x.de`) }), null);
    assert.deepEqual(mail.suggestBody({ duration: 60, from: 1, attendees: ['a@x.de'], limit: 4 }), { duration: 60, attendees: ['a@x.de'], from: 1, limit: 4 });
    for (const bad of [{ duration: 4 }, { duration: 1441 }, { duration: 60, from: 1, to: 1 + 15 * DAY }, { duration: 60, limit: 11 }]) assert.equal(mail.suggestBody({ attendees: [], ...bad }), null, JSON.stringify(bad));
    const s = mail.normalizeSuggest({ items: [{ start: 10, end: 20 }, { start: 30 }], unknown: ['kunde@mueller.de'], workHours: { days: [1], from: '08:00', to: '12:00' }, timeZone: 'Europe/Berlin' });
    assert.deepEqual([s.items, s.unknown, s.workHours.to, s.timeZone], [[{ start: 10, end: 20 }], ['kunde@mueller.de'], '12:00', 'Europe/Berlin']);
  });

  it('shares, „Mit mir geteilt“, people and groups: known fields only, never addresses', () => {
    const sh = mail.normalizeShares({ items: [{ id: 71, type: 'user', principalId: 7, name: 'Sabine', level: 'write', state: 'accepted', members: 5 }, { id: 72, type: 'group', principalId: 3, name: 'Familie', level: 'x', members: 4 }, { id: 73, type: 'team' }], freeBusy: false });
    assert.deepEqual(sh.items.map((x) => [x.id, x.type, x.level, x.state, x.members]), [[71, 'user', 'write', 'accepted', null], [72, 'group', 'read', 'group', 4]]);
    assert.equal(sh.freeBusy, false);
    assert.deepEqual(mail.shareBody({ type: 'group', id: '3', level: 'freebusy' }), { type: 'group', id: 3, level: 'freebusy' });
    assert.equal(mail.shareBody({ type: 'user', id: 3, level: 'owner' }), null);
    const shared = mail.normalizeShared({ items: [{ id: 50, owner: { userId: 7, name: 'Sabine' }, level: 'write' }], accounts: [{ calendarId: 5, accountId: 2, name: 'Team', owner: { email: 'team@firma.de' }, writable: true }, { calendarId: 6, owner: {} }] });
    assert.deepEqual([shared.items[0].writable, shared.accounts.length, shared.accounts[0].owner.email], [true, 1, 'team@firma.de']);
    assert.deepEqual(mail.sharedPatch({ visible: true, color: '#abcdef' }), { visible: true, color: '#ABCDEF' });
    assert.deepEqual(mail.sharedPatch({ color: null }), { color: null });
    assert.equal(mail.sharedPatch({ color: 'red' }), null);
    const p = mail.normalizePrincipals({ items: [{ type: 'user', id: 7, name: 'Sabine Keller', initials: 'sk', color: '#F28CC2', email: 'sabine@firma.de' }, { type: 'group', id: 4, name: 'Vertrieb', sub: 'Firma › Vertrieb', members: 6 }, { type: 'robot', id: 5, name: 'X' }] });
    assert.deepEqual(p.items, [{ type: 'user', id: 7, name: 'Sabine Keller', initials: 'SK', color: '#F28CC2' }, { type: 'group', id: 4, name: 'Vertrieb', sub: 'Firma › Vertrieb', members: 6 }]);
    assert.deepEqual([mail.principalsQuery(' s '), mail.principalsQuery(' sa ')], [null, { q: 'sa' }]);
  });

  it('resources, bookings, decisions and the refusals\' details', () => {
    const r = mail.normalizeResources({ items: [
      { id: 11, name: 'Firmenwagen', kind: 'vehicle', approval: 'approval', approvers: ['Fuhrpark', ''], rules: { maxMinutes: 1440, hours: { days: [1], from: '08:00', to: '18:00' } }, address: 'Resource-11@resources.gatecontrol.invalid', busy: [{ start: 1, end: 2, status: 'pending', mine: true }, { start: 3, end: 4, status: 'free' }] },
      { id: 12, name: 'Raum', kind: 'castle', address: 'raum@firma.de', seats: 0 }, { id: 13 },
    ], kinds: ['room', 'castle'] });
    assert.deepEqual(r.items.map((x) => [x.id, x.kind, x.approval, x.address, x.seats]), [[11, 'vehicle', 'approval', 'resource-11@resources.gatecontrol.invalid', null], [12, 'other', 'auto', null, null]]);
    assert.deepEqual([r.items[0].approvers, r.items[0].rules.maxMinutes, r.items[0].rules.hours.days, r.items[0].busy], [['Fuhrpark'], 1440, [1], [{ start: 1, end: 2, status: 'pending', mine: true }, { start: 3, end: 4, status: 'busy', mine: false }]]);
    assert.deepEqual(r.kinds, ['room']);
    assert.ok(mail.isResourceAddress('resource-7@resources.gatecontrol.invalid') && !mail.isResourceAddress('resource-7@firma.de'));
    assert.deepEqual(mail.resourcesQuery({ from: 1, to: 2, kind: 'room' }), { from: 1, to: 2, kind: 'room' });
    assert.deepEqual(mail.resourcesQuery({ kind: 'all' }), {});
    assert.equal(mail.resourcesQuery({ from: 1 }), null);
    assert.equal(mail.resourcesQuery({ from: 1, to: 1 + 32 * DAY }), null);
    assert.deepEqual(mail.bookBody({ title: ' Kunde ', start: 10, end: 20, timeZone: 'Europe/Berlin', note: '' }), { title: 'Kunde', start: 10, end: 20, timeZone: 'Europe/Berlin' });
    assert.deepEqual(mail.bookBody({ allDay: true, startDate: '2026-11-06' }), { allDay: true, startDate: '2026-11-06', endDate: '2026-11-06' });
    for (const bad of [{ start: 20, end: 10 }, { allDay: true, startDate: '2026-11-06', endDate: '2026-11-05' }, { allDay: 'yes', startDate: '2026-11-06' }, { start: 1, end: 2, calendarId: 'x' }]) assert.equal(mail.bookBody(bad), null, JSON.stringify(bad));
    const b = mail.normalizeBookings({ items: [
      { id: 802, resourceId: 11, resource: { id: 11, name: 'Firmenwagen', kind: 'vehicle' }, title: 'Messe', start: 10, end: 20, allDay: true, startDate: '2026-11-06', endDate: '2026-11-07', state: 'pending', booker: { userId: 21, name: 'Lisa' },
        violations: [{ rule: 'max_duration', limit: 1440 }, { rule: 'hours', days: [1, 2], from: '08:00', to: '18:00' }, { rule: 'teleport' }], conflicts: [{ start: 12, end: 14 }], canDecide: true, day: [{ start: 1, end: 2, status: 'pending' }] },
      { id: 803, resource: { id: 12, name: 'Raum' }, start: 10, end: 20, state: 'confirmed', conflicts: [{ start: 1, end: 2 }], decidedBy: { userId: 1, name: 'Max' }, override: true, comment: 'Ausnahme' },
    ], counts: { open: 2 } });
    assert.deepEqual(b.items[0].violations, [{ rule: 'max_duration', limit: 1440 }, { rule: 'hours', days: [1, 2], from: '08:00', to: '18:00' }]);
    assert.deepEqual([b.items[0].endDate, b.items[0].conflicts.length, b.items[1].conflicts.length, b.items[1].resourceId, b.items[1].decidedBy.name, b.counts.open], ['2026-11-07', 1, 0, 12, 'Max', 2]);
    assert.deepEqual(mail.decideBody({ decision: 'approve', override: true, comment: 'ok' }), { decision: 'approve', comment: 'ok', override: true });
    assert.deepEqual(mail.decideBody({ decision: 'decline', override: false }), { decision: 'decline' });
    assert.equal(mail.decideBody({ decision: 'maybe' }), null);
    assert.deepEqual(mail.refusalDetail({ code: 'already_decided', state: 'confirmed', decidedBy: { userId: 4, name: 'Fuhrpark-Chef', email: 'x@y.de' }, violations: [{ rule: 'horizon', limit: 30 }], conflicts: [{ start: 1, end: 2 }, 'x'] }),
      { violations: [{ rule: 'horizon', limit: 30 }], conflicts: [{ start: 1, end: 2 }], decidedBy: { userId: 4, name: 'Fuhrpark-Chef' } });
  });

  it('live events and push clicks of 1.9.0', () => {
    assert.deepEqual(mail.normalizeResourcesLive({ kind: 'request', bookingId: '801', resourceId: 11, state: 'pending' }), { kind: 'request', bookingId: 801, resourceId: 11, state: 'pending' });
    assert.deepEqual(mail.normalizeResourcesLive({ kind: 'booking', bookingId: null, resourceId: 11, state: 'boom' }), { kind: 'booking', bookingId: null, resourceId: 11, state: null });
    assert.deepEqual(mail.normalizeResourcesLive({ kind: 'resources' }), { kind: 'resources' });
    assert.equal(mail.normalizeResourcesLive({ kind: 'x' }), null);
    assert.deepEqual(mail.normalizeCalendarLive({ kind: 'shares', calendarId: '1' }), { kind: 'shares', calendarId: 1 });
    assert.deepEqual(mail.normalizeCalendarLive({ kind: 'changed', calendarId: 50, accountId: null, shared: true }), { kind: 'changed', calendarId: 50, accountId: null, from: null, to: null, shared: true });
    assert.deepEqual(mail.pushTarget(mail.RESOURCE_REQUEST_TOPIC, { resources: { bookingId: 801, resourceId: 11 } }), { kind: 'requests', bookingId: 801, resourceId: 11 });
    assert.deepEqual(mail.pushTarget(mail.RESOURCE_BOOKING_TOPIC, { resources: { bookingId: 805, resourceId: 12 }, calendar: { eventId: 302, occurrence: null } }), { kind: 'event', eventId: 302, occurrence: null, bookingId: 805 });
    assert.deepEqual(mail.pushTarget(mail.RESOURCE_BOOKING_TOPIC, { resources: { bookingId: 805 } }), { kind: 'bookings', bookingId: 805 });
    assert.deepEqual(mail.pushTarget(mail.SHARE_TOPIC, { calendar: { sharedCalendarId: 50 } }), { kind: 'shared', calendarId: 50 });
  });
});

describe('MailService – free/busy, sharing, resources', () => {
  it('free/busy and suggestions are asked fresh; the planner\'s rows', async () => {
    const { svc, srv } = await setup();
    const fb = await svc.freeBusy({ from: at(0, 0), to: at(1, 0), attendees: ['tim@firma.de', 'kunde@mueller.de'], resources: [12] });
    assert.deepEqual(fb.items.map((r) => [r.kind, r.state]), [['self', 'ok'], ['person', 'ok'], ['external', 'unknown'], ['resource', 'ok']]);
    assert.deepEqual(srv.state.plan.lastFreeBusy.attendees, ['tim@firma.de', 'kunde@mueller.de']);
    const s = await svc.suggestTimes({ duration: 60, from: at(0, 8), attendees: ['tim@firma.de', 'kunde@mueller.de'], limit: 4 });
    assert.deepEqual([s.items.length, s.unknown, s.items[0].end - s.items[0].start], [4, ['kunde@mueller.de'], HOUR]);
    await assert.rejects(svc.freeBusy({ from: 5, to: 4, attendees: [] }), (e) => e.code === 'invalid');
    srv.down = true;
    await assert.rejects(svc.freeBusy({ from: at(0, 0), to: at(1, 0), attendees: [] }), (e) => e.transient, 'offline: no cache');
  });

  it('sharing an own calendar, „Mit mir geteilt“, the shared items in GET events and the offline window', async () => {
    const dir = tmpDir('mail-cache-');
    const { svc, srv } = await setup({}, { cacheDir: () => dir, protect: fakeProtect() });
    const cal = [];
    svc.on('calendar', (x) => cal.push(x));
    const c = await svc.calendars();
    assert.deepEqual([c.shared.map((x) => x.id), c.calendars.find((x) => x.id === 5).sharedBy, c.prefs.freeBusy], [[50, 51], { email: 'team@firma.de' }, true]);
    const sh = await svc.shares(1);
    assert.deepEqual(sh.items.map((x) => [x.name, x.level, x.state]), [['Sabine Keller', 'write', 'accepted'], ['Familie', 'read', 'group'], ['Tom Brandt', 'freebusy', 'pending']]);
    await assert.rejects(svc.shares(3), (e) => e.code === 'not_supported' && e.detail.what === 'share');
    const added = await svc.addShare(1, { type: 'user', id: 9, level: 'read' });
    assert.deepEqual([added.share.name, added.share.state], ['Lisa Maier', 'pending']);
    await assert.rejects(svc.addShare(1, { type: 'user', id: 1, level: 'read' }), (e) => e.code === 'invalid');
    assert.equal((await svc.updateShare(1, added.share.id, 'write')).share.level, 'write');
    assert.deepEqual(await svc.removeShare(1, added.share.id), { ok: true });
    assert.deepEqual(cal.slice(-3), [{ kind: 'shares', calendarId: 1 }, { kind: 'shares', calendarId: 1 }, { kind: 'shares', calendarId: 1 }]);
    assert.deepEqual((await svc.principals('ver')).items.map((x) => [x.type, x.name]), [['group', 'Vertrieb']]);
    assert.equal((await svc.principals('s')).items.length, 0, 'two characters at least');
    const mine = await svc.shared();
    assert.deepEqual([mine.items.length, mine.accounts[0].owner.email], [2, 'team@firma.de']);
    // shown: Team (free/busy only) — its items come without eventId; Urlaube once it is shown
    const range = { from: at(-1, 0), to: at(5, 0) };
    let ev = await svc.events({ ...range, calendars: [1, 2, 51] });
    const busy = ev.items.filter((x) => x.calendarId === 51);
    assert.deepEqual(busy.map((x) => [x.eventId, x.shared, x.title, x.busy]), [[null, 'freebusy', 'Gebucht', 'busy'], [null, 'freebusy', 'Vorläufig', 'tentative']]);
    assert.equal((await svc.updateShared(50, { visible: true })).item.accepted, true);
    assert.deepEqual(cal.at(-1), { kind: 'shares', calendarId: 50 });
    ev = await svc.events({ ...range, calendars: [1, 2, 50, 51] });
    assert.equal(ev.items.find((x) => x.calendarId === 50).shared, 'read');
    const read = await svc.event(950);
    assert.deepEqual([read.event.readOnly, read.event.canEdit, read.event.shared], [true, false, 'read']);
    // offline: the shared items from the cache, with `shared`
    srv.down = true;
    const off = await svc.events({ ...range, calendars: [1, 2, 50, 51] });
    assert.equal(off.offline, true);
    assert.ok(off.items.some((x) => x.calendarId === 51 && x.eventId === null && x.shared === 'freebusy'));
  });

  it('the offline window holds the shown shared calendars', async () => {
    const dir = tmpDir('mail-cache-');
    const { svc, srv } = await setup({}, { cacheDir: () => dir, protect: fakeProtect() });
    await svc.calendars();
    const fills = () => srv.state.requests.filter((r) => r.method === 'GET' && /\/api\/events$/.test(r.path));
    const until = Date.now() + 3000;
    while (fills().length < 2 && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
    assert.equal(fills().length, 2, 'filled');
    for (const r of fills()) assert.deepEqual(r.query.calendars.split(',').filter((x) => ['50', '51'].includes(x)), ['51'], 'with the shown shared calendar');
  });

  it('resources: book (at once / as a request), the refusals in words, bookings, decisions, calling off; events with resources', async () => {
    const { svc, srv } = await setup();
    const cal = [];
    const res = [];
    svc.on('calendar', (x) => cal.push(x));
    svc.on('resources', (x) => res.push(x));
    const list = await svc.resources({ from: at(1, 0), to: at(2, 0) });
    assert.deepEqual(list.items.map((r) => [r.id, r.kind, r.approval]), [[11, 'vehicle', 'approval'], [12, 'room', 'auto'], [13, 'device', 'auto']]);
    assert.deepEqual(list.items[0].busy.map((b) => b.status), ['pending']);
    assert.deepEqual(list.items[1].busy.map((b) => [b.status, b.mine]), [['busy', true]]);
    const car = await svc.book(11, { title: 'Kunde Müller', start: at(3, 12), end: at(3, 15), timeZone: 'Europe/Berlin' });
    assert.deepEqual([car.bookings[0].state, car.event.attendees[0].role, car.event.attendees[0].response], ['pending', 'resource', 'needs_action']);
    assert.deepEqual(cal.at(-1).kind, 'changed');
    const room = await svc.book(13, { title: 'Präsentation', start: at(3, 9), end: at(3, 10) });
    assert.equal(room.bookings[0].state, 'confirmed');
    // the room is taken at 14:00 tomorrow → resource_busy with the conflicts; a long one breaks its rule
    await assert.rejects(svc.book(12, { start: at(1, 14), end: at(1, 15) }), (e) => e.code === 'resource_busy' && e.detail.conflicts.length === 1 && e.detail.name === 'Besprechungsraum 1');
    await assert.rejects(svc.book(12, { start: at(3, 8), end: at(3, 17) }), (e) => e.code === 'rule_violation' && e.detail.violations[0].rule === 'max_duration' && e.detail.violations[0].limit === 480);
    const open = await svc.bookings('open');
    assert.deepEqual([open.items.map((b) => b.id), open.counts.open], [[801, 802], 2]);
    assert.deepEqual([open.items[0].resource.name, open.items[0].resource.kind, open.items[0].booker.name], ['Firmenwagen Kombi', 'vehicle', 'Markus B.']);
    const decline = await svc.decide(801, { decision: 'decline', comment: 'Belegt' });
    assert.deepEqual([decline.booking.state, decline.booking.decidedBy.name], ['declined', 'Max']);
    assert.deepEqual(res.at(-1), { kind: 'request', bookingId: 801, resourceId: 11, state: 'declined' });
    // first decision settles it: already_decided with who decided
    await assert.rejects(svc.decide(801, { decision: 'approve' }), (e) => e.code === 'already_decided' && e.detail.decidedBy.name === 'Max' && e.detail.state === 'declined');
    // a conflict: no approving, not even anyway; a broken rule only with override
    srv.state.plan.bookings.find((b) => b.id === 802).conflicts = [];
    await assert.rejects(svc.decide(802, { decision: 'approve' }), (e) => e.code === 'rule_violation' && e.detail.violations.length === 1);
    assert.equal((await svc.decide(802, { decision: 'approve', override: true })).booking.override, true);
    assert.deepEqual(srv.state.plan.lastDecide, { id: 802, decision: 'approve', override: true });
    const mineList = await svc.bookings('mine');
    assert.ok(mineList.items.some((b) => b.id === 804 && b.state === 'confirmed'));
    assert.deepEqual(await svc.cancelBooking(804), { ok: true });
    assert.deepEqual(res.at(-1), { kind: 'booking', bookingId: 804, resourceId: null, state: 'cancelled' });
    assert.equal((await svc.booking(804)).booking.state, 'cancelled');
    // resources as attendees of a new event: bookings in the answer; not in an account's calendar
    const made = await svc.createEvent({ calendarId: 1, title: 'Sprint', allDay: false, start: at(4, 10), end: at(4, 11), attendees: [{ email: 'tim@firma.de' }, { email: 'resource-11@resources.gatecontrol.invalid', name: 'Firmenwagen Kombi', role: 'resource' }] });
    assert.deepEqual(made.bookings.map((b) => [b.resourceId, b.state]), [[11, 'pending']]);
    await assert.rejects(svc.createEvent({ calendarId: 3, title: 'X', allDay: false, start: at(4, 10), end: at(4, 11), attendees: [{ email: 'resource-12@resources.gatecontrol.invalid', role: 'resource' }] }), (e) => e.code === 'not_supported' && e.detail.what === 'resource');
  });

  it('without the features (a server before 1.9.0) the paths answer feature_off', async () => {
    const { svc } = await setup({ plan: false });
    assert.deepEqual((await svc.me()).features.filter((f) => ['freeBusy', 'calendarSharing', 'resources', 'bookingRequests'].includes(f)), []);
    const c = await svc.calendars();
    assert.deepEqual([c.shared, c.prefs.freeBusy], [[], true]);
    await assert.rejects(svc.resources(), (e) => e.code === 'feature_off' && e.detail.feature === 'resources');
    await assert.rejects(svc.shared(), (e) => e.code === 'feature_off' && e.detail.feature === 'sharing');
  });

  it('live events and push clicks', async () => {
    const pushClient = new EventEmitter();
    const nc = new EventEmitter();
    let resolver = null;
    nc.addClickRoute = (route, fn) => { resolver = fn; return () => { resolver = null; }; };
    const { svc } = await setup({}, { pushClient, notificationCenter: nc });
    const cal = [];
    const res = [];
    svc.on('calendar', (x) => cal.push(x));
    svc.on('resources', (x) => res.push(x));
    const send = (type, data) => pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-mail', type, data } });
    send('resources', { kind: 'request', bookingId: 801, resourceId: 11, state: 'pending' });
    send('resources', { kind: 'booking', bookingId: 805, resourceId: 12, state: 'confirmed' });
    send('resources', { kind: 'resources' });
    send('resources', { kind: 'nope' });
    send('calendar', { kind: 'shares', calendarId: 1 });
    send('calendar', { kind: 'changed', calendarId: 50, accountId: null, shared: true });
    assert.deepEqual(res, [{ kind: 'request', bookingId: 801, resourceId: 11, state: 'pending' }, { kind: 'booking', bookingId: 805, resourceId: 12, state: 'confirmed' }, { kind: 'resources' }]);
    assert.deepEqual(cal, [{ kind: 'shares', calendarId: 1 }, { kind: 'changed', calendarId: 50, accountId: null, from: null, to: null, shared: true }]);
    assert.deepEqual(resolver({ topic: mail.RESOURCE_REQUEST_TOPIC, data: { resources: { bookingId: 801, resourceId: 11 } } }), { kind: 'requests', bookingId: 801, resourceId: 11 });
    assert.deepEqual(resolver({ topic: mail.RESOURCE_BOOKING_TOPIC, data: { resources: { bookingId: 805, resourceId: 12 }, calendar: { eventId: 302, occurrence: null } } }), { kind: 'event', eventId: 302, occurrence: null, bookingId: 805 });
    assert.deepEqual(resolver({ topic: mail.SHARE_TOPIC, data: { calendar: { sharedCalendarId: 50 } } }), { kind: 'shared', calendarId: 50 });
  });
});

describe('mail IPC – free/busy, sharing, resources', () => {
  it('checks arguments, passes the refusals\' details and forwards mail:resources', async () => {
    const { svc } = await setup();
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerMailHandlers((ch, fn) => { handlers[ch] = fn; }, { mail: svc, getMainWindow: () => win, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('mail:freebusy', { from: 'x', to: 5 })).code, 'invalid');
    assert.equal((await call('mail:freebusy', { from: at(0, 0), to: at(1, 0), attendees: 'tim@firma.de' })).code, 'invalid');
    assert.equal((await call('mail:freebusy', { from: at(0, 0), to: at(1, 0), attendees: ['tim@firma.de'] })).items[1].name, 'Tom');
    assert.equal((await call('mail:freebusy:suggest', { duration: '60', attendees: [] })).code, 'invalid');
    assert.equal((await call('mail:freebusy:suggest', { duration: 30, attendees: [] })).items.length, 4);
    assert.equal((await call('mail:shares', { calendarId: '1' })).code, 'invalid');
    assert.equal((await call('mail:share:add', { calendarId: 1, type: 'user', id: 9, level: 'owner' })).code, 'invalid');
    assert.equal((await call('mail:share:add', { calendarId: 1, type: 'group', id: 4, level: 'freebusy' })).share.members, 6);
    assert.equal((await call('mail:share:update', { calendarId: 1, shareId: 'x', level: 'read' })).code, 'invalid');
    assert.equal((await call('mail:share:delete', { calendarId: 1, shareId: 71 })).ok, true);
    assert.equal((await call('mail:shared')).items.length, 2);
    assert.equal((await call('mail:shared:update', { id: 51, color: 'red' })).code, 'invalid');
    assert.equal((await call('mail:shared:update', { id: 51, visible: false })).item.visible, false);
    assert.equal((await call('mail:principals', { q: 5 })).code, 'invalid');
    assert.equal((await call('mail:principals', { q: 'sab' })).items[0].initials, 'SK');
    assert.equal((await call('mail:resources', { kind: 'castle' })).code, 'invalid');
    assert.equal((await call('mail:resources', { kind: 'room' })).items.length, 1);
    const busy = await call('mail:resource:book', { id: 12, start: at(1, 14), end: at(1, 15) });
    assert.deepEqual([busy.ok, busy.code, busy.detail.conflicts.length], [false, 'resource_busy', 1]);
    const rule = await call('mail:resource:book', { id: 12, start: at(3, 8), end: at(3, 17) });
    assert.deepEqual([rule.code, rule.detail.violations], ['rule_violation', [{ rule: 'max_duration', limit: 480 }]]);
    assert.equal((await call('mail:bookings', { state: 'all' })).code, 'invalid');
    assert.equal((await call('mail:bookings', { state: 'open' })).counts.open, 2);
    assert.equal((await call('mail:booking:decide', { id: 801, decision: 'yes' })).code, 'invalid');
    assert.equal((await call('mail:booking:decide', { id: 801, decision: 'approve', override: 'x' })).code, 'invalid');
    assert.equal((await call('mail:booking:decide', { id: 801, decision: 'approve' })).booking.state, 'confirmed');
    const again = await call('mail:booking:decide', { id: 801, decision: 'decline' });
    assert.deepEqual([again.code, again.detail.decidedBy.name, again.detail.state], ['already_decided', 'Max', 'confirmed']);
    assert.equal((await call('mail:booking:cancel', { id: 'x' })).code, 'invalid');
    assert.equal((await call('mail:cal:settings', { freeBusy: false })).prefs.freeBusy, false);
    assert.equal((await call('mail:cal:settings', { workHours: { days: [1], from: '10:00', to: '09:00' } })).code, 'invalid');
    svc.emit('resources', { kind: 'resources' });
    assert.deepEqual(sent.at(-1), ['mail:resources', { kind: 'resources' }]);
  });
});
