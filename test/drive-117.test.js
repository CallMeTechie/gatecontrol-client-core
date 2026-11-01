'use strict';

// Drive 1.17 in the Windows Pro app ('deadlineMailCalendar'): deadlines into a calendar of the mail plugin too — the
// calendars to choose (deadlines/calendars), the person's own target per area (deadlines/targets), "In Kalender
// eintragen" with a target, the entry's target — and the IPC.

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

const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(features) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive117-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api };
}

describe('utils/drive: Drive 1.17 answers', () => {
  it('cleans targets, the calendars to choose, the targets per area and the entry of a deadline', () => {
    assert.equal(drive.normalizeDeadlineTarget(null), null);
    assert.equal(drive.normalizeDeadlineTarget({ kind: 'other' }), null);
    assert.deepEqual(drive.normalizeDeadlineTarget({ kind: 'family' }), { kind: 'family', label: null });
    assert.deepEqual(drive.normalizeDeadlineTarget({ kind: 'mail', calendarId: 7, label: ' Outlook · Kalender ' }), { kind: 'mail', calendarId: '7', label: 'Outlook · Kalender' });

    assert.equal(drive.deadlineTargetBody(null), null);
    assert.deepEqual(drive.deadlineTargetBody({ kind: 'family', label: 'x' }), { kind: 'family' });
    assert.deepEqual(drive.deadlineTargetBody({ kind: 'mail', calendarId: 'cal-1' }), { kind: 'mail', calendarId: 'cal-1' });
    assert.deepEqual(drive.deadlineTargetBody({ kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' }), { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' });
    assert.equal(drive.deadlineTargetBody({ kind: 'mail' }), undefined);
    assert.equal(drive.deadlineTargetBody(undefined), undefined);
    assert.equal(drive.deadlineTargetBody('family'), undefined);

    const c = drive.normalizeDeadlineCalendars({
      family: true,
      mail: [
        { id: 'cal-1', name: 'Kalender', account: { id: 'acc-1', label: 'Outlook', kind: 'microsoft' }, color: '#3366ff' },
        { id: 'cal-1', name: 'doppelt' },
        { id: 9, name: '', account: null, color: 'red' },
        { name: 'ohne id' },
      ],
    });
    assert.deepEqual(c, {
      family: true,
      mail: [
        { id: 'cal-1', name: 'Kalender', account: { id: 'acc-1', label: 'Outlook', kind: 'microsoft' }, color: '#3366ff' },
        { id: '9', name: '9', account: { id: '', label: '', kind: null }, color: null },
      ],
    });
    assert.deepEqual(drive.normalizeDeadlineCalendars(null), { family: false, mail: [] });

    assert.deepEqual(drive.normalizeDeadlineTargets({
      targets: [
        { areaId: 'mine:2', label: 'Meine Dateien', target: { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' } },
        { areaId: 'mine:2', label: 'doppelt', target: null },
        { areaId: 'family:1', label: 'Familie', target: { kind: 'family' } },
        { areaId: 'a b', target: null },
      ],
    }).targets, [
      { areaId: 'mine:2', label: 'Meine Dateien', target: { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' } },
      { areaId: 'family:1', label: 'Familie', target: { kind: 'family', label: null } },
    ]);

    const d = drive.normalizeDeadline({ id: 3, kind: 'cancellation', date: '2026-11-30', calendar: { eventId: 'm1', at: '2026-11-01T10:00:00Z', target: { kind: 'mail', label: 'Outlook' } } });
    assert.deepEqual(d.calendar, { eventId: 'm1', at: Date.parse('2026-11-01T10:00:00Z'), target: { kind: 'mail', calendarId: null, label: 'Outlook' } });
  });
});

describe('DriveService: Drive 1.17', () => {
  it('deadlineMailCalendar: the calendars, my target per area, a deadline into a mail calendar (once), mail_unavailable', async () => {
    const { srv, svc } = await setup(['docAi', 'deadlineCalendar', 'deadlineMailCalendar']);
    const cals = await svc.deadlineCalendars();
    assert.equal(cals.ok, true);
    assert.equal(cals.family, true);
    assert.deepEqual(cals.mail.map((c) => `${c.account.label} · ${c.name}`), ['Outlook · Kalender', 'Posteo · Privat']);

    // the areas with AI for documents, the old switch as the default
    await svc.setDeadlinesToCalendar('family:1', true);
    const t0 = (await svc.deadlineTargets()).targets;
    assert.deepEqual(t0.find((t) => t.areaId === 'family:1').target, { kind: 'family', label: null });
    assert.equal(t0.find((t) => t.areaId === 'mine:2').target, null);

    const t1 = (await svc.setDeadlineTarget('mine:2', { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' })).targets;
    assert.deepEqual(t1.find((t) => t.areaId === 'mine:2').target, { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' });
    assert.equal((await svc.setDeadlineTarget('mine:2', null)).targets.find((t) => t.areaId === 'mine:2').target, null);
    await assert.rejects(svc.setDeadlineTarget('mine:2', { kind: 'mail' }), (e) => e.code === 'invalid');
    await assert.rejects(svc.setDeadlineTarget('mine:2', { kind: 'mail', calendarId: 'gone' }), (e) => e.code === 'not_found');

    srv.setInsight(12, { kind: 'contract', deadlines: [{ kind: 'cancellation', date: '2099-11-30', label: 'Kfz-Versicherung kündigen' }, { kind: 'payment', date: '2099-12-01', label: 'Zahlen' }] });
    const list = (await svc.deadlines({ from: '2026-01-01', to: '2099-12-31' })).deadlines;
    const r = await svc.calendar(list[0].id, { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' });
    assert.deepEqual(r.deadline.calendar.target, { kind: 'mail', calendarId: null, label: 'Outlook' });
    // the same target again: the entry there
    assert.equal((await svc.calendar(list[0].id, { kind: 'mail', calendarId: 'cal-1' })).deadline.calendar.eventId, r.deadline.calendar.eventId);
    // the family calendar as before (no target in the body)
    assert.equal((await svc.calendar(list[1].id, { kind: 'family' })).deadline.calendar.eventId, `ev-${list[1].id}`);
    assert.deepEqual(srv.state.calendarBodies.map((b) => b.target ? b.target.calendarId : null), ['cal-1', 'cal-1', null]);

    srv.mail = false;
    srv.setInsight(13, { kind: 'other', deadlines: [{ kind: 'payment', date: '2099-10-01' }] });
    const third = (await svc.deadlines({ from: '2026-01-01', to: '2099-12-31' })).deadlines.find((d) => !d.calendar);
    await assert.rejects(svc.calendar(third.id, { kind: 'mail', calendarId: 'cal-2' }), (e) => e.code === 'mail_unavailable' && e.body.reason === 'auth_expired');
    assert.deepEqual((await svc.deadlineCalendars()).mail, []);
  });

  it('older Drives: no calendars, no targets, no mail target — the family calendar as before', async () => {
    const { srv, svc } = await setup(['docAi', 'deadlineCalendar']);
    await assert.rejects(svc.deadlineCalendars(), (e) => e.code === 'unsupported');
    await assert.rejects(svc.deadlineTargets(), (e) => e.code === 'unsupported');
    await assert.rejects(svc.setDeadlineTarget('mine:2', { kind: 'family' }), (e) => e.code === 'unsupported');
    srv.setInsight(12, { kind: 'contract', deadlines: [{ kind: 'cancellation', date: '2099-11-30' }] });
    const [d] = (await svc.deadlines({ from: '2026-01-01', to: '2099-12-31' })).deadlines;
    await assert.rejects(svc.calendar(d.id, { kind: 'mail', calendarId: 'cal-1' }), (e) => e.code === 'unsupported');
    const r = await svc.calendar(d.id);
    assert.deepEqual(r.deadline.calendar, { eventId: `ev-${d.id}`, at: r.deadline.calendar.at, target: null });
    assert.deepEqual(srv.state.calendarBodies, [{}]);
  });
});

describe('IPC: Drive 1.17', () => {
  it('drive:deadline:calendars / targets / target and the target of drive:deadline:calendar, checked', async () => {
    const { srv, svc } = await setup(['docAi', 'deadlineCalendar', 'deadlineMailCalendar']);
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    for (const [ch, arg] of [
      ['drive:deadline:target', { areaId: 'mine:2' }], ['drive:deadline:target', { areaId: '', target: null }],
      ['drive:deadline:target', { areaId: 'mine:2', target: { kind: 'mail' } }], ['drive:deadline:target', { areaId: 'mine:2', target: 'family' }],
      ['drive:deadline:target', { areaId: 'mine:2', target: { kind: 'mail', calendarId: 'x'.repeat(201) } }],
      ['drive:deadline:calendar', { id: 3, target: { kind: 'weird' } }], ['drive:deadline:calendar', { id: 3, target: [] }],
    ]) {
      const r = await handlers[ch](null, arg);
      assert.equal(r.ok, false, `${ch} ${JSON.stringify(arg)}`);
      assert.equal(r.code, 'invalid');
    }
    assert.equal((await handlers['drive:deadline:calendars'](null)).mail.length, 2);
    assert.equal((await handlers['drive:deadline:targets'](null)).targets.length > 0, true);
    const set = await handlers['drive:deadline:target'](null, { areaId: 'mine:2', target: { kind: 'family' } });
    assert.deepEqual(set.targets.find((t) => t.areaId === 'mine:2').target, { kind: 'family', label: null });
    srv.setInsight(12, { kind: 'contract', deadlines: [{ kind: 'cancellation', date: '2099-11-30' }] });
    const [d] = (await svc.deadlines({ from: '2026-01-01', to: '2099-12-31' })).deadlines;
    const r = await handlers['drive:deadline:calendar'](null, { id: d.id, target: { kind: 'mail', calendarId: 'cal-2', label: 'Posteo · Privat' } });
    assert.deepEqual(r.deadline.calendar.target, { kind: 'mail', calendarId: null, label: 'Posteo' });
  });
});
