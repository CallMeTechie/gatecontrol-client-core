'use strict';

// Notizen & Aufgaben 1.7.0 with Drive 1.30.0: „Notizen & Aufgaben“ rings the reminders of Drive's deadlines. Told by the
// words only — `driveDeadlines` of the hub's me.features, `deadlineHub` of Drive's — never by a version. The pure
// helpers (utils/notes.js: a task's `deadline`, `me.driveDeadlines`, the file of the button „Datei öffnen“;
// utils/drive.js: who rings a reminder, `reminder.by`; utils/portal.js: the tab of a portal path with a query),
// NotesService and DriveService against the fake servers (an older plugin stays as it was), and the button „Datei
// öffnen“ of the reminder: the Drive page opens the file when there is one, else the portal as the server sent it.
// Also here: the own role in a list or a notebook as the plugin names it (owner | write | read) with `canEdit`.

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

const N = require('../src/utils/notes');
const drive = require('../src/utils/drive');
const { portalTab } = require('../src/utils/portal');
const NotesService = require('../src/services/notes');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const NotificationCenter = require('../src/services/notification-center');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer, FEATURES, STAGE1, STAGE2, STAGE3, STAGE4, STAGE5 } = require('./fixtures/notes-server');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const OLD = [...FEATURES, ...STAGE1, ...STAGE2, ...STAGE3, ...STAGE4];
const ALL = [...OLD, ...STAGE5];
const TOPIC = 'plugin:gatecontrol-notizen:reminders';
const DEADLINE = { date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf', daysBefore: 3, open: { plugin: 'gatecontrol-drive', route: 'node/41' } };
const FILE_BTN = { id: 'open_file', type: 'open_portal', label: 'Datei öffnen', target: '/portal?drive=41#plg-gatecontrol-drive' };

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function notesSetup(opts = {}, notificationCenter = null) {
  const srv = await notesServer(opts);
  cleanup.push(() => srv.close());
  const svc = new NotesService({
    apiClient: new ApiClient(srv.url, 'gc_token', log), log, store: createMemoryStore(), protect: null, getLang: () => 'de',
    pushClient: null, notificationCenter, dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}

async function driveSetup(features, notificationCenter = null) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  apiClient.portalUrl = 'https://gc.example.com/portal';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive130-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({
    apiClient, api: new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} }), log, store: createMemoryStore(), tempDir: () => tmp,
    allowedHosts: () => ['gc.example.com'], notificationCenter, shell: { openExternal: async () => {}, openPath: async () => '' },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}

function center() {
  class FakeNotification extends EventEmitter {
    show() {} close() { this.emit('close'); }
    static isSupported() { return true; }
  }
  const push = new EventEmitter();
  push.acks = [];
  push.ack = async (seqs, state, action) => { push.acks.push({ seqs, state, action }); return { ok: true }; };
  const portal = [];
  const nc = new NotificationCenter({
    store: createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } }), log, pushClient: push,
    Notification: FakeNotification, platform: 'win32', protocol: 'gatecontrol-pro', showWindow: () => {}, openPortal: async (p) => { portal.push(p); return true; },
  });
  const navigate = [];
  nc.on('navigate', (x) => navigate.push(x));
  return { nc, push, portal, navigate };
}

const note = (seq, p) => ({
  seq, id: seq + 1000, event_id: 'reminder', topic: p.topic, priority: 'normal', title: p.title, body: p.body, created_at: '2026-11-27T07:00:00Z',
  expires_at: '2026-12-27T07:00:00Z', collapse_key: p.collapseKey, silent: false, data: p.data, received_at: '2026-11-27T07:00:01Z', via: 'direct',
});

describe('utils: plugin 1.7.0 / Drive 1.30.0', () => {
  it('cleans a task\'s deadline; every other task and an older plugin have none', () => {
    const t = N.normalizeTask({ id: 77, title: 'Kfz-Versicherung kündigen', due: { date: '2026-11-30', time: null }, source: { plugin: 'gatecontrol-drive', id: 'deadline:12' }, deadline: DEADLINE });
    assert.deepEqual(t.deadline, DEADLINE);
    assert.deepEqual(t.source, { plugin: 'gatecontrol-drive', id: 'deadline:12' });
    assert.equal(N.normalizeTask({ id: 1, title: 'x' }).deadline, null);
    assert.equal(N.normalizeTask({ id: 1, title: 'x', deadline: null }).deadline, null);
    assert.equal(N.normalizeTask({ id: 1, title: 'x', deadline: 'soon' }).deadline, null);
    // what does not fit is left out, not guessed: an unknown kind, a strange day, days outside 0…90, a link that is no plugin's
    const odd = N.normalizeTask({ id: 1, deadline: { date: '30.11.2026', kind: 'tax', file: ' Schein.pdf\n', daysBefore: 91, open: { plugin: 'https://evil.example', route: 'node/1' } } }).deadline;
    assert.deepEqual(odd, { date: null, kind: null, file: 'Schein.pdf', daysBefore: null, open: null });
    assert.deepEqual([0, 1, 90, -1, 2.5, '3'].map((daysBefore) => N.normalizeTask({ id: 1, deadline: { daysBefore } }).deadline.daysBefore), [0, 1, 90, null, null, null]);
    assert.deepEqual(['payment', 'cancellation', 'objection', 'warranty', 'renewal', null].map((kind) => N.normalizeTask({ id: 1, deadline: { kind } }).deadline.kind),
      ['payment', 'cancellation', 'objection', 'warranty', 'renewal', null]);
    // a route that is none stays the plugin's start
    assert.deepEqual(N.normalizeTask({ id: 1, deadline: { open: { plugin: 'gatecontrol-drive', route: 'node/41?x=<y>' } } }).deadline.open, { plugin: 'gatecontrol-drive', route: '' });
  });

  it('cleans me.driveDeadlines', () => {
    assert.deepEqual(N.normalizeMe({ driveDeadlines: { available: true, active: true } }).driveDeadlines, { available: true, active: true });
    assert.deepEqual(N.normalizeMe({ driveDeadlines: { available: 1, active: 'yes' } }).driveDeadlines, { available: false, active: false });
    assert.equal(N.normalizeMe({}).driveDeadlines, null);
  });

  it('the reminder of a deadline is a reminder: a click opens the task; „Datei öffnen“ names the file', () => {
    const data = { notizen: { kind: 'reminder', taskId: 77, task: 77, listId: 5, area: 'private', tag: 'task:77:1795762800000', deadline: DEADLINE }, actions: [FILE_BTN] };
    assert.deepEqual(N.pushTarget(TOPIC, data), { kind: 'task', taskId: 77 });
    assert.deepEqual(N.pushTarget(TOPIC, data, 'done'), { kind: 'task', taskId: 77 });
    assert.deepEqual(N.pushFile(TOPIC, data, 'open_file'), { plugin: 'gatecontrol-drive', route: 'node/41' });
    // another button, a click on the message, another plugin's push, a reminder without a deadline, a deadline without its file
    assert.equal(N.pushFile(TOPIC, data, 'done'), null);
    assert.equal(N.pushFile(TOPIC, data, null), null);
    assert.equal(N.pushFile('plugin:gatecontrol-drive:deadline', data, 'open_file'), null);
    assert.equal(N.pushFile(TOPIC, { notizen: { kind: 'reminder', taskId: 77 } }, 'open_file'), null);
    assert.equal(N.pushFile(TOPIC, { notizen: { deadline: { ...DEADLINE, open: { plugin: 'gatecontrol-drive', route: '' } } } }, 'open_file'), null);
    assert.equal(N.pushFile(TOPIC, { notizen: { deadline: { ...DEADLINE, open: null } } }, 'open_file'), null);
    assert.equal(N.pushFile(TOPIC, null, 'open_file'), null);
  });

  it('a deadline of Drive names who rings its reminder; an older Drive names nobody: Drive', () => {
    const dl = (reminder) => drive.normalizeDeadline({ id: 12, kind: 'cancellation', date: '2026-11-30', reminder }).reminder;
    assert.deepEqual(dl({ at: '2026-11-27T07:00:00.000Z', daysBefore: 3, sent: false, by: 'notizen' }), { at: Date.parse('2026-11-27T07:00:00Z'), daysBefore: 3, sent: false, by: 'notizen' });
    assert.equal(dl({ at: '2026-11-27T07:00:00.000Z', daysBefore: 3, sent: false, by: 'drive' }).by, 'drive');
    assert.equal(dl({ at: '2026-11-27T07:00:00.000Z', daysBefore: 3, sent: true }).by, 'drive');
    assert.equal(dl({ at: '2026-11-27T07:00:00.000Z', daysBefore: 3, by: 'somebody' }).by, 'drive');
    assert.equal(dl(null), null);
  });

  it('the tab of a portal path, with or without a query', () => {
    assert.equal(portalTab('/portal?drive=41#plg-gatecontrol-drive'), 'plg-gatecontrol-drive');
    assert.equal(portalTab('/portal#plg-gatecontrol-notizen'), 'plg-gatecontrol-notizen');
    assert.equal(portalTab('/#geraete'), 'geraete');
    assert.equal(portalTab('/portal/?open=node/41#plg-gatecontrol-drive'), 'plg-gatecontrol-drive');
    for (const bad of ['/portal', '/portal?drive=41', '//evil.example#plg-gatecontrol-drive', '/other#plg-gatecontrol-drive', '/portal#unknown', '/portal#plg-x#plg-y', '', null, 41]) {
      assert.equal(portalTab(bad), null, String(bad));
    }
  });

  it('the own role in a list and a notebook: owner, write, read — and may this person change anything', () => {
    const role = (o) => { const l = N.normalizeList({ id: 5, name: 'Haus', ...o }); return [l.role, l.canEdit]; };
    assert.deepEqual(role({ role: 'owner', canEdit: true }), ['owner', true]);
    assert.deepEqual(role({ role: 'write', canEdit: true }), ['write', true]);
    assert.deepEqual(role({ role: 'read', canEdit: false }), ['read', false]);
    // a plugin before 1.2.0 names no `canEdit` and has nobody who only reads
    assert.deepEqual(role({ role: 'owner' }), ['owner', true]);
    assert.deepEqual(role({ role: 'member' }), ['write', true]);
    assert.deepEqual(role({ role: 'read' }), ['read', false]);
    assert.deepEqual(role({ role: 'boss' }), [null, true]);
    assert.deepEqual(role({}), [null, true]);
    const nb = (o) => { const b = N.normalizeNotebook({ id: 5, name: 'Rezepte', ...o }); return [b.role, b.canEdit]; };
    assert.deepEqual([nb({ role: 'owner', canEdit: true }), nb({ role: 'write', canEdit: true }), nb({ role: 'read', canEdit: false }), nb({})], [['owner', true], ['write', true], ['read', false], [null, true]]);
  });
});

describe('NotesService: an older plugin (without the word of 1.7.0) stays as it was', () => {
  it('no deadline at a task, no me.driveDeadlines; the reminder has its three buttons', async () => {
    const { srv, svc } = await notesSetup({ features: OLD });
    const x = srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf' });
    assert.equal(svc.status().features.includes('driveDeadlines'), false);
    assert.equal((await svc.me({ refresh: true })).me.driveDeadlines, null);
    const got = (await svc.task(x.id)).task;
    assert.equal(got.deadline, null);
    assert.deepEqual(got.source, { plugin: 'gatecontrol-drive', id: 'deadline:12' });
    const p = srv.reminderPush(x.id);
    assert.deepEqual(p.data.actions.map((a) => a.id), ['done', 'snooze_1h', 'snooze_eve']);
    assert.equal(p.data.notizen.deadline, undefined);
    assert.deepEqual(svc.clickContext({ topic: p.topic, data: p.data }, { id: 'open_file' }), { kind: 'task', taskId: x.id });
  });
});

describe('NotesService: a task that reminds of a deadline in Drive (plugin 1.7.0)', () => {
  it('the deadline at the task, in the views and in me; it is completed, changed and deleted like any task', async () => {
    const { srv, svc } = await notesSetup({ features: ALL });
    assert.deepEqual((await svc.me({ refresh: true })).me.driveDeadlines, { available: true, active: false });
    const x = srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf', daysBefore: 3, nodeId: 41 });
    assert.deepEqual((await svc.me({ refresh: true })).me.driveDeadlines, { available: true, active: true });
    const got = (await svc.task(x.id)).task;
    assert.deepEqual(got.deadline, DEADLINE);
    assert.deepEqual([got.due, got.remindAt], [{ date: '2026-11-30', time: null }, '2026-11-27T08:00:00+01:00']);
    const row = (await svc.view({ name: 'list:1' })).view.sections.flatMap((s) => s.items).find((r) => r.id === x.id);
    assert.deepEqual(row.deadline, DEADLINE);
    // every other task: null
    assert.equal((await svc.task(11)).task.deadline, null);
    // the reminder time at the task, „Erledigt“, deleting: the routes of every task
    assert.equal((await svc.updateTask(x.id, { remindAt: { date: '2026-11-26', time: '09:00' } })).task.remindAt, '2026-11-26T09:00:00+01:00');
    assert.equal((await svc.completeTask(x.id, true)).task.done, true);
    await svc.deleteTask(x.id);
    assert.deepEqual((await svc.me({ refresh: true })).me.driveDeadlines, { available: true, active: false });
  });
});

describe('DriveService: who rings a reminder (Drive 1.30.0)', () => {
  it('„über Notizen & Aufgaben“ while the hub reminds; a Drive that reminds itself; an older Drive', async () => {
    const hub = await driveSetup(['docAi', 'deadlineHub']);
    hub.srv.setInsight(12, { kind: 'contract', deadlines: [{ kind: 'cancellation', date: '2099-03-31', label: 'Kündigung' }] });
    const id = (await hub.svc.insight(12)).insight.deadlines[0].id;
    assert.equal((await hub.svc.remind(id, 3)).deadline.reminder.by, 'notizen');
    assert.equal((await hub.svc.deadlines({})).deadlines[0].reminder.by, 'notizen');
    assert.equal((await hub.svc.insight(12)).insight.deadlines[0].reminder.by, 'notizen');
    // the administrator switched back: Drive reminds itself
    hub.srv.remindBy = 'drive';
    assert.equal((await hub.svc.remind(id, 7)).deadline.reminder.by, 'drive');
    assert.equal((await hub.svc.remind(id, null)).deadline.reminder, null);

    const old = await driveSetup(['docAi']);
    old.srv.setInsight(12, { kind: 'contract', deadlines: [{ kind: 'cancellation', date: '2099-03-31', label: 'Kündigung' }] });
    const oid = (await old.svc.insight(12)).insight.deadlines[0].id;
    await old.svc.remind(oid, 3);
    assert.equal(Object.prototype.hasOwnProperty.call(old.srv.state.deadlines[0].reminder, 'by'), false, 'the fake of an older Drive names nobody');
    assert.equal((await old.svc.deadlines({})).deadlines[0].reminder.by, 'drive');
  });
});

describe('„Datei öffnen“ at the reminder of a deadline', () => {
  it('opens the file on the Drive page — whichever page was asked first; every other button stays what it was', async () => {
    for (const order of ['notes-first', 'drive-first']) {
      const { nc, push, portal, navigate } = center();
      let notes;
      if (order === 'notes-first') { notes = await notesSetup({ features: ALL }, nc); await driveSetup(['docAi', 'deadlineHub'], nc); }
      else { await driveSetup(['docAi', 'deadlineHub'], nc); notes = await notesSetup({ features: ALL }, nc); }
      const x = notes.srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf', daysBefore: 3, nodeId: 41 });
      const p = notes.srv.reminderPush(x.id);
      assert.deepEqual([p.title, p.body], ['Frist in 3 Tagen: Kfz-Versicherung kündigen', 'Kündigung bis 30.11.2026 · Versicherungsschein.pdf']);
      assert.deepEqual(p.data.actions.map((a) => [a.id, a.type]), [['done', 'callback'], ['snooze_1h', 'callback'], ['snooze_eve', 'callback'], ['open_file', 'open_portal']]);
      nc.handleNotification(note(1, p));
      // the fourth button: the file on the Drive page, not the portal
      assert.deepEqual(await nc.performAction(1001, 'open_file'), { ok: true }, order);
      assert.deepEqual(navigate, [{ route: 'plg-gatecontrol-drive', id: 1001, context: { kind: 'deadline', nodeId: 41, deadlineId: null, areaId: null, action: 'open_file' } }], order);
      assert.deepEqual(portal, [], order);
      assert.deepEqual(push.acks.at(-1), { seqs: [1], state: 'read', action: 'open_file' });
      // „Erledigt“ is the callback of every reminder: nothing opens
      assert.deepEqual(await nc.performAction(1001, 'done'), { ok: true });
      assert.equal(navigate.length, 1);
      assert.deepEqual(push.acks.at(-1), { seqs: [1], state: 'read', action: 'done' });
      // a click on the message itself opens the task
      assert.deepEqual(nc.clickTarget(nc.get(1001)), { route: 'plg-gatecontrol-notizen', context: { kind: 'task', taskId: x.id } }, order);
      for (const fn of cleanup.splice(0).reverse()) await fn();
    }
  });

  it('opens the portal as the server sent it when there is no Drive page, and for a file that is no file of Drive', async () => {
    const { nc, portal, navigate } = center();
    const notes = await notesSetup({ features: ALL }, nc);
    const x = notes.srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf', nodeId: 41 });
    const p = notes.srv.reminderPush(x.id);
    nc.handleNotification(note(1, p));
    assert.deepEqual(await nc.performAction(1001, 'open_file'), { ok: true });
    assert.deepEqual(portal, ['/portal?drive=41#plg-gatecontrol-drive']);
    assert.equal(navigate.length, 0);
    // Drive is there, but the push names another plugin's page or no node: not Drive's
    const d = await driveSetup(['docAi', 'deadlineHub'], nc);
    const entry = (open) => ({ topic: TOPIC, data: { notizen: { kind: 'reminder', taskId: 77, task: 77, deadline: { ...DEADLINE, open } }, actions: [FILE_BTN] } });
    assert.equal(d.svc.clickContext(entry({ plugin: 'gatecontrol-mail', route: 'message/9' }), FILE_BTN), null);
    assert.equal(d.svc.clickContext(entry({ plugin: 'gatecontrol-drive', route: 'folder/9' }), FILE_BTN), null);
    assert.equal(d.svc.clickContext(entry(DEADLINE.open), { id: 'done', type: 'callback' }), null);
    assert.equal(d.svc.clickContext(entry(DEADLINE.open), null), null, 'a click on the message is the task\'s');
    assert.deepEqual(d.svc.clickContext(entry(DEADLINE.open), FILE_BTN), { kind: 'deadline', nodeId: 41, deadlineId: null, areaId: null, action: 'open_file' });
    // Drive's own reminder (the hub does not ring): unchanged
    assert.deepEqual(d.svc.clickContext({ topic: 'plugin:gatecontrol-drive:deadline', data: { drive: { node: 12, area: 'mine:2', deadline: 3 } } }), { kind: 'deadline', nodeId: 12, deadlineId: 3, areaId: 'mine:2' });
  });
});

describe('NotesService: a member who only reads a list', () => {
  it('the list says so (role read, canEdit false), its tasks too, and the server refuses a change', async () => {
    const { srv, svc } = await notesSetup({ features: ALL });
    const l = srv.state.lists.get(2);
    Object.assign(l, { ownerId: 12, readers: [1] });
    srv.addTask({ id: 61, listId: 2, title: 'Hecke schneiden' });
    srv.addTask({ id: 62, listId: 2, title: 'Laub rechen', assigneeId: 1 });
    const lists = (await svc.nav({ area: 'private' })).nav.lists;
    assert.deepEqual(lists.map((x) => [x.id, x.role, x.canEdit]), [[1, 'owner', true], [2, 'read', false], [3, 'owner', true]]);
    const v = (await svc.view({ name: 'list:2' })).view;
    assert.deepEqual([v.list.role, v.list.canEdit], ['read', false]);
    assert.deepEqual(v.sections[0].items.filter((x) => x.id > 60).map((x) => [x.id, x.canEdit, x.canComplete]), [[61, false, false], [62, false, true]]);
    await assert.rejects(svc.updateTask(61, { title: 'x' }), (e) => e.code === 'forbidden');
    await assert.rejects(svc.createTask({ listId: 2, title: 'x' }), (e) => e.code === 'forbidden');
    // somebody who writes
    l.readers = [];
    assert.deepEqual((({ role, canEdit }) => [role, canEdit])((await svc.view({ name: 'list:2' })).view.list), ['write', true]);
  });
});
