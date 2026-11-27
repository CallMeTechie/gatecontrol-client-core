'use strict';

// Notizen & Aufgaben, plugin 1.6.0 (the words taskTurns, taskStars, familyTasks, doneFeedback, placeMine of me.features
// — never a version): whose turn („reihum“, „wer zuerst“), stars and the family's list in the Windows apps. The plugin's
// second small module after the parser (src/vendor/notizen/turnwords.js, unchanged) against ALL of its vectors — the
// parser and its vectors stay untouched —, the pure helpers (utils/notes.js: a task's turn, people, stars, doneBy,
// family; the family's list; me.familyTasks; prefs.feedback; a place's mine / canConsent; what the renderer may send;
// where a click on the new messages leads), NotesService against the fake server (an older plugin stays as it was;
// „reihum“ and „wer zuerst“ made and ticked off; stars only by parents; a parent ticks off for a child; what a child
// may; the note „Umzug abgeschlossen“; the message to the parents; who may accept a place) and the IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const N = require('../src/utils/notes');
const R = require('../src/vendor/notizen/repeat');
global.GCRepeat = R;
const Q = require('../src/vendor/notizen/quickparse');
const TW = require('../src/vendor/notizen/turnwords');
const NotesService = require('../src/services/notes');
const ApiClient = require('../src/services/api-client');
const { registerNotesHandlers } = require('../src/ipc/notes-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer, FEATURES, STAGE1, STAGE2, STAGE3, STAGE4 } = require('./fixtures/notes-server');
const tv = require('./fixtures/notes/turnwords-vectors.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const OLD = [...FEATURES, ...STAGE1, ...STAGE2, ...STAGE3];
const ALL = [...OLD, ...STAGE4];
const TOPIC = 'plugin:gatecontrol-notizen:shared';
const sha = (file) => crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '..', file))).digest('hex');

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(opts = {}) {
  const srv = await notesServer(opts);
  cleanup.push(() => srv.close());
  const svc = new NotesService({
    apiClient: new ApiClient(srv.url, 'gc_token', log), log, store: createMemoryStore(), protect: null, getLang: () => 'de',
    pushClient: null, notificationCenter: null, dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}
const asked = (srv, re) => srv.state.requests.filter((r) => re.test(`${r.method} ${r.path}`));
/** A failure → [code, reason | field] */
const why = async (p) => { try { await p; return null; } catch (err) { return [err.code, (err.body && (err.body.reason || err.body.field)) || null]; } };
/** The same server asked as another person (a child of the family). */
const as = async (t, uid) => { t.srv.state.user = { id: uid, name: t.srv.state.people.find((p) => p.id === uid).name }; await t.svc.me({ refresh: true }); };

describe('vendor/notizen: whose turn and stars from the typed line (the plugin\'s second module, its frozen vectors)', () => {
  it('every one of the 16 vectors, applied after the parser', () => {
    assert.equal(tv.cases.length, 16);
    for (const c of tv.cases) {
      const w = TW.apply(Q.parse(c.input, tv.ctx), { people: tv.ctx.people, stars: c.stars !== false });
      assert.deepEqual({ title: w.title, people: w.people.map((p) => p.id), turn: w.turn, stars: w.stars }, c.expect, `${c.input}${c.stars === false ? ' (no stars)' : ''}`);
    }
    // nothing taken: the title is the parser's, untouched
    const p = Q.parse('Morgen 9 Uhr Zahnarzt anrufen', tv.ctx);
    assert.deepEqual(TW.apply(p, { people: tv.ctx.people, stars: true }), { title: p.title, people: [], turn: null, stars: null });
  });

  it('the parser, its vectors, the new module and its vectors are the plugin\'s files, byte for byte', () => {
    assert.equal(sha('src/vendor/notizen/quickparse.js'), 'aeb7ab3f0db8dec9c5bfcebc760d67a9153330cb195b733920cdfae121e8d6f1');
    assert.equal(sha('test/fixtures/notes/quickparse-vectors.json'), '66b9dec6cb2aa989307e81a3559112f84a124897d0dd3ff9eb15a2aaca5e5115');
    assert.equal(sha('src/vendor/notizen/turnwords.js'), 'c4165bd24a00400a0e696eed661d24852be005ccfe9caf78f6fcc03f50544b37');
    assert.equal(sha('test/fixtures/notes/turnwords-vectors.json'), '37594e565a64772f2884a40a2bb00c4ec82d10cb5f3201b132476c9ac38159a3');
  });
});

describe('utils/notes: plugin 1.6.0', () => {
  it('cleans a task\'s turn, people, stars, doneBy and family; an older plugin has none of them', () => {
    const t = N.normalizeTask({ id: 77, listId: 12, title: 'Spülmaschine ausräumen', assignee: { id: 4, name: 'Lena' }, turn: 'rotate', people: [{ id: 4, name: 'Lena' }, { id: 5, name: 'Tim' }, { name: 'x' }, 'y'],
      stars: 2, doneBy: { id: 4, name: 'Lena' }, family: true, canEdit: false, canComplete: true });
    assert.deepEqual([t.turn, t.people, t.stars, t.doneBy, t.family, t.canEdit, t.canComplete], ['rotate', [{ id: 4, name: 'Lena' }, { id: 5, name: 'Tim' }], 2, { id: 4, name: 'Lena' }, true, false, true]);
    const old = N.normalizeTask({ id: 77, title: 'x' });
    assert.deepEqual([old.turn, old.people, old.stars, old.doneBy, old.family], [null, [], 0, null, false]);
    // an unknown turn, fewer than two people, stars outside 1…10, a person without a number
    assert.deepEqual(['later', 'first'].map((turn) => N.normalizeTask({ id: 1, turn, people: [{ id: 4 }, { id: 5 }] }).turn), [null, 'first']);
    assert.deepEqual([N.normalizeTask({ id: 1, turn: 'rotate', people: [{ id: 4 }] }).turn, N.normalizeTask({ id: 1, turn: 'rotate', people: [{ id: 4 }] }).people], [null, []]);
    assert.deepEqual(N.normalizeTask({ id: 1, people: [{ id: 4 }, { id: 5 }] }).people, []);
    assert.deepEqual([11, -1, 2.5, '3', 10].map((stars) => N.normalizeTask({ id: 1, stars }).stars), [0, 0, 0, 0, 10]);
    assert.equal(N.normalizeTask({ id: 1, doneBy: { name: 'Lena' } }).doneBy, null);
  });

  it('cleans the family\'s list, me.familyTasks, prefs.feedback, what the server read and a place\'s mine / canConsent', () => {
    assert.deepEqual([N.normalizeList({ id: 12, name: 'Familie', family: true }).family, N.normalizeList({ id: 12, name: 'x' }).family, N.normalizeList({ id: 12, family: 'yes' }).family], [true, false, false]);
    const ft = { available: true, bound: true, listId: 12, parent: false, stars: true, starsMax: 10, moved: { at: '2026-11-14T10:00:00Z', tasks: 12, places: 3, seen: false } };
    assert.deepEqual(N.normalizeMe({ familyTasks: ft }).familyTasks, ft);
    assert.equal(N.normalizeMe({}).familyTasks, null);
    // bound without a list is not bound; no move; a strange maximum
    assert.deepEqual(N.normalizeMe({ familyTasks: { available: true, bound: true, parent: true, starsMax: 99 } }).familyTasks, { available: true, bound: false, listId: null, parent: true, stars: false, starsMax: 10, moved: null });
    assert.deepEqual([N.normalizePrefs({ feedback: 'stars' }).feedback, N.normalizePrefs({ feedback: 'loud' }).feedback, N.normalizePrefs({}).feedback], ['stars', undefined, undefined]);
    const p = N.normalizeParsed({ title: 'Spülmaschine ausräumen', people: [{ id: 4, name: 'Lena' }, { id: 5, name: 'Tim' }], turn: 'rotate', stars: 2 });
    assert.deepEqual([p.title, p.people, p.turn, p.stars], ['Spülmaschine ausräumen', [{ id: 4, name: 'Lena' }, { id: 5, name: 'Tim' }], 'rotate', 2]);
    assert.deepEqual((({ people, turn, stars }) => [people, turn, stars])(N.normalizeParsed({ title: 'x' })), [[], null, null]);
    const place = { mode: 'place', name: 'Lidl', lat: 52.5, lon: 13.4, consent: 'pending', by: 2 };
    const got = N.normalizeTask({ id: 1, place: { ...place, mine: true, canConsent: true } }).place;
    assert.deepEqual([got.mine, got.canConsent], [true, true]);
    assert.deepEqual([N.normalizeTask({ id: 1, place: { ...place, mine: false, canConsent: false } }).place.canConsent, 'canConsent' in N.normalizeTask({ id: 1, place }).place, 'mine' in N.normalizeTask({ id: 1, place: { ...place, mine: 'yes' } }).place], [false, false, false]);
  });

  it('checks turn, people and stars the renderer sends', () => {
    assert.deepEqual(N.taskPatch({ turn: 'rotate', people: [4, 5, 4], stars: 2 }), { turn: 'rotate', people: [4, 5], stars: 2 });
    assert.deepEqual(N.taskPatch({ turn: null, stars: 0 }), { turn: null, stars: 0 });
    for (const bad of [{ turn: 'later' }, { turn: '' }, { people: '4,5' }, { people: [4, 'x'] }, { people: [0] }, { people: Array.from({ length: 51 }, (_, i) => i + 1) }, { stars: 11 }, { stars: -1 }, { stars: 1.5 }, { stars: '2' }, { stars: null }]) {
      assert.equal(N.taskPatch(bad), null, JSON.stringify(bad));
    }
    assert.deepEqual(N.taskCreate({ title: 'Blumen gießen', listId: 12, turn: 'first', people: [4, 5], stars: 1 }), { title: 'Blumen gießen', listId: 12, turn: 'first', people: [4, 5], stars: 1 });
    assert.equal(N.taskCreate({ title: 'x', turn: 'both' }), null);
    assert.deepEqual(N.taskCreate({ text: '@Lena @Tim Müll reihum' }), { text: '@Lena @Tim Müll reihum' });
  });

  it('a click on „… hat ‚…‘ erledigt“ and on „Erledigt von …“ opens the task', () => {
    const data = { notizen: { kind: 'done_feedback', taskId: 77, listId: 12, area: 'private', task: 77, userId: 4, stars: 2 },
      actions: [{ type: 'open_app_route', id: 'open', label: 'Ansehen', target: 'plg-gatecontrol-notizen' }, { type: 'callback', id: 'not_done', label: 'Noch nicht fertig' }] };
    assert.deepEqual(N.pushTarget(TOPIC, data), { kind: 'task', taskId: 77 });
    assert.deepEqual(N.pushTarget(TOPIC, data, 'open'), { kind: 'task', taskId: 77 });
    assert.deepEqual(N.pushTarget(TOPIC, { notizen: { kind: 'done_feedback', taskId: 77, listId: 12 } }), { kind: 'task', taskId: 77 });
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:reminders', { notizen: { kind: 'reminder_done', taskId: 78, listId: 12, area: 'private', userId: 4 } }), { kind: 'task', taskId: 78 });
    // another kind that names `taskId` only stays what it was; a strange number is no task
    assert.deepEqual(N.pushTarget(TOPIC, { notizen: { kind: 'other', taskId: 78 } }), { kind: 'home' });
    assert.deepEqual(N.pushTarget(TOPIC, { notizen: { kind: 'reminder_done', taskId: '78' } }), { kind: 'home' });
  });
});

describe('NotesService: an older plugin (without the words of 1.6.0) stays as it was', () => {
  it('no new field, no new call; what only 1.6.0 understands is refused here', async () => {
    const { srv, svc } = await setup({ features: OLD });
    const me = (await svc.me()).me;
    assert.deepEqual([me.familyTasks, me.prefs.feedback], [null, undefined]);
    const t = (await svc.task(12)).task;
    assert.deepEqual([t.turn, t.people, t.stars, t.doneBy, t.family], [null, [], 0, null, false]);
    assert.equal((await svc.lists({ area: 'private' })).lists.every((l) => l.family === false), true);
    // the typed line: the server (the parser alone) reads it; the page gets no people, no turn, no stars
    const p = await svc.parse({ text: '@Jenny @Noah Müll rausbringen reihum', area: 'private', listId: 2 });
    assert.deepEqual([p.parsed.title, p.parsed.assignee.id, p.parsed.people, p.parsed.turn, p.parsed.stars], ['@Noah Müll rausbringen reihum', 12, [], null, null]);
    assert.deepEqual(asked(srv, /POST .*\/api\/parse$/).map((r) => r.body), [{ text: '@Jenny @Noah Müll rausbringen reihum', area: 'private' }]);
    // an older plugin would pass the new fields over in silence — they are refused before the server is asked
    const before = srv.state.requests.length;
    for (const p2 of [svc.createTask({ title: 'x', listId: 2, turn: 'rotate', people: [1, 12] }), svc.createTask({ title: 'x', stars: 2 }), svc.updateTask(12, { turn: null }), svc.updateTask(12, { people: [1, 12] }),
      svc.updateTask(12, { stars: 0 }), svc.completeTask(12, true, 15), svc.familySeen(), svc.setPrefs({ feedback: 'off' })]) assert.deepEqual(await why(p2), ['unsupported', null]);
    assert.equal(srv.state.requests.length, before);
    // ticking off is what it was
    const done = await svc.completeTask(12, true);
    assert.deepEqual([done.task.done, done.task.doneBy, asked(srv, /\/tasks\/12\/complete$/).map((r) => r.body)], [true, null, [{ done: true }]]);
  });
});

describe('NotesService: whose turn, stars and the family\'s list (plugin 1.6.0)', () => {
  it('„reihum“ from the typed line: the next person is on after ticking off', async () => {
    const t = await setup({ features: ALL });
    const { srv, svc } = t;
    const fam = srv.addFamily();
    const me = (await svc.me({ refresh: true })).me;
    assert.deepEqual(me.familyTasks, { available: true, bound: true, listId: fam.id, parent: true, stars: true, starsMax: 10, moved: null });
    const lists = (await svc.lists({ area: 'private' })).lists;
    assert.deepEqual(lists.filter((l) => l.family).map((l) => [l.id, l.name, l.members.map((m) => m.id)]), [[fam.id, 'Familie', [12, 15, 16]]]);
    // what the server reads (the parser, then turnwords): people, turn, stars — stars only in the family's list
    const p = await svc.parse({ text: '@Noah @Mia Spülmaschine ausräumen täglich 18 Uhr reihum 2 Sterne', area: 'private', listId: fam.id });
    assert.deepEqual([p.parsed.title, p.parsed.people.map((x) => x.id), p.parsed.turn, p.parsed.stars, p.parsed.repeat.type, p.parsed.time], ['Spülmaschine ausräumen', [15, 16], 'rotate', 2, 'daily', '18:00']);
    assert.deepEqual(asked(srv, /POST .*\/api\/parse$/).at(-1).body, { text: '@Noah @Mia Spülmaschine ausräumen täglich 18 Uhr reihum 2 Sterne', area: 'private', listId: fam.id });
    assert.deepEqual((({ title, stars }) => [title, stars])((await svc.parse({ text: 'Hotel 4 Sterne buchen', area: 'private', listId: 1 })).parsed), ['Hotel 4 Sterne buchen', null]);
    const made = await svc.createTask({ text: '@Noah @Mia Spülmaschine ausräumen täglich 18 Uhr reihum 2 Sterne', listId: fam.id });
    assert.deepEqual([made.task.title, made.task.turn, made.task.people.map((x) => x.id), made.task.assignee.id, made.task.stars, made.task.family, made.parsed.turn], ['Spülmaschine ausräumen', 'rotate', [15, 16], 15, 2, true, 'rotate']);
    // a parent ticks off the task of the child that is on: for the child; the next one is Mia's
    const done = await svc.completeTask(made.task.id, true);
    assert.deepEqual([done.task.done, done.task.doneBy, done.next.turn, done.next.assignee, done.next.due.date, done.next.done], [true, { id: 15, name: 'Noah Muster' }, 'rotate', { id: 16, name: 'Mia Muster' }, '2026-11-09', false]);
    assert.deepEqual(srv.state.feedback, [{ taskId: made.task.id, userId: 15, stars: 2 }]);
    // … and back: open again, nobody it was ticked off for
    const back = await svc.completeTask(made.task.id, false);
    assert.deepEqual([back.task.done, back.task.doneBy], [false, null]);
  });

  it('„wer zuerst“ and „Eine Person“ chosen in the page: turn and people go with the task, wrong ones come back as the server says', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const fam = srv.addFamily();
    await svc.me({ refresh: true });
    const first = (await svc.createTask({ title: 'Blumen gießen', listId: fam.id, turn: 'first', people: [12, 15, 16] })).task;
    assert.deepEqual([first.turn, first.people.map((x) => x.id), first.assignee, first.stars], ['first', [12, 15, 16], null, 0]);
    assert.deepEqual(asked(srv, /POST .*\/api\/tasks$/).at(-1).body, { title: 'Blumen gießen', listId: fam.id, turn: 'first', people: [12, 15, 16] });
    // „Reihum“ instead, Mia starts; then „Eine Person“: who was on stays assigned
    const rot = (await svc.updateTask(first.id, { turn: 'rotate', people: [15, 16], assigneeId: 16 })).task;
    assert.deepEqual([rot.turn, rot.people.map((x) => x.id), rot.assignee.id], ['rotate', [15, 16], 16]);
    const one = (await svc.updateTask(first.id, { turn: null })).task;
    assert.deepEqual([one.turn, one.people, one.assignee.id], [null, [], 16]);
    // in any shared list, not only the family's (list 2: Max and Jenny) — but no stars there
    const shared = (await svc.createTask({ title: 'Rasen sprengen', listId: 2, turn: 'rotate', people: [1, 12] })).task;
    assert.deepEqual([shared.turn, shared.assignee.id, shared.family], ['rotate', 1, false]);
    assert.deepEqual(await why(svc.updateTask(shared.id, { stars: 2 })), ['invalid', 'family']);
    assert.deepEqual(await why(svc.createTask({ title: 'x', listId: 2, turn: 'rotate', people: [1] })), ['invalid', 'people']);
    assert.deepEqual(await why(svc.createTask({ title: 'x', listId: 2, turn: 'first', people: [1, 15] })), ['not_member', 'people']);
    // „wer zuerst“: the first one does it for all
    await svc.updateTask(first.id, { turn: 'first', people: [12, 15, 16] });
    const done = await svc.completeTask(first.id, true, 16);
    assert.deepEqual([done.task.done, done.task.doneBy, done.next], [true, { id: 16, name: 'Mia Muster' }, null]);
    assert.deepEqual(asked(srv, new RegExp(`/tasks/${first.id}/complete$`)).at(-1).body, { done: true, userId: 16 });
  });

  it('stars: a parent sets them, a child may not; a child changes what no parent made and ticks off what is theirs', async () => {
    const t = await setup({ features: ALL });
    const { srv, svc } = t;
    const fam = srv.addFamily();
    await svc.me({ refresh: true });
    const room = (await svc.createTask({ title: 'Zimmer aufräumen', listId: fam.id, assigneeId: 15, stars: 2 })).task;
    assert.deepEqual([room.stars, room.canEdit, room.canComplete], [2, true, true]);
    assert.equal((await svc.updateTask(room.id, { stars: 3 })).task.stars, 3);
    const mias = (await svc.createTask({ title: 'Hasen füttern', listId: fam.id, assigneeId: 16 })).task;
    // the child Noah
    await as(t, 15);
    assert.deepEqual((({ bound, parent, listId }) => [bound, parent, listId])((await svc.me()).me.familyTasks), [true, false, fam.id]);
    const seen = (await svc.view({ name: `list:${fam.id}`, area: 'private' })).view.sections[0].items;
    assert.deepEqual(seen.map((x) => [x.title, x.canEdit, x.canComplete, x.stars]), [['Zimmer aufräumen', false, true, 3], ['Hasen füttern', false, false, 0]]);
    assert.deepEqual(await why(svc.updateTask(room.id, { stars: 5 })), ['forbidden', 'parents_only']);
    assert.deepEqual(await why(svc.updateTask(room.id, { title: 'Nichts' })), ['forbidden', 'parents_only']);
    assert.deepEqual(await why(svc.deleteTask(room.id)), ['forbidden', 'parents_only']);
    assert.equal((await svc.updateTask(room.id, { myDay: true })).task.myDay, true);
    assert.deepEqual(await why(svc.completeTask(mias.id, true)), ['forbidden', null]);
    assert.deepEqual(await why(svc.completeTask(room.id, true, 16)), ['forbidden', 'parents_only']);
    // its own task: no stars from a child, also not from the typed line — an ordinary task is made
    const own = (await svc.createTask({ text: 'Fahrrad putzen 3 Sterne', listId: fam.id })).task;
    assert.deepEqual([own.title, own.stars, own.canEdit], ['Fahrrad putzen 3 Sterne', 0, true]);
    assert.deepEqual(await why(svc.createTask({ title: 'Fahrrad putzen', listId: fam.id, stars: 3 })), ['forbidden', 'parents_only']);
    assert.equal((await svc.updateTask(own.id, { title: 'Fahrrad putzen' })).task.title, 'Fahrrad putzen');
    const done = await svc.completeTask(room.id, true);
    assert.deepEqual([done.task.done, done.task.doneBy.id, srv.state.feedback], [true, 15, [{ taskId: room.id, userId: 15, stars: 3 }]]);
    // the parent again: „Noch nicht fertig“ in the app is the way back; for a member of the family only
    await as(t, 1);
    assert.deepEqual((({ done: d, doneBy }) => [d, doneBy])((await svc.completeTask(room.id, false)).task), [false, null]);
    assert.deepEqual(await why(svc.completeTask(room.id, true, 99)), ['invalid', 'userId']);
    assert.deepEqual(await why(svc.completeTask(12, true, 15)), ['invalid', 'userId']);
    assert.equal((await svc.completeTask(mias.id, true, 16)).task.doneBy.id, 16);
  });

  it('the family\'s list is managed by Familie; „Umzug abgeschlossen“ once; the message to the parents; who may accept a place', async () => {
    const t = await setup({ features: ALL });
    const { srv, svc } = t;
    const fam = srv.addFamily({ moved: { tasks: 12, places: 3 } });
    assert.deepEqual((await svc.me({ refresh: true })).me.familyTasks.moved, { at: '2026-11-08T07:00:00Z', tasks: 12, places: 3, seen: false });
    assert.deepEqual(await why(svc.deleteList(fam.id)), ['forbidden', 'family']);
    assert.deepEqual(await why(svc.setListMembers(fam.id, [12])), ['forbidden', 'family']);
    assert.equal((await svc.updateList(fam.id, { color: 'green' })).list.color, 'green');
    assert.equal((await svc.familySeen()).ok, true);
    assert.equal((await svc.me()).me.familyTasks.moved.seen, true);
    assert.equal((await svc.me({ refresh: true })).me.familyTasks.moved.seen, true);
    assert.equal(asked(srv, /POST .*\/api\/family\/seen$/).length, 1);
    // the message when a child ticks off
    assert.equal((await svc.me()).me.prefs.feedback, 'all');
    assert.deepEqual([(await svc.setPrefs({ feedback: 'stars' })).prefs.feedback, (await svc.me()).me.prefs.feedback], ['stars', 'stars']);
    // a place someone else set at Jenny's task: Max sees the state, only Jenny may answer
    const lidl = srv.addPlace({ name: 'Lidl Nordstraße', lat: 52.54, lon: 13.42 });
    srv.setTaskPlace(12, { placeId: lidl.id, by: 15, who: 12 });
    const place = (await svc.task(12)).task.place;
    assert.deepEqual([place.consent, place.mine, place.canConsent], ['pending', false, false]);
    srv.setTaskPlace(12, { placeId: lidl.id, by: 12, who: 1 });
    assert.deepEqual((({ mine, canConsent }) => [mine, canConsent])((await svc.task(12)).task.place), [true, true]);
    // without the word placeMine the fields are not there (the page decides as before)
    const old = await setup({ features: ALL.filter((f) => f !== 'placeMine') });
    old.srv.setTaskPlace(12, { placeId: old.srv.addPlace({ name: 'Lidl', lat: 52.54, lon: 13.42 }).id, by: 12, who: 1 });
    assert.equal('canConsent' in (await old.svc.task(12)).task.place, false);
  });
});

describe('ipc/notes-handlers: plugin 1.6.0', () => {
  it('checks turn, people, stars, userId and feedback; refuses for an older plugin', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const fam = srv.addFamily({ moved: { tasks: 2, places: 0 } });
    await svc.me({ refresh: true });
    const handlers = {};
    registerNotesHandlers((ch, fn) => { handlers[ch] = fn; }, { notes: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.deepEqual([(await call('notes:task:create', { task: { title: 'x', listId: fam.id, turn: 'both' } })).code, (await call('notes:task:create', { task: { title: 'x', listId: fam.id, people: [15, 'Mia'] } })).field], ['invalid', 'task']);
    const made = (await call('notes:task:create', { task: { title: 'Tisch decken', listId: fam.id, turn: 'rotate', people: [15, 16], stars: 1 } })).task;
    assert.deepEqual([made.turn, made.assignee.id, made.stars], ['rotate', 15, 1]);
    assert.deepEqual([(await call('notes:task:update', { id: made.id, patch: { stars: 11 } })).code, (await call('notes:task:update', { id: made.id, patch: { stars: 4 } })).task.stars, (await call('notes:task:update', { id: 12, patch: { stars: 4 } })).reason], ['invalid', 4, 'family']);
    assert.deepEqual([(await call('notes:task:complete', { id: made.id, done: true, userId: 'Noah' })).field, (await call('notes:task:complete', { id: made.id, done: true, userId: 16 })).task.doneBy.id], ['userId', 16]);
    assert.deepEqual([(await call('notes:parse', { text: 'x', listId: 'a' })).field, (await call('notes:parse', { text: '@Noah @Mia Müll wer zuerst', area: 'private', listId: fam.id })).parsed.turn], ['listId', 'first']);
    assert.deepEqual([(await call('notes:prefs:set', { patch: { feedback: 'loud' } })).field, (await call('notes:prefs:set', { patch: { feedback: 'off' } })).prefs.feedback], ['feedback', 'off']);
    assert.deepEqual([(await call('notes:family:seen', {})).ok, (await call('notes:me', {})).me.familyTasks.moved.seen], [true, true]);

    const old = await setup({ features: OLD });
    const h2 = {};
    registerNotesHandlers((ch, fn) => { h2[ch] = fn; }, { notes: old.svc, getMainWindow: () => null, log });
    assert.deepEqual([(await h2['notes:task:create']({}, { task: { title: 'x', turn: 'first', people: [1, 12] } })).code, (await h2['notes:task:update']({}, { id: 12, patch: { stars: 1 } })).code,
      (await h2['notes:task:complete']({}, { id: 12, done: true, userId: 15 })).code, (await h2['notes:family:seen']({}, {})).code, (await h2['notes:prefs:set']({}, { patch: { feedback: 'off' } })).code], ['unsupported', 'unsupported', 'unsupported', 'unsupported', 'unsupported']);
    assert.equal((await h2['notes:task:complete']({}, { id: 12, done: true })).task.done, true);
    assert.deepEqual(asked(old.srv, /\/family\//), []);
  });
});
