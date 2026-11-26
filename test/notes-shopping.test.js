'use strict';

// Notizen & Aufgaben, plugin 1.4.0 (the words shoppingLists, taskList, familyShopping of me.features — never a version):
// the shopping lists of the hub in the Windows apps. The pure helpers (utils/notes.js: the answers cleaned, what the
// renderer may send; utils/notes-shopping.js: `since`, tombstones, the queue on top), NotesService against the fake
// server (an older plugin stays as it was; lists and items with ids made by the device; in order and safe to repeat;
// without the server: queued, stored, sent later; a list at a task, the suggestion of the quick entry, „alles
// abgehakt“ with its way back; the reminder's button „Liste öffnen“) and the IPC (notes:shopping*).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const N = require('../src/utils/notes');
const Shop = require('../src/utils/notes-shopping');
const NotesService = require('../src/services/notes');
const ApiClient = require('../src/services/api-client');
const { registerNotesHandlers } = require('../src/ipc/notes-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer, FEATURES, STAGE1, STAGE2 } = require('./fixtures/notes-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const ALL = [...FEATURES, ...STAGE1, ...STAGE2];
const EINKAUF = '6f1c2a90-1111-4c1d-9a00-000000000001';
const DROGERIE = '6f1c2a90-1111-4c1d-9a00-000000000002';
const POINTS = ['Milch', 'Brot', 'Äpfel', 'Butter', 'Nudeln', 'Kaffee', 'Joghurt', 'Spülmittel'];

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function service(srv, opts = {}) {
  const svc = new NotesService({
    apiClient: new ApiClient(srv.url, 'gc_token', log), log, store: opts.store || createMemoryStore(), protect: null, getLang: () => 'de',
    pushClient: opts.pushClient || null, notificationCenter: opts.notificationCenter || null, dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  return svc;
}

async function setup(opts = {}, svcOpts = {}) {
  const srv = await notesServer(opts);
  cleanup.push(() => srv.close());
  const store = svcOpts.store || createMemoryStore();
  const svc = service(srv, { ...svcOpts, store });
  await svc.check();
  return { srv, svc, store };
}

/** The list „Einkauf“ of the mockup (8 open items, shared with the family) and a task that carries it. */
function seed(srv) {
  const list = srv.addShopList({ id: EINKAUF, name: 'Einkauf', family: true, items: POINTS.map((text, i) => ({ text, qty: [, , '1 kg'][i] || (i === 0 ? '2 l' : null) })) });
  const task = srv.addTask({ title: 'Bei Lidl einkaufen', due: { date: '2026-11-08', time: null } });
  srv.state.attached.set(task.id, list.num);
  return { list, task };
}
const ops = (srv) => srv.state.requests.filter((r) => r.method === 'POST' && r.path.endsWith('/api/shopping/ops')).map((r) => r.body.ops);
const names = (r, uid) => r.items.filter((i) => i.listId === uid).map((i) => i.text);

describe('utils/notes: plugin 1.4.0', () => {
  it('cleans a shopping list, its items, a task\'s list, the suggestion and the answer of the ops', () => {
    const l = N.normalizeShopList({ id: EINKAUF, listId: 12, name: ' Einkauf\u0007 ', icon: 'cart', area: 'private', role: 'write', canEdit: true, canManage: false, owner: { id: 1, name: 'Anna' }, shared: true,
      members: [{ id: 2, name: 'Marc', role: 'write' }, { id: 'x' }], family: true, open: 9, total: 8, tasks: [{ id: 41, title: 'Bei Lidl einkaufen' }, { id: 0 }], going: [{ userId: 2, at: '2026-11-14T10:00:00Z' }], updatedAt: '2026-11-14T09:58:00+01:00' });
    assert.deepEqual([l.id, l.listId, l.name, l.role, l.canEdit, l.canManage, l.family, l.open, l.total], [EINKAUF, 12, 'Einkauf', 'write', true, false, true, 8, 8]);
    assert.deepEqual([l.members, l.tasks, l.going.length], [[{ id: 2, name: 'Marc', role: 'write' }], [{ id: 41, title: 'Bei Lidl einkaufen' }], 1]);
    assert.equal(N.normalizeShopList({ id: 'short', name: 'x' }), null);
    assert.equal(N.normalizeShopList({ id: 12, name: 'x' }), null);
    const i = N.normalizeShopItem({ id: '0a0b0c0d-0001', listId: EINKAUF, text: 'Milch\n<b>', qty: '2 l', checked: true, checkedBy: 2, deleted: false });
    assert.deepEqual([i.text, i.qty, i.checked, i.checkedBy, i.deleted], ['Milch <b>', '2 l', true, 2, false]);
    assert.equal(N.normalizeShopItem({ id: '0a0b0c0d-0001', listId: 12, text: 'x' }), null);
    const g = N.normalizeShopping({ lists: [{ id: EINKAUF, name: 'Einkauf', deleted: true }, null], items: [{ id: '0a0b0c0d-0001', listId: EINKAUF, deleted: true }], serverTime: '2026-11-14T10:14:07+01:00' });
    assert.deepEqual([g.lists[0].deleted, g.items[0].deleted, g.serverTime], [true, true, '2026-11-14T10:14:07+01:00']);

    const al = { id: 12, uid: EINKAUF, name: 'Einkauf', icon: 'cart', open: 8, total: 8, done: 0, family: true };
    assert.deepEqual(N.normalizeTask({ id: 41, title: 'x', attachedList: al }).attachedList, al);
    assert.deepEqual(N.normalizeTask({ id: 41, title: 'x', attachedList: { ...al, open: 3, done: 99 } }).attachedList.done, 5);
    assert.equal(N.normalizeTask({ id: 41, title: 'x' }).attachedList, null);
    assert.equal(N.normalizeTask({ id: 41, title: 'x', attachedList: { id: 12, uid: '../x' } }).attachedList, null);
    assert.deepEqual(N.normalizeAttach({ via: 'word', word: 'einkaufen', list: al, lists: [al] }), { via: 'word', word: 'einkaufen', list: al, lists: [al] });
    assert.deepEqual(N.normalizeAttach({ via: 'name', list: null, lists: [al, { ...al, id: 13, uid: DROGERIE }] }).lists.map((x) => x.id), [12, 13]);
    assert.equal(N.normalizeAttach({ via: 'guess', list: al }), null);
    assert.equal(N.normalizeAttach(null), null);
    assert.deepEqual(N.normalizeOpsAnswer({ applied: 6, rejected: [{ index: 3, code: 'not_found' }, { index: 4, code: '<x>' }, { code: 'invalid' }], serverTime: '2026-11-14T10:14:07+01:00', completed: [{ taskId: 41, title: 'Bei Lidl einkaufen', listId: EINKAUF }, { taskId: 'x' }] }),
      { applied: 6, rejected: [{ index: 3, code: 'not_found' }, { index: 4, code: 'invalid' }], serverTime: '2026-11-14T10:14:07+01:00', completed: [{ taskId: 41, title: 'Bei Lidl einkaufen', listId: EINKAUF }] });
    const nav = N.normalizeNav({ shopping: [{ id: EINKAUF, listId: 12, name: 'Einkauf', icon: 'cart', open: 8, total: 8, family: true, shared: true, role: 'write' }, { id: 5 }] });
    assert.deepEqual(nav.shopping, [{ id: EINKAUF, listId: 12, name: 'Einkauf', icon: 'cart', open: 8, total: 8, family: true, shared: true, role: 'write' }]);
    assert.deepEqual(N.normalizeNav({}).shopping, []);
    assert.deepEqual(N.normalizeMe({ shopping: { family: { available: true, bound: true, parent: false } }, listIcons: ['cart', '<svg>'] }).shopping, { family: { available: true, bound: true, parent: false } });
    assert.deepEqual([N.normalizeMe({}).shopping, N.normalizeMe({ listIcons: ['cart', '<svg>'] }).listIcons], [null, ['cart']]);
    assert.deepEqual(N.changedOf({ what: ['shopping', 'tasks', 'nonsense'] }), { what: ['shopping', 'tasks'] });
  });

  it('checks the operations, a task\'s list and the reminder\'s button', () => {
    let n = 0;
    const make = () => `made-by-device-${++n}`;
    assert.deepEqual(N.shopOps([{ op: 'list_add', name: ' Baumarkt ', icon: 'tool', area: 'work' }, { op: 'item_add', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' }, { op: 'item_add', id: 'my-own-id-1', listId: EINKAUF, text: 'Salz', qty: '' },
      { op: 'item_edit', id: 'my-own-id-1', qty: null }, { op: 'item_check', id: 'my-own-id-1', checked: true }, { op: 'item_delete', id: 'my-own-id-1' }, { op: 'clear_checked', listId: EINKAUF },
      { op: 'list_rename', id: EINKAUF, name: 'Wocheneinkauf' }, { op: 'list_delete', id: EINKAUF }], make), [
      { op: 'list_add', id: 'made-by-device-1', name: 'Baumarkt', icon: 'tool', area: 'work' }, { op: 'item_add', id: 'made-by-device-2', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' },
      { op: 'item_add', id: 'my-own-id-1', listId: EINKAUF, text: 'Salz' }, { op: 'item_edit', id: 'my-own-id-1', qty: null }, { op: 'item_check', id: 'my-own-id-1', checked: true },
      { op: 'item_delete', id: 'my-own-id-1' }, { op: 'clear_checked', listId: EINKAUF }, { op: 'list_rename', id: EINKAUF, name: 'Wocheneinkauf' }, { op: 'list_delete', id: EINKAUF }]);
    for (const bad of [{ op: 'item_add', listId: EINKAUF, text: '' }, { op: 'item_add', listId: 12, text: 'x' }, { op: 'item_add', listId: EINKAUF, text: 'x'.repeat(121) }, { op: 'item_add', listId: EINKAUF, text: 'x', qty: 'q'.repeat(41) },
      { op: 'item_check', id: 'my-own-id-1', checked: 'yes' }, { op: 'item_check', id: 'short', checked: true }, { op: 'item_edit', id: 'my-own-id-1' }, { op: 'list_add', name: 'x'.repeat(41) }, { op: 'list_add', name: 'x', icon: '<svg>' },
      { op: 'list_add', name: 'x', family: 'yes' }, { op: 'drop_everything', id: EINKAUF }, { op: 'item_delete' }, null]) assert.equal(N.shopOps([bad], make), null, JSON.stringify(bad));
    // an edit or a tick never gets a made-up id; no ops, too many ops
    assert.equal(N.shopOp({ op: 'item_check', checked: true }, make), null);
    assert.equal(N.shopOps([], make), null);
    assert.equal(N.shopOps(Array.from({ length: 201 }, () => ({ op: 'item_check', id: 'my-own-id-1', checked: true })), make), null);
    assert.equal(N.shopOps(Array.from({ length: 200 }, () => ({ op: 'item_check', id: 'my-own-id-1', checked: true })), make).length, 200);

    assert.deepEqual(N.taskPatch({ attachedListId: 12 }), { attachedListId: 12 });
    assert.deepEqual(N.taskPatch({ attachedListId: null }), { attachedListId: null });
    assert.deepEqual(N.taskPatch({ attachedListUid: EINKAUF }), { attachedListUid: EINKAUF });
    assert.deepEqual(N.taskPatch({ attachedListUid: null }), { attachedListId: null });
    assert.deepEqual([N.taskPatch({ attachedListId: '12' }), N.taskPatch({ attachedListUid: 'x y' })], [null, null]);
    assert.deepEqual(N.taskCreate({ text: 'bei Lidl einkaufen', attachedListId: 12 }), { text: 'bei Lidl einkaufen', attachedListId: 12 });
    assert.deepEqual(N.taskCreate({ text: 'bei Lidl einkaufen', attach: 'auto' }), { text: 'bei Lidl einkaufen', attach: 'auto' });
    assert.deepEqual([N.taskCreate({ text: 'x', attach: 'always' }), N.taskCreate({ text: 'x', attachedListId: -1 })], [null, null]);
    assert.deepEqual(N.assignArg({ userId: 12, notify: 'family', dueAt: '2026-11-14T18:00:00+01:00' }), { userId: 12, dueAt: '2026-11-14T18:00:00+01:00', notify: 'family' });
    assert.deepEqual([N.assignArg({ userId: null }), N.assignArg({ userId: 'x' }), N.assignArg({ userId: 12, notify: 'sms' })], [{ userId: null }, null, null]);

    const topic = 'plugin:gatecontrol-notizen:reminders';
    const data = { notizen: { kind: 'reminder', taskId: 41, task: 41, listId: 3, attachedList: { id: 12, uid: EINKAUF, name: 'Einkauf', open: 8, total: 8 } } };
    assert.deepEqual(N.pushTarget(topic, data, 'open_list'), { kind: 'shopping', uid: EINKAUF, listId: 12, taskId: 41 });
    // a click on the message itself, „Erledigt“, a reminder without a list: the task as before
    assert.deepEqual(N.pushTarget(topic, data), { kind: 'task', taskId: 41 });
    assert.deepEqual(N.pushTarget(topic, data, 'done'), { kind: 'task', taskId: 41 });
    assert.deepEqual(N.pushTarget(topic, { notizen: { task: 41 } }, 'open_list'), { kind: 'task', taskId: 41 });
    assert.deepEqual(N.pushTarget(topic, { notizen: { task: 41, attachedList: { id: 12, uid: '../etc' } } }, 'open_list'), { kind: 'task', taskId: 41 });
  });
});

describe('utils/notes-shopping: `since`, tombstones, the queue on top', () => {
  const L = (id, extra = {}) => N.normalizeShopList({ id, listId: 12, name: 'Einkauf', role: 'owner', canEdit: true, canManage: true, ...extra });
  const I = (id, text, extra = {}) => N.normalizeShopItem({ id, listId: EINKAUF, text, ...extra });

  it('`lists` is always complete; items come changed-only with `since`; what is gone goes', () => {
    const st = Shop.newState();
    assert.deepEqual(Shop.merge(st, { lists: [L(EINKAUF), L(DROGERIE)], items: [I('item-0001', 'Milch'), I('item-0002', 'Brot'), I('item-0003', 'Zahnpasta', { listId: DROGERIE })], serverTime: '2026-11-14T10:14:07+01:00' }, { full: true }), { needFull: false });
    assert.deepEqual([st.since, st.loaded, st.items.size], ['2026-11-14T10:14:07+01:00', true, 3]);
    // since: one item ticked, one deleted (tombstone), one came twice — never missing, never double
    Shop.merge(st, { lists: [L(EINKAUF), L(DROGERIE)], items: [I('item-0001', 'Milch', { checked: true }), I('item-0002', 'Brot', { deleted: true }), I('item-0001', 'Milch', { checked: true })], serverTime: '2026-11-14T11:02:41+01:00' });
    assert.deepEqual([...st.items.values()].map((i) => [i.id, i.checked]), [['item-0001', true], ['item-0003', false]]);
    assert.equal(st.since, '2026-11-14T11:02:41+01:00');
    // a list deleted since (tombstone) and its items; a list that is simply missing (left) the same way
    Shop.merge(st, { lists: [L(EINKAUF), { ...L(DROGERIE), deleted: true }], items: [], serverTime: '2026-11-14T11:03:00+01:00' });
    assert.deepEqual([[...st.lists.keys()], [...st.items.keys()]], [[EINKAUF], ['item-0001']]);
    Shop.merge(st, { lists: [], items: [], serverTime: '2026-11-14T11:04:00+01:00' });
    assert.deepEqual([st.lists.size, st.items.size], [0, 0]);
    // a list the device does not know (newly shared): ask once without `since`; that `since` is not kept
    assert.deepEqual(Shop.merge(st, { lists: [L(DROGERIE)], items: [], serverTime: '2026-11-14T11:05:00+01:00' }), { needFull: true });
    assert.equal(st.since, '2026-11-14T11:04:00+01:00');
    assert.deepEqual(Shop.merge(st, { lists: [L(DROGERIE)], items: [I('item-0003', 'Zahnpasta', { listId: DROGERIE })], serverTime: '2026-11-14T11:05:01+01:00' }, { full: true }), { needFull: false });
    assert.deepEqual([st.since, st.items.size], ['2026-11-14T11:05:01+01:00', 1]);
  });

  it('the queue shows at once; the numbers are counted from the items; the same operation twice changes nothing', () => {
    const st = Shop.newState();
    Shop.merge(st, { lists: [L(EINKAUF, { open: 2, total: 2 })], items: [I('item-0001', 'Milch'), I('item-0002', 'Brot')], serverTime: '2026-11-14T10:14:07+01:00' }, { full: true });
    const queue = [{ op: 'item_check', id: 'item-0001', checked: true }, { op: 'item_add', id: 'item-0009', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' }, { op: 'item_add', id: 'item-0009', listId: EINKAUF, text: 'Hefe' },
      { op: 'item_edit', id: 'item-0002', qty: '2' }, { op: 'list_add', id: DROGERIE, name: 'Drogerie' }, { op: 'item_add', id: 'item-0010', listId: DROGERIE, text: 'Seife' }, { op: 'item_add', id: 'item-0011', listId: 'list-unknown', text: 'x' }];
    const v = Shop.view(st, queue, { userId: 1 });
    assert.deepEqual(v.lists.map((l) => [l.name, l.open, l.total, !!l.pending]), [['Einkauf', 2, 3, false], ['Drogerie', 1, 1, true]]);
    assert.deepEqual(v.items.map((i) => [i.text, i.qty, i.checked, !!i.pending]), [['Milch', null, true, false], ['Brot', '2', false, false], ['Hefe', '1 Würfel', false, true], ['Seife', null, false, true]]);
    // base is untouched until the server confirmed; what it rejected never gets in
    assert.deepEqual([st.items.size, st.items.get('item-0001').checked], [2, false]);
    Shop.confirm(st, queue, [{ index: 3, code: 'forbidden' }, { index: 6, code: 'not_found' }], { userId: 1 });
    assert.deepEqual([st.items.get('item-0001').checked, st.items.get('item-0001').checkedBy, st.items.get('item-0002').qty, st.lists.has(DROGERIE), !!st.items.get('item-0009').pending], [true, 1, null, true, false]);
    const cleared = Shop.view(st, [{ op: 'clear_checked', listId: EINKAUF }, { op: 'list_delete', id: DROGERIE }], { userId: 1 });
    assert.deepEqual([cleared.lists.map((l) => [l.name, l.open, l.total]), cleared.items.map((i) => i.text)], [[['Einkauf', 2, 2]], ['Brot', 'Hefe']]);
    // the stored queue: only this server's and person's, cleaned again
    assert.deepEqual(Shop.storedQueue({ scope: 'a', ops: [{ op: 'item_check', id: 'item-0001', checked: true }, { op: 'rm', id: 'x' }] }, 'a'), [{ op: 'item_check', id: 'item-0001', checked: true }]);
    assert.deepEqual([Shop.storedQueue({ scope: 'a', ops: [{ op: 'item_check', id: 'item-0001', checked: true }] }, 'b'), Shop.storedQueue(null, 'a')], [[], []]);
  });
});

describe('NotesService: plugin 1.4.0 (shopping lists, a list at a task)', () => {
  it('an older plugin: nothing new is asked, nothing new is sent', async () => {
    const routes = new Map();
    const nc = Object.assign(new EventEmitter(), { addClickRoute: (r, fn) => { routes.set(r, fn); return () => routes.delete(r); } });
    const { srv, svc } = await setup({ features: [...FEATURES, ...STAGE1] }, { notificationCenter: nc });
    const { list, task } = seed(srv);
    assert.equal(STAGE2.some((f) => svc.status().features.includes(f)), false);
    assert.deepEqual([(await svc.me()).me.shopping, (await svc.nav({ area: 'private' })).nav.shopping], [null, []]);
    assert.equal((await svc.task(task.id)).task.attachedList, null);
    assert.equal((await svc.parse({ text: 'bei Lidl einkaufen', area: 'private' })).attach, null);
    const before = srv.state.requests.length;
    for (const p of [svc.shopping(), svc.shoppingOps([{ op: 'item_check', id: list.items[0], checked: true }]), svc.shoppingRestore(list.num), svc.shoppingGoing(EINKAUF), svc.shoppingFamily(EINKAUF, true), svc.shoppingAssign(EINKAUF, { userId: 12 }),
      svc.createTask({ text: 'bei Lidl einkaufen', attachedListId: list.num }), svc.createTask({ text: 'bei Lidl einkaufen', attach: 'auto' }), svc.updateTask(task.id, { attachedListId: null })]) await assert.rejects(p, (e) => e.code === 'unsupported');
    assert.equal(srv.state.requests.length, before);
    // the reminder's button „Liste öffnen“ opens the task (the list is not offered here)
    const entry = { topic: 'plugin:gatecontrol-notizen:reminders', data: { notizen: { kind: 'reminder', task: task.id, attachedList: { id: list.num, uid: EINKAUF } } } };
    assert.deepEqual(routes.get('plg-gatecontrol-notizen')(entry, { id: 'open_list', type: 'open_app_route', target: 'plg-gatecontrol-notizen' }), { kind: 'task', taskId: task.id });
  });

  it('the lists and their items; ticking, adding, changing, deleting with ids made here; `since` and what another device did', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const { list } = seed(srv);
    const drog = srv.addShopList({ id: DROGERIE, name: 'Drogerie', role: 'read', items: [{ text: 'Zahnpasta' }] });
    assert.deepEqual((await svc.me({ refresh: true })).me.shopping, { family: { available: true, bound: true, parent: true } });
    assert.deepEqual((await svc.nav({ area: 'private' })).nav.shopping.map((l) => [l.name, l.open, l.total, l.family, l.role]), [['Einkauf', 8, 8, true, 'owner'], ['Drogerie', 1, 1, false, 'read']]);
    const all = await svc.shopping();
    assert.deepEqual(all.lists.map((l) => [l.id, l.listId, l.name, l.open, l.total, l.canEdit, l.canManage, l.tasks.map((t) => t.title)]),
      [[EINKAUF, list.num, 'Einkauf', 8, 8, true, true, ['Bei Lidl einkaufen']], [DROGERIE, drog.num, 'Drogerie', 1, 1, false, false, []]]);
    assert.deepEqual([names(all, EINKAUF), all.items[0].qty, all.pending, all.stale], [POINTS, '2 l', 0, false]);
    assert.equal(srv.state.requests.filter((r) => r.path.endsWith('/api/shopping')).pop().query.since, undefined);

    // one call, in order: tick, a new item (its id is given), change, delete
    const r = await svc.shoppingOps([{ op: 'item_check', id: list.items[0], checked: true }, { op: 'item_add', id: '5d1e0000-77aa', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' },
      { op: 'item_edit', id: list.items[1], text: 'Vollkornbrot', qty: '1' }, { op: 'item_delete', id: list.items[7] }]);
    assert.deepEqual([r.applied, r.rejected, r.completed, r.offline, r.pending, r.ids.length], [4, [], [], false, 0, 4]);
    assert.deepEqual(r.lists.map((l) => [l.name, l.open, l.total]), [['Einkauf', 7, 8], ['Drogerie', 1, 1]]);
    assert.deepEqual(names(r, EINKAUF), ['Milch', 'Vollkornbrot', 'Äpfel', 'Butter', 'Nudeln', 'Kaffee', 'Joghurt', 'Hefe']);
    assert.deepEqual(ops(srv).pop().map((o) => o.op), ['item_check', 'item_add', 'item_edit', 'item_delete']);
    assert.equal(srv.state.shopItems.get('5d1e0000-77aa').qty, '1 Würfel');

    // the same call again (a retry): nothing twice
    const again = await svc.shoppingOps([{ op: 'item_check', id: list.items[0], checked: true }, { op: 'item_add', id: '5d1e0000-77aa', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' }, { op: 'item_delete', id: list.items[7] }]);
    assert.deepEqual([again.rejected, again.lists[0].total, [...srv.state.shopItems.values()].filter((i) => i.text === 'Hefe').length], [[], 8, 1]);

    // another device ticks „Butter“, deletes „Nudeln“ and writes „Salz“; the next call asks with `since` and gets only that
    srv.state.now += 5000;
    const st = srv.state.shopItems;
    Object.assign(st.get(list.items[3]), { checked: true, checkedBy: 12, updatedAt: srv.state.now });
    Object.assign(st.get(list.items[4]), { deleted: true, updatedAt: srv.state.now });
    st.set('other-device-01', { id: 'other-device-01', list: EINKAUF, text: 'Salz', qty: null, checked: false, checkedBy: null, updatedAt: srv.state.now, deleted: false, seq: 999 });
    const next = await svc.shopping();
    const asked = srv.state.requests.filter((q) => q.path.endsWith('/api/shopping')).pop();
    assert.match(asked.query.since, /^2026-11-08T08:00:00\+01:00$/);
    assert.deepEqual(names(next, EINKAUF), ['Milch', 'Vollkornbrot', 'Äpfel', 'Butter', 'Kaffee', 'Joghurt', 'Hefe', 'Salz']);
    assert.deepEqual([next.items.find((i) => i.text === 'Butter').checkedBy, next.lists[0].open, next.lists[0].total], [12, 6, 8]);

    // a list only read: the server refuses, the page is put right again; what is refused is not sent again
    const no = await svc.shoppingOps([{ op: 'item_check', id: drog.items[0], checked: true }, { op: 'item_add', listId: DROGERIE, id: 'not-allowed-01', text: 'Seife' }]);
    assert.deepEqual(no.rejected.map((x) => [x.op, x.code]), [['item_check', 'forbidden'], ['item_add', 'forbidden']]);
    const sent = ops(srv).length;
    const after = await svc.shopping();
    assert.deepEqual([names(after, DROGERIE), after.items.find((i) => i.listId === DROGERIE).checked, after.pending, ops(srv).length], [['Zahnpasta'], false, 0, sent]);

    // a new list made here, an item in it; renamed; deleted — and gone for the page after the tombstone
    const made = await svc.shoppingOps([{ op: 'list_add', id: 'baumarkt-list-0001', name: 'Baumarkt', icon: 'tool' }, { op: 'item_add', id: 'baumarkt-item-0001', listId: 'baumarkt-list-0001', text: 'Dübel', qty: '20' }]);
    assert.deepEqual(made.lists.map((l) => [l.name, l.icon, l.open]).pop(), ['Baumarkt', 'tool', 1]);
    // its number (for sharing, attaching, restoring) comes with the same answer
    assert.equal(made.lists.find((l) => l.id === 'baumarkt-list-0001').listId, srv.state.shopLists.get('baumarkt-list-0001').num);
    await svc.shoppingOps([{ op: 'list_rename', id: 'baumarkt-list-0001', name: 'Bauhaus' }]);
    assert.equal(srv.state.shopLists.get('baumarkt-list-0001').name, 'Bauhaus');
    const gone = await svc.shoppingOps([{ op: 'list_delete', id: 'baumarkt-list-0001' }]);
    assert.deepEqual([gone.lists.map((l) => l.name), gone.items.some((i) => i.listId === 'baumarkt-list-0001')], [['Einkauf', 'Drogerie'], false]);
    // … by mistake: it comes back with its items (its owner, by the list's number); what is not in the trash does not
    const num = srv.state.shopLists.get('baumarkt-list-0001').num;
    assert.deepEqual(await svc.shoppingRestore(num), { ok: true });
    const back = await svc.shopping();
    assert.deepEqual([back.lists.map((l) => l.name), names(back, 'baumarkt-list-0001')], [['Einkauf', 'Drogerie', 'Bauhaus'], ['Dübel']]);
    await assert.rejects(svc.shoppingRestore(num), (e) => e.code === 'not_found');
    await svc.shoppingOps([{ op: 'list_delete', id: 'baumarkt-list-0001' }]);
    // deleted by someone else: the tombstone of the next `since` takes it away with its items; `full` asks without `since`
    srv.state.now += 5000;
    Object.assign(srv.state.shopLists.get(DROGERIE), { deletedAt: srv.state.now, was: [1, 12] });
    assert.deepEqual((await svc.shopping()).lists.map((l) => l.name), ['Einkauf']);
    await svc.shopping({ full: true });
    assert.equal(srv.state.requests.filter((q) => q.path.endsWith('/api/shopping')).pop().query.since, undefined);

    // the family: shared with it, „Ich gehe einkaufen“, „Kannst du einkaufen gehen?“
    assert.deepEqual([(await svc.shoppingGoing(EINKAUF)).notified, (await svc.shoppingAssign(EINKAUF, { userId: 12, notify: 'direct' })).list.assignee.userId, srv.state.going, srv.state.assigned], [2, 12, [EINKAUF], [{ list: EINKAUF, userId: 12 }]]);
    assert.equal((await svc.shoppingFamily(EINKAUF, false)).list.family, false);
    await assert.rejects(svc.shoppingGoing(EINKAUF), (e) => e.code === 'invalid' && e.body.field === 'family');
  });

  it('without the server: shown at once, queued in order, stored, sent later unchanged — nothing twice', async () => {
    const pc = new EventEmitter();
    const { srv, svc, store } = await setup({ features: ALL }, { pushClient: pc });
    const { list } = seed(srv);
    await svc.shopping();
    srv.down = true;
    const a = await svc.shoppingOps([{ op: 'item_check', id: list.items[0], checked: true }]);
    assert.deepEqual([a.offline, a.pending, a.applied, a.lists[0].open, a.items[0].checked], [true, 1, 0, 7, true]);
    const b = await svc.shoppingOps([{ op: 'item_add', id: '5d1e0000-77aa', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' }, { op: 'item_check', id: list.items[7], checked: true }]);
    assert.deepEqual([b.offline, b.pending, b.lists[0].open, b.lists[0].total, names(b, EINKAUF).pop()], [true, 3, 7, 9, 'Hefe']);
    // the page asks again while the server is away: the last copy with what waits
    const stale = await svc.shopping();
    assert.deepEqual([stale.stale, stale.pending, stale.lists[0].open, stale.items.filter((i) => i.pending).map((i) => i.text)], [true, 3, 7, ['Hefe']]);
    assert.deepEqual(store.get('notesShopQueue').ops.map((o) => o.op), ['item_check', 'item_add', 'item_check']);
    assert.equal(srv.state.shopItems.get(list.items[0]).checked, false);

    // the app is closed and opened again: the queue is read from the store, for this server only
    svc.stop();
    srv.down = false;
    const svc2 = service(srv, { store, pushClient: pc });
    await svc2.check();
    const changed = [];
    svc2.on('changed', (c) => changed.push(c.what));
    // a reconnect sends what waits, then the pages fetch again
    pc.emit('hello');
    await new Promise((r) => svc2.once('changed', r));
    assert.deepEqual(ops(srv).pop(), [{ op: 'item_check', id: list.items[0], checked: true }, { op: 'item_add', id: '5d1e0000-77aa', listId: EINKAUF, text: 'Hefe', qty: '1 Würfel' }, { op: 'item_check', id: list.items[7], checked: true }]);
    assert.deepEqual([store.get('notesShopQueue').ops, srv.state.shopItems.get(list.items[0]).checked, srv.state.shopItems.get('5d1e0000-77aa').text], [[], true, 'Hefe']);
    const now = await svc2.shopping();
    assert.deepEqual([now.pending, now.stale, now.lists[0].open, now.lists[0].total], [0, false, 7, 9]);

    // the answer was lost on the way (the server took the batch, the device does not know): sent again, nothing twice
    const real = svc2.api.shoppingOps.bind(svc2.api);
    let lost = 1;
    svc2.api.shoppingOps = async (batch) => { const r = await real(batch); if (lost-- > 0) throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }); return r; };
    const c = await svc2.shoppingOps([{ op: 'item_add', id: 'salz-item-0001', listId: EINKAUF, text: 'Salz' }]);
    assert.deepEqual([c.offline, c.pending, srv.state.shopItems.has('salz-item-0001')], [true, 1, true]);
    const d = await svc2.shopping();
    assert.deepEqual([d.pending, names(d, EINKAUF).filter((x) => x === 'Salz').length, [...srv.state.shopItems.values()].filter((i) => i.text === 'Salz').length], [0, 1, 1]);
    // another server (server:setup): its queue and lists are not this one's
    await svc2.shoppingOps([{ op: 'item_check', id: list.items[1], checked: true }]);
    const other = await notesServer({ features: ALL });
    cleanup.push(() => other.close());
    const svc3 = service(other, { store: createMemoryStore({ notesShopQueue: store.get('notesShopQueue') }) });
    await svc3.check();
    store.set('notesShopQueue', { scope: 'someone-else', ops: [{ op: 'item_check', id: list.items[2], checked: true }] });
    const svc4 = service(srv, { store });
    await svc4.check();
    assert.deepEqual([(await svc4.shopping()).pending, srv.state.shopItems.get(list.items[2]).checked], [0, false]);
  });

  it('a list at a task: the suggestion, attaching, „alles abgehakt“ completes the task — and back', async () => {
    const routes = new Map();
    const nc = Object.assign(new EventEmitter(), { addClickRoute: (r, fn) => { routes.set(r, fn); return () => routes.delete(r); } });
    const { srv, svc } = await setup({ features: ALL }, { notificationCenter: nc });
    const { list, task } = seed(srv);
    const drog = srv.addShopList({ id: DROGERIE, name: 'Drogerie', icon: 'heart', items: [{ text: 'Zahnpasta' }] });
    const al = { id: list.num, uid: EINKAUF, name: 'Einkauf', icon: 'cart', open: 8, total: 8, done: 0, family: true };
    assert.deepEqual((await svc.task(task.id)).task.attachedList, al);
    assert.deepEqual((await svc.view({ name: 'myday', area: 'private' })).view.sections.find((s) => s.id === 'today').items.find((x) => x.id === task.id).attachedList, al);

    // „bei Lidl einkaufen“: one of the fixed words → the list „Einkauf“; the title stays what the parser made
    const p = await svc.parse({ text: 'bei Lidl einkaufen', area: 'private' });
    assert.deepEqual([p.parsed.title, p.attach.via, p.attach.word, p.attach.list, p.attach.lists.length], ['bei Lidl einkaufen', 'word', 'einkaufen', al, 1]);
    assert.deepEqual([(await svc.parse({ text: 'Zahnpasta Drogerie', area: 'private' })).attach.via, (await svc.parse({ text: 'Rasen mähen', area: 'private' })).attach], ['name', null]);
    const tag = await svc.parse({ text: 'Shampoo #drog', area: 'private' });
    assert.deepEqual([tag.attach.via, tag.attach.list.uid, tag.parsed.listName], ['tag', DROGERIE, 'drog']);
    // the chip stayed: attachedListId; taken away: no field, and the server attaches nothing by itself
    const withList = await svc.createTask({ text: 'bei Lidl einkaufen', area: 'private', attachedListId: list.num });
    assert.deepEqual([withList.task.title, withList.task.attachedList.uid], ['bei Lidl einkaufen', EINKAUF]);
    assert.equal((await svc.createTask({ text: 'bei Lidl einkaufen', area: 'private' })).task.attachedList, null);
    const auto = await svc.createTask({ text: 'Drogerie Shampoo', area: 'private', attach: 'auto' });
    assert.deepEqual([auto.task.attachedList.uid, auto.attach.via], [DROGERIE, 'name']);
    // the details: another list (its number or its text id), none; a task list is no shopping list
    const t2 = srv.addTask({ title: 'Zur Drogerie' });
    assert.equal((await svc.updateTask(t2.id, { attachedListId: drog.num })).task.attachedList.name, 'Drogerie');
    assert.equal((await svc.updateTask(t2.id, { attachedListUid: EINKAUF })).task.attachedList.id, list.num);
    assert.equal((await svc.updateTask(t2.id, { attachedListId: null })).task.attachedList, null);
    await assert.rejects(svc.updateTask(t2.id, { attachedListId: 2 }), (e) => e.code === 'invalid' && e.body.field === 'attachedListId' && e.body.reason === 'kind');
    await assert.rejects(svc.updateTask(t2.id, { attachedListId: 99999 }), (e) => e.code === 'not_found' && e.body.field === 'attachedListId');

    // the last open item: both tasks carrying the list are completed; the list stays ticked
    await svc.shopping();
    const most = await svc.shoppingOps(list.items.slice(0, 7).map((id) => ({ op: 'item_check', id, checked: true })));
    assert.deepEqual([most.completed, most.lists[0].open], [[], 1]);
    assert.deepEqual((await svc.task(task.id)).task.attachedList, { ...al, open: 1, done: 7 });
    const last = await svc.shoppingOps([{ op: 'item_check', id: list.items[7], checked: true }]);
    assert.deepEqual(last.completed, [{ taskId: task.id, title: 'Bei Lidl einkaufen', listId: EINKAUF }, { taskId: withList.task.id, title: 'bei Lidl einkaufen', listId: EINKAUF }]);
    assert.deepEqual([(await svc.task(task.id)).task.done, last.lists[0].open, last.lists[0].total], [true, 0, 8]);
    // two calls right after each other: „alles abgehakt“ is told once
    await svc.shoppingOps([{ op: 'item_check', id: list.items[6], checked: false }, { op: 'item_check', id: list.items[7], checked: false }]);
    await svc.completeTask(task.id, false);
    const both = await Promise.all([svc.shoppingOps([{ op: 'item_check', id: list.items[6], checked: true }]), svc.shoppingOps([{ op: 'item_check', id: list.items[7], checked: true }])]);
    assert.deepEqual([both.flatMap((r) => r.completed).map((c) => c.taskId), both.map((r) => r.lists[0].open), (await svc.task(task.id)).task.done], [[task.id], [0, 0], true]);
    // „Rückgängig“: the task is open again, no item is unticked; the same tick again completes nothing
    const undo = await svc.completeTask(task.id, false);
    assert.deepEqual([undo.task.done, undo.task.attachedList.done, srv.state.shopItems.get(list.items[7]).checked], [false, 8, true]);
    assert.deepEqual((await svc.shoppingOps([{ op: 'item_check', id: list.items[7], checked: true }])).completed, []);
    // deleting the last open item or clearing the ticked ones completes nothing
    await svc.shoppingOps([{ op: 'item_add', id: 'salz-item-0001', listId: EINKAUF, text: 'Salz' }]);
    assert.deepEqual([(await svc.shoppingOps([{ op: 'item_delete', id: 'salz-item-0001' }])).completed, (await svc.shoppingOps([{ op: 'clear_checked', listId: EINKAUF }])).lists[0].total, (await svc.task(task.id)).task.done], [[], 0, false]);

    // the reminder: „Liste öffnen“ opens the list in the page; the message itself and „Erledigt“ the task
    const resolve = routes.get('plg-gatecontrol-notizen');
    const entry = { topic: 'plugin:gatecontrol-notizen:reminders', data: { notizen: { kind: 'reminder', taskId: task.id, task: task.id, attachedList: { id: list.num, uid: EINKAUF, name: 'Einkauf', open: 8, total: 8 } },
      actions: [{ id: 'open_list', label: 'Liste öffnen', type: 'open_app_route', target: 'plg-gatecontrol-notizen' }, { id: 'done', label: 'Erledigt', type: 'callback' }, { id: 'snooze_1h', label: 'In 1 Std.', type: 'callback' }] } };
    assert.deepEqual(resolve(entry, { id: 'open_list', type: 'open_app_route', target: 'plg-gatecontrol-notizen' }), { kind: 'shopping', uid: EINKAUF, listId: list.num, taskId: task.id });
    assert.deepEqual([resolve(entry), resolve(entry, { id: 'done', type: 'callback' })], [{ kind: 'task', taskId: task.id }, { kind: 'task', taskId: task.id }]);
  });
});

describe('ipc/notes-handlers: plugin 1.4.0', () => {
  it('checks the operations, makes the ids of new rows, refuses for an older plugin', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const { list } = seed(srv);
    const handlers = {};
    registerNotesHandlers((ch, fn) => { handlers[ch] = fn; }, { notes: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('notes:shopping', {})).lists[0].name, 'Einkauf');
    for (const bad of [{}, { ops: [] }, { ops: 'x' }, { ops: [{ op: 'item_check', id: list.items[0] }] }, { ops: [{ op: 'item_add', listId: EINKAUF, text: '' }] }]) assert.deepEqual([(await call('notes:shopping:ops', bad)).code, (await call('notes:shopping:ops', bad)).field], ['invalid', 'ops']);
    const r = await call('notes:shopping:ops', { ops: [{ op: 'item_add', listId: EINKAUF, text: 'Hefe' }, { op: 'list_add', name: 'Baumarkt', icon: 'tool' }] });
    assert.deepEqual([r.ok, r.applied, r.ids.every((x) => /^[0-9a-f-]{36}$/.test(x)), r.lists.map((l) => l.name)], [true, 2, true, ['Einkauf', 'Baumarkt']]);
    assert.equal(srv.state.shopItems.get(r.ids[0]).text, 'Hefe');
    assert.deepEqual([(await call('notes:shopping:going', { id: 12 })).code, (await call('notes:shopping:family', { id: EINKAUF, on: 'yes' })).code, (await call('notes:shopping:assign', { id: EINKAUF, userId: 'x' })).field], ['invalid', 'invalid', 'userId']);
    assert.equal((await call('notes:shopping:going', { id: EINKAUF })).notified, 2);
    assert.deepEqual([(await call('notes:shopping:restore', { listId: EINKAUF })).field, (await call('notes:shopping:restore', { listId: list.num })).code], ['listId', 'not_found']);
    assert.deepEqual([(await call('notes:task:update', { id: 12, patch: { attachedListId: 'x' } })).code, (await call('notes:task:update', { id: 12, patch: { attachedListId: list.num } })).task.attachedList.uid], ['invalid', EINKAUF]);
    assert.equal((await call('notes:parse', { text: 'einkaufen', area: 'private' })).attach.list.uid, EINKAUF);

    const old = await setup();
    const h2 = {};
    registerNotesHandlers((ch, fn) => { h2[ch] = fn; }, { notes: old.svc, getMainWindow: () => null, log });
    assert.deepEqual([(await h2['notes:shopping']({}, {})).code, (await h2['notes:shopping:ops']({}, { ops: [{ op: 'list_add', name: 'x' }] })).code, (await h2['notes:task:create']({}, { task: { text: 'einkaufen', attach: 'auto' } })).code], ['unsupported', 'unsupported', 'unsupported']);
  });
});
