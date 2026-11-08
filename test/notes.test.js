'use strict';

// Notizen & Aufgaben (plugin gatecontrol-notizen 1.0.0) in the Windows apps: the pure helpers (utils/notes.js), the
// plugin's own modules unchanged (src/vendor/notizen: the quick entry and the repeat rules against the plugin's frozen
// vectors), the Tresor format (Drive's with "gcnotes-v1": the plugin's frozen vectors byte for byte), NotesService
// against the fake server (availability and feature flags, the views, the quick entry, ticking off, notes, check
// boxes, attachments, Tresor notebooks with the lock, a second device, the recovery key, a new key), the moves from
// Microsoft To Do (device code) and DS Note (the .nsx read here, protected notes into a Tresor) and the IPC (notes:*).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const N = require('../src/utils/notes');
const V = require('../src/utils/drive-vault');
const Q = require('../src/vendor/notizen/quickparse');
const R = require('../src/vendor/notizen/repeat');
const NotesService = require('../src/services/notes');
const NotesApi = require('../src/services/notes-api');
const NotesVault = require('../src/services/notes-vault');
const ApiClient = require('../src/services/api-client');
const { openNsx } = require('../src/services/notes-import');
const { registerNotesHandlers, NOTES_EVENTS } = require('../src/ipc/notes-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer } = require('./fixtures/notes-server');
const vectors = require('./fixtures/notes-vault-vectors.json');
const qv = require('./fixtures/notes/quickparse-vectors.json');
const rv = require('./fixtures/notes/repeat-vectors.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const H = (s) => Buffer.from(s, 'hex');
const NSX_FILE = path.join(__dirname, 'fixtures', 'notes', 'sample.nsx');

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function until(fn, ms = 6000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** safeStorage stand-in: never the plain bytes in the store. */
function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0x3c));
  return { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]), decrypt: (b) => x(Buffer.from(b).subarray(6)) };
}

/** Windows Hello as a confirmation: the next answers, every prompt counted. */
function fakeConsent() {
  const f = { answers: [], prompts: [] };
  f.available = async () => ({ available: true, reason: null });
  f.verify = async (message) => { f.prompts.push(message); return { status: f.answers.length ? f.answers.shift() : 'verified' }; };
  return f;
}

async function setup(opts = {}, svcOpts = {}) {
  const srv = await notesServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const temp = tmpDir('notes-tmp-');
  const store = svcOpts.store || createMemoryStore();
  const svc = new NotesService({
    apiClient, log, store, protect: svcOpts.protect === undefined ? fakeProtect() : svcOpts.protect, tempDir: () => temp, getLang: () => 'de',
    shell: svcOpts.shell || null, dialog: svcOpts.dialog || null, pushClient: svcOpts.pushClient || null, notificationCenter: svcOpts.notificationCenter || null,
    consent: svcOpts.consent, ocr: svcOpts.ocr || null, deviceName: () => svcOpts.deviceName || 'Büro-PC', dialogPath: () => null,
    timing: { retryMinMs: 10, retryMaxMs: 20, minuteMs: svcOpts.minuteMs || 60000 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, apiClient, temp, store };
}

// ── the plugin's modules, unchanged ────────────────────────

describe('vendor/notizen: the plugin\'s quick entry and repeat rules (its frozen vectors)', () => {
  it('quick entry: every vector', () => {
    assert.ok(qv.cases.length >= 50);
    for (const c of qv.cases) {
      const p = Q.parse(c.input, qv.ctx);
      const got = { title: p.title, date: p.date, time: p.time, remind: p.remind, important: p.important, list: p.list, listName: p.listName, assignee: p.assignee, assigneeName: p.assigneeName, repeat: p.repeat };
      assert.deepEqual(got, c.expect, c.input);
    }
    assert.deepEqual(Q.parse(qv.cases[0].input, qv.ctx).marks, qv.marksOfFirst);
  });

  it('repeat rules: every vector', () => {
    for (const c of rv.next) assert.equal(R.next(c.rule, { due: c.due, done: c.done }), c.expect, JSON.stringify(c));
    for (const c of rv.first) assert.equal(R.first(c.rule, c.today), c.expect, JSON.stringify(c));
    for (const c of rv.describe) { assert.equal(R.describe(c.rule, 'de'), c.de); assert.equal(R.describe(c.rule, 'en'), c.en); }
    for (const r of rv.invalid) assert.equal(R.normalize(r), null, JSON.stringify(r));
  });
});

// ── the Tresor format ─────────────────────────────────────

describe('Tresor notebooks: Drive\'s format with "gcnotes-v1" (the plugin\'s vectors)', () => {
  const NV = V.withPrefix('gcnotes-v1');
  it('device key, device id, safety number, wrap, name, note, content and recovery key bit for bit', async () => {
    assert.equal(vectors.input.prefix, 'gcnotes-v1');
    assert.equal(NotesVault.crypto.PREFIX, 'gcnotes-v1');
    const dev = NV.publicFromPrivate(H(vectors.input.deviceSeed));
    assert.equal(NV.b64u(dev), vectors.device.publicKey);
    assert.equal(NV.deviceId(dev), vectors.device.deviceId);
    assert.equal(NV.safetyNumber(dev), vectors.device.safetyNumber);
    const eph = { privateRaw: H(vectors.input.ephemeralSeed), publicRaw: NV.publicFromPrivate(H(vectors.input.ephemeralSeed)) };
    assert.equal(NV.b64u(eph.publicRaw), vectors.ephemeralPublicKey);
    const tk = H(vectors.input.vaultKey);
    const vid = vectors.input.vaultId;
    assert.equal(NV.wrapKey(tk, dev, vid, 1, { ephemeral: eph }), vectors.wrap);
    assert.deepEqual(NV.unwrapKey(vectors.wrap, H(vectors.input.deviceSeed), dev, vid, 1), tk);
    assert.equal(NV.encryptName(tk, vid, 1, vectors.input.name, { nonce: H(vectors.input.nameNonce) }), vectors.nameCipher);
    assert.equal(NV.decryptName(new Map([[1, tk]]), vid, vectors.nameCipher), vectors.input.name);
    // a note's Markdown (the content format, base64url in `cipher`)
    assert.equal(NV.decryptBuffer({ 1: tk }, vid, Buffer.from(vectors.noteCipher, 'base64url')).toString('utf8'), vectors.input.note);
    const pt = Buffer.from(Array.from({ length: vectors.input.content.length }, (_, i) => (i * 7 + 3) & 255));
    const ct = NV.encryptBuffer(tk, vid, 1, pt, { chunkSize: vectors.input.content.chunkSize, salt: H(vectors.input.content.salt) });
    assert.equal(ct.length, vectors.content.size);
    assert.equal(ct.subarray(0, NV.HEADER).toString('hex'), vectors.content.header);
    assert.equal(crypto.createHash('sha256').update(ct).digest('hex'), vectors.content.sha256);
    assert.equal(ct.toString('base64url'), vectors.content.base64url);
    const rk = H(vectors.input.recoveryKey);
    assert.equal(await NV.formatRecoveryKey(rk), vectors.recovery.text);
    assert.equal(NV.b64u(NV.recoveryKeyPair(rk).publicRaw), vectors.recovery.publicKey);
    assert.equal(NV.recoveryAuth(rk), vectors.recovery.auth);
    assert.equal(NV.wrapKey(tk, NV.recoveryKeyPair(rk).publicRaw, vid, 1, { ephemeral: eph }), vectors.recovery.wrap);
  });

  it('domain separation: Drive\'s labels never open a note, and the other way round', () => {
    const tk = V.newVaultKey();
    const vid = V.newVaultId();
    const dev = V.generateKeyPair();
    assert.notEqual(V.deviceId(dev.publicRaw), NV.deviceId(dev.publicRaw));
    assert.notEqual(V.safetyNumber(dev.publicRaw), NV.safetyNumber(dev.publicRaw));
    assert.throws(() => V.decryptName({ 1: tk }, vid, NV.encryptName(tk, vid, 1, 'x')), (e) => e.code === 'decrypt');
    assert.throws(() => NV.decryptBuffer({ 1: tk }, vid, V.encryptBuffer(tk, vid, 1, Buffer.from('x'))), (e) => e.code === 'decrypt');
    assert.throws(() => NV.unwrapKey(V.wrapKey(tk, dev.publicRaw, vid, 1), dev.privateRaw, dev.publicRaw, vid, 1), (e) => e.code === 'decrypt');
    assert.equal(V.withPrefix('gcdrive-v1').deviceId(dev.publicRaw), V.deviceId(dev.publicRaw));
    assert.throws(() => V.withPrefix('Bad Prefix'), (e) => e.code === 'invalid');
  });
});

// ── the pure helpers ──────────────────────────────────────

describe('utils/notes', () => {
  it('cleans a task, an item, a list, a notebook and a note; texts stay text', () => {
    const t = N.normalizeTask({ id: 5, listId: 1, title: 'A\u0007 <b>x</b>', important: true, due: { date: '2026-11-09', time: '25:00' }, repeat: { type: 'weekly', days: [9, 3, 3, 1] }, progress: { done: 9, total: 3 }, subtasks: [{ id: 6, title: 's', done: true }, { id: 'x' }] });
    assert.equal(t.uid, 't:5');
    assert.equal(t.title, 'A  <b>x</b>');
    assert.deepEqual(t.due, { date: '2026-11-09', time: null });
    assert.deepEqual(t.repeat, { type: 'weekly', interval: 1, days: [1, 3] });
    assert.deepEqual(t.progress, { done: 3, total: 3 });
    assert.deepEqual(t.subtasks, [{ id: 6, title: 's', done: true }]);
    assert.equal(N.normalizeTask({ id: 0 }), null);
    const i = N.normalizeItem({ id: 9, type: 'source', kind: 'deadline', title: 'R', source: { plugin: 'gatecontrol-drive', label: 'Drive', open: { plugin: 'gatecontrol-drive', route: 'node/5?x=<script>' } }, meta: { amount: '84,20 €', bad: { x: 1 }, stars: 2 } });
    assert.deepEqual(i.source.open, { plugin: 'gatecontrol-drive', route: '' });
    assert.deepEqual(i.meta, { amount: '84,20 €', stars: 2 });
    assert.equal(N.normalizeItem({ id: 9, source: { plugin: 'evil' } }), null);
    const nb = N.normalizeNotebook({ id: 3, name: 'geheim', vault: { id: 'Vt9bJm0n2QwErTyUiOpAsD', nameCipher: 'AQAB', keyVersion: 2 } });
    assert.equal(nb.name, null);
    assert.equal(nb.vault.keyVersion, 2);
    const n = N.normalizeNote({ id: 4, notebookId: 3, encrypted: true, title: 'leak', body: 'leak', titleCipher: 'AQAB', cipher: 'R0NE' });
    assert.deepEqual([n.title, n.body, n.cipher], [null, null, 'R0NE']);
  });

  it('checks what the renderer may send', () => {
    assert.equal(N.viewName('myday'), 'myday');
    assert.equal(N.viewName('list:12'), 'list:12');
    assert.equal(N.viewName('source:gatecontrol-mail'), 'source:gatecontrol-mail');
    assert.equal(N.viewName('list:../me'), null);
    assert.deepEqual(N.taskPatch({ title: ' x ', due: { date: '2026-11-09', time: '' }, myDay: true, evil: 1 }), { title: 'x', due: { date: '2026-11-09', time: null }, myDay: true });
    assert.equal(N.taskPatch({ due: { date: 'morgen' } }), null);
    assert.equal(N.taskPatch({ assigneeId: -1 }), null);
    assert.deepEqual(N.taskCreate({ text: 'Morgen 9 Uhr Zahnarzt', area: 'work', myDay: true }), { text: 'Morgen 9 Uhr Zahnarzt', area: 'work', myDay: true });
    assert.equal(N.taskCreate({ text: '   ' }), null);
    assert.deepEqual(N.notesQuery({ area: 'private', pinned: true, before: '1:2', limit: 60 }), { area: 'private', pinned: '1', before: '1:2', limit: 60 });
    assert.equal(N.notesQuery({ before: "1' OR 1" }), null);
    assert.deepEqual(N.notePatch({ title: 'T', body: 'B', rev: 3, color: 'yellow' }), { title: 'T', body: 'B', rev: 3, color: 'yellow' });
    assert.equal(N.notePatch({ color: 'red' }), null);
  });

  it('a check box of the Markdown (notemd.toggle) and the targets of a push click', () => {
    const md = '# T\n- [ ] eins\n  * [x] zwei [Aufgabe](task:5)\ntext';
    assert.equal(N.toggleCheck(md, 1, true), '# T\n- [x] eins\n  * [x] zwei [Aufgabe](task:5)\ntext');
    assert.equal(N.toggleCheck(md, 2, false).split('\n')[2], '  * [ ] zwei [Aufgabe](task:5)');
    assert.equal(N.toggleCheck(md, 3, true), null);
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:reminders', { notizen: { task: 7 } }), { kind: 'task', taskId: 7 });
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:shared', { notizen: { list: 3 } }), { kind: 'list', listId: 3 });
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:vault', { notizen: { vault: 'Vt9bJm0n2QwErTyUiOpAsD', event: 'request' } }), { kind: 'vault', vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', event: 'request' });
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:reminders', null), { kind: 'home' });
    assert.equal(N.pushTarget('plugin:gatecontrol-mail:mail', { notizen: { task: 7 } }), null);
    assert.deepEqual(N.changedOf({ what: ['notes', 'x'] }), { what: ['notes'] });
  });
});

// ── the service ───────────────────────────────────────────

describe('NotesService: availability and feature flags', () => {
  it('no plugin (or no licence: not listed) → unavailable; not let in → unavailable; else the features of `me`', async () => {
    const a = await setup({ plugin: false });
    assert.deepEqual([a.svc.status().state, a.svc.status().reason], ['unavailable', 'not_installed']);
    await assert.rejects(a.svc.nav({ area: 'private' }), (e) => e.code === 'unavailable');
    const b = await setup({ allowed: false });
    assert.deepEqual([b.svc.status().state, b.svc.status().reason], ['unavailable', 'forbidden']);
    const c = await setup({ features: ['tasks', 'notes'] });
    assert.equal(c.svc.status().state, 'available');
    assert.deepEqual(c.svc.status().features, ['tasks', 'notes']);
    assert.equal(c.svc.status().vaultSupported, true);
    await assert.rejects(c.svc.search({ q: 'Zahn' }), (e) => e.code === 'unsupported');
    await assert.rejects(c.svc.dsPick({ path: NSX_FILE }), (e) => e.code === 'unsupported');
    // the plugin goes away (or its licence ends): the next check hides the page
    c.srv.state.plugin = false;
    const states = [];
    c.svc.on('state', (s) => states.push(s.state));
    await c.svc.check();
    assert.deepEqual(states, ['unavailable']);
  });

  it('network trouble keeps the page; a reconnect asks again; live events and push clicks', async () => {
    const pushClient = new EventEmitter();
    const routes = new Map();
    const nc = Object.assign(new EventEmitter(), { addClickRoute: (r, fn) => { routes.set(r, fn); return () => routes.delete(r); } });
    const { srv, svc } = await setup({}, { pushClient, notificationCenter: nc });
    srv.down = true;
    await svc.check();
    assert.deepEqual([svc.status().state, svc.status().reason], ['available', 'network']);
    srv.down = false;
    const changed = [];
    svc.on('changed', (c) => changed.push(c));
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-notizen', type: 'changed', data: { what: ['tasks'] } } });
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-mail', type: 'changed', data: { what: ['tasks'] } } });
    pushClient.emit('hello');
    assert.deepEqual(changed.map((c) => c.what), [['tasks'], ['tasks', 'notes', 'items', 'lists', 'notebooks']]);
    const vaults = [];
    svc.on('vault', (v) => vaults.push(v));
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-notizen', type: 'vault', data: { vault: 'Vt9bJm0n2QwErTyUiOpAsD', event: 'request' } } });
    assert.deepEqual(vaults, [{ vault: 'Vt9bJm0n2QwErTyUiOpAsD', event: 'request' }]);
    assert.deepEqual(routes.get('plg-gatecontrol-notizen')({ topic: 'plugin:gatecontrol-notizen:reminders', data: { notizen: { task: 11 } } }), { kind: 'task', taskId: 11 });
  });
});

describe('NotesService: tasks', () => {
  it('Mein Tag, the menu, the quick entry with the plugin\'s parser, ticking off (a repeating task gets its next one)', async () => {
    const { srv, svc } = await setup();
    const nav = (await svc.nav({ area: 'private' })).nav;
    assert.deepEqual(nav.lists.map((l) => l.name), ['Aufgaben', 'Haus & Garten', 'Gesundheit']);
    assert.ok(nav.sources.some((s) => s.plugin === 'gatecontrol-mail' && s.open === 1));
    assert.ok(nav.smart.myday >= 5);
    const md = (await svc.view({ name: 'myday', area: 'private' })).view;
    assert.deepEqual(md.sections.map((s) => s.id), ['events', 'overdue', 'today', 'upcoming', 'done']);
    const sec = (id) => md.sections.find((s) => s.id === id).items.map((x) => x.title);
    assert.deepEqual(sec('events'), ['Gelbe Tonne rausstellen', 'Elternabend Klasse 6b']);
    assert.deepEqual(sec('overdue'), ['Rechnung Stadtwerke bezahlen']);
    assert.ok(sec('today').includes('Zahnarzt anrufen') && sec('today').includes('Angebot von ACME beantworten'));
    const mail = md.sections.find((s) => s.id === 'today').items.find((x) => x.type === 'source' && x.source.plugin === 'gatecontrol-mail');
    assert.deepEqual(mail.source.open, { plugin: 'gatecontrol-mail', route: 'message/4711' });

    const made = await svc.createTask({ text: 'Morgen 9 Uhr Zahnarzt anrufen, wichtig, #gesundheit', area: 'private', myDay: true });
    assert.equal(made.task.title, 'Zahnarzt anrufen');
    assert.deepEqual(made.task.due, { date: '2026-11-09', time: '09:00' });
    assert.equal(made.task.important, true);
    assert.equal(made.task.listId, 3);
    assert.equal(made.parsed.list.name, 'Gesundheit');
    assert.equal((await svc.parse({ text: 'jeden Montag Müll', area: 'private' })).parsed.repeat.type, 'weekly');

    const r = await svc.completeTask(16, true);
    assert.equal(r.task.done, true);
    assert.ok(r.next && r.next.due.date > '2026-11-11');
    const item = await svc.completeItem(204, true);
    assert.equal(item.item.done, true);
    await assert.rejects(svc.completeItem(202, true), (e) => e.code === 'forbidden');
    const t = (await svc.task(12)).task;
    assert.deepEqual(t.subtasks.map((s) => s.done), [false, true, false]);
    assert.equal(t.note, 'Rabatt ab 50 Stück nachfragen');
    const u = (await svc.updateTask(12, { due: { date: '2026-11-10', time: '14:00' }, myDay: true })).task;
    assert.deepEqual(u.due, { date: '2026-11-10', time: '14:00' });
    const carried = (await svc.carryItem(204)).task;
    assert.deepEqual(carried.source, { plugin: 'gatecontrol-mail', id: '204' });
    assert.ok(srv.state.requests.some((x) => x.method === 'POST' && x.path.endsWith('/api/tasks') && x.body && x.body.text));
  });
});

describe('NotesService: notes and attachments', () => {
  it('notes, a check box, a line → a task, a stale rev, attachments up and back, the picture\'s text for the search', async () => {
    const dir = tmpDir('notes-files-');
    const png = Buffer.from('89504e470d0a1a0a0000000d4948445200000001000000010806000000', 'hex');
    fs.writeFileSync(path.join(dir, 'skizze.png'), png);
    fs.writeFileSync(path.join(dir, 'leer.txt'), '');
    const ocr = { available: async () => ({ available: true }), recognize: async () => ({ text: 'Gartenhaus 2,40 m' }) };
    const dialog = { showOpenDialog: async () => ({ canceled: false, filePaths: [path.join(dir, 'skizze.png'), path.join(dir, 'leer.txt')] }) };
    const { srv, svc } = await setup({}, { ocr, dialog });
    const list = await svc.notes({ area: 'private' });
    assert.deepEqual(list.notes.map((n) => n.title), ['Werkstatt Montag', 'Lasagne (Oma)']);
    assert.deepEqual(list.notes[0].check, { done: 1, total: 3 });
    assert.deepEqual(list.notes[0].tags, ['auto', 'werkstatt']);
    const made = (await svc.createNote({ notebookId: 32, title: 'Einkauf', body: '- [ ] Milch\n- [ ] Brot' })).note;
    assert.equal(made.body, '- [ ] Milch\n- [ ] Brot');
    const checked = (await svc.checkNote(made.id, 1, true)).note;
    assert.equal(checked.body, '- [ ] Milch\n- [x] Brot');
    const tk = await svc.noteToTask(made.id, { line: 0, myDay: true });
    assert.equal(tk.task.title, 'Milch');
    assert.match(tk.note.body.split('\n')[0], /\[Aufgabe\]\(task:\d+\)$/);
    await assert.rejects(svc.updateNote(made.id, { body: 'x', rev: 1 }), (e) => e.code === 'conflict');
    const up = (await svc.updateNote(made.id, { title: 'Einkauf Samstag', body: '**fett**', rev: tk.note.rev })).note;
    assert.equal(up.title, 'Einkauf Samstag');

    const att = await svc.addAttachments({ kind: 'note', refId: made.id });
    assert.equal(att.attachments.length, 1);
    assert.deepEqual(att.rejected, [{ name: 'leer.txt', code: 'empty' }]);
    const a = att.attachments[0];
    assert.equal(a.name, 'skizze.png');
    const img = await svc.attachmentImage(a.id);
    assert.deepEqual([img.mime, img.data.equals(png)], ['image/png', true]);
    await until(() => srv.state.attachments.get(a.id).ocr === 'Gartenhaus 2,40 m');
    // the url is fetched by the main process only, nothing else
    await assert.rejects(svc.api.mediaBytes('https://evil.example/x'), (e) => e.code === 'invalid');
    await assert.rejects(svc.api.mediaBytes('/api/v1/client/plugins/x'), (e) => e.code === 'invalid');
    const s = await svc.search({ q: 'samstag', area: 'private' });
    assert.deepEqual(s.notes.map((n) => n.title), ['Einkauf Samstag']);
  });
});

describe('NotesService: Tresor notebooks', () => {
  it('a Tresor notebook made here: the server holds only ciphertext; locked after the lock, open again with Windows Hello', async () => {
    const consent = fakeConsent();
    const { srv, svc, store } = await setup({}, { consent });
    const locks = [];
    svc.on('vaultLock', (e) => locks.push(e.locked));
    await svc.vaultUnlock();
    assert.equal(consent.prompts.length, 1);
    assert.match(consent.prompts[0], /Notizen/);
    const nb = await svc.createNotebook({ name: 'Versicherungen', area: 'private', vault: true });
    assert.match(nb.recoveryKey, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
    assert.equal(nb.notebook.name, 'Versicherungen');
    const vid = nb.vault.id;
    const n = (await svc.createNote({ notebookId: nb.notebook.id, title: 'Kfz', body: '- [ ] Police prüfen\nVertrag **4711**' })).note;
    assert.deepEqual([n.title, n.body, n.locked], ['Kfz', '- [ ] Police prüfen\nVertrag **4711**', false]);
    // what the server keeps: no title, no text, no key
    const raw = JSON.stringify([...srv.state.notes.values()].filter((x) => x.notebookId === nb.notebook.id)) + JSON.stringify([...srv.state.vaults.values()]);
    for (const leak of ['Kfz', 'Police', '4711', 'Versicherungen', nb.recoveryKey]) assert.ok(!raw.includes(leak), leak);
    const checked = (await svc.checkNote(n.id, 0, true)).note;
    assert.equal(checked.body.split('\n')[0], '- [x] Police prüfen');
    const nav = (await svc.nav({ area: 'private' })).nav;
    const tb = nav.notes.notebooks.find((b) => b.vault);
    assert.deepEqual([tb.name, tb.locked], ['Versicherungen', false]);
    assert.deepEqual((await svc.notes({ notebook: nb.notebook.id })).notes.map((x) => x.title), ['Kfz']);

    // locked: no names, no text; the device key under DPAPI stays
    svc.vaultLockNow();
    assert.deepEqual(locks, [false, true]);
    const n2 = (await svc.note(n.id)).note;
    assert.deepEqual([n2.locked, n2.title, n2.body], [true, null, null]);
    const nav2 = (await svc.nav({ area: 'private' })).nav;
    assert.deepEqual([nav2.notes.notebooks.find((b) => b.vault).name, nav2.notes.notebooks.find((b) => b.vault).locked], [null, true]);
    await assert.rejects(svc.updateNote(n.id, { body: 'x' }), (e) => e.code === 'vault_locked');
    consent.answers.push('cancelled');
    await assert.rejects(svc.vaultUnlock(vid), (e) => e.code === 'hello_cancelled');
    const open = await svc.vaultUnlock(vid);
    assert.deepEqual([open.unlocked, open.state], [true, 'open']);
    assert.equal((await svc.note(n.id)).note.body, '- [x] Police prüfen\nVertrag **4711**');
    const devKeys = JSON.stringify(store.get('notesVault'));
    assert.ok(devKeys.includes('DPAPI') || /"enc"/.test(devKeys));
    assert.equal(store.get('driveVault'), undefined);
  });

  it('a second device asks, is approved after the safety number; the recovery key opens it; a new key', async () => {
    const { srv, svc } = await setup();
    await svc.vaultUnlock();
    const nb = await svc.createNotebook({ name: 'Dokumente', area: 'private', vault: true });
    const vid = nb.vault.id;
    await svc.createNote({ notebookId: nb.notebook.id, title: 'Pass', body: 'Nr. 123' });
    // another PC of the same person against the same server
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const other = new NotesService({ apiClient, log, store: createMemoryStore(), protect: fakeProtect(), tempDir: () => tmpDir('notes-b-'), deviceName: () => 'Laptop', dialogPath: () => null });
    cleanup.push(() => other.stop());
    await other.check();
    assert.equal((await other.vaultOpen(vid)).state, 'none');
    const asked = await other.vaultRequest(vid);
    assert.match(asked.safetyNumber, /^\d{5}( \d{5}){3}$/);
    assert.equal((await other.vaultOpen(vid)).state, 'pending');
    const devs = (await svc.vaultDevices(vid)).devices;
    const pending = devs.find((d) => d.state === 'pending');
    assert.equal(pending.safetyNumber, asked.safetyNumber);
    await assert.rejects(svc.vaultApprove(vid, pending.deviceId, '00000 00000 00000 00000'), (e) => e.code === 'safety');
    await svc.vaultApprove(vid, pending.deviceId, asked.safetyNumber);
    assert.equal((await other.vaultOpen(vid)).state, 'open');
    const notes = (await other.notes({ notebook: nb.notebook.id })).notes;
    assert.equal(notes[0].title, 'Pass');
    // a third PC with the recovery key
    const third = new NotesService({ apiClient, log, store: createMemoryStore(), protect: fakeProtect(), tempDir: () => tmpDir('notes-c-'), dialogPath: () => null });
    cleanup.push(() => third.stop());
    await third.check();
    await assert.rejects(third.vaultRecover(vid, 'AAAA-'.repeat(13) + 'AAAA'), (e) => e.code === 'recovery_key');
    await third.vaultRecover(vid, nb.recoveryKey.toLowerCase());
    assert.equal((await third.note(notes[0].id)).note.body, 'Nr. 123');
    // a new key (after someone left): every approved device gets it
    const rot = await svc.vaultRotate(vid);
    assert.equal(rot.vault.keyVersion, 2);
    await svc.updateNote(notes[0].id, { body: 'Nr. 456' });
    assert.equal(srv.state.notes.get(notes[0].id).keyVersion, 2);
    assert.equal((await other.vaultOpen(vid)).state, 'open');
    other.vault.clear();
    assert.equal((await other.note(notes[0].id)).note.body, 'Nr. 456');
  });

  it('without protected key storage there is no Tresor on this PC', async () => {
    const { svc } = await setup({}, { protect: null });
    assert.equal(svc.status().vaultSupported, false);
    await assert.rejects(svc.createNotebook({ name: 'x', area: 'private', vault: true }), (e) => e.code === 'vault_unsupported');
  });
});

describe('NotesService: moving over', () => {
  it('Microsoft To Do: the device code, Microsoft\'s page only, the preview, the job', async () => {
    const opened = [];
    const shell = { openExternal: async (u) => { opened.push(u); } };
    const { svc } = await setup({}, { shell });
    const acc = await svc.msAccounts();
    assert.deepEqual(acc.accounts.map((a) => [a.email, a.tasks]), [['max@outlook.com', false]]);
    await assert.rejects(svc.msPreview(3), (e) => e.code === 'consent_required');
    const c = await svc.msConsent(3);
    assert.deepEqual([c.userCode, c.verificationUri, c.interval], ['ABCD-EFGH', 'https://microsoft.com/devicelogin', 5]);
    assert.deepEqual(await svc.openVerification(c.verificationUri), { ok: true });
    assert.deepEqual(await svc.openVerification('https://evil.example/devicelogin'), { ok: false, code: 'invalid' });
    assert.deepEqual(await svc.openVerification('http://microsoft.com/devicelogin'), { ok: false, code: 'invalid' });
    assert.deepEqual(opened, ['https://microsoft.com/devicelogin']);
    assert.equal((await svc.msConsentPoll(3, c.deviceId)).status, 'pending');
    assert.equal((await svc.msConsentPoll(3, c.deviceId)).status, 'done');
    const pv = await svc.msPreview(3);
    assert.deepEqual(pv.lists.map((l) => [l.name, l.area, l.include]), [['Aufgaben', 'private', true], ['Projekt X', 'work', true], ['Markierte E-Mails', 'private', false]]);
    const j = (await svc.msStart({ accountId: 3, lists: pv.lists.map((l) => ({ id: l.id, name: l.name, area: l.area, include: l.include })), doneDays: 90, twoWay: true })).job;
    assert.equal(j.state, 'running');
    let job;
    for (let i = 0; i < 3; i++) job = (await svc.job(j.id)).job;
    assert.deepEqual([job.state, job.stats.tasks], ['done', 19]);
    assert.equal((await svc.msLinks()).links.length, 2);
  });

  it('DS Note: the .nsx read here; notes, tags, pictures and tables over; protected notes into a new Tresor', async () => {
    const { srv, svc } = await setup();
    const sum = await svc.dsPick({ path: NSX_FILE });
    assert.deepEqual([sum.file, sum.notes, sum.protectedNotes, sum.attachments], ['sample.nsx', 4, 1, 2]);
    assert.deepEqual(sum.notebooks.map((b) => [b.title, b.notes, b.protected]), [['Haushalt', 2, 0], ['Rezepte & Dokumente', 2, 1]]);
    await svc.vaultUnlock();
    const events = [];
    svc.on('import', (e) => events.push(e));
    const r = await svc.dsImport({ password: 'geheim', area: 'private' });
    assert.deepEqual([r.started, r.total], [true, 4]);
    const end = await until(() => events.find((e) => e.state !== 'running'));
    assert.deepEqual([end.state, end.notes, end.protectedSkipped, end.vaults], ['done', 4, 0, 1]);
    const vaultEv = events.find((e) => e.vault);
    assert.match(vaultEv.vault.recoveryKey, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
    assert.equal(vaultEv.vault.name, 'Rezepte & Dokumente (DS Note)');
    const garden = [...srv.state.notes.values()].find((n) => n.title === 'Gartenhaus Maße');
    assert.match(garden.body, /## Maße/);
    assert.match(garden.body, /\*\*2,40 m\*\*/);
    assert.match(garden.body, /!\[Bild\]\(att:\d+\)/);
    assert.match(garden.body, /#garten #bauen/);
    const pack = [...srv.state.notes.values()].find((n) => n.title === 'Packliste Harz');
    assert.match(pack.body, /- \[x\] Zahnbürste/);
    assert.match(pack.body, /\| Tag \| Ziel \|/);
    // the protected note: only ciphertext on the server, readable here
    const secret = [...srv.state.notes.values()].find((n) => n.titleCipher && n.notebookId === vaultEv.vault.notebookId);
    assert.ok(secret && !JSON.stringify(secret).includes('4711'));
    assert.deepEqual([(await svc.note(secret.id)).note.title, (await svc.note(secret.id)).note.body], ['Versicherungen', 'Police **4711**']);
    // again: every note once (per ref)
    events.length = 0;
    await svc.dsImport({ password: '', area: 'private' });
    const again = await until(() => events.find((e) => e.state !== 'running'));
    assert.deepEqual([again.notes, again.protectedSkipped], [0, 1]);
  });

  it('DS Note: a wrong password skips the protected notes; a broken file is refused', async () => {
    const { svc } = await setup();
    const dir = tmpDir('nsx-bad-');
    fs.writeFileSync(path.join(dir, 'kaputt.nsx'), 'not a zip at all, sorry');
    await assert.rejects(svc.dsPick({ path: path.join(dir, 'kaputt.nsx') }), (e) => e.code === 'nsx_invalid');
    await svc.dsPick({ path: NSX_FILE });
    const events = [];
    svc.on('import', (e) => events.push(e));
    await svc.dsImport({ password: 'falsch', area: 'work' });
    const end = await until(() => events.find((e) => e.state !== 'running'));
    assert.deepEqual([end.state, end.notes, end.protectedSkipped, end.vaults], ['done', 3, 1, 0]);
    const opened = await openNsx(NSX_FILE);
    assert.equal(opened.summary.noteIds.length, 4);
    await opened.close();
  });
});

describe('ipc/notes-handlers', () => {
  it('checks arguments, answers failures as { ok: false, code }, forwards events', async () => {
    const { svc } = await setup();
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerNotesHandlers((ch, fn) => { handlers[ch] = fn; }, { notes: svc, getMainWindow: () => win, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('notes:view', { name: 'list:1; DROP', area: 'private' })).code, 'invalid');
    assert.equal((await call('notes:search', { q: 'x' })).code, 'invalid');
    assert.equal((await call('notes:task:update', { id: 12, patch: { due: { date: 'gestern' } } })).code, 'invalid');
    assert.equal((await call('notes:vault:approve', { vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', deviceId: 'Vt9bJm0n2QwErTyUiOpAsD', safetyNumber: '1' })).code, 'invalid');
    assert.equal((await call('notes:mstodo:start', { accountId: 3, lists: [], doneDays: 7 })).code, 'invalid');
    const v = await call('notes:view', { name: 'myday', area: 'private' });
    assert.equal(v.ok, true);
    const nf = await call('notes:task', { id: 99999 });
    assert.deepEqual([nf.ok, nf.code, nf.status], [false, 'not_found', 404]);
    const t = await call('notes:task:create', { task: { text: 'Fr 10 Uhr Angebot nachfassen #büro', area: 'work' } });
    assert.deepEqual([t.task.title, t.task.due.date, t.task.listId], ['Angebot nachfassen', '2026-11-13', 5]);
    svc.emit('changed', { what: ['notes'] });
    assert.deepEqual(sent.pop(), [NOTES_EVENTS.changed, { what: ['notes'] }]);
    const st = await call('notes:status');
    assert.equal(st.state, 'available');
    const api = new NotesApi({ apiClient: null });
    assert.throws(() => api._id('x'), (e) => e.code === 'invalid');
  });
});
