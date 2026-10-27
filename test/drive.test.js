'use strict';

// Drive (plugin gatecontrol-drive): the pure helpers (utils/drive.js —
// names, cleaned answers, request bodies), the service (services/drive.js —
// availability from the plugin list, browse / change, uploads with
// "same file" and taken names, resumable uploads, open / save as, previews,
// the folder last picked per server), its IPC (drive:*), and "In Drive
// speichern" of the other plugins: Messenger (chat:to-drive), Schule
// (attachments, school:attachment:drive) and GateDrop ("Mein Drive").

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

const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const MessengerApi = require('../src/services/messenger-api');
const SchoolService = require('../src/services/school');
const school = require('../src/utils/school');
const gd = require('../src/utils/gatedrop');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { registerSchoolHandlers } = require('../src/ipc/school-handlers');
const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function until(fn, ms = 5000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function setup(opts = {}, { store = createMemoryStore(), shell = null, dialog = null, partSize, resumableFrom, token = 'gc_token' } = {}) {
  const srv = await driveServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, token, log);
  const temp = tmpDir('drive-tmp-');
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {}, partSize, resumableFrom });
  const svc = new DriveService({ apiClient, api, log, store, shell, dialog, tempDir: () => temp, timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, store, temp, apiClient };
}

describe('utils/drive', () => {
  it('names: forbidden characters, trailing dots, .gcdrive', () => {
    assert.equal(drive.safeName('Brief: 1/2?.pdf'), 'Brief_ 1_2_.pdf');
    assert.equal(drive.safeName('  Notizen.  '), 'Notizen');
    assert.equal(drive.safeName('...'), null);
    assert.equal(drive.safeName('.gcdrive'), null);
    assert.equal(drive.safeName('x'.repeat(300)).length, 255);
    assert.equal(drive.validName('Urlaub 2026'), true);
    assert.equal(drive.validName('a/b'), false);
    assert.equal(drive.validName('Ende.'), false);
    assert.equal(drive.validName('   '), false);
    assert.equal(drive.validName(42), false);
  });

  it('nodes: ids, preview flag, snippet only for text matches, times in ms', () => {
    const n = drive.normalizeNode({
      id: 5, areaId: 'mine:2', parentId: '1', name: 'Foto\u0007.jpg', isDir: false, size: 10, mime: 'image/jpeg', mediaId: 'abcdef12',
      rev: 3, mtime: '2026-10-20T10:00:00.000Z', preview: { url: '/x' }, sha256: 'A'.repeat(64), match: 'text', snippet: 'die Miete', extra: 1,
    });
    assert.equal(n.name, 'Foto .jpg');
    assert.equal(n.parentId, 1);
    assert.equal(n.preview, true);
    assert.equal(n.sha256, 'a'.repeat(64));
    assert.equal(n.mtime, Date.parse('2026-10-20T10:00:00.000Z'));
    assert.equal(n.snippet, 'die Miete');
    assert.equal(n.extra, undefined);
    assert.equal(drive.normalizeNode({ id: 5, areaId: 'mine:2', name: 'x', match: 'name', snippet: 's' }).snippet, null);
    assert.equal(drive.normalizeNode({ id: 5, areaId: 'mine:2', name: 'x', mediaId: 'abcdef12', preview: null }).preview, false);
    assert.equal(drive.normalizeNode({ id: 0, areaId: 'mine:2', name: 'x' }), null);
    assert.equal(drive.normalizeNode({ id: 1, areaId: 'bad area', name: 'x' }), null);
    assert.equal(drive.normalizeNode({ id: 1, areaId: 'mine:2', name: '' }), null);
  });

  it('areas: writable only for write / manage and not archived; sorted mine, family, child, team', () => {
    const { areas } = drive.normalizeAreas({
      areas: [
        { id: 'team:1', kind: 'team', label: 'Büro', role: 'write', rootId: 4, archived: true },
        { id: 'child:7', kind: 'child', label: 'Lena', role: 'read', rootId: 3 },
        { id: 'family:1', kind: 'family', label: 'Familie', role: 'write', rootId: 2, storage: { bytes: 5, quota: 10, target: { label: 'NAS' } } },
        { id: 'mine:2', kind: 'mine', label: 'Meine Dateien', role: 'manage', rootId: 1 },
        { id: 'x', kind: 'mine', role: 'manage' },
      ],
    });
    assert.deepEqual(areas.map((a) => [a.id, a.writable]), [['mine:2', true], ['family:1', true], ['child:7', false], ['team:1', false]]);
    assert.deepEqual(areas[1].storage, { bytes: 5, quota: 10, form: null, target: 'NAS', state: null });
  });

  it('me, folder, versions, links, saved', () => {
    const me = drive.normalizeMe({ me: { id: 2, name: 'Marc', seat: 'weird' }, licence: { valid: true, tier: 'combo' }, areas: [], people: [{ id: 2, name: 'Marc' }, { id: 'x' }] });
    assert.equal(me.me.seat, null);
    assert.deepEqual(me.people, [{ id: 2, name: 'Marc' }]);
    const f = drive.normalizeFolder(
      { node: { id: 10, areaId: 'mine:2', name: 'Dokumente', isDir: true, crumbs: [{ id: 1, name: 'Meine Dateien' }, { id: 10, name: 'Dokumente' }, { id: 'x' }] } },
      { items: [{ id: 12, areaId: 'mine:2', name: 'Brief.pdf' }, { id: -1 }], role: 'write' },
    );
    assert.equal(f.writable, true);
    assert.equal(f.items.length, 1);
    assert.equal(f.crumbs.length, 2);
    assert.equal(drive.normalizeFolder({ node: {} }, { items: [] }), null);
    const v = drive.normalizeVersions({ current: { id: 1, areaId: 'mine:2', name: 'a' }, versions: [{ id: 3, rev: 1 }, { id: 4, rev: 2 }, { id: 'x' }] });
    assert.deepEqual(v.versions.map((x) => x.id), [4, 3]);
    const l = drive.normalizeLinks({ links: [{ token: 'tok_old_1', active: false, createdAt: '2026-10-01T00:00:00Z' }, { token: 'tok_new_1', active: true, url: 'javascript:alert(1)', pin: true }, { token: '!' }] });
    assert.deepEqual(l.links.map((x) => x.token), ['tok_new_1', 'tok_old_1']);
    assert.equal(l.links[0].url, null);
    assert.equal(l.links[0].pin, true);
    assert.deepEqual(drive.savedOf({ saved: { nodeId: 812, name: 'Brief.pdf', where: 'Familie › Schule › Lena › Brief.pdf' } }), { nodeId: 812, name: 'Brief.pdf', where: 'Familie › Schule › Lena › Brief.pdf' });
    assert.deepEqual(drive.savedOf({}), { nodeId: null, name: null, where: null });
  });

  it('request bodies: link (PIN 4–12 digits), children query', () => {
    assert.deepEqual(drive.linkBody({ nodeId: 5, mode: 'view', expires: '7d', pin: '1234' }), { nodeId: 5, mode: 'view', expires: '7d', pin: '1234' });
    assert.deepEqual(drive.linkBody({ nodeId: 5, mode: 'download', expires: 'never', pin: '' }), { nodeId: 5, mode: 'download', expires: 'never' });
    assert.equal(drive.linkBody({ nodeId: 5, mode: 'view', expires: '7d', pin: '12' }), null);
    assert.equal(drive.linkBody({ nodeId: 5, mode: 'edit', expires: '7d' }), null);
    assert.equal(drive.linkBody({ nodeId: 5, mode: 'view', expires: '1h' }), null);
    assert.deepEqual(drive.childrenQuery({}), { sort: 'name', order: 'asc', offset: 0, limit: 500 });
    assert.deepEqual(drive.childrenQuery({ sort: 'size', limit: 5000 }), { sort: 'size', order: 'desc', offset: 0, limit: 1000 });
    assert.equal(drive.errorCode({ code: 'no_seat' }), 'no_seat');
    assert.equal(drive.errorCode({ code: 'bad code!' }), 'failed');
  });
});

describe('DriveService', () => {
  it('available when the server lists the plugin, unavailable without', async () => {
    const { svc } = await setup();
    assert.equal(svc.status().state, 'available');
    assert.equal(svc.status().version, '1.4.0');
    const off = await setup({ plugin: false });
    assert.equal(off.svc.status().state, 'unavailable');
    assert.equal(off.svc.status().reason, 'not_installed');
    await assert.rejects(off.svc.areas(), (e) => e.code === 'drive_unavailable');
  });

  it('me: usable only with a seat and a valid licence; Drive codes pass through', async () => {
    const { svc } = await setup();
    const me = await svc.me();
    assert.equal(me.usable, true);
    assert.equal(me.areas[0].id, 'mine:2');
    const noSeat = await setup({ seat: null });
    assert.equal((await noSeat.svc.me()).usable, false);
    await assert.rejects(noSeat.svc.areas(), (e) => e.code === 'no_seat' && e.status === 403);
    const noLicence = await setup({ licence: false });
    await assert.rejects(noLicence.svc.folder(1), (e) => e.code === 'not_licensed');
  });

  it('browses a folder (crumbs, role) and sends the language', async () => {
    const { svc, srv } = await setup();
    const f = await svc.folder(10);
    assert.deepEqual(f.crumbs, [{ id: 1, name: 'Meine Dateien' }, { id: 10, name: 'Dokumente' }]);
    assert.equal(f.writable, true);
    assert.deepEqual(f.items.map((i) => i.name), ['Brief.pdf']);
    const childrenCall = srv.state.requests.find((r) => r.path.endsWith('/nodes/10/children'));
    assert.deepEqual(childrenCall.query, { sort: 'name', order: 'asc', offset: '0', limit: '500', lang: 'de' });
    const root = await svc.folder(1);
    assert.deepEqual(root.items.map((i) => [i.name, i.isDir, i.preview]), [['Dokumente', true, false], ['Foto.jpg', false, true], ['setup.exe', false, false]]);
    const ro = await svc.folder(3);
    assert.equal(ro.writable, false);
  });

  it('new folder, rename, move, trash, restore, purge', async () => {
    const { svc } = await setup();
    await assert.rejects(svc.mkdir(1, 'a/b'), (e) => e.code === 'invalid_name');
    const made = await svc.mkdir(1, 'Urlaub');
    assert.equal(made.node.name, 'Urlaub');
    assert.equal((await svc.mkdir(1, 'Urlaub')).node.name, 'Urlaub (2)');
    assert.equal((await svc.rename(made.node.id, 'Reisen')).node.name, 'Reisen');
    await assert.rejects(svc.rename(made.node.id, 'Dokumente'), (e) => e.code === 'exists');
    assert.equal((await svc.move(12, made.node.id)).node.parentId, made.node.id);
    await assert.rejects(svc.move(12, 3), (e) => e.code === 'forbidden');
    assert.deepEqual(await svc.remove(12), { ok: true, id: 12, trashed: true });
    const trash = await svc.trashList();
    assert.deepEqual(trash.items.map((i) => [i.id, i.from]), [[12, 'Meine Dateien/Reisen']]);
    assert.equal((await svc.restore(12)).node.id, 12);
    await svc.remove(12);
    assert.deepEqual(await svc.purge(12), { ok: true, id: 12 });
    assert.equal((await svc.trashList()).items.length, 0);
  });

  it('versions and restoring one', async () => {
    const { svc } = await setup();
    const v = await svc.versions(11);
    assert.equal(v.current.rev, 2);
    assert.deepEqual(v.versions.map((x) => [x.id, x.rev]), [[501, 1]]);
    assert.equal((await svc.restoreVersion(11, 501)).node.rev, 3);
  });

  it('search by name and recognised text (snippet)', async () => {
    const { svc } = await setup();
    await assert.rejects(svc.search('a'), (e) => e.code === 'invalid');
    const r = await svc.search('Miete');
    assert.deepEqual(r.items.map((i) => [i.name, i.match, i.snippet]), [['Brief.pdf', 'text', '… die Miete für Oktober …']]);
    assert.equal((await svc.search('brief')).items[0].path, 'Dokumente');
  });

  it('links: create (mode, validity, PIN), list, end', async () => {
    const { svc, srv } = await setup();
    await assert.rejects(svc.createLink({ nodeId: 12, mode: 'view', expires: '7d', pin: '1' }), (e) => e.code === 'invalid');
    const { link } = await svc.createLink({ nodeId: 12, mode: 'download', expires: '7d', pin: '4711' });
    assert.ok(link.url.startsWith('https://gc.example.com/s/'));
    assert.equal(link.pin, true);
    assert.deepEqual(srv.state.requests.at(-1).body, { nodeId: 12, mode: 'download', expires: '7d', pin: '4711' });
    assert.equal((await svc.links()).links.length, 1);
    assert.deepEqual(await svc.endLink(link.token), { ok: true, ended: true });
    assert.equal((await svc.links()).links[0].active, false);
    await assert.rejects(svc.createLink({ nodeId: 3, mode: 'view', expires: '1d' }), (e) => e.code === 'forbidden');
  });

  it('uploads a new file, skips the same file, asks for a taken name', async () => {
    const { svc, srv } = await setup();
    const dir = tmpDir('drive-up-');
    const changed = [];
    svc.on('changed', (c) => changed.push(c));
    const fresh = path.join(dir, 'Neu?.txt');
    fs.writeFileSync(fresh, 'hallo');
    const same = path.join(dir, 'Brief.pdf');
    fs.writeFileSync(same, '%PDF-1.4 brief');
    const r = await svc.upload(10, [fresh, same, dir, path.join(dir, 'gone.txt'), 'relative.txt']);
    assert.equal(r.queued.length, 2);
    assert.deepEqual(r.rejected.map((x) => x.code).sort(), ['folder', 'missing']);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    const rows = svc.transfers();
    assert.deepEqual(rows.map((t) => [t.name, t.state]), [['Neu_.txt', 'done'], ['Brief.pdf', 'same']]);
    assert.deepEqual(changed, [{ folderId: 10 }]);

    // A taken name with other content: the person chooses.
    const other = path.join(dir, 'Foto.jpg');
    fs.writeFileSync(other, 'new photo bytes');
    const q = await svc.upload(1, [other]);
    await until(() => svc.transfers().find((t) => t.id === q.queued[0] && t.state === 'conflict'));
    svc.resolve(q.queued[0], 'version');
    await until(() => svc.transfers().find((t) => t.id === q.queued[0] && t.state === 'done'));
    assert.equal(srv.state.nodes.get(11).rev, 3);
    const commit = srv.state.requests.filter((x) => x.path.endsWith('uploads/commit')).at(-1);
    assert.equal(commit.body.onConflict, 'version');

    fs.writeFileSync(other, 'newer photo bytes');
    const q2 = await svc.upload(1, [other]);
    await until(() => svc.transfers().find((t) => t.id === q2.queued[0] && t.state === 'conflict'));
    svc.resolve(q2.queued[0], null);
    assert.equal(svc.transfers().find((t) => t.id === q2.queued[0]).state, 'skipped');
    assert.throws(() => svc.resolve(q2.queued[0], 'rename'), (e) => e.code === 'not_found');
    assert.equal(svc.clearTransfers().transfers.length, 0);
  });

  it('uploads larger files resumable and goes on after a cut', async () => {
    const { svc, srv } = await setup({}, { resumableFrom: 1000, partSize: 128 * 1024 });
    const dir = tmpDir('drive-big-');
    const big = path.join(dir, 'Video.mp4');
    const data = Buffer.alloc(300 * 1024, 7);
    fs.writeFileSync(big, data);
    srv.cutUploadAfter = 70 * 1024;
    await svc.upload(1, [big]);
    await until(() => svc.transfers().find((t) => t.state === 'done' || t.state === 'failed'));
    assert.equal(svc.transfers()[0].state, 'done');
    const n = [...srv.state.nodes.values()].find((x) => x.name === 'Video.mp4');
    assert.equal(srv.state.media.get(n.mediaId).data.length, data.length);
    assert.ok(srv.state.uploadCalls.length >= 3);
    assert.ok(srv.state.uploadCalls.every((c) => c.uploadId));
  });

  it('a refused upload fails its row with the Drive code', async () => {
    const { svc, srv } = await setup();
    srv.state.fail['POST uploads/commit'] = { status: 507, code: 'quota' };
    const dir = tmpDir('drive-q-');
    const f = path.join(dir, 'a.txt');
    fs.writeFileSync(f, 'x');
    await svc.upload(1, [f]);
    await until(() => svc.transfers().find((t) => t.state === 'failed'));
    assert.equal(svc.transfers()[0].code, 'quota');
  });

  it('opens a file named like a Windows device under a renamed local copy', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; } };
    const { svc, srv, temp } = await setup({}, { shell });
    srv.state.nodes.get(12).name = 'CON.pdf';
    const r = await svc.open(12);
    assert.equal(r.ok, true);
    assert.equal(r.path, path.join(temp, '12-1', '_CON.pdf'));
    assert.deepEqual(opened, [r.path]);
  });

  it('opens a file from the temp folder, never an executable; save as', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; }, showItemInFolder: (p) => opened.push(`show:${p}`) };
    const dest = path.join(tmpDir('drive-save-'), 'Kopie.pdf');
    const dialog = { showSaveDialog: async (...a) => ({ canceled: false, filePath: a.at(-1).defaultPath === 'Brief.pdf' ? dest : null }) };
    const { svc, temp } = await setup({}, { shell, dialog });
    const r = await svc.open(12);
    assert.equal(r.ok, true);
    assert.equal(r.path, path.join(temp, '12-1', 'Brief.pdf'));
    assert.equal(fs.readFileSync(r.path, 'utf8'), '%PDF-1.4 brief');
    assert.deepEqual(opened, [r.path]);
    assert.equal(fs.readdirSync(path.dirname(r.path)).length, 1); // no .part left
    const exe = await svc.open(13);
    assert.equal(exe.code, 'unsafe');
    assert.equal(opened.length, 1);
    const v = await svc.open(11, { versionId: 501 });
    assert.equal(fs.readFileSync(v.path, 'utf8'), 'old');
    const saved = await svc.saveAs(12);
    assert.deepEqual(saved, { ok: true, path: dest });
    assert.equal(fs.readFileSync(dest, 'utf8'), '%PDF-1.4 brief');
    assert.deepEqual(svc.showItem(dest), { ok: true });
    assert.throws(() => svc.showItem('C:\\Windows\\notepad.exe'), (e) => e.code === 'invalid');
    const cancelled = await (await setup({}, { shell, dialog: { showSaveDialog: async () => ({ canceled: true }) } })).svc.saveAs(12);
    assert.equal(cancelled.cancelled, true);
  });

  it('empty files (Drive 1.5 emptyFiles): up without media, open and save as an empty file; older Drives refuse', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; } };
    const { svc, srv } = await setup({ features: ['emptyFiles'] }, { shell });
    const dir = tmpDir('drive-empty-');
    const leer = path.join(dir, 'Leer.txt');
    fs.writeFileSync(leer, '');
    const r = await svc.upload(10, [leer]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.equal(svc.transfers().find((t) => t.id === r.queued[0]).state, 'done');
    const body = srv.state.requests.filter((x) => x.path.endsWith('uploads/commit')).at(-1).body;
    assert.equal(body.size, 0);
    assert.equal('mediaId' in body, false);
    assert.equal(srv.state.uploadCalls.length, 0, 'no media upload');
    const n = [...srv.state.nodes.values()].find((x) => x.name === 'Leer.txt');
    assert.equal(n.size, 0);
    const o = await svc.open(n.id);
    assert.equal(o.ok, true);
    assert.equal(fs.readFileSync(o.path, 'utf8'), '');

    const old = await setup();
    const q = await old.svc.upload(10, [leer]);
    await until(() => old.svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.deepEqual(old.svc.transfers().filter((t) => t.id === q.queued[0]).map((t) => [t.state, t.code]), [['failed', 'empty_file']]);
    assert.deepEqual(drive.normalizeMe({ features: ['devices', 'bad key', 7] }).features, ['devices']);
    assert.deepEqual(drive.normalizeContent({ empty: true, name: 'x' }), { mediaId: null, name: 'x', mime: null, size: 0, empty: true });
    assert.equal(drive.normalizeDevice({ device: { id: 'pc-1', name: 'PC', folder: { id: 5, name: 'PC' } } }).folder.id, 5);
    assert.equal(drive.normalizeDevice({ device: { id: 'bad id!' } }), null);
  });

  it('previews: cached by mediaId; still being made → preview_pending', async () => {
    const { svc, srv } = await setup();
    const p = await svc.preview('photoMedia000001');
    assert.equal(p.mime, 'image/jpeg');
    await svc.preview('photoMedia000001');
    assert.equal(srv.state.requests.filter((r) => r.path.endsWith('/preview')).length, 1);
    srv.state.pending.add('oldMedia00000001');
    await assert.rejects(svc.preview('oldMedia00000001'), (e) => e.code === 'preview_pending');
    await assert.rejects(svc.preview('../x'), (e) => e.code === 'invalid');
  });

  it('remembers the folder last picked per server', async () => {
    const store = createMemoryStore();
    const { svc, apiClient } = await setup({}, { store });
    assert.deepEqual(svc.lastFolder(), { ok: true, folderId: null });
    svc.rememberFolder(10);
    assert.deepEqual(svc.lastFolder(), { ok: true, folderId: 10 });
    assert.equal(JSON.stringify(store.get(DriveService.STORE_KEY)).includes('gc_token'), false);
    apiClient.configure('https://other.example.com', 'other_token');
    assert.deepEqual(svc.lastFolder(), { ok: true, folderId: null });
    assert.throws(() => svc.rememberFolder(0), (e) => e.code === 'invalid');
  });

  it('a new server drops waiting uploads and asks again', async () => {
    const { svc } = await setup();
    const dir = tmpDir('drive-r-');
    const f = path.join(dir, 'Foto.jpg');
    fs.writeFileSync(f, 'other');
    const q = await svc.upload(1, [f]);
    await until(() => svc.transfers().find((t) => t.state === 'conflict'));
    const st = await svc.resetForNewServer();
    assert.equal(st.state, 'available');
    assert.equal(svc.transfers().find((t) => t.id === q.queued[0]).state, 'skipped');
  });
});

describe('drive:* IPC', () => {
  function register(svc) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => win, log });
    return { handlers, sent, call: (ch, arg) => handlers[ch]({}, arg) };
  }

  it('checks arguments and passes events on', async () => {
    const { svc } = await setup();
    const { call, sent } = register(svc);
    assert.equal((await call('drive:folder', { id: 'x' })).code, 'invalid');
    assert.equal((await call('drive:mkdir', { parentId: 1, name: '' })).code, 'invalid');
    assert.equal((await call('drive:upload', { parentId: 1, paths: 'C:\\x' })).code, 'invalid');
    assert.equal((await call('drive:upload:resolve', { id: 'u1', choice: 'delete' })).code, 'invalid');
    assert.equal((await call('drive:link:create', { nodeId: 12, mode: 'view', expires: '7d', pin: 1234 })).code, 'invalid');
    assert.equal((await call('drive:rename', { id: 12, name: 'a:b' })).code, 'invalid_name');
    const f = await call('drive:folder', { id: 10, sort: 'size' });
    assert.equal(f.ok, true);
    const p = await call('drive:preview', { mediaId: 'photoMedia000001' });
    assert.ok(p.data instanceof Uint8Array);
    assert.equal((await call('drive:last-folder:set', { folderId: 10 })).folderId, 10);
    assert.equal((await call('drive:last-folder')).folderId, 10);
    svc.emit('changed', { folderId: 10 });
    assert.deepEqual(sent.at(-1), ['drive:changed', { folderId: 10 }]);
  });
});

describe('"In Drive speichern" of other plugins', () => {
  it('Messenger: POST messages/<id>/to-drive { folderId } → saved', async () => {
    const calls = [];
    const api = new MessengerApi({ apiClient: { client: { request: async (o) => { calls.push(o); return { status: 200, data: { ok: true, saved: { nodeId: 9, name: 'Foto.jpg', where: 'Meine Dateien › Messenger › Foto.jpg' } } }; } } } });
    const r = await api.toDrive(55, 12);
    assert.equal(calls[0].url, '/api/v1/client/plugins/gatecontrol-messenger/api/messages/55/to-drive');
    assert.deepEqual(calls[0].data, { folderId: 12 });
    assert.equal(r.saved.where, 'Meine Dateien › Messenger › Foto.jpg');
    await api.toDrive(55);
    assert.deepEqual(calls[1].data, {});

    const handlers = {};
    const m = Object.assign(new EventEmitter(), { toDrive: async (id, folderId) => ({ nodeId: 9, name: 'x', where: `${id}/${folderId}` }) });
    registerMessengerHandlers((ch, fn) => { handlers[ch] = fn; }, { messenger: m, getMainWindow: () => null, log });
    assert.deepEqual(await handlers['chat:to-drive']({}, { id: 55, folderId: 12 }), { ok: true, saved: { nodeId: 9, name: 'x', where: '55/12' } });
    assert.equal((await handlers['chat:to-drive']({}, { id: 55, folderId: -1 })).code, 'invalid');
  });

  it('Schule: attachments and the drive flag of app/messages; POST …/attachments/<id>/drive with its own timeout', async () => {
    const r = school.normalizeMessages({
      drive: true,
      messages: [{ id: 77, subject: 'Elternbrief', hasAttachments: true, attachments: [{ id: 'a1', name: 'Brief.pdf', size: 1200, mime: 'application/pdf' }, { id: '../x' }, { id: 3, name: null, size: -1 }] }],
    });
    assert.equal(r.drive, true);
    assert.deepEqual(r.messages[0].attachments, [{ id: 'a1', name: 'Brief.pdf', size: 1200, mime: 'application/pdf' }, { id: 3, name: '3', size: null, mime: null }]);
    assert.equal(school.normalizeMessages({ messages: [] }).drive, false);
    assert.equal(school.attachmentDrivePath(77, 'a1'), 'app/messages/77/attachments/a1/drive');
    assert.equal(school.attachmentDrivePath(77, '../x'), null);

    const calls = [];
    const api = { scope: () => 's', _call: async (method, p, o) => { calls.push({ method, p, o }); return { ok: true, saved: { nodeId: 812, name: 'Brief.pdf', where: 'Familie › Schule › Lena › Brief.pdf' } }; } };
    const svc = new SchoolService({ apiClient: null, api, log });
    const saved = await svc.attachmentToDrive({ messageId: 77, attachmentId: 'a1', folderId: 17 });
    assert.deepEqual(saved, { ok: true, saved: { nodeId: 812, name: 'Brief.pdf', where: 'Familie › Schule › Lena › Brief.pdf' } });
    assert.equal(calls[0].p, '/api/v1/client/plugins/gatecontrol-schule/api/app/messages/77/attachments/a1/drive');
    assert.deepEqual(calls[0].o.body, { folderId: 17 });
    assert.equal(calls[0].o.timeout, 90000);
    await svc.attachmentToDrive({ messageId: 77, attachmentId: 'a1' });
    assert.deepEqual(calls[1].o.body, {});
    await assert.rejects(svc.attachmentToDrive({ messageId: 77, attachmentId: 'a1', folderId: 'x' }), (e) => e.code === 'invalid');

    const handlers = {};
    registerSchoolHandlers((ch, fn) => { handlers[ch] = fn; }, { school: Object.assign(new EventEmitter(), { attachmentToDrive: async (a) => ({ ok: true, a }) }), getMainWindow: () => null, log });
    assert.deepEqual(await handlers['school:attachment:drive']({}, { messageId: 77, attachmentId: 'a1', folderId: 17 }), { ok: true, a: { messageId: 77, attachmentId: 'a1', folderId: 17 } });
    assert.equal((await handlers['school:attachment:drive']({}, { messageId: {}, attachmentId: 'a1' })).code, 'invalid');
  });

  it('GateDrop: "Mein Drive" target (true | { folderId }), files only, deliveries with where', () => {
    assert.equal(gd.normalizeTargets({ drive: true }).drive, true);
    assert.equal(gd.normalizeTargets({}).drive, false);
    assert.deepEqual(gd.sendTargets({ drive: true }), { people: [], devices: [], nas: [], drive: true });
    assert.deepEqual(gd.sendTargets({ drive: { folderId: 12 } }).drive, { folderId: 12 });
    assert.deepEqual(gd.sendTargets({ drive: {} }).drive, true);
    assert.equal(gd.sendTargets({ drive: { folderId: 'x' } }), null);
    assert.equal(gd.sendTargets({ drive: 'yes' }), null);
    assert.equal(gd.sendTargets({ drive: false }), null);
    const d = gd.normalizeDelivery({ kind: 'drive', target: 'mine', label: 'Meine Dateien › GateDrop', status: 'delivered', where: ['Meine Dateien › GateDrop › Foto.jpg', 5] });
    assert.deepEqual(d.where, ['Meine Dateien › GateDrop › Foto.jpg']);
    assert.equal(d.targetName, 'Meine Dateien › GateDrop');
  });
});
