'use strict';

// Drive 1.7 in the Windows Pro app: the answers (time travel, photos, albums,
// storage, takenAt), the API calls and DriveService against the fake Drive
// server (only with the features `me` reports), the time of photos with the
// uploads of the page and of "Ordner sichern", DriveSync after a time travel
// ("Abgleichen": Drive's old state comes to the PC, PC changes stay as
// conflict copies; "Nur sichern": the PC is not written, Drive stays its
// backup) and the IPC.

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

const drive = require('../src/utils/drive');
const S = require('../src/utils/drive-sync');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createBridgeApi } = require('../src/preload/bridge');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');
const { tiff, jpeg } = require('./fixtures/exif-files');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const ALL = ['devices', 'deleteAfter', 'emptyFiles', 'timeTravel', 'takenAt', 'photos', 'albums', 'frame', 'storage'];

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}
function write(root, rel, content) {
  const p = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}
const read = (root, rel) => fs.readFileSync(path.join(root, ...rel.split('/')), 'utf8');
const exists = (root, rel) => fs.existsSync(path.join(root, ...rel.split('/')));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const commits = (srv) => srv.state.requests.filter((r) => r.path.endsWith('uploads/commit'));
const childNamed = (srv, parentId, name) => [...srv.state.nodes.values()].find((n) => n.parentId === parentId && !n.deleted && n.name === name);

async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 15));
  }
}

async function setup(features = ALL) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  // one temp folder: a new one per call would come after the cleanup (svc.stop() asks for it) and stay behind
  const tmp = tmpDir('drive17-tmp-');
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp, timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api, apiClient };
}

function syncOf({ srv, svc, api }) {
  const sync = new DriveSync({
    drive: svc, api, store: createMemoryStore(), dir: tmpDir('drive17-state-'), log,
    hostname: () => 'Desktop-PC',
    getDeviceKey: () => 'ab12cd34',
    trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); },
    timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 },
    readPdfText: async () => null,
  });
  sync.start();
  cleanup.push(() => sync.stop());
  return sync;
}

// ── Answers ────────────────────────────────────────────────

describe('utils/drive: Drive 1.7 answers', () => {
  it('cleans time travel, photos, albums, storage, takenAt and me.admin', () => {
    const p = drive.normalizeTimeTravelPreview({ at: '2026-10-01T10:00:00Z', historySince: '2026-09-01T00:00:00Z', restore: 2, revert: '3', trash: 4, move: -1, sample: [{ op: 'trash', name: 'neu.txt', path: 'A/neu.txt' }, { op: 'x', name: 'b' }, { name: '' }, null], limited: true });
    assert.deepEqual(p, { at: Date.parse('2026-10-01T10:00:00Z'), historySince: Date.parse('2026-09-01T00:00:00Z'), restore: 2, revert: 3, trash: 4, move: 0, sample: [{ op: 'trash', name: 'neu.txt', path: 'A/neu.txt' }, { op: null, name: 'b', path: null }], limited: true, lost: 0, total: 9, ops: 9, max: null });
    const lim = drive.normalizeTimeTravelPreview({ restore: 1, lost: 2, ops: 2500, max: 2000 });
    assert.deepEqual([lim.lost, lim.ops, lim.max], [2, 2500, 2000]);
    assert.deepEqual(drive.normalizeTimeTravelResult({ at: '2026-10-01T10:00:00Z', before: '2026-10-28T09:00:00.123Z', restored: 1, reverted: [1, 2], trashed: 0, moved: 0, failed: [] }),
      { at: Date.parse('2026-10-01T10:00:00Z'), before: Date.parse('2026-10-28T09:00:00.123Z'), restored: 1, reverted: 2, trashed: 0, moved: 0, failed: 0, lost: 0 });
    assert.equal(drive.isoOf(Date.UTC(2026, 0, 2)), '2026-01-02T00:00:00.000Z');
    assert.equal(drive.isoOf('nope'), null);

    const ph = drive.normalizePhotos({ items: [{ id: 5, name: 'a.jpg', mime: 'image/jpeg', size: 9, takenAt: '2026-07-14T18:03:22+02:00', areaId: 'mine:2', parentId: 1, preview: true }, { id: 6, name: 'v.mp4', mime: 'video/mp4', preview: false, mediaId: 'abcdef123456' }, { id: 'x' }], next: '2026-07-01T00:00:00.000Z' });
    assert.equal(ph.items.length, 2);
    assert.deepEqual(ph.items[0], { id: 5, name: 'a.jpg', mime: 'image/jpeg', kind: 'image', size: 9, takenAt: Date.parse('2026-07-14T16:03:22Z'), areaId: 'mine:2', parentId: 1, preview: true, mediaId: null, geo: null, located: false, people: null });
    assert.equal(ph.items[1].kind, 'video');
    assert.equal(ph.items[1].mediaId, 'abcdef123456');
    assert.equal(ph.next, '2026-07-01T00:00:00.000Z');
    assert.equal(drive.normalizePhotos({ items: [], next: '<script>' }).next, null);
    assert.deepEqual(drive.normalizeMonths({ months: [{ month: '2025-01', count: 3 }, { month: '2026-10', count: 1 }, { month: '2026-13', count: 1 }] }).months.map((m) => m.month), ['2026-10', '2025-01']);
    const mem = drive.normalizeMemories({ groups: [{ yearsAgo: 2, date: '2024-10-28', items: [{ id: 1, name: 'x.jpg' }] }, { yearsAgo: 1, items: [{ id: 2, name: 'y.jpg' }] }, { yearsAgo: 3, items: [] }] });
    assert.deepEqual(mem.groups.map((g) => [g.yearsAgo, g.date, g.items.length]), [[1, null, 1], [2, '2024-10-28', 1]]);

    const al = drive.normalizeAlbums({ albums: [{ id: 3, name: 'Urlaub', areaId: 'family:1', count: 4, coverId: 11, frame: true, updatedAt: '2026-10-01T00:00:00Z', canEdit: true }, { id: 'a_b', name: 'Bilder' }, { id: '../x', name: 'böse' }] });
    assert.deepEqual(al.albums.map((a) => a.id), ['a_b', 3]);
    assert.equal(al.albums[1].frame, true);
    assert.equal(drive.normalizeAlbumPage({ album: null }), null);

    const st = drive.normalizeStorage({
      total: { bytes: 100, files: 3, versionsBytes: 10, trashBytes: 5 }, limit: { maxBytes: 1000 },
      areas: [{ id: 'mine:2', label: 'Meine Dateien', kind: 'mine', bytes: 40, files: 2 }, { id: 'family:1', label: 'Familie', kind: 'family', bytes: 60, files: 1, quota: 500 }],
      largest: [{ id: 1, name: 'gross.iso', size: 60, path: 'ISO/gross.iso' }],
      duplicates: [{ sha256: 'A'.repeat(64), size: 10, count: 2, wasted: 10, items: [{ id: 2, name: 'a', canDelete: true }, { id: 3, name: 'a', canDelete: false }] }, { items: [{ id: 4, name: 'nur eins' }] }],
    });
    assert.deepEqual(st.areas.map((a) => a.id), ['family:1', 'mine:2']);
    assert.equal(st.limit.maxBytes, 1000);
    assert.equal(st.people.length, 0);
    assert.equal(st.duplicates.length, 1);
    assert.equal(st.duplicates[0].sha256, 'a'.repeat(64));
    assert.equal(st.duplicates[0].items[0].canDelete, true);

    assert.equal(drive.normalizeNode({ id: 1, areaId: 'mine:2', name: 'a.jpg', takenAt: '2026-07-14T18:03:22+02:00' }).takenAt, Date.parse('2026-07-14T16:03:22Z'));
    assert.equal(drive.normalizeMe({ me: { id: 2, admin: true } }).me.admin, true);
    assert.equal(drive.normalizeMe({ me: { id: 2 } }).me.admin, false);
  });
});

// ── Service ────────────────────────────────────────────────

describe('DriveService: Drive 1.7', () => {
  it('uses nothing new on a Drive that does not report it', async () => {
    const { svc, srv } = await setup(['devices']);
    for (const run of [() => svc.timeTravelPreview(1, Date.now()), () => svc.photos(), () => svc.albums(), () => svc.storage(), () => svc.memories()]) {
      await assert.rejects(run(), (e) => e.code === 'unsupported');
    }
    assert.equal(srv.state.requests.filter((r) => /timetravel|photos|albums|storage/.test(r.path)).length, 0);
  });

  it('time travel: preview, run (event), "Rückgängig" with `before`', async () => {
    const { svc, srv } = await setup();
    const f = srv.mutate.dir(1, 'Projekt');
    const a = srv.mutate.file(f.id, 'a.txt', 'A1');
    await sleep(5);
    const T = Date.now();
    await sleep(5);
    srv.mutate.change(a.id, 'A2');
    const n = srv.mutate.file(f.id, 'neu.txt', 'N');
    const p = await svc.timeTravelPreview(f.id, T);
    assert.equal(p.ok, true);
    assert.equal(p.revert, 1);
    assert.equal(p.trash, 1);
    assert.equal(p.total, 2);
    assert.equal(p.limited, false);
    assert.equal(p.ops, 2);
    assert.equal(p.max, 2000);
    assert.equal(p.lost, 0);
    assert.equal(srv.state.nodes.get(a.id).sha256, sha('A2')); // the preview changes nothing
    const events = [];
    svc.on('timetravel', (e) => events.push(e));
    const r = await svc.timeTravel(f.id, new Date(T).toISOString());
    assert.equal(r.reverted, 1);
    assert.equal(r.trashed, 1);
    assert.ok(r.before > T);
    assert.deepEqual(events, [{ folderId: f.id, at: r.at, before: r.before }]);
    assert.equal(srv.state.nodes.get(a.id).sha256, sha('A1'));
    assert.equal(srv.state.nodes.get(n.id).deleted, true);
    // the request carried an ISO time
    const post = srv.state.requests.find((x) => x.method === 'POST' && x.path.endsWith('/timetravel'));
    assert.equal(post.body.at, new Date(T).toISOString());
    // "Rückgängig"
    const u = await svc.timeTravel(f.id, r.before);
    assert.equal(u.reverted, 1);
    assert.equal(u.restored, 1);
    assert.equal(srv.state.nodes.get(a.id).sha256, sha('A2'));
    assert.equal(srv.state.nodes.get(n.id).deleted, false);
    await assert.rejects(svc.timeTravel(f.id, 'gestern'), (e) => e.code === 'invalid');
    // more steps than the plugin does at once
    srv.timeTravelMax = 1;
    await assert.rejects(svc.timeTravel(f.id, T), (e) => e.status === 400 && e.body.field === 'at' && e.body.max === 1);
  });

  it('photos: pages, months, memories; previews by the node; albums; storage', async () => {
    const { svc, srv } = await setup();
    const d = srv.mutate.dir(1, 'Bilder');
    const old = Date.UTC(2024, 9, 28, 12);
    for (let i = 0; i < 5; i++) srv.mutate.photo(d.id, `IMG_${i}.jpg`, { takenAt: Date.UTC(2026, 9, 1 + i, 10) });
    const memo = srv.mutate.photo(d.id, 'Vor2Jahren.jpg', { takenAt: old });
    const p1 = await svc.photos({ limit: 3 });
    assert.deepEqual(p1.items.map((x) => x.name), ['IMG_4.jpg', 'IMG_3.jpg', 'IMG_2.jpg']);
    assert.ok(p1.next);
    const p2 = await svc.photos({ limit: 3, before: p1.next });
    assert.deepEqual(p2.items.map((x) => x.name), ['IMG_1.jpg', 'IMG_0.jpg', 'Foto.jpg']);
    const m = await svc.photoMonths();
    assert.equal(m.months[0].month, '2026-10');
    assert.equal(m.months[0].count, 5);
    const mem = await svc.memories('2026-10-28');
    assert.equal(mem.date, '2026-10-28');
    assert.deepEqual(mem.groups.map((g) => [g.yearsAgo, g.items[0].id]), [[2, memo.id]]);
    // an answer without a mediaId: the node is asked once, then the preview
    srv.photoMediaIds = false;
    const p0 = await svc.photos({ limit: 3 });
    assert.equal(p0.items[0].mediaId, null);
    svc._mediaOf.clear(); // the page of p1 named the media already
    const before = srv.state.requests.length;
    const pv = await svc.previewOf(p1.items[0].id);
    assert.equal(pv.ok, true);
    assert.equal(pv.mime, 'image/jpeg');
    await svc.previewOf(p1.items[0].id);
    const asked = srv.state.requests.slice(before).map((r) => r.path);
    assert.equal(asked.filter((x) => /\/nodes\/\d+$/.test(x)).length, 1);
    assert.equal(asked.filter((x) => x.endsWith('/content')).length, 0); // nothing that tells a child "a parent looked"
    // with a mediaId in the answer: no node call
    srv.photoMediaIds = true;
    const p3 = await svc.photos({ limit: 1 });
    const b2 = srv.state.requests.length;
    await svc.previewOf(p3.items[0].id, { large: true });
    assert.equal(srv.state.requests.slice(b2).filter((r) => /\/nodes\//.test(r.path)).length, 0);

    // albums
    const c = await svc.createAlbum({ name: 'Herbst', areaId: 'family:1' });
    assert.equal(c.album.name, 'Herbst');
    assert.equal(c.album.canEdit, true);
    const ids = p1.items.map((x) => x.id);
    let r = await svc.albumItems(c.album.id, ids);
    assert.equal(r.album.count, 3);
    r = await svc.albumItems(c.album.id, [ids[0]], { remove: true });
    assert.equal(r.album.count, 2);
    const del = srv.state.requests.filter((x) => x.method === 'DELETE' && x.path.endsWith('/items')).pop();
    assert.deepEqual(del.body, { ids: [ids[0]] });
    assert.equal(del.query.ids, String(ids[0]));
    r = await svc.updateAlbum(c.album.id, { name: 'Herbst 2026', frame: true });
    assert.equal(r.album.name, 'Herbst 2026');
    assert.equal(r.album.frame, true);
    assert.equal(r.album.canFrame, true);
    srv.noFrame = true;
    await assert.rejects(svc.updateAlbum(c.album.id, { frame: false }), (e) => e.status === 403);
    srv.noFrame = false;
    const page = await svc.album(c.album.id);
    assert.deepEqual(page.items.map((x) => x.id), ids.slice(1));
    assert.equal((await svc.albums()).albums.length, 1);
    await svc.deleteAlbum(c.album.id);
    assert.equal((await svc.albums()).albums.length, 0);
    await assert.rejects(svc.albumItems(5, []), (e) => e.code === 'invalid');

    // storage: the same bytes twice are a duplicate
    srv.mutate.photo(d.id, 'Kopie.jpg', { content: 'IMG_0.jpg' });
    const st = await svc.storage();
    assert.equal(st.ok, true);
    assert.ok(st.total.files >= 9);
    assert.equal(st.duplicates.length, 1);
    assert.deepEqual(st.duplicates[0].items.map((x) => x.name).sort(), ['IMG_0.jpg', 'Kopie.jpg']);
    assert.equal(st.people.length, 0);
    const all = await svc.storage({ all: true });
    assert.equal(all.people.length, 1);
    assert.equal(srv.state.requests.filter((x) => x.path.endsWith('/storage')).pop().query.all, '1');
    const pr = await svc.pruneVersions({ areaId: 'mine:2', keep: 0 });
    assert.equal(pr.removed, 1);
    assert.equal(pr.more, false);
    assert.equal(st.areas.find((a) => a.id === 'mine:2').canPrune, true);
    assert.equal(all.all, true);
  });

  it('a photo uploaded from the page carries when it was taken (only to Drives with takenAt)', async () => {
    for (const features of [ALL, ['emptyFiles']]) {
      const { svc, srv } = await setup(features);
      const dir = tmpDir('drive17-up-');
      const p = write(dir, 'IMG_1.jpg', jpeg(tiff()));
      write(dir, 'notiz.txt', 'hallo');
      await svc.upload(1, [p, path.join(dir, 'notiz.txt')]);
      await until(() => svc.transfers().every((x) => x.state === 'done'));
      const c = commits(srv);
      const img = c.find((x) => x.body.name === 'IMG_1.jpg');
      const txt = c.find((x) => x.body.name === 'notiz.txt');
      if (features === ALL) {
        assert.equal(img.body.takenAt, '2026-07-14T18:03:22+02:00');
        assert.equal(childNamed(srv, 1, 'IMG_1.jpg').takenAt, '2026-07-14T16:03:22.000Z');
      } else {
        assert.equal(img.body.takenAt, undefined);
      }
      assert.equal(txt.body.takenAt, undefined);
    }
  });
});

// ── "Ordner sichern" and the time travel ───────────────────

describe('DriveSync: after a time travel', () => {
  it('"Abgleichen": Drive\'s old state comes to the PC, unsynced PC changes stay as conflict copies, no mass-delete question', async () => {
    const env = await setup();
    const { srv, svc } = env;
    const sync = syncOf(env);
    const P = srv.mutate.dir(1, 'Projekt');
    const root = tmpDir('pc-tt-sync-');
    for (const x of ['a', 'b', 'c', 'd']) write(root, `${x}.txt`, `${x.toUpperCase()}1`);
    const { folder } = await sync.addFolder({ path: root, mode: 'sync', targetId: P.id });
    await sync.idle();
    assert.ok(childNamed(srv, P.id, 'd.txt'));
    await sleep(5);
    const T = Date.now();
    await sleep(5);
    // after T: another device changes a, this PC changes b and adds 12 files
    srv.mutate.change(childNamed(srv, P.id, 'a.txt').id, 'A2');
    write(root, 'b.txt', 'B2');
    for (let i = 0; i < 12; i++) write(root, `neu${i}.txt`, `N${i}`);
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(read(root, 'a.txt'), 'A2');
    assert.equal(childNamed(srv, P.id, 'b.txt').sha256, sha('B2'));
    // b changes again on the PC, not synced yet
    write(root, 'b.txt', 'B3 lokal');
    const linked = await sync.linkedFolders(P.id);
    assert.deepEqual(linked.map((l) => [l.id, l.mode, l.relation]), [[folder.id, 'sync', 'same']]);
    assert.deepEqual((await sync.linkedFolders(1)).map((l) => l.relation), ['contains']);

    const r = await svc.timeTravel(P.id, T);
    assert.equal(r.trashed, 12);
    await until(async () => { await sync.idle(); return !exists(root, 'neu0.txt') && read(root, 'a.txt') === 'A1'; });
    await sync.idle();
    // Drive's old state on the PC …
    assert.equal(read(root, 'a.txt'), 'A1');
    assert.equal(read(root, 'b.txt'), 'B1');
    assert.equal(read(root, 'c.txt'), 'C1');
    for (let i = 0; i < 12; i++) assert.equal(exists(root, `neu${i}.txt`), false);
    // … the PC's unsynced change next to it
    const copy = fs.readdirSync(root).find((x) => /^b \(Konflikt Desktop-PC .*\)\.txt$/.test(x));
    assert.ok(copy, fs.readdirSync(root).join(', '));
    assert.equal(read(root, copy), 'B3 lokal');
    assert.ok(childNamed(srv, P.id, copy));
    const st = sync.status().folders[0];
    assert.equal(st.confirm, null);
    assert.equal(st.state, 'idle');

    // "Rückgängig": back to `before`
    await svc.timeTravel(P.id, r.before);
    await until(async () => { await sync.idle(); return exists(root, 'neu0.txt'); });
    await sync.idle();
    assert.equal(read(root, 'a.txt'), 'A2');
    assert.equal(read(root, 'b.txt'), 'B2');
    assert.equal(read(root, 'neu11.txt'), 'N11');
  });

  it('"Nur sichern": the PC is not written, Drive gets the PC\'s state back (the old one stays a version)', async () => {
    const env = await setup();
    const { srv, svc } = env;
    const sync = syncOf(env);
    const root = tmpDir('pc-tt-backup-');
    write(root, 'x.txt', 'X1');
    write(root, 'y.txt', 'Y1');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const D = sync._folder(folder.id).target.nodeId;
    await sleep(5);
    const T = Date.now();
    await sleep(5);
    write(root, 'x.txt', 'X2');
    write(root, 'z.txt', 'Z1');
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(childNamed(srv, D, 'x.txt').sha256, sha('X2'));
    assert.deepEqual((await sync.linkedFolders(D)).map((l) => [l.mode, l.relation]), [['backup', 'same']]);

    const before = commits(srv).length;
    const r = await svc.timeTravel(D, T);
    assert.equal(r.reverted, 1);
    assert.equal(r.trashed, 1);
    await until(async () => { await sync.idle(); return commits(srv).length >= before + 2; });
    await sync.idle();
    // the PC as it was
    assert.equal(read(root, 'x.txt'), 'X2');
    assert.equal(read(root, 'z.txt'), 'Z1');
    // Drive: the PC's state again, the time travel's file an older version
    const x = childNamed(srv, D, 'x.txt');
    assert.equal(x.sha256, sha('X2'));
    assert.ok((srv.state.versions.get(x.id) || []).some((v) => srv.state.media.get(v.mediaId).data.toString() === 'X1'));
    assert.ok(childNamed(srv, D, 'z.txt'));
    assert.equal(childNamed(srv, D, 'y.txt').sha256, sha('Y1'));
    assert.equal(sync._states.get(folder.id).reassert, false);
    // nothing more goes up
    const n = commits(srv).length;
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(commits(srv).length, n);
  });

  it('plan(): reassert uploads a file changed only in Drive (backup)', () => {
    const base = { 'a.txt': { path: 'a.txt', dir: false, size: 2, mtime: 5, sha256: 's1', nodeId: 7, rev: 1 } };
    const local = new Map([['a.txt', { path: 'a.txt', dir: false, size: 2, mtime: 5 }]]);
    const remote = new Map([['a.txt', { path: 'a.txt', dir: false, size: 2, nodeId: 7, rev: 2, sha256: 's0' }]]);
    assert.deepEqual(S.plan({ mode: 'backup', base, local, remote }).actions.map((a) => a.op), ['record']);
    const p = S.plan({ mode: 'backup', base, local, remote, reassert: true }).actions;
    assert.deepEqual(p, [{ op: 'upload', key: 'a.txt', path: 'a.txt', nodeId: 7, baseRev: 2, sha256: 's0', reassert: true }]);
    assert.deepEqual(S.plan({ mode: 'sync', base, local, remote, reassert: true }).actions.map((a) => a.op), ['download']);
  });

  it('keeps the flag in the state file', () => {
    const st = DriveSync.parseState({ v: 1, scope: 's', rootId: 4, cursor: 1, tree: {}, base: {}, pending: {}, reassert: true });
    assert.equal(st.reassert, true);
    assert.equal(DriveSync.parseState({ v: 1, rootId: 4 }).reassert, false);
  });
});

// ── IPC ────────────────────────────────────────────────────

describe('drive IPC: Drive 1.7 channels', () => {
  it('checks arguments, adds the folders of this PC to the preview, and the bridge has the channels', async () => {
    const handlers = {};
    const calls = [];
    const rec = (name) => async (...a) => { calls.push([name, ...a]); return { ok: true, mime: 'image/jpeg', data: Buffer.from('x') }; };
    const svc = Object.assign(new EventEmitter(), {
      status: () => ({}),
      timeTravelPreview: rec('ttp'), timeTravel: rec('tt'), photos: rec('photos'), photoMonths: rec('months'), memories: rec('memories'),
      previewOf: rec('previewOf'), albums: rec('albums'), album: rec('album'), createAlbum: rec('create'), updateAlbum: rec('update'),
      deleteAlbum: rec('delete'), albumItems: rec('items'), storage: rec('storage'), pruneVersions: rec('prune'),
    });
    const sync = Object.assign(new EventEmitter(), { linkedFolders: async (id) => [{ id: 'f1', mode: 'sync', relation: 'same', nodeId: id }] });
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, sync, getMainWindow: () => null, log });
    const pv = await handlers['drive:timetravel:preview'](null, { id: 5, at: '2026-10-01T10:00:00Z' });
    assert.deepEqual(pv.linked, [{ id: 'f1', mode: 'sync', relation: 'same', nodeId: 5 }]);
    const bad = [
      ['drive:timetravel:preview', { id: 5, at: 'gestern' }], ['drive:timetravel', { id: 0, at: 1 }], ['drive:photos', { area: '../x' }],
      ['drive:photos', { limit: 1000 }], ['drive:photos', { before: '<x>' }], ['drive:photos:memories', { date: '28.10.2026' }],
      ['drive:album', { id: '../1' }], ['drive:album:create', { name: '' }], ['drive:album:update', { id: 3 }], ['drive:album:update', { id: 3, frame: 'ja' }],
      ['drive:album:items', { id: 3, ids: [] }], ['drive:album:items', { id: 3, ids: ['x'] }], ['drive:storage:prune', { areaId: 'mine:2', keep: -1 }],
      ['drive:preview:node', { id: 'x' }],
    ];
    for (const [ch, a] of bad) assert.equal((await handlers[ch](null, a)).code, 'invalid', `${ch} ${JSON.stringify(a)}`);
    await handlers['drive:timetravel'](null, { id: 5, at: 1760000000000 });
    await handlers['drive:photos'](null, { area: 'mine:2', before: '2026-10-01T00:00:00.000Z', limit: 50 });
    await handlers['drive:photos:memories'](null, { date: '2026-10-28' });
    await handlers['drive:album:update'](null, { id: 3, frame: true });
    await handlers['drive:album:items'](null, { id: 3, ids: [1, 2], remove: true });
    await handlers['drive:storage'](null, { all: true });
    const pr = await handlers['drive:preview:node'](null, { id: 9, large: true });
    assert.ok(pr.data instanceof Uint8Array);
    assert.deepEqual(calls.slice(1).map((c) => c.slice(0, 3)), [
      ['tt', 5, 1760000000000], ['photos', { area: 'mine:2', before: '2026-10-01T00:00:00.000Z', limit: 50 }], ['memories', '2026-10-28'],
      ['update', 3, { frame: true }], ['items', 3, [1, 2]], ['storage', { all: true }], ['previewOf', 9, { large: true }],
    ]);

    const invoked = [];
    const bridge = createBridgeApi({ invoke: (ch, a) => { invoked.push([ch, a]); return Promise.resolve(); }, on() {}, removeListener() {} }, { t: () => '', setLocale() {}, getLocale: () => 'de', onLocaleChange() {}, getSupportedLocales: () => [] });
    const d = bridge.drive;
    d.timeTravelPreview(5, 'x'); d.timeTravel(5, 'y'); d.photos({ limit: 5 }); d.photoMonths(); d.memories(); d.previewOf(4); d.albums(); d.album(3, { before: 'c' });
    d.createAlbum('A'); d.updateAlbum(3, { name: 'B' }); d.deleteAlbum(3); d.addToAlbum(3, [1]); d.removeFromAlbum(3, [1]); d.storage(true); d.pruneVersions('mine:2', 3);
    assert.deepEqual(invoked.map((x) => x[0]), ['drive:timetravel:preview', 'drive:timetravel', 'drive:photos', 'drive:photos:months', 'drive:photos:memories', 'drive:preview:node', 'drive:albums', 'drive:album',
      'drive:album:create', 'drive:album:update', 'drive:album:delete', 'drive:album:items', 'drive:album:items', 'drive:storage', 'drive:storage:prune']);
    assert.deepEqual(invoked[12][1], { id: 3, ids: [1], remove: true });
    for (const ch of invoked.map((x) => x[0])) assert.ok(handlers[ch], ch);
  });
});
