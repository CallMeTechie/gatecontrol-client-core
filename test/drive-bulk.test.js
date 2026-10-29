'use strict';

// Drive 1.12 in the Windows Pro app (core): the selection of many files and folders — what a job would do (conflicts,
// what cannot go), the job (move, copy, into the trash) as a row of the transfer list that runs on in the server, its
// progress, "Abbrechen", "Rückgängig", the jobs still running after a restart; an older Drive (move and trash as a loop
// of single calls), vault folders (never across the border, moving inside one here with the decrypted names), the ZIP of
// a selection, one link for several files, the IPC checks and "Ordner sichern" seeing copies as new files. Against the
// fake Drive server (fixtures/drive-server.js) with and without 'bulk' / 'zip' / 'multiLink'.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { PassThrough } = require('node:stream');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
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

async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0xa5));
  return { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]), decrypt: (b) => x(Buffer.from(b).subarray(6)) };
}

async function service(srv, { savePath = null, hosts = null } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('db-tmp-');
  const dialogs = [];
  const svc = new DriveService({
    apiClient, api, log, store: createMemoryStore(), protect: fakeProtect(), deviceName: () => 'Desktop-PC', tempDir: () => tmp,
    timing: { progressMs: 0, opPollMs: 20 }, getMainWindow: () => null, getLang: () => 'de', consent: null,
    ...(hosts ? { allowedHosts: () => hosts } : {}),
    dialog: { showSaveDialog: async (o) => { dialogs.push(o); return savePath ? { canceled: false, filePath: savePath } : { canceled: true }; } },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const events = [];
  for (const ev of ['op', 'changed', 'transfers']) svc.on(ev, (p) => events.push({ ev, p }));
  return { svc, api, tmp, events, dialogs };
}

async function setup(features, opts = {}) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  return { srv, ...(await service(srv, opts)) };
}

const BULK = ['devices', 'emptyFiles', 'vault', 'vaultsApart', 'bulk', 'zip', 'multiLink', 'copyServer'];
const OLD = ['devices', 'emptyFiles', 'vault', 'vaultsApart'];
const byName = (srv, name, parentId) => [...srv.state.nodes.values()].find((n) => n.name === name && !n.deleted && (parentId === undefined || n.parentId === parentId));
const opRows = (svc) => svc.transfers().filter((r) => r.dir === 'op');

// ── utils ──────────────────────────────────────────────────

describe('Drive 1.12: answers and requests (utils/drive.js)', () => {
  it('normalizeOp: known fields, counts, results, undo time; undo jobs; junk dropped', () => {
    const op = drive.normalizeOp({ op: {
      id: 'op123', kind: 'copy', state: 'running', total: 128, done: 58, bytesTotal: 3e9, bytesDone: 1.4e9, targetId: '7',
      targetPath: 'Meine Dateien › Familie', results: { done: [1, 2], skipped: 1, failed: [{ id: 5, reason: 'forbidden' }, { id: 'x' }] },
      undoUntil: '2026-10-29T10:00:00Z', extra: 'x', name: 'Urlaub\u0007 2026',
    } });
    assert.equal(op.id, 'op123');
    assert.equal(op.kind, 'copy');
    assert.equal(op.done, 58);
    assert.equal(op.targetId, 7);
    assert.deepEqual(op.results, { done: 2, skipped: 1, failed: [{ id: 5, reason: 'forbidden' }], failedCount: 1, resultIds: [] });
    assert.equal(op.undoUntil, Date.parse('2026-10-29T10:00:00Z'));
    assert.equal(op.name, 'Urlaub  2026');
    assert.equal(op.extra, undefined);
    assert.equal(drive.normalizeOp({ id: 9, kind: 'undo', state: 'weird', undoOf: 'op1' }).state, 'running');
    assert.equal(drive.normalizeOp({ id: 9, kind: 'undo', undoOf: 'op1' }).kind, 'undo');
    assert.equal(drive.normalizeOp({ id: '../x' }), null);
    assert.equal(drive.normalizeOp(null), null);
  });

  it('normalizeOpCheck, opBody, idList, normalizeZip, multiLinkBody', () => {
    const c = drive.normalizeOpCheck({ files: 3, folders: 1, bytes: 10, conflicts: [{ id: 4, name: 'a.pdf', existing: { id: 9, size: 5, mtime: 1760000000000 }, same: true }, { id: 0, name: 'x' }], blocked: [{ id: 5, reason: 'into_itself' }, { id: 6, reason: 'BAD reason' }] });
    assert.deepEqual(c.conflicts.map((x) => [x.id, x.existing.id, x.same]), [[4, 9, true]]);
    assert.deepEqual(c.blocked, [{ id: 5, reason: 'into_itself' }, { id: 6, reason: 'failed' }]);
    assert.deepEqual(drive.opBody({ op: 'move', ids: [1, 2, 2], target: 3, onConflict: 'skip' }), { op: 'move', ids: [1, 2], target: 3, onConflict: 'skip' });
    assert.equal(drive.opBody({ op: 'move', ids: [1] }), null, 'a move needs its target');
    assert.equal(drive.opBody({ op: 'copy', ids: [1, 'x'], target: 3 }), null);
    assert.equal(drive.opBody({ op: 'delete', ids: [1] }), null);
    assert.equal(drive.opBody({ op: 'trash', ids: [1], onConflict: 'merge' }), null);
    assert.deepEqual(drive.opBody({ op: 'trash', ids: [1], target: 9 }), { op: 'trash', ids: [1] });
    assert.equal(drive.idList(new Array(10001).fill(1)), null);
    assert.equal(drive.idList([]), null);
    assert.deepEqual(drive.normalizeZip({ url: '/api/v1/client/plugins/gatecontrol-drive/media/abc', name: 'Fotos', expiresAt: 5 }), { url: '/api/v1/client/plugins/gatecontrol-drive/media/abc', name: 'Fotos.zip', expiresAt: 5, files: null, skipped: [] });
    assert.equal(drive.normalizeZip({ url: 'https://gc.example.com/s/tok', name: 'a/b.zip' }).name, 'a_b.zip');
    assert.equal(drive.normalizeZip({ url: '//evil.example/x' }), null);
    assert.equal(drive.normalizeZip({ url: 'javascript:alert(1)' }), null);
    assert.deepEqual(drive.multiLinkBody({ ids: [1, 2], mode: 'download', expires: '7d', pin: '1234' }), { nodeIds: [1, 2], mode: 'download', expires: '7d', pin: '1234' });
    assert.equal(drive.multiLinkBody({ ids: [1, 2], mode: 'upload', expires: '7d' }), null);
    assert.equal(drive.multiLinkBody({ ids: [1], mode: 'view', expires: '7d', pin: '12' }), null);
  });
});

// ── jobs on a Drive with 'bulk' ────────────────────────────

describe("Drive 1.12 'bulk': jobs of the server", () => {
  it('check: conflicts by name (same content), blocked into itself / read only — changes nothing', async () => {
    const { srv, svc } = await setup(BULK);
    const ziel = srv.mutate.dir(1, 'Ziel');
    srv.mutate.file(ziel.id, 'Brief.pdf', '%PDF-1.4 brief');
    srv.mutate.file(ziel.id, 'Foto.jpg', 'andere bytes');
    const before = srv.state.log.length;
    const c = await svc.opsCheck({ op: 'move', ids: [12, 11, 10, ziel.id], target: ziel.id });
    assert.equal(c.ok, true);
    assert.equal(c.bulk, true);
    assert.equal(c.local, false);
    assert.deepEqual(c.conflicts.map((x) => [x.name, x.same]).sort(), [['Brief.pdf', true], ['Foto.jpg', false]]);
    assert.deepEqual(c.blocked, [{ id: ziel.id, reason: 'into_itself' }]);
    assert.equal(c.files, 3, 'Dokumente counts its Brief.pdf');
    assert.equal(c.folders, 1);
    assert.equal(srv.state.log.length, before, 'nothing changed');
    const ro = await svc.opsCheck({ op: 'trash', ids: [3] });
    assert.deepEqual(ro.blocked, [{ id: 3, reason: 'forbidden' }]);
  });

  it('move with "Als neue Version speichern": done at once, a row, the event op with Rückgängig — undo puts it back', async () => {
    const { srv, svc, events } = await setup(BULK);
    const ziel = srv.mutate.dir(1, 'Ziel');
    const old = srv.mutate.file(ziel.id, 'Foto.jpg', 'alt');
    const r = await svc.opsStart({ op: 'move', ids: [11, 13], target: ziel.id, onConflict: 'version', meta: { name: 'Foto.jpg', count: 2, target: 'Ziel', parents: [1] } });
    assert.equal(r.ok, true);
    assert.equal(r.op.dir, 'op');
    const done = await until(() => events.find((e) => e.ev === 'op' && e.p.state === 'done'));
    assert.equal(done.p.kind, 'move');
    assert.equal(done.p.count, 2);
    assert.equal(done.p.targetName, 'Ziel');
    assert.equal(done.p.undoable, true);
    assert.deepEqual(done.p.results, { done: 2, skipped: 0, failed: [], failedCount: 0, resultIds: [13] });
    assert.equal(srv.state.nodes.get(13).parentId, ziel.id);
    assert.equal(srv.state.nodes.get(11).deleted, true, 'became a new version of the file there');
    assert.equal(srv.state.nodes.get(old.id).rev, 2);
    assert.deepEqual(srv.state.opCalls[0], { op: 'move', ids: [11, 13], target: ziel.id, onConflict: 'version' });
    const changed = events.filter((e) => e.ev === 'changed').map((e) => e.p.folderId);
    assert.ok(changed.includes(ziel.id) && changed.includes(1));
    // Rückgängig
    const u = await svc.opUndo(done.p.opId);
    assert.equal(u.ok, true);
    await until(() => events.find((e) => e.ev === 'op' && e.p.undo && e.p.state === 'done'));
    assert.equal(srv.state.nodes.get(13).parentId, 1);
    assert.equal(srv.state.nodes.get(11).deleted, false);
    const row = opRows(svc).find((x) => x.opId === done.p.opId);
    assert.equal(row.undoable, false);
    assert.equal(row.undone, true);
  });

  it('copy: "Beide behalten", folders of the same name merged; the copies are new files in the change log', async () => {
    const { srv, svc, events } = await setup(BULK);
    const ziel = srv.mutate.dir(1, 'Ziel');
    const zd = srv.mutate.dir(ziel.id, 'Dokumente');
    srv.mutate.file(zd.id, 'Brief.pdf', 'anders');
    srv.mutate.file(ziel.id, 'Foto.jpg', 'andere bytes');
    const seq = srv.state.seq;
    await svc.opsStart({ op: 'copy', ids: [10, 11], target: ziel.id, onConflict: 'rename', meta: { name: 'Dokumente', count: 2, target: 'Ziel' } });
    await until(() => events.find((e) => e.ev === 'op' && e.p.state === 'done'));
    assert.ok(byName(srv, 'Foto (2).jpg', ziel.id));
    assert.ok(byName(srv, 'Brief (2).pdf', zd.id), 'merged into the folder there');
    assert.equal(srv.state.nodes.get(11).parentId, 1, 'the original stays');
    const created = srv.state.log.filter((c) => c.seq > seq && c.op === 'create').length;
    assert.equal(created, 2);
  });

  it('copying needs copyServer (GateControl copies the media); the job carries items, label and the new nodes', async () => {
    const noCopy = await setup(BULK.filter((f) => f !== 'copyServer'));
    await assert.rejects(noCopy.svc.opsCheck({ op: 'copy', ids: [11], target: 10 }), (e) => e.code === 'unsupported');
    const { srv, svc, events } = await setup(BULK);
    await svc.opsStart({ op: 'copy', ids: [11, 13], target: 10 });
    const e = await until(() => events.find((x) => x.ev === 'op'));
    assert.equal(e.p.count, 2, 'items of the job');
    assert.equal(e.p.name, 'Foto.jpg', 'its label');
    assert.equal(e.p.results.resultIds.length, 2);
    assert.ok(e.p.results.resultIds.every((id) => srv.state.nodes.get(id).parentId === 10));
    // a job limit of the person
    srv.opAsync = true;
    srv.opsMax = 1;
    await svc.opsStart({ op: 'trash', ids: [12] });
    await assert.rejects(svc.opsStart({ op: 'trash', ids: [13] }), (x) => x.code === 'job_limit');
  });

  it('a large job runs on: a row with progress (asked again), "Abbrechen" ends it with what is done', async () => {
    const { srv, svc, events } = await setup(BULK);
    srv.opAsync = true;
    const ziel = srv.mutate.dir(1, 'Ziel');
    const r = await svc.opsStart({ op: 'copy', ids: [10, 11], target: ziel.id, meta: { name: 'Dokumente', count: 2, target: 'Ziel' } });
    assert.equal(r.op.state, 'running');
    const opId = r.op.opId;
    srv.progressOp(opId, 1, 14);
    await until(() => opRows(svc).find((x) => x.opId === opId && x.done === 1 && x.bytesDone === 14));
    assert.equal(opRows(svc)[0].total, 2, 'files of the job');
    const c = await svc.opCancel(opId);
    assert.equal(c.ok, true);
    const ended = await until(() => events.find((e) => e.ev === 'op' && e.p.opId === opId));
    assert.equal(ended.p.state, 'cancelled');
    assert.equal(ended.p.undoable, false);
    assert.equal(svc.clearTransfers().transfers.length, 0, 'an ended job is cleared like any row');
  });

  it('after a restart the person\'s running jobs show again; the live event op moves them on', async () => {
    const { srv, svc } = await setup(BULK);
    srv.opAsync = true;
    await svc.opsStart({ op: 'trash', ids: [13], meta: { name: 'setup.exe', count: 1 } });
    svc.stop();
    const again = await service(srv);
    const row = await until(() => opRows(again.svc).find((x) => x.state === 'running'));
    assert.equal(row.kind, 'trash');
    srv.finishOps();
    again.svc.ops.onEvent({ op: { id: row.opId, state: 'done', kind: 'trash', total: 1, done: 1, results: { done: 1, skipped: 0, failed: [] }, undoUntil: new Date(Date.now() + 60000).toISOString() } });
    const ev = await until(() => again.events.find((e) => e.ev === 'op'));
    assert.equal(ev.p.state, 'done');
    assert.equal(ev.p.undoable, true);
    assert.equal(srv.state.nodes.get(13).deleted, true);
  });

  it('a failed job: the row says why; 404 of a job that is gone ends it', async () => {
    const { srv, svc, events } = await setup(BULK);
    srv.opAsync = true;
    const a = await svc.opsStart({ op: 'trash', ids: [13] });
    srv.failOp(a.op.opId, 'quota');
    const e1 = await until(() => events.find((e) => e.ev === 'op' && e.p.opId === a.op.opId));
    assert.equal(e1.p.state, 'failed');
    const b = await svc.opsStart({ op: 'trash', ids: [11] });
    srv.state.ops.delete(b.op.opId);
    const e2 = await until(() => events.find((e) => e.ev === 'op' && e.p.opId === b.op.opId));
    assert.equal(e2.p.state, 'failed');
    assert.equal(e2.p.code, 'not_found');
  });
});

// ── an older Drive (no 'bulk') ─────────────────────────────

describe('Drive 1.12 on an older Drive: a loop of single calls', () => {
  it('check finds conflicts, "into itself" and "already there" here; copy and undo are not offered', async () => {
    const { srv, svc } = await setup(OLD);
    const ziel = srv.mutate.dir(10, 'Ziel');
    srv.mutate.file(ziel.id, 'Foto.jpg', 'x');
    const c = await svc.opsCheck({ op: 'move', ids: [11, 10, 12], target: ziel.id });
    assert.equal(c.bulk, false);
    assert.equal(c.local, true);
    assert.deepEqual(c.conflicts.map((x) => x.name), ['Foto.jpg']);
    assert.deepEqual(c.blocked, [{ id: 10, reason: 'into_itself' }]);
    const c2 = await svc.opsCheck({ op: 'move', ids: [12], target: 10 });
    assert.deepEqual(c2.blocked, [{ id: 12, reason: 'same_folder' }]);
    assert.equal(srv.state.requests.some((r) => r.path.endsWith('/ops/check')), false);
    await assert.rejects(svc.opsCheck({ op: 'copy', ids: [11], target: ziel.id }), (e) => e.code === 'unsupported');
    await assert.rejects(svc.opsStart({ op: 'copy', ids: [11], target: ziel.id }), (e) => e.code === 'unsupported');
    await assert.rejects(svc.opUndo('op1'), (e) => e.code === 'unsupported');
  });

  it('move: "Beide behalten" gives a free name, "Überspringen" leaves it; trash one by one', async () => {
    const { srv, svc, events } = await setup(OLD);
    const ziel = srv.mutate.dir(1, 'Ziel');
    srv.mutate.file(ziel.id, 'Foto.jpg', 'x');
    await svc.opsStart({ op: 'move', ids: [11, 13], target: ziel.id, onConflict: 'rename', meta: { count: 2, target: 'Ziel' } });
    const e = await until(() => events.find((x) => x.ev === 'op'));
    assert.equal(e.p.state, 'done');
    assert.equal(e.p.local, true);
    assert.equal(e.p.undoable, false);
    assert.equal(srv.state.nodes.get(11).name, 'Foto (2).jpg');
    assert.equal(srv.state.nodes.get(11).parentId, ziel.id);
    assert.equal(srv.state.nodes.get(13).parentId, ziel.id);
    const b = srv.mutate.file(1, 'Foto (2).jpg', 'y');
    await svc.opsStart({ op: 'move', ids: [b.id], target: ziel.id, onConflict: 'skip' });
    const e2 = await until(() => events.filter((x) => x.ev === 'op')[1]);
    assert.deepEqual(e2.p.results, { done: 0, skipped: 1, failed: [], failedCount: 0, resultIds: [] });
    assert.equal(srv.state.nodes.get(b.id).parentId, 1);
    await svc.opsStart({ op: 'trash', ids: [12, b.id] });
    await until(() => events.filter((x) => x.ev === 'op')[2]);
    assert.equal(srv.state.nodes.get(12).deleted, true);
    assert.equal(srv.state.nodes.get(b.id).deleted, true);
    assert.equal(srv.state.requests.filter((r) => r.method === 'DELETE' && /\/nodes\/\d+$/.test(r.path)).length, 2);
  });

  it('a read-only node fails, the rest goes; the report names it', async () => {
    const { srv, svc, events } = await setup(OLD);
    const lena = srv.mutate.file(3, 'Kind.txt', 'k');
    await svc.opsStart({ op: 'trash', ids: [lena.id, 13] });
    const e = await until(() => events.find((x) => x.ev === 'op'));
    assert.equal(e.p.state, 'done');
    assert.deepEqual(e.p.results.failed, [{ id: lena.id, reason: 'forbidden' }]);
    assert.equal(e.p.results.done, 1);
  });
});

// ── vault folders ──────────────────────────────────────────

describe('Drive 1.12 and vault folders', () => {
  async function vaultSetup(features) {
    const s = await setup(features);
    await s.svc.vaultLockSettings({ hello: false });
    const made = await s.svc.vaultCreate(null, 'Geheim', { areaId: 'mine:2' });
    const a = (await s.svc.mkdir(made.node.id, 'A')).node;
    const b = (await s.svc.mkdir(made.node.id, 'B')).node;
    const x = (await s.svc.mkdir(a.id, 'X')).node;
    await s.svc.mkdir(b.id, 'X');
    return { ...s, vault: made, a, b, x };
  }

  for (const [label, features] of [['with bulk', BULK], ['an older Drive', OLD]]) {
    it(`${label}: moving inside the same vault runs here, conflicts by the decrypted names, "Beide behalten" encrypts a free name`, async () => {
      const { srv, svc, events, b, x } = await vaultSetup(features);
      const c = await svc.opsCheck({ op: 'move', ids: [x.id], target: b.id });
      assert.equal(c.local, true);
      assert.deepEqual(c.conflicts.map((k) => k.name), ['X']);
      await svc.opsStart({ op: 'move', ids: [x.id], target: b.id, onConflict: 'rename' });
      await until(() => events.find((e) => e.ev === 'op'));
      assert.equal(srv.state.nodes.get(x.id).parentId, b.id);
      const f = await svc.folder(b.id);
      assert.deepEqual(f.items.map((n) => n.name).sort(), ['X', 'X (2)']);
      assert.equal(srv.state.opCalls.length, 0, 'never a job of the server for a vault move');
    });
  }

  it('never across the border: move out / in and any copy are blocked as encrypted', async () => {
    const { svc, x } = await vaultSetup(BULK);
    const out = await svc.opsCheck({ op: 'move', ids: [x.id], target: 10 });
    assert.deepEqual(out.blocked, [{ id: x.id, reason: 'encrypted' }]);
    const into = await svc.opsCheck({ op: 'move', ids: [12], target: x.id });
    assert.deepEqual(into.blocked, [{ id: 12, reason: 'encrypted' }]);
    const copy = await svc.opsCheck({ op: 'copy', ids: [x.id], target: x.id });
    assert.equal(copy.blocked[0].reason, 'encrypted');
    await assert.rejects(svc.opsStart({ op: 'move', ids: [12], target: x.id }), (e) => e.code === 'encrypted');
  });

  it('into the trash inside a vault: a job of the server with Rückgängig', async () => {
    const { srv, svc, events, a } = await vaultSetup(BULK);
    await svc.opsStart({ op: 'trash', ids: [a.id] });
    const e = await until(() => events.find((x) => x.ev === 'op'));
    assert.equal(e.p.undoable, true);
    assert.equal(srv.state.nodes.get(a.id).deleted, true);
    await svc.opUndo(e.p.opId);
    await until(() => !srv.state.nodes.get(a.id).deleted);
  });
});

// ── ZIP, one link for many ─────────────────────────────────

describe("Drive 1.12 'zip' and 'multiLink'", () => {
  it('ZIP: "Speichern unter …" first, then the ZIP streams into that path (a row of the list)', async () => {
    const dir = tmpDir('db-zip-');
    const dest = path.join(dir, 'Auswahl.zip');
    const { srv, svc, dialogs } = await setup([...BULK, 'zipMixed'], { savePath: dest });
    const r = await svc.zip([10, 11], { name: 'Auswahl' });
    assert.equal(r.ok, true);
    assert.equal(dialogs[0].defaultPath, 'Auswahl.zip');
    assert.deepEqual(dialogs[0].filters[0].extensions, ['zip']);
    const text = fs.readFileSync(dest, 'utf8');
    assert.ok(text.includes('Dokumente/Brief.pdf') && text.includes('Foto.jpg'));
    assert.deepEqual(srv.state.zips[0].ids, [10, 11]);
    const row = svc.transfers().find((x) => x.dir === 'down');
    assert.equal(row.state, 'done');
    assert.equal(row.path, dest);
    assert.deepEqual(fs.readdirSync(dir), ['Auswahl.zip'], 'no .part left');
  });

  it('ZIP: cancelled dialog asks Drive nothing; a vault is refused; an older Drive cannot', async () => {
    const { srv, svc } = await setup(BULK);
    const r = await svc.zip([11]);
    assert.equal(r.cancelled, true);
    assert.equal(srv.state.zips.length, 0);
    const old = await setup(OLD, { savePath: path.join(tmpDir('db-z2-'), 'x.zip') });
    await assert.rejects(old.svc.zip([11]), (e) => e.code === 'unsupported');
  });

  it('ZIP at GateControl\'s bearer address: fetched without the device token; plain http elsewhere refused', async () => {
    const dest = path.join(tmpDir('db-z3-'), 'x.zip');
    const { srv, svc, api } = await setup(BULK, { savePath: dest });
    srv.zipUrl = () => 'http://evil.example.org/zip/1';
    await assert.rejects(svc.zip([11]), (e) => e.code === 'invalid');
    assert.equal(fs.existsSync(dest), false);
    srv.zipUrl = (m) => `${srv.url}/s/${m}/zip`;
    assert.equal((await svc.zip([11], { name: 'Fotos' })).ok, true);
    assert.ok(fs.readFileSync(dest, 'utf8').includes('Foto.jpg'));
    assert.deepEqual(srv.state.zipGets, [{ token: null }], 'no device token on the bearer link');
    assert.equal(srv.state.zips[0].name, null);
    assert.equal(srv.state.zips[1].name, 'Fotos');
    await assert.rejects(api.downloadZip('/x/../y', new PassThrough()), (e) => e.code === 'invalid');
  });

  it('ZIP limits without zipMixed: one folder or ≤ 20 files (400 mixed), with zipMixed a mixed selection', async () => {
    const dest = path.join(tmpDir('db-z5-'), 'x.zip');
    const { svc } = await setup(BULK, { savePath: dest });
    await assert.rejects(svc.zip([10, 11]), (e) => e.code === 'invalid' && e.body && e.body.reason === 'mixed');
    const mixed = await setup([...BULK, 'zipMixed'], { savePath: dest });
    assert.equal((await mixed.svc.zip([10, 11])).ok, true);
  });

  it('one link for several files; with a folder: invalid (mixed); an older Drive cannot', async () => {
    const { srv, svc } = await setup(BULK);
    const two = srv.mutate.file(1, 'Zwei.txt', '2');
    const r = await svc.createLink({ ids: [11, two.id], mode: 'download', expires: '7d', pin: '1234' });
    assert.equal(r.ok, true);
    assert.equal(r.link.kind, 'files');
    assert.deepEqual(srv.state.links[0].nodeIds, [11, two.id]);
    await assert.rejects(svc.createLink({ ids: [10, 11], mode: 'view', expires: '7d' }), (e) => e.code === 'invalid' && e.body && e.body.reason === 'mixed');
    const old = await setup(OLD);
    await assert.rejects(old.svc.createLink({ ids: [11, 13], mode: 'view', expires: '7d' }), (e) => e.code === 'unsupported');
    // a single link as before
    assert.equal((await old.svc.createLink({ nodeId: 11, mode: 'view', expires: '7d' })).ok, true);
  });
});

// ── IPC ────────────────────────────────────────────────────

describe('Drive 1.12 IPC', () => {
  it('checks every argument; failures come back with the plugin\'s reason', async () => {
    const { srv, svc } = await setup(BULK);
    const h = {};
    const sent = [];
    registerDriveHandlers((ch, fn) => { h[ch] = fn; }, { drive: svc, getMainWindow: () => ({ isDestroyed: () => false, webContents: { send: (c, p) => sent.push([c, p]) } }), log });
    const bad = [
      ['drive:ops:check', { op: 'delete', ids: [1] }],
      ['drive:ops:check', { op: 'move', ids: [1] }],
      ['drive:ops:check', { op: 'trash', ids: [] }],
      ['drive:ops:check', { op: 'trash', ids: [1, 'x'] }],
      ['drive:ops:start', { op: 'copy', ids: [1], target: 2, onConflict: 'merge' }],
      ['drive:ops:start', { op: 'trash', ids: [1], meta: { parents: ['x'] } }],
      ['drive:ops:start', { op: 'trash', ids: [1], meta: { name: 5 } }],
      ['drive:ops:cancel', { id: '../1' }],
      ['drive:ops:undo', { id: null }],
      ['drive:zip', { ids: [1], name: 'x'.repeat(300) }],
      ['drive:link:create', { ids: [1, 2], mode: 'upload', expires: '7d' }],
      ['drive:link:create', { ids: [], mode: 'view', expires: '7d' }],
    ];
    for (const [ch, arg] of bad) assert.equal((await h[ch](null, arg)).code, 'invalid', `${ch} ${JSON.stringify(arg)}`);
    const c = await h['drive:ops:check'](null, { op: 'trash', ids: [13] });
    assert.equal(c.ok, true);
    const s = await h['drive:ops:start'](null, { op: 'trash', ids: [13], meta: { name: 'setup.exe', count: 1, parents: [1] } });
    assert.equal(s.ok, true);
    await until(() => sent.find(([ch]) => ch === 'drive:op'));
    const mixed = await h['drive:link:create'](null, { ids: [10, 11], mode: 'view', expires: '7d' });
    assert.equal(mixed.ok, false);
    assert.equal(mixed.reason, 'mixed');
    assert.equal(srv.state.nodes.get(13).deleted, true);
  });
});

// ── "Ordner sichern" ───────────────────────────────────────

describe("Drive 1.12: 'Ordner sichern' sees jobs like any change", () => {
  it('a synced folder: copies come down as new files, moved ones move on the PC, nothing asks', async () => {
    const { srv, svc, api, events } = await setup(BULK);
    const sync = new DriveSync({
      drive: svc, api, store: createMemoryStore(), dir: tmpDir('db-state-'), log, hostname: () => 'Desktop-PC', getDeviceKey: () => 'ab12cd34',
      trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); }, timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 }, readPdfText: async () => null,
    });
    sync.start();
    cleanup.push(async () => { sync.stop(); await sync.idle(); });
    const pc = tmpDir('db-pc-');
    const f = await sync.addFolder({ path: pc, mode: 'sync', targetId: 1 });
    sync.sync(f.folder.id, { full: true });
    await sync.idle();
    assert.ok(fs.existsSync(path.join(pc, 'Foto.jpg')));
    await svc.opsStart({ op: 'copy', ids: [12], target: 1, meta: { count: 1 } });
    await svc.opsStart({ op: 'move', ids: [11], target: 10, meta: { count: 1 } });
    await until(() => events.filter((e) => e.ev === 'op').length === 2);
    sync.sync(f.folder.id, { full: true });
    await sync.idle();
    assert.equal(fs.readFileSync(path.join(pc, 'Brief.pdf'), 'utf8'), '%PDF-1.4 brief');
    assert.ok(fs.existsSync(path.join(pc, 'Dokumente', 'Foto.jpg')));
    assert.equal(fs.existsSync(path.join(pc, 'Foto.jpg')), false);
    const st = sync.status().folders.find((x) => x.id === f.folder.id);
    assert.equal(st.error || null, null);
    assert.notEqual(st.state, 'confirm');
  });
});
