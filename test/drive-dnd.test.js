'use strict';

// Drag & drop from the Explorer into Drive (Windows app): files and whole folders dropped (`dropped`: a folder there
// already takes the files, empty folders made, Thumbs.db / desktop.ini / links left out, a folder reached twice only
// once), "Abbrechen" of one upload, of a folder or of all (queued, asking, on its way — the rest goes on), the abort
// of a media upload (GateDropApi `signal`), the IPC and the bridge (paths only from webUtils, turns of 200) — against
// the fake Drive server.

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

const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createBridgeApi } = require('../src/preload/bridge');
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

function write(root, rel, content) {
  const p = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}

async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 15));
  }
}

const childNamed = (srv, parentId, name) => [...srv.state.nodes.values()].find((n) => n.parentId === parentId && !n.deleted && n.name === name);
const childrenOf = (srv, parentId) => [...srv.state.nodes.values()].filter((n) => n.parentId === parentId && !n.deleted).map((n) => n.name).sort();
const settled = (svc) => svc.transfers().every((t) => !['queued', 'running'].includes(t.state));
const commits = (srv) => srv.state.requests.filter((r) => r.path.endsWith('uploads/commit'));

async function setup(opts = {}) {
  const srv = await driveServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('drive-dnd-tmp-');
  const svc = new DriveService({ apiClient, api, log, tempDir: () => tmp, timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api };
}

/** api.upload held until released (or aborted by its signal) — a file "on its way". */
function holdUploads(api) {
  const real = api.upload.bind(api);
  const held = [];
  api.upload = (file, o = {}) => new Promise((resolve, reject) => {
    const h = { file, signal: o.signal || null, go: () => real(file, o).then(resolve, reject) };
    held.push(h);
    if (h.signal) h.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { code: 'network' })), { once: true });
  });
  return held;
}

describe('Drive drag & drop: folders', () => {
  it('a dropped folder: structure with its empty folders, Thumbs.db / desktop.ini left out, into a folder there already', async () => {
    const { srv, svc } = await setup({ features: [] });
    const top = path.join(tmpDir('drive-dnd-'), 'Projekt');
    write(top, 'Plan.txt', 'plan');
    write(top, 'Thumbs.db', 'x');
    write(top, 'Bilder/desktop.ini', 'x');
    write(top, 'Bilder/Skizze.png', 'png');
    write(top, 'Bilder/2026/Mai/Foto.jpg', 'jpg');
    fs.mkdirSync(path.join(top, 'Leer', 'Auch leer'), { recursive: true });
    const r = await svc.upload(1, [top], { dropped: true });
    assert.equal(r.ok, true);
    assert.equal(r.queued.length, 3);
    assert.equal(r.folders, 6); // Projekt, Bilder, 2026, Mai, Leer, Auch leer
    await until(() => settled(svc));
    const p = childNamed(srv, 1, 'Projekt');
    assert.deepEqual(childrenOf(srv, p.id), ['Bilder', 'Leer', 'Plan.txt']);
    const bilder = childNamed(srv, p.id, 'Bilder');
    assert.deepEqual(childrenOf(srv, bilder.id), ['2026', 'Skizze.png']);
    assert.ok(childNamed(srv, childNamed(srv, childNamed(srv, bilder.id, '2026').id, 'Mai').id, 'Foto.jpg'));
    assert.deepEqual(childrenOf(srv, childNamed(srv, p.id, 'Leer').id), ['Auch leer']);

    // dropped again with one more file and one changed: into the same folders (no "Projekt (2)"); the same file there
    // is "schon vorhanden", a changed one asks as in every upload
    write(top, 'Bilder/Neu.txt', 'neu');
    write(top, 'Plan.txt', 'plan v2');
    const again = await svc.upload(1, [top], { dropped: true });
    assert.equal(again.queued.length, 4);
    await until(() => settled(svc) && svc.transfers().some((t) => t.state === 'conflict'));
    const st = svc.transfers().filter((t) => again.queued.includes(t.id)).map((t) => [t.name, t.state]).sort();
    assert.deepEqual(st, [['Foto.jpg', 'same'], ['Neu.txt', 'done'], ['Plan.txt', 'conflict'], ['Skizze.png', 'same']]);
    assert.equal(childNamed(srv, 1, 'Projekt (2)'), undefined);
    assert.ok(childNamed(srv, bilder.id, 'Neu.txt'));
    const folderRows = svc.transfers().filter((t) => t.folder);
    assert.deepEqual(folderRows.map((x) => [x.name, x.state, x.nodeId]), [['Projekt', 'done', p.id], ['Projekt', 'done', p.id]]);
    // a taken name: "Beide behalten" as in every upload
    const ask = svc.transfers().find((t) => t.state === 'conflict' && t.name === 'Plan.txt');
    svc.resolve(ask.id, 'rename');
    await until(() => childrenOf(srv, p.id).length === 4);
    assert.ok(childrenOf(srv, p.id).includes('Plan.txt'));
  });

  it('without `dropped` ("Ordner hochladen") a taken top folder still gets a free name', async () => {
    const { srv, svc } = await setup({ features: [] });
    const top = path.join(tmpDir('drive-dnd-'), 'Fotos');
    write(top, 'a.txt', 'a');
    await svc.upload(1, [top]);
    await until(() => settled(svc));
    await svc.upload(1, [top]);
    await until(() => settled(svc));
    assert.ok(childNamed(srv, 1, 'Fotos (2)'));
  });

  it('several files and folders at once; a dropped Thumbs.db, the same path twice and a link left out', async () => {
    const { srv, svc } = await setup({ features: [] });
    const base = tmpDir('drive-dnd-');
    const a = write(base, 'a.txt', 'a');
    const b = write(base, 'b.txt', 'b');
    const thumbs = write(base, 'Thumbs.db', 'x');
    const dir = path.join(base, 'Ordner');
    write(dir, 'c.txt', 'c');
    const r = await svc.upload(1, [a, b, a, thumbs, dir, path.join(base, 'fehlt.txt')], { dropped: true });
    assert.deepEqual(r.rejected, [{ name: 'fehlt.txt', code: 'missing' }]);
    assert.equal(r.queued.length, 3);
    await until(() => settled(svc));
    assert.deepEqual(childrenOf(srv, 1).filter((n) => ['a.txt', 'b.txt', 'Ordner', 'Thumbs.db'].includes(n)), ['Ordner', 'a.txt', 'b.txt']);
    assert.equal(commits(srv).filter((c) => c.body.name === 'a.txt').length, 1);
  });

  it('links inside a folder are never followed (no loop), the real folder goes once', { skip: process.platform === 'win32' }, async () => {
    const { srv, svc } = await setup({ features: [] });
    const top = path.join(tmpDir('drive-dnd-'), 'Schleife');
    write(top, 'Sub/x.txt', 'x');
    fs.symlinkSync(top, path.join(top, 'Sub', 'zurueck'), 'dir');
    fs.symlinkSync(path.join(top, 'Sub', 'x.txt'), path.join(top, 'link.txt'));
    const r = await svc.upload(1, [top], { dropped: true });
    assert.equal(r.queued.length, 1);
    assert.equal(r.skipped, 2);
    await until(() => settled(svc));
    const s = childNamed(srv, 1, 'Schleife');
    assert.deepEqual(childrenOf(srv, s.id), ['Sub']);
    assert.deepEqual(childrenOf(srv, childNamed(srv, s.id, 'Sub').id), ['x.txt']);
    // a dropped link itself is no file
    const r2 = await svc.upload(1, [path.join(top, 'link.txt')], { dropped: true });
    assert.deepEqual(r2.rejected, [{ name: 'link.txt', code: 'missing' }]);
  });

  it('a path that is not absolute or holds a NUL is ignored', async () => {
    const { svc } = await setup({ features: [] });
    const r = await svc.upload(1, ['relativ.txt', `${path.sep}x\0y`], { dropped: true });
    assert.deepEqual([r.queued.length, r.rejected.length], [0, 0]);
  });
});

describe('Drive drag & drop: cancelling', () => {
  it('one file waiting: cancelled, the others go on; a failed file never stops the rest', async () => {
    const { srv, svc, api } = await setup({ features: [] });
    const held = holdUploads(api);
    const base = tmpDir('drive-dnd-');
    const files = ['1.txt', '2.txt', '3.txt', '4.txt'].map((n) => write(base, n, n));
    const r = await svc.upload(1, files, { dropped: true });
    assert.equal(r.queued.length, 4);
    await until(() => held.length === 1);
    // the second waits: "Abbrechen"
    assert.deepEqual(svc.cancelUpload(r.queued[1]), { ok: true, cancelled: 1 });
    assert.equal(svc.transfers().find((t) => t.id === r.queued[1]).state, 'cancelled');
    // the third fails on the server
    srv.state.fail = { 'POST uploads/commit': { status: 500, code: 'server_error' } };
    held[0].go();
    await until(() => held.length === 2);
    srv.state.fail = {};
    held[1].go();
    await until(() => held.length === 3);
    held[2].go();
    await until(() => settled(svc));
    const st = Object.fromEntries(svc.transfers().map((t) => [t.name, t.state]));
    assert.deepEqual(st, { '1.txt': 'failed', '2.txt': 'cancelled', '3.txt': 'done', '4.txt': 'done' });
    assert.equal(childNamed(srv, 1, '2.txt'), undefined);
    assert.throws(() => svc.cancelUpload(r.queued[1]), (e) => e.code === 'not_found');
  });

  it('a file on its way: its request is aborted (signal), the next one goes', async () => {
    const { srv, svc, api } = await setup({ features: [] });
    const held = holdUploads(api);
    const base = tmpDir('drive-dnd-');
    const r = await svc.upload(1, [write(base, 'gross.bin', 'g'.repeat(1000)), write(base, 'klein.txt', 'k')], { dropped: true });
    await until(() => held.length === 1);
    assert.ok(held[0].signal, 'the upload gets a signal');
    assert.equal(svc.transfers().find((t) => t.id === r.queued[0]).state, 'running');
    svc.cancelUpload(r.queued[0]);
    assert.equal(held[0].signal.aborted, true);
    await until(() => held.length === 2);
    held[1].go();
    await until(() => settled(svc));
    assert.equal(svc.transfers().find((t) => t.id === r.queued[0]).state, 'cancelled');
    assert.equal(childNamed(srv, 1, 'gross.bin'), undefined);
    assert.ok(childNamed(srv, 1, 'klein.txt'));
  });

  it('a file asking about a taken name: cancelled, it asks no more', async () => {
    const { srv, svc } = await setup({ features: [] });
    const base = tmpDir('drive-dnd-');
    await svc.upload(1, [write(base, 'Doppelt.txt', 'eins')]);
    await until(() => settled(svc));
    write(base, 'Doppelt.txt', 'zwei');
    const r = await svc.upload(1, [path.join(base, 'Doppelt.txt')], { dropped: true });
    await until(() => svc.transfers().some((t) => t.id === r.queued[0] && t.state === 'conflict'));
    svc.cancelUpload(r.queued[0]);
    assert.equal(svc.transfers().find((t) => t.id === r.queued[0]).state, 'cancelled');
    assert.throws(() => svc.resolve(r.queued[0], 'version'), (e) => e.code === 'not_found');
    assert.equal(commits(srv).length, 1);
  });

  it('a folder: its row cancels every file of it not through yet; "Alle abbrechen" stops the rest', async () => {
    const { srv, svc, api } = await setup({ features: [] });
    const held = holdUploads(api);
    const base = tmpDir('drive-dnd-');
    const dir = path.join(base, 'Viele');
    for (let i = 0; i < 5; i++) write(dir, `f${i}.txt`, `f${i}`);
    const einzeln = write(base, 'einzeln.txt', 'e');
    const later = write(base, 'danach.txt', 'd');
    const r = await svc.upload(1, [dir, einzeln], { dropped: true });
    assert.equal(r.queued.length, 6);
    const row = svc.transfers().find((t) => t.folder);
    assert.ok(svc.transfers().filter((t) => t.group === row.id).length === 5);
    await until(() => held.length === 1);
    // the folder's row: its 5 files (one on its way)
    assert.equal(svc.cancelUpload(row.id).cancelled, 5);
    await until(() => held.length === 2);
    assert.equal(held[1].file.size, 1); // einzeln.txt goes on
    const r2 = await svc.upload(1, [later], { dropped: true });
    assert.equal(svc.cancelUploads().cancelled, 2);
    await until(() => settled(svc));
    const states = svc.transfers().filter((t) => !t.folder).map((t) => t.state);
    assert.deepEqual(states, Array(7).fill('cancelled'));
    assert.equal(svc.transfers().find((t) => t.id === r2.queued[0]).state, 'cancelled');
    assert.equal(commits(srv).length, 0);
    // the folders made stay (empty)
    assert.ok(childNamed(srv, 1, 'Viele'));
    assert.deepEqual(svc.cancelUploads(), { ok: true, cancelled: 0 });
  });

  it('a folder being walked stops when cancelled', async () => {
    const { srv, svc, api } = await setup({ features: [] });
    const dir = path.join(tmpDir('drive-dnd-'), 'Tief');
    for (let i = 0; i < 4; i++) write(dir, `d${i}/x.txt`, 'x');
    // the second subfolder's mkdir: "Alle abbrechen" while the walk runs
    const mkdir = api.mkdir.bind(api);
    let n = 0;
    api.mkdir = async (...args) => {
      if (++n === 3) svc.cancelUploads();
      return mkdir(...args);
    };
    const r = await svc.upload(1, [dir], { dropped: true });
    await until(() => settled(svc));
    const row = svc.transfers().find((t) => t.folder);
    assert.equal(row.state, 'cancelled');
    assert.ok(r.queued.length < 4);
    assert.ok(childrenOf(srv, childNamed(srv, 1, 'Tief').id).length < 4);
  });
});

describe('Drive drag & drop: media upload abort, IPC, bridge', () => {
  it('GateDropApi.upload stops at its signal: before it starts, and between parts', async () => {
    const { srv, api } = await setup({ features: [] });
    const file = write(tmpDir('drive-dnd-'), 'teile.bin', Buffer.alloc(65536 * 4, 7));
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(api.media.upload({ path: file, size: 65536 * 4, mime: 'application/octet-stream' }, { signal: ac.signal }), (e) => e.code === 'cancelled');
    assert.equal(srv.state.uploadCalls.length, 0);
    api.media.resumableFrom = 1;
    api.media.partSize = 65536;
    const ac2 = new AbortController();
    await assert.rejects(api.media.upload({ path: file, size: 65536 * 4, mime: 'application/octet-stream' }, {
      signal: ac2.signal,
      onProgress: (sent) => { if (sent >= 65536) ac2.abort(); },
    }), (e) => e.code === 'cancelled');
    assert.ok(srv.state.uploadCalls.length <= 2, `${srv.state.uploadCalls.length} parts went`);
  });

  it('IPC: drive:upload takes `dropped`, drive:upload:cancel { id } | { all }', async () => {
    const { svc } = await setup({ features: [] });
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.equal((await call('drive:upload', { parentId: 1, paths: [], dropped: 'ja' })).code, 'invalid');
    assert.equal((await call('drive:upload:cancel', {})).code, 'invalid');
    assert.equal((await call('drive:upload:cancel', { id: 'u999' })).code, 'not_found');
    assert.deepEqual(await call('drive:upload:cancel', { all: true }), { ok: true, cancelled: 0 });
    const calls = [];
    svc.upload = async (...args) => { calls.push(args); return { ok: true, queued: [], rejected: [], folders: 0, skipped: 0, move: null }; };
    await call('drive:upload', { parentId: 1, paths: ['/x'], dropped: true });
    await call('drive:upload', { parentId: 1, paths: ['/y'] });
    assert.deepEqual(calls, [[1, ['/x'], { dropped: true }], [1, ['/y'], { dropped: false }]]);
  });

  it('bridge: paths from webUtils only, each once, in turns of 200; cancel channels', async () => {
    const invoked = [];
    const ipc = {
      invoke: (ch, arg) => {
        invoked.push([ch, arg]);
        const n = arg && arg.paths ? arg.paths.length : 0;
        return Promise.resolve({ ok: true, queued: Array.from({ length: n }, (_, i) => `u${invoked.length}-${i}`), rejected: [], folders: 1, skipped: 2, move: null });
      },
      send() {}, on() {}, removeListener() {},
    };
    const files = Array.from({ length: 450 }, (_, i) => ({ name: `f${i}`, path: '/untrusted/property' }));
    const webUtils = { getPathForFile: (f) => (f.name === 'f3' ? '' : `/drop/${f.name === 'f4' ? 'f0' : f.name}`) };
    const api = createBridgeApi(ipc, { t: (k) => k }, { webUtils });
    const r = await api.drive.uploadDropped(7, files);
    assert.equal(invoked.length, 3);
    assert.deepEqual(invoked.map(([ch, a]) => [ch, a.parentId, a.dropped, a.paths.length]), [['drive:upload', 7, true, 200], ['drive:upload', 7, true, 200], ['drive:upload', 7, true, 48]]);
    assert.ok(invoked.every(([, a]) => a.paths.every((p) => p.startsWith('/drop/'))));
    assert.deepEqual([r.ok, r.queued.length, r.folders, r.skipped], [true, 448, 3, 6]);
    // without webUtils nothing is taken from the object
    invoked.length = 0;
    await createBridgeApi(ipc, { t: (k) => k }).drive.uploadDropped(7, files.slice(0, 2));
    assert.deepEqual(invoked[0][1].paths, []);
    invoked.length = 0;
    await api.drive.cancelUpload('u3');
    await api.drive.cancelUploads();
    assert.deepEqual(invoked, [['drive:upload:cancel', { id: 'u3' }], ['drive:upload:cancel', { all: true }]]);
  });
});
