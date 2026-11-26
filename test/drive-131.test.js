'use strict';

// Drive 1.31 'framePhotos': photos of the person for the photo frame of the GateControl TV — GET frame/photos[?ids=],
// POST / DELETE frame/photos { ids }; the skipped photos with their reason; 403 { field: 'frame' } for a person who may
// not share; an older Drive without the feature: 'unsupported'.

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

async function setup(features = ['photos', 'albums', 'framePhotos']) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive131-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}

describe('Drive 1.31: framePhotos', () => {
  it('normalizeFramePhotos: album, ids, counts and skipped with their reason', () => {
    const r = drive.normalizeFramePhotos({
      ok: true, album: { id: 9, name: 'Fotorahmen', frame: true }, added: 2, ids: [5, '4', 4, -1, 'x'], count: 2,
      skipped: [{ id: 7, reason: 'not_image' }, { id: 8, reason: 'vault' }, { id: 'y', reason: 'child' }, { id: 10, reason: 'Böse<b>' }, null],
    });
    assert.equal(r.album.id, 9);
    assert.equal(r.album.frame, true);
    assert.deepEqual(r.ids, [5, 4]);
    assert.equal(r.count, 2);
    assert.equal(r.added, 2);
    assert.equal(r.removed, 0);
    assert.deepEqual(r.skipped, [{ id: 7, reason: 'not_image' }, { id: 8, reason: 'vault' }, { id: 10, reason: 'unknown' }]);
    // no album yet, or only its id
    assert.equal(drive.normalizeFramePhotos({ ok: true, album: null, ids: [], count: 0 }).album, null);
    assert.deepEqual(drive.normalizeFramePhotos({ album: 12 }).album, { id: 12 });
    assert.deepEqual(drive.normalizeFramePhotos(null), { album: null, ids: [], count: 0, added: 0, removed: 0, skipped: [] });
    assert.deepEqual(drive.FRAME_SKIP_REASONS, ['not_found', 'not_image', 'vault', 'blocked', 'child']);
  });

  it('service: share, ask which are shared, remove; skipped photos say why', async () => {
    const { srv, svc } = await setup();
    const a = srv.mutate.photo(1, 'a.jpg', { takenAt: Date.UTC(2025, 0, 1) });
    const b = srv.mutate.photo(1, 'b.jpg', { takenAt: Date.UTC(2025, 0, 2) });
    const v = srv.mutate.photo(1, 'c.mp4', { mime: 'video/mp4', durationMs: 3000 });
    const k = srv.mutate.photo(1, 'k.jpg');
    const x = srv.mutate.photo(1, 'x.jpg');
    srv.frameChild = new Set([k.id]);
    srv.frameBlocked = new Set([x.id]);

    let r = await svc.framePhotos();
    assert.deepEqual([r.ok, r.album, r.ids, r.count], [true, null, [], 0]);

    r = await svc.setFramePhotos([a.id, b.id, v.id, k.id, x.id, 99999]);
    assert.equal(r.ok, true);
    assert.equal(r.added, 2);
    assert.equal(r.album.name, 'Fotorahmen');
    assert.deepEqual(r.ids, [b.id, a.id]);
    assert.deepEqual(r.skipped, [{ id: v.id, reason: 'not_image' }, { id: k.id, reason: 'child' }, { id: x.id, reason: 'blocked' }, { id: 99999, reason: 'not_found' }]);

    // with ids: only those of them in the frame (for the menu)
    r = await svc.framePhotos([a.id, v.id]);
    assert.deepEqual(r.ids, [a.id]);
    assert.equal(r.count, 2);
    assert.equal(srv.state.frameCalls.at(-1).method, 'GET');
    assert.deepEqual(srv.state.frameCalls.at(-1).ids, [a.id, v.id]);

    r = await svc.setFramePhotos([a.id], { remove: true });
    assert.deepEqual([r.ok, r.removed, r.ids, r.count], [true, 1, [b.id], 1]);
    assert.equal(srv.state.frameCalls.at(-1).method, 'DELETE');
    assert.ok(!srv.state.nodes.get(a.id).deleted, 'the photo itself stays');
  });

  it('403 { field: frame }: this account may not share photos', async () => {
    const { srv, svc } = await setup();
    const a = srv.mutate.photo(1, 'a.jpg');
    srv.frameForbidden = true;
    await assert.rejects(svc.setFramePhotos([a.id]), (e) => e.status === 403 && e.code === 'forbidden' && e.body.field === 'frame');
    // GET stays allowed
    assert.equal((await svc.framePhotos([a.id])).ok, true);
  });

  it('an older Drive without framePhotos: unsupported, no call', async () => {
    const { srv, svc } = await setup(['photos', 'albums']);
    const a = srv.mutate.photo(1, 'a.jpg');
    await assert.rejects(svc.framePhotos([a.id]), (e) => e.code === 'unsupported');
    await assert.rejects(svc.setFramePhotos([a.id]), (e) => e.code === 'unsupported');
    assert.equal(srv.state.frameCalls.length, 0);
  });

  it('no ids or more than 500: invalid before any call', async () => {
    const { srv, svc } = await setup();
    await assert.rejects(svc.setFramePhotos([]), (e) => e.code === 'invalid');
    await assert.rejects(svc.setFramePhotos(Array.from({ length: 501 }, (_, i) => i + 1)), (e) => e.code === 'invalid');
    await assert.rejects(svc.framePhotos([]), (e) => e.code === 'invalid');
    assert.equal(srv.state.frameCalls.length, 0);
  });

  it('IPC: drive:frame:photos / drive:frame:set check their arguments, 403 keeps field', async () => {
    const handlers = {};
    const calls = [];
    const { EventEmitter } = require('node:events');
    const svc = Object.assign(new EventEmitter(), {
      status: () => ({}),
      framePhotos: async (ids) => { calls.push(['get', ids]); return { ok: true, ids: ids || [] }; },
      setFramePhotos: async (ids, o) => {
        calls.push(['set', ids, o]);
        if (ids[0] === 13) {
          const MessengerApi = require('../src/services/messenger-api');
          throw new MessengerApi.MessengerError('forbidden', { status: 403, code: 'forbidden', body: { code: 'forbidden', field: 'frame' } });
        }
        return { ok: true };
      },
    });
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    for (const [ch, arg] of [
      ['drive:frame:photos', { ids: [] }], ['drive:frame:photos', { ids: ['1'] }], ['drive:frame:set', { ids: [] }],
      ['drive:frame:set', { ids: [0] }], ['drive:frame:set', { ids: [1], remove: 'ja' }], ['drive:frame:set', {}],
      ['drive:frame:set', { ids: Array.from({ length: 501 }, (_, i) => i + 1) }],
    ]) {
      assert.equal((await handlers[ch](null, arg)).code, 'invalid', `${ch} ${JSON.stringify(arg).slice(0, 40)}`);
    }
    assert.equal(calls.length, 0);
    await handlers['drive:frame:photos'](null, {});
    await handlers['drive:frame:photos'](null, { ids: [3, 4] });
    await handlers['drive:frame:set'](null, { ids: [3] });
    await handlers['drive:frame:set'](null, { ids: [3], remove: true });
    assert.deepEqual(calls, [['get', null], ['get', [3, 4]], ['set', [3], { remove: false }], ['set', [3], { remove: true }]]);
    const r = await handlers['drive:frame:set'](null, { ids: [13] });
    assert.deepEqual([r.ok, r.code, r.status, r.field], [false, 'forbidden', 403, 'frame']);
  });
});
