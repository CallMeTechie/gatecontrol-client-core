'use strict';

// Drive 1.26 'memoryCollections' in the Windows Pro app: the page „Erinnerungen“ — GET memories cleaned, the photos of
// one collection page by page, the overview's card with its collection id; the IPC and the bridge. Without the
// feature: 'unsupported', nothing sent.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const DriveApi = require('../src/services/drive-api');
const DriveService = require('../src/services/drive');
const drive = require('../src/utils/drive');
const OV = require('../src/utils/drive-overview');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { driveServer } = require('./fixtures/drive-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

const ANSWER = {
  date: '2026-11-08',
  home: { key: 'geonames:2879185', name: 'Langenlonsheim' },
  collections: [
    { id: 'day:2025-11-08', kind: 'day', yearsAgo: 1, date: '2025-11-08', count: 14, cover: { id: 1, areaId: 'mine:2', name: 'a.jpg' }, from: '2025-11-07T00:00:00.000Z', to: '2025-11-10T00:00:00.000Z' },
    { id: 'trip:2025-07-10:2025-07-14', kind: 'trip', place: { key: 'geonames:2911298', name: 'Hamburg' }, places: ['Hamburg', 'Lübeck'], days: 5, firstDay: '2025-07-10', lastDay: '2025-07-14', count: 87 },
    { id: 'person:12', kind: 'person', person: { id: 12, name: 'Noah' }, count: 120 },
    { id: 'month:2024-11', kind: 'month', yearsAgo: 2, month: '2024-11', count: 20 },
    { id: 'year:2025', kind: 'year', year: 2025, count: 1234 },
    { id: 'place:geonames:2879185', kind: 'place', place: { key: 'geonames:2879185', name: 'Langenlonsheim' }, count: 12 },
    { id: 'day:2020-01-01', kind: 'year', count: 3 },
    { id: 'x:1', kind: 'day', count: 3 },
    { id: 'year:2019', kind: 'year', count: 0 },
  ],
};

async function setup(features = ['photos', 'memoryCollections']) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const t0 = Date.UTC(2025, 10, 8, 12);
  const ids = Array.from({ length: 5 }, (_, i) => srv.mutate.photo(1, `p${i}.jpg`, { takenAt: t0 + i * 60000 }).id);
  srv.memoryCollections = ANSWER;
  srv.memoryPhotos = { 'day:2025-11-08': ids };
  return { srv, svc, ids };
}

const lastQuery = (srv, p) => [...srv.state.requests].reverse().find((r) => r.path.endsWith(p)).query;

describe('Drive 1.26: the page „Erinnerungen“', () => {
  it('utils: the collections cleaned, unknown or broken ones dropped', () => {
    const r = drive.normalizeMemoryCollections(ANSWER);
    assert.equal(r.date, '2026-11-08');
    assert.deepEqual(r.home, { key: 'geonames:2879185', name: 'Langenlonsheim' });
    assert.deepEqual(r.collections.map((c) => c.kind), drive.MEMORY_KINDS);
    const [day, trip, person, month, year, place] = r.collections;
    assert.deepEqual([day.yearsAgo, day.date, day.count, day.cover.id, day.from], [1, '2025-11-08', 14, 1, Date.parse('2025-11-07T00:00:00.000Z')]);
    assert.deepEqual([trip.place.name, trip.places, trip.days, trip.firstDay, trip.lastDay], ['Hamburg', ['Hamburg', 'Lübeck'], 5, '2025-07-10', '2025-07-14']);
    assert.deepEqual(person.person, { id: 12, name: 'Noah' });
    assert.deepEqual([month.month, month.yearsAgo, year.year, place.place.name], ['2024-11', 2, 2025, 'Langenlonsheim']);
    assert.equal(drive.memoryIdOf('day:2025-11-08'), 'day:2025-11-08');
    assert.equal(drive.memoryIdOf('place:geonames:12'), 'place:geonames:12');
    for (const bad of ['', 'day:heute', 'x:1', 'person:abc', 'trip:2025-01-01', null, 5]) assert.equal(drive.memoryIdOf(bad), null, String(bad));
    assert.deepEqual(drive.normalizeMemoryCollections(null), { date: null, home: null, collections: [] });
    assert.equal(drive.MEMORY_DAY_MORE_THAN, 10);
  });

  it('service: the collections, the photos of one page by page', async () => {
    const { srv, svc, ids } = await setup();
    const r = await svc.memoryCollections('2026-11-08');
    assert.equal(r.ok, true);
    assert.equal(r.collections.length, 6);
    assert.equal(lastQuery(srv, '/memories').date, '2026-11-08');
    const p1 = await svc.memoryPhotos('day:2025-11-08', { limit: 3 });
    assert.deepEqual(p1.items.map((x) => x.id), [ids[4], ids[3], ids[2]]);
    assert.ok(p1.next);
    assert.deepEqual([lastQuery(srv, '/memories/photos').id, lastQuery(srv, '/memories/photos').limit], ['day:2025-11-08', '3']);
    const p2 = await svc.memoryPhotos('day:2025-11-08', { limit: 3, before: p1.next });
    assert.deepEqual(p2.items.map((x) => x.id), [ids[1], ids[0]]);
    assert.equal(p2.next, null);
    await assert.rejects(svc.memoryPhotos('nonsense'), { code: 'invalid' });
    await assert.rejects(svc.memoryCollections('heute'), { code: 'invalid' });
  });

  it('an older Drive: unsupported, nothing sent', async () => {
    const { srv, svc } = await setup(['photos']);
    const before = srv.state.requests.length;
    await assert.rejects(svc.memoryCollections(), { code: 'unsupported' });
    await assert.rejects(svc.memoryPhotos('day:2025-11-08'), { code: 'unsupported' });
    assert.ok(!srv.state.requests.slice(before).some((r) => r.path.includes('/memories')));
  });

  it('IPC: drive:memories and drive:memories:photos check what they get', async () => {
    const { svc, ids } = await setup();
    const handlers = new Map();
    registerDriveHandlers((ch, fn) => handlers.set(ch, fn), { drive: svc, getMainWindow: () => null, log });
    const call = (ch, a) => handlers.get(ch)(null, a);
    assert.equal((await call('drive:memories', {})).collections.length, 6);
    assert.equal((await call('drive:memories', { date: 'gestern' })).code, 'invalid');
    assert.equal((await call('drive:memories:photos', { id: 'day:2025-11-08' })).items.length, ids.length);
    assert.equal((await call('drive:memories:photos', { id: 'nope' })).code, 'invalid');
    assert.equal((await call('drive:memories:photos', { id: 'day:2025-11-08', limit: 500 })).code, 'invalid');
  });

  it('the bridge offers memoryCollections and memoryPhotos', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'preload', 'bridge.js'), 'utf8');
    assert.match(src, /memoryCollections: \(date\) => ipcRenderer\.invoke\('drive:memories', \{ date: date \|\| null \}\)/);
    assert.match(src, /memoryPhotos: \(id, opts\) => ipcRenderer\.invoke\('drive:memories:photos', \{ \.\.\.\(opts \|\| \{\}\), id \}\)/);
  });

  it('the overview card carries the collection id (GET overview of Drive 1.26)', () => {
    const o = OV.normalizeOverview({ memories: [{ yearsAgo: 1, date: '2025-11-08', count: 14, id: 'day:2025-11-08', cover: { id: 1, name: 'a.jpg' } }, { yearsAgo: 2, count: 12, id: 'bad', cover: { id: 2, name: 'b.jpg' } }] });
    assert.deepEqual(o.memories.map((m) => m.id), ['day:2025-11-08', null]);
  });
});
