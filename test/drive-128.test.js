'use strict';

// Drive 1.28 'memoryPicks' in the Windows Pro app: GET overview's `memoryPicks` — collections of the page
// „Erinnerungen“ for a day without „Heute vor X Jahren“, cleaned exactly as GET memories; the tile "Erinnerungen"
// shows the days, else the picks, else nothing; an older Drive without the field: no picks.

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

const OV = require('../src/utils/drive-overview');
const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

/** The README's example (Drive 1.28, "Overview"), then a broken one and one of a kind this app does not know. */
const PICKS = [
  { id: 'trip:2025-07-10:2025-07-14', kind: 'trip',
    place: { key: 'geonames:2911298', name: 'Hamburg', region: 'Hamburg', country: 'DE' },
    places: ['Hamburg'], days: 5, firstDay: '2025-07-10', lastDay: '2025-07-14', count: 16,
    cover: { id: 812, areaId: 'mine:2', name: 'IMG_2041.jpg', mime: 'image/jpeg' },
    from: '2025-07-10T00:00:00.000Z', to: '2025-07-15T00:00:00.000Z' },
  { id: 'person:7', kind: 'person', person: { id: 7, name: 'Noah' }, count: 11,
    cover: { id: 640, areaId: 'mine:2', name: 'IMG_640.jpg' }, from: '2024-01-01T11:00:00.000Z', to: '2024-01-21T11:00:00.000Z' },
  { id: 'month:2025-10', kind: 'month', yearsAgo: 1, month: '2025-10', count: 20,
    cover: { id: 901, areaId: 'mine:2', name: 'IMG_901.jpg' }, from: '2025-10-01T00:00:00.000Z', to: '2025-11-01T00:00:00.000Z' },
  { id: 'year:2024', kind: 'year', year: 2024, count: 71, cover: null, from: '2024-01-01T00:00:00.000Z', to: '2025-01-01T00:00:00.000Z' },
  { id: 'place:geonames:1', kind: 'place', place: { key: 'geonames:1', name: 'Köln' }, count: 0 },
  { id: 'later:1', kind: 'later', count: 3 },
];

const day = { yearsAgo: 1, date: '2025-11-08', count: 14, id: 'day:2025-11-08', cover: { id: 1, name: 'a.jpg' } };

describe('Drive 1.28: the overview\'s memoryPicks', () => {
  it('cleaned exactly as GET memories cleans its collections, at most four', () => {
    const o = OV.normalizeOverview({ memories: [], memoryPicks: PICKS });
    assert.deepEqual(o.memoryPicks.map((c) => c.kind), ['trip', 'person', 'month', 'year']);
    assert.deepEqual(o.memoryPicks, drive.normalizeMemoryCollections({ collections: PICKS }).collections);
    const [trip, person, month, year] = o.memoryPicks;
    assert.deepEqual([trip.id, trip.place.name, trip.places, trip.days, trip.count, trip.cover.id], ['trip:2025-07-10:2025-07-14', 'Hamburg', ['Hamburg'], 5, 16, 812]);
    assert.deepEqual(person.person, { id: 7, name: 'Noah' });
    assert.deepEqual([month.yearsAgo, month.month], [1, '2025-10']);
    assert.deepEqual([year.year, year.cover], [2024, null]);
    const many = Array.from({ length: 9 }, (_, i) => ({ id: `year:${2015 + i}`, kind: 'year', year: 2015 + i, count: 60 }));
    assert.equal(OV.normalizeOverview({ overview: { memoryPicks: many } }).memoryPicks.length, 4);
  });

  it('an older Drive without the field, or a wrong shape: no picks', () => {
    assert.deepEqual(OV.normalizeOverview({ memories: [] }).memoryPicks, []);
    assert.deepEqual(OV.normalizeOverview({ memoryPicks: { id: 'year:2024' } }).memoryPicks, []);
    assert.deepEqual(OV.normalizeOverview({ memoryPicks: null }).memoryPicks, []);
    assert.deepEqual(OV.assembleOverview({}).memoryPicks, []);
    // a cleaned overview of an older core (no memoryPicks at all) is fine too
    assert.deepEqual(OV.memoryPicks({ memories: [] }), []);
    assert.deepEqual(OV.memoryPicks(null), []);
  });

  it('"Erinnerungen": the days as before, else the picks, else no tile', () => {
    const withDays = OV.normalizeOverview({ memories: [day], memoryPicks: PICKS });
    assert.deepEqual(OV.memoryPicks(withDays), []);
    assert.deepEqual(OV.overviewTiles(withDays), ['memories']);
    assert.equal(OV.overviewView(withDays).memories.length, 1);
    assert.deepEqual(OV.overviewView(withDays).memoryPicks, []);
    const onlyPicks = OV.normalizeOverview({ memories: [], memoryPicks: PICKS });
    assert.deepEqual(OV.overviewTiles(onlyPicks), ['memories']);
    assert.deepEqual(OV.overviewView(onlyPicks).memoryPicks.map((c) => c.id), ['trip:2025-07-10:2025-07-14', 'person:7', 'month:2025-10', 'year:2024']);
    const none = OV.normalizeOverview({ memories: [], memoryPicks: [] });
    assert.deepEqual(OV.overviewTiles(none), []);
    // with the storage alone it stays the storage
    assert.deepEqual(OV.overviewTiles({ ...none, storage: { used: 1, total: null, target: null } }), ['storage']);
    assert.deepEqual(OV.overviewTiles({ ...onlyPicks, storage: { used: 1, total: null, target: null } }), ['storage', 'memories']);
  });

  it('service: GET overview of Drive 1.28 hands the picks to the page', async () => {
    const srv = await driveServer({ features: ['photos', 'overview', 'memoryCollections', 'memoryPicks'] });
    cleanup.push(() => srv.close());
    const apiClient = new ApiClient(srv.url, 'gc_token', log);
    const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive128-'));
    cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
    const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp });
    svc.start();
    cleanup.push(() => svc.stop());
    await svc.check();
    srv.overview = { todo: null, recent: [], memories: [], memoryPicks: PICKS, people: null, places: null, activity: [], storage: null };
    const r = await svc.overview();
    assert.equal(r.ok, true);
    assert.equal(r.overview.memoryPicks.length, 4);
    assert.deepEqual(r.view.tiles, ['memories']);
    assert.deepEqual(r.view.memoryPicks.map((c) => c.kind), ['trip', 'person', 'month', 'year']);
    // the photos of a pick: GET memories/photos?id= as on the page
    const ids = [srv.mutate.photo(1, 'p.jpg', { takenAt: Date.UTC(2025, 6, 11, 10) }).id];
    srv.memoryPhotos = { 'trip:2025-07-10:2025-07-14': ids };
    const p = await svc.memoryPhotos(r.view.memoryPicks[0].id);
    assert.deepEqual(p.items.map((x) => x.id), ids);
  });
});
