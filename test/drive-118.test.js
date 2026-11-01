'use strict';

// Drive 1.18 in the Windows Pro app ('overview'): the page "Übersicht" — GET overview cleaned, an older Drive's
// overview built from what it has, the tiles of the page (which show, numbers, labels) — and the IPC.

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

async function setup(features) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive118-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api };
}

const node = (id, name, extra = {}) => ({ id, areaId: 'mine:7', parentId: 1, name, isDir: false, size: 10, mime: null, rev: 1, ...extra });

/** An answer of GET overview as the contract describes it. */
const answer = () => ({
  todo: {
    deadlines: [
      { id: 1, kind: 'payment', date: '2026-11-04', label: 'Rechnung Stadtwerke zahlen', node: node(11, 'Rechnung.pdf') },
      { id: 2, kind: 'cancellation', date: '2026-11-13', label: 'Kfz-Versicherung kündigen', node: node(12, 'Kfz.pdf') },
      { id: 3, kind: 'bogus', date: '2026-11-14' },
    ],
    deadlinesTotal: 2,
    review: 12,
    toFile: 3,
    toFileHint: ' Familie › Versicherungen ',
  },
  recent: [
    { ...node(21, 'Steuerbescheid 2025.pdf', { mime: 'application/pdf' }), openedAt: '2026-10-31T09:00:00Z', areaLabel: 'Familie' },
    { ...node(22, 'Urlaub.jpg', { mime: 'image/jpeg' }), openedAt: '2026-10-31T09:00:00Z' },
    { ...node(23, 'Ordner', { isDir: true }), changedAt: '2026-10-30T09:00:00Z' },
    { ...node(24, 'Haushaltsbuch.xlsx'), changedAt: '2026-10-29T09:00:00Z' },
  ],
  memories: [
    { yearsAgo: 2, date: '2024-11-01', cover: { id: 31, name: 'Strand.jpg', mime: 'image/jpeg', takenAt: '2024-11-01T10:00:00Z' }, count: 30 },
    { yearsAgo: 1, date: '2025-11-01', count: 2 },
  ],
  people: [{ id: 41, name: 'Lea', count: 30 }, { id: 42, name: 'Mama', count: 20 }, { id: 43, name: null, count: 9 }, { id: 44, name: 'Weg', hidden: true }],
  unnamed: 4,
  places: { top: [{ key: 'geonames:2886242', name: 'Köln', count: 1629 }, { key: 'geonames:2911298', name: 'Hamburg', count: 214 }, { key: 'bad key!', name: 'x' }], cluster: { lat: 50.94, lon: 6.96, count: 3871 }, total: 3871 },
  activity: [
    { at: '2026-11-01T08:00:00Z', user: { id: 2, name: 'Mama' }, kind: 'added_photos', count: 14, area: { id: 'family:1', label: 'Familie' }, folder: { id: 51, path: 'Urlaub 2026' }, sample: node(52, 'IMG.jpg', { mime: 'image/jpeg' }) },
    { at: '2026-10-31T08:00:00Z', user: { id: 3, name: 'Papa' }, kind: 'added_files', count: 1, area: { id: 'family:1', label: 'Familie' }, folder: null, sample: node(53, 'Zeugnis Lea.pdf') },
    { at: '2026-10-31T08:00:00Z', user: { id: 3, name: 'Papa' }, kind: 'deleted', count: 1 },
  ],
  storage: { used: 212e9, total: 1e12, target: 'NAS' },
});

describe('utils/drive-overview: GET overview cleaned', () => {
  it('keeps what the contract names, drops what it does not understand', () => {
    const o = OV.normalizeOverview({ ok: true, ...answer() });
    assert.equal(o.assembled, false);
    assert.deepEqual(o.todo.deadlines.map((d) => d.id), [1, 2]);
    assert.equal(o.todo.deadlinesTotal, 2);
    assert.equal(o.todo.review, 12);
    assert.equal(o.todo.toFile, 3);
    assert.equal(o.todo.toFileHint, 'Familie › Versicherungen');
    // no folders, no photos in "Zuletzt geöffnet"
    assert.deepEqual(o.recent.map((r) => r.node.name), ['Steuerbescheid 2025.pdf', 'Haushaltsbuch.xlsx']);
    assert.equal(o.recent[0].areaLabel, 'Familie');
    assert.equal(o.recent[0].openedAt, Date.parse('2026-10-31T09:00:00Z'));
    // a memory needs a cover (or an item)
    assert.equal(o.memories.length, 1);
    assert.equal(o.memories[0].count, 30);
    // named, not hidden; the unnamed as a number (and the first one when it came along)
    assert.deepEqual(o.people.people.map((p) => p.name), ['Lea', 'Mama']);
    assert.equal(o.people.unnamed, 4);
    assert.equal(o.people.firstUnnamed, 43);
    assert.deepEqual(o.places.top.map((p) => p.name), ['Köln', 'Hamburg']);
    assert.deepEqual(o.places.cluster, { lat: 50.94, lon: 6.96, count: 3871 });
    assert.equal(o.activity.length, 2);
    assert.deepEqual(o.activity[0].folder, { id: 51, path: 'Urlaub 2026' });
    assert.deepEqual(o.storage, { used: 212e9, total: 1e12, target: 'NAS' });
  });

  it('takes the overview nested and people as an object; empty or wrong parts become null / []', () => {
    const o = OV.normalizeOverview({ overview: { people: { people: [{ id: 1, name: 'Tim' }], unnamed: 0 }, todo: 'x', places: [], storage: { used: -1 } } });
    assert.deepEqual(o.people.people.map((p) => p.name), ['Tim']);
    assert.equal(o.people.unnamed, 0);
    assert.equal(o.todo, null);
    assert.equal(o.places, null);
    assert.equal(o.storage, null);
    const empty = OV.normalizeOverview(null);
    assert.deepEqual(empty, { todo: null, recent: [], memories: [], people: null, places: null, activity: [], storage: null, assembled: false });
    assert.deepEqual(OV.overviewTiles(empty), []);
  });
});

describe('utils/drive-overview: the tiles', () => {
  it('shows a tile only when it has something, in the mockup order', () => {
    const o = OV.normalizeOverview(answer());
    assert.deepEqual(OV.overviewTiles(o), ['todo', 'recent', 'activity', 'memories', 'people', 'places']);
    // nothing to do, no activity: the storage takes the place of "Neu in …"
    const b = { ...o, todo: { ...o.todo, deadlines: [], deadlinesTotal: 0, review: 0, toFile: null }, activity: [] };
    assert.deepEqual(OV.overviewTiles(b), ['recent', 'storage', 'memories', 'people', 'places']);
    // people: only "Wer ist das?" left still shows; places without a place does not
    const c = { ...b, people: { people: [], unnamed: 2, firstUnnamed: null }, places: { top: [], cluster: null, total: 0 }, storage: null };
    assert.deepEqual(OV.overviewTiles(c), ['recent', 'memories', 'people']);
    assert.equal(OV.todoCount(o.todo), 4);
    assert.equal(OV.todoCount(null), 0);
  });

  it('labels: "Heute vor 2 Jahren", "Vor einem Jahr", the deadlines, "Neu in …"', () => {
    const now = new Date(2026, 10, 1, 9).getTime();
    assert.deepEqual(OV.memoryLabel({ yearsAgo: 2, cover: { takenAt: new Date(2024, 10, 1, 15).getTime() } }, now), { today: true, years: 2 });
    // a day beside it (the plugin takes ± 1 day)
    assert.deepEqual(OV.memoryLabel({ yearsAgo: 1, cover: { takenAt: new Date(2025, 9, 31, 15).getTime() } }, now), { today: false, years: 1 });
    // no time on the cover: the group's date
    assert.deepEqual(OV.memoryLabel({ yearsAgo: 3, date: '2023-11-01', cover: {} }, now), { today: true, years: 3 });
    assert.deepEqual(OV.deadlineWhen('2026-11-04', now), { key: 'in', days: 3 });
    assert.deepEqual(OV.deadlineWhen('2026-11-01', now), { key: 'today', days: 0 });
    assert.equal(OV.deadlineWhen('bogus', now), null);
    const o = OV.normalizeOverview(answer());
    assert.deepEqual(OV.activityLine(o.activity[0]), { key: 'photos', n: 14, name: 'Mama', file: null });
    assert.deepEqual(OV.activityLine(o.activity[1]), { key: 'file', n: 1, name: 'Papa', file: 'Zeugnis Lea.pdf' });
    assert.equal(OV.activityArea(o.activity), 'Familie');
    assert.equal(OV.activityArea([...o.activity, { area: { label: 'Team' } }]), null);
    assert.equal(OV.folderName('Familie/Urlaub 2026/'), 'Urlaub 2026');
    assert.equal(OV.storageFill(o.storage), 0.212);
    assert.equal(OV.storageFill({ used: 5, total: null }), null);
  });

  it('the small map: the box around the places, else a region around the bubble', () => {
    const o = OV.normalizeOverview(answer());
    const v = OV.mapView(o.places);
    assert.deepEqual(v.bubble, { lat: 50.94, lon: 6.96, count: 3871 });
    assert.ok(v.bbox[0] < 6.96 && v.bbox[2] > 6.96 && v.bbox[1] < 50.94 && v.bbox[3] > 50.94);
    const two = OV.mapView({ top: [{ lat: 50.9, lon: 6.9, count: 1 }, { lat: 53.5, lon: 10, count: 1 }], cluster: null, total: 2 });
    assert.ok(two.bbox[0] < 6.9 && two.bbox[2] > 10 && two.bbox[1] < 50.9 && two.bbox[3] > 53.5);
    assert.equal(OV.mapView({ top: [{ key: 'k', name: 'n', count: 1, lat: null, lon: null }], cluster: null, total: 1 }), null);
  });
});

describe('utils/drive-overview: an older Drive without overview', () => {
  it('builds the overview from deadlines, classes, memories, people, places and the areas', () => {
    const now = new Date(2026, 10, 1, 9).getTime();
    const o = OV.assembleOverview({
      now,
      deadlines: { deadlines: [{ id: 2, date: '2026-11-20', node: {} }, { id: 1, date: '2026-10-01', node: {} }, { id: 3, date: '2026-11-02', node: {} }, { id: 4, date: '2026-12-01', node: { encrypted: true } }] },
      classes: { work: 1, private: 2, review: 5 },
      memories: { groups: [{ yearsAgo: 1, date: '2025-11-01', items: [{ id: 9, name: 'a.jpg' }, { id: 10, name: 'b.jpg' }] }, { yearsAgo: 2, items: [] }] },
      people: { people: [{ id: 1, name: 'Mama', count: 5 }, { id: 2, name: null, count: 9 }, { id: 3, name: null, count: 20 }, { id: 4, name: 'X', hidden: true, count: 99 }] },
      places: { places: [{ key: 'b', name: 'Hamburg', count: 2, lat: 53.5, lon: 10 }, { key: 'a', name: 'Köln', count: 7, lat: 50.9, lon: 6.9 }] },
      areas: [{ kind: 'family', storage: { bytes: 9 } }, { kind: 'mine', storage: { bytes: 100, quota: 1000, target: 'NAS' } }],
    });
    assert.equal(o.assembled, true);
    assert.deepEqual(o.todo.deadlines.map((d) => d.id), [3, 2]);
    assert.equal(o.todo.deadlinesTotal, 2);
    assert.equal(o.todo.review, 5);
    assert.equal(o.todo.toFile, null);
    assert.deepEqual(o.memories.map((m) => [m.yearsAgo, m.count, m.cover.id]), [[1, 2, 9]]);
    assert.deepEqual(o.people, { people: [{ id: 1, name: 'Mama', count: 5 }], unnamed: 2, firstUnnamed: 3 });
    assert.deepEqual(o.places.top.map((p) => p.name), ['Köln', 'Hamburg']);
    assert.deepEqual(o.places.cluster, { lat: 50.9, lon: 6.9, count: 9 });
    assert.deepEqual(o.storage, { used: 100, total: 1000, target: 'NAS' });
    // "Zuletzt geöffnet" and "Neu in …" cannot be built: they stay out
    assert.deepEqual(OV.overviewTiles(o), ['todo', 'storage', 'memories', 'people', 'places']);
    // a feature off: its part is missing
    const none = OV.assembleOverview({ now });
    assert.equal(none.todo, null);
    assert.equal(none.people, null);
    assert.deepEqual(OV.overviewTiles(none), []);
  });
});

describe('DriveService.overview / IPC (Drive 1.18)', () => {
  it('with overview: one call, cleaned', async () => {
    const { srv, svc } = await setup(['photos', 'overview']);
    srv.overview = answer();
    const r = await svc.overview();
    assert.equal(r.ok, true);
    assert.equal(r.overview.assembled, false);
    assert.equal(r.overview.todo.review, 12);
    assert.equal(srv.overviewCalls, 1);
    // the tiles and their texts, ready for the page
    assert.deepEqual(r.view.tiles, ['todo', 'recent', 'activity', 'memories', 'people', 'places']);
    assert.equal(r.view.todoCount, 4);
    assert.equal(r.view.deadlines.length, 2);
    assert.equal(r.view.memories.length, 1);
    assert.deepEqual(r.view.activity[0], { key: 'photos', n: 14, name: 'Mama', file: null, folder: 'Urlaub 2026' });
    assert.equal(r.view.activityArea, 'Familie');
    assert.equal(r.view.storageFill, 0.212);
    assert.deepEqual(r.view.map.bubble, { lat: 50.94, lon: 6.96, count: 3871 });
  });

  it('without overview: built from the endpoints of the features there are', async () => {
    const { srv, svc } = await setup(['photos', 'photoPlaces', 'photoPeople', 'photoClasses']);
    srv.classes = { work: 0, private: 3, review: 7 };
    srv.addPhoto({ name: 'Dom.jpg', takenAt: Date.UTC(2025, 6, 20, 10), geo: { lat: 50.9413, lon: 6.9583 } });
    const a = srv.addPhoto({ name: 'Altona.jpg', takenAt: Date.UTC(2026, 2, 14, 10), geo: { lat: 53.5502, lon: 9.9351 } });
    srv.addPerson({ name: 'Lea', nodes: [a.id] });
    srv.addPerson({ nodes: [a.id] });
    const r = await svc.overview();
    assert.equal(r.ok, true);
    assert.equal(r.overview.assembled, true);
    assert.equal(srv.overviewCalls || 0, 0);
    assert.equal(r.overview.todo.review, 7);
    assert.deepEqual(r.overview.people.people.map((p) => p.name), ['Lea']);
    assert.equal(r.overview.people.unnamed, 1);
    assert.equal(r.overview.places.total, 2);
    assert.deepEqual(r.overview.recent, []);
    assert.deepEqual(r.overview.activity, []);
  });

  it('drive:overview over IPC', async () => {
    const { srv, svc } = await setup(['photos', 'overview']);
    srv.overview = answer();
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc });
    const r = await handlers['drive:overview'](null, {});
    assert.equal(r.ok, true);
    assert.deepEqual(r.overview.places.top.map((p) => p.name), ['Köln', 'Hamburg']);
  });
});
