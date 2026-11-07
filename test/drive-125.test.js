'use strict';

// Drive 1.25 'mediaFilter' — only pictures or only videos: photos / photos/months with media=image|video, the search
// with media (then also without a word), durationMs on photo items and nodes; the IPC drive:photos, drive:photos:months
// and drive:search and the bridge. Without the feature: 'unsupported', nothing sent.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
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
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { driveServer } = require('./fixtures/drive-server');
const { createMemoryStore } = require('./fixtures/memory-store');
const fs = require('node:fs');
const path = require('node:path');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(features = ['photos', 'mediaFilter']) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const t0 = Date.UTC(2026, 9, 1, 12);
  const pic = srv.mutate.photo(1, 'Strand.jpg', { takenAt: t0 });
  const vid = srv.mutate.photo(1, 'Strand.mp4', { takenAt: t0 + 1000, mime: 'video/mp4', durationMs: 83456 });
  return { srv, svc, pic, vid };
}

const lastQuery = (srv, p) => [...srv.state.requests].reverse().find((r) => r.path.endsWith(p)).query;

describe('Drive 1.25: only pictures or only videos', () => {
  it('photos and months with media, the video with its length', async () => {
    const { srv, svc, pic, vid } = await setup();
    const all = await svc.photos({});
    assert.ok(all.items.some((x) => x.id === vid.id) && all.items.some((x) => x.id === pic.id), 'both without media');
    const v = await svc.photos({ media: 'video' });
    assert.equal(v.ok, true);
    assert.ok(v.items.length && v.items.every((x) => x.kind === 'video'));
    assert.deepEqual(v.items.find((x) => x.id === vid.id).durationMs, 83456);
    assert.equal(lastQuery(srv, '/photos').media, 'video');
    const p = await svc.photos({ media: 'image' });
    assert.ok(p.items.every((x) => x.kind === 'image' && x.durationMs === null) && p.items.some((x) => x.id === pic.id));
    const m = await svc.photoMonths(null, { media: 'video' });
    assert.equal(m.months.reduce((n, x) => n + x.count, 0), v.items.length);
    assert.equal(lastQuery(srv, '/photos/months').media, 'video');
    // anything else is refused before a request
    await assert.rejects(svc.photos({ media: 'audio' }), { code: 'invalid' });
  });

  it('the search with media: only those, also without a word; q still two characters otherwise', async () => {
    const { srv, svc, vid } = await setup();
    const r = await svc.search('strand', null, 'video');
    assert.deepEqual(r.items.map((x) => [x.id, x.durationMs]), [[vid.id, 83456]]);
    assert.equal(lastQuery(srv, '/search').media, 'video');
    const newest = await svc.search('', null, 'video');
    assert.equal(newest.ok, true);
    assert.deepEqual(newest.items.map((x) => x.id), [vid.id]);
    await assert.rejects(svc.search('', null, null), { code: 'invalid' });
    await assert.rejects(svc.search('s', null, 'video'), { code: 'invalid' });
    await assert.rejects(svc.search('strand', null, 'gif'), { code: 'invalid' });
  });

  it('an older Drive: unsupported, nothing sent with media', async () => {
    const { srv, svc } = await setup(['photos']);
    const before = srv.state.requests.length;
    await assert.rejects(svc.photos({ media: 'video' }), { code: 'unsupported' });
    await assert.rejects(svc.search('', null, 'video'), { code: 'unsupported' });
    assert.ok(!srv.state.requests.slice(before).some((r) => r.query && r.query.media), 'no media sent');
    // without media as before
    assert.equal((await svc.photos({})).ok, true);
  });

  it('IPC: drive:photos / drive:photos:months / drive:search take media, an empty q only with it', async () => {
    const { svc, vid } = await setup();
    const handlers = new Map();
    registerDriveHandlers((ch, fn) => handlers.set(ch, fn), { drive: svc, getMainWindow: () => null, log });
    const call = (ch, a) => handlers.get(ch)(null, a);
    assert.ok((await call('drive:photos', { media: 'video' })).items.some((x) => x.id === vid.id));
    assert.equal((await call('drive:photos', { media: 'audio' })).code, 'invalid');
    assert.ok((await call('drive:photos:months', { media: 'video' })).months.length >= 1);
    assert.deepEqual((await call('drive:search', { q: '', media: 'video' })).items.map((x) => x.id), [vid.id]);
    assert.equal((await call('drive:search', { q: '' })).code, 'invalid');
    assert.equal((await call('drive:search', { q: 'strand', media: 'x' })).code, 'invalid');
  });

  it('the bridge passes media to the search', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'preload', 'bridge.js'), 'utf8');
    assert.match(src, /search: +\(q, area, media\) => ipcRenderer\.invoke\('drive:search', \{ q, area: area \|\| null, \.\.\.\(media \? \{ media \} : \{\}\) \}\)/);
  });

  it('utils: media, durations', () => {
    assert.equal(drive.mediaOf('video'), 'video');
    assert.equal(drive.mediaOf('image'), 'image');
    assert.equal(drive.mediaOf('gif'), null);
    assert.equal(drive.durationOf(83456), 83456);
    assert.equal(drive.durationOf(0), null);
    assert.equal(drive.durationOf(1.5), null);
    assert.equal(drive.durationOf(drive.DURATION_MAX_MS + 1), null);
    assert.equal(drive.durationText(7000), '0:07');
    assert.equal(drive.durationText(83456), '1:23');
    assert.equal(drive.durationText(3723000), '1:02:03');
    assert.equal(drive.durationText(null), '');
    assert.equal(drive.normalizeNode({ id: 3, areaId: 'mine:2', name: 'a.mp4', mime: 'video/mp4', durationMs: 5000 }).durationMs, 5000);
    assert.equal(drive.normalizeNode({ id: 3, areaId: 'mine:2', name: 'd', isDir: true, durationMs: 5000 }).durationMs, null);
  });
});
