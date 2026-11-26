'use strict';

// Drive 1.16 in the Windows Pro app: places ('photoPlaces': the position from EXIF GPS / a video's ©xyz with the
// commit unless keepGeo is off, the places, the map's clusters, photos of a place / a box, "Orte löschen") and people
// ('photoPeople': people, a person with "Ist das auch …?", "Zusammen mit", naming with merging, hiding, "Sieht aus wie
// …", a face to another person, "Alle Gesichtsdaten löschen"), the search with suggestions and marks — only with the
// features `me` reports — and the IPC (also the map tiles).

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
const DriveSync = require('../src/services/drive-sync');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { shot, shotOf, bufferSource, iso6709, geoOf } = require('../src/utils/taken-at');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');
const { tiff, jpeg, heic, mp4, webp, png } = require('./fixtures/exif-files');

const log = { info() {}, warn() {}, debug() {}, error() {} };
/** The code a call of the service fails with ('ok' when it did not fail). */
const codeOf = (p) => Promise.resolve(p).then(() => 'ok', (e) => e.code);
const PP = ['photos', 'takenAt', 'photoPlaces', 'photoPeople', 'photoSearch'];
const HH = { lat: [53, 33, 3.6], latRef: 'N', lon: [9, 59, 38.4], lonRef: 'E' };

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}
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

async function setup(features = PP) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('drive116-tmp-');
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp, timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api };
}

/** Photos in Hamburg (Altona, St. Pauli), Köln and one without a place; Lea on 3, Mama on 2 (one with Lea). */
function world(srv) {
  const t = (d) => Date.UTC(2026, 2, d, 10);
  const p = {
    a: srv.addPhoto({ name: 'Altona.jpg', takenAt: t(14), geo: { lat: 53.5502, lon: 9.9351 } }),
    b: srv.addPhoto({ name: 'Pauli.jpg', takenAt: t(13), geo: { lat: 53.5561, lon: 9.9641 } }),
    c: srv.addPhoto({ name: 'Dom.jpg', takenAt: Date.UTC(2025, 6, 20, 10), geo: { lat: 50.9413, lon: 6.9583 } }),
    d: srv.addPhoto({ name: 'Ohne.jpg', takenAt: t(1) }),
  };
  const lea = srv.addPerson({ name: 'Lea', nodes: [p.a.id, p.b.id, p.c.id], uncertain: [p.d.id] });
  const mama = srv.addPerson({ name: 'Mama', nodes: [p.a.id, p.c.id] });
  const unnamed = srv.addPerson({ nodes: [p.b.id, p.d.id] });
  srv.state.labels.set(p.a.id, ['Hafen']);
  return { p, lea, mama, unnamed };
}

// ── EXIF ───────────────────────────────────────────────────

describe('utils/taken-at: where a photo was taken (Drive 1.16)', () => {
  const geo = async (buf, opts) => (await shotOf(bufferSource(buf), opts)).geo;

  it('reads the GPS IFD of JPEG, TIFF (both byte orders), HEIC, WebP and PNG with the date in one go', async () => {
    const want = { lat: 53.551, lon: 9.994 };
    for (const t of [tiff({ gps: HH }), tiff({ gps: HH, le: false })]) {
      for (const buf of [t, jpeg(t), heic(t), webp(t), png(t)]) {
        const r = await shotOf(bufferSource(buf));
        assert.deepEqual(r.geo, want);
        assert.equal(r.date.iso, '2026-07-14T18:03:22+02:00');
      }
    }
    // south / west, no date at all
    assert.deepEqual(await geo(jpeg(tiff({ gps: { lat: [33, 51, 0], latRef: 'S', lon: [151, 12, 30], lonRef: 'W' }, original: null, offset: null, dateTime: null }))), { lat: -33.85, lon: -151.208333 });
    // no GPS, 0/0 (no fix), out of range, geo: false
    assert.equal(await geo(jpeg(tiff())), null);
    assert.equal(await geo(jpeg(tiff({ gps: { lat: [0, 0, 0], latRef: 'N', lon: [0, 0, 0], lonRef: 'E' } }))), null);
    assert.equal(await geo(jpeg(tiff({ gps: { lat: [95, 0, 0], latRef: 'N', lon: [9, 0, 0], lonRef: 'E' } }))), null);
    assert.equal(await geo(jpeg(tiff({ gps: HH })), { geo: false }), null);
  });

  it('reads ©xyz of a video (ISO 6709) and checks positions', async () => {
    assert.deepEqual(await geo(mp4(100, 0, '+53.5510+009.9937+012.000/')), { lat: 53.551, lon: 9.9937 });
    assert.equal(await geo(mp4(100)), null);
    assert.deepEqual(iso6709('-33.8500-151.2083/'), { lat: -33.85, lon: -151.2083 });
    for (const bad of ['', 'nonsense', '+95.0+010.0/', '+00.0000+000.0000/']) assert.equal(iso6709(bad), null, bad);
    assert.equal(geoOf(NaN, 1), null);
    assert.deepEqual(geoOf(1.12345678, -2.1234567), { lat: 1.123457, lon: -2.123457 });
  });

  it('shot(file): date and position of pictures and videos, never throws', async () => {
    const dir = tmpDir('shot-');
    const p = path.join(dir, 'IMG_2.jpg');
    fs.writeFileSync(p, jpeg(tiff({ gps: HH })));
    assert.deepEqual(await shot(p), { takenAt: '2026-07-14T18:03:22+02:00', geo: { lat: 53.551, lon: 9.994 } });
    assert.deepEqual(await shot(p, { geo: false }), { takenAt: '2026-07-14T18:03:22+02:00', geo: null });
    const q = path.join(dir, 'kopie.bin');
    fs.writeFileSync(q, jpeg(tiff({ gps: HH })));
    assert.deepEqual(await shot(q), { takenAt: null, geo: null });
    assert.deepEqual(await shot(path.join(dir, 'fehlt.jpg')), { takenAt: null, geo: null });
  });
});

// ── Answers ────────────────────────────────────────────────

describe('utils/drive: Drive 1.16 answers', () => {
  it('cleans photo items with geo / people, places, clusters, suggestions, marks and districts', () => {
    const ph = drive.normalizePhoto({
      id: 5, name: 'a.jpg', mime: 'image/jpeg', located: true, people: [3, 'p_9', '../x', 0],
      geo: { lat: 53.5511111, lon: '9.9937', place: { key: 'geonames:2911298', name: 'Hamburg', district: 'Altona', region: 'Hamburg', country: 'de' } },
    });
    assert.deepEqual(ph.geo, { lat: 53.551111, lon: 9.9937, place: { key: 'geonames:2911298', name: 'Hamburg', district: 'Altona', region: 'Hamburg', country: 'DE' } });
    assert.equal(ph.located, true);
    assert.deepEqual(ph.people, [3, 'p_9']);
    const none = drive.normalizePhoto({ id: 6, name: 'b.jpg', geo: { lat: 0, lon: 0 } });
    assert.equal(none.geo, null);
    assert.equal(none.located, false);
    assert.equal(none.people, null);
    assert.equal(drive.normalizePhoto({ id: 7, name: 'c.jpg', geo: { lat: 1, lon: 2, place: { key: 'bad key!', name: 'X' } } }).geo.place, null);

    const pl = drive.normalizePlaces({ places: [
      { key: 'geonames:1', name: 'Köln', region: 'NRW', country: 'DE', count: 3, lat: 50.9, lon: 6.9, from: '2025-01-01T00:00:00Z', to: '2026-01-01T00:00:00Z', cover: { id: 9, name: 'x.jpg' } },
      { key: 'geonames:2', name: 'Hamburg', count: 9 }, { key: 'x', name: '' }, null,
    ] });
    assert.deepEqual(pl.places.map((x) => [x.key, x.count]), [['geonames:2', 9], ['geonames:1', 3]]);
    assert.equal(pl.places[1].cover.id, 9);
    assert.equal(pl.places[0].lat, null);

    const map = drive.normalizeMap({ clusters: [{ lat: 53.5, lon: 9.9, count: 4, key: 'geonames:2' }, { lat: 91, lon: 0, count: 2 }, { lat: 1, lon: 1, count: 0 }] });
    assert.deepEqual(map.clusters, [{ lat: 53.5, lon: 9.9, count: 4, key: 'geonames:2', cover: null }]);

    const sg = drive.normalizeSuggest({ people: [{ id: 3, name: 'Lea', count: 5 }, { id: 4, name: null }], places: [{ key: 'geonames:2', name: 'Hamburg', sub: 'Ort', count: 2 }], labels: [{ label: 'strand', text: 'Strand', count: 7 }, { label: '' }] });
    assert.deepEqual(sg, { people: [{ id: 3, name: 'Lea', count: 5 }], places: [{ key: 'geonames:2', name: 'Hamburg', sub: 'Ort', count: 2 }], labels: [{ label: 'strand', text: 'Strand', count: 7 }] });

    const page = drive.normalizePhotos({ items: [], search: { people: [{ id: 3, name: 'Mama' }], places: [{ key: 'geonames:2', name: 'Hamburg' }], total: 4 }, districts: [{ name: 'Altona', count: 2 }, { name: '' }] });
    assert.deepEqual(page.marks, { people: [{ id: 3, name: 'Mama' }], places: [{ key: 'geonames:2', name: 'Hamburg' }] });
    assert.deepEqual(page.districts, [{ name: 'Altona', count: 2 }]);
    assert.equal(page.total, 4);
    assert.equal(drive.normalizePhotos({ items: [] }).marks, undefined);
  });

  it('cleans people, a person, updates, similar people, uncertain faces and the settings; checks bodies', () => {
    const cover = { faceId: 'f1', nodeId: 9, box: [0.1, 0.2, 0.3, 0.4], item: { id: 9, name: 'x.jpg' } };
    const pe = drive.normalizePeople({ people: [{ id: 3, name: 'Lea', count: 12, hidden: false, cover, contact: { kind: 'family', id: 7, name: 'Lea' } }, { id: 4, count: 2, cover: { ...cover, box: [0, 0, 2, 1] } }, { id: '' }], progress: { done: 9, total: 4 } });
    assert.equal(pe.people.length, 2);
    assert.deepEqual(pe.people[0].cover.box, [0.1, 0.2, 0.3, 0.4]);
    assert.deepEqual(pe.people[0].contact, { kind: 'family', id: 7, name: 'Lea' });
    assert.equal(pe.people[1].name, null);
    assert.equal(pe.people[1].cover, null);
    assert.deepEqual(pe.progress, { done: 4, total: 4 });
    assert.equal(drive.normalizePeople({}).progress, null);

    const flat = drive.normalizePersonDetail({ id: 3, name: 'Lea', count: 3, together: [{ id: 4, name: 'Mama', count: 2 }], places: [{ key: 'geonames:2', name: 'Hamburg', count: 2 }], uncertain: 5, years: { from: 2026, to: 2016 } });
    const nested = drive.normalizePersonDetail({ person: { id: 3, name: 'Lea', count: 3 }, together: [{ id: 4, name: 'Mama', count: 2 }], places: [], uncertain: 1, years: null });
    assert.deepEqual(flat.years, { from: 2016, to: 2026 });
    assert.equal(flat.uncertain, 5);
    assert.deepEqual(flat.together, [{ id: 4, name: 'Mama', count: 2 }]);
    assert.equal(nested.person.name, 'Lea');
    assert.equal(nested.together.length, 1);
    assert.equal(drive.normalizePersonDetail({ name: 'x' }), null);

    assert.deepEqual(drive.normalizePersonUpdate({ person: { id: 4, name: 'Mama' }, mergedInto: 4 }).mergedInto, 4);
    assert.deepEqual(drive.normalizeSimilar({ people: [{ id: 5, name: 'Tim', count: 3, score: 0.5 }, { id: 6, name: null, count: 1, score: 0.7 }, { id: 7 }, { id: 8 }] }).people.map((p) => p.id), [6, 5, 7]);
    assert.deepEqual(drive.normalizeUncertain({ faces: [{ faceId: 'f2', box: [0.1, 0.1, 0.2, 0.2], score: 0.33, item: { id: 9, name: 'x.jpg' } }, { faceId: 'f3', box: [0.1], item: { id: 9, name: 'x.jpg' } }] }).faces.length, 1);

    assert.deepEqual(drive.normalizePhotoSettings({ keepGeo: false, people: true, workFolder: 4 }), { keepGeo: false, stripGeoOnShare: null, people: true, peopleKids: false, deleted: null });
    assert.deepEqual(drive.normalizePhotoSettings({ stripGeoOnShare: true, deleted: 12 }), { keepGeo: true, stripGeoOnShare: true, people: false, peopleKids: false, deleted: 12 });

    assert.deepEqual(drive.geoBody({ lat: 53.12345678, lon: 9.1 }), { lat: 53.123457, lon: 9.1 });
    for (const bad of [null, {}, { lat: 91, lon: 1 }, { lat: 'x', lon: 1 }, { lat: 0, lon: 0 }]) assert.equal(drive.geoBody(bad), null);
    assert.equal(drive.bboxOf([9.1, 53.4, 10.2, 53.7]), '9.1,53.4,10.2,53.7');
    assert.equal(drive.bboxOf([170, -10, -170, 10]), '170,-10,-170,10');
    for (const bad of [[1, 2, 3], [0, 60, 1, 50], [0, 0, 200, 1], 'a,b,c,d']) assert.equal(drive.bboxOf(bad), null, String(bad));
    assert.equal(drive.contactBody(null), null);
    assert.deepEqual(drive.contactBody({ kind: 'contact', id: 12, name: 'Klaus Kramer' }), { kind: 'contact', id: 12, name: 'Klaus Kramer' });
    assert.equal(drive.contactBody({ kind: 'friend', id: 1, name: 'x' }), undefined);
  });
});

// ── Places ─────────────────────────────────────────────────

describe('DriveService: Drive 1.16 places', () => {
  it('an upload from the page carries the position — not with keepGeo off, not to older Drives, never for other files', async () => {
    for (const [features, keepGeo, want] of [[PP, true, true], [PP, false, false], [['photos', 'takenAt'], true, false]]) {
      const { svc, srv } = await setup(features);
      srv.state.photoSettings.keepGeo = keepGeo;
      const dir = tmpDir('drive116-up-');
      const p = path.join(dir, 'IMG_3.jpg');
      fs.writeFileSync(p, jpeg(tiff({ gps: HH })));
      fs.writeFileSync(path.join(dir, 'notiz.txt'), 'hallo');
      await svc.upload(1, [p, path.join(dir, 'notiz.txt')]);
      await until(() => svc.transfers().every((x) => x.state === 'done'));
      const img = commits(srv).find((x) => x.body.name === 'IMG_3.jpg');
      assert.equal(img.body.takenAt, '2026-07-14T18:03:22+02:00', JSON.stringify(features));
      assert.deepEqual(img.body.geo, want ? { lat: 53.551, lon: 9.994 } : undefined, `${features} ${keepGeo}`);
      if (want) assert.deepEqual(childNamed(srv, 1, 'IMG_3.jpg').geo, { lat: 53.551, lon: 9.994 });
      assert.equal(commits(srv).find((x) => x.body.name === 'notiz.txt').body.geo, undefined);
    }
  });

  it('"Ordner sichern" sends the position with the commit; keepGeo switched off here stops it', async () => {
    const env = await setup();
    const { srv, svc, api } = env;
    const sync = new DriveSync({
      drive: svc, api, store: createMemoryStore(), dir: tmpDir('drive116-state-'), log,
      hostname: () => 'Desktop-PC', getDeviceKey: () => 'ab12cd34',
      trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); },
      timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 },
      readPdfText: async () => null,
    });
    sync.start();
    cleanup.push(() => sync.stop());
    const root = tmpDir('pc-geo-');
    fs.writeFileSync(path.join(root, 'IMG_4.jpg'), jpeg(tiff({ gps: HH })));
    const target = srv.mutate.dir(1, 'Bilder');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup', targetId: target.id });
    await sync.idle();
    assert.deepEqual(commits(srv).find((x) => x.body.name === 'IMG_4.jpg').body.geo, { lat: 53.551, lon: 9.994 });
    // switched off on this PC: remembered at once, the next photo goes without
    assert.equal((await svc.setPhotoSettings({ keepGeo: false })).keepGeo, false);
    fs.writeFileSync(path.join(root, 'IMG_5.jpg'), jpeg(tiff({ gps: HH })));
    sync.sync(folder.id);
    await sync.idle();
    const c5 = commits(srv).find((x) => x.body.name === 'IMG_5.jpg');
    assert.ok(c5);
    assert.equal(c5.body.geo, undefined);
  });

  it('places, the map, photos of a place with districts, of a box, settings and "Orte löschen"', async () => {
    const { svc, srv } = await setup();
    const { p } = world(srv);
    const pl = await svc.photoPlaces();
    assert.deepEqual(pl.places.map((x) => [x.name, x.count]), [['Hamburg', 2], ['Köln', 1]]);
    assert.equal(pl.places[0].country, 'DE');
    const map = await svc.photoMap({ bbox: [5, 45, 15, 55], zoom: 6 });
    assert.equal(map.clusters.reduce((a, c) => a + c.count, 0), 3);
    assert.ok(map.clusters.some((c) => c.key === 'geonames:2911298' && c.count === 2));
    const hh = await svc.photos({ place: 'geonames:2911298', districts: true });
    assert.deepEqual(hh.items.map((x) => x.name), ['Altona.jpg', 'Pauli.jpg']);
    assert.equal(hh.items[0].geo.place.district, 'Altona');
    assert.deepEqual(hh.districts.map((d) => d.name).sort(), ['Altona', 'St. Pauli']);
    const box = await svc.photos({ bbox: [6, 50, 7.5, 51.5] });
    assert.deepEqual(box.items.map((x) => x.id), [p.c.id]);
    const months = await svc.photoMonths(null, { place: 'geonames:2911298' });
    assert.deepEqual(months.months, [{ month: '2026-03', count: 2 }]);
    // the timeline itself: geo and located on each photo
    const all = await svc.photos({});
    assert.equal(all.items.find((x) => x.id === p.d.id).located, false);
    assert.equal(all.items.find((x) => x.id === p.a.id).geo.place.name, 'Hamburg');

    // Drive 1.16.0 does not report stripGeoOnShare (then the switch is not shown); a Drive that does
    assert.deepEqual(await svc.photoSettings().then((x) => [x.keepGeo, x.stripGeoOnShare, x.people]), [true, null, false]);
    srv.stripGeo = true;
    assert.equal((await svc.photoSettings()).stripGeoOnShare, true);
    assert.equal((await svc.setPhotoSettings({ stripGeoOnShare: false })).stripGeoOnShare, false);
    const del = await svc.deletePhotoGeo();
    assert.equal(del.deleted, 3);
    assert.deepEqual((await svc.photoPlaces()).places, []);
    // what it refuses
    assert.equal(await codeOf(svc.photoMap({ bbox: [1, 2, 3], zoom: 4 })), 'invalid');
    assert.equal(await codeOf(svc.photos({ place: 'a b' })), 'invalid');
    assert.equal(await codeOf(svc.setPhotoSettings({ keepGeo: 'ja' })), 'invalid');
  });

  it('without the features nothing is asked: unsupported, the timeline as before', async () => {
    const { svc, srv } = await setup(['photos', 'takenAt']);
    for (const call of [() => svc.photoPlaces(), () => svc.photoMap({ bbox: [0, 0, 1, 1], zoom: 3 }), () => svc.photos({ place: 'geonames:1' }), () => svc.people(),
      () => svc.photos({ person: 3 }), () => svc.photoSuggest('Le'), () => svc.photoSettings(), () => svc.deletePhotoGeo(), () => svc.photos({ q: 'Hund' })]) {
      assert.equal(await codeOf(call()), 'unsupported', String(call));
    }
    const n = srv.state.requests.length;
    assert.equal((await svc.photos({})).ok, true);
    assert.ok(srv.state.requests.slice(n).every((r) => !/people|places|map|suggest|settings/.test(r.path)));
    // only one of them: the settings of the other are refused
    const env = await setup(['photos', 'photoPlaces']);
    assert.equal(await codeOf(env.svc.setPhotoSettings({ people: true })), 'unsupported');
    assert.equal((await env.svc.setPhotoSettings({ keepGeo: false })).ok, true);
  });
});

// ── People ─────────────────────────────────────────────────

describe('DriveService: Drive 1.16 people', () => {
  it('people, a person with together / places / years, photos of people (all of them), the people on each photo', async () => {
    const { svc, srv } = await setup();
    const { p, lea, mama, unnamed } = world(srv);
    srv.state.peopleProgress = { done: 3, total: 4 };
    const pe = await svc.people();
    assert.deepEqual(pe.people.map((x) => [x.name, x.count]), [['Lea', 3], ['Mama', 2], [null, 2]]);
    assert.deepEqual(pe.progress, { done: 3, total: 4 });
    assert.equal(pe.people[0].cover.item.id, p.a.id);
    const d = await svc.person(lea.id);
    assert.equal(d.person.name, 'Lea');
    assert.deepEqual(d.together, [{ id: mama.id, name: 'Mama', count: 2 }]);
    assert.deepEqual(d.places.map((x) => [x.name, x.count]), [['Hamburg', 2], ['Köln', 1]]);
    assert.equal(d.uncertain, 1);
    assert.deepEqual(d.years, { from: 2025, to: 2026 });
    const both = await svc.photos({ person: [lea.id, mama.id], withPeople: true });
    assert.deepEqual(both.items.map((x) => x.id).sort(), [p.a.id, p.c.id].sort());
    assert.deepEqual(both.items.find((x) => x.id === p.a.id).people.sort(), [lea.id, mama.id].sort());
    assert.equal((await svc.photoMonths(null, { person: unnamed.id })).months.length, 1);
  });

  it('naming (a name taken merges), hiding, linking, merging, similar people, uncertain faces, a face moved', async () => {
    const { svc, srv } = await setup();
    const { p, lea, mama, unnamed } = world(srv);
    srv.state.similar.set(unnamed.id, [{ id: lea.id, score: 0.51 }]);
    assert.deepEqual((await svc.similarPeople(unnamed.id)).people.map((x) => [x.name, x.score]), [['Lea', 0.51]]);
    // a new name
    let r = await svc.updatePerson(unnamed.id, { name: '  Oma Gerda ', contact: { kind: 'family', id: 9, name: 'Gerda' } });
    assert.deepEqual([r.person.name, r.mergedInto, r.person.contact.kind], ['Oma Gerda', null, 'family']);
    // a name that is taken: both together
    r = await svc.updatePerson(unnamed.id, { name: 'lea' });
    assert.equal(r.mergedInto, lea.id);
    assert.equal(r.person.count, 4);
    assert.equal(srv.state.people.has(unnamed.id), false);
    // hidden, the name removed, unlinked
    r = await svc.updatePerson(mama.id, { hidden: true });
    assert.equal(r.person.hidden, true);
    r = await svc.updatePerson(mama.id, { name: '', contact: null, hidden: false });
    assert.deepEqual([r.person.name, r.person.contact, r.person.hidden], [null, null, false]);
    // merged by hand
    r = await svc.mergePerson(mama.id, lea.id);
    assert.equal(r.person.id, lea.id);
    // "Ist das auch Lea?"
    const un = await svc.uncertainFaces(lea.id, 10);
    assert.equal(un.faces.length, 1);
    assert.equal(un.faces[0].item.id, p.d.id);
    r = await svc.confirmFaces(lea.id, [un.faces[0].faceId], true);
    assert.equal(r.person.count, 4);
    assert.equal((await svc.person(lea.id)).uncertain, 0);
    // "Nicht diese Person"
    const face = srv.state.people.get(lea.id).faces[0];
    assert.deepEqual(await svc.moveFace(face.faceId, null), { ok: true });
    assert.equal(srv.state.people.get(lea.id).faces.some((f) => f.faceId === face.faceId), false);
    // what it refuses
    assert.equal(await codeOf(svc.updatePerson(lea.id, {})), 'invalid');
    assert.equal(await codeOf(svc.updatePerson(lea.id, { contact: { kind: 'x', id: 1, name: 'y' } })), 'invalid');
    assert.equal(await codeOf(svc.person('a/b')), 'invalid');
    assert.equal(await codeOf(svc.confirmFaces(lea.id, [], true)), 'invalid');
    assert.equal(await codeOf(svc.person(99999)), 'not_found');
  });

  it('the search: suggestions while typing, names of people and places with the marks ("mama hamburg"); all face data deleted', async () => {
    const { svc, srv } = await setup();
    const { p, mama } = world(srv);
    const sg = await svc.photoSuggest('ha');
    assert.deepEqual(sg.places.map((x) => x.name), ['Hamburg']);
    assert.deepEqual(sg.labels.map((x) => x.text), ['Hafen']);
    assert.deepEqual((await svc.photoSuggest('ma')).people.map((x) => x.name), ['Mama']);
    const r = await svc.photos({ q: 'mama hamburg' });
    assert.deepEqual(r.items.map((x) => x.id), [p.a.id]);
    assert.deepEqual(r.marks, { people: [{ id: mama.id, name: 'Mama' }], places: [{ key: 'geonames:2911298', name: 'Hamburg' }] });
    assert.deepEqual((await svc.photos({ q: 'cologne' })).items.map((x) => x.id), [p.c.id]);
    assert.equal(await codeOf(svc.photoSuggest('')), 'invalid');
    // "Alle Gesichtsdaten löschen"
    await svc.setPhotoSettings({ people: true });
    const off = await svc.setPhotoSettings({ people: false });
    assert.equal(off.people, false);
    assert.equal(off.deleted, 8);
    assert.deepEqual((await svc.people()).people, []);
  });
});

// ── IPC ────────────────────────────────────────────────────

describe('IPC: Drive 1.16', () => {
  it('checks the arguments of the new channels and serves the map tiles from the MapService', async () => {
    const { svc, srv } = await setup();
    const { lea, mama } = world(srv);
    const handlers = {};
    const tiles = [];
    const maps = { tile: async (z, x, y) => { tiles.push([z, x, y]); return { mime: 'image/png', data: Buffer.from('png') }; } };
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, maps, getMainWindow: () => null, log });
    const bad = [
      ['drive:photos', { place: 'a b' }], ['drive:photos', { bbox: [1, 2, 3] }], ['drive:photos', { person: [] }], ['drive:photos', { districts: 'ja' }],
      ['drive:photos:months', { person: {} }], ['drive:photos:places', { q: 5 }], ['drive:photos:map', { bbox: [0, 0, 1, 1], zoom: 20 }],
      ['drive:photos:map', { zoom: 3 }], ['drive:photos:suggest', { q: '' }], ['drive:photos:settings:set', {}], ['drive:photos:settings:set', { people: 1 }],
      ['drive:person', { id: 'a b' }], ['drive:person:update', { id: lea.id }], ['drive:person:update', { id: lea.id, name: 5 }],
      ['drive:person:update', { id: lea.id, contact: { kind: 'family', id: 1 } }], ['drive:person:merge', { id: lea.id, into: lea.id }],
      ['drive:person:uncertain', { id: lea.id, limit: 500 }], ['drive:person:confirm', { id: lea.id, faceIds: [1], yes: 'ja' }],
      ['drive:face:move', { id: 3, person: {} }], ['drive:map:tile', { z: -1, x: 0, y: 0 }],
    ];
    for (const [ch, a] of bad) assert.equal((await handlers[ch](null, a)).code, 'invalid', `${ch} ${JSON.stringify(a)}`);
    assert.equal((await handlers['drive:photos'](null, { place: 'geonames:2911298', districts: true })).districts.length, 2);
    assert.equal((await handlers['drive:photos'](null, { person: [lea.id, mama.id], withPeople: true })).items.length, 2);
    assert.equal((await handlers['drive:photos:months'](null, { place: 'geonames:2911298' })).months[0].count, 2);
    assert.equal((await handlers['drive:photos:places'](null, {})).places.length, 2);
    assert.ok((await handlers['drive:photos:map'](null, { bbox: [5, 45, 15, 55], zoom: 5 })).clusters.length >= 1);
    assert.equal((await handlers['drive:photos:suggest'](null, { q: 'Le' })).people[0].name, 'Lea');
    assert.equal((await handlers['drive:photos:settings:set'](null, { people: true })).people, true);
    assert.equal((await handlers['drive:photos:settings'](null, {})).people, true);
    assert.equal((await handlers['drive:people'](null, {})).people.length, 3);
    assert.equal((await handlers['drive:person'](null, { id: lea.id })).person.name, 'Lea');
    assert.equal((await handlers['drive:person:update'](null, { id: mama.id, name: 'Mutti' })).person.name, 'Mutti');
    assert.equal((await handlers['drive:person:similar'](null, { id: lea.id })).ok, true);
    const un = await handlers['drive:person:uncertain'](null, { id: lea.id, limit: null });
    assert.equal(un.faces.length, 1);
    assert.equal((await handlers['drive:person:confirm'](null, { id: lea.id, faceIds: [un.faces[0].faceId], yes: false })).ok, true);
    assert.equal((await handlers['drive:person:merge'](null, { id: mama.id, into: lea.id })).person.id, lea.id);
    assert.equal((await handlers['drive:face:move'](null, { id: srv.state.people.get(lea.id).faces[0].faceId, person: null })).ok, true);
    assert.equal((await handlers['drive:photos:geo:delete'](null, {})).deleted, 3);
    const t = await handlers['drive:map:tile'](null, { z: 5, x: 16, y: 10 });
    assert.deepEqual([t.ok, t.mime, Buffer.from(t.data).toString()], [true, 'image/png', 'png']);
    assert.deepEqual(tiles, [[5, 16, 10]]);
    // without a MapService
    const h2 = {};
    registerDriveHandlers((ch, fn) => { h2[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await h2['drive:map:tile'](null, { z: 1, x: 0, y: 0 })).code, 'unsupported');
  });
});
