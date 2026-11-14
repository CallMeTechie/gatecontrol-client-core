'use strict';

// Notizen & Aufgaben, plugin 1.5.0 (the words places, placeSearch of me.features — never a version): a task at a place
// in the Windows apps. The phone watches the places and reminds; a PC shows the place and lets it be changed. The pure
// helpers (utils/notes.js: a task's place, „Meine Orte“, the suggestion of the quick entry, the search answer, what the
// renderer may send — never a position), NotesService against the fake server (an older plugin stays as it was; the
// place from the typed line; choosing, changing, taking off; „Meine Orte“ and the remembered place; the search near one
// of the person's places, switched off, not reachable, busy; the consent; the person's switches) and the IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const N = require('../src/utils/notes');
const NotesService = require('../src/services/notes');
const ApiClient = require('../src/services/api-client');
const { registerNotesHandlers } = require('../src/ipc/notes-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { notesServer, FEATURES, STAGE1, STAGE2, STAGE3 } = require('./fixtures/notes-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const OLD = [...FEATURES, ...STAGE1, ...STAGE2];
const ALL = [...OLD, ...STAGE3];
const OSM = { text: '© OpenStreetMap', url: 'https://www.openstreetmap.org/copyright' };
const NORD = { ref: 'osm:W101', name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424 };

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(opts = {}, svcOpts = {}) {
  const srv = await notesServer(opts);
  cleanup.push(() => srv.close());
  const svc = new NotesService({
    apiClient: new ApiClient(srv.url, 'gc_token', log), log, store: createMemoryStore(), protect: null, getLang: () => 'de',
    pushClient: svcOpts.pushClient || null, notificationCenter: svcOpts.notificationCenter || null, dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc };
}
const asked = (srv, re) => srv.state.requests.filter((r) => re.test(`${r.method} ${r.path}`));
const code = async (p) => { try { await p; return null; } catch (err) { return err.code; } };

describe('utils/notes: plugin 1.5.0', () => {
  it('cleans a task\'s place, „Meine Orte“, the suggestion, the search answer and me.places', () => {
    const place = { mode: 'place', id: 1, name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, radius: 150, ref: 'osm:W101', own: false, trigger: 'enter', key: 'kind:diy',
      label: 'Baumarkt', by: 1, consent: 'accepted', watch: true, nearby: true, skipped: 0, later: null };
    assert.deepEqual(N.normalizeTask({ id: 41, title: 'x', place }).place, place);
    assert.equal(N.normalizeTask({ id: 41, title: 'x' }).place, null);
    assert.equal(N.normalizeTask({ id: 41, title: 'x', place: null }).place, null);
    // „Jeder Lidl“: no point, no radius; a place without a point or a name is none
    assert.deepEqual(N.normalizeTask({ id: 41, title: 'x', place: { mode: 'any', id: 7, name: 'Jeder Lidl', lat: 1, lon: 2, radius: 150, ref: 'osm:N1', trigger: 'exit', key: 'name:lidl', label: 'Lidl', consent: 'pending', later: '2026-11-08T13:00:00+01:00' } }).place,
      { mode: 'any', id: null, name: 'Jeder Lidl', address: '', lat: null, lon: null, radius: null, ref: null, own: false, trigger: 'exit', key: 'name:lidl', label: 'Lidl', by: null, consent: 'pending', watch: false, nearby: false, skipped: 0, later: '2026-11-08T13:00:00+01:00' });
    for (const bad of [{ mode: 'place', name: 'x', lat: 91, lon: 0 }, { mode: 'place', name: 'x', lat: '52', lon: 13 }, { mode: 'place', lat: 1, lon: 2 }, { mode: 'any', name: 'Jeder' }, 'Baumarkt', []]) assert.equal(N.normalizeTask({ id: 41, title: 'x', place: bad }).place, null, JSON.stringify(bad));
    const odd = N.normalizeTask({ id: 41, title: 'x', place: { ...place, name: ' Bau\u0007markt ', ref: 'javascript:alert(1)', trigger: 'sometimes', key: 'kind:<b>', consent: 'maybe', radius: 99999, skipped: -1 } }).place;
    assert.deepEqual([odd.name, odd.ref, odd.trigger, odd.key, odd.consent, odd.radius, odd.skipped], ['Bau markt', null, 'enter', null, 'accepted', 2000, 0]);
    assert.equal(N.normalizeTask({ id: 41, title: 'x', place: { ...place, ref: 'familie:home' } }).place.ref, 'familie:home');

    const own = { id: 2, name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2, radius: 150, named: true, ref: null, family: false, favFor: [], uses: 0, updatedAt: 1794128400000 };
    const all = N.normalizePlaces({ places: [{ ...own }, { id: 1, ...NORD, radius: 150, named: false, favFor: [{ key: 'kind:diy', label: 'Baumarkt' }, { key: 'x' }], updatedAt: 1794128400000 }, { id: 3, name: 'ohne Punkt' }, null],
      family: [{ familyId: 'home', name: 'Zuhause', lat: 52.5203, lon: 13.4051, radius: 150 }, { familyId: '../x', name: 'x', lat: 1, lon: 1 }], favs: [{ key: 'kind:diy', label: 'Baumarkt', placeId: 1, uses: 6 }, { key: 'kind:diy' }] });
    assert.deepEqual(all.places[0], own);
    assert.deepEqual([all.places.length, all.places[1].favFor, all.places[1].ref], [2, [{ key: 'kind:diy', label: 'Baumarkt' }], 'osm:W101']);
    assert.deepEqual(all.family, [{ familyId: 'home', name: 'Zuhause', address: '', lat: 52.5203, lon: 13.4051, radius: 150, family: true }]);
    assert.deepEqual(all.favs, [{ key: 'kind:diy', label: 'Baumarkt', placeId: 1, uses: 6 }]);
    assert.deepEqual(N.normalizePlaces(null), { places: [], family: [], favs: [] });

    const sug = N.normalizePlaceSuggest({ via: 'kind', word: 'beim Baumarkt', query: 'Baumarkt', key: 'kind:diy', label: 'Baumarkt', title: 'Schrauben kaufen', certain: true, trigger: 'enter', place: null, uses: 0, options: [], search: 'on' });
    assert.deepEqual(sug, { via: 'kind', word: 'beim Baumarkt', query: 'Baumarkt', key: 'kind:diy', label: 'Baumarkt', title: 'Schrauben kaufen', certain: true, trigger: 'enter', place: null, uses: 0, options: [], search: 'on' });
    const home = N.normalizePlaceSuggest({ via: 'family', word: 'zu Hause', label: 'Zuhause', title: 'Blumen gießen', certain: true, place: { familyId: 'home', name: 'Zuhause', address: '', lat: 52.5203, lon: 13.4051, radius: 150, family: true }, search: 'sometimes' });
    assert.deepEqual([home.place.familyId, home.place.family, home.key, home.search], ['home', true, null, 'off']);
    assert.deepEqual(N.normalizePlaceSuggest({ via: 'own', place: own, options: [own, { id: 'x' }], uses: 6 }).options, [own]);
    assert.deepEqual([N.normalizePlaceSuggest(null), N.normalizePlaceSuggest({ via: 'guess', key: 'kind:diy' })], [null, null]);

    const found = N.normalizePlaceSearch({ key: 'kind:diy', label: 'Baumarkt', kind: 'kind', radiusKm: 15, cell: { lat: 52.52, lon: 13.41 },
      results: [{ ...NORD, distanceM: 2315, minutes: 6, placeId: null, fav: false, uses: 0 }, { ref: 'https://evil.example', name: 'ohne Ref', address: '', lat: 1, lon: 2, distanceM: null, minutes: null }, { name: 'ohne Punkt' }],
      any: true, approx: true, attribution: OSM });
    assert.deepEqual(found.results, [{ ...NORD, distanceM: 2315, minutes: 6, placeId: null, fav: false, uses: 0 }, { ref: null, name: 'ohne Ref', address: '', lat: 1, lon: 2, distanceM: null, minutes: null, placeId: null, fav: false, uses: 0 }]);
    assert.deepEqual([found.key, found.label, found.kind, found.radiusKm, found.any, found.approx, found.attribution], ['kind:diy', 'Baumarkt', 'kind', 15, true, true, OSM]);
    // the position the server counted from is not handed on; a link that is not https is none
    assert.equal('cell' in found, false);
    assert.deepEqual(N.normalizePlaceSearch({ attribution: { text: '© OpenStreetMap', url: 'javascript:alert(1)' } }).attribution, { text: '© OpenStreetMap', url: null });
    assert.deepEqual(N.normalizePlaceSearch(null), { key: null, label: null, kind: 'name', radiusKm: 15, results: [], any: false, approx: true, attribution: null });

    const me = N.normalizeMe({ features: ['places', 'placeSearch'], places: { search: { state: 'on', enabled: true, mine: true, service: 'osm', radiusKm: 15, decimals: 2, attribution: OSM }, nearby: true, quiet: { from: '21:00', to: '07:00' }, perTask: 5,
      radius: { min: 50, max: 2000, default: 150 }, family: true }, prefs: { places: { search: true, nearby: false, quiet: { from: '22:00', to: '22:00' } } } });
    assert.deepEqual(me.places, { search: { state: 'on', enabled: true, mine: true, service: 'osm', radiusKm: 15, attribution: OSM }, nearby: true, quiet: { from: '21:00', to: '07:00' }, perTask: 5, radius: { min: 50, max: 2000, default: 150 }, family: true });
    assert.deepEqual(me.prefs.places, { search: true, nearby: false, quiet: null });
    assert.deepEqual([N.normalizeMe({}).places, 'places' in N.normalizeMe({}).prefs, N.normalizeMe({ places: { search: { state: '<on>' } } }).places.search.state], [null, false, 'off']);
    assert.deepEqual(N.changedOf({ what: ['places', 'tasks', 'nonsense'] }), { what: ['places', 'tasks'] });
    // „… möchte dich erinnern“: a click opens the task; the buttons are callbacks and stay what they are
    const consent = { notizen: { kind: 'place_consent', taskId: 41, listId: 3, area: 'private', task: 41 } };
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:shared', consent), { kind: 'task', taskId: 41 });
    assert.deepEqual(N.pushTarget('plugin:gatecontrol-notizen:shared', consent, 'place_accept'), { kind: 'task', taskId: 41 });
  });

  it('checks what the renderer may send: a task\'s place, a place, a search — never a position', () => {
    assert.equal(N.placeArg(null), null);
    assert.deepEqual(N.placeArg({ placeId: 2 }), { placeId: 2 });
    assert.deepEqual(N.placeArg({ placeId: 1, key: 'kind:diy', label: 'Baumarkt', trigger: 'exit', remember: true }), { trigger: 'exit', key: 'kind:diy', label: 'Baumarkt', placeId: 1, remember: true });
    assert.deepEqual(N.placeArg({ familyId: 'home', key: null }), { key: null, familyId: 'home' });
    assert.deepEqual(N.placeArg({ ...NORD, key: 'kind:diy', trigger: 'enter', remember: true, distanceM: 2315, minutes: 6, fav: false }), { trigger: 'enter', key: 'kind:diy', ref: 'osm:W101', name: 'Baumarkt Nord', lat: 52.539, lon: 13.424, address: 'Industriestraße 4, Berlin', remember: true });
    assert.deepEqual(N.placeArg({ name: 'Garten', lat: 52.4, lon: 13.2, radius: 300 }), { name: 'Garten', lat: 52.4, lon: 13.2, radius: 300 });
    assert.deepEqual(N.placeArg({ any: true, key: 'name:lidl', label: 'Lidl' }), { key: 'name:lidl', label: 'Lidl', any: true });
    assert.deepEqual(N.placeArg({ trigger: 'exit' }), { trigger: 'exit' });
    for (const bad of [{}, 'auto', [], { placeId: 'x' }, { placeId: 2, trigger: 'sometimes' }, { placeId: 2, key: 'kind:<b>' }, { familyId: '../home' }, { any: true }, { any: true, key: null }, { name: 'x', lat: 91, lon: 0 }, { lat: 52, lon: 13 },
      { name: 'x', lat: 52, lon: 13, ref: 'familie:home' }, { name: 'x', lat: 52, lon: 13, radius: 10 }, { placeId: 2, remember: true }, { any: true, key: 'name:lidl', remember: true }, { familyId: 'home', key: 'kind:diy', remember: true },
      { placeId: 2, key: 'kind:diy', remember: 'yes' }, { label: 'Baumarkt' }]) assert.equal(N.placeArg(bad), undefined, JSON.stringify(bad));

    assert.deepEqual(N.taskPatch({ place: null }), { place: null });
    assert.deepEqual(N.taskPatch({ place: { trigger: 'exit' } }), { place: { trigger: 'exit' } });
    assert.deepEqual([N.taskPatch({ place: 'auto' }), N.taskPatch({ place: { placeId: 0 } })], [null, null]);
    assert.deepEqual(N.taskCreate({ text: 'beim Baumarkt Schrauben kaufen', place: 'auto' }), { text: 'beim Baumarkt Schrauben kaufen', place: 'auto' });
    assert.deepEqual(N.taskCreate({ text: 'bei Oma Leiter zurückgeben', place: { placeId: 2 } }), { text: 'bei Oma Leiter zurückgeben', place: { placeId: 2 } });
    // no place for a new task: the field is not sent at all
    assert.deepEqual(N.taskCreate({ text: 'Rasen mähen', place: null }), { text: 'Rasen mähen' });
    assert.deepEqual([N.taskCreate({ text: 'x', place: 'always' }), N.taskCreate({ text: 'x', place: {} })], [null, null]);

    assert.deepEqual(N.placeCreate({ name: ' Oma ', address: 'Gartenweg 5', lat: 52.4, lon: 13.2, radius: 200 }), { name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2, radius: 200 });
    assert.deepEqual(N.placeCreate({ name: 'Ringstraße 21', lat: 52.5, lon: 13.3, ref: 'osm:W900' }), { name: 'Ringstraße 21', lat: 52.5, lon: 13.3, ref: 'osm:W900' });
    for (const bad of [{ name: '', lat: 1, lon: 2 }, { name: 'x', lat: 1 }, { name: 'x', lat: 1, lon: 181 }, { name: 'x', lat: 1, lon: 2, radius: 5000 }, { name: 'x', lat: 1, lon: 2, ref: 'osm:X1' }, null]) assert.equal(N.placeCreate(bad), null, JSON.stringify(bad));
    assert.deepEqual(N.placePatch({ name: 'Oma Erna', radius: 300, named: true }), { name: 'Oma Erna', radius: 300, named: true });
    assert.deepEqual([N.placePatch({ name: '' }), N.placePatch({ lat: 'x' }), N.placePatch({ named: 'yes' })], [null, null, null]);
    assert.deepEqual([N.favArg({ key: 'kind:diy', placeId: 1 }), N.favArg({ key: 'kind:diy', placeId: null }), N.favArg({ key: 'diy', placeId: 1 }), N.favArg({ key: 'kind:diy' })], [{ key: 'kind:diy', placeId: 1 }, { key: 'kind:diy', placeId: null }, null, null]);

    assert.deepEqual(N.placeSearchArg({ key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' }), { key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' });
    assert.deepEqual(N.placeSearchArg({ q: ' Lidl ', nearPlaceId: 2 }), { q: 'Lidl', nearPlaceId: 2 });
    assert.deepEqual(N.placeSearchArg({ q: 'Ringstraße 21', address: true }), { q: 'Ringstraße 21', address: true });
    // a position is never sent from a PC — coordinates are dropped, and without a place to search near the search is refused
    assert.deepEqual(N.placeSearchArg({ key: 'kind:diy', nearFamilyId: 'home', near: { lat: 52.5203, lon: 13.4051 } }), { key: 'kind:diy', nearFamilyId: 'home' });
    for (const bad of [{ key: 'kind:diy', near: { lat: 52.52, lon: 13.41 } }, { key: 'kind:diy' }, { q: 'L', nearPlaceId: 2 }, { q: 'x'.repeat(81), nearPlaceId: 2 }, { key: 'diy', nearPlaceId: 2 }, { q: 'Lidl', nearPlaceId: 'x' }, { q: 'Lidl', nearFamilyId: '../x' }, {}, null]) {
      assert.equal(N.placeSearchArg(bad), null, JSON.stringify(bad));
    }
    assert.deepEqual(N.placePrefsArg({ search: false, nearby: true, quiet: { from: '22:00', to: '06:30' } }), { search: false, nearby: true, quiet: { from: '22:00', to: '06:30' } });
    assert.deepEqual([N.placePrefsArg({ quiet: null }), N.placePrefsArg({ search: 'no' }), N.placePrefsArg({ quiet: { from: '25:00', to: '07:00' } }), N.placePrefsArg({})], [{ quiet: null }, null, null, null]);
  });
});

describe('NotesService: plugin 1.5.0 (a task at a place)', () => {
  it('an older plugin: nothing new is asked, nothing new is sent', async () => {
    const { srv, svc } = await setup({ features: OLD });
    assert.equal((await svc.me()).me.places, null);
    assert.deepEqual([(await svc.task(12)).task.place, (await svc.parse({ text: 'beim Baumarkt Schrauben kaufen' })).place], [null, null]);
    for (const p of [svc.places(), svc.createPlace({ name: 'Oma', lat: 1, lon: 2 }), svc.updatePlace(1, { name: 'x' }), svc.deletePlace(1), svc.setPlaceFav({ key: 'kind:diy', placeId: 1 }), svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' }),
      svc.placeConsent(12, true), svc.createTask({ text: 'beim Baumarkt Schrauben kaufen', place: 'auto' }), svc.updateTask(12, { place: null }), svc.setPrefs({ places: { search: false } })]) assert.equal(await code(p), 'unsupported');
    // a task without the field is made as before, the whole line as its title
    const r = await svc.createTask({ text: 'beim Baumarkt Schrauben kaufen' });
    assert.deepEqual([r.task.title, r.task.place, r.place], ['beim Baumarkt Schrauben kaufen', null, null]);
    assert.deepEqual(asked(srv, /\/api\/(places|tasks\/\d+\/place)/), []);
    assert.deepEqual(asked(srv, /POST .*\/api\/tasks$/).map((x) => x.body), [{ text: 'beim Baumarkt Schrauben kaufen' }]);
  });

  it('the place from the typed line: a kind is searched near home and remembered, an own place and home are decided', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const me = (await svc.me()).me;
    assert.deepEqual([me.places.search.state, me.places.family, me.places.search.attribution], ['on', true, OSM]);
    const p = await svc.parse({ text: 'beim Baumarkt Schrauben kaufen', area: 'private' });
    assert.deepEqual(p.place, { via: 'kind', word: 'beim Baumarkt', query: 'Baumarkt', key: 'kind:diy', label: 'Baumarkt', title: 'Schrauben kaufen', certain: true, trigger: 'enter', place: null, uses: 0, options: [], search: 'on' });
    // the parser itself knows nothing of the place: the title stays whole there
    assert.equal(p.parsed.title, 'beim Baumarkt Schrauben kaufen');
    assert.equal(srv.state.placeSearches.length, 0);
    // the person asks: near „Zuhause“ — a place to search near goes out, no position
    const found = await svc.searchPlaces({ key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' });
    assert.deepEqual(srv.state.placeSearches, [{ key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' }]);
    assert.deepEqual(found.results.map((x) => [x.name, x.minutes, x.distanceM > 1000, x.placeId]), [['Baumarkt Nord', 6, true, null], ['Baumarkt am Ring', 10, true, null], ['Baumarkt Süd', 22, true, null]]);
    assert.deepEqual([found.any, found.label, found.radiusKm, found.attribution], [true, 'Baumarkt', 15, OSM]);
    // the hit goes back unchanged, remembered as „mein Baumarkt“; the words of the place leave the title
    const hit = found.results[0];
    const made = await svc.createTask({ text: 'beim Baumarkt Schrauben kaufen', area: 'private', place: N.placeArg({ ref: hit.ref, name: hit.name, address: hit.address, lat: hit.lat, lon: hit.lon, key: 'kind:diy', label: 'Baumarkt', trigger: 'enter', remember: true }) });
    assert.equal(made.task.title, 'Schrauben kaufen');
    assert.deepEqual([made.task.place.mode, made.task.place.name, made.task.place.ref, made.task.place.key, made.task.place.label, made.task.place.trigger, made.task.place.consent, made.task.place.watch, made.task.place.nearby],
      ['place', 'Baumarkt Nord', 'osm:W101', 'kind:diy', 'Baumarkt', 'enter', 'accepted', true, true]);
    assert.equal(made.place.title, 'Schrauben kaufen');
    // the next time the remembered place is decided; `place: 'auto'` sets it without asking
    const again = await svc.parse({ text: 'beim Baumarkt Dübel holen' });
    assert.deepEqual([again.place.place.name, again.place.uses, again.place.options.length, again.place.certain], ['Baumarkt Nord', 1, 1, true]);
    const auto = await svc.createTask({ text: 'beim Baumarkt Dübel holen', place: 'auto' });
    assert.deepEqual([auto.task.title, auto.task.place.id, auto.task.place.key], ['Dübel holen', made.task.place.id, 'kind:diy']);
    // not surely meant („Apotheke anrufen“): a suggestion only — 'auto' sets nothing
    const unsure = await svc.createTask({ text: 'Apotheke anrufen', place: 'auto' });
    assert.deepEqual([unsure.task.title, unsure.task.place, unsure.place.certain, unsure.place.key], ['Apotheke anrufen', null, false, 'kind:pharmacy']);
    // an own place by its name, a place of the family
    const oma = (await svc.createPlace({ name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2 })).place;
    assert.deepEqual([oma.name, oma.named, oma.radius], ['Oma', true, 150]);
    const atOma = await svc.parse({ text: 'bei Oma Leiter zurückgeben' });
    assert.deepEqual([atOma.place.via, atOma.place.key, atOma.place.place.id, atOma.place.title], ['own', null, oma.id, 'Leiter zurückgeben']);
    const t1 = await svc.createTask({ text: 'bei Oma Leiter zurückgeben', place: { placeId: oma.id } });
    assert.deepEqual([t1.task.title, t1.task.place.own, t1.task.place.nearby, t1.task.place.key], ['Leiter zurückgeben', true, false, null]);
    const atHome = await svc.parse({ text: 'zu Hause Blumen gießen' });
    assert.deepEqual([atHome.place.via, atHome.place.place.familyId, atHome.place.place.family], ['family', 'home', true]);
    const t2 = await svc.createTask({ text: 'zu Hause Blumen gießen', place: { familyId: 'home' } });
    assert.deepEqual([t2.task.title, t2.task.place.name, t2.task.place.ref], ['Blumen gießen', 'Zuhause', 'familie:home']);
    // the chip taken away: no field, the title stays whole
    const plain = await svc.createTask({ text: 'beim Baumarkt Farbe holen' });
    assert.deepEqual([plain.task.title, plain.task.place, plain.place], ['beim Baumarkt Farbe holen', null, null]);
    // a PC watches nothing: what a phone watches and what fired is never asked
    assert.deepEqual(asked(srv, /\/api\/places\/(watch|fired)|\/place\/(skip|later)/), []);
  });

  it('a task\'s place chosen, changed and taken off; „Jeder Lidl“; „Meine Orte“ and the remembered place', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const lidl = await svc.searchPlaces({ q: 'Lidl', nearFamilyId: 'home' });
    assert.deepEqual([lidl.key, lidl.label, lidl.kind, lidl.results.map((x) => x.name)], ['name:lidl', 'Lidl', 'name', ['Lidl Marktstraße', 'Lidl Bahnhofsplatz']]);
    const any = (await svc.updateTask(12, { place: { any: true, key: 'name:lidl', label: 'Lidl' } })).task.place;
    assert.deepEqual([any.mode, any.name, any.lat, any.radius, any.key, any.nearby], ['any', 'Jeder Lidl', null, null, 'name:lidl', false]);
    const one = (await svc.updateTask(12, { place: { ...N.placeArg({ ...lidl.results[1], key: 'name:lidl', label: 'Lidl' }) } })).task.place;
    assert.deepEqual([one.mode, one.name, one.trigger, one.nearby], ['place', 'Lidl Bahnhofsplatz', 'enter', true]);
    // only the trigger: the place stays
    const out = (await svc.updateTask(12, { place: { trigger: 'exit' } })).task.place;
    assert.deepEqual([out.id, out.trigger, out.nearby], [one.id, 'exit', false]);
    assert.equal((await svc.view({ name: 'myday', area: 'private' })).view.sections.flatMap((s) => s.items).find((x) => x.id === 12).place.name, 'Lidl Bahnhofsplatz');
    assert.equal((await svc.updateTask(12, { place: null })).task.place, null);
    assert.equal(srv.state.taskPlace.has(12), false);
    // a place taken once is none of „Meine Orte“ until it is remembered or named
    assert.deepEqual((await svc.places()).places, []);
    const favs = (await svc.setPlaceFav({ key: 'name:lidl', placeId: one.id })).favs;
    assert.deepEqual(favs, [{ key: 'name:lidl', label: 'Lidl', placeId: one.id, uses: 1 }]);
    let all = await svc.places();
    assert.deepEqual([all.places.map((x) => [x.name, x.named, x.favFor]), all.family.map((f) => f.familyId)], [[['Lidl Bahnhofsplatz', false, [{ key: 'name:lidl', label: 'Lidl' }]]], ['home', 'place:3']]);
    // the remembered one comes first in the next search and is one of the own places there
    const next = await svc.searchPlaces({ key: 'name:lidl', nearPlaceId: one.id });
    assert.deepEqual(next.results.map((x) => [x.name, x.fav, x.placeId]), [['Lidl Bahnhofsplatz', true, one.id], ['Lidl Marktstraße', false, null]]);
    assert.deepEqual((await svc.setPlaceFav({ key: 'name:lidl', placeId: null })).favs, []);
    // an own place: made, changed, deleted (a second time: gone)
    const oma = (await svc.createPlace({ name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2 })).place;
    assert.deepEqual([(await svc.updatePlace(oma.id, { name: 'Oma Erna', radius: 300 })).place.name, srv.state.places.get(oma.id).radius], ['Oma Erna', 300]);
    all = await svc.places();
    assert.deepEqual(all.places.map((x) => x.name), ['Oma Erna']);
    assert.deepEqual([await svc.deletePlace(oma.id), await svc.deletePlace(oma.id)], [{ ok: true, gone: false }, { ok: true, gone: true }]);
    assert.deepEqual([await code(svc.updateTask(12, { place: { placeId: oma.id } })), await code(svc.updateTask(12, { place: { familyId: 'place:99' } }))], ['not_found', 'not_found']);
    // an address is searched without a place to search near (the first place a person saves)
    const adr = await svc.searchPlaces({ q: 'Ringstraße 21', address: true });
    assert.deepEqual([adr.kind, adr.key, adr.any, adr.results.map((x) => [x.name, x.distanceM, x.minutes])], ['address', null, false, [['Ringstraße 21', null, null]]]);
  });

  it('the search: off for the person, off by the administrator, not reachable, busy — the server is not asked while it is off', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const prefs = (await svc.setPrefs({ places: { search: false, quiet: null } })).prefs;
    assert.deepEqual([prefs.places, srv.state.prefs.places.nearby], [{ search: false, nearby: true, quiet: null }, true]);
    let me = (await svc.me({ refresh: true })).me;
    assert.deepEqual([me.places.search.state, me.places.search.enabled, me.places.search.mine, me.places.quiet], ['off', true, false, null]);
    assert.equal((await svc.parse({ text: 'beim Baumarkt Schrauben kaufen' })).place.search, 'off');
    assert.equal(await code(svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' })), 'module_off');
    assert.equal(srv.state.placeSearches.length, 0);
    await svc.setPrefs({ places: { search: true } });
    srv.state.placeCfg.mode = 'off';
    me = (await svc.me({ refresh: true })).me;
    assert.deepEqual([me.places.search.state, me.places.search.enabled, me.places.search.service], ['off', false, 'off']);
    assert.equal(await code(svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' })), 'module_off');
    // switched off while the page still thinks it is on: the server says so
    srv.state.placeCfg.mode = 'osm';
    await svc.me({ refresh: true });
    srv.state.placeCfg.mode = 'off';
    const off = await svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' }).catch((e) => e);
    assert.deepEqual([off.status, off.code, off.body.reason], [403, 'module_off', 'admin']);
    srv.state.placeCfg = { mode: 'osm', down: true };
    const down = await svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' }).catch((e) => e);
    assert.deepEqual([down.status, down.code], [503, 'unavailable']);
    srv.state.placeCfg.down = false;
    srv.state.fail['POST places/search'] = { status: 429, code: 'busy', extra: { retryAfter: 20, reason: 'limit' } };
    const busy = await svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' }).catch((e) => e);
    assert.deepEqual([busy.status, busy.code, busy.body.retryAfter], [429, 'busy', 20]);
    // an own service that is not set up: not asked either
    delete srv.state.fail['POST places/search'];
    srv.state.placeCfg = { mode: 'own', down: true };
    await svc.me({ refresh: true });
    const before = srv.state.placeSearches.length;
    assert.equal(await code(svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'home' })), 'unavailable');
    assert.equal(srv.state.placeSearches.length, before);
    // a search without a known place to search near
    srv.state.placeCfg = { mode: 'osm', down: false };
    await svc.me({ refresh: true });
    assert.equal(await code(svc.searchPlaces({ key: 'kind:diy', nearFamilyId: 'place:99' })), 'not_found');
  });

  it('a place someone else set: shown, not watched until the person agrees; the push opens the task', async () => {
    const nc = { routes: [], addClickRoute(route, fn) { this.routes.push({ route, fn }); return () => {}; } };
    const { srv, svc } = await setup({ features: ALL }, { notificationCenter: nc });
    const lidl = srv.addPlace({ name: 'Lidl Marktstraße', address: 'Marktstraße 3, Berlin', lat: 52.526, lon: 13.401, named: false, ref: 'osm:N201' });
    const task = srv.addTask({ title: 'Milch mitbringen', due: { date: '2026-11-08', time: null } });
    srv.setTaskPlace(task.id, { placeId: lidl.id, key: 'name:lidl', label: 'Lidl', by: 12, who: 1 });
    let p = (await svc.task(task.id)).task.place;
    assert.deepEqual([p.name, p.by, p.consent, p.watch], ['Lidl Marktstraße', 12, 'pending', false]);
    const push = { topic: 'plugin:gatecontrol-notizen:shared', data: { notizen: { kind: 'place_consent', taskId: task.id, listId: 1, area: 'private', task: task.id }, actions: [{ id: 'place_accept', label: 'Annehmen', type: 'callback' }, { id: 'place_decline', label: 'Ablehnen', type: 'callback' }] } };
    assert.deepEqual(nc.routes[0].fn(push, null), { kind: 'task', taskId: task.id });
    assert.deepEqual(await svc.placeConsent(task.id, true), { ok: true, consent: 'accepted' });
    p = (await svc.task(task.id)).task.place;
    assert.deepEqual([p.consent, p.watch], ['accepted', true]);
    assert.deepEqual(await svc.placeConsent(task.id, false), { ok: true, consent: 'declined' });
    assert.equal((await svc.task(task.id)).task.place.watch, false);
    assert.deepEqual(asked(srv, /\/place\/consent$/).map((r) => r.body), [{ accept: true }, { accept: false }]);
    // only the person whose task it is may answer
    srv.setTaskPlace(12, { placeId: lidl.id, by: 1, who: 12 });
    assert.equal(await code(svc.placeConsent(12, true)), 'forbidden');
    assert.equal(await code(svc.placeConsent(11, true)), 'invalid');
  });

  it('the live event `places` reaches the page', async () => {
    const pc = new EventEmitter();
    const { svc } = await setup({ features: ALL }, { pushClient: pc });
    const changed = [];
    svc.on('changed', (c) => changed.push(c.what));
    pc.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-notizen', type: 'changed', data: { what: ['tasks', 'places'] } } });
    assert.deepEqual(changed, [['tasks', 'places']]);
  });
});

describe('ipc/notes-handlers: plugin 1.5.0', () => {
  it('checks a place, a search and the consent; a position never goes out; refuses for an older plugin', async () => {
    const { srv, svc } = await setup({ features: ALL });
    const handlers = {};
    registerNotesHandlers((ch, fn) => { handlers[ch] = fn; }, { notes: svc, getMainWindow: () => null, log });
    const call = (ch, arg) => handlers[ch]({}, arg);
    assert.deepEqual((await call('notes:places', {})).family.map((f) => f.name), ['Zuhause', 'Schule']);
    for (const bad of [{}, { place: { name: '', lat: 1, lon: 2 } }, { place: { name: 'x', lat: 'a', lon: 2 } }]) assert.deepEqual([(await call('notes:place:create', bad)).code, (await call('notes:place:create', bad)).field], ['invalid', 'place']);
    const oma = (await call('notes:place:create', { place: { name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2 } })).place;
    assert.deepEqual([(await call('notes:place:update', { id: oma.id, patch: {} })).code, (await call('notes:place:update', { id: oma.id, patch: { radius: 5 } })).code, (await call('notes:place:update', { id: oma.id, patch: { radius: 500 } })).place.radius], ['invalid', 'invalid', 500]);
    assert.deepEqual([(await call('notes:place:fav', { key: 'diy', placeId: oma.id })).field, (await call('notes:place:fav', { key: 'kind:diy', placeId: oma.id })).favs.length, (await call('notes:place:fav', { key: 'kind:diy' })).favs.length], ['key', 1, 0]);
    // the renderer cannot make the main process send coordinates as a position
    assert.deepEqual([(await call('notes:place:search', { key: 'kind:diy', near: { lat: 52.5203, lon: 13.4051 } })).field, (await call('notes:place:search', { q: 'B', nearFamilyId: 'home' })).code], ['near', 'invalid']);
    const found = await call('notes:place:search', { key: 'kind:diy', label: 'Baumarkt', nearPlaceId: oma.id, near: { lat: 52.5203, lon: 13.4051 } });
    assert.deepEqual([found.ok, found.results.length, srv.state.placeSearches], [true, 3, [{ key: 'kind:diy', label: 'Baumarkt', nearPlaceId: oma.id }]]);
    srv.state.fail['POST places/search'] = { status: 429, code: 'busy', extra: { retryAfter: 20, reason: 'limit' } };
    const busy = await call('notes:place:search', { key: 'kind:diy', nearPlaceId: oma.id });
    assert.deepEqual([busy.ok, busy.code, busy.status, busy.retryAfter, busy.reason], [false, 'busy', 429, 20, 'limit']);
    delete srv.state.fail['POST places/search'];
    assert.deepEqual([(await call('notes:task:update', { id: 12, patch: { place: { placeId: 'x' } } })).code, (await call('notes:task:update', { id: 12, patch: { place: { placeId: oma.id, trigger: 'exit' } } })).task.place.trigger], ['invalid', 'exit']);
    assert.deepEqual([(await call('notes:task:create', { task: { text: 'x', place: 'always' } })).code, (await call('notes:task:create', { task: { text: 'bei Oma Leiter zurückgeben', place: 'auto' } })).task.place.name], ['invalid', 'Oma']);
    assert.deepEqual([(await call('notes:task:place:consent', { id: 12 })).field, (await call('notes:task:place:consent', { id: 12, accept: true })).consent], ['accept', 'accepted']);
    assert.deepEqual([(await call('notes:prefs:set', { patch: { places: { search: 'no' } } })).field, (await call('notes:prefs:set', { patch: { places: { nearby: false } } })).prefs.places.nearby], ['places', false]);
    assert.equal((await call('notes:parse', { text: 'zu Hause Blumen gießen', area: 'private' })).place.place.familyId, 'home');
    assert.deepEqual((await call('notes:place:delete', { id: oma.id })).ok, true);

    const old = await setup({ features: OLD });
    const h2 = {};
    registerNotesHandlers((ch, fn) => { h2[ch] = fn; }, { notes: old.svc, getMainWindow: () => null, log });
    assert.deepEqual([(await h2['notes:places']({}, {})).code, (await h2['notes:place:search']({}, { key: 'kind:diy', nearFamilyId: 'home' })).code, (await h2['notes:task:create']({}, { task: { text: 'beim Baumarkt', place: 'auto' } })).code,
      (await h2['notes:task:place:consent']({}, { id: 12, accept: true })).code, (await h2['notes:prefs:set']({}, { patch: { places: { search: false } } })).code], ['unsupported', 'unsupported', 'unsupported', 'unsupported', 'unsupported']);
    assert.deepEqual(asked(old.srv, /\/api\/places|\/place\//), []);
  });
});
