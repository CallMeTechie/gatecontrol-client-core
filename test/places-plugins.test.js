'use strict';

// „Meine Orte“ in the plugins' forms on Windows: Messenger 1.28 (`profilePlaces`: GET places — the source of the place
// choice, Familie's places as before without the word) and Notizen 1.8.0 (`profilePlaces`: the places are the
// profile's — ref profile:<id>, symbol, visibility, „Genutzt von“, 409 in_use with force, notMoved, a task's place by
// its reference). Fixtures: test/fixtures/messenger-server.js, test/fixtures/notes-server.js.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const NotesService = require('../src/services/notes');
const U = require('../src/utils/messenger');
const N = require('../src/utils/notes');
const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
const { registerNotesHandlers } = require('../src/ipc/notes-handlers');
const { messengerServer, API, FEATURES_14 } = require('./fixtures/messenger-server');
const { notesServer, FEATURES, STAGE3, STAGE6 } = require('./fixtures/notes-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };

const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

function ipc(register, deps) {
  const handlers = {};
  register((ch, fn) => { handlers[ch] = fn; }, { getMainWindow: () => null, log, ...deps });
  return (ch, arg) => handlers[ch]({}, arg);
}

describe('Messenger 1.28: the source of the place choice', () => {
  async function setup(features, familie = true) {
    const srv = await messengerServer({ features, familie });
    cleanups.push(() => srv.close());
    const m = new MessengerService({ apiClient: new ApiClient(srv.url, 'gc_token', log), store: createMemoryStore(), log, timing: FAST });
    cleanups.push(() => m.stop());
    m.start();
    await m.check();
    return { srv, m };
  }

  it('with profilePlaces: GET places — own profile places and Familie\'s, with ref, in the Messenger\'s order', async () => {
    const { srv, m } = await setup({ ...FEATURES_14, placeMessages: true, profilePlaces: true });
    assert.deepEqual(m.status().updateHint || null, null);
    const call = ipc(registerMessengerHandlers, { messenger: m, maps: null });
    const r = await call('chat:places', { all: true });
    assert.equal(r.ok, true);
    assert.equal(r.profile, true);
    assert.deepEqual(r.sources, { profile: true, familie: true });
    assert.deepEqual(r.places.map((p) => [p.ref, p.source, p.id, p.icon, p.rank]), [['profile:12', 'profile', 12, 'work', 0], ['home', 'familie', 'home', 'home', 1]]);
    assert.equal(r.places[0].address, 'Hafenstraße 4, Musterstadt');
    assert.equal(r.places[0].usageCount, 3);
    assert.ok(srv.state.requests.some((q) => q.path === `${API}places`));
    // the old call stays Familie's places (an older renderer keeps working)
    const old = await call('chat:places', {});
    assert.deepEqual(old.places.map((p) => p.id), ['home']);
  });

  it('without the word: Familie\'s places as before (source familie, ref home / place:<id>); without Familie: none', async () => {
    const { srv, m } = await setup({ ...FEATURES_14, placeMessages: true });
    srv.state.places.push({ id: 5, name: 'Grundschule', lat: 50.12, lon: 8.66, radiusM: 150 });
    const r = await m.pickPlaces();
    assert.equal(r.profile, false);
    assert.deepEqual(r.places.map((p) => [p.ref, p.source, p.id]), [['home', 'familie', 'home'], ['place:5', 'familie', 5]]);
    assert.ok(!srv.state.requests.some((q) => q.path === `${API}places`));
    const none = await setup({ ...FEATURES_14 }, false);
    assert.deepEqual((await none.m.pickPlaces()).places, []);
  });

  it('normalizePickPlace: invalid refs, 0/0 and names left out or marked', () => {
    assert.equal(U.normalizePickPlace({ ref: 'profile:0', name: 'A', lat: 1, lon: 1 }), null);
    assert.equal(U.normalizePickPlace({ ref: 'Profile:1', name: 'A', lat: 1, lon: 1 }), null);
    assert.equal(U.normalizePickPlace({ ref: 'home', name: ' ', lat: 1, lon: 1 }), null);
    const p = U.normalizePickPlace({ ref: 'profile:3', name: 'Alt', lat: 0, lon: 0, icon: 'castle', usageCount: -2 });
    assert.deepEqual([p.lat, p.lon, p.icon, p.usageCount], [null, null, 'pin', 0]);
    assert.deepEqual(U.normalizePickPlaces([{ ref: 'home', name: 'Zuhause', lat: 1, lon: 1 }, { ref: 'home', name: 'Doppelt', lat: 1, lon: 1 }]).length, 1);
  });
});

describe('Notizen 1.8.0: the places are the profile\'s', () => {
  async function setup() {
    const srv = await notesServer({ features: [...FEATURES, ...STAGE3, ...STAGE6] });
    cleanups.push(() => srv.close());
    const svc = new NotesService({ apiClient: new ApiClient(srv.url, 'gc_token', log), log, store: createMemoryStore(), protect: null, getLang: () => 'de', dialogPath: () => null, timing: { retryMinMs: 10, retryMaxMs: 20 } });
    svc.start();
    cleanups.push(() => svc.stop());
    await svc.check();
    return { srv, svc, call: ipc(registerNotesHandlers, { notes: svc }) };
  }

  it('GET places: ref profile:<id>, symbol, visibility, usedBy, profile, notMoved; me.places.profile', async () => {
    const { srv, svc, call } = await setup();
    srv.state.notMoved.push({ name: 'Garten', reason: 'invalid', field: 'lat' });
    const c = await call('notes:place:create', { place: { name: 'Oma', lat: 50.12, lon: 8.66, icon: 'family', visibility: 'family' } });
    assert.equal(c.ok, true);
    assert.equal(c.place.ref, `profile:${c.place.id}`);
    assert.equal(c.place.icon, 'family');
    const r = await svc.places();
    assert.equal(r.profile, true);
    assert.deepEqual(r.notMoved, [{ name: 'Garten', reason: 'invalid', field: 'lat' }]);
    assert.deepEqual(r.places[0].usedBy, []);
    const me = await svc.me();
    assert.deepEqual((me.me || me).places.profile, { places: true, edit: 'plugin' });
    const u = await call('notes:place:update', { id: c.place.id, patch: { visibility: 'all' } });
    assert.equal(u.place.visibility, 'all');
    assert.equal((await call('notes:place:update', { id: c.place.id, patch: { icon: 'castle' } })).code, 'invalid');
  });

  it('DELETE: in_use with usedBy while another plugin uses the place; force deletes it all the same', async () => {
    const { srv, call } = await setup();
    const c = await call('notes:place:create', { place: { name: 'Arbeit', lat: 50.11, lon: 8.68 } });
    srv.state.placeUses.set(c.place.id, [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }]);
    const r = await call('notes:place:delete', { id: c.place.id });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'in_use');
    assert.deepEqual(r.usedBy, [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }]);
    assert.equal(r.ref, `profile:${c.place.id}`);
    const f = await call('notes:place:delete', { id: c.place.id, force: true });
    assert.equal(f.ok, true);
    assert.equal(srv.state.requests.at(-1).query.force, '1');
  });

  it('a task\'s place by the profile\'s reference; the old plugin refs stay valid', () => {
    assert.deepEqual(N.placeArg({ ref: 'profile:12', trigger: 'enter' }), { trigger: 'enter', ref: 'profile:12' });
    assert.equal(N.placeArg({ ref: 'profile:0' }), undefined);
    assert.deepEqual(N.placeArg({ ref: 'osm:N12', name: 'Bauhaus', lat: 50.09, lon: 8.7 }), { ref: 'osm:N12', name: 'Bauhaus', lat: 50.09, lon: 8.7 });
    assert.equal(N.normalizePlace({ id: 12, name: 'Arbeit', lat: 50.1, lon: 8.6, ref: 'profile:12' }).ref, 'profile:12');
  });
});
