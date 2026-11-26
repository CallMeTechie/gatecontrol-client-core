'use strict';

// „Mein Profil › Meine Orte“ (GateControl 1.299.0): utils/places.js, PlacesService with the real ApiClient against the
// fake of test/fixtures/places-server.js, the IPC (ipc/places-handlers.js) and the push control event `places`.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');

const P = require('../src/utils/places');
const { PlacesService } = require('../src/services/places');
const { registerPlacesHandlers, PLACES_EVENTS } = require('../src/ipc/places-handlers');
const PushClient = require('../src/services/push-client');
const PushControl = require('../src/services/push-control');
const ApiClient = require('../src/services/api-client');
const { placesServer } = require('./fixtures/places-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };

describe('utils/places', () => {
  it('cleans a place: ref, icon, visibility, radius, „kein Standort“ for 0/0 or a point out of range', () => {
    const p = P.normalizePlace({ id: 12, name: '  Arbeit\n', icon: 'work', lat: '50.110922', lon: 8.682127, radiusM: 5000, address: '', visibility: 'all', updatedAt: '2026-11-18 09:12:44',
      usedBy: [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 2 }, { plugin: 'BAD', kind: 'task', count: 1 }, { plugin: 'x', kind: 'task', count: 0 }] });
    assert.equal(p.ref, 'profile:12');
    assert.equal(p.name, 'Arbeit');
    assert.equal(p.lat, 50.110922);
    assert.equal(p.hasPoint, true);
    assert.equal(p.radiusM, 2000);
    assert.equal(p.address, null);
    assert.equal(p.visibility, 'all');
    assert.equal(p.updatedAt, '2026-11-18T09:12:44.000Z');
    assert.deepEqual(p.usedBy, [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 2 }]);
    const none = P.normalizePlace({ id: 3, name: 'Alt', lat: 0, lon: 0, icon: 'castle', visibility: 'world' });
    assert.equal(none.hasPoint, false);
    assert.equal(none.lat, null);
    assert.equal(none.icon, 'pin');
    assert.equal(none.visibility, 'self');
    assert.equal(P.normalizePlace({ id: 0, name: 'x', lat: 1, lon: 1 }), null);
    assert.equal(P.normalizePlace({ id: 4, name: ' ', lat: 1, lon: 1 }), null);
  });

  it('a list answer: each id once, the options, the search mode; a foreign place carries its owner and no usedBy', () => {
    const l = P.normalizeList({ places: [{ id: 1, name: 'A', lat: 1, lon: 1 }, { id: 1, name: 'B', lat: 1, lon: 1 }], family: true, search: 'own',
      shared: [{ id: 9, name: 'Oma', lat: 2, lon: 2, own: false, ownerId: 4, ownerName: 'Kim Beispiel', usedBy: [{ plugin: 'a', kind: 'task', count: 1 }] }] });
    assert.equal(l.places.length, 1);
    assert.equal(l.family, true);
    assert.equal(l.search, 'own');
    assert.deepEqual(l.icons, P.ICONS);
    assert.deepEqual(l.limits.radius, { min: 50, max: 2000, default: 150 });
    assert.deepEqual(l.shared[0].usedBy, []);
    assert.equal(l.shared[0].ownerName, 'Kim Beispiel');
    assert.equal(P.normalizeList({ ok: true }), null);
    assert.equal(P.normalizeList({ places: [], search: 'google' }).search, 'off');
  });

  it('bodies: only the known keys, lat and lon together, never 0/0, an emptied address clears', () => {
    assert.deepEqual(P.createBody({ name: ' Schule ', lat: 50.1234567, lon: 8.1, icon: 'school', radiusM: 150, address: '', visibility: 'family' }),
      { name: 'Schule', lat: 50.123457, lon: 8.1, icon: 'school', radiusM: 150, visibility: 'family' });
    assert.throws(() => P.createBody({ name: 'A', lat: 0, lon: 0 }), (e) => e.field === 'lat');
    assert.throws(() => P.createBody({ name: 'A', lat: 1 }), (e) => e.field === 'lon');
    assert.throws(() => P.createBody({ name: 'A', lat: 1, lon: 1, favorite: true }), (e) => e.field === 'favorite');
    assert.throws(() => P.createBody({ name: 'A', lat: 1, lon: 1, radiusM: 10 }), (e) => e.field === 'radiusM');
    assert.throws(() => P.patchBody({ lat: 1 }), (e) => e.field === 'lon');
    assert.deepEqual(P.patchBody({ address: null }), { address: null });
    assert.deepEqual(P.patchBody({}), {});
  });

  it('the editor\'s draft → only what changed (point together, emptied address null)', () => {
    const old = P.normalizePlace({ id: 12, name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, address: 'Hafenstraße 4', visibility: 'self' });
    assert.deepEqual(P.diffBody(old, { name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, address: 'Hafenstraße 4', visibility: 'self' }), {});
    assert.deepEqual(P.diffBody(old, { name: 'Büro', icon: 'work', lat: 50.2, lon: 8.682127, radiusM: 250, address: '', visibility: 'family' }),
      { name: 'Büro', lat: 50.2, lon: 8.682127, radiusM: 250, address: null, visibility: 'family' });
  });

  it('the search: 3–120 characters, near rounded to two places (~1 km) on this PC', () => {
    assert.deepEqual(P.searchArg({ q: ' bau ', near: { lat: 50.110922, lon: 8.682127 } }), { q: 'bau', near: '50.11,8.68' });
    assert.deepEqual(P.searchArg({ q: 'Bauhaus', near: '50.119,8.6' }), { q: 'Bauhaus', near: '50.12,8.60' });
    assert.throws(() => P.searchArg({ q: 'ba' }), (e) => e.field === 'q');
    assert.throws(() => P.searchArg({ q: 'x'.repeat(121) }), (e) => e.field === 'q');
    assert.throws(() => P.searchArg({ q: 'bau', near: { lat: 0, lon: 0 } }), (e) => e.field === 'near');
  });

  it('refs: profile:<id>, Familie\'s home / place:<id>', () => {
    assert.equal(P.idOfRef('profile:12'), 12);
    assert.equal(P.idOfRef('profile:0'), null);
    assert.equal(P.idOfRef('Profile:1'), null);
    assert.ok(P.isRef('home') && P.isRef('place:3') && !P.isRef('profile: 1') && !P.isRef('profile:1:2'));
  });
});

describe('PlacesService against the fake GateControl', () => {
  let srv;
  let api;
  let svc;
  let pc;
  beforeEach(async () => {
    srv = await placesServer();
    api = new ApiClient(srv.url, 'gc_token', log, null, { clientType: 'pro' });
    pc = new EventEmitter();
    svc = new PlacesService({ apiClient: api, log, pushClient: pc, timing: { cacheTtlMs: 60000 } });
    svc.start();
  });
  afterEach(async () => { svc.stop(); await srv.close(); });

  it('lists the places, from memory a second time; a network error answers the last copy (stale)', async () => {
    const r = await svc.list();
    assert.equal(r.ok, true);
    assert.deepEqual(r.places.map((p) => p.name), ['Zuhause', 'Arbeit', 'Fitnessstudio', 'Baumarkt']);
    assert.equal(r.places[0].ref, 'profile:11');
    assert.equal(r.search, 'osm');
    assert.equal(svc.status().state, 'available');
    await svc.list();
    assert.equal(srv.calls.filter((c) => c.method === 'GET').length, 1);
    await srv.close();
    const stale = await svc.list({ refresh: true });
    assert.equal(stale.stale, true);
    assert.equal(stale.places.length, 4);
  });

  it('an older GateControl (404 without a code) is unsupported', async () => {
    srv.unsupported = true;
    await assert.rejects(svc.list(), (e) => e.code === 'unsupported');
    assert.equal(svc.status().state, 'unsupported');
  });

  it('creates, changes, marks used and deletes — the copy follows, „changed“ is emitted locally', async () => {
    await svc.list();
    const seen = [];
    svc.on('changed', (c) => seen.push(c));
    const c = await svc.create({ name: 'Schule', icon: 'school', lat: 50.08, lon: 8.65, radiusM: 150, visibility: 'family' });
    assert.equal(c.place.ref, `profile:${c.place.id}`);
    assert.deepEqual(srv.calls.at(-1).body, { name: 'Schule', icon: 'school', lat: 50.08, lon: 8.65, radiusM: 150, visibility: 'family' });
    const u = await svc.update(c.place.id, { radiusM: 300, address: null });
    assert.equal(u.place.radiusM, 300);
    assert.deepEqual(srv.calls.at(-1).body, { radiusM: 300, address: null });
    const used = await svc.markUsed(c.place.id);
    assert.ok(used.place.lastUsedAt);
    const before = srv.calls.length;
    await svc.update(c.place.id, {});
    assert.equal(srv.calls.length, before, 'an empty patch asks nothing');
    const list = await svc.list();
    assert.equal(list.places.find((p) => p.id === c.place.id).radiusM, 300);
    await svc.remove(c.place.id);
    assert.equal((await svc.list()).places.some((p) => p.id === c.place.id), false);
    assert.deepEqual(seen.map((x) => [x.deleted, x.origin]), [[false, 'local'], [false, 'local'], [true, 'local']]);
  });

  it('refusals keep the server\'s code (lower case), field and usedBy; force deletes a place in use', async () => {
    await assert.rejects(svc.create({ name: 'arbeit', lat: 50, lon: 8 }), (e) => e.code === 'duplicate' && e.field === 'name');
    await assert.rejects(svc.create({ name: 'A', lat: 0, lon: 0 }), (e) => e.code === 'invalid' && e.body.field === 'lat');
    await assert.rejects(svc.update(999, { name: 'X' }), (e) => e.code === 'not_found');
    await assert.rejects(svc.remove(12), (e) => e.code === 'in_use' && e.usedBy[0].kind === 'location_message');
    const r = await svc.remove(12, { force: true });
    assert.deepEqual(r, { ok: true, deleted: true, id: 12 });
    assert.equal(srv.calls.at(-1).query.force, '1');
    srv.fail('/api/v1/client/me/profile/places', 429, 'RATE_LIMITED', 1);
    await assert.rejects(svc.create({ name: 'B', lat: 1, lon: 1 }), (e) => e.code === 'rate_limited');
  });

  it('searches the server (near rounded); off at the server → this PC\'s map service answers (via device)', async () => {
    const r = await svc.search({ q: 'bau', near: { lat: 50.110922, lon: 8.682127 } });
    assert.equal(r.via, 'server');
    assert.deepEqual(r.results.map((h) => h.name), ['Bauhaus', 'Baustoffhandel Nord']);
    assert.equal(r.results[0].distanceM, 6000);
    assert.equal(srv.calls.at(-1).query.near, '50.11,8.68');
    assert.equal(r.attribution.text, '© OpenStreetMap');

    srv.state.search = 'off';
    await assert.rejects(svc.search({ q: 'Hafenstraße' }), (e) => e.code === 'search_off');
    const asked = [];
    svc.maps = { search: async (q, o) => { asked.push([q, o.lang]); return [{ lat: 50.11, lon: 8.68, label: 'Hafenstraße 4, 60311 Musterstadt' }, { lat: 0, lon: 0, label: 'x' }]; } };
    const d = await svc.search({ q: 'Hafenstraße' }, { lang: 'en' });
    assert.equal(d.via, 'device');
    assert.deepEqual(d.results, [{ name: 'Hafenstraße 4', address: 'Hafenstraße 4, 60311 Musterstadt', lat: 50.11, lon: 8.68, source: 'osm', distanceM: null }]);
    assert.deepEqual(asked, [['Hafenstraße', 'en']]);
    await assert.rejects(svc.search({ q: 'ab' }), (e) => e.code === 'invalid');
  });

  it('push: the control event `places` and a reconnect drop the copy and emit „changed“', async () => {
    await svc.list();
    const seen = [];
    svc.on('changed', (c) => seen.push(c));
    pc.emit('control', { type: 'places', ids: [12], deleted: false });
    pc.emit('control', { type: 'config_changed' });
    await svc.list();
    assert.equal(srv.calls.filter((c) => c.method === 'GET').length, 2);
    pc.emit('hello', {});
    assert.deepEqual(seen.map((c) => [c.ids, c.origin]), [[[12], 'push'], [[], 'reconnect']]);
  });

  it('a new server drops everything', async () => {
    await svc.list();
    svc.resetForNewServer();
    assert.equal(svc.status().state, 'unknown');
    assert.equal(svc.status().count, 0);
  });
});

describe('push stream: control `places`', () => {
  it('normalizeControl keeps ids (positive, ≤ 100, once) and deleted; PushControl passes it on', () => {
    const c = PushClient.normalizeControl({ type: 'places', ids: [12, 12, -1, 'x', 13], deleted: true, name: 'Arbeit' });
    assert.deepEqual(c, { type: 'places', ids: [12, 13], deleted: true });
    assert.deepEqual(PushClient.normalizeControl({ type: 'places' }), { type: 'places', ids: [], deleted: false });
    const pc = new EventEmitter();
    pc.controlSupported = () => true;
    const ctl = new PushControl({ pushClient: pc, log });
    const seen = [];
    ctl.on('control', (x) => seen.push(x));
    ctl.handleControl(c);
    assert.deepEqual(seen, [c]);
  });
});

describe('IPC places:*', () => {
  function setup(service) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerPlacesHandlers((ch, fn) => { handlers[ch] = fn; }, { places: service, maps: null, getMainWindow: () => win, log });
    return { handlers, sent, call: (ch, arg) => handlers[ch]({}, arg) };
  }

  it('checks what the renderer sends before the service is asked; forwards the events', async () => {
    const asked = [];
    const svc = Object.assign(new EventEmitter(), {
      status: () => ({ state: 'available' }),
      create: async (p) => { asked.push(['create', p]); return { ok: true, place: { id: 1 } }; },
      update: async (id, p) => { asked.push(['update', id, p]); return { ok: true }; },
      remove: async (id, o) => { asked.push(['remove', id, o]); return { ok: true }; },
      search: async (a, o) => { asked.push(['search', a, o]); return { ok: true, results: [] }; },
      list: async () => { const e = new Error('nope'); e.code = 'in_use'; e.usedBy = [{ plugin: 'a', kind: 'task', count: 1 }]; e.field = 'id'; throw e; },
    });
    const { call, sent, handlers } = setup(svc);
    assert.deepEqual(Object.keys(handlers).sort(), ['places:create', 'places:delete', 'places:get', 'places:list', 'places:map:reverse', 'places:map:tile', 'places:search', 'places:status', 'places:update', 'places:used']);
    assert.deepEqual(await call('places:create', { place: { name: 'A', lat: 1, lon: 1, evil: 1 } }), { ok: false, code: 'invalid', error: 'invalid argument', status: null, field: 'evil' });
    assert.equal((await call('places:update', { id: -1, patch: {} })).field, 'id');
    assert.equal((await call('places:update', { id: 2, patch: { lat: 1 } })).field, 'lon');
    assert.equal((await call('places:search', { q: 'ab' })).field, 'q');
    assert.equal((await call('places:map:tile', { z: 1, x: 0, y: 0 })).code, 'unavailable');
    await call('places:create', { place: { name: 'A', lat: 1, lon: 1 } });
    await call('places:delete', { id: 3, force: 'yes' });
    await call('places:delete', { id: 3, force: true });
    await call('places:search', { q: 'bau', near: { lat: 50.1, lon: 8.6 }, lang: 'fr' });
    assert.deepEqual(asked, [
      ['create', { name: 'A', lat: 1, lon: 1 }],
      ['remove', 3, { force: false }],
      ['remove', 3, { force: true }],
      ['search', { q: 'bau', near: { lat: 50.1, lon: 8.6 } }, { lang: undefined }],
    ]);
    const f = await call('places:list', {});
    assert.deepEqual(f, { ok: false, code: 'in_use', error: 'nope', status: null, field: 'id', usedBy: [{ plugin: 'a', kind: 'task', count: 1 }] });
    svc.emit('changed', { ids: [1], deleted: false, origin: 'push' });
    assert.deepEqual(sent, [[PLACES_EVENTS.changed, { ids: [1], deleted: false, origin: 'push' }]]);
  });
});
