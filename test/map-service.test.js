'use strict';

// MapService (services/map-service.js): OpenStreetMap tiles with the app's
// User-Agent, a bounded number of requests at a time, one request per tile,
// LRU cache, stale copy on failure; Nominatim search / reverse one request
// at a time with a gap, cached, short address labels.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const MapService = require('../src/services/map-service');
const { userAgentFor, tileCoords, shortAddress, MapError } = MapService;

const PNG = (n = 8) => Buffer.alloc(n, 1);

/** Fake axios: answers from `route(url)`; `hold` keeps requests open until released. */
function fakeHttp(route, { hold = false } = {}) {
  const calls = [];
  const waiting = [];
  const http = {
    calls,
    waiting,
    get: (url, config) => {
      calls.push({ url, config });
      const answer = () => Promise.resolve().then(() => route(url, config));
      if (!hold) return answer();
      return new Promise((resolve, reject) => waiting.push(() => answer().then(resolve, reject)));
    },
    releaseAll() { while (waiting.length) waiting.shift()(); },
  };
  return http;
}

const tileOk = () => ({ status: 200, headers: { 'content-type': 'image/png' }, data: PNG() });

describe('MapService helpers', () => {
  it('User-Agent names the application and the project', () => {
    assert.equal(userAgentFor('GateControl Pro Client', '1.30.0'), 'GateControl-Pro-Client/1.30.0 (+https://github.com/CallMeTechie/gatecontrol)');
    assert.equal(userAgentFor(null, null), 'GateControl-Client (+https://github.com/CallMeTechie/gatecontrol)');
  });

  it('tile coordinates inside the zoom level only', () => {
    assert.deepEqual(tileCoords(0, 0, 0), { z: 0, x: 0, y: 0 });
    assert.deepEqual(tileCoords(19, 524287, 1), { z: 19, x: 524287, y: 1 });
    assert.equal(tileCoords(20, 0, 0), null);
    assert.equal(tileCoords(2, 4, 0), null);
    assert.equal(tileCoords(2, -1, 0), null);
    assert.equal(tileCoords(1.5, 0, 0), null);
    assert.equal(tileCoords('a', 0, 0), null);
  });

  it('short address: street + number, postcode + place; name first; fallback display_name', () => {
    assert.equal(shortAddress({ address: { road: 'Marienplatz', house_number: '8', postcode: '80331', city: 'München' }, display_name: 'long' }), 'Marienplatz 8, 80331 München');
    assert.equal(shortAddress({ name: 'Rathaus', address: { road: 'Marienplatz', town: 'Erding' } }), 'Rathaus, Marienplatz, Erding');
    assert.equal(shortAddress({ name: 'Erding', address: { town: 'Erding', postcode: '85435' } }), '85435 Erding');
    assert.equal(shortAddress({ display_name: 'Somewhere, Earth' }), 'Somewhere, Earth');
    assert.equal(shortAddress({ address: { country: 'Deutschland' } }), 'Deutschland');
    assert.equal(shortAddress(null), '');
    assert.equal(shortAddress({ display_name: 'a\u0000b'.padEnd(400, 'x') }).length, 200);
  });
});

describe('MapService tiles', () => {
  it('fetches with the User-Agent, caches, refuses invalid tiles', async () => {
    const http = fakeHttp(tileOk);
    const maps = new MapService({ http, userAgent: 'UA/1', tileUrl: 'https://tiles.example/' });
    const a = await maps.tile(3, 4, 2);
    assert.equal(a.mime, 'image/png');
    assert.equal(a.data.length, 8);
    assert.equal(http.calls[0].url, 'https://tiles.example/3/4/2.png');
    assert.equal(http.calls[0].config.headers['User-Agent'], 'UA/1');
    assert.equal(http.calls[0].config.responseType, 'arraybuffer');
    await maps.tile(3, 4, 2);
    assert.equal(http.calls.length, 1, 'second call from the cache');
    await assert.rejects(maps.tile(3, 8, 0), (e) => e instanceof MapError && e.code === 'invalid');
    assert.equal(http.calls.length, 1);
  });

  it('one request per tile, at most maxActive at a time, busy beyond the queue', async () => {
    const http = fakeHttp(tileOk, { hold: true });
    const maps = new MapService({ http, maxActive: 2, maxQueue: 1 });
    const same = [maps.tile(5, 1, 1), maps.tile(5, 1, 1)];
    const other = maps.tile(5, 2, 1);
    const queued = maps.tile(5, 3, 1);
    await assert.rejects(maps.tile(5, 4, 1), (e) => e.code === 'busy');
    await new Promise((r) => setImmediate(r));
    assert.equal(http.calls.length, 2, 'two at a time, the same tile only once');
    http.releaseAll();
    await Promise.all([...same, other]);
    await new Promise((r) => setImmediate(r));
    http.releaseAll();
    await queued;
    assert.deepEqual(http.calls.map((c) => c.url.split('/').slice(-3).join('/')), ['5/1/1.png', '5/2/1.png', '5/3/1.png']);
    assert.equal(maps._active, 0);
  });

  it('errors: 404, server error, network; a stale copy wins over an error', async () => {
    let answer = tileOk;
    let t = 1000;
    const http = fakeHttp(() => answer());
    const maps = new MapService({ http, tileTtlMs: 100, now: () => t });
    await maps.tile(1, 0, 0);
    t += 500; // expired
    answer = () => ({ status: 503, headers: {}, data: Buffer.from('busy') });
    assert.equal((await maps.tile(1, 0, 0)).data.length, 8, 'stale copy');
    await assert.rejects(maps.tile(1, 1, 0), (e) => e.code === 'unavailable' && e.status === 503);
    answer = () => ({ status: 404, headers: {}, data: Buffer.alloc(0) });
    await assert.rejects(maps.tile(1, 1, 1), (e) => e.code === 'not_found');
    answer = () => { throw new Error('ECONNRESET'); };
    await assert.rejects(maps.tile(1, 0, 1), (e) => e.code === 'network');
    answer = () => ({ status: 200, headers: { 'content-type': 'text/html' }, data: Buffer.from('<html>') });
    await assert.rejects(maps.tile(2, 0, 1), (e) => e.code === 'unavailable');
    assert.equal(maps._active, 0);
  });

  it('LRU: the cache stays below its byte limit', async () => {
    const http = fakeHttp(() => ({ status: 200, headers: { 'content-type': 'image/png' }, data: PNG(100) }));
    const maps = new MapService({ http, cacheMaxBytes: 250 });
    await maps.tile(2, 0, 0);
    await maps.tile(2, 1, 0);
    await maps.tile(2, 0, 0); // refresh → 2/1/0 is the oldest
    await maps.tile(2, 2, 0);
    assert.ok(maps._tileBytes <= 250);
    assert.deepEqual([...maps._tiles.keys()], ['2/0/0', '2/2/0']);
  });
});

describe('MapService addresses', () => {
  it('search: one request at a time with a gap, results with short labels, cached', async () => {
    let t = 10000;
    const slept = [];
    const http = fakeHttp((url) => {
      if (url.includes('/search?')) {
        return {
          status: 200,
          data: [
            { lat: '48.137', lon: '11.575', display_name: 'Marienplatz, Altstadt, München, Bayern, 80331, Deutschland', address: { road: 'Marienplatz', postcode: '80331', city: 'München' } },
            { lat: 'x', lon: '1' },
          ],
        };
      }
      return { status: 200, data: { display_name: 'Am Bahnhof 1, Erding', address: { road: 'Am Bahnhof', house_number: '1', town: 'Erding' } } };
    });
    const maps = new MapService({
      http, userAgent: 'UA/1', geocodeUrl: 'https://geo.example', geocodeGapMs: 1000, now: () => t,
      sleep: async (ms) => { slept.push(ms); t += ms; },
    });
    const [r1, r2] = await Promise.all([maps.search('  Marienplatz ', { lang: 'en' }), maps.reverse(48.30612345, 11.90712345)]);
    assert.deepEqual(r1, [{ lat: 48.137, lon: 11.575, label: 'Marienplatz, 80331 München' }]);
    assert.deepEqual(r2, { label: 'Am Bahnhof 1, Erding' });
    const u1 = new URL(http.calls[0].url);
    assert.equal(u1.origin + u1.pathname, 'https://geo.example/search');
    assert.equal(u1.searchParams.get('q'), 'Marienplatz');
    assert.equal(u1.searchParams.get('accept-language'), 'en');
    assert.equal(u1.searchParams.get('format'), 'jsonv2');
    assert.equal(http.calls[0].config.headers['User-Agent'], 'UA/1');
    const u2 = new URL(http.calls[1].url);
    assert.equal(u2.pathname, '/reverse');
    assert.equal(u2.searchParams.get('lat'), '48.306123');
    assert.equal(u2.searchParams.get('accept-language'), 'de');
    assert.deepEqual(slept, [1000], 'second request waits for its turn');
    await maps.search('marienplatz', { lang: 'en' });
    await maps.reverse(48.30614, 11.90709);
    assert.equal(http.calls.length, 2, 'both from the cache');
  });

  it('search refuses too short queries; errors become codes; a failure does not block the next', async () => {
    let answer = () => ({ status: 429, data: null });
    const http = fakeHttp(() => answer());
    const maps = new MapService({ http, geocodeGapMs: 0 });
    await assert.rejects(maps.search(' a '), (e) => e.code === 'invalid');
    await assert.rejects(maps.reverse(91, 0), (e) => e.code === 'invalid');
    await assert.rejects(maps.search('Erding'), (e) => e.code === 'rate_limited');
    answer = () => ({ status: 500, data: null });
    await assert.rejects(maps.search('Erding'), (e) => e.code === 'unavailable');
    answer = () => { throw new Error('ENOTFOUND'); };
    await assert.rejects(maps.search('Erding'), (e) => e.code === 'network');
    answer = () => ({ status: 200, data: { error: 'Unable to geocode' } });
    assert.deepEqual(await maps.reverse(0, 0), { label: null });
    answer = () => ({ status: 200, data: '[{"lat":"1","lon":"2","display_name":"X"}]' });
    assert.deepEqual(await maps.search('Erding'), [{ lat: 1, lon: 2, label: 'X' }]);
  });
});
