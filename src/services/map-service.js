'use strict';

/**
 * Map data for the Chats page ("Standort senden", location previews):
 * OpenStreetMap tiles and address search / reverse geocoding (Nominatim),
 * fetched by the main process and handed to the renderer as bytes / plain
 * data over IPC (chat:map:*). The renderer never talks to the internet itself
 * (CSP `img-src 'self' data: blob:`).
 *
 * Why not the GateControl tile relay (`/plugins/_shared/tiles/<token>/…`):
 * its token is minted only for the sandboxed map frames of `ui.maps`
 * plugins; a device token cannot get one. Like the Android app (osmdroid),
 * the client loads the tiles itself and follows the OSM tile usage policy
 * the same way the relay does:
 *
 *   * a User-Agent naming the application (`GateControl-Pro-Client/1.30.0
 *     (+https://github.com/CallMeTechie/gatecontrol)`),
 *   * at most MAX_ACTIVE tile requests at a time, the rest in a bounded
 *     queue (`busy` beyond it), one request per tile however many views ask,
 *   * a memory cache (LRU, CACHE_MAX_BYTES, kept TILE_TTL_MS);
 *
 * and the Nominatim usage policy:
 *
 *   * the same User-Agent, at most one request per GEOCODE_GAP_MS (requests
 *     wait for their turn, one at a time), results cached,
 *   * no autocomplete: the page searches on Enter / button only.
 *
 * What leaves the PC: the map area shown (tiles) and the searched address /
 * picked point (Nominatim) — to OpenStreetMap, not to the GateControl server.
 */

const axios = require('axios');

const TILE_URL = 'https://tile.openstreetmap.org';
const GEOCODE_URL = 'https://nominatim.openstreetmap.org';
const PROJECT_URL = 'https://github.com/CallMeTechie/gatecontrol';
const MAX_ZOOM = 19;
const MAX_ACTIVE = 2;
const MAX_QUEUE = 96;
const MAX_TILE_BYTES = 512 * 1024;
const CACHE_MAX_BYTES = 32 * 1024 * 1024;
const TILE_TTL_MS = 24 * 3600 * 1000;
const TIMEOUT_MS = 10 * 1000;
const GEOCODE_GAP_MS = 1100;
const GEOCODE_CACHE = 64;
const QUERY_MAX = 200;
const LABEL_MAX = 200;
const RESULTS_MAX = 5;

class MapError extends Error {
  constructor(code, message, status = null) {
    super(message || code);
    this.code = code;
    this.status = status;
  }
}

/** "GateControl Pro Client", "1.30.0" → "GateControl-Pro-Client/1.30.0 (+https://github.com/…)". */
function userAgentFor(name, version) {
  const product = String(name || 'GateControl-Client').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'GateControl-Client';
  const ver = String(version || '').replace(/[^A-Za-z0-9._-]+/g, '');
  return `${product}${ver ? `/${ver}` : ''} (+${PROJECT_URL})`;
}

/** { z, x, y } as numbers, or null outside 0 ≤ z ≤ 19, 0 ≤ x, y < 2^z. */
function tileCoords(z, x, y) {
  const c = { z: Number(z), x: Number(x), y: Number(y) };
  if (![c.z, c.x, c.y].every((v) => Number.isSafeInteger(v) && v >= 0)) return null;
  const n = 2 ** c.z;
  return c.z <= MAX_ZOOM && c.x < n && c.y < n ? c : null;
}

/** Latitude / longitude as numbers in range, or null. */
function latLon(lat, lon) {
  const a = Number(lat);
  const o = Number(lon);
  if (!Number.isFinite(a) || !Number.isFinite(o) || Math.abs(a) > 90 || Math.abs(o) > 180) return null;
  return { lat: a, lon: o };
}

const langOf = (lang) => (lang === 'en' ? 'en' : 'de');
const clip = (s, n) => String(s || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);

/**
 * Short address of a Nominatim result: "Marienplatz 8, 80331 München"
 * (street + number, postcode + place), else its name, else display_name.
 */
function shortAddress(r) {
  if (!r || typeof r !== 'object') return '';
  const a = r.address && typeof r.address === 'object' ? r.address : {};
  const street = a.road || a.pedestrian || a.footway || a.path || a.square || a.cycleway || null;
  const place = a.city || a.town || a.village || a.hamlet || a.municipality || a.suburb || a.county || null;
  const parts = [];
  const name = typeof r.name === 'string' && r.name.trim() ? r.name.trim() : null;
  if (name && name !== street && name !== place) parts.push(name);
  if (street) parts.push(a.house_number ? `${street} ${a.house_number}` : street);
  if (place) parts.push(a.postcode ? `${a.postcode} ${place}` : place);
  if (!parts.length && !place && a.country) parts.push(a.country);
  const label = parts.length ? parts.join(', ') : (r.display_name || '');
  return clip(label, LABEL_MAX);
}

class MapService {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log]
   * @param {Function} [opts.http] - axios-like: http.get(url, config) → { status, data, headers }
   * @param {string} [opts.userAgent] - userAgentFor(app name, version)
   * @param {string} [opts.tileUrl] - tile server ({z}/{x}/{y}.png below it)
   * @param {string} [opts.geocodeUrl] - Nominatim base URL
   * @param {() => string} [opts.getLang] - default language for addresses ('de' | 'en')
   */
  constructor({
    log = null, http = axios, userAgent = userAgentFor(), tileUrl = TILE_URL, geocodeUrl = GEOCODE_URL,
    getLang = () => 'de', maxActive = MAX_ACTIVE, maxQueue = MAX_QUEUE, cacheMaxBytes = CACHE_MAX_BYTES,
    tileTtlMs = TILE_TTL_MS, timeoutMs = TIMEOUT_MS, geocodeGapMs = GEOCODE_GAP_MS,
    now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  } = {}) {
    this.log = log;
    this.http = http;
    this.userAgent = userAgent;
    this.tileUrl = String(tileUrl).replace(/\/+$/, '');
    this.geocodeUrl = String(geocodeUrl).replace(/\/+$/, '');
    this.getLang = getLang;
    this.maxActive = maxActive;
    this.maxQueue = maxQueue;
    this.cacheMaxBytes = cacheMaxBytes;
    this.tileTtlMs = tileTtlMs;
    this.timeoutMs = timeoutMs;
    this.geocodeGapMs = geocodeGapMs;
    this.now = now;
    this.sleep = sleep;

    this._tiles = new Map();      // key → { data, at }  (insertion order = LRU)
    this._tileBytes = 0;
    this._inflight = new Map();   // key → Promise
    this._active = 0;
    this._queue = [];             // resolvers waiting for a slot
    this._geoChain = Promise.resolve();
    this._geoLast = 0;
    this._geoCache = new Map();   // key → result (LRU)
    this._failLogged = 0;
  }

  // ── Tiles ─────────────────────────────────────────────────

  /**
   * One 256 px PNG tile.
   * @returns {Promise<{ mime: 'image/png', data: Buffer }>}
   * @throws {MapError} invalid | busy | not_found | network | unavailable
   */
  async tile(z, x, y) {
    const c = tileCoords(z, x, y);
    if (!c) throw new MapError('invalid', 'invalid tile');
    const key = `${c.z}/${c.x}/${c.y}`;
    const hit = this._tiles.get(key);
    if (hit && this.now() - hit.at < this.tileTtlMs) {
      this._tiles.delete(key);
      this._tiles.set(key, hit);
      return { mime: 'image/png', data: hit.data };
    }
    if (this._inflight.has(key)) return this._inflight.get(key);
    const p = this._fetchTile(key, hit).finally(() => this._inflight.delete(key));
    this._inflight.set(key, p);
    return p;
  }

  async _fetchTile(key, stale) {
    await this._slot();
    try {
      const res = await this.http.get(`${this.tileUrl}/${key}.png`, {
        responseType: 'arraybuffer',
        timeout: this.timeoutMs,
        maxContentLength: MAX_TILE_BYTES,
        maxRedirects: 2,
        validateStatus: () => true,
        headers: { 'User-Agent': this.userAgent, Accept: 'image/png' },
      });
      const type = String((res.headers && (res.headers['content-type'] || res.headers['Content-Type'])) || '');
      if (res.status === 200 && /^image\/png\b/i.test(type) && res.data && res.data.byteLength) {
        const data = Buffer.from(res.data);
        this._store(key, data);
        return { mime: 'image/png', data };
      }
      if (stale) return { mime: 'image/png', data: stale.data };
      if (res.status === 404) throw new MapError('not_found', 'tile not found', 404);
      this._logFail(`tile ${key}: HTTP ${res.status}`);
      throw new MapError('unavailable', `tile server answered ${res.status}`, res.status);
    } catch (err) {
      if (err instanceof MapError) throw err;
      if (stale) return { mime: 'image/png', data: stale.data };
      this._logFail(`tile ${key}: ${err.message}`);
      throw new MapError('network', err.message);
    } finally {
      this._release();
    }
  }

  _store(key, data) {
    const old = this._tiles.get(key);
    if (old) { this._tileBytes -= old.data.length; this._tiles.delete(key); }
    this._tiles.set(key, { data, at: this.now() });
    this._tileBytes += data.length;
    for (const [k, v] of this._tiles) {
      if (this._tileBytes <= this.cacheMaxBytes) break;
      this._tiles.delete(k);
      this._tileBytes -= v.data.length;
    }
  }

  _slot() {
    if (this._active < this.maxActive) { this._active++; return Promise.resolve(); }
    if (this._queue.length >= this.maxQueue) return Promise.reject(new MapError('busy', 'too many tile requests'));
    return new Promise((resolve) => this._queue.push(resolve));
  }

  _release() {
    const next = this._queue.shift();
    if (next) next(); else this._active--;
  }

  _logFail(msg) {
    // A broken connection fails every tile — log once a minute at most.
    const t = this.now();
    if (!this.log || t - this._failLogged < 60000) return;
    this._failLogged = t;
    this.log.warn(`Map: ${msg}`);
  }

  // ── Addresses (Nominatim) ─────────────────────────────────

  /**
   * Address search (on Enter / button, never while typing).
   * @returns {Promise<Array<{ lat: number, lon: number, label: string }>>}
   * @throws {MapError} invalid | network | unavailable | rate_limited
   */
  async search(q, { lang } = {}) {
    const query = clip(q, QUERY_MAX);
    if (query.length < 2) throw new MapError('invalid', 'query too short');
    const l = langOf(lang || this.getLang());
    const key = `s|${l}|${query.toLowerCase()}`;
    const data = await this._geocode(key, '/search', {
      q: query, format: 'jsonv2', addressdetails: '1', limit: String(RESULTS_MAX), 'accept-language': l,
    });
    const list = Array.isArray(data) ? data : [];
    const out = [];
    for (const r of list) {
      const p = r && latLon(r.lat, r.lon);
      if (!p) continue;
      out.push({ lat: p.lat, lon: p.lon, label: shortAddress(r) || `${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}` });
      if (out.length >= RESULTS_MAX) break;
    }
    return out;
  }

  /**
   * Address of a point (label for a picked / own position).
   * @returns {Promise<{ label: string|null }>}
   */
  async reverse(lat, lon, { lang } = {}) {
    const p = latLon(lat, lon);
    if (!p) throw new MapError('invalid', 'invalid position');
    const l = langOf(lang || this.getLang());
    // ~10 m grid: a slightly different click asks again only when it matters.
    const la = p.lat.toFixed(4);
    const lo = p.lon.toFixed(4);
    const data = await this._geocode(`r|${l}|${la}|${lo}`, '/reverse', {
      lat: p.lat.toFixed(6), lon: p.lon.toFixed(6), format: 'jsonv2', zoom: '18', addressdetails: '1', 'accept-language': l,
    });
    const label = data && !data.error ? shortAddress(data) : '';
    return { label: label || null };
  }

  _geocode(key, path, params) {
    if (this._geoCache.has(key)) {
      const v = this._geoCache.get(key);
      this._geoCache.delete(key);
      this._geoCache.set(key, v);
      return Promise.resolve(v);
    }
    // One request at a time, GEOCODE_GAP_MS apart (Nominatim: max. 1/s).
    const run = async () => {
      const wait = this._geoLast + this.geocodeGapMs - this.now();
      if (wait > 0) await this.sleep(wait);
      this._geoLast = this.now();
      let res;
      try {
        res = await this.http.get(`${this.geocodeUrl}${path}?${new URLSearchParams(params)}`, {
          responseType: 'json',
          timeout: this.timeoutMs,
          maxContentLength: 1024 * 1024,
          maxRedirects: 2,
          validateStatus: () => true,
          headers: { 'User-Agent': this.userAgent, Accept: 'application/json', 'Accept-Language': params['accept-language'] },
        });
      } catch (err) {
        this._logFail(`geocoding: ${err.message}`);
        throw new MapError('network', err.message);
      }
      if (res.status === 429) throw new MapError('rate_limited', 'geocoding rate limited', 429);
      if (res.status !== 200) {
        this._logFail(`geocoding: HTTP ${res.status}`);
        throw new MapError('unavailable', `geocoder answered ${res.status}`, res.status);
      }
      let data = res.data;
      if (typeof data === 'string') { try { data = JSON.parse(data); } catch { data = null; } }
      this._geoCache.set(key, data);
      while (this._geoCache.size > GEOCODE_CACHE) this._geoCache.delete(this._geoCache.keys().next().value);
      return data;
    };
    const p = this._geoChain.then(run, run);
    this._geoChain = p.catch(() => null);
    return p;
  }
}

module.exports = MapService;
module.exports.MapService = MapService;
module.exports.MapError = MapError;
module.exports.userAgentFor = userAgentFor;
module.exports.tileCoords = tileCoords;
module.exports.shortAddress = shortAddress;
