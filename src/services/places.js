'use strict';

/**
 * GateControl – Meine Orte (Core service)
 *
 * The data side of „Mein Profil › Meine Orte“ in the Windows apps and the source of the shared place choice of the
 * forms (Chats, Notizen): the person's own places in the profile of GateControl ≥ 1.299.0 (utils/places.js has the
 * contract), over the device token of the existing ApiClient.
 *
 * - list({ refresh }) reads GET …/me/profile/places; answers younger than a few seconds come from memory, a network
 *   error answers with the last copy (`stale: true`). A server without the route (404 without a code) is
 *   `unsupported` — the page says „ab GateControl 1.299“, the forms offer what the plugins offer, as before.
 * - create / update / remove / markUsed change the profile; the copy in memory follows at once and 'changed' is
 *   emitted ({ ids, deleted, origin: 'local' }) — the server tells every other device of the person, never the one that
 *   made the change. A refusal comes back with the server's code in lower case (`invalid` + `field`, `duplicate`,
 *   `limit`, `in_use` + `usedBy`, `not_found`, `rate_limited`, …); remove({ force: true }) deletes a place in use.
 * - search({ q, near }) asks GateControl's address search (only when the person asks: „Suchen“ / Enter, from 3
 *   characters; `near` rounded to ~1 km on this PC). When the administrator switched it off (`search: 'off'` or 403
 *   SEARCH_OFF), the map service of this PC (OpenStreetMap Nominatim, services/map-service.js) answers instead —
 *   `via: 'device'` says so. 429 brings `retryAfter` (seconds).
 * - Push (GateControl's stream, services/push-client.js): the control event `places` ({ ids, deleted }) drops the copy
 *   and emits 'changed' ({ origin: 'push' }); a reconnect does the same (a change while offline has no catch-up).
 *   Windows watches no places (that stays the phone's job) — the pages just load again.
 *
 * Events: 'changed' ({ ids, deleted, origin: 'local' | 'push' | 'reconnect' }), 'state' (status()).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const P = require('../utils/places');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  cacheTtlMs: 10 * 1000, // answers younger than this are served from memory
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** A refusal → { code (lower case), status, field?, usedBy?, retryAfter? } on a MessengerError. */
function placesError(err) {
  const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
  const body = e.body && typeof e.body === 'object' ? e.body : null;
  // 404 without a code of the profile: a server before „Meine Orte“ (the route is missing)
  if (e.status === 404 && !(body && typeof body.code === 'string')) e.code = 'unsupported';
  else if (typeof e.code === 'string') e.code = e.code.toLowerCase();
  if (body) {
    if (typeof body.field === 'string' && /^[A-Za-z0-9_.]{1,40}$/.test(body.field)) e.field = body.field;
    if (Array.isArray(body.usedBy)) e.usedBy = P.usedByOf(body.usedBy);
    if (Number.isSafeInteger(body.retryAfter) && body.retryAfter > 0) e.retryAfter = Math.min(body.retryAfter, 3600);
  }
  return e;
}

class PlacesService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.pushClient] - PushClient: control `places` and a reconnect ('hello') drop the copy
   * @param {object} [opts.maps] - MapService: the address search of this PC while the server's is off
   * @param {() => string} [opts.getLang] - 'de' | 'en' (the map service's addresses)
   * @param {object} [opts.http] - MessengerApi-compatible transport (_call) for tests
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({ apiClient, log, pushClient = null, maps = null, getLang = () => 'de', http = null, timing = {}, now = Date.now } = {}) {
    super();
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.pushClient = pushClient;
    this.maps = maps;
    this.getLang = getLang;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this._list = null;        // the last list answer (normalized)
    this._at = 0;             // when it came
    this._fresh = false;      // false after a push / reconnect / change elsewhere
    this._inflight = null;
    this._state = 'unknown';  // unknown | available | unsupported | error
    this._scope = this._scopeNow();
    this._unsub = [];
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._unsub.length) return;
    const pc = this.pushClient;
    if (!pc || typeof pc.on !== 'function') return;
    const onControl = (c) => {
      if (!c || c.type !== 'places') return;
      this._drop();
      this.emit('changed', { ids: Array.isArray(c.ids) ? c.ids.slice(0, 100) : [], deleted: c.deleted === true, origin: 'push' });
    };
    // a reconnect: what changed while offline is not caught up by the stream — load again
    const onHello = () => {
      if (!this._list) return;
      this._drop();
      this.emit('changed', { ids: [], deleted: false, origin: 'reconnect' });
    };
    pc.on('control', onControl);
    pc.on('hello', onHello);
    this._unsub.push(() => pc.removeListener('control', onControl), () => pc.removeListener('hello', onHello));
  }

  stop() {
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: the old server's places go. */
  resetForNewServer() {
    this._list = null;
    this._at = 0;
    this._inflight = null;
    this._scope = this._scopeNow();
    this._setState('unknown');
    this.emit('changed', { ids: [], deleted: false, origin: 'reset' });
  }

  /** { state, search, family, count } — what the menu needs without asking the server. */
  status() {
    const l = this._list;
    return { state: this._state, search: l ? l.search : null, family: l ? l.family : false, count: l ? l.places.length : 0 };
  }

  // ── Reading ──────────────────────────────────────────────

  /** → { ok, places, family, limits, icons, visibility, search, fetchedAt, stale } (shared: with `shared`). */
  async list({ refresh = false, shared = false } = {}) {
    this._checkScope();
    if (!shared && !refresh && this._fresh && this._list && this.now() - this._at < this.timing.cacheTtlMs) return this._answer(false);
    if (!shared && this._inflight) return this._inflight;
    const run = (async () => {
      try {
        const data = await this.http._call('GET', P.PLACES_PATH, shared ? { params: { shared: 1 } } : {});
        const l = P.normalizeList(data);
        if (!l) throw new MessengerError('not a list of places', { code: 'unsupported', status: 200 });
        if (shared) return { ok: true, ...l, fetchedAt: new Date(this.now()).toISOString(), stale: false };
        this._list = l;
        this._at = this.now();
        this._fresh = true;
        this._setState('available');
        return this._answer(false);
      } catch (err) {
        const e = placesError(err);
        if (e.code === 'unsupported') { this._list = null; this._setState('unsupported'); throw e; }
        if (!shared && this._list && e.transient) return this._answer(true);
        if (!this._list) this._setState('error');
        throw e;
      }
    })();
    if (shared) return run;
    this._inflight = run;
    try { return await run; } finally { if (this._inflight === run) this._inflight = null; }
  }

  /** One place → { ok, place } (404 not_found when it is not the person's). */
  async get(id) {
    const r = await this._write('GET', `${P.PLACES_PATH}/${this._id(id)}`);
    const place = P.normalizePlace(r.place);
    if (place) this._put(place);
    return { ok: true, place };
  }

  // ── Changing ─────────────────────────────────────────────

  /** A new place ({ name, lat, lon, icon?, radiusM?, address?, visibility? }) → { ok, place }. */
  async create(input) {
    const body = this._check(() => P.createBody(input));
    const r = await this._write('POST', P.PLACES_PATH, { body });
    const place = P.normalizePlace(r.place);
    if (place) { this._put(place); this.emit('changed', { ids: [place.id], deleted: false, origin: 'local' }); }
    return { ok: true, place };
  }

  /** Only the fields given (utils/places.js patchBody) → { ok, place }; an empty patch answers the place unchanged. */
  async update(id, patch) {
    this._id(id);
    const body = this._check(() => P.patchBody(patch));
    if (!Object.keys(body).length) {
      const known = this._list && this._list.places.find((p) => p.id === id);
      return known ? { ok: true, place: known } : this.get(id);
    }
    const r = await this._write('PATCH', `${P.PLACES_PATH}/${id}`, { body });
    const place = P.normalizePlace(r.place);
    if (place) { this._put(place); this.emit('changed', { ids: [place.id], deleted: false, origin: 'local' }); }
    return { ok: true, place };
  }

  /** Delete → { ok, deleted, id }; in use without force → code 'in_use' with `usedBy`. */
  async remove(id, { force = false } = {}) {
    this._id(id);
    await this._write('DELETE', `${P.PLACES_PATH}/${id}`, force ? { params: { force: 1 } } : {});
    if (this._list) this._list = { ...this._list, places: this._list.places.filter((p) => p.id !== id) };
    this.emit('changed', { ids: [id], deleted: true, origin: 'local' });
    return { ok: true, deleted: true, id };
  }

  /** „zuletzt genutzt“ (a form took the place) → { ok, place }; no event at the server, none here. */
  async markUsed(id) {
    const r = await this._write('POST', `${P.PLACES_PATH}/${this._id(id)}/used`, { body: {} });
    const place = P.normalizePlace(r.place);
    if (place) this._put(place);
    return { ok: true, place };
  }

  // ── Address search ───────────────────────────────────────

  /**
   * { q, near? } → { ok, results, attribution, via: 'server' | 'device' }. Only on the person's „Suchen“ — never while
   * typing. With the server's search off, this PC's map service (Nominatim) answers; without one: code 'search_off'.
   */
  async search(input, { lang } = {}) {
    const arg = this._check(() => P.searchArg(input));
    const l = lang === 'en' || lang === 'de' ? lang : (this.getLang() === 'en' ? 'en' : 'de');
    if (this._list && this._list.search === 'off') return this._deviceSearch(arg, l, new MessengerError('search off', { code: 'search_off', status: 403 }));
    try {
      const data = await this.http._call('GET', P.SEARCH_PATH, { params: arg, headers: { 'Accept-Language': l } });
      return { ok: true, ...P.normalizeSearch(data), via: 'server' };
    } catch (err) {
      const e = placesError(err);
      if (e.code === 'search_off') {
        if (this._list) this._list = { ...this._list, search: 'off' };
        return this._deviceSearch(arg, l, e);
      }
      throw e;
    }
  }

  async _deviceSearch(arg, lang, refusal) {
    if (!this.maps || typeof this.maps.search !== 'function') throw refusal;
    const hits = await this.maps.search(arg.q, { lang });
    const results = (Array.isArray(hits) ? hits : []).map(P.hitOfMap).filter(Boolean).slice(0, P.HITS_MAX);
    return { ok: true, results, attribution: { ...P.OSM_ATTRIBUTION }, via: 'device' };
  }

  // ── Internals ────────────────────────────────────────────

  _answer(stale) {
    const l = this._list;
    return {
      ok: true, places: l.places.map((p) => ({ ...p })), family: l.family, limits: l.limits, icons: [...l.icons],
      visibility: [...l.visibility], search: l.search, fetchedAt: new Date(this._at).toISOString(), stale,
    };
  }

  _put(place) {
    if (!this._list) return;
    const places = this._list.places.filter((p) => p.id !== place.id);
    const at = this._list.places.findIndex((p) => p.id === place.id);
    if (at >= 0) places.splice(at, 0, place); else places.push(place);
    this._list = { ...this._list, places };
  }

  _drop() {
    this._fresh = false;
    this._inflight = null;
  }

  async _write(method, path, opts = {}) {
    this._checkScope();
    try {
      return await this.http._call(method, path, opts);
    } catch (err) {
      const e = placesError(err);
      if (e.code === 'unsupported') this._setState('unsupported');
      throw e;
    }
  }

  _check(fn) {
    try {
      return fn();
    } catch (err) {
      throw new MessengerError(err.message, { code: 'invalid', body: { field: err.field || null } });
    }
  }

  _id(id) {
    if (!Number.isSafeInteger(id) || id <= 0) throw new MessengerError('invalid id', { code: 'invalid', body: { field: 'id' } });
    return id;
  }

  _scopeNow() {
    return typeof this.http.scope === 'function' ? this.http.scope() : '';
  }

  /** Another server / token since the last answer: start from scratch. */
  _checkScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._list = null;
    this._at = 0;
    this._inflight = null;
    this._setState('unknown');
  }

  _setState(state) {
    if (state === this._state) return;
    this._state = state;
    this.emit('state', this.status());
  }

  /** EventEmitter: listener errors must not break a call. */
  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Places listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

PlacesService.placesError = placesError;

module.exports = { PlacesService, placesError };
