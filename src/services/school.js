'use strict';

/**
 * GateControl – Schule (Core service)
 *
 * The data side of the page "Schule" in the Windows apps: the WebUntis
 * timetable of the plugin `gatecontrol-schule` (contract: the plugin's
 * README "API"), over the device token of the existing ApiClient:
 *
 *   GET /api/v1/client/plugins                                   is the plugin there?
 *   GET …/gatecontrol-schule/api/app/timetable?from&to           week view (≤ 14 days)
 *   GET …/gatecontrol-schule/api/app/changes?days=7              "Änderungen"
 *   GET …/gatecontrol-schule/api/app/messages?days=30            "Nachrichten" (plugin ≥ 1.4.0)
 *   GET …/gatecontrol-schule/api/app/absences?days=60            "Fehlzeiten"  (plugin ≥ 1.4.0)
 *   GET /avatars/<file>                                          the children's pictures
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins
 *   lists `gatecontrol-schule` (the plugin has no app tab of its own, the
 *   list entry is enough). Asked at start, every 30 min, after a push
 *   reconnect and on check(); network errors are retried (5 s … 5 min).
 * - Messages / absences: plugin ≥ 1.4.0 (version of the plugin list). An
 *   older plugin, or a 404 of the route, hides them (status().features).
 * - Answers are cleaned (utils/school.js) and cached for a minute; a
 *   network error answers with the last copy (`stale: true`).
 * - Push: messages of the topics `plugin:gatecontrol-schule:*` drop the
 *   cache and emit 'push' (the page reloads); with a NotificationCenter a
 *   click on their toast opens the page (addClickRoute → navigate {
 *   route: 'plg-gatecontrol-schule', id, context: { kind, studentId, date,
 *   messageId } }) instead of the inbox — only while the page exists.
 *
 * Events: 'state' (status()), 'push' (context of a Schule push message).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const { PLUGINS_PATH } = require('../utils/messenger');
const school = require('../utils/school');
const { savedOf } = require('../utils/drive');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,    // available / unavailable: ask again
  retryMinMs: 5000,             // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,    // … 5 min
  cacheTtlMs: 60 * 1000,        // answers younger than this are served from memory
  avatarCache: 40,              // pictures kept
  driveTimeoutMs: 90 * 1000,    // "In Drive speichern": fetch from WebUntis + Drive's copy
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class SchoolService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.notificationCenter] - NotificationCenter: Schule pushes → 'push',
   *   their toast click opens the page
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks for the plugin again
   * @param {object} [opts.api] - MessengerApi-compatible transport (tests)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({ apiClient, log, notificationCenter = null, pushClient = null, api = null, timing = {}, now = Date.now } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this.notificationCenter = notificationCenter;
    this.pushClient = pushClient;

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._features = { messages: null, absences: null };
    this._cache = new Map();   // key → { at, data }
    this._inflight = new Map();
    this._avatars = new Map(); // url → { mime, data }
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this._scopeNow();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const nc = this.notificationCenter;
    if (nc && typeof nc.on === 'function') {
      const onNew = (entry) => this._onPush(entry);
      nc.on('new', onNew);
      this._unsub.push(() => nc.removeListener('new', onNew));
      if (typeof nc.addClickRoute === 'function') {
        this._unsub.push(nc.addClickRoute(school.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      // A reconnect may come with another server state (plugin installed / removed).
      const onHello = () => { if (this._state.state !== 'available') this.check().catch(() => {}); };
      pc.on('hello', onHello);
      this._unsub.push(() => pc.removeListener('hello', onHello));
    }
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    this._timer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: the old server's answers and state are dropped, the new one is asked. */
  resetForNewServer() {
    this._cache.clear();
    this._avatars.clear();
    this._inflight.clear();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null }, { messages: null, absences: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * { state: 'unknown'|'available'|'unavailable'|'error', reason, version,
   *   checkedAt, features: { messages, absences } } — features: true / false /
   *   null (not known yet: the page shows the tab and asks).
   */
  status() {
    return { ...this._state, features: { ...this._features } };
  }

  available() {
    return this._state.state === 'available';
  }

  /** Ask GET /api/v1/client/plugins now → status(). */
  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    this._ensureScope();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    try {
      const data = await this.api._call('GET', PLUGINS_PATH);
      const plugins = Array.isArray(data.plugins) ? data.plugins : [];
      const p = plugins.find((x) => x && x.id === school.PLUGIN_ID);
      this._retry = 0;
      if (!p) {
        this._setState({ state: 'unavailable', reason: 'not_installed', version: null, checkedAt: this.now() });
      } else {
        const version = typeof p.version === 'string' ? p.version.slice(0, 40) : null;
        const sup = school.messagesSupported(version);
        // A known version decides; an unknown one keeps what the routes said.
        this._setState({ state: 'available', reason: null, version, checkedAt: this.now() }, sup === null ? this._features : { messages: sup, absences: sup });
      }
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        this._setState({ state: 'unavailable', reason: 'unsupported', version: null, checkedAt: this.now() });
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setState({ state: 'unavailable', reason: err.status === 401 ? 'auth' : 'forbidden', version: null, checkedAt: this.now() });
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        // Network / 5xx: keep "available" (the page stays, answers come from the cache).
        const keep = this._state.state === 'available';
        this._setState({ ...this._state, state: keep ? 'available' : 'error', reason: (err && err.code) || 'network', checkedAt: this.now() });
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._started) {
      this._timer = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timer.unref) this._timer.unref();
    }
    return this.status();
  }

  _setState(s, features = this._features) {
    const key = () => JSON.stringify([this._state.state, this._state.reason, this._state.version, this._features]);
    const before = key();
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    this._features = { ...features };
    if (key() !== before) this.emit('state', this.status());
  }

  _setFeature(name, value) {
    if (this._features[name] === value) return;
    this._features = { ...this._features, [name]: value };
    this.emit('state', this.status());
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  /** URL / token changed under us (configure()): the cache belongs to the old one. */
  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._cache.clear();
    this._avatars.clear();
  }

  // ── Data ─────────────────────────────────────────────────

  /**
   * GET app/timetable → { ok, updatedAt, students, stale?, fetchedAt }.
   * from / to: 'YYYY-MM-DD', at most 14 days.
   */
  async timetable({ from, to, refresh = false } = {}) {
    const range = school.rangeArgs(from, to);
    if (!range) throw new MessengerError('invalid range', { code: 'invalid' });
    return this._get(`timetable|${range.from}|${range.to}`, 'app/timetable', range, school.normalizeTimetable, refresh);
  }

  /** GET app/changes?days → { ok, changes, stale?, fetchedAt } */
  async changes({ days, refresh = false } = {}) {
    const d = school.daysArg(days, school.CHANGES_DAYS);
    if (!d) throw new MessengerError('invalid days', { code: 'invalid' });
    return this._get(`changes|${d}`, 'app/changes', { days: d }, school.normalizeChanges, refresh);
  }

  /** GET app/messages?days (plugin ≥ 1.4.0) → { ok, messages, … } | code 'unsupported' */
  async messages({ days, refresh = false } = {}) {
    const d = school.daysArg(days, school.MESSAGES_DAYS);
    if (!d) throw new MessengerError('invalid days', { code: 'invalid' });
    return this._optional('messages', `messages|${d}`, 'app/messages', { days: d }, school.normalizeMessages, refresh);
  }

  /** GET app/absences?days (plugin ≥ 1.4.0) → { ok, absences, … } | code 'unsupported' */
  async absences({ days, refresh = false } = {}) {
    const d = school.daysArg(days, school.ABSENCES_DAYS);
    if (!d) throw new MessengerError('invalid days', { code: 'invalid' });
    return this._optional('absences', `absences|${d}`, 'app/absences', { days: d }, school.normalizeAbsences, refresh);
  }

  async _optional(feature, key, path, params, normalize, refresh) {
    if (this._features[feature] === false) throw new MessengerError('not supported by the plugin', { code: 'unsupported' });
    try {
      const r = await this._get(key, path, params, normalize, refresh);
      this._setFeature(feature, true);
      return r;
    } catch (err) {
      if (err && err.status === 404) {
        this._setFeature(feature, false);
        throw new MessengerError('not supported by the plugin', { status: 404, code: 'unsupported' });
      }
      throw err;
    }
  }

  async _get(key, path, params, normalize, refresh) {
    this._ensureScope();
    const hit = this._cache.get(key);
    if (!refresh && hit && this.now() - hit.at < this.timing.cacheTtlMs) return { ok: true, ...this._copy(hit.data), fetchedAt: hit.at, stale: false };
    if (this._inflight.has(key)) return this._inflight.get(key);
    const scope = this._scope;
    const run = (async () => {
      try {
        const raw = await this.api._call('GET', school.API_BASE + path, { params });
        const data = normalize(raw);
        const at = this.now();
        if (scope === this._scope) this._cache.set(key, { at, data });
        if (this._state.state !== 'available' && this._state.state !== 'unknown') this.check().catch(() => {});
        return { ok: true, ...this._copy(data), fetchedAt: at, stale: false };
      } catch (err) {
        const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
        // Plugin gone (404 on the timetable) or no longer allowed: ask for the plugin again.
        if (e.status === 404 || e.status === 403) this.check().catch(() => {});
        const old = this._cache.get(key);
        if (old && e.transient) return { ok: true, ...this._copy(old.data), fetchedAt: old.at, stale: true, error: e.code };
        throw e;
      } finally {
        this._inflight.delete(key);
      }
    })();
    this._inflight.set(key, run);
    return run;
  }

  /**
   * "In Drive speichern" (plugin 1.7.0, `drive: true` in app/messages): an
   * attachment into Drive → { ok, saved: { nodeId, name, where } }. Without
   * `folderId` the plugin picks the family area › Schule › <child> (else
   * Meine Dateien). Slow: the attachment may have to be fetched from WebUntis
   * first, then Drive copies it — its own timeout.
   */
  async attachmentToDrive({ messageId, attachmentId, folderId = null } = {}) {
    const p = school.attachmentDrivePath(messageId, attachmentId);
    if (!p) throw new MessengerError('invalid attachment', { code: 'invalid' });
    const body = {};
    if (folderId !== null && folderId !== undefined) {
      const f = Number.isSafeInteger(folderId) && folderId > 0 ? folderId : null;
      if (!f) throw new MessengerError('invalid folder', { code: 'invalid' });
      body.folderId = f;
    }
    this._ensureScope();
    try {
      const r = await this.api._call('POST', school.API_BASE + p, { body, timeout: this.timing.driveTimeoutMs });
      return { ok: true, saved: savedOf(r) };
    } catch (err) {
      throw err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
    }
  }

  _copy(data) {
    return JSON.parse(JSON.stringify(data));
  }

  /** A child's picture (/avatars/… of the own server) → { mime, data: Buffer } */
  async avatar(url) {
    this._ensureScope();
    const hit = this._avatars.get(url);
    if (hit) return hit;
    const key = `avatar:${url}`;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.avatar(url).then((r) => {
      this._avatars.set(url, r);
      while (this._avatars.size > this.timing.avatarCache) this._avatars.delete(this._avatars.keys().next().value);
      return r;
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── Push ─────────────────────────────────────────────────

  _onPush(entry) {
    const ctx = school.pushContext(entry);
    if (!ctx) return;
    // New changes / reminders / messages: the next answer comes from the server.
    this._cache.clear();
    this.emit('push', { ...ctx, notificationId: entry && Number.isSafeInteger(entry.id) ? entry.id : null });
  }

  /**
   * Context for a click on a Schule toast while the page exists, else null
   * (the inbox opens). Used through NotificationCenter.addClickRoute.
   */
  clickContext(entry) {
    if (!this.available()) return null;
    return school.pushContext(entry);
  }
}

SchoolService.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = SchoolService;
