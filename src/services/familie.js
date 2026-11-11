'use strict';

/**
 * GateControl – Familie (Core service)
 *
 * The data side of the page "Familie" in the Windows apps: "Internet zu
 * Hause" of the plugin `gatecontrol-familie` (contract: the plugin's app
 * API, plugin 1.20.0), over the device token of the existing ApiClient:
 *
 *   GET /api/v1/client/plugins                          is the plugin there?
 *   GET …/gatecontrol-familie/api/me                    member of a family? role, modules
 *   GET …/api/internet                                  the children's cards (plugin ≥ 1.18.0)
 *   POST …/api/internet/<childId>/pause|resume|extend   parents: pause, "Heute länger"
 *   GET …/api/rules · rules/options                     the rules and the rule action "Internet zu Hause"
 *   PATCH …/api/rules/<id>                              { active } / { actions }
 *   GET …/api/presence · PUT presence/consent           one's own presence, "Anwesenheit teilen"
 *   GET|PUT …/api/presence/wifi[/devices/<id>]          "WLAN-Erkennung verwenden", one's own devices
 *   GET /avatars/<file>                                 the members' pictures
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins
 *   lists `gatecontrol-familie` AND `GET me` answers with a member (parent
 *   or child; 403 not_member / a wall tablet: no page). Asked at start,
 *   every 30 min, after a push reconnect and on check(); network errors are
 *   retried (5 s … 5 min).
 * - Older plugins / servers are no error: without the route `internet`
 *   (plugin < 1.18.0) the answer is `supported: false`, without `presence/wifi`
 *   (< 1.17.0) "not available"; fields a plugin < 1.20.0 does not send are
 *   simply missing (utils/familie.js).
 * - Answers are cleaned (utils/familie.js) and cached for a few seconds; a
 *   network error answers with the last copy (`stale: true`). A change
 *   drops the copies it touches.
 * - Push: messages of the topic `plugin:gatecontrol-familie:internet` drop
 *   the cache and emit 'push' (the page reloads); with a NotificationCenter
 *   a click on their toast opens the page (addClickRoute → navigate {
 *   route: 'plg-gatecontrol-familie', id, context: { type: 'internet', kind,
 *   userId, until, ruleId } }) instead of the inbox — only while the page exists.
 *
 * Events: 'state' (status()), 'push' (context of an "Internet zu Hause" push).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const { PLUGINS_PATH, posInt } = require('../utils/messenger');
const familie = require('../utils/familie');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,    // available / unavailable: ask again
  retryMinMs: 5000,             // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,    // … 5 min
  cacheTtlMs: 15 * 1000,        // answers younger than this are served from memory
  avatarCache: 40,              // pictures kept
};

const NO_MODULES = Object.freeze({ rules: false, presence: false });

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class FamilieService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.notificationCenter] - NotificationCenter: "Internet zu Hause" pushes → 'push',
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
    this._me = null;           // { userId, name, role }
    this._modules = { ...NO_MODULES };
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
        this._unsub.push(nc.addClickRoute(familie.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      // A reconnect may come with another server state (plugin installed / removed, added to the family).
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
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null }, null, NO_MODULES);
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * { state: 'unknown'|'available'|'unavailable'|'error', reason, version,
   *   checkedAt, me: { userId, name, role: 'parent'|'child' } | null,
   *   modules: { rules, presence } } — reason of 'unavailable': not_installed,
   *   not_member, forbidden (a wall tablet), unsupported, auth, not_configured.
   */
  status() {
    return { ...this._state, me: this._me ? { ...this._me } : null, modules: { ...this._modules } };
  }

  available() {
    return this._state.state === 'available';
  }

  /** Ask the plugin list and `me` now → status(). */
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
    const gone = (reason, version = null) => this._setState({ state: 'unavailable', reason, version, checkedAt: this.now() }, null, NO_MODULES);
    try {
      const data = await this.api._call('GET', PLUGINS_PATH);
      const plugins = Array.isArray(data.plugins) ? data.plugins : [];
      const p = plugins.find((x) => x && x.id === familie.PLUGIN_ID);
      if (!p) {
        this._retry = 0;
        gone('not_installed');
      } else {
        const version = typeof p.version === 'string' ? p.version.slice(0, 40) : null;
        let mine = null;
        let refused = null;
        try {
          mine = familie.normalizeMe(await this.api._call('GET', `${familie.API_BASE}me`));
        } catch (err) {
          // Not in a family (403 not_member) or a plugin without the app API (404): no page, no error.
          if (err && err.status === 403) refused = err.code === 'not_member' ? 'not_member' : 'forbidden';
          else if (err && err.status === 404) refused = 'unsupported';
          else throw err;
        }
        this._retry = 0;
        if (refused) gone(refused, version);
        else if (!mine || mine.me.role === 'wall') gone(mine ? 'forbidden' : 'unsupported', version);
        else this._setState({ state: 'available', reason: null, version, checkedAt: this.now() }, mine.me, mine.modules);
      }
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        gone('unsupported');
      } else if (err && (err.status === 401 || err.status === 403)) {
        gone(err.status === 401 ? 'auth' : 'forbidden');
      } else if (err && err.code === 'not_configured') {
        gone('not_configured');
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

  _setState(s, me = this._me, modules = this._modules) {
    const key = () => JSON.stringify([this._state.state, this._state.reason, this._state.version, this._me, this._modules]);
    const before = key();
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    this._me = me ? { ...me } : null;
    this._modules = { ...modules };
    if (key() !== before) this.emit('state', this.status());
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

  // ── Internet zu Hause ────────────────────────────────────

  /**
   * GET internet → { ok, internet: { available, supported, manage, serverTime,
   * timezone, children }, fetchedAt, stale }. A plugin without the route
   * (< 1.18.0) answers `supported: false` — no error.
   */
  async internet({ refresh = false } = {}) {
    try {
      return await this._get('internet', 'internet', (raw) => ({ internet: familie.normalizeInternet(raw) }), refresh);
    } catch (err) {
      if (err && err.status === 404) return { ok: true, internet: { ...familie.NO_INTERNET, children: [] }, fetchedAt: this.now(), stale: false };
      throw err;
    }
  }

  /** POST internet/<childId>/pause { minutes | until | add } → { ok, child } */
  async pause(childId, args) {
    const body = familie.pauseBody(args);
    return this._act(childId, 'pause', body);
  }

  /** POST internet/<childId>/resume → { ok, child } (an extra time stays) */
  async resume(childId) {
    return this._act(childId, 'resume', {});
  }

  /** POST internet/<childId>/extend { minutes: 0…1440, fromNow? } → { ok, child } (0 ends the extra time) */
  async extend(childId, args) {
    return this._act(childId, 'extend', familie.extendBody(args));
  }

  async _act(childId, op, body) {
    const path = familie.internetPath(childId, op);
    if (!path || !body) throw new MessengerError('invalid argument', { code: 'invalid' });
    this._ensureScope();
    const raw = await this._send('POST', path, body);
    this._cache.delete('internet');
    const child = familie.normalizeChild(raw.child);
    if (!child) throw new MessengerError('unexpected answer', { code: 'bad_response' });
    return { ok: true, child };
  }

  // ── Rules ────────────────────────────────────────────────

  /** GET rules → { ok, rules, can, fetchedAt, stale } (403 module_off: the module "Regeln" is off) */
  async rules({ refresh = false } = {}) {
    return this._get('rules', 'rules', familie.normalizeRules, refresh);
  }

  /** GET rules/options → { ok, internet: { available, reason, children }, people, fetchedAt, stale } */
  async ruleOptions({ refresh = false } = {}) {
    return this._get('rules/options', 'rules/options', familie.normalizeOptions, refresh);
  }

  /** PATCH rules/<id> { active } → { ok, rule } */
  async setRuleActive(id, active) {
    if (!posInt(id) || typeof active !== 'boolean') throw new MessengerError('invalid argument', { code: 'invalid' });
    return this._patchRule(posInt(id), { active });
  }

  /**
   * PATCH rules/<id> { actions } → { ok, rule }. `actions` replaces all of the
   * rule's actions: the caller sends the `input` of every action it keeps
   * (utils/familie.js actionInput) next to the one it changed.
   */
  async setRuleActions(id, actions) {
    const body = familie.actionsBody(actions);
    if (!posInt(id) || !body) throw new MessengerError('invalid argument', { code: 'invalid' });
    return this._patchRule(posInt(id), { actions: body });
  }

  async _patchRule(id, body) {
    this._ensureScope();
    const raw = await this._send('PATCH', `rules/${id}`, body);
    this._cache.delete('rules');
    const rule = familie.normalizeRule(raw.rule);
    if (!rule) throw new MessengerError('unexpected answer', { code: 'bad_response' });
    return { ok: true, rule };
  }

  // ── Presence ─────────────────────────────────────────────

  /** GET presence → { ok, me: { share, wifi }, self: { state, since, source } | null, fetchedAt, stale } */
  async presence({ refresh = false } = {}) {
    const userId = this._me ? this._me.userId : null;
    return this._get('presence', 'presence', (raw) => familie.normalizePresence(raw, userId), refresh);
  }

  /** PUT presence/consent { share } ("Anwesenheit teilen") → { ok, share, self } */
  async setShare(share) {
    if (typeof share !== 'boolean') throw new MessengerError('invalid argument', { code: 'invalid' });
    this._ensureScope();
    const raw = await this._send('PUT', 'presence/consent', { share });
    this._cache.delete('presence');
    const c = raw.consent && typeof raw.consent === 'object' ? raw.consent : {};
    return { ok: true, share: c.share === true, self: familie.normalizeOwnState(raw.state) };
  }

  /**
   * GET presence/wifi → { ok, wifi: { available, consent, since, devices }, … }.
   * A plugin without the route (< 1.17.0) answers "not available" — no error.
   */
  async wifi({ refresh = false } = {}) {
    try {
      return await this._get('presence/wifi', 'presence/wifi', (raw) => ({ wifi: familie.normalizeWifi(raw) }), refresh);
    } catch (err) {
      if (err && err.status === 404) return { ok: true, wifi: { ...familie.NO_WIFI, devices: [] }, fetchedAt: this.now(), stale: false };
      throw err;
    }
  }

  /** PUT presence/wifi { enabled } ("WLAN-Erkennung verwenden", only for oneself) → { ok, wifi } */
  async setWifi(enabled) {
    if (typeof enabled !== 'boolean') throw new MessengerError('invalid argument', { code: 'invalid' });
    return this._putWifi('presence/wifi', { enabled });
  }

  /** PUT presence/wifi/devices/<id> { counts } (does this device count for "zu Hause"?) → { ok, wifi } */
  async setWifiDevice(id, counts) {
    if (!posInt(id) || typeof counts !== 'boolean') throw new MessengerError('invalid argument', { code: 'invalid' });
    return this._putWifi(`presence/wifi/devices/${posInt(id)}`, { counts });
  }

  async _putWifi(path, body) {
    this._ensureScope();
    const raw = await this._send('PUT', path, body);
    this._cache.delete('presence/wifi');
    this._cache.delete('presence');
    return { ok: true, wifi: familie.normalizeWifi(raw) };
  }

  // ── Transport ────────────────────────────────────────────

  async _send(method, path, body) {
    try {
      return await this.api._call(method, familie.API_BASE + path, { body });
    } catch (err) {
      const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
      // No longer a member / the plugin gone: ask again.
      if (e.status === 404 || (e.status === 403 && (e.code === 'not_member' || e.code === 'forbidden'))) this.check().catch(() => {});
      throw e;
    }
  }

  async _get(key, path, normalize, refresh) {
    this._ensureScope();
    const hit = this._cache.get(key);
    if (!refresh && hit && this.now() - hit.at < this.timing.cacheTtlMs) return { ok: true, ...this._copy(hit.data), fetchedAt: hit.at, stale: false };
    if (this._inflight.has(key)) return this._inflight.get(key);
    const scope = this._scope;
    const run = (async () => {
      try {
        const raw = await this.api._call('GET', familie.API_BASE + path);
        const data = normalize(raw);
        const at = this.now();
        if (scope === this._scope) this._cache.set(key, { at, data });
        return { ok: true, ...this._copy(data), fetchedAt: at, stale: false };
      } catch (err) {
        const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
        // No longer a member (or a wall tablet now): ask for the page again.
        if (e.status === 403 && (e.code === 'not_member' || e.code === 'forbidden')) this.check().catch(() => {});
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

  _copy(data) {
    return JSON.parse(JSON.stringify(data));
  }

  /** A member's picture (/avatars/… of the own server) → { mime, data: Buffer } */
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
    const ctx = familie.pushContext(entry);
    if (!ctx) return;
    // A pause set, ended or run out: the next answer comes from the server.
    this._cache.delete('internet');
    this.emit('push', { ...ctx, notificationId: entry && Number.isSafeInteger(entry.id) ? entry.id : null });
  }

  /**
   * Context for a click on an "Internet zu Hause" toast while the page
   * exists, else null (the inbox opens). Used through
   * NotificationCenter.addClickRoute.
   */
  clickContext(entry) {
    if (!this.available()) return null;
    return familie.pushContext(entry);
  }
}

FamilieService.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = FamilieService;
