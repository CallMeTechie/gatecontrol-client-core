'use strict';

/**
 * GateControl – DNS-Schutz (Core service)
 *
 * The data side of the card "DNS-Schutz" and of its tray entries in the
 * Windows apps: the server-side DNS filter of the VPN devices (plugin
 * gatecontrol-dns from 1.0.0, server from 1.264.0; contract: the plugin's
 * README "App-API"), over the device token of the existing ApiClient:
 *
 *   GET  /api/v1/client/permissions      `vpnDns: { plugin, state }` — is there a DNS protection?
 *   GET  …/plugins/<plugin>/api/status   state of this device, counters, what the person may do
 *   POST …/api/pause                     { minutes } | { forever: true } | { extend }
 *   POST …/api/resume                    {}
 *
 * - Availability: only while `permissions.vpnDns` is an object. The field
 *   missing (server < 1.264.0) or null (no plugin, off, no licence): no card,
 *   no tray entry, no error. The plugin's id is taken from the answer. Asked
 *   at start, every 10 min while there is none, after a push reconnect and on
 *   check(); network errors are retried (5 s … 5 min).
 * - The apps draw what the server says (`may`) and check nothing themselves.
 * - There are no live events: `status` is asked again every 45 s while the
 *   card is watched (watch(true)), every 5 min otherwise (tray, outage), and
 *   shortly after the end of a running pause. 429 stretches the interval.
 * - A plugin that is gone or switched off under us (404, 501 unsupported,
 *   409 off, 403 without a person) is "no DNS protection"; a plugin in
 *   trouble (502 / 503 / 504, no network) keeps the last answer (`stale`).
 * - 'outage' when the filter goes from running to "fallback" (the plugin
 *   tells only admins; the app shows its own Windows notification).
 *
 * Events: 'change' (snapshot()), 'outage' ({ since }).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const dns = require('../utils/dns-protect');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 10 * 60 * 1000,   // no DNS protection: ask permissions again
  retryMinMs: 5000,            // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,   // … 5 min
  goneMinMs: 60 * 1000,        // the plugin refused although permissions names it: 1 min … recheckMs
  pollMs: 45 * 1000,           // status while the card is shown
  idleMs: 5 * 60 * 1000,       // status otherwise
  afterPauseMs: 2000,          // status this long after the end of a pause
};

// Refusals that mean "no DNS protection (any more)".
const GONE = (e) => e.status === 404 || e.status === 501 || (e.status === 409 && e.code === 'off') || (e.status === 403 && (e.code === 'forbidden' || e.code === 'no_user'));

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class DnsProtectService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks again
   * @param {() => string} [opts.getLocale] - 'de' | 'en': the language of the plugin's error texts
   * @param {object} [opts.api] - MessengerApi-compatible transport (tests)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({ apiClient, log, pushClient = null, getLocale = null, api = null, timing = {}, now = Date.now } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this.pushClient = pushClient;
    this.getLocale = getLocale;

    this._avail = { state: 'unknown', reason: null, plugin: null, filter: null, checkedAt: null };
    this._data = null;
    this._fetchedAt = null;
    this._stale = false;
    this._error = null;
    this._down = null;        // filter in the fallback? null: not known yet
    this._watched = false;
    this._slow = 0;           // 429: the poll interval is doubled this often
    this._retry = 0;
    this._gone = 0;
    this._checkTimer = null;
    this._pollTimer = null;
    this._checking = null;
    this._refreshing = null;
    this._started = false;
    this._unsub = [];
    this._last = '';
    this._scope = this._scopeNow();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      // A reconnect may come with another server state (plugin installed, switched on or off).
      const onHello = () => { this.check().catch(() => {}); };
      pc.on('hello', onHello);
      this._unsub.push(() => pc.removeListener('hello', onHello));
    }
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._checkTimer);
    clearTimeout(this._pollTimer);
    this._checkTimer = null;
    this._pollTimer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: the old server's state is dropped, the new one is asked. */
  resetForNewServer() {
    this._scope = this._scopeNow();
    this._forget();
    this._avail = { state: 'unknown', reason: null, plugin: null, filter: null, checkedAt: null };
    this._publish();
    if (this._started) return this.check().catch(() => this.snapshot());
    return Promise.resolve(this.snapshot());
  }

  _forget() {
    this._data = null;
    this._fetchedAt = null;
    this._stale = false;
    this._error = null;
    this._down = null;
    this._slow = 0;
    this._retry = 0;
    this._gone = 0;
  }

  // ── State ────────────────────────────────────────────────

  /**
   * { state: 'unknown'|'available'|'unavailable'|'error', reason, plugin,
   *   filter: 'starting'|'filtering'|'fallback'|null, checkedAt,
   *   data: status (utils/dns-protect.js normalizeStatus) | null, fetchedAt,
   *   stale, error } — reason of 'unavailable': old_server, none, auth,
   *   not_configured, or the plugin's refusal (not_found, unsupported, off,
   *   forbidden, no_user). `stale`: the answer is the last one before the
   *   plugin or the network failed (`error` = code).
   */
  snapshot() {
    return {
      ...this._avail,
      data: this._data ? JSON.parse(JSON.stringify(this._data)) : null,
      fetchedAt: this._fetchedAt,
      stale: this._stale,
      error: this._error,
    };
  }

  available() {
    return this._avail.state === 'available';
  }

  /** The card is on screen (true) or not: how often `status` is asked. */
  watch(on) {
    const next = on === true;
    if (next === this._watched) return;
    this._watched = next;
    if (!this.available() || !this._started) return;
    // Shown again: an answer older than the short interval is asked now.
    if (next && (!this._fetchedAt || this.now() - this._fetchedAt >= this.timing.pollMs)) this.refresh().catch(() => {});
    else this._schedulePoll();
  }

  _publish() {
    const snap = this.snapshot();
    const key = JSON.stringify(snap);
    if (key === this._last) return;
    this._last = key;
    this.emit('change', snap);
  }

  /** The filter's state as seen now: running → fallback emits 'outage' once. */
  _noteFilter(down, since = null) {
    const before = this._down;
    this._down = down;
    if (before === false && down) this.emit('outage', { since });
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  /** URL / token changed under us (configure()): the state belongs to the old one. */
  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._forget();
  }

  _params() {
    const l = typeof this.getLocale === 'function' ? this.getLocale() : null;
    return l === 'de' || l === 'en' ? { lang: l } : undefined;
  }

  // ── Availability ─────────────────────────────────────────

  /** Ask GET permissions now → snapshot(). */
  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    this._ensureScope();
    clearTimeout(this._checkTimer);
    this._checkTimer = null;
    let next = this.timing.recheckMs;
    const at = this.now();
    const none = (reason) => {
      this._retry = 0;
      this._data = null;
      this._fetchedAt = null;
      this._stale = false;
      this._error = null;
      this._down = null;
      clearTimeout(this._pollTimer);
      this._pollTimer = null;
      this._avail = { state: 'unavailable', reason, plugin: null, filter: null, checkedAt: at };
    };
    let ask = false;
    try {
      const v = dns.vpnDnsOf(await this.api._call('GET', dns.PERMISSIONS_PATH));
      if (!v.supported) none('old_server');
      else if (!v.plugin) none('none');
      else {
        this._retry = 0;
        if (this._avail.plugin && this._avail.plugin !== v.plugin) this._forget();
        this._avail = { state: 'available', reason: null, plugin: v.plugin, filter: v.filter, checkedAt: at };
        this._noteFilter(v.filter === 'fallback');
        ask = true;
        next = 0; // while it runs, `status` is the clock
      }
    } catch (err) {
      const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
      if (e.status === 401 || e.status === 403) none('auth');
      else if (e.code === 'not_configured') none('not_configured');
      else if (e.status === 404) none('old_server');
      else {
        // Network / 5xx: keep what is shown (the card stays, with the last answer).
        const keep = this._avail.state === 'available';
        this._avail = { ...this._avail, state: keep ? 'available' : 'error', reason: e.code || 'network', checkedAt: at };
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._started && next > 0) this._scheduleCheck(next);
    if (ask) await this._refreshNow();
    else this._publish();
    return this.snapshot();
  }

  _scheduleCheck(ms) {
    clearTimeout(this._checkTimer);
    this._checkTimer = setTimeout(() => this.check().catch(() => {}), ms);
    if (this._checkTimer.unref) this._checkTimer.unref();
  }

  // ── Status ───────────────────────────────────────────────

  /** GET status now → snapshot() (never throws; trouble is in `stale` / `error`). */
  refresh() {
    if (!this.available()) return this.check();
    return this._refreshNow();
  }

  _refreshNow() {
    if (this._refreshing) return this._refreshing;
    this._refreshing = this._refresh().finally(() => { this._refreshing = null; });
    return this._refreshing;
  }

  async _refresh() {
    this._ensureScope();
    const base = dns.apiBase(this._avail.plugin);
    if (!this.available() || !base) return this.snapshot();
    const scope = this._scope;
    try {
      const raw = await this.api._call('GET', `${base}status`, { params: this._params() });
      if (scope !== this._scope) return this.snapshot();
      this._take(raw);
    } catch (err) {
      if (scope !== this._scope) return this.snapshot();
      this._failed(err instanceof MessengerError ? err : MessengerApi.toMessengerError(err));
    }
    this._publish();
    this._schedulePoll();
    return this.snapshot();
  }

  /** A `status` of the plugin (from GET status or inside the answer of a change). */
  _take(raw) {
    const data = dns.normalizeStatus(raw);
    if (!data) throw new MessengerError('unexpected answer', { code: 'bad_response', status: 502 });
    this._data = data;
    this._fetchedAt = this.now();
    this._stale = false;
    this._error = null;
    this._slow = 0;
    this._avail = { ...this._avail, state: 'available', reason: null, filter: data.state === 'fallback' ? 'fallback' : data.state === 'starting' || data.state === 'off' ? 'starting' : 'filtering' };
    this._noteFilter(data.state === 'fallback', data.outage ? data.outage.since : null);
    // "off": the core reports only a running protection — permissions decides.
    if (data.state !== 'off') { this._gone = 0; return; }
    if (this._started) this._scheduleCheck(Math.min(this.timing.recheckMs, this.timing.retryMinMs * (2 ** this._gone)));
    this._gone = Math.min(this._gone + 1, 10);
  }

  _failed(e) {
    if (GONE(e)) {
      // No DNS protection (any more): no card; permissions is asked again later.
      this._data = null;
      this._fetchedAt = null;
      this._stale = false;
      this._error = null;
      this._down = null;
      this._avail = { state: 'unavailable', reason: e.status === 404 ? 'not_found' : e.code, plugin: null, filter: null, checkedAt: this.now() };
      clearTimeout(this._pollTimer);
      this._pollTimer = null;
      if (this._started) this._scheduleCheck(Math.min(this.timing.recheckMs, this.timing.goneMinMs * (2 ** this._gone)));
      this._gone = Math.min(this._gone + 1, 10);
      return;
    }
    if (e.status === 429) this._slow = Math.min(this._slow + 1, 4);
    this._stale = !!this._data;
    this._error = e.code || 'failed';
  }

  _schedulePoll() {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
    if (!this._started || !this.available()) return;
    let ms = (this._watched ? this.timing.pollMs : this.timing.idleMs) * (2 ** this._slow);
    // A running pause ends: ask shortly after.
    const p = this._data && this._data.pause;
    if (p && p.until && !this._stale) {
      const left = p.until - dns.serverNow(this.snapshot(), this.now());
      ms = Math.min(ms, Math.max(0, left) + this.timing.afterPauseMs);
    }
    this._pollTimer = setTimeout(() => this._refreshNow().catch(() => {}), ms);
    if (this._pollTimer.unref) this._pollTimer.unref();
  }

  // ── Changes ──────────────────────────────────────────────

  /**
   * POST pause { minutes } | { forever: true } | { extend } for the asking
   * device → { ok, snapshot }. Refusals throw a MessengerError with the
   * plugin's code and sentence (`not_allowed` with body.reason,
   * `forever_not_allowed`, `too_long`, `not_filtering`, …); the status is
   * asked again after one.
   */
  async pause(args) {
    const body = dns.pauseBody(args);
    if (!body) throw new MessengerError('invalid argument', { code: 'invalid' });
    await this._change('pause', body);
    return { ok: true, snapshot: this.snapshot() };
  }

  /** POST resume → { ok, resumed, snapshot } (`resumed: false`: nothing was paused — no error). */
  async resume() {
    const raw = await this._change('resume', {});
    return { ok: true, resumed: raw.resumed !== false, snapshot: this.snapshot() };
  }

  async _change(op, body) {
    this._ensureScope();
    const base = dns.apiBase(this._avail.plugin);
    if (!this.available() || !base) throw new MessengerError('not available', { code: 'unavailable' });
    const scope = this._scope;
    let raw;
    try {
      raw = await this.api._call('POST', `${base}${op}`, { body, params: this._params() });
    } catch (err) {
      const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
      if (scope === this._scope) {
        if (GONE(e)) { this._failed(e); this._publish(); }
        // Refused: what the server allows has changed — show it.
        else if (e.status === 403 || e.status === 409) this._refreshNow().catch(() => {});
      }
      throw e;
    }
    if (scope === this._scope) {
      try { this._take(raw.status); } catch { this._refreshNow().catch(() => {}); return raw; }
      this._publish();
      this._schedulePoll();
    }
    return raw;
  }
}

DnsProtectService.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = DnsProtectService;
