/**
 * GateControl – Push client (Core service, notification center)
 *
 * Holds the outgoing HTTPS connection to the own GateControl server that
 * carries push notifications (Server-Sent Events, GET /api/v1/client/push),
 * without any third-party push service and without needing the VPN.
 * Contract: gatecontrol docs/feature-notification-center.md,
 * "Vertrag Gerät ↔ Server".
 *
 *   - Node http(s), no extra dependency; same identification headers as
 *     ApiClient (apiClient.buildHeaders()).
 *   - Resume with Last-Event-ID = last processed seq (store
 *     `notifications.lastSeq`, scoped to server + token: a new setup starts
 *     from scratch).
 *   - Reconnect with exponential backoff and jitter (1 s → 5 min); 404 (old
 *     server) / 503 push_disabled / 403 direct_not_allowed → hourly retry;
 *     401/403 → stop until restart() (server:setup); 429 → ≥ 15 min.
 *   - Keepalive watchdog: no byte for 2 × keepalive_s → reconnect.
 *   - Every notification is confirmed `delivered` (batched POST …/push/ack;
 *     failed confirmations are retried after the next hello).
 *   - Device settings: `notifications.enabled` (off → no stream),
 *     `notifications.direct` (false → only while the tunnel is up, server
 *     mode 'vpn_only'), `notifications.mutedTopics` (sent to the server).
 *
 * Pattern like ClientPolicyService: constructor({ apiClient, store, log, … }),
 * start()/stop(). Events (EventEmitter, or the matching on* callbacks):
 *   'hello'        (hello)            stream open; { keepalive_s, via, unread, topics, … }
 *   'notification' (n)                payload of the contract + { received_at, via }
 *   'read'         ({ ids })          read on another device → hide here
 *   'revoke'       ({ ids })          withdrawn by the server → hide here
 *   'status'       (status())         state changes (see status())
 *   'event'        ({ event, data })  other stream events (policy, support_bundle, …)
 *   'reset'        ()                 server/token changed: lastSeq cleared, drop caches
 */

'use strict';

const EventEmitter = require('events');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { SseParser } = require('../utils/sse-parser');
const { readNotificationSettings } = require('../utils/notify-schema');
const { checkPushPath, isTunnelOnly } = require('../utils/push-path');

const ENDPOINT = '/api/v1/client/push';
const TOPIC_RE = /^(?:security|devices|services|system|admin_notice|plugin:[a-z0-9]+(?:-[a-z0-9]+)*:[a-z][a-z0-9_-]{0,31})$/;
const ACK_STATES = new Set(['delivered', 'read', 'dismissed']);
const ACTION_RE = /^[A-Za-z0-9_.:-]{1,40}$/;
const MAX_ACK = 200;
const MAX_ERROR_BODY = 4096;

const DEFAULT_TIMING = Object.freeze({
  initialDelayMs: 1000,        // first reconnect delay
  maxDelayMs: 5 * 60 * 1000,   // backoff ceiling
  disabledRetryMs: 60 * 60 * 1000, // 404 / push_disabled / direct_not_allowed
  rateLimitMs: 15 * 60 * 1000, // 429 minimum
  connectTimeoutMs: 15000,     // until the response headers arrive
  defaultKeepaliveS: 25,       // until hello says otherwise
  stableAfterMs: 30000,        // a stream that lived this long resets the backoff
  ackDelayMs: 250,             // batching of `delivered` confirmations
  networkDebounceMs: 1000,     // networkChanged() → reconnect
});

/** Connection states reported by status().state. */
const STATE = Object.freeze({
  STOPPED: 'stopped',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISABLED: 'disabled',
  ERROR: 'error',
});

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

class PushClient extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient (serverUrl, apiKey, buildHeaders, pushAck, pushInbox, pushPrefs, pushTest)
   * @param {object} opts.store - electron-store compatible ({ get, set }), dot paths
   * @param {object} [opts.log]
   * @param {string} [opts.storeKey='notifications']
   * @param {() => boolean} [opts.isTunnelUp] - tunnel state (mode vpn_only)
   * @param {() => boolean} [opts.isKillSwitchActive]
   * @param {() => (string|null|Promise<string|null>)} [opts.getWgConfig] - WireGuard config text (kill-switch check)
   * @param {Function} [opts.lookup] - dns.promises.lookup (tests)
   * @param {object} [opts.agent] - http(s).Agent for the stream (e.g. a proxy agent)
   * @param {boolean} [opts.allowHttp=false] - allow http:// (tests only; setups are https)
   * @param {() => number} [opts.random=Math.random]
   * @param {object} [opts.timing] - overrides of DEFAULT_TIMING (tests)
   * @param {Function} [opts.onHello] [opts.onNotification] [opts.onRead] [opts.onRevoke] [opts.onStatus] [opts.onEvent]
   */
  constructor({
    apiClient, store, log, storeKey = 'notifications',
    isTunnelUp, isKillSwitchActive, getWgConfig, lookup, agent,
    allowHttp = false, random = Math.random, timing = {},
    onHello, onNotification, onRead, onRevoke, onStatus, onEvent,
  } = {}) {
    super();
    this.apiClient = apiClient;
    this.store = store;
    this.log = log || noopLog();
    this.storeKey = storeKey;
    this.isTunnelUp = typeof isTunnelUp === 'function' ? isTunnelUp : () => false;
    this.isKillSwitchActive = typeof isKillSwitchActive === 'function' ? isKillSwitchActive : () => false;
    this.getWgConfig = typeof getWgConfig === 'function' ? getWgConfig : null;
    this.lookup = lookup;
    this.agent = agent;
    this.allowHttp = allowHttp === true;
    this.random = random;
    this.timing = { ...DEFAULT_TIMING, ...timing };

    const cb = { hello: onHello, notification: onNotification, read: onRead, revoke: onRevoke, status: onStatus, event: onEvent };
    for (const [ev, fn] of Object.entries(cb)) if (typeof fn === 'function') this.on(ev, fn);

    this._running = false;
    this._gen = 0;
    this._req = null;
    this._res = null;
    this._timers = { retry: null, connect: null, watchdog: null, ack: null, network: null };
    this._attempt = 0;
    this._openedAt = 0;
    this._keepaliveS = this.timing.defaultKeepaliveS;
    this._pendingDelivered = new Set();
    this._ackInflight = null;
    this._prefsSynced = false;
    this._path = null;
    this._status = {
      state: STATE.STOPPED, reason: null, code: null, via: null, since: null, retryAt: null,
      attempt: 0, unread: null, topics: [], keepaliveS: null, serverTime: null, lastEventAt: null,
    };

    this._parser = new SseParser({
      onEvent: (ev) => this._onSse(ev),
      onComment: () => {},
    });
  }

  // ── Public API ───────────────────────────────────────────

  /** Open the stream (no-op while running). */
  start() {
    if (this._running) return;
    this._running = true;
    this._attempt = 0;
    this._prefsSynced = false;
    this.refreshPath();
    this._connect();
  }

  /** Close the stream and stop reconnecting. Pending delivered-acks are flushed. */
  stop() {
    this._running = false;
    this._teardown();
    this._clearTimer('retry');
    this._clearTimer('network');
    this._flushAcks();
    this._setStatus({ state: STATE.STOPPED, reason: null, code: null, via: null, since: null, retryAt: null });
  }

  /**
   * Stop and start again — after server:setup (new URL / token) or to retry
   * after an auth error. { resetSeq: true } also forgets the last seq.
   */
  restart({ resetSeq = false } = {}) {
    this.stop();
    if (resetSeq) this._writeSeq(0, '');
    this._attempt = 0;
    this.start();
  }

  /**
   * Network changed (tunnel up/down, interface change): reconnect so the
   * server sees the new path (`via`), connect now when waiting for the
   * tunnel / for direct access, disconnect in mode vpn_only without tunnel.
   */
  networkChanged() {
    if (!this._running) return;
    this._clearTimer('network');
    this._timers.network = this._timer(() => {
      this._timers.network = null;
      this.refreshPath();
      const { state, reason } = this._status;
      if (state === STATE.ERROR && (reason === 'auth' || reason === 'rate_limited')) return;
      if (state === STATE.DISABLED && (reason === 'unsupported' || reason === 'push_disabled' || reason === 'off')) return;
      this._teardown();
      this._clearTimer('retry');
      this._connect();
    }, this.timing.networkDebounceMs);
  }

  /**
   * Re-read the device settings (enabled / direct / mutedTopics changed):
   * tells the server and connects or disconnects accordingly.
   */
  applySettings() {
    this._prefsSynced = false;
    const s = this._settings();
    if (!this._running) return;
    if (!s.enabled) {
      // Tell the server first so it stops queueing for this device.
      this.setPrefs(this._serverPrefs(s)).catch(() => {});
      this._teardown();
      this._clearTimer('retry');
      this._setStatus({ state: STATE.DISABLED, reason: 'off', code: null, via: null, since: null, retryAt: null });
      return;
    }
    if (this._status.state === STATE.CONNECTED) {
      this._syncPrefs();
      if (!s.direct && !this.isTunnelUp()) this.networkChanged();
      return;
    }
    if (this._status.state === STATE.ERROR && this._status.reason === 'auth') return;
    this._teardown();
    this._clearTimer('retry');
    this._connect();
  }

  /**
   * Current state for the UI:
   * { state: 'stopped'|'connecting'|'connected'|'disabled'|'error', reason, code,
   *   via: 'direct'|'tunnel'|null, since (ISO, stream open), retryAt (ISO),
   *   attempt, unread, topics, keepaliveS, serverTime, lastEventAt, lastSeq,
   *   serverHost, killSwitch: { active, tunnelOnly, path } }
   */
  status() {
    const ks = this._safe(() => this.isKillSwitchActive(), false) === true;
    let serverHost = null;
    try { serverHost = new URL(this.apiClient.serverUrl).host; } catch { /* not configured */ }
    return {
      ...this._status,
      topics: this._status.topics.slice(),
      lastSeq: this._settings().lastSeq,
      serverHost,
      killSwitch: { active: ks, tunnelOnly: isTunnelOnly(this._path, ks), path: this._path },
    };
  }

  /**
   * Confirm deliveries now. state: 'delivered' | 'read' | 'dismissed'.
   * Resolves { ok: true } or { ok: false, error } — never throws.
   */
  async ack(seqs, state = 'read', action = null) {
    const list = [...new Set((Array.isArray(seqs) ? seqs : [seqs]).filter((s) => Number.isSafeInteger(s) && s > 0))];
    if (!list.length) return { ok: true, count: 0 };
    if (!ACK_STATES.has(state)) return { ok: false, error: 'invalid_state' };
    if (action != null && !ACTION_RE.test(String(action))) return { ok: false, error: 'invalid_action' };
    try {
      for (let i = 0; i < list.length; i += MAX_ACK) {
        await this.apiClient.pushAck({ seqs: list.slice(i, i + MAX_ACK), state, action: action || undefined });
      }
      if (state !== 'delivered') for (const s of list) this._pendingDelivered.delete(s);
      return { ok: true, count: list.length };
    } catch (err) {
      return { ok: false, error: this._errCode(err) };
    }
  }

  /** Server inbox: { ok, items, unread } or { ok: false, error }. */
  async fetchInbox({ limit = 100, before = null } = {}) {
    try {
      const data = await this.apiClient.pushInbox({ limit, before: before == null ? undefined : before });
      if (!data || !Array.isArray(data.items)) return { ok: false, error: 'bad_response' };
      return { ok: true, items: data.items, unread: Number.isFinite(data.unread) ? data.unread : null };
    } catch (err) {
      return { ok: false, error: this._errCode(err) };
    }
  }

  /**
   * Device preferences on the server. Accepts { enabled, mode, muted_topics }
   * (or mutedTopics / direct). Resolves { ok } or { ok: false, error }.
   */
  async setPrefs(prefs = {}) {
    const body = {};
    if (typeof prefs.enabled === 'boolean') body.enabled = prefs.enabled;
    if (prefs.mode === 'always' || prefs.mode === 'vpn_only') body.mode = prefs.mode;
    else if (typeof prefs.direct === 'boolean') body.mode = prefs.direct ? 'always' : 'vpn_only';
    const topics = prefs.muted_topics !== undefined ? prefs.muted_topics : prefs.mutedTopics;
    if (topics !== undefined) {
      if (!Array.isArray(topics)) return { ok: false, error: 'invalid_topics' };
      body.muted_topics = [...new Set(topics.filter((t) => typeof t === 'string' && TOPIC_RE.test(t)))].slice(0, 100);
    }
    try {
      const data = await this.apiClient.pushPrefs(body);
      return { ok: !data || data.ok !== false };
    } catch (err) {
      return { ok: false, error: this._errCode(err) };
    }
  }

  /** Ask the server for a test message: { ok, seq } or { ok: false, error }. */
  async requestTest() {
    try {
      const data = await this.apiClient.pushTest();
      return { ok: !!data && data.ok !== false, seq: data && Number.isSafeInteger(data.seq) ? data.seq : null };
    } catch (err) {
      return { ok: false, error: this._errCode(err) };
    }
  }

  /**
   * Re-check whether the kill switch lets the push channel through outside
   * the tunnel (status().killSwitch). Best-effort, never throws.
   */
  async refreshPath() {
    if (!this.getWgConfig) return null;
    try {
      const wgConfig = await this.getWgConfig();
      this._path = await checkPushPath({ serverUrl: this.apiClient && this.apiClient.serverUrl, wgConfig, lookup: this.lookup });
    } catch (err) {
      this.log.debug(`Push path check failed: ${err.message}`);
      this._path = null;
    }
    this.emit('status', this.status());
    return this._path;
  }

  // ── Connection ───────────────────────────────────────────

  _connect() {
    if (!this._running) return;
    const s = this._settings();
    const api = this.apiClient || {};
    if (!s.enabled) {
      this._setStatus({ state: STATE.DISABLED, reason: 'off', code: null, via: null, since: null, retryAt: null });
      return;
    }
    if (!api.serverUrl || !api.apiKey || typeof api.buildHeaders !== 'function') {
      this._setStatus({ state: STATE.DISABLED, reason: 'not_configured', code: null, via: null, since: null, retryAt: null });
      return;
    }
    if (!s.direct && !this._safe(() => this.isTunnelUp(), false)) {
      this._setStatus({ state: STATE.DISABLED, reason: 'vpn_only', code: null, via: null, since: null, retryAt: null });
      return;
    }
    let url;
    try {
      url = new URL(ENDPOINT, String(api.serverUrl).replace(/\/+$/, '') + '/');
    } catch {
      this._setStatus({ state: STATE.DISABLED, reason: 'not_configured', code: null, via: null, since: null, retryAt: null });
      return;
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && this.allowHttp)) {
      this._setStatus({ state: STATE.DISABLED, reason: 'insecure_url', code: null, via: null, since: null, retryAt: null });
      return;
    }

    const lastSeq = this._scopedSeq(url.origin, api.apiKey);
    const headers = {
      ...api.buildHeaders(),
      Accept: 'text/event-stream',
      'Cache-Control': 'no-cache',
    };
    delete headers['Content-Type'];
    if (lastSeq > 0) headers['Last-Event-ID'] = String(lastSeq);

    const gen = ++this._gen;
    this._setStatus({ state: STATE.CONNECTING, reason: null, code: null, via: null, since: null, retryAt: null, attempt: this._attempt });
    const mod = url.protocol === 'https:' ? https : http;
    let req;
    try {
      req = mod.request(url, { method: 'GET', headers, agent: this.agent });
    } catch (err) {
      this._fail(gen, 'network', err.message);
      return;
    }
    this._req = req;
    this._timers.connect = this._timer(() => {
      this._timers.connect = null;
      if (gen !== this._gen) return;
      this._fail(gen, 'timeout');
    }, this.timing.connectTimeoutMs);

    req.on('response', (res) => this._onResponse(gen, res));
    req.on('error', (err) => {
      if (gen !== this._gen) return;
      this._fail(gen, 'network', err.code || err.message);
    });
    req.end();
  }

  _onResponse(gen, res) {
    if (gen !== this._gen) { res.resume(); return; }
    this._clearTimer('connect');
    const status = res.statusCode;
    const type = String(res.headers['content-type'] || '');
    if (status !== 200) {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (body.length < MAX_ERROR_BODY) body += c; });
      res.on('end', () => {
        if (gen !== this._gen) return;
        const data = parseJson(body);
        this._httpError(gen, status, data && typeof data.error === 'string' ? data.error : null, res.headers);
      });
      res.on('error', () => { if (gen === this._gen) this._httpError(gen, status, null, res.headers); });
      return;
    }
    if (!/^text\/event-stream/i.test(type)) {
      res.resume();
      this._fail(gen, 'bad_response', type || 'no content-type');
      return;
    }
    this._res = res;
    this._openedAt = Date.now();
    this._parser.reset();
    this._keepaliveS = this.timing.defaultKeepaliveS;
    this._armWatchdog(gen);
    res.on('data', (chunk) => {
      if (gen !== this._gen) return;
      this._armWatchdog(gen);
      try {
        this._parser.push(chunk);
      } catch (err) {
        this._fail(gen, 'bad_response', err.message);
      }
    });
    const ended = () => {
      if (gen !== this._gen) return;
      this._parser.end();
      this._streamEnded(gen);
    };
    res.on('end', ended);
    res.on('close', ended);
    res.on('error', ended);
  }

  _armWatchdog(gen) {
    this._clearTimer('watchdog');
    const ms = Math.max(1000, this._keepaliveS * 2 * 1000);
    this._timers.watchdog = this._timer(() => {
      this._timers.watchdog = null;
      if (gen !== this._gen) return;
      this.log.info(`Push stream silent for ${ms / 1000} s — reconnecting`);
      this._fail(gen, 'keepalive_timeout');
    }, ms);
  }

  _streamEnded(gen) {
    const lived = this._openedAt ? Date.now() - this._openedAt : 0;
    this._teardown();
    if (!this._running) return;
    if (lived >= this.timing.stableAfterMs) this._attempt = 0;
    this._retry(gen, this._nextDelay(), { state: STATE.CONNECTING, reason: 'reconnecting' });
  }

  _fail(gen, reason, detail) {
    if (gen !== this._gen) return;
    const lived = this._openedAt ? Date.now() - this._openedAt : 0;
    this._teardown();
    if (!this._running) return;
    if (lived >= this.timing.stableAfterMs) this._attempt = 0;
    this.log.debug(`Push stream ${reason}${detail ? `: ${detail}` : ''}`);
    this._retry(gen, this._nextDelay(), { state: STATE.ERROR, reason });
  }

  _httpError(gen, status, code, headers) {
    this._teardown();
    if (!this._running) return;
    const T = this.timing;
    if (status === 404) {
      this.log.info('Push not supported by this server — retrying hourly');
      return this._retry(gen, T.disabledRetryMs, { state: STATE.DISABLED, reason: 'unsupported', code: 404 });
    }
    if (status === 503 && code === 'push_disabled') {
      this.log.info('Push is switched off on the server — retrying hourly');
      return this._retry(gen, T.disabledRetryMs, { state: STATE.DISABLED, reason: 'push_disabled', code });
    }
    if (status === 403 && code === 'direct_not_allowed') {
      this.log.info('Server allows push only through the tunnel — waiting for the VPN');
      return this._retry(gen, T.disabledRetryMs, { state: STATE.DISABLED, reason: 'direct_not_allowed', code });
    }
    if (status === 429) {
      const retryAfter = Number(headers && headers['retry-after']);
      const ms = Math.max(T.rateLimitMs, Number.isFinite(retryAfter) ? retryAfter * 1000 : 0);
      this.log.warn(`Push stream rate limited — next attempt in ${Math.round(ms / 60000)} min`);
      return this._retry(gen, ms, { state: STATE.ERROR, reason: 'rate_limited', code: code || 429 });
    }
    if (status === 401 || status === 403) {
      this.log.warn(`Push stream refused (${status} ${code || ''}) — stopped until the server setup changes`);
      this._clearTimer('retry');
      this._setStatus({ state: STATE.ERROR, reason: 'auth', code: code || status, via: null, since: null, retryAt: null });
      return undefined;
    }
    this.log.debug(`Push stream HTTP ${status}${code ? ` ${code}` : ''}`);
    return this._retry(gen, this._nextDelay(), { state: STATE.ERROR, reason: code || `http_${status}`, code: code || status });
  }

  _nextDelay() {
    const T = this.timing;
    const base = Math.min(T.maxDelayMs, T.initialDelayMs * 2 ** Math.min(this._attempt, 30));
    this._attempt += 1;
    return Math.round(base / 2 + this.random() * (base / 2));
  }

  _retry(gen, ms, status) {
    this._clearTimer('retry');
    this._setStatus({ code: null, via: null, since: null, ...status, retryAt: new Date(Date.now() + ms).toISOString(), attempt: this._attempt });
    this._timers.retry = this._timer(() => {
      this._timers.retry = null;
      if (!this._running) return;
      this._connect();
    }, ms);
  }

  /** Abort the current request/stream (no retry scheduling). */
  _teardown() {
    this._gen++;
    this._clearTimer('connect');
    this._clearTimer('watchdog');
    const req = this._req;
    const res = this._res;
    this._req = null;
    this._res = null;
    this._openedAt = 0;
    if (res) { try { res.destroy(); } catch { /* gone */ } }
    if (req) { try { req.destroy(); } catch { /* gone */ } }
  }

  // ── Stream events ────────────────────────────────────────

  _onSse({ event, data, id }) {
    this._status.lastEventAt = new Date().toISOString();
    const payload = parseJson(data);
    switch (event) {
      case 'hello': return this._onHello(payload || {});
      case 'notification': return this._onNotification(payload, id);
      case 'read':
      case 'revoke': {
        const ids = payload && Array.isArray(payload.ids) ? payload.ids.filter((x) => Number.isSafeInteger(x)) : [];
        if (ids.length) this.emit(event, { ids });
        return undefined;
      }
      default:
        this.emit('event', { event, data: payload !== null ? payload : data, id });
        return undefined;
    }
  }

  _onHello(hello) {
    const ka = Number(hello.keepalive_s);
    this._keepaliveS = Number.isFinite(ka) && ka >= 1 && ka <= 600 ? ka : this.timing.defaultKeepaliveS;
    this._armWatchdog(this._gen);
    const via = hello.via === 'tunnel' || hello.via === 'direct' ? hello.via : null;
    const topics = Array.isArray(hello.topics)
      ? hello.topics.filter((t) => t && typeof t.id === 'string').map((t) => ({ id: t.id, label: typeof t.label === 'string' ? t.label : t.id }))
      : [];
    this._setStatus({
      state: STATE.CONNECTED, reason: null, code: null, retryAt: null,
      via, since: new Date().toISOString(),
      unread: Number.isFinite(hello.unread) ? hello.unread : null,
      topics, keepaliveS: this._keepaliveS,
      serverTime: typeof hello.server_time === 'string' ? hello.server_time : null,
    });
    this.log.info(`Push connected (${via || 'unknown path'})`);
    this.emit('hello', { ...hello, via, topics });
    this._flushAcks();
    this._syncPrefs();
  }

  _onNotification(n, id) {
    if (!n || typeof n !== 'object') return;
    const seq = Number.isSafeInteger(n.seq) ? n.seq : Number(id);
    if (!Number.isSafeInteger(seq) || seq <= 0) return;
    const s = this._settings();
    this._queueDelivered(seq);
    if (seq <= s.lastSeq) return; // replay of something already processed
    this._writeSeq(seq);
    this.emit('notification', { ...n, seq, received_at: new Date().toISOString(), via: this._status.via });
  }

  // ── Acks / prefs ─────────────────────────────────────────

  _queueDelivered(seq) {
    this._pendingDelivered.add(seq);
    if (this._timers.ack) return;
    this._timers.ack = this._timer(() => {
      this._timers.ack = null;
      this._flushAcks();
    }, this.timing.ackDelayMs);
  }

  /**
   * Send the waiting `delivered` confirmations (≤ 200 per request; the rest
   * follows). On failure they stay queued and go out after the next hello.
   */
  _flushAcks() {
    this._clearTimer('ack');
    if (this._ackInflight) return this._ackInflight;
    if (!this._pendingDelivered.size) return Promise.resolve({ ok: true, count: 0 });
    const seqs = [...this._pendingDelivered].slice(0, MAX_ACK);
    this._ackInflight = this.ack(seqs, 'delivered').then((r) => {
      this._ackInflight = null;
      if (!r.ok) {
        this.log.debug(`Push ack failed (${r.error}) — retrying after the next connect`);
        return r;
      }
      for (const s of seqs) this._pendingDelivered.delete(s);
      return this._pendingDelivered.size ? this._flushAcks() : r;
    });
    return this._ackInflight;
  }

  _serverPrefs(s) {
    return { enabled: s.enabled, mode: s.direct ? 'always' : 'vpn_only', muted_topics: s.mutedTopics };
  }

  _syncPrefs() {
    if (this._prefsSynced) return;
    this._prefsSynced = true;
    this.setPrefs(this._serverPrefs(this._settings())).then((r) => {
      if (!r.ok) {
        this._prefsSynced = false;
        this.log.debug(`Push prefs not sent: ${r.error}`);
      }
    });
  }

  // ── Store ────────────────────────────────────────────────

  _settings() {
    return readNotificationSettings(this.store, this.storeKey);
  }

  /** lastSeq of this server + token; a different scope starts at 0. */
  _scopedSeq(origin, apiKey) {
    const scope = crypto.createHash('sha256').update(`${origin}\n${apiKey}`).digest('hex').slice(0, 16);
    const s = this._settings();
    if (s.seqScope === scope) return s.lastSeq;
    const changed = s.seqScope !== '' || s.lastSeq !== 0;
    this._writeSeq(0, scope);
    if (changed) {
      this.log.info('Push: new server or token — starting without resume position');
      this.emit('reset');
    }
    return 0;
  }

  _writeSeq(seq, scope) {
    try {
      this.store.set(`${this.storeKey}.lastSeq`, seq);
      if (scope !== undefined) this.store.set(`${this.storeKey}.seqScope`, scope);
    } catch (err) {
      this.log.warn(`Push position could not be saved: ${err.message}`);
    }
  }

  // ── Helpers ──────────────────────────────────────────────

  _setStatus(patch) {
    const before = JSON.stringify(this._status);
    Object.assign(this._status, patch);
    if (JSON.stringify(this._status) !== before) this.emit('status', this.status());
  }

  _timer(fn, ms) {
    const t = setTimeout(fn, ms);
    if (t && typeof t.unref === 'function') t.unref();
    return t;
  }

  _clearTimer(name) {
    if (this._timers[name]) clearTimeout(this._timers[name]);
    this._timers[name] = null;
  }

  _safe(fn, fallback) {
    try { return fn(); } catch { return fallback; }
  }

  _errCode(err) {
    const data = err && err.response && err.response.data;
    if (data && typeof data.error === 'string') return data.error;
    if (err && err.response && err.response.status) return `http_${err.response.status}`;
    return (err && (err.code || err.message)) || 'failed';
  }

  /** EventEmitter: listener errors must not break the stream. */
  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Push listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

PushClient.ENDPOINT = ENDPOINT;
PushClient.STATE = STATE;
PushClient.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = PushClient;
