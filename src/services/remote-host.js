'use strict';

/**
 * GateControl – Fernzugriff: this PC as a host (Core service, stage 2 "Windows-Schalter")
 *
 * The existing switch "Remote Desktop erlauben" registers the PC with the plugin
 * `gatecontrol-remote` (1.1): it shows up at once under Fernzugriff › Geräte and for everybody
 * allowed. Standard "nur mit Code": the app shows a code (a new one after every session and when
 * one runs out); a helper redeems it and the person here confirms in a dialog ("Ansehen und
 * steuern" / "Nur ansehen" / "Ablehnen", 30 s). "Ohne Code für Berechtigte" is the second switch.
 *
 * Port 3389 stays closed until the plugin asks for a session: silent data pushes on the topic
 * plugin:gatecontrol-remote:remote_signal (notification center → addPushHandler) say
 *   remote.request / remote.request.cancel    a helper asks (→ event 'request')
 *   remote.firewall.open { sessionKey, allow, port, until }   a rule for exactly one address
 *   remote.firewall.close { sessionKey }     the session is over → the rule goes, a new code
 *   remote.code.void                         too many wrong codes → a new code
 * The app reports every rule (POST host/firewall). On start (and when the switch goes on) it
 * removes all rules "GateControl RDP *" and asks GET host/firewall for the ones still open.
 *
 * A server without the plugin (or with 1.0): status 'unavailable' — the caller keeps the old
 * behaviour (rdp-allow.js, 3389 for the whole VPN).
 *
 * status: 'off' | 'starting' | 'ready' | 'rdp_off' | 'home' | 'no_right' | 'unavailable' | 'offline' | 'error'
 * Events: 'state' (status()), 'request' ({ requestId, from: { userId, name }, mode, via, expiresAt } | null)
 */

const { EventEmitter } = require('events');
const { IPV4_RE } = require('../utils/validation');
const RemoteHostApi = require('./remote-host-api');
const RdpSessionFirewall = require('./rdp-session-firewall');

const SIGNAL_TOPIC = 'plugin:gatecontrol-remote:remote_signal';
const HEARTBEAT_MS = 60000;
const REQUEST_MS = 30000;
const MAX_RULE_MS = 8 * 3600000;
const UNAVAILABLE_CODES = new Set(['not_found', 'not_running', 'offline', 'forbidden', 'http_404', 'http_503']);

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class RemoteHost extends EventEmitter {
  /**
   * @param {object} o
   * @param {object} o.api - RemoteHostApi
   * @param {object} o.firewall - RdpSessionFirewall
   * @param {object} o.info - WindowsRdpInfo
   * @param {object} [o.notificationCenter] - addPushHandler(handler)
   * @param {object} [o.log]
   * @param {string} [o.name] - the PC's name (os.hostname())
   * @param {string} [o.appVersion]
   * @param {() => number} [o.now]
   * @param {Function} [o.setTimer] / [o.clearTimer] - tests
   */
  constructor({ api, firewall, info, notificationCenter = null, log, name = null, appVersion = null, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    super();
    this.api = api;
    this.firewall = firewall;
    this.info = info;
    this.log = log || noopLog();
    this.name = name || require('os').hostname();
    this.appVersion = appVersion;
    this.now = now;
    this._set = setTimer;
    this._clear = clearTimer;
    this._timers = new Map(); // beat | code | request → timer
    this._rules = new Map(); // sessionKey → { allow, untilTimer }
    this._state = { enabled: false, status: 'off', deviceId: null, shareMode: 'code', allowOpen: true, code: null, codeExpiresAt: null, request: null, sessions: 0, builtInOpen: null, edition: null, error: null };
    this._seq = 0;
    if (notificationCenter && typeof notificationCenter.addPushHandler === 'function') {
      this._offPush = notificationCenter.addPushHandler({ notification: (n) => this._push(n) });
    }
  }

  /** The state for the UI (never a session key or an address). */
  status() {
    const s = this._state;
    return { enabled: s.enabled, status: s.status, deviceId: s.deviceId, shareMode: s.shareMode, allowOpen: s.allowOpen, code: s.code, codeExpiresAt: s.codeExpiresAt,
      request: s.request ? { ...s.request } : null, sessions: this._rules.size, builtInOpen: s.builtInOpen, edition: s.edition, error: s.error };
  }

  _update(patch) {
    Object.assign(this._state, patch);
    this.emit('state', this.status());
  }

  _timer(name, ms, fn) {
    const old = this._timers.get(name);
    if (old) this._clear(old);
    this._timers.delete(name);
    if (ms == null) return;
    const t = this._set(() => { if (this._timers.get(name) === t) this._timers.delete(name); fn(); }, Math.max(0, ms));
    this._timers.set(name, t);
  }

  /** App start: clean up the rules, then register when the switch is on. */
  async start(enabled) {
    await this.firewall.closeAll();
    if (enabled) return this.enable();
    return this.status();
  }

  /** The switch is on → registers the PC; returns status(). */
  async enable() {
    const seq = ++this._seq;
    this._update({ enabled: true, status: 'starting', error: null });
    const det = await this.info.detect();
    if (seq !== this._seq) return this.status();
    this._update({ edition: det.edition });
    if (det.rdpAvailable === false) { this._update({ status: 'home' }); return this.status(); }
    let r;
    try {
      r = await this.api.register({ name: this.name, edition: det.edition || 'pro', rdp: { available: true, enabled: det.rdpEnabled !== false, port: 3389 },
        osUser: det.osUser, appVersion: this.appVersion });
    } catch (err) {
      if (seq !== this._seq) return this.status();
      return this._failed(err, true);
    }
    if (seq !== this._seq) return this.status();
    const h = (r && r.host) || {};
    this._update({ deviceId: h.deviceId || null, shareMode: h.shareMode === 'open' ? 'open' : 'code', allowOpen: h.allowOpen !== false,
      status: h.state === 'rdp_off' ? 'rdp_off' : 'ready', builtInOpen: await this.firewall.builtInOpen() });
    await this._restoreRules();
    await this.newCode();
    this._timer('beat', HEARTBEAT_MS, () => this.heartbeat());
    return this.status();
  }

  _failed(err, retry) {
    const code = err && err.code;
    let status = 'error';
    if (code === 'home_edition') status = 'home';
    else if (code === 'no_share_right') status = 'no_right';
    else if (UNAVAILABLE_CODES.has(code)) status = 'unavailable';
    else if (code === 'network' || code === 'timeout' || code === 'not_configured' || (err && err.transient)) status = 'offline';
    this.log.warn(`Remote host: ${status} (${code || (err && err.message)})`);
    this._update({ status, error: status === 'error' ? String(code || 'failed') : null });
    // offline: try again with the next beat
    if (retry && status === 'offline') this._timer('beat', HEARTBEAT_MS, () => this.enable());
    return this.status();
  }

  /** The switch is off: the PC is signed off, every rule goes. */
  async disable() {
    this._seq++;
    for (const k of [...this._timers.keys()]) this._timer(k, null);
    const wasRegistered = !!this._state.deviceId && this._state.status !== 'unavailable';
    this._update({ enabled: false, status: 'off', code: null, codeExpiresAt: null, request: null, deviceId: null, error: null });
    this.emit('request', null);
    for (const key of [...this._rules.keys()]) await this._closeRule(key, false);
    await this.firewall.closeAll();
    if (wasRegistered) { try { await this.api.unregister(); } catch (err) { this.log.warn('Remote host: sign-off failed:', err && err.code); } }
    return this.status();
  }

  /** Every 60 s and after changes: the state to the server, waiting requests back. */
  async heartbeat() {
    if (!this._state.enabled || !this._state.deviceId) return this.status();
    const det = await this.info.detect();
    try {
      const r = await this.api.state({ rdp: { enabled: det.rdpEnabled !== false }, osUser: det.osUser, online: true });
      this._update({ shareMode: r.shareMode === 'open' ? 'open' : 'code', allowOpen: r.allowOpen !== false, status: det.rdpEnabled === false ? 'rdp_off' : 'ready' });
      const p = Array.isArray(r.pending) ? r.pending[0] : null;
      if (p && !this._state.request) this._ask(p);
    } catch (err) {
      // the plugin forgot the PC (deleted by an administrator): register again
      if (err && err.code === 'not_found') { this._timer('beat', null); return this.enable(); }
      this.log.debug('Remote host: heartbeat failed', err && err.code);
    }
    this._timer('beat', HEARTBEAT_MS, () => this.heartbeat());
    return this.status();
  }

  /** A new code (after every session, when one runs out, on request). */
  async newCode() {
    if (!this._state.enabled || !this._state.deviceId) return this.status();
    try {
      const c = await this.api.code();
      this._update({ code: c.code, codeExpiresAt: c.expiresAt });
      const left = Date.parse(c.expiresAt) - this.now();
      this._timer('code', Number.isFinite(left) ? left + 500 : HEARTBEAT_MS, () => this.newCode());
    } catch (err) {
      this.log.debug('Remote host: no code', err && err.code);
      this._update({ code: null, codeExpiresAt: null });
      this._timer('code', HEARTBEAT_MS, () => this.newCode());
    }
    return this.status();
  }

  /** "Ohne Code für Berechtigte" on / off. */
  async setShareMode(mode) {
    const m = mode === 'open' ? 'open' : 'code';
    const r = await this.api.share(m);
    this._update({ shareMode: r.shareMode === 'open' ? 'open' : 'code' });
    return this.status();
  }

  /** "In Windows einschalten" (Remote Desktop off in Windows). */
  async enableRdpInWindows() {
    await this.info.enable();
    return this.heartbeat();
  }

  _ask(p) {
    const req = { requestId: String(p.requestId), from: { userId: p.from && p.from.userId ? p.from.userId : null, name: p.from && p.from.name ? String(p.from.name).slice(0, 120) : null },
      mode: p.mode === 'view' ? 'view' : 'control', via: p.via === 'app' ? 'app' : 'browser', expiresAt: p.expiresAt || new Date(this.now() + REQUEST_MS).toISOString() };
    if (!RemoteHostApi.REQUEST_RE.test(req.requestId)) return;
    this._update({ request: req });
    this.emit('request', { ...req });
    const left = Date.parse(req.expiresAt) - this.now();
    this._timer('request', Number.isFinite(left) ? Math.min(left, REQUEST_MS) : REQUEST_MS, () => {
      if (this._state.request && this._state.request.requestId === req.requestId) this._endRequest(true);
    });
  }

  _endRequest(renew) {
    this._timer('request', null);
    this._update({ request: null });
    this.emit('request', null);
    if (renew) this.newCode().catch(() => {});
  }

  /** The answer of the person here: 'allow' (mode view|control) or 'deny'. */
  async decide(requestId, decision, mode) {
    const cur = this._state.request;
    if (!cur || cur.requestId !== requestId) throw Object.assign(new Error('no such request'), { code: 'request_expired' });
    const allow = decision === 'allow';
    try {
      await this.api.decide(requestId, allow ? 'allow' : 'deny', allow && mode === 'view' ? 'view' : undefined);
    } finally {
      // denied or failed: the code is used — show a new one; allowed: a new one after the session
      this._endRequest(!allow);
    }
    return this.status();
  }

  // ── Signals ──────────────────────────────────────────────

  _push(n) {
    if (!n || n.kind !== 'data' || n.topic !== SIGNAL_TOPIC) return false;
    const d = n.data && typeof n.data === 'object' ? n.data : {};
    if (!this._state.enabled) return 'consumed';
    Promise.resolve().then(() => this._signal(d)).catch((err) => this.log.warn('Remote host: signal failed:', err && err.message));
    return 'consumed';
  }

  async _signal(d) {
    switch (d.type) {
      case 'remote.request': return this._ask(d);
      case 'remote.request.cancel':
        if (this._state.request && this._state.request.requestId === d.requestId) this._endRequest(true);
        return null;
      case 'remote.firewall.open': return this._openRule(d);
      case 'remote.firewall.close': return this._closeRule(d.sessionKey, true);
      case 'remote.code.void': return this.newCode();
      default: return null;
    }
  }

  async _openRule(d) {
    const key = String(d.sessionKey || '');
    if (!RdpSessionFirewall.SESSION_KEY_RE.test(key)) return;
    if (typeof d.allow !== 'string' || !IPV4_RE.test(d.allow) || (d.port != null && Number(d.port) !== 3389)) {
      await this.api.firewallReport(key, 'failed', 'invalid').catch(() => {});
      return;
    }
    try {
      await this.firewall.open(key, d.allow, 3389);
    } catch (err) {
      this.log.warn('Remote host: rule not opened:', err && err.message);
      await this.api.firewallReport(key, 'failed', 'netsh').catch(() => {});
      return;
    }
    const until = Date.parse(d.until);
    const ms = Math.min(Number.isFinite(until) ? until - this.now() : MAX_RULE_MS, MAX_RULE_MS);
    const old = this._rules.get(key);
    if (old && old.timer) this._clear(old.timer);
    this._rules.set(key, { allow: d.allow, timer: this._set(() => { this._closeRule(key, true).catch(() => {}); }, Math.max(0, ms)) });
    this._update({});
    await this.api.firewallReport(key, 'open').catch((err) => this.log.warn('Remote host: open not reported:', err && err.code));
  }

  async _closeRule(key, report) {
    if (!RdpSessionFirewall.SESSION_KEY_RE.test(String(key || ''))) return;
    const r = this._rules.get(key);
    if (r && r.timer) this._clear(r.timer);
    this._rules.delete(key);
    await this.firewall.close(key).catch(() => {});
    this._update({});
    if (report) {
      await this.api.firewallReport(key, 'closed').catch(() => {});
      // the session is over: a new code
      await this.newCode();
    }
  }

  /** After a start of the app: the rules the plugin still wants (the app removed all of them first). */
  async _restoreRules() {
    let list = [];
    try { list = ((await this.api.firewallList()) || {}).open || []; } catch { list = []; }
    for (const x of list) await this._openRule(x);
  }

  stop() {
    for (const k of [...this._timers.keys()]) this._timer(k, null);
    for (const r of this._rules.values()) if (r.timer) this._clear(r.timer);
    if (this._offPush) this._offPush();
  }
}

RemoteHost.SIGNAL_TOPIC = SIGNAL_TOPIC;
RemoteHost.HEARTBEAT_MS = HEARTBEAT_MS;

module.exports = RemoteHost;
