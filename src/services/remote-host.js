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
 * Stage 7 (plugin 1.5, contract stage 7): the second switch "Bildschirm teilen" (setScreen) — also on Windows Home.
 * The PC registers with screen: { view, control } and rdp.offered (the first switch); one code serves both. A
 * request of kind 'screen' is asked here like any other ("Nur ansehen" / "Ansehen und steuern"); allowed, the plugin
 * hands the sending side of a ticket of GateControl's relay and ScreenShare sends the picture (and, in control, takes
 * the helper's mouse and keyboard). After the session a new code. Signal remote.screen.end: the helper or the plugin
 * ended it.
 *
 * status: 'off' | 'starting' | 'ready' | 'rdp_off' | 'home' | 'no_right' | 'unavailable' | 'offline' | 'error'
 * screen: { enabled, status: 'off' | 'ready' | 'unavailable', session: ScreenShare.status() | null }
 * Events: 'state' (status()), 'request' ({ requestId, from: { userId, name }, mode, via, kind, expiresAt } | null)
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
   * @param {object} [o.screenShare] - ScreenShare (stage 7; without it "Bildschirm teilen" is not offered)
   * @param {object} [o.log]
   * @param {string} [o.name] - the PC's name (os.hostname())
   * @param {string} [o.appVersion]
   * @param {() => number} [o.now]
   * @param {Function} [o.setTimer] / [o.clearTimer] - tests
   */
  constructor({ api, firewall, info, notificationCenter = null, screenShare = null, log, name = null, appVersion = null, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    super();
    this.api = api;
    this.screenShare = screenShare;
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
    this._state = { enabled: false, status: 'off', deviceId: null, shareMode: 'code', allowOpen: true, code: null, codeExpiresAt: null, request: null, sessions: 0, builtInOpen: null, edition: null, error: null,
      rdpAvailable: null, screenEnabled: false, screenStatus: 'off' };
    this._seq = 0;
    this._screenRequest = null; // the request whose picture runs (or ran): { requestId }
    if (screenShare) screenShare.on('session', (st) => this._onScreen(st));
    if (notificationCenter && typeof notificationCenter.addPushHandler === 'function') {
      this._offPush = notificationCenter.addPushHandler({ notification: (n) => this._push(n) });
    }
  }

  /** The state for the UI (never a session key or an address). */
  status() {
    const s = this._state;
    return { enabled: s.enabled, status: s.status, deviceId: s.deviceId, shareMode: s.shareMode, allowOpen: s.allowOpen, code: s.code, codeExpiresAt: s.codeExpiresAt,
      request: s.request ? { ...s.request } : null, sessions: this._rules.size, builtInOpen: s.builtInOpen, edition: s.edition, error: s.error, rdpAvailable: s.rdpAvailable,
      screen: { supported: !!this.screenShare, enabled: s.screenEnabled, status: s.screenStatus, session: this.screenShare ? this.screenShare.status() : null } };
  }

  /** Is a switch on — the PC should be registered? */
  _wanted() { return this._state.enabled || (this._state.screenEnabled && !!this.screenShare); }

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

  /** App start: clean up the rules, then register when a switch is on (screen: "Bildschirm teilen", stage 7). */
  async start(enabled, screen = false) {
    await this.firewall.closeAll();
    this._state.screenEnabled = screen === true && !!this.screenShare;
    if (enabled) return this.enable();
    if (this._state.screenEnabled) return this._register();
    return this.status();
  }

  /** The switch "Remote Desktop erlauben" is on → registers the PC; returns status(). */
  async enable() {
    this._state.enabled = true;
    return this._register();
  }

  /** Stage 7: "Bildschirm teilen" on / off. Off ends a running session; with both switches off the PC signs off. */
  async setScreen(on) {
    if (on && !this.screenShare) throw Object.assign(new Error('screen sharing not available'), { code: 'unsupported' });
    this._update({ screenEnabled: on === true });
    if (!on) {
      if (this.screenShare && this.screenShare.busy) this.screenShare.stop('switched_off');
      if (this._state.request && this._state.request.kind === 'screen') this._endRequest(false);
      this._update({ screenStatus: 'off' });
      if (!this._state.enabled) return this._signOff();
    }
    return this._register();
  }

  /** Register (or update) the PC with what its switches offer now. */
  async _register() {
    const seq = ++this._seq;
    this._update({ status: 'starting', error: null });
    const det = await this.info.detect();
    if (seq !== this._seq) return this.status();
    const rdpOn = this._state.enabled && det.rdpAvailable !== false;
    const screenOn = this._state.screenEnabled && !!this.screenShare;
    this._update({ edition: det.edition, rdpAvailable: det.rdpAvailable !== false });
    if (!rdpOn && !screenOn) {
      // Windows Home with only "Remote Desktop erlauben": nothing to offer (the app shows "Bildschirm teilen");
      // a PC registered for its screen before signs off
      if (this._state.deviceId) {
        for (const k of [...this._timers.keys()]) this._timer(k, null);
        this._update({ deviceId: null, code: null, codeExpiresAt: null });
        try { await this.api.unregister(); } catch (err) { this.log.warn('Remote host: sign-off failed:', err && err.code); }
      }
      this._update({ status: det.rdpAvailable === false && this._state.enabled ? 'home' : 'off' });
      return this.status();
    }
    let r;
    try {
      r = await this.api.register({ name: this.name, edition: det.edition || 'pro',
        rdp: { available: det.rdpAvailable !== false, enabled: det.rdpEnabled !== false, port: 3389, offered: rdpOn },
        ...(screenOn ? { screen: { view: true, control: true } } : {}), osUser: det.osUser, appVersion: this.appVersion });
    } catch (err) {
      if (seq !== this._seq) return this.status();
      if (err && err.code === 'screen_unavailable') this._update({ screenStatus: 'unavailable' });
      return this._failed(err, true);
    }
    if (seq !== this._seq) return this.status();
    const h = (r && r.host) || {};
    const fresh = !this._state.deviceId || this._state.deviceId !== (h.deviceId || null);
    // a plugin before 1.5 does not know the screen of a PC (no `screen` in the answer)
    const screenOk = screenOn && !!(h.screen && h.screen.view === true);
    this._update({ deviceId: h.deviceId || null, shareMode: h.shareMode === 'open' ? 'open' : 'code', allowOpen: h.allowOpen !== false,
      status: rdpOn && h.state === 'rdp_off' ? 'rdp_off' : 'ready', builtInOpen: rdpOn ? await this.firewall.builtInOpen() : null,
      screenStatus: screenOn ? (screenOk ? 'ready' : 'unavailable') : 'off' });
    if (rdpOn) await this._restoreRules();
    else for (const key of [...this._rules.keys()]) await this._closeRule(key, false);
    if (fresh || !this._state.code) await this.newCode();
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
    if (retry && status === 'offline') this._timer('beat', HEARTBEAT_MS, () => this._register());
    return this.status();
  }

  /** "Remote Desktop erlauben" is off: its rules go; with "Bildschirm teilen" on the PC stays registered for it. */
  async disable() {
    this._update({ enabled: false });
    if (this._state.screenEnabled && this.screenShare) {
      if (this._state.request && this._state.request.kind !== 'screen') this._endRequest(false);
      for (const key of [...this._rules.keys()]) await this._closeRule(key, false);
      await this.firewall.closeAll();
      return this._register();
    }
    return this._signOff();
  }

  /** Both switches are off: the PC is signed off, every rule goes, a running screen session ends. */
  async _signOff() {
    this._seq++;
    if (this.screenShare && this.screenShare.busy) this.screenShare.stop('switched_off');
    for (const k of [...this._timers.keys()]) this._timer(k, null);
    const wasRegistered = !!this._state.deviceId && this._state.status !== 'unavailable';
    this._update({ enabled: false, screenEnabled: false, screenStatus: 'off', status: 'off', code: null, codeExpiresAt: null, request: null, deviceId: null, error: null });
    this.emit('request', null);
    for (const key of [...this._rules.keys()]) await this._closeRule(key, false);
    await this.firewall.closeAll();
    if (wasRegistered) { try { await this.api.unregister(); } catch (err) { this.log.warn('Remote host: sign-off failed:', err && err.code); } }
    return this.status();
  }

  /** Every 60 s and after changes: the state to the server, waiting requests back. */
  async heartbeat() {
    if (!this._wanted() || !this._state.deviceId) return this.status();
    const det = await this.info.detect();
    try {
      const r = await this.api.state({ rdp: { enabled: det.rdpEnabled !== false }, osUser: det.osUser, online: true });
      this._update({ shareMode: r.shareMode === 'open' ? 'open' : 'code', allowOpen: r.allowOpen !== false,
        status: this._state.enabled && det.rdpAvailable !== false && det.rdpEnabled === false ? 'rdp_off' : 'ready' });
      const p = Array.isArray(r.pending) ? r.pending[0] : null;
      if (p && !this._state.request) this._ask(p);
    } catch (err) {
      // the plugin forgot the PC (deleted by an administrator): register again
      if (err && err.code === 'not_found') { this._timer('beat', null); return this._register(); }
      this.log.debug('Remote host: heartbeat failed', err && err.code);
    }
    this._timer('beat', HEARTBEAT_MS, () => this.heartbeat());
    return this.status();
  }

  /** A new code (after every session, when one runs out, on request). */
  async newCode() {
    if (!this._wanted() || !this._state.deviceId) return this.status();
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
      mode: p.mode === 'view' ? 'view' : 'control', via: p.via === 'app' ? 'app' : 'browser', kind: p.kind === 'screen' ? 'screen' : 'rdp',
      expiresAt: p.expiresAt || new Date(this.now() + REQUEST_MS).toISOString() };
    if (!RemoteHostApi.REQUEST_RE.test(req.requestId)) return;
    // a screen request without the switch (or while a session runs): nothing to ask — it runs out at the plugin
    if (req.kind === 'screen' && (!this._state.screenEnabled || !this.screenShare || this.screenShare.busy)) return;
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
    if (cur.kind === 'screen') return this._decideScreen(cur, allow, mode);
    try {
      await this.api.decide(requestId, allow ? 'allow' : 'deny', allow && mode === 'view' ? 'view' : undefined);
    } finally {
      // denied or failed: the code is used — show a new one; allowed: a new one after the session
      this._endRequest(!allow);
    }
    return this.status();
  }

  /**
   * Stage 7: the answer to a screen request. Control only when it was asked for and the person chose it now
   * (mode 'control' said explicitly); anything else is view. Allowed: the picture starts (ScreenShare).
   */
  async _decideScreen(cur, allow, mode) {
    const granted = allow && cur.mode === 'control' && mode === 'control' ? 'control' : 'view';
    let r;
    try {
      r = await this.api.decide(cur.requestId, allow ? 'allow' : 'deny', allow ? granted : undefined);
    } catch (err) {
      this._endRequest(true);
      throw err;
    }
    this._endRequest(!allow);
    if (!allow) return this.status();
    const scr = r && r.screen;
    if (!scr || typeof scr.ref !== 'string') {
      this.log.warn('Remote host: no relay ticket for the screen');
      await this.api.screenEnd(cur.requestId, 'failed').catch(() => {});
      await this.newCode();
      return this.status();
    }
    const mode2 = r.request && r.request.mode === 'control' && granted === 'control' ? 'control' : 'view';
    this._screenRequest = { requestId: cur.requestId };
    try {
      await this.screenShare.start({ requestId: cur.requestId, ref: scr.ref, wsPath: scr.wsPath, mode: mode2, viewerName: cur.from && cur.from.name });
    } catch (err) {
      this.log.warn('Remote host: screen not shared:', err && err.code);
      this._update({ error: err && err.code ? String(err.code) : 'failed' });
    }
    return this.status();
  }

  /** ScreenShare's session changed: the state to the UI; at the end the plugin hears a start that never ran, and a new code. */
  _onScreen(st) {
    this._update({});
    if (!st || st.state !== 'ended') return;
    const req = this._screenRequest;
    this._screenRequest = null;
    if (req && !st.started && st.reason !== 'viewer' && st.reason !== 'ended_by_plugin') {
      this.api.screenEnd(req.requestId, st.reason === 'sender' || st.reason === 'switched_off' ? 'stopped' : 'failed').catch(() => {});
    }
    if (this._wanted()) this.newCode().catch(() => {});
  }

  /** "Nur ansehen" in the bar (stage 7). */
  screenViewOnly() { if (this.screenShare) this.screenShare.downgrade(); return this.status(); }

  /** "Beenden" in the bar (stage 7). */
  screenStop() { if (this.screenShare) this.screenShare.stop('sender'); return this.status(); }

  // ── Signals ──────────────────────────────────────────────

  _push(n) {
    if (!n || n.kind !== 'data' || n.topic !== SIGNAL_TOPIC) return false;
    const d = n.data && typeof n.data === 'object' ? n.data : {};
    if (!this._wanted()) return 'consumed';
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
      // stage 7: the helper or the plugin ended the screen session (the relay already did)
      case 'remote.screen.end':
        if (this.screenShare && this._screenRequest && this._screenRequest.requestId === d.requestId) this.screenShare.end(typeof d.reason === 'string' ? d.reason.slice(0, 40) : 'ended_by_plugin');
        return null;
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
    if (this.screenShare && this.screenShare.busy) this.screenShare.stop('switched_off');
    for (const k of [...this._timers.keys()]) this._timer(k, null);
    for (const r of this._rules.values()) if (r.timer) this._clear(r.timer);
    if (this._offPush) this._offPush();
  }
}

RemoteHost.SIGNAL_TOPIC = SIGNAL_TOPIC;
RemoteHost.HEARTBEAT_MS = HEARTBEAT_MS;

module.exports = RemoteHost;
