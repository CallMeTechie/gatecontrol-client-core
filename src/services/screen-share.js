'use strict';

/**
 * GateControl – Fernzugriff stage 7: one session of "Bildschirm teilen" — this PC as the sender of gc-screen.v1
 * (Core service, contract stage 7)
 *
 * The person here allowed a request (RemoteHost): the plugin handed the sending side of a ticket of GateControl's
 * relay (`ref`). The session turns it into a token (POST /api/v1/client/remote/screen-token, 60 s, once), opens
 * wss://<server>/api/v1/remote/screen-relay with `Sec-WebSocket-Protocol: gc-screen.v1, token.<token>` (the token
 * never in the URL), says hello (input 'desktop', the displays) and sends the picture of ScreenCapture. In mode
 * control the helper's mouse and keyboard go to ScreenInput — only then, and never after "Nur ansehen" or "Beenden".
 *
 *   start({ requestId, ref, wsPath, mode, viewerName })   mode: what the person here allowed (view | control)
 *   downgrade()   "Nur ansehen" in the bar: input stops at once, the relay hears {t:'mode', mode:'view'} (for good)
 *   stop()        "Beenden": input stops at once, then {t:'bye'}
 *   end(reason)   the relay or the plugin ended it (remote.screen.end)
 * Event 'session': { state: 'connecting'|'waiting'|'live'|'ended', requestId, viewer, mode, since, paused, reason, started }
 *
 * A lost connection without an end comes back (1, 2, 4, 8 s, a new token with the same ref); the relay keeps the
 * session 30 s. Windows' secure desktop (UAC prompt, lock screen): the picture is paused for the viewer and input is
 * refused. Nothing of a picture, an input, a ref or a token is logged.
 */

const { EventEmitter } = require('events');
const { frameHeader } = require('../screen-share/h264');

const PROTOCOL = 'gc-screen.v1';
const WS_PATH = '/api/v1/remote/screen-relay';
const PING_MS = 25000;
const DESKTOP_MS = 1000;
const BACKOFF = [1000, 2000, 4000, 8000];
const HIGH_WATER = 2 * 1024 * 1024;
const FAILS_PER_S = 2;
const FPS = 15;
const BITRATE = 2000000;
const FINAL_ERRORS = new Set(['role_mismatch', 'bad_frame', 'rate_exceeded', 'replaced', 'hello_timeout']);

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class ScreenShare extends EventEmitter {
  /**
   * @param {object} o
   * @param {object} o.api - { screenToken(ref) → { token, wsPath, role } } (RemoteHostApi)
   * @param {object} o.capture - ScreenCapture
   * @param {object} o.input - ScreenInput
   * @param {() => string} o.serverUrl - https://… of the GateControl server
   * @param {Function} [o.WebSocketImpl] - the WHATWG WebSocket (Node's global one)
   * @param {string} [o.appVersion]
   * @param {object} [o.log]
   * @param {() => number} [o.now]
   * @param {Function} [o.setTimer] / [o.clearTimer] / [o.setRepeat] / [o.clearRepeat]
   */
  constructor({ api, capture, input, serverUrl, WebSocketImpl = globalThis.WebSocket, appVersion = null, log, now = Date.now,
    setTimer = setTimeout, clearTimer = clearTimeout, setRepeat = setInterval, clearRepeat = clearInterval } = {}) {
    super();
    this.api = api;
    this.capture = capture;
    this.input = input;
    this.serverUrl = serverUrl;
    this.WebSocketImpl = WebSocketImpl;
    this.appVersion = appVersion;
    this.log = log || noopLog();
    this.now = now;
    this._set = setTimer;
    this._clear = clearTimer;
    this._setRepeat = setRepeat;
    this._clearRepeat = clearRepeat;
    this.s = null;
    capture.on('config', (c) => this._onConfig(c));
    capture.on('chunk', (c) => this._onChunk(c));
    capture.on('error', (e) => { if (this.s && !this.s.ended) this.end('failed', e && e.code); });
  }

  get busy() { return !!(this.s && !this.s.ended); }

  /** The state for the UI (never a ref or a token). */
  status() {
    const s = this.s;
    if (!s) return null;
    return { state: s.state, requestId: s.requestId, viewer: s.viewer, mode: s.mode, since: s.since, paused: s.paused, reason: s.reason || null, started: !!s.since };
  }

  _emit() { this.emit('session', this.status()); }

  async start({ requestId, ref, wsPath = WS_PATH, mode = 'view', viewerName = null } = {}) {
    if (this.busy) throw Object.assign(new Error('busy'), { code: 'busy' });
    if (wsPath !== WS_PATH) throw Object.assign(new Error('bad path'), { code: 'invalid' });
    if (typeof this.WebSocketImpl !== 'function') throw Object.assign(new Error('no WebSocket'), { code: 'unsupported' });
    this.s = { requestId, ref, allowed: mode === 'control' ? 'control' : 'view', mode: 'view', viewer: viewerName ? String(viewerName).slice(0, 120) : null,
      state: 'connecting', since: null, paused: false, ended: false, ws: null, ready: false, attempt: 0, config: null, display: null, desk: 'default',
      fails: { at: 0, n: 0 }, timers: new Set(), pingTimer: null, deskTimer: null, reason: null };
    this._emit();
    try {
      const c = await this.capture.start(this.capture.primaryIndex(), { fps: FPS, bitrate: BITRATE });
      if (!this.s || this.s.ended) return this.status();
      this.s.display = c.display;
      this.s.size = { width: c.width, height: c.height };
    } catch (err) {
      this.end('failed', (err && err.code) || 'capture_failed');
      throw Object.assign(new Error('capture failed'), { code: (err && err.code) || 'capture_failed' });
    }
    this.s.deskTimer = this._setRepeat(() => this._checkDesktop(), DESKTOP_MS);
    await this._connect();
    return this.status();
  }

  _timer(ms, fn) {
    const s = this.s;
    const t = this._set(() => { s.timers.delete(t); fn(); }, ms);
    s.timers.add(t);
    return t;
  }

  async _connect() {
    const s = this.s;
    if (!s || s.ended) return;
    let tk;
    try {
      tk = await this.api.screenToken(s.ref);
    } catch (err) {
      if (s.ended) return;
      // the ticket is gone, the plugin stopped, no licence: nothing to come back to
      if (err && (err.status === 404 || err.status === 403 || err.status === 401 || err.code === 'not_found')) { this.end('failed', 'token_failed'); return; }
      this._retry();
      return;
    }
    if (s.ended) return;
    if (!tk || typeof tk.token !== 'string' || tk.wsPath !== WS_PATH || (tk.role && tk.role !== 'sender')) { this.end('failed', 'token_failed'); return; }
    const base = String(this.serverUrl() || '').replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(base)) { this.end('failed', 'token_failed'); return; }
    const url = base.replace(/^http/i, 'ws') + WS_PATH;
    let ws;
    try {
      ws = new this.WebSocketImpl(url, [PROTOCOL, 'token.' + tk.token]);
    } catch {
      this._retry();
      return;
    }
    ws.binaryType = 'arraybuffer';
    s.ws = ws;
    s.ready = false;
    ws.onopen = () => {
      if (s.ws !== ws || s.ended) return;
      const list = this.capture.displays().map((d) => ({ i: d.i, primary: d.primary, w: d.w, h: d.h }));
      this._send({ t: 'hello', role: 'sender', width: s.size.width, height: s.size.height, fps: FPS, scope: 'display', input: 'desktop',
        control: s.allowed === 'control', app: { platform: 'windows', version: this.appVersion || '' }, displays: list, display: s.display ? s.display.i : 0 });
      if (s.pingTimer) this._clearRepeat(s.pingTimer);
      s.pingTimer = this._setRepeat(() => this._send({ t: 'ping' }), PING_MS);
    };
    ws.onmessage = (ev) => {
      if (s.ws !== ws || s.ended || typeof ev.data !== 'string') return;
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      if (m && typeof m === 'object' && typeof m.t === 'string') this._onText(m);
    };
    ws.onclose = () => {
      if (s.ws !== ws) return;
      s.ws = null;
      s.ready = false;
      if (s.pingTimer) { this._clearRepeat(s.pingTimer); s.pingTimer = null; }
      // nobody controls while the line is down
      this.input.releaseAll();
      if (!s.ended) this._retry();
    };
    ws.onerror = () => { /* onclose follows */ };
  }

  _retry() {
    const s = this.s;
    if (!s || s.ended) return;
    const wait = BACKOFF[s.attempt++];
    if (wait == null) { this.end('sender_lost'); return; }
    if (s.state !== 'connecting') { s.state = 'connecting'; this._emit(); }
    this._timer(wait, () => { this._connect().catch(() => this._retry()); });
  }

  _send(o) {
    const ws = this.s && this.s.ws;
    try { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); } catch { /* closed */ }
  }

  _onText(m) {
    const s = this.s;
    switch (m.t) {
      case 'ready':
        s.ready = true;
        s.attempt = 0;
        this._setMode(m.mode === 'control' && s.allowed === 'control' ? 'control' : 'view');
        if (s.config) this._send(s.config);
        this.capture.keyframe();
        if (s.state === 'connecting') { s.state = 'waiting'; this._emit(); }
        return;
      case 'viewer':
        if (m.state === 'joined') {
          if (typeof m.name === 'string' && m.name) s.viewer = m.name.slice(0, 120);
          s.state = 'live';
          if (!s.since) s.since = this.now();
          this.capture.keyframe();
        } else if (m.state === 'left') {
          this.input.releaseAll();
          s.state = 'waiting';
        }
        this._emit();
        return;
      case 'keyframe': this.capture.keyframe(); return;
      case 'rate': if (Number.isFinite(m.bitrate) && m.bitrate > 0) this.capture.setBitrate(Math.min(BITRATE, m.bitrate)); return;
      case 'mode': if (m.mode === 'view') this._setMode('view'); return;
      case 'input': this._onInput(m); return;
      case 'display': this._switchDisplay(m.i).catch(() => {}); return;
      case 'end': this.end(typeof m.reason === 'string' ? m.reason : 'ended'); return;
      case 'error':
        if (FINAL_ERRORS.has(m.code)) this.end('failed', m.code);
        return;
      default:
    }
  }

  _setMode(mode) {
    const s = this.s;
    // control only when the person here allowed it — and never back after view (the relay says so, too)
    const next = mode === 'control' && s.allowed === 'control' ? 'control' : 'view';
    if (next === 'control') {
      s.mode = 'control';
      this.input.enable(s.display ? s.display.rect : null);
    } else {
      if (s.mode === 'control') s.allowed = 'view';
      s.mode = 'view';
      this.input.stop();
    }
    this._emit();
  }

  _onInput(m) {
    const s = this.s;
    if (s.mode !== 'control' || s.paused) {
      if (s.mode === 'control' && s.paused) this._fail(m.k, s.desk === 'locked' ? 'locked' : 'secure');
      return;
    }
    const r = this.input.handle(m);
    if (!r.ok && r.reason !== 'rate') this._fail(m.k, r.reason);
  }

  _fail(k, reason) {
    const s = this.s;
    const now = this.now();
    if (now - s.fails.at >= 1000) s.fails = { at: now, n: 0 };
    if (++s.fails.n > FAILS_PER_S) return;
    this._send({ t: 'input_fail', ...(typeof k === 'string' ? { k } : {}), reason: ['secure', 'locked', 'blocked'].includes(reason) ? reason : 'blocked' });
  }

  /** Windows' secure desktop (UAC prompt, lock screen) came or went: the viewer hears it, no input meanwhile. */
  _checkDesktop() {
    const s = this.s;
    if (!s || s.ended) return;
    const d = this.input.desktop();
    if (d === s.desk) return;
    s.desk = d;
    s.paused = d !== 'default';
    if (s.paused) this.input.releaseAll();
    this._send({ t: 'state', paused: s.paused, ...(s.paused ? { reason: d === 'locked' ? 'locked' : 'secure' } : {}) });
    this._emit();
  }

  async _switchDisplay(i) {
    const s = this.s;
    if (!s || s.ended || !Number.isInteger(i) || (s.display && s.display.i === i)) return;
    if (!this.capture.displays().some((d) => d.i === i)) return;
    this.input.releaseAll();
    const c = await this.capture.start(i, { fps: FPS, bitrate: BITRATE });
    if (!this.s || this.s !== s || s.ended) return;
    s.display = c.display;
    s.size = { width: c.width, height: c.height };
    s.config = null;
    this.input.setDisplay(c.display.rect);
    this._send({ t: 'displays', displays: this.capture.displays().map((d) => ({ i: d.i, primary: d.primary, w: d.w, h: d.h })), display: c.display.i });
  }

  _onConfig(c) {
    const s = this.s;
    if (!s || s.ended) return;
    s.config = { t: 'config', codec: c.codec, width: c.width, height: c.height };
    if (s.ready) this._send(s.config);
  }

  _onChunk(c) {
    const s = this.s;
    if (!s || s.ended || !s.ready || !s.config || !s.ws || s.ws.readyState !== 1) return;
    // the line is full: drop delta frames until it drains, then a key frame
    if (s.ws.bufferedAmount > HIGH_WATER) { if (!c.key) { s.needKey = true; return; } }
    if (s.needKey && !c.key) { this.capture.keyframe(); return; }
    s.needKey = false;
    const head = frameHeader(c.key, c.ts);
    const buf = new Uint8Array(head.length + c.data.length);
    buf.set(head, 0);
    buf.set(c.data, head.length);
    try { s.ws.send(buf); } catch { /* closed */ }
  }

  /** "Nur ansehen" (the bar): no more input, for good in this session. */
  downgrade() {
    const s = this.s;
    if (!s || s.ended) return this.status();
    this.input.stop();
    s.allowed = 'view';
    if (s.mode === 'control') {
      s.mode = 'view';
      this._send({ t: 'mode', mode: 'view', reason: 'sender' });
    }
    this._emit();
    return this.status();
  }

  /** "Beenden" (the bar, the switch off): input stops first, then bye. */
  stop(reason = 'sender') {
    const s = this.s;
    if (!s || s.ended) return this.status();
    this.input.stop();
    this._send({ t: 'bye' });
    this.end(reason);
    return this.status();
  }

  /** The session is over (both sides, the relay, an error). */
  end(reason = 'ended', code = null) {
    const s = this.s;
    if (!s || s.ended) return;
    s.ended = true;
    s.state = 'ended';
    s.reason = reason;
    s.code = code;
    this.input.stop();
    try { this.capture.stop(); } catch { /* gone */ }
    for (const t of s.timers) this._clear(t);
    s.timers.clear();
    if (s.pingTimer) this._clearRepeat(s.pingTimer);
    if (s.deskTimer) this._clearRepeat(s.deskTimer);
    const ws = s.ws;
    s.ws = null;
    if (ws) { try { ws.close(1000); } catch { /* closed */ } }
    this.log.info(`Screen share: ended (${reason}${code ? ', ' + code : ''})`);
    this._emit();
  }
}

ScreenShare.WS_PATH = WS_PATH;
ScreenShare.PROTOCOL = PROTOCOL;

module.exports = ScreenShare;
