'use strict';

/**
 * GateControl – Fernzugriff stage 3: the native SSH terminal of the Windows client (Core service, app contract
 * „Fernzugriff Stufe 3 – Apps“)
 *
 * No UI. The plugin "Fernzugriff" lists the SSH devices and their tmux sessions and hands a ticket of engine term
 * (POST …/devices/<id>/connect { via: 'app', protocol: 'ssh', tmux?, record? } → { session: { ref, … } }); GateControl
 * turns its ref into a single-use token (POST /api/v1/client/remote/term-token, 60 s) for
 * wss://<server>/api/v1/remote/ssh-tunnel with `Sec-WebSocket-Protocol: gc-term.v1, token.<token>` (never in the URL).
 * The WebSocket runs here in the main process; the renderer only gets the terminal's bytes and the state.
 *
 *   devices()                         → { devices: [ssh devices], sshRight }
 *   tmux(deviceId)                    → { sessions, hidden, others, kill, tmux, hostKey: 'pinned' | 'unpinned' | null }
 *                                       (sessions: only attachable names; with kill, each with its id and windowList,
 *                                       and the other sessions in others, so they can be ended)
 *   tmuxKill(deviceId, { session, window? })  → { killed: 'session' | 'window', …the new list }  (Fernzugriff 1.8)
 *   tmuxKillDetached(deviceId, [sessionIds])  → { killed: [ids], skipped: [{ id, reason }], …the new list }
 *   open({ deviceId, deviceName, tmux, recording, record, cols, rows }) → status of the new session (its local id)
 *   input(id, data) · resize(id, cols, rows) · trust(id, yes) · reconnect(id) · close(id) · closeAll() · list()
 * Events: 'status' (status of one session, also { closed: true } when it is gone), 'data' { id, data: Uint8Array }.
 *
 * Several sessions at a time (a tab each). A socket lost without exit or a final error comes back with the backoff
 * 1, 2, 4, 8, 15 s, each time with a new token and the same ref; then 'offline'. `shell_refused` is final like the
 * other final codes of the contract (design question 9). Nothing of a ref, a token, a fingerprint or the terminal's
 * content is ever logged.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const MessengerApi = require('./messenger-api');

const { MessengerError: RemoteTermError } = MessengerApi;

const PLUGIN_ID = 'gatecontrol-remote';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const TOKEN_PATH = '/api/v1/client/remote/term-token';
const PROTOCOL = 'gc-term.v1';
const WS_PATH = '/api/v1/remote/ssh-tunnel';
const TERM = 'xterm-256color';
const BACKOFF = [1000, 2000, 4000, 8000, 15000];
const PING_MS = 25000;
const HOST_KEY_MS = 60000;
const MAX_SESSIONS = 12;
const TMUX_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const REF_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_RE = /^[a-z_]{1,40}$/;
const ALG_RE = /^[A-Za-z0-9@._+-]{1,40}$/;
const SHA_RE = /^[A-Za-z0-9+/=_-]{20,90}$/;
const SESSION_ID_RE = /^\$\d{1,6}$/;
const WINDOW_ID_RE = /^@\d{1,6}$/;
const MAX_KILL_DETACHED = 50;

/** Final: no automatic reconnect (contract §3 plus shell_refused, design question 9). */
const FINAL = new Set(['host_key_rejected', 'host_key_unpinned', 'auth_failed', 'key_unreadable', 'credential_required',
  'credential_unreadable', 'credential_missing', 'recording_unavailable', 'recording_required', 'plugin_unavailable', 'shell_refused',
  'no_right', 'forbidden', 'unlicensed', 'disabled', 'maintenance', 'invalid', 'no_user', 'mint_failed', 'invalid_answer', 'http_503']);

/** What happens after an error code: retry | final | locked | expired | limit. */
function verdict(code) {
  if (code === 'host_key_mismatch') return 'locked';
  if (FINAL.has(code)) return 'final';
  if (code === 'not_found' || code === 'http_404') return 'expired';
  if (code === 'limit' || code === 'limit_reached' || code === 'rate_limited' || code === 'http_429') return 'limit';
  return 'retry';
}

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const clean = (v, max = 100) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').trim().slice(0, max) : '') || null;
const clamp = (v, lo, hi, d) => (Number.isFinite(v) ? Math.max(lo, Math.min(hi, Math.round(v))) : d);
/** A time as GateControl sends it: ISO text, or tmux's seconds since 1970 (as a number or as digits). */
const isoMs = (v) => {
  if (typeof v === 'string' && /^\d{9,11}$/.test(v)) v = Number(v);
  if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? (v < 1e11 ? v * 1000 : v) : null;
  const t = typeof v === 'string' ? Date.parse(v) : NaN;
  return Number.isFinite(t) ? t : null;
};
const posId = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);

/** An SSH device of GET devices, or null (another protocol, broken). */
function deviceOf(d) {
  if (!d || typeof d !== 'object' || d.protocol !== 'ssh') return null;
  const id = posId(d.id);
  const name = clean(d.name);
  if (!id || !name) return null;
  const engine = d.engine === 'term' || d.engine === 'guac' ? d.engine : null;
  return {
    id, name, description: clean(d.description, 200), online: d.online === true, engine, native: engine === 'term',
    tmux: engine === 'term' && typeof d.tmux === 'string' && TMUX_RE.test(d.tmux) ? d.tmux : null,
    recording: ['off', 'optional', 'always'].includes(d.recording) ? d.recording : 'off',
    maintenance: d.maintenance === true, wake: d.wake === true, credentialUnreadable: d.credentialUnreadable === true,
    tags: Array.isArray(d.tags) ? d.tags.map((t) => clean(t, 40)).filter(Boolean).slice(0, 20) : [],
  };
}

/** The windows of a session (Fernzugriff 1.8, only with kill): id @n, index, name, active, the running command. */
function windowsOf(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  return list.slice(0, 200).map((w) => (w && typeof w === 'object' && WINDOW_ID_RE.test(String(w.id)) ? {
    id: w.id, index: clamp(w.index, 0, 99999, 0), name: clean(w.name, 64) || '', active: w.active === true,
    panes: clamp(w.panes, 0, 999, 1), command: clean(w.command, 64),
  } : null)).filter((w) => w && !seen.has(w.id) && seen.add(w.id)).sort((a, b) => a.index - b.index);
}

/** What the plugin needs back to end a session: its number, its name and its creation time exactly as listed. */
function identityOf(s) {
  if (!s || typeof s !== 'object' || !SESSION_ID_RE.test(String(s.id)) || typeof s.name !== 'string' || !s.name || s.name.length > 256) return null;
  const c = s.created;
  const created = (typeof c === 'number' && Number.isFinite(c)) || (typeof c === 'string' && c.length <= 64) ? c : null;
  return { id: s.id, name: s.name, created };
}

/**
 * The tmux sessions: only names the core can attach are offered, the others only counted. With `kill` (GateControl
 * with gc.remote 9, plugin 1.8) each session also has its id and windowList, and the others come in `others`
 * (they cannot be resumed, but ended).
 */
function tmuxOf(body) {
  const b = body && typeof body === 'object' ? body : {};
  const list = Array.isArray(b.sessions) ? b.sessions : [];
  const kill = b.kill === true;
  const seen = new Set();
  const all = list.slice(0, 200).map((s) => {
    const o = {
      name: clean(s && s.name, 64), windows: clamp(s && s.windows, 0, 9999, 0), attached: clamp(s && s.attached, 0, 9999, 0),
      activity: isoMs(s && s.activity), attachable: !!(s && s.attachable === true),
    };
    if (kill) {
      const ident = identityOf(s);
      if (!ident || seen.has(ident.id)) return o;
      seen.add(ident.id);
      o.id = ident.id;
      o.created = isoMs(s.created);
      o.windowList = windowsOf(s.windowList);
    }
    return o;
  }).filter((s) => s.name);
  const byActivity = (a, b2) => (b2.activity || 0) - (a.activity || 0);
  const ok = all.filter((s) => s.attachable && TMUX_RE.test(s.name)).sort(byActivity);
  const out = {
    sessions: ok, hidden: all.length - ok.length,
    tmux: typeof b.tmux === 'string' && TMUX_RE.test(b.tmux) ? b.tmux : null,
    hostKey: b.hostKey === 'pinned' || b.hostKey === 'unpinned' ? b.hostKey : null,
    kill,
  };
  if (kill) out.others = all.filter((s) => !(s.attachable && TMUX_RE.test(s.name)) && s.id).sort(byActivity);
  return out;
}

/** The sessions as GateControl listed them, by id (for the body of tmux/kill and tmux/kill-detached). */
function identitiesOf(body) {
  const m = new Map();
  if (!body || body.kill !== true || !Array.isArray(body.sessions)) return m;
  for (const s of body.sessions.slice(0, 200)) {
    const ident = identityOf(s);
    if (!ident || m.has(ident.id)) continue;
    const windows = new Map(windowsOf(s.windowList).map((w) => [w.id, w.index]));
    m.set(ident.id, { ...ident, attached: clamp(s.attached, 0, 9999, 0), windows });
  }
  return m;
}

/** A name for „Neue Sitzung“: tmux, taken → tmux-2 … */
function suggestName(taken, base = 'tmux') {
  const b = TMUX_RE.test(base) && base.length <= 28 ? base : 'tmux';
  const set = new Set(taken || []);
  if (!set.has(b)) return b;
  let i = 2;
  while (set.has(`${b}-${i}`) && i < 999) i++;
  return `${b}-${i}`;
}

/** The body of POST devices/<id>/connect; record only when the policy is not off, always true for always. */
function connectBody({ tmux, recording, record }) {
  const b = { via: 'app', protocol: 'ssh' };
  if (tmux && typeof tmux === 'object') {
    const attach = tmux.attach != null;
    const name = String(attach ? tmux.attach : tmux.create);
    if ((!attach && tmux.create == null) || !TMUX_RE.test(name)) throw new RemoteTermError('invalid tmux', { code: 'invalid' });
    b.tmux = attach ? { attach: name } : { create: name };
  }
  if (recording === 'always') b.record = true;
  else if (recording === 'optional') b.record = record === true;
  return b;
}

/** A text frame of the server → message or null. */
function parseFrame(text) {
  if (typeof text !== 'string' || text.length > 16384) return null;
  let m;
  try { m = JSON.parse(text); } catch { return null; }
  if (!m || typeof m !== 'object' || typeof m.t !== 'string') return null;
  switch (m.t) {
    case 'hostkey': {
      const k = m.hostKey;
      if (!k || !ALG_RE.test(String(k.alg)) || !SHA_RE.test(String(k.sha256))) return null;
      return { t: 'hostkey', hostKey: { alg: k.alg, sha256: k.sha256 } };
    }
    case 'ready': {
      const t = m.tmux && typeof m.tmux === 'object' ? m.tmux : {};
      return { t: 'ready', tmuxAvailable: typeof t.available === 'boolean' ? t.available : null,
        tmuxSession: typeof t.session === 'string' && TMUX_RE.test(t.session) ? t.session : null,
        recording: m.recording === true, view: m.mode === 'view', hostKeyNew: m.hostKeyNew === true };
    }
    case 'exit': return { t: 'exit', code: Number.isInteger(m.code) ? m.code : null, reason: CODE_RE.test(String(m.reason)) ? m.reason : 'closed' };
    case 'error': return { t: 'error', code: CODE_RE.test(String(m.code)) ? m.code : 'error' };
    case 'pong': return { t: 'pong' };
    default: return null;
  }
}

/** The fingerprint in groups of four for comparing by eye. */
function groups(sha256) { return String(sha256 || '').replace(/=+$/, '').match(/.{1,4}/g)?.join(' ') || ''; }

class RemoteTerm extends EventEmitter {
  /**
   * @param {object} o
   * @param {object} [o.apiClient] - ApiClient / ApiClientPro (its axios client, re-read on every call)
   * @param {object} [o.http] - MessengerApi-compatible transport (tests)
   * @param {() => string} o.serverUrl - https://… of the GateControl server
   * @param {Function} [o.WebSocketImpl] - the WHATWG WebSocket (Node's global one, like ScreenShare)
   * @param {object} [o.log]
   * @param {() => number} [o.now]
   * @param {Function} [o.setTimer] / [o.clearTimer] / [o.setRepeat] / [o.clearRepeat]
   */
  constructor({ apiClient, http = null, serverUrl, WebSocketImpl = globalThis.WebSocket, log, now = Date.now,
    setTimer = setTimeout, clearTimer = clearTimeout, setRepeat = setInterval, clearRepeat = clearInterval } = {}) {
    super();
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.serverUrl = serverUrl;
    this.WebSocketImpl = WebSocketImpl;
    this.now = now;
    this._set = setTimer;
    this._clear = clearTimer;
    this._setRepeat = setRepeat;
    this._clearRepeat = clearRepeat;
    this.sessions = new Map();
    /** deviceId → the tmux sessions of the last list (id → { id, name, created, attached, windows }). */
    this._tmuxSeen = new Map();
  }

  _api(method, p, body, params) {
    const o = body === undefined ? {} : { body };
    if (params) o.params = params;
    return this.http._call(method, API_BASE + p, o);
  }

  // ─── The plugin ───

  async devices() {
    const r = await this._api('GET', 'devices');
    const seen = new Set();
    const devices = (Array.isArray(r.devices) ? r.devices : []).map(deviceOf).filter((d) => d && !seen.has(d.id) && seen.add(d.id)).slice(0, 500);
    const sshRight = r.rights && typeof r.rights.ssh === 'boolean' ? r.rights.ssh : devices.length > 0;
    return { devices, sshRight };
  }

  /** The list with the windows (windows=1; older plugins ignore it and answer as before, kill: false). */
  async tmux(deviceId) {
    if (!posId(deviceId)) throw new RemoteTermError('invalid device', { code: 'invalid' });
    return this._tmuxList(deviceId, await this._api('GET', `devices/${deviceId}/tmux`, undefined, { windows: 1 }));
  }

  _tmuxList(deviceId, body) {
    this._tmuxSeen.set(deviceId, identitiesOf(body));
    if (this._tmuxSeen.size > 100) this._tmuxSeen.delete(this._tmuxSeen.keys().next().value);
    return tmuxOf(body);
  }

  /** A session (or one window of it) of the last list; gone from it → tmux_gone (the renderer reloads quietly). */
  _tmuxKnown(deviceId, sessionId) {
    const s = this._tmuxSeen.get(deviceId) && this._tmuxSeen.get(deviceId).get(sessionId);
    if (!s) throw new RemoteTermError('unknown tmux session', { code: 'tmux_gone' });
    return s;
  }

  /**
   * „Beenden“ (a session) or „Schließen“ (one window): GateControl lists again and checks number, name and creation
   * time before kill-session / kill-window. The answer carries the new list.
   */
  async tmuxKill(deviceId, { session, window = null } = {}) {
    if (!posId(deviceId) || !SESSION_ID_RE.test(String(session)) || (window != null && !WINDOW_ID_RE.test(String(window)))) {
      throw new RemoteTermError('invalid tmux target', { code: 'invalid' });
    }
    const s = this._tmuxKnown(deviceId, session);
    const body = { session: { id: s.id, name: s.name, created: s.created } };
    if (window != null) {
      if (!s.windows.has(window)) throw new RemoteTermError('unknown tmux window', { code: 'tmux_gone' });
      body.window = { id: window, index: s.windows.get(window) };
    }
    const r = await this._api('POST', `devices/${deviceId}/tmux/kill`, body);
    this.log.info(`Remote terminal: tmux ${window != null ? 'window closed' : 'session ended'}`);
    return { killed: r.killed === 'window' ? 'window' : 'session', ...this._tmuxList(deviceId, r) };
  }

  /** „Alle getrennten Sitzungen beenden“: the checked ones (1–50); GateControl skips any that is attached by now. */
  async tmuxKillDetached(deviceId, ids) {
    if (!posId(deviceId) || !Array.isArray(ids) || !ids.length || ids.length > MAX_KILL_DETACHED || !ids.every((x) => SESSION_ID_RE.test(String(x)))) {
      throw new RemoteTermError('invalid tmux sessions', { code: 'invalid' });
    }
    const sessions = [...new Set(ids)].map((x) => this._tmuxKnown(deviceId, x)).map((s) => ({ id: s.id, name: s.name, created: s.created }));
    const r = await this._api('POST', `devices/${deviceId}/tmux/kill-detached`, { sessions });
    const killed = (Array.isArray(r.killed) ? r.killed : []).filter((x) => SESSION_ID_RE.test(String(x))).slice(0, MAX_KILL_DETACHED);
    const skipped = (Array.isArray(r.skipped) ? r.skipped : []).filter((x) => x && SESSION_ID_RE.test(String(x.id)))
      .map((x) => ({ id: x.id, reason: CODE_RE.test(String(x.reason)) ? x.reason : 'failed' })).slice(0, MAX_KILL_DETACHED);
    this.log.info(`Remote terminal: ${killed.length} detached tmux session(s) ended`);
    return { killed, skipped, ...this._tmuxList(deviceId, r) };
  }

  // ─── Sessions ───

  /** The state for the renderer (never a ref, a token or anything of the terminal). */
  status(id) {
    const s = this.sessions.get(id);
    if (!s) return null;
    return { id, deviceId: s.deviceId, deviceName: s.deviceName, tmux: s.tmux, state: s.state, attempt: s.attempt, at: s.at || null,
      hostKey: s.hostKey ? { alg: s.hostKey.alg, sha256: s.hostKey.sha256, groups: groups(s.hostKey.sha256), until: s.hostKeyUntil } : null,
      recording: s.recording, tmuxMissing: s.tmuxMissing, view: s.view, cols: s.cols, rows: s.rows,
      code: s.code || null, verdict: s.verdict || null, reason: s.reason || null, exitCode: s.exitCode == null ? null : s.exitCode };
  }

  list() { return [...this.sessions.keys()].map((id) => this.status(id)); }

  _emit(s) { this.emit('status', this.status(s.id)); }

  /** A ticket (the plugin), then the socket. Throws the plugin's refusal ({ code }) before a session exists. */
  async open({ deviceId, deviceName = null, tmux = null, recording = 'off', record = false, cols = 80, rows = 24 } = {}) {
    if (!posId(deviceId)) throw new RemoteTermError('invalid device', { code: 'invalid' });
    if (typeof this.WebSocketImpl !== 'function') throw new RemoteTermError('no WebSocket', { code: 'unsupported' });
    if (this.sessions.size >= MAX_SESSIONS) throw new RemoteTermError('too many', { code: 'limit' });
    const r = await this._api('POST', `devices/${deviceId}/connect`, connectBody({ tmux, recording, record }));
    const t = r && r.session;
    if (!t || t.engine !== 'term' || !REF_RE.test(String(t.ref))) throw new RemoteTermError('not a terminal ticket', { code: 'invalid_answer' });
    const tm = t.tmux && typeof t.tmux === 'object' ? (t.tmux.attach || t.tmux.create) : null;
    const id = 'term_' + crypto.randomBytes(9).toString('base64url');
    const s = {
      id, ref: t.ref, deviceId, deviceName: clean(t.device && t.device.name) || clean(deviceName) || '',
      tmux: typeof tm === 'string' && TMUX_RE.test(tm) ? tm : null, state: 'connecting', attempt: 0, at: null,
      cols: clamp(cols, 10, 500, 80), rows: clamp(rows, 5, 200, 24), recording: t.recording === true, tmuxMissing: false, view: false,
      ws: null, open: false, stopped: false, timers: new Set(), ping: null, lastPong: 0, hostKey: null, hostKeyUntil: null,
    };
    this.sessions.set(id, s);
    this._emit(s);
    this._connect(s);
    return this.status(id);
  }

  _timer(s, ms, fn) {
    const t = this._set(() => { s.timers.delete(t); fn(); }, ms);
    s.timers.add(t);
    return t;
  }

  _clearTimers(s) {
    for (const t of s.timers) this._clear(t);
    s.timers.clear();
  }

  async _connect(s) {
    if (s.stopped) return;
    s.state = 'connecting';
    s.at = null;
    this._emit(s);
    let tk;
    try {
      tk = await this.http._call('POST', TOKEN_PATH, { body: { ref: s.ref } });
    } catch (err) {
      if (s.stopped) return;
      const code = (err && err.code) || 'network';
      if (verdict(code) === 'retry') this._lost(s);
      else this._fail(s, code);
      return;
    }
    if (s.stopped) return;
    if (!tk || typeof tk.token !== 'string' || !REF_RE.test(tk.token) || tk.wsPath !== WS_PATH) { this._fail(s, 'invalid_answer'); return; }
    const base = String((this.serverUrl && this.serverUrl()) || '').replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(base)) { this._fail(s, 'invalid_answer'); return; }
    let ws;
    try {
      ws = new this.WebSocketImpl(base.replace(/^http/i, 'ws') + WS_PATH, [PROTOCOL, 'token.' + tk.token]);
    } catch {
      this._lost(s);
      return;
    }
    ws.binaryType = 'arraybuffer';
    s.ws = ws;
    ws.onopen = () => {
      if (s.ws !== ws || s.stopped) return;
      if (ws.protocol && ws.protocol !== PROTOCOL) { this._fail(s, 'invalid_answer'); return; }
      s.open = true;
      this._send(s, { t: 'hello', cols: s.cols, rows: s.rows, term: TERM });
      s.lastPong = this.now();
      if (s.ping) this._clearRepeat(s.ping);
      s.ping = this._setRepeat(() => {
        // two missed answers: the line is dead although the socket did not notice
        if (this.now() - s.lastPong > PING_MS * 2.5) { try { ws.close(4000); } catch { /* gone */ } this._gone(s, ws); return; }
        this._send(s, { t: 'ping' });
      }, PING_MS);
    };
    ws.onmessage = (ev) => {
      if (s.ws !== ws || s.stopped) return;
      s.lastPong = this.now();
      if (typeof ev.data === 'string') { this._onText(s, parseFrame(ev.data)); return; }
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : ArrayBuffer.isView(ev.data) ? new Uint8Array(ev.data.buffer, ev.data.byteOffset, ev.data.byteLength) : null;
      if (data && data.length) this.emit('data', { id: s.id, data });
    };
    ws.onclose = () => this._gone(s, ws);
    ws.onerror = () => { /* onclose follows */ };
  }

  _gone(s, ws) {
    if (s.ws !== ws) return;
    this._dropSocket(s, false);
    if (!s.stopped) this._lost(s);
  }

  _onText(s, m) {
    if (!m) return;
    switch (m.t) {
      case 'hostkey':
        s.hostKey = m.hostKey;
        s.hostKeyUntil = this.now() + HOST_KEY_MS;
        s.state = 'hostkey';
        this._emit(s);
        return;
      case 'ready':
        s.state = 'ready';
        s.attempt = 0;
        s.hostKey = null;
        s.recording = m.recording;
        s.tmuxMissing = m.tmuxAvailable === false;
        s.view = m.view;
        if (m.tmuxSession) s.tmux = m.tmuxSession;
        this._emit(s);
        return;
      case 'exit':
        s.stopped = true;
        s.state = 'exited';
        s.reason = m.reason;
        s.exitCode = m.code;
        this._dropSocket(s, false);
        this._emit(s);
        return;
      case 'error': this._fail(s, m.code); return;
      default:
    }
  }

  _lost(s) {
    if (s.stopped) return;
    const wait = BACKOFF[s.attempt];
    if (wait == null) {
      s.stopped = true;
      s.state = 'offline';
      s.at = null;
      this._emit(s);
      return;
    }
    s.attempt += 1;
    s.state = 'reconnecting';
    s.at = this.now() + wait;
    this._emit(s);
    this._timer(s, wait, () => { this._connect(s).catch(() => this._lost(s)); });
  }

  _fail(s, code) {
    s.stopped = true;
    this._clearTimers(s);
    this._dropSocket(s, false);
    s.state = 'failed';
    s.code = code;
    s.verdict = verdict(code);
    this.log.info(`Remote terminal: ended (${code})`);
    this._emit(s);
  }

  _dropSocket(s, bye) {
    if (s.ping) { this._clearRepeat(s.ping); s.ping = null; }
    const ws = s.ws;
    s.ws = null;
    s.open = false;
    if (!ws) return;
    if (bye) { try { if (ws.readyState === 1) ws.send(JSON.stringify({ t: 'bye' })); } catch { /* closed */ } }
    try { ws.close(1000); } catch { /* closed */ }
  }

  _send(s, o) {
    const ws = s.ws;
    try { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); } catch { /* closed */ }
  }

  _need(id) {
    const s = this.sessions.get(id);
    if (!s) throw new RemoteTermError('no such session', { code: 'not_found' });
    return s;
  }

  /** Typed or pasted bytes (only while ready and allowed; view mode: the server drops them anyway). */
  input(id, data) {
    const s = this.sessions.get(id);
    if (!s || !s.open || s.state !== 'ready' || s.view) return false;
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data instanceof Uint8Array ? data : null;
    if (!buf || !buf.length || buf.length > 1024 * 1024) return false;
    try { s.ws.send(buf); return true; } catch { return false; }
  }

  resize(id, cols, rows) {
    const s = this.sessions.get(id);
    if (!s) return;
    const c = clamp(cols, 10, 500, s.cols);
    const r = clamp(rows, 5, 200, s.rows);
    if (c === s.cols && r === s.rows) return;
    s.cols = c;
    s.rows = r;
    if (s.open) this._send(s, { t: 'resize', cols: c, rows: r });
    this._emit(s);
  }

  /** The answer to the fingerprint; distrust ends the session. */
  trust(id, yes) {
    const s = this._need(id);
    if (s.state !== 'hostkey') return this.status(id);
    this._send(s, { t: yes ? 'trust' : 'distrust' });
    if (yes) { s.state = 'connecting'; s.hostKey = null; this._emit(s); } else this._fail(s, 'host_key_rejected');
    return this.status(id);
  }

  /** „Jetzt versuchen“ / „Neu verbinden“: the same ref now (not after an administrator ended it or a lock). */
  reconnect(id) {
    const s = this._need(id);
    const again = s.state === 'reconnecting' || s.state === 'offline'
      || (s.state === 'exited' && s.reason !== 'ended_by_plugin')
      || (s.state === 'failed' && (s.code === 'host_key_rejected' || s.verdict === 'limit'));
    if (!again) return this.status(id);
    this._clearTimers(s);
    this._dropSocket(s, false);
    s.stopped = false;
    s.attempt = 0;
    s.code = null;
    s.verdict = null;
    s.reason = null;
    this._connect(s).catch(() => this._lost(s));
    return this.status(id);
  }

  /** „Trennen“ / tab closed: bye, then the session is gone (its tmux keeps running on the device). */
  close(id) {
    const s = this.sessions.get(id);
    if (!s) return;
    s.stopped = true;
    this._clearTimers(s);
    this._dropSocket(s, true);
    this.sessions.delete(id);
    this.emit('status', { id, closed: true });
  }

  closeAll() { for (const id of [...this.sessions.keys()]) this.close(id); }
}

RemoteTerm.RemoteTermError = RemoteTermError;
RemoteTerm.PROTOCOL = PROTOCOL;
RemoteTerm.WS_PATH = WS_PATH;
RemoteTerm.BACKOFF = BACKOFF;
RemoteTerm.TMUX_RE = TMUX_RE;
RemoteTerm.verdict = verdict;
RemoteTerm.deviceOf = deviceOf;
RemoteTerm.tmuxOf = tmuxOf;
RemoteTerm.identitiesOf = identitiesOf;
RemoteTerm.suggestName = suggestName;
RemoteTerm.connectBody = connectBody;
RemoteTerm.parseFrame = parseFrame;
RemoteTerm.groups = groups;

module.exports = RemoteTerm;
