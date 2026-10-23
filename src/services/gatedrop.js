'use strict';

/**
 * GateControl – GateDrop (Core service)
 *
 * Sharing like Quick Share, through the own GateControl server (plugin
 * `gatecontrol-gatedrop`, contract "GateDrop – Schnittstelle" B, C, G):
 *
 *   - Availability: the plugin list (GET /api/v1/client/plugins), like Schule.
 *   - Presence: PUT presence { lan: [{ ip, prefix }], port: 47731, listening }
 *     at start, every 5 min and when the LAN addresses change (checked every 30 s).
 *   - LAN listener (services/gatedrop-listener.js) while the plugin is there.
 *   - Send: files (≤ 20, ≤ 2 GB each), text, link, note to people, own
 *     devices, the NAS or a public link. Only own devices in the same WLAN
 *     selected → the items go as `local` and the files directly (protocol C,
 *     push to a listening device or offered for pull); everything else, and
 *     every failed direct transfer, goes through the server (upload, resumable
 *     above 50 MB; after a failed direct one POST sends/<id>/items).
 *   - Receive: pushes with `data.gatedrop` — `{ transfer … }` (silent: take
 *     the files directly, push or pull) and `{ send }` (fetch the items from
 *     the server) — are saved to Downloads\GateControl (unique names), then
 *     one toast "… hat dir … geschickt" with "Ordner öffnen" / "Anzeigen"
 *     (text: "Kopieren", link: "Öffnen"). A click opens the GateDrop page.
 *   - Sent while this PC was offline (GateDrop 1.1.0): GET pending lists the
 *     sends waiting for this device; they are fetched like a `{ send }` push
 *     and acknowledged with POST sends/<id>/opened. Polled when GateDrop
 *     becomes available, on every push-stream hello, after resume from sleep,
 *     after a network change and with the 5-minute presence tick (debounced,
 *     one poll at a time). Handled send ids (last 500, store
 *     `gatedropHandled`) are shared with the push path: a send is saved once,
 *     whichever way it arrives first; a failed download stays unhandled and
 *     the next poll tries again (only the items still missing).
 *   - Lists: inbox (Empfangen / Gesendet / Links), end a link.
 *   - Who may send to this PC (GateDrop 1.2.0, GET/PUT device): only its
 *     owner ("Nur ich", default) or everyone of this GateControl ("Alle im
 *     GateControl-Netz"). Others' devices open for everyone come with the
 *     targets (`peopleDevices`) and are sent to like own devices; a send from
 *     another person names that person in the toast, an own device its name.
 *
 * Events: 'state' (status()), 'compose' ({ files, rejected }) open the send
 * dialog, 'progress' ({ id, dir, phase, sent, total, name }), 'received'
 * (record), 'changed' ({ kind }), 'navigate' ({ tab, sendId }).
 * Phases out: upload → sent → direct / failed (direct failed, the server takes
 * over) → done | error; in: download / direct → done | failed.
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { t } = require('../i18n');
const GateDropApi = require('./gatedrop-api');
const GateDropListener = require('./gatedrop-listener');
const directDefault = require('./gatedrop-direct');
const gd = require('../utils/gatedrop');
const { buildToastXml } = require('../utils/toast-xml');
const { isSafeExternalUrl } = require('../utils/external-url');

const { GateDropError } = GateDropApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,
  retryMinMs: 5000,
  retryMaxMs: 5 * 60 * 1000,
  presenceMs: 5 * 60 * 1000,
  networkCheckMs: 30 * 1000,
  targetsTtlMs: 30 * 1000,
  inboxTtlMs: 30 * 1000,
  pullStartMs: 60 * 1000,      // a device that should pull from us: first request within 1 min
  preparedTtlMs: 60 * 60 * 1000,
  pendingDebounceMs: 2000,     // GET pending: triggers close together → one poll
  resumeDelayMs: 5000,         // after resume from sleep: give the network a moment
};
const MAX_SAVED = 100;
const MAX_HANDLED = 500;
const MAX_NONCES = 60;
const MAX_SEEN = 300;
/** A caller's own job id for the 'progress' events of a send. */
const JOB_RE = /^[A-Za-z0-9_-]{1,64}$/;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

function defaultDownloadsDir() {
  return path.join(os.homedir(), 'Downloads', 'GateControl');
}

class GateDropService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro
   * @param {object} [opts.log]
   * @param {object} [opts.store] - electron-store (received files: `gatedropSaved`)
   * @param {object} [opts.notificationCenter] - NotificationCenter (push handler, toast rules, click route)
   * @param {object} [opts.pushClient] - PushClient ('hello' → ask again, presence)
   * @param {object} [opts.api] - GateDropApi (tests)
   * @param {object|false} [opts.listener] - GateDropListener; false: no listener
   * @param {() => string} [opts.downloadsDir] - default %USERPROFILE%\Downloads\GateControl
   * @param {object} [opts.shell] - Electron shell (openPath, showItemInFolder, openExternal)
   * @param {object} [opts.clipboard] - Electron clipboard (writeText)
   * @param {Function} [opts.Notification] - Electron Notification
   * @param {string} [opts.platform]
   * @param {string} [opts.protocol] - the app's toast protocol (buttons)
   * @param {string} [opts.toastImagePath]
   * @param {Function} [opts.showWindow]
   * @param {object} [opts.direct] - { pushTo, pullFrom } (tests)
   * @param {Function} [opts.resolveCandidate] - default: private IPv4 only
   * @param {() => object} [opts.getInterfaces]
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   * @param {string} [opts.storeKey] - saved files (default `gatedropSaved`)
   * @param {string} [opts.handledKey] - handled send ids (default `gatedropHandled`)
   * @param {object|null} [opts.powerMonitor] - Electron powerMonitor ('resume'); default: electron's, when there
   */
  constructor({
    apiClient, log, store = null, notificationCenter = null, pushClient = null, api = null, listener = null,
    downloadsDir = defaultDownloadsDir, shell = null, clipboard = null, Notification = null, platform = process.platform,
    protocol = null, toastImagePath = null, showWindow = null, direct = null, resolveCandidate = gd.parseCandidate,
    getInterfaces = () => os.networkInterfaces(), timing = {}, now = Date.now, storeKey = 'gatedropSaved',
    handledKey = 'gatedropHandled', powerMonitor,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new GateDropApi({ apiClient, log: this.log });
    this.store = store;
    this.storeKey = storeKey;
    this.handledKey = handledKey;
    this._powerMonitor = powerMonitor;
    this.notificationCenter = notificationCenter;
    this.pushClient = pushClient;
    this.getInterfaces = getInterfaces;
    this.listener = listener === false ? null : (listener || new GateDropListener({ log: this.log, getInterfaces }));
    if (this.listener && !this.listener.resolveIncoming) this.listener.resolveIncoming = (id) => this._resolveIncoming(id);
    this.downloadsDir = typeof downloadsDir === 'function' ? downloadsDir : () => downloadsDir;
    this.shell = shell;
    this.clipboard = clipboard;
    this._Notification = Notification;
    this.platform = platform;
    this.protocol = protocol;
    this.toastImagePath = toastImagePath;
    this.showWindow = showWindow;
    this.direct = direct || directDefault;
    this.resolveCandidate = resolveCandidate;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._retry = 0;
    this._timers = {};
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this.api.scope();
    this._targets = null;        // { at, data }
    this._inbox = new Map();     // kind → { at, data }
    this._prepared = new Map();  // token → { path, name, size, mime, at }
    this._pendingCompose = null;
    this._nonces = new Map();    // toast button nonce → action
    this._seen = new Set();      // handled direct transfers (replays)
    this._handled = null;        // Set of handled send ids (store `gatedropHandled`), loaded on first use
    this._inflight = new Map();  // send id → Promise of its running download (push and poll share it)
    this._failToasted = new Set(); // sends whose failure was already shown (a poll retries quietly)
    this._acked = new Set();     // sends acknowledged (POST opened) in this session
    this._polling = null;        // running GET pending
    this._pollAgain = false;     // a trigger came in while it ran
    this._pendingOff = undefined; // plugin version without GET pending (404)
    this._jobs = new Set();
    this._lanKey = '';
    this._lastPresence = null;
    this._toasts = new Set();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const nc = this.notificationCenter;
    if (nc) {
      if (typeof nc.addPushHandler === 'function') {
        this._unsub.push(nc.addPushHandler({ notification: (n) => this._onPush(n), protocol: (nonce) => this._onProtocol(nonce) }));
      }
      if (typeof nc.addClickRoute === 'function') {
        this._unsub.push(nc.addClickRoute(gd.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      // Stream (re)connected: what was sent while we were away is waiting.
      const onHello = () => {
        if (this._state.state !== 'available') this.check().catch(() => {});
        else {
          this.reportPresence({ force: true }).catch(() => {});
          this.schedulePending();
        }
      };
      pc.on('hello', onHello);
      this._unsub.push(() => pc.removeListener('hello', onHello));
    }
    const pm = this._powerMonitorOf();
    if (pm) {
      const onResume = () => this.schedulePending(this.timing.resumeDelayMs);
      pm.on('resume', onResume);
      this._unsub.push(() => pm.removeListener('resume', onResume));
    }
    this._every('network', this.timing.networkCheckMs, () => this._checkNetwork());
    this._every('presence', this.timing.presenceMs, () => {
      this.reportPresence({ force: true }).catch(() => {});
      this.schedulePending();
    });
    this.check().catch(() => {});
  }

  _powerMonitorOf() {
    if (this._powerMonitor !== undefined) return this._powerMonitor && typeof this._powerMonitor.on === 'function' ? this._powerMonitor : null;
    try {
      const pm = require('electron').powerMonitor;
      return pm && typeof pm.on === 'function' ? pm : null;
    } catch {
      return null;
    }
  }

  stop() {
    this._started = false;
    for (const k of Object.keys(this._timers)) { clearTimeout(this._timers[k]); clearInterval(this._timers[k]); }
    this._timers = {};
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    if (this.listener) this.listener.stop().catch(() => {});
  }

  _every(name, ms, fn) {
    clearInterval(this._timers[name]);
    this._timers[name] = setInterval(fn, ms);
    if (this._timers[name].unref) this._timers[name].unref();
  }

  /** server:setup: caches and state of the old server are dropped. */
  resetForNewServer() {
    this._targets = null;
    this._inbox.clear();
    this._retry = 0;
    this._lastPresence = null;
    this._pendingOff = undefined;
    this._failToasted.clear();
    this._acked.clear();
    this._scope = this.api.scope();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  /** Wait for background work (direct transfers, downloads) — tests and shutdown. */
  async idle() {
    while (this._jobs.size) await Promise.allSettled([...this._jobs]);
  }

  _job(promise) {
    const p = Promise.resolve(promise).catch((err) => this.log.warn(`GateDrop: ${err.message}`)).finally(() => this._jobs.delete(p));
    this._jobs.add(p);
    return p;
  }

  // ── Availability ─────────────────────────────────────────

  status() {
    const l = this.listener ? this.listener.status() : { listening: false, port: gd.PORT, addresses: [] };
    return {
      ...this._state,
      listening: l.listening,
      port: l.port,
      addresses: l.addresses.map((a) => ({ ip: a.ip, prefix: a.prefix })),
      folder: this.downloadsDir(),
    };
  }

  available() {
    return this._state.state === 'available';
  }

  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    const was = this.available();
    this._ensureScope();
    clearTimeout(this._timers.check);
    let next = this.timing.recheckMs;
    try {
      const p = await this.api.plugin();
      this._retry = 0;
      if (!p) this._setState({ state: 'unavailable', reason: 'not_installed', version: null, checkedAt: this.now() });
      else this._setState({ state: 'available', reason: null, version: typeof p.version === 'string' ? p.version.slice(0, 40) : null, checkedAt: this.now() });
    } catch (err) {
      if (err && err.status === 404) {
        this._setState({ state: 'unavailable', reason: 'unsupported', version: null, checkedAt: this.now() });
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setState({ state: 'unavailable', reason: err.status === 401 ? 'auth' : 'forbidden', version: null, checkedAt: this.now() });
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        const keep = this._state.state === 'available';
        this._setState({ ...this._state, state: keep ? 'available' : 'error', reason: (err && err.code) || 'network', checkedAt: this.now() });
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    await this._applyAvailability();
    // Became available (app start, server back): fetch what waits for this PC.
    if (!was && this.available()) this.schedulePending();
    if (this._started) {
      this._timers.check = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timers.check.unref) this._timers.check.unref();
    }
    return this.status();
  }

  async _applyAvailability() {
    if (!this.listener || !this._started) return;
    if (this.available()) {
      if (!this.listener.listening) {
        try { await this.listener.start(); } catch (err) { this.log.warn(`GateDrop listener: ${err.message}`); }
      }
      this._lanKey = this._lanSignature();
      await this.reportPresence().catch(() => {});
    } else if (this._state.state === 'unavailable' && this.listener.listening) {
      await this.listener.stop().catch(() => {});
    }
  }

  _setState(s) {
    const before = JSON.stringify([this._state.state, this._state.reason, this._state.version]);
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    if (JSON.stringify([this._state.state, this._state.reason, this._state.version]) !== before) this.emit('state', this.status());
  }

  _ensureScope() {
    const s = this.api.scope();
    if (s === this._scope) return;
    this._scope = s;
    this._targets = null;
    this._inbox.clear();
    this._lastPresence = null;
  }

  // ── Presence ─────────────────────────────────────────────

  _lanSignature() {
    try { return gd.lanAddresses(this.getInterfaces()).map((a) => `${a.ip}/${a.prefix}`).join(','); } catch { return ''; }
  }

  async _checkNetwork() {
    if (!this.available()) return;
    const key = this._lanSignature();
    if (key === this._lanKey) return;
    this._lanKey = key;
    this.log.info('GateDrop: network changed');
    if (this.listener) await this.listener.refresh().catch(() => {});
    this._targets = null;
    await this.reportPresence({ force: true }).catch(() => {});
    this.emit('state', this.status());
    this.schedulePending();
  }

  /** PUT presence (skipped when nothing changed, unless force). */
  async reportPresence({ force = false } = {}) {
    if (!this.available()) return null;
    const l = this.listener ? this.listener.status() : { listening: false, addresses: [] };
    const lan = l.listening ? l.addresses.map((a) => ({ ip: a.ip, prefix: a.prefix })) : gd.lanAddresses(this.getInterfaces()).map((a) => ({ ip: a.ip, prefix: a.prefix }));
    const body = { lan, port: gd.PORT, listening: l.listening };
    const key = JSON.stringify(body);
    if (!force && key === this._lastPresence) return null;
    try {
      await this.api.presence(body);
      this._lastPresence = key;
      return body;
    } catch (err) {
      this.log.debug(`GateDrop presence failed: ${err.code || err.message}`);
      throw err;
    }
  }

  // ── Targets / lists ──────────────────────────────────────

  async targets({ refresh = false } = {}) {
    this._ensureScope();
    if (!refresh && this._targets && this.now() - this._targets.at < this.timing.targetsTtlMs) return { ok: true, ...this._copy(this._targets.data) };
    try {
      const data = await this.api.targets();
      this._targets = { at: this.now(), data };
      return { ok: true, ...this._copy(data) };
    } catch (err) {
      if (this._targets && err.transient) return { ok: true, ...this._copy(this._targets.data), stale: true };
      throw err;
    }
  }

  /** Inbox list kind received | sent | links → { ok, kind, items, stale? }. Received entries carry `local` (saved files). */
  async inbox({ kind = 'received', refresh = false } = {}) {
    this._ensureScope();
    const k = gd.INBOX_KINDS.includes(kind) ? kind : 'received';
    const hit = this._inbox.get(k);
    let items;
    let stale = false;
    if (!refresh && hit && this.now() - hit.at < this.timing.inboxTtlMs) items = hit.data;
    else {
      try {
        items = await this.api.inbox(k);
        this._inbox.set(k, { at: this.now(), data: items });
      } catch (err) {
        if (!hit || !err.transient) throw err;
        items = hit.data;
        stale = true;
      }
    }
    const out = this._copy(items);
    if (k === 'received') {
      const saved = this._savedList();
      for (const s of out) {
        const rec = saved.find((r) => r.sendId === s.id);
        s.local = rec ? rec.files.filter((f) => this._exists(f.path)).map((f) => ({ name: f.name, path: f.path, bytes: f.bytes })) : [];
      }
      // Direct transfers the server lists later (or never): show what we saved.
      const known = new Set(out.map((s) => s.id));
      for (const r of saved) {
        if (r.sendId && known.has(r.sendId)) continue;
        out.push({
          id: r.sendId || `local-${r.key}`, at: r.at, from: r.from, to: null, text: r.text, link: r.link, note: r.note || null,
          items: r.files.map((f, i) => ({ index: i, mediaId: null, name: f.name, mime: gd.guessMime(f.name), bytes: f.bytes })),
          deliveries: [], opened: false, expiresAt: null,
          local: r.files.filter((f) => this._exists(f.path)).map((f) => ({ name: f.name, path: f.path, bytes: f.bytes })),
          localOnly: true, via: r.via,
        });
      }
      out.sort((a, b) => (b.at || 0) - (a.at || 0));
    }
    return { ok: true, kind: k, items: out, stale };
  }

  /**
   * Who may send to this PC (GET device, GateDrop 1.2.0) →
   * { ok, supported, receiveFrom: 'self' | 'everyone' | null }. supported false:
   * a plugin older than 1.2.0 (404) or a token GateDrop knows no app
   * installation of (409 no_device) — the setting is not offered then.
   */
  async deviceAccess() {
    this._ensureScope();
    if (!this.available()) return { ok: true, supported: false, receiveFrom: null };
    try {
      const d = await this.api.getDevice();
      this._setReceiveFrom(d.receiveFrom);
      return { ok: true, supported: true, receiveFrom: d.receiveFrom };
    } catch (err) {
      if (err && (err.status === 404 || (err.status === 409 && err.code === 'no_device'))) return { ok: true, supported: false, receiveFrom: null };
      throw err;
    }
  }

  /** PUT device { receiveFrom } → { ok, supported: true, receiveFrom } */
  async setDeviceAccess(mode) {
    if (!gd.RECEIVE_FROM.includes(mode)) throw new GateDropError('invalid mode', { code: 'invalid' });
    if (!this.available()) throw new GateDropError('GateDrop is not available', { code: 'unavailable' });
    this._ensureScope();
    const d = await this.api.putDevice(mode);
    this._setReceiveFrom(d.receiveFrom);
    this.log.info(`GateDrop: this PC takes sends from ${d.receiveFrom === 'everyone' ? 'everyone' : 'its owner only'}`);
    return { ok: true, supported: true, receiveFrom: d.receiveFrom };
  }

  _setReceiveFrom(mode) {
    const me = this._targets && this._targets.data && this._targets.data.me;
    if (me) me.receiveFrom = mode;
  }

  async sendDetails(id) {
    return { ok: true, send: await this.api.send(id) };
  }

  async endLink(token) {
    await this.api.endLink(token);
    this._inbox.delete('links');
    this.emit('changed', { kind: 'links' });
    return { ok: true };
  }

  _copy(v) { return JSON.parse(JSON.stringify(v)); }

  // ── Files to send ────────────────────────────────────────

  /**
   * Check local files (dialog, drag & drop, "Senden an") → { files: [{ id,
   * name, size, mime }], rejected: [{ name, reason }] }. The ids stand for
   * the paths in send(): the renderer never sends paths of its own choosing.
   */
  async prepareFiles(paths) {
    const files = [];
    const rejected = [];
    const list = Array.isArray(paths) ? paths : [];
    this._sweepPrepared();
    for (const p of list) {
      if (typeof p !== 'string' || !p || p.length > 4096 || p.includes('\u0000') || !(path.isAbsolute(p) || path.win32.isAbsolute(p))) {
        rejected.push({ name: typeof p === 'string' ? path.basename(p).slice(0, 120) : '', reason: 'invalid' });
        continue;
      }
      const name = gd.safeFileName(path.basename(p), 'datei');
      if (files.length >= gd.MAX_ITEMS) { rejected.push({ name, reason: 'too_many' }); continue; }
      let st;
      try { st = await fs.promises.stat(p); } catch { rejected.push({ name, reason: 'missing' }); continue; }
      if (st.isDirectory()) { rejected.push({ name, reason: 'directory' }); continue; }
      if (!st.isFile()) { rejected.push({ name, reason: 'invalid' }); continue; }
      if (st.size === 0) { rejected.push({ name, reason: 'empty' }); continue; }
      if (st.size > gd.MAX_FILE_BYTES) { rejected.push({ name, reason: 'too_large' }); continue; }
      const id = crypto.randomBytes(12).toString('base64url');
      const f = { path: p, name, size: st.size, mime: gd.guessMime(name), at: this.now() };
      this._prepared.set(id, f);
      files.push({ id, name, size: st.size, mime: f.mime });
    }
    return { ok: true, files, rejected };
  }

  _sweepPrepared() {
    const limit = this.now() - this.timing.preparedTtlMs;
    for (const [id, f] of this._prepared) if (f.at < limit) this._prepared.delete(id);
    while (this._prepared.size > 400) this._prepared.delete(this._prepared.keys().next().value);
  }

  /** Files from "Senden an", the command line or drag & drop → open the send dialog. */
  async compose(paths) {
    const r = await this.prepareFiles(paths);
    this._pendingCompose = { files: r.files, rejected: r.rejected, at: this.now() };
    this.emit('compose', { files: r.files, rejected: r.rejected });
    return r;
  }

  /** The files of the last compose not yet picked up by the window (it was still loading). */
  takeCompose() {
    const p = this._pendingCompose;
    this._pendingCompose = null;
    if (!p || this.now() - p.at > 10 * 60 * 1000) return { files: [], rejected: [] };
    return { files: p.files, rejected: p.rejected };
  }

  // ── Send ─────────────────────────────────────────────────

  /**
   * @param {object} o
   * @param {string[]} [o.files] - ids from prepareFiles()
   * @param {string} [o.text] [o.link] [o.note]
   * @param {object} o.to - { people, devices, nas, link: { expires, pin } }
   * @param {string} [o.job] - id of the 'progress' events of this send (the caller's
   *   own, so it can follow the upload before the answer arrives)
   * @returns {Promise<{ ok, id, job, deliveries, link, direct }>} after the send exists on
   *   the server; direct transfers and fallbacks continue in the background ('progress').
   *   The job ends with phase 'done' ({ via: 'direct' | 'server' }) or 'error' ({ code }).
   */
  async send({ files = [], text = null, link = null, note = null, to, job = null } = {}) {
    if (!this.available()) throw new GateDropError('GateDrop is not available', { code: 'unavailable' });
    const list = [];
    for (const id of Array.isArray(files) ? files : []) {
      const f = typeof id === 'string' ? this._prepared.get(id) : null;
      if (!f) throw new GateDropError('unknown file', { code: 'invalid' });
      list.push(f);
    }
    if (list.length > gd.MAX_ITEMS) throw new GateDropError('too many files', { code: 'too_many' });
    const body = { items: [] };
    if (text !== null && text !== undefined && text !== '') {
      if (typeof text !== 'string' || text.length > gd.MAX_TEXT) throw new GateDropError('text too long', { code: 'invalid' });
      body.text = text;
    }
    if (link !== null && link !== undefined && link !== '') {
      const l = gd.linkArg(link);
      if (!l) throw new GateDropError('invalid link', { code: 'invalid' });
      body.link = l;
    }
    if (note !== null && note !== undefined && note !== '') {
      if (typeof note !== 'string' || note.length > gd.MAX_NOTE) throw new GateDropError('note too long', { code: 'invalid' });
      body.note = note;
    }
    if (!list.length && !body.text && !body.link) throw new GateDropError('nothing to send', { code: 'empty' });
    body.to = gd.sendTargets(to);
    if (!body.to) throw new GateDropError('no target', { code: 'no_target' });
    if (body.to.link && !list.length) throw new GateDropError('a link needs files', { code: 'invalid' });

    // Fresh files: changed or gone since they were picked?
    for (const f of list) {
      let st;
      try { st = await fs.promises.stat(f.path); } catch { throw new GateDropError(`${f.name} is gone`, { code: 'missing' }); }
      if (!st.isFile() || st.size !== f.size) throw new GateDropError(`${f.name} changed`, { code: 'changed' });
    }

    const jobId = typeof job === 'string' && JOB_RE.test(job) ? job : crypto.randomBytes(8).toString('hex');
    const total = list.reduce((s, f) => s + f.size, 0);
    const end = (phase, extra) => this.emit('progress', { id: jobId, dir: 'out', phase, sent: phase === 'done' ? total : 0, total, ...extra });
    const upload = this._uploader(list, jobId, total);
    let result;
    let localOk = false;
    try {
      localOk = list.length > 0 && await this._allDirect(body.to);
      if (list.length) {
        if (localOk) body.items = list.map((f) => ({ name: f.name, bytes: f.size, mime: f.mime, local: true }));
        else body.items = (await upload.run()).map((it) => ({ mediaId: it.mediaId, name: it.name }));
      }
      try {
        result = await this.api.createSend(body);
      } catch (err) {
        // 409 upload_required: a target needs the files on the server after all.
        if (!(localOk && err && err.code === 'upload_required')) throw err;
        body.items = (await upload.run()).map((it) => ({ mediaId: it.mediaId, name: it.name }));
        result = await this.api.createSend(body);
      }
    } catch (err) {
      // 409 unavailable (GateDrop 1.2.0): another person's device was closed for others meanwhile.
      if (err && err.status === 409 && err.code === 'unavailable') {
        err.code = 'target_unavailable';
        this._targets = null;
      }
      end('error', { code: (err && err.code) || 'failed' });
      throw err;
    }
    this._inbox.delete('sent');
    this._inbox.delete('links');
    this.emit('progress', { id: jobId, dir: 'out', phase: 'sent', sent: total, total, sendId: result.id });

    const direct = list.length ? result.direct : [];
    if (direct.length) {
      this._job(Promise.allSettled(direct.map((d) => this._sendDirect(d, list, result.id, upload, jobId, total, { local: localOk })))
        .then((outcomes) => {
          this._inbox.delete('sent');
          this.emit('changed', { kind: 'sent' });
          // A fallback that could not get the files to the server: the send is incomplete.
          const bad = outcomes.find((o) => o.status === 'rejected');
          if (bad) end('error', { sendId: result.id, code: (bad.reason && bad.reason.code) || 'failed' });
          else end('done', { sendId: result.id, via: outcomes.every((o) => o.value && o.value.via === 'direct') ? 'direct' : 'server' });
        }));
    } else {
      end('done', { sendId: result.id, via: 'server' });
    }
    this.emit('changed', { kind: 'sent' });
    return { ok: true, id: result.id, job: jobId, deliveries: result.deliveries, link: result.link, direct: direct.map((d) => ({ deviceId: d.deviceId, mode: d.mode })) };
  }

  /**
   * Only devices in the same network that listen — own ones or others' open
   * for everyone (peopleDevices) — → items may go `local`.
   */
  async _allDirect(to) {
    if (!to.devices.length || to.people.length || to.nas.length || to.link) return false;
    let targets;
    try { targets = await this.targets(); } catch { return false; }
    const all = [...(targets.devices || []), ...(targets.peopleDevices || [])];
    return to.devices.every((id) => {
      const d = all.find((x) => x.id === id);
      return !!(d && d.direct);
    });
  }

  /**
   * Uploads files by local index, each at most once (memoized):
   * run() → all, run([indexes]) → those → [{ index, mediaId, name }].
   */
  _uploader(list, jobId, total) {
    const done = new Map(); // index → Promise<{ index, mediaId, name }>
    let chain = Promise.resolve();
    let base = 0;
    const one = (index) => {
      if (done.has(index)) return done.get(index);
      const f = list[index];
      // One file after the other (progress, bandwidth); a failed one may be tried again.
      const p = chain.then(async () => {
        const start = base;
        const r = await this.api.upload(f, {
          onProgress: (sent) => this.emit('progress', { id: jobId, dir: 'out', phase: 'upload', sent: Math.min(total, start + sent), total, name: f.name }),
        });
        base += f.size;
        return { index, mediaId: r.mediaId, name: f.name };
      });
      chain = p.catch(() => {});
      done.set(index, p);
      p.catch(() => done.delete(index));
      return p;
    };
    return {
      started: () => done.size > 0,
      run: (indexes = null) => {
        const want = (Array.isArray(indexes) ? indexes : list.map((_, i) => i)).filter((i) => Number.isSafeInteger(i) && i >= 0 && i < list.length);
        return Promise.all([...new Set(want)].map(one));
      },
    };
  }

  /** POST transfers/<id>/result, tried 3 times (the answer decides the fallback) → answer or null. */
  async _report(transferId, body) {
    for (let i = 0; i < 3; i++) {
      try {
        return await this.api.transferResult(transferId, body);
      } catch (err) {
        this.log.warn(`GateDrop transfer result failed: ${err.code || err.message}`);
        if (err.transient === false || i === 2) return null;
        await new Promise((r) => { const tm = setTimeout(r, 2000 * (i + 1)); if (tm.unref) tm.unref(); });
      }
    }
    return null;
  }

  async _sendDirect(d, list, sendId, upload, jobId, total, { local = true } = {}) {
    const progress = (sent) => this.emit('progress', { id: jobId, dir: 'out', phase: 'direct', sent, total, deviceId: d.deviceId });
    let ok = false;
    let bytes = 0;
    let error = null;
    try {
      if (d.mode === 'push') {
        const r = await this.direct.pushTo({
          candidates: d.candidates, transferId: d.transferId, ticket: d.ticket, key: d.key,
          files: list.map((f) => ({ path: f.path, name: f.name, size: f.size })),
          onProgress: progress, resolveCandidate: this.resolveCandidate,
        });
        ok = true;
        bytes = r.bytes;
      } else {
        if (!this.listener || !this.listener.listening) throw Object.assign(new Error('not listening'), { code: 'not_listening' });
        const offer = this.listener.offerOutgoing({
          transferId: d.transferId, ticket: d.ticket, key: d.key,
          items: list.map((f) => ({ path: f.path, name: f.name, size: f.size })),
        });
        const startTimer = setTimeout(() => { if (!offer.started()) this.listener.cancelOutgoing(d.transferId, 'not_fetched'); }, this.timing.pullStartMs);
        try {
          const r = await offer.done;
          ok = true;
          bytes = r.bytes;
          progress(total);
        } finally {
          clearTimeout(startTimer);
        }
      }
    } catch (err) {
      error = err.code || err.message || 'failed';
      this.log.info(`GateDrop direct to ${d.deviceId || 'device'} failed (${error}) – server path`);
    }
    const answer = await this._report(d.transferId, ok ? { ok: true, bytes } : { ok: false, error });
    if (ok) return { ok: true, via: 'direct' };
    // fallback 'server': the files are on the server, the plugin delivers.
    // fallback 'upload': upload the `missing` local items, then POST sends/<id>/items.
    let indexes = null;
    if (answer && answer.fallback === 'upload') indexes = answer.missing && answer.missing.length ? answer.missing : list.map((_, i) => i);
    else if (!answer && local) indexes = list.map((_, i) => i); // no answer: the files must get there anyway
    if (indexes && indexes.length && sendId) {
      this.emit('progress', { id: jobId, dir: 'out', phase: 'failed', sent: 0, total });
      const items = await upload.run(indexes);
      await this.api.addItems(sendId, items.map((it) => ({ index: it.index, mediaId: it.mediaId })));
    }
    return { ok: true, via: 'server' };
  }

  // ── Receive ──────────────────────────────────────────────

  /** NotificationCenter push handler → 'consumed' | 'quiet' | false */
  _onPush(n) {
    if (!gd.isGateDropPush(n)) return false;
    const p = gd.parsePushData(n.data);
    // "Link geladen" / "Link gesperrt" (topic link): a normal notification.
    if (!p || p.kind === 'link') return false;
    // Data pushes (`kind: "data"`, core 1.193) are only dispatched; a visible
    // "… hat dir … geschickt" stays in the inbox without the center's toast.
    const hidden = n.kind === 'data';
    // `silent` without kind data: quiet hours → no toast of ours either.
    p.quiet = !hidden && n.silent === true;
    if (p.kind === 'direct') {
      const key = `t:${p.transferId}`;
      if (this._seen.has(key)) return 'consumed';
      this._remember(key);
      this._job(this.receiveDirect(p));
      return 'consumed';
    }
    // A send: saved once, whether this push or GET pending gets there first.
    if (!this._isHandled(p.sendId) && !this._inflight.has(p.sendId)) this._job(this._receiveOnce(p));
    return hidden ? 'consumed' : 'quiet';
  }

  _remember(key) {
    this._seen.add(key);
    while (this._seen.size > MAX_SEEN) this._seen.delete(this._seen.values().next().value);
  }

  /** The sender reached the listener before the silent push: ask the plugin. */
  async _resolveIncoming(transferId) {
    const p = await this.api.transfer(transferId);
    if (!p || p.kind !== 'direct' || p.mode !== 'push' || p.transferId !== transferId) return;
    if (this._seen.has(`t:${transferId}`)) return;
    this._remember(`t:${transferId}`);
    this._job(this.receiveDirect(p));
  }

  /** A direct transfer to this PC (push: wait for the sender; pull: fetch it). */
  async receiveDirect(p) {
    if (!p.items.length && p.itemCount) {
      // The push left the item list out (too long): GET transfers/<id>.
      try {
        const full = await this.api.transfer(p.transferId);
        if (full && full.items.length) p = { ...p, items: full.items, sendId: p.sendId || full.sendId, from: p.from || full.from };
      } catch (err) {
        this.log.warn(`GateDrop transfer ${p.transferId} could not be read: ${err.code || err.message}`);
      }
    }
    const jobId = p.transferId;
    const total = p.items.reduce((s, it) => s + (it.bytes || 0), 0);
    const progress = (sent) => this.emit('progress', { id: jobId, dir: 'in', phase: 'direct', sent, total });
    let saved = [];
    let error = null;
    try {
      if (p.mode === 'push') {
        if (!this.listener || !this.listener.listening) throw Object.assign(new Error('not listening'), { code: 'not_listening' });
        const onItem = (e) => { if (e.transferId === p.transferId) progress(e.bytes); };
        this.listener.on('incoming-item', onItem);
        try {
          saved = await this.listener.expectIncoming({
            transferId: p.transferId, ticket: p.ticket, key: p.key, items: p.items, expiresAt: p.expiresAt,
            sink: (meta) => this._sink(meta),
          });
        } finally {
          this.listener.removeListener('incoming-item', onItem);
        }
      } else {
        if (!p.items.length) throw Object.assign(new Error('no items'), { code: 'no_items' });
        const r = await this.direct.pullFrom({
          candidates: p.candidates, transferId: p.transferId, ticket: p.ticket, key: p.key, items: p.items,
          sink: (meta) => this._sink(meta), onProgress: progress, resolveCandidate: this.resolveCandidate,
        });
        saved = r.items;
      }
    } catch (err) {
      error = err.code || err.message || 'failed';
      // Files that did arrive before it broke off: the server path brings all again.
      for (const f of err.saved || err.received || []) { try { await fs.promises.unlink(f.path); } catch { /* gone */ } }
      saved = [];
    }
    const bytes = saved.reduce((s, f) => s + f.bytes, 0);
    try {
      await this.api.transferResult(p.transferId, error ? { ok: false, error } : { ok: true, bytes });
    } catch (err) {
      this.log.warn(`GateDrop transfer result failed: ${err.code || err.message}`);
    }
    if (error) {
      this.log.info(`GateDrop direct receive failed (${error}) – the server path follows`);
      this.emit('progress', { id: jobId, dir: 'in', phase: 'failed', sent: 0, total });
      return { ok: false, error };
    }
    const rec = this._record({ key: p.transferId, sendId: p.sendId, transferId: p.transferId, from: p.from, files: saved, via: 'direct' });
    if (p.sendId) this._markHandled(p.sendId);
    this.emit('progress', { id: jobId, dir: 'in', phase: 'done', sent: total, total });
    this._toastReceived(rec, { quiet: p.quiet === true });
    return { ok: true, record: rec };
  }

  /**
   * A send to fetch from the server: GET sends/<id> (unless the push has it), download every item.
   * @param {object} p - { sendId, send?, from?, quiet? } (parsePushData kind 'send', or a send of GET pending)
   * @param {object} [o]
   * @param {boolean} [o.failToast=true] - toast "… konnte nicht geladen werden" on failure
   * @param {boolean} [o.resume=false] - keep the items an earlier attempt saved (only the missing ones
   *   are downloaded; nothing new and nothing failed → { ok: true, skipped: 'saved' } without a toast)
   * @returns {Promise<{ ok, record?, failed?, error?, skipped? }>} ok with failed > 0: some items are missing
   */
  async receiveSend(p, { failToast = true, resume = false } = {}) {
    let send = p.send && (p.send.items.length || p.send.text || p.send.link) ? p.send : null;
    try {
      if (!send) send = await this.api.send(p.sendId);
      if (!send) throw new GateDropError('send not found', { code: 'not_found' });
    } catch (err) {
      this.log.warn(`GateDrop send ${p.sendId} could not be loaded: ${err.code || err.message}`);
      if (failToast) this._toastFailed(p.from, { quiet: p.quiet === true });
      return { ok: false, error: err.code || 'failed' };
    }
    const from = send.from || p.from;
    const prior = resume ? this._savedList().find((r) => r.sendId === send.id) || null : null;
    const have = prior ? prior.files.filter((f) => Number.isSafeInteger(f.index) && this._exists(f.path)) : [];
    const haveIdx = new Set(have.map((f) => f.index));
    const files = [];
    const total = send.items.reduce((s, it) => s + (it.bytes || 0), 0);
    let base = 0;
    let failed = 0;
    for (const it of send.items) {
      if (!it.mediaId || !it.available) continue; // local on the sender's device / removed
      if (haveIdx.has(it.index)) continue; // saved by an earlier attempt
      let target = null;
      try {
        target = await this._sink({ index: it.index, name: it.name, bytes: it.bytes });
        const r = await this.api.download(it.mediaId, target.stream, {
          onProgress: (got) => this.emit('progress', { id: send.id, dir: 'in', phase: 'download', sent: base + got, total, name: it.name }),
        });
        files.push({ index: it.index, name: it.name, path: await target.commit(), bytes: r.bytes });
        base += r.bytes;
      } catch (err) {
        failed++;
        if (target) { try { await target.abort(); } catch { /* best effort */ } }
        this.log.warn(`GateDrop item ${it.name} could not be loaded: ${err.code || err.message}`);
      }
    }
    if (!files.length && !have.length && !send.text && !send.link && (failed || send.items.length)) {
      if (failToast) this._toastFailed(from, { quiet: p.quiet === true });
      return { ok: false, error: 'download_failed' };
    }
    // Saved before (all of it, or the text / link): nothing new to show.
    if (prior && !files.length) return failed ? { ok: false, error: 'download_failed', failed } : { ok: true, record: prior, failed: 0, skipped: 'saved' };
    const all = [...have, ...files].sort((a, b) => a.index - b.index);
    const rec = this._record({ key: send.id, sendId: send.id, from, files: all, text: send.text, link: send.link, note: send.note, via: 'server' });
    this._inbox.delete('received');
    this.emit('progress', { id: send.id, dir: 'in', phase: 'done', sent: total, total });
    // A second attempt names only what it added.
    const fresh = new Set(files.map((f) => f.path));
    this._toastReceived(have.length ? { ...rec, files: rec.files.filter((f) => fresh.has(f.path)), text: null, link: null, note: null } : rec, { quiet: p.quiet === true });
    return { ok: true, record: rec, failed };
  }

  // ── Handled sends / GET pending ──────────────────────────

  _handledSet() {
    if (!this._handled) {
      let ids = [];
      try {
        const raw = this.store && this.store.get(this.handledKey);
        ids = raw && Array.isArray(raw.ids) ? raw.ids.filter((x) => typeof x === 'string' && x.length <= 128) : [];
      } catch { ids = []; }
      this._handled = new Set(ids.slice(-MAX_HANDLED));
    }
    return this._handled;
  }

  _isHandled(id) {
    return typeof id === 'string' && this._handledSet().has(id);
  }

  /** Remember a send as saved (oldest dropped beyond 500), persisted in the store. */
  _markHandled(id) {
    if (typeof id !== 'string' || !id) return;
    const set = this._handledSet();
    set.delete(id);
    set.add(id);
    while (set.size > MAX_HANDLED) set.delete(set.values().next().value);
    if (this.store) {
      try { this.store.set(this.handledKey, { v: 1, ids: [...set] }); } catch (err) { this.log.warn(`GateDrop handled list could not be saved: ${err.message}`); }
    }
  }

  /**
   * One download per send, whichever path asks first (push or GET pending):
   * handled → { ok, skipped: 'handled' }; running → that same promise.
   * Handled once every item is saved; a failure toast only the first time.
   */
  _receiveOnce(p) {
    const id = p.sendId;
    if (this._isHandled(id)) return Promise.resolve({ ok: true, skipped: 'handled' });
    const running = this._inflight.get(id);
    if (running) return running;
    const failToast = !this._failToasted.has(id);
    const run = this.receiveSend(p, { failToast, resume: true })
      .catch((err) => ({ ok: false, error: (err && err.code) || 'failed' }))
      .then((r) => {
        if (r.ok && !r.failed) {
          this._markHandled(id);
          this._failToasted.delete(id);
        } else {
          this._failToasted.add(id);
          while (this._failToasted.size > MAX_HANDLED) this._failToasted.delete(this._failToasted.values().next().value);
        }
        return r;
      })
      .finally(() => this._inflight.delete(id));
    this._inflight.set(id, run);
    return run;
  }

  /** Poll GET pending soon (triggers close together → one poll). */
  schedulePending(delayMs = this.timing.pendingDebounceMs) {
    if (!this._started) return;
    clearTimeout(this._timers.pending);
    this._timers.pending = setTimeout(() => {
      this._timers.pending = null;
      this._job(this.pollPending());
    }, Math.max(0, delayMs));
    if (this._timers.pending.unref) this._timers.pending.unref();
  }

  /**
   * GET pending → save each send waiting for this PC (as a `{ send }` push),
   * then POST sends/<id>/opened. Never two at once: a call while one runs
   * makes it go round once more.
   * @returns {Promise<{ ok, supported?, received?, failed?, error? }>}
   */
  pollPending() {
    if (this._polling) {
      this._pollAgain = true;
      return this._polling;
    }
    this._polling = (async () => {
      let r;
      do {
        this._pollAgain = false;
        r = await this._pollOnce();
      } while (this._pollAgain && this._started && this.available());
      return r;
    })().finally(() => { this._polling = null; });
    return this._polling;
  }

  async _pollOnce() {
    if (!this.available()) return { ok: false, error: 'unavailable' };
    this._ensureScope();
    // An older plugin (no GET pending) stays skipped until its version changes.
    if (this._pendingOff !== undefined && this._pendingOff === this._state.version) return { ok: true, supported: false };
    let list;
    try {
      list = await this.api.pending();
    } catch (err) {
      this.log.debug(`GateDrop pending failed: ${err.code || err.message}`);
      return { ok: false, error: (err && err.code) || 'failed' };
    }
    if (list === null) {
      this._pendingOff = this._state.version;
      this.log.info('GateDrop: the plugin has no pending list (older than 1.1.0)');
      return { ok: true, supported: false };
    }
    this._pendingOff = undefined;
    let received = 0;
    let failed = 0;
    // Own devices are named in the toast ("Pixel hat dir …") and this
    // device's delivery is found by me.deviceId: needs `me`. The entries are
    // own sends (role "sent") when they come from one's own devices — the
    // role says nothing here, the delivery to this device does.
    if (list.some((s) => !this._isHandled(s.id)) && !this._targets) await this.targets().catch(() => {});
    const me = this._targets && this._targets.data && this._targets.data.me;
    const myId = me && me.deviceId;
    for (const send of list) {
      const mine = myId ? send.deliveries.find((d) => d.kind === 'device' && d.target === myId) : null;
      if (mine && mine.status === 'opened') { this._markHandled(send.id); continue; } // taken care of here before
      const r = await this._receiveOnce({ kind: 'send', sendId: send.id, send, from: send.from });
      if (r.ok && !r.failed) {
        if (!r.skipped) received++;
        await this._ack(send.id);
      } else {
        failed++;
      }
    }
    if (received || failed) this.log.info(`GateDrop pending: ${received} saved, ${failed} failed of ${list.length}`);
    return { ok: true, supported: true, received, failed };
  }

  /** POST sends/<id>/opened: the receipt, the plugin drops the send from `pending`. */
  async _ack(id) {
    if (this._acked.has(id)) return;
    try {
      await this.api.opened(id);
      this._acked.add(id);
      while (this._acked.size > MAX_HANDLED) this._acked.delete(this._acked.values().next().value);
    } catch (err) {
      this.log.debug(`GateDrop opened ${id} failed: ${err.code || err.message}`);
    }
  }

  /**
   * Save a received send again (button on the page, e.g. after it was
   * deleted or the automatic download failed).
   */
  async saveSend(sendId) {
    const send = await this.api.send(sendId);
    if (!send) throw new GateDropError('send not found', { code: 'not_found' });
    const r = await this.receiveSend({ kind: 'send', sendId: send.id, send, from: send.from });
    if (r.ok && !r.failed) this._markHandled(send.id);
    return r;
  }

  /**
   * Target of one received file: Downloads\GateControl\<unique name>, written
   * as <name>.gdpart first and renamed when complete.
   */
  async _sink({ name }) {
    const dir = this.downloadsDir();
    await fs.promises.mkdir(dir, { recursive: true });
    const base = gd.safeFileName(name, 'datei');
    let finalPath = null;
    for (let n = 1; n < 1000 && !finalPath; n++) {
      const candidate = path.join(dir, gd.numberedName(base, n));
      if (path.dirname(candidate) !== dir) throw new GateDropError('bad name', { code: 'invalid' });
      try {
        const fh = await fs.promises.open(candidate, 'wx');
        await fh.close();
        finalPath = candidate;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
      }
    }
    if (!finalPath) throw new GateDropError('no free name', { code: 'exists' });
    const tmp = `${finalPath}.${crypto.randomBytes(4).toString('hex')}.gdpart`;
    const stream = fs.createWriteStream(tmp, { flags: 'wx' });
    const cleanup = async () => {
      stream.destroy();
      await fs.promises.unlink(tmp).catch(() => {});
      await fs.promises.unlink(finalPath).catch(() => {});
    };
    return {
      path: finalPath,
      stream,
      commit: async () => {
        if (!stream.closed && !stream.writableFinished) await new Promise((r) => stream.once('close', r));
        await fs.promises.rename(tmp, finalPath);
        return finalPath;
      },
      abort: cleanup,
    };
  }

  // ── Saved files ──────────────────────────────────────────

  _savedList() {
    try {
      const raw = this.store && this.store.get(this.storeKey);
      return raw && Array.isArray(raw.items) ? raw.items.filter((r) => r && Array.isArray(r.files)) : [];
    } catch {
      return [];
    }
  }

  _record({ key, sendId = null, transferId = null, from = null, files = [], text = null, link = null, note = null, via }) {
    const rec = {
      key: String(key), sendId, transferId, at: this.now(),
      from: from ? { id: from.id || null, name: from.name || null, deviceId: from.deviceId || null, deviceName: from.deviceName || null, own: typeof from.own === 'boolean' ? from.own : null } : null,
      files: files.map((f) => ({ ...(Number.isSafeInteger(f.index) ? { index: f.index } : {}), name: f.name, path: f.path, bytes: f.bytes })),
      text: text || null, link: link || null, note: note || null, via,
    };
    const list = this._savedList().filter((r) => r.key !== rec.key && !(rec.sendId && r.sendId === rec.sendId));
    list.unshift(rec);
    if (this.store) {
      try { this.store.set(this.storeKey, { v: 1, items: list.slice(0, MAX_SAVED) }); } catch (err) { this.log.warn(`GateDrop list could not be saved: ${err.message}`); }
    }
    this.emit('received', this._copy(rec));
    this.emit('changed', { kind: 'received' });
    return rec;
  }

  _exists(p) {
    try { return fs.statSync(p).isFile(); } catch { return false; }
  }

  /** Only files GateDrop saved itself may be shown / opened from the page. */
  isSavedPath(p) {
    if (typeof p !== 'string') return false;
    return this._savedList().some((r) => r.files.some((f) => f.path === p));
  }

  async openFolder() {
    const dir = this.downloadsDir();
    await fs.promises.mkdir(dir, { recursive: true }).catch(() => {});
    if (this.shell && typeof this.shell.openPath === 'function') {
      const err = await this.shell.openPath(dir);
      if (err) throw new GateDropError(err, { code: 'open_failed' });
    }
    return { ok: true };
  }

  showItem(p) {
    if (!this.isSavedPath(p)) throw new GateDropError('unknown file', { code: 'invalid' });
    if (this.shell && typeof this.shell.showItemInFolder === 'function') this.shell.showItemInFolder(p);
    return { ok: true };
  }

  async openItem(p) {
    if (!this.isSavedPath(p)) throw new GateDropError('unknown file', { code: 'invalid' });
    if (this.shell && typeof this.shell.openPath === 'function') {
      const err = await this.shell.openPath(p);
      if (err) throw new GateDropError(err, { code: 'open_failed' });
    }
    return { ok: true };
  }

  copyText(text) {
    if (typeof text !== 'string' || !text || text.length > gd.MAX_TEXT + 2048) throw new GateDropError('invalid text', { code: 'invalid' });
    if (this.clipboard && typeof this.clipboard.writeText === 'function') this.clipboard.writeText(text);
    return { ok: true };
  }

  async openLink(url) {
    if (!isSafeExternalUrl(url)) throw new GateDropError('invalid link', { code: 'invalid' });
    if (this.shell && typeof this.shell.openExternal === 'function') await this.shell.openExternal(url);
    return { ok: true };
  }

  // ── Toasts ───────────────────────────────────────────────

  _NotificationClass() {
    if (this._Notification) return this._Notification;
    if (this.notificationCenter && typeof this.notificationCenter.notificationClass === 'function') return this.notificationCenter.notificationClass();
    try { return require('electron').Notification; } catch { return null; }
  }

  _nonce(action) {
    const nonce = crypto.randomBytes(12).toString('base64url');
    this._nonces.set(nonce, action);
    while (this._nonces.size > MAX_NONCES) this._nonces.delete(this._nonces.keys().next().value);
    return nonce;
  }

  /** Toast button (NotificationCenter.handleProtocolUrl → here). */
  _onProtocol(nonce) {
    const a = this._nonces.get(nonce);
    if (!a) return false;
    this._nonces.delete(nonce);
    const run = async () => {
      if (a.type === 'folder') await this.openFolder();
      else if (a.type === 'show') this.showItem(a.path);
      else if (a.type === 'copy') this.copyText(a.text);
      else if (a.type === 'open') await this.openLink(a.url);
      if (a.sendId && a.type !== 'copy') await this.api.opened(a.sendId).catch(() => {});
    };
    run().catch((err) => this.log.warn(`GateDrop toast action failed: ${err.message}`));
    return true;
  }

  _decide(quiet = false) {
    const nc = this.notificationCenter;
    if (nc && typeof nc.decideToast === 'function') return nc.decideToast({ priority: 'normal', topic: `${gd.TOPIC_PREFIX}received`, silent: quiet });
    return quiet ? { show: false, silent: true } : { show: true, silent: false };
  }

  /**
   * "Pixel" for one's own devices, else the person's name ("Marc" — also for
   * a direct transfer from Marc's device to this PC when it is open for
   * everyone). `from.own` (GateDrop 1.2.0) decides; without it (older
   * plugins): a direct transfer or a sender with the own user id is own.
   */
  _fromName(from, { device = false } = {}) {
    if (!from) return t('gatedrop.someone');
    let own = from.own;
    if (typeof own !== 'boolean') {
      const me = this._targets && this._targets.data && this._targets.data.me;
      own = device || (!!me && !!me.id && from.id === me.id);
    }
    return (own && from.deviceName) || from.name || from.deviceName || t('gatedrop.someone');
  }

  _folderLabel() {
    const dir = this.downloadsDir();
    return `${path.basename(path.dirname(dir))}\\${path.basename(dir)}`;
  }

  _toastReceived(rec, { quiet = false } = {}) {
    const from = this._fromName(rec.from, { device: rec.via === 'direct' });
    let title;
    let body = '';
    const buttons = [];
    if (rec.files.length) {
      title = rec.files.length === 1
        ? t('gatedrop.toast.receivedFile', { from, name: rec.files[0].name })
        : t('gatedrop.toast.receivedFiles', { from, count: rec.files.length });
      body = t('gatedrop.toast.savedIn', { folder: this._folderLabel() });
      buttons.push({ label: t('gatedrop.toast.openFolder'), action: { type: 'folder', sendId: rec.sendId } });
      buttons.push({ label: t('gatedrop.toast.show'), action: { type: 'show', path: rec.files[0].path, sendId: rec.sendId } });
    } else if (rec.link) {
      title = t('gatedrop.toast.receivedLink', { from });
      body = rec.link;
      buttons.push({ label: t('gatedrop.toast.open'), action: { type: 'open', url: rec.link, sendId: rec.sendId } });
      buttons.push({ label: t('gatedrop.toast.copy'), action: { type: 'copy', text: rec.link } });
    } else if (rec.text) {
      title = t('gatedrop.toast.receivedText', { from });
      body = rec.text.length > 200 ? `${rec.text.slice(0, 200)}…` : rec.text;
      buttons.push({ label: t('gatedrop.toast.copy'), action: { type: 'copy', text: rec.text } });
    } else {
      return null;
    }
    if (rec.note) body = body ? `${rec.note} · ${body}` : rec.note;
    return this._showToast({ title, body, buttons, quiet, context: { tab: 'received', sendId: rec.sendId } });
  }

  _toastFailed(from, { quiet = false } = {}) {
    return this._showToast({
      quiet,
      title: t('gatedrop.toast.failed'),
      body: t('gatedrop.toast.failedBody', { from: this._fromName(from) }),
      buttons: [],
      context: { tab: 'received', sendId: null },
    });
  }

  _showToast({ title, body, buttons, context, quiet = false }) {
    const decision = this._decide(quiet);
    if (!decision.show) return null;
    const N = this._NotificationClass();
    if (!N || (typeof N.isSupported === 'function' && !N.isSupported())) return null;
    let options;
    if (this.platform === 'win32') {
      const btns = this.protocol ? buttons.map((b) => ({ label: b.label, nonce: this._nonce(b.action) })) : [];
      options = {
        toastXml: buildToastXml({
          title, body, attribution: 'GateDrop', silent: decision.silent, buttons: btns, scheme: this.protocol,
          imagePath: this.toastImagePath, launch: 'gatecontrol-gatedrop',
        }),
      };
    } else {
      options = { title, body, silent: !!decision.silent };
    }
    let n;
    try { n = new N(options); } catch (err) { this.log.warn(`GateDrop toast: ${err.message}`); return null; }
    this._toasts.add(n);
    const forget = () => this._toasts.delete(n);
    n.on('click', () => {
      forget();
      if (this.showWindow) { try { this.showWindow(); } catch { /* window gone */ } }
      this.emit('navigate', context);
    });
    n.on('close', forget);
    n.on('failed', forget);
    try { n.show(); } catch (err) { this.log.warn(`GateDrop toast: ${err.message}`); }
    while (this._toasts.size > 20) this._toasts.delete(this._toasts.values().next().value);
    return n;
  }

  /** Click on a GateDrop entry of the inbox / its toast → the page (route plg-gatecontrol-gatedrop). */
  clickContext(entry) {
    if (!this.available() || !entry || !gd.isGateDropPush(entry)) return null;
    const p = gd.parsePushData(entry.data);
    return { tab: entry.topic === `${gd.TOPIC_PREFIX}link` ? 'links' : 'received', sendId: p && p.sendId ? p.sendId : null };
  }

  // ── Command line ("Senden an") ───────────────────────────

  /** argv with --gatedrop-send → compose() with the files; true when it was one. */
  handleArgv(argv) {
    const { parseSendArgs } = require('../utils/gatedrop-shell');
    const paths = parseSendArgs(argv);
    if (!paths) return false;
    this.compose(paths).catch((err) => this.log.warn(`GateDrop compose failed: ${err.message}`));
    return true;
  }
}

GateDropService.DEFAULT_TIMING = DEFAULT_TIMING;
GateDropService.GateDropError = GateDropError;

module.exports = GateDropService;
