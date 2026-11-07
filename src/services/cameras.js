'use strict';

/**
 * GateControl – Kameras im Heimnetz (Core service)
 *
 * The data side of the page "Kameras" in the Windows apps: the home cameras
 * (ONVIF / RTSP through a GateControl gateway) of the plugin
 * `gatecontrol-door` 1.6.0 "Tür & Kamera" (GateControl ≥ 1.240.0, gateway
 * ≥ 1.28.0), over the device token of the existing ApiClient:
 *
 *   GET /api/v1/client/plugins                                    is the plugin there?
 *   GET …/gatecontrol-door/api/cameras/home                       the cameras this person sees
 *   GET …/gatecontrol-door/api/cameras/home/<id>/live             live (VPN / LAN) or a still every 10 s
 *   GET …/gatecontrol-door/api/cameras/home/<id>/still            "Standbild speichern"
 *   GET …/gatecontrol-door/api/cameras/home/<id>/clips[?day=]     "Clips heute"
 *   PUT …/gatecontrol-door/api/cameras/home/<id>/prefs { push }   own push "Personen an der Kamera" (plugin 1.7.0)
 *   GET /camera-media/<token>/<file>                              the media (no login, token 10 min)
 *
 * - Availability: the page exists while the plugin list names
 *   `gatecontrol-door` (≥ 1.6.0 when it says its version), GET cameras/home
 *   answers `supported: true` (GateControl with gc.cameras) and the person
 *   sees at least one camera (the plugin lists only the cameras of the
 *   person's rights). Asked at start, every 30 min, after a push reconnect,
 *   on a camera push and on check(); network errors are retried (5 s … 5 min).
 *   Ring and the locks are not part of this service (they stay in the
 *   portal and the chat cards as before).
 * - Media: the answers carry `gccam://media/<token>/<file>` (utils/cameras.js);
 *   handleProtocol() serves them from the own server with the client's
 *   connection (streamed: live.mp4 is a continuous fragmented MP4, clips with
 *   Range). Only `/camera-media/` of the configured server can be reached.
 * - Push "Personen an der Kamera" (topic `plugin:gatecontrol-door:kamera`,
 *   data.door { type: 'home_camera_event', cameraId, eventId }): drops the
 *   cached clips and emits 'push'; a click on its toast opens the page on
 *   that camera (NotificationCenter.addClickRoute) while the page exists;
 *   the toast shows the picture of the push (its `imageUrl`, else a fresh
 *   still) when the NotificationCenter takes toast pictures (addToastImage).
 *
 * Events: 'state' (status()), 'push' ({ cameraId, eventId, notificationId }).
 */

const EventEmitter = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Readable } = require('stream');
const MessengerApi = require('./messenger-api');
const { PLUGINS_PATH, isNotifyMediaPath } = require('../utils/messenger');
const cam = require('../utils/cameras');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,    // available / unavailable: ask again
  retryMinMs: 5000,             // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,    // … 5 min
  listTtlMs: 15 * 1000,         // the camera list (its stills change every few seconds)
  clipsTtlMs: 30 * 1000,        // clips of a day
  mediaHeaderMs: 20 * 1000,     // a media answer must start within this time
  mediaIdleMs: 30 * 1000,       // … and keep flowing (live.mp4 sends a fragment every ~2 s)
  toastKeep: 20,                // toast pictures kept in the temp folder
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class CamerasService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.notificationCenter] - camera pushes → 'push', their toast click opens the page,
   *   their toast gets the picture (addToastImage, when the center has it)
   * @param {object} [opts.pushClient] - a reconnect ('hello') asks for the plugin again
   * @param {() => string} [opts.tempDir] - folder of the toast pictures (default %TEMP%\gatecontrol-cameras)
   * @param {object} [opts.api] - MessengerApi-compatible transport (tests)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({ apiClient, log, notificationCenter = null, pushClient = null, tempDir = null, api = null, timing = {}, now = Date.now } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this.notificationCenter = notificationCenter;
    this.pushClient = pushClient;
    this.tempDir = typeof tempDir === 'function' ? tempDir : () => path.join(os.tmpdir(), 'gatecontrol-cameras');

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null, count: 0, minGatecontrol: null };
    this._list = null;         // { at, data } of GET cameras/home
    this._clips = new Map();   // `${id}|${day}` → { at, data }
    this._inflight = new Map();
    this._toastFiles = [];
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
        this._unsub.push(nc.addClickRoute(cam.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
      if (typeof nc.addToastImage === 'function') {
        this._unsub.push(nc.addToastImage((entry) => this.toastImage(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
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
    this._list = null;
    this._clips.clear();
    this._inflight.clear();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null, count: 0, minGatecontrol: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt, count, minGatecontrol }
   * reason (unavailable): not_installed | unsupported (plugin < 1.6.0) | needs_gatecontrol (no gc.cameras,
   * minGatecontrol says which) | no_cameras (the person sees none) | auth | forbidden | not_configured.
   */
  status() {
    return { ...this._state };
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
    this._ensureScope();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    try {
      const data = await this.api._call('GET', PLUGINS_PATH);
      const plugins = Array.isArray(data.plugins) ? data.plugins : [];
      const p = plugins.find((x) => x && x.id === cam.PLUGIN_ID);
      this._retry = 0;
      const version = p && typeof p.version === 'string' ? p.version.slice(0, 40) : null;
      if (!p) {
        this._setState({ state: 'unavailable', reason: 'not_installed', version: null, checkedAt: this.now() });
      } else if (cam.homeSupported(version) === false) {
        this._setState({ state: 'unavailable', reason: 'unsupported', version, checkedAt: this.now() });
      } else {
        await this._loadList(version);
      }
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        this._setState({ state: 'unavailable', reason: 'unsupported', version: this._state.version, checkedAt: this.now() });
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setState({ state: 'unavailable', reason: err.status === 401 ? 'auth' : 'forbidden', version: null, checkedAt: this.now() });
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        // Network / 5xx: keep "available" (the page stays, the list comes from the cache).
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

  /** GET cameras/home → the list (cached) and the state that follows from it. */
  async _loadList(version = this._state.version) {
    const scope = this._scope;
    const raw = await this.api._call('GET', `${cam.API_BASE}cameras/home`);
    const data = cam.normalizeList(raw);
    const at = this.now();
    if (scope === this._scope) this._list = { at, data };
    this._applyList(data, version);
    return { at, data };
  }

  _applyList(data, version = this._state.version) {
    const base = { version, checkedAt: this.now(), count: data.cameras.length, minGatecontrol: data.minGatecontrol };
    if (!data.supported) this._setState({ ...base, state: 'unavailable', reason: 'needs_gatecontrol', count: 0 });
    else if (!data.cameras.length) this._setState({ ...base, state: 'unavailable', reason: 'no_cameras' });
    else this._setState({ ...base, state: 'available', reason: null });
  }

  _setState(s) {
    const key = (x) => JSON.stringify([x.state, x.reason, x.version, x.count, x.minGatecontrol]);
    const before = key(this._state);
    this._state = {
      state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null,
      count: Number.isSafeInteger(s.count) ? s.count : 0, minGatecontrol: s.minGatecontrol || null,
    };
    if (key(this._state) !== before) this.emit('state', this.status());
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._list = null;
    this._clips.clear();
  }

  _err(err) {
    const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
    // Plugin gone or no longer allowed / camera no longer seen: ask again.
    if (e.status === 404 || e.status === 403) this.check().catch(() => {});
    return e;
  }

  _id(id) {
    if (!cam.isCameraId(id)) throw new MessengerError('invalid camera', { code: 'invalid' });
    return id;
  }

  // ── Data ─────────────────────────────────────────────────

  /** GET cameras/home → { ok, supported, every, cameras, fetchedAt, stale } */
  async list({ refresh = false } = {}) {
    this._ensureScope();
    const hit = this._list;
    if (!refresh && hit && this.now() - hit.at < this.timing.listTtlMs) return { ok: true, ...copy(hit.data), fetchedAt: hit.at, stale: false };
    if (this._inflight.has('list')) return this._inflight.get('list');
    const run = (async () => {
      try {
        const r = await this._loadList();
        return { ok: true, ...copy(r.data), fetchedAt: r.at, stale: false };
      } catch (err) {
        const e = this._err(err);
        if (this._list && e.transient) return { ok: true, ...copy(this._list.data), fetchedAt: this._list.at, stale: true, error: e.code };
        throw e;
      } finally {
        this._inflight.delete('list');
      }
    })();
    this._inflight.set('list', run);
    return run;
  }

  /** GET cameras/home/<id>/live → { ok, live } (never cached: the tokens and the way depend on now). */
  async live(id) {
    this._id(id);
    this._ensureScope();
    try {
      const raw = await this.api._call('GET', `${cam.API_BASE}cameras/home/${id}/live`);
      const live = cam.normalizeLive(raw);
      if (!live) throw new MessengerError('no picture', { code: 'bad_response' });
      return { ok: true, live };
    } catch (err) {
      throw this._err(err);
    }
  }

  /**
   * PUT cameras/home/<id>/prefs { push } (plugin 1.7.0) → { ok, push }: this person's push of the camera.
   * The cached list carries the new value at once (the next list from the server says the same).
   */
  async setPush(id, on) {
    this._id(id);
    if (typeof on !== 'boolean') throw new MessengerError('push must be true or false', { code: 'invalid' });
    this._ensureScope();
    try {
      const raw = await this.api._call('PUT', `${cam.API_BASE}cameras/home/${id}/prefs`, { body: { push: on } });
      const push = cam.normalizePrefs(raw);
      if (push === null) throw new MessengerError('bad answer', { code: 'bad_response' });
      const hit = this._list;
      if (hit && hit.data && Array.isArray(hit.data.cameras)) {
        hit.data = { ...hit.data, cameras: hit.data.cameras.map((c) => (c.id === id ? { ...c, myPush: push } : c)) };
      }
      return { ok: true, push };
    } catch (err) {
      throw this._err(err);
    }
  }

  /** GET cameras/home/<id>/still → { mime, data: Buffer, at } */
  async still(id) {
    this._id(id);
    this._ensureScope();
    try {
      const raw = await this.api._call('GET', `${cam.API_BASE}cameras/home/${id}/still`);
      const s = cam.normalizeStill(raw);
      if (!s) throw new MessengerError('no picture', { code: 'no_image' });
      return s;
    } catch (err) {
      throw this._err(err);
    }
  }

  /** GET cameras/home/<id>/clips[?day] → { ok, day, clips, fetchedAt, stale } */
  async clips(id, { day, refresh = false } = {}) {
    this._id(id);
    const d = cam.dayArg(day);
    if (d === null) throw new MessengerError('invalid day', { code: 'invalid' });
    this._ensureScope();
    const key = `${id}|${d || ''}`;
    const hit = this._clips.get(key);
    if (!refresh && hit && this.now() - hit.at < this.timing.clipsTtlMs) return { ok: true, ...copy(hit.data), fetchedAt: hit.at, stale: false };
    const ik = `clips:${key}`;
    if (this._inflight.has(ik)) return this._inflight.get(ik);
    const scope = this._scope;
    const run = (async () => {
      try {
        const raw = await this.api._call('GET', `${cam.API_BASE}cameras/home/${id}/clips`, d ? { params: { day: d } } : {});
        const data = cam.normalizeClips(raw);
        const at = this.now();
        if (scope === this._scope) {
          this._clips.set(key, { at, data });
          while (this._clips.size > 40) this._clips.delete(this._clips.keys().next().value);
        }
        return { ok: true, ...copy(data), fetchedAt: at, stale: false };
      } catch (err) {
        const e = this._err(err);
        const old = this._clips.get(key);
        if (old && e.transient) return { ok: true, ...copy(old.data), fetchedAt: old.at, stale: true, error: e.code };
        throw e;
      } finally {
        this._inflight.delete(ik);
      }
    })();
    this._inflight.set(ik, run);
    return run;
  }

  /** The camera's name in the last list (file names), else its id. */
  nameOf(id) {
    const c = this._list && this._list.data.cameras.find((x) => x.id === id);
    return c ? c.name : id;
  }

  // ── Media (protocol gccam:) ──────────────────────────────

  /**
   * Electron protocol.handle('gccam', (req) => cameras.handleProtocol(req)) → a Response.
   * gccam://media/<token>/<file> → GET /camera-media/<token>/<file> of the own server, streamed;
   * clip.mp4 with the Range of the request. The content type comes from the file name, never from
   * the answer; nothing is cached.
   */
  async handleProtocol(request) {
    const url = request && typeof request.url === 'string' ? request.url : '';
    const method = request && request.method ? String(request.method).toUpperCase() : 'GET';
    const target = cam.parseMediaUrl(url);
    if (method !== 'GET' && method !== 'HEAD') return plain(405);
    if (!target) return plain(404);
    let client;
    try { client = this.api._client(); } catch { return plain(503); }
    // identity: the bytes go on as they come (Content-Length / Content-Range stay right)
    const headers = { Accept: '*/*', 'Accept-Encoding': 'identity' };
    const range = target.file === 'clip.mp4' ? cam.rangeOf(headerOf(request, 'range')) : null;
    if (range) headers.Range = range;
    const ctrl = new AbortController();
    const startTimer = setTimeout(() => ctrl.abort(), this.timing.mediaHeaderMs);
    let res;
    try {
      res = await client.request({
        method: 'GET', url: target.path, responseType: 'stream', headers, signal: ctrl.signal,
        timeout: this.timing.mediaIdleMs, maxRedirects: 0, validateStatus: () => true, decompress: false,
      });
    } catch (err) {
      clearTimeout(startTimer);
      this.log.debug(`Camera media failed: ${(err && (err.code || err.message)) || 'error'}`);
      return plain(502);
    }
    clearTimeout(startTimer);
    const status = res.status;
    if (status !== 200 && status !== 206) {
      try { res.data.destroy(); } catch { /* ignore */ }
      return plain(status === 404 || status === 410 ? 404 : status === 416 ? 416 : 502);
    }
    const out = {
      'Content-Type': target.type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
    };
    const h = res.headers || {};
    for (const [k, name] of [['content-length', 'Content-Length'], ['content-range', 'Content-Range'], ['accept-ranges', 'Accept-Ranges']]) {
      const v = typeof h.get === 'function' ? h.get(k) : h[k];
      if (v !== undefined && v !== null && /^[A-Za-z0-9 */=-]{1,80}$/.test(String(v))) out[name] = String(v);
    }
    if (method === 'HEAD') {
      try { res.data.destroy(); } catch { /* ignore */ }
      return new Response(null, { status, headers: out });
    }
    // A cancelled body (the page stopped the video / left) destroys the upstream answer as well.
    return new Response(Readable.toWeb(res.data), { status, headers: out });
  }

  // ── Push ─────────────────────────────────────────────────

  _onPush(entry) {
    const ctx = cam.pushContext(entry);
    if (!ctx) return;
    // A new clip: the next answers come from the server.
    for (const k of [...this._clips.keys()]) if (k.startsWith(`${ctx.cameraId}|`)) this._clips.delete(k);
    this._list = null;
    if (this._state.state !== 'available') this.check().catch(() => {});
    this.emit('push', { ...ctx, notificationId: entry && Number.isSafeInteger(entry.id) ? entry.id : null });
  }

  /** Context for a click on a camera toast while the page exists, else null (the inbox opens). */
  clickContext(entry) {
    if (!this.available()) return null;
    return cam.pushContext(entry);
  }

  /**
   * The picture of a camera toast (NotificationCenter.addToastImage): null for any other push;
   * for a camera push a Promise of a JPEG file in the temp folder — the push's own picture
   * (`imageUrl`, /notify-media/… of the own server) or a fresh still — or null.
   */
  toastImage(entry) {
    const ctx = cam.pushContext(entry);
    if (!ctx) return null;
    return this._toastImage(entry, ctx).catch((err) => {
      this.log.debug(`Camera toast picture failed: ${(err && (err.code || err.message)) || 'error'}`);
      return null;
    });
  }

  async _toastImage(entry, ctx) {
    let img = null;
    const url = entry && entry.image_url;
    if (isNotifyMediaPath(url) && typeof this.api.noticeImage === 'function') {
      try {
        const r = await this.api.noticeImage(url);
        if (r && /^image\/(jpeg|png)$/.test(r.mime) && r.data && r.data.length) img = r;
      } catch { img = null; }
    }
    if (!img) {
      try { img = await this.still(ctx.cameraId); } catch { img = null; }
    }
    if (!img) return null;
    const dir = this.tempDir();
    await fs.promises.mkdir(dir, { recursive: true });
    const id = entry && Number.isSafeInteger(entry.id) ? entry.id : this.now();
    const file = path.join(dir, `toast-${id}.${img.mime === 'image/png' ? 'png' : 'jpg'}`);
    await fs.promises.writeFile(file, img.data);
    this._toastFiles = this._toastFiles.filter((f) => f !== file);
    this._toastFiles.push(file);
    while (this._toastFiles.length > this.timing.toastKeep) {
      const old = this._toastFiles.shift();
      fs.promises.unlink(old).catch(() => {});
    }
    return file;
  }
}

function copy(data) {
  return JSON.parse(JSON.stringify(data));
}

function plain(status) {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}

function headerOf(request, name) {
  const h = request && request.headers;
  if (!h) return null;
  if (typeof h.get === 'function') return h.get(name);
  return h[name] || h[name.toLowerCase()] || null;
}

CamerasService.DEFAULT_TIMING = DEFAULT_TIMING;
CamerasService.SCHEME = cam.SCHEME;
// <video> / <img> of the page: a standard, secure scheme with streamed answers (live.mp4, Range for clips).
CamerasService.SCHEME_PRIVILEGES = Object.freeze({ standard: true, secure: true, supportFetchAPI: false, corsEnabled: false, stream: true });

module.exports = CamerasService;
