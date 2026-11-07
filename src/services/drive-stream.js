'use strict';

/**
 * The viewer of pictures and videos of Drive (Drive 1.21): the bytes of a Drive file for the page's <img> / <video>
 * through the scheme `gcdrive:` — streamed from the own server's media route with the client's connection and the
 * Range of the request, so a video plays without loading it whole first (seeking asks for the part it needs).
 *
 *   open(nodeId) → { ok, url: 'gcdrive://media/<token>', mime, size, kind: 'image' | 'video' | 'audio' }
 *     GET nodes/<id> first (no folder, nothing of a vault, nothing the virus scan holds back: 423 with its code), then
 *     GET nodes/<id>/content — the plugin checks the rights there, tells a child that a parent looked and keeps
 *     "Zuletzt geöffnet"; the media id stays in the main process, the page only gets a random token (6 h, the last
 *     40, gone when the server or the account changes).
 *   handleProtocol(request) → Response (Electron protocol.handle('gcdrive', …)):
 *     gcdrive://media/<token> → GET /api/v1/client/plugins/gatecontrol-drive/media/<mediaId> of the own server, the
 *     Range passed on (one range), the type of the content answer — never the server's answer, never a type a page
 *     could run —, Content-Length / Content-Range / Accept-Ranges as they come, nothing cached; 416 stays 416,
 *     423 (the scan, later) stays 423, anything else 404 / 502.
 *   revoke(token), clear()
 *
 * Not for vault files: their content is ciphertext (the vault's viewer decrypts in memory).
 */

const crypto = require('crypto');
const { Readable } = require('stream');
const drive = require('../utils/drive');
const SC = require('../utils/scan');
const DriveApi = require('./drive-api');

const { DriveError } = DriveApi;
const SCHEME = 'gcdrive';
const MEDIA_HOST = 'media';
const TOKEN_RE = /^[A-Za-z0-9_-]{24}$/;
const MIME_RE = /^(image|video|audio)\/[a-z0-9][a-z0-9.+-]{0,80}$/;
const DEFAULT_TIMING = Object.freeze({ ttlMs: 6 * 60 * 60 * 1000, headerMs: 15000, idleMs: 30000 });
const MAX_TOKENS = 40;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** The kind of a Drive file for the viewer by its type: 'image' | 'video' | 'audio' | null. */
function mediaKind(mime) {
  const m = typeof mime === 'string' ? mime.split(';')[0].trim().toLowerCase() : '';
  // SVG is a document that can carry scripts: not through this scheme
  return MIME_RE.test(m) && m !== 'image/svg+xml' ? m.split('/')[0] : null;
}

/** A `gcdrive:` URL of the renderer → its token, else null. */
function parseUrl(url) {
  if (typeof url !== 'string' || url.length > 200) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== `${SCHEME}:` || u.hostname !== MEDIA_HOST || u.username || u.password || u.port || u.search) return null;
  const t = u.pathname.replace(/^\//, '');
  return TOKEN_RE.test(t) ? t : null;
}

/** A Range header worth passing on (`bytes=a-b`, one range), else null. */
function rangeOf(v) {
  const s = typeof v === 'string' ? v.trim() : '';
  return /^bytes=\d{0,15}-\d{0,15}$/.test(s) && s !== 'bytes=-' ? s : null;
}

function headerOf(request, name) {
  const h = request && request.headers;
  if (!h) return null;
  if (typeof h.get === 'function') return h.get(name);
  return h[name] || h[name.toLowerCase()] || null;
}

function plain(status) {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}

class DriveStreamService {
  /**
   * @param {object} opts
   * @param {object} opts.drive - DriveService (its api: DriveApi, _run)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing] - { ttlMs, headerMs, idleMs }
   */
  constructor({ drive: service, log, now = Date.now, timing = {} } = {}) {
    this.drive = service;
    this.log = log || noopLog();
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this._tokens = new Map();  // token → { mediaId, mime, exp, scope }
  }

  _api() { return this.drive.api; }

  _scope() {
    try { return this._api().scope(); } catch { return ''; }
  }

  /** A picture, video or sound of Drive for the viewer → { ok, url, mime, size, kind }. */
  async open(nodeId) {
    const run = typeof this.drive._run === 'function' ? (fn) => this.drive._run(fn) : (fn) => fn();
    return run(async () => {
      const api = this._api();
      const node = await api.node(nodeId);
      if (node.isDir || node.encrypted) throw new DriveError('not a picture or video', { code: 'invalid' });
      if (SC.isBlocked(node.scan)) throw new DriveError('blocked by the virus scan', { status: 423, code: SC.refusalOf(node.scan), body: { scan: node.scan } });
      const c = await api.content(node.id);
      if (c.empty || !drive.isMediaId(c.mediaId)) throw new DriveError('an empty file', { code: 'empty' });
      const kind = mediaKind(c.mime) || mediaKind(node.mime);
      if (!kind) throw new DriveError('not a picture or video', { code: 'invalid' });
      const mime = mediaKind(c.mime) ? c.mime.split(';')[0].trim().toLowerCase() : node.mime.split(';')[0].trim().toLowerCase();
      this._prune();
      const token = crypto.randomBytes(18).toString('base64url');
      this._tokens.set(token, { mediaId: c.mediaId, mime, exp: this.now() + this.timing.ttlMs, scope: this._scope() });
      while (this._tokens.size > MAX_TOKENS) this._tokens.delete(this._tokens.keys().next().value);
      return { ok: true, url: `${SCHEME}://${MEDIA_HOST}/${token}`, mime, size: Number.isSafeInteger(c.size) ? c.size : node.size, kind };
    });
  }

  /** The viewer closed or moved on: the address stops working. */
  revoke(url) {
    const t = parseUrl(url) || (TOKEN_RE.test(String(url || '')) ? String(url) : null);
    if (t) this._tokens.delete(t);
    return { ok: true };
  }

  clear() { this._tokens.clear(); }

  _prune() {
    const now = this.now();
    for (const [t, e] of this._tokens) if (e.exp <= now) this._tokens.delete(t);
  }

  _entry(token) {
    const e = token ? this._tokens.get(token) : null;
    if (!e) return null;
    if (e.exp <= this.now() || e.scope !== this._scope()) { this._tokens.delete(token); return null; }
    return e;
  }

  /** Electron protocol.handle('gcdrive', (req) => stream.handleProtocol(req)) → a Response. */
  async handleProtocol(request) {
    const method = request && request.method ? String(request.method).toUpperCase() : 'GET';
    if (method !== 'GET' && method !== 'HEAD') return plain(405);
    const entry = this._entry(parseUrl(request && request.url));
    if (!entry) return plain(404);
    let client;
    try { client = this._api().http._client(); } catch { return plain(503); }
    const headers = { Accept: '*/*', 'Accept-Encoding': 'identity' };
    const range = rangeOf(headerOf(request, 'range'));
    if (range) headers.Range = range;
    const ctrl = new AbortController();
    const startTimer = setTimeout(() => ctrl.abort(), this.timing.headerMs);
    let res;
    try {
      res = await client.request({
        method: 'GET', url: `${drive.MEDIA_PATH}/${entry.mediaId}`, responseType: 'stream', headers, signal: ctrl.signal,
        timeout: this.timing.idleMs, maxRedirects: 0, validateStatus: () => true, decompress: false,
      });
    } catch (err) {
      clearTimeout(startTimer);
      this.log.debug(`Drive media failed: ${(err && (err.code || err.message)) || 'error'}`);
      return plain(502);
    }
    clearTimeout(startTimer);
    const status = res.status;
    if (status !== 200 && status !== 206) {
      try { res.data.destroy(); } catch { /* ignore */ }
      return plain(status === 404 || status === 410 ? 404 : status === 416 || status === 423 ? status : 502);
    }
    const out = {
      'Content-Type': entry.mime, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
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
    // A cancelled body (the page stopped the video / moved on) destroys the upstream answer as well.
    return new Response(Readable.toWeb(res.data), { status, headers: out });
  }
}

DriveStreamService.SCHEME = SCHEME;
// <img> / <video> of the page: a standard, secure scheme with streamed answers (Range for seeking).
DriveStreamService.SCHEME_PRIVILEGES = Object.freeze({ standard: true, secure: true, supportFetchAPI: false, corsEnabled: false, stream: true });
DriveStreamService.DEFAULT_TIMING = DEFAULT_TIMING;
DriveStreamService.mediaKind = mediaKind;
DriveStreamService.parseUrl = parseUrl;

module.exports = DriveStreamService;
