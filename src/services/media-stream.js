'use strict';

/**
 * Medien (Stufe 4e): the bytes for the page's <video> / <img> / hls.js through the scheme `gcmedia:` — as `gcdrive:`
 * (services/drive-stream.js): the page only gets a random token, the main process fetches with the Jellyfin token or
 * the share's access and the way of now (at home bound to the LAN, away through the tunnel), passes Range on and
 * gives the type. No access ever reaches the renderer.
 *
 *   gcmedia://media/<token>/<file>[?query]   Jellyfin: a stream of one play (the file itself `stream?static=true…`, an
 *     HLS playlist `master.m3u8?…` and what it names below the same folder: `main.m3u8`, `hls1/main/0.mp4`, a subtitle).
 *     `api_key` never goes to the page: taken out of the playlists (the access goes in the header instead), taken out
 *     of what the page asks. Nothing outside the play's folder of the server.
 *   gcmedia://media/<token>/<name>           a file of a share (SMB: a read stream from the place asked for; WebDAV:
 *     the Range passed on).
 *   gcmedia://image/<token>/Items/<id>/Images/<Primary|Backdrop|Thumb>?maxHeight&quality&tag   a poster or backdrop
 *     of a Jellyfin source (one token per source).
 *
 * Answers: the type of the file (video/audio/image/text/vtt, an HLS playlist — never a type a page could run),
 * Content-Length / Content-Range / Accept-Ranges, nothing cached, Access-Control-Allow-Origin only for the app's page
 * (hls.js loads with fetch/XHR: the scheme is CORS-enabled); 416 stays 416, anything else 404 / 502.
 */

const crypto = require('crypto');
const { Readable } = require('stream');
const S = require('../utils/media-share');
const { pageOrigin } = require('./drive-vault-view');

const SCHEME = 'gcmedia';
const TOKEN_RE = /^[A-Za-z0-9_-]{24}$/;
const SEG_RE = /^[A-Za-z0-9._-]{1,160}$/;
const IMAGE_PATH_RE = /^Items\/[A-Za-z0-9-]{1,64}\/Images\/(?:Primary|Backdrop|Thumb)(?:\/\d{1,2})?$/;
const IMAGE_QUERY = new Set(['maxHeight', 'maxWidth', 'fillHeight', 'fillWidth', 'quality', 'tag', 'format']);
const SECRET_PARAMS = /^(?:api_key|apikey|x-emby-token|x-mediabrowser-token|token)$/i;
const MIME_RE = /^(?:(?:video|audio)\/[a-z0-9][a-z0-9.+-]{0,80}|image\/(?:jpeg|png|webp|gif|avif)|text\/vtt|application\/(?:vnd\.apple\.mpegurl|x-mpegurl|mp4|octet-stream))$/;
const PLAYLIST_RE = /^(?:application\/(?:vnd\.apple\.mpegurl|x-mpegurl)|audio\/(?:x-)?mpegurl)$/;
const DEFAULT_TIMING = Object.freeze({ ttlMs: 6 * 60 * 60 * 1000, headerMs: 15000, idleMs: 30000 });
const MAX_TOKENS = 200;
const MAX_PLAYLIST = 4 * 1024 * 1024;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** A `gcmedia:` URL → { host: 'media' | 'image', token, rest: ['seg', …], query: URLSearchParams } or null. */
function parseUrl(url) {
  if (typeof url !== 'string' || url.length > 4096) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== `${SCHEME}:` || (u.hostname !== 'media' && u.hostname !== 'image') || u.username || u.password || u.port) return null;
  const segs = u.pathname.split('/').filter(Boolean).map((s) => {
    try { return decodeURIComponent(s); } catch { return null; }
  });
  if (!segs.length || segs.some((s) => s === null) || !TOKEN_RE.test(segs[0])) return null;
  return { host: u.hostname, token: segs[0], rest: segs.slice(1), query: u.searchParams };
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

/** The query without anything that is an access. */
function cleanQuery(params) {
  const out = new URLSearchParams();
  for (const [k, v] of params) if (!SECRET_PARAMS.test(k)) out.append(k, v);
  const s = out.toString();
  return s ? `?${s}` : '';
}

function typeOf(raw, name) {
  const t = typeof raw === 'string' ? raw.split(';')[0].trim().toLowerCase() : '';
  if (PLAYLIST_RE.test(t)) return 'application/vnd.apple.mpegurl';
  if (MIME_RE.test(t) && t !== 'application/octet-stream') return t;
  const byName = S.mimeOf(name || '');
  if (name && name.toLowerCase().endsWith('.m3u8')) return 'application/vnd.apple.mpegurl';
  if (name && /\.(?:mp4|m4s)$/i.test(name)) return 'video/mp4';
  return MIME_RE.test(byName) ? byName : 'application/octet-stream';
}

/**
 * An HLS playlist of the server, made fit for the page: every URI (lines and URI="…" attributes) loses its access
 * parameters; one under the play's folder (`dirUrl`) becomes relative to it, so it stays under the same token.
 */
function rewritePlaylist(text, dirUrl) {
  let dir;
  try { dir = new URL(dirUrl); } catch { return ''; }
  const fix = (raw) => {
    const uri = raw.trim();
    if (!uri) return uri;
    let abs;
    try { abs = new URL(uri, dir); } catch { return ''; }
    if (abs.origin !== dir.origin || !abs.pathname.startsWith(dir.pathname)) return '';
    const rel = abs.pathname.slice(dir.pathname.length);
    if (!rel || rel.split('/').some((s) => !SEG_RE.test(decodeSafe(s)) || s === '..' || s === '.')) return '';
    return rel + cleanQuery(abs.searchParams);
  };
  return String(text).split(/\r?\n/).map((line) => {
    if (line.startsWith('#')) return line.replace(/URI="([^"]*)"/g, (_m, u) => `URI="${fix(u)}"`);
    return line.trim() ? fix(line) : line;
  }).join('\n');
}

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch { return '\u0000'; }
}

function plainHeaders(origin) {
  const h = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
  if (origin) { h['Access-Control-Allow-Origin'] = origin; h.Vary = 'Origin'; }
  return h;
}

class MediaStreamService {
  /**
   * @param {object} opts
   * @param {(sourceId: string) => object|null} opts.jellyfin - the JellyfinClient of a source (its way of now)
   * @param {(sourceId: string) => Promise<object|null>|object|null} opts.share - the share to read a file from (of a
   *   pair the one of the network now: SmbShare / WebDavShare)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing]
   */
  constructor({ jellyfin, share, log = null, now = Date.now, timing = {} }) {
    this.jellyfin = typeof jellyfin === 'function' ? jellyfin : () => null;
    this.share = typeof share === 'function' ? share : () => null;
    this.log = log || noopLog();
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this._tokens = new Map();
  }

  _token(entry) {
    this._prune();
    const token = crypto.randomBytes(18).toString('base64url');
    this._tokens.set(token, { ...entry, exp: this.now() + this.timing.ttlMs });
    while (this._tokens.size > MAX_TOKENS) this._tokens.delete(this._tokens.keys().next().value);
    return token;
  }

  /**
   * A URL of the Jellyfin server (the plan's url, a side subtitle) → `gcmedia://media/<token>/<file>?query` (the
   * query without the access); the token allows that folder of the server only.
   */
  openJellyfin(sourceId, absUrl, { play = null } = {}) {
    let u;
    try { u = new URL(absUrl); } catch { return null; }
    const cut = u.pathname.lastIndexOf('/');
    const dir = `${u.origin}${u.pathname.slice(0, cut + 1)}`;
    const file = u.pathname.slice(cut + 1);
    if (!file || !SEG_RE.test(decodeSafe(file))) return null;
    const token = this._token({ kind: 'jellyfin', sourceId, dir, play });
    return `${SCHEME}://media/${token}/${file}${cleanQuery(u.searchParams)}`;
  }

  /** A file of a share → `gcmedia://media/<token>/<its name>` (the extension stays for the player's guess). */
  openShare(sourceId, path, { mime = null, play = null } = {}) {
    const clean = S.clean(path);
    if (!clean) return null;
    const token = this._token({ kind: 'share', sourceId, path: clean, mime: mime || S.mimeOf(clean), play });
    return `${SCHEME}://media/${token}/${encodeURIComponent(S.baseName(clean))}`;
  }

  /** The pictures of a Jellyfin source: one token per source; imageUrl(sourceId, 'Items/…?…') → gcmedia://image/… */
  imageBase(sourceId) {
    for (const [t, e] of this._tokens) if (e.kind === 'image' && e.sourceId === sourceId && e.exp > this.now() + 60000) return `${SCHEME}://image/${t}/`;
    return `${SCHEME}://image/${this._token({ kind: 'image', sourceId })}/`;
  }

  imageUrl(sourceId, pathAndQuery) {
    return pathAndQuery ? this.imageBase(sourceId) + pathAndQuery : null;
  }

  /** The play ended / the page moved on: its addresses stop working (all of `play` when given). */
  revoke(urlOrPlay) {
    const p = parseUrl(String(urlOrPlay || ''));
    if (p) this._tokens.delete(p.token);
    else for (const [t, e] of this._tokens) if (e.play && e.play === urlOrPlay) this._tokens.delete(t);
    return { ok: true };
  }

  /** A source went (removed, signed out): its addresses stop working. */
  revokeSource(sourceId) {
    for (const [t, e] of this._tokens) if (e.sourceId === sourceId) this._tokens.delete(t);
  }

  clear() { this._tokens.clear(); }

  _prune() {
    const now = this.now();
    for (const [t, e] of this._tokens) if (e.exp <= now) this._tokens.delete(t);
  }

  _entry(token) {
    const e = token ? this._tokens.get(token) : null;
    if (!e) return null;
    if (e.exp <= this.now()) { this._tokens.delete(token); return null; }
    return e;
  }

  /** Electron protocol.handle('gcmedia', (req) => stream.handleProtocol(req)) → a Response. */
  async handleProtocol(request) {
    const origin = pageOrigin(headerOf(request, 'origin'));
    const plain = (status) => new Response(null, { status, headers: plainHeaders(origin) });
    const method = request && request.method ? String(request.method).toUpperCase() : 'GET';
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...plainHeaders(origin), 'Access-Control-Allow-Methods': 'GET, HEAD', 'Access-Control-Allow-Headers': 'Range', 'Access-Control-Max-Age': '600' } });
    }
    if (method !== 'GET' && method !== 'HEAD') return plain(405);
    const p = parseUrl(request && request.url);
    const entry = p ? this._entry(p.token) : null;
    if (!entry) return plain(404);
    const range = rangeOf(headerOf(request, 'range'));
    try {
      if (p.host === 'image' && entry.kind === 'image') return await this._image(entry, p, method, origin);
      if (p.host === 'media' && entry.kind === 'jellyfin') return await this._jellyfin(entry, p, method, range, origin);
      if (p.host === 'media' && entry.kind === 'share') return await this._share(entry, p, method, range, origin);
    } catch (err) {
      this.log.debug(`Medien stream failed: ${(err && (err.code || err.message)) || 'error'}`);
      return plain(502);
    }
    return plain(404);
  }

  _out(type, origin, upstream = {}) {
    const out = { ...plainHeaders(origin), 'Content-Type': type, 'Content-Security-Policy': "default-src 'none'" };
    for (const [k, name] of [['content-length', 'Content-Length'], ['content-range', 'Content-Range'], ['accept-ranges', 'Accept-Ranges']]) {
      const v = upstream[k];
      if (v !== undefined && v !== null && /^[A-Za-z0-9 */=-]{1,80}$/.test(String(v))) out[name] = String(v);
    }
    if (origin) out['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Accept-Ranges';
    return out;
  }

  async _fetch(client, upstreamUrl, range, method) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timing.headerMs);
    try {
      return await client.stream(upstreamUrl, { headers: { Accept: '*/*', ...(range ? { Range: range } : {}) }, signal: ctrl.signal, timeout: this.timing.idleMs, method });
    } finally {
      clearTimeout(timer);
    }
  }

  async _jellyfin(entry, p, method, range, origin) {
    if (!p.rest.length || p.rest.length > 8 || p.rest.some((s) => !SEG_RE.test(s) || s === '..' || s === '.')) return new Response(null, { status: 404, headers: plainHeaders(origin) });
    const client = this.jellyfin(entry.sourceId);
    if (!client) return new Response(null, { status: 503, headers: plainHeaders(origin) });
    const upstream = entry.dir + p.rest.map((s) => encodeURIComponent(s)).join('/') + cleanQuery(p.query);
    const res = await this._fetch(client, upstream, range, method);
    const status = res.status;
    const h = res.headers || {};
    if (status !== 200 && status !== 206) {
      try { res.data.destroy(); } catch { /* ignore */ }
      return new Response(null, { status: status === 404 || status === 410 ? 404 : status === 416 ? 416 : 502, headers: plainHeaders(origin) });
    }
    const name = p.rest[p.rest.length - 1];
    const type = typeOf(h['content-type'], name);
    if (type === 'application/vnd.apple.mpegurl') {
      const chunks = [];
      let got = 0;
      for await (const c of res.data) {
        got += c.length;
        if (got > MAX_PLAYLIST) { res.data.destroy(); return new Response(null, { status: 502, headers: plainHeaders(origin) }); }
        chunks.push(c);
      }
      const body = Buffer.from(rewritePlaylist(Buffer.concat(chunks).toString('utf8'), entry.dir), 'utf8');
      const out = this._out(type, origin, { 'content-length': body.length });
      return new Response(method === 'HEAD' ? null : body, { status: 200, headers: out });
    }
    const out = this._out(type, origin, h);
    if (method === 'HEAD') {
      try { res.data.destroy(); } catch { /* ignore */ }
      return new Response(null, { status, headers: out });
    }
    // a cancelled body (the page stopped the video / moved on) destroys the upstream answer as well
    return new Response(Readable.toWeb(res.data), { status, headers: out });
  }

  async _image(entry, p, method, origin) {
    const path = p.rest.join('/');
    if (!IMAGE_PATH_RE.test(path)) return new Response(null, { status: 404, headers: plainHeaders(origin) });
    const client = this.jellyfin(entry.sourceId);
    if (!client) return new Response(null, { status: 503, headers: plainHeaders(origin) });
    const q = new URLSearchParams();
    for (const [k, v] of p.query) if (IMAGE_QUERY.has(k) && /^[A-Za-z0-9._-]{1,80}$/.test(v)) q.append(k, v);
    const qs = q.toString();
    const res = await this._fetch(client, client.url(path) + (qs ? `?${qs}` : ''), null, method);
    if (res.status !== 200) {
      try { res.data.destroy(); } catch { /* ignore */ }
      return new Response(null, { status: res.status === 404 ? 404 : 502, headers: plainHeaders(origin) });
    }
    const type = typeOf((res.headers || {})['content-type'], 'x.jpg');
    if (!type.startsWith('image/')) { try { res.data.destroy(); } catch { /* ignore */ } return new Response(null, { status: 502, headers: plainHeaders(origin) }); }
    const out = this._out(type, origin, { 'content-length': (res.headers || {})['content-length'] });
    if (method === 'HEAD') { try { res.data.destroy(); } catch { /* ignore */ } return new Response(null, { status: 200, headers: out }); }
    return new Response(Readable.toWeb(res.data), { status: 200, headers: out });
  }

  async _share(entry, p, method, range, origin) {
    const fsx = await this.share(entry.sourceId);
    if (!fsx) return new Response(null, { status: 503, headers: plainHeaders(origin) });
    const type = typeOf(entry.mime, entry.path);
    if (fsx.kind === 'webdav') {
      const r = await fsx.get(entry.path, range);
      if (!r.ok) return new Response(null, { status: r.code === 'unsatisfiable' ? 416 : r.code === 'not_found' ? 404 : 502, headers: plainHeaders(origin) });
      const out = this._out(type, origin, r.value.headers);
      if (!out['Accept-Ranges']) out['Accept-Ranges'] = r.value.status === 206 ? 'bytes' : 'none';
      if (method === 'HEAD') { try { r.value.stream.destroy(); } catch { /* ignore */ } return new Response(null, { status: r.value.status, headers: out }); }
      return new Response(Readable.toWeb(r.value.stream), { status: r.value.status, headers: out });
    }
    const st = await fsx.stat(entry.path);
    if (!st.ok) return new Response(null, { status: st.code === 'not_found' ? 404 : 502, headers: plainHeaders(origin) });
    const size = st.value.size;
    const want = range ? S.byteRange(range, size) : null;
    if (want === 'unsatisfiable') {
      return new Response(null, { status: 416, headers: { ...plainHeaders(origin), 'Content-Range': `bytes */${size}` } });
    }
    const start = want ? want.start : 0;
    const end = want ? want.end : size - 1;
    const out = this._out(type, origin, {
      'content-length': Math.max(0, end - start + 1),
      'accept-ranges': 'bytes',
      ...(want ? { 'content-range': `bytes ${start}-${end}/${size}` } : {}),
    });
    const status = want ? 206 : 200;
    if (method === 'HEAD' || size === 0) return new Response(null, { status, headers: out });
    const r = await fsx.open(entry.path, { start, end });
    if (!r.ok) return new Response(null, { status: 502, headers: plainHeaders(origin) });
    return new Response(Readable.toWeb(r.value.stream), { status, headers: out });
  }
}

MediaStreamService.SCHEME = SCHEME;
// <video>, <img>, <track> and hls.js (fetch / XHR from the app's page: CORS on, only that origin may read)
MediaStreamService.SCHEME_PRIVILEGES = Object.freeze({ standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true });
MediaStreamService.DEFAULT_TIMING = DEFAULT_TIMING;
MediaStreamService.parseUrl = parseUrl;
MediaStreamService.rewritePlaylist = rewritePlaylist;
MediaStreamService.cleanQuery = cleanQuery;
MediaStreamService.typeOf = typeOf;

module.exports = MediaStreamService;
