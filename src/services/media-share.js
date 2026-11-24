'use strict';

/**
 * Medien (Stufe 4e): the folders and files of a NAS share — SMB through Windows itself, WebDAV over HTTP.
 *
 * SmbShare: the UNC path `\\192.168.1.20\filme` read with fs (folders; a file from a place: a read stream with start /
 * end). The access is announced to Windows with WNetAddConnection2W (mpr.dll through the koffi the core has): no drive
 * letter, not remembered in the profile (only for this app session), cancelled again by close(). No SMB library in
 * JavaScript (the usual ones are old and speak no SMB3). Windows refuses a second user for a server the Explorer is
 * connected to already (error 1219, ERROR_SESSION_CREDENTIAL_CONFLICT): code 'smb_conflict' — the page offers "Mit
 * dem Explorer-Zugang verwenden" (source.useExisting: no WNetAddConnection2W, Windows' own session is used).
 *
 * WebDavShare: PROPFIND (Depth 1) for folders, GET with Range for files, Basic or Digest as the server asks (after the
 * first 401 the scheme is known and every further request carries it at once — the player's range requests do not
 * wait for a 401 each), only to the share's own server; Basic only over HTTPS or to a host of the home network. A
 * self-signed certificate is trusted only once confirmed (source.tlsPin, services/media-net.js).
 *
 * Both: list(dir) → { ok, value: [{ name, path, directory, size, modifiedAt, kind }] }, stat(path), bytes(path, max)
 * (a poster, at most max bytes; null otherwise), read(path, start, length) (the start of a file for the format check),
 * open(path, { start, end }) → { ok, stream, size, start, end } (end inclusive), check() (the root can be read with
 * this access), close(). Failures: { ok: false, code: 'offline' | 'unauthorized' | 'not_found' | 'smb_conflict' |
 * 'cert_untrusted' | 'cert_changed' | 'unsupported' | 'failed' }.
 */

const fs = require('fs');
const nodePath = require('path');
const { Readable } = require('stream');
const MA = require('../utils/media-address');
const S = require('../utils/media-share');
const MediaNet = require('./media-net');

const MAX_ENTRIES = 5000;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }
const ok = (value) => ({ ok: true, value });
const no = (code, extra = {}) => ({ ok: false, code, ...extra });

// ── Windows: WNetAddConnection2W / WNetCancelConnection2W ─────

const RESOURCETYPE_DISK = 1;
const WNET_CODES = {
  0: null,
  85: null, // ERROR_ALREADY_ASSIGNED
  1202: null, // ERROR_DEVICE_ALREADY_REMEMBERED
  1219: 'smb_conflict', // ERROR_SESSION_CREDENTIAL_CONFLICT
  5: 'unauthorized', 86: 'unauthorized', 1326: 'unauthorized', 1327: 'unauthorized', 1330: 'unauthorized', 1331: 'unauthorized', 1909: 'unauthorized',
  53: 'offline', 64: 'offline', 121: 'offline', 1203: 'offline', 1222: 'offline', 1231: 'offline', 1311: 'offline',
  67: 'not_found', // ERROR_BAD_NET_NAME: the server is there, the share is not
  50: 'unsupported', // ERROR_NOT_SUPPORTED (SMB1 only: the NAS needs SMB2/3)
};

/** A Windows error of WNetAddConnection2W → our code (null: connected). */
function wnetCode(err) {
  return Object.prototype.hasOwnProperty.call(WNET_CODES, err) ? WNET_CODES[err] : 'failed';
}

let wnet;

/** mpr.dll through koffi → { add(remote, user, password) → error, cancel(remote) → error }; null when not Windows. */
function loadWnet(koffi = null) {
  if (wnet !== undefined && !koffi) return wnet;
  let api = null;
  try {
    if (process.platform !== 'win32' && !koffi) throw new Error('not Windows');
    const k = koffi || require('koffi');
    const mpr = k.load('mpr.dll');
    const NR = k.struct('GC_MEDIA_NETRESOURCEW', {
      dwScope: 'uint32_t', dwType: 'uint32_t', dwDisplayType: 'uint32_t', dwUsage: 'uint32_t',
      lpLocalName: 'char16_t *', lpRemoteName: 'char16_t *', lpComment: 'char16_t *', lpProvider: 'char16_t *',
    });
    const add = mpr.func('WNetAddConnection2W', 'uint32_t', [k.pointer(NR), 'char16_t *', 'char16_t *', 'uint32_t']);
    const cancel = mpr.func('WNetCancelConnection2W', 'uint32_t', ['char16_t *', 'uint32_t', 'int']);
    api = {
      add: (remote, user, password) => add({
        dwScope: 0, dwType: RESOURCETYPE_DISK, dwDisplayType: 0, dwUsage: 0,
        lpLocalName: null, lpRemoteName: remote, lpComment: null, lpProvider: null,
      }, password == null ? null : String(password), user == null ? null : String(user), 0),
      cancel: (remote) => cancel(remote, 0, 0),
    };
  } catch {
    api = null;
  }
  if (!koffi) wnet = api;
  return api;
}

function fsCode(err) {
  const c = (err && err.code) || '';
  if (c === 'ENOENT' || c === 'ENOTDIR') return 'not_found';
  if (c === 'EACCES' || c === 'EPERM') return 'unauthorized';
  if (c === 'EISDIR') return 'not_found';
  if (['ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED', 'EHOSTDOWN', 'ENETDOWN', 'EIO', 'UNKNOWN', 'EBUSY', 'ECONNRESET'].includes(c)) return 'offline';
  return 'failed';
}

class SmbShare {
  /**
   * @param {object} opts
   * @param {object} opts.source - { address: 'smb://nas/filme', userName?, password?, useExisting? }
   * @param {object} [opts.wnet] - loadWnet() (tests: a fake)
   * @param {object} [opts.fs] - fs (tests)
   * @param {string} [opts.localRoot] - tests on Linux: a folder standing in for the UNC path
   * @param {object} [opts.log]
   */
  constructor({ source, wnet: w = undefined, fs: fsm = fs, localRoot = null, log = null }) {
    this.source = source;
    this.smb = MA.parseSmb(source.address);
    this.wnet = w === undefined ? loadWnet() : w;
    this.fs = fsm;
    this.localRoot = localRoot;
    this.log = log || noopLog();
    this._connected = false;
    this._added = false;
  }

  get kind() { return 'smb'; }

  /** The UNC root of the share itself (`\\nas\filme`): Windows connects to shares, not to their folders. */
  get remote() { return this.smb ? `\\\\${this.smb.host}\\${this.smb.share}` : null; }

  _path(rel) {
    if (this.localRoot) {
      const c = S.clean(rel);
      return c === null ? null : nodePath.join(this.localRoot, ...(this.smb && this.smb.path ? this.smb.path.split('/') : []), ...c.split('/').filter(Boolean));
    }
    if (!this.smb) return null;
    const inside = [this.smb.path, S.clean(rel)];
    if (inside[1] === null) return null;
    return S.uncPath(this.remote, inside.filter(Boolean).join('/'));
  }

  /** Windows knows the access (once per app session). */
  async connect() {
    if (!this.smb) return no('invalid');
    if (this.smb.port !== MA.SMB_PORT) return no('unsupported');
    if (this._connected) return ok(true);
    if (this.source.useExisting || !this.source.userName) { this._connected = true; return ok(true); }
    if (!this.wnet) return no('unsupported');
    let err;
    try { err = this.wnet.add(this.remote, this.source.userName, this.source.password || ''); } catch { err = -1; }
    const code = wnetCode(err);
    if (code) {
      this.log.debug(`SMB: ${this.smb.host} refused the connection (${err})`);
      return no(code, { winError: err });
    }
    this._connected = true;
    this._added = err === 0;
    return ok(true);
  }

  async _ready() {
    const c = await this.connect();
    return c.ok ? null : c;
  }

  async list(dir = '') {
    const r = await this._ready();
    if (r) return r;
    const clean = S.clean(dir);
    const p = clean === null ? null : this._path(clean);
    if (!p) return no('not_found');
    let entries;
    try { entries = await this.fs.promises.readdir(p, { withFileTypes: true }); } catch (err) { return no(fsCode(err)); }
    const out = [];
    for (const e of entries.slice(0, MAX_ENTRIES)) {
      const name = e.name;
      if (S.hidden(name) || S.clean(name) !== name) continue;
      const directory = e.isDirectory();
      if (!directory && !e.isFile()) continue;
      let size = 0;
      let modifiedAt = null;
      try {
        const st = await this.fs.promises.stat(nodePath.join(p, name));
        size = directory ? 0 : st.size;
        modifiedAt = Number.isFinite(st.mtimeMs) ? Math.floor(st.mtimeMs) : null;
      } catch { /* listed without size */ }
      out.push({ name, path: S.join(clean, name), directory, size, modifiedAt, kind: directory ? 'folder' : S.kindOf(name) });
    }
    return ok(out);
  }

  async stat(path) {
    const r = await this._ready();
    if (r) return r;
    const p = this._path(path);
    if (!p || !S.clean(path)) return no('not_found');
    try {
      const st = await this.fs.promises.stat(p);
      if (!st.isFile()) return no('not_found');
      return ok({ size: st.size, modifiedAt: Math.floor(st.mtimeMs) });
    } catch (err) { return no(fsCode(err)); }
  }

  async read(path, start, length) {
    const r = await this._ready();
    if (r) return r;
    const p = this._path(path);
    if (!p || !S.clean(path)) return no('not_found');
    let fh;
    try {
      fh = await this.fs.promises.open(p, 'r');
      const buf = Buffer.alloc(Math.max(0, Math.min(length, 64 * 1024 * 1024)));
      const { bytesRead } = await fh.read(buf, 0, buf.length, start);
      return ok(buf.subarray(0, bytesRead));
    } catch (err) {
      return no(fsCode(err));
    } finally {
      if (fh) await fh.close().catch(() => {});
    }
  }

  async bytes(path, max) {
    const st = await this.stat(path);
    if (!st.ok || st.value.size > max) return null;
    const r = await this.read(path, 0, st.value.size);
    return r.ok ? r.value : null;
  }

  /** File `path` from `start` to `end` (inclusive) as a stream. */
  async open(path, { start = 0, end = null } = {}) {
    const st = await this.stat(path);
    if (!st.ok) return st;
    const size = st.value.size;
    const last = end === null || end === undefined ? size - 1 : Math.min(end, size - 1);
    if (size === 0) return ok({ stream: Readable.from([]), size, start: 0, end: -1 });
    const stream = this.fs.createReadStream(this._path(path), { start, end: last, highWaterMark: 256 * 1024 });
    return ok({ stream, size, start, end: last });
  }

  async check() {
    const r = await this.list('');
    return r.ok ? ok(true) : r;
  }

  /** The access announced by connect() goes again (not one of the Explorer). */
  async close() {
    if (this._added && this.wnet) {
      try { this.wnet.cancel(this.remote); } catch { /* gone */ }
    }
    this._added = false;
    this._connected = false;
  }
}

// ── WebDAV ───────────────────────────────────────────────────

function davCode(status) {
  if (status === 401 || status === 403) return 'unauthorized';
  if (status === 404 || status === 410) return 'not_found';
  return 'failed';
}

class WebDavShare {
  /**
   * @param {object} opts
   * @param {object} opts.source - { address: 'https://192.168.1.20:5006/filme', userName?, password?, tlsPin? }
   * @param {object} opts.net - MediaNet
   * @param {() => { localAddress?: string|null }} [opts.way]
   * @param {object} [opts.log]
   */
  constructor({ source, net, way = null, log = null }) {
    this.source = source;
    this.base = String(source.address).replace(/\/+$/, '');
    this.net = net;
    this.way = typeof way === 'function' ? way : () => ({});
    this.log = log || noopLog();
    this._challenge = null;
    this._nc = 0;
    const u = new URL(this.base);
    this._origin = u.origin;
    this._basicAllowed = u.protocol === 'https:' || MA.isHomeHost(u.hostname);
  }

  get kind() { return 'webdav'; }

  url(path, directory) { return S.davUrl(this.base, path, directory); }

  _authHeader(method, url, c) {
    if (!c || !this.source.userName) return null;
    if (c.scheme === 'basic') return S.basicHeader(this.source.userName, this.source.password);
    const u = new URL(url);
    this._nc += 1;
    return S.digestHeader({ method, uri: u.pathname + u.search, user: this.source.userName, password: this.source.password, challenge: c, nc: this._nc });
  }

  /** One request with the access: after a 401 once more with the scheme the server asked for. */
  async send(method, url, { headers = {}, data, responseType = 'text', timeout = 20000, signal } = {}) {
    const same = new URL(url).origin === this._origin;
    const w = this.way() || {};
    const go = (c) => {
      const auth = same ? this._authHeader(method, url, c) : null;
      return this.net.request({
        method, url, data, responseType, timeout, signal,
        headers: { ...headers, ...(auth ? { Authorization: auth } : {}) },
        localAddress: w.localAddress || null,
        pin: this.source.tlsPin || null,
        maxBytes: responseType === 'stream' ? undefined : S.MAX_LISTING_BYTES,
      });
    };
    const known = this._challenge;
    const first = await go(known);
    if (first.status !== 401 || !same || !this.source.userName) return first;
    const offered = S.parseChallenges(first.headers && first.headers['www-authenticate']);
    const pick = S.chooseChallenge(offered, this._basicAllowed);
    if (!pick) return first;
    const stale = String(pick.params.stale || '').toLowerCase() === 'true';
    // the same challenge refused again: the name or the password is wrong
    if (known && !stale && known.scheme === pick.scheme && known.params.nonce === pick.params.nonce) return first;
    this._challenge = pick;
    this._nc = 0;
    if (responseType === 'stream' && first.data && typeof first.data.destroy === 'function') first.data.destroy();
    return go(pick);
  }

  async _do(fn) {
    try { return await fn(); } catch (err) {
      const e = MediaNet.toError(err);
      this.log.debug(`WebDAV: not reached (${e.code})`);
      return no(e.code === 'timeout' || e.code === 'failed' ? 'offline' : e.code, e.fingerprint ? { fingerprint: e.fingerprint } : {});
    }
  }

  async list(dir = '') {
    const clean = S.clean(dir);
    if (clean === null) return no('not_found');
    return this._do(async () => {
      const r = await this.send('PROPFIND', this.url(clean, true), {
        headers: { Depth: '1', 'Content-Type': 'application/xml; charset=utf-8' }, data: S.PROPFIND_BODY, responseType: 'text',
      });
      if (r.status !== 207 && (r.status < 200 || r.status >= 300)) return no(davCode(r.status));
      const entries = S.parseMultistatus(typeof r.data === 'string' ? r.data : '', this.base, clean);
      if (!entries) return no('failed');
      return ok(entries.slice(0, MAX_ENTRIES).map((e) => ({ ...e, kind: e.directory ? 'folder' : S.kindOf(e.name) })));
    });
  }

  async stat(path) {
    const clean = S.clean(path);
    if (!clean) return no('not_found');
    return this._do(async () => {
      const r = await this.send('PROPFIND', this.url(clean, false), { headers: { Depth: '0', 'Content-Type': 'application/xml; charset=utf-8' }, data: S.PROPFIND_BODY });
      if (r.status !== 207 && (r.status < 200 || r.status >= 300)) return no(davCode(r.status));
      const entries = S.parseMultistatus(typeof r.data === 'string' ? r.data : '', this.base, S.parent(clean));
      const e = entries && entries.find((x) => x.path === clean && !x.directory);
      return e ? ok({ size: e.size, modifiedAt: e.modifiedAt }) : no('not_found');
    });
  }

  /** The answer of GET with `range` ('bytes=a-b' or null) as a stream: { status, headers, stream }. */
  async get(path, range = null, { signal } = {}) {
    const clean = S.clean(path);
    if (!clean) return no('not_found');
    return this._do(async () => {
      const r = await this.send('GET', this.url(clean, false), { headers: range ? { Range: range } : {}, responseType: 'stream', timeout: 30000, signal });
      if (r.status !== 200 && r.status !== 206) {
        try { r.data.destroy(); } catch { /* ignore */ }
        return no(r.status === 416 ? 'unsatisfiable' : davCode(r.status), { status: r.status });
      }
      return ok({ status: r.status, headers: r.headers || {}, stream: r.data });
    });
  }

  async read(path, start, length) {
    const r = await this.get(path, `bytes=${start}-${start + Math.max(1, length) - 1}`);
    if (!r.ok) return r;
    const chunks = [];
    let got = 0;
    let skip = r.value.status === 200 ? start : 0;
    try {
      for await (const c of r.value.stream) {
        let b = c;
        if (skip > 0) {
          if (b.length <= skip) { skip -= b.length; continue; }
          b = b.subarray(skip);
          skip = 0;
        }
        chunks.push(b);
        got += b.length;
        if (got >= length) break;
      }
    } catch (err) {
      return no(MediaNet.toError(err).code === 'cancelled' ? 'failed' : 'offline');
    } finally {
      try { r.value.stream.destroy(); } catch { /* ignore */ }
    }
    return ok(Buffer.concat(chunks).subarray(0, length));
  }

  async bytes(path, max) {
    const r = await this.get(path, null);
    if (!r.ok) return null;
    const len = Number(r.value.headers['content-length']);
    if (Number.isFinite(len) && len > max) { try { r.value.stream.destroy(); } catch { /* ignore */ } return null; }
    const chunks = [];
    let got = 0;
    try {
      for await (const c of r.value.stream) {
        got += c.length;
        if (got > max) { r.value.stream.destroy(); return null; }
        chunks.push(c);
      }
    } catch { return null; }
    return Buffer.concat(chunks);
  }

  /**
   * File `path` from `start` to `end` (inclusive). A server that ignores the range is skipped to the place, as
   * Android's WebDavFs.open.
   */
  async open(path, { start = 0, end = null, signal } = {}) {
    const range = start > 0 || (end !== null && end !== undefined) ? `bytes=${start}-${end === null || end === undefined ? '' : end}` : null;
    const r = await this.get(path, range, { signal });
    if (!r.ok) return r;
    const h = r.value.headers;
    if (r.value.status === 206) {
      const cr = S.contentRange(h['content-range']);
      return ok({ stream: r.value.stream, size: cr ? cr.total : null, start: cr ? cr.start : start, end: cr ? cr.end : end });
    }
    const length = Number(h['content-length']);
    const size = Number.isFinite(length) ? length : null;
    let stream = r.value.stream;
    if (start > 0) {
      let skip = start;
      const src = stream;
      stream = Readable.from((async function* skipTo() {
        for await (const c of src) {
          if (skip >= c.length) { skip -= c.length; continue; }
          yield skip ? c.subarray(skip) : c;
          skip = 0;
        }
      })());
      stream.once('close', () => { try { src.destroy(); } catch { /* ignore */ } });
    }
    const last = size === null ? null : (end === null || end === undefined ? size - 1 : Math.min(end, size - 1));
    return ok({ stream, size, start, end: last });
  }

  async check() {
    const r = await this.list('');
    return r.ok ? ok(true) : r;
  }

  async close() { this._challenge = null; }
}

module.exports = { SmbShare, WebDavShare, loadWnet, wnetCode, fsCode, WNET_CODES };
