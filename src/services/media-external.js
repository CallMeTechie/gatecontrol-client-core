'use strict';

/**
 * Medien (Stufe 4h): a share's file Chromium cannot play (DTS or AC3 sound, some mkv, avi) in another app — "In VLC
 * öffnen" when VLC is installed, else "In anderer App öffnen" (Windows' app for the file type).
 *
 * VLC gets an address of this PC's loopback (`http://127.0.0.1:<port>/<token>/<name>`), never the share's access:
 * the relay answers only for 127.0.0.1 with the right Host, only tokens made for it, with Range (VLC seeks), and goes
 * through the same code as the page's gcmedia: (MediaStreamService) — the access stays in this process. The loopback
 * works whatever session VLC runs in (an already running VLC that is not elevated takes the file over; it could not
 * read a share this elevated app connected). "In anderer App öffnen" hands the UNC path of an SMB file to Windows;
 * a WebDAV file has none (then only VLC can play it).
 */

const http = require('http');
const nodePath = require('path');
const { Readable } = require('stream');

const TOKEN_RE = /^[A-Za-z0-9_-]{24}$/;
const MAX_TOKENS = 16;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Where VLC may be: the registry's InstallDir first, then the usual folders (also the Store app's alias). */
function vlcCandidates(env = process.env, registryDir = null) {
  const out = [];
  const add = (dir) => { if (dir) out.push(nodePath.win32.join(dir, 'vlc.exe')); };
  add(registryDir);
  add(env.ProgramFiles && nodePath.win32.join(env.ProgramFiles, 'VideoLAN', 'VLC'));
  add(env['ProgramFiles(x86)'] && nodePath.win32.join(env['ProgramFiles(x86)'], 'VideoLAN', 'VLC'));
  add(env.ProgramW6432 && nodePath.win32.join(env.ProgramW6432, 'VideoLAN', 'VLC'));
  add(env.LOCALAPPDATA && nodePath.win32.join(env.LOCALAPPDATA, 'Programs', 'VideoLAN', 'VLC'));
  add(env.LOCALAPPDATA && nodePath.win32.join(env.LOCALAPPDATA, 'Microsoft', 'WindowsApps'));
  return [...new Set(out)];
}

/** `reg query` output → the InstallDir (or the default value: the path of vlc.exe) of HKLM\SOFTWARE\VideoLAN\VLC. */
function parseRegistry(text) {
  const lines = String(text || '').split(/\r?\n/);
  for (const name of ['InstallDir', '(Default)', '(Standard)']) {
    for (const l of lines) {
      const m = /^\s*(\S.*?)\s+REG_(?:EXPAND_)?SZ\s+(.+?)\s*$/.exec(l);
      if (m && m[1] === name) {
        const v = m[2];
        if (/\\vlc\.exe$/i.test(v)) return nodePath.win32.dirname(v);
        if (/^[A-Za-z]:\\/.test(v)) return v;
      }
    }
  }
  return null;
}

class MediaExternal {
  /**
   * @param {object} o
   * @param {object} o.stream - MediaStreamService (the relay asks it like the page does)
   * @param {(target: string) => Promise<string>|string} [o.openPath] - Electron's shell.openPath ('' = done)
   * @param {string} [o.platform]
   * @param {object} [o.env]
   * @param {object} [o.fs] - node:fs (tests)
   * @param {Function} [o.spawn] - child_process.spawn (tests)
   * @param {Function} [o.execFile] - child_process.execFile (tests)
   * @param {object} [o.log]
   */
  constructor({ stream, openPath = null, platform = process.platform, env = process.env, fs = null, spawn = null, execFile = null, log = null }) {
    this.stream = stream;
    this.openPath = typeof openPath === 'function' ? openPath : null;
    this.platform = platform;
    this.env = env;
    this.fs = fs || require('fs');
    this.spawn = spawn || require('child_process').spawn;
    this.execFile = execFile || require('child_process').execFile;
    this.log = log || noopLog();
    this._vlc = undefined;   // the path once looked for (null: none)
    this._server = null;
    this._port = 0;
    this._tokens = new Map(); // relay token → the gcmedia: URL it stands for
  }

  _registryDir() {
    return new Promise((resolve) => {
      try {
        this.execFile('reg', ['query', 'HKLM\\SOFTWARE\\VideoLAN\\VLC'], { windowsHide: true, timeout: 4000 }, (err, stdout) => resolve(err ? null : parseRegistry(stdout)));
      } catch { resolve(null); }
    });
  }

  /** The path of vlc.exe, or null (looked for once; `fresh`: again, e.g. after VLC was installed). */
  async vlcPath({ fresh = false } = {}) {
    if (this.platform !== 'win32') return null;
    if (this._vlc !== undefined && !fresh) return this._vlc;
    const dir = await this._registryDir();
    let found = null;
    for (const p of vlcCandidates(this.env, dir)) {
      try { if (this.fs.statSync(p).isFile()) { found = p; break; } } catch { /* not there */ }
    }
    this._vlc = found;
    return found;
  }

  async info() {
    return { ok: true, vlc: !!(await this.vlcPath({ fresh: this._vlc === null })), openPath: !!this.openPath };
  }

  // ── the loopback relay for VLC ──────────────────────────────

  async _listen() {
    if (this._server) return this._port;
    const server = http.createServer((req, res) => { this._serve(req, res).catch(() => { try { res.destroy(); } catch { /* gone */ } }); });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
    this._server = server;
    this._port = server.address().port;
    return this._port;
  }

  async _serve(req, res) {
    const end = (status) => { res.writeHead(status, { 'Cache-Control': 'no-store' }); res.end(); };
    // only this PC's loopback under its own name (no DNS rebinding: a page of the browser cannot ask)
    if (req.socket.remoteAddress !== '127.0.0.1' && req.socket.remoteAddress !== '::ffff:127.0.0.1') return end(403);
    if (req.headers.host !== `127.0.0.1:${this._port}`) return end(403);
    if (req.method !== 'GET' && req.method !== 'HEAD') return end(405);
    const segs = String(req.url || '').split('?')[0].split('/').filter(Boolean);
    if (segs.length !== 2 || !TOKEN_RE.test(segs[0])) return end(404);
    const target = this._tokens.get(segs[0]);
    if (!target) return end(404);
    const headers = {};
    if (typeof req.headers.range === 'string') headers.range = req.headers.range;
    const answer = await this.stream.handleProtocol({ url: target, method: req.method, headers });
    const out = {};
    for (const [k, v] of answer.headers) if (!/^access-control-|^vary$|^content-security-policy$/i.test(k)) out[k] = v;
    res.writeHead(answer.status, out);
    if (!answer.body || req.method === 'HEAD') { res.end(); return; }
    const body = Readable.fromWeb(answer.body);
    req.on('close', () => body.destroy());
    body.on('error', () => res.destroy());
    body.pipe(res);
  }

  /** A loopback address for the gcmedia: URL of a share's file (the relay knows at most MAX_TOKENS). */
  async relay(gcmediaUrl) {
    const p = this.stream.constructor.parseUrl(gcmediaUrl);
    if (!p) return null;
    const port = await this._listen();
    this._tokens.set(p.token, gcmediaUrl);
    while (this._tokens.size > MAX_TOKENS) this._tokens.delete(this._tokens.keys().next().value);
    const name = p.rest.length ? encodeURIComponent(p.rest[p.rest.length - 1]) : 'video';
    return `http://127.0.0.1:${port}/${p.token}/${name}`;
  }

  /** VLC with the file: → { ok } | { ok: false, code: 'no_vlc' | 'failed' }. */
  async openInVlc(gcmediaUrl, { title = null } = {}) {
    const vlc = await this.vlcPath({ fresh: true });
    if (!vlc) return { ok: false, code: 'no_vlc' };
    const url = await this.relay(gcmediaUrl);
    if (!url) return { ok: false, code: 'failed' };
    const args = [url];
    if (title) args.push(`:meta-title=${String(title).replace(/[\u0000-\u001f]/g, ' ').slice(0, 200)}`); // eslint-disable-line no-control-regex
    try {
      const child = this.spawn(vlc, args, { detached: true, stdio: 'ignore', windowsHide: false });
      if (child && typeof child.on === 'function') child.on('error', (err) => this.log.warn(`VLC could not be started: ${err.code || err.message}`));
      if (child && typeof child.unref === 'function') child.unref();
      return { ok: true, app: 'vlc' };
    } catch (err) {
      this.log.warn(`VLC could not be started: ${err.code || err.message}`);
      return { ok: false, code: 'failed' };
    }
  }

  /** Windows' app for the file type with an SMB file's UNC path → { ok } | { ok: false, code: 'unsupported' | 'failed' }. */
  async openWithDefault(uncPath) {
    if (!this.openPath || typeof uncPath !== 'string' || !uncPath.startsWith('\\\\')) return { ok: false, code: 'unsupported' };
    try {
      const err = await this.openPath(uncPath);
      return err ? { ok: false, code: 'failed', error: String(err).slice(0, 200) } : { ok: true, app: 'default' };
    } catch (e) {
      return { ok: false, code: 'failed', error: String(e && e.message).slice(0, 200) };
    }
  }

  /** The relay's tokens of a play / a source go with them; on quit the relay closes. */
  forget(gcmediaUrlPrefix = null) {
    if (!gcmediaUrlPrefix) { this._tokens.clear(); return; }
    for (const [t, u] of this._tokens) if (u.startsWith(gcmediaUrlPrefix)) this._tokens.delete(t);
  }

  close() {
    this._tokens.clear();
    if (this._server) { try { this._server.close(); } catch { /* closed */ } }
    this._server = null;
    this._port = 0;
  }
}

MediaExternal.vlcCandidates = vlcCandidates;
MediaExternal.parseRegistry = parseRegistry;

module.exports = MediaExternal;
