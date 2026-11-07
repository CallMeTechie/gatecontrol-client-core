'use strict';

/**
 * The viewer of vault files on Windows (Drive plugin 1.22) — the counterpart of the portal's ui/vaultview.js.
 *
 * Before, a vault file was decrypted into %TEMP%\gatecontrol-drive\vault\… and opened with the program Windows picks
 * (drive.js _openVaultFile). The viewer instead shows it in the app's own window, and the plaintext exists in memory
 * only:
 *   * open() loads the file's CIPHERTEXT (as the server keeps it) into %TEMP%\gatecontrol-drive\vault-view\<random>.enc
 *     and opens it for random access (drive-vault.openContent) — nothing in plain text is written;
 *   * the page reads it through the privileged scheme gcvault://v/<token> (Electron protocol.handle → handleProtocol):
 *     every request decrypts just the chunks of its Range in memory (1 MiB each) and streams them — <img> and <video>
 *     directly, a PDF and a text through fetch() into the renderer's memory (pdf.js draws it on <canvas>). Chromium
 *     keeps nothing of a custom scheme in its HTTP cache (and the answers say no-store);
 *   * the token is 32 random hex characters, known only to the page that asked; close(token), closeAll() (the vaults
 *     lock, the service stops) forget it, overwrite the file key and delete the ciphertext — a request after that
 *     answers 404, a running stream ends with an error.
 * Office files and anything without a viewer: no download at all (`note`) — the explicit "Mit anderem Programm öffnen"
 * of drive.js stays the way out (it asks first in the page).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const V = require('../utils/drive-vault');

const SCHEME = 'gcvault';
// <img>, <video> and fetch() of the page; a secure, standard scheme with streamed answers (Range for videos). fetch()
// from the app's page (file://, an opaque origin) is cross-origin: CORS on, and only that origin is let read
// (Access-Control-Allow-Origin of the request's Origin when it is the page's — 'null' / file://; anything else none).
const SCHEME_PRIVILEGES = Object.freeze({ standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true });

/** The app page's Origin (file:// is opaque: 'null'), else null — no other origin may read a vault file. */
function pageOrigin(o) {
  const v = o == null ? '' : String(o);
  return v === 'null' || v === 'file://' ? v : null;
}

const MB = 1048576;
/** What the page holds in memory at most (by the size of the ciphertext); a video streams, chunk by chunk. */
const LIMITS = Object.freeze({ image: 64 * MB, pdf: 200 * MB, text: 8 * MB, markdown: 8 * MB, video: Number.MAX_SAFE_INTEGER, audio: Number.MAX_SAFE_INTEGER });

const IMAGE = { jpg: 'image/jpeg', jpeg: 'image/jpeg', jfif: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp', ico: 'image/x-icon' };
const VIDEO = { mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/mp4', webm: 'video/webm', mkv: 'video/webm', ogv: 'video/ogg' };
const AUDIO = { mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', ogg: 'audio/ogg', oga: 'audio/ogg', opus: 'audio/ogg', wav: 'audio/wav', flac: 'audio/flac' };
const TEXT = new Set(['txt', 'text', 'log', 'csv', 'tsv', 'json', 'xml', 'yml', 'yaml', 'ini', 'conf', 'cfg', 'toml', 'env', 'sh', 'ps1', 'bat', 'js', 'ts', 'py', 'java', 'kt', 'c', 'h', 'cpp', 'cs', 'go', 'rs', 'sql', 'html', 'htm', 'css', 'vcf', 'ics']);
const MARKDOWN = new Set(['md', 'markdown', 'mdown', 'mkd']);
const OFFICE = new Set(['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'pages', 'numbers', 'key']);
const HEIC = new Set(['heic', 'heif']);

function extOf(name) {
  const m = /\.([a-z0-9]{1,8})$/i.exec(String(name || ''));
  return m ? m[1].toLowerCase() : '';
}

/** image | pdf | text | markdown | video | audio | office | heic | other */
function kindOf(name) {
  const e = extOf(name);
  if (IMAGE[e]) return 'image';
  if (e === 'pdf') return 'pdf';
  if (MARKDOWN.has(e)) return 'markdown';
  if (TEXT.has(e)) return 'text';
  if (VIDEO[e]) return 'video';
  if (AUDIO[e]) return 'audio';
  if (OFFICE.has(e)) return 'office';
  if (HEIC.has(e)) return 'heic';
  return 'other';
}

/** The type the page gets (never sniffed): text as plain text (no HTML of the file ever renders). */
function mimeOf(name) {
  const e = extOf(name);
  if (IMAGE[e]) return IMAGE[e];
  if (VIDEO[e]) return VIDEO[e];
  if (AUDIO[e]) return AUDIO[e];
  if (e === 'pdf') return 'application/pdf';
  return 'text/plain; charset=utf-8';
}

const TOKEN_RE = /^[0-9a-f]{32}$/;

/** gcvault://v/<token> → the token, or null. */
function tokenOf(url) {
  const m = /^gcvault:\/\/v\/([0-9a-f]{32})\/?(?:[?#].*)?$/.exec(String(url || ''));
  return m ? m[1] : null;
}

/** "bytes=a-b" | "bytes=a-" | "bytes=-n" of `size` → { start, end } (end inclusive), null: the whole, false: unsatisfiable. */
function rangeOf(header, size) {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(header).trim());
  if (!m || (m[1] === '' && m[2] === '')) return null;
  let start;
  let end;
  if (m[1] === '') {
    const n = Number(m[2]);
    if (!n) return false;
    start = Math.max(0, size - n);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) return false;
  return { start, end };
}

const headerOf = (req, name) => {
  const h = req && req.headers;
  if (!h) return null;
  if (typeof h.get === 'function') return h.get(name);
  return h[name] || h[name.toLowerCase()] || null;
};

const answer = (status) => new Response(null, { status, headers: { 'Cache-Control': 'no-store' } });

class DriveVaultViews {
  /**
   * @param {object} o
   * @param {Function} o.dir - () → the folder for ciphertexts (%TEMP%\gatecontrol-drive\vault-view)
   * @param {object} [o.log]
   */
  constructor({ dir, log = null } = {}) {
    this.dir = dir;
    this.log = log || { debug() {}, info() {}, warn() {} };
    this._views = new Map(); // token → { file, content, mime, name, kind, size, streams: Set of { ctrl, done } }
  }

  /**
   * Opens a vault file for the viewer → { kind, name, mime, size, token, url } | { kind, name, note } (nothing loaded:
   * 'office', 'heic', 'other', 'too_large'). o: { node, name, vaultId, keys (keyVersion → TK), download(file) (writes
   * the ciphertext), signal }.
   */
  async open({ node, name, vaultId, keys, download }) {
    const kind = kindOf(name);
    if (['office', 'heic', 'other'].includes(kind)) return { kind, name, note: kind };
    const limit = LIMITS[kind] || 0;
    if (Number.isSafeInteger(node && node.size) && node.size > limit) return { kind, name, note: 'too_large', limitMb: Math.round(limit / MB) };
    const dir = this.dir();
    await fs.promises.mkdir(dir, { recursive: true });
    const file = path.join(dir, `${crypto.randomBytes(8).toString('hex')}.enc`);
    let content = null;
    try {
      await download(file);
      const fh = await fs.promises.open(file, 'r');
      try {
        const total = (await fh.stat()).size;
        const head = Buffer.alloc(V.HEADER);
        const { bytesRead } = await fh.read(head, 0, V.HEADER, 0);
        if (bytesRead !== V.HEADER) throw new V.DriveVaultError('invalid', 'too short');
        content = V.openContent(keys, vaultId, head, total);
      } finally {
        await fh.close().catch(() => {});
      }
    } catch (err) {
      await fs.promises.rm(file, { force: true }).catch(() => {});
      throw err;
    }
    const token = crypto.randomBytes(16).toString('hex');
    this._views.set(token, { file, content, kind, name, mime: mimeOf(name), size: content.plainSize, streams: new Set() });
    return { kind, name, mime: mimeOf(name), size: content.plainSize, token, url: `${SCHEME}://v/${token}` };
  }

  /** Whether `token` is open. */
  has(token) { return this._views.has(token); }

  get size() { return this._views.size; }

  /** The viewer closed: the token, the file key and the ciphertext go; a running answer ends. */
  async close(token) {
    const v = TOKEN_RE.test(String(token || '')) ? this._views.get(token) : null;
    if (!v) return false;
    this._views.delete(token);
    v.content.close();
    const running = [...v.streams];
    v.streams.clear();
    await Promise.all(running.map(async (s) => {
      await s.done();
      try { s.ctrl.error(new Error('closed')); } catch { /* ended already */ }
    }));
    await fs.promises.rm(v.file, { force: true }).catch(() => {});
    return true;
  }

  /** Everything goes (the vaults locked, the service stops). */
  async closeAll() {
    await Promise.all([...this._views.keys()].map((t) => this.close(t)));
  }

  /**
   * Electron protocol.handle('gcvault', (req) => …) → a Response: the plaintext of the Range asked for, decrypted chunk
   * by chunk from the ciphertext. GET / HEAD only; an unknown or closed token 404.
   */
  async handleProtocol(request) {
    const method = request && request.method ? String(request.method).toUpperCase() : 'GET';
    if (method !== 'GET' && method !== 'HEAD') return answer(405);
    const token = tokenOf(request && request.url);
    const v = token ? this._views.get(token) : null;
    if (!v) return answer(404);
    const size = v.size;
    const r = rangeOf(headerOf(request, 'range'), size);
    if (r === false) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}`, 'Cache-Control': 'no-store' } });
    const start = r ? r.start : 0;
    const end = r ? r.end : size - 1;
    const headers = {
      'Content-Type': v.mime, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Accept-Ranges': 'bytes',
      'Content-Security-Policy': "default-src 'none'; sandbox", 'Content-Length': String(Math.max(0, end - start + 1)),
      ...(r ? { 'Content-Range': `bytes ${start}-${end}/${size}` } : {}),
    };
    const origin = pageOrigin(headerOf(request, 'origin'));
    if (origin) { headers['Access-Control-Allow-Origin'] = origin; headers.Vary = 'Origin'; }
    const status = r ? 206 : 200;
    if (method === 'HEAD' || size === 0) return new Response(null, { status, headers });
    const content = v.content;
    let fh = null;
    let pos = start;
    const entry = { ctrl: null, done: null };
    const stream = new ReadableStream({
      start(c) { entry.ctrl = c; v.streams.add(entry); },
      async pull(c) {
        try {
          if (pos > end) { await done(); c.close(); return; }
          if (content.closed) throw new Error('closed');
          if (!fh) fh = await fs.promises.open(v.file, 'r');
          const i = content.chunkOf(pos);
          const { offset, length } = content.range(i);
          const ct = Buffer.allocUnsafe(length);
          const { bytesRead } = await fh.read(ct, 0, length, offset);
          if (bytesRead !== length) throw new Error('short read');
          const pt = content.decrypt(i, ct);
          const from = pos - i * content.chunkSize;
          const to = Math.min(pt.length, end - i * content.chunkSize + 1);
          // a copy of the part asked for; the chunk itself is overwritten at once
          c.enqueue(new Uint8Array(pt.subarray(from, to)));
          V.wipe(pt);
          pos += to - from;
          if (pos > end) { await done(); c.close(); }
        } catch (err) {
          await done();
          c.error(err);
        }
      },
      async cancel() { await done(); },
    });
    async function done() {
      v.streams.delete(entry);
      if (fh) { const f = fh; fh = null; await f.close().catch(() => {}); }
    }
    entry.done = done;
    return new Response(stream, { status, headers });
  }
}

DriveVaultViews.SCHEME = SCHEME;
DriveVaultViews.SCHEME_PRIVILEGES = SCHEME_PRIVILEGES;
DriveVaultViews.LIMITS = LIMITS;
DriveVaultViews.kindOf = kindOf;
DriveVaultViews.mimeOf = mimeOf;
DriveVaultViews.rangeOf = rangeOf;
DriveVaultViews.tokenOf = tokenOf;
DriveVaultViews.pageOrigin = pageOrigin;

module.exports = DriveVaultViews;
