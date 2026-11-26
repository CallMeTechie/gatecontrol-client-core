'use strict';

/**
 * Medien (Stufe 4e): the pure parts of the NAS shares — paths below a share's root (no way out of it), the UNC path of
 * an SMB file, the access to a WebDAV share (Basic or Digest RFC 7616, as Android's WebDavAuth), a `207 Multi-Status`
 * read without a DTD or entities (a small XML reader of its own: the listing comes from the network), Range headers
 * and the types of the files. Unit-tested with the cases of Android's WebDavFsTest and SharePaths.
 */

const crypto = require('crypto');

const DAV = 'DAV:';
const MAX_LISTING_BYTES = 16 * 1024 * 1024;
const PROPFIND_BODY = '<?xml version="1.0" encoding="utf-8"?>\n'
  + '<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>';

const VIDEO = Object.freeze(['mkv', 'mp4', 'm4v', 'avi', 'mov', 'webm', 'ts', 'm2ts', 'mts', 'mpg', 'mpeg', 'wmv', 'ogv', '3gp', 'flv']);
const IMAGE = Object.freeze(['jpg', 'jpeg', 'png', 'webp']);
const AUDIO = Object.freeze(['mp3', 'm4a', 'aac', 'flac', 'opus', 'ogg', 'oga', 'wav']);
const SUBTITLE = Object.freeze(['srt', 'vtt', 'ass', 'ssa']);

// Matroska as video/webm (as the Drive viewer, drive-vault-view.js): Chromium's demuxer reads it under that type
const MIME = {
  mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/mp4', webm: 'video/webm', mkv: 'video/webm',
  ts: 'video/mp2t', m2ts: 'video/mp2t', mts: 'video/mp2t', avi: 'video/x-msvideo', mpg: 'video/mpeg', mpeg: 'video/mpeg',
  wmv: 'video/x-ms-wmv', ogv: 'video/ogg', '3gp': 'video/3gpp', flv: 'video/x-flv',
  mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', flac: 'audio/flac', opus: 'audio/ogg', ogg: 'audio/ogg', oga: 'audio/ogg', wav: 'audio/wav',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp',
  vtt: 'text/vtt', srt: 'text/plain', ass: 'text/plain', ssa: 'text/plain',
};

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
// characters a Windows path cannot have in a name — ':' also opens an alternate data stream
const WINDOWS_BAD_RE = /[<>:"|?*]/;

// ── paths ────────────────────────────────────────────────────

/** `path` cleaned ("a//b/" → "a/b"); null when it would leave the root or carries what a share cannot have. */
function clean(path) {
  const parts = String(path == null ? '' : path).replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.some((p) => p === '.' || p === '..' || CONTROL_RE.test(p))) return null;
  return parts.join('/');
}

const join = (dir, name) => (dir ? `${dir}/${name}` : name);
const parent = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const baseName = (p) => p.slice(p.lastIndexOf('/') + 1);

function extension(name) {
  const n = String(name || '');
  const i = n.lastIndexOf('.');
  return i > 0 ? n.slice(i + 1).toLowerCase() : '';
}

/** Not shown and not searched: hidden files, Synology's `@eaDir`, recycle bins, `Thumbs.db`. */
function hidden(name) {
  const n = String(name || '').toLowerCase();
  return !n || '.@#$~'.includes(n[0]) || n === 'thumbs.db' || n === 'desktop.ini';
}

function kindOf(name) {
  if (hidden(name)) return null;
  const e = extension(name);
  if (VIDEO.includes(e)) return /(?:^|[ ._\-[\]()])sample$/i.test(name.slice(0, name.lastIndexOf('.'))) ? null : 'video';
  if (AUDIO.includes(e)) return 'audio';
  if (IMAGE.includes(e)) return 'image';
  if (SUBTITLE.includes(e)) return 'subtitle';
  return null;
}

function mimeOf(name) {
  const e = extension(name);
  return Object.prototype.hasOwnProperty.call(MIME, e) ? MIME[e] : 'application/octet-stream';
}

/**
 * The UNC path of `rel` in the share `unc` (`\\nas\filme`) → `\\nas\filme\Neu\Kobaltnacht (2025).mkv`, or null when
 * `rel` would leave the share or names what Windows reads as something else (`a.mkv:stream`, devices).
 */
function uncPath(unc, rel) {
  const c = clean(rel);
  if (c === null || typeof unc !== 'string' || !/^\\\\[^\\]+\\[^\\]+/.test(unc)) return null;
  if (!c) return unc;
  const parts = c.split('/');
  if (parts.some((p) => WINDOWS_BAD_RE.test(p) || /[. ]$/.test(p) || /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(p))) return null;
  return `${unc.replace(/\\+$/, '')}\\${parts.join('\\')}`;
}

// ── Range ────────────────────────────────────────────────────

/**
 * A Range header (one range) for a file of `size` bytes → { start, end } (end inclusive), 'unsatisfiable', or null
 * (none / not one we take: the whole file).
 */
function byteRange(header, size) {
  const h = typeof header === 'string' ? header.trim() : '';
  const m = /^bytes=(\d{0,15})-(\d{0,15})$/.exec(h);
  if (!m || (m[1] === '' && m[2] === '')) return null;
  if (!Number.isSafeInteger(size) || size < 0) return null;
  let start;
  let end;
  if (m[1] === '') {
    const n = Number(m[2]);
    if (n === 0) return 'unsatisfiable';
    start = Math.max(0, size - n);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (start >= size || end < start) return 'unsatisfiable';
  return { start, end };
}

/** `bytes 500-999/1000` → { start, end, total } (total null for `*`), else null. */
function contentRange(v) {
  const m = /^bytes (\d{1,15})-(\d{1,15})\/(\d{1,15}|\*)$/.exec(typeof v === 'string' ? v.trim() : '');
  return m ? { start: Number(m[1]), end: Number(m[2]), total: m[3] === '*' ? null : Number(m[3]) } : null;
}

// ── WebDAV access: Basic or Digest ───────────────────────────

/**
 * The challenges of the `WWW-Authenticate` headers (several in one header are split at their scheme) →
 * [{ scheme: 'digest' | 'basic' | …, params: { realm, nonce, … } }] (scheme and parameter names in lower case).
 */
function parseChallenges(headers) {
  const list = Array.isArray(headers) ? headers : headers ? [headers] : [];
  const out = [];
  for (const raw of list) {
    const header = String(raw).slice(0, 4096);
    let i = 0;
    let cur = null;
    const n = header.length;
    while (i < n) {
      while (i < n && (header[i] === ' ' || header[i] === ',' || header[i] === '\t')) i++;
      const st = i;
      while (i < n && /[A-Za-z0-9_-]/.test(header[i])) i++;
      const token = header.slice(st, i);
      if (!token) { i++; continue; }
      let j = i;
      while (j < n && (header[j] === ' ' || header[j] === '\t')) j++;
      if (header[j] === '=') {
        // a parameter of the current challenge
        j++;
        while (j < n && (header[j] === ' ' || header[j] === '\t')) j++;
        let value = '';
        if (header[j] === '"') {
          j++;
          while (j < n && header[j] !== '"') {
            if (header[j] === '\\' && j + 1 < n) j++;
            value += header[j];
            j++;
          }
          j++;
        } else {
          const vs = j;
          while (j < n && header[j] !== ',' && header[j] !== ' ' && header[j] !== '\t') j++;
          value = header.slice(vs, j);
        }
        if (cur) cur.params[token.toLowerCase()] = value;
        i = j;
      } else {
        // a new challenge starts at a token followed by a space and a parameter (or the header's end)
        cur = { scheme: token.toLowerCase(), params: {} };
        out.push(cur);
        i = j;
      }
    }
  }
  return out;
}

function algorithmOf(c) {
  const a = String(c.params.algorithm || 'MD5').toUpperCase();
  return ['MD5', 'MD5-SESS', 'SHA-256', 'SHA-256-SESS'].includes(a) ? a.replace('-SESS', '-sess') : null;
}

/** Digest (SHA-256 before MD5) before Basic; null when none can be answered. Basic only when `basicAllowed`. */
function chooseChallenge(list, basicAllowed) {
  const digests = list.filter((c) => c.scheme === 'digest' && c.params.nonce && algorithmOf(c));
  return digests.find((c) => algorithmOf(c).startsWith('SHA-256'))
    || digests[0]
    || (basicAllowed ? list.find((c) => c.scheme === 'basic') || null : null);
}

function basicHeader(user, password) {
  return `Basic ${Buffer.from(`${user || ''}:${password || ''}`, 'utf8').toString('base64')}`;
}

/**
 * The `Authorization: Digest …` of `method` `uri` for challenge `c` (nc: the count of this nonce, 1 for the first).
 * Null when it cannot be answered (an algorithm or qop not known).
 */
function digestHeader({ method, uri, user, password, challenge: c, nc = 1, cnonce = crypto.randomBytes(12).toString('hex') }) {
  const algorithm = algorithmOf(c);
  if (!algorithm) return null;
  const hashName = algorithm.startsWith('SHA-256') ? 'sha256' : 'md5';
  const h = (x) => crypto.createHash(hashName).update(x, 'utf8').digest('hex');
  const realm = c.params.realm || '';
  const nonce = c.params.nonce;
  if (!nonce) return null;
  const qops = c.params.qop ? c.params.qop.split(',').map((q) => q.trim().toLowerCase()) : [];
  const qop = qops.includes('auth') ? 'auth' : null;
  if (qops.length && !qop) return null;
  const ncs = nc.toString(16).padStart(8, '0');
  let ha1 = h(`${user || ''}:${realm}:${password || ''}`);
  if (algorithm.endsWith('-sess')) ha1 = h(`${ha1}:${nonce}:${cnonce}`);
  const ha2 = h(`${method}:${uri}`);
  const response = qop ? h(`${ha1}:${nonce}:${ncs}:${cnonce}:${qop}:${ha2}`) : h(`${ha1}:${nonce}:${ha2}`);
  const q = (x) => `"${String(x).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const parts = [`username=${q(user || '')}`, `realm=${q(realm)}`, `nonce=${q(nonce)}`, `uri=${q(uri)}`, `algorithm=${algorithm}`, `response=${q(response)}`];
  if (qop) parts.push(`qop=${qop}`, `nc=${ncs}`, `cnonce=${q(cnonce)}`);
  if (c.params.opaque !== undefined) parts.push(`opaque=${q(c.params.opaque)}`);
  return `Digest ${parts.join(', ')}`;
}

// ── a small XML reader (no DTD, no entities but the five and character references) ─

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decodeText(t) {
  if (!t.includes('&')) return t;
  let out = '';
  let i = 0;
  while (i < t.length) {
    const a = t.indexOf('&', i);
    if (a < 0) { out += t.slice(i); break; }
    out += t.slice(i, a);
    const b = t.indexOf(';', a);
    if (b < 0 || b - a > 12) return null;
    const name = t.slice(a + 1, b);
    if (Object.prototype.hasOwnProperty.call(ENTITIES, name)) out += ENTITIES[name];
    else if (/^#\d{1,7}$/.test(name)) out += String.fromCodePoint(Math.min(Number(name.slice(1)), 0x10ffff));
    else if (/^#x[0-9a-fA-F]{1,6}$/.test(name)) out += String.fromCodePoint(Math.min(parseInt(name.slice(2), 16), 0x10ffff));
    else return null;
    i = b + 1;
  }
  return out;
}

const isNameChar = (ch) => /[A-Za-z0-9_.:-]/.test(ch);

/**
 * `text` → the root element { ns, local, children, text } (namespaces resolved), or null: not well formed, a DTD, an
 * entity of its own, too deep or too large.
 */
function parseXml(text, { maxElements = 200000, maxDepth = 64 } = {}) {
  if (typeof text !== 'string' || text.length > MAX_LISTING_BYTES) return null;
  const n = text.length;
  let i = 0;
  let root = null;
  const stack = [];
  let count = 0;
  while (i < n) {
    const lt = text.indexOf('<', i);
    const chunk = lt < 0 ? text.slice(i) : text.slice(i, lt);
    if (chunk) {
      if (stack.length) {
        const d = decodeText(chunk);
        if (d === null) return null;
        stack[stack.length - 1].text += d;
      } else if (chunk.trim()) return null;
    }
    if (lt < 0) break;
    if (text.startsWith('<?', lt)) {
      const e = text.indexOf('?>', lt + 2);
      if (e < 0) return null;
      i = e + 2;
      continue;
    }
    if (text.startsWith('<!--', lt)) {
      const e = text.indexOf('-->', lt + 4);
      if (e < 0) return null;
      i = e + 3;
      continue;
    }
    if (text.startsWith('<![CDATA[', lt)) {
      const e = text.indexOf(']]>', lt + 9);
      if (e < 0 || !stack.length) return null;
      stack[stack.length - 1].text += text.slice(lt + 9, e);
      i = e + 3;
      continue;
    }
    // a DTD, an entity declaration or anything else of '<!': never read
    if (text[lt + 1] === '!') return null;
    if (text[lt + 1] === '/') {
      let j = lt + 2;
      while (j < n && isNameChar(text[j])) j++;
      const qname = text.slice(lt + 2, j);
      while (j < n && /\s/.test(text[j])) j++;
      if (text[j] !== '>') return null;
      const el = stack.pop();
      if (!el || el.qname !== qname) return null;
      i = j + 1;
      continue;
    }
    // an element
    let j = lt + 1;
    while (j < n && isNameChar(text[j])) j++;
    const qname = text.slice(lt + 1, j);
    if (!qname) return null;
    const attrs = {};
    let selfClose = false;
    for (;;) {
      while (j < n && /\s/.test(text[j])) j++;
      if (j >= n) return null;
      if (text[j] === '>') { j++; break; }
      if (text[j] === '/' && text[j + 1] === '>') { selfClose = true; j += 2; break; }
      const as = j;
      while (j < n && isNameChar(text[j])) j++;
      const an = text.slice(as, j);
      if (!an) return null;
      while (j < n && /\s/.test(text[j])) j++;
      if (text[j] !== '=') return null;
      j++;
      while (j < n && /\s/.test(text[j])) j++;
      const quote = text[j];
      if (quote !== '"' && quote !== "'") return null;
      const ve = text.indexOf(quote, j + 1);
      if (ve < 0) return null;
      const v = decodeText(text.slice(j + 1, ve));
      if (v === null || v.includes('<')) return null;
      attrs[an] = v;
      j = ve + 1;
    }
    if (++count > maxElements || stack.length >= maxDepth) return null;
    const parentEl = stack.length ? stack[stack.length - 1] : null;
    const nsMap = { ...(parentEl ? parentEl.nsMap : {}) };
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'xmlns') nsMap[''] = v;
      else if (k.startsWith('xmlns:')) nsMap[k.slice(6)] = v;
    }
    const colon = qname.indexOf(':');
    const prefix = colon >= 0 ? qname.slice(0, colon) : '';
    const local = colon >= 0 ? qname.slice(colon + 1) : qname;
    const el = { qname, ns: Object.prototype.hasOwnProperty.call(nsMap, prefix) ? nsMap[prefix] : null, local, children: [], text: '', nsMap };
    if (parentEl) parentEl.children.push(el);
    else if (root) return null;
    else root = el;
    if (!selfClose) stack.push(el);
    i = j;
  }
  return root && !stack.length ? root : null;
}

const child = (e, local) => (e ? e.children.find((c) => c.local === local && c.ns === DAV) || null : null);
const childrenOf = (e, local) => (e ? e.children.filter((c) => c.local === local && c.ns === DAV) : []);

function segmentsOf(pathname) {
  return pathname.split('/').filter(Boolean).map((s) => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
}

/**
 * The entries of a `207 Multi-Status` for folder `dir` of the share at `baseUrl`, the folder itself left out →
 * [{ name, path, directory, size, modifiedAt }], or null when it is not one. Only what lies in that folder, one
 * level down; hidden names left out.
 */
function parseMultistatus(xml, baseUrl, dir) {
  const root = parseXml(typeof xml === 'string' ? xml : Buffer.isBuffer(xml) ? xml.toString('utf8') : '');
  if (!root || root.ns !== DAV || root.local !== 'multistatus') return null;
  let base;
  try { base = new URL(String(baseUrl).replace(/\/*$/, '/')); } catch { return null; }
  const own = [...segmentsOf(base.pathname), ...String(dir || '').split('/').filter(Boolean)];
  const out = [];
  for (const resp of childrenOf(root, 'response')) {
    const hrefEl = child(resp, 'href');
    const href = hrefEl ? hrefEl.text.trim() : '';
    if (!href) continue;
    let u;
    try { u = new URL(href, base); } catch { continue; }
    const segs = segmentsOf(u.pathname);
    if (segs.length !== own.length + 1 || own.some((s, k) => segs[k] !== s)) continue;
    const name = segs[segs.length - 1];
    if (hidden(name) || clean(name) !== name) continue;
    let prop = null;
    for (const st of childrenOf(resp, 'propstat')) {
      const status = child(st, 'status');
      const t = status ? status.text : '';
      if (!t || t.includes(' 200')) { prop = child(st, 'prop'); break; }
    }
    if (!prop) continue;
    const rt = child(prop, 'resourcetype');
    const directory = !!child(rt, 'collection');
    const len = child(prop, 'getcontentlength');
    const size = len && /^\d{1,15}$/.test(len.text.trim()) ? Number(len.text.trim()) : 0;
    const mod = child(prop, 'getlastmodified');
    const t = mod ? Date.parse(mod.text.trim()) : NaN;
    out.push({ name, path: join(String(dir || ''), name), directory, size, modifiedAt: Number.isFinite(t) ? t : null });
  }
  return out;
}

/** The URL of `path` below the share's root (a folder with its trailing slash). */
function davUrl(baseUrl, path, directory) {
  const base = new URL(String(baseUrl).replace(/\/*$/, '/'));
  const parts = String(path || '').split('/').filter(Boolean).map((p) => encodeURIComponent(p));
  base.pathname = base.pathname.replace(/\/+$/, '') + (parts.length ? `/${parts.join('/')}` : '') + (directory ? '/' : '');
  return base.toString();
}

module.exports = {
  DAV,
  MAX_LISTING_BYTES,
  PROPFIND_BODY,
  VIDEO,
  IMAGE,
  AUDIO,
  SUBTITLE,
  clean,
  join,
  parent,
  baseName,
  extension,
  hidden,
  kindOf,
  mimeOf,
  uncPath,
  byteRange,
  contentRange,
  parseChallenges,
  chooseChallenge,
  basicHeader,
  digestHeader,
  parseXml,
  parseMultistatus,
  davUrl,
};
