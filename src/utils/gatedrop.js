'use strict';

/**
 * Pure helpers of the GateDrop client (plugin `gatecontrol-gatedrop`,
 * contract "GateDrop – Schnittstelle" B/C/G): constants, argument checks,
 * tolerant parsing of the plugin's answers and push data, LAN addresses,
 * safe file names.
 *
 * Electron-free and side-effect free (unit-tested directly). Every parser
 * here accepts more than it needs and drops what it does not understand, so
 * later additions on the plugin side do not break older Windows apps.
 */

const path = require('path');

const PLUGIN_ID = 'gatecontrol-gatedrop';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_PATH = `/api/v1/client/plugins/${PLUGIN_ID}/media`;
const PLUGINS_PATH = '/api/v1/client/plugins';

const PORT = 47731;                          // LAN listener (protocol C), firewall rule of the installer
const BLOCK_SIZE = 1024 * 1024;              // 1 MiB plaintext per AES-GCM block
const TAG_SIZE = 16;
const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB per file
const MAX_ITEMS = 20;
const MAX_TEXT = 20000;
const MAX_NOTE = 500;
const MAX_LINK = 2048;
const RESUMABLE_FROM = 50 * 1024 * 1024;     // uploads above 50 MB use the resumable PUT (A1)
const TICKET_TTL_MS = 10 * 60 * 1000;        // ticket: single use, 10 min
const CONNECT_TIMEOUT_MS = 2000;             // direct candidate: connect within 2 s, else server path
const LINK_EXPIRES = Object.freeze(['1h', '1d', '7d', 'once']);
const INBOX_KINDS = Object.freeze(['received', 'sent', 'links']);
// waiting (GateDrop 1.1.0): the target device was offline, the send waits in its `pending` list.
const DELIVERY_STATUS = Object.freeze(['pending', 'waiting', 'direct', 'delivered', 'opened', 'failed', 'expired']);
const PLATFORMS = Object.freeze(['android', 'windows', 'ios', 'web']);
// Who may send to this device (GateDrop 1.2.0, GET/PUT device): only its owner, or every account.
const RECEIVE_FROM = Object.freeze(['self', 'everyone']);

const TRANSFER_ID_RE = /^[A-Za-z0-9_-]{4,100}$/;
const TICKET_RE = /^[A-Za-z0-9_\-+/=.~]{8,512}$/;
const MEDIA_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const LINK_TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;
const CANDIDATE_RE = /^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/;
const AVATAR_PATH_RE = /^\/avatars\/[A-Za-z0-9_-]{16,128}\.(?:png|jpe?g|webp)$/;

const str = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').slice(0, max) : '');
const bool = (v) => v === true;
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);

/** Non-negative safe integer (number or numeric string), else null. */
function nonNegInt(v) {
  const n = typeof v === 'string' && /^\d{1,16}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

/** Ids of the plugin: numbers or short strings → string, else null. */
function idOf(v) {
  if (Number.isSafeInteger(v) && v >= 0) return String(v);
  return typeof v === 'string' && ID_RE.test(v) ? v : null;
}

const isTransferId = (v) => typeof v === 'string' && TRANSFER_ID_RE.test(v);
const isTicket = (v) => typeof v === 'string' && TICKET_RE.test(v);
const isMediaId = (v) => typeof v === 'string' && MEDIA_ID_RE.test(v);
const isLinkToken = (v) => typeof v === 'string' && LINK_TOKEN_RE.test(v);

/** Time (ms number, numeric string or ISO string) → ms, else null. */
function timeOf(v) {
  if (Number.isFinite(v) && v > 0) return Math.round(v < 1e12 ? v * 1000 : v);
  if (typeof v === 'string' && v) {
    if (/^\d{9,15}$/.test(v)) return timeOf(Number(v));
    const ms = Date.parse(v.includes('T') || v.endsWith('Z') ? v : v.replace(' ', 'T') + 'Z');
    return Number.isNaN(ms) ? null : ms;
  }
  return null;
}

/** Transfer key: base64 / base64url of exactly 32 bytes → Buffer, else null. */
function decodeKey(v) {
  if (typeof v !== 'string' || !/^[A-Za-z0-9+/_-]{42,44}={0,2}$/.test(v)) return null;
  const buf = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return buf.length === 32 ? buf : null;
}

// ── Names ──────────────────────────────────────────────────

/** X-GD-Name: base64url of the UTF-8 name (no padding). */
function encodeName(name) {
  return Buffer.from(String(name), 'utf8').toString('base64url');
}

/** X-GD-Name → string, or null when it is not base64url / not valid UTF-8. */
function decodeName(v) {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]{1,1400}={0,2}$/.test(v)) return null;
  const buf = Buffer.from(v.replace(/=+$/, ''), 'base64url');
  const s = buf.toString('utf8');
  if (!s || Buffer.from(s, 'utf8').compare(buf) !== 0) return null; // replacement chars → not UTF-8
  return s;
}

/** A name that tries to leave the target folder (separators, `..`, NUL, drive). */
function isTraversalName(name) {
  if (typeof name !== 'string') return true;
  if (/[\\/\u0000]/.test(name)) return true;
  if (/^[A-Za-z]:/.test(name)) return true;
  const t = name.trim();
  return t === '.' || t === '..' || t === '';
}

const RESERVED_RE = /^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?$/i;

/**
 * File name that is safe on Windows: no path parts, no characters Windows
 * refuses, no trailing dots / spaces, no device names, ≤ 180 characters
 * (the extension kept). null when nothing usable remains.
 */
function safeFileName(name, fallback = null) {
  if (typeof name !== 'string') return fallback;
  let s = name.normalize('NFC').replace(/[\u0000-\u001F\u007F]/g, '');
  s = s.split(/[\\/]/).pop();                 // only the last part of a path
  s = s.replace(/[<>:"|?*]/g, '_').replace(/^[\s.]+/, '').replace(/[\s.]+$/, '');
  if (!s || s === '.' || s === '..') return fallback;
  if (RESERVED_RE.test(s)) s = `_${s}`;
  if (s.length > 180) {
    const ext = path.extname(s).slice(0, 20);
    s = s.slice(0, 180 - ext.length).replace(/[\s.]+$/, '') + ext;
  }
  return s || fallback;
}

/** 'Bericht.pdf', 2 → 'Bericht (2).pdf' */
function numberedName(name, n) {
  if (n <= 1) return name;
  const ext = path.extname(name);
  const base = ext && ext !== name ? name.slice(0, -ext.length) : name;
  return `${base} (${n})${ext && ext !== name ? ext : ''}`;
}

const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.heic': 'image/heic', '.bmp': 'image/bmp', '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.mkv': 'video/x-matroska', '.webm': 'video/webm', '.avi': 'video/x-msvideo',
  '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.opus': 'audio/ogg', '.wav': 'audio/wav', '.flac': 'audio/flac',
  '.pdf': 'application/pdf', '.zip': 'application/zip', '.7z': 'application/x-7z-compressed', '.rar': 'application/vnd.rar', '.gz': 'application/gzip',
  '.txt': 'text/plain', '.csv': 'text/csv', '.json': 'application/json', '.xml': 'application/xml',
  '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.odt': 'application/vnd.oasis.opendocument.text', '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
  '.apk': 'application/vnd.android.package-archive', '.exe': 'application/octet-stream', '.msi': 'application/octet-stream',
};

/** MIME type from the file name (upload Content-Type), octet-stream otherwise. */
function guessMime(name) {
  return MIME[path.extname(String(name || '')).toLowerCase()] || 'application/octet-stream';
}

/** Size of the encrypted body of `plain` bytes (16-byte tag per started 1 MiB block). */
function encryptedSize(plain) {
  if (!Number.isSafeInteger(plain) || plain < 0) return null;
  return plain + Math.ceil(plain / BLOCK_SIZE) * TAG_SIZE;
}

// ── LAN ────────────────────────────────────────────────────

function ipv4ToInt(ip) {
  const m = typeof ip === 'string' ? /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip) : null;
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** RFC 1918 address (10/8, 172.16/12, 192.168/16). */
function isPrivateIPv4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  const a = n >>> 24;
  const b = (n >>> 16) & 0xff;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** '::ffff:192.168.1.5' → '192.168.1.5' */
function plainIPv4(ip) {
  return typeof ip === 'string' ? ip.replace(/^::ffff:/i, '') : '';
}

function prefixOf(netmask) {
  const n = ipv4ToInt(netmask);
  if (n === null) return null;
  let bits = 0;
  for (let i = 31; i >= 0; i--) { if ((n >>> i) & 1) bits++; else break; }
  return bits;
}

/** Two addresses in the same IPv4 network of `prefix` bits. */
function sameSubnet(a, b, prefix) {
  const x = ipv4ToInt(a);
  const y = ipv4ToInt(b);
  if (x === null || y === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return ((x & mask) >>> 0) === ((y & mask) >>> 0);
}

// Tunnel adapters are no LAN: the VPN subnet is private as well.
const DEFAULT_EXCLUDE_RE = /gatecontrol|wireguard|wintun|^wg|vpn|tap-|tun\d|vethernet|virtualbox|vmware|hyper-v|docker|loopback/i;
// Hyper-V with an external virtual switch moves the PC's LAN address from the
// WLAN/Ethernet adapter to "vEthernet (<switch name>)". Such an adapter only
// counts when no other LAN adapter has an address; the internal NAT switches
// (Default Switch, WSL, nat) never do.
const HYPERV_EXTERNAL_RE = /^vethernet\b/i;
const HYPERV_INTERNAL_RE = /default switch|wsl|\bnat\b|internal/i;

function ipv4Entries(list) {
  return arr(list).filter((a) => a && !a.internal && (a.family === 'IPv4' || a.family === 4) && typeof a.address === 'string');
}

function prefixFor(a) {
  let prefix = null;
  if (typeof a.cidr === 'string' && /\/\d{1,2}$/.test(a.cidr)) prefix = Number(a.cidr.split('/')[1]);
  if (prefix === null) prefix = prefixOf(a.netmask);
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 32) prefix = 24;
  return prefix;
}

/**
 * The LAN adapters of os.networkInterfaces() → { addresses: [{ ip, prefix, name }]
 * (sorted, no duplicates), skipped: [{ name, ip, why }] } — `why` says why an
 * adapter with an IPv4 address does not count: 'virtual' (tunnel, VM switch,
 * VPN), 'link_local' (169.254.x.x: no address from the router), 'public'.
 * The skipped list is the diagnosis when no address is left.
 */
function lanScan(ifaces, { exclude = DEFAULT_EXCLUDE_RE } = {}) {
  const out = [];
  const skipped = [];
  const seen = new Set();
  const hyperv = [];
  const take = (name, a) => {
    if (seen.has(a.address)) return;
    seen.add(a.address);
    out.push({ ip: a.address, prefix: prefixFor(a), name });
  };
  for (const [name, list] of Object.entries(ifaces || {})) {
    const entries = ipv4Entries(list);
    if (exclude && exclude.test(name)) {
      for (const a of entries) {
        if (isPrivateIPv4(a.address) && HYPERV_EXTERNAL_RE.test(name) && !HYPERV_INTERNAL_RE.test(name)) hyperv.push({ name, a });
        else skipped.push({ name, ip: a.address, why: 'virtual' });
      }
      continue;
    }
    for (const a of entries) {
      if (isPrivateIPv4(a.address)) take(name, a);
      else skipped.push({ name, ip: a.address, why: /^169\.254\./.test(a.address) ? 'link_local' : 'public' });
    }
  }
  const hasLan = out.length > 0;
  for (const { name, a } of hyperv) {
    if (hasLan) skipped.push({ name, ip: a.address, why: 'virtual' });
    else take(name, a);
  }
  out.sort((x, y) => (ipv4ToInt(x.ip) - ipv4ToInt(y.ip)));
  return { addresses: out, skipped };
}

/**
 * Private IPv4 addresses of the LAN adapters (os.networkInterfaces()) →
 * [{ ip, prefix, name }] (sorted, no duplicates).
 */
function lanAddresses(ifaces, opts) {
  return lanScan(ifaces, opts).addresses;
}

// Why direct receiving on this PC is off (or at risk) — the GateDrop page
// shows it next to "Direktempfang im WLAN …", the log names it.
const DIRECT_REASONS = Object.freeze([
  'unavailable', 'starting', 'no_lan', 'bind_failed',
  'firewall_shields_up', 'firewall_blocked', 'firewall_rule', 'firewall_unknown',
]);

/**
 * State of direct receiving → { state: 'on' | 'warn' | 'off', reason, detail }.
 * @param {object} o
 * @param {boolean} o.available - the plugin is there
 * @param {object} o.listener - GateDropListener.status() ({ listening, addresses, skipped, bindErrors })
 * @param {object|null} [o.firewall] - GateDropFirewall result ({ checked, issues: [{ code, detail }] }) or null
 */
function directState({ available, listener, firewall = null }) {
  const l = obj(listener) || {};
  if (!available) return { state: 'off', reason: 'unavailable', detail: null };
  if (!l.listening) {
    const errs = arr(l.bindErrors);
    if (errs.length) return { state: 'off', reason: 'bind_failed', detail: errs.map((e) => `${e.ip}: ${e.code}`).join(', ') };
    if (l.started && !arr(l.addresses).length) {
      const names = [...new Set(arr(l.skipped).map((s) => `${s.name} (${s.ip})`))];
      return { state: 'off', reason: 'no_lan', detail: names.length ? names.join(', ') : null };
    }
    return { state: 'off', reason: 'starting', detail: null };
  }
  const issues = arr(firewall && firewall.issues);
  for (const code of ['firewall_shields_up', 'firewall_blocked', 'firewall_rule', 'firewall_unknown']) {
    const hit = issues.find((i) => i && i.code === code);
    if (hit) return { state: code === 'firewall_unknown' ? 'on' : 'warn', reason: code, detail: hit.detail || null };
  }
  return { state: 'on', reason: null, detail: null };
}

/** 'ip:port' of a direct candidate (private IPv4 only) → { host, port }, else null. */
function parseCandidate(v) {
  const m = typeof v === 'string' ? /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(v.trim()) : null;
  if (!m || !isPrivateIPv4(m[1])) return null;
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return null;
  return { host: m[1], port };
}

// ── Answers of the plugin ──────────────────────────────────

/** One device of GET targets (own or another person's) → { id, name, platform, online, direct, mode, self } or null. */
function deviceOf(d) {
  const o = obj(d);
  const id = o && idOf(o.id);
  if (!id) return null;
  return {
    id,
    name: str(o.name, 80) || id,
    platform: PLATFORMS.includes(o.platform) ? o.platform : 'unknown',
    online: bool(o.online),
    direct: bool(o.direct),
    mode: o.mode === 'push' || o.mode === 'pull' ? o.mode : null,
    self: bool(o.self),
  };
}

/** GET / PUT device (GateDrop 1.2.0) → { id, receiveFrom } or null when the answer has no known mode. */
function normalizeDeviceAccess(raw) {
  const r = obj(raw) || {};
  const d = obj(r.device) || r;
  if (!RECEIVE_FROM.includes(d.receiveFrom)) return null;
  return { id: idOf(d.id), receiveFrom: d.receiveFrom };
}

/**
 * GET targets → { me, people, devices, peopleDevices, nas, links, messenger, limits, storage }
 * (unknown entries dropped; peopleDevices: [{ …device, owner: { id, name } }], [] before GateDrop 1.2.0).
 */
function normalizeTargets(raw) {
  const r = obj(raw) || {};
  const me = obj(r.me) || {};
  const people = [];
  for (const p of arr(r.people)) {
    const o = obj(p);
    const id = o && (o.kind === 'family' || o.id === 'family' ? 'family' : idOf(o.id));
    if (!id) continue;
    people.push({
      id,
      name: str(o.name, 80) || (id === 'family' ? 'Familie' : id),
      avatar: typeof o.avatar === 'string' && AVATAR_PATH_RE.test(o.avatar) ? o.avatar : null,
      initials: str(o.initials, 4) || null,
      colorHex: typeof o.colorHex === 'string' && /^#[0-9a-fA-F]{6}$/.test(o.colorHex) ? o.colorHex : null,
      kind: id === 'family' || o.kind === 'family' ? 'family' : 'user',
    });
  }
  const devices = arr(r.devices).map((d) => deviceOf(d)).filter(Boolean);
  // Other people's devices open for everyone (GateDrop 1.2.0): sent to like own ones (`to.devices`).
  const peopleDevices = [];
  for (const d of arr(r.peopleDevices)) {
    const dev = deviceOf(d);
    const owner = dev && obj(d.owner);
    const ownerId = owner && idOf(owner.id);
    if (!ownerId || devices.some((x) => x.id === dev.id) || peopleDevices.some((x) => x.id === dev.id)) continue;
    delete dev.self;
    peopleDevices.push({ ...dev, owner: { id: ownerId, name: str(owner.name, 80) || null } });
  }
  const nas = [];
  for (const n of arr(r.nas)) {
    const o = obj(n);
    const id = o && idOf(o.id);
    if (!id) continue;
    nas.push({ id, label: str(o.label, 80) || id, path: str(o.path, 400) });
  }
  const links = obj(r.links) || {};
  const l = obj(r.limits) || {};
  const expires = arr(l.linkExpires).filter((x) => LINK_EXPIRES.includes(x));
  const posOr = (v, def, max) => { const n = nonNegInt(v); return n !== null && n > 0 ? Math.min(n, max) : def; };
  const storage = obj(r.storage);
  return {
    me: {
      id: idOf(me.id), name: str(me.name, 80) || null, canLink: bool(me.canLink), canNas: bool(me.canNas), deviceId: idOf(me.deviceId),
      receiveFrom: RECEIVE_FROM.includes(me.receiveFrom) ? me.receiveFrom : null,
    },
    people,
    devices,
    peopleDevices,
    nas,
    links: { enabled: bool(links.enabled) },
    messenger: bool(r.messenger),
    limits: {
      maxItems: posOr(l.maxItems, MAX_ITEMS, MAX_ITEMS),
      maxBytes: posOr(l.maxBytes, MAX_FILE_BYTES, MAX_FILE_BYTES),
      types: arr(l.types).filter((x) => typeof x === 'string' && x.length <= 80).slice(0, 40),
      textMax: posOr(l.textMax, MAX_TEXT, MAX_TEXT),
      noteMax: posOr(l.noteMax, MAX_NOTE, MAX_NOTE),
      retentionDays: posOr(l.retentionDays, 7, 365),
      linkExpires: expires.length ? expires : LINK_EXPIRES.slice(),
      directPort: posOr(l.directPort, PORT, 65535),
      presenceEveryS: posOr(l.presenceEveryS, 300, 86400),
      ticketS: posOr(l.ticketS, TICKET_TTL_MS / 1000, 86400),
    },
    storage: storage && nonNegInt(storage.bytes) !== null ? { bytes: nonNegInt(storage.bytes), quota: nonNegInt(storage.quota) } : null,
  };
}

/** One `direct` entry of POST sends (and the silent push) → clean object or null. */
function normalizeDirect(d) {
  const o = obj(d);
  if (!o) return null;
  const transferId = isTransferId(o.transferId) ? o.transferId : isTransferId(o.transfer) ? o.transfer : (obj(o.transfer) && isTransferId(o.transfer.id) ? o.transfer.id : null);
  const key = decodeKey(o.key);
  if (!transferId || !key || !isTicket(o.ticket)) return null;
  const mode = o.mode === 'pull' ? 'pull' : o.mode === 'push' ? 'push' : null;
  if (!mode) return null;
  // Shape only; whether an address may be used (private IPv4) decides the connecting side.
  const candidates = arr(o.candidates).map((c) => (typeof c === 'string' && CANDIDATE_RE.test(c.trim()) ? c.trim() : null)).filter(Boolean).slice(0, 8);
  return { deviceId: idOf(o.deviceId), transferId, mode, candidates, key, ticket: o.ticket, expiresAt: timeOf(o.expiresAt) };
}

/** items of a send / transfer → [{ index, mediaId, name, mime, bytes, local, available }] */
function normalizeItems(list) {
  const out = [];
  arr(list).slice(0, MAX_ITEMS).forEach((it, i) => {
    const o = obj(it);
    if (!o) return;
    const idx = nonNegInt(o.index);
    const mediaId = isMediaId(o.mediaId) ? o.mediaId : null;
    out.push({
      index: idx !== null && idx < MAX_ITEMS ? idx : i,
      mediaId,
      name: safeFileName(str(o.name, 400), `datei-${i + 1}`),
      mime: str(o.mime, 120) || guessMime(o.name),
      bytes: nonNegInt(o.bytes),
      local: bool(o.local),
      // `available` (plugin): the file is on the server; older answers: a mediaId says so.
      available: typeof o.available === 'boolean' ? o.available && !!mediaId : !!mediaId,
    });
  });
  return out;
}

function normalizeDelivery(d) {
  const o = obj(d);
  if (!o) return null;
  const kind = ['device', 'person', 'nas', 'link'].includes(o.kind) ? o.kind : null;
  if (!kind) return null;
  return {
    kind,
    target: str(typeof o.target === 'number' ? String(o.target) : o.target, 200),
    targetName: str(o.label || o.targetName || o.name, 120) || null,
    status: DELIVERY_STATUS.includes(o.status) ? o.status : 'pending',
    via: o.via === 'direct' || o.via === 'server' ? o.via : null,
    at: timeOf(o.at),
    openedAt: timeOf(o.openedAt),
    error: str(o.error, 200) || null,
  };
}

/** The public link of POST sends → { token, url, pin, expiresAt, maxDownloads } or null. */
function linkOf(v) {
  const link = obj(v);
  if (!link || typeof link.url !== 'string' || !/^https?:\/\//i.test(link.url)) return null;
  return {
    token: isLinkToken(link.token) ? link.token : null,
    url: link.url.slice(0, 2048),
    pin: typeof link.pin === 'string' && /^\d{4,8}$/.test(link.pin) ? link.pin : null,
    expiresAt: timeOf(link.expiresAt),
    maxDownloads: nonNegInt(link.maxDownloads),
  };
}

/** POST sends → { id, deliveries, link, direct, send } */
function normalizeSendResult(raw) {
  const r = obj(raw) || {};
  return {
    id: idOf(r.id) || (obj(r.send) ? idOf(r.send.id) : null),
    deliveries: arr(r.deliveries).map(normalizeDelivery).filter(Boolean),
    link: linkOf(r.link),
    direct: arr(r.direct).map(normalizeDirect).filter(Boolean),
    send: normalizeSend(r.send),
  };
}

/**
 * Sender of a send / push: { id, name, deviceId, deviceName, own }. own (GateDrop 1.2.0):
 * true — from the viewer's own account (name it by the device), false — from another
 * person (name them), null — an older plugin that does not say.
 */
function personOf(v) {
  if (typeof v === 'string') return { id: null, name: str(v, 80), deviceId: null, deviceName: null, own: null };
  const o = obj(v);
  if (!o) return null;
  return {
    id: idOf(o.userId !== undefined ? o.userId : o.id),
    name: str(o.name, 80) || null,
    deviceId: idOf(o.deviceId),
    deviceName: str(o.deviceName, 80) || null,
    own: typeof o.own === 'boolean' ? o.own : null,
  };
}

/** A send of `GET inbox` / `GET sends/<id>` → clean object or null. */
function normalizeSend(raw) {
  const o = obj(raw);
  if (!o) return null;
  const id = idOf(o.id);
  if (!id) return null;
  return {
    id,
    role: o.role === 'sent' || o.role === 'received' ? o.role : null,
    at: timeOf(o.createdAt || o.created_at || o.at),
    from: personOf(o.from),
    to: str(o.toLabel || (typeof o.to === 'string' ? o.to : ''), 200) || null,
    text: str(o.text, MAX_TEXT) || null,
    link: typeof o.link === 'string' && /^https?:\/\//i.test(o.link) ? o.link.slice(0, MAX_LINK) : null,
    note: str(o.note, MAX_NOTE) || null,
    items: normalizeItems(o.items),
    deliveries: arr(o.deliveries).map(normalizeDelivery).filter(Boolean),
    opened: bool(o.opened),
    expired: bool(o.expired),
    expiresAt: timeOf(o.expiresAt || o.expires_at),
  };
}

const LINK_STATES = ['active', 'expired', 'revoked', 'locked', 'used', 'gone'];

/** An active / old public link of `GET inbox?kind=links`. */
function normalizeLink(raw) {
  const o = obj(raw);
  if (!o) return null;
  const token = isLinkToken(o.token) ? o.token : null;
  if (!token) return null;
  const state = LINK_STATES.includes(o.state) ? o.state : null;
  return {
    token,
    url: typeof o.url === 'string' && /^https?:\/\//i.test(o.url) ? o.url.slice(0, 2048) : null,
    sendId: idOf(o.sendId || o.send_id),
    title: str(o.title, 120) || null,
    items: normalizeItems(o.items || o.files),
    expiresAt: timeOf(o.expiresAt || o.expires_at),
    pin: bool(o.pin) || bool(o.hasPin),
    once: bool(o.once) || o.maxDownloads === 1,
    downloads: nonNegInt(o.downloads) || 0,
    maxDownloads: nonNegInt(o.maxDownloads),
    state,
    locked: bool(o.locked) || state === 'locked',
    revoked: bool(o.revoked) || state === 'revoked',
    // used up (single download), expired or the files gone: no longer usable
    expired: bool(o.expired) || state === 'expired' || state === 'used' || state === 'gone' || (state === 'active' && o.active === false),
    at: timeOf(o.createdAt || o.created_at),
  };
}

/** GET inbox?kind= → [sends] | [links]; accepts `{ items }`, `{ sends }`, `{ links }` or a bare list. */
function normalizeInbox(raw, kind) {
  const r = obj(raw);
  const list = Array.isArray(raw) ? raw : r ? (r.items || r.sends || r.links || r.list || []) : [];
  const norm = kind === 'links' ? normalizeLink : normalizeSend;
  return arr(list).slice(0, 500).map(norm).filter(Boolean);
}

/**
 * GET pending (GateDrop 1.1.0) → the sends waiting for this device, oldest
 * first ({ ok, items: [send view] }; a bare list is taken too).
 */
function normalizePending(raw) {
  const r = obj(raw);
  const list = Array.isArray(raw) ? raw : r ? (r.items || r.sends || []) : [];
  return arr(list).slice(0, 500).map(normalizeSend).filter((s) => s && !s.expired)
    .map((s, i) => ({ s, i })).sort((a, b) => ((a.s.at || 0) - (b.s.at || 0)) || (a.i - b.i)).map((x) => x.s);
}

/**
 * `data.gatedrop` of a push →
 *   { kind: 'direct', transferId, sendId, mode, key, ticket, candidates, items, itemCount, from, expiresAt }
 *     (items [] with itemCount when the push left them out: GET transfers/<id>)
 *   { kind: 'send', sendId, send (when the push carries it), from }
 *   { kind: 'link', token, sendId }  (topic `link`: "Link geladen" / "Link gesperrt")
 * or null. `transfer` wins over `send` (a direct push carries both).
 */
function parsePushData(data) {
  const d = obj(data);
  const g = d && obj(d.gatedrop);
  if (!g) return null;
  if (g.transfer !== undefined || g.transferId !== undefined) {
    const direct = normalizeDirect(g);
    if (!direct) return null;
    const items = normalizeItems(g.items);
    const count = nonNegInt(g.itemCount);
    return {
      kind: 'direct',
      transferId: direct.transferId,
      mode: direct.mode,
      key: direct.key,
      ticket: direct.ticket,
      candidates: direct.candidates,
      items,
      itemCount: items.length || (count !== null && count <= MAX_ITEMS ? count : 0),
      from: personOf(g.from),
      sendId: idOf(g.send) || idOf(g.sendId) || (obj(g.transfer) ? idOf(g.transfer.send) : null),
      expiresAt: direct.expiresAt,
    };
  }
  if (g.link !== undefined) {
    return { kind: 'link', token: isLinkToken(g.link) ? g.link : null, sendId: idOf(g.send) };
  }
  if (g.send !== undefined) {
    const sendObj = obj(g.send);
    const sendId = sendObj ? idOf(sendObj.id) : idOf(g.send);
    if (!sendId) return null;
    return { kind: 'send', sendId, send: sendObj ? normalizeSend(sendObj) : null, from: personOf(g.from) };
  }
  return null;
}

/**
 * GET transfers/<id> → { transfer: { id, sendId, side, mode, status, from, candidates, key, ticket, expiresAt, items } }
 * → the same shape as a direct push (parsePushData), plus side / status; null when not usable.
 */
function transferOf(raw, transferId) {
  const r = obj(raw);
  const t = r && (obj(r.transfer) || r);
  if (!t) return null;
  const p = parsePushData({ gatedrop: { ...t, transfer: isTransferId(t.id) ? t.id : transferId, send: t.sendId || t.send } });
  if (!p || p.kind !== 'direct') return null;
  return { ...p, side: t.side === 'sender' || t.side === 'receiver' ? t.side : null, status: typeof t.status === 'string' ? t.status : null };
}

// ── Requests ───────────────────────────────────────────────

/**
 * Checked `to` of POST sends: { people: [ids|'family'], devices: [ids],
 * nas: [{ id, path? }], link?: { expires, pin } } or null when empty / invalid.
 */
function sendTargets(to) {
  const o = obj(to) || {};
  const ids = (v, max) => [...new Set(arr(v).map((x) => (x === 'family' ? 'family' : idOf(x))).filter(Boolean))].slice(0, max);
  const out = {
    people: ids(o.people, 50),
    devices: ids(o.devices, 20).filter((x) => x !== 'family'),
    nas: arr(o.nas).map((n) => {
      const x = obj(n);
      const id = x && idOf(x.id);
      if (!id) return null;
      const p = str(x.path, 400);
      return p && !/(^|[\\/])\.\.([\\/]|$)/.test(p) ? { id, path: p } : { id };
    }).filter(Boolean).slice(0, 5),
  };
  const link = obj(o.link);
  if (link) {
    if (!LINK_EXPIRES.includes(link.expires)) return null;
    out.link = { expires: link.expires, pin: link.pin === true };
  }
  if (!out.people.length && !out.devices.length && !out.nas.length && !out.link) return null;
  return out;
}

/** http(s) link of a send (≤ 2048), else null. */
function linkArg(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || s.length > MAX_LINK) return null;
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:' ? s : null;
  } catch {
    return null;
  }
}

/** Is this push one of GateDrop (topic or data)? */
function isGateDropPush(n) {
  const o = obj(n);
  if (!o) return false;
  if (typeof o.topic === 'string' && o.topic.startsWith(TOPIC_PREFIX)) return true;
  return !!(obj(o.data) && obj(o.data.gatedrop));
}

module.exports = {
  PLUGIN_ID, APP_ROUTE, TOPIC_PREFIX, API_BASE, MEDIA_PATH, PLUGINS_PATH,
  PORT, BLOCK_SIZE, TAG_SIZE, MAX_FILE_BYTES, MAX_ITEMS, MAX_TEXT, MAX_NOTE, MAX_LINK,
  RESUMABLE_FROM, TICKET_TTL_MS, CONNECT_TIMEOUT_MS, LINK_EXPIRES, INBOX_KINDS, DELIVERY_STATUS, RECEIVE_FROM,
  idOf, nonNegInt, timeOf, isTransferId, isTicket, isMediaId, isLinkToken, decodeKey,
  encodeName, decodeName, isTraversalName, safeFileName, numberedName, guessMime, encryptedSize,
  isPrivateIPv4, plainIPv4, sameSubnet, lanAddresses, lanScan, parseCandidate, ipv4ToInt, DIRECT_REASONS, directState,
  normalizeTargets, normalizeDeviceAccess, normalizeDirect, normalizeItems, normalizeSendResult, normalizeSend, normalizeLink,
  normalizeInbox, normalizePending, parsePushData, transferOf, linkOf, sendTargets, linkArg, isGateDropPush,
};
