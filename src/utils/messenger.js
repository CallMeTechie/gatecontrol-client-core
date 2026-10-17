'use strict';

/**
 * Pure helpers of the GateControl Messenger client (plugin
 * `gatecontrol-messenger`, contract: the plugin's README "App-API").
 *
 * Electron-free and side-effect free: shared by services/messenger-*.js,
 * services/chat-notifier.js and the IPC handlers, unit-tested directly.
 */

const crypto = require('crypto');

const PLUGIN_ID = 'gatecontrol-messenger';
const CHAT_TOPIC = `plugin:${PLUGIN_ID}:message`;
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/media`;
const PLUGINS_PATH = '/api/v1/client/plugins';

const CLIENT_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const MEDIA_ID_RE = /^[0-9a-f]{32}$/;
// Avatars of accounts: a /avatars/ path of the own server (contract "Person").
const AVATAR_PATH_RE = /^\/avatars\/[A-Za-z0-9_-]{16,128}\.(?:png|jpe?g|webp)$/;
// A relative path of the plugin's client API as sent in push actions
// (`conversations/12/read`): no scheme, no `..`, no query.
const API_PATH_RE = /^(?!.*\.\.)[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+){0,5}$/;
const KINDS = ['text', 'image', 'voice', 'file', 'location'];
const DELETE_SCOPES = ['me', 'all'];
const EMOJI_MAX = 16;
const TEXT_MAX = 4000;

/**
 * File types that must never be opened straight from a chat (they run code
 * or open other programs). "Speichern unter …" is still offered.
 */
const UNSAFE_EXT = new Set([
  'exe', 'com', 'bat', 'cmd', 'msi', 'msp', 'msix', 'appx', 'appxbundle', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe',
  'js', 'jse', 'mjs', 'cjs', 'wsf', 'wsh', 'hta', 'scr', 'pif', 'cpl', 'lnk', 'url', 'reg', 'inf', 'jar', 'dll',
  'sys', 'drv', 'ocx', 'application', 'appref-ms', 'gadget', 'msc', 'scf', 'settingcontent-ms', 'library-ms',
  'xll', 'xlam', 'docm', 'dotm', 'xlsm', 'xltm', 'pptm', 'potm', 'ppam', 'sldm', 'chm', 'iso', 'img', 'vhd', 'vhdx',
  'website', 'diagcab', 'search-ms', 'py', 'pyw', 'rb', 'pl', 'sh', 'bash', 'zsh', 'command', 'svg', 'html', 'htm',
  'xhtml', 'mht', 'mhtml', 'shtml', 'xml', 'xsl',
]);

/** Fresh idempotency key for POST …/messages (UUID, matches [A-Za-z0-9_-]{8,64}). */
function newClientId() {
  return crypto.randomUUID();
}

const isClientId = (v) => typeof v === 'string' && CLIENT_ID_RE.test(v);
const isMediaId = (v) => typeof v === 'string' && MEDIA_ID_RE.test(v);
const isAvatarPath = (v) => typeof v === 'string' && AVATAR_PATH_RE.test(v);
const isApiPath = (v) => typeof v === 'string' && v.length <= 200 && API_PATH_RE.test(v);
const posInt = (v) => {
  const n = typeof v === 'string' && /^\d{1,15}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
};

/** Lower-case extension of a file name ('' when none). */
function extOf(name) {
  const base = String(name || '').slice(-300).trim().replace(/[\s.]+$/, '');
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase() : '';
}

/** True when a file must not be opened directly (only saved). */
function unsafeToOpen(fileName, mime) {
  if (UNSAFE_EXT.has(extOf(fileName))) return true;
  const m = String(mime || '').toLowerCase();
  return m === 'application/x-msdownload' || m === 'application/x-ms-installer' || m === 'text/html'
    || m === 'image/svg+xml' || m === 'application/javascript' || m === 'text/javascript' || m === 'application/hta';
}

/**
 * A file name that is safe on Windows: no path, no reserved characters or
 * device names, at most 120 characters. `fallback` when nothing is left.
 */
function safeFileName(name, fallback = 'datei') {
  let s = String(name == null ? '' : name).slice(0, 1000).replace(/^.*[\\/]/, '');
  s = s.replace(/[\u0000-\u001f<>:"/\\|?*\u007f]/g, '_').replace(/^[\s.]+|[\s.]+$/g, '');
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(s)) s = `_${s}`;
  if (s.length > 120) {
    const ext = extOf(s);
    s = ext && ext.length < 12 ? `${s.slice(0, 119 - ext.length)}.${ext}` : s.slice(0, 120);
  }
  return s || fallback;
}

/** File extension for a stored type (used when a message has no file name). */
function extForMime(mime) {
  const map = {
    'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif', 'audio/ogg': 'ogg',
    'audio/mp4': 'm4a', 'audio/aac': 'aac', 'audio/mpeg': 'mp3', 'audio/webm': 'webm', 'video/mp4': 'mp4',
    'application/pdf': 'pdf', 'text/plain': 'txt', 'application/zip': 'zip',
  };
  return map[String(mime || '').toLowerCase().split(';')[0]] || 'bin';
}

/**
 * Status of an own message: 'pending' (outbox), 'failed', 'read',
 * 'delivered', 'sent' — or null for others' and system messages.
 */
function messageStatus(m, conv) {
  if (!m) return null;
  if (m.pending) return m.failed ? 'failed' : 'pending';
  if (!m.mine || m.kind === 'system') return null;
  const read = conv && Number.isSafeInteger(conv.readUpTo) ? conv.readUpTo : null;
  const delivered = conv && Number.isSafeInteger(conv.deliveredUpTo) ? conv.deliveredUpTo : null;
  if (read != null && m.id <= read) return 'read';
  if (delivered != null && m.id <= delivered) return 'delivered';
  if (m.status === 'read' || m.status === 'delivered') return m.status;
  return 'sent';
}

/**
 * Merge server messages into a cached list: unique by id (incoming wins),
 * ascending by id.
 */
function mergeMessages(list, incoming) {
  const map = new Map();
  for (const m of Array.isArray(list) ? list : []) if (m && Number.isSafeInteger(m.id)) map.set(m.id, m);
  for (const m of Array.isArray(incoming) ? incoming : []) if (m && Number.isSafeInteger(m.id)) map.set(m.id, m);
  return [...map.values()].sort((a, b) => a.id - b.id);
}

/** Time of the newest activity of a conversation (ISO) for sorting. */
function activityOf(c) {
  if (!c) return '';
  return (c.lastMessage && c.lastMessage.createdAt) || c.updatedAt || c.createdAt || '';
}

/** Newest activity first, then the higher id. */
function sortConversations(list) {
  return list.slice().sort((a, b) => {
    const ta = activityOf(a);
    const tb = activityOf(b);
    if (ta !== tb) return ta < tb ? 1 : -1;
    return (b.id || 0) - (a.id || 0);
  });
}

/**
 * The body of POST conversations/:id/messages from a client request. Throws
 * an Error with `code` 'invalid' for anything the server would refuse anyway.
 */
function buildSendBody(req, { textMax = TEXT_MAX } = {}) {
  const r = req && typeof req === 'object' ? req : {};
  const kind = r.kind == null ? 'text' : r.kind;
  const invalid = (what) => Object.assign(new Error(`invalid ${what}`), { code: 'invalid' });
  if (!KINDS.includes(kind)) throw invalid('kind');
  const body = { kind };
  if (r.text != null) {
    if (typeof r.text !== 'string') throw invalid('text');
    const text = r.text.replace(/\r\n?/g, '\n').trim();
    if (text.length > textMax) throw invalid('text');
    if (text) body.text = text;
  }
  if (kind === 'text' && !body.text) throw invalid('text');
  if (r.replyTo != null) {
    const id = posInt(r.replyTo);
    if (!id) throw invalid('replyTo');
    body.replyTo = id;
  }
  if (r.meta != null) {
    if (typeof r.meta !== 'object' || Array.isArray(r.meta)) throw invalid('meta');
    const meta = {};
    if (Number.isFinite(r.meta.durationMs) && r.meta.durationMs >= 0) meta.durationMs = Math.round(r.meta.durationMs);
    if (Array.isArray(r.meta.waveform)) {
      meta.waveform = r.meta.waveform.slice(0, 64).map((v) => Math.max(0, Math.min(255, Math.round(Number(v) || 0))));
    }
    if (Number.isSafeInteger(r.meta.w) && r.meta.w > 0) meta.w = r.meta.w;
    if (Number.isSafeInteger(r.meta.h) && r.meta.h > 0) meta.h = r.meta.h;
    if (typeof r.meta.fileName === 'string' && r.meta.fileName.trim()) meta.fileName = r.meta.fileName.trim().slice(0, 200);
    if (Object.keys(meta).length) body.meta = meta;
  }
  if (kind === 'location') {
    const l = r.location;
    if (!l || !Number.isFinite(l.lat) || !Number.isFinite(l.lon) || Math.abs(l.lat) > 90 || Math.abs(l.lon) > 180) throw invalid('location');
    body.location = { lat: l.lat, lon: l.lon };
    if (typeof l.label === 'string' && l.label.trim()) body.location.label = l.label.trim().slice(0, 200);
    if (Number.isFinite(l.accuracy) && l.accuracy >= 0) body.location.accuracy = l.accuracy;
  }
  if (r.source === 'notification') body.source = 'notification';
  return body;
}

/**
 * A chat notification (push payload with `kind: "message"`) → the fields the
 * client uses, or null when it is not one / malformed.
 * → { seq, id, conversationId, messageId, title, body, priority, silent,
 *     createdAt, expiresAt, collapseKey, isGroup, conversationTitle,
 *     sender: { id, name, avatarUrl }, reply: { label, path, body } | null,
 *     markRead: { label, path, body } | null }
 */
function parseChatNotification(n) {
  if (!n || typeof n !== 'object' || n.kind !== 'message') return null;
  const seq = Number(n.seq);
  const id = Number(n.id);
  if (!Number.isSafeInteger(seq) || seq <= 0 || !Number.isSafeInteger(id) || id <= 0) return null;
  const data = n.data && typeof n.data === 'object' && !Array.isArray(n.data) ? n.data : {};
  const conv = data.conversation && typeof data.conversation === 'object' ? data.conversation : {};
  const conversationId = posInt(conv.id) || posInt(data.conversationId);
  if (!conversationId) return null;
  const sender = data.sender && typeof data.sender === 'object' ? data.sender : {};
  const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
  const action = (type) => {
    const list = Array.isArray(data.actions) ? data.actions : [];
    const a = list.find((x) => x && typeof x === 'object' && x.type === type);
    if (!a || !isApiPath(String(a.path || '').replace(/^\/+/, ''))) return null;
    const body = a.body && typeof a.body === 'object' && !Array.isArray(a.body) ? a.body : {};
    return { id: str(a.id, 40) || type, label: str(a.label, 24), path: String(a.path).replace(/^\/+/, ''), body };
  };
  const avatar = typeof sender.avatarUrl === 'string' && isAvatarPath(sender.avatarUrl) ? sender.avatarUrl : null;
  return {
    seq,
    id,
    conversationId,
    messageId: posInt(data.messageId),
    title: str(n.title, 120),
    body: str(n.body, 1000),
    priority: ['info', 'normal', 'high', 'critical'].includes(n.priority) ? n.priority : 'normal',
    silent: n.silent === true,
    createdAt: typeof n.created_at === 'string' ? n.created_at : null,
    expiresAt: typeof n.expires_at === 'string' ? n.expires_at : null,
    collapseKey: str(n.collapse_key, 120) || `plugin:${PLUGIN_ID}:chat:${conversationId}`,
    topic: str(n.topic, 120) || CHAT_TOPIC,
    isGroup: conv.isGroup === true,
    conversationTitle: str(conv.title, 80) || null,
    sender: {
      id: sender.id == null ? null : (typeof sender.id === 'number' ? sender.id : str(String(sender.id), 64)),
      name: str(sender.name, 80),
      avatarUrl: avatar,
    },
    reply: action('reply'),
    markRead: action('mark_read'),
  };
}

/** Byte length of a Buffer / typed array / ArrayBuffer (0 otherwise). */
function byteLength(v) {
  if (!v) return 0;
  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v)) return v.byteLength;
  if (v instanceof ArrayBuffer) return v.byteLength;
  return 0;
}

/** Buffer view of a Buffer / typed array / ArrayBuffer (from IPC), or null. */
function toBuffer(v) {
  if (!v) return null;
  if (Buffer.isBuffer(v)) return v;
  if (ArrayBuffer.isView(v)) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  if (v instanceof ArrayBuffer) return Buffer.from(v);
  return null;
}

/** MIME type without parameters, lower case, or '' when malformed. */
function baseMime(m) {
  const s = String(m || '').toLowerCase().split(';')[0].trim();
  return /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(s) ? s : '';
}

module.exports = {
  PLUGIN_ID,
  CHAT_TOPIC,
  APP_ROUTE,
  API_BASE,
  MEDIA_BASE,
  PLUGINS_PATH,
  KINDS,
  DELETE_SCOPES,
  EMOJI_MAX,
  TEXT_MAX,
  CLIENT_ID_RE,
  MEDIA_ID_RE,
  AVATAR_PATH_RE,
  newClientId,
  isClientId,
  isMediaId,
  isAvatarPath,
  isApiPath,
  posInt,
  extOf,
  unsafeToOpen,
  safeFileName,
  extForMime,
  messageStatus,
  mergeMessages,
  sortConversations,
  buildSendBody,
  parseChatNotification,
  byteLength,
  toBuffer,
  baseMime,
};
