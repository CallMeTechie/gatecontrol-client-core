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
// Pictures of notifications on the own server (core `imageUrl`, Messenger 1.6 notice cards).
const NOTIFY_MEDIA_RE = /^\/notify-media\/[A-Za-z0-9_-]{8,128}\.(?:jpg|jpeg|png|webp)$/;
// A relative path of the plugin's client API as sent in push actions
// (`conversations/12/read`): no scheme, no `..`, no query.
const API_PATH_RE = /^(?!.*\.\.)[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+){0,5}$/;
// Kinds this client sends. `poll`, `event`, `action` since Messenger 1.4.0
// (features polls / events / actions); `arrival` and `card` are shown only
// (Windows sends no live arrival, cards come from other plugins).
const KINDS = ['text', 'image', 'voice', 'file', 'location', 'poll', 'event', 'action'];
// Message kinds this client can draw; anything else → "needs a newer app version".
const SHOWN_KINDS = Object.freeze(['text', 'image', 'voice', 'file', 'location', 'system', 'poll', 'event', 'arrival', 'action', 'card']);
// GET conversations/:id/media?kind= (`video` since Messenger 1.3.0).
const MEDIA_KINDS = ['image', 'voice', 'file', 'video', 'all'];
// `GET me` feature keys this client knows. A server that sets another key to
// `true` has chat functions this version does not offer → update hint.
const KNOWN_FEATURES = Object.freeze([
  'direct', 'groups', 'voice', 'files', 'location', 'reactions', 'edit', 'search', 'disappearing', 'bridges', 'e2e',
  'video_meta', 'file_thumbs',
  // Messenger 1.4.0 (only true keys are present)
  'status', 'stories', 'polls', 'events', 'arrival', 'actions', 'msg_tools', 'privacy2',
  // Messenger 1.4.1
  'story_duration',
  // Messenger 1.6: GateControl's notifications in chats (notice channels and
  // cards, `listPinned`) and "Wo Mitteilungen erscheinen" (core push routes)
  'notices', 'notice_routes',
  // Messenger 1.11: the host's virus scan (`media.scan`, 422 infected / 423 scan_blocked on send, message.update { scan })
  'scan',
  // Messenger 1.13: „Verknüpfte Dienste“ (GET bridges …); 1.14: chats over a bridge (`bridge` on conversations and
  // messages, the mark ?bridged=1) — the second one only for people who have such a chat
  'linked_services', 'bridge_chats',
  // Messenger 1.15: files and pictures over a bridge; a new chat by phone number (POST bridges/:network/resolve, …/chats)
  // — set only together with bridge_chats (1.16: bridge_new_chat as soon as a service is linked)
  'bridge_media', 'bridge_new_chat',
  // Messenger 1.17: older history at a new link (GET/PUT bridges/history), its files on request
  // (POST messages/:id/fetch), the phone warning — only for people who linked a service
  'bridge_history',
  // Messenger 1.18: „Neuer Chat“ with contacts — GateControl, WhatsApp, the address book (GET contacts/new-chat,
  // POST bridges/:network/chats { ref } | { contactId, phoneKind }) — only for people who linked a service
  'bridge_contacts',
  // Messenger 1.20: WhatsApp channels on a page of their own (GET channels, ?channels=1 — they leave GET conversations),
  // groups where only admins write, format (`marks`), link previews, the own reaction in a channel — for the same
  // people as bridge_chats
  'bridge_channels',
  // Messenger 1.21: persons — the chat with a GateControl account and the WhatsApp chat of the same human as one entry
  // (?people=1: `person`, `folded`, persons/… routes, suggestions, „Trennen“) — for the same people as bridge_chats
  'chat_people',
]);
// Messenger 1.13 / 1.14 `GET me` features (present only when true).
const FEATURE_LINKED = 'linked_services';
const FEATURE_BRIDGE_CHATS = 'bridge_chats';
// Messenger 1.15 `GET me` features.
const FEATURE_BRIDGE_MEDIA = 'bridge_media';
const FEATURE_BRIDGE_NEW_CHAT = 'bridge_new_chat';
// Messenger 1.18 `GET me` feature: „Neuer Chat“ with contacts.
const FEATURE_BRIDGE_CONTACTS = 'bridge_contacts';
// Messenger 1.20 `GET me` feature: channels, read-only groups, format, link previews.
const FEATURE_BRIDGE_CHANNELS = 'bridge_channels';
// Messenger 1.21 `GET me` feature: persons (one entry per human over several ways).
const FEATURE_CHAT_PEOPLE = 'chat_people';
// The way of a message / a conversation of a person: GateControl or the network of a bridge.
const GC_WAY = 'gatecontrol';
const WAY_RE = /^[a-z]{2,20}$/;
// GET contacts/new-chat: the search (q) the server takes, the sealed reference of a WhatsApp contact, the key of an
// address book number (POST …/chats { phoneKind }) and the order of the kinds in „Welche Nummer?“.
const CONTACTS_QUERY_MAX = 100;
const CONTACT_REF_RE = /^k[A-Za-z0-9_-]{40,1400}$/;
const PHONE_KEY_RE = /^(mobile|work|home|other)(-[2-9])?$/;
const PHONE_KINDS = Object.freeze(['mobile', 'work', 'home', 'other']);
const CONTACT_LIST_STATES = Object.freeze(['ok', 'unreachable', 'logged_out']);
// Messenger 1.17 `GET me` feature.
const FEATURE_BRIDGE_HISTORY = 'bridge_history';
// What of the older messages comes over at a new link (PUT bridges/history { days }): nothing, 30 days, everything.
const HISTORY_DAYS = Object.freeze([0, 30, -1]);
// The push of „Verknüpfte Dienste“ (Messenger 1.17: the phone was not seen for days).
const BRIDGE_TOPIC = `plugin:${PLUGIN_ID}:bridge`;
// Why a new chat by number is not possible right now (GET bridges → networks[].newChat.reason, Messenger 1.16).
const NEW_CHAT_REASONS = Object.freeze(['unlinked', 'logged_out', 'unreachable', 'child_locked', 'child_new_chat_off', 'off']);
// The country code a number without one gets (the dialog's default).
const DEFAULT_CC = '+49';
// The ways to link an account (POST bridges/:network/login { flow }).
const BRIDGE_FLOWS = Object.freeze(['phone', 'qr']);
// A network id as the plugin names it (today: whatsapp), a login / process / step id of the bridge.
const BRIDGE_NET_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const BRIDGE_ID_RE = /^[A-Za-z0-9._:=+-]{1,128}$/;
const BRIDGE_LOGIN_STATES = Object.freeze(['connected', 'connecting', 'logged_out', 'error', 'unknown']);
// A QR code has at most 177 modules a side (version 40).
const QR_MAX = 177;
// Messenger 1.4.0 `GET me` features (README "Since 1.4.0").
const FEATURES_14 = Object.freeze({
  status: 'status', stories: 'stories', polls: 'polls', events: 'events', arrival: 'arrival', actions: 'actions', tools: 'msg_tools', privacy: 'privacy2',
  // since 1.4.1: `POST status/stories` takes `durationH` (present together with `stories`)
  storyDuration: 'story_duration',
  // since 1.6: notice channels / cards, the family chat pinned to the list
  notices: 'notices', noticeRoutes: 'notice_routes',
});
// Story durations in hours (Messenger 1.4.1 `durationH`, `limits.storyDurationsH`); the server's default is 24.
const STORY_DURATIONS_H = Object.freeze([1, 3, 6, 12, 24]);
const STORY_DURATION_DEFAULT_H = 24;
// Feature a send kind needs (absent → refused with code `unsupported`).
const KIND_FEATURE = Object.freeze({ poll: 'polls', event: 'events', action: 'actions' });
// prefs of Messenger 1.4.0 (PUT prefs takes partial objects; README "Preferences").
const PREF_RULES = Object.freeze({
  privacy: {
    lastSeen: ['all', 'family', 'nobody'],
    avatar: ['all', 'family', 'nobody'],
    statusDefault: ['all', 'family', 'custom'],
    placeInStatus: ['nobody', 'family', 'all'],
    groupAdd: ['all', 'family', 'nobody'],
    defaultDisappearingS: [0, 86400, 604800, 2592000],
  },
  notify: {
    groupsMentionsOnly: 'bool', reactions: 'bool', statusDigest: 'bool', eventReminderMin: [0, 15, 60, 120, 1440],
  },
  chats: { keepArchived: 'bool' },
});
const STATUS_PRESETS = Object.freeze(['none', 'homeoffice', 'away', 'dnd', 'auto_place']);
const AUDIENCES = Object.freeze(['all', 'family', 'custom']);
const REMINDER_MIN = Object.freeze([0, 15, 60, 120, 1440]);
// An app route of another plugin (card link): plg-<id>; since Messenger 1.6 it
// may name a screen of the plugin after a `/` (notice cards:
// plg-gatecontrol-schule/messages/<id>), no `.` / `..` segments.
const ROUTE_RE = /^plg-[a-z0-9]+(?:-[a-z0-9]+)*(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9_.:-]{1,80}){0,3}$/;
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
// Messenger 1.3.0 `GET me` features that unlock optional send fields.
const FEATURE_VIDEO_META = 'video_meta';   // `video: { durationMs, width, height }` on video files
const FEATURE_FILE_THUMBS = 'file_thumbs'; // `thumbMediaId` on file messages
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

/**
 * `GET me` features as an object { name: true|false } (the plugin's form
 * since 1.0); a list of names is accepted as well.
 */
function normalizeFeatures(f) {
  const out = {};
  if (Array.isArray(f)) {
    for (const k of f) if (typeof k === 'string' && k && k.length <= 64) out[k] = true;
  } else if (f && typeof f === 'object') {
    for (const [k, v] of Object.entries(f)) out[k] = v;
  }
  return out;
}

/** Does the server offer `name` (features as list or object)? */
function hasFeature(features, name) {
  if (Array.isArray(features)) return features.includes(name);
  return !!features && typeof features === 'object' && features[name] === true;
}

/**
 * Feature keys the server switches on (`true`) that this client does not
 * know (KNOWN_FEATURES), sorted — empty when it knows them all.
 */
function unknownFeatures(features, known = KNOWN_FEATURES) {
  const f = normalizeFeatures(features);
  return Object.keys(f).filter((k) => f[k] === true && !known.includes(k) && /^[A-Za-z0-9_.-]{1,64}$/.test(k)).sort();
}

/** `video/*` without parameters. */
const isVideoMime = (m) => /^video\/[a-z0-9.+-]+$/.test(String(m || '').toLowerCase().split(';')[0].trim());

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
    'video/webm': 'webm', 'video/quicktime': 'mov', 'video/x-matroska': 'mkv',
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
  // Messenger 1.14, a chat over a bridge: what the other messenger said about this very message
  const b = m.bridge && typeof m.bridge === 'object' ? m.bridge.state : null;
  if (b === 'failed' || m.status === 'failed') return 'failed';
  if (b === 'pending' || m.status === 'sending') return 'pending';
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
function mergeMessages(list, incoming, { byTime = false } = {}) {
  const map = new Map();
  for (const m of Array.isArray(list) ? list : []) if (m && Number.isSafeInteger(m.id)) map.set(m.id, m);
  for (const m of Array.isArray(incoming) ? incoming : []) if (m && Number.isSafeInteger(m.id)) map.set(m.id, m);
  // Messenger 1.21: a person's shared history mixes its ways — by time (createdAt, a tie by id), as the server pages it
  if (byTime) return [...map.values()].sort(byTimeOrder);
  return [...map.values()].sort((a, b) => a.id - b.id);
}

/** Messages by `createdAt`, a tie (or a missing time) by id. */
function byTimeOrder(a, b) {
  const ta = typeof a.createdAt === 'string' ? a.createdAt : '';
  const tb = typeof b.createdAt === 'string' ? b.createdAt : '';
  if (ta !== tb) return ta < tb ? -1 : 1;
  return a.id - b.id;
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
  if (r.video != null) {
    // Video files (Messenger 1.3.0, feature `video_meta`): kind stays 'file'.
    const v = r.video;
    if (kind !== 'file' || typeof v !== 'object' || Array.isArray(v)) throw invalid('video');
    const video = {};
    if (Number.isFinite(v.durationMs) && v.durationMs >= 0) video.durationMs = Math.round(v.durationMs);
    if (Number.isSafeInteger(v.width) && v.width > 0 && v.width <= 65535) video.width = v.width;
    if (Number.isSafeInteger(v.height) && v.height > 0 && v.height <= 65535) video.height = v.height;
    if (Object.keys(video).length) body.video = video;
  }
  if (kind === 'location') {
    const l = r.location;
    if (!l || !Number.isFinite(l.lat) || !Number.isFinite(l.lon) || Math.abs(l.lat) > 90 || Math.abs(l.lon) > 180) throw invalid('location');
    body.location = { lat: l.lat, lon: l.lon };
    if (typeof l.label === 'string' && l.label.trim()) body.location.label = l.label.trim().slice(0, 200);
    if (Number.isFinite(l.accuracy) && l.accuracy >= 0) body.location.accuracy = l.accuracy;
  }
  if (kind === 'poll') body.poll = normalizePoll(r.poll);
  if (kind === 'event') body.event = normalizeEvent(r.event);
  if (kind === 'action') body.action = normalizeAction(r.action);
  if (['poll', 'event', 'action'].includes(kind)) {
    // these kinds carry no text, meta or media (the server refuses them)
    delete body.text;
    delete body.meta;
  }
  if (r.replyStory != null) {
    // Messenger 1.4.0: a reply to a story (direct chat with its owner)
    const sid = posInt(r.replyStory && typeof r.replyStory === 'object' ? r.replyStory.storyId : r.replyStory);
    if (!sid || kind !== 'text') throw invalid('replyStory');
    body.replyStory = { storyId: sid };
  }
  if (r.source === 'notification') body.source = 'notification';
  return body;
}

const invalidErr = (what) => Object.assign(new Error(`invalid ${what}`), { code: 'invalid' });
const isIso = (v) => typeof v === 'string' && v.length <= 40 && !Number.isNaN(Date.parse(v));
const cleanLine = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max) : '');

/** `poll` of a send body (Messenger 1.4.0): question 1…200, 2…12 distinct options ≤ 80. */
function normalizePoll(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw invalidErr('poll');
  const question = cleanLine(p.question, 200);
  if (!question) throw invalidErr('poll question');
  const seen = new Set();
  const options = [];
  for (const o of Array.isArray(p.options) ? p.options : []) {
    const v = cleanLine(o, 80);
    if (!v || seen.has(v.toLowerCase())) continue;
    seen.add(v.toLowerCase());
    options.push(v);
  }
  if (options.length < 2 || options.length > 12) throw invalidErr('poll options');
  const out = { question, options, multi: p.multi === true, anonymous: p.anonymous === true, allowAdd: p.allowAdd === true };
  if (p.closesAt != null) {
    if (!isIso(p.closesAt)) throw invalidErr('poll closesAt');
    out.closesAt = new Date(p.closesAt).toISOString();
  }
  return out;
}

/** `place` of an event: { label, familiePlaceId?, lat?, lon? } or null. */
function normalizePlace(v) {
  if (v == null) return null;
  const pl = typeof v === 'string' ? { label: v } : v;
  if (typeof pl !== 'object' || Array.isArray(pl)) throw invalidErr('place');
  const label = cleanLine(pl.label, 120);
  if (!label) return null;
  const out = { label };
  if (pl.familiePlaceId != null && (typeof pl.familiePlaceId === 'string' || Number.isSafeInteger(pl.familiePlaceId))) out.familiePlaceId = pl.familiePlaceId;
  if (Number.isFinite(pl.lat) && Number.isFinite(pl.lon) && Math.abs(pl.lat) <= 90 && Math.abs(pl.lon) <= 180) { out.lat = pl.lat; out.lon = pl.lon; }
  return out;
}

/**
 * `event` of a send body (Messenger 1.4.0) or — `partial: true` — of PATCH
 * messages/:id/event (only the fields given, plus `cancelled: true`).
 */
function normalizeEvent(e, { partial = false } = {}) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) throw invalidErr('event');
  const out = {};
  if (!partial || e.title !== undefined) {
    const title = cleanLine(e.title, 120);
    if (!title) throw invalidErr('event title');
    out.title = title;
  }
  if (!partial || e.startsAt !== undefined) {
    if (!isIso(e.startsAt)) throw invalidErr('event startsAt');
    out.startsAt = new Date(e.startsAt).toISOString();
  }
  if (e.endsAt !== undefined) {
    if (e.endsAt === null) out.endsAt = null;
    else if (!isIso(e.endsAt)) throw invalidErr('event endsAt');
    else out.endsAt = new Date(e.endsAt).toISOString();
    if (out.endsAt && out.startsAt && Date.parse(out.endsAt) < Date.parse(out.startsAt)) throw invalidErr('event endsAt');
  }
  if (typeof e.allDay === 'boolean') out.allDay = e.allDay;
  if (e.place !== undefined) out.place = normalizePlace(e.place);
  if (e.description !== undefined) {
    const d = typeof e.description === 'string' ? e.description.replace(/\r\n?/g, '\n').trim().slice(0, 1000) : '';
    out.description = d || null;
  }
  if (e.checklist !== undefined) {
    if (!Array.isArray(e.checklist)) throw invalidErr('event checklist');
    out.checklist = e.checklist.map((x) => cleanLine(typeof x === 'object' && x ? x.text : x, 80)).filter(Boolean).slice(0, 20);
  }
  for (const k of ['rsvp', 'guests', 'familyCalendar', 'departureHint']) if (typeof e[k] === 'boolean') out[k] = e[k];
  if (e.reminderMin !== undefined) {
    if (!REMINDER_MIN.includes(e.reminderMin)) throw invalidErr('event reminderMin');
    out.reminderMin = e.reminderMin;
  }
  if (partial && e.cancelled === true) out.cancelled = true;
  if (partial && !Object.keys(out).length) throw invalidErr('event patch');
  return out;
}

/** `action` of a send body (Messenger 1.4.0 home actions): run, request or grant. */
function normalizeAction(a) {
  if (!a || typeof a !== 'object' || Array.isArray(a)) throw invalidErr('action');
  if (!['run', 'request', 'grant'].includes(a.mode)) throw invalidErr('action mode');
  const actionId = typeof a.actionId === 'string' ? a.actionId.trim().slice(0, 200) : '';
  if (!actionId) throw invalidErr('action id');
  const out = { mode: a.mode, actionId };
  if (typeof a.plugin === 'string' && /^[a-z0-9][a-z0-9-]{0,80}$/.test(a.plugin)) out.plugin = a.plugin;
  const label = cleanLine(a.label, 80);
  if (label) out.label = label;
  if (a.mode === 'request' && Array.isArray(a.approverIds)) {
    const ids = [...new Set(a.approverIds.map(posInt).filter(Boolean))].slice(0, 256);
    if (ids.length) out.approverIds = ids;
  }
  if (a.mode === 'grant') {
    const g = a.grant && typeof a.grant === 'object' ? a.grant : {};
    const to = posInt(g.toUserId);
    if (!to || !isIso(g.until)) throw invalidErr('action grant');
    out.grant = { toUserId: to, until: new Date(g.until).toISOString() };
  }
  return out;
}

/**
 * A `PUT prefs` body from a patch: the booleans of 1.0 and the 1.4.0
 * sections privacy / notify / chats with known keys and values only
 * (anything else is dropped). → {} when nothing is left.
 */
function prefsBody(patch) {
  const p = patch && typeof patch === 'object' && !Array.isArray(patch) ? patch : {};
  const body = {};
  for (const k of ['readReceipts', 'typing', 'preview']) if (typeof p[k] === 'boolean') body[k] = p[k];
  for (const [section, rules] of Object.entries(PREF_RULES)) {
    const v = p[section];
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    const out = {};
    for (const [k, rule] of Object.entries(rules)) {
      if (v[k] === undefined) continue;
      if (rule === 'bool' ? typeof v[k] === 'boolean' : rule.includes(v[k])) out[k] = v[k];
    }
    if (Object.keys(out).length) body[section] = out;
  }
  return body;
}

/**
 * `PUT status` body (Messenger 1.4.0): preset, text ≤ 60 (preset `none`
 * needs one), until (future ISO), visibility (+ userIds for custom), eta and
 * destLabel for `away`. Throws code `invalid`.
 */
function statusBody(s, { textMax = 60, now = Date.now() } = {}) {
  const r = s && typeof s === 'object' && !Array.isArray(s) ? s : {};
  const preset = r.preset == null ? 'none' : r.preset;
  if (!STATUS_PRESETS.includes(preset)) throw invalidErr('status preset');
  const body = { preset };
  const text = cleanLine(r.text, textMax);
  if (text) body.text = text;
  if (preset === 'none' && !text) throw invalidErr('status text');
  if (r.until != null) {
    if (!isIso(r.until) || Date.parse(r.until) <= now) throw invalidErr('status until');
    body.until = new Date(r.until).toISOString();
  }
  Object.assign(body, audienceOf(r));
  if (preset === 'away') {
    if (r.eta != null && isIso(r.eta)) body.eta = new Date(r.eta).toISOString();
    const dest = cleanLine(r.destLabel, 80);
    if (dest) body.destLabel = dest;
  }
  return body;
}

/** { visibility, userIds } of a status / story (custom needs ≥ 1 user), or {} for the default. */
function audienceOf(r) {
  if (r.visibility == null) return {};
  if (!AUDIENCES.includes(r.visibility)) throw invalidErr('visibility');
  if (r.visibility !== 'custom') return { visibility: r.visibility };
  const ids = [...new Set((Array.isArray(r.userIds) ? r.userIds : []).map(posInt).filter(Boolean))].slice(0, 500);
  if (!ids.length) throw invalidErr('userIds');
  return { visibility: 'custom', userIds: ids };
}

/**
 * The story durations a server takes (Messenger 1.4.1): `limits.storyDurationsH`
 * limited to the known values, or all known values when it sends none.
 */
function storyDurationsOf(limits) {
  const src = limits && Array.isArray(limits.storyDurationsH) ? limits.storyDurationsH : null;
  const list = src ? STORY_DURATIONS_H.filter((h) => src.includes(h)) : [];
  return list.length ? list : STORY_DURATIONS_H.slice();
}

/**
 * `POST status/stories` body without the media ids (the service uploads the
 * files first): kind text (text required) / image / video, bg, font,
 * visibility, eventMessageId, place, video meta, and `durationH` — only when
 * `durations` (the allowed hours, Messenger 1.4.1) is given; another value
 * is refused, without `durations` it is left out (the server's 24 h).
 */
function storyBody(s, { textMax = 700, durations = null } = {}) {
  const r = s && typeof s === 'object' && !Array.isArray(s) ? s : {};
  if (!['text', 'image', 'video'].includes(r.kind)) throw invalidErr('story kind');
  const body = { kind: r.kind };
  const text = typeof r.text === 'string' ? r.text.replace(/\r\n?/g, '\n').trim().slice(0, textMax) : '';
  if (text) body.text = text;
  if (r.kind === 'text' && !text) throw invalidErr('story text');
  if (typeof r.bg === 'string' && COLOR_RE.test(r.bg)) body.bg = r.bg;
  if (['sans', 'serif', 'mono'].includes(r.font)) body.font = r.font;
  Object.assign(body, audienceOf(r));
  if (posInt(r.eventMessageId)) body.eventMessageId = posInt(r.eventMessageId);
  const place = cleanLine(r.place, 80);
  if (place) body.place = place;
  if (r.kind === 'video' && r.video && typeof r.video === 'object') {
    const v = {};
    if (Number.isFinite(r.video.durationMs) && r.video.durationMs >= 0) v.durationMs = Math.round(r.video.durationMs);
    if (Number.isSafeInteger(r.video.width) && r.video.width > 0) v.width = r.video.width;
    if (Number.isSafeInteger(r.video.height) && r.video.height > 0) v.height = r.video.height;
    if (Object.keys(v).length) body.video = v;
  }
  if (r.durationH != null && Array.isArray(durations)) {
    const h = Number(r.durationH);
    if (!durations.includes(h)) throw invalidErr('durationH');
    body.durationH = h;
  }
  return body;
}

/** Custom chat filters (`PUT lists`): ≤ 20, id [A-Za-z0-9_-]{1,40}, name 1…40, conversation ids. */
function listsBody(lists) {
  const src = Array.isArray(lists) ? lists : (lists && Array.isArray(lists.lists) ? lists.lists : null);
  if (!src) throw invalidErr('lists');
  const seen = new Set();
  const out = [];
  for (const l of src) {
    if (!l || typeof l !== 'object') continue;
    const id = typeof l.id === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(l.id) ? l.id : null;
    const name = cleanLine(l.name, 40);
    if (!id || !name || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name, conversationIds: [...new Set((Array.isArray(l.conversationIds) ? l.conversationIds : []).map(posInt).filter(Boolean))].slice(0, 1000) });
  }
  if (out.length > 20) throw invalidErr('lists');
  return out;
}

/** `integrations.familie` of `GET me` (Messenger 1.4.0) → { lists, calendar, places } booleans. */
function familieOf(me) {
  const f = me && me.integrations && me.integrations.familie && typeof me.integrations.familie === 'object' ? me.integrations.familie : {};
  return { lists: f.lists === true, calendar: f.calendar === true, places: f.places === true };
}

/**
 * A card link's route that the apps may open (another plugin's app route
 * plg-<id>, with Messenger 1.6 optionally followed by up to three path
 * segments: plg-gatecontrol-schule/messages/123) or null.
 */
function cardRoute(link) {
  const r = link && typeof link === 'object' && typeof link.route === 'string' ? link.route : '';
  return r.length <= 200 && ROUTE_RE.test(r) ? r : null;
}

/** A notification picture path of the own server (`/notify-media/<id>.<ext>`). */
const isNotifyMediaPath = (v) => typeof v === 'string' && NOTIFY_MEDIA_RE.test(v);

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
    // Messenger 1.4.0: pushes that are not "a new message" carry data.kind
    // (poll_nudge, event_reminder, event_departure, arrived, reminder,
    // action_approved, action_denied, reaction) and their own collapse_key.
    // Messenger 1.14: a message of a chat over a bridge (`data.bridge: "whatsapp"`)
    bridge: isBridgeNet(data.bridge) ? data.bridge : null,
    // Messenger 1.20: a post of a channel („<Kanal> · Kanal über WhatsApp“, only „Als gelesen“)
    channel: isBridgeNet(data.bridge) && data.channel === true,
    // Messenger 1.21: a message of a way of a person („Jenny Backes · über WhatsApp“) — a click opens the person's entry
    person: data.person && typeof data.person === 'object' && posInt(data.person.id) && posInt(data.person.conversationId)
      ? { id: posInt(data.person.id), conversationId: posInt(data.person.conversationId) } : null,
    pushKind: typeof data.kind === 'string' && /^[a-z_]{1,40}$/.test(data.kind) ? data.kind : null,
    deepLink: typeof data.deepLink === 'string' && /^[a-z_]{1,40}$/.test(data.deepLink) ? data.deepLink : null,
    reminderId: posInt(data.reminderId),
  };
}

// ── Messenger 1.13 / 1.14: linked services (bridges to other messengers) ──

/**
 * A push of „Verknüpfte Dienste“ (Messenger 1.17, topic `bridge`: „WhatsApp: Handy seit N Tagen nicht gesehen“,
 * data { deepLink: 'bridges', bridge }) → { type: 'bridges', bridge } — a click opens „Verknüpfte Dienste“ —
 * or null when the entry is none.
 */
function bridgePushContext(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {};
  const topic = typeof entry.topic === 'string' ? entry.topic : '';
  const ours = topic === BRIDGE_TOPIC || (topic.startsWith(`plugin:${PLUGIN_ID}:`) && data.deepLink === 'bridges');
  if (!ours) return null;
  return { type: 'bridges', bridge: typeof data.bridge === 'string' && BRIDGE_NET_RE.test(data.bridge) ? data.bridge : null };
}

// The services' own names (never translated); an id this version does not know shows as it is.
const BRIDGE_LABELS = Object.freeze({ whatsapp: 'WhatsApp' });
const bridgeLabel = (id) => BRIDGE_LABELS[id] || (typeof id === 'string' && id ? id.charAt(0).toUpperCase() + id.slice(1) : '');
const isBridgeNet = (v) => typeof v === 'string' && BRIDGE_NET_RE.test(v);
const isBridgeId = (v) => typeof v === 'string' && BRIDGE_ID_RE.test(v);

/**
 * A phone number as typed → '+<6–15 digits>' (spaces, brackets, dots, dashes
 * and slashes removed, a leading 00 becomes +), or null. It is sent once and
 * never kept or logged.
 */
function bridgePhone(raw) {
  let v = String(raw == null ? '' : raw).replace(/[\s()/.-]/g, '');
  if (v.startsWith('00')) v = `+${v.slice(2)}`;
  return /^\+[0-9]{6,15}$/.test(v) ? v : null;
}

/**
 * A phone number for a new chat over a bridge, as typed in the dialog → '+<country code><number>' or null:
 * spaces, brackets, dots, dashes and slashes go, a leading 00 becomes +, a number with + keeps its own country
 * code, any other gets `cc` (default +49) and loses its leading 0. 8–15 digits in all, the first one not 0
 * (+49: a mobile number has at least 10 after the country code).
 * The server checks it again; it is sent only on „Prüfen“ / „Chat starten“ and never kept or logged.
 */
function bridgeNumber(raw, cc = DEFAULT_CC) {
  const code = typeof cc === 'string' && /^\+[1-9][0-9]{0,3}$/.test(cc) ? cc : DEFAULT_CC;
  let v = String(raw == null ? '' : raw).trim().replace(/[\s()/.\u2010-\u2015-]/g, '');
  if (!v || v.length > 24) return null;
  if (v.startsWith('00')) v = `+${v.slice(2)}`;
  else if (!v.startsWith('+')) v = code + v.replace(/^0+/, '');
  if (!/^\+[1-9][0-9]{7,14}$/.test(v)) return null;
  // Germany: at least 6 digits after +49, a mobile number (015x, 016x, 017x) at least 10
  if (v.startsWith('+49')) {
    const nat = v.slice(3);
    if (nat.length < 6 || (/^1[5-7]/.test(nat) && nat.length < 10)) return null;
  }
  return v;
}

/**
 * `newChat` of a service in GET bridges (Messenger 1.16) → { available, reason, limit: { perHour, left, retryAfterS } | null },
 * or null when the server does not say (then the person's links decide alone).
 */
function normalizeNewChat(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const int = (x, max) => (Number.isSafeInteger(x) && x >= 0 && x <= max ? x : null);
  const l = v.limit && typeof v.limit === 'object' ? v.limit : null;
  const reason = typeof v.reason === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(v.reason) ? v.reason : null;
  return {
    available: v.available === true,
    reason: v.available === true ? null : reason,
    limit: l ? { perHour: int(l.perHour, 1000), left: int(l.left, 1000), retryAfterS: int(l.retryAfterS, 86400) || 0 } : null,
  };
}

/**
 * POST bridges/:network/resolve → { found, name, avatarMediaId, existing: { conversationId } | null }: is the number
 * at the service and under which name; `existing` (Messenger 1.16) = there is a chat with it already.
 */
function normalizeResolve(r) {
  const src = r && typeof r === 'object' ? r : {};
  const found = src.found === true;
  const name = found && typeof src.name === 'string' ? src.name.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, 120) || null : null;
  const ex = src.existing && typeof src.existing === 'object' ? posInt(src.existing.conversationId) : null;
  return { found, name, avatarMediaId: found && isMediaId(src.avatarMediaId) ? src.avatarMediaId : null, existing: found && ex ? { conversationId: ex } : null };
}

/**
 * Messenger 1.18: GET contacts/new-chat → { network, query, gatecontrol, whatsapp, addressBook, addressBookReason,
 * number, numberEntry, limit } — the three sections of „Neuer Chat“ (GateControl → WhatsApp → address book, each
 * null / empty when the server leaves it out). WhatsApp contacts carry a sealed `ref`, never a number; the numbers
 * of the address book are the person's own (sorted mobile, work, home, other). Nothing of it is kept or logged.
 */
function normalizeNewChatContacts(r) {
  const src = r && typeof r === 'object' ? r : {};
  const name = (v) => (typeof v === 'string' ? v.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, 120) : '');
  const int = (x, max) => (Number.isSafeInteger(x) && x >= 0 && x <= max ? x : null);
  // a picture's address as GET people gives it (absolute http(s) or a path of the server), nothing else
  const url = (v) => (typeof v === 'string' && v.length <= 2048 && (/^https?:\/\//i.test(v) || !/^[a-z][a-z0-9+.-]*:/i.test(v)) ? v : null);
  const state = (v) => (CONTACT_LIST_STATES.includes(v) ? v : 'unreachable');
  const gatecontrol = (Array.isArray(src.gatecontrol) ? src.gatecontrol : []).filter((p) => p && posInt(p.userId)).slice(0, 2000).map((p) => ({
    id: p.userId,
    userId: p.userId,
    name: name(p.name) || null,
    avatarUrl: url(p.avatarUrl),
    // whole characters (never half an emoji: a slice of UTF-16 units cut „M💕“ in the middle of the heart)
    initials: typeof p.initials === 'string' ? Array.from(p.initials).slice(0, 4).join('') || null : null,
    colorHex: typeof p.colorHex === 'string' && /^#[0-9a-fA-F]{6}$/.test(p.colorHex) ? p.colorHex : null,
    conversationId: posInt(p.conversationId),
  }));
  let whatsapp = null;
  const wa = src.whatsapp && typeof src.whatsapp === 'object' ? src.whatsapp : null;
  if (wa) {
    const items = (Array.isArray(wa.items) ? wa.items : []).filter((c) => c && typeof c.ref === 'string' && CONTACT_REF_RE.test(c.ref)).slice(0, 5000).map((c) => ({
      ref: c.ref,
      name: name(c.name) || null,
      avatarMediaId: isMediaId(c.avatarMediaId) ? c.avatarMediaId : null,
      avatarUrl: url(c.avatarUrl),
      conversationId: posInt(c.conversationId),
      alsoInAddressBook: c.alsoInAddressBook === true,
      addressBookId: posInt(c.addressBookId),
    }));
    const st = state(wa.state);
    whatsapp = { state: st, total: int(wa.total, 100000) != null ? wa.total : items.length, items: st === 'ok' ? items : [] };
  }
  let addressBook = null;
  const ab = whatsapp && src.addressBook && typeof src.addressBook === 'object' ? src.addressBook : null;
  if (ab) {
    const items = [];
    for (const x of (Array.isArray(ab.items) ? ab.items : []).slice(0, 5000)) {
      if (!x || !posInt(x.contactId)) continue;
      const phones = (Array.isArray(x.phones) ? x.phones : []).filter((p) => p && typeof p.key === 'string' && PHONE_KEY_RE.test(p.key) && typeof p.number === 'string' && p.number.trim()).slice(0, 20).map((p) => ({
        key: p.key,
        kind: PHONE_KINDS.includes(p.kind) ? p.kind : p.key.replace(/-.*/, ''),
        number: p.number.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, 40),
        e164: typeof p.e164 === 'string' && /^\+[1-9][0-9]{5,15}$/.test(p.e164) ? p.e164 : null,
        landline: p.landline === true,
        notOnNetwork: p.notOnNetwork === true,
      }));
      if (!phones.length) continue;
      phones.sort((a, b) => PHONE_KINDS.indexOf(a.kind) - PHONE_KINDS.indexOf(b.kind));
      items.push({ contactId: x.contactId, name: name(x.name) || null, conversationId: posInt(x.conversationId), phones });
    }
    addressBook = { state: whatsapp.state, total: int(ab.total, 100000) != null ? ab.total : items.length, items };
  }
  const n = src.number && typeof src.number === 'object' ? src.number : null;
  const number = n && typeof n.e164 === 'string' && /^\+[1-9][0-9]{5,15}$/.test(n.e164)
    ? { e164: n.e164, show: typeof n.show === 'string' && n.show.trim() ? n.show.trim().slice(0, 40) : n.e164, conversationId: posInt(n.conversationId) }
    : null;
  const l = src.limit && typeof src.limit === 'object' ? src.limit : null;
  return {
    network: isBridgeNet(src.network) ? src.network : null,
    query: typeof src.query === 'string' ? src.query.slice(0, CONTACTS_QUERY_MAX) : '',
    gatecontrol,
    whatsapp,
    addressBook,
    addressBookReason: typeof src.addressBookReason === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(src.addressBookReason) ? src.addressBookReason : null,
    number: whatsapp ? number : null,
    numberEntry: !!whatsapp && src.numberEntry === true,
    limit: l ? { perHour: int(l.perHour, 1000), left: int(l.left, 1000), retryAfterS: int(l.retryAfterS, 86400) || 0 } : null,
  };
}

/**
 * Messenger 1.18: what POST bridges/:network/chats gets for a contact of GET contacts/new-chat → { ref } (a WhatsApp
 * contact) or { contactId, phoneKind } (a number of the address book), or null.
 */
function contactChatBody(v) {
  const o = v && typeof v === 'object' ? v : {};
  if (typeof o.ref === 'string') return CONTACT_REF_RE.test(o.ref) ? { ref: o.ref } : null;
  const id = posInt(o.contactId);
  return id && typeof o.phoneKind === 'string' && PHONE_KEY_RE.test(o.phoneKind) ? { contactId: id, phoneKind: o.phoneKind } : null;
}

/** Messenger 1.20: is this conversation a channel of another messenger (`bridge.channel`, read only)? */
function isChannel(c) {
  return !!(c && c.bridge && typeof c.bridge === 'object' && c.bridge.channel === true);
}

/**
 * Messenger 1.20: `channels` of GET conversations?channels=1 → { count, unread } (channels with a post, their new
 * posts together), or null when the answer has none (an older plugin, a client without ?channels=1).
 */
function normalizeChannelSummary(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const int = (x) => (Number.isSafeInteger(x) && x >= 0 && x <= 1e6 ? x : 0);
  return { count: int(v.count), unread: int(v.unread) };
}

/**
 * Messenger 1.21 (chat_people): is this list entry a person — one entry for several ways (`person` { id, ways, reply, … };
 * its id is the lead conversation's)? Its routes are persons/:id/….
 */
function isPerson(c) {
  const p = c && c.person;
  return !!(p && typeof p === 'object' && posInt(p.id) && Array.isArray(p.ways) && p.ways.length);
}

/** The conversation ids of a person's ways (the entry itself when it is none). */
function personWayIds(c) {
  if (!isPerson(c)) return c && posInt(c.id) ? [c.id] : [];
  return [...new Set(c.person.ways.map((w) => posInt(w && w.conversationId)).filter(Boolean))];
}

/** The way an answer to the person takes (`person.reply`, the server's pick) → that entry of `person.ways`, or null. */
function personReplyWay(c) {
  if (!isPerson(c) || !c.person.reply) return null;
  const id = posInt(c.person.reply.conversationId);
  return c.person.ways.find((w) => w && posInt(w.conversationId) === id) || null;
}

/** The way of a message (`way`, sent with ?people=1) — 'gatecontrol' or a bridge's network, else null. */
function wayOf(m) {
  return m && typeof m.way === 'string' && WAY_RE.test(m.way) ? m.way : null;
}

/** POST persons { conversationIds, userId?, name? } from a client request, or null (merge by hand / a suggestion). */
function mergeBody(v) {
  const o = v && typeof v === 'object' ? v : {};
  const ids = [...new Set((Array.isArray(o.conversationIds) ? o.conversationIds : []).map(posInt).filter(Boolean))];
  if (!ids.length || ids.length > 6) return null;
  const body = { conversationIds: ids };
  if (o.userId != null) {
    const uid = posInt(o.userId);
    if (!uid) return null;
    body.userId = uid;
  }
  if (o.name === 'account') body.name = 'account';
  else if (o.name != null) {
    const nid = posInt(o.name);
    if (!nid) return null;
    body.name = nid;
  }
  return body;
}

/** A suggestion id of GET persons/suggestions („<conversationId>-<userId>“). */
function isSuggestionId(v) {
  return typeof v === 'string' && /^\d{1,15}-\d{1,15}$/.test(v);
}

/** GET bridges → recognition { available, network, asked, allowed } (gc.bridges version 9), else null. */
function normalizeRecognition(r) {
  if (!r || typeof r !== 'object' || r.available !== true) return null;
  return { available: true, network: isBridgeNet(r.network) ? r.network : 'whatsapp', asked: r.asked === true, allowed: r.allowed === true };
}

/** The kind a file goes out as over a bridge (like the plugin): image | voice | video (a file of video/*) | file. */
function bridgeOutKind(kind, mime) {
  if (kind === 'image' || kind === 'voice') return kind;
  return /^video\//.test(baseMime(mime) || '') ? 'video' : 'file';
}

/**
 * May a file go into a chat over a bridge (Messenger 1.15: `bridge.supports`, `bridge.mediaTypes`)?
 * → null (yes), 'text_only' (the chat takes no files of this kind) or the kind whose types it misses
 * ('image' | 'voice' | 'video' — 409 bridge_media_type at the server).
 */
function bridgeMediaRefusal(bridge, kind, mime) {
  const b = bridge && typeof bridge === 'object' ? bridge : {};
  const k = bridgeOutKind(kind, mime);
  if (!Array.isArray(b.supports) || !b.supports.includes(k)) return 'text_only';
  const types = b.mediaTypes && typeof b.mediaTypes === 'object' ? b.mediaTypes[k] : null;
  if (!Array.isArray(types)) return null;
  return types.includes(baseMime(mime)) ? null : k;
}

/**
 * `history` of GET bridges (Messenger 1.17) → { available, days, default, options, pending }, or null (a server
 * without older history: the row is left out). `days` / `options` only from 0, 30 and -1 (everything).
 */
function normalizeBridgeHistory(h) {
  if (!h || typeof h !== 'object' || Array.isArray(h)) return null;
  const day = (v) => (HISTORY_DAYS.includes(v) ? v : null);
  const options = (Array.isArray(h.options) ? h.options : HISTORY_DAYS).filter((v) => HISTORY_DAYS.includes(v));
  const uniq = [...new Set(options.length ? options : HISTORY_DAYS)];
  const days = day(h.days);
  return {
    available: h.available === true,
    days: days === null ? (day(h.default) === null ? 30 : day(h.default)) : days,
    default: day(h.default) === null ? 30 : day(h.default),
    options: uniq,
    pending: Number.isSafeInteger(h.pending) && h.pending > 0 ? h.pending : 0,
  };
}

/** `phone` of a service in GET bridges (Messenger 1.17) → { offline, days, leftDays } (days null when not offline). */
function normalizePhone(p) {
  const v = p && typeof p === 'object' && !Array.isArray(p) ? p : {};
  if (v.offline !== true) return { offline: false, days: null, leftDays: null };
  const int = (x) => (Number.isSafeInteger(x) && x >= 0 && x <= 100000 ? x : null);
  return { offline: true, days: int(v.days), leftDays: int(v.leftDays) };
}

/**
 * `GET bridges` → { available, location, networks: [{ id, state, allowed, lock, consent, outdated, clientOutdated,
 * version, wantVersion, logins, newChat, phone }], history }.
 */
function normalizeBridges(b) {
  const src = b && typeof b === 'object' ? b : {};
  const s = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
  const networks = (Array.isArray(src.networks) ? src.networks : []).filter((n) => n && isBridgeNet(n.id)).slice(0, 20).map((n) => ({
    id: n.id,
    state: s(n.state, 24) || 'unknown',
    allowed: n.allowed !== false,
    lock: n.lock === 'child' ? 'child' : null,
    consent: !!n.consent,
    outdated: n.outdated === true,
    // Messenger 1.17: WhatsApp turned the bridge's version away — shown like `outdated`
    clientOutdated: n.clientOutdated === true,
    version: s(n.version, 40),
    wantVersion: s(n.wantVersion, 40),
    logins: (Array.isArray(n.logins) ? n.logins : []).filter((l) => l && isBridgeId(l.id)).slice(0, 10).map((l) => ({
      id: l.id,
      name: s(l.name, 80) || '',
      state: BRIDGE_LOGIN_STATES.includes(l.state) ? l.state : 'unknown',
      since: s(l.since, 40),
    })),
    // Messenger 1.16: may the person start a chat by number here (only with the feature bridge_new_chat)
    newChat: normalizeNewChat(n.newChat),
    // Messenger 1.17: the bridge's warning — the phone was not seen for `days` (≥ 12) days
    phone: normalizePhone(n.phone),
  }));
  // Messenger 1.21: „Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?“ (only when GateControl has the call)
  const recognition = src.available === true ? normalizeRecognition(src.recognition) : null;
  return {
    available: src.available === true,
    location: src.location === 'gateway' ? 'gateway' : 'server',
    networks: src.available === true ? networks : [],
    // Messenger 1.17: older messages at a new link (null: the server has none)
    history: src.available === true ? normalizeBridgeHistory(src.history) : null,
    ...(recognition ? { recognition } : {}),
  };
}

/** `display.matrix` of a QR step → { size, rows: ['0101…'] } (square, only 0 / 1), or null. */
function normalizeQrMatrix(m) {
  if (!m || typeof m !== 'object' || !Array.isArray(m.rows)) return null;
  const size = m.rows.length;
  if (size < 21 || size > QR_MAX) return null;
  const re = new RegExp(`^[01]{${size}}$`);
  if (!m.rows.every((r) => typeof r === 'string' && re.test(r))) return null;
  return { size, rows: m.rows.slice() };
}

/**
 * `login` of POST bridges/:network/login[/…] → what the page shows next:
 *   { processId, waiting: true }                       the phone has not confirmed yet — ask again
 *   { processId, step: { id, type: 'complete' } }
 *   { processId, step: { id, type: 'phone', fieldId } } the number is asked for
 *   { processId, step: { id, type: 'code', code } }     the pairing code, then wait
 *   { processId, step: { id, type: 'qr', matrix } }     the QR code (drawn from its modules), then wait
 *   { processId, step: { id, type: 'unsupported' } }    a step this version cannot show
 * null when the answer names no process.
 */
function normalizeBridgeLogin(l) {
  const src = l && typeof l === 'object' ? l : {};
  if (!isBridgeId(src.processId)) return null;
  if (src.waiting === true) return { processId: src.processId, waiting: true };
  const st = src.step && typeof src.step === 'object' ? src.step : {};
  const id = isBridgeId(st.id) ? st.id : null;
  const none = { processId: src.processId, step: { id, type: 'unsupported' } };
  if (st.type === 'complete') return { processId: src.processId, step: { id, type: 'complete' } };
  if (!id) return none;
  if (st.type === 'user_input') {
    const f = (Array.isArray(st.fields) ? st.fields : []).find((x) => x && isBridgeId(x.id));
    return { processId: src.processId, step: { id, type: 'phone', fieldId: f ? f.id : 'phone_number' } };
  }
  if (st.type === 'display_and_wait') {
    const d = st.display && typeof st.display === 'object' ? st.display : {};
    if (d.type === 'qr') {
      const matrix = normalizeQrMatrix(d.matrix);
      return matrix ? { processId: src.processId, step: { id, type: 'qr', matrix } } : none;
    }
    if (d.type === 'code' && typeof d.data === 'string' && /^[A-Za-z0-9 -]{4,24}$/.test(d.data)) {
      return { processId: src.processId, step: { id, type: 'code', code: d.data } };
    }
  }
  return none;
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
  SHOWN_KINDS,
  FEATURES_14,
  KIND_FEATURE,
  PREF_RULES,
  STATUS_PRESETS,
  AUDIENCES,
  REMINDER_MIN,
  normalizePoll,
  normalizeEvent,
  normalizeAction,
  normalizePlace,
  prefsBody,
  statusBody,
  storyBody,
  storyDurationsOf,
  STORY_DURATIONS_H,
  STORY_DURATION_DEFAULT_H,
  listsBody,
  familieOf,
  cardRoute,
  PLUGIN_ID,
  CHAT_TOPIC,
  APP_ROUTE,
  API_BASE,
  MEDIA_BASE,
  PLUGINS_PATH,
  KINDS,
  MEDIA_KINDS,
  FEATURE_VIDEO_META,
  FEATURE_FILE_THUMBS,
  KNOWN_FEATURES,
  FEATURE_LINKED,
  FEATURE_BRIDGE_CHATS,
  FEATURE_BRIDGE_MEDIA,
  FEATURE_BRIDGE_NEW_CHAT,
  FEATURE_BRIDGE_CONTACTS,
  FEATURE_BRIDGE_CHANNELS,
  isChannel,
  normalizeChannelSummary,
  FEATURE_CHAT_PEOPLE,
  GC_WAY,
  byTimeOrder,
  isPerson,
  personWayIds,
  personReplyWay,
  wayOf,
  mergeBody,
  isSuggestionId,
  normalizeRecognition,
  CONTACTS_QUERY_MAX,
  normalizeNewChatContacts,
  contactChatBody,
  NEW_CHAT_REASONS,
  DEFAULT_CC,
  bridgeNumber,
  normalizeNewChat,
  normalizeResolve,
  bridgeOutKind,
  bridgeMediaRefusal,
  BRIDGE_FLOWS,
  isBridgeNet,
  isBridgeId,
  bridgeLabel,
  bridgePhone,
  normalizeBridges,
  normalizeBridgeHistory,
  normalizePhone,
  bridgePushContext,
  FEATURE_BRIDGE_HISTORY,
  HISTORY_DAYS,
  BRIDGE_TOPIC,
  normalizeQrMatrix,
  normalizeBridgeLogin,
  DELETE_SCOPES,
  EMOJI_MAX,
  TEXT_MAX,
  CLIENT_ID_RE,
  MEDIA_ID_RE,
  AVATAR_PATH_RE,
  NOTIFY_MEDIA_RE,
  isNotifyMediaPath,
  newClientId,
  isClientId,
  isMediaId,
  isAvatarPath,
  isApiPath,
  posInt,
  normalizeFeatures,
  hasFeature,
  unknownFeatures,
  isVideoMime,
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
