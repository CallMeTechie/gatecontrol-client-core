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
]);
// Messenger 1.4.0 `GET me` features (README "Since 1.4.0").
const FEATURES_14 = Object.freeze({
  status: 'status', stories: 'stories', polls: 'polls', events: 'events', arrival: 'arrival', actions: 'actions', tools: 'msg_tools', privacy: 'privacy2',
});
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
// An app route of another plugin (card link): plg-<id>.
const ROUTE_RE = /^plg-[a-z0-9]+(?:-[a-z0-9]+)*$/;
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
 * `POST status/stories` body without the media ids (the service uploads the
 * files first): kind text (text required) / image / video, bg, font,
 * visibility, eventMessageId, place, video meta.
 */
function storyBody(s, { textMax = 700 } = {}) {
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

/** A card link's route that the apps may open (another plugin's app route plg-<id>) or null. */
function cardRoute(link) {
  const r = link && typeof link === 'object' && typeof link.route === 'string' ? link.route : '';
  return ROUTE_RE.test(r) && r.length <= 80 ? r : null;
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
    // Messenger 1.4.0: pushes that are not "a new message" carry data.kind
    // (poll_nudge, event_reminder, event_departure, arrived, reminder,
    // action_approved, action_denied, reaction) and their own collapse_key.
    pushKind: typeof data.kind === 'string' && /^[a-z_]{1,40}$/.test(data.kind) ? data.kind : null,
    deepLink: typeof data.deepLink === 'string' && /^[a-z_]{1,40}$/.test(data.deepLink) ? data.deepLink : null,
    reminderId: posInt(data.reminderId),
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
