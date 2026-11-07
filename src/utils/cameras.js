'use strict';

/**
 * Pure helpers of "Kameras im Heimnetz" (plugin `gatecontrol-door` 1.6.0,
 * "Tür & Kamera"; contract: the plugin's README "Kameras im Heimnetz", the
 * gateway's docs/cameras.md §7/§8 and GateControl's docs/plugins.md
 * "Cameras"): paths, argument checks, cleaned answers of
 *
 *   GET cameras/home                      → the home cameras this person sees
 *   GET cameras/home/<id>/live            → live video (VPN / LAN) or a still every 10 s
 *   GET cameras/home/<id>/still           → a still as base64 JPEG (≤ 700 KB)
 *   GET cameras/home/<id>/clips[?day=]    → the clips of a day
 *
 * and the context of a camera push (topic `kamera`, data.door.type
 * `home_camera_event`).
 *
 * Media addresses: the server answers relative `/camera-media/<token>/<file>`
 * paths (no login, the token is the permission, 10 min; clips 1 h). They
 * reach the renderer only as `gccam://media/<token>/<file>` — the app serves
 * that scheme from the main process with the client's connection to its own
 * server (services/cameras.js handleProtocol), so the page never needs the
 * server's origin in its CSP and nothing else can be fetched through it.
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * enums checked, ids `c…` / `e…` as the gateway makes them.
 */

const PLUGIN_ID = 'gatecontrol-door';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
// The plugin's push topic "Personen an der Kamera" (gc.notify topic `kamera`).
const TOPIC = `plugin:${PLUGIN_ID}:kamera`;
const PUSH_TYPE = 'home_camera_event';
const SCHEME = 'gccam';
const MEDIA_HOST = 'media';
// Plugin version with "Kameras im Heimnetz"; GateControl 1.240.0 with gc.cameras.
const MIN_PLUGIN = '1.6.0';

const CAM_ID_RE = /^c[0-9a-f]{15}$/;
const EVENT_ID_RE = /^e[0-9a-f]{15}$/;
const TOKEN = '[A-Za-z0-9_-]{16,400}\\.[A-Za-z0-9_-]{43}';
const FILE = '(?:snapshot\\.jpg|index\\.m3u8|init\\.mp4|s\\d{1,9}\\.m4s|live\\.mp4|clip\\.mp4|thumb\\.jpg)';
const MEDIA_PATH_RE = new RegExp(`^/camera-media/(${TOKEN})/(${FILE})$`);
const MEDIA_URL_PATH_RE = new RegExp(`^/(${TOKEN})/(${FILE})$`);
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const CTRL_RE = /[\u0000-\u001F\u007F]/g;

const KINDS = ['person', 'vehicle', 'animal', 'motion'];
const STATES = ['ok', 'unreachable', 'auth_failed', 'not_allowed', 'no_stream', 'error'];
const RECORD = ['motion', 'away', 'never'];
const SOURCES = ['onvif', 'rtsp'];
const EVENT_STATES = ['pullpoint', 'unsupported', 'off', 'error'];
// Content types of the media files (the scheme sets them itself, never the server's).
const TYPES = { jpg: 'image/jpeg', mp4: 'video/mp4', m4s: 'video/iso.segment', m3u8: 'application/vnd.apple.mpegurl' };
const STILL_MAX = 1024 * 1024; // base64 of a JPEG ≤ 700 KB
const MAX_CAMERAS = 64;
const MAX_CLIPS = 200;
const EVERY_DEFAULT = 10;

/** Trimmed single-line string ≤ max, or null. */
function line(v, max) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const s = String(v).replace(CTRL_RE, ' ').trim().slice(0, max);
  return s || null;
}

/** ms timestamp from a number or an ISO string, or null. */
function msOf(v) {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return Math.round(v);
  if (typeof v === 'string' && v) {
    const t = Date.parse(v);
    if (Number.isFinite(t)) return t;
  }
  return null;
}

const isCameraId = (v) => typeof v === 'string' && CAM_ID_RE.test(v);
const isEventId = (v) => typeof v === 'string' && EVENT_ID_RE.test(v);
const oneOf = (v, list) => (list.includes(v) ? v : null);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/** 'YYYY-MM-DD' of a real calendar day? */
function isDate(v) {
  if (typeof v !== 'string') return false;
  const m = DATE_RE.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
}

/** ?day= of clips: undefined (the plugin's today) or a real date; null when invalid. */
function dayArg(v) {
  if (v === undefined || v === null || v === '') return undefined;
  return isDate(v) ? v : null;
}

/** Semver compare (major.minor.patch): a < b → -1. */
function cmpVersion(a, b) {
  const pa = String(a || '').split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  const pb = String(b || '').split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1;
  return 0;
}

/** Does this plugin version have home cameras? true / false / null (unknown version). */
function homeSupported(version) {
  if (typeof version !== 'string' || !/^\d+\.\d+/.test(version)) return null;
  return cmpVersion(version, MIN_PLUGIN) >= 0;
}

// ── Media addresses ─────────────────────────────────────────

/** `/camera-media/<token>/<file>` of the own server → `gccam://media/<token>/<file>`, else null. */
function mediaUrl(path) {
  if (typeof path !== 'string' || path.length > 600) return null;
  const m = MEDIA_PATH_RE.exec(path);
  return m ? `${SCHEME}://${MEDIA_HOST}/${m[1]}/${m[2]}` : null;
}

/**
 * A `gccam:` URL of the renderer → { path: '/camera-media/<token>/<file>', file, ext, type }
 * or null. The query (`?t=<n>` against caching) is dropped: the server sends no-store anyway.
 */
function parseMediaUrl(url) {
  if (typeof url !== 'string' || url.length > 700) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== `${SCHEME}:` || u.hostname !== MEDIA_HOST || u.username || u.password || u.port) return null;
  const m = MEDIA_URL_PATH_RE.exec(u.pathname);
  if (!m) return null;
  const ext = m[2].split('.').pop();
  return { path: `/camera-media/${m[1]}/${m[2]}`, file: m[2], ext, type: TYPES[ext] || 'application/octet-stream' };
}

/** A Range header worth passing on (`bytes=a-b`, one range), else null. */
function rangeOf(v) {
  return typeof v === 'string' && /^bytes=\d{0,15}-\d{0,15}$/.test(v.trim()) && v.trim() !== 'bytes=-' ? v.trim() : null;
}

// ── Answers ─────────────────────────────────────────────────

function kindsOf(v) {
  return Array.isArray(v) ? [...new Set(v.filter((k) => KINDS.includes(k)))] : [];
}

function settingsOf(v) {
  const s = obj(v);
  const days = Number.isSafeInteger(s.retentionDays) && s.retentionDays >= 1 && s.retentionDays <= 90 ? s.retentionDays : null;
  return { record: oneOf(s.record, RECORD) || 'motion', events: kindsOf(s.events), retentionDays: days, stream: s.stream === 'sub' ? 'sub' : 'main', audio: s.audio === true };
}

/** One camera of GET cameras/home (never its address or the camera account). */
function normalizeCamera(c) {
  if (!c || typeof c !== 'object' || !isCameraId(c.id)) return null;
  const ev = obj(c.events);
  return {
    id: c.id,
    kind: 'home',
    name: line(c.name, 60) || c.id,
    gateway: line(c.gateway, 60),
    model: line(c.model, 80),
    source: oneOf(c.source, SOURCES),
    state: oneOf(c.state, STATES),
    online: c.online === true,
    codec: c.codec === 'h264' || c.codec === 'h265' ? c.codec : null,
    events: { supported: ev.supported === true ? true : ev.supported === false ? false : null, state: oneOf(ev.state, EVENT_STATES), kinds: kindsOf(ev.kinds) },
    settings: settingsOf(c.settings),
    push: c.push !== false,
    snapshotUrl: mediaUrl(c.snapshotUrl),
    snapshotAt: msOf(c.snapshotAt),
    lastEventAt: msOf(c.lastEventAt),
  };
}

/** GET cameras/home → { supported, minGatecontrol, every, cameras } */
function normalizeList(raw) {
  const r = obj(raw);
  const seen = new Set();
  const cameras = [];
  for (const c of Array.isArray(r.cameras) ? r.cameras : []) {
    const v = normalizeCamera(c);
    if (!v || seen.has(v.id)) continue;
    seen.add(v.id);
    cameras.push(v);
    if (cameras.length >= MAX_CAMERAS) break;
  }
  return {
    supported: r.supported === true,
    minGatecontrol: typeof r.minGatecontrol === 'string' && /^\d+\.\d+\.\d+$/.test(r.minGatecontrol) ? r.minGatecontrol : null,
    every: everyOf(r.every),
    cameras: r.supported === true ? cameras : [],
  };
}

function everyOf(v) {
  return Number.isSafeInteger(v) && v >= 5 && v <= 60 ? v : EVERY_DEFAULT;
}

/**
 * GET cameras/home/<id>/live → `live`:
 *   { mode: 'live', via, ready, mp4, hls, snapshot, codec, audio, every, expiresAt }   (VPN / LAN)
 *   { mode: 'snapshot', snapshot, every, reason, via }                                 (otherwise)
 * A live answer without a playable address falls back to the still. null: nothing usable.
 */
function normalizeLive(raw) {
  const l = obj(obj(raw).live);
  const snapshot = mediaUrl(l.snapshot);
  const every = everyOf(l.every);
  const via = oneOf(l.via, ['vpn', 'lan', 'internet']);
  if (l.mode === 'live') {
    const mp4 = mediaUrl(l.mp4);
    const hls = mediaUrl(l.hls);
    if (mp4 || hls) {
      return {
        mode: 'live', via, ready: l.ready !== false, mp4, hls, snapshot, every,
        codec: line(l.codec, 80), audio: l.audio === true, expiresAt: msOf(l.expiresAt),
      };
    }
  }
  if (!snapshot) return null;
  return { mode: 'snapshot', snapshot, every, reason: line(l.reason, 40) || (l.mode === 'live' ? null : 'vpn_required'), via };
}

/** GET cameras/home/<id>/still → { mime, data: Buffer, at } or null. */
function normalizeStill(raw) {
  const s = obj(obj(raw).still);
  if (typeof s.data !== 'string' || !s.data || s.data.length > STILL_MAX || !B64_RE.test(s.data)) return null;
  const data = Buffer.from(s.data, 'base64');
  // JPEG only (FF D8 FF)
  if (data.length < 4 || data[0] !== 0xff || data[1] !== 0xd8 || data[2] !== 0xff) return null;
  return { mime: 'image/jpeg', data, at: msOf(s.at) };
}

/** One clip of GET cameras/home/<id>/clips. */
function normalizeClip(e) {
  if (!e || typeof e !== 'object' || !isEventId(e.id)) return null;
  const kinds = kindsOf(e.kinds);
  const kind = oneOf(e.kind, KINDS) || kinds[0] || 'motion';
  return {
    id: e.id,
    cameraId: isCameraId(e.cameraId) ? e.cameraId : null,
    camera: line(e.camera, 60),
    kind,
    kinds: kinds.length ? kinds : [kind],
    startedAt: msOf(e.startedAt),
    endedAt: msOf(e.endedAt),
    nobodyHome: e.nobodyHome === true ? true : e.nobodyHome === false ? false : null,
    ms: Number.isSafeInteger(e.ms) && e.ms > 0 ? e.ms : null,
    thumbUrl: mediaUrl(e.thumbUrl),
    clipUrl: mediaUrl(e.clipUrl),
  };
}

/** GET cameras/home/<id>/clips → { day, clips } (newest first). */
function normalizeClips(raw) {
  const r = obj(raw);
  const seen = new Set();
  const clips = [];
  for (const e of Array.isArray(r.clips) ? r.clips : []) {
    const v = normalizeClip(e);
    if (!v || !v.startedAt || seen.has(v.id)) continue;
    seen.add(v.id);
    clips.push(v);
    if (clips.length >= MAX_CLIPS) break;
  }
  clips.sort((a, b) => b.startedAt - a.startedAt);
  return { day: isDate(r.day) ? r.day : null, clips };
}

// ── Push ────────────────────────────────────────────────────

/**
 * A camera push (topic `kamera` of the plugin, data.door.type `home_camera_event`)
 * → { cameraId, eventId } or null (any other push — Ring doorbell / motion,
 * locks — stays as it is).
 */
function pushContext(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const data = obj(entry.data);
  const door = obj(data.door);
  const topic = typeof entry.topic === 'string' ? entry.topic : '';
  if (door.type !== PUSH_TYPE || (topic && topic !== TOPIC)) return null;
  if (!isCameraId(door.cameraId)) return null;
  return { cameraId: door.cameraId, eventId: isEventId(door.eventId) ? door.eventId : null };
}

/** "Einfahrt 2026-11-07 14-02-31.jpg" — a still's file name (local time). */
function stillFileName(name, at) {
  const d = new Date(Number.isFinite(at) ? at : Date.now());
  const p = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}-${p(d.getMinutes())}-${p(d.getSeconds())}`;
  const base = String(name || 'Kamera').replace(/[\u0000-\u001f<>:"/\\|?*\u007f]/g, '_').replace(/^[\s.]+|[\s.]+$/g, '').slice(0, 60) || 'Kamera';
  return `${base} ${stamp}.jpg`;
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  API_BASE,
  TOPIC,
  PUSH_TYPE,
  SCHEME,
  MEDIA_HOST,
  MIN_PLUGIN,
  KINDS,
  TYPES,
  isCameraId,
  isEventId,
  isDate,
  dayArg,
  homeSupported,
  mediaUrl,
  parseMediaUrl,
  rangeOf,
  normalizeCamera,
  normalizeList,
  normalizeLive,
  normalizeStill,
  normalizeClip,
  normalizeClips,
  pushContext,
  stillFileName,
};
