'use strict';

/**
 * „Videos umwandeln“ of the plugin `gatecontrol-medien` (from 1.6.0, app API v1 `v1/convert/…`, contract
 * „umwandeln-apps-vertrag“): the hint before playing a file this PC does not play directly. Pure, unit-tested; the
 * service (asking together, keeping, switching off) is services/media-convert.js.
 *
 *   itemId(raw)                     a Jellyfin item id as the plugin takes it (32 hex digits, lower case), else null
 *   statusOf(raw)                   GET v1/convert/status → { available, items: Map <id> → item } (`items`, else `states`)
 *   requestedOf(id, raw)            POST v1/convert/request → the item afterwards (requested)
 *   videoProblem(video, caps)       does the app's Chromium show the picture itself? null, or { code, codec }
 *   hintOf(problem, item, available) what the page says: null | { kind: 'offer' | 'requested' | 'queued' | 'running', … }
 *   switchesOff(err)                the refusals after which the plugin is not asked for a while (no route, no right, …)
 *
 * The picture on Windows (checked with the Electron of the Pro client): H.264 plays in every form — also High 10
 * (10 bit), 4:2:2 and 4:4:4. Chromium's hardware decoder (D3D11) takes only 8-bit H.264, for the rest Chromium falls back
 * to its own software decoder (FFmpeg); 1080p50 in 10 bit runs smoothly on a usual PC. So H.264 10-bit, the plugin's
 * most common finding („h264_10bit“, its Windows column says „no“), plays directly here and gets no hint. What Chromium
 * does not show itself — Jellyfin converts the picture on the NAS — is HEVC without the hardware decoder, AV1 without a
 * decoder, MPEG-2 / VC-1 / MPEG-4 ASP / WMV and other old codecs, Dolby Vision without a fallback, HDR on an SDR screen.
 *
 * The hint (Windows, decision of the task): only when the picture is converted here (videoProblem) AND the plugin knows
 * the file. `queued` / `running` say so, `done` says nothing (it plays directly now); `requested` says „vorgemerkt“.
 * „Für heute Nacht vormerken“ (state `none`) only when the plugin rates the file `convert` — the NAS does not convert
 * it smoothly while playing — and a gateway can convert (`available`). A `hint` file the NAS converts live without
 * trouble, so there is nothing to offer. Playing stays possible always.
 */

const MAX_IDS = 100;
const HEX32_RE = /^[0-9a-f]{32}$/;
const STATES = new Set(['none', 'queued', 'running', 'done']);
const LEVELS = new Set(['convert', 'hint', 'info']);
const SWITCH_OFF_CODES = new Set(['no_access', 'license_required', 'plugin_unavailable', 'not_found', 'forbidden']);

/** Video codecs Chromium shows itself (HEVC and AV1 only with a decoder: caps). */
const PLAIN_CODECS = new Set(['h264', 'avc', 'vp8', 'vp9']);
const HDR_TYPES = new Set(['HDR10', 'HDR10Plus', 'HLG', 'DOVIWithHDR10', 'DOVIWithHLG', 'DOVIWithEL', 'DOVIWithHDR10Plus', 'DOVIWithELHDR10Plus', 'DOVIInvalid']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** `raw` as a Jellyfin item id the plugin takes (32 hex digits, lower case, without dashes); null: not one. */
function itemId(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().replace(/-/g, '').toLowerCase();
  return HEX32_RE.test(s) ? s : null;
}

function int(v) { return Number.isInteger(v) ? v : null; }

function time(v) {
  if (typeof v !== 'string' || v.length > 40) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

/** One file of the answer; `base` fills what `o` leaves out (`states` over `items`). */
function itemOf(id, o, base = null) {
  const b = base || {};
  const state = STATES.has(o.state) ? o.state : b.state || 'none';
  const position = int(o.position) !== null ? o.position : b.position;
  const startsAt = time(o.startsAt) !== null ? time(o.startsAt) : b.startsAt;
  const percent = Number.isFinite(o.percent) ? o.percent : b.percent;
  const level = LEVELS.has(o.level) ? o.level : LEVELS.has(b.level) ? b.level : null;
  return {
    id,
    state,
    position: state === 'queued' && Number.isInteger(position) && position > 0 ? position : null,
    startsAt: state === 'queued' && Number.isFinite(startsAt) ? startsAt : null,
    percent: state === 'running' && Number.isFinite(percent) ? Math.round(Math.min(100, Math.max(0, percent))) : null,
    requested: typeof o.requested === 'boolean' ? o.requested : b.requested === true,
    level,
  };
}

/** `GET v1/convert/status`: { available, items: Map <id> → { id, state, position, startsAt (ms), percent, requested, level } }. */
function statusOf(raw) {
  const o = isObj(raw) ? raw : {};
  const items = new Map();
  for (const e of Array.isArray(o.items) ? o.items : []) {
    if (!isObj(e)) continue;
    const id = itemId(e.id);
    if (id) items.set(id, itemOf(id, e));
  }
  if (isObj(o.states)) {
    for (const [key, v] of Object.entries(o.states)) {
      const id = itemId(key);
      if (id && isObj(v)) items.set(id, itemOf(id, v, items.get(id)));
    }
  }
  return { available: o.available === true, items };
}

/** `POST v1/convert/request` for `id`: the file afterwards (requested), `before` keeps its level. */
function requestedOf(id, raw, before = null) {
  const o = isObj(raw) ? raw : {};
  return { ...itemOf(id, o, before), requested: true };
}

/**
 * Whether the app's Chromium shows the picture of `video` (a Jellyfin video stream: codec, videoRange, videoRangeType)
 * itself with `caps` (utils/media-jellyfin.js capsOf). null: it does (H.264 in every bit depth, VP8/VP9, HEVC / AV1 with
 * a decoder, SDR or HDR on an HDR screen); else { code: 'hevc' | 'av1' | 'video_codec' | 'dovi' | 'hdr', codec }.
 */
function videoProblem(video, caps = {}) {
  if (!isObj(video)) return null;
  const codec = typeof video.codec === 'string' ? video.codec.toLowerCase() : '';
  if (!codec) return null;
  const c = caps || {};
  if (codec === 'hevc' || codec === 'h265') {
    if (c.hevc !== true) return { code: 'hevc', codec: 'hevc' };
  } else if (codec === 'av1') {
    if (c.av1 === false) return { code: 'av1', codec };
  } else if (!PLAIN_CODECS.has(codec)) {
    return { code: 'video_codec', codec };
  }
  const type = typeof video.videoRangeType === 'string' ? video.videoRangeType : '';
  // Dolby Vision without a fallback layer: Chromium has no Dolby Vision, only the NAS's tone-mapping gives right colours
  if (type === 'DOVI') return { code: 'dovi', codec };
  const hdr = HDR_TYPES.has(type) || video.videoRange === 'HDR';
  if (hdr && c.hdr !== true) return { code: 'hdr', codec };
  return null;
}

/**
 * The hint for a file whose picture is converted here (`problem`: videoProblem; null → no hint), by the plugin's
 * `item` (statusOf; null: not known → no hint) and whether a gateway converts (`available`).
 * → null | { kind: 'offer' } | { kind: 'requested' } | { kind: 'queued', position, startsAt } | { kind: 'running', percent }
 */
function hintOf(problem, item, available) {
  if (!problem || !isObj(item)) return null;
  switch (item.state) {
    case 'done': return null;
    case 'queued': return { kind: 'queued', position: item.position || null, startsAt: item.startsAt || null };
    case 'running': return { kind: 'running', percent: Number.isFinite(item.percent) ? item.percent : null };
    default:
      if (item.requested === true) return { kind: 'requested' };
      if (available === true && item.level === 'convert') return { kind: 'offer' };
      return null;
  }
}

/** No route (plugin before 1.6.0: 404), no right „Medien“, no licence, the plugin off: not asked again for a while. */
function switchesOff(err) {
  if (!err) return false;
  if (err.status === 404 || err.status === 403) return true;
  return SWITCH_OFF_CODES.has(err.code);
}

/** "1.6.0" ≥ 1.6? Unknown (null): asked (the route's 404 decides). */
function versionOk(version) {
  if (typeof version !== 'string' || !version) return true;
  const m = /^(\d+)\.(\d+)/.exec(version.trim());
  if (!m) return true;
  const [maj, min] = [Number(m[1]), Number(m[2])];
  return maj > 1 || (maj === 1 && min >= 6);
}

module.exports = { MAX_IDS, itemId, statusOf, requestedOf, videoProblem, hintOf, switchesOff, versionOk };
