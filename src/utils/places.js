'use strict';

/**
 * „Meine Orte“ (GateControl ≥ 1.299.0: Mein Profil › Meine Orte) — pure helpers of services/places.js and its IPC.
 *
 * Contract (gatecontrol docs/feature-user-profile.md „Meine Orte“), device token, always the person signed in:
 *
 *   GET    /api/v1/client/me/profile/places            → { ok, places, family, limits, options, search: osm|own|off }
 *   POST   /api/v1/client/me/profile/places            { name, lat, lon, icon?, radiusM?, address?, visibility? } → 201 { ok, place }
 *   PATCH  /api/v1/client/me/profile/places/:id        the same fields, all optional; lat and lon only together; address null clears
 *   DELETE /api/v1/client/me/profile/places/:id[?force=1]  → { ok, deleted, id } | 409 { code: 'IN_USE', usedBy }
 *   POST   /api/v1/client/me/profile/places/:id/used   → { ok, place } (lastUsedAt)
 *   GET    /api/v1/client/me/places/search?q=&near=lat,lon → { ok, results: [{ name, address, lat, lon, source, distanceM? }], attribution }
 *
 * A place: { id, ref: 'profile:<id>', name, icon, lat, lon, radiusM, address, visibility, source, usedBy, updatedAt,
 * lastUsedAt }. A point is never 0/0; an answer without a usable point is kept as „kein Standort“ (lat / lon null).
 * Everything the renderer sends is checked here before it reaches the network: only the keys the server knows (an
 * unknown key is a 400 there), a search only from 3 characters and `near` rounded to two places (~1 km) on this PC.
 */

const API_BASE = '/api/v1/client/me/';
const PLACES_PATH = `${API_BASE}profile/places`;
const SEARCH_PATH = `${API_BASE}places/search`;

const ICONS = Object.freeze(['home', 'work', 'school', 'gym', 'shop', 'family', 'pin']);
const VISIBILITY = Object.freeze(['self', 'family', 'all']);
const SEARCH_MODES = Object.freeze(['osm', 'own', 'off']);
const SOURCES = Object.freeze(['manual', 'notizen', 'familie', 'messenger']);
const LIMITS = Object.freeze({ places: 100, name: 60, address: 200, radius: Object.freeze({ min: 50, max: 2000, default: 150 }) });
const SEARCH_MIN = 3;
const SEARCH_MAX = 120;
const HITS_MAX = 8;
const LIST_MAX = 200;
const USED_BY_MAX = 50;
const OSM_ATTRIBUTION = Object.freeze({ text: '© OpenStreetMap', url: 'https://www.openstreetmap.org/copyright' });

// `profile:<id>` of the profile; Familie's `home` / `place:<id>` (Messenger 1.28, Familie 1.30 use the same pattern)
const PROFILE_REF_RE = /^profile:([1-9][0-9]{0,15})$/;
const ANY_REF_RE = /^(?:profile:[1-9][0-9]{0,15}|home|place:[1-9][0-9]{0,15})$/;
const PLUGIN_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KIND_RE = /^[a-z][a-z0-9_.-]{0,39}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/;
// eslint-disable-next-line no-control-regex
const CTRL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);
const posId = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);

/** Number or decimal string → finite number, else null. */
function num(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && /^\s*-?\d+(?:\.\d+)?\s*$/.test(v)) return Number(v);
  return null;
}

/** One line: control characters → spaces, spaces folded, trimmed, at most `max` (the server's name rule). */
function line(v, max) {
  if (typeof v !== 'string') return '';
  return v.replace(CTRL_RE, ' ').replace(/\s+/g, ' ').trim().slice(0, max).trim();
}

/** A real point: within range and never 0/0 (what an empty position turns into). */
function hasPoint(lat, lon) {
  return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && !(lat === 0 && lon === 0);
}

const round6 = (v) => Math.round(v * 1e6) / 1e6;
const round2 = (v) => Math.round(v * 100) / 100;

function clampRadius(v, limits = LIMITS) {
  const r = limits.radius || LIMITS.radius;
  const n = num(v);
  return n === null ? r.default : Math.min(r.max, Math.max(r.min, Math.round(n)));
}

const iconOf = (v) => (ICONS.includes(v) ? v : 'pin');
const visibilityOf = (v) => (VISIBILITY.includes(v) ? v : 'self');

/** 'profile:<id>' → id, else null. */
function idOfRef(ref) {
  const m = typeof ref === 'string' ? PROFILE_REF_RE.exec(ref) : null;
  return m ? Number(m[1]) : null;
}
const refOf = (id) => (posId(id) ? `profile:${id}` : null);
const isRef = (v) => typeof v === 'string' && ANY_REF_RE.test(v);

/** GateControl's 'YYYY-MM-DD HH:MM:SS' (UTC) or ISO 8601 → ISO string, else null. */
function timeOf(v) {
  if (typeof v !== 'string' || !TIME_RE.test(v)) return null;
  const s = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(v) ? `${v.replace(' ', 'T')}Z` : v;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** One entry of „Genutzt von“ → { plugin, pluginName, kind, count } or null. */
function normalizeUse(v) {
  const o = obj(v);
  if (!o || typeof o.plugin !== 'string' || !PLUGIN_RE.test(o.plugin) || typeof o.kind !== 'string' || !KIND_RE.test(o.kind)) return null;
  const count = num(o.count);
  if (count === null || count <= 0) return null;
  return { plugin: o.plugin, pluginName: line(o.pluginName, 60) || null, kind: o.kind, count: Math.min(1000000, Math.round(count)) };
}

const usedByOf = (v) => arr(v).slice(0, USED_BY_MAX).map(normalizeUse).filter(Boolean);

/**
 * One place of an answer → cleaned, or null without an id or a name. A point out of range (or 0/0) is kept as
 * „kein Standort“ (lat / lon null, hasPoint false).
 */
function normalizePlace(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const name = o && line(o.name, LIMITS.name);
  if (!id || !name) return null;
  const lat = num(o.lat);
  const lon = num(o.lon);
  const point = hasPoint(lat, lon);
  const out = {
    id, ref: refOf(id), name, icon: iconOf(o.icon),
    lat: point ? lat : null, lon: point ? lon : null, hasPoint: point,
    radiusM: clampRadius(o.radiusM),
    address: line(o.address, LIMITS.address) || null,
    visibility: visibilityOf(o.visibility),
    source: SOURCES.includes(o.source) ? o.source : 'manual',
    usedBy: usedByOf(o.usedBy),
    updatedAt: timeOf(o.updatedAt),
    lastUsedAt: timeOf(o.lastUsedAt),
    own: o.own !== false,
  };
  if (o.own === false) {
    out.ownerId = posId(o.ownerId);
    out.ownerName = line(o.ownerName, 120) || null;
    out.usedBy = [];
  }
  return out;
}

/** `limits` of the list answer, with the contract's defaults. */
function limitsOf(v) {
  const o = obj(v) || {};
  const r = obj(o.radius) || {};
  const int = (x, d, lo, hi) => { const n = num(x); return n === null ? d : Math.min(hi, Math.max(lo, Math.round(n))); };
  const min = int(r.min, LIMITS.radius.min, 10, 10000);
  const max = int(r.max, LIMITS.radius.max, min, 100000);
  return {
    places: int(o.places, LIMITS.places, 0, 10000),
    name: int(o.name, LIMITS.name, 1, 200),
    address: int(o.address, LIMITS.address, 0, 1000),
    radius: { min, max, default: int(r.default, LIMITS.radius.default, min, max) },
  };
}

/** GET profile/places → { places, family, limits, icons, visibility, search, shared }; null when it is no such answer. */
function normalizeList(v) {
  const o = obj(v);
  if (!o || !Array.isArray(o.places)) return null;
  const seen = new Set();
  const places = [];
  for (const p of o.places.slice(0, LIST_MAX * 2).map(normalizePlace)) {
    if (!p || seen.has(p.id)) continue;
    seen.add(p.id);
    places.push(p);
    if (places.length >= LIST_MAX) break;
  }
  const opts = obj(o.options) || {};
  const icons = arr(opts.icons).filter((x) => ICONS.includes(x));
  const vis = arr(opts.visibility).filter((x) => VISIBILITY.includes(x));
  const out = {
    places,
    family: o.family === true,
    limits: limitsOf(o.limits),
    icons: icons.length ? icons : [...ICONS],
    visibility: vis.length ? vis : [...VISIBILITY],
    search: SEARCH_MODES.includes(o.search) ? o.search : 'off',
  };
  if (Array.isArray(o.shared)) out.shared = o.shared.slice(0, LIST_MAX).map(normalizePlace).filter((p) => p && !p.own);
  return out;
}

/** One hit of the address search → { name, address, lat, lon, source, distanceM } or null. */
function normalizeHit(v) {
  const o = obj(v);
  if (!o) return null;
  const lat = num(o.lat);
  const lon = num(o.lon);
  if (!hasPoint(lat, lon)) return null;
  const address = line(o.address, LIMITS.address) || null;
  const name = line(o.name, LIMITS.name) || (address ? line(address.split(',')[0], LIMITS.name) : '');
  if (!name) return null;
  const d = num(o.distanceM);
  return { name, address, lat, lon, source: typeof o.source === 'string' && /^[a-z]{2,20}$/.test(o.source) ? o.source : 'osm', distanceM: d !== null && d >= 0 ? Math.round(d) : null };
}

function attributionOf(v) {
  const o = obj(v);
  const text = o && line(o.text, 120);
  const url = o && typeof o.url === 'string' && /^https:\/\/[^\s]{1,300}$/.test(o.url) ? o.url : null;
  return text ? { text, url } : { ...OSM_ATTRIBUTION };
}

/** GET places/search → { results, attribution }. */
function normalizeSearch(v) {
  const o = obj(v) || {};
  return { results: arr(o.results).slice(0, HITS_MAX * 2).map(normalizeHit).filter(Boolean).slice(0, HITS_MAX), attribution: attributionOf(o.attribution) };
}

/** A hit of the map service (Nominatim of this PC, `{ lat, lon, label }`) in the shape of the server's hits. */
function hitOfMap(v) {
  const o = obj(v);
  if (!o) return null;
  const label = line(o.label, LIMITS.address);
  return normalizeHit({ name: label.split(',')[0], address: label || null, lat: o.lat, lon: o.lon, source: 'osm' });
}

// ── what the renderer may send ───────────────────────────────

function invalidField(field) {
  const e = new Error(`invalid ${field}`);
  e.code = 'invalid';
  e.field = field;
  return e;
}

/** The fields of a body (create: all required ones), checked; throws code 'invalid' with `field`. */
function fieldsOf(p, { create }) {
  const o = obj(p);
  if (!o) throw invalidField('body');
  for (const k of Object.keys(o)) {
    if (!['name', 'lat', 'lon', 'icon', 'radiusM', 'address', 'visibility'].includes(k)) throw invalidField(k);
  }
  const b = {};
  if (o.name !== undefined || create) {
    const n = line(o.name, LIMITS.name);
    if (!n) throw invalidField('name');
    b.name = n;
  }
  const hasLat = o.lat !== undefined;
  const hasLon = o.lon !== undefined;
  if (create || hasLat || hasLon) {
    if (!hasLat) throw invalidField('lat');
    if (!hasLon) throw invalidField('lon');
    const lat = num(o.lat);
    const lon = num(o.lon);
    if (lat === null || Math.abs(lat) > 90) throw invalidField('lat');
    if (lon === null || Math.abs(lon) > 180) throw invalidField('lon');
    if (lat === 0 && lon === 0) throw invalidField('lat');
    b.lat = round6(lat);
    b.lon = round6(lon);
  }
  if (o.icon !== undefined) { if (!ICONS.includes(o.icon)) throw invalidField('icon'); b.icon = o.icon; }
  if (o.radiusM !== undefined) {
    const r = num(o.radiusM);
    if (r === null || r < LIMITS.radius.min || r > LIMITS.radius.max) throw invalidField('radiusM');
    b.radiusM = Math.round(r);
  }
  if (o.address !== undefined) {
    if (o.address === null) b.address = null;
    else if (typeof o.address !== 'string') throw invalidField('address');
    else b.address = line(o.address, LIMITS.address) || null;
    if (create && b.address === null) delete b.address;
  }
  if (o.visibility !== undefined) { if (!VISIBILITY.includes(o.visibility)) throw invalidField('visibility'); b.visibility = o.visibility; }
  return b;
}

/** POST profile/places body (name, lat, lon required). */
const createBody = (p) => fieldsOf(p, { create: true });
/** PATCH profile/places/:id body (all optional; lat and lon together; address null clears). */
const patchBody = (p) => fieldsOf(p, { create: false });

/**
 * The editor's draft against the place it changes → only what differs (lat and lon together, an emptied address as
 * null). `{}`: nothing changed. Throws like patchBody when the draft is not savable.
 */
function diffBody(old, draft) {
  const d = createBody({ ...draft, address: draft && draft.address ? draft.address : undefined });
  const o = obj(old) || {};
  const b = {};
  if (d.name !== o.name) b.name = d.name;
  if (draft.icon !== undefined && iconOf(draft.icon) !== o.icon) b.icon = iconOf(draft.icon);
  if (!hasPoint(o.lat, o.lon) || round6(o.lat) !== d.lat || round6(o.lon) !== d.lon) { b.lat = d.lat; b.lon = d.lon; }
  if (draft.radiusM !== undefined && d.radiusM !== o.radiusM) b.radiusM = d.radiusM;
  const addr = d.address || null;
  if (addr !== (o.address || null)) b.address = addr;
  if (draft.visibility !== undefined && visibilityOf(draft.visibility) !== o.visibility) b.visibility = visibilityOf(draft.visibility);
  return b;
}

/** `near` as the server takes it: two decimals (~1 km), rounded on this PC already; null without a point. */
function nearOf(v) {
  if (v == null) return null;
  let lat;
  let lon;
  if (typeof v === 'string') {
    const m = /^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/.exec(v);
    if (!m) return undefined;
    lat = Number(m[1]);
    lon = Number(m[2]);
  } else {
    const o = obj(v);
    if (!o) return undefined;
    lat = num(o.lat);
    lon = num(o.lon);
  }
  if (!hasPoint(lat, lon)) return undefined;
  return `${round2(lat).toFixed(2)},${round2(lon).toFixed(2)}`;
}

/** The search as the renderer asks it: { q (3–120 characters), near? } → { q, near? }; throws code 'invalid'. */
function searchArg(p) {
  const o = obj(p);
  if (!o) throw invalidField('q');
  const q = line(o.q, SEARCH_MAX + 1);
  if (q.length < SEARCH_MIN || q.length > SEARCH_MAX) throw invalidField('q');
  const out = { q };
  const near = nearOf(o.near);
  if (near === undefined) throw invalidField('near');
  if (near) out.near = near;
  return out;
}

module.exports = {
  API_BASE, PLACES_PATH, SEARCH_PATH, ICONS, VISIBILITY, SEARCH_MODES, SOURCES, LIMITS, SEARCH_MIN, SEARCH_MAX, HITS_MAX,
  OSM_ATTRIBUTION, PROFILE_REF_RE, ANY_REF_RE,
  line, num, hasPoint, round6, clampRadius, iconOf, visibilityOf, idOfRef, refOf, isRef, timeOf,
  normalizeUse, usedByOf, normalizePlace, limitsOf, normalizeList, normalizeHit, normalizeSearch, hitOfMap,
  createBody, patchBody, diffBody, nearOf, searchArg,
};
