'use strict';

/**
 * Drive 1.18 – the overview (feature `overview`, GET overview): the cleaned answer, the overview of an older Drive
 * built from the endpoints it has (deadlines, photos/memories, people, photos/places, photos/classes) and the logic
 * of the tiles of the Windows page (which tiles show, their numbers and labels). Pure, Electron-free, unit-tested.
 *
 * The overview (each part null / empty when there is nothing or its feature is off):
 *   { todo: { deadlines (≤ 3), deadlinesTotal, review, toFile|null, toFileHint|null } | null,
 *     recent: [{ node, openedAt, changedAt, areaLabel }] (≤ 10, files only — no folders, photos, videos),
 *     memories: [{ yearsAgo, date, cover, count, items }] (≤ 4),
 *     people: { people (≤ 8 named, not hidden), unnamed, firstUnnamed } | null,
 *     places: { top: [{ key, name, count, lat, lon }] (≤ 3), cluster: { lat, lon, count } | null, total } | null,
 *     activity: [{ at, user: { id, name }, kind, count, area: { id, label }, folder: { id, path } | null, sample }] (≤ 5),
 *     storage: { used, total, target } | null,
 *     assembled: built here from the older endpoints (no "Zuletzt geöffnet", no "Neu in …") }
 */

const drive = require('./drive');

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);

const DEADLINES_MAX = 3;
const RECENT_MAX = 10;
const MEMORIES_MAX = 4;
const PEOPLE_MAX = 8;
const PLACES_MAX = 3;
const ACTIVITY_MAX = 5;
const ACTIVITY_KINDS = Object.freeze(['added_photos', 'added_files', 'changed']);
/** The tiles of the Windows page in the mockup's order (first row, then second row). */
const TILES = Object.freeze(['todo', 'recent', 'activity', 'memories', 'people', 'places']);
/** Live changes reload the overview at most this often. */
const LIVE_THROTTLE_MS = 15000;

const DAY_MS = 86400000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Pictures and videos belong to Fotos, not to "Zuletzt geöffnet". */
function isMedia(node) {
  const mime = String((node && node.mime) || '').toLowerCase();
  if (mime.startsWith('image/') || mime.startsWith('video/')) return true;
  return /\.(jpe?g|png|gif|heic|heif|webp|bmp|tiff?|dng|cr2|nef|arw|mp4|mov|m4v|avi|mkv|3gp|webm)$/i.test(String((node && node.name) || ''));
}

function todoOf(v) {
  const o = obj(v);
  if (!o) return null;
  const deadlines = arr(o.deadlines).slice(0, 50).map(drive.normalizeDeadline).filter((d) => d && !(d.node && d.node.encrypted)).slice(0, DEADLINES_MAX);
  const total = drive.count(o.deadlinesTotal);
  const toFile = drive.count(o.toFile);
  return {
    deadlines,
    deadlinesTotal: Math.max(total === null ? deadlines.length : total, deadlines.length),
    review: drive.count(o.review) || 0,
    toFile,
    toFileHint: drive.line(o.toFileHint, 200),
  };
}

function recentOf(v) {
  const o = obj(v);
  const node = o && drive.normalizeNode(o);
  if (!node || node.isDir || node.encrypted || isMedia(node)) return null;
  return { node, openedAt: drive.msOf(o.openedAt), changedAt: drive.msOf(o.changedAt), areaLabel: drive.line(o.areaLabel, 100) };
}

function memoryOf(v) {
  const o = obj(v);
  if (!o) return null;
  const items = arr(o.items).slice(0, 30).map(drive.normalizePhoto).filter(Boolean);
  const cover = drive.normalizePhoto(o.cover) || items[0] || null;
  if (!cover) return null;
  const n = drive.count(o.count);
  return {
    yearsAgo: drive.count(o.yearsAgo) || 0,
    date: typeof o.date === 'string' && DAY_RE.test(o.date.slice(0, 10)) ? o.date.slice(0, 10) : null,
    cover,
    count: Math.max(n === null ? items.length : n, 1),
    items,
  };
}

/** `people: [...]` with `unnamed` beside it, or `people: { people|items: [...], unnamed }`; null when missing. */
function peopleOf(src) {
  const e = src.people;
  let list;
  let unnamed;
  if (Array.isArray(e)) { list = e; unnamed = drive.count(src.unnamed); }
  else if (obj(e)) { list = arr(e.people).length ? e.people : arr(e.items).length ? e.items : arr(e.named); unnamed = drive.count(e.unnamed); }
  else return null;
  const all = arr(list).slice(0, 100).map(drive.normalizePerson).filter(Boolean);
  const named = all.filter((p) => p.name && !p.hidden).slice(0, PEOPLE_MAX);
  const first = all.find((p) => !p.name && !p.hidden);
  return { people: named, unnamed: unnamed === null ? all.filter((p) => !p.name && !p.hidden).length : unnamed, firstUnnamed: first ? first.id : null };
}

function placesOf(v) {
  const o = obj(v);
  if (!o) return null;
  const top = arr(o.top).slice(0, 20).map((x) => {
    const p = obj(x);
    const key = p && drive.placeKeyOf(p.key);
    const name = p && drive.line(p.name, 200);
    if (!key || !name) return null;
    const at = drive.latLonOf(p.lat, p.lon);
    return { key, name, count: drive.count(p.count) || 0, lat: at ? at.lat : null, lon: at ? at.lon : null };
  }).filter(Boolean).slice(0, PLACES_MAX);
  const c = obj(o.cluster);
  const at = c && drive.latLonOf(c.lat, c.lon);
  const total = drive.count(o.total);
  return {
    top,
    cluster: at ? { lat: at.lat, lon: at.lon, count: drive.count(c.count) || 0 } : null,
    total: total === null ? top.reduce((s, p) => s + p.count, 0) : total,
  };
}

function activityOf(v) {
  const o = obj(v);
  if (!o || !ACTIVITY_KINDS.includes(o.kind)) return null;
  const u = obj(o.user);
  const a = obj(o.area);
  const f = obj(o.folder);
  const sample = drive.normalizeNode(o.sample);
  return {
    at: drive.msOf(o.at),
    user: { id: u ? drive.posId(u.id) : null, name: u ? drive.line(u.name, 100) : null },
    kind: o.kind,
    count: Math.max(drive.count(o.count) || 0, 1),
    area: a ? { id: drive.areaIdOf(a.id), label: drive.line(a.label, 100) } : null,
    folder: f && drive.posId(f.id) ? { id: drive.posId(f.id), path: drive.line(f.path, 500) } : null,
    sample: sample && !sample.encrypted ? sample : null,
  };
}

function storageOf(v) {
  const o = obj(v);
  const used = o && drive.count(o.used);
  if (used === null || used === undefined) return null;
  const total = drive.count(o.total);
  return { used, total: total ? total : null, target: drive.line(o.target, 100) };
}

/** GET overview → the overview (at the top or as `overview`). */
function normalizeOverview(raw) {
  const r = obj(raw) || {};
  const src = obj(r.overview) || r;
  return {
    todo: todoOf(src.todo),
    recent: arr(src.recent).slice(0, 50).map(recentOf).filter(Boolean).slice(0, RECENT_MAX),
    memories: arr(src.memories).slice(0, 20).map(memoryOf).filter(Boolean).slice(0, MEMORIES_MAX),
    people: peopleOf(src),
    places: placesOf(src.places),
    activity: arr(src.activity).slice(0, 50).map(activityOf).filter(Boolean).slice(0, ACTIVITY_MAX),
    storage: storageOf(src.storage),
    assembled: false,
  };
}

/** GET photos/classes → { work, private, review } (Drive 1.13 'photoClasses'); null when a number is missing. */
function normalizePhotoClasses(raw) {
  const r = obj(raw) || {};
  const [work, priv, review] = [r.work, r.private, r.review].map(drive.count);
  return work === null || priv === null || review === null ? null : { work, private: priv, review };
}

/** YYYY-MM-DD of `ms` in local time. */
function dayOf(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** The storage of "Meine Dateien" from the areas (what the storage page shows for the person). */
function storageFromAreas(areas) {
  const mine = arr(areas).find((a) => a && a.kind === 'mine');
  const s = mine && mine.storage;
  if (!s || s.bytes === null || s.bytes === undefined) return null;
  return { used: s.bytes, total: s.quota ? s.quota : null, target: s.target || null };
}

/**
 * The overview of a Drive without `overview` (≤ 1.17) from what it has (each argument null when the feature is
 * off): the deadlines from today, the review count, the memories, the people, the places, the storage of the areas.
 */
function assembleOverview({ now = Date.now(), deadlines = null, classes = null, memories = null, people = null, places = null, areas = null } = {}) {
  const today = dayOf(now);
  const next = deadlines ? arr(deadlines.deadlines).filter((d) => d && d.date >= today && !(d.node && d.node.encrypted)) : [];
  next.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.id - b.id));
  const review = classes ? classes.review || 0 : 0;
  const todo = deadlines || classes ? { deadlines: next.slice(0, DEADLINES_MAX), deadlinesTotal: next.length, review, toFile: null, toFileHint: null } : null;
  const cards = memories ? arr(memories.groups).filter((g) => g && arr(g.items).length).slice(0, MEMORIES_MAX)
    .map((g) => ({ yearsAgo: g.yearsAgo, date: g.date || null, cover: g.items[0], count: g.items.length, items: g.items })) : [];
  let ov = null;
  if (people) {
    const visible = arr(people.people).filter((p) => p && !p.hidden);
    const named = visible.filter((p) => p.name).sort((a, b) => b.count - a.count || String(a.name).localeCompare(String(b.name)));
    const unnamed = visible.filter((p) => !p.name).sort((a, b) => b.count - a.count);
    ov = { people: named.slice(0, PEOPLE_MAX), unnamed: unnamed.length, firstUnnamed: unnamed.length ? unnamed[0].id : null };
  }
  let pl = null;
  const list = places ? arr(places.places).filter(Boolean) : [];
  if (list.length) {
    const sorted = [...list].sort((a, b) => b.count - a.count);
    const total = list.reduce((s, p) => s + (p.count || 0), 0);
    const first = sorted.find((p) => p.lat !== null && p.lon !== null);
    pl = {
      top: sorted.slice(0, PLACES_MAX).map((p) => ({ key: p.key, name: p.name, count: p.count, lat: p.lat, lon: p.lon })),
      cluster: first ? { lat: first.lat, lon: first.lon, count: total } : null,
      total,
    };
  }
  return { todo, recent: [], memories: cards, people: ov, places: pl, activity: [], storage: storageFromAreas(areas), assembled: true };
}

// ── The tiles ───────────────────────────────────────────────

const hasTodo = (t) => !!t && (t.deadlines.length > 0 || t.review > 0 || (t.toFile || 0) > 0);

/** The number beside "Zu erledigen": the deadlines, then one each for the review and "Zum Ablegen". */
function todoCount(t) {
  if (!t) return 0;
  return t.deadlinesTotal + (t.review > 0 ? 1 : 0) + ((t.toFile || 0) > 0 ? 1 : 0);
}

/**
 * The tiles shown, in order (an empty one is left out): todo, recent, activity, memories, people, places. The storage
 * is the foot of "Neu in …" (mockup); without activity it is a tile of its own ('storage'), right after recent.
 */
function overviewTiles(ov) {
  if (!ov) return [];
  const on = {
    todo: hasTodo(ov.todo),
    recent: ov.recent.length > 0,
    activity: ov.activity.length > 0,
    memories: ov.memories.length > 0,
    people: !!ov.people && (ov.people.people.length > 0 || ov.people.unnamed > 0),
    places: !!ov.places && ov.places.top.length > 0,
  };
  const out = TILES.filter((k) => on[k]);
  if (!on.activity && ov.storage) out.splice(out.indexOf('memories') >= 0 ? out.indexOf('memories') : out.length, 0, 'storage');
  return out;
}

/**
 * The label of a memory: { today: true, years } "Heute vor 2 Jahren" when the cover is of exactly this calendar day,
 * { today: false, years } "Vor 2 Jahren" for a day beside it (the plugin takes ± 1 day); years 0: "An diesem Tag".
 */
function memoryLabel(card, now = Date.now()) {
  const t = new Date(now);
  const at = card && card.cover && card.cover.takenAt ? new Date(card.cover.takenAt) : card && card.date ? new Date(`${card.date}T12:00:00`) : null;
  const same = !!at && !Number.isNaN(at.getTime()) && at.getMonth() === t.getMonth() && at.getDate() === t.getDate();
  let years = card && card.yearsAgo > 0 ? card.yearsAgo : 0;
  if (!years && at && !Number.isNaN(at.getTime())) years = Math.max(0, t.getFullYear() - at.getFullYear());
  return { today: same, years };
}

/** The relative day of a deadline: { key: 'past'|'today'|'in', days } */
function deadlineWhen(date, now = Date.now()) {
  if (typeof date !== 'string' || !DAY_RE.test(date)) return null;
  const [y, m, d] = date.split('-').map(Number);
  const t = new Date(now);
  const days = Math.round((Date.UTC(y, m - 1, d) - Date.UTC(t.getFullYear(), t.getMonth(), t.getDate())) / DAY_MS);
  return { key: days < 0 ? 'past' : days === 0 ? 'today' : 'in', days };
}

/**
 * A row of "Neu in …" as text parts: { key, n, name, file } — key 'photos' ("hat 14 Fotos hinzugefügt"), 'files',
 * 'file' (one file, named: "hat „Zeugnis.pdf“ abgelegt"), 'changed', 'changedOne'.
 */
function activityLine(a) {
  const one = a.count === 1 && a.sample ? a.sample.name : null;
  const key = a.kind === 'added_photos' ? 'photos' : a.kind === 'added_files' ? (one ? 'file' : 'files') : (one ? 'changedOne' : 'changed');
  return { key, n: a.count, name: a.user.name || null, file: one };
}

/** "Neu in Familie" when every row is of one area, else null (the page says "Neu in geteilten Bereichen"). */
function activityArea(activity) {
  const labels = [...new Set(arr(activity).map((a) => a.area && a.area.label).filter(Boolean))];
  return labels.length === 1 ? labels[0] : null;
}

/** The last folder of a path ("Familie/Urlaub 2026" → "Urlaub 2026"). */
function folderName(path) {
  const s = String(path || '').replace(/^\/+|\/+$/g, '');
  return s ? s.split('/').pop() : null;
}

/** How full, 0…1 (null without a limit). */
function storageFill(s) {
  return s && s.total ? Math.max(0, Math.min(1, s.used / s.total)) : null;
}

/** The small map: the box around the top places (with coordinates), else a region around the bubble. */
function mapView(places) {
  if (!places) return null;
  const pts = places.top.filter((p) => p.lat !== null && p.lon !== null);
  const bubble = places.cluster ? { ...places.cluster, count: places.cluster.count || places.total }
    : pts.length ? { lat: pts[0].lat, lon: pts[0].lon, count: places.total } : null;
  if (pts.length >= 2) {
    const s = Math.min(...pts.map((p) => p.lat)); const n = Math.max(...pts.map((p) => p.lat));
    const w = Math.min(...pts.map((p) => p.lon)); const e = Math.max(...pts.map((p) => p.lon));
    const dy = Math.max((n - s) * 0.3, 0.05); const dx = Math.max((e - w) * 0.3, 0.05);
    return { bbox: [Math.max(-180, w - dx), Math.max(-85, s - dy), Math.min(180, e + dx), Math.min(85, n + dy)], bubble };
  }
  if (!bubble) return null;
  return { bbox: [Math.max(-180, bubble.lon - 4), Math.max(-85, bubble.lat - 2.5), Math.min(180, bubble.lon + 4), Math.min(85, bubble.lat + 2.5)], bubble };
}

/**
 * What the page shows of an overview at `now`: the tiles in order, the number of "Zu erledigen", each deadline's day,
 * each memory's label, each row of "Neu in …" as text parts and its folder, the area of the heading, how full the
 * storage is and the small map (box and bubble). The page only puts it into words (its locale).
 */
function overviewView(ov, now = Date.now()) {
  return {
    tiles: overviewTiles(ov),
    todoCount: todoCount(ov && ov.todo),
    deadlines: ov && ov.todo ? ov.todo.deadlines.map((d) => ({ id: d.id, when: deadlineWhen(d.date, now) })) : [],
    memories: ov ? ov.memories.map((m) => memoryLabel(m, now)) : [],
    activity: ov ? ov.activity.map((a) => ({ ...activityLine(a), folder: folderName(a.folder && a.folder.path) })) : [],
    activityArea: activityArea(ov && ov.activity),
    storageFill: storageFill(ov && ov.storage),
    map: mapView(ov && ov.places),
  };
}

module.exports = {
  ACTIVITY_KINDS,
  TILES,
  LIVE_THROTTLE_MS,
  isMedia,
  normalizeOverview,
  normalizePhotoClasses,
  assembleOverview,
  storageFromAreas,
  hasTodo,
  todoCount,
  overviewTiles,
  memoryLabel,
  deadlineWhen,
  activityLine,
  activityArea,
  folderName,
  storageFill,
  mapView,
  overviewView,
};
