'use strict';

/**
 * Pure helpers of Drive (plugin `gatecontrol-drive`: the files of the person,
 * the family and the team on the own storage; contract: the plugin's README
 * "API"): constants, argument checks, cleaned answers of the app API and the
 * request bodies.
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * enums checked, ids positive integers, times as milliseconds. Every parser
 * accepts more than it needs and drops what it does not understand, so later
 * additions on the plugin side do not break older Windows apps. Electron-free
 * and side-effect free (unit-tested directly).
 */

const PLUGIN_ID = 'gatecontrol-drive';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const PLUGINS_PATH = '/api/v1/client/plugins';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_PATH = `/api/v1/client/plugins/${PLUGIN_ID}/media`;

const MAX_FILE_BYTES = 100 * 1024 * 1024 * 1024; // plugin.json media.maxBytes: 100 GB
const RESUMABLE_FROM = 8 * 1024 * 1024;           // larger files go up in resumable parts (like the Android app)
const SHA_MAX_BYTES = 2 * 1024 * 1024 * 1024;     // `uploads/check` with a SHA-256 up to 2 GB (reading more takes too long)
const TEXT_MAX = 100000;
const NAME_MAX = 255;
const PIN_RE = /^\d{4,12}$/;

const ROLES = Object.freeze(['read', 'write', 'manage']);
const AREA_KINDS = Object.freeze(['mine', 'family', 'child', 'team']);
const SORTS = Object.freeze(['name', 'mtime', 'size', 'updated']);
const ON_CONFLICT = Object.freeze(['rename', 'version']);
const LINK_MODES = Object.freeze(['view', 'download', 'upload']);
const LINK_EXPIRES = Object.freeze(['1d', '7d', '30d', 'never']);
const LINK_KINDS = Object.freeze(['files', 'folder', 'upload']);

const MEDIA_ID_RE = /^[A-Za-z0-9_-]{6,128}$/;
const AREA_ID_RE = /^[A-Za-z0-9:_-]{1,80}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{6,200}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const CODE_RE = /^[A-Za-z0-9_.-]{1,60}$/;
// Characters a NAS (and Windows) does not take in a name, and control characters.
const FORBIDDEN_RE = /[/\\:*?"<>|\u0000-\u001f]/g;
const CTRL_LINE_RE = /[\u0000-\u001F\u007F]/g;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);
const bool = (v) => v === true;

/** Trimmed single-line string ≤ max, or null. */
function line(v, max) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const s = String(v).replace(CTRL_LINE_RE, ' ').trim().slice(0, max);
  return s || null;
}

/** Positive safe integer (number or numeric string), else null. */
function posId(v) {
  const n = typeof v === 'string' && /^\d{1,16}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** Non-negative safe integer, else null. */
function count(v) {
  const n = typeof v === 'string' && /^\d{1,16}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

const isMediaId = (v) => typeof v === 'string' && MEDIA_ID_RE.test(v);
const areaIdOf = (v) => (typeof v === 'string' && AREA_ID_RE.test(v) ? v : null);
const isLinkToken = (v) => typeof v === 'string' && TOKEN_RE.test(v);
const sha256Of = (v) => (typeof v === 'string' && SHA256_RE.test(v.toLowerCase()) ? v.toLowerCase() : null);
const codeOf = (v) => (typeof v === 'string' && CODE_RE.test(v) ? v : null);

/** ISO-8601 string or epoch ms → ms, else null. */
function msOf(v) {
  if (Number.isFinite(v) && v > 0) return Math.round(v);
  if (typeof v !== 'string' || v.length > 40) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

// ── Names ──────────────────────────────────────────────────

/**
 * A name Drive takes (README: no `/ \ : * ? " < > |`, no trailing dot or
 * space, ≤ 255 characters, not `.gcdrive`): forbidden characters become `_`;
 * null when nothing is left.
 */
function safeName(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.normalize('NFC').replace(FORBIDDEN_RE, '_').trim().replace(/[. ]+$/, '').slice(0, NAME_MAX).replace(/[. ]+$/, '');
  if (!s || s === '.' || s === '..' || s.toLowerCase() === '.gcdrive') return null;
  return s;
}

/** Is `raw` a valid new name as typed (before any replacing)? */
function validName(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return false;
  if (/[/\\:*?"<>|\u0000-\u001f]/.test(raw)) return false;
  return safeName(raw) === raw.trim();
}

// ── Answers ────────────────────────────────────────────────

function storageOf(v) {
  const s = obj(v);
  if (!s) return null;
  const target = typeof s.target === 'string' ? line(s.target, 100) : obj(s.target) ? line(s.target.label || s.target.kind, 100) : null;
  return { bytes: count(s.bytes), quota: count(s.quota), form: line(s.form, 20), target, state: line(s.state, 40) };
}

/** An area of `GET areas` / `GET me` → { id, kind, label, role, via, rootId, owner, archived, writable, storage } or null. */
function normalizeArea(v) {
  const a = obj(v);
  const id = a && areaIdOf(a.id);
  const rootId = a && posId(a.rootId);
  if (!id || !rootId) return null;
  const role = ROLES.includes(a.role) ? a.role : 'read';
  const archived = bool(a.archived);
  return {
    id,
    kind: AREA_KINDS.includes(a.kind) ? a.kind : 'mine',
    label: line(a.label, 200) || id,
    role,
    via: line(a.via, 20),
    rootId,
    owner: posId(a.owner),
    archived,
    writable: !archived && (role === 'write' || role === 'manage'),
    storage: storageOf(a.storage),
  };
}

const AREA_RANK = { mine: 0, family: 1, child: 2, team: 3 };

/** Order of the areas: my files, the family, the children, the teams (then by label). */
function sortAreas(list) {
  return arr(list).slice().sort((a, b) => ((AREA_RANK[a.kind] ?? 9) - (AREA_RANK[b.kind] ?? 9)) || String(a.label).localeCompare(String(b.label)));
}

/** GET areas → { areas } (sorted). */
function normalizeAreas(raw) {
  const r = obj(raw) || {};
  return { areas: sortAreas(arr(r.areas).slice(0, 500).map(normalizeArea).filter(Boolean)) };
}

/** A node (folder or file) → clean object or null. */
function normalizeNode(v) {
  const o = obj(v);
  if (!o) return null;
  const id = posId(o.id);
  const areaId = areaIdOf(o.areaId);
  const name = line(o.name, NAME_MAX);
  if (!id || !areaId || !name) return null;
  const isDir = bool(o.isDir);
  const mediaId = isMediaId(o.mediaId) ? o.mediaId : null;
  const match = o.match === 'text' || o.match === 'name' ? o.match : null;
  return {
    id,
    areaId,
    parentId: posId(o.parentId),
    name,
    isDir,
    size: count(o.size) || 0,
    mime: line(o.mime, 100),
    mediaId,
    rev: count(o.rev) || 0,
    mtime: msOf(o.mtime),
    updatedAt: msOf(o.updatedAt),
    updatedBy: posId(o.updatedBy),
    createdAt: msOf(o.createdAt),
    sha256: sha256Of(o.sha256),
    // A preview picture exists (or is being made); the app loads it by mediaId.
    preview: !isDir && !!mediaId && !!obj(o.preview),
    // search: the folder path and where it matched (Drive 1.3: in the recognised text, with a snippet)
    path: line(o.path, 2000),
    match,
    snippet: match === 'text' ? line(o.snippet, 300) : null,
    // trash: where it was, files that went with a folder, when
    from: line(o.from, 2000),
    files: count(o.files),
    deletedAt: msOf(o.deletedAt),
  };
}

function normalizeItems(raw, max = 1000) {
  const r = obj(raw) || {};
  return arr(r.items).slice(0, max).map(normalizeNode).filter(Boolean);
}

function crumbsOf(v) {
  return arr(v).slice(0, 100).map((c) => {
    const o = obj(c);
    const id = o && posId(o.id);
    const name = o && line(o.name, NAME_MAX);
    return id && name ? { id, name } : null;
  }).filter(Boolean);
}

/**
 * `GET nodes/<id>` + `GET nodes/<id>/children` → { node, crumbs, role,
 * writable, items, total, next } or null.
 */
function normalizeFolder(nodeAnswer, childrenAnswer) {
  const na = obj(nodeAnswer) || {};
  const n = obj(na.node);
  const node = normalizeNode(n);
  if (!node) return null;
  const ca = obj(childrenAnswer) || {};
  if (!Array.isArray(ca.items)) return null;
  const items = normalizeItems(ca);
  const roleRaw = ca.role || n.role || na.role;
  const role = ROLES.includes(roleRaw) ? roleRaw : 'read';
  return {
    node,
    crumbs: crumbsOf(n.crumbs || na.crumbs),
    role,
    writable: role === 'write' || role === 'manage',
    items,
    total: count(ca.total) ?? items.length,
    next: count(ca.next),
  };
}

/** GET me → { me, licence, areas, latest, settings, limits, people } */
function normalizeMe(raw) {
  const r = obj(raw) || {};
  const me = obj(r.me) || {};
  const lic = obj(r.licence) || {};
  const st = obj(r.settings) || {};
  const lim = obj(r.limits) || {};
  return {
    me: {
      id: posId(me.id),
      name: line(me.name, 200),
      seat: me.seat === 'family' || me.seat === 'business' ? me.seat : null,
      deviceId: line(me.deviceId, 128),
    },
    licence: { valid: bool(lic.valid), tier: line(lic.tier, 20) },
    areas: sortAreas(arr(r.areas).slice(0, 500).map(normalizeArea).filter(Boolean)),
    latest: count(r.latest) || 0,
    settings: { trashDays: count(st.trashDays), versionsDays: count(st.versionsDays) },
    limits: { maxBytes: count(lim.maxBytes) },
    people: arr(r.people).slice(0, 2000).map((p) => {
      const o = obj(p);
      const id = o && posId(o.id);
      const name = o && line(o.name, 200);
      return id && name ? { id, name } : null;
    }).filter(Boolean),
  };
}

/** GET nodes/<id>/versions → { current, versions: [{ id, rev, size, at, by }] } or null. */
function normalizeVersions(raw) {
  const r = obj(raw) || {};
  const current = normalizeNode(r.current);
  if (!current) return null;
  const versions = arr(r.versions).slice(0, 500).map((v) => {
    const o = obj(v);
    const id = o && posId(o.id);
    if (!id) return null;
    return { id, rev: count(o.rev) || 0, size: count(o.size) || 0, at: msOf(o.at), by: posId(o.by) };
  }).filter(Boolean);
  versions.sort((a, b) => b.rev - a.rev);
  return { current, versions };
}

/** POST uploads/check → { exists, same, node } or null. */
function normalizeUploadCheck(raw) {
  const r = obj(raw);
  if (!r || typeof r.exists !== 'boolean') return null;
  return { exists: r.exists, same: bool(r.same), node: normalizeNode(r.node) };
}

/** POST uploads/commit → { node, created } or null. */
function normalizeCommit(raw) {
  const r = obj(raw) || {};
  const node = normalizeNode(r.node);
  return node ? { node, created: r.created !== false } : null;
}

/** GET nodes/<id>/content → { mediaId, name, mime, size } or null. */
function normalizeContent(raw) {
  const r = obj(raw) || {};
  if (!isMediaId(r.mediaId)) return null;
  return { mediaId: r.mediaId, name: line(r.name, NAME_MAX), mime: line(r.mime, 100), size: count(r.size) };
}

/** A shared link → clean object or null. */
function normalizeLink(v) {
  const o = obj(v);
  if (!o || !isLinkToken(o.token)) return null;
  const url = typeof o.url === 'string' && /^https?:\/\//i.test(o.url) && o.url.length <= 2000 ? o.url : null;
  return {
    token: o.token,
    url,
    nodeId: posId(o.nodeId),
    areaId: areaIdOf(o.areaId),
    kind: LINK_KINDS.includes(o.kind) ? o.kind : null,
    mode: LINK_MODES.includes(o.mode) ? o.mode : null,
    name: line(o.name, NAME_MAX) || line(o.title, NAME_MAX),
    path: line(o.path, 2000),
    active: bool(o.active),
    endedWhy: line(o.endedWhy, 40),
    expiresAt: msOf(o.expiresAt),
    pin: o.pin === true || (typeof o.pin === 'string' && PIN_RE.test(o.pin)),
    opens: count(o.opens) || 0,
    downloads: count(o.downloads) || 0,
    createdAt: msOf(o.createdAt),
  };
}

/** GET links → { links, enabled } (active ones first, newest first). */
function normalizeLinks(raw) {
  const r = obj(raw) || {};
  const links = arr(r.links).slice(0, 500).map(normalizeLink).filter(Boolean);
  links.sort((a, b) => (Number(b.active) - Number(a.active)) || ((b.createdAt || 0) - (a.createdAt || 0)));
  return { links, enabled: r.enabled !== false };
}

/**
 * Answer of another plugin's "In Drive speichern" (Messenger `to-drive`,
 * Schule `attachments/<id>/drive`): `{ saved: { nodeId, name, where } }` →
 * { nodeId, name, where } (where: "Meine Dateien › Messenger › Foto.jpg").
 */
function savedOf(raw) {
  const r = obj(raw) || {};
  const s = obj(r.saved) || {};
  return { nodeId: posId(s.nodeId), name: line(s.name, NAME_MAX), where: line(s.where, 600) };
}

// ── Requests ───────────────────────────────────────────────

/** Children query: sort, order, offset, limit (≤ 1000) — unknown values fall back to name / asc. */
function childrenQuery({ sort, order, offset, limit } = {}) {
  const s = SORTS.includes(sort) ? sort : 'name';
  const o = order === 'desc' || order === 'asc' ? order : (s === 'name' ? 'asc' : 'desc');
  const off = count(offset) || 0;
  const lim = Math.min(1000, posId(limit) || 500);
  return { sort: s, order: o, offset: off, limit: lim };
}

/** Link body → { nodeId, mode, expires, pin? } or null when invalid. */
function linkBody({ nodeId, mode, expires, pin } = {}) {
  const id = posId(nodeId);
  if (!id || !LINK_MODES.includes(mode) || !LINK_EXPIRES.includes(expires)) return null;
  const body = { nodeId: id, mode, expires };
  if (pin !== undefined && pin !== null && pin !== '') {
    if (typeof pin !== 'string' || !PIN_RE.test(pin)) return null;
    body.pin = pin;
  }
  return body;
}

/** The plugin's error code of a failure (or 'failed'). */
function errorCode(err) {
  return (err && codeOf(err.code)) || 'failed';
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  PLUGINS_PATH,
  API_BASE,
  MEDIA_PATH,
  MAX_FILE_BYTES,
  RESUMABLE_FROM,
  SHA_MAX_BYTES,
  TEXT_MAX,
  NAME_MAX,
  PIN_RE,
  ROLES,
  AREA_KINDS,
  SORTS,
  ON_CONFLICT,
  LINK_MODES,
  LINK_EXPIRES,
  LINK_KINDS,
  line,
  posId,
  count,
  msOf,
  isMediaId,
  areaIdOf,
  isLinkToken,
  sha256Of,
  safeName,
  validName,
  sortAreas,
  normalizeArea,
  normalizeAreas,
  normalizeNode,
  normalizeItems,
  normalizeFolder,
  normalizeMe,
  normalizeVersions,
  normalizeUploadCheck,
  normalizeCommit,
  normalizeContent,
  normalizeLink,
  normalizeLinks,
  savedOf,
  childrenQuery,
  linkBody,
  errorCode,
};
