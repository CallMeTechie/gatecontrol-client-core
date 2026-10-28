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
// Drive 1.5: `mark` / `unmark` – a file is marked for a delayed delete (deleteAt) or no longer
const CHANGE_OPS = Object.freeze(['create', 'update', 'move', 'delete', 'restore', 'purge', 'mark', 'unmark']);
const CHANGES_MAX = 1000;

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
    deleted: bool(o.deleted),
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
    // Drive 1.5 ('deleteAfter'): goes into the trash at this time (deleted on a device that backs it up)
    deleteAt: msOf(o.deleteAt),
    deletedOnDevice: line(o.deletedOnDevice, 128),
    // Drive 1.7 ('takenAt'): when a photo / video was taken (EXIF, else mtime) or null
    takenAt: msOf(o.takenAt),
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
      // an administrator of GateControl (Drive 1.7 'storage': "Alle")
      admin: bool(me.admin),
    },
    licence: { valid: bool(lic.valid), tier: line(lic.tier, 20) },
    // Drive 1.5: what this Drive can ('devices', 'deleteAfter', 'emptyFiles', …); older ones send none
    features: arr(r.features).slice(0, 50).filter((f) => typeof f === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(f)),
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
    // Drive 1.6 ('links'): direct links into the portal; ('guard'): the ransomware guard
    links: normalizeLinks16(r.links),
    guard: normalizeGuard(r.guard),
    incidents: arr(r.incidents).slice(0, 50).map(normalizeIncident).filter(Boolean),
  };
}

// ── Drive 1.6: portal links, guard ─────────────────────────

const LINK_URL_MAX = 2000;

/** An https URL (no user / password), else null. */
function httpsUrl(v) {
  if (typeof v !== 'string' || !v || v.length > LINK_URL_MAX) return null;
  let u;
  try { u = new URL(v); } catch { return null; }
  if (u.protocol !== 'https:' || !u.hostname || u.username || u.password) return null;
  return v;
}

/** me.links → { node: '…{id}…', drive } | null (the node template must hold `{id}`). */
function normalizeLinks16(v) {
  const o = obj(v);
  if (!o) return null;
  const node = typeof o.node === 'string' && o.node.includes('{id}') && httpsUrl(o.node.split('{id}').join('1')) ? o.node : null;
  const d = httpsUrl(o.drive);
  return node || d ? { node, drive: d } : null;
}

/**
 * The portal link of a node from the template `me.links.node` → https URL or null.
 * `allowedHosts`: the host names the link may point to (the server, the portal).
 */
function nodeLink(template, id, allowedHosts = null) {
  const n = posId(id);
  if (!n || typeof template !== 'string' || !template.includes('{id}')) return null;
  return allowedLink(template.split('{id}').join(String(n)), allowedHosts);
}

/** An https URL whose host is one of `allowedHosts` (null: any host) → the URL or null. */
function allowedLink(raw, allowedHosts = null) {
  const url = httpsUrl(raw);
  if (!url) return null;
  if (Array.isArray(allowedHosts)) {
    const host = new URL(url).hostname.toLowerCase();
    if (!allowedHosts.some((h) => typeof h === 'string' && h.toLowerCase() === host)) return null;
  }
  return url;
}

const INCIDENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** A guard incident → { id, at, device, deviceName, files, sample: [string] } or null. */
function normalizeIncident(v) {
  const o = obj(v);
  if (!o) return null;
  const id = posId(o.id) || (typeof o.id === 'string' && INCIDENT_ID_RE.test(o.id) ? o.id : null);
  if (!id) return null;
  const sample = arr(o.sample).slice(0, 10).map((x) => {
    if (typeof x === 'string') return line(x, 1000);
    const s = obj(x);
    return s ? line(s.path || s.name, 1000) : null;
  }).filter(Boolean);
  return {
    id,
    at: msOf(o.at),
    device: line(o.device, 128),
    deviceName: line(o.deviceName, 100),
    files: count(o.files) || 0,
    sample,
    state: line(o.state, 20),
  };
}

/** me.guard → { locked, incident } | null */
function normalizeGuard(v) {
  const o = obj(v);
  if (!o) return null;
  return { locked: bool(o.locked), incident: normalizeIncident(o.incident) };
}

/** Is `id` a guard incident id (number or token)? */
function incidentIdOf(v) {
  return posId(v) || (typeof v === 'string' && INCIDENT_ID_RE.test(v) ? v : null);
}

/** POST guard/incidents/<id>/release|undo → { incident, restored, trashed } */
function normalizeGuardAnswer(raw) {
  const r = obj(raw) || {};
  return { incident: normalizeIncident(r.incident), restored: count(r.restored) || 0, trashed: count(r.trashed) || 0 };
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

/**
 * GET changes?since= → { changes: [{ seq, op, areaId, nodeId, at, by, device, node }], next, more } or null.
 * `node`: the node as it is now (null once purged, or when it moved to another area: then the
 * change is a `delete` in the old area); `device`: the device that made the change ('nas' for
 * the NAS, a plugin's id for its services). Rows without a seq or a node id are dropped.
 */
function normalizeChanges(raw) {
  const r = obj(raw);
  if (!r || !Array.isArray(r.changes)) return null;
  const changes = r.changes.slice(0, CHANGES_MAX).map((c) => {
    const o = obj(c);
    const seq = o && posId(o.seq);
    const nodeId = o && posId(o.nodeId);
    if (!seq || !nodeId || !CHANGE_OPS.includes(o.op)) return null;
    return {
      seq,
      op: o.op,
      areaId: areaIdOf(o.areaId),
      nodeId,
      at: msOf(o.at),
      by: posId(o.by),
      device: line(o.device, 128),
      node: normalizeNode(o.node),
    };
  }).filter(Boolean);
  changes.sort((a, b) => a.seq - b.seq);
  const last = changes.length ? changes[changes.length - 1].seq : 0;
  return { changes, next: Math.max(count(r.next) || 0, last), more: bool(r.more) };
}

/**
 * GET nodes/<id>/content → { mediaId, name, mime, size, empty } or null.
 * Drive 1.5: an empty file has no media (`empty: true`, `mediaId: null`) – write an empty file.
 */
function normalizeContent(raw) {
  const r = obj(raw) || {};
  if (r.empty === true) return { mediaId: null, name: line(r.name, NAME_MAX), mime: line(r.mime, 100), size: 0, empty: true };
  if (!isMediaId(r.mediaId)) return null;
  return { mediaId: r.mediaId, name: line(r.name, NAME_MAX), mime: line(r.mime, 100), size: count(r.size), empty: false };
}

const DEVICE_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Drive 1.5 PUT devices/<id> → { id, name, platform, folder: { id, name, areaId, path, where } | null } or null. */
function normalizeDevice(raw) {
  const r = obj(raw) || {};
  const d = obj(r.device) || r;
  const id = typeof d.id === 'string' && DEVICE_ID_RE.test(d.id) ? d.id : null;
  if (!id) return null;
  const f = obj(d.folder);
  const fid = f && posId(f.id);
  return {
    id,
    name: line(d.name, 100),
    platform: line(d.platform, 20),
    folder: fid ? { id: fid, name: line(f.name, NAME_MAX), areaId: areaIdOf(f.areaId), path: line(f.path, 2000), where: line(f.where, 2000) } : null,
  };
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

// ── Drive 1.7: time travel, photos, albums, storage ────────

const TT_OPS = Object.freeze(['restore', 'revert', 'trash', 'move']);
const CURSOR_RE = /^[A-Za-z0-9:._+|,-]{1,100}$/;
const ALBUM_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;
const DATE_RE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;

/** An ISO time for a query (`at`, `before`): a Date, ms or an ISO string → ISO string, else null. */
function isoOf(v) {
  const ms = v instanceof Date ? v.getTime() : msOf(v);
  if (!Number.isFinite(ms) || ms <= 0) return null;
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}

/** A paging cursor of the plugin (kept as it came: a time or an opaque token) or null. */
function cursorOf(v) {
  if (Number.isFinite(v) && v > 0) return String(Math.round(v));
  return typeof v === 'string' && CURSOR_RE.test(v) ? v : null;
}

/** An album id (number or token) or null. */
function albumIdOf(v) {
  return posId(v) || (typeof v === 'string' && ALBUM_ID_RE.test(v) ? v : null);
}

/**
 * GET nodes/<id>/timetravel?at= → { at, historySince, restore, revert, trash, move, total, sample: [{ op, name, path }], limited,
 * lost, ops, max } or null. lost: files whose content of then is gone already (they stay as they are); ops / max: the steps
 * of this time travel and the most the plugin does at once (more: 400 invalid { field: 'at' }).
 */
function normalizeTimeTravelPreview(raw) {
  const r = obj(raw);
  if (!r) return null;
  const n = (k) => count(r[k]) || 0;
  const sample = arr(r.sample).slice(0, 50).map((x) => {
    const o = obj(x);
    const name = o && line(o.name, NAME_MAX);
    if (!name) return null;
    return { op: TT_OPS.includes(o.op) ? o.op : null, name, path: line(o.path, 2000) };
  }).filter(Boolean);
  const out = { at: msOf(r.at), historySince: msOf(r.historySince), restore: n('restore'), revert: n('revert'), trash: n('trash'), move: n('move'), sample, limited: bool(r.limited), lost: n('lost') };
  out.total = out.restore + out.revert + out.trash + out.move;
  out.ops = count(r.ops) ?? out.total;
  out.max = count(r.max) || null;
  return out;
}

/** POST nodes/<id>/timetravel → { at, before, restored, reverted, trashed, moved, failed, lost } or null (`before`: ms, "Rückgängig"). */
function normalizeTimeTravelResult(raw) {
  const r = obj(raw);
  if (!r) return null;
  const n = (k) => (Array.isArray(r[k]) ? r[k].length : count(r[k]) || 0);
  return { at: msOf(r.at), before: msOf(r.before), restored: n('restored'), reverted: n('reverted'), trashed: n('trashed'), moved: n('moved'), failed: n('failed'), lost: n('lost') };
}

/** A photo / video of GET photos, an album or memories → clean object or null. */
function normalizePhoto(v) {
  const o = obj(v);
  if (!o) return null;
  const id = posId(o.id);
  const name = line(o.name, NAME_MAX);
  if (!id || !name) return null;
  const mime = line(o.mime, 100);
  const mediaId = isMediaId(o.mediaId) ? o.mediaId : null;
  return {
    id,
    name,
    mime,
    kind: /^video\//i.test(mime || '') ? 'video' : 'image',
    size: count(o.size) || 0,
    takenAt: msOf(o.takenAt),
    areaId: areaIdOf(o.areaId),
    parentId: posId(o.parentId),
    // Drive 1.7: a boolean (1.1.0 nodes: an object) – the picture is loaded by mediaId, or by the node
    preview: o.preview === true || !!obj(o.preview),
    mediaId,
  };
}

function photoList(v, max) {
  return arr(v).slice(0, max).map(normalizePhoto).filter(Boolean);
}

/** GET photos → { items, next } (next: the cursor for `before`, or null) */
function normalizePhotos(raw) {
  const r = obj(raw) || {};
  return { items: photoList(r.items, 500), next: cursorOf(r.next) };
}

/** GET photos/months → { months: [{ month: 'YYYY-MM', count }] } (newest first) */
function normalizeMonths(raw) {
  const r = obj(raw) || {};
  const months = arr(r.months).slice(0, 2400).map((m) => {
    const o = obj(m);
    return o && typeof o.month === 'string' && MONTH_RE.test(o.month) ? { month: o.month, count: count(o.count) || 0 } : null;
  }).filter(Boolean);
  months.sort((a, b) => (a.month < b.month ? 1 : a.month > b.month ? -1 : 0));
  return { months };
}

/** GET photos/memories → { date, groups: [{ yearsAgo, date, items }] } (the closest year first; date: the day asked for) */
function normalizeMemories(raw) {
  const r = obj(raw) || {};
  const groups = arr(r.groups).slice(0, 100).map((g) => {
    const o = obj(g);
    const yearsAgo = o && posId(o.yearsAgo);
    if (!yearsAgo) return null;
    const items = photoList(o.items, 30);
    return items.length ? { yearsAgo, date: typeof o.date === 'string' && DATE_RE.test(o.date.slice(0, 10)) ? o.date.slice(0, 10) : null, items } : null;
  }).filter(Boolean);
  groups.sort((a, b) => a.yearsAgo - b.yearsAgo);
  return { date: typeof r.date === 'string' && DATE_RE.test(r.date.slice(0, 10)) ? r.date.slice(0, 10) : null, groups };
}

/**
 * An album → { id, name, areaId, count, coverId, frame, updatedAt, canEdit, canFrame, createdBy } or null.
 * canFrame: may switch the photo frame (Drive decides; canEdit alone is not enough).
 */
function normalizeAlbum(v) {
  const o = obj(v);
  const id = o && albumIdOf(o.id);
  const name = o && line(o.name, 200);
  if (!id || !name) return null;
  return {
    id,
    name,
    areaId: areaIdOf(o.areaId),
    count: count(o.count) || 0,
    coverId: posId(o.coverId),
    frame: bool(o.frame),
    updatedAt: msOf(o.updatedAt),
    canEdit: bool(o.canEdit),
    canFrame: bool(o.canFrame),
    createdBy: posId(o.createdBy),
  };
}

/** GET albums → { albums } (by name) */
function normalizeAlbums(raw) {
  const r = obj(raw) || {};
  const albums = arr(r.albums).slice(0, 1000).map(normalizeAlbum).filter(Boolean);
  albums.sort((a, b) => a.name.localeCompare(b.name));
  return { albums };
}

/** GET albums/<id> → { album, items, next } or null. */
function normalizeAlbumPage(raw) {
  const r = obj(raw) || {};
  const album = normalizeAlbum(r.album);
  if (!album) return null;
  return { album, items: photoList(r.items, 500), next: cursorOf(r.next) };
}

function storageNode(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const name = o && line(o.name, NAME_MAX);
  if (!id || !name) return null;
  return { id, name, size: count(o.size) || 0, areaId: areaIdOf(o.areaId), parentId: posId(o.parentId), path: line(o.path, 2000), updatedAt: msOf(o.updatedAt), canDelete: bool(o.canDelete) };
}

/** GET storage → { all, total, limit, areas, people, largest, duplicates } or null (all: every area of the server was counted). */
function normalizeStorage(raw) {
  const r = obj(raw);
  if (!r) return null;
  const t = obj(r.total) || {};
  const lim = obj(r.limit);
  const nums = (o) => ({ bytes: count(o.bytes) || 0, files: count(o.files) || 0, versionsBytes: count(o.versionsBytes) || 0, trashBytes: count(o.trashBytes) || 0 });
  const areas = arr(r.areas).slice(0, 500).map((a) => {
    const o = obj(a);
    const id = o && areaIdOf(o.id);
    if (!id) return null;
    return { id, label: line(o.label, 200) || id, kind: AREA_KINDS.includes(o.kind) ? o.kind : null, ...nums(o), quota: count(o.quota) || null, canPrune: bool(o.canPrune) };
  }).filter(Boolean);
  areas.sort((a, b) => b.bytes - a.bytes);
  const people = arr(r.people).slice(0, 2000).map((p) => {
    const o = obj(p);
    const user = o && posId(o.user);
    return user ? { user, name: line(o.name, 200), bytes: count(o.bytes) || 0, files: count(o.files) || 0 } : null;
  }).filter(Boolean);
  people.sort((a, b) => b.bytes - a.bytes);
  const largest = arr(r.largest).slice(0, 100).map(storageNode).filter(Boolean);
  const duplicates = arr(r.duplicates).slice(0, 100).map((d) => {
    const o = obj(d);
    const items = o ? arr(o.items).slice(0, 200).map(storageNode).filter(Boolean) : [];
    if (items.length < 2) return null;
    return { sha256: sha256Of(o.sha256), size: count(o.size) || 0, count: count(o.count) || items.length, wasted: count(o.wasted) || 0, items };
  }).filter(Boolean);
  return {
    all: bool(r.all),
    total: nums(t),
    limit: lim && count(lim.maxBytes) ? { maxBytes: count(lim.maxBytes) } : null,
    areas,
    people,
    largest,
    duplicates,
  };
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
  isoOf,
  cursorOf,
  albumIdOf,
  normalizeTimeTravelPreview,
  normalizeTimeTravelResult,
  normalizePhoto,
  normalizePhotos,
  normalizeMonths,
  normalizeMemories,
  normalizeAlbum,
  normalizeAlbums,
  normalizeAlbumPage,
  normalizeStorage,
  normalizeLinks16,
  nodeLink,
  allowedLink,
  normalizeIncident,
  normalizeGuard,
  normalizeGuardAnswer,
  incidentIdOf,
  DEVICE_ID_RE,
  normalizeDevice,
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
  CHANGE_OPS,
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
  normalizeChanges,
  normalizeContent,
  normalizeLink,
  normalizeLinks,
  savedOf,
  childrenQuery,
  linkBody,
  errorCode,
};
