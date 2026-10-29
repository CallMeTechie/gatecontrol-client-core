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
    // Drive 1.8 ('docAi'): AI for documents on in this area (null: the Drive does not say)
    docAi: typeof a.docAi === 'boolean' ? a.docAi : null,
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
    // Drive 1.8 ('docAi'): the short form of the recognition { status, kind } on files while the feature is on
    insight: insightShort(o.insight),
    // Drive 1.9 ('vault'): a node of a vault folder — `name` is opaque, the device decrypts nameCipher
    ...(o.encrypted === true ? {
      encrypted: true,
      vaultId: VAULT_ID_RE.test(String(o.vaultId || '')) ? o.vaultId : null,
      nameCipher: typeof o.nameCipher === 'string' && o.nameCipher.length <= 2000 && /^[A-Za-z0-9_-]+$/.test(o.nameCipher) ? o.nameCipher : null,
      keyVersion: posId(o.keyVersion),
    } : { encrypted: false }),
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

// ── Drive 1.8: AI for documents, deadlines, the import ─────

const INSIGHT_STATUS = Object.freeze(['none', 'pending', 'ready', 'failed', 'off']);
const DOC_KINDS = Object.freeze(['invoice', 'contract', 'notice', 'medical', 'certificate', 'statement', 'insurance', 'warranty', 'other']);
const DEADLINE_KINDS = Object.freeze(['payment', 'cancellation', 'objection']);
const DAY_RE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const dayOf = (v) => (typeof v === 'string' && DAY_RE.test(v) ? v : null);

/** node.insight → { status, kind } or null (older Drives, the feature off, a folder). */
function insightShort(v) {
  const o = obj(v);
  if (!o || !INSIGHT_STATUS.includes(o.status)) return null;
  return { status: o.status, kind: o.status === 'ready' && DOC_KINDS.includes(o.kind) ? o.kind : null };
}

/** A deadline → { id, kind, date: 'YYYY-MM-DD', label, reminder: { at, daysBefore, sent } | null, node? } or null. */
function normalizeDeadline(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const date = o && dayOf(o.date);
  if (!id || !date || !DEADLINE_KINDS.includes(o.kind)) return null;
  const r = obj(o.reminder);
  const days = r ? count(r.daysBefore) : null;
  const out = {
    id,
    kind: o.kind,
    date,
    label: line(o.label, 200),
    reminder: r && days !== null && days <= 90 ? { at: msOf(r.at), daysBefore: days, sent: bool(r.sent) } : null,
  };
  if (o.node !== undefined) out.node = normalizeNode(o.node);
  return out;
}

/** GET deadlines → { deadlines } (by date; rows without their file dropped). */
function normalizeDeadlines(raw) {
  const r = obj(raw) || {};
  const list = arr(r.deadlines).slice(0, 500).map(normalizeDeadline).filter((d) => d && d.node);
  list.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.id - b.id));
  return { deadlines: list };
}

/**
 * GET / POST nodes/<id>/insight → { status, kind, title, date, sender, amount, currency, error, at,
 * suggestion: { folderId, folderPath, name } | null, deadlines } or null.
 */
function normalizeInsight(raw) {
  const r = obj(raw);
  if (!r || !INSIGHT_STATUS.includes(r.status)) return null;
  const s = obj(r.suggestion);
  const folderId = s ? posId(s.folderId) : null;
  const name = s ? line(s.name, NAME_MAX) : null;
  const amount = typeof r.amount === 'number' && Number.isFinite(r.amount) && Math.abs(r.amount) < 1e12 ? r.amount : null;
  const currency = typeof r.currency === 'string' && /^[A-Z]{3}$/.test(r.currency) ? r.currency : null;
  return {
    status: r.status,
    kind: DOC_KINDS.includes(r.kind) ? r.kind : null,
    title: line(r.title, 200),
    date: dayOf(r.date),
    sender: line(r.sender, 200),
    amount,
    currency: amount === null ? null : currency,
    error: codeOf(r.error),
    at: msOf(r.at),
    // folderPath: relative to the area's root ('' the top folder)
    suggestion: folderId || name ? { folderId, folderPath: folderId ? (typeof s.folderPath === 'string' ? s.folderPath.replace(CTRL_LINE_RE, ' ').slice(0, 2000) : '') : null, name } : null,
    deadlines: arr(r.deadlines).slice(0, 20).map(normalizeDeadline).filter(Boolean).map(({ node, ...d }) => d),
  };
}

/**
 * The portal's page of the import (Drive 1.8 'cloudImport'): `/portal?drive=import#plg-gatecontrol-drive` on the
 * origin of `base` (me.links.drive, else the portal's address) → https URL or null.
 */
function importLink(base) {
  const u = httpsUrl(base);
  if (!u) return null;
  return `${new URL(u).origin}/portal?drive=import#${APP_ROUTE}`;
}

// ── Drive 1.9: vault folders, office ───────────────────────

const VAULT_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const VAULT_DEVICE_RE = /^[A-Za-z0-9_-]{22}$/;
const VAULT_DEVICE_STATES = Object.freeze(['approved', 'pending', 'revoked']);
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const b64uOf = (v, max) => (typeof v === 'string' && v.length <= max && B64U_RE.test(v) ? v : null);
const vaultIdOf = (v) => (typeof v === 'string' && VAULT_ID_RE.test(v) ? v : null);
const vaultDeviceIdOf = (v) => (typeof v === 'string' && VAULT_DEVICE_RE.test(v) ? v : null);

/** A vault → { id, nodeId, areaId, parentId, nameCipher, keyVersion, recoveryPub, recoveryHolder, needsRotation, createdAt, createdBy, rotatedAt, myDevices, pending } or null. */
function normalizeVault(v) {
  const o = obj(v);
  const id = o && vaultIdOf(o.id);
  const nodeId = o && posId(o.nodeId);
  if (!id || !nodeId) return null;
  return {
    id,
    nodeId,
    areaId: areaIdOf(o.areaId),
    parentId: posId(o.parentId),
    nameCipher: b64uOf(o.nameCipher, 2000),
    keyVersion: posId(o.keyVersion) || 1,
    recoveryPub: b64uOf(o.recoveryPub, 43),
    recoveryHolder: posId(o.recoveryHolder),
    needsRotation: bool(o.needsRotation),
    createdAt: msOf(o.createdAt),
    createdBy: posId(o.createdBy),
    rotatedAt: msOf(o.rotatedAt),
    myDevices: arr(o.myDevices).slice(0, 200).map((d) => {
      const x = obj(d);
      const did = x && vaultDeviceIdOf(x.deviceId);
      return did && VAULT_DEVICE_STATES.includes(x.state) ? { deviceId: did, state: x.state, name: line(x.name, 80) } : null;
    }).filter(Boolean),
    pending: count(o.pending) || 0,
  };
}

/** A device of a vault → { deviceId, userId, name, platform, publicKey, state, via, createdAt, approvedAt, approvedBy, revokedAt } or null. */
function normalizeVaultDevice(v) {
  const o = obj(v);
  const deviceId = o && vaultDeviceIdOf(o.deviceId);
  const publicKey = o && b64uOf(o.publicKey, 43);
  if (!deviceId || !publicKey || publicKey.length !== 43 || !VAULT_DEVICE_STATES.includes(o.state)) return null;
  return {
    deviceId,
    userId: posId(o.userId),
    name: line(o.name, 80),
    platform: typeof o.platform === 'string' && /^[a-z]{1,16}$/.test(o.platform) ? o.platform : null,
    publicKey,
    state: o.state,
    via: ['create', 'device', 'recovery'].includes(o.via) ? o.via : null,
    createdAt: msOf(o.createdAt),
    approvedAt: msOf(o.approvedAt),
    approvedBy: posId(o.approvedBy),
    revokedAt: msOf(o.revokedAt),
  };
}

/** The wraps of GET vaults/<id>/keys or …/recovery → [{ keyVersion, wrap }] (by version). */
function wrapsOf(v) {
  const out = arr(v).slice(0, 10000).map((w) => {
    const o = obj(w);
    const kv = o && posId(o.keyVersion);
    const wrap = o && b64uOf(o.wrap, 108);
    return kv && wrap && wrap.length === 108 ? { keyVersion: kv, wrap } : null;
  }).filter(Boolean);
  out.sort((a, b) => a.keyVersion - b.keyVersion);
  return out;
}

/** GET vaults/<id>/keys?deviceId= → { deviceId, state, keyVersion, keys } or null. */
function normalizeVaultKeys(raw) {
  const r = obj(raw);
  if (!r || !VAULT_DEVICE_STATES.includes(r.state)) return null;
  return { deviceId: vaultDeviceIdOf(r.deviceId), state: r.state, keyVersion: posId(r.keyVersion), keys: wrapsOf(r.keys) };
}

/** GET vaults/<id>/recovery → { recoveryPub, keyVersion, keys } or null. */
function normalizeVaultRecovery(raw) {
  const r = obj(raw);
  const pub = r && b64uOf(r.recoveryPub, 43);
  if (!pub) return null;
  return { recoveryPub: pub, keyVersion: posId(r.keyVersion), keys: wrapsOf(r.keys) };
}

/** The documents office in the browser opens (contract): word processing, spreadsheets, presentations, CSV. */
const OFFICE_EXTS = Object.freeze(['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'csv']);

/** Is `name` a document "Im Browser bearbeiten" offers? */
function isOfficeName(name) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(typeof name === 'string' ? name : '');
  return !!m && OFFICE_EXTS.includes(m[1].toLowerCase());
}

/** POST nodes/<id>/office → { url, mode: 'edit' | 'view', expiresAt } or null (an https URL only). */
function normalizeOffice(raw) {
  const r = obj(raw);
  const url = r && httpsUrl(r.url);
  if (!url) return null;
  return { url, mode: r.mode === 'edit' ? 'edit' : 'view', expiresAt: msOf(r.expiresAt) };
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

/**
 * Drive 1.11 ('vaultsApart'): vault folders are not part of the files any more (only the menu "Tresore" shows them).
 * Without the feature the app leaves them out itself: in a folder outside a vault every encrypted node is a vault's
 * own folder (or lies in one) → the list without them.
 */
function withoutVaults(items, { inVault = false } = {}) {
  const list = arr(items);
  return inVault ? list : list.filter((n) => !(n && n.encrypted));
}

/**
 * The folder tree of the menu: `GET nodes/<id>/children?dirs=1` (Drive 1.11: folders only, no vaults, each with
 * `hasDirs`) or a plain children page (older Drives: hasDirs unknown → null) → { items: [{ id, name, hasDirs }], next }.
 */
function normalizeDirs(raw, max = 1000) {
  const r = obj(raw) || {};
  const items = [];
  for (const v of arr(r.items).slice(0, max)) {
    const n = normalizeNode(v);
    if (!n || !n.isDir || n.deleted || n.encrypted) continue;
    items.push({ id: n.id, name: n.name, hasDirs: typeof v.hasDirs === 'boolean' ? v.hasDirs : null });
  }
  return { items, next: count(r.next) };
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

// ── Drive 1.12: jobs for many nodes at once, ZIP, one link for many ──

const OP_KINDS = Object.freeze(['move', 'copy', 'trash', 'restore', 'purge']);
const OP_STATES = Object.freeze(['running', 'done', 'failed', 'cancelled']);
const OP_CONFLICT = Object.freeze(['version', 'rename', 'skip']);
const OP_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const REASON_RE = /^[a-z_]{1,40}$/;
const OP_IDS_MAX = 10000;          // ids of one request (the plugin limits the nodes after expanding folders itself)
const LINK_IDS_MAX = 5000;      // one link for several: with 'zipMixed' up to 5000 files

/** A job's id (number or token) → string, else null. */
function opIdOf(v) {
  const n = posId(v);
  if (n) return String(n);
  return typeof v === 'string' && OP_ID_RE.test(v) ? v : null;
}

/** Distinct positive node ids (at most `max`), or null when none, too many or one is not an id. */
function idList(ids, max = OP_IDS_MAX) {
  if (!Array.isArray(ids) || !ids.length || ids.length > max) return null;
  const list = ids.map(posId);
  if (list.some((x) => !x)) return null;
  return [...new Set(list)];
}

const reasonOf = (v) => (typeof v === 'string' && REASON_RE.test(v) ? v : 'failed');
const countOrLength = (v) => (Array.isArray(v) ? v.length : count(v) || 0);

/** [{ id, reason, name? }] of a check / a job's report. */
function blockedList(v, max = 1000) {
  return arr(v).slice(0, max).map((x) => {
    const o = obj(x);
    const id = o && posId(o.id);
    if (!id) return null;
    const out = { id, reason: reasonOf(o.reason || o.code) };
    const name = line(o.name, NAME_MAX);
    if (name) out.name = name;
    return out;
  }).filter(Boolean);
}

/**
 * POST ops/check → { items, files, folders, bytes, conflicts: [{ id, name, path, isDir, size, mtime, existing: { id, size,
 * mtime, isDir }, same }], conflictsMore, merges, blocked: [{ id, reason, name? }], quota: { needed, free } | null, limit,
 * tooMany } or null. `same`: the file there has the same content (counts as done, never stored twice); folders of the
 * same name are merged (`merges`), their files in conflicts with their `path`.
 */
function normalizeOpCheck(raw) {
  const r = obj(raw);
  if (!r) return null;
  const conflicts = arr(r.conflicts).slice(0, 1000).map((x) => {
    const o = obj(x);
    const id = o && posId(o.id);
    const name = o && line(o.name, NAME_MAX);
    if (!id || !name) return null;
    const e = obj(o.existing) || {};
    return {
      id,
      name,
      // inside a merged folder: "Ordner/datei"
      path: line(o.path, 2000),
      isDir: bool(o.isDir),
      size: count(o.size),
      mtime: msOf(o.mtime),
      existing: { id: posId(e.id), size: count(e.size), mtime: msOf(e.mtime), isDir: bool(e.isDir) },
      same: bool(o.same),
    };
  }).filter(Boolean);
  const q = obj(r.quota);
  return {
    items: count(r.items),
    files: count(r.files) || 0,
    folders: count(r.folders) || 0,
    bytes: count(r.bytes) || 0,
    conflicts,
    conflictsMore: count(r.conflictsMore) || 0,
    merges: count(r.merges) || 0,
    blocked: blockedList(r.blocked),
    // copy / move into another area: { needed, free } (free null: unknown)
    quota: q ? { needed: count(q.needed) || 0, free: count(q.free) } : null,
    limit: count(r.limit),
    tooMany: bool(r.tooMany),
  };
}

/**
 * A job (POST ops, GET ops/<id>, live event `op`) → { id, kind, state, total, done, bytesTotal, bytesDone, targetId,
 * targetPath, targetName, name, count, results: { done, skipped, failed: [{ id, reason }] } | null, undoUntil, undoOf, code } or null.
 */
function normalizeOp(raw) {
  const r = obj(raw);
  const o = (r && obj(r.op)) || r;
  const id = o && opIdOf(o.id);
  if (!id) return null;
  const res = obj(o.results);
  const failed = res ? blockedList(res.failed, 100) : [];
  return {
    id,
    // 'undo': the job that undoes another one (undoOf)
    kind: OP_KINDS.includes(o.kind) || o.kind === 'undo' ? o.kind : (OP_KINDS.includes(o.op) ? o.op : null),
    state: OP_STATES.includes(o.state) ? o.state : 'running',
    total: count(o.total) || 0,
    done: count(o.done) || 0,
    bytesTotal: count(o.bytesTotal) || 0,
    bytesDone: count(o.bytesDone) || 0,
    targetId: posId(o.targetId) || posId(o.target),
    targetPath: line(o.targetPath, 2000),
    targetName: line(o.targetName, NAME_MAX),
    // the first node's name (null in a vault)
    name: line(o.label, NAME_MAX) || line(o.name, NAME_MAX),
    // the ids asked for ("N Elemente …"); total / done count files
    count: count(o.items) ?? count(o.count),
    results: res ? {
      done: countOrLength(res.done),
      skipped: countOrLength(res.skipped),
      failed,
      failedCount: Math.max(count(res.failedCount) || 0, failed.length),
      // the top nodes made / moved at the target ("neu hier")
      resultIds: arr(res.resultIds).slice(0, 500).map(posId).filter(Boolean),
    } : null,
    undoUntil: msOf(o.undoUntil),
    undoOf: opIdOf(o.undoOf),
    undoneBy: opIdOf(o.undoneBy),
    // copy: who brings the bytes ('server' with GateControl's media copy; 'client' is not done by this app)
    transfer: o.transfer === 'client' || o.transfer === 'server' ? o.transfer : null,
    transfersLeft: count(o.transfersLeft) || 0,
    code: codeOf(o.error) || codeOf(o.code),
  };
}

/** GET ops?state=running → [job] */
function normalizeOps(raw) {
  const r = obj(raw) || {};
  return arr(r.ops).slice(0, 100).map(normalizeOp).filter(Boolean);
}

/** POST ops / ops/check body { op, ids, target?, onConflict? } or null when invalid. */
function opBody({ op, ids, target = null, onConflict = null } = {}) {
  const list = idList(ids);
  if (!OP_KINDS.includes(op) || !list) return null;
  const body = { op, ids: list };
  if (op === 'move' || op === 'copy') {
    const tg = posId(target);
    if (!tg) return null;
    body.target = tg;
  }
  if (onConflict !== null && onConflict !== undefined) {
    if (!OP_CONFLICT.includes(onConflict)) return null;
    body.onConflict = onConflict;
  }
  return body;
}

/**
 * POST zip → { url, name, expiresAt, files, skipped } or null: `url` the short-lived address of the ZIP — Drive 1.12 an
 * absolute bearer address of GateControl (`https://<GateControl>/s/<token>/zip`, no login), or a path on the server;
 * `name` its file name (…zip).
 */
function normalizeZip(raw) {
  const r = obj(raw) || {};
  const z = obj(r.zip) || r;
  let url = null;
  if (typeof z.url === 'string' && z.url.length <= LINK_URL_MAX) {
    if (/^\/[A-Za-z0-9/_.~%?=&:+,-]*$/.test(z.url) && !z.url.includes('..') && !z.url.startsWith('//')) url = z.url;
    else if (/^https?:\/\//i.test(z.url)) { try { url = new URL(z.url).href; } catch { url = null; } }
  }
  if (!url) return null;
  const name = safeName(line(z.name, NAME_MAX) || '') || 'Drive.zip';
  return { url, name: /\.zip$/i.test(name) ? name : `${name}.zip`, expiresAt: msOf(z.expiresAt), files: count(z.files), skipped: blockedList(z.skipped) };
}

/** Body of one link for several files: { nodeIds, mode: 'view' | 'download', expires, pin? } or null. */
function multiLinkBody({ ids, mode, expires, pin } = {}) {
  const list = idList(ids, LINK_IDS_MAX);
  if (!list || (mode !== 'view' && mode !== 'download') || !LINK_EXPIRES.includes(expires)) return null;
  const body = { nodeIds: list, mode, expires };
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
  INSIGHT_STATUS,
  DOC_KINDS,
  DEADLINE_KINDS,
  insightShort,
  normalizeInsight,
  normalizeDeadline,
  normalizeDeadlines,
  importLink,
  VAULT_ID_RE,
  VAULT_DEVICE_RE,
  vaultIdOf,
  vaultDeviceIdOf,
  normalizeVault,
  normalizeVaultDevice,
  normalizeVaultKeys,
  normalizeVaultRecovery,
  OFFICE_EXTS,
  isOfficeName,
  normalizeOffice,
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
  withoutVaults,
  normalizeDirs,
  linkBody,
  errorCode,
  OP_KINDS,
  OP_STATES,
  OP_CONFLICT,
  OP_IDS_MAX,
  LINK_IDS_MAX,
  opIdOf,
  idList,
  normalizeOpCheck,
  normalizeOp,
  normalizeOps,
  opBody,
  normalizeZip,
  multiLinkBody,
};
