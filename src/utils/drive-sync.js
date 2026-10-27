'use strict';

/**
 * Pure helpers of "Ordner sichern" (Drive's folder backup / sync of the
 * Windows Pro app, services/drive-sync.js): settings and folder entries,
 * what is left out (temporary files, node_modules / .git, too large), names
 * of conflict copies, the guard against mass deletes, the home network, the
 * remote tree (from the plugin's children and its change log) and the
 * planner that compares the last agreed state (base) with this PC (local)
 * and the Drive (remote).
 *
 * Paths are relative to the folder, with '/' between the parts; keys are the
 * paths in lower case (NFC) — Windows and Drive both ignore the case of names.
 *
 * Shapes:
 *   base   { [key]: { path, dir, size, mtime, sha256, nodeId, rev } }     what both sides had after the last run
 *   local  Map key → { path, dir, size, mtime }                           this PC now (scanLocal of the service)
 *   tree   { [nodeId]: { id, parentId, name, isDir, size, sha256, rev, mtime } }   the folder in Drive (below rootId)
 *   remote Map key → { path, dir, nodeId, parentId, rev, size, sha256, mtime }     the tree by path (remoteByPath)
 *
 * Electron-free and side-effect free (unit-tested directly).
 */

const crypto = require('crypto');
const drive = require('./drive');

const MODES = Object.freeze(['backup', 'sync']);
const GB = 1024 * 1024 * 1024;
const DEFAULT_MAX_BYTES = 10 * GB;
const MAX_KBS = 1024 * 1024;                 // 1 GB/s: anything above is "unlimited" anyway
const BACKUP_DELETE_DAYS = 30;               // "Nur sichern": a file deleted on the PC goes in Drive after 30 days
const MASS_DELETE_COUNT = 500;               // more deletes than this at once: ask first
const MASS_DELETE_SHARE = 0.2;               // … or more than 20 % of the folder's files …
const MASS_DELETE_MIN = 10;                  // … when that is at least 10 files (a folder of 3 files asks for nothing)
const DEVICES_FOLDER = 'Geräte';
const DOWNLOAD_SUFFIX = '.gcdownload';       // files being downloaded (next to their place, never synced)
const MAX_FOLDERS = 50;
const HOME_MAX = 10;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const bool = (v, def) => (typeof v === 'boolean' ? v : def);

// ── Paths and keys ─────────────────────────────────────────

/** 'A/B/c.txt' → 'a/b/c.txt' (NFC, lower case): the same place for Windows and Drive. */
function keyOf(rel) {
  return String(rel || '').normalize('NFC').toLowerCase();
}

function parentOf(rel) {
  const s = String(rel || '');
  const i = s.lastIndexOf('/');
  return i < 0 ? '' : s.slice(0, i);
}

function baseName(rel) {
  const s = String(rel || '');
  return s.slice(s.lastIndexOf('/') + 1);
}

function joinRel(a, b) {
  return a ? `${a}/${b}` : b;
}

/** Is `key` the folder `dirKey` itself or below it? */
function under(key, dirKey) {
  return key === dirKey || key.startsWith(`${dirKey}/`);
}

const depth = (rel) => (rel ? rel.split('/').length : 0);

// ── What is left out ───────────────────────────────────────

const TEMP_NAMES = new Set(['thumbs.db', 'desktop.ini', '.ds_store', 'ehthumbs.db', 'ehthumbs_vista.db']);
const DEV_DIRS = new Set(['node_modules', '.git']);

/** Temporary files: `~$*` (Office), `*.tmp`, `Thumbs.db`, `desktop.ini`, `.DS_Store`, our own downloads. */
function isTempName(name) {
  const n = String(name || '').toLowerCase();
  if (!n) return true;
  if (TEMP_NAMES.has(n)) return true;
  if (n.startsWith('~$') || n.endsWith('.tmp') || n.endsWith(DOWNLOAD_SUFFIX)) return true;
  // Office / LibreOffice lock files
  if (n.startsWith('.~lock.') && n.endsWith('#')) return true;
  return false;
}

/**
 * Why `rel` is left out, or null.
 * @param {string} rel
 * @param {{ dir?: boolean, size?: number }} item
 * @param {object} settings - normalizeSettings()
 * @returns {null | 'temp' | 'dev' | 'too_large' | 'name'}
 */
function excluded(rel, { dir = false, size = 0 } = {}, settings = DEFAULT_SETTINGS) {
  const parts = String(rel || '').split('/');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    const last = i === parts.length - 1;
    if (settings.skipDev && DEV_DIRS.has(p.toLowerCase()) && (!last || dir)) return 'dev';
    if (last && !dir && isTempName(p)) return 'temp';
    // A name Drive does not take (forbidden characters, a dot or space at the end) cannot go there.
    if (drive.safeName(p) !== p) return 'name';
  }
  if (!dir && settings.maxFileBytes > 0 && Number(size) > settings.maxFileBytes) return 'too_large';
  return null;
}

// ── Names ──────────────────────────────────────────────────

const pad = (n) => String(n).padStart(2, '0');

/**
 * The name of the copy that keeps a conflicting local file:
 * "Bericht.docx" → "Bericht (Konflikt Desktop-PC 2026-10-27 14-05).docx".
 */
function conflictName(name, device, at = Date.now()) {
  const n = String(name || 'Datei');
  const d = new Date(at);
  const stamp = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}-${pad(d.getMinutes())}`;
  const dev = drive.safeName(String(device || '')) || 'PC';
  const dot = n.lastIndexOf('.');
  const stem = dot > 0 ? n.slice(0, dot) : n;
  const ext = dot > 0 ? n.slice(dot) : '';
  const tag = ` (Konflikt ${dev} ${stamp})`;
  const room = drive.NAME_MAX - tag.length - ext.length;
  return drive.safeName(`${stem.slice(0, Math.max(1, room))}${tag}${ext}`) || `Konflikt ${stamp}`;
}

/** "Name (2)", "Name (3)" … the first that `taken` does not hold (keys). */
function freeName(name, taken) {
  if (!taken.has(keyOf(name))) return name;
  for (let i = 2; i < 10000; i++) {
    const c = `${name} (${i})`;
    if (!taken.has(keyOf(c))) return c;
  }
  return `${name} (${Date.now()})`;
}

/** The PC's name in Drive ("Geräte › <Name>"): the host name, cleaned. */
function deviceName(raw) {
  const s = drive.safeName(String(raw || '').trim().slice(0, 60));
  return s || 'PC';
}

// ── Settings and folders ───────────────────────────────────

const DEFAULT_SETTINGS = Object.freeze({
  deviceName: null,     // set when the first folder is added (the host name)
  paused: false,        // all folders
  skipDev: true,        // node_modules and .git
  maxFileBytes: DEFAULT_MAX_BYTES,
  upKBs: 0,             // 0 = unlimited
  downKBs: 0,
  homeOnly: false,      // only in a home network (homeNets)
  homeNets: [],         // fingerprints of the networks marked as home (networkFingerprint)
  vpnOnly: false,       // only while the VPN is connected
});

function kbs(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.min(MAX_KBS, Math.round(n)) : 0;
}

/** Settings as stored / sent by the page → clean settings (unknown keys dropped). */
function normalizeSettings(raw) {
  const r = obj(raw) || {};
  const max = Number(r.maxFileBytes);
  return {
    deviceName: typeof r.deviceName === 'string' && drive.safeName(r.deviceName) ? deviceName(r.deviceName) : null,
    paused: bool(r.paused, false),
    skipDev: bool(r.skipDev, true),
    maxFileBytes: Number.isSafeInteger(max) && max >= 0 ? Math.min(max, drive.MAX_FILE_BYTES) : DEFAULT_MAX_BYTES,
    upKBs: kbs(r.upKBs),
    downKBs: kbs(r.downKBs),
    homeOnly: bool(r.homeOnly, false),
    homeNets: (Array.isArray(r.homeNets) ? r.homeNets : []).filter((x) => typeof x === 'string' && /^[0-9a-f]{16,64}$/.test(x)).slice(0, HOME_MAX),
    vpnOnly: bool(r.vpnOnly, false),
  };
}

const FOLDER_ID_RE = /^[a-f0-9]{8,32}$/;

/**
 * A folder of the list → { id, path, mode, remoteName, target, scope, paused, addedAt, lastSyncAt } or null.
 * target: { nodeId, areaId, label } — the Drive folder (backup: Geräte › <PC> › <name>, made on the first run).
 */
function normalizeFolder(raw) {
  const r = obj(raw);
  if (!r || typeof r.id !== 'string' || !FOLDER_ID_RE.test(r.id)) return null;
  if (typeof r.path !== 'string' || !r.path || r.path.length > 4096) return null;
  const mode = MODES.includes(r.mode) ? r.mode : null;
  if (!mode) return null;
  const t = obj(r.target) || {};
  const target = {
    nodeId: drive.posId(t.nodeId),
    areaId: drive.areaIdOf(t.areaId),
    label: drive.line(t.label, 600),
  };
  if (mode === 'sync' && !target.nodeId) return null;
  return {
    id: r.id,
    path: r.path,
    mode,
    remoteName: drive.safeName(typeof r.remoteName === 'string' ? r.remoteName : '') || null,
    target,
    scope: typeof r.scope === 'string' && /^[0-9a-f]{16}$/.test(r.scope) ? r.scope : null,
    paused: bool(r.paused, false),
    addedAt: drive.msOf(r.addedAt),
    lastSyncAt: drive.msOf(r.lastSyncAt),
  };
}

/** The stored config → { v, settings, folders }. */
function normalizeConfig(raw) {
  const r = obj(raw) || {};
  const folders = [];
  const seen = new Set();
  for (const f of (Array.isArray(r.folders) ? r.folders : []).slice(0, MAX_FOLDERS)) {
    const n = normalizeFolder(f);
    if (!n || seen.has(n.id)) continue;
    seen.add(n.id);
    folders.push(n);
  }
  return { v: 1, settings: normalizeSettings(r.settings), folders };
}

/** Does the new folder `p` overlap one of the list (the same, inside, or around it)? Windows paths, case-insensitive. */
function overlaps(p, folders, sep = '\\') {
  const norm = (x) => String(x || '').replace(/[\\/]+/g, sep).replace(/[\\/]+$/, '').toLowerCase();
  const a = norm(p);
  return folders.some((f) => {
    const b = norm(f.path);
    return a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
  });
}

// ── Mass deletes ───────────────────────────────────────────

/** Deleting `count` of the folder's `total` files at once: ask first? (> 500, or > 20 % and at least 10) */
function massDelete(count, total) {
  const c = Number(count) || 0;
  const t = Number(total) || 0;
  if (c > MASS_DELETE_COUNT) return true;
  return c >= MASS_DELETE_MIN && c > MASS_DELETE_SHARE * t;
}

// ── Home network ───────────────────────────────────────────

const VPN_IF_RE = /wireguard|gatecontrol|\bwg|tun|tap|vpn|virtual|vethernet|hyper-v|vmware|virtualbox|loopback|docker/i;

function ipv4ToInt(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function isPrivateV4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  const a = n >>> 24;
  const b = (n >>> 16) & 255;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * The networks this PC is in: '192.168.178.0/24' per private IPv4 address of a
 * physical adapter (VPN and virtual adapters left out), from os.networkInterfaces().
 */
function localNetworks(ifaces) {
  const out = new Set();
  for (const [name, list] of Object.entries(obj(ifaces) || {})) {
    if (VPN_IF_RE.test(name)) continue;
    for (const a of Array.isArray(list) ? list : []) {
      if (!a || a.internal || (a.family !== 'IPv4' && a.family !== 4) || !isPrivateV4(a.address)) continue;
      const ip = ipv4ToInt(a.address);
      const mask = ipv4ToInt(a.netmask);
      if (ip === null || mask === null) continue;
      const prefix = mask.toString(2).replace(/0+$/, '').length;
      if (prefix < 8 || prefix > 30) continue;
      const net = (ip & mask) >>> 0;
      out.add(`${net >>> 24}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${prefix}`);
    }
  }
  return [...out].sort();
}

/**
 * Fingerprints of the networks (sha-256, 32 hex): with the gateway's MAC address when known
 * (getGateways → { '192.168.178.0/24': 'aa:bb:…' }), so two routers with the same addresses differ.
 */
function networkFingerprints(networks, gateways = {}) {
  return (networks || []).map((n) => {
    const mac = gateways && typeof gateways[n] === 'string' ? gateways[n].toLowerCase() : '';
    return crypto.createHash('sha256').update(`gc-home\n${n}\n${mac}`).digest('hex').slice(0, 32);
  });
}

/** Is one of the networks now one of the home networks? */
function atHome(current, homeNets) {
  const set = new Set(homeNets || []);
  return (current || []).some((x) => set.has(x));
}

// ── The remote tree ────────────────────────────────────────

/** A node of the plugin → the fields the sync keeps. */
function slimNode(n) {
  return {
    id: n.id,
    parentId: n.parentId,
    name: n.name,
    isDir: !!n.isDir,
    size: n.size || 0,
    sha256: n.sha256 || null,
    rev: n.rev || 0,
    mtime: Number.isFinite(n.mtime) ? n.mtime : null,
  };
}

/** Removes `id` and everything below it from `tree` (in place) → ids removed. */
function dropSubtree(tree, id) {
  const gone = [];
  const kids = new Map();
  for (const n of Object.values(tree)) {
    if (!kids.has(n.parentId)) kids.set(n.parentId, []);
    kids.get(n.parentId).push(n.id);
  }
  const stack = [id];
  while (stack.length) {
    const x = stack.pop();
    if (!tree[x]) continue;
    gone.push(x);
    delete tree[x];
    for (const k of kids.get(x) || []) stack.push(k);
  }
  return gone;
}

/**
 * Applies changes of `GET changes` to the tree of the folder `rootId` (in place)
 * → { touched, rescan: [dir ids that came in with content], rootGone }.
 * A node counts when its parent is the root or a folder of the tree; one whose
 * parent left the tree left with it.
 */
function applyChanges(tree, rootId, changes) {
  let touched = false;
  let rootGone = false;
  const rescan = new Set();
  for (const c of changes || []) {
    const n = c.node;
    if (c.nodeId === rootId) {
      if (!n || n.deleted || c.op === 'delete' || c.op === 'purge') rootGone = true;
      continue;
    }
    const known = !!tree[c.nodeId];
    if (!n || n.deleted || c.op === 'purge') {
      if (known) { dropSubtree(tree, c.nodeId); touched = true; }
      rescan.delete(c.nodeId);
      continue;
    }
    const parentIn = n.parentId === rootId || !!(tree[n.parentId] && tree[n.parentId].isDir);
    if (parentIn) {
      tree[n.id] = slimNode(n);
      touched = true;
      if (n.isDir && (!known || c.op === 'restore')) rescan.add(n.id);
    } else if (known) {
      dropSubtree(tree, n.id);
      touched = true;
    }
  }
  return { touched, rescan: [...rescan], rootGone };
}

/**
 * The tree by path → Map key → { path, dir, nodeId, parentId, rev, size, sha256, mtime }.
 * Two nodes with the same name ignoring case (the plugin does not allow it): the first wins.
 */
function remoteByPath(tree, rootId) {
  const kids = new Map();
  for (const n of Object.values(tree || {})) {
    if (!kids.has(n.parentId)) kids.set(n.parentId, []);
    kids.get(n.parentId).push(n);
  }
  const out = new Map();
  const stack = [[rootId, '']];
  const seen = new Set();
  while (stack.length) {
    const [id, rel] = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const list = (kids.get(id) || []).slice().sort((a, b) => a.id - b.id);
    for (const n of list) {
      const p = joinRel(rel, n.name);
      const k = keyOf(p);
      if (out.has(k)) continue;
      out.set(k, { path: p, dir: n.isDir, nodeId: n.id, parentId: n.parentId, rev: n.rev, size: n.size, sha256: n.sha256, mtime: n.mtime });
      if (n.isDir) stack.push([n.id, p]);
    }
  }
  return out;
}

// ── Planning ───────────────────────────────────────────────

const sameFile = (a, b) => !!a && !!b && a.size === b.size && a.mtime === b.mtime;
const remoteSame = (b, r) => !!b && !!r && b.nodeId === r.nodeId && b.rev === r.rev;

/** Rewrites the keys of `base` below `fromKey` to below `toPath` (after a move) → new base. */
function rebase(base, fromKey, toPath) {
  const out = {};
  const toKey = keyOf(toPath);
  for (const [k, e] of Object.entries(base)) {
    if (!under(k, fromKey)) { out[k] = e; continue; }
    const rest = e.path.slice(fromKey.length);
    const p = toPath + rest;
    out[toKey + k.slice(fromKey.length)] = { ...e, path: p };
  }
  return out;
}

/**
 * Moves that are sure (done as moves, not as delete + upload / download):
 *   local  — a folder renamed / moved on the PC: every file it had is in a new folder under the same names
 *            (size and time unchanged); a file renamed / moved: the only new file with its size and time.
 *   remote — a node of the base (by its id) has another path in Drive while the PC still has the old one.
 * The source must be unchanged on the other side and the target free on both.
 * → [{ op: 'moveRemote' | 'moveLocal', from, to, fromKey, toKey, nodeId, dir }]
 * Only the first sure move per run is returned for folders (the keys change); the service plans again after.
 */
function planMoves({ base, local, remote, mode }) {
  const out = [];
  const used = new Set();
  const baseKeys = Object.keys(base);
  const newLocal = [...local.entries()].filter(([k]) => !base[k]);
  const ok = (fromKey, toKey) => !used.has(fromKey) && !used.has(toKey);

  // Folders renamed / moved on the PC
  for (const [k, b] of Object.entries(base)) {
    if (!b.dir || local.has(k)) continue;
    const r = remote.get(k);
    if (!remoteSame(b, r)) continue;
    if (local.has(parentOf(k)) === false && parentOf(k) !== '') continue; // the parent went too: move the parent
    const files = baseKeys.filter((x) => x !== k && under(x, k) && !base[x].dir);
    if (!files.length) continue;
    for (const [nk, l] of newLocal) {
      if (!l.dir || remote.has(nk) || !ok(k, nk)) continue;
      const all = files.every((fk) => {
        const lk = nk + fk.slice(k.length);
        return sameFile(local.get(lk), base[fk]) && !base[lk];
      });
      if (!all) continue;
      out.push({ op: 'moveRemote', from: b.path, to: l.path, fromKey: k, toKey: nk, nodeId: b.nodeId, dir: true });
      return out;
    }
  }

  // Folders renamed / moved in Drive (sync only)
  if (mode === 'sync') {
    const byNode = new Map();
    for (const [k, r] of remote) byNode.set(r.nodeId, k);
    for (const [k, b] of Object.entries(base)) {
      if (!b.dir || !local.has(k) || remote.has(k)) continue;
      const rk = byNode.get(b.nodeId);
      if (!rk || rk === k || local.has(rk) || base[rk]) continue;
      if (under(rk, k)) continue;
      out.push({ op: 'moveLocal', from: b.path, to: remote.get(rk).path, fromKey: k, toKey: rk, nodeId: b.nodeId, dir: true });
      return out;
    }
  }

  // Files renamed / moved on the PC
  const gone = Object.entries(base).filter(([k, b]) => !b.dir && !local.has(k));
  for (const [k, b] of gone) {
    const r = remote.get(k);
    if (!remoteSame(b, r)) continue;
    const cands = newLocal.filter(([nk, l]) => !l.dir && sameFile(l, b) && !remote.has(nk) && !base[nk]);
    if (cands.length !== 1) continue;
    const others = gone.filter(([, x]) => sameFile(x, b));
    if (others.length !== 1) continue; // two files with the same size and time went: not sure which is which
    const [nk, l] = cands[0];
    if (!ok(k, nk)) continue;
    used.add(k); used.add(nk);
    out.push({ op: 'moveRemote', from: b.path, to: l.path, fromKey: k, toKey: nk, nodeId: b.nodeId, dir: false });
  }

  // Files renamed / moved in Drive (sync only)
  if (mode === 'sync') {
    const byNode = new Map();
    for (const [k, r] of remote) if (!r.dir) byNode.set(r.nodeId, k);
    for (const [k, b] of Object.entries(base)) {
      if (b.dir || remote.has(k) || !sameFile(local.get(k), b)) continue;
      const rk = byNode.get(b.nodeId);
      if (!rk || rk === k || local.has(rk) || base[rk] || !ok(k, rk)) continue;
      const r = remote.get(rk);
      if (r.rev !== b.rev) continue; // changed too: download + delete
      used.add(k); used.add(rk);
      out.push({ op: 'moveLocal', from: b.path, to: r.path, fromKey: k, toKey: rk, nodeId: b.nodeId, dir: false });
    }
  }
  return out;
}

const ORDER = { mkdirRemote: 0, mkdirLocal: 0, record: 1, upload: 2, merge: 2, download: 2, trashRemote: 3, pendingDelete: 3, deleteLocal: 3, forget: 4 };

/**
 * What to do so both sides agree.
 * @param {object} o
 * @param {'backup'|'sync'} o.mode
 * @param {object} o.base
 * @param {Map} o.local
 * @param {Map} o.remote
 * @param {boolean} [o.restoreDeleted] - files deleted on the PC come back from Drive (the answer "Wiederherstellen")
 * @returns {{ actions: object[], deletes: number, driveDeletes: number, files: number }}
 *   deletes: files that leave Drive because they were deleted on the PC (the mass-delete guard),
 *   driveDeletes: files that leave the PC because they were deleted in Drive (the same guard, other way),
 *   files: files of the base (its size)
 *
 * Actions: mkdirRemote { key, path } · mkdirLocal { key, path, nodeId, rev } · upload { key, path, nodeId, baseRev }
 *   · download { key, path, nodeId, rev, size, mtime, sha256 } · merge { key, path, nodeId, rev, size, sha256 }
 *   (both sides new / changed: the same bytes → record, else a conflict copy) · trashRemote { key, path, nodeId, dir, files }
 *   · pendingDelete { key, path, nodeId, dir, files } (backup: in Drive after 30 days) · deleteLocal { key, path, dir }
 *   · record { key, entry } · forget { key }
 */
function plan({ mode, base, local, remote, restoreDeleted = false }) {
  const actions = [];
  const done = new Set();         // keys handled (a whole folder handled at once)
  const keys = new Set([...Object.keys(base), ...local.keys(), ...remote.keys()]);
  const sorted = [...keys].sort((a, b) => depth(a) - depth(b) || (a < b ? -1 : a > b ? 1 : 0));
  const backup = mode === 'backup';
  let deletes = 0;
  let driveDeletes = 0;
  const files = Object.values(base).filter((e) => !e.dir).length;
  const covered = (k) => { for (const d of done) if (under(k, d)) return true; return false; };

  const lChanged = (k) => { const l = local.get(k); const b = base[k]; return !!l && !l.dir && (!b || b.dir || !sameFile(l, b)); };
  const rChanged = (k) => { const r = remote.get(k); const b = base[k]; return !!r && !r.dir && (!b || b.dir || !remoteSame(b, r)); };
  const below = (map, k) => [...map.keys()].filter((x) => x !== k && under(x, k));

  for (const k of sorted) {
    if (covered(k)) continue;
    const b = base[k];
    const l = local.get(k);
    const r = remote.get(k);
    const isDir = (l && l.dir) || (r && r.dir) || (b && b.dir);

    // A file on one side, a folder on the other: the folder wins, the file is kept as a conflict copy.
    if (l && r && l.dir !== r.dir) {
      actions.push({ op: 'kindClash', key: k, path: l.path, localDir: l.dir, nodeId: r.nodeId });
      done.add(k);
      continue;
    }

    if (isDir) {
      if (l && r) {
        if (!b || b.nodeId !== r.nodeId) actions.push({ op: 'record', key: k, entry: { path: l.path, dir: true, size: 0, mtime: 0, sha256: null, nodeId: r.nodeId, rev: r.rev } });
        continue;
      }
      if (l && !r) {
        if (!b || backup) { actions.push({ op: 'mkdirRemote', key: k, path: l.path }); continue; }
        // gone in Drive: the PC lets it go too, unless something below changed on the PC
        const changed = below(local, k).some((x) => lChanged(x));
        if (!changed && !restoreDeleted) {
          const n = below(local, k).filter((x) => !local.get(x).dir).length;
          driveDeletes += n;
          actions.push({ op: 'deleteLocal', key: k, path: l.path, dir: true, files: n });
          done.add(k);
          continue;
        }
        actions.push({ op: 'mkdirRemote', key: k, path: l.path });
        continue;
      }
      if (!l && r) {
        if (!b) {
          if (backup) continue; // what is in Drive only stays there
          actions.push({ op: 'mkdirLocal', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev });
          continue;
        }
        if (restoreDeleted) { actions.push({ op: 'mkdirLocal', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev }); continue; }
        // deleted on the PC
        const rFiles = below(remote, k).filter((x) => !remote.get(x).dir);
        const bFiles = Object.keys(base).filter((x) => x !== k && under(x, k) && !base[x].dir);
        const untouched = rFiles.every((x) => remoteSame(base[x], remote.get(x)));
        const allGone = bFiles.every((x) => !local.has(x)) && below(local, k).length === 0;
        if (untouched && allGone) {
          const n = rFiles.length;
          deletes += n;
          actions.push({ op: backup ? 'pendingDelete' : 'trashRemote', key: k, path: b.path, nodeId: r.nodeId, dir: true, files: n });
          done.add(k);
          continue;
        }
        if (backup) continue;
        actions.push({ op: 'mkdirLocal', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev });
        continue;
      }
      if (b) actions.push({ op: 'forget', key: k });
      continue;
    }

    // ── Files
    if (l && r) {
      if (!b) { actions.push({ op: 'merge', key: k, path: l.path, nodeId: r.nodeId, rev: r.rev, size: r.size, sha256: r.sha256, mtime: r.mtime }); continue; }
      const lc = lChanged(k);
      const rc = rChanged(k);
      if (!lc && !rc) continue;
      if (lc && !rc) { actions.push({ op: 'upload', key: k, path: l.path, nodeId: r.nodeId, baseRev: r.rev }); continue; }
      if (!lc && rc) {
        if (backup) { if (b.nodeId !== r.nodeId) actions.push({ op: 'record', key: k, entry: { ...b, nodeId: r.nodeId, rev: r.rev } }); else actions.push({ op: 'record', key: k, entry: { ...b, rev: r.rev } }); continue; }
        actions.push({ op: 'download', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev, size: r.size, mtime: r.mtime, sha256: r.sha256 });
        continue;
      }
      actions.push({ op: 'merge', key: k, path: l.path, nodeId: r.nodeId, rev: r.rev, size: r.size, sha256: r.sha256, mtime: r.mtime });
      continue;
    }
    if (l && !r) {
      if (!b || backup || lChanged(k) || restoreDeleted) { actions.push({ op: 'upload', key: k, path: l.path, nodeId: null, baseRev: null }); continue; }
      driveDeletes += 1;
      actions.push({ op: 'deleteLocal', key: k, path: l.path, dir: false, files: 1 });
      continue;
    }
    if (!l && r) {
      if (!b) {
        if (!backup) actions.push({ op: 'download', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev, size: r.size, mtime: r.mtime, sha256: r.sha256 });
        continue;
      }
      if (restoreDeleted || (rChanged(k) && !backup)) {
        actions.push({ op: 'download', key: k, path: r.path, nodeId: r.nodeId, rev: r.rev, size: r.size, mtime: r.mtime, sha256: r.sha256 });
        continue;
      }
      deletes += 1;
      actions.push({ op: backup ? 'pendingDelete' : 'trashRemote', key: k, path: b.path, nodeId: r.nodeId, dir: false, files: 1 });
      continue;
    }
    if (b) actions.push({ op: 'forget', key: k });
  }
  actions.sort((a, b) => (ORDER[a.op] ?? 2) - (ORDER[b.op] ?? 2) || ((a.op === 'deleteLocal' || a.op === 'trashRemote') ? depth(b.key) - depth(a.key) : depth(a.key) - depth(b.key)));
  return { actions, deletes, driveDeletes, files };
}

module.exports = {
  MODES,
  DEFAULT_MAX_BYTES,
  BACKUP_DELETE_DAYS,
  MASS_DELETE_COUNT,
  MASS_DELETE_SHARE,
  MASS_DELETE_MIN,
  DEVICES_FOLDER,
  DOWNLOAD_SUFFIX,
  DEFAULT_SETTINGS,
  MAX_FOLDERS,
  keyOf,
  parentOf,
  baseName,
  joinRel,
  under,
  isTempName,
  excluded,
  conflictName,
  freeName,
  deviceName,
  normalizeSettings,
  normalizeFolder,
  normalizeConfig,
  overlaps,
  massDelete,
  localNetworks,
  networkFingerprints,
  atHome,
  slimNode,
  dropSubtree,
  applyChanges,
  remoteByPath,
  rebase,
  planMoves,
  plan,
};
