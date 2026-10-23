'use strict';

/**
 * Pure helpers of "Vault" (plugin `gatecontrol-vault`, the end-to-end
 * encrypted password manager; contract: the plugin's README "App-API" and
 * "Kryptoformat"). The same rules as the Android app (vault/VaultJson.kt,
 * VaultStore.kt, VaultModels.kt, VaultTotp.kt, VaultGenerator.kt,
 * VaultMatch.kt, VaultImport.kt):
 *
 *   - the server's answers → checked records (anything without the
 *     documented shape is dropped, or makes the whole answer invalid);
 *   - the device's copy (state): merge of a sync page (a vault missing from
 *     the list is gone with its entries, a tombstone drops the entry and an
 *     unsent change of it), the outbox (one save per entry, the first base
 *     revision stays), JSON of the copy — encrypted records only;
 *   - the entry JSON v1 `{ v: 1, type, title, fav, notes, urls, apps,
 *     fields, custom }` (unknown keys are kept as they are);
 *   - 2FA codes (TOTP, RFC 6238), the password generator and its strength
 *     estimate, matching by web address, import of other password managers'
 *     exports, the Vault context of a push message.
 *
 * Nothing in here holds a key; the crypto is utils/vault-crypto.js.
 */

const crypto = require('node:crypto');

const PLUGIN_ID = 'gatecontrol-vault';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;

const ID_RE = /^[A-Za-z0-9_-]{16,40}$/;
const B64_RE = /^[A-Za-z0-9_-]+$/;
const EMERGENCY_ID_RE = /^[0-9a-f]{24}$/;
const CODE_RE = /^[A-Za-z0-9_]{1,60}$/;

const ROLES = ['read', 'write', 'manage'];
const ITEM_TYPES = ['login', 'totp', 'note', 'card', 'wifi', 'identity'];
const ITEM_STATES = ['live', 'trash', 'purged'];
const EMERGENCY_STATES = ['ready', 'requested', 'granted'];
const EMERGENCY_STEPS = ['request', 'deny', 'approve'];
const PUSH_TOPICS = ['share', 'emergency'];
const PUSH_EVENTS = ['shared', 'requested', 'denied', 'granted', 'released'];
const AUTO_LOCK_CHOICES = [0, 1, 5, 15, 60];
const DEFAULT_AUTO_LOCK = 5;

// An app request is ≤ 64 KB: POST items batches stay well below (README "Limits": ≤ 100 entries).
const BATCH_BYTES = 48000;
const BATCH_ITEMS = 100;
const MAX_LIST = 5000;
const SYNC_LIMIT = 500;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (o, k) => (typeof o[k] === 'string' ? o[k] : null);
const int = (o, k) => (Number.isSafeInteger(o[k]) && Math.abs(o[k]) <= 2e9 ? o[k] : null);
const long = (o, k) => (Number.isSafeInteger(o[k]) ? o[k] : null);
const isId = (v) => typeof v === 'string' && ID_RE.test(v);
const b64 = (v) => (typeof v === 'string' && v.length >= 1 && v.length <= 65536 && B64_RE.test(v) ? v : null);
const optStr = (o, k, max = 64) => (typeof o[k] === 'string' ? o[k].slice(0, max) : null);
const clone = (v) => JSON.parse(JSON.stringify(v));

/** The plugin's error code of a refusal body, or null. */
function errorCode(o) {
  return isObj(o) && typeof o.code === 'string' && CODE_RE.test(o.code) ? o.code : null;
}

// ── The server's records (README "App-API"), still encrypted ─────────

function parseKdf(o) {
  if (!isObj(o)) return null;
  const alg = str(o, 'alg');
  const m = int(o, 'm');
  const t = int(o, 't');
  const p = int(o, 'p');
  const salt = b64(o.salt);
  if (!alg || m == null || t == null || p == null || !salt) return null;
  return { alg, m, t, p, salt };
}

function parseAccount(o) {
  if (!isObj(o)) return null;
  const kdf = parseKdf(o.kdf);
  const a = { kdf, userKeyPw: b64(o.userKeyPw), userKeyRk: b64(o.userKeyRk), publicKey: b64(o.publicKey), privateKeyEnc: b64(o.privateKeyEnc), rev: int(o, 'rev') };
  if (!kdf || !a.userKeyPw || !a.userKeyRk || !a.publicKey || !a.privateKeyEnc || a.rev == null) return null;
  return a;
}

/** GET account → { account } (account null: Vault is not set up yet) or null for an invalid answer. */
function parseAccountAnswer(o) {
  if (!isObj(o) || !Object.prototype.hasOwnProperty.call(o, 'account')) return null;
  if (o.account === null) return { account: null };
  const account = parseAccount(o.account);
  return account ? { account } : null;
}

function parseVault(o) {
  if (!isObj(o)) return null;
  let pending = null;
  if (isObj(o.pending)) {
    const keyRev = int(o.pending, 'keyRev');
    if (keyRev == null) return null;
    pending = { keyRev, sealedKey: b64(o.pending.sealedKey) };
  }
  const id = isId(o.id) ? o.id : null;
  const kind = o.kind === 'personal' || o.kind === 'shared' ? o.kind : null;
  const nameEnc = b64(o.nameEnc);
  const role = ROLES.includes(o.role) ? o.role : null;
  const keyRev = int(o, 'keyRev');
  const sealedKey = b64(o.sealedKey);
  if (!id || !kind || !nameEnc || !role || !(keyRev > 0) || !sealedKey) return null;
  const members = [];
  for (const m of Array.isArray(o.members) ? o.members : []) {
    if (!isObj(m) || int(m, 'userId') == null) continue;
    members.push({ userId: m.userId, name: (str(m, 'name') || '').slice(0, 120), role: ROLES.includes(m.role) ? m.role : 'read' });
  }
  return {
    id, kind, ownerId: int(o, 'ownerId') || 0, nameEnc, role, keyRev, sealedKey, pending,
    needsRekey: o.needsRekey === true, members, updatedAt: optStr(o, 'updatedAt'),
  };
}

function parseItem(o) {
  if (!isObj(o)) return null;
  const state = ITEM_STATES.includes(o.state) ? o.state : null;
  if (!state) return null;
  const blob = b64(o.blob);
  if (state !== 'purged' && !blob) return null;
  const rev = int(o, 'rev');
  const keyRev = int(o, 'keyRev');
  if (!isId(o.id) || !isId(o.vaultId) || !(rev > 0) || !(keyRev > 0)) return null;
  return {
    id: o.id, vaultId: o.vaultId, rev, keyRev, blob: state === 'purged' ? null : blob, state,
    trashedAt: optStr(o, 'trashedAt'), updatedAt: optStr(o, 'updatedAt'), updatedBy: int(o, 'updatedBy'),
    device: optStr(o, 'device', 80), seq: long(o, 'seq') || 0,
  };
}

const parseItems = (a) => (Array.isArray(a) ? a.slice(0, MAX_LIST).map(parseItem).filter(Boolean) : []);

/** GET sync → { seq, account, vaults, items, more, next } or null. */
function parseSync(o) {
  if (!isObj(o) || !Array.isArray(o.vaults)) return null;
  const seq = long(o, 'seq');
  const next = long(o, 'next');
  if (seq == null || next == null) return null;
  let account = null;
  if (isObj(o.account)) {
    account = parseAccount(o.account);
    if (!account) return null;
  }
  return { seq, account, vaults: o.vaults.map(parseVault).filter(Boolean), items: parseItems(o.items), more: o.more === true, next };
}

function parsePeople(o) {
  if (!isObj(o) || !Array.isArray(o.people)) return null;
  return o.people.filter(isObj).filter((p) => int(p, 'id') != null)
    .map((p) => ({ id: p.id, name: (str(p, 'name') || '').slice(0, 120), publicKey: b64(p.publicKey) }));
}

function parseSaveResults(o) {
  if (!isObj(o) || !Array.isArray(o.results)) return null;
  return o.results.filter((r) => isObj(r) && typeof r.id === 'string').map((r) => ({
    id: r.id, ok: r.ok === true, rev: int(r, 'rev'), seq: long(r, 'seq'), code: errorCode(r), current: parseItem(r.current),
  }));
}

function parseHistory(o) {
  if (!isObj(o) || !Array.isArray(o.history)) return null;
  const out = [];
  for (const h of o.history) {
    if (!isObj(h) || int(h, 'rev') == null || int(h, 'keyRev') == null || !b64(h.blob)) continue;
    out.push({ rev: h.rev, keyRev: h.keyRev, blob: h.blob, updatedAt: optStr(h, 'updatedAt'), updatedBy: int(h, 'updatedBy'), device: optStr(h, 'device', 80) });
  }
  return out;
}

function parseEmergency(o) {
  if (!isObj(o) || !isObj(o.grantor) || !isObj(o.grantee)) return null;
  if (typeof o.id !== 'string' || !EMERGENCY_ID_RE.test(o.id)) return null;
  if (int(o.grantor, 'id') == null || int(o.grantee, 'id') == null || int(o, 'waitHours') == null) return null;
  if (!EMERGENCY_STATES.includes(o.status)) return null;
  return {
    id: o.id,
    grantor: { id: o.grantor.id, name: (str(o.grantor, 'name') || '').slice(0, 120) },
    grantee: { id: o.grantee.id, name: (str(o.grantee, 'name') || '').slice(0, 120) },
    waitHours: o.waitHours, status: o.status,
    requestedAt: optStr(o, 'requestedAt'), releaseAt: optStr(o, 'releaseAt'), grantedAt: optStr(o, 'grantedAt'),
  };
}

function parseEmergencyList(o) {
  if (!isObj(o) || !Array.isArray(o.granted) || !Array.isArray(o.received)) return null;
  return { granted: o.granted.map(parseEmergency).filter(Boolean), received: o.received.map(parseEmergency).filter(Boolean) };
}

function parseAccess(o) {
  if (!isObj(o) || !isObj(o.grantor) || !Array.isArray(o.vaults)) return null;
  const g = o.grantor;
  const a = {
    sealedKey: b64(o.sealedKey),
    grantor: { id: int(g, 'id'), name: (str(g, 'name') || '').slice(0, 120), publicKey: b64(g.publicKey), privateKeyEnc: b64(g.privateKeyEnc) },
    vaults: o.vaults.map(parseVault).filter(Boolean),
  };
  if (!a.sealedKey || a.grantor.id == null || !a.grantor.publicKey || !a.grantor.privateKeyEnc) return null;
  return a;
}

function parseItemsPage(o) {
  if (!isObj(o)) return null;
  const seq = long(o, 'seq');
  const next = long(o, 'next');
  if (seq == null || next == null) return null;
  return { seq, items: parseItems(o.items), more: o.more === true, next };
}

/** One entry of POST items (and of the outbox in the device's copy). */
function parseSaveItem(o) {
  if (!isObj(o) || !isId(o.id) || !isId(o.vaultId) || !b64(o.blob)) return null;
  const keyRev = int(o, 'keyRev');
  const baseRev = int(o, 'baseRev');
  if (keyRev == null || baseRev == null || baseRev < 0) return null;
  return { id: o.id, vaultId: o.vaultId, blob: o.blob, keyRev, baseRev };
}

/** Rough size of one entry inside POST items (an app request is ≤ 64 KB). */
const saveItemBytes = (i) => i.blob.length + i.id.length + i.vaultId.length + 80;

/**
 * Splits saves into POST items requests: ≤ BATCH_ITEMS entries and about
 * ≤ BATCH_BYTES each (one entry alone may be larger; the server allows 32 KiB).
 */
function batches(list, maxBytes = BATCH_BYTES, maxItems = BATCH_ITEMS) {
  const out = [];
  let cur = [];
  let bytes = 0;
  for (const s of list) {
    const b = saveItemBytes(s);
    if (cur.length && (bytes + b > maxBytes || cur.length >= maxItems)) {
      out.push(cur);
      cur = [];
      bytes = 0;
    }
    cur.push(s);
    bytes += b;
  }
  if (cur.length) out.push(cur);
  return out;
}

/** The key generation a save must use now: the new one during a key change. */
const wantedKeyRev = (v) => (v.pending ? v.pending.keyRev : v.keyRev);
const canWrite = (v) => !!v && (v.role === 'write' || v.role === 'manage');
const canManage = (v) => !!v && v.role === 'manage';

// ── The device's copy ────────────────────────────────────────────

/**
 * The copy of the server's Vault data — encrypted, exactly as the server sent
 * it — and the outbox of saves not yet confirmed:
 * { account, known, seq, vaults: [Vault], items: Map<id, Item>, outbox: [SaveItem], lastSyncMs, fresh: [vault id] }.
 * `fresh`: vaults that appeared after the first sync (shared with the person since) whose older entries still have
 * to be fetched (vault=<id>&since=0) — kept in the copy so an interrupted sync does not skip them.
 */
function emptyState() {
  return { account: null, known: false, seq: 0, vaults: [], items: new Map(), outbox: [], lastSyncMs: 0, fresh: [] };
}

/**
 * Applies one page of GET sync. The vault list is always complete: a vault
 * missing now is gone (with its entries and unsent saves). A tombstone drops
 * the entry and an unsent change of it. An older copy of an entry (lower seq
 * or revision) never replaces a newer one.
 */
function mergePage(state, page, nowMs) {
  const vaultIds = new Set(page.vaults.map((v) => v.id));
  const had = new Set(state.vaults.map((v) => v.id));
  // after the first full sync (seq > 0) a new vault's older entries are not in `since` pages: remember to fetch them
  const added = state.seq > 0 ? page.vaults.filter((v) => !had.has(v.id)).map((v) => v.id) : [];
  const fresh = [...new Set([...(state.fresh || []), ...added])].filter((id) => vaultIds.has(id));
  const items = new Map();
  for (const [id, it] of state.items) if (vaultIds.has(it.vaultId)) items.set(id, it);
  const purged = new Set();
  for (const i of page.items) {
    const cur = items.get(i.id);
    if (cur && (i.seq < cur.seq || (i.state !== 'purged' && i.rev < cur.rev))) continue;
    if (i.state === 'purged') {
      items.delete(i.id);
      purged.add(i.id);
    } else {
      items.set(i.id, i);
    }
  }
  return {
    ...state,
    account: page.account || state.account,
    known: true,
    vaults: page.vaults,
    items,
    outbox: state.outbox.filter((o) => vaultIds.has(o.vaultId) && !purged.has(o.id)),
    lastSyncMs: nowMs,
    fresh,
  };
}

/** A save into the outbox: replaces an earlier one of the same entry, keeping its base revision. */
function queueSave(state, save) {
  const earlier = state.outbox.find((o) => o.id === save.id);
  const next = earlier ? { ...save, baseRev: earlier.baseRev } : save;
  return { ...state, outbox: [...state.outbox.filter((o) => o.id !== save.id), next] };
}

/** The copy as JSON (per server and login: `owner`). Encrypted records and metadata only. */
function stateToJson(state, owner) {
  return {
    v: 1,
    owner,
    known: state.known,
    account: state.account,
    seq: state.seq,
    lastSyncMs: state.lastSyncMs,
    vaults: state.vaults,
    items: [...state.items.values()],
    outbox: state.outbox,
    fresh: state.fresh || [],
  };
}

/** The copy back from JSON; null when it is not this owner's or damaged. */
function stateFromJson(o, owner) {
  if (!isObj(o) || o.v !== 1 || o.owner !== owner) return null;
  const items = new Map();
  for (const it of parseItems(o.items)) items.set(it.id, it);
  return {
    account: o.account ? parseAccount(o.account) : null,
    known: o.known === true,
    seq: long(o, 'seq') || 0,
    vaults: Array.isArray(o.vaults) ? o.vaults.map(parseVault).filter(Boolean) : [],
    items,
    outbox: Array.isArray(o.outbox) ? o.outbox.map(parseSaveItem).filter(Boolean) : [],
    lastSyncMs: long(o, 'lastSyncMs') || 0,
    fresh: Array.isArray(o.fresh) ? o.fresh.filter(isId) : [],
  };
}

/** File-name-safe key of a server + login (ApiClient scope: origin and token); '' when not configured. */
function ownerKey(scope) {
  if (!scope) return '';
  return crypto.createHash('sha256').update(String(scope)).digest('hex').slice(0, 32);
}

// ── Entry JSON v1 ────────────────────────────────────────────────

const ENTRY_KNOWN = new Set(['v', 'type', 'title', 'fav', 'notes', 'urls', 'apps', 'fields', 'custom']);
const strings = (a) => (Array.isArray(a) ? a.filter((x) => typeof x === 'string' && x.trim() !== '') : []);

/**
 * An entry's plaintext in the shape every platform writes:
 * `{ v: 1, type, title, fav?, notes?, urls: [], apps: [], fields: { … }, custom: [{ name, value, secret }] }`.
 * Field keys per type: login `username`, `password`, `totp` · totp `totp` · card `holder`, `number`,
 * `expiry` (MM/YY), `cvc`, `pin` · wifi `ssid`, `password`, `security` · identity `name`, `email`, `phone`,
 * `address`, `birthday` · note: only `notes`. Keys this version does not know are kept unchanged.
 * `v` may be left out (a new entry from the page); any other version, an unknown type → null.
 */
function normalizeEntry(input) {
  if (!isObj(input)) return null;
  if (input.v !== undefined && input.v !== 1) return null;
  if (!ITEM_TYPES.includes(input.type)) return null;
  const out = {};
  // defineProperty: a key "__proto__" (JSON of another member's app) stays a kept key instead of setting the prototype
  for (const [k, v] of Object.entries(input)) {
    if (!ENTRY_KNOWN.has(k) && v !== undefined) Object.defineProperty(out, k, { value: clone(v), enumerable: true, writable: true, configurable: true });
  }
  out.v = 1;
  out.type = input.type;
  out.title = typeof input.title === 'string' ? input.title : '';
  if (input.fav === true) out.fav = true;
  if (typeof input.notes === 'string' && input.notes !== '') out.notes = input.notes;
  out.urls = strings(input.urls);
  out.apps = strings(input.apps);
  const fields = {};
  if (isObj(input.fields)) {
    for (const k of Object.keys(input.fields).sort()) {
      const v = input.fields[k];
      if (typeof v === 'string' && v !== '') fields[k] = v;
    }
  }
  out.fields = fields;
  out.custom = (Array.isArray(input.custom) ? input.custom : []).filter(isObj)
    .map((c) => ({ name: typeof c.name === 'string' ? c.name : '', value: typeof c.value === 'string' ? c.value : '', secret: c.secret === true }))
    .filter((c) => c.name.trim() !== '' || c.value !== '');
  return out;
}

const field = (d, k) => (d && d.fields && typeof d.fields[k] === 'string' ? d.fields[k] : '');
const entryUsername = (d) => field(d, 'username') || field(d, 'email');

/** The second line of a list row — never a password. */
function entrySubtitle(d) {
  switch (d.type) {
    case 'login': return entryUsername(d);
    case 'card': {
      const n = field(d, 'number').replace(/\D/g, '');
      return n.length >= 4 ? `•••• ${n.slice(-4)}` : field(d, 'holder');
    }
    case 'wifi': return field(d, 'ssid');
    case 'identity': return field(d, 'name') || field(d, 'email');
    default: return '';
  }
}

/** A list row: titles, user names and metadata, no secret. */
function entrySummary(e) {
  const d = e.data;
  return {
    id: e.id,
    vaultId: e.vaultId,
    rev: e.rev,
    type: d.type,
    title: d.title,
    subtitle: entrySubtitle(d),
    username: entryUsername(d),
    urls: d.urls.slice(0, 20),
    host: d.urls.map(urlHost).find(Boolean) || null,
    fav: d.fav === true,
    tags: Array.isArray(d.tags) ? d.tags.filter((x) => typeof x === 'string').slice(0, 20) : [],
    hasPassword: field(d, 'password') !== '',
    hasTotp: field(d, 'totp') !== '',
    trashed: e.trashed,
    trashedAt: e.trashedAt || null,
    updatedAt: e.updatedAt || null,
    updatedBy: e.updatedBy == null ? null : e.updatedBy,
    device: e.device || null,
    pending: e.pending === true,
  };
}

/**
 * One value of an entry for the clipboard: 'username', 'password', 'totp'
 * (the current code), 'notes', 'url' (the first), 'custom:<index>' or any
 * key of `fields`. '' when the entry has none.
 */
function entryValue(d, name, nowMs = Date.now()) {
  if (typeof name !== 'string') return '';
  if (name === 'username') return entryUsername(d);
  if (name === 'totp') {
    const p = parseTotp(field(d, 'totp'));
    return p ? totpCode(p, nowMs).code : '';
  }
  if (name === 'notes') return typeof d.notes === 'string' ? d.notes : '';
  if (name === 'url') return d.urls[0] || '';
  const m = /^custom:(\d{1,3})$/.exec(name);
  if (m) {
    const c = d.custom[Number(m[1])];
    return c ? c.value : '';
  }
  return field(d, name);
}

// ── 2FA codes (TOTP, RFC 6238) ───────────────────────────────────

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32 (spaces, '=' and '-' ignored, any case) → Buffer, or null. */
function base32Decode(text) {
  if (typeof text !== 'string') return null;
  const s = text.toUpperCase().replace(/[\s=-]/g, '');
  if (!s || /[^A-Z2-7]/.test(s)) return null;
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const ch of s) {
    acc = (acc << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  return out.length ? Buffer.from(out) : null;
}

function decodePart(s) {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; }
}

function otpQuery(uri) {
  const i = uri.indexOf('?');
  const q = i < 0 ? '' : uri.slice(i + 1).split('#')[0];
  const out = {};
  for (const kv of q.split('&')) {
    const j = kv.indexOf('=');
    const k = (j < 0 ? kv : kv.slice(0, j)).toLowerCase();
    if (k && !(k in out)) out[k] = decodePart(j < 0 ? '' : kv.slice(j + 1));
  }
  return out;
}

/**
 * An entry's `totp` field → { secret: Buffer, algorithm, digits, period } or
 * null: an `otpauth://totp/…?secret=…` URI (SHA1 / SHA256 / SHA512, 6–8
 * digits, period 10–300 s) or a bare base32 secret (SHA1, 6 digits, 30 s).
 */
function parseTotp(text) {
  if (typeof text !== 'string') return null;
  const f = text.trim();
  if (!f) return null;
  if (!/^otpauth:\/\//i.test(f)) {
    const secret = base32Decode(f);
    return secret ? { secret, algorithm: 'SHA1', digits: 6, period: 30 } : null;
  }
  if (!/^totp/i.test(f.slice(10))) return null;
  const q = otpQuery(f);
  const secret = base32Decode(q.secret || '');
  if (!secret) return null;
  const algorithm = (q.algorithm || 'SHA1').toUpperCase();
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) return null;
  const d = /^\d{1,2}$/.test(q.digits || '') ? Number(q.digits) : 6;
  const p = /^\d{1,4}$/.test(q.period || '') ? Number(q.period) : 30;
  return { secret, algorithm, digits: d >= 6 && d <= 8 ? d : 6, period: p >= 10 && p <= 300 ? p : 30 };
}

/** The issuer / account an otpauth URI names (a new entry's title), else null. */
function totpLabel(text) {
  if (typeof text !== 'string' || !/^otpauth:\/\//i.test(text)) return null;
  const issuer = otpQuery(text).issuer;
  if (issuer && issuer.trim()) return issuer;
  const rest = text.slice(text.indexOf('://') + 3);
  const slash = rest.indexOf('/');
  const pathPart = slash < 0 ? '' : decodePart(rest.slice(slash + 1).split('?')[0]);
  const label = pathPart.split(':')[0];
  return label.trim() ? label : null;
}

/** The code now → { code, secondsLeft, period, digits }. */
function totpCode(p, nowMs = Date.now()) {
  const secs = Math.floor(nowMs / 1000);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(secs / p.period)));
  const h = crypto.createHmac(p.algorithm.toLowerCase(), p.secret).update(counter).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  const code = String(bin % (10 ** p.digits)).padStart(p.digits, '0');
  return { code, secondsLeft: p.period - (secs % p.period), period: p.period, digits: p.digits };
}

/** "482913" → "482 913" (8 digits: 4 + 4). */
function prettyCode(code) {
  if (typeof code !== 'string') return '';
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

// ── Password generator and strength ──────────────────────────────

const GEN = {
  lower: 'abcdefghijkmnopqrstuvwxyzl',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZIO',
  digits: '2345678901',
  symbols: '!#$%&*+-=?@^_~',
  ambiguous: 'l1IO0',
  consonants: 'bdfgkmnprstvz',
  vowels: 'aeiou',
};

const pick = (s) => s[crypto.randomInt(s.length)];
const clampInt = (v, min, max, def) => (Number.isSafeInteger(v) ? Math.min(max, Math.max(min, v)) : def);

/** Generator options with defaults: { words, length 8–64 (20), upper, digits, symbols, avoidAmbiguous, wordCount 3–8 (4) }. */
function generatorOptions(o = {}) {
  const x = isObj(o) ? o : {};
  return {
    words: x.words === true,
    length: clampInt(x.length, 8, 64, 20),
    upper: x.upper !== false,
    digits: x.digits !== false,
    symbols: x.symbols !== false,
    avoidAmbiguous: x.avoidAmbiguous === true,
    wordCount: clampInt(x.wordCount, 3, 8, 4),
  };
}

/**
 * A new password. Characters: lower case always; upper case, digits, symbols
 * each on request and each at least once; "avoid look-alikes" drops l 1 I O 0.
 * Words: made-up pronounceable words (consonant-vowel syllables) joined by
 * "-", one with a number.
 */
function generatePassword(opts = {}) {
  const o = generatorOptions(opts);
  if (o.words) {
    const list = [];
    for (let i = 0; i < o.wordCount; i++) {
      let w = '';
      const syllables = 2 + crypto.randomInt(2);
      for (let j = 0; j < syllables; j++) w += pick(GEN.consonants) + pick(GEN.vowels);
      list.push(w[0].toUpperCase() + w.slice(1));
    }
    const k = crypto.randomInt(list.length);
    list[k] += String(2 + crypto.randomInt(98));
    return list.join('-');
  }
  const clean = (s) => (o.avoidAmbiguous ? [...s].filter((c) => !GEN.ambiguous.includes(c)).join('') : s);
  const classes = [clean(GEN.lower)];
  if (o.upper) classes.push(clean(GEN.upper));
  if (o.digits) classes.push(clean(GEN.digits));
  if (o.symbols) classes.push(GEN.symbols);
  const all = classes.join('');
  const out = Array.from({ length: o.length }, () => pick(all));
  // each chosen class at least once, at distinct random places
  const places = Array.from({ length: o.length }, (_, i) => i);
  for (let i = 0; i < classes.length; i++) {
    const j = i + crypto.randomInt(places.length - i);
    [places[i], places[j]] = [places[j], places[i]];
    out[places[i]] = pick(classes[i]);
  }
  return out.join('');
}

/** Rough entropy in bits: the character pool per class used and the length; repeats count less. */
function passwordBits(password) {
  if (typeof password !== 'string' || !password) return 0;
  const chars = Array.from(password);
  let pool = 0;
  if (chars.some((c) => /\p{Ll}/u.test(c))) pool += 26;
  if (chars.some((c) => /\p{Lu}/u.test(c))) pool += 26;
  if (chars.some((c) => /\p{Nd}/u.test(c))) pool += 10;
  if (chars.some((c) => !/[\p{L}\p{Nd}]/u.test(c))) pool += 33;
  const effective = Math.min(chars.length, new Set(chars).size * 1.5);
  return effective * Math.log2(Math.max(pool, 10));
}

/** 'weak' | 'fair' | 'strong' | 'very_strong' */
function passwordStrength(password) {
  const b = passwordBits(password);
  if (typeof password !== 'string' || Array.from(password).length < 10 || b < 50) return 'weak';
  if (b < 70) return 'fair';
  if (b < 100) return 'strong';
  return 'very_strong';
}

/** Words in a passphrase ("Sonnenblume-Kanu-Turm-47" → 4). */
const wordCount = (password) => (typeof password === 'string' ? password.split(/[\s\-_.]+/).filter((w) => w.length >= 2).length : 0);

/** The master password rule: at least 12 characters and not weak. */
const goodMasterPassword = (password) => typeof password === 'string' && Array.from(password).length >= 12 && passwordStrength(password) !== 'weak';

// ── Matching by web address ──────────────────────────────────────

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'or', 'ne', 'go']);

/** "https://www.Login.Example.co.uk:8443/x" → "login.example.co.uk"; null when it is no host. */
function urlHost(url) {
  if (typeof url !== 'string') return null;
  let s = url.trim().toLowerCase();
  if (!s) return null;
  const i = s.indexOf('://');
  if (i >= 0) s = s.slice(i + 3);
  s = s.split('/')[0].split('?')[0].split('#')[0];
  s = s.slice(s.lastIndexOf('@') + 1).split(':')[0].replace(/\.+$/, '');
  if (s.startsWith('www.')) s = s.slice(4);
  if (!s || !/^[\p{L}\p{Nd}.-]+$/u.test(s)) return null;
  return s;
}

/** The registrable part of a host: "login.example.co.uk" → "example.co.uk"; an IP stays as it is. */
function siteOf(host) {
  if (/^[\d.]+$/.test(host)) return host;
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2];
  const n = tld.length === 2 && SECOND_LEVEL.has(sld) ? 3 : 2;
  return parts.slice(-n).join('.');
}

function fitsDomain(data, webDomain) {
  const h = urlHost(webDomain);
  if (!h) return false;
  const want = siteOf(h);
  return data.urls.some((u) => {
    const x = urlHost(u);
    return !!x && siteOf(x) === want;
  });
}

const fitsApp = (data, app) => typeof app === 'string' && data.apps.some((a) => a.toLowerCase() === app.toLowerCase());

/**
 * Entries for a login form: by the page's domain (same site), else by the
 * app (`apps`). Logins (or entries with a user name / password), not trashed,
 * favourites first. entries: [{ data, trashed }].
 */
function matchEntries(entries, { domain = null, app = null } = {}) {
  const live = entries.filter((e) => !e.trashed && (e.data.type === 'login' || entryUsername(e.data) || field(e.data, 'password')));
  let hits = [];
  if (typeof domain === 'string' && domain.trim()) hits = live.filter((e) => fitsDomain(e.data, domain));
  else if (typeof app === 'string' && app.trim()) hits = live.filter((e) => fitsApp(e.data, app));
  return hits.sort((a, b) => (a.data.fav === b.data.fav ? a.data.title.toLowerCase().localeCompare(b.data.title.toLowerCase()) : a.data.fav ? -1 : 1));
}

// ── Import ───────────────────────────────────────────────────────

const entry = (type, title, extra = {}) => normalizeEntry({ v: 1, type, title, ...extra });
const nonEmpty = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => typeof v === 'string' && v !== ''));
const numText = (o, k) => (typeof o[k] === 'string' ? o[k] : typeof o[k] === 'number' ? String(o[k]) : '');

function bitwardenItem(i) {
  const name = str(i, 'name') || '';
  const notes = str(i, 'notes') || '';
  const fav = i.favorite === true;
  const custom = (Array.isArray(i.fields) ? i.fields : []).filter(isObj)
    .map((f) => ({ name: str(f, 'name') || '', value: str(f, 'value') || '', secret: f.type === 1 }))
    .filter((c) => c.name.trim() || c.value.trim());
  const base = { fav, notes, custom };
  switch (i.type) {
    case 1: {
      const l = isObj(i.login) ? i.login : {};
      const urls = (Array.isArray(l.uris) ? l.uris : []).filter(isObj).map((u) => str(u, 'uri')).filter(Boolean);
      return entry('login', name.trim() ? name : (urls.map(urlHost).find(Boolean) || ''), {
        ...base,
        urls,
        apps: urls.filter((u) => u.startsWith('androidapp://')).map((u) => u.slice('androidapp://'.length)),
        fields: nonEmpty({ username: str(l, 'username') || '', password: str(l, 'password') || '', totp: str(l, 'totp') || '' }),
      });
    }
    case 2: return entry('note', name, base);
    case 3: {
      const c = isObj(i.card) ? i.card : {};
      const month = numText(c, 'expMonth').padStart(2, '0');
      const year = numText(c, 'expYear').slice(-2);
      return entry('card', name, {
        ...base,
        fields: nonEmpty({
          holder: str(c, 'cardholderName') || '', number: str(c, 'number') || '',
          expiry: month !== '00' && year ? `${month}/${year}` : '', cvc: str(c, 'code') || '',
        }),
      });
    }
    case 4: {
      const d = isObj(i.identity) ? i.identity : {};
      const s = (k) => str(d, k) || '';
      const full = [s('firstName'), s('middleName'), s('lastName')].filter((x) => x.trim()).join(' ');
      const address = [s('address1'), s('address2'), [s('postalCode'), s('city')].filter(Boolean).join(' '), s('country')].filter((x) => x.trim()).join(', ');
      return entry('identity', name, { ...base, fields: nonEmpty({ name: full, email: s('email'), phone: s('phone'), address }) });
    }
    default: return null;
  }
}

function bitwardenJson(text) {
  let o;
  try { o = JSON.parse(text); } catch { return { ok: false, code: 'unknown' }; }
  if (!isObj(o)) return { ok: false, code: 'unknown' };
  if (o.encrypted === true) return { ok: false, code: 'encrypted' };
  if (!Array.isArray(o.items)) return { ok: false, code: 'unknown' };
  return { ok: true, source: 'Bitwarden', entries: o.items.filter(isObj).map(bitwardenItem).filter(Boolean) };
}

/** RFC 4180 rows: quotes, doubled quotes, line breaks inside quotes; comma or semicolon separated. */
function csvRows(text) {
  const firstLine = text.split('\n')[0];
  const count = (c) => firstLine.split(c).length - 1;
  const sep = count(';') > count(',') ? ';' : ',';
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === sep) { row.push(cell); cell = ''; }
    else if (c === '\r') { /* CR LF */ }
    else if (c === '\n') { row.push(cell); cell = ''; rows.push(row); row = []; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}

const CSV_COLUMNS = {
  title: ['title', 'name', 'account', 'item name'],
  url: ['url', 'login_uri', 'uri', 'website', 'web site', 'login url', 'origin'],
  username: ['username', 'login_username', 'user name', 'login name', 'user', 'login', 'email', 'e-mail'],
  password: ['password', 'login_password'],
  notes: ['notes', 'note', 'extra', 'comments'],
  totp: ['totp', 'login_totp', 'otpauth', 'one-time password', 'otp'],
  type: ['type'],
  favorite: ['favorite', 'favourite'],
};

function csv(text) {
  const rows = csvRows(text);
  if (rows.length < 2) return { ok: false, code: 'unknown' };
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = {};
  for (const [k, names] of Object.entries(CSV_COLUMNS)) {
    const n = names.find((x) => header.includes(x));
    col[k] = n === undefined ? -1 : header.indexOf(n);
  }
  if (col.password < 0 && col.notes < 0) return { ok: false, code: 'unknown' };
  let source = 'CSV';
  if (header.includes('login_uri')) source = 'Bitwarden';
  else if (header.includes('httprealm')) source = 'Firefox';
  else if (header.includes('group')) source = 'KeePass';
  else if (header.includes('otpauth')) source = '1Password';
  else if (header.slice(0, 5).join(',') === 'name,url,username,password,note') source = 'Chrome / Edge';
  const raw = (r, k) => (col[k] >= 0 && r[col[k]] !== undefined ? r[col[k]] : '');
  const get = (r, k) => raw(r, k).trim();
  const out = [];
  for (const r of rows.slice(1)) {
    const url = get(r, 'url');
    // as it is: spaces at either end can be part of a password
    const password = raw(r, 'password');
    const username = get(r, 'username');
    const notes = get(r, 'notes');
    const title = get(r, 'title') || urlHost(url) || '';
    const isNote = get(r, 'type') === 'note' || (!password.trim() && !username && !url);
    if (!title.trim() && !password.trim() && !notes.trim()) continue;
    if (isNote) out.push(entry('note', title.trim() ? title : notes.slice(0, 40), { notes }));
    else {
      out.push(entry('login', title, {
        notes, fav: get(r, 'favorite') === '1', urls: url ? [url] : [],
        fields: nonEmpty({ username, password, totp: get(r, 'totp') }),
      }));
    }
  }
  return { ok: true, source, entries: out.filter(Boolean) };
}

/**
 * An export of another password manager → { ok: true, source, entries } or
 * { ok: false, code: 'encrypted' (a password-protected export: export again
 * without one) | 'unknown' }. A Bitwarden JSON export (unencrypted), or a CSV
 * of Bitwarden, 1Password, KeePass(XC), Chrome / Edge or Firefox — the
 * columns are recognised by their names.
 */
function parseImport(text) {
  if (typeof text !== 'string') return { ok: false, code: 'unknown' };
  const t = text.replace(/^﻿/, '').trim();
  return t.startsWith('{') ? bitwardenJson(t) : csv(t);
}

/** Counts of an import for the preview. */
function importCounts(entries) {
  return {
    total: entries.length,
    logins: entries.filter((e) => e.type === 'login').length,
    withTotp: entries.filter((e) => field(e, 'totp')).length,
    notes: entries.filter((e) => e.type === 'note').length,
    cards: entries.filter((e) => e.type === 'card').length,
  };
}

function dupKey(e) {
  const host = e.urls.length ? urlHost(e.urls[0]) : null;
  return [e.title.trim().toLowerCase(), entryUsername(e).trim().toLowerCase(), host ? siteOf(host) : ''].join('\n');
}

/** Entries the vault already has (same title, user name and site) and repeats in the list → { keep, duplicates }. */
function withoutDuplicates(found, existing) {
  const have = new Set(existing.map(dupKey));
  const seen = new Set();
  const keep = found.filter((e) => {
    const k = dupKey(e);
    if (have.has(k) || seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { keep, duplicates: found.length - keep.length };
}

/** Is this entry a duplicate of one in `existing`? (preview marks) */
function duplicateFlags(found, existing) {
  const have = new Set(existing.map(dupKey));
  const seen = new Set();
  return found.map((e) => {
    const k = dupKey(e);
    const dup = have.has(k) || seen.has(k);
    seen.add(k);
    return dup;
  });
}

// ── Push ─────────────────────────────────────────────────────────

/**
 * The Vault context of a push message (topics `share`, `emergency`; data
 * `{ vault: { topic, event, vault?, emergency? } }`) → { topic, event,
 * vaultId, emergencyId, page: 'emergency' | 'home' }, or null for other senders.
 * Pushes never carry names or key material.
 */
function pushContext(n) {
  if (!isObj(n)) return null;
  const topic = typeof n.topic === 'string' ? n.topic : '';
  const data = isObj(n.data) ? n.data : {};
  if (!topic.startsWith(TOPIC_PREFIX) && data.route !== APP_ROUTE) return null;
  const v = isObj(data.vault) ? data.vault : {};
  const fromTopic = topic.startsWith(TOPIC_PREFIX) ? topic.slice(TOPIC_PREFIX.length) : '';
  const t = PUSH_TOPICS.includes(fromTopic) ? fromTopic : PUSH_TOPICS.includes(v.topic) ? v.topic : null;
  return {
    topic: t,
    event: PUSH_EVENTS.includes(v.event) ? v.event : null,
    vaultId: isId(v.vault) ? v.vault : null,
    emergencyId: typeof v.emergency === 'string' && EMERGENCY_ID_RE.test(v.emergency) ? v.emergency : null,
    page: t === 'emergency' ? 'emergency' : 'home',
  };
}

module.exports = {
  PLUGIN_ID, APP_ROUTE, TOPIC_PREFIX, API_BASE, ID_RE, EMERGENCY_ID_RE,
  ROLES, ITEM_TYPES, EMERGENCY_STEPS, AUTO_LOCK_CHOICES, DEFAULT_AUTO_LOCK, BATCH_BYTES, BATCH_ITEMS, SYNC_LIMIT,
  isId, errorCode,
  parseKdf, parseAccount, parseAccountAnswer, parseVault, parseItem, parseSync, parsePeople, parseSaveResults,
  parseHistory, parseEmergency, parseEmergencyList, parseAccess, parseItemsPage, parseSaveItem,
  saveItemBytes, batches, wantedKeyRev, canWrite, canManage,
  emptyState, mergePage, queueSave, stateToJson, stateFromJson, ownerKey,
  normalizeEntry, entryUsername, entrySubtitle, entrySummary, entryValue,
  base32Decode, parseTotp, totpLabel, totpCode, prettyCode,
  generatorOptions, generatePassword, passwordBits, passwordStrength, wordCount, goodMasterPassword,
  urlHost, siteOf, fitsDomain, fitsApp, matchEntries,
  csvRows, parseImport, importCounts, withoutDuplicates, duplicateFlags,
  pushContext,
};
