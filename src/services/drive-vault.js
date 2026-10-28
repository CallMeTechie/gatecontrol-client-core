'use strict';

/**
 * GateControl – Drive vault folders (Core, Drive 1.9 feature `vault`)
 *
 * The keys and the flows of the end-to-end encrypted folders of Drive (plugin README "Tresor-Ordner"; the format is
 * utils/drive-vault.js). Used by DriveService (services/drive.js), which lists, uploads, opens and renames with it.
 *
 * - The device key: X25519, made once per server on first use; the private key lies in the store only as Electron
 *   safeStorage (Windows: DPAPI, bound to the Windows user) — never plain. Without safeStorage (`protect`) this PC
 *   cannot use vaults ('vault_unsupported'). Device id and safety number come from the public key.
 * - The vault keys (TK per key version) are unwrapped with the device key and kept in memory only (per server; gone
 *   at a server change and when the app ends). Names are decrypted with them (a cache node id → name for the
 *   breadcrumbs).
 * - Flows: make (TK, vault id, the recovery key — shown once), open (GET keys of this device: approved → the keys;
 *   pending: waits for an approval; none: may ask), ask for access (POST devices → the safety number to compare),
 *   approve / decline a request of another device (its safety number shown before), open with the recovery key
 *   (the device approves itself with the key's proof), a new vault key (`needsRotation`; with a new recovery key when
 *   Drive says `recovery_required`), stale keys (409 stale_key: the keys are fetched again, the caller retries once).
 *
 * - Drive 1.11 "Tresor-Sperre" (services/drive-vault-lock.js): the device key unwraps the vault keys only while
 *   `isUnlocked()` (after Windows Hello); before that an approved vault is 'locked'. forget() wipes the keys and the
 *   decrypted names (the device key stays under DPAPI). A vault made here or opened with its recovery key keeps the
 *   keys it got that way until the next lock.
 *
 * Errors: DriveError (MessengerApi) with code 'vault_unsupported' · 'vault_locked' (no key here) · 'recovery_key'
 * (wrong recovery key) · 'safety' (the safety number did not match) · the plugin's codes.
 */

const crypto = require('crypto');
const os = require('os');
const MessengerApi = require('./messenger-api');
const drive = require('../utils/drive');
const V = require('../utils/drive-vault');

const { MessengerError: DriveError } = MessengerApi;

const STORE_KEY = 'driveVault';
const RETRY_OPEN_MS = 30 * 1000;
const NAMES_MAX = 20000;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const isStale = (err) => !!err && err.status === 409 && !!err.body && err.body.reason === 'stale_key';

class DriveVault {
  /**
   * @param {object} opts
   * @param {object} opts.api - DriveApi
   * @param {object} [opts.store] - electron-store (the protected device key per server)
   * @param {object} [opts.protect] - { available(), encrypt(buf) → Buffer, decrypt(Buffer) → buf } (safeStorage)
   * @param {() => string} opts.scope - the server (origin + token): keys and caches per server
   * @param {() => string} [opts.deviceName] - the name other devices see ("Desktop-PC")
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {() => boolean} [opts.isUnlocked] - Drive 1.11: may the device key unwrap vault keys now (Windows Hello)?
   */
  constructor({ api, store = null, protect = null, scope, deviceName = null, log = null, now = Date.now, isUnlocked = null } = {}) {
    this.api = api;
    this.store = store;
    this.protect = protect;
    this.scope = typeof scope === 'function' ? scope : () => '';
    this.deviceName = typeof deviceName === 'function' ? deviceName : () => os.hostname().slice(0, 80) || 'PC';
    this.log = log || noopLog();
    this.now = now;
    this.isUnlocked = typeof isUnlocked === 'function' ? isUnlocked : () => true;
    this._scope = null;
    this._device = null;      // { id, publicRaw, publicKey, safetyNumber } of this server
    this._keys = new Map();   // vaultId → Map keyVersion → TK
    this._current = new Map(); // vaultId → the vault's current key version (last seen)
    this._states = new Map();  // vaultId → { state, at }
    this._names = new Map();   // node id → decrypted name
    this._opening = new Map();
  }

  // ── scope, device ─────────────────────────────────────────

  /** Drive 1.11: the vaults lock — every vault key wiped, the decrypted names forgotten (the device stays). */
  forget() {
    for (const m of this._keys.values()) for (const k of m.values()) V.wipe(k);
    this._keys.clear();
    this._states.clear();
    this._names.clear();
    this._opening.clear();
  }

  /** Forget every key and name (a server change, the app ends). */
  clear() {
    for (const m of this._keys.values()) for (const k of m.values()) V.wipe(k);
    this._keys.clear();
    this._current.clear();
    this._states.clear();
    this._names.clear();
    this._opening.clear();
    this._device = null;
  }

  _ensureScope() {
    const s = this.scope();
    if (s !== this._scope) {
      this.clear();
      this._scope = s;
    }
  }

  _scopeKey() {
    return crypto.createHash('sha256').update(this.scope() || '').digest('hex').slice(0, 16);
  }

  /** Can this PC keep a device key (safeStorage / DPAPI)? */
  supported() {
    try { return !!(this.protect && this.protect.available()); } catch { return false; }
  }

  _need() {
    if (!this.supported()) throw new DriveError('no protected key storage', { code: 'vault_unsupported' });
  }

  _record() {
    let v = null;
    try { v = this.store && this.store.get(STORE_KEY); } catch { v = null; }
    const r = v && typeof v === 'object' && v.devices && typeof v.devices === 'object' ? v.devices[this._scopeKey()] : null;
    return r && typeof r.pub === 'string' && typeof r.enc === 'string' ? r : null;
  }

  /** This PC's device of this server, made on first use → { id, publicKey, safetyNumber, name } (create: false → null when none). */
  async device({ create = true } = {}) {
    this._ensureScope();
    this._need();
    if (this._device) return this._public();
    const r = this._record();
    if (r) {
      let pub;
      try { pub = V.unb64u(r.pub, 32, 'public key'); } catch { pub = null; }
      if (pub) {
        this._device = { publicRaw: pub, publicKey: r.pub, id: V.deviceId(pub), safetyNumber: V.safetyNumber(pub) };
        return this._public();
      }
    }
    if (!create) return null;
    const kp = V.generateKeyPair();
    let enc;
    try {
      enc = Buffer.from(this.protect.encrypt(kp.privateRaw)).toString('base64');
    } finally {
      V.wipe(kp.privateRaw);
    }
    const pub = V.b64u(kp.publicRaw);
    try {
      const all = (this.store && this.store.get(STORE_KEY)) || {};
      const devices = all && typeof all.devices === 'object' && all.devices ? { ...all.devices } : {};
      devices[this._scopeKey()] = { pub, enc, at: this.now() };
      this.store.set(STORE_KEY, { v: 1, devices });
    } catch (err) {
      throw new DriveError(`device key not stored: ${err.message}`, { code: 'vault_unsupported' });
    }
    this._device = { publicRaw: kp.publicRaw, publicKey: pub, id: V.deviceId(kp.publicRaw), safetyNumber: V.safetyNumber(kp.publicRaw) };
    this.log.info('Drive vault: device key made (DPAPI)');
    return this._public();
  }

  _public() {
    const d = this._device;
    return { id: d.id, publicKey: d.publicKey, safetyNumber: d.safetyNumber, name: this.deviceName() };
  }

  /** The device's private key for one operation (wiped by the caller). */
  _private() {
    const r = this._record();
    if (!r || !this._device || r.pub !== this._device.publicKey) throw new DriveError('no device key', { code: 'vault_locked' });
    let raw;
    try { raw = Buffer.from(this.protect.decrypt(Buffer.from(r.enc, 'base64'))); } catch { raw = null; }
    if (!raw || raw.length !== 32 || !V.publicFromPrivate(raw).equals(this._device.publicRaw)) {
      if (raw) V.wipe(raw);
      throw new DriveError('device key unreadable', { code: 'vault_unsupported' });
    }
    return raw;
  }

  // ── keys ──────────────────────────────────────────────────

  /** The keys of a vault in memory (Map keyVersion → TK) or null. */
  keysOf(vaultId) {
    this._ensureScope();
    const m = this._keys.get(vaultId);
    return m && m.size ? m : null;
  }

  isOpen(vaultId) {
    return !!this.keysOf(vaultId);
  }

  /** Any vault key in memory (Drive 1.11: the lock's timers wipe them)? */
  hasKeys() {
    for (const m of this._keys.values()) if (m.size) return true;
    return false;
  }

  /** 'open' | 'locked' (approved, Windows Hello first) | 'pending' | 'none' | 'revoked' | 'unsupported' | null (not asked yet) */
  stateOf(vaultId) {
    if (this.isOpen(vaultId)) return 'open';
    if (!this.supported()) return 'unsupported';
    const s = this._states.get(vaultId);
    return s ? s.state : null;
  }

  _addKeys(vaultId, list, privRaw, pubRaw) {
    const m = this._keys.get(vaultId) || new Map();
    for (const w of list) {
      if (m.has(w.keyVersion)) continue;
      try {
        m.set(w.keyVersion, V.unwrapKey(w.wrap, privRaw, pubRaw, vaultId, w.keyVersion));
      } catch (err) {
        this.log.warn(`Drive vault: a key of version ${w.keyVersion} did not open (${err.code || 'error'})`);
      }
    }
    if (m.size) this._keys.set(vaultId, m);
    return m;
  }

  /**
   * Opens a vault on this device: GET keys → { state: 'open' | 'pending' | 'none' | 'revoked', keyVersion }.
   * 'none': this device never asked (404) — it may ask (request()). `fresh`: ask again although the keys are here.
   */
  async open(vaultId, { fresh = false } = {}) {
    this._ensureScope();
    const id = drive.vaultIdOf(vaultId);
    if (!id) throw new DriveError('invalid vault', { code: 'invalid' });
    if (!fresh && this.isOpen(id)) return { state: 'open', keyVersion: this._current.get(id) || null };
    if (this._opening.has(id)) return this._opening.get(id);
    const run = this._open(id).finally(() => this._opening.delete(id));
    this._opening.set(id, run);
    return run;
  }

  async _open(id) {
    const dev = await this.device({ create: false });
    if (!dev) { this._states.set(id, { state: 'none', at: this.now() }); return { state: 'none', keyVersion: null }; }
    let r;
    try {
      r = await this.api.vaultKeys(id, dev.id);
    } catch (err) {
      if (err && err.status === 404 && err.code === 'not_found') {
        this._states.set(id, { state: 'none', at: this.now() });
        return { state: 'none', keyVersion: null };
      }
      throw err;
    }
    if (r.keyVersion) this._current.set(id, r.keyVersion);
    if (r.state !== 'approved') {
      this._states.set(id, { state: r.state, at: this.now() });
      return { state: r.state, keyVersion: r.keyVersion };
    }
    // Drive 1.11: the device key unwraps nothing while the vaults are locked
    if (!this.isUnlocked()) {
      const st = this.isOpen(id) ? 'open' : 'locked';
      this._states.set(id, { state: st, at: this.now() });
      return { state: st, keyVersion: r.keyVersion };
    }
    const priv = this._private();
    try {
      this._addKeys(id, r.keys, priv, this._device.publicRaw);
    } finally {
      V.wipe(priv);
    }
    const open = this.isOpen(id);
    this._states.set(id, { state: open ? 'open' : 'none', at: this.now() });
    return { state: open ? 'open' : 'none', keyVersion: r.keyVersion };
  }

  /** Opens it quietly when this device has a key (a listing): at most every 30 s per vault, never makes a key. */
  async tryOpen(vaultId) {
    if (!this.supported() || this.isOpen(vaultId)) return this.stateOf(vaultId);
    const s = this._states.get(vaultId);
    if (s && this.now() - s.at < RETRY_OPEN_MS && !(s.state === 'locked' && this.isUnlocked())) return s.state;
    try { return (await this.open(vaultId)).state; } catch (err) {
      this._states.set(vaultId, { state: (s && s.state) || null, at: this.now() });
      this.log.info(`Drive vault: not opened (${err.code || 'error'})`);
      return this.stateOf(vaultId);
    }
  }

  /** The keys of an open vault (else 'vault_locked'). */
  keys(vaultId) {
    const m = this.keysOf(vaultId);
    if (!m) throw new DriveError('vault is locked', { code: 'vault_locked' });
    return m;
  }

  /** The current key → { keyVersion, tk } (its version: the last the server named, else the newest here). */
  current(vaultId) {
    const m = this.keys(vaultId);
    const want = this._current.get(vaultId) || Math.max(...m.keys());
    const tk = m.get(want);
    if (!tk) throw new DriveError('the current vault key is missing here', { code: 'stale_key' });
    return { keyVersion: want, tk };
  }

  /** Runs `fn(current)` and, on 409 stale_key, once more after fetching the keys again. */
  async withCurrent(vaultId, fn) {
    try {
      return await fn(this.current(vaultId));
    } catch (err) {
      if (!isStale(err) && !(err && err.code === 'stale_key' && !err.status)) throw err;
      const kv = drive.posId(err.body && err.body.keyVersion);
      if (kv) this._current.set(vaultId, kv);
      await this.open(vaultId, { fresh: true });
      return fn(this.current(vaultId));
    }
  }

  // ── names ─────────────────────────────────────────────────

  /** A vault node's name (null: no key for it here). Remembered for the breadcrumbs. */
  nameOf(node) {
    if (!node || !node.encrypted || !node.vaultId || !node.nameCipher) return null;
    const m = this.keysOf(node.vaultId);
    if (!m) return null;
    try {
      const name = V.decryptName(m, node.vaultId, node.nameCipher);
      this._names.set(node.id, name);
      while (this._names.size > NAMES_MAX) this._names.delete(this._names.keys().next().value);
      return name;
    } catch {
      return null;
    }
  }

  /** The name remembered for node `id` (breadcrumbs), or null. */
  knownName(id) {
    return this._names.get(id) || null;
  }

  /** A name → { nameCipher, keyVersion } under the current key. */
  encryptName(vaultId, name, cur = null) {
    // a key wiped by a lock in between (Drive 1.11) never encrypts anything
    if (cur && this.keys(vaultId).get(cur.keyVersion) !== cur.tk) throw new DriveError('vault is locked', { code: 'vault_locked' });
    const c = cur || this.current(vaultId);
    return { nameCipher: V.encryptName(c.tk, vaultId, c.keyVersion, name), keyVersion: c.keyVersion };
  }

  // ── listing ───────────────────────────────────────────────

  /** A vault as the page shows it (its name when open, this device's state). */
  view(v) {
    const dev = this._device;
    const mine = dev ? v.myDevices.find((d) => d.deviceId === dev.id) : null;
    let name = null;
    const m = this.keysOf(v.id);
    if (m && v.nameCipher) { try { name = V.decryptName(m, v.id, v.nameCipher); this._names.set(v.nodeId, name); } catch { name = null; } }
    if (v.keyVersion) this._current.set(v.id, Math.max(this._current.get(v.id) || 0, v.keyVersion));
    return {
      id: v.id, nodeId: v.nodeId, areaId: v.areaId, parentId: v.parentId, name, keyVersion: v.keyVersion,
      needsRotation: v.needsRotation, pending: v.pending, recoveryHolder: v.recoveryHolder, createdAt: v.createdAt,
      state: this.isOpen(v.id) ? 'open' : mine ? (mine.state === 'approved' ? (this.isUnlocked() ? 'approved' : 'locked') : mine.state) : 'none',
    };
  }

  /** GET vaults → [view] (open ones are tried quietly first). */
  async list() {
    this._ensureScope();
    const list = await this.api.vaults();
    if (this.supported() && await this.device({ create: false })) {
      for (const v of list) await this.tryOpen(v.id);
    }
    return list.map((v) => this.view(v));
  }

  async get(vaultId) {
    return this.view(await this.api.vault(vaultId));
  }

  // ── flows ─────────────────────────────────────────────────

  /**
   * A new vault folder `name` in `parentId` → { vault, node, recoveryKey } — recoveryKey (text) is shown once; Drive
   * keeps only its public key and the SHA-256 of its proof.
   */
  async create(parentId, name) {
    this._ensureScope();
    const dev = await this.device();
    const id = V.newVaultId();
    const tk = V.newVaultKey();
    const rec = await V.newRecoveryKey();
    const rk = V.recoveryKeyPair(rec.key);
    try {
      const body = {
        id,
        parentId,
        nameCipher: V.encryptName(tk, id, 1, name),
        recoveryPub: V.b64u(rk.publicRaw),
        recoveryAuth: V.recoveryAuth(rec.key),
        recoveryWrap: V.wrapKey(tk, rk.publicRaw, id, 1),
        device: { publicKey: dev.publicKey, name: dev.name, platform: 'windows' },
        wrap: V.wrapKey(tk, this._device.publicRaw, id, 1),
      };
      const r = await this.api.createVault(body);
      this._keys.set(id, new Map([[1, Buffer.from(tk)]]));
      this._current.set(id, 1);
      this._states.set(id, { state: 'open', at: this.now() });
      this._names.set(r.node.id, name);
      return { vault: this.view(r.vault), node: { ...r.node, name, vaultRoot: true }, recoveryKey: rec.text };
    } finally {
      V.wipe(tk);
      V.wipe(rec.key);
      V.wipe(rk.privateRaw);
    }
  }

  /** This device asks for the vault (pending) → { device, safetyNumber } — the number the approving device compares. */
  async request(vaultId) {
    const dev = await this.device();
    const d = await this.api.askVault(vaultId, { publicKey: dev.publicKey, name: dev.name, platform: 'windows' });
    this._states.set(vaultId, { state: d.state === 'approved' ? 'approved' : d.state, at: this.now() });
    if (d.state === 'approved') await this.open(vaultId, { fresh: true }).catch(() => null);
    return { device: d, safetyNumber: dev.safetyNumber, state: this.stateOf(vaultId) || d.state };
  }

  /** The devices of a vault, each with its safety number (mine: this PC). */
  async devices(vaultId) {
    const dev = this.supported() ? await this.device({ create: false }) : null;
    const list = await this.api.vaultDevices(vaultId);
    return list.map((d) => {
      let safetyNumber = null;
      try { safetyNumber = V.safetyNumber(V.unb64u(d.publicKey, 32)); } catch { safetyNumber = null; }
      return { ...d, safetyNumber, mine: !!dev && d.deviceId === dev.id };
    });
  }

  /** Every key of the vault wrapped for public key `pubRaw` → [{ keyVersion, wrap }]. */
  _wrapsFor(vaultId, pubRaw, keys) {
    return [...keys.entries()].sort((a, b) => a[0] - b[0]).map(([kv, tk]) => ({ keyVersion: kv, wrap: V.wrapKey(tk, pubRaw, vaultId, kv) }));
  }

  /**
   * Approves the request of device `deviceId` (after the person compared its safety number: `safetyNumber` must be
   * the one shown) — every key version wrapped for its public key → device.
   */
  async approve(vaultId, deviceId, safetyNumber) {
    const keys = this.keys(vaultId);
    const d = (await this.devices(vaultId)).find((x) => x.deviceId === deviceId);
    if (!d || d.state === 'revoked') throw new DriveError('no such request', { code: 'not_found' });
    if (!d.safetyNumber || d.safetyNumber !== safetyNumber) throw new DriveError('safety number differs', { code: 'safety' });
    const pub = V.unb64u(d.publicKey, 32, 'public key');
    if (V.deviceId(pub) !== d.deviceId) throw new DriveError('device id does not match its key', { code: 'safety' });
    return this.api.approveVaultDevice(vaultId, deviceId, { wraps: this._wrapsFor(vaultId, pub, keys) });
  }

  /** Declines a request (or removes a device) → device. */
  decline(vaultId, deviceId) {
    return this.api.revokeVaultDevice(vaultId, deviceId);
  }

  /**
   * Opens the vault with its recovery key (the 56 characters written down): the recovery key pair is checked against
   * recoveryPub, its wraps unwrapped, this device asks and approves itself with the key's proof → { state: 'open' }.
   */
  async recover(vaultId, text) {
    const key = await V.parseRecoveryKey(text);
    const rk = V.recoveryKeyPair(key);
    try {
      const dev = await this.device();
      const r = await this.api.vaultRecovery(vaultId);
      if (V.b64u(rk.publicRaw) !== r.recoveryPub) throw new DriveError('not this vault\'s recovery key', { code: 'recovery_key' });
      const keys = new Map();
      for (const w of r.keys) {
        try { keys.set(w.keyVersion, V.unwrapKey(w.wrap, rk.privateRaw, rk.publicRaw, vaultId, w.keyVersion)); } catch { /* another version */ }
      }
      if (!keys.size) throw new DriveError('the recovery key opens nothing', { code: 'recovery_key' });
      if (r.keyVersion) this._current.set(vaultId, r.keyVersion);
      const asked = await this.api.askVault(vaultId, { publicKey: dev.publicKey, name: dev.name, platform: 'windows' });
      if (asked.state !== 'approved') {
        await this.api.approveVaultDevice(vaultId, dev.id, { wraps: this._wrapsFor(vaultId, this._device.publicRaw, keys), via: 'recovery', recoveryAuth: V.recoveryAuth(key) });
      }
      const m = this._keys.get(vaultId) || new Map();
      for (const [kv, tk] of keys) if (!m.has(kv)) m.set(kv, tk);
      this._keys.set(vaultId, m);
      this._states.set(vaultId, { state: 'open', at: this.now() });
      // the versions the recovery key did not have (none, normally) come with the device's own keys
      await this.open(vaultId, { fresh: true }).catch(() => null);
      return { state: 'open' };
    } finally {
      V.wipe(key);
      V.wipe(rk.privateRaw);
    }
  }

  /**
   * A new vault key (`needsRotation`: someone lost the area) for exactly the approved devices and the recovery key
   * → { vault, recoveryKey } — recoveryKey (text, shown once) only when Drive asked for a new one (recovery_required).
   */
  async rotate(vaultId) {
    const keys = this.keys(vaultId);
    const v = await this.api.vault(vaultId);
    const next = v.keyVersion + 1;
    const tk = V.newVaultKey();
    let rec = null;
    try {
      const all = new Map(keys);
      all.set(next, tk);
      const body = async (forceRecovery) => {
        const devices = (await this.api.vaultDevices(vaultId)).filter((d) => d.state === 'approved');
        const b = { keyVersion: next, wraps: devices.map((d) => ({ deviceId: d.deviceId, wrap: V.wrapKey(tk, V.unb64u(d.publicKey, 32), vaultId, next) })) };
        if (forceRecovery) {
          if (!rec) rec = await V.newRecoveryKey();
          const rk = V.recoveryKeyPair(rec.key);
          try {
            b.recovery = { pub: V.b64u(rk.publicRaw), auth: V.recoveryAuth(rec.key), wraps: this._wrapsFor(vaultId, rk.publicRaw, all) };
          } finally {
            V.wipe(rk.privateRaw);
          }
        } else {
          if (!v.recoveryPub) throw new DriveError('no recovery key', { code: 'invalid' });
          b.recoveryWrap = V.wrapKey(tk, V.unb64u(v.recoveryPub, 32), vaultId, next);
        }
        return b;
      };
      let out;
      let forceRecovery = false;
      for (let i = 0; ; i++) {
        try {
          out = await this.api.rotateVault(vaultId, await body(forceRecovery));
          break;
        } catch (err) {
          const b = (err && err.status === 409 && err.body) || null;
          if (i < 2 && b && b.reason === 'recovery_required') { forceRecovery = true; continue; }
          if (i < 2 && b && Array.isArray(b.devices)) continue; // the list of devices changed in between
          throw err;
        }
      }
      const m = this._keys.get(vaultId) || new Map();
      m.set(next, Buffer.from(tk));
      this._keys.set(vaultId, m);
      this._current.set(vaultId, next);
      return { vault: this.view(out), recoveryKey: rec ? rec.text : null };
    } finally {
      V.wipe(tk);
      if (rec) V.wipe(rec.key);
    }
  }

  /** The live event / push `vault` { vault, event, keyVersion }: a new key → fetched on next use. */
  onEvent(data) {
    const id = drive.vaultIdOf(data && data.vault);
    if (!id) return;
    const kv = drive.posId(data.keyVersion);
    if (kv) this._current.set(id, Math.max(this._current.get(id) || 0, kv));
    if (data.event === 'approved' || data.event === 'rotated') this._states.delete(id);
  }
}

DriveVault.STORE_KEY = STORE_KEY;
DriveVault.isStale = isStale;

module.exports = DriveVault;
