'use strict';

/**
 * GateControl – Vault (Core service)
 *
 * The data side of the page "Vault" in the Windows apps: the end-to-end
 * encrypted password manager of the plugin `gatecontrol-vault` (contract:
 * the plugin's README "App-API" and "Kryptoformat"; reference: the Android
 * app's vault/VaultRepository.kt), over the device token of the existing
 * ApiClient (MessengerApi transport):
 *
 *   GET  /api/v1/client/plugins                                is the plugin there?
 *   ALL  /api/v1/client/plugins/gatecontrol-vault/api/…        account, people, sync, vaults, items, emergency
 *
 * - Crypto: utils/vault-crypto.js (libsodium). The account keys and the
 *   vault keys live in memory only while unlocked; lock() zeroes them.
 *   Decrypted entries exist only in memory, only while unlocked.
 * - Offline copy: the server's ENCRYPTED records (account, vaults, items) and
 *   the outbox of saves not yet confirmed, as JSON in `<dir>/vault-<owner>.json`
 *   (owner: a hash of server + device token; another login never sees it),
 *   written atomically (tmp + rename). Never plaintext, never a key.
 * - Sync: send the outbox → fetch every page of GET sync since the last
 *   counter → fetch vaults shared since (vault=<id>&since=0) → send what was
 *   saved meanwhile → a manager's app changes keys that need it (rekey in
 *   steps ≤ 48 KB / ≤ 100 entries). A save goes to the outbox first, so it
 *   works offline. A `conflict` keeps both versions (the other as a copy
 *   "… (Konflikt)"); `stale_key` encrypts again with the vault's new key.
 * - Auto-lock: after `autoLockMinutes` without touch() (1, 5, 15, 60); 0 =
 *   when the window is hidden (windowHidden()). Always on lock-screen /
 *   suspend when a powerMonitor is given.
 * - "Remember unlock" (Windows: DPAPI through Electron safeStorage): the
 *   user key protected by `opts.protect` in `<dir>/remember-<owner>.bin` —
 *   only when the person turns it on; turned off, the file goes.
 * - "Mit Windows Hello entsperren" (opts.hello, services/windows-hello.js):
 *   the user key wrapped by a key derived from a Windows Hello signature
 *   (utils/vault-hello.js), the record DPAPI-protected in
 *   `<dir>/hello-<owner>.bin`. Turning it on needs the vault unlocked and the
 *   master password; it replaces "remember unlock". After MAX_FAILS failed or
 *   cancelled Hello unlocks only the master password opens (until it did).
 * - Clipboard: copy() writes a secret and clears it after 30 s when it is
 *   still the same text.
 * - Availability like Schule: the page exists while GET /api/v1/client/plugins
 *   lists `gatecontrol-vault`. Pushes (topics `plugin:gatecontrol-vault:*`)
 *   start a sync and emit 'push'; a toast click opens the page (route
 *   `plg-gatecontrol-vault`, context { topic, event, vaultId, emergencyId, page }).
 *
 * Failures are thrown as MessengerError { code }: the plugin's codes
 * (`conflict`, `forbidden`, `no_account`, `not_found`, `exists`, `limit`,
 * `last_manager`, `rekeying`, `stale_key`, `invalid`), the transport's
 * (`network`, `timeout`, `not_configured`, `http_<status>`), and this
 * service's own: `locked`, `wrong_password`, `recovery_key`, `weak_password`,
 * `read_only`, `too_large`, `no_setup`, `not_remembered`, `remember_failed`,
 * `unsupported`, `empty`, `import_encrypted`, `import_unknown`, `invalid_answer`, `hello_on` (remember while Windows
 * Hello is on); Windows Hello: `hello_unavailable`, `hello_off`, `hello_cancelled`, `hello_locked`, `hello_failed`,
 * `hello_invalid` (the Hello key is gone or changed: turned off), `hello_blocked` (too many tries); wifiScan(): `no_adapter`,
 * `service_off`, `radio_off`, `location_denied`, `failed`; totpQr(): `none_found`, `hotp`, `invalid_code`,
 * `no_image`, `unsupported`, `cancelled`, `failed`.
 *
 * Events: 'state' (status()), 'push' (context of a Vault push message).
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const os = require('os');
const MessengerApi = require('./messenger-api');
const { PLUGINS_PATH } = require('../utils/messenger');
const vc = require('../utils/vault-crypto');
const vault = require('../utils/vault');
const vh = require('../utils/vault-hello');
const { t } = require('../i18n');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,    // plugin there / not there: ask again
  retryMinMs: 5000,             // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,    // … 5 min
  syncMs: 5 * 60 * 1000,        // background sync while set up
  minuteMs: 60 * 1000,          // auto-lock unit (tests shorten it)
  clipboardMs: 30 * 1000,       // a copied secret leaves the clipboard
};

const MAX_NOTICES = 5;
const WIFI_CODES = ['no_adapter', 'service_off', 'radio_off', 'location_denied'];
const QR_SOURCES = ['screen', 'clipboard', 'file'];
const QR_CODES = ['none_found', 'hotp', 'invalid_code', 'no_image', 'unsupported', 'cancelled'];

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const fail = (code, status = null) => new MessengerError(code, { code, status });

/** Zeroes a Buffer / Uint8Array in place (key material from Windows Hello). */
function wipeBytes(b) {
  if (b instanceof Uint8Array) b.fill(0);
}

async function atomicWrite(file, data) {
  await fs.promises.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.promises.writeFile(tmp, data, { mode: 0o600 });
  await fs.promises.rename(tmp, file);
}

class VaultService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {string} [opts.dir] - folder of the offline copy, settings and the remembered key
   *   (e.g. path.join(app.getPath('userData'), 'vault')); without it nothing is persisted
   * @param {object} [opts.protect] - { available(): boolean, encrypt(Buffer): Buffer, decrypt(Buffer): Buffer }
   *   for "remember unlock" (VaultService.safeStorageProtect(safeStorage))
   * @param {object} [opts.clipboard] - Electron clipboard (writeText, readText, clear)
   * @param {object} [opts.notificationCenter] - NotificationCenter: Vault pushes → sync + 'push', toast click → page
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks again and syncs
   * @param {object} [opts.powerMonitor] - Electron powerMonitor: lock on 'lock-screen' / 'suspend'
   * @param {string} [opts.deviceName] - shown in an entry's history (default: the computer's name)
   * @param {object} [opts.kdf] - { m, t } of new accounts / passwords (default Argon2id 64 MiB, 3 passes)
   * @param {object} [opts.log]
   * @param {Function} [opts.wifiScan] - Wi-Fi scan for Wi-Fi entries (default: services/wifi-scan.js scanWifi; tests)
   * @param {Function} [opts.totpQr] - QR code reader for 2FA keys (default: services/totp-qr.js scanTotpQr; tests)
   * @param {object} [opts.hello] - Windows Hello provider (services/windows-hello.js createWindowsHello(), or a fake):
   *   { available(), create(name, challenge), sign(name, challenge), remove(name) }; without it Hello is off
   * @param {string} [opts.helloName] - prefix of the Windows Hello key's name (one key per app and login)
   * @param {object} [opts.api] - MessengerApi-compatible transport (tests)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({
    apiClient, log, dir = null, protect = null, clipboard = null, notificationCenter = null, pushClient = null,
    powerMonitor = null, deviceName = null, kdf = null, api = null, timing = {}, now = Date.now, wifiScan = null,
    totpQr = null, hello = null, helloName = 'GateControl Vault',
  } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.dir = dir || null;
    this.protect = protect;
    this.clipboard = clipboard;
    this.notificationCenter = notificationCenter;
    this.pushClient = pushClient;
    this.powerMonitor = powerMonitor;
    this.deviceName = String(deviceName || os.hostname() || 'Windows').slice(0, 80);
    this.kdfOpts = kdf && typeof kdf === 'object' ? { m: kdf.m, t: kdf.t } : {};
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this._wifiScan = typeof wifiScan === 'function' ? wifiScan : null;
    this._totpQr = typeof totpQr === 'function' ? totpQr : null;
    this._qrRun = null;
    this.hello = hello && typeof hello.sign === 'function' ? hello : null;
    this.helloName = helloName;
    this._helloOn = false;
    this._helloAvail = { available: false, reason: this.hello ? 'unknown' : 'unsupported_os' };
    this._helloChecking = null;
    this._helloRun = null;
    this._helloFails = 0;

    this._ready = vc.ready();
    this._sodium = false;
    this._ready.then(() => { this._sodium = true; }, () => {});

    this._avail = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._owner = undefined;      // loaded copy's owner key
    this._loaded = false;
    this._loading = null;
    this._state = vault.emptyState();

    this._keys = null;            // { userKey, publicKey, secretKey } while unlocked
    this._vaultKeys = new Map();  // vault id → Map(keyRev → key)
    this._decrypted = new Map();  // entry id → { blob, data }
    this._entries = [];           // decrypted, trash included
    this._views = [];             // vaults with their names
    this._unreadable = 0;
    this._dataRev = 0;
    this._recovering = false;
    this._pendingSetup = null;    // createAccount() result until confirmSetup()
    this._emergency = new Map();  // emergency id → opened view (decrypted, while unlocked)
    this._importDraft = null;
    this._people = new Map();     // id → { id, name, publicKey } (last GET people)
    this._lastLock = null;

    this._sync = { state: 'idle', code: null, at: null };
    this._syncing = null;
    this._again = false;
    this._notices = [];

    this._mutex = Promise.resolve();
    this._pendingWrite = null;
    this._writing = null;
    this._rememberOn = false;
    this._copied = null;
    this._lockTimer = null;
    this._timer = null;
    this._syncTimer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._lastEmit = '';

    this._settings = this._readSettings();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const nc = this.notificationCenter;
    if (nc && typeof nc.on === 'function') {
      const onNew = (entry) => this._onPush(entry);
      nc.on('new', onNew);
      this._unsub.push(() => nc.removeListener('new', onNew));
      if (typeof nc.addClickRoute === 'function') {
        this._unsub.push(nc.addClickRoute(vault.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onHello = () => {
        if (this._avail.state !== 'available') this.check().catch(() => {});
        else if (this._state.account) this.syncSoon();
      };
      pc.on('hello', onHello);
      this._unsub.push(() => pc.removeListener('hello', onHello));
    }
    const pm = this.powerMonitor;
    if (pm && typeof pm.on === 'function') {
      const onSystem = () => this.lock('system');
      for (const ev of ['lock-screen', 'suspend']) {
        pm.on(ev, onSystem);
        this._unsub.push(() => pm.removeListener(ev, onSystem));
      }
    }
    this._syncTimer = setInterval(() => {
      if (this._avail.state === 'available' && this._state.account) this.syncSoon();
    }, this.timing.syncMs);
    if (this._syncTimer.unref) this._syncTimer.unref();
    this.check().then(() => { if (this._state.account) this.syncSoon(); }).catch(() => {});
    if (this.hello) this.checkHello().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    clearInterval(this._syncTimer);
    this._timer = null;
    this._syncTimer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: lock, the old login's copy stays on disk (its own file), the new one is loaded and asked. */
  async resetForNewServer() {
    this.lock('server');
    this._wipeSetup();
    await this.flush();
    this._owner = undefined;
    this._loaded = false;
    this._state = vault.emptyState();
    this._people.clear();
    this._notices = [];
    this._retry = 0;
    this._sync = { state: 'idle', code: null, at: null };
    this._avail = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._emit();
    if (this._started) {
      try {
        await this.check();
        if (this._state.account) this.syncSoon();
      } catch { /* status says why */ }
    }
    return this.status();
  }

  /** Pending writes of the offline copy done (tests, shutdown). */
  async flush() {
    while (this._writing) await this._writing;
  }

  // ── Status ───────────────────────────────────────────────

  /**
   * {
   *   state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt,   (the plugin)
   *   account: 'unknown'|'none'|'ready', unlocked, recovering, setupPending,
   *   sync: { state: 'idle'|'running'|'done'|'offline'|'error', code, at }, lastSyncAt,
   *   pending (saves not yet on the server), unreadable (entries that could not be decrypted),
   *   dataRev (changes whenever entries / vaults change: fetch them again),
   *   myUserId, safetyNumber (own, compare with others), autoLockMinutes, remember, rememberAvailable,
   *   hello (Windows Hello unlock on), helloAvailable, helloReason (null | 'unknown' | 'unsupported_os' |
   *   'remote_session' | 'not_set_up' | 'no_protect' | 'error'), helloBlocked (too many tries: master password),
   *   helloBusy (a Hello prompt is open),
   *   lastLock: { reason, at } | null, notices: [{ code: 'conflict'|'limit'|'refused', at }]
   * }
   */
  status() {
    const s = this._state;
    let account = 'unknown';
    if (this._loaded && s.account) account = 'ready';
    else if (this._loaded && s.known) account = 'none';
    let safetyNumber = null;
    if (s.account && this._sodium) { try { safetyNumber = vc.safetyNumber(s.account.publicKey); } catch { /* damaged */ } }
    return {
      ...this._avail,
      account,
      unlocked: !!this._keys,
      recovering: this._recovering,
      setupPending: !!this._pendingSetup,
      sync: { ...this._sync },
      lastSyncAt: s.lastSyncMs || null,
      pending: s.outbox.length,
      unreadable: this._unreadable,
      dataRev: this._dataRev,
      myUserId: this._myUserId(),
      safetyNumber,
      autoLockMinutes: this._settings.autoLockMinutes,
      remember: this._rememberOn,
      rememberAvailable: this._protectAvailable(),
      ...this._helloStatus(),
      helloBusy: !!this._helloRun,
      lastLock: this._lastLock ? { ...this._lastLock } : null,
      notices: this._notices.map((n) => ({ ...n })),
    };
  }

  available() {
    return this._avail.state === 'available';
  }

  _emit() {
    const st = this.status();
    const key = JSON.stringify({ ...st, checkedAt: null });
    if (key === this._lastEmit) return;
    this._lastEmit = key;
    this.emit('state', st);
  }

  _notice(code) {
    this._notices = [...this._notices, { code, at: this.now() }].slice(-MAX_NOTICES);
  }

  clearNotices() {
    this._notices = [];
    this._emit();
  }

  // ── Availability ─────────────────────────────────────────

  /** Ask GET /api/v1/client/plugins (and GET account while not known) → status(). */
  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    await this._ensureLoaded();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    try {
      const data = await this.api._call('GET', PLUGINS_PATH);
      const plugins = Array.isArray(data.plugins) ? data.plugins : [];
      const p = plugins.find((x) => x && x.id === vault.PLUGIN_ID);
      this._retry = 0;
      if (!p) this._setAvail('unavailable', 'not_installed', null);
      else this._setAvail('available', null, typeof p.version === 'string' ? p.version.slice(0, 40) : null);
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        this._setAvail('unavailable', 'unsupported', null);
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setAvail('unavailable', err.status === 401 ? 'auth' : 'forbidden', null);
      } else if (err && err.code === 'not_configured') {
        this._setAvail('unavailable', 'not_configured', null);
      } else {
        // Network / 5xx: keep "available" (the page stays, the offline copy works).
        const keep = this._avail.state === 'available';
        this._setAvail(keep ? 'available' : 'error', (err && err.code) || 'network', this._avail.version);
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._avail.state === 'available' && !this._state.account) {
      await this.refreshAccount().catch(() => {});
    }
    if (this._started) {
      this._timer = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timer.unref) this._timer.unref();
    }
    return this.status();
  }

  _setAvail(state, reason, version) {
    this._avail = { state, reason: reason || null, version: version || null, checkedAt: this.now() };
    this._emit();
  }

  // ── Transport ────────────────────────────────────────────

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  _req(method, p, { body, params } = {}) {
    return this.api._call(method, vault.API_BASE + p, { body, params });
  }

  _seg(id) {
    if (!vault.isId(id)) throw fail('invalid');
    return id;
  }

  // ── Offline copy ─────────────────────────────────────────

  _stateFile(owner) { return path.join(this.dir, `vault-${owner}.json`); }

  _rememberFile(owner) { return path.join(this.dir, `remember-${owner}.bin`); }

  _helloFile(owner) { return path.join(this.dir, `hello-${owner}.bin`); }

  _ensureLoaded() {
    const owner = vault.ownerKey(this._scopeNow());
    if (this._loaded && owner === this._owner) return Promise.resolve();
    if (this._loading && this._loading.owner === owner) return this._loading.p;
    const p = (async () => {
      let st = null;
      if (owner && this.dir) {
        try {
          const raw = await fs.promises.readFile(this._stateFile(owner), 'utf8');
          st = vault.stateFromJson(JSON.parse(raw), owner);
          if (!st) this.log.warn('Vault: local copy does not belong to this login, ignored');
        } catch (err) {
          if (err && err.code !== 'ENOENT') this.log.warn(`Vault: local copy unreadable (${err.code || err.name})`);
        }
      }
      if (this._loading && this._loading.p !== p) return;
      // another login: keys and views of the previous one go
      this.lock('server');
      this._wipeSetup();
      this._owner = owner;
      this._state = st || vault.emptyState();
      this._loaded = true;
      this._rememberOn = !!(owner && this.dir && fs.existsSync(this._rememberFile(owner)));
      this._helloOn = !!(this.hello && owner && this.dir && fs.existsSync(this._helloFile(owner)));
      this._helloFails = 0;
      this._rebuild();
      this._emit();
    })().finally(() => { if (this._loading && this._loading.p === p) this._loading = null; });
    this._loading = { owner, p };
    return p;
  }

  _setState(s) {
    this._state = s;
    this._persist();
    this._emit();
  }

  _persist() {
    if (!this._owner || !this.dir) return;
    this._pendingWrite = { owner: this._owner, state: this._state };
    if (!this._writing) {
      this._writing = this._writeLoop().finally(() => { this._writing = null; });
    }
  }

  async _writeLoop() {
    while (this._pendingWrite) {
      const w = this._pendingWrite;
      this._pendingWrite = null;
      try {
        await atomicWrite(this._stateFile(w.owner), JSON.stringify(vault.stateToJson(w.state, w.owner)));
      } catch (err) {
        this.log.warn(`Vault: local copy not written (${err.code || err.message})`);
      }
    }
  }

  async _forgetCopy(owner) {
    if (!owner || !this.dir) return;
    if (this._pendingWrite && this._pendingWrite.owner === owner) this._pendingWrite = null;
    await this.flush();
    for (const f of [this._stateFile(owner), this._rememberFile(owner)]) {
      try { await fs.promises.rm(f, { force: true }); } catch (err) { this.log.warn(`Vault: ${path.basename(f)} not removed (${err.code})`); }
    }
    if (owner === this._owner) this._rememberOn = false;
    await this._forgetHello(owner);
  }

  // ── Settings ─────────────────────────────────────────────

  _settingsFile() { return this.dir ? path.join(this.dir, 'settings.json') : null; }

  _readSettings() {
    const out = { autoLockMinutes: vault.DEFAULT_AUTO_LOCK };
    const f = this._settingsFile();
    if (!f) return out;
    try {
      const o = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (vault.AUTO_LOCK_CHOICES.includes(o.autoLockMinutes)) out.autoLockMinutes = o.autoLockMinutes;
    } catch { /* defaults */ }
    return out;
  }

  _protectAvailable() {
    try { return !!(this.protect && typeof this.protect.available === 'function' && this.protect.available()); } catch { return false; }
  }

  /** { autoLockMinutes, choices, remember, rememberAvailable, hello, helloAvailable, helloReason, helloBlocked } */
  settings() {
    return {
      autoLockMinutes: this._settings.autoLockMinutes,
      choices: [...vault.AUTO_LOCK_CHOICES],
      remember: this._rememberOn,
      rememberAvailable: this._protectAvailable(),
      ...this._helloStatus(),
    };
  }

  /**
   * { autoLockMinutes?: 0|1|5|15|60, remember?: boolean } → settings().
   * remember: true needs the vault unlocked (the user key is protected now).
   */
  async setSettings({ autoLockMinutes, remember } = {}) {
    await this._ensureLoaded();
    if (autoLockMinutes !== undefined) {
      if (!vault.AUTO_LOCK_CHOICES.includes(autoLockMinutes)) throw fail('invalid');
      this._settings = { ...this._settings, autoLockMinutes };
      const f = this._settingsFile();
      if (f) await atomicWrite(f, JSON.stringify(this._settings));
      this.touch();
    }
    if (remember === true) {
      if (!this._keys) throw fail('locked');
      if (!this._protectAvailable() || !this._owner || !this.dir) throw fail('unsupported');
      // Windows Hello asks for the person; a kept key would open without them
      if (this._helloOn) throw fail('hello_on');
      const plain = Buffer.from(this._keys.userKey);
      try {
        const blob = this.protect.encrypt(plain);
        await atomicWrite(this._rememberFile(this._owner), Buffer.from(blob));
      } finally {
        plain.fill(0);
      }
      this._rememberOn = true;
    } else if (remember === false) {
      if (this._owner && this.dir) await fs.promises.rm(this._rememberFile(this._owner), { force: true });
      this._rememberOn = false;
    }
    this._emit();
    return this.settings();
  }

  // ── Auto-lock ────────────────────────────────────────────

  /** Activity on the page: the auto-lock time starts again. */
  touch() {
    clearTimeout(this._lockTimer);
    this._lockTimer = null;
    const m = this._settings.autoLockMinutes;
    if (!this._keys || !(m > 0)) return;
    this._lockTimer = setTimeout(() => this.lock('timeout'), m * this.timing.minuteMs);
    if (this._lockTimer.unref) this._lockTimer.unref();
  }

  /** The main window was hidden / minimized: "immediately" (0) locks now. */
  windowHidden() {
    if (this._keys && this._settings.autoLockMinutes === 0) this.lock('hidden');
  }

  // ── Keys ─────────────────────────────────────────────────

  _myUserId() {
    const p = this._state.vaults.find((v) => v.kind === 'personal');
    return p ? p.ownerId : null;
  }

  _vault(id) {
    return this._state.vaults.find((v) => v.id === id) || null;
  }

  /** The vault's keys (current and, during a key change, the new one), opened once per unlock. */
  _keysOf(v) {
    if (!this._keys || !v) return new Map();
    let m = this._vaultKeys.get(v.id);
    if (!m) {
      m = new Map();
      this._vaultKeys.set(v.id, m);
    }
    const { publicKey, secretKey } = this._keys;
    if (!m.has(v.keyRev)) { try { m.set(v.keyRev, vc.openSealed(v.sealedKey, publicKey, secretKey)); } catch { /* not ours */ } }
    if (v.pending && v.pending.sealedKey && !m.has(v.pending.keyRev)) {
      try { m.set(v.pending.keyRev, vc.openSealed(v.pending.sealedKey, publicKey, secretKey)); } catch { /* not ours */ }
    }
    return m;
  }

  _putKey(vaultId, keyRev, key) {
    let m = this._vaultKeys.get(vaultId);
    if (!m) {
      m = new Map();
      this._vaultKeys.set(vaultId, m);
    }
    m.set(keyRev, Uint8Array.from(key));
  }

  _opened(keys, { recovering = false } = {}) {
    if (this._keys && this._keys !== keys) vc.wipe(this._keys);
    this._keys = keys;
    this._recovering = recovering;
    this._lastLock = null;
    this._helloFails = 0;
    this._rebuild();
    this.touch();
    this._emit();
    this.syncSoon();
  }

  /** Forget every key and everything decrypted. reason: manual | timeout | hidden | system | server | account */
  lock(reason = 'manual') {
    clearTimeout(this._lockTimer);
    this._lockTimer = null;
    const was = !!this._keys;
    if (this._keys) vc.wipe(this._keys);
    this._keys = null;
    for (const m of this._vaultKeys.values()) for (const k of m.values()) vc.wipe(k);
    this._vaultKeys.clear();
    this._decrypted.clear();
    this._emergency.clear();
    this._importDraft = null;
    this._recovering = false;
    // a setup not yet confirmed holds keys too: it starts over after a lock
    this._wipeSetup();
    // a copied secret does not outlive the unlock (only while it is still what we put there)
    this._clearClipboard();
    if (was) this._lastLock = { reason, at: this.now() };
    this._rebuild();
    this._emit();
  }

  _wipeSetup() {
    if (this._pendingSetup) {
      vc.wipe(this._pendingSetup.keys);
      this._pendingSetup = null;
    }
  }

  // ── Decrypted view ───────────────────────────────────────

  _decryptBlob(v, id, rev, keyRev, blob) {
    const key = this._keysOf(v).get(keyRev);
    if (!key || !blob) return null;
    try {
      return vault.normalizeEntry(vc.decryptItem(key, { id, vaultId: v.id, rev, blob }));
    } catch {
      return null;
    }
  }

  /** Redoes the decrypted lists from the copy (unchanged blobs are not decrypted again). */
  _rebuild() {
    this._dataRev++;
    if (!this._keys) {
      this._entries = [];
      this._views = [];
      this._unreadable = 0;
      this._decrypted.clear();
      return;
    }
    const s = this._state;
    const byId = new Map(s.vaults.map((v) => [v.id, v]));
    const views = [];
    for (const v of s.vaults) {
      const key = this._keysOf(v).get(v.keyRev);
      if (!key) continue;
      let name = null;
      try { name = vc.decryptName(key, v.id, v.nameEnc); } catch { /* shown as … */ }
      views.push({ vault: v, name });
    }
    const pending = new Map(s.outbox.map((o) => [o.id, o]));
    const out = [];
    const seen = new Set();
    let unreadable = 0;
    const cached = (id, blob, make) => {
      const c = this._decrypted.get(id);
      if (c && c.blob === blob) return c.data;
      const data = make();
      if (data) this._decrypted.set(id, { blob, data });
      return data;
    };
    for (const item of s.items.values()) {
      if (item.state === 'purged' || !byId.has(item.vaultId)) continue;
      seen.add(item.id);
      const p = pending.get(item.id);
      const src = p ? { blob: p.blob, rev: p.baseRev + 1, keyRev: p.keyRev, vaultId: p.vaultId } : { blob: item.blob, rev: item.rev, keyRev: item.keyRev, vaultId: item.vaultId };
      const v = byId.get(src.vaultId) || byId.get(item.vaultId);
      const data = cached(item.id, src.blob, () => this._decryptBlob(v, item.id, src.rev, src.keyRev, src.blob));
      if (!data) {
        unreadable++;
        continue;
      }
      out.push({
        id: item.id, vaultId: v.id, rev: item.rev, trashed: item.state === 'trash', trashedAt: item.trashedAt,
        updatedAt: item.updatedAt, updatedBy: item.updatedBy, device: item.device, data, pending: !!p,
      });
    }
    for (const p of s.outbox) {
      if (seen.has(p.id)) continue;
      const v = byId.get(p.vaultId);
      if (!v) continue;
      const data = cached(p.id, p.blob, () => this._decryptBlob(v, p.id, p.baseRev + 1, p.keyRev, p.blob));
      if (!data) continue;
      out.push({
        id: p.id, vaultId: p.vaultId, rev: p.baseRev, trashed: false, trashedAt: null, updatedAt: null,
        updatedBy: this._myUserId(), device: this.deviceName, data, pending: true,
      });
    }
    const keep = new Set(out.map((e) => e.id));
    for (const id of [...this._decrypted.keys()]) if (!keep.has(id)) this._decrypted.delete(id);
    const coll = (a, b) => a.localeCompare(b, 'de', { sensitivity: 'base' });
    this._views = views.sort((a, b) => (a.vault.kind === b.vault.kind ? coll(a.name || '', b.name || '') : a.vault.kind === 'personal' ? -1 : 1));
    this._entries = out.sort((a, b) => coll(a.data.title, b.data.title));
    this._unreadable = unreadable;
  }

  _vaultView(x) {
    const v = x.vault;
    let count = 0;
    let trash = 0;
    for (const e of this._entries) if (e.vaultId === v.id) { if (e.trashed) trash++; else count++; }
    return {
      id: v.id, kind: v.kind, personal: v.kind === 'personal', name: x.name, role: v.role,
      canWrite: vault.canWrite(v), canManage: vault.canManage(v), ownerId: v.ownerId, keyRev: v.keyRev,
      needsRekey: v.needsRekey, rekeying: !!v.pending, members: v.members.map((m) => ({ ...m })),
      updatedAt: v.updatedAt, count, trash,
    };
  }

  _needKeys() {
    if (!this._keys) throw fail('locked');
    return this._keys;
  }

  /** { entries: [summary] (no secrets), vaults, unreadable }. opts: { vaultId?, trash?: true = trash only } */
  async entries({ vaultId = null, trash = false } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    const list = this._entries.filter((e) => (!vaultId || e.vaultId === vaultId) && e.trashed === (trash === true));
    return { entries: list.map(vault.entrySummary), vaults: this._views.map((x) => this._vaultView(x)), unreadable: this._unreadable };
  }

  _find(id, emergencyId = null) {
    this._needKeys();
    let e = null;
    if (emergencyId) {
      const view = this._emergency.get(emergencyId);
      if (!view) throw fail('not_found');
      e = view.entries.find((x) => x.id === id) || null;
    } else {
      e = this._entries.find((x) => x.id === id) || null;
    }
    if (!e) throw fail('not_found');
    return e;
  }

  /**
   * Entries for a login form or a web address: same site by `domain`, else
   * by `app` (an entry's `apps`); logins, not trashed, favourites first → [summary].
   */
  async match({ domain = null, app = null } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    return vault.matchEntries(this._entries, { domain, app }).map(vault.entrySummary);
  }

  /** One entry with its secrets (the detail page): { ...summary, data }. */
  async entry(id, { emergencyId = null } = {}) {
    await this._ensureLoaded();
    const e = this._find(id, emergencyId);
    return { ...vault.entrySummary(e), data: JSON.parse(JSON.stringify(e.data)) };
  }

  /** { vaults: [view] } */
  async vaults() {
    await this._ensureLoaded();
    this._needKeys();
    return { vaults: this._views.map((x) => this._vaultView(x)) };
  }

  // ── Account ──────────────────────────────────────────────

  /** GET account: is Vault set up here? → status(). */
  async refreshAccount() {
    await this._ensureLoaded();
    const a = vault.parseAccountAnswer(await this._req('GET', 'account'));
    if (!a) throw fail('invalid_answer');
    if (!a.account) this._accountGone();
    else this._setState({ ...this._state, account: a.account, known: true });
    return this.status();
  }

  _accountGone() {
    const had = !!this._state.account;
    // nothing to lock when there never was an account (e.g. a check while the person is setting up: that setup
    // and the recovery key on screen must stay)
    if (had) this.lock('account');
    this._setState({ ...vault.emptyState(), known: true });
    if (had && this._owner && this.dir) {
      fs.promises.rm(this._rememberFile(this._owner), { force: true }).catch(() => {});
      this._rememberOn = false;
      this._forgetHello(this._owner).catch(() => {});
    }
    this._rebuild();
    this._emit();
  }

  /**
   * Setup, step 1: keys and the personal vault are made here, nothing is sent
   * yet → { recoveryKey } to show (print / write down). Step 2: confirmSetup()
   * once the person confirmed keeping it. The master password needs ≥ 12
   * characters and must not be weak.
   */
  async setup({ password, personalName = null } = {}) {
    await this._ensureLoaded();
    if (this._state.account) throw fail('exists');
    if (!vault.goodMasterPassword(password)) throw fail('weak_password');
    await this._ready;
    this._wipeSetup();
    const name = (typeof personalName === 'string' && personalName.trim() ? personalName.trim() : t('vault.personalName')).slice(0, 200);
    const made = vc.createAccount(password, name, this.kdfOpts);
    this._pendingSetup = made;
    this._emit();
    return { recoveryKey: made.recoveryKey };
  }

  /** Setup, step 2: POST account → unlocked. */
  async confirmSetup() {
    await this._ensureLoaded();
    const p = this._pendingSetup;
    if (!p) throw fail('no_setup');
    let account;
    try {
      account = vault.parseAccount((await this._req('POST', 'account', { body: p.body })).account);
      if (!account) throw fail('invalid_answer');
    } catch (err) {
      // offline: the person may try again with the same recovery key; refused: start over
      if (!(err && err.transient)) {
        this._wipeSetup();
        this._emit();
        if (err && err.code === 'exists') this.refreshAccount().catch(() => {});
      }
      throw err;
    }
    this._pendingSetup = null;
    const { userKey, publicKey, secretKey, personalKey } = p.keys;
    this._setState({ ...vault.emptyState(), account, known: true });
    this._putKey(p.body.personal.id, 1, personalKey);
    vc.wipe(personalKey);
    this._opened({ userKey, publicKey, secretKey });
    return this.status();
  }

  cancelSetup() {
    this._wipeSetup();
    this._emit();
  }

  async _accountForUnlock() {
    await this._ensureLoaded();
    if (!this._state.account) await this.refreshAccount();
    if (!this._state.account) throw fail('no_account');
    await this._ready;
    return this._state.account;
  }

  /** The master password → unlocked (works offline with the copy). Argon2id blocks ~0.5–1 s. */
  async unlock({ password } = {}) {
    if (typeof password !== 'string' || !password) throw fail('invalid');
    let account = await this._accountForUnlock();
    try {
      this._opened(vc.unlock(account, password));
      return this.status();
    } catch (err) {
      if (!(err instanceof vc.VaultCryptoError) || err.code !== 'decrypt') throw fail('invalid');
    }
    // changed on another device meanwhile? ask once
    const before = account.rev;
    try { await this.refreshAccount(); } catch { /* offline: the copy decides */ }
    account = this._state.account;
    if (!account || account.rev === before) throw fail('wrong_password');
    try {
      this._opened(vc.unlock(account, password));
    } catch {
      throw fail('wrong_password');
    }
    return this.status();
  }

  /** The user key kept by "remember unlock" (DPAPI) → unlocked. */
  async unlockRemembered() {
    const account = await this._accountForUnlock();
    if (!this._protectAvailable()) throw fail('unsupported');
    if (!this._rememberOn || !this._owner || !this.dir) throw fail('not_remembered');
    let buf;
    try {
      buf = Buffer.from(this.protect.decrypt(await fs.promises.readFile(this._rememberFile(this._owner))));
    } catch {
      await this.setSettings({ remember: false }).catch(() => {});
      throw fail('remember_failed');
    }
    const userKey = Uint8Array.from(buf);
    buf.fill(0);
    try {
      this._opened(vc.keysFrom(account, userKey));
    } catch {
      vc.wipe(userKey);
      await this.setSettings({ remember: false }).catch(() => {});
      throw fail('remember_failed');
    }
    return this.status();
  }

  // ── Windows Hello ────────────────────────────────────────

  _helloStatus() {
    let reason = this._helloAvail.reason;
    let available = this._helloAvail.available;
    if (available && !this._protectAvailable()) {
      available = false;
      reason = 'no_protect';
    }
    return {
      hello: this._helloOn,
      helloAvailable: available,
      helloReason: available ? null : reason,
      helloBlocked: this._helloOn && this._helloFails >= vh.MAX_FAILS,
    };
  }

  _helloKeyName(owner = this._owner) {
    return vh.keyName(this.helloName, owner);
  }

  /** Is Windows Hello usable here (set up, not in a remote session)? Asks Windows again → { available, reason }. */
  checkHello() {
    if (!this.hello) return Promise.resolve({ available: false, reason: 'unsupported_os' });
    if (this._helloChecking) return this._helloChecking;
    this._helloChecking = (async () => {
      let a;
      try {
        a = await this.hello.available();
      } catch (err) {
        this.log.warn(`Vault: Windows Hello check failed (${err && err.message})`);
        a = null;
      }
      this._helloAvail = a && typeof a === 'object'
        ? { available: a.available === true, reason: a.available === true ? null : String(a.reason || 'error') }
        : { available: false, reason: 'error' };
      this._emit();
      const s = this._helloStatus();
      return { available: s.helloAvailable, reason: s.helloReason };
    })().finally(() => { this._helloChecking = null; });
    return this._helloChecking;
  }

  /** The record of this login (DPAPI-opened), or null. */
  async _readHello(owner) {
    let raw;
    try {
      raw = await fs.promises.readFile(this._helloFile(owner));
    } catch {
      return null;
    }
    try {
      return vh.parseRecord(this.protect.decrypt(raw));
    } catch {
      return null;
    }
  }

  /** Hello off for `owner`: the record goes, and the Windows Hello key (best effort, no prompt). */
  async _forgetHello(owner) {
    if (!owner || !this.dir) return;
    const had = fs.existsSync(this._helloFile(owner));
    try { await fs.promises.rm(this._helloFile(owner), { force: true }); } catch (err) { this.log.warn(`Vault: Windows Hello record not removed (${err.code})`); }
    if (this.hello && had) {
      try { await this.hello.remove(this._helloKeyName(owner)); } catch { /* the key stays unused */ }
    }
    if (owner === this._owner && this._helloOn) {
      this._helloOn = false;
      this._helloFails = 0;
      this._emit();
    }
  }

  _helloFail(status) {
    const map = { cancelled: 'hello_cancelled', prefers_password: 'hello_cancelled', locked: 'hello_locked', unavailable: 'hello_unavailable' };
    return map[status] || 'hello_failed';
  }

  /**
   * Windows Hello unlock on / off. On: { on: true, password } — needs the vault unlocked and the master password
   * (checked again: the key Hello guards is the one this password opens); Windows asks for face, fingerprint or PIN
   * (creating the key, then signing). Replaces "remember unlock". Off: { on: false } — the record and the Hello key go
   * (works locked, too). → settings()
   */
  async setHello({ on, password } = {}) {
    await this._ensureLoaded();
    if (on === false) {
      await this._forgetHello(this._owner);
      this._emit();
      return this.settings();
    }
    if (on !== true) throw fail('invalid');
    const keys = this._needKeys();
    if (!this.hello || !this._owner || !this.dir) throw fail('unsupported');
    if (!this._protectAvailable()) throw fail('unsupported');
    if (typeof password !== 'string' || !password) throw fail('invalid');
    await this._ready;
    let check;
    try {
      check = vc.unlock(this._state.account, password);
    } catch {
      throw fail('wrong_password');
    }
    const same = this._keys === keys && check.userKey.length === keys.userKey.length && Buffer.from(check.userKey).equals(Buffer.from(keys.userKey));
    vc.wipe(check);
    if (!same) throw fail('locked');
    // already on: nothing to do (a new key would replace the one the record needs)
    if (this._helloOn) return this.settings();
    const a = await this.checkHello();
    if (!a.available) throw fail('hello_unavailable');

    const owner = this._owner;
    const name = this._helloKeyName(owner);
    const challenge = vh.newChallenge();
    const made = await this.hello.create(name, challenge);
    if (!made || made.status !== 'ok' || !made.signature || !made.publicKey) {
      const status = made ? made.status : 'failed';
      this.log.info(`Vault: Windows Hello not turned on (${status})`);
      // cancelled after the key was made (at the signature): it stays unused
      if (status !== 'unavailable') { try { await this.hello.remove(name); } catch { /* unused */ } }
      if (made) wipeBytes(made.signature);
      throw fail(this._helloFail(status));
    }
    const signature = Buffer.from(made.signature);
    const wipeSig = () => { signature.fill(0); wipeBytes(made.signature); };
    let mode = 'pkcs1';
    try {
      if (!vh.verifies(made.publicKey, challenge, signature)) {
        // not the expected scheme: usable only when it signs the same bytes again
        const again = await this.hello.sign(name, challenge);
        const equal = again && again.status === 'ok' && again.signature && Buffer.from(again.signature).equals(signature);
        if (again) wipeBytes(again.signature);
        if (!equal) {
          this.log.warn('Vault: Windows Hello signature is not stable, not turned on');
          try { await this.hello.remove(name); } catch { /* unused */ }
          throw fail(again && again.status !== 'ok' ? this._helloFail(again.status) : 'hello_failed');
        }
        mode = 'repeat';
      }
      // locked, another login or Hello turned on elsewhere meanwhile: nothing is written
      if (!this._keys || this._keys !== keys || this._owner !== owner) {
        try { await this.hello.remove(name); } catch { /* unused */ }
        throw fail('locked');
      }
      let record;
      try {
        record = vh.seal({ keyName: name, challenge, publicKey: made.publicKey, signature, check: mode, userKey: keys.userKey });
      } catch (err) {
        this.log.warn(`Vault: Windows Hello key not usable (${err && err.code}), not turned on`);
        try { await this.hello.remove(name); } catch { /* unused */ }
        throw fail('hello_failed');
      }
      const plain = vh.encodeRecord(record);
      try {
        await atomicWrite(this._helloFile(owner), Buffer.from(this.protect.encrypt(plain)));
      } finally {
        plain.fill(0);
      }
    } finally {
      wipeSig();
    }
    if (this._rememberOn) {
      await fs.promises.rm(this._rememberFile(owner), { force: true }).catch(() => {});
      this._rememberOn = false;
    }
    this._helloOn = true;
    this._helloFails = 0;
    this.log.info(`Vault: Windows Hello unlock turned on (${mode})`);
    this._emit();
    return this.settings();
  }

  /**
   * Windows Hello → unlocked. One prompt at a time (a second call shares it). Failed / cancelled tries count;
   * after MAX_FAILS only the master password (status().helloBlocked). A key that is gone or changed (Hello reset,
   * PIN removed, another account) turns Hello off: `hello_invalid`.
   */
  unlockHello() {
    if (this._helloRun) return this._helloRun;
    this._helloRun = this._unlockHello().finally(() => {
      this._helloRun = null;
      this._emit();
    });
    this._emit();
    return this._helloRun;
  }

  async _unlockHello() {
    const account = await this._accountForUnlock();
    if (!this.hello || !this._helloOn || !this._owner || !this.dir) throw fail('hello_off');
    if (this._keys) return this.status();
    if (this._helloFails >= vh.MAX_FAILS) throw fail('hello_blocked');
    if (!this._protectAvailable()) throw fail('hello_unavailable');
    const owner = this._owner;
    const record = await this._readHello(owner);
    if (!record || record.keyName !== this._helloKeyName(owner)) {
      this.log.warn('Vault: Windows Hello record unreadable, turned off');
      await this._forgetHello(owner);
      throw fail('hello_invalid');
    }
    const res = await this.hello.sign(record.keyName, Buffer.from(record.challenge, 'base64url'));
    if (this._owner !== owner) {
      if (res) wipeBytes(res.signature);
      throw fail('locked');
    }
    if (!res || res.status !== 'ok' || !res.signature) {
      const status = res ? res.status : 'failed';
      this.log.info(`Vault: Windows Hello unlock: ${status}`);
      if (status === 'not_found') {
        await this._forgetHello(owner);
        throw fail('hello_invalid');
      }
      if (status === 'unavailable') {
        this.checkHello().catch(() => {});
        throw fail('hello_unavailable');
      }
      this._helloFails = status === 'prefers_password' ? vh.MAX_FAILS : this._helloFails + 1;
      throw fail(this._helloFail(status));
    }
    if (this._keys) {
      // opened with the password meanwhile
      wipeBytes(res.signature);
      return this.status();
    }
    let userKey;
    try {
      userKey = vh.open(record, res.signature);
    } catch (err) {
      this.log.warn(`Vault: Windows Hello key does not open the vault (${err && err.code}), turned off`);
      await this._forgetHello(owner);
      throw fail('hello_invalid');
    } finally {
      wipeBytes(res.signature);
    }
    let keys;
    try {
      keys = vc.keysFrom(account, userKey);
    } catch {
      vc.wipe(userKey);
      this.log.warn('Vault: Windows Hello key belongs to another account, turned off');
      await this._forgetHello(owner);
      throw fail('hello_invalid');
    }
    this._opened(keys);
    return this.status();
  }

  /** The recovery key → unlocked; then completeRecovery() sets a new password and a new recovery key. */
  async recover({ recoveryKey } = {}) {
    const account = await this._accountForUnlock();
    try {
      this._opened(vc.unlockWithRecovery(account, recoveryKey), { recovering: true });
    } catch (err) {
      throw fail(err && err.code === 'recovery_key' ? 'recovery_key' : 'wrong_password');
    }
    return this.status();
  }

  /** After recover(): a new master password and a new recovery key → { recoveryKey } (show once). Needs the server. */
  async completeRecovery({ password } = {}) {
    this._needKeys();
    // only after recover(): otherwise it would set a new password without the current one (changePassword checks it)
    if (!this._recovering) throw fail('invalid');
    if (!vault.goodMasterPassword(password)) throw fail('weak_password');
    await this._ready;
    const recoveryKey = await this._updateAccount((account, keys) => {
      const r = vc.recover(account, keys, password, this.kdfOpts);
      return { body: r.body, extra: r.recoveryKey };
    });
    this._recovering = false;
    this._emit();
    return { recoveryKey };
  }

  /** A new master password (the user key stays — nothing else changes). `current` is checked first. */
  async changePassword({ current, password } = {}) {
    const keys = this._needKeys();
    if (typeof current !== 'string' || !current) throw fail('invalid');
    if (!vault.goodMasterPassword(password)) throw fail('weak_password');
    await this._ready;
    try {
      vc.wipe(vc.unlock(this._state.account, current));
    } catch {
      throw fail('wrong_password');
    }
    if (!this._keys || this._keys !== keys) throw fail('locked');
    await this._updateAccount((account, k) => ({ body: vc.changePassword(account, k, password, this.kdfOpts), extra: null }));
    return this.status();
  }

  async _updateAccount(make) {
    for (let i = 0; i < 2; i++) {
      const keys = this._needKeys();
      const account = this._state.account;
      if (!account) throw fail('no_account');
      const { body, extra } = make(account, keys);
      try {
        const a = vault.parseAccount((await this._req('PUT', 'account', { body })).account);
        if (!a) throw fail('invalid_answer');
        this._setState({ ...this._state, account: a });
        return extra;
      } catch (err) {
        // another device changed it meanwhile: take theirs and do it again on top
        const cur = err && err.code === 'conflict' && err.body ? vault.parseAccount(err.body.account) : null;
        if (!cur) throw err;
        this._setState({ ...this._state, account: cur });
      }
    }
    throw fail('conflict');
  }

  /** Deletes the account and everything only this person had (needs the server, unlocked). confirm: 'DELETE'. */
  async deleteAccount({ confirm } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    if (confirm !== 'DELETE') throw fail('invalid');
    await this._req('POST', 'account/delete', { body: { confirm: 'DELETE' } });
    const owner = this._owner;
    this.lock('account');
    this._setState({ ...vault.emptyState(), known: true });
    await this._forgetCopy(owner);
    this._emit();
    return this.status();
  }

  // ── Sync ─────────────────────────────────────────────────

  /** A sync in the background (once more after the running one, when one runs). */
  syncSoon() {
    this.sync().catch(() => {});
  }

  /** Send the outbox, fetch what changed, run key changes → { state: 'done'|'offline'|'error', code }. */
  sync() {
    if (this._syncing) {
      this._again = true;
      return this._syncing;
    }
    this._syncing = (async () => {
      let r;
      do {
        this._again = false;
        r = await this._syncOnce();
      } while (this._again && r.state === 'done');
      return r;
    })().finally(() => { this._syncing = null; });
    return this._syncing;
  }

  async _syncOnce() {
    await this._ensureLoaded();
    this._sync = { ...this._sync, state: 'running' };
    this._emit();
    let res;
    try {
      await this._exclusive(() => this._syncLocked());
      res = { state: 'done', code: null };
    } catch (err) {
      res = { state: err && err.transient ? 'offline' : 'error', code: (err && err.code) || 'failed' };
      if (!(err && err.transient)) this.log.warn(`Vault: sync failed (${res.code})`);
    }
    this._sync = { ...res, at: this.now() };
    this._emit();
    if (res.state === 'done' && this._keys) await this._runRekeys();
    return res;
  }

  /** One network write sequence at a time (sync, key change). */
  _exclusive(fn) {
    const run = this._mutex.then(() => fn());
    this._mutex = run.catch(() => {});
    return run;
  }

  async _syncLocked() {
    if (!this._state.account) {
      const a = vault.parseAccountAnswer(await this._req('GET', 'account'));
      if (!a) throw fail('invalid_answer');
      if (!a.account) {
        this._accountGone();
        return;
      }
      this._setState({ ...this._state, account: a.account, known: true });
    }
    await this._flushLocked();
    if (!(await this._pull(null, this._state.seq))) return;
    // a vault shared with this person since: all its entries (they are older than our counter). mergePage keeps
    // such vaults in `fresh` (in the copy) until fetched, so an interrupted sync or a restart does not skip them.
    for (const id of [...this._state.fresh]) {
      if (!this._vault(id)) continue;
      if (!(await this._pull(id, 0))) return;
      this._setState({ ...this._state, fresh: this._state.fresh.filter((x) => x !== id) });
    }
    this._rebuild();
    // the outbox again: saves made while fetching, saves to encrypt again with a new key
    await this._flushLocked();
  }

  /** Every page of GET sync from `since`; false when the account is gone. */
  async _pull(vaultId, since) {
    let from = since;
    for (let guard = 0; guard < 200; guard++) {
      const params = { since: from, limit: vault.SYNC_LIMIT };
      if (vaultId) params.vault = vaultId;
      let raw;
      try {
        raw = await this._req('GET', 'sync', { params });
      } catch (err) {
        if (err && err.code === 'no_account') {
          this._accountGone();
          return false;
        }
        throw err;
      }
      const page = vault.parseSync(raw);
      if (!page) throw fail('invalid_answer');
      let s = vault.mergePage(this._state, page, this.now());
      if (!page.more && !vaultId) s = { ...s, seq: page.next };
      this._setState(s);
      if (!page.more) return true;
      from = page.next;
    }
    throw fail('too_many_pages');
  }

  /** POST items for the outbox in requests ≤ ~48 KB / ≤ 100 entries. Only while unlocked (conflicts need the keys). */
  async _flushLocked() {
    for (let round = 0; round < 60 && this._keys && this._state.outbox.length; round++) {
      this._rekeyOutbox();
      const [batch] = vault.batches(this._state.outbox);
      const results = vault.parseSaveResults(await this._req('POST', 'items', { body: { items: batch, device: this.deviceName } }));
      if (!results) throw fail('invalid_answer');
      if (this._applyResults(batch, results)) break;
    }
  }

  /** Saves still on an old key generation (the vault got a new key): encrypted again with the one a save must use now. */
  _rekeyOutbox() {
    let changed = false;
    const outbox = this._state.outbox.map((o) => {
      const v = this._vault(o.vaultId);
      if (!v || o.keyRev === vault.wantedKeyRev(v) || !this._keysOf(v).has(vault.wantedKeyRev(v))) return o;
      const again = this._reencrypt(o, o.baseRev);
      if (!again) return o;
      changed = true;
      return again;
    });
    if (changed) this._setState({ ...this._state, outbox });
  }

  /**
   * POST items' results → the copy. Returns true when the server asked for a
   * new key (stale_key): the rest waits for the next pull.
   */
  _applyResults(batch, results, { rekey = false } = {}) {
    let s = this._state;
    const byId = new Map(results.map((r) => [r.id, r]));
    const me = this._myUserId();
    let stale = false;
    for (const sent of batch) {
      const res = byId.get(sent.id);
      if (!res) continue;
      const queued = s.outbox.find((o) => o.id === sent.id) || null;
      // the entry was changed again meanwhile: that newer save stays queued (on top of the new revision)
      const changedAgain = !!queued && queued.blob !== sent.blob;
      // a conflict with exactly what we sent: our earlier try got through, only its answer was lost
      const echoed = !res.ok && res.code === 'conflict' && !!res.current && res.current.blob === sent.blob;
      const items = new Map(s.items);
      let outbox = s.outbox;
      if (res.ok || echoed) {
        const old = items.get(sent.id);
        const rev = echoed ? res.current.rev : res.rev || sent.baseRev + 1;
        items.set(sent.id, {
          id: sent.id, vaultId: sent.vaultId, rev, keyRev: sent.keyRev, blob: sent.blob,
          state: old && old.state === 'trash' ? 'trash' : 'live', trashedAt: old ? old.trashedAt : null,
          updatedAt: new Date(this.now()).toISOString(), updatedBy: me, device: this.deviceName,
          seq: (echoed ? res.current.seq : res.seq) || (old ? old.seq : 0),
        });
        if (changedAgain) {
          // its blob is bound to the old revision (AD): encrypt again on top of the new one; locked meanwhile
          // (no keys): it stays as it is — never dropped (at worst a conflict copy once unlocked)
          const again = this._reencrypt(queued, rev);
          if (again || this._keys) outbox = outbox.filter((o) => o.id !== sent.id).concat(again ? [again] : []);
        } else if (queued) {
          outbox = outbox.filter((o) => o.id !== sent.id);
        }
      } else if (res.code === 'conflict' && res.current) {
        // both versions stay: the server's as the entry, ours as a copy
        items.set(sent.id, res.current);
        // (a key change's save conflicting: just the newer version; a queued change of it meets it on its own)
        // locked meanwhile (no keys for the copy): ours stays queued and meets the conflict again once unlocked
        if (!rekey && this._keys) {
          outbox = outbox.filter((o) => o.id !== sent.id);
          const copy = this._conflictCopy(queued || sent);
          if (copy) {
            outbox = [...outbox, copy];
            this._notice('conflict');
          }
        }
      } else if (res.code === 'stale_key') {
        // the vault got a new key: the pull brings it, the next flush encrypts again
        stale = true;
      } else if (!rekey && queued) {
        outbox = outbox.filter((o) => o.id !== sent.id);
        this._notice(res.code === 'limit' ? 'limit' : 'refused');
      }
      s = { ...s, items, outbox };
    }
    this._setState(s);
    this._rebuild();
    this._emit();
    return stale;
  }

  _plainOf(save) {
    const v = this._vault(save.vaultId);
    return v ? this._decryptBlob(v, save.id, save.baseRev + 1, save.keyRev, save.blob) : null;
  }

  _conflictCopy(save) {
    const v = this._vault(save.vaultId);
    const data = this._plainOf(save);
    if (!v || !data) return null;
    try {
      return this._encryptSave(v, vc.newId(), 0, { ...data, title: `${data.title} ${t('vault.conflictSuffix')}`.trim() });
    } catch {
      return null;
    }
  }

  _reencrypt(save, baseRev) {
    const v = this._vault(save.vaultId);
    const data = this._plainOf(save);
    if (!v || !data) return null;
    try {
      return this._encryptSave(v, save.id, baseRev, data);
    } catch {
      return null;
    }
  }

  /** The save of `data` as entry `id` on top of `baseRev`, encrypted with the key a save must use now; null without it. */
  _encryptSave(v, id, baseRev, data) {
    const keyRev = vault.wantedKeyRev(v);
    const key = this._keysOf(v).get(keyRev);
    if (!key) return null;
    const blob = vc.encryptItem(key, { vaultId: v.id, itemId: id, rev: baseRev + 1 }, data);
    return { id, vaultId: v.id, blob, keyRev, baseRev };
  }

  // ── Entries ──────────────────────────────────────────────

  /**
   * Saves an entry (new when `id` is empty) into `vaultId` — another vault
   * than before moves it. Goes to the outbox first (works offline), the
   * server gets it right away when reachable → { id }.
   */
  async save({ id = null, vaultId, data } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    const v = this._vault(vaultId);
    if (!v) throw fail('not_found');
    if (!vault.canWrite(v)) throw fail('read_only');
    const d = vault.normalizeEntry(data);
    if (!d) throw fail('invalid');
    if (id != null && !vault.isId(id)) throw fail('invalid');
    await this._ready;
    const entryId = id || vc.newId();
    const s = this._state;
    const queued = s.outbox.find((o) => o.id === entryId);
    const item = s.items.get(entryId);
    const baseRev = queued ? queued.baseRev : item ? item.rev : 0;
    let save;
    try {
      save = this._encryptSave(v, entryId, baseRev, d);
    } catch (err) {
      throw fail(err && err.code === 'too_large' ? 'too_large' : 'invalid');
    }
    if (!save) throw fail('locked');
    this._setState(vault.queueSave(this._state, save));
    this._rebuild();
    this._emit();
    this.syncSoon();
    return { id: entryId };
  }

  /** Several new entries at once (import): one outbox, sent in batches → number queued. */
  async saveMany(vaultId, list) {
    await this._ensureLoaded();
    this._needKeys();
    const v = this._vault(vaultId);
    if (!v) throw fail('not_found');
    if (!vault.canWrite(v)) throw fail('read_only');
    await this._ready;
    // new ids each: appended in one go (queueSave per entry scans the outbox — quadratic for a big import)
    const saves = [];
    for (const raw of Array.isArray(list) ? list : []) {
      const d = vault.normalizeEntry(raw);
      if (!d) continue;
      let save = null;
      try { save = this._encryptSave(v, vc.newId(), 0, d); } catch { /* too large: left out */ }
      if (save) saves.push(save);
    }
    const n = saves.length;
    this._setState({ ...this._state, outbox: [...this._state.outbox, ...saves] });
    this._rebuild();
    this._emit();
    this.syncSoon();
    return n;
  }

  async _itemCall(method, p) {
    const item = vault.parseItem((await this._req(method, p, method === 'POST' ? { body: {} } : {})).item);
    if (!item) throw fail('invalid_answer');
    const s = this._state;
    const items = new Map(s.items);
    if (item.state === 'purged') items.delete(item.id);
    else items.set(item.id, item);
    this._setState({ ...s, items, outbox: item.state === 'purged' ? s.outbox.filter((o) => o.id !== item.id) : s.outbox });
    this._rebuild();
    this._emit();
    return item;
  }

  /** Into the trash (needs the server). */
  async trash(id) {
    await this._ensureLoaded();
    this._needKeys();
    await this._itemCall('POST', `items/${this._seg(id)}/trash`);
  }

  /** Out of the trash (needs the server). */
  async restore(id) {
    await this._ensureLoaded();
    this._needKeys();
    await this._itemCall('POST', `items/${this._seg(id)}/restore`);
  }

  /** Deleted for good, also from the trash (needs the server). */
  async purge(id) {
    await this._ensureLoaded();
    this._needKeys();
    try {
      await this._itemCall('DELETE', `items/${this._seg(id)}`);
    } catch (err) {
      if (!(err && err.code === 'not_found')) throw err;
      const s = this._state;
      const items = new Map(s.items);
      items.delete(id);
      this._setState({ ...s, items, outbox: s.outbox.filter((o) => o.id !== id) });
      this._rebuild();
      this._emit();
    }
  }

  /** The earlier versions an entry still has (≤ 10), decrypted → [{ rev, updatedAt, updatedBy, device, data }]. */
  async history(id) {
    await this._ensureLoaded();
    this._needKeys();
    const item = this._state.items.get(id);
    const v = item ? this._vault(item.vaultId) : null;
    if (!item || !v) throw fail('not_found');
    const list = vault.parseHistory(await this._req('GET', `items/${this._seg(id)}/history`));
    if (!list) throw fail('invalid_answer');
    const out = [];
    for (const h of list) {
      const data = this._decryptBlob(v, id, h.rev, h.keyRev, h.blob);
      if (data) out.push({ rev: h.rev, updatedAt: h.updatedAt, updatedBy: h.updatedBy, device: h.device, data });
    }
    return out;
  }

  // ── Vaults and members ───────────────────────────────────

  _applyVault(v) {
    const s = this._state;
    const vaults = s.vaults.some((x) => x.id === v.id) ? s.vaults.map((x) => (x.id === v.id ? v : x)) : [...s.vaults, v];
    this._setState({ ...s, vaults });
    this._rebuild();
    this._emit();
    const x = this._views.find((y) => y.vault.id === v.id);
    return x ? this._vaultView(x) : null;
  }

  _dropVault(vaultId) {
    const s = this._state;
    const items = new Map([...s.items].filter(([, it]) => it.vaultId !== vaultId));
    this._setState({ ...s, vaults: s.vaults.filter((v) => v.id !== vaultId), items, outbox: s.outbox.filter((o) => o.vaultId !== vaultId) });
    const m = this._vaultKeys.get(vaultId);
    if (m) for (const k of m.values()) vc.wipe(k);
    this._vaultKeys.delete(vaultId);
    this._rebuild();
    this._emit();
  }

  _name(name) {
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 200) throw fail('invalid');
    return name.trim();
  }

  /** A new shared vault ("Familie", "Team"); the creator manages it → view. */
  async createVault(name) {
    await this._ensureLoaded();
    const keys = this._needKeys();
    const n = this._name(name);
    await this._ready;
    const id = vc.newId();
    const key = vc.newVaultKey();
    try {
      const v = vault.parseVault((await this._req('POST', 'vaults', { body: { id, nameEnc: vc.encryptName(key, id, n), sealedKey: vc.sealKey(key, keys.publicKey) } })).vault);
      if (!v) throw fail('invalid_answer');
      if (this._keys === keys) this._putKey(id, v.keyRev, key);
      return this._applyVault(v);
    } finally {
      vc.wipe(key);
    }
  }

  async renameVault(vaultId, name) {
    await this._ensureLoaded();
    this._needKeys();
    const n = this._name(name);
    const v = this._vault(vaultId);
    if (!v) throw fail('not_found');
    const key = this._keysOf(v).get(v.keyRev);
    if (!key) throw fail('locked');
    const nv = vault.parseVault((await this._req('PUT', `vaults/${this._seg(vaultId)}`, { body: { nameEnc: vc.encryptName(key, vaultId, n) } })).vault);
    if (!nv) throw fail('invalid_answer');
    return this._applyVault(nv);
  }

  async deleteVault(vaultId) {
    await this._ensureLoaded();
    this._needKeys();
    const v = this._vault(vaultId);
    if (!v) throw fail('not_found');
    if (v.kind === 'personal') throw fail('forbidden');
    await this._req('DELETE', `vaults/${this._seg(vaultId)}`);
    this._dropVault(vaultId);
  }

  /** Everyone one could share with → [{ id, name, hasVault, safetyNumber }] (compare the number with them). */
  async people() {
    await this._ensureLoaded();
    this._needKeys();
    await this._ready;
    const list = vault.parsePeople(await this._req('GET', 'people'));
    if (!list) throw fail('invalid_answer');
    this._people = new Map(list.map((p) => [p.id, p]));
    return list.map((p) => {
      let safetyNumber = null;
      if (p.publicKey) { try { safetyNumber = vc.safetyNumber(p.publicKey); } catch { /* damaged key */ } }
      return { id: p.id, name: p.name, hasVault: !!(p.publicKey && safetyNumber), safetyNumber };
    });
  }

  async _person(userId) {
    if (!Number.isSafeInteger(userId) || userId <= 0) throw fail('invalid');
    if (!this._people.has(userId)) await this.people();
    const p = this._people.get(userId);
    if (!p) throw fail('not_found');
    if (!p.publicKey) throw fail('no_account');
    return p;
  }

  /** Adds a person: the vault key sealed to their public key (from the last people()) → view. */
  async addMember(vaultId, userId, role) {
    await this._ensureLoaded();
    this._needKeys();
    if (!vault.ROLES.includes(role)) throw fail('invalid');
    const v = this._vault(vaultId);
    if (!v) throw fail('not_found');
    const person = await this._person(userId);
    const key = this._keysOf(v).get(v.keyRev);
    if (!key) throw fail('locked');
    let sealedKey;
    try { sealedKey = vc.sealKey(key, person.publicKey); } catch { throw fail('invalid'); }
    const nv = vault.parseVault((await this._req('POST', `vaults/${this._seg(vaultId)}/members`, { body: { userId, role, sealedKey } })).vault);
    if (!nv) throw fail('invalid_answer');
    return this._applyVault(nv);
  }

  async setRole(vaultId, userId, role) {
    await this._ensureLoaded();
    this._needKeys();
    if (!vault.ROLES.includes(role) || !Number.isSafeInteger(userId) || userId <= 0) throw fail('invalid');
    const nv = vault.parseVault((await this._req('PUT', `vaults/${this._seg(vaultId)}/members/${userId}`, { body: { role } })).vault);
    if (!nv) throw fail('invalid_answer');
    return this._applyVault(nv);
  }

  /** Removes someone (or leaves, with one's own id) → view, or null after leaving. A manager's app then changes the key. */
  async removeMember(vaultId, userId) {
    await this._ensureLoaded();
    this._needKeys();
    if (!Number.isSafeInteger(userId) || userId <= 0) throw fail('invalid');
    const r = await this._req('DELETE', `vaults/${this._seg(vaultId)}/members/${userId}`);
    const nv = r.vault ? vault.parseVault(r.vault) : null;
    let view = null;
    if (!nv || userId === this._myUserId()) this._dropVault(vaultId);
    else view = this._applyVault(nv);
    this.syncSoon();
    return view;
  }

  // ── Key change (README › Schlüsselwechsel) ───────────────

  async _runRekeys() {
    for (const v of this._state.vaults) {
      if (!vault.canManage(v) || v.kind === 'personal' || (!v.needsRekey && !v.pending)) continue;
      try {
        await this._exclusive(() => this._rekey(v.id));
      } catch (err) {
        this.log.warn(`Vault: key change failed (${(err && err.code) || (err && err.message)})`);
      }
    }
  }

  /**
   * Gives a vault a new key: start (sealed to exactly the current members) →
   * every entry encrypted again with it (batches ≤ 48 KB / ≤ 100) → finish.
   * Resumes an interrupted change (the new key is in `pending`).
   */
  async _rekey(vaultId) {
    const keys = this._keys;
    let v = this._vault(vaultId);
    if (!keys || !v) return false;
    // lock() zeroes the keys this run holds (newKey too): after any await, stop unless still the same unlock
    const alive = () => this._keys === keys;
    let newRev;
    if (v.pending && this._keysOf(v).has(v.pending.keyRev)) {
      newRev = v.pending.keyRev;
    } else {
      const people = vault.parsePeople(await this._req('GET', 'people'));
      const me = this._myUserId();
      if (!people || me == null || !alive()) return false;
      const pks = new Map(people.map((p) => [p.id, p.publicKey]));
      const key = vc.newVaultKey();
      try {
        const sealed = [];
        for (const m of v.members) {
          const pk = m.userId === me ? keys.publicKey : pks.get(m.userId);
          if (!pk) return false;
          sealed.push({ userId: m.userId, sealedKey: vc.sealKey(key, pk) });
        }
        newRev = v.keyRev + 1;
        const nv = vault.parseVault((await this._req('POST', `vaults/${this._seg(vaultId)}/rekey/start`, { body: { keyRev: newRev, keys: sealed } })).vault);
        if (!nv) throw fail('invalid_answer');
        if (!alive()) return false;
        this._putKey(vaultId, newRev, key);
        this._applyVault(nv);
        v = nv;
      } finally {
        vc.wipe(key);
      }
    }
    const newKey = this._keysOf(v).get(newRev);
    if (!newKey) return false;
    for (let round = 0; round < 10; round++) {
      if (!alive()) return false;
      const left = [...this._state.items.values()].filter((it) => it.vaultId === vaultId && it.state !== 'purged' && it.keyRev !== newRev);
      if (!left.length) break;
      const old = this._keysOf(v);
      const saves = [];
      for (const it of left) {
        const key = old.get(it.keyRev);
        if (!key || !it.blob) continue;
        let obj;
        try { obj = vc.decryptItem(key, it); } catch { continue; }
        // the JSON as it is (unknown types and keys too), bound to the next revision
        const blob = vc.encryptItemBytes(newKey, { vaultId, itemId: it.id, rev: it.rev + 1 }, new Uint8Array(Buffer.from(JSON.stringify(obj), 'utf8')));
        saves.push({ id: it.id, vaultId, blob, keyRev: newRev, baseRev: it.rev });
      }
      if (!saves.length) break;
      for (const batch of vault.batches(saves)) {
        const results = vault.parseSaveResults(await this._req('POST', 'items', { body: { items: batch, device: this.deviceName } }));
        if (!results) throw fail('invalid_answer');
        this._applyResults(batch, results, { rekey: true });
        if (!alive()) return false;
      }
      // conflicts brought newer versions: fetch them and go again
      if (!(await this._pull(null, this._state.seq))) return false;
      v = this._vault(vaultId) || v;
    }
    const cur = alive() ? this._keysOf(v).get(v.keyRev) : null;
    if (!cur) return false;
    let name;
    try { name = vc.decryptName(cur, vaultId, v.nameEnc); } catch { return false; }
    const done = vault.parseVault((await this._req('POST', `vaults/${this._seg(vaultId)}/rekey/finish`, { body: { nameEnc: vc.encryptName(newKey, vaultId, name) } })).vault);
    if (!done) throw fail('invalid_answer');
    this._applyVault(done);
    return true;
  }

  // ── Emergency access (README › Notfallzugriff) ───────────

  /** { granted: [Emergency] (I gave), received: [Emergency] (I got) } */
  async emergency() {
    await this._ensureLoaded();
    const r = vault.parseEmergencyList(await this._req('GET', 'emergency'));
    if (!r) throw fail('invalid_answer');
    return r;
  }

  /** Names a trusted person: the user key sealed to them, released after waitHours (1–720) → Emergency. */
  async emergencyAdd(userId, waitHours) {
    await this._ensureLoaded();
    const keys = this._needKeys();
    if (!Number.isSafeInteger(waitHours) || waitHours < 1 || waitHours > 720) throw fail('invalid');
    const person = await this._person(userId);
    let sealedKey;
    try { sealedKey = vc.sealForEmergency(keys, person.publicKey); } catch { throw fail('invalid'); }
    const e = vault.parseEmergency((await this._req('POST', 'emergency', { body: { granteeId: userId, waitHours, sealedKey } })).emergency);
    if (!e) throw fail('invalid_answer');
    return e;
  }

  /** The grantor withdraws it, or the trusted person declines it. */
  async emergencyRemove(id) {
    await this._ensureLoaded();
    if (typeof id !== 'string' || !vault.EMERGENCY_ID_RE.test(id)) throw fail('invalid');
    await this._req('DELETE', `emergency/${id}`);
    this._emergency.delete(id);
  }

  /** request (trusted person), deny / approve (grantor) → Emergency. */
  async emergencyStep(id, step) {
    await this._ensureLoaded();
    if (typeof id !== 'string' || !vault.EMERGENCY_ID_RE.test(id) || !vault.EMERGENCY_STEPS.includes(step)) throw fail('invalid');
    // approving hands out read access to every vault: only while unlocked
    if (step === 'approve') this._needKeys();
    const e = vault.parseEmergency((await this._req('POST', `emergency/${id}/${step}`, { body: {} })).emergency);
    if (!e) throw fail('invalid_answer');
    return e;
  }

  /**
   * What a trusted person sees after the release: the grantor's vaults and
   * entries, read-only → { grantor: { id, name }, vaults: [{ id, kind, name }], entries: [summary] }.
   * The decrypted entries stay in memory (entry / copy / totp with emergencyId) until lock.
   */
  async emergencyOpen(id) {
    await this._ensureLoaded();
    const mine = this._needKeys();
    if (typeof id !== 'string' || !vault.EMERGENCY_ID_RE.test(id)) throw fail('invalid');
    await this._ready;
    const access = vault.parseAccess(await this._req('GET', `emergency/${id}/access`));
    if (!access) throw fail('invalid_answer');
    let grantor;
    try { grantor = vc.openEmergency(access, mine); } catch { throw fail('decrypt'); }
    const keysByVault = new Map();
    try {
      for (const v of access.vaults) {
        const m = new Map();
        try { m.set(v.keyRev, vc.openSealed(v.sealedKey, grantor.publicKey, grantor.secretKey)); } catch { /* skip */ }
        if (v.pending && v.pending.sealedKey) { try { m.set(v.pending.keyRev, vc.openSealed(v.pending.sealedKey, grantor.publicKey, grantor.secretKey)); } catch { /* skip */ } }
        keysByVault.set(v.id, m);
      }
      const vaults = [];
      for (const v of access.vaults) {
        const k = keysByVault.get(v.id).get(v.keyRev);
        if (!k) continue;
        let name = null;
        try { name = vc.decryptName(k, v.id, v.nameEnc); } catch { /* … */ }
        vaults.push({ id: v.id, kind: v.kind, name });
      }
      const entries = [];
      let since = 0;
      for (let guard = 0; guard < 100; guard++) {
        const page = vault.parseItemsPage(await this._req('GET', `emergency/${id}/items`, { params: { since, limit: vault.SYNC_LIMIT } }));
        if (!page) throw fail('invalid_answer');
        for (const it of page.items) {
          const k = keysByVault.has(it.vaultId) ? keysByVault.get(it.vaultId).get(it.keyRev) : null;
          if (!k || !it.blob) continue;
          let data = null;
          try { data = vault.normalizeEntry(vc.decryptItem(k, it)); } catch { /* unreadable */ }
          if (!data) continue;
          entries.push({ id: it.id, vaultId: it.vaultId, rev: it.rev, trashed: it.state === 'trash', trashedAt: it.trashedAt, updatedAt: it.updatedAt, updatedBy: it.updatedBy, device: it.device, data });
        }
        if (!page.more) break;
        since = page.next;
      }
      entries.sort((a, b) => a.data.title.localeCompare(b.data.title, 'de', { sensitivity: 'base' }));
      if (!this._keys) throw fail('locked');
      this._emergency.set(id, { grantor: { id: access.grantor.id, name: access.grantor.name }, vaults, entries });
      return { grantor: { id: access.grantor.id, name: access.grantor.name }, vaults, entries: entries.map(vault.entrySummary) };
    } finally {
      for (const m of keysByVault.values()) for (const k of m.values()) vc.wipe(k);
      vc.wipe(grantor);
    }
  }

  // ── Import ───────────────────────────────────────────────

  /**
   * An export of another password manager (text of the file) → preview
   * { source, counts, duplicates, preview: [{ index, type, title, username, host, hasPassword, hasTotp, duplicate }] }.
   * The parsed entries wait in memory for importSave(); duplicates are
   * counted against `vaultId` (or every vault).
   */
  async importParse(text, { vaultId = null } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    const r = vault.parseImport(text);
    if (!r.ok) throw fail(r.code === 'encrypted' ? 'import_encrypted' : 'import_unknown');
    const existing = this._entries.filter((e) => !e.trashed && (!vaultId || e.vaultId === vaultId)).map((e) => e.data);
    const flags = vault.duplicateFlags(r.entries, existing);
    this._importDraft = { source: r.source, entries: r.entries };
    return {
      source: r.source,
      counts: vault.importCounts(r.entries),
      duplicates: flags.filter(Boolean).length,
      preview: r.entries.map((e, index) => ({
        index, type: e.type, title: e.title, username: vault.entryUsername(e), host: e.urls.map(vault.urlHost).find(Boolean) || null,
        hasPassword: !!(e.fields.password), hasTotp: !!(e.fields.totp), duplicate: flags[index],
      })),
    };
  }

  /** The parsed import into `vaultId` (duplicates left out unless skipDuplicates: false) → { saved, skipped }. */
  async importSave(vaultId, { skipDuplicates = true } = {}) {
    await this._ensureLoaded();
    this._needKeys();
    const draft = this._importDraft;
    if (!draft) throw fail('no_import');
    const existing = this._entries.filter((e) => !e.trashed && e.vaultId === vaultId).map((e) => e.data);
    const list = skipDuplicates ? vault.withoutDuplicates(draft.entries, existing).keep : draft.entries;
    const saved = await this.saveMany(vaultId, list);
    this._importDraft = null;
    return { saved, skipped: draft.entries.length - saved };
  }

  // ── Generator, 2FA codes, clipboard ──────────────────────

  /** A new password → { password, strength, bits }. */
  generate(opts = {}) {
    const password = vault.generatePassword(opts);
    return { password, strength: vault.passwordStrength(password), bits: Math.round(vault.passwordBits(password)) };
  }

  /** { strength, bits, good (fit as master password), words } */
  strength(password) {
    return {
      strength: vault.passwordStrength(password),
      bits: Math.round(vault.passwordBits(password)),
      good: vault.goodMasterPassword(password),
      words: vault.wordCount(password),
    };
  }

  /** The current 2FA code of an entry ({ id, emergencyId? }) or of an otpauth URI / secret ({ uri }) → { code, secondsLeft, period, digits }. */
  async totp({ id = null, emergencyId = null, uri = null } = {}) {
    let text = typeof uri === 'string' ? uri : '';
    if (id) {
      await this._ensureLoaded();
      text = this._find(id, emergencyId).data.fields.totp || '';
    }
    const p = vault.parseTotp(text);
    if (!p) throw fail(text ? 'invalid' : 'empty');
    return vault.totpCode(p, this.now());
  }

  /**
   * Wi-Fi networks nearby, for a Wi-Fi entry ("WLAN in der Nähe suchen"; Windows Native Wifi API,
   * services/wifi-scan.js) → { networks: [{ ssid, security, signal, connected }] }. Only while unlocked.
   * Codes: `no_adapter`, `service_off`, `radio_off`, `location_denied` (Windows' location access is off),
   * `failed`.
   */
  async wifiScan() {
    this._needKeys();
    const scan = this._wifiScan || require('./wifi-scan').scanWifi;
    try {
      return { networks: await scan({ log: this.log }) };
    } catch (err) {
      const code = err && WIFI_CODES.includes(err.code) ? err.code : 'failed';
      this.log.info(`Vault: Wi-Fi scan: ${code}${err && err.win32 != null ? ` (Windows error ${err.win32})` : ''}`);
      throw fail(code);
    }
  }

  /**
   * 2FA keys from a QR code for the entry editor ("QR-Code scannen", services/totp-qr.js):
   * { source: 'screen' | 'clipboard' | 'file', getWindow? } → { uris: ['otpauth://totp/…'] } (at least one;
   * otpauth-migration exports become one URI per TOTP account). Only while unlocked; one scan at a time
   * (a second call waits for the first). The URIs are never logged.
   * Codes: `none_found`, `hotp`, `invalid_code`, `no_image`, `unsupported`, `cancelled`, `failed`.
   */
  async totpQr({ source, getWindow = null } = {}) {
    this._needKeys();
    if (!QR_SOURCES.includes(source)) throw fail('invalid');
    const scan = this._totpQr || require('./totp-qr').scanTotpQr;
    const prev = this._qrRun || Promise.resolve();
    const run = prev.catch(() => {}).then(async () => {
      this._needKeys();
      try {
        const uris = await scan({ source, getWindow, log: this.log });
        this._needKeys();   // locked meanwhile (auto-lock): the keys found stay here
        if (!Array.isArray(uris) || !uris.length) throw Object.assign(new Error('none_found'), { code: 'none_found' });
        this.log.info(`Vault: QR scan (${source}): ${uris.length} 2FA code(s)`);
        return { uris: uris.slice() };
      } catch (err) {
        if (err && err.code === 'locked') throw err;
        const code = err && QR_CODES.includes(err.code) ? err.code : 'failed';
        this.log.info(`Vault: QR scan (${source}): ${code}${code === 'failed' && err && err.name ? ` (${err.name})` : ''}`);
        throw fail(code);
      }
    });
    this._qrRun = run;
    try {
      return await run;
    } finally {
      if (this._qrRun === run) this._qrRun = null;
    }
  }

  /**
   * Copies a value to the clipboard and clears it after 30 s when it is still
   * there: { id, field, emergencyId? } (field: username, password, totp, notes,
   * url, custom:<n>, any key of fields) or { text } (e.g. a generated password).
   */
  async copy({ id = null, field = null, emergencyId = null, text = null } = {}) {
    if (!this.clipboard || typeof this.clipboard.writeText !== 'function') throw fail('unsupported');
    let value = typeof text === 'string' ? text : '';
    if (id) {
      await this._ensureLoaded();
      value = vault.entryValue(this._find(id, emergencyId).data, field, this.now());
    }
    if (!value) throw fail('empty');
    await this.clipboard.writeText(value);   // Electron ≥ 44: a Promise
    if (this._copied) clearTimeout(this._copied.timer);
    const timer = setTimeout(() => {
      if (this._copied && this._copied.timer === timer) this._clearClipboard();
    }, this.timing.clipboardMs);
    if (timer.unref) timer.unref();
    this._copied = { timer, value };
    return { clearsInMs: this.timing.clipboardMs };
  }

  /**
   * Clears the clipboard when it still holds what copy() put there. readText() is asynchronous since
   * Electron 44 (a Promise), synchronous before: a synchronous one clears at once. → Promise (tests).
   */
  _clearClipboard() {
    const copied = this._copied;
    if (!copied) return Promise.resolve();
    clearTimeout(copied.timer);
    this._copied = null;
    const cb = this.clipboard;
    const clear = (current) => {
      if (current !== copied.value) return;
      if (typeof cb.clear === 'function') cb.clear();
      else cb.writeText('');
    };
    try {
      const current = typeof cb.readText === 'function' ? cb.readText() : copied.value;
      if (current && typeof current.then === 'function') return Promise.resolve(current).then(clear).catch(() => { /* clipboard busy */ });
      clear(current);
    } catch { /* clipboard busy */ }
    return Promise.resolve();
  }

  // ── Push ─────────────────────────────────────────────────

  _onPush(entry) {
    const ctx = vault.pushContext(entry);
    if (!ctx) return;
    // a vault shared just now, an emergency request: fetch
    if (this._state.account) this.syncSoon();
    this.emit('push', { ...ctx, notificationId: entry && Number.isSafeInteger(entry.id) ? entry.id : null });
  }

  /** Context for a click on a Vault toast while the page exists, else null (the inbox opens). */
  clickContext(entry) {
    if (!this.available()) return null;
    return vault.pushContext(entry);
  }
}

/**
 * opts.protect from Electron's safeStorage (Windows: DPAPI, bound to the
 * Windows user): VaultService.safeStorageProtect(require('electron').safeStorage).
 */
VaultService.safeStorageProtect = function safeStorageProtect(safeStorage) {
  return {
    available: () => !!(safeStorage && safeStorage.isEncryptionAvailable()),
    encrypt: (buf) => safeStorage.encryptString(Buffer.from(buf).toString('base64')),
    decrypt: (buf) => Buffer.from(safeStorage.decryptString(Buffer.from(buf)), 'base64'),
  };
};

VaultService.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = VaultService;
