'use strict';

/**
 * GateControl – "Ordner sichern" (Core service, Drive's folder backup / sync)
 *
 * Folders of this PC in Drive (plugin `gatecontrol-drive`), in the main
 * process of the Windows Pro app — also while the window is closed (tray):
 *
 * - "Nur sichern" (mode 'backup'): one way, PC → Drive, into
 *   Meine Dateien › Geräte › <PC> › <folder>. The folder stays complete on the
 *   PC. A file deleted on the PC stays in Drive for 30 days, then goes into
 *   Drive's trash: Drive 1.5 ('deleteAfter') keeps the time itself
 *   (DELETE nodes/<id>?after=2592000&device=<id>, the node gets `deleteAt`;
 *   a file that is back on the PC calls it off: PATCH { deleteAt: null } or a
 *   new version); older Drives: the folder's state keeps the list ("pending")
 *   and the PC moves the files into the trash after 30 days. A list kept by
 *   an older version goes to Drive on the first run with the time left. What
 *   changes in Drive is never written back to the PC.
 * - "Abgleichen" (mode 'sync'): both ways with a Drive folder the person
 *   picked (writable); every file complete on each device. Drive's changes
 *   come from its change log (GET changes?since=, live event `changed` of the
 *   push stream, else every 5 min). A conflict (both sides changed, or the
 *   commit's `baseRev` is old → 409) keeps the PC's bytes as
 *   "Name (Konflikt <PC> <Datum>).ext" next to it — nothing is lost. Moves and
 *   renames that are sure (utils/drive-sync.js planMoves) are moves on the
 *   other side; files deleted on one side go to Windows' recycle bin /
 *   Drive's trash.
 * - Watching: fs.watch (recursive) per folder → a run 3 s after the last
 *   change; a full run at start and every 15 minutes. Files that are still
 *   being written (changed in the last 2 s) wait for the next run.
 * - Vault folders (Drive 1.9 'vault', end-to-end encrypted on the devices):
 *   never part of "Ordner sichern" — nodes with `encrypted: true` are left out
 *   of Drive's tree (their names are opaque, their contents ciphertext), a
 *   folder of the PC is never uploaded into one, and a vault folder cannot be
 *   the Drive folder of "Abgleichen" ('encrypted').
 * - Left out: temporary files (~$*, *.tmp, Thumbs.db, desktop.ini,
 *   .DS_Store), node_modules and .git (switch, on by default), files over a
 *   size (10 GB by default), empty files on Drives before 1.5 (the media upload
 *   takes no empty body; Drive 1.5 'emptyFiles': they go up as `size: 0`
 *   without media and come down as empty files) and names Drive does not take.
 *   A folder that lies in Drive itself (`blockedPaths`: the folder
 *   "GateControl Drive" of the Pro app's files on demand) is not taken (`in_drive`).
 * - Guard: deleting more than 500 files at once, or more than 20 % of a
 *   folder (at least 10 files), waits for the person ("Löschen übertragen" /
 *   "Wiederherstellen").
 * - Ransomware (utils/drive-guard.js): many existing files changed into
 *   high-entropy content, or renamed to a ransomware extension (≥ 50, or ≥ 20 %
 *   of a folder with ≥ 20 files): nothing goes up, the folder waits for the
 *   person ("Hochladen" / "Pausiert lassen"). Every commit carries the entropy
 *   of the first 64 KB (Drive 1.6 'guard'). Drive itself can stop this device
 *   (423 `device_locked`, the live event `guard`, me.guard): every folder stops
 *   at once ("Von Drive gestoppt") until the person decides on the page; after
 *   "Rückgängig machen" the files of each folder come back from Drive – a PC
 *   file that differs stays next to it as a conflict copy that is not
 *   uploaded (with files new on the PC since then: "zurückgehalten").
 * - PDFs with a text layer: their text goes with the commit (search);
 *   pictures and videos carry when they were taken (Drive 1.7 'takenAt').
 * - Time travel (Drive 1.7 'timeTravel', DriveService event 'timetravel'):
 *   every folder of this PC whose Drive folder is the folder sent back in
 *   time, lies in it or holds it runs at once.
 *   "Abgleichen": what the time travel changed comes to the PC as any change
 *   in Drive – a PC file changed since the last run is kept as a conflict
 *   copy next to the file from Drive; files the time travel moved into the
 *   trash go into the recycle bin (only while unchanged on the PC, the
 *   mass-delete question is not asked for this one run).
 *   "Nur sichern": the PC is never written. Drive stays the backup of the PC:
 *   the next run uploads the PC's file again where Drive now has another one
 *   (the time travel's file stays as an older version), files it moved into
 *   the trash that the PC still has go up again; files it brought back that
 *   the PC does not have stay in Drive (like anything only in Drive).
 * - Control: pause all / a folder, upload / download limit (KB/s, shared by
 *   every transfer of a direction), "nur im Heimnetz" (networks marked as
 *   home: utils/drive-sync.js localNetworks + fingerprints), "nur mit VPN".
 *   A run needs Drive to be available (DriveService.status()); network
 *   failures wait and try again (1 min … 15 min).
 * - The device: the plugin knows it by the app's device token (me.deviceId,
 *   kept for the page); its name in Drive is the folder Geräte › <PC> (the
 *   host name when the first folder is added); the page also shows the PC's
 *   stable short id (getDeviceKey). Drive 1.5 ('devices' in me.features):
 *   the PC registers itself (PUT devices/<id>, id 'pc-' + the short id, kept
 *   in the settings) and gets its own folder Meine Dateien › Geräte › <Name>
 *   (unique per person: a second "PC" is "PC (2)"); "Nur sichern" goes below
 *   it, and the folder list goes to Drive (PUT devices/<id>/folders) for the
 *   portal page "Geräte". Older Drives: the folder Geräte › <PC> by name.
 *
 * Stored: the folder list and the settings in the electron-store key
 * `driveSync` (no tokens), the state of each folder (the last agreed files
 * with size / time / SHA-256 / node / rev, Drive's tree below the folder,
 * the change-log cursor, pending deletes) in <dir>/<folder id>.json (written
 * to a temporary file, then renamed). A broken state file starts the folder
 * fresh: everything is compared by content, nothing is deleted.
 *
 * Events: 'change' (status()).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const DriveApi = require('./drive-api');
const MessengerApi = require('./messenger-api');
const drive = require('../utils/drive');
const S = require('../utils/drive-sync');
const G = require('../utils/drive-guard');
const { pdfText, isPdf } = require('../utils/pdf-text');
const { takenAt: readTakenAt, isMediaName } = require('../utils/taken-at');
const { createLimiter } = require('../utils/throttle');
const { guessMime } = require('../utils/gatedrop');

const { MessengerError: DriveError } = MessengerApi;

const STORE_KEY = 'driveSync';
const DAY = 24 * 60 * 60 * 1000;
const DEFAULT_TIMING = {
  startMs: 15000,             // first run after start (the tunnel and the plugin check first)
  fullMs: 15 * 60 * 1000,     // full run of every folder
  pollMs: 5 * 60 * 1000,      // Drive's change log of "Abgleichen" folders without a live event
  watchMs: 3000,              // a run after the last change on disk
  liveMs: 2000,               // a run after Drive's live event
  settleMs: 2000,             // files changed in the last 2 s are still being written
  retryMinMs: 60 * 1000,
  retryMaxMs: 15 * 60 * 1000,
  emitMs: 250,
  saveEvery: 200,             // the state file is written every 200 actions (and at the end)
  watch: true,
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const isNetwork = (err) => !!err && (err.code === 'network' || err.code === 'timeout' || err.code === 'not_configured' || err.code === 'offline'
  || err.status === 502 || err.status === 503 || err.status === 504 || err.status === 429);
// Drive 1.6 'guard': Drive stopped this device – the run ends at once
const isLocked = (err) => !!err && err.status === 423 && err.code === 'device_locked';

class SyncStop extends Error {}

class DriveSync extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.drive - DriveService (status(), 'state' events, its api)
   * @param {object} [opts.api] - DriveApi (default: drive.api)
   * @param {object} opts.store - electron-store
   * @param {string} opts.dir - folder of the state files (%APPDATA%\…\drive-sync)
   * @param {object} [opts.log]
   * @param {(p: string) => Promise<void>} [opts.trashItem] - into the recycle bin (Electron shell.trashItem)
   * @param {object} [opts.dialog] - Electron dialog (pick a folder)
   * @param {object} [opts.shell] - Electron shell (open a folder)
   * @param {Function} [opts.getMainWindow]
   * @param {() => string} [opts.hostname]
   * @param {() => object} [opts.getInterfaces] - os.networkInterfaces
   * @param {() => object} [opts.getGateways] - { '<net>/<prefix>': '<gateway mac>' } (optional)
   * @param {() => boolean} [opts.isVpnUp]
   * @param {() => string|null} [opts.getDeviceKey] - the PC's stable short id (Pro: first 8 hex of the machine fingerprint)
   * @param {() => Array<{ key: string, path: string }>} [opts.knownFolders] - Desktop, Dokumente, Bilder …
   * @param {() => string[]} [opts.blockedPaths] - folders that cannot be added (Pro: the folder
   *   "GateControl Drive" of "Dateien bei Bedarf" – it is Drive itself)
   * @param {string} [opts.appVersion] - sent with the device (Drive 1.5 'devices')
   * @param {object} [opts.pushClient] - live events of the plugin (changed)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   * @param {(file: string, o: object) => Promise<string|null>} [opts.readPdfText] - text layer of a PDF (tests)
   */
  constructor({
    drive: driveSvc, api = null, store, dir, log, trashItem = null, dialog = null, shell = null, getMainWindow = null,
    hostname = () => os.hostname(), getInterfaces = () => os.networkInterfaces(), getGateways = null, isVpnUp = null, getDeviceKey = null,
    knownFolders = null, blockedPaths = null, appVersion = '', pushClient = null, timing = {}, now = Date.now, readPdfText = null,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.readPdfText = typeof readPdfText === 'function' ? readPdfText : (file, o) => pdfText(file, { ...o, log: this.log });
    this._guard = null;            // Drive 1.6: { locked, incident } – Drive stopped this device
    this.driveSvc = driveSvc || null;
    this.api = api || (driveSvc && driveSvc.api) || new DriveApi({ log: this.log });
    this.store = store;
    this.dir = dir;
    this.trashItem = typeof trashItem === 'function' ? trashItem : (p) => fs.promises.rm(p, { recursive: true, force: true });
    this.dialog = dialog;
    this.shell = shell;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.hostname = hostname;
    this.getInterfaces = getInterfaces;
    this.getGateways = typeof getGateways === 'function' ? getGateways : () => ({});
    this.isVpnUp = typeof isVpnUp === 'function' ? isVpnUp : () => true;
    this.getDeviceKey = typeof getDeviceKey === 'function' ? getDeviceKey : () => null;
    this.knownFolders = typeof knownFolders === 'function' ? knownFolders : () => [];
    this.blockedPaths = typeof blockedPaths === 'function' ? blockedPaths : () => [];
    this.appVersion = typeof appVersion === 'string' ? appVersion.slice(0, 40) : '';
    this._devReg = null;           // Drive 1.5: { device, at } of the last PUT devices/<id>
    this._devReport = { key: '', at: 0 };
    this.pushClient = pushClient;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;

    this._cfg = S.normalizeConfig(null);
    this._rt = new Map();          // folder id → runtime status
    this._states = new Map();      // folder id → loaded state
    this._watchers = new Map();
    this._debounce = new Map();
    this._queue = new Map();       // folder id → { full, remote }
    this._running = null;          // folder id of the run
    this._pumping = false;
    this._started = false;
    this._timers = [];
    this._retryTimer = null;
    this._retry = 0;
    this._unsub = [];
    this._emitTimer = null;
    this._lastEmit = 0;
    this._device = { id: null };
    this._meAt = 0;
    this._deferrals = new Map();    // `${folder}|${key}` → runs a file waited (still being written)
    this.up = createLimiter(() => this._cfg.settings.upKBs);
    this.down = createLimiter(() => this._cfg.settings.downKBs);
    this._load();
  }

  // ── Config ───────────────────────────────────────────────

  _load() {
    let raw = null;
    try { raw = this.store && this.store.get(STORE_KEY); } catch { raw = null; }
    this._cfg = S.normalizeConfig(raw);
  }

  _save() {
    try { if (this.store) this.store.set(STORE_KEY, this._cfg); } catch (err) { this.log.warn(`Drive sync settings not saved: ${err.message}`); }
  }

  _folder(id) {
    return this._cfg.folders.find((f) => f.id === id) || null;
  }

  _scopeKey() {
    const s = typeof this.api.scope === 'function' ? this.api.scope() : '';
    return crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
  }

  _runtime(id) {
    if (!this._rt.has(id)) {
      // a folder that never ran: "being checked" until its first run ends
      const f = this._folder(id);
      const fresh = !!f && !f.lastSyncAt;
      this._rt.set(id, {
        state: fresh ? 'syncing' : 'idle', reason: fresh ? 'queued' : null, dirty: true, total: 0, done: 0, current: null, failed: 0, failure: null,
        confirm: null, allowDeletes: false, restore: false, files: null, bytes: null, skipped: 0, pendingDeletes: 0, pendingUntil: null,
        conflicts: 0, watching: false, suspect: null, allowSuspect: false, undo: false, held: 0, timeTravel: 0,
      });
    }
    return this._rt.get(id);
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const d = this.driveSvc;
    if (d && typeof d.on === 'function') {
      const onState = (st) => { if (st && st.state === 'available') this.syncAll({ full: true }); else this._emit(); };
      const onGuard = (g) => this._onGuard(g);
      // Drive 1.7: a folder went back in time – the folders of this PC that lie there run now
      const onTimeTravel = (e) => { this.afterTimeTravel(e && e.folderId).catch((err) => this.log.info(`Drive sync after a time travel: ${drive.errorCode(err)}`)); };
      d.on('state', onState);
      d.on('guard', onGuard);
      d.on('timetravel', onTimeTravel);
      this._unsub.push(() => { d.removeListener('state', onState); d.removeListener('guard', onGuard); d.removeListener('timetravel', onTimeTravel); });
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== drive.PLUGIN_ID) return;
        if (ev.data.type !== 'changed') return;
        clearTimeout(this._liveTimer);
        this._liveTimer = setTimeout(() => this._queueSync({ remote: true }), this.timing.liveMs);
        if (this._liveTimer.unref) this._liveTimer.unref();
      };
      const onHello = () => this._queueSync({ remote: true });
      pc.on('event', onEvent);
      pc.on('hello', onHello);
      this._unsub.push(() => { pc.removeListener('event', onEvent); pc.removeListener('hello', onHello); });
    }
    for (const f of this._cfg.folders) this._watch(f);
    const first = setTimeout(() => this.syncAll({ full: true }), this.timing.startMs);
    const full = setInterval(() => this.syncAll({ full: true }), this.timing.fullMs);
    const poll = setInterval(() => this._queueSync({ remote: true }), this.timing.pollMs);
    for (const t of [first, full, poll]) { if (t.unref) t.unref(); this._timers.push(t); }
  }

  stop() {
    this._started = false;
    for (const t of this._timers.splice(0)) { clearTimeout(t); clearInterval(t); }
    clearTimeout(this._retryTimer);
    clearTimeout(this._liveTimer);
    clearTimeout(this._emitTimer);
    for (const t of this._debounce.values()) clearTimeout(t);
    this._debounce.clear();
    for (const id of [...this._watchers.keys()]) this._unwatch(id);
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    this._queue.clear();
  }

  /** server:setup: runs stop; folders of the old server wait ("anderer Server"). */
  resetForNewServer() {
    this._queue.clear();
    this._states.clear();
    this._guard = null;
    for (const rt of this._rt.values()) { rt.confirm = null; rt.allowDeletes = false; rt.restore = false; rt.suspect = null; rt.allowSuspect = false; rt.undo = false; }
    this._device = { id: null };
    this._meAt = 0;
    this._emit(true);
    if (this._started) this.syncAll({ full: true });
    return Promise.resolve(this.status());
  }

  // ── Status ───────────────────────────────────────────────

  /**
   * → { ok, settings, device: { name, id }, network: { home, known }, paused, state, folders: [view], known: [{ key, path, folderId }] }
   * state of the whole: 'idle' | 'syncing' | 'paused' | 'waiting' | 'error' | 'confirm' | 'empty'
   */
  status() {
    const s = this._cfg.settings;
    const folders = this._cfg.folders.map((f) => this._view(f));
    const pick = (st) => folders.some((f) => f.state === st);
    const state = !folders.length ? 'empty' : this._isLocked() ? 'locked' : s.paused ? 'paused' : pick('confirm') ? 'confirm' : pick('syncing') ? 'syncing'
      : pick('error') ? 'error' : pick('waiting') ? 'waiting' : folders.every((f) => f.state === 'paused') ? 'paused' : 'idle';
    const last = folders.reduce((m, f) => Math.max(m, f.lastSyncAt || 0), 0) || null;
    let known = [];
    try { known = (this.knownFolders() || []).filter((k) => k && typeof k.path === 'string' && k.path).slice(0, 10); } catch { known = []; }
    return {
      ok: true,
      settings: { ...s, homeNets: undefined, homeCount: s.homeNets.length },
      device: { name: s.deviceName || S.deviceName(this._host()), id: this._device.id, key: this._deviceKey() },
      network: { home: this._atHome(), known: s.homeNets.length },
      paused: s.paused,
      state,
      // Drive 1.6 'guard': Drive stopped this device ({ locked, incident }) or null
      guard: this._isLocked() ? { locked: true, incident: this._guard.incident || null } : null,
      lastSyncAt: last,
      folders,
      known: known.map((k) => {
        const f = this._cfg.folders.find((x) => x.path.toLowerCase() === k.path.toLowerCase());
        return { key: String(k.key || ''), path: k.path, folderId: f ? f.id : null, mode: f ? f.mode : null };
      }),
    };
  }

  _view(f) {
    const rt = this._runtime(f.id);
    const scopeOk = !f.scope || f.scope === this._scopeKey();
    let state = rt.state;
    let reason = rt.reason;
    if (!scopeOk) { state = 'error'; reason = 'other_server'; } else if (this._isLocked()) { state = 'locked'; reason = 'guard_locked'; } else if (f.paused || this._cfg.settings.paused) { if (state !== 'syncing') { state = 'paused'; reason = this._cfg.settings.paused ? 'all' : 'folder'; } } else if (rt.suspect) { state = 'confirm'; reason = 'suspect'; } else if (rt.confirm) { state = 'confirm'; reason = 'mass_delete'; }
    return {
      id: f.id,
      path: f.path,
      name: path.win32.basename(f.path) || f.path,
      mode: f.mode,
      target: { ...f.target },
      paused: f.paused,
      state,
      reason,
      total: rt.total,
      done: rt.done,
      current: rt.current,
      failed: rt.failed,
      failure: rt.failure,
      confirm: rt.confirm ? { ...rt.confirm } : null,
      // "ungewöhnliche Änderungen": { count, sample, why: 'entropy' | 'extension' }
      suspect: rt.suspect ? { ...rt.suspect, sample: rt.suspect.sample.slice() } : null,
      files: rt.files,
      bytes: rt.bytes,
      skipped: rt.skipped,
      pendingDeletes: rt.pendingDeletes,
      // the first time one of them goes into Drive's trash (ms) or null
      pendingUntil: rt.pendingUntil,
      // files new / differing on the PC after "Rückgängig machen", not uploaded
      held: rt.held,
      conflicts: rt.conflicts,
      watching: rt.watching,
      lastSyncAt: f.lastSyncAt,
    };
  }

  _emit(now = false) {
    const fire = () => {
      this._emitTimer = null;
      this._lastEmit = Date.now();
      this.emit('change', this.status());
    };
    if (now) { clearTimeout(this._emitTimer); fire(); return; }
    if (this._emitTimer) return;
    const wait = Math.max(0, this.timing.emitMs - (Date.now() - this._lastEmit));
    this._emitTimer = setTimeout(fire, wait);
    if (this._emitTimer.unref) this._emitTimer.unref();
  }

  _deviceKey() {
    let k = null;
    try { k = this.getDeviceKey(); } catch { k = null; }
    return typeof k === 'string' && /^[0-9a-f]{4,64}$/.test(k) ? k : null;
  }

  _host() {
    try { return this.hostname(); } catch { return 'PC'; }
  }

  // ── Network ──────────────────────────────────────────────

  _fingerprints() {
    let ifaces = {};
    let gws = {};
    try { ifaces = this.getInterfaces() || {}; } catch { ifaces = {}; }
    try { gws = this.getGateways() || {}; } catch { gws = {}; }
    return S.networkFingerprints(S.localNetworks(ifaces), gws);
  }

  _atHome() {
    const s = this._cfg.settings;
    return s.homeNets.length > 0 && S.atHome(this._fingerprints(), s.homeNets);
  }

  /** "Dieses Netz ist mein Heimnetz" (on) / forget all home networks (off) → status. */
  setHome(on) {
    const s = this._cfg.settings;
    if (on) {
      const now = this._fingerprints();
      if (!now.length) throw new DriveError('no network', { code: 'no_network' });
      s.homeNets = [...new Set([...now, ...s.homeNets])].slice(0, 10);
    } else {
      s.homeNets = [];
      s.homeOnly = false;
    }
    this._save();
    this._emit(true);
    if (on) this.syncAll({ full: false });
    return this.status();
  }

  // ── Settings ─────────────────────────────────────────────

  /** Changes settings: paused, skipDev, maxFileBytes, upKBs, downKBs, homeOnly, vpnOnly → status. */
  setSettings(patch) {
    const p = patch && typeof patch === 'object' ? patch : {};
    const keys = ['paused', 'skipDev', 'maxFileBytes', 'upKBs', 'downKBs', 'homeOnly', 'vpnOnly'];
    const next = { ...this._cfg.settings };
    for (const k of keys) if (Object.prototype.hasOwnProperty.call(p, k)) next[k] = p[k];
    if (next.homeOnly && !next.homeNets.length) throw new DriveError('no home network', { code: 'no_home' });
    const wasPaused = this._cfg.settings.paused;
    this._cfg.settings = S.normalizeSettings(next);
    this._save();
    this._emit(true);
    if (wasPaused && !this._cfg.settings.paused) this.syncAll({ full: true });
    else if (['skipDev', 'maxFileBytes', 'homeOnly', 'vpnOnly'].some((k) => k in p)) this.syncAll({ full: true });
    return this.status();
  }

  // ── Folders ──────────────────────────────────────────────

  /** Folder dialog → { ok, path } | { ok: false, code: 'cancelled' } */
  async pickFolder() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const opts = { properties: ['openDirectory', 'dontAddToRecent'] };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths[0]) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, path: r.filePaths[0] };
  }

  /**
   * Adds a folder → { ok, folder }.
   * @param {{ path: string, mode: 'backup' | 'sync', targetId?: number }} o
   *   targetId: the Drive folder of "Abgleichen" (writable)
   */
  async addFolder({ path: p, mode, targetId = null } = {}) {
    if (!S.MODES.includes(mode)) throw new DriveError('invalid mode', { code: 'invalid' });
    if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p)) throw new DriveError('invalid path', { code: 'invalid' });
    const abs = path.resolve(p);
    let st;
    try { st = await fs.promises.stat(abs); } catch { throw new DriveError('folder not found', { code: 'folder_missing' }); }
    if (!st.isDirectory()) throw new DriveError('not a folder', { code: 'not_a_folder' });
    if (path.parse(abs).root === abs) throw new DriveError('a whole drive', { code: 'drive_root' });
    if (this._cfg.folders.length >= S.MAX_FOLDERS) throw new DriveError('too many folders', { code: 'too_many' });
    if (S.overlaps(abs, this._cfg.folders, path.sep)) throw new DriveError('overlaps a folder', { code: 'overlap' });
    if (this.dir && S.overlaps(abs, [{ path: this.dir }], path.sep)) throw new DriveError('the app folder', { code: 'overlap' });
    let blocked = [];
    try { blocked = (this.blockedPaths() || []).filter((b) => typeof b === 'string' && b); } catch { blocked = []; }
    if (blocked.length && S.overlaps(abs, blocked.map((b) => ({ path: b })), path.sep)) throw new DriveError('lies in Drive itself', { code: 'in_drive' });
    const s = this._cfg.settings;
    if (!s.deviceName) s.deviceName = S.deviceName(this._host());
    const folder = { id: crypto.randomBytes(8).toString('hex'), path: abs, mode, remoteName: null, target: { nodeId: null, areaId: null, label: null }, scope: this._scopeKey(), paused: false, addedAt: this.now(), lastSyncAt: null };
    if (mode === 'sync') {
      const id = drive.posId(targetId);
      if (!id) throw new DriveError('no Drive folder', { code: 'invalid' });
      if (this._cfg.folders.some((f) => f.mode === 'sync' && f.target.nodeId === id && f.scope === folder.scope)) throw new DriveError('Drive folder synced already', { code: 'target_taken' });
      const r = await this.api.folder(id, { limit: 1 });
      if (r.node.encrypted) throw new DriveError('a vault folder', { code: 'encrypted' });
      if (!r.writable) throw new DriveError('read only', { code: 'forbidden' });
      const area = (await this.api.areas().catch(() => ({ areas: [] }))).areas.find((a) => a.id === r.node.areaId);
      const names = r.crumbs.filter((c) => c.id !== r.node.id).map((c) => c.name);
      if (r.node.parentId === null) names.splice(0, names.length, area ? area.label : r.node.name);
      else {
        if (area && names.length) names[0] = area.label;
        names.push(r.node.name);
      }
      folder.target = { nodeId: r.node.id, areaId: r.node.areaId, label: names.join(' › ').slice(0, 600) };
    } else {
      const base = drive.safeName(path.basename(abs)) || 'Ordner';
      const taken = new Set(this._cfg.folders.filter((f) => f.mode === 'backup' && f.remoteName).map((f) => S.keyOf(f.remoteName)));
      folder.remoteName = S.freeName(base, taken);
      folder.target.label = ['Meine Dateien', S.DEVICES_FOLDER, s.deviceName, folder.remoteName].join(' › ');
    }
    const clean = S.normalizeFolder(folder);
    this._cfg.folders.push(clean);
    this._save();
    this._states.set(clean.id, freshState(clean.scope));
    await this._writeState(clean.id).catch((err) => this.log.warn(`Drive sync state not written: ${err.message}`));
    this._watch(clean);
    this._emit(true);
    this.sync(clean.id, { full: true });
    return { ok: true, folder: this._view(clean) };
  }

  /** Stops a folder: nothing is deleted, neither on the PC nor in Drive. */
  async removeFolder(id) {
    const f = this._folder(id);
    if (!f) throw new DriveError('no such folder', { code: 'not_found' });
    // "deletes nothing": deletes Drive keeps the time of (Drive 1.5 'deleteAfter') are called off
    await this._unmarkAll(f).catch((err) => this.log.info(`Drive sync: delayed deletes not called off (${drive.errorCode(err)})`));
    this._unwatch(id);
    this._queue.delete(id);
    this._cfg.folders = this._cfg.folders.filter((x) => x.id !== id);
    this._save();
    this._rt.delete(id);
    this._states.delete(id);
    if (this.dir) await fs.promises.rm(this._statePath(id), { force: true }).catch(() => {});
    this._emit(true);
    this._reportFolders({ force: true });
    return { ok: true };
  }

  /** Pause / go on: one folder (id) or all (id null). */
  setPaused(id, paused) {
    if (id === null || id === undefined) return this.setSettings({ paused: !!paused });
    const f = this._folder(id);
    if (!f) throw new DriveError('no such folder', { code: 'not_found' });
    f.paused = !!paused;
    this._save();
    this._emit(true);
    if (!f.paused) this.sync(f.id, { full: true });
    return this.status();
  }

  /** The answer to "Viele Dateien gelöscht": 'apply' (delete in Drive too) | 'restore' (bring them back). */
  confirmDeletes(id, decision) {
    const f = this._folder(id);
    const rt = f && this._rt.get(id);
    if (!f || !rt || !rt.confirm) throw new DriveError('nothing to confirm', { code: 'not_found' });
    if (decision !== 'apply' && decision !== 'restore') throw new DriveError('invalid decision', { code: 'invalid' });
    rt.confirm = null;
    rt.allowDeletes = decision === 'apply';
    rt.restore = decision === 'restore';
    this._emit(true);
    this.sync(id, { full: true });
    return this.status();
  }

  /**
   * The answer to "ungewöhnliche Änderungen" (many files changed into encrypted-looking content):
   * 'upload' (they are the person's changes: upload them) | 'keep' (the folder stays paused).
   */
  confirmSuspect(id, decision) {
    const f = this._folder(id);
    const rt = f && this._rt.get(id);
    if (!f || !rt || !rt.suspect) throw new DriveError('nothing to confirm', { code: 'not_found' });
    if (decision !== 'upload' && decision !== 'keep') throw new DriveError('invalid decision', { code: 'invalid' });
    rt.suspect = null;
    if (decision === 'keep') {
      f.paused = true;
      rt.allowSuspect = false;
      this._save();
      this._emit(true);
      return this.status();
    }
    rt.allowSuspect = true;
    this._emit(true);
    this.sync(id, { full: true });
    return this.status();
  }

  // ── Guard (Drive 1.6) ────────────────────────────────────

  _isLocked() {
    return !!(this._guard && this._guard.locked);
  }

  /**
   * The guard state of DriveService ('guard' event): locked → every folder stops; free again →
   * every folder runs (after "Rückgängig machen" first bringing the files back from Drive).
   */
  _onGuard(g) {
    if (!g || typeof g !== 'object') return;
    const was = this._isLocked();
    this._guard = g.locked ? { locked: true, incident: g.incident || null } : null;
    if (g.decided === 'undo') {
      for (const f of this._cfg.folders) this._runtime(f.id).undo = true;
      this.log.info('Drive sync: Drive undid the changes of this PC – the files come back from Drive');
    }
    this._emit(true);
    if ((was && !g.locked) || g.decided) {
      this._retry = 0;
      this.syncAll({ full: true });
    }
  }

  /** A write was refused because Drive stopped this device (423 device_locked). */
  _lockedBy(err) {
    if (!(err && err.status === 423 && err.code === 'device_locked')) return false;
    const inc = drive.normalizeIncident(err.body && err.body.incident);
    this._guard = { locked: true, incident: inc || (this._guard && this._guard.incident) || null };
    this.log.warn('Drive sync: Drive stopped this PC after unusual changes – nothing more goes up');
    if (this.driveSvc && typeof this.driveSvc.guard === 'function') this.driveSvc.guard({ fresh: true }).catch(() => {});
    this._emit(true);
    return true;
  }

  // ── Time travel (Drive 1.7) ──────────────────────────────

  /**
   * How the Drive folder `nodeId` relates to the folder `f` of this PC: 'same', 'inside' (it lies in
   * f's Drive folder), 'contains' (it holds f's Drive folder) or null. Errors count as null.
   */
  async _relation(f, nodeId) {
    const id = drive.posId(nodeId);
    if (!id || !f.target || !f.target.nodeId || (f.scope && f.scope !== this._scopeKey())) return null;
    if (f.target.nodeId === id) return 'same';
    try {
      const st = await this._state(f);
      if (st.rootId === f.target.nodeId && st.tree && st.tree[id] && st.tree[id].isDir) return 'inside';
    } catch { /* no state yet */ }
    try {
      const r = await this.api.folder(f.target.nodeId, { limit: 1 });
      if (r.crumbs.some((c) => c.id === id)) return 'contains';
    } catch { /* gone, offline */ }
    return null;
  }

  /** The folders of this PC the Drive folder `nodeId` touches → [{ id, path, name, mode, relation }] (the time travel's preview). */
  async linkedFolders(nodeId) {
    const out = [];
    for (const f of this._cfg.folders) {
      const relation = await this._relation(f, nodeId);
      if (relation) out.push({ id: f.id, path: f.path, name: path.win32.basename(f.path) || f.path, mode: f.mode, relation });
    }
    return out;
  }

  /**
   * After a time travel of the Drive folder `nodeId`: the folders of this PC it touches run now.
   * "Nur sichern" uploads the PC's files again where Drive has another one now (`reassert`, kept in
   * the state until a run went through); "Abgleichen" takes Drive's changes without asking about
   * mass deletes in this run. → [{ id, mode }]
   */
  async afterTimeTravel(nodeId) {
    const out = [];
    for (const f of this._cfg.folders) {
      if (!(await this._relation(f, nodeId))) continue;
      if (f.mode === 'backup') {
        const st = await this._state(f);
        st.reassert = true;
        await this._writeState(f.id).catch((err) => this.log.warn(`Drive sync state not written: ${err.message}`));
      } else {
        this._runtime(f.id).timeTravel = this.now();
      }
      this.log.info(`Drive sync: a time travel in Drive touches a folder of this PC (${f.mode}) – it runs now`);
      this.sync(f.id, { full: true });
      out.push({ id: f.id, mode: f.mode });
    }
    return out;
  }

  /** Opens the local folder in the Explorer. */
  async openFolder(id) {
    const f = this._folder(id);
    if (!f) throw new DriveError('no such folder', { code: 'not_found' });
    if (!this.shell || typeof this.shell.openPath !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    const err = await this.shell.openPath(f.path);
    if (err) return { ok: false, code: 'open_failed', error: String(err) };
    return { ok: true };
  }

  // ── Watching ─────────────────────────────────────────────

  _watch(f) {
    if (!this.timing.watch || this._watchers.has(f.id)) return;
    const rt = this._runtime(f.id);
    try {
      const w = fs.watch(f.path, { recursive: true, persistent: false }, (_ev, file) => {
        const name = file ? String(file).split(/[\\/]/).pop() : '';
        if (name && S.isTempName(name)) return;
        rt.dirty = true;
        clearTimeout(this._debounce.get(f.id));
        const t = setTimeout(() => { this._debounce.delete(f.id); this.sync(f.id, { full: false }); }, this.timing.watchMs);
        if (t.unref) t.unref();
        this._debounce.set(f.id, t);
      });
      w.on('error', (err) => {
        this.log.info(`Drive sync: watching a folder stopped (${err.code || err.message})`);
        this._unwatch(f.id);
      });
      this._watchers.set(f.id, w);
      rt.watching = true;
    } catch (err) {
      rt.watching = false;
      this.log.info(`Drive sync: folder not watched (${err.code || err.message}); full runs only`);
    }
  }

  _unwatch(id) {
    const w = this._watchers.get(id);
    if (w) { try { w.close(); } catch { /* closed */ } }
    this._watchers.delete(id);
    clearTimeout(this._debounce.get(id));
    this._debounce.delete(id);
    const rt = this._rt.get(id);
    if (rt) rt.watching = false;
  }

  // ── The queue ────────────────────────────────────────────

  /** Runs every folder (full: also scans the PC). */
  syncAll({ full = true } = {}) {
    for (const f of this._cfg.folders) this.sync(f.id, { full });
    return { ok: true };
  }

  _queueSync({ remote = false } = {}) {
    for (const f of this._cfg.folders) if (f.mode === 'sync') this.sync(f.id, { full: false, remote });
  }

  /** Queues a run of the folder `id` → { ok }. Runs one folder after the other. */
  sync(id, { full = true, remote = false } = {}) {
    if (!this._folder(id)) return { ok: false, code: 'not_found' };
    const q = this._queue.get(id) || { full: false, remote: true };
    q.full = q.full || full;
    q.remote = q.remote && remote;
    this._queue.set(id, q);
    this._pump();
    return { ok: true };
  }

  /** Waits until the queue is empty (tests, quit). */
  async idle() {
    while (this._pumping || this._queue.size) await new Promise((r) => setTimeout(r, 10));
  }

  async _pump() {
    if (this._pumping) return;
    this._pumping = true;
    try {
      while (this._queue.size) {
        const [id, q] = this._queue.entries().next().value;
        this._queue.delete(id);
        const f = this._folder(id);
        if (!f) continue;
        this._running = id;
        try {
          await this._run(f, q);
        } catch (err) {
          this.log.warn(`Drive sync run failed: ${err.code || err.message}`);
        } finally {
          this._running = null;
        }
      }
    } finally {
      this._pumping = false;
      this._emit(true);
    }
    await this._reportFolders();
  }

  _retryLater() {
    if (this._retryTimer || !this._started) return;
    const wait = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
    this._retry = Math.min(this._retry + 1, 8);
    this._retryTimer = setTimeout(() => { this._retryTimer = null; this.syncAll({ full: false }); }, wait);
    if (this._retryTimer.unref) this._retryTimer.unref();
  }

  // ── Gates ────────────────────────────────────────────────

  /** Why the folder cannot run now ({ state, reason }) or null. */
  _blocked(f) {
    const s = this._cfg.settings;
    if (f.scope && f.scope !== this._scopeKey()) return { state: 'error', reason: 'other_server' };
    if (this._isLocked()) return { state: 'locked', reason: 'guard_locked' };
    if (s.paused) return { state: 'paused', reason: 'all' };
    if (f.paused) return { state: 'paused', reason: 'folder' };
    const ds = this.driveSvc && typeof this.driveSvc.status === 'function' ? this.driveSvc.status() : { state: 'available' };
    if (ds.state === 'unavailable') return { state: 'waiting', reason: ds.reason === 'not_installed' || ds.reason === 'unsupported' ? 'unavailable' : (ds.reason || 'unavailable') };
    if (ds.state !== 'available') return { state: 'waiting', reason: 'offline' };
    if (s.homeOnly && !this._atHome()) return { state: 'waiting', reason: 'not_home' };
    if (s.vpnOnly) {
      let up = false;
      try { up = !!this.isVpnUp(); } catch { up = false; }
      if (!up) return { state: 'waiting', reason: 'no_vpn' };
    }
    return null;
  }

  _check(f) {
    const b = this._blocked(f);
    if (b) throw new SyncStop(b.reason);
  }

  /** While Drive keeps this device stopped: ask again now and then (a release in the portal without a live event). */
  _recheckGuard() {
    if (this._guardAsked && this.now() - this._guardAsked < 5 * 60 * 1000) return;
    this._guardAsked = this.now();
    if (this.driveSvc && typeof this.driveSvc.guard === 'function') this.driveSvc.guard({ fresh: true }).catch(() => {});
  }

  // ── State files ──────────────────────────────────────────

  _statePath(id) {
    return path.join(this.dir, `${id}.json`);
  }

  async _state(f) {
    if (this._states.has(f.id)) return this._states.get(f.id);
    let st = null;
    if (this.dir) {
      try {
        st = parseState(JSON.parse(await fs.promises.readFile(this._statePath(f.id), 'utf8')));
      } catch (err) {
        if (err.code !== 'ENOENT') this.log.warn(`Drive sync state of a folder unreadable (${err.code || err.message}); it starts fresh`);
      }
    }
    if (!st || st.scope !== (f.scope || st.scope)) st = freshState(f.scope);
    this._states.set(f.id, st);
    return st;
  }

  async _writeState(id) {
    const st = this._states.get(id);
    if (!st || !this.dir) return;
    await fs.promises.mkdir(this.dir, { recursive: true });
    const file = this._statePath(id);
    const tmp = `${file}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    await fs.promises.writeFile(tmp, JSON.stringify(st));
    await fs.promises.rename(tmp, file);
  }

  // ── A run ────────────────────────────────────────────────

  async _run(f, q) {
    const rt = this._runtime(f.id);
    const blocked = this._blocked(f);
    if (blocked) {
      rt.state = blocked.state;
      rt.reason = blocked.reason;
      if (blocked.reason === 'guard_locked') this._recheckGuard();
      this._emit();
      return;
    }
    const st = await this._state(f);
    const ctx = { f, st, rt, root: f.path, actions: 0, me: null, deferred: 0, uploaded: new Set(), entropy: new Map(), started: this.now() };
    rt.state = 'syncing';
    rt.reason = 'checking';
    rt.total = 0;
    rt.done = 0;
    rt.current = null;
    rt.failed = 0;
    rt.failure = null;
    this._emit();
    try {
      await this._ensureLocal(ctx);
      // seat, licence and the device's id: on the first run and every 30 minutes
      if (!this._meAt || this.now() - this._meAt > 30 * 60 * 1000) await this._me(ctx);
      // Drive 1.5: empty files go up without media (older Drives: they are left out)
      ctx.emptyOk = await this._has('emptyFiles');
      // Drive 1.5: Drive keeps the 30 days of "Nur sichern"; 1.6: the entropy goes with each commit
      ctx.deleteAfter = await this._has('deleteAfter');
      ctx.guard = await this._has('guard');
      // Drive 1.7: when a photo / video was taken goes with its commit
      ctx.takenAt = await this._has('takenAt');
      await this._ensureTarget(ctx);
      const touched = await this._pullRemote(ctx);
      if (q.remote && !q.full && !touched && !rt.dirty && rt.watching && st.base && Object.keys(st.base).length) {
        rt.state = 'idle';
        rt.reason = null;
        return;
      }
      rt.dirty = false;
      await this._reconcile(ctx);
      await this._expirePending(ctx);
      f.lastSyncAt = this.now();
      st.lastSyncAt = f.lastSyncAt;
      this._save();
      this._retry = 0;
      // files still being written: the folder is not up to date yet (another run follows)
      rt.state = rt.failed ? 'error' : ctx.deferred ? 'syncing' : 'idle';
      rt.reason = rt.failed ? 'some_failed' : ctx.deferred ? 'settling' : null;
    } catch (err) {
      if (err instanceof SyncStop) {
        const b = this._blocked(f) || { state: 'waiting', reason: err.message };
        rt.state = b.state;
        rt.reason = b.reason;
      } else if (this._lockedBy(err)) {
        rt.state = 'locked';
        rt.reason = 'guard_locked';
      } else if (isNetwork(err)) {
        rt.state = 'waiting';
        rt.reason = 'offline';
        this._retryLater();
      } else {
        rt.state = 'error';
        rt.reason = drive.errorCode(err);
        this.log.warn(`Drive sync of a folder failed: ${rt.reason}`);
        if (err && (err.status === 401 || err.status === 403 || err.status === 404) && this.driveSvc && typeof this.driveSvc.check === 'function') this.driveSvc.check().catch(() => {});
      }
    } finally {
      rt.current = null;
      if (rt.state !== 'syncing') rt.total = rt.done;
      await this._writeState(f.id).catch((err) => this.log.warn(`Drive sync state not written: ${err.message}`));
      this._emit();
    }
  }

  async _ensureLocal(ctx) {
    let st;
    try { st = await fs.promises.stat(ctx.root); } catch { st = null; }
    if (!st || !st.isDirectory()) throw new DriveError('folder missing', { code: 'folder_missing' });
  }

  async _me(ctx) {
    if (ctx.me) return ctx.me;
    const m = await this.api.me();
    if (!m.licence.valid) throw new DriveError('no licence', { code: 'not_licensed' });
    if (!m.me.seat) throw new DriveError('no seat', { code: 'no_seat' });
    this._device.id = m.me.deviceId || null;
    this._meAt = this.now();
    ctx.me = m;
    // Drive 1.6 'guard': Drive stopped this device – nothing goes up
    if (m.guard && m.guard.locked) {
      this._guard = { locked: true, incident: m.guard.incident || null };
      this._emit(true);
      this._recheckGuard(); // the page learns it too (DriveService 'guard')
      throw new SyncStop('guard_locked');
    }
    return m;
  }

  /** Can this Drive do `name` (Drive 1.5 features)? false on older Drives or errors. */
  async _has(name) {
    if (!this.api || typeof this.api.has !== 'function') return false;
    try { return !!(await this.api.has(name)); } catch { return false; }
  }

  /** This PC's own device id for Drive 1.5 ('pc-' + the short device key, or random), kept in the settings. */
  _deviceId() {
    const s = this._cfg.settings;
    if (s.deviceId) return s.deviceId;
    const key = this._deviceKey();
    s.deviceId = key && /^[A-Za-z0-9]{4,32}$/.test(key) ? `pc-${key.toLowerCase()}` : `pc-${crypto.randomBytes(8).toString('hex')}`;
    this._save();
    return s.deviceId;
  }

  /**
   * Drive 1.5 ('devices'): PUT devices/<id> → the device with its folder Meine Dateien ›
   * Geräte › <Name> (Drive makes it and keeps names unique per person). At most every 30 minutes.
   * null on older Drives.
   */
  async _registerDevice() {
    if (!(await this._has('devices'))) return null;
    if (this._devReg && this.now() - this._devReg.at < 30 * 60 * 1000 && this._devReg.device.folder) return this._devReg.device;
    const s = this._cfg.settings;
    const device = await this.api.putDevice(this._deviceId(), { name: s.deviceName || S.deviceName(this._host()), platform: 'windows', version: this.appVersion });
    this._devReg = { device, at: this.now() };
    return device;
  }

  /**
   * Drive 1.5 ('devices'): tells Drive the folders of this PC (portal "Geräte") – when the list
   * changed, else at most every 30 minutes. Failures only go to the log.
   */
  async _reportFolders({ force = false } = {}) {
    try {
      if (!this._cfg.folders.length && !force) return;
      if (!(await this._has('devices'))) return;
      const scope = this._scopeKey();
      const list = this._cfg.folders.filter((f) => !f.scope || f.scope === scope)
        .map((f) => ({ localPath: f.path, mode: f.mode, nodeId: f.target.nodeId || null, lastBackup: f.lastSyncAt || null }));
      const key = JSON.stringify(list.map((f) => [f.localPath, f.mode, f.nodeId]));
      if (!force && key === this._devReport.key && this.now() - this._devReport.at < 30 * 60 * 1000) return;
      const dev = await this._registerDevice();
      if (!dev) return;
      await this.api.putDeviceFolders(dev.id, list);
      this._devReport = { key, at: this.now() };
    } catch (err) {
      this.log.info(`Drive devices: folders not reported (${drive.errorCode(err)})`);
    }
  }

  /** The Drive folder: "Abgleichen" — the one picked; "Nur sichern" — Meine Dateien › Geräte › <PC> › <name> (made). */
  async _ensureTarget(ctx) {
    const { f, st } = ctx;
    if (f.mode === 'sync') {
      if (st.rootId !== f.target.nodeId) Object.assign(st, freshState(st.scope), { rootId: f.target.nodeId });
      try {
        await this.api.node(f.target.nodeId);
      } catch (err) {
        if (err && err.status === 404) throw new DriveError('Drive folder gone', { code: 'target_gone' });
        throw err;
      }
      return;
    }
    if (f.target.nodeId) {
      try {
        const n = await this.api.node(f.target.nodeId);
        if (n.isDir && !n.deleted) {
          if (st.rootId !== n.id) Object.assign(st, freshState(st.scope), { rootId: n.id });
          return;
        }
      } catch (err) {
        if (!(err && err.status === 404)) throw err;
      }
    }
    // Drive 1.5: below the device's own folder (Meine Dateien › Geräte › <Name>, unique per person)
    const dev = await this._registerDevice().catch((err) => {
      this.log.info(`Drive devices: not registered (${drive.errorCode(err)}) – the folder is made by name`);
      return null;
    });
    if (dev && dev.folder) {
      const leaf = f.remoteName || 'Ordner';
      const find = async () => (await this.api.childrenAll(dev.folder.id)).find((n) => n.isDir && !n.deleted && !n.encrypted && S.keyOf(n.name) === S.keyOf(leaf)) || null;
      let n = await find();
      if (!n) {
        try {
          n = await this.api.mkdir(dev.folder.id, leaf, { rename: false });
        } catch (err) {
          if (!(err && err.status === 409)) throw err;
          n = await find();
        }
      }
      if (!n || !n.isDir) throw new DriveError('a file is in the way', { code: 'exists' });
      f.target = { nodeId: n.id, areaId: n.areaId || dev.folder.areaId, label: ['Meine Dateien', S.DEVICES_FOLDER, dev.name || dev.folder.name, leaf].join(' › ') };
      this._save();
      Object.assign(st, freshState(st.scope), { rootId: n.id, base: st.rootId ? {} : st.base });
      return;
    }
    // Made (again): Meine Dateien › Geräte › <PC> › <name>
    const m = await this._me(ctx);
    const mine = m.areas.find((a) => a.kind === 'mine' && a.writable);
    if (!mine) throw new DriveError('no own area', { code: 'no_area' });
    const segs = [S.DEVICES_FOLDER, this._cfg.settings.deviceName || S.deviceName(this._host()), f.remoteName || 'Ordner'];
    let parent = mine.rootId;
    let rel = '';
    for (const seg of segs) {
      rel = S.joinRel(rel, seg);
      let n = await this.api.byPath(mine.id, rel);
      if (!n) {
        try {
          n = await this.api.mkdir(parent, seg, { rename: false });
        } catch (err) {
          if (!(err && err.status === 409)) throw err;
          n = await this.api.byPath(mine.id, rel);
        }
      }
      if (!n || !n.isDir) throw new DriveError('a file is in the way', { code: 'exists' });
      parent = n.id;
    }
    f.target = { nodeId: parent, areaId: mine.id, label: ['Meine Dateien', ...segs].join(' › ') };
    this._save();
    Object.assign(st, freshState(st.scope), { rootId: parent, base: st.rootId ? {} : st.base });
  }

  /** Drive's side: the whole tree (first run) or the change log since the cursor → anything new? */
  async _pullRemote(ctx) {
    const { st } = ctx;
    if (!st.tree || st.cursor === null) {
      const m = await this._me(ctx);
      const cursor = m.latest || 0;
      st.tree = await this._scanRemote(st.rootId);
      st.cursor = cursor;
      return true;
    }
    let touched = false;
    for (let round = 0; round < 200; round++) {
      const page = await this.api.changes(st.cursor, { limit: 1000 });
      const r = S.applyChanges(st.tree, st.rootId, page.changes);
      if (r.rootGone) {
        st.tree = null;
        st.cursor = null;
        throw new DriveError('Drive folder gone', { code: 'target_gone' });
      }
      for (const id of r.rescan) {
        const sub = await this._scanRemote(id);
        Object.assign(st.tree, sub);
      }
      touched = touched || r.touched;
      st.cursor = page.next;
      if (!page.more) break;
    }
    return touched;
  }

  /** Every node below `rootId` → tree. */
  async _scanRemote(rootId) {
    const tree = {};
    const dirs = [rootId];
    let count = 0;
    while (dirs.length) {
      const id = dirs.shift();
      for (const n of await this.api.childrenAll(id)) {
        // Drive 1.9: vault folders and their content are never synced (opaque names, ciphertext)
        if (n.deleted || n.encrypted) continue;
        tree[n.id] = S.slimNode(n);
        if (n.isDir) dirs.push(n.id);
        if (++count > 500000) throw new DriveError('too many files', { code: 'too_many_files' });
      }
    }
    return tree;
  }

  /** This PC's side → Map key → { path, dir, size, mtime } (left-out files counted in rt.skipped). */
  async _scanLocal(ctx) {
    const { root, rt } = ctx;
    const settings = this._cfg.settings;
    const out = new Map();
    const unreadable = [];
    let skipped = 0;
    let bytes = 0;
    let files = 0;
    const walk = async (abs, rel) => {
      let entries;
      try {
        entries = await fs.promises.readdir(abs, { withFileTypes: true });
      } catch (err) {
        if (!rel) throw new DriveError('folder unreadable', { code: 'folder_missing' });
        unreadable.push(S.keyOf(rel));
        return;
      }
      for (const e of entries) {
        const r = S.joinRel(rel, e.name.normalize('NFC'));
        if (e.isSymbolicLink()) continue;
        if (e.isDirectory()) {
          if (S.excluded(r, { dir: true }, settings)) { skipped++; continue; }
          out.set(S.keyOf(r), { path: r, dir: true, size: 0, mtime: 0 });
          await walk(path.join(abs, e.name), r);
        } else if (e.isFile()) {
          let s;
          try { s = await fs.promises.stat(path.join(abs, e.name)); } catch { continue; }
          const why = S.excluded(r, { dir: false, size: s.size }, settings) || (s.size === 0 && !ctx.emptyOk ? 'empty' : null);
          if (why) { if (why !== 'temp') skipped++; continue; }
          files++;
          bytes += s.size;
          out.set(S.keyOf(r), { path: r, dir: false, size: s.size, mtime: Math.floor(s.mtimeMs) });
        }
      }
    };
    await walk(root, '');
    rt.skipped = skipped;
    rt.files = files;
    rt.bytes = bytes;
    return { local: out, unreadable };
  }

  /** The views the planner sees: what is left out goes from all three (it stays as it is on both sides). */
  _views(ctx, local, unreadable) {
    const settings = this._cfg.settings;
    const { st } = ctx;
    const base = {};
    for (const [k, e] of Object.entries(st.base)) {
      if (S.excluded(e.path, { dir: e.dir, size: e.size }, settings)) continue;
      // a folder the PC could not read: its files count as unchanged
      if (unreadable.some((u) => S.under(k, u))) { if (!local.has(k)) local.set(k, { path: e.path, dir: e.dir, size: e.size, mtime: e.mtime }); }
      base[k] = e;
    }
    const remote = new Map();
    for (const [k, r] of S.remoteByPath(st.tree, st.rootId)) {
      if (S.excluded(r.path, { dir: r.dir, size: r.size }, settings) || (!r.dir && !r.size && !ctx.emptyOk)) continue;
      remote.set(k, r);
    }
    // held back after "Rückgängig machen" (not uploaded while unchanged)
    const view = new Map(local);
    for (const [k, q] of Object.entries(st.quarantine || {})) {
      const l = view.get(k);
      if (!l || l.dir || l.size !== q.size || l.mtime !== q.mtime || st.base[k]) { delete st.quarantine[k]; continue; }
      view.delete(k);
    }
    ctx.rt.held = Object.keys(st.quarantine || {}).length;
    return { base, local: view, remote };
  }

  async _reconcile(ctx) {
    const { f, st, rt } = ctx;
    let { local, unreadable } = await this._scanLocal(ctx);
    // after "Rückgängig machen" (Drive 1.6 'guard'): the files come back from Drive first
    if (rt.undo) {
      rt.undo = false;
      await this._restoreAfterUndo(ctx, local);
      ({ local, unreadable } = await this._scanLocal(ctx));
    }
    // Moves first (as moves: nothing is uploaded or downloaded again)
    for (let round = 0; round < 50; round++) {
      const v = this._views(ctx, local, unreadable);
      const moves = S.planMoves({ base: v.base, local: v.local, remote: v.remote, mode: f.mode });
      if (!moves.length) break;
      let moved = false;
      for (const m of moves) {
        this._check(f);
        const ok = m.op === 'moveRemote' ? await this._moveRemote(ctx, m) : await this._moveLocal(ctx, m);
        if (ok && m.op === 'moveLocal') local = rebaseMap(local, m.fromKey, m.to);
        moved = moved || ok;
      }
      if (!moved) break;
    }

    const v = this._views(ctx, local, unreadable);
    // after a time travel ("Nur sichern"): the PC's files go up again where Drive has another one now
    const reassert = f.mode === 'backup' && st.reassert === true;
    const p = S.plan({ mode: f.mode, base: v.base, local: v.local, remote: v.remote, restoreDeleted: rt.restore, reassert });
    let actions = p.actions;
    const isDelete = (a) => a.op === 'trashRemote' || (a.op === 'pendingDelete' && !st.pending[a.key]);
    const deletes = actions.filter(isDelete).reduce((n, a) => n + (a.files || 0), 0);
    // The same guard the other way: many files gone in Drive at once (or a Drive answer that lost a
    // folder) must not empty the PC folder without asking.
    const driveDeletes = actions.filter((a) => a.op === 'deleteLocal').reduce((n, a) => n + (a.files || 0), 0);
    const massPc = S.massDelete(deletes, p.files);
    const massDrive = S.massDelete(driveDeletes, p.files);
    // a time travel of this person (Drive 1.7) moved many files into Drive's trash: no question for that run
    const tt = rt.timeTravel && ctx.started >= rt.timeTravel && this.now() - rt.timeTravel < 30 * 60 * 1000;
    if (rt.timeTravel && ctx.started >= rt.timeTravel) rt.timeTravel = 0;
    if (!rt.allowDeletes && !rt.restore && (massPc || (massDrive && !tt))) {
      actions = actions.filter((a) => !isDelete(a) && a.op !== 'deleteLocal');
      rt.confirm = massDrive && !massPc ? { count: driveDeletes, total: p.files, from: 'drive' } : { count: deletes, total: p.files, from: 'pc' };
      this.log.info(`Drive sync: ${rt.confirm.count} of ${p.files} files deleted ${rt.confirm.from === 'drive' ? 'in Drive' : 'on this PC'} at once — waiting for the person`);
    } else {
      rt.confirm = null;
    }
    rt.allowDeletes = false;
    rt.restore = false;

    // Ransomware: many existing files changed into encrypted-looking content (or renamed to a
    // ransomware extension) → nothing of this run goes to Drive; the person decides.
    if (!rt.allowSuspect) {
      const sus = await this._suspicious(ctx, actions, v);
      if (sus.trip) {
        rt.suspect = { count: sus.count, sample: sus.sample, why: sus.why };
        rt.total = 0;
        rt.done = 0;
        this.log.warn(`Drive sync: ${sus.count} files changed in an unusual way (${sus.why}) — nothing uploaded, waiting for the person`);
        rt.pendingDeletes = Object.keys(st.pending).length;
        return;
      }
    }
    rt.suspect = null;
    rt.allowSuspect = false;

    const transfers = actions.filter((a) => a.op === 'upload' || a.op === 'download' || a.op === 'merge');
    rt.total = transfers.length;
    rt.done = 0;
    rt.reason = transfers.length ? 'transfer' : null;
    this._emit();
    for (const a of actions) {
      this._check(f);
      try {
        await this._do(ctx, a);
      } catch (err) {
        if (err instanceof SyncStop || isNetwork(err) || isLocked(err)) throw err;
        rt.failed++;
        rt.failure = { name: S.baseName(a.path || a.key), code: drive.errorCode(err) };
        this.log.info(`Drive sync: ${a.op} of a file failed (${rt.failure.code})`);
      }
      if (a.op === 'upload' || a.op === 'download' || a.op === 'merge') { rt.done++; rt.current = null; this._emit(); }
      if (++ctx.actions % this.timing.saveEvery === 0) await this._writeState(f.id).catch(() => {});
    }
    rt.pendingDeletes = Object.keys(st.pending).length;
    if (reassert && !rt.failed) st.reassert = false;
  }

  /**
   * The ransomware check of a run (utils/drive-guard.js): existing files changed into high-entropy
   * content that was not high-entropy before, and new files named like a file that went plus a
   * ransomware extension → { trip, count, sample, why }. The entropies are kept for the commits.
   */
  async _suspicious(ctx, actions, v) {
    const { base, local } = v;
    ctx.entropy = ctx.entropy || new Map();
    const changed = actions.filter((a) => (a.op === 'upload' || a.op === 'merge') && base[a.key] && !base[a.key].dir);
    const fresh = actions.filter((a) => a.op === 'upload' && !base[a.key]);
    // fewer than 4 candidates can never reach a threshold (20 % of at least 20 files)
    if (changed.length + fresh.length < 4) return { trip: false, count: 0, sample: [], why: null };
    const gone = new Map(); // folder key → names of files that left the PC
    for (const [k, b] of Object.entries(base)) {
      if (b.dir || local.has(k)) continue;
      const d = S.parentOf(k);
      if (!gone.has(d)) gone.set(d, []);
      gone.get(d).push(S.baseName(k));
    }
    const list = [];
    let ent = 0;
    let ext = 0;
    for (const a of changed) {
      const e = await G.fileEntropy(this._abs(ctx, a.path));
      if (e !== null) ctx.entropy.set(a.key, e);
      if (G.suspiciousChange(a.path, e, base[a.key].ent)) { list.push({ dir: S.parentOf(a.key), name: S.baseName(a.path) }); ent++; }
    }
    for (const a of fresh) {
      if (G.ransomRename(S.baseName(a.key), gone.get(S.parentOf(a.key)))) { list.push({ dir: S.parentOf(a.key), name: S.baseName(a.path) }); ext++; }
    }
    const files = new Map();
    for (const [k, b] of Object.entries(base)) if (!b.dir) files.set(S.parentOf(k), (files.get(S.parentOf(k)) || 0) + 1);
    const r = G.guardTrips(list, (d) => files.get(d) || 0);
    return { ...r, why: ext > ent ? 'extension' : 'entropy' };
  }

  /**
   * After "Rückgängig machen": Drive has the files as they were before. Every file of the last
   * agreed state that differs on the PC (or is gone there) comes back from Drive; the PC's
   * differing bytes stay next to it as a conflict copy, held back (not uploaded) like files that
   * are new on the PC since then. Nothing on the PC is overwritten without a copy.
   */
  async _restoreAfterUndo(ctx, local) {
    const { st } = ctx;
    st.quarantine = st.quarantine || {};
    const remote = S.remoteByPath(st.tree, st.rootId);
    const device = this._cfg.settings.deviceName || S.deviceName(this._host());
    let back = 0;
    for (const [k, b] of Object.entries(st.base)) {
      if (b.dir) continue;
      this._check(ctx.f);
      const r = remote.get(k);
      const l = local.get(k);
      if (!r) {
        // gone in Drive (a file the incident made, trashed by the undo): the PC's copy is held back
        if (l && !l.dir) { st.quarantine[k] = { size: l.size, mtime: l.mtime }; delete st.base[k]; }
        continue;
      }
      if (r.dir || (l && l.dir)) continue;
      const lSame = !!l && l.size === b.size && l.mtime === b.mtime;
      if (lSame && r.nodeId === b.nodeId && r.rev === b.rev) continue;
      if (l) {
        const abs = this._abs(ctx, l.path);
        const sha = await this._hash(ctx, abs, l.size);
        if (sha && r.sha256 && sha === r.sha256) {
          this._record(ctx, k, { ...b, path: l.path, size: l.size, mtime: l.mtime, sha256: sha, nodeId: r.nodeId, rev: r.rev });
          continue;
        }
        const crel = S.joinRel(S.parentOf(l.path), S.conflictName(S.baseName(l.path), device, this.now()));
        if (await this._stat(this._abs(ctx, crel))) continue;
        await fs.promises.rename(abs, this._abs(ctx, crel));
        st.quarantine[S.keyOf(crel)] = { size: l.size, mtime: l.mtime };
        ctx.rt.conflicts++;
      }
      try {
        await this._download(ctx, { key: k, path: r.path, nodeId: r.nodeId, rev: r.rev, size: r.size, mtime: r.mtime, sha256: r.sha256 }, { force: true });
        back++;
      } catch (err) {
        if (err instanceof SyncStop || isNetwork(err) || isLocked(err)) throw err;
        this.log.info(`Drive sync: a file did not come back from Drive (${drive.errorCode(err)})`);
      }
    }
    // files new on the PC (not in the last agreed state, not in Drive): held back
    for (const [k, l] of local) {
      if (l.dir || st.base[k] || remote.has(k)) continue;
      st.quarantine[k] = { size: l.size, mtime: l.mtime };
    }
    ctx.rt.held = Object.keys(st.quarantine).length;
    this.log.info(`Drive sync: ${back} files back from Drive, ${ctx.rt.held} held back`);
  }

  // ── Actions ──────────────────────────────────────────────

  _abs(ctx, rel) {
    return path.join(ctx.root, ...String(rel).split('/'));
  }

  /** The Drive folder of the parent of `key` (the root for the top). */
  _parentNode(ctx, key) {
    const pk = S.parentOf(key);
    if (!pk) return ctx.st.rootId;
    const b = ctx.st.base[pk];
    if (b && b.dir && b.nodeId) return b.nodeId;
    const r = S.remoteByPath(ctx.st.tree, ctx.st.rootId).get(pk);
    if (r && r.dir) return r.nodeId;
    return null;
  }

  async _ensureParent(ctx, key, relPath) {
    const pk = S.parentOf(key);
    if (!pk) return ctx.st.rootId;
    const have = this._parentNode(ctx, key);
    if (have) return have;
    await this._mkdirRemote(ctx, { key: pk, path: S.parentOf(relPath) });
    return this._parentNode(ctx, key);
  }

  _record(ctx, key, entry) {
    ctx.st.base[key] = entry;
  }

  _forget(ctx, key) {
    for (const k of Object.keys(ctx.st.base)) if (S.under(k, key)) delete ctx.st.base[k];
    for (const k of Object.keys(ctx.st.pending)) if (S.under(k, key)) delete ctx.st.pending[k];
  }

  _tree(ctx, node) {
    if (!ctx.st.tree || !node || node.encrypted) return;
    ctx.st.tree[node.id] = S.slimNode(node);
  }

  async _do(ctx, a) {
    switch (a.op) {
      case 'mkdirRemote': return this._mkdirRemote(ctx, a);
      case 'mkdirLocal': {
        await fs.promises.mkdir(this._abs(ctx, a.path), { recursive: true });
        this._record(ctx, a.key, { path: a.path, dir: true, size: 0, mtime: 0, sha256: null, nodeId: a.nodeId, rev: a.rev });
        return undefined;
      }
      case 'record': this._record(ctx, a.key, a.entry); return undefined;
      case 'forget': this._forget(ctx, a.key); return undefined;
      case 'upload': return this._upload(ctx, a);
      case 'download': return this._download(ctx, a);
      case 'merge': return this._merge(ctx, a);
      case 'deleteLocal': return this._deleteLocal(ctx, a);
      case 'trashRemote': return this._trashRemote(ctx, a);
      case 'pendingDelete': return this._pendingDelete(ctx, a);
      case 'kindClash': return this._kindClash(ctx, a);
      default: return undefined;
    }
  }

  /**
   * "Nur sichern": a file (folder) deleted on the PC stays in Drive for 30 days. Drive 1.5
   * ('deleteAfter') keeps the time (DELETE ?after=…&device=…); older Drives: the list here.
   */
  async _pendingDelete(ctx, a) {
    if (ctx.st.pending[a.key]) return;
    const p = { at: this.now(), nodeId: a.nodeId, path: a.path, dir: !!a.dir, server: false, deleteAt: null };
    if (ctx.deleteAfter && a.nodeId) {
      const r = await this._markRemote(a.nodeId, S.BACKUP_DELETE_DAYS * DAY / 1000);
      if (r) Object.assign(p, { server: true, deleteAt: r.deleteAt || this.now() + S.BACKUP_DELETE_DAYS * DAY });
    }
    ctx.st.pending[a.key] = p;
  }

  /** DELETE nodes/<id>?after=<s>&device=<id> → { deleteAt } | null when the node is gone (404). */
  async _markRemote(nodeId, seconds) {
    const after = Math.max(60, Math.round(seconds));
    try {
      const r = await this.api.trash(nodeId, { after, device: this._deviceId() });
      return { deleteAt: r.deleteAt || this.now() + after * 1000 };
    } catch (err) {
      if (err && err.status === 404) return null;
      throw err;
    }
  }

  /** Calls off the delayed deletes Drive keeps for this folder (removing the folder deletes nothing). */
  async _unmarkAll(f) {
    if (!this.dir) return;
    let st = this._states.get(f.id);
    if (!st) {
      try { st = parseState(JSON.parse(await fs.promises.readFile(this._statePath(f.id), 'utf8'))); } catch { st = null; }
    }
    const list = st ? Object.values(st.pending).filter((p) => p.server && p.nodeId) : [];
    for (const p of list.slice(0, 5000)) {
      try { await this.api.unmark(p.nodeId); } catch (err) { if (!(err && (err.status === 404 || err.status === 400))) throw err; }
    }
  }

  async _mkdirRemote(ctx, a) {
    const parentId = await this._ensureParent(ctx, a.key, a.path);
    if (!parentId) throw new DriveError('parent missing', { code: 'parent_missing' });
    const name = S.baseName(a.path);
    let node;
    try {
      node = await this.api.mkdir(parentId, name, { rename: false });
    } catch (err) {
      if (!(err && err.status === 409)) throw err;
      const kids = await this.api.childrenAll(parentId);
      node = kids.find((n) => S.keyOf(n.name) === S.keyOf(name));
      // a vault folder (Drive 1.9) is never a folder of the PC: nothing goes into it
      if (!node || !node.isDir || node.encrypted) throw new DriveError('a file is in the way', { code: 'exists' });
      for (const k of kids) this._tree(ctx, k);
    }
    this._tree(ctx, node);
    this._record(ctx, a.key, { path: a.path, dir: true, size: 0, mtime: 0, sha256: null, nodeId: node.id, rev: node.rev });
  }

  /**
   * Changed in the last moments (still being written)? Then the file waits for
   * the next run (ctx.deferred) — at most 3 times, a file that is written all
   * the time (a log) goes anyway. A time in the future is not "settling".
   */
  _settling(ctx, s, key) {
    const age = this.now() - s.mtimeMs;
    if (!(age >= 0 && age < this.timing.settleMs)) { this._deferrals.delete(`${ctx.f.id}|${key}`); return false; }
    const k = `${ctx.f.id}|${key}`;
    const n = this._deferrals.get(k) || 0;
    if (n >= 3) { this._deferrals.delete(k); return false; }
    this._deferrals.set(k, n + 1);
    while (this._deferrals.size > 10000) this._deferrals.delete(this._deferrals.keys().next().value);
    ctx.deferred++;
    ctx.rt.dirty = true;
    this._later(ctx.f.id);
    return true;
  }

  async _stat(p) {
    try { return await fs.promises.stat(p); } catch { return null; }
  }

  async _hash(ctx, p, size) {
    if (size > drive.SHA_MAX_BYTES) return null;
    ctx.rt.reason = 'hashing';
    return sha256File(p).catch(() => null);
  }

  _progress(ctx, name) {
    return (sent, total) => {
      ctx.rt.current = { name, sent, total: total || null };
      this._emit();
    };
  }

  async _uploadMedia(ctx, abs, size, name) {
    // Drive 1.5 ('emptyFiles'): no media for an empty file – commit with `empty`
    if (!size) return { mediaId: null, empty: true };
    ctx.rt.reason = 'transfer';
    ctx.rt.current = { name, sent: 0, total: size };
    this._emit();
    return this.api.upload({ path: abs, size, mime: guessMime(name) }, { onProgress: this._progress(ctx, name), throttle: () => this.up.stream() });
  }

  async _upload(ctx, a) {
    const { f, st } = ctx;
    const abs = this._abs(ctx, a.path);
    const s = await this._stat(abs);
    if (!s || !s.isFile() || (!s.size && !ctx.emptyOk)) return;
    if (this._settling(ctx, s, a.key)) return;
    const name = S.baseName(a.path);
    const parentId = await this._ensureParent(ctx, a.key, a.path);
    if (!parentId) throw new DriveError('parent missing', { code: 'parent_missing' });
    const mtime = Math.floor(s.mtimeMs);
    const sha = await this._hash(ctx, abs, s.size);
    const b = st.base[a.key];
    // after a time travel ("Nur sichern", reassert): Drive has the PC's bytes already
    if (a.reassert && sha && a.sha256 === sha && a.nodeId) {
      this._record(ctx, a.key, { ...(b || {}), path: a.path, dir: false, size: s.size, mtime, sha256: sha, nodeId: a.nodeId, rev: a.baseRev });
      return;
    }
    // only the time changed: nothing to upload
    if (b && sha && b.sha256 === sha && a.nodeId && b.nodeId === a.nodeId && b.rev === a.baseRev) {
      this._record(ctx, a.key, { ...b, path: a.path, size: s.size, mtime });
      return;
    }
    if (!a.nodeId) {
      const c = await this.api.check({ parentId, name, sha256: sha, size: s.size });
      if (c.same && c.node) {
        this._tree(ctx, c.node);
        this._record(ctx, a.key, { path: a.path, dir: false, size: s.size, mtime, sha256: sha, nodeId: c.node.id, rev: c.node.rev });
        return;
      }
    }
    const up = await this._uploadMedia(ctx, abs, s.size, name);
    const extra = await this._commitExtra(ctx, a.key, abs, name, s.size);
    const opts = f.mode === 'backup'
      ? { onConflict: 'version' }
      : { onConflict: null, baseRev: a.nodeId ? a.baseRev : null };
    let res;
    try {
      res = await this.api.commit({ mediaId: up.mediaId, empty: !!up.empty, parentId, name, mtime, ...opts, ...extra.send });
    } catch (err) {
      if (err && err.status === 409 && err.code === 'conflict') {
        const cur = drive.normalizeNode(err.body && err.body.current);
        return this._conflict(ctx, a, { mediaId: up.mediaId, empty: !!up.empty, sha, size: s.size, mtime, parentId, cur, extra });
      }
      throw err;
    }
    this._tree(ctx, res.node);
    this._record(ctx, a.key, { path: a.path, dir: false, size: s.size, mtime, sha256: sha || res.node.sha256, nodeId: res.node.id, rev: res.node.rev, ent: extra.ent });
    if (ctx.uploaded) ctx.uploaded.add(a.key);
  }

  /**
   * What goes with a commit: the text layer of a PDF (search), the entropy of the first 64 KB
   * (sent to Drive 1.6 'guard', kept in the state as `ent` for the ransomware check).
   * → { send: { text?, entropy? }, ent }
   */
  async _commitExtra(ctx, key, abs, name, size) {
    const send = {};
    let ent = ctx.entropy && ctx.entropy.has(key) ? ctx.entropy.get(key) : null;
    if (size > 0 && ent === null) ent = await G.fileEntropy(abs);
    if (ctx.guard && ent !== null) send.entropy = ent;
    if (size > 0 && isPdf(name)) {
      const text = await Promise.resolve(this.readPdfText(abs, { size })).catch(() => null);
      if (text) send.text = text;
    }
    if (ctx.takenAt && size > 0 && isMediaName(name)) {
      const at = await readTakenAt(abs, { name }).catch(() => null);
      if (at) send.takenAt = at;
    }
    return { send, ent };
  }

  /**
   * Both sides changed: the PC's bytes (already uploaded as `mediaId`) become
   * "Name (Konflikt <PC> <Datum>).ext" next to the file — in Drive and on the PC —
   * and Drive's file comes to its place on the PC.
   */
  async _conflict(ctx, a, { mediaId, empty = false, sha, size, mtime, parentId, cur, extra = null }) {
    const { st, rt } = ctx;
    if (cur && sha && cur.sha256 === sha) {
      this._tree(ctx, cur);
      this._record(ctx, a.key, { path: a.path, dir: false, size, mtime, sha256: sha, nodeId: cur.id, rev: cur.rev });
      return;
    }
    const dirRel = S.parentOf(a.path);
    const device = this._cfg.settings.deviceName || S.deviceName(this._host());
    const cname = S.conflictName(S.baseName(a.path), device, this.now());
    let crel = S.joinRel(dirRel, cname);
    const from = this._abs(ctx, a.path);
    let to = this._abs(ctx, crel);
    if (await this._stat(to)) throw new DriveError('conflict copy exists', { code: 'exists' });
    // the PC's copy moves aside first (a file that is open stays as it is: nothing is uploaded twice)
    await fs.promises.rename(from, to);
    let res;
    try {
      res = await this.api.commit({ mediaId, empty, parentId, name: cname, mtime, onConflict: 'rename', ...(extra ? extra.send : {}) });
    } catch (err) {
      await fs.promises.rename(to, from).catch(() => {});
      throw err;
    }
    if (res.node.name !== cname) {
      const other = S.joinRel(dirRel, res.node.name);
      if (!(await this._stat(this._abs(ctx, other)))) {
        await fs.promises.rename(to, this._abs(ctx, other)).then(() => { crel = other; to = this._abs(ctx, other); }).catch(() => {});
      }
    }
    this._tree(ctx, res.node);
    this._record(ctx, S.keyOf(crel), { path: crel, dir: false, size, mtime, sha256: sha || res.node.sha256, nodeId: res.node.id, rev: res.node.rev, ent: extra ? extra.ent : null });
    delete st.base[a.key];
    rt.conflicts++;
    this.log.info('Drive sync: a conflict — the PC\'s copy is kept next to the file');
    if (cur && !cur.isDir) {
      this._tree(ctx, cur);
      await this._download(ctx, { key: a.key, path: a.path, nodeId: cur.id, rev: cur.rev, size: cur.size, mtime: cur.mtime, sha256: cur.sha256 }, { force: true });
    }
  }

  async _merge(ctx, a) {
    const { f } = ctx;
    const abs = this._abs(ctx, a.path);
    const s = await this._stat(abs);
    if (!s || !s.isFile()) return;
    if (this._settling(ctx, s, a.key)) return;
    const mtime = Math.floor(s.mtimeMs);
    const sha = await this._hash(ctx, abs, s.size);
    if (sha && a.sha256 && sha === a.sha256 && s.size === a.size) {
      this._record(ctx, a.key, { path: a.path, dir: false, size: s.size, mtime, sha256: sha, nodeId: a.nodeId, rev: a.rev });
      return;
    }
    const parentId = await this._ensureParent(ctx, a.key, a.path);
    if (!parentId) throw new DriveError('parent missing', { code: 'parent_missing' });
    const name = S.baseName(a.path);
    const up = await this._uploadMedia(ctx, abs, s.size, name);
    const extra = await this._commitExtra(ctx, a.key, abs, name, s.size);
    if (f.mode === 'backup') {
      // "Nur sichern": the PC's file is the new version (Drive keeps the old one as a version)
      const res = await this.api.commit({ mediaId: up.mediaId, empty: !!up.empty, parentId, name, mtime, onConflict: 'version', ...extra.send });
      this._tree(ctx, res.node);
      this._record(ctx, a.key, { path: a.path, dir: false, size: s.size, mtime, sha256: sha || res.node.sha256, nodeId: res.node.id, rev: res.node.rev, ent: extra.ent });
      if (ctx.uploaded) ctx.uploaded.add(a.key);
      return;
    }
    const tree = ctx.st.tree && ctx.st.tree[a.nodeId];
    const cur = tree ? { id: tree.id, isDir: false, rev: tree.rev, size: tree.size, mtime: tree.mtime, sha256: tree.sha256, name: tree.name, parentId: tree.parentId } : null;
    await this._conflict(ctx, a, { mediaId: up.mediaId, empty: !!up.empty, sha, size: s.size, mtime, parentId, cur, extra });
  }

  async _download(ctx, a, { force = false } = {}) {
    const { st } = ctx;
    const abs = this._abs(ctx, a.path);
    const have = await this._stat(abs);
    if (have && !force) {
      const b = st.base[a.key];
      if (have.isDirectory()) throw new DriveError('a folder is in the way', { code: 'exists' });
      // changed on the PC since the scan: the next run compares both
      if (!b || b.size !== have.size || b.mtime !== Math.floor(have.mtimeMs)) { ctx.deferred++; ctx.rt.dirty = true; this._later(ctx.f.id); return; }
    }
    await fs.promises.mkdir(path.dirname(abs), { recursive: true });
    const name = S.baseName(a.path);
    const c = await this.api.content(a.nodeId);
    const tmp = path.join(path.dirname(abs), `.${crypto.randomBytes(5).toString('hex')}${S.DOWNLOAD_SUFFIX}`);
    ctx.rt.reason = 'transfer';
    ctx.rt.current = { name, sent: 0, total: a.size || null };
    this._emit();
    const out = fs.createWriteStream(tmp);
    try {
      // Drive 1.5: an empty file has no media
      if (c.empty) await new Promise((resolve, reject) => { out.on('error', reject); out.end(resolve); });
      else await this.api.download(c.mediaId, out, { onProgress: this._progress(ctx, name), throttle: () => this.down.stream() });
      if (Number.isFinite(a.mtime) && a.mtime > 0) await fs.promises.utimes(tmp, new Date(), new Date(a.mtime));
      await fs.promises.rename(tmp, abs);
    } catch (err) {
      out.destroy();
      await fs.promises.rm(tmp, { force: true }).catch(() => {});
      throw err;
    }
    const s = await fs.promises.stat(abs);
    const ent = s.size > 0 ? await G.fileEntropy(abs) : null;
    this._record(ctx, a.key, { path: a.path, dir: false, size: s.size, mtime: Math.floor(s.mtimeMs), sha256: a.sha256 || null, nodeId: a.nodeId, rev: a.rev, ent });
  }

  async _deleteLocal(ctx, a) {
    const abs = this._abs(ctx, a.path);
    const s = await this._stat(abs);
    if (s && !a.dir) {
      const b = ctx.st.base[a.key];
      if (!b || b.size !== s.size || b.mtime !== Math.floor(s.mtimeMs)) { ctx.rt.dirty = true; return; }
    }
    if (s) await this.trashItem(abs);
    this._forget(ctx, a.key);
  }

  async _trashRemote(ctx, a) {
    try {
      await this.api.trash(a.nodeId);
    } catch (err) {
      if (!(err && err.status === 404)) throw err;
    }
    if (ctx.st.tree) S.dropSubtree(ctx.st.tree, a.nodeId);
    this._forget(ctx, a.key);
  }

  async _kindClash(ctx, a) {
    if (ctx.f.mode === 'backup') throw new DriveError('a file and a folder of the same name', { code: 'kind_clash' });
    // the PC's item moves aside (it comes back as a new one with the next run)
    const device = this._cfg.settings.deviceName || S.deviceName(this._host());
    const crel = S.joinRel(S.parentOf(a.path), S.conflictName(S.baseName(a.path), device, this.now()));
    if (await this._stat(this._abs(ctx, crel))) throw new DriveError('conflict copy exists', { code: 'exists' });
    await fs.promises.rename(this._abs(ctx, a.path), this._abs(ctx, crel));
    this._forget(ctx, a.key);
    ctx.rt.conflicts++;
    ctx.rt.dirty = true;
    this._later(ctx.f.id);
  }

  async _moveRemote(ctx, m) {
    const toParentKey = S.parentOf(m.toKey);
    const fromParentKey = S.parentOf(m.fromKey);
    let parentId = null;
    try {
      parentId = toParentKey === fromParentKey ? null : await this._ensureParent(ctx, m.toKey, m.to);
    } catch (err) {
      if (isNetwork(err) || isLocked(err)) throw err;
      return false;
    }
    const name = S.baseName(m.to);
    try {
      const node = await this.api.place(m.nodeId, { name: name !== S.baseName(m.from) ? name : null, parentId });
      this._tree(ctx, node);
    } catch (err) {
      if (isNetwork(err) || isLocked(err)) throw err;
      this.log.info(`Drive sync: a move in Drive failed (${drive.errorCode(err)}); delete and upload instead`);
      return false;
    }
    ctx.st.base = S.rebase(ctx.st.base, m.fromKey, m.to);
    return true;
  }

  async _moveLocal(ctx, m) {
    const from = this._abs(ctx, m.from);
    const to = this._abs(ctx, m.to);
    if (await this._stat(to)) return false;
    try {
      await fs.promises.mkdir(path.dirname(to), { recursive: true });
      await fs.promises.rename(from, to);
    } catch (err) {
      this.log.info(`Drive sync: a move on this PC failed (${err.code || err.message})`);
      return false;
    }
    ctx.st.base = S.rebase(ctx.st.base, m.fromKey, m.to);
    return true;
  }

  /**
   * "Nur sichern": files deleted on the PC 30 days ago go into Drive's trash – Drive 1.5
   * ('deleteAfter') does that itself (a list of an older version goes there with the time left);
   * a file back on the PC calls the delete off.
   */
  async _expirePending(ctx) {
    const { f, st } = ctx;
    if (f.mode !== 'backup') { st.pending = {}; ctx.rt.pendingUntil = null; return; }
    const limit = S.BACKUP_DELETE_DAYS * DAY;
    const keys = Object.keys(st.pending).sort((a, b) => a.length - b.length);
    for (const k of keys) {
      const p = st.pending[k];
      if (!p) continue;
      const b = st.base[k];
      if (!b || await this._stat(this._abs(ctx, b.path))) {
        // back on the PC: Drive calls its delete off (a new version did that already)
        if (b && p.server && p.nodeId && !(ctx.uploaded && ctx.uploaded.has(k))) {
          this._check(f);
          try { await this.api.unmark(p.nodeId); } catch (err) { if (!(err && err.status === 404)) throw err; }
        }
        delete st.pending[k];
        continue;
      }
      if (p.server) continue; // Drive moves it into the trash at deleteAt (change log: delete)
      const left = limit - (this.now() - p.at);
      if (left > 0) {
        // an older version kept the list: Drive keeps the time from now on
        if (ctx.deleteAfter && p.nodeId) {
          this._check(f);
          const r = await this._markRemote(p.nodeId, left / 1000);
          if (r) Object.assign(p, { server: true, deleteAt: r.deleteAt });
          else this._forget(ctx, k);
        }
        continue;
      }
      this._check(f);
      const node = st.tree && st.tree[p.nodeId];
      if (node && (b.dir || node.rev === b.rev)) {
        try { await this.api.trash(p.nodeId); } catch (err) { if (!(err && err.status === 404)) throw err; }
        S.dropSubtree(st.tree, p.nodeId);
      }
      this._forget(ctx, k);
    }
    const all = Object.values(st.pending);
    ctx.rt.pendingDeletes = all.length;
    ctx.rt.pendingUntil = all.length ? Math.min(...all.map((p) => p.deleteAt || p.at + limit)) : null;
  }

  /** Another run soon (a file still being written, a conflict copy to upload). */
  _later(id) {
    if (this._debounce.has(id)) return;
    const t = setTimeout(() => { this._debounce.delete(id); this.sync(id, { full: false }); }, Math.max(this.timing.watchMs, this.timing.settleMs + 500));
    if (t.unref) t.unref();
    this._debounce.set(id, t);
  }
}

function freshState(scope) {
  return { v: 1, scope: scope || null, rootId: null, cursor: null, tree: null, base: {}, pending: {}, quarantine: {}, lastSyncAt: null, reassert: false };
}

const entOf = (v) => (Number.isFinite(v) && v >= 0 && v <= 8 ? v : null);

/** A state file → state, or null when it is not one. */
function parseState(raw) {
  if (!raw || typeof raw !== 'object' || raw.v !== 1) return null;
  const st = freshState(typeof raw.scope === 'string' ? raw.scope : null);
  st.rootId = drive.posId(raw.rootId);
  st.cursor = drive.count(raw.cursor);
  st.lastSyncAt = drive.msOf(raw.lastSyncAt);
  st.reassert = raw.reassert === true;
  if (raw.tree && typeof raw.tree === 'object') {
    st.tree = {};
    for (const [id, n] of Object.entries(raw.tree)) {
      if (n && drive.posId(n.id) === Number(id) && typeof n.name === 'string') st.tree[id] = { id: n.id, parentId: drive.posId(n.parentId), name: n.name, isDir: n.isDir === true, size: drive.count(n.size) || 0, sha256: drive.sha256Of(n.sha256), rev: drive.count(n.rev) || 0, mtime: drive.msOf(n.mtime) };
    }
  }
  for (const [k, e] of Object.entries(raw.base && typeof raw.base === 'object' ? raw.base : {})) {
    if (!e || typeof e.path !== 'string' || S.keyOf(e.path) !== k) continue;
    st.base[k] = { path: e.path, dir: e.dir === true, size: drive.count(e.size) || 0, mtime: drive.count(e.mtime) || 0, sha256: drive.sha256Of(e.sha256), nodeId: drive.posId(e.nodeId), rev: drive.count(e.rev) || 0, ent: entOf(e.ent) };
  }
  for (const [k, p] of Object.entries(raw.pending && typeof raw.pending === 'object' ? raw.pending : {})) {
    if (p && drive.msOf(p.at) && st.base[k]) st.pending[k] = { at: drive.msOf(p.at), nodeId: drive.posId(p.nodeId), path: st.base[k].path, dir: p.dir === true, server: p.server === true, deleteAt: drive.msOf(p.deleteAt) };
  }
  for (const [k, q] of Object.entries(raw.quarantine && typeof raw.quarantine === 'object' ? raw.quarantine : {})) {
    if (q && drive.count(q.size) !== null && drive.count(q.mtime) !== null && k.length <= 4096) st.quarantine[k] = { size: q.size, mtime: q.mtime };
  }
  if (!st.rootId) { st.tree = null; st.cursor = null; }
  return st;
}

/** The keys of `map` below `fromKey` rewritten to below `toPath`. */
function rebaseMap(map, fromKey, toPath) {
  const out = new Map();
  const toKey = S.keyOf(toPath);
  for (const [k, e] of map) {
    if (!S.under(k, fromKey)) { out.set(k, e); continue; }
    out.set(toKey + k.slice(fromKey.length), { ...e, path: toPath + e.path.slice(fromKey.length) });
  }
  return out;
}

/** SHA-256 of a file (hex), streamed. */
function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(p);
    s.on('error', reject);
    s.on('data', (c) => h.update(c));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

DriveSync.STORE_KEY = STORE_KEY;
DriveSync.DEFAULT_TIMING = DEFAULT_TIMING;
DriveSync.parseState = parseState;

module.exports = DriveSync;
