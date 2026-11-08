'use strict';

/**
 * GateControl – Notizen & Aufgaben (Core service)
 *
 * The data side of the page "Notizen & Aufgaben" in the Windows Pro app (plugin `gatecontrol-notizen` 1.0.0, README
 * "API"), over the device token of the existing ApiClient (services/notes-api.js):
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins lists `gatecontrol-notizen` (a plugin that
 *   needs a licence and has none is not listed) and `GET me` lets the person in (403 / 404 → no page). Asked at start,
 *   every 30 min, after a push reconnect and on check(); network errors are retried (5 s … 5 min). status().features
 *   are `me.features` of the plugin (tasks, notes, sources, vault, mstodo, dsnote, search, …); what the person may use
 *   besides (vaults, imports) comes with me().
 * - Tasks and items: the menu (nav), the views (Mein Tag, Wichtig, Geplant, Mir zugewiesen, a list, a source), the quick
 *   entry (POST tasks { text } — the server reads it with the plugin's ui/quickparse.js), a task with its sub tasks,
 *   ticking off (an item of another plugin is ticked off there), lists, groups, sharing, „Quellen“.
 * - Notes: notebooks, notes (Markdown), check boxes, a line → a task, attachments (files of this PC, uploaded; pictures
 *   of a note as bytes for the page; opened from %TEMP%\gatecontrol-notizen or saved where the person picks). A picture
 *   gets the text Windows recognises in it (Windows.Media.Ocr, when an OCR language is there) for the search.
 * - Tresor notebooks (services/notes-vault.js — Drive's vault format with "gcnotes-v1"): names, titles, texts and
 *   attachments en- and decrypted here only; the lock (services/drive-vault-lock.js with its own settings
 *   `notesVaultLock`): Windows Hello before the keys are unwrapped, locked after 15 minutes without use, when the window
 *   is hidden, when Windows locks or sleeps, on a server change.
 * - Moving over: Microsoft To Do through the Microsoft account of GateControl Mail (device code: the code is shown, the
 *   page opens Microsoft's page in the browser), DS Note: the .nsx export read on this PC (services/notes-import.js).
 * - Live: the plugin's realtime events `changed` { what } → 'changed', `vault` { vault, event } → 'vault'; a click on a
 *   push of the plugin (topics reminders / shared / vault, data.notizen) opens the page (NotificationCenter.addClickRoute).
 *
 * Events: 'state' (status()), 'changed' ({ what }), 'vault' ({ vault, event }), 'vaultLock' ({ locked, reason }),
 * 'import' (the DS Note import: { state, done, total, notes, skipped, protectedSkipped, vault?, code? }).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const NotesApi = require('./notes-api');
const NotesVault = require('./notes-vault');
const DriveVaultLock = require('./drive-vault-lock');
const MessengerApi = require('./messenger-api');
const { openNsx, runImport, ImportError } = require('./notes-import');
const N = require('../utils/notes');
const { guessMime } = require('../utils/gatedrop');
const { unsafeToOpen, safeFileName } = require('../utils/messenger');
const { openExternalSafely } = require('../utils/external-url');
const { dialogPath: defaultDialogPath } = require('../utils/user-folders');

const { MessengerError: NotesError } = MessengerApi;
const NV = NotesVault.crypto;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,
  retryMinMs: 5000,
  retryMaxMs: 5 * 60 * 1000,
  minuteMs: 60 * 1000,      // the vault lock's minutes
};
const MAX_PATHS = 20;
const OCR_MAX_BYTES = 12 * 1024 * 1024;
const OCR_MIME_RE = /^image\/(jpeg|png|bmp|gif|tiff)$/;
// Microsoft's device-code pages (Mail 1.12.0 ms_tasks_consent): only these open in the browser
const VERIFY_HOSTS = ['microsoft.com', 'www.microsoft.com', 'login.microsoft.com', 'login.microsoftonline.com', 'aka.ms', 'login.live.com'];
const LOCK_TEXTS = Object.freeze({
  label: 'Notizen vaults',
  de: { unlock: 'GateControl Notizen: Tresor-Notizbücher entsperren', settings: 'GateControl Notizen: Tresore ohne Windows Hello öffnen' },
  en: { unlock: 'GateControl Notes: unlock vault notebooks', settings: 'GateControl Notes: open vaults without Windows Hello' },
});

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class NotesService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.api] - NotesApi (tests)
   * @param {object} [opts.store] - electron-store (the Tresor device keys under DPAPI, the lock's settings)
   * @param {object} [opts.protect] - { available(), encrypt(buf), decrypt(buf) } (safeStorage); without it no Tresor here
   * @param {object} [opts.shell] - Electron shell (open attachments, Microsoft's page)
   * @param {object} [opts.dialog] - Electron dialog (pick files and the .nsx export, "Speichern unter")
   * @param {() => object} [opts.getMainWindow]
   * @param {() => string} [opts.tempDir] - opened attachments and the import's uploads (%TEMP%\gatecontrol-notizen)
   * @param {() => string} [opts.getLang]
   * @param {() => string} [opts.deviceName] - the name other devices see at a Tresor ("Desktop-PC")
   * @param {object} [opts.pushClient] - live events; a reconnect asks for the plugin again
   * @param {object} [opts.notificationCenter] - a click on a push of the plugin opens the page
   * @param {object|null} [opts.consent] - Windows Hello as the confirmation before the Tresore unlock (createConsentVerifier)
   * @param {object} [opts.powerMonitor] - the Tresore lock when Windows locks or sleeps
   * @param {object|null} [opts.ocr] - the text recognition of Windows (windowsOcr.createWindowsOcr()) for pictures
   * @param {Function} [opts.dialogPath] - utils/user-folders dialogPath
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({
    apiClient, log, api = null, store = null, protect = null, shell = null, dialog = null, getMainWindow = null, tempDir = null,
    getLang = null, deviceName = null, pushClient = null, notificationCenter = null, consent, powerMonitor = null, ocr = null,
    dialogPath = null, timing = {}, now = Date.now,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new NotesApi({ apiClient, log: this.log });
    this.shell = shell;
    this.dialog = dialog;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.tempDir = typeof tempDir === 'function' ? tempDir : () => path.join(os.tmpdir(), 'gatecontrol-notizen');
    this.getLang = typeof getLang === 'function' ? getLang : () => 'de';
    this.pushClient = pushClient;
    this.notificationCenter = notificationCenter;
    this.ocr = ocr && typeof ocr.recognize === 'function' ? ocr : null;
    this.dialogPath = typeof dialogPath === 'function' ? dialogPath : defaultDialogPath;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;

    this.vaultLock = new DriveVaultLock({
      consent, store, powerMonitor, getWindow: () => { const w = this.getMainWindow(); return w && typeof w.getNativeWindowHandle === 'function' ? w.getNativeWindowHandle() : null; },
      getLang: this.getLang, hasKeys: () => this.vault.hasKeys(), timing: { minuteMs: this.timing.minuteMs }, log: this.log,
      storeKey: 'notesVaultLock', defaults: { hello: true, autoLockMinutes: 15, lockOnLeave: true }, texts: LOCK_TEXTS,
    });
    this.vaultLock.on('lock', (e) => this._onVaultLock(e));
    this.vaultLock.on('unlock', () => this.emit('vaultLock', { locked: false, reason: null }));
    this.vault = new NotesVault({ api: this.api, store, protect, scope: () => this._scopeNow(), deviceName, log: this.log, now, isUnlocked: () => this.vaultLock.isUnlocked() });

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._me = null;
    this._nbVault = new Map();   // notebook id → vault id (Tresor notebooks seen in nav / notebooks)
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._nsx = null;            // the .nsx export picked: { archive, summary, close }
    this._import = null;         // { signal } while an import runs
    this._scope = this._scopeNow();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    this.vaultLock.start();
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onHello = () => {
        if (this._state.state !== 'available') { this.check().catch(() => {}); return; }
        this.emit('changed', N.changedOf({}));
      };
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== N.PLUGIN_ID) return;
        const d = ev.data.data && typeof ev.data.data === 'object' ? ev.data.data : {};
        if (ev.data.type === 'changed') this.emit('changed', N.changedOf(d));
        else if (ev.data.type === 'vault') {
          const vid = N.vaultIdOf(d.vault);
          if (!vid) return;
          this.vault.onEvent({ vault: vid, event: d.event });
          this.emit('vault', { vault: vid, event: d.event === 'request' || d.event === 'approved' ? d.event : null });
        }
      };
      pc.on('hello', onHello);
      pc.on('event', onEvent);
      this._unsub.push(() => { pc.removeListener('hello', onHello); pc.removeListener('event', onEvent); });
    }
    const nc = this.notificationCenter;
    if (nc && typeof nc.addClickRoute === 'function') {
      this._unsub.push(nc.addClickRoute(N.APP_ROUTE, (entry) => this.clickContext(entry)));
    }
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    this._timer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    this.vaultLock.stop();
    this.dsCancel();
    this._closeNsx();
  }

  /** A click on a push of the plugin while the page exists → the target (utils/notes.js pushTarget) or null. */
  clickContext(entry) {
    if (!this.available() || !entry || typeof entry !== 'object') return null;
    return N.pushTarget(entry.topic, entry.data);
  }

  /** server:setup: the old server's state, its keys and the export picked go, the new one is asked. */
  resetForNewServer() {
    this.vaultLock.lock('server');
    this.vault.clear();
    this.dsCancel();
    this._closeNsx();
    this._me = null;
    this._nbVault.clear();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /** { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt, features, vaultSupported } */
  status() {
    return { ...this._state, features: this._me ? [...this._me.features] : [], vaultSupported: this.vault.supported() };
  }

  available() {
    return this._state.state === 'available';
  }

  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    this._ensureScope();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    const gone = (reason) => {
      this._retry = 0;
      this._me = null;
      this._setState({ state: 'unavailable', reason, version: null, checkedAt: this.now() });
    };
    try {
      const p = await this.api.plugin();
      if (!p) {
        gone('not_installed');
      } else {
        const version = typeof p.version === 'string' ? p.version.slice(0, 40) : null;
        try {
          this._me = await this.api.me();
          this._retry = 0;
          this._setState({ state: 'available', reason: null, version, checkedAt: this.now() });
        } catch (err) {
          if (err && (err.status === 403 || err.status === 404)) gone(err.status === 403 ? 'forbidden' : 'not_found');
          else throw err;
        }
      }
    } catch (err) {
      if (err && err.status === 404) gone('unsupported');
      else if (err && err.status === 401) gone('auth');
      else if (err && err.code === 'not_configured') gone('not_configured');
      else {
        const keep = this._state.state === 'available';
        this._setState({ ...this._state, state: keep ? 'available' : 'error', reason: (err && err.code) || 'network', checkedAt: this.now() });
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._started) {
      this._timer = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timer.unref) this._timer.unref();
    }
    return this.status();
  }

  _setState(s) {
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    const k = JSON.stringify([this._state.state, this._state.reason, this._state.version, this._me ? this._me.features : null]);
    if (k !== this._stateKey) {
      this._stateKey = k;
      this.emit('state', this.status());
    }
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._me = null;
    this._nbVault.clear();
    this.vault.clear();
    this.vaultLock.lock('server');
  }

  async _run(fn) {
    if (!this.available() && this._state.state !== 'error') throw new NotesError('Notizen & Aufgaben is not available', { code: 'unavailable' });
    this._ensureScope();
    try {
      return await fn();
    } catch (err) {
      const e = err instanceof NotesError ? err : (err instanceof ImportError || (err && err.name === 'DriveVaultError') ? new NotesError(err.message, { code: err.code }) : MessengerApi.toMessengerError(err));
      if ((e.status === 404 && /^http_/.test(e.code)) || e.status === 401) this.check().catch(() => {});
      throw e;
    }
  }

  _feature(name) {
    if (this._me && !this._me.features.includes(name)) throw new NotesError(`${name} is not offered by the plugin`, { code: 'unsupported' });
  }

  // ── the person, the menu, the views ──────────────────────

  /** GET me (cached from the check; `refresh` asks again) → { ok, me } */
  async me({ refresh = false } = {}) {
    return this._run(async () => {
      if (refresh || !this._me) this._me = await this.api.me();
      return { ok: true, me: this._me, vaultSupported: this.vault.supported() };
    });
  }

  /** Tresor notebooks of a list of notebooks: the vault map and their names when the keys are here. */
  async _tresorNames(notebooks) {
    const tresors = notebooks.filter((b) => b.vault);
    for (const b of tresors) this._nbVault.set(b.id, b.vault.id);
    if (tresors.length && this.vault.supported() && this.vaultLock.isUnlocked()) {
      let dev = null;
      try { dev = await this.vault.device({ create: false }); } catch { dev = null; }
      if (dev) for (const b of tresors) await this.vault.tryOpen(b.vault.id);
    }
    for (const b of tresors) {
      b.name = this.vault.notebookName(b);
      b.locked = !this.vault.isOpen(b.vault.id);
    }
    return notebooks;
  }

  async nav({ area } = {}) {
    return this._run(async () => {
      const n = await this.api.nav(N.areaOf(area) || 'private');
      await this._tresorNames(n.notes.notebooks);
      return { ok: true, nav: n };
    });
  }

  async view({ name, area } = {}) {
    return this._run(async () => ({ ok: true, view: await this.api.view(name, N.areaOf(area) || undefined) }));
  }

  async parse({ text, area } = {}) {
    return this._run(async () => ({ ok: true, parsed: await this.api.parse(text, N.areaOf(area) || undefined) }));
  }

  async people() {
    return this._run(async () => ({ ok: true, people: await this.api.people() }));
  }

  async search({ q, area } = {}) {
    return this._run(async () => {
      this._feature('search');
      const r = await this.api.search(q, N.areaOf(area) || undefined);
      await this._noteTitles(r.notes);
      return { ok: true, ...r };
    });
  }

  async prefs() {
    return this._run(async () => ({ ok: true, prefs: await this.api.prefs() }));
  }

  async setPrefs(patch) {
    return this._run(async () => {
      const prefs = await this.api.setPrefs(patch);
      if (this._me) this._me.prefs = prefs;
      return { ok: true, prefs };
    });
  }

  async sources() {
    return this._run(async () => ({ ok: true, sources: await this.api.sources() }));
  }

  async syncSource(plugin) {
    return this._run(async () => ({ ok: true, ...(await this.api.syncSource(plugin)) }));
  }

  // ── lists and groups ─────────────────────────────────────

  async lists({ area } = {}) { return this._run(async () => ({ ok: true, ...(await this.api.lists(N.areaOf(area) || undefined)) })); }

  async createList(body) { return this._run(async () => ({ ok: true, list: await this.api.createList(body) })); }

  async updateList(id, body) { return this._run(async () => ({ ok: true, list: await this.api.updateList(id, body) })); }

  async deleteList(id) { return this._run(async () => ({ ok: true, ...(await this.api.deleteList(id)) })); }

  async setListMembers(id, members) { return this._run(async () => ({ ok: true, list: await this.api.setListMembers(id, members) })); }

  async createGroup(body) { return this._run(async () => ({ ok: true, group: await this.api.createGroup(body) })); }

  async updateGroup(id, body) { return this._run(async () => { await this.api.updateGroup(id, body); return { ok: true }; }); }

  async deleteGroup(id) { return this._run(async () => { await this.api.deleteGroup(id); return { ok: true }; }); }

  // ── tasks and items ──────────────────────────────────────

  async createTask(body) { return this._run(async () => ({ ok: true, ...(await this.api.createTask(body)) })); }

  async task(id) { return this._run(async () => ({ ok: true, task: await this.api.task(id) })); }

  async updateTask(id, body) { return this._run(async () => ({ ok: true, task: await this.api.updateTask(id, body) })); }

  async completeTask(id, done) { return this._run(async () => ({ ok: true, ...(await this.api.completeTask(id, done)) })); }

  async deleteTask(id) { return this._run(async () => { await this.api.deleteTask(id); return { ok: true }; }); }

  async item(id) { return this._run(async () => ({ ok: true, ...(await this.api.item(id)) })); }

  async completeItem(id, done) { return this._run(async () => ({ ok: true, ...(await this.api.completeItem(id, done)) })); }

  async carryItem(id) { return this._run(async () => ({ ok: true, task: await this.api.carryItem(id) })); }

  // ── notebooks ────────────────────────────────────────────

  async notebooks({ area } = {}) {
    return this._run(async () => {
      const r = await this.api.notebooks(N.areaOf(area) || undefined);
      await this._tresorNames(r.notebooks);
      return { ok: true, ...r };
    });
  }

  /** A new notebook; `vault: true` makes a Tresor notebook here → { ok, notebook, recoveryKey? } (the key shown once). */
  async createNotebook({ name, area, color, vault = false } = {}) {
    return this._run(async () => {
      const a = N.areaOf(area) || 'private';
      if (vault) {
        this._feature('vault');
        if (this._me && this._me.vaults === false) throw new NotesError('vaults are switched off', { code: 'forbidden' });
        if (!this.vault.supported()) throw new NotesError('no protected key storage', { code: 'vault_unsupported' });
        const r = await this.vault.create(a, name);
        this._nbVault.set(r.notebook.id, r.vault.id);
        this.vaultLock.touch();
        return { ok: true, notebook: { ...r.notebook, locked: false }, vault: r.vault, recoveryKey: r.recoveryKey };
      }
      return { ok: true, notebook: await this.api.createNotebook({ name, area: a, ...(color ? { color } : {}) }) };
    });
  }

  /** { name?, color?, area?, position? } — a Tresor notebook's new name is encrypted here (nameCipher). */
  async updateNotebook(id, patch = {}) {
    return this._run(async () => {
      const vid = await this._vaultOfNotebook(id);
      const body = {};
      if (patch.color !== undefined) body.color = patch.color;
      if (patch.area !== undefined) body.area = patch.area;
      if (patch.position !== undefined) body.position = patch.position;
      if (patch.name !== undefined) {
        if (vid) {
          const c = this.vault.encryptName(vid, patch.name);
          body.nameCipher = c.nameCipher;
          this.vaultLock.touch();
        } else body.name = patch.name;
      }
      const nb = await this.api.updateNotebook(id, body);
      if (nb) await this._tresorNames([nb]);
      return { ok: true, notebook: nb };
    });
  }

  async deleteNotebook(id) { return this._run(async () => ({ ok: true, ...(await this.api.deleteNotebook(id)) })); }

  async setNotebookMembers(id, members) { return this._run(async () => ({ ok: true, notebook: await this.api.setNotebookMembers(id, members) })); }

  /** The vault id of a Tresor notebook (null for a plain one); unknown notebooks: both areas are asked once. */
  async _vaultOfNotebook(notebookId) {
    const id = N.posId(notebookId);
    if (!id) return null;
    if (this._nbVault.has(id)) return this._nbVault.get(id);
    if (!this._nbSeen || !this._nbSeen.has(id)) {
      for (const area of N.AREAS) {
        const r = await this.api.notebooks(area);
        this._nbSeen = this._nbSeen || new Set();
        for (const b of r.notebooks) {
          this._nbSeen.add(b.id);
          if (b.vault) this._nbVault.set(b.id, b.vault.id);
        }
      }
    }
    return this._nbVault.get(id) || null;
  }

  // ── notes ────────────────────────────────────────────────

  /** The keys of a Tresor here — opened quietly when this PC has a key and the Tresore are unlocked — or null. */
  async _keysOf(vid) {
    if (!vid) return null;
    const have = this.vault.keysOf(vid);
    if (have || !this.vault.supported() || !this.vaultLock.isUnlocked()) return have;
    await this.vault.tryOpen(vid);
    return this.vault.keysOf(vid);
  }

  /** The titles of Tresor notes decrypted when their keys are here (`locked` otherwise). */
  async _noteTitles(list) {
    for (const n of list) {
      if (!n.encrypted) continue;
      const vid = await this._vaultOfNotebook(n.notebookId);
      const keys = await this._keysOf(vid);
      n.vaultId = vid;
      n.locked = !keys;
      if (keys && n.titleCipher) { try { n.title = NV.decryptName(keys, vid, n.titleCipher); } catch { n.title = null; } }
    }
    return list;
  }

  async notes(query = {}) {
    return this._run(async () => {
      const r = await this.api.notes(query);
      if (query.notebook) {
        const vid = await this._vaultOfNotebook(query.notebook);
        if (vid && this.vault.keysOf(vid)) this.vaultLock.touch();
      }
      await this._noteTitles(r.notes);
      return { ok: true, ...r };
    });
  }

  /** A note; a Tresor note decrypted (title, body, attachment names) when its keys are here, else `locked`. */
  async _plain(n) {
    if (!n.encrypted) return n;
    const vid = await this._vaultOfNotebook(n.notebookId);
    const keys = await this._keysOf(vid);
    n.vaultId = vid;
    n.locked = !keys;
    if (!keys) return n;
    this.vaultLock.touch();
    n.title = n.titleCipher ? NV.decryptName(keys, vid, n.titleCipher) : '';
    n.body = n.cipher ? NV.decryptBuffer(keys, vid, Buffer.from(n.cipher, 'base64url')).toString('utf8') : '';
    n.cipher = null;
    for (const a of n.attachments) {
      if (a.encrypted && a.nameCipher) { try { a.name = NV.decryptName(keys, vid, a.nameCipher); } catch { a.name = null; } }
      if (a.encrypted && a.name) a.mime = guessMime(a.name);
    }
    return n;
  }

  async note(id) {
    return this._run(async () => ({ ok: true, note: await this._plain(await this.api.note(id)) }));
  }

  /** { titleCipher, cipher, keyVersion } of a Tresor note's title and Markdown under the current key. */
  _sealNote(vid, cur, title, body) {
    return {
      titleCipher: NV.encryptName(cur.tk, vid, cur.keyVersion, String(title || '').trim().slice(0, 300) || (this.getLang() === 'en' ? 'Untitled' : 'Ohne Titel')),
      cipher: NV.encryptBuffer(cur.tk, vid, cur.keyVersion, Buffer.from(String(body || ''), 'utf8')).toString('base64url'),
      keyVersion: cur.keyVersion,
    };
  }

  /** POST notes { notebookId?, area?, title?, body?, pinned?, color? } (a Tresor notebook: encrypted here). */
  async createNote(input = {}) {
    return this._run(async () => {
      const vid = await this._vaultOfNotebook(input.notebookId);
      if (vid) {
        this.vault.keys(vid);
        const n = await this.vault.withCurrent(vid, (cur) => this.api.createNote({ notebookId: input.notebookId, ...this._sealNote(vid, cur, input.title, input.body) }));
        return { ok: true, note: await this._plain(n) };
      }
      const body = { title: input.title || '', body: input.body || '' };
      if (input.notebookId) body.notebookId = input.notebookId;
      else body.area = N.areaOf(input.area) || 'private';
      if (input.pinned === true) body.pinned = true;
      if (input.color) body.color = input.color;
      return { ok: true, note: await this.api.createNote(body) };
    });
  }

  /**
   * PATCH notes/<id> — a plain note: { title?, body?, pinned?, color?, due?, expiresAt?, notebookId?, rev? } (a stale
   * rev → 409 conflict); a Tresor note: title and body encrypted here (the other one kept), pinned / color as they are.
   */
  async updateNote(id, patch = {}) {
    return this._run(async () => {
      const cur0 = await this.api.note(id);
      if (!cur0.encrypted) return { ok: true, note: await this.api.updateNote(id, patch) };
      const n = await this._plain(cur0);
      if (n.locked) throw new NotesError('vault is locked', { code: 'vault_locked' });
      const body = {};
      if (patch.pinned !== undefined) body.pinned = patch.pinned;
      if (patch.color !== undefined) body.color = patch.color;
      const title = patch.title !== undefined ? patch.title : n.title;
      const text = patch.body !== undefined ? patch.body : n.body;
      const out = await this.vault.withCurrent(n.vaultId, (cur) => this.api.updateNote(id, { ...body, ...this._sealNote(n.vaultId, cur, title, text) }));
      return { ok: true, note: await this._plain(out) };
    });
  }

  async deleteNote(id) { return this._run(async () => { await this.api.deleteNote(id); return { ok: true }; }); }

  /** A check box of the text (a Tresor note: changed and encrypted here). */
  async checkNote(id, line, done) {
    return this._run(async () => {
      const n0 = await this.api.note(id);
      if (!n0.encrypted) return { ok: true, note: await this.api.checkNote(id, line, done) };
      const n = await this._plain(n0);
      if (n.locked) throw new NotesError('vault is locked', { code: 'vault_locked' });
      const md = N.toggleCheck(n.body, line, done);
      if (md === null) throw new NotesError('no check box on that line', { code: 'invalid' });
      const out = await this.vault.withCurrent(n.vaultId, (cur) => this.api.updateNote(id, this._sealNote(n.vaultId, cur, n.title, md)));
      return { ok: true, note: await this._plain(out) };
    });
  }

  async noteToTask(id, body) { return this._run(async () => ({ ok: true, ...(await this.api.noteToTask(id, body)) })); }

  // ── attachments ──────────────────────────────────────────

  /** File dialog → { ok, paths } | { ok: false, code: 'cancelled' } */
  async pickFiles({ images = false } = {}) {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new NotesError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const start = this.dialogPath(images ? 'pictures' : 'documents');
    const opts = { properties: ['openFile', 'multiSelections'], ...(start ? { defaultPath: start } : {}), ...(images ? { filters: [{ name: 'Bilder', extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'bmp'] }] } : {}) };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, paths: r.filePaths.slice(0, MAX_PATHS) };
  }

  /**
   * Files of this PC to a note or a task → { ok, attachments, rejected: [{ name, code }] }. Without `paths` the file
   * dialog asks (`images`: pictures only). A Tresor note's files are encrypted here first (their name too).
   */
  async addAttachments({ kind, refId, paths = null, images = false } = {}) {
    return this._run(async () => {
      this._feature('attachments');
      let list = paths;
      if (!list) {
        const p = await this.pickFiles({ images });
        if (!p.ok) return p;
        list = p.paths;
      }
      const me = this._me || (await this.me()).me;
      const maxBytes = me.attachMB * 1048576;
      let vid = null;
      if (kind === 'note') {
        const n = await this.api.note(refId);
        vid = n.encrypted ? await this._vaultOfNotebook(n.notebookId) : null;
        if (vid) this.vault.keys(vid);
      }
      const attachments = [];
      const rejected = [];
      for (const p of list.slice(0, MAX_PATHS)) {
        if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p)) continue;
        const name = safeFileName(path.basename(p), 'Datei');
        let st;
        try { st = await fs.promises.stat(p); } catch { rejected.push({ name, code: 'missing' }); continue; }
        if (!st.isFile()) { rejected.push({ name, code: 'missing' }); continue; }
        if (st.size <= 0) { rejected.push({ name, code: 'empty' }); continue; }
        if (st.size > maxBytes) { rejected.push({ name, code: 'too_large' }); continue; }
        try {
          if (vid) {
            const a = await this.vault.withCurrent(vid, async (cur) => {
              const tmp = path.join(this.tempDir(), 'up', crypto.randomBytes(8).toString('hex'));
              await fs.promises.mkdir(path.dirname(tmp), { recursive: true });
              try {
                const enc = await NV.encryptFile(cur.tk, vid, cur.keyVersion, p, tmp);
                const up = await this.api.upload({ path: tmp, size: enc.cipherSize, mime: 'application/octet-stream' });
                return this.api.addAttachment({ kind, refId, mediaId: up.mediaId, nameCipher: NV.encryptName(cur.tk, vid, cur.keyVersion, name) });
              } finally {
                await fs.promises.rm(tmp, { force: true }).catch(() => {});
              }
            });
            attachments.push({ ...a, name, mime: guessMime(name) });
            this.vaultLock.touch();
          } else {
            const mime = guessMime(name);
            const up = await this.api.upload({ path: p, size: st.size, mime });
            const a = await this.api.addAttachment({ kind, refId, mediaId: up.mediaId, name });
            attachments.push(a);
            this._ocrLater(a, p, mime, st.size);
          }
        } catch (err) {
          rejected.push({ name, code: N.errorCode(err) });
        }
      }
      return { ok: true, attachments, rejected };
    });
  }

  /** The text Windows reads in a picture → PUT attachments/<id>/text (for the search; best effort, in the background). */
  _ocrLater(a, file, mime, size) {
    if (!this.ocr || !a || !OCR_MIME_RE.test(mime) || size > OCR_MAX_BYTES || (this._me && !this._me.features.includes('ocrText'))) return;
    (async () => {
      const av = await Promise.resolve(this.ocr.available()).catch(() => null);
      if (!av || !av.available) return;
      const r = await this.ocr.recognize(await fs.promises.readFile(file));
      const text = r && typeof r.text === 'string' ? r.text.trim() : '';
      if (text) await this.api.setAttachmentText(a.id, text.slice(0, 100000));
    })().catch((err) => this.log.debug(`Notizen OCR: ${err && (err.code || err.message)}`));
  }

  /** A fresh attachment (its signed url) and, for a Tresor's, its keys → { a, vid, keys } */
  async _attachment(id, vaultId) {
    const a = await this.api.attachment(id);
    if (!a || !a.url) throw new NotesError('attachment not available', { code: 'not_found' });
    if (!a.encrypted) return { a, vid: null, keys: null };
    const vid = N.vaultIdOf(vaultId);
    if (!vid) throw new NotesError('vault needed', { code: 'invalid' });
    const keys = this.vault.keys(vid);
    a.name = a.nameCipher ? NV.decryptName(keys, vid, a.nameCipher) : null;
    a.mime = guessMime(a.name || '');
    this.vaultLock.touch();
    return { a, vid, keys };
  }

  /** A picture of a note → { ok, mime, data } (a Tresor's decrypted here; ≤ 16 MB). */
  async attachmentImage(id, { vaultId = null } = {}) {
    return this._run(async () => {
      const { a, vid, keys } = await this._attachment(id, vaultId);
      const r = await this.api.mediaBytes(a.url);
      let data = r.data;
      let mime = r.mime;
      if (vid) { data = NV.decryptBuffer(keys, vid, data); mime = a.mime; }
      if (!/^image\/(jpeg|png|gif|webp|bmp)$/.test(mime)) throw new NotesError('not a picture', { code: 'not_picture' });
      return { ok: true, mime, data };
    });
  }

  /** Writes an attachment (decrypted) to `dest`. */
  async _attachmentFile(a, vid, keys, dest) {
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    if (!vid) {
      const out = fs.createWriteStream(dest);
      try {
        await this.api.streamMedia(a.url, out);
      } catch (err) {
        out.destroy();
        await fs.promises.rm(dest, { force: true }).catch(() => {});
        throw err;
      }
      return;
    }
    const tmp = `${dest}.gcv`;
    const out = fs.createWriteStream(tmp);
    try {
      await this.api.streamMedia(a.url, out);
      await NV.decryptFile(keys, vid, tmp, dest);
    } catch (err) {
      out.destroy();
      await fs.promises.rm(dest, { force: true }).catch(() => {});
      throw err;
    } finally {
      await fs.promises.rm(tmp, { force: true }).catch(() => {});
    }
  }

  /** Opens an attachment in its program (from %TEMP%\gatecontrol-notizen; executables are never opened). */
  async openAttachment(id, { vaultId = null } = {}) {
    if (!this.shell || typeof this.shell.openPath !== 'function') throw new NotesError('no shell', { code: 'unsupported' });
    return this._run(async () => {
      const { a, vid, keys } = await this._attachment(id, vaultId);
      const fname = safeFileName(a.name || 'Anhang', 'Anhang');
      if (unsafeToOpen(fname, a.mime)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
      const file = path.join(this.tempDir(), `a${N.posId(id)}-${crypto.randomBytes(4).toString('hex')}`, fname);
      await this._attachmentFile(a, vid, keys, file);
      const err = await this.shell.openPath(file);
      if (err) return { ok: false, code: 'open_failed', error: String(err) };
      return { ok: true, path: file };
    });
  }

  /** "Speichern unter …" of an attachment. */
  async saveAttachment(id, { vaultId = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new NotesError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const { a, vid, keys } = await this._attachment(id, vaultId);
      const win = this.getMainWindow();
      const opts = { defaultPath: this.dialogPath('downloads', safeFileName(a.name || 'Anhang', 'Anhang')) };
      const res = win ? await this.dialog.showSaveDialog(win, opts) : await this.dialog.showSaveDialog(opts);
      if (!res || res.canceled || !res.filePath) return { ok: false, code: 'cancelled', cancelled: true };
      await this._attachmentFile(a, vid, keys, res.filePath);
      return { ok: true, path: res.filePath };
    });
  }

  async deleteAttachment(id) { return this._run(async () => { await this.api.deleteAttachment(id); return { ok: true }; }); }

  // ── Tresor notebooks ─────────────────────────────────────

  /** { ok, supported, device: { id, safetyNumber } | null, lock: { enforced, unlocked, settings, hello, choices, lastLock } } */
  async vaultStatus() {
    let device = null;
    if (this.vault.supported()) { try { device = await this.vault.device({ create: false }); } catch { device = null; } }
    return { ok: true, supported: this.vault.supported(), device: device ? { id: device.id, safetyNumber: device.safetyNumber } : null, lock: await this.vaultLock.status() };
  }

  /** Windows Hello, then the Tresore of this PC unlock; with `vaultId` that one opens → { ok, unlocked, state? } */
  async vaultUnlock(vaultId = null) {
    return this._run(async () => {
      await this.vaultLock.unlock();
      if (!vaultId) return { ok: true, unlocked: true };
      const r = await this.vault.open(vaultId, { fresh: true });
      return { ok: true, unlocked: true, state: r.state };
    });
  }

  vaultLockNow() {
    this.vaultLock.lock('manual');
    return { ok: true };
  }

  async vaultLockSettings(patch) {
    return { ok: true, ...(await this.vaultLock.setSettings(patch)) };
  }

  /** The window was hidden / minimized: "Beim Verlassen sperren". */
  windowHidden() {
    this.vaultLock.windowHidden();
  }

  _onVaultLock({ reason = 'manual' } = {}) {
    this.vault.forget();
    this.emit('vaultLock', { locked: true, reason });
  }

  /** A Tresor as the page shows it (its state on this PC, pending requests, a new key needed). */
  async vaultInfo(vaultId) {
    return this._run(async () => ({ ok: true, vault: this.vault.view(await this.api.vault(vaultId)) }));
  }

  /** Opens a Tresor on this PC → { ok, state: 'open' | 'locked' | 'pending' | 'none' | 'revoked' } */
  async vaultOpen(vaultId) {
    return this._run(async () => {
      if (!this.vault.supported()) return { ok: true, state: 'unsupported' };
      const r = await this.vault.open(vaultId);
      if (r.state === 'open') this.vaultLock.touch();
      return { ok: true, state: r.state };
    });
  }

  async vaultRequest(vaultId) { return this._run(async () => ({ ok: true, ...(await this.vault.request(vaultId)) })); }

  async vaultDevices(vaultId) { return this._run(async () => ({ ok: true, devices: await this.vault.devices(vaultId) })); }

  async vaultApprove(vaultId, deviceId, safetyNumber) {
    return this._run(async () => ({ ok: true, device: await this.vault.approve(vaultId, deviceId, safetyNumber) }));
  }

  async vaultDecline(vaultId, deviceId) { return this._run(async () => ({ ok: true, device: await this.vault.decline(vaultId, deviceId) })); }

  async vaultRecover(vaultId, text) {
    return this._run(async () => {
      const r = await this.vault.recover(vaultId, text);
      this.vaultLock.touch();
      return { ok: true, ...r };
    });
  }

  async vaultRotate(vaultId) { return this._run(async () => ({ ok: true, ...(await this.vault.rotate(vaultId)) })); }

  // ── Microsoft To Do ──────────────────────────────────────

  async msAccounts() { return this._run(async () => ({ ok: true, ...(await this.api.msAccounts()) })); }

  /** Microsoft's device code for the consent to To Do → { ok, deviceId, userCode, verificationUri, expiresIn, interval } */
  async msConsent(accountId) { return this._run(async () => ({ ok: true, ...(await this.api.msConsent(accountId)) })); }

  /** One poll of the consent → { ok, status: 'pending' | 'done' | 'expired' | 'denied' | 'failed' } */
  async msConsentPoll(accountId, deviceId) {
    return this._run(async () => {
      const r = await this.api.msConsent(accountId, deviceId);
      return { ok: true, status: r.status || 'pending' };
    });
  }

  /** Microsoft's device-code page in the default browser (only its own hosts). */
  async openVerification(uri) {
    let u;
    try { u = new URL(uri); } catch { return { ok: false, code: 'invalid' }; }
    if (u.protocol !== 'https:' || !VERIFY_HOSTS.includes(u.hostname.toLowerCase())) return { ok: false, code: 'invalid' };
    if (!this.shell || typeof this.shell.openExternal !== 'function') return { ok: false, code: 'unsupported' };
    const ok = await openExternalSafely(this.shell, u.href, { log: this.log, label: 'Notizen consent' });
    return ok ? { ok: true } : { ok: false, code: 'open_failed' };
  }

  async msPreview(accountId) { return this._run(async () => ({ ok: true, ...(await this.api.msPreview(accountId)) })); }

  async msStart(body) { return this._run(async () => ({ ok: true, job: await this.api.msStart(body) })); }

  async job(id) { return this._run(async () => ({ ok: true, job: await this.api.job(id) })); }

  async msLinks() { return this._run(async () => ({ ok: true, links: await this.api.msLinks() })); }

  async msUnlink(id) { return this._run(async () => { await this.api.msUnlink(id); return { ok: true }; }); }

  // ── DS Note ──────────────────────────────────────────────

  _closeNsx() {
    if (this._nsx) { this._nsx.close(); this._nsx = null; }
  }

  /**
   * The .nsx export (file dialog without `path`), read on this PC → { ok, file, size, notebooks: [{ id, title, notes,
   * protected }], notes, protectedNotes, attachments, bytes }.
   */
  async dsPick({ path: file = null } = {}) {
    return this._run(async () => {
      this._feature('dsnote');
      if (this._import) throw new NotesError('an import is running', { code: 'busy' });
      let p = file;
      if (!p) {
        if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new NotesError('no dialog', { code: 'unsupported' });
        const win = this.getMainWindow();
        const opts = { properties: ['openFile'], filters: [{ name: 'DS Note (.nsx)', extensions: ['nsx'] }], defaultPath: this.dialogPath('downloads') || undefined };
        const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
        if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', cancelled: true };
        p = r.filePaths[0];
      }
      if (typeof p !== 'string' || !path.isAbsolute(p)) throw new NotesError('invalid path', { code: 'invalid' });
      this._closeNsx();
      this._nsx = await openNsx(p);
      const s = this._nsx.summary;
      return {
        ok: true, file: s.file, size: s.size, notes: s.notes, protectedNotes: s.protectedNotes, attachments: s.attachments, bytes: s.bytes,
        notebooks: s.notebooks.map((b) => ({ id: b.id, title: b.title, notes: b.notes, protected: b.protected })),
      };
    });
  }

  /**
   * The import of the export picked, in the background → { ok, started } — progress, a Tresor made for protected notes
   * (its recovery key, shown once) and the end come as 'import' events.
   */
  async dsImport({ password = '', area = 'private' } = {}) {
    return this._run(async () => {
      this._feature('dsnote');
      if (!this._nsx) throw new NotesError('no export picked', { code: 'invalid' });
      if (this._import) throw new NotesError('an import is running', { code: 'busy' });
      const me = this._me || (await this.me()).me;
      const signal = { aborted: false };
      this._import = { signal };
      const nsx = this._nsx;
      const a = N.areaOf(area) || 'private';
      const total = nsx.summary.notes;
      this.emit('import', { state: 'running', done: 0, total, notes: 0, skipped: 0, protectedSkipped: 0 });
      runImport({
        archive: nsx.archive, summary: nsx.summary, api: this.api, area: a, password: typeof password === 'string' ? password : '',
        vault: this.vault.supported() && me.vaults !== false && me.features.includes('vault') ? this.vault : null,
        attachMB: me.attachMB, tmpDir: path.join(this.tempDir(), 'import'), signal,
        untitled: () => (this.getLang() === 'en' ? 'Untitled' : 'Ohne Titel'),
        onProgress: (p) => this.emit('import', { state: 'running', ...p }),
        onVault: (v) => { this.vaultLock.touch(); this.emit('import', { state: 'running', vault: v, done: null, total }); },
      }).then((r) => {
        this.emit('import', { state: 'done', done: total, total, notes: r.notes, skipped: r.skipped, protectedSkipped: r.protectedSkipped, vaults: r.vaults });
      }, (err) => {
        this.log.warn(`DS Note import: ${err && (err.code || err.message)}`);
        this.emit('import', { state: signal.aborted ? 'cancelled' : 'failed', code: N.errorCode(err) });
      }).finally(() => {
        if (this._import && this._import.signal === signal) this._import = null;
      });
      return { ok: true, started: true, total };
    });
  }

  dsCancel() {
    if (this._import) this._import.signal.aborted = true;
    return { ok: true };
  }
}

NotesService.DEFAULT_TIMING = DEFAULT_TIMING;
NotesService.VERIFY_HOSTS = VERIFY_HOSTS;

module.exports = NotesService;
