'use strict';

/**
 * GateControl – Drucken (Core service)
 *
 * The data side of the page "Drucken" in the Windows apps: printing on the
 * printers at home through the plugin `gatecontrol-print` (contract: the
 * plugin's README "API", plugin 1.1.1), over the device token of the
 * existing ApiClient. It uses the app's normal server connection — with or
 * without the VPN: the server hands the job to the gateway at home.
 *
 *   GET  /api/v1/client/plugins                      is the plugin there for the apps?
 *   GET  …/gatecontrol-print/api/overview            rights, pages left today, printers, the last 10 jobs
 *   PUT  …/gatecontrol-print/media                   the file (resumable like Drive) → { mediaId }
 *   POST …/api/print { deviceId, mediaId, copies, color, duplex, name, media?, source? } → { job, pagesLeft }
 *   GET  …/api/jobs/<id>                             one job, fresh (plugin ≥ 1.1.0; `expiresAt` / `doneAt` ≥ 1.1.1)
 *   POST …/api/jobs/<id>/cancel                      → { canceled }
 *
 * - Availability: the page exists while GET /api/v1/client/plugins lists
 *   `gatecontrol-print`. Asked at start, every 30 min, after a push
 *   reconnect and on check(); network errors are retried (5 s … 5 min). The
 *   rights of the person (print at all, pages a day, black and white only)
 *   are the plugin's: `overview` names them, the plugin checks every call.
 * - Files are never named by the page: it gets a token for a file the
 *   person picked in the file dialog (pick()), dropped on the window
 *   (addPaths() — the preload reads the paths from the dropped File objects)
 *   or chose in Drive (addDrive() — a vault file only after the person said
 *   yes: it leaves the vault decrypted). Each is checked here: a regular
 *   file, at most 50 MB, one of the plugin's types by name and content;
 *   files of Drive the virus scan blocks are refused. submit() takes tokens.
 * - A job in the making is a "transfer" (a Drive file is loaded, the file
 *   goes up, `POST print`): one at a time, with the upload's progress;
 *   `print_failed` right after the upload is asked twice more (the server's
 *   virus scan may still hold the file). Done, it becomes a job ('job').
 * - Older plugins are no error: without `jobs/<id>` (< 1.1.0) a job is read
 *   from the overview's last jobs; missing fields (paper, tray, `expiresAt`,
 *   `doneAt`) are simply not there (utils/print.js).
 * - `overview` is cached for a few seconds; a network error answers with
 *   the last copy (`stale: true`).
 * - Push: "Druck fertig" / "Druck fehlgeschlagen" drop the cache and emit
 *   'push'; with a NotificationCenter a click on their toast opens the page
 *   (addClickRoute → navigate { route: 'plg-gatecontrol-print', id,
 *   context: { type: 'print', kind, jobId } }) instead of the inbox.
 *
 * Events: 'state' (status()), 'push' ({ type, kind, jobId, notificationId }),
 * 'transfers' (transfers()), 'job' ({ job, pagesLeft, transferId }).
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const MessengerApi = require('./messenger-api');
const GateDropApi = require('./gatedrop-api');
const { PLUGINS_PATH, posInt } = require('../utils/messenger');
const SC = require('../utils/scan');
const print = require('../utils/print');
const { dialogPath: defaultDialogPath } = require('../utils/user-folders');

const { MessengerError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,    // available / unavailable: ask again
  retryMinMs: 5000,             // network errors: 5 s …
  retryMaxMs: 5 * 60 * 1000,    // … 5 min
  cacheTtlMs: 3000,             // an overview younger than this is served from memory
  printTimeoutMs: 60 * 1000,    // POST print (the server counts the pages first)
  printRetries: 2,              // print_failed right after the upload: asked again …
  printRetryMs: 4000,           // … after 4 s, 8 s
  tokenTtlMs: 60 * 60 * 1000,   // a picked file is kept this long for its dialog
};

const MAX_TOKENS = 200;
const MAX_SOURCES = 30;             // jobs whose file is remembered for "Erneut drucken"
const HEAD_BYTES = 1024;
const PAGES_MAX_BYTES = 20 * 1024 * 1024; // PDFs up to this size are looked into for their page count
const STORE_KEY = 'printSources';
const TRANSFER_ID_RE = /^t[0-9]{1,9}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{16,40}$/;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class PrintService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.notificationCenter] - NotificationCenter: print pushes → 'push', their toast click opens the page
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks for the plugin again
   * @param {object} [opts.drive] - DriveService (fileInfo / fileCopy): files of Drive can be printed
   * @param {Electron.Dialog} [opts.dialog] - the file dialog of pick()
   * @param {() => Electron.BrowserWindow|null} [opts.getMainWindow]
   * @param {(key: string) => string|undefined} [opts.dialogPath] - where the file dialog starts (utils/user-folders dialogPath)
   * @param {object} [opts.store] - electron-store: where the files of the last jobs lie ("Erneut drucken")
   * @param {object} [opts.api] - MessengerApi-compatible transport (tests)
   * @param {object} [opts.media] - upload({ path, size, mime }, { onProgress }) → { mediaId, scan? } (tests)
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   * @param {(ms: number) => Promise<void>} [opts.sleep]
   */
  constructor({
    apiClient, log, notificationCenter = null, pushClient = null, drive = null, dialog = null, getMainWindow = null,
    dialogPath = defaultDialogPath, store = null, api = null, media = null, timing = {}, now = Date.now, sleep = null,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.media = media || new GateDropApi({ http: this.api, log: this.log, mediaPath: print.MEDIA_PATH, maxFileBytes: print.MAX_BYTES, label: 'Drucken' });
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this.sleep = typeof sleep === 'function' ? sleep : (ms) => new Promise((r) => setTimeout(r, ms));
    this.notificationCenter = notificationCenter;
    this.pushClient = pushClient;
    this.drive = drive;
    this.dialog = dialog;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.dialogPath = typeof dialogPath === 'function' ? dialogPath : () => undefined;
    this.store = store;

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._overview = null;        // { at, data }
    this._overviewRun = null;
    this._printerNames = new Map(); // device id → name, of the last overview (for the jobs in the making)
    this._jobRoute = null;        // does the plugin answer jobs/<id> (≥ 1.1.0)? null until known
    this._tokens = new Map();     // token → { file (what the page sees), src, at }
    this._transfers = [];         // jobs in the making, oldest first
    this._nextTransfer = 0;
    this._pumping = false;
    this._sources = null;         // jobId → src (lazy, from the store)
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this._scopeNow();
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
        this._unsub.push(nc.addClickRoute(print.APP_ROUTE, (entry) => this.clickContext(entry)));
      }
    }
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      // A reconnect may come with another server state (plugin installed / removed / licensed).
      const onHello = () => { if (this._state.state !== 'available') this.check().catch(() => {}); };
      pc.on('hello', onHello);
      this._unsub.push(() => pc.removeListener('hello', onHello));
    }
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    this._timer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: the old server's answers, picked files and jobs in the making are dropped, the new one is asked. */
  resetForNewServer() {
    this._dropAll();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  _dropAll() {
    this._overview = null;
    this._printerNames.clear();
    this._jobRoute = null;
    this._tokens.clear();
    for (const tr of this._transfers) tr.canceled = true;
    if (this._transfers.length) { this._transfers = []; this.emit('transfers', this.transfers()); }
    // the files remembered for "Erneut drucken" are read again for the server now set
    this._sources = null;
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt } — reason of
   * 'unavailable': not_installed (also: not licensed, not for the apps), unsupported, auth, forbidden, not_configured.
   */
  status() {
    return { ...this._state };
  }

  available() {
    return this._state.state === 'available';
  }

  /** Ask the plugin list now → status(). */
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
    const gone = (reason) => this._setState({ state: 'unavailable', reason, version: null, checkedAt: this.now() });
    try {
      const data = await this.api._call('GET', PLUGINS_PATH);
      const plugins = Array.isArray(data.plugins) ? data.plugins : [];
      const p = plugins.find((x) => x && x.id === print.PLUGIN_ID);
      this._retry = 0;
      if (!p) gone('not_installed');
      else this._setState({ state: 'available', reason: null, version: typeof p.version === 'string' ? p.version.slice(0, 40) : null, checkedAt: this.now() });
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        gone('unsupported');
      } else if (err && (err.status === 401 || err.status === 403)) {
        gone(err.status === 401 ? 'auth' : 'forbidden');
      } else if (err && err.code === 'not_configured') {
        gone('not_configured');
      } else {
        // Network / 5xx: keep "available" (the page stays, the list comes from the last copy).
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
    const key = () => JSON.stringify([this._state.state, this._state.reason, this._state.version]);
    const before = key();
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    if (key() !== before) this.emit('state', this.status());
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  /** URL / token changed under us (configure()): everything belongs to the old one. */
  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._dropAll();
  }

  // ── Overview, jobs ───────────────────────────────────────

  /**
   * GET overview → { ok, rights: { print, pagesPerDay, bwOnly }, pagesLeft, printers, jobs, fetchedAt, stale }.
   * 404 (the plugin is not there for the apps any more): code 'unavailable'.
   */
  async overview({ refresh = false, maxAgeMs = this.timing.cacheTtlMs } = {}) {
    this._ensureScope();
    const hit = this._overview;
    if (!refresh && hit && this.now() - hit.at < maxAgeMs) return { ok: true, ...this._copy(hit.data), fetchedAt: hit.at, stale: false };
    if (this._overviewRun) return this._overviewRun;
    const scope = this._scope;
    const run = (async () => {
      try {
        const data = print.normalizeOverview(await this.api._call('GET', `${print.API_BASE}overview`));
        if (!data) throw new MessengerError('unexpected answer', { code: 'bad_response' });
        const at = this.now();
        if (scope === this._scope) {
          this._overview = { at, data };
          if (data.rights.print) this._printerNames = new Map(data.printers.map((p) => [p.id, p.name]));
        }
        return { ok: true, ...this._copy(data), fetchedAt: at, stale: false };
      } catch (err) {
        const e = this._error(err);
        const old = this._overview;
        if (old && e.transient) return { ok: true, ...this._copy(old.data), fetchedAt: old.at, stale: true, error: e.code };
        // the plugin is not there for the apps any more (removed, stopped, licence gone)
        if (e.status === 404) throw new MessengerError('print is not available', { status: 404, code: 'unavailable' });
        throw e;
      } finally {
        this._overviewRun = null;
      }
    })();
    this._overviewRun = run;
    return run;
  }

  /**
   * One job of the person → { ok, job } — `job` null: not among the last jobs any more. GET jobs/<id> (the real
   * state, the printer's stop reason, `expiresAt` / `doneAt` with plugin 1.1.1); a plugin without the route
   * (< 1.1.0) is read from the overview's last jobs.
   */
  async job(id) {
    if (!print.isJobId(id)) throw new MessengerError('invalid argument', { code: 'invalid' });
    this._ensureScope();
    if (this._jobRoute !== false) {
      try {
        const raw = await this.api._call('GET', `${print.API_BASE}jobs/${id}`);
        const job = print.normalizeJob(raw.job);
        if (!job) throw new MessengerError('unexpected answer', { code: 'bad_response' });
        this._jobRoute = true;
        return { ok: true, job };
      } catch (err) {
        const e = this._error(err, { recheck: false });
        if (e.status !== 404) throw e;
        if (this._jobRoute === true) return { ok: true, job: null };
        // the first 404: an older plugin without the route, or really gone — the overview tells
        const o = await this.overview({ refresh: true });
        const job = o.jobs.find((j) => j.id === id) || null;
        if (job) this._jobRoute = false;
        return { ok: true, job };
      }
    }
    const o = await this.overview();
    return { ok: true, job: o.jobs.find((j) => j.id === id) || null };
  }

  /** POST jobs/<id>/cancel (while it is on its way or waits) → { ok, canceled } */
  async cancel(id) {
    if (!print.isJobId(id)) throw new MessengerError('invalid argument', { code: 'invalid' });
    this._ensureScope();
    try {
      const raw = await this.api._call('POST', `${print.API_BASE}jobs/${id}/cancel`, { body: {} });
      this._overview = null;
      return { ok: true, canceled: raw.canceled === true };
    } catch (err) {
      throw this._error(err);
    }
  }

  /** Thrown errors as MessengerError; a 404 of the plugin's base: ask for the plugin again. */
  _error(err, { recheck = true } = {}) {
    const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
    if (recheck && e.status === 404 && (/^http_/.test(e.code) || e.code === 'not_found')) this.check().catch(() => {});
    return e;
  }

  _copy(data) {
    return JSON.parse(JSON.stringify(data));
  }

  // ── Files ────────────────────────────────────────────────

  /**
   * The file dialog ("Datei drucken …") → { ok, files, rejected } | { ok: false, code: 'cancelled' } — files:
   * [{ token, name, size, type, kind: 'pdf'|'image'|'text'|'office', from: 'pc', vault: false, pages }],
   * rejected: [{ name, code: 'missing'|'folder'|'empty'|'too_large'|'format'|'too_many' }].
   */
  async pick() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new MessengerError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const start = this.dialogPath('documents');
    const opts = {
      properties: ['openFile', 'multiSelections'],
      filters: [{ name: 'PDF, Bild, Text, Office', extensions: Object.keys(print.EXTENSIONS) }],
      ...(start ? { defaultPath: start } : {}),
    };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return this.addPaths(r.filePaths);
  }

  /** Files the person dropped on the window (paths the preload read from the File objects) → as pick(). */
  async addPaths(paths) {
    const files = [];
    const rejected = [];
    const all = Array.isArray(paths) ? paths : [];
    for (const p of all.slice(0, print.MAX_FILES)) {
      const r = await this._inspect(p);
      if (r.rejected) rejected.push(r.rejected);
      else files.push(this._register(r.file, { kind: 'pc', path: r.path }));
    }
    for (const p of all.slice(print.MAX_FILES, print.MAX_FILES + 50)) rejected.push({ name: typeof p === 'string' ? print.line(path.basename(p), 200) || '' : '', code: 'too_many' });
    return { ok: true, files, rejected };
  }

  /**
   * Files of Drive (node ids) → as pick(), `from: 'drive'`. `vault: true` is the person's yes to printing vault
   * files (they leave the vault decrypted): without it they are rejected with 'vault_confirm'. Further codes:
   * 'folder', 'format', 'too_large', 'empty', the virus scan's ('quarantined', 'scan_pending', 'scan_blocked'),
   * 'vault_locked', 'not_found'.
   */
  async addDrive(ids, { vault = false } = {}) {
    const d = this.drive;
    if (!d || typeof d.fileInfo !== 'function' || typeof d.fileCopy !== 'function') throw new MessengerError('no Drive', { code: 'unsupported' });
    const files = [];
    const rejected = [];
    const all = (Array.isArray(ids) ? ids : []).map(posInt).filter(Boolean);
    for (const id of all.slice(0, print.MAX_FILES)) {
      let info;
      try { info = await d.fileInfo(id); } catch (err) {
        const c = (err && err.code) || 'failed';
        rejected.push({ name: '', code: c === 'invalid' ? 'folder' : c });
        continue;
      }
      const name = print.line(info.name, 200) || 'Datei';
      const type = print.uploadType(name, info.encrypted ? null : info.mime);
      if (!type) rejected.push({ name, code: 'format' });
      else if (!(info.size > 0)) rejected.push({ name, code: 'empty' });
      else if (info.size > print.MAX_BYTES) rejected.push({ name, code: 'too_large' });
      else if (info.encrypted && vault !== true) rejected.push({ name, code: 'vault_confirm' });
      else {
        files.push(this._register(
          { name, size: info.size, type, kind: print.kindOf(type), from: 'drive', vault: !!info.encrypted, pages: print.kindOf(type) === 'image' ? 1 : null },
          { kind: 'drive', nodeId: info.id, vault: !!info.encrypted },
        ));
      }
    }
    for (let i = print.MAX_FILES; i < all.length; i++) rejected.push({ name: '', code: 'too_many' });
    return { ok: true, files, rejected };
  }

  /** The dialog was closed without printing: its files are forgotten. */
  forget(tokens) {
    for (const t of Array.isArray(tokens) ? tokens : []) this._tokens.delete(t);
    return { ok: true };
  }

  /** A file of this PC: a regular file, 1 byte … 50 MB, one of the plugin's types by name and content. */
  async _inspect(p) {
    const bad = (name, c) => ({ rejected: { name: print.line(name, 200) || '', code: c } });
    if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p) || p.includes('\0')) return bad('', 'missing');
    const name = path.basename(p);
    let st;
    try { st = await fs.promises.stat(p); } catch { return bad(name, 'missing'); }
    if (st.isDirectory()) return bad(name, 'folder');
    if (!st.isFile()) return bad(name, 'missing');
    if (st.size <= 0) return bad(name, 'empty');
    if (st.size > print.MAX_BYTES) return bad(name, 'too_large');
    let head;
    try { head = await readHead(p); } catch { return bad(name, 'missing'); }
    const type = print.uploadType(name, null, head);
    if (!type) return bad(name, 'format');
    const kind = print.kindOf(type);
    let pages = kind === 'image' ? 1 : null;
    if (kind === 'pdf' && st.size <= PAGES_MAX_BYTES) {
      try { pages = print.pdfPages(await fs.promises.readFile(p)); } catch { pages = null; }
    }
    return { path: p, file: { name: print.line(name, 200) || 'Datei', size: st.size, type, kind, from: 'pc', vault: false, pages } };
  }

  _register(file, src) {
    const at = this.now();
    for (const [k, v] of this._tokens) if (at - v.at > this.timing.tokenTtlMs) this._tokens.delete(k);
    while (this._tokens.size >= MAX_TOKENS) this._tokens.delete(this._tokens.keys().next().value);
    const token = crypto.randomBytes(18).toString('base64url');
    this._tokens.set(token, { file, src, at });
    return { token, ...file };
  }

  // ── Printing ─────────────────────────────────────────────

  /**
   * Prints the files of `tokens` (pick() / addPaths() / addDrive()) with one set of options — each file a job of
   * its own → { ok, transfers } (the jobs in the making; 'transfers' and 'job' tell how they go on).
   * @param {{ tokens: string[], deviceId: string, copies?: number, color?: boolean, duplex?: boolean, media?: string, source?: string }} a
   */
  async submit(a) {
    const opts = print.printOptions(a);
    const tokens = a && Array.isArray(a.tokens) ? a.tokens : [];
    if (!opts || !tokens.length || tokens.length > print.MAX_FILES || !tokens.every((t) => typeof t === 'string' && TOKEN_RE.test(t))) {
      throw new MessengerError('invalid argument', { code: 'invalid' });
    }
    this._ensureScope();
    const entries = tokens.map((t) => this._tokens.get(t));
    if (entries.some((e) => !e)) throw new MessengerError('file not picked', { code: 'not_picked' });
    const device = this._printerName(opts.deviceId);
    const added = [];
    for (const t of tokens) this._tokens.delete(t);
    for (const e of entries) {
      const tr = {
        id: `t${++this._nextTransfer}`, name: e.file.name, size: e.file.size, type: e.file.type, from: e.file.from, vault: e.file.vault,
        src: e.src, opts, device, phase: 'waiting', sent: 0, total: e.file.size, code: null, error: null, left: null, pages: null,
        at: this.now(), canceled: false, scope: this._scope,
      };
      this._transfers.push(tr);
      added.push(tr);
    }
    this.emit('transfers', this.transfers());
    this._pump();
    return { ok: true, transfers: added.map(view) };
  }

  /** The jobs in the making, oldest first: [{ id, name, size, from, device, deviceId, copies, color, duplex, media, source, phase, sent, total, code, error, left, pages, at }] */
  transfers() {
    return this._transfers.map(view);
  }

  /**
   * "Abbrechen" of a job in the making / "Entfernen" of a failed one → { ok }. A file that is going up right now is
   * not sent to the printer any more.
   */
  cancelTransfer(id) {
    const tr = this._transfers.find((t) => t.id === id);
    if (!tr) return { ok: true };
    tr.canceled = true;
    this._transfers = this._transfers.filter((t) => t !== tr);
    this.emit('transfers', this.transfers());
    return { ok: true };
  }

  /**
   * "Erneut drucken": the file of a job (`jobId`) or of a failed job in the making (`transferId`) again, when it
   * still lies where it was → { ok, files, rejected, options: { deviceId, copies, color, duplex, media, source } | null }
   * | { ok: false, code: 'source_gone' } (the file is not known any more).
   */
  async again({ jobId = null, transferId = null } = {}) {
    let src = null;
    let options = null;
    if (typeof transferId === 'string' && TRANSFER_ID_RE.test(transferId)) {
      const tr = this._transfers.find((t) => t.id === transferId);
      if (tr) { src = tr.src; options = { ...tr.opts }; }
    } else if (print.isJobId(jobId)) {
      src = this._sourceMap().get(jobId) || null;
    }
    if (!src) return { ok: false, code: 'source_gone', error: 'the file is not known any more' };
    const r = src.kind === 'drive' ? await this.addDrive([src.nodeId], { vault: src.vault === true }) : await this.addPaths([src.path]);
    if (!r.files.length) return { ok: false, code: 'source_gone', error: 'the file is not there any more' };
    return { ...r, options };
  }

  _printerName(deviceId) {
    return this._printerNames.get(deviceId) || null;
  }

  _touch(tr, patch) {
    Object.assign(tr, patch);
    if (!tr.canceled) this.emit('transfers', this.transfers());
  }

  async _pump() {
    if (this._pumping) return;
    this._pumping = true;
    try {
      for (;;) {
        const tr = this._transfers.find((t) => t.phase === 'waiting' && !t.canceled);
        if (!tr) break;
        await this._runTransfer(tr);
      }
    } finally {
      this._pumping = false;
    }
  }

  async _runTransfer(tr) {
    let dispose = null;
    let lastEmit = 0;
    try {
      let file;
      if (tr.src.kind === 'drive') {
        this._touch(tr, { phase: 'loading' });
        const c = await this.drive.fileCopy(tr.src.nodeId);
        dispose = c.dispose;
        // what Drive called a PDF must be one: the content decides as for a file of this PC
        const type = print.uploadType(tr.name, null, await readHead(c.path));
        if (!type) throw new MessengerError('not printable', { code: 'format' });
        if (!(c.size > 0)) throw new MessengerError('empty file', { code: 'empty' });
        if (c.size > print.MAX_BYTES) throw new MessengerError('file too large', { code: 'too_large' });
        file = { path: c.path, size: c.size, mime: type };
      } else {
        const r = await this._inspect(tr.src.path);
        if (r.rejected) throw new MessengerError('file not readable', { code: r.rejected.code });
        file = { path: r.path, size: r.file.size, mime: r.file.type };
      }
      if (tr.canceled || tr.scope !== this._scope) return;
      this._touch(tr, { phase: 'uploading', sent: 0, total: file.size });
      const up = await this.media.upload(file, {
        onProgress: (sent, total) => {
          tr.sent = Math.min(sent, total || file.size);
          if (total) tr.total = total;
          const t = this.now();
          if (t - lastEmit >= 200 && !tr.canceled) { lastEmit = t; this.emit('transfers', this.transfers()); }
        },
      });
      if (up && SC.isBlocked(up.scan) && SC.refusalOf(up.scan) !== 'scan_pending') throw new MessengerError('blocked by the virus scan', { status: 423, code: SC.refusalOf(up.scan) });
      if (tr.canceled || tr.scope !== this._scope) return;
      this._touch(tr, { phase: 'sending', sent: tr.total });
      const body = { ...tr.opts, mediaId: up.mediaId, name: print.jobName(tr.name) };
      let raw;
      for (let attempt = 0; ; attempt++) {
        try {
          raw = await this.api._call('POST', `${print.API_BASE}print`, { body, timeout: this.timing.printTimeoutMs });
          break;
        } catch (err) {
          const e = this._error(err);
          // the server's virus scan may still hold the file: asked again after a short wait
          if (e.code !== 'print_failed' || attempt >= this.timing.printRetries || tr.canceled) throw e;
          await this.sleep(this.timing.printRetryMs * (attempt + 1));
        }
      }
      const job = print.normalizeJob(raw.job);
      if (!job) throw new MessengerError('unexpected answer', { code: 'bad_response' });
      this._overview = null;
      this._remember(job.id, tr.src);
      const i = this._transfers.indexOf(tr);
      if (i >= 0) this._transfers.splice(i, 1);
      this.emit('transfers', this.transfers());
      const left = Number.isFinite(raw.pagesLeft) && raw.pagesLeft >= 0 ? Math.floor(raw.pagesLeft) : null;
      this.emit('job', { job, pagesLeft: left, transferId: tr.id });
    } catch (err) {
      const e = err instanceof MessengerError ? err : MessengerApi.toMessengerError(err);
      const b = e.body && typeof e.body === 'object' ? e.body : {};
      this.log.info(`Drucken: job not sent (${e.code})`);
      this._touch(tr, {
        phase: 'failed', code: e.code || 'failed',
        // the plugin's own sentence (in the asked language) when it has one
        error: e.status && typeof b.error === 'string' && b.error !== e.code ? print.line(b.error, 300) : null,
        left: Number.isFinite(b.left) && b.left >= 0 ? Math.floor(b.left) : null,
        pages: Number.isFinite(b.pages) && b.pages >= 0 ? Math.floor(b.pages) : null,
      });
    } finally {
      if (dispose) await Promise.resolve().then(dispose).catch(() => {});
    }
  }

  // ── "Erneut drucken": where the files of the last jobs lie ──

  _sourceMap() {
    if (this._sources) return this._sources;
    const m = new Map();
    let list = [];
    try { list = this.store && typeof this.store.get === 'function' ? this.store.get(STORE_KEY) : []; } catch { list = []; }
    for (const x of Array.isArray(list) ? list.slice(-MAX_SOURCES) : []) {
      if (!x || typeof x !== 'object' || !print.isJobId(x.jobId) || x.scope !== scopeKey(this._scope)) continue;
      if (x.kind === 'drive' && posInt(x.nodeId)) m.set(x.jobId, { kind: 'drive', nodeId: posInt(x.nodeId), vault: x.vault === true });
      else if (x.kind === 'pc' && typeof x.path === 'string' && x.path.length <= 4096) m.set(x.jobId, { kind: 'pc', path: x.path });
    }
    this._sources = m;
    return m;
  }

  _remember(jobId, src) {
    const m = this._sourceMap();
    m.delete(jobId);
    m.set(jobId, src);
    while (m.size > MAX_SOURCES) m.delete(m.keys().next().value);
    this._saveSources();
  }

  _saveSources() {
    if (!this.store || typeof this.store.set !== 'function') return;
    const scope = scopeKey(this._scope);
    try { this.store.set(STORE_KEY, [...(this._sources || new Map())].map(([jobId, s]) => ({ jobId, scope, ...s }))); } catch (err) { this.log.debug(`Drucken: sources not saved (${err.message})`); }
  }

  /** Jobs whose file is still known for "Erneut drucken" → { ok, ids } */
  sources() {
    return { ok: true, ids: [...this._sourceMap().keys()] };
  }

  // ── Push ─────────────────────────────────────────────────

  _onPush(entry) {
    const ctx = print.pushContext(entry);
    if (!ctx) return;
    this._overview = null;
    this.emit('push', { ...ctx, notificationId: entry && Number.isSafeInteger(entry.id) ? entry.id : null });
  }

  /**
   * Context for a click on a print toast while the page exists, else null (the inbox opens). Used through
   * NotificationCenter.addClickRoute.
   */
  clickContext(entry) {
    if (!this.available()) return null;
    return print.pushContext(entry);
  }
}

/** A job in the making as the page sees it (no path, no node). */
function view(tr) {
  return {
    id: tr.id, name: tr.name, size: tr.size, from: tr.from, device: tr.device, deviceId: tr.opts.deviceId,
    copies: tr.opts.copies, color: tr.opts.color, duplex: tr.opts.duplex, media: tr.opts.media || null, source: tr.opts.source || null,
    phase: tr.phase, sent: tr.sent, total: tr.total, code: tr.code, error: tr.error, left: tr.left, pages: tr.pages, at: tr.at,
  };
}

/** The server a remembered file belongs to: its address (the first line of the scope), never the token. */
function scopeKey(scope) {
  return String(scope || '').split('\n')[0].slice(0, 300);
}

async function readHead(file) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const buf = Buffer.alloc(HEAD_BYTES);
    const { bytesRead } = await fh.read(buf, 0, HEAD_BYTES, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

PrintService.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = PrintService;
