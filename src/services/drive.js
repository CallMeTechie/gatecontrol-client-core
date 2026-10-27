'use strict';

/**
 * GateControl – Drive (Core service)
 *
 * The data side of the page "Drive" in the Windows Pro app: the files of the
 * person, the family, the children and the team on the own storage (plugin
 * `gatecontrol-drive`, README "API"), over the device token of the existing
 * ApiClient (services/drive-api.js):
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins lists
 *   `gatecontrol-drive` (like Schule / GateDrop / Vault). Asked at start,
 *   every 30 min, after a push reconnect and on check(); network errors are
 *   retried (5 s … 5 min). Seat and licence come with `me()` (the page tells
 *   "not switched on" / "no licence").
 * - Browse: areas, folders (crumbs, role, content), search (name and the
 *   recognised text of scans), trash, versions, links — every answer cleaned
 *   by utils/drive.js.
 * - Change: new folder, rename, move, into the trash, restore, purge, restore
 *   a version, create / end links.
 * - Upload: files from disk, one after the other in the background: SHA-256
 *   (≤ 2 GB) → `uploads/check` (the same file there already: skipped; the
 *   name taken: the person chooses "Neue Version" / "Beide behalten" /
 *   "Überspringen") → media upload (resumable above 8 MiB, GateDropApi) →
 *   `uploads/commit`. The list of transfers goes to the page ('transfers').
 * - Open / save: `nodes/<id>/content` → the file streamed into
 *   %TEMP%\gatecontrol-drive\<node>-<rev>\<name> and opened with the default
 *   program (executables only "Speichern unter …"), or into a path the person
 *   picks ("Speichern unter …"; a version too).
 * - Previews: the small / large picture of a file by mediaId (cached in memory).
 * - The folder last picked in "In Drive speichern" (chat, GateDrop, Schule) is
 *   remembered per server (store key `driveLastFolder`).
 *
 * Events: 'state' (status()), 'transfers' (list of uploads / downloads),
 * 'changed' ({ folderId }) after an upload landed in a folder.
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const DriveApi = require('./drive-api');
const MessengerApi = require('./messenger-api');
const drive = require('../utils/drive');
const { unsafeToOpen, safeFileName } = require('../utils/messenger');
const { guessMime } = require('../utils/gatedrop');

const { MessengerError: DriveError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,
  retryMinMs: 5000,
  retryMaxMs: 5 * 60 * 1000,
  progressMs: 250,         // transfer list updates at most every 250 ms while bytes move
  previewCache: 300,       // pictures kept in memory
  keepTransfers: 50,       // finished rows kept in the list
};
const STORE_KEY = 'driveLastFolder';
const MAX_PATHS = 200;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class DriveService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.api] - DriveApi (tests)
   * @param {object} [opts.store] - electron-store (the folder last picked)
   * @param {object} [opts.shell] - Electron shell (open, show in folder)
   * @param {object} [opts.dialog] - Electron dialog (pick files, save as)
   * @param {Function} [opts.getMainWindow]
   * @param {() => string} [opts.tempDir] - folder for opened files (%TEMP%\gatecontrol-drive)
   * @param {() => string} [opts.getLang] - 'de' | 'en'
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks for the plugin again
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({
    apiClient, log, api = null, store = null, shell = null, dialog = null, getMainWindow = null,
    tempDir = null, getLang = null, pushClient = null, timing = {}, now = Date.now,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.api = api || new DriveApi({ apiClient, log: this.log, getLang });
    this.store = store;
    this.shell = shell;
    this.dialog = dialog;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.tempDir = typeof tempDir === 'function' ? tempDir : () => path.join(os.tmpdir(), 'gatecontrol-drive');
    this.pushClient = pushClient;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this._scopeNow();
    this._previews = new Map();     // `${mediaId}|${size}` → { mime, data }
    this._inflight = new Map();
    this._transfers = [];           // rows of the transfer list (see _row)
    this._jobs = new Map();         // upload id → job (queued / waiting for a choice)
    this._queue = [];
    this._pumping = false;
    this._nextId = 0;
    this._emitTimer = null;
    this._lastEmit = 0;
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
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
    clearTimeout(this._emitTimer);
    this._emitTimer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** server:setup: the old server's state goes (queued uploads are dropped), the new one is asked. */
  resetForNewServer() {
    this._previews.clear();
    this._inflight.clear();
    for (const job of this._queue.splice(0)) this._set(job.id, { state: 'skipped' });
    for (const [id, job] of this._jobs) if (job.waiting) this._set(id, { state: 'skipped' });
    this._jobs.clear();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /** { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt } */
  status() {
    return { ...this._state };
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
    try {
      const p = await this.api.plugin();
      this._retry = 0;
      if (!p) this._setState({ state: 'unavailable', reason: 'not_installed', version: null, checkedAt: this.now() });
      else this._setState({ state: 'available', reason: null, version: typeof p.version === 'string' ? p.version.slice(0, 40) : null, checkedAt: this.now() });
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        this._setState({ state: 'unavailable', reason: 'unsupported', version: null, checkedAt: this.now() });
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setState({ state: 'unavailable', reason: err.status === 401 ? 'auth' : 'forbidden', version: null, checkedAt: this.now() });
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        // Network / 5xx: keep "available" (the page stays and says it is offline).
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

  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._previews.clear();
  }

  /** Drive is not listed (any more): the call fails like the plugin would. */
  _need() {
    if (this._state.state === 'unavailable') throw new DriveError('Drive is not available', { code: 'drive_unavailable' });
  }

  /** A 404 of the plugin's base or a refusal of the token: ask for the plugin again. */
  async _run(fn) {
    this._need();
    this._ensureScope();
    try {
      return await fn();
    } catch (err) {
      const e = err instanceof DriveError ? err : MessengerApi.toMessengerError(err);
      if (e.status === 404 && /^http_/.test(e.code)) this.check().catch(() => {});
      throw e;
    }
  }

  // ── Browse ───────────────────────────────────────────────

  /** GET me → { ok, me, licence, areas, settings, limits, people, usable } */
  async me() {
    return this._run(async () => {
      const m = await this.api.me();
      return { ok: true, ...m, usable: m.licence.valid && !!m.me.seat };
    });
  }

  /** GET areas → { ok, areas } (sorted: mine, family, children, teams). */
  async areas() {
    return this._run(async () => ({ ok: true, ...(await this.api.areas()) }));
  }

  /** A folder: { ok, node, crumbs, role, writable, items, total, next } */
  async folder(id, query = {}) {
    return this._run(async () => ({ ok: true, ...(await this.api.folder(id, query)) }));
  }

  async search(q, area = null) {
    const text = typeof q === 'string' ? q.trim() : '';
    if (text.length < 2 || text.length > 100) throw new DriveError('search needs 2 to 100 characters', { code: 'invalid' });
    return this._run(async () => ({ ok: true, items: await this.api.search(text, area) }));
  }

  async trashList(area = null) {
    return this._run(async () => ({ ok: true, items: await this.api.trashList(area) }));
  }

  async versions(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.versions(id)) }));
  }

  async links(nodeId = null) {
    return this._run(async () => ({ ok: true, ...(await this.api.links(nodeId)) }));
  }

  // ── Change ───────────────────────────────────────────────

  _name(name) {
    if (!drive.validName(name)) throw new DriveError('name not allowed', { code: 'invalid_name' });
    return name.trim();
  }

  async mkdir(parentId, name) {
    const n = this._name(name);
    return this._run(async () => ({ ok: true, node: await this.api.mkdir(parentId, n) }));
  }

  async rename(id, name) {
    const n = this._name(name);
    return this._run(async () => ({ ok: true, node: await this.api.rename(id, n) }));
  }

  async move(id, parentId) {
    return this._run(async () => ({ ok: true, node: await this.api.move(id, parentId) }));
  }

  async remove(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.trash(id)) }));
  }

  async restore(id) {
    return this._run(async () => ({ ok: true, node: await this.api.restore(id) }));
  }

  async purge(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.purge(id)) }));
  }

  async restoreVersion(id, versionId) {
    return this._run(async () => ({ ok: true, node: await this.api.restoreVersion(id, versionId) }));
  }

  async createLink(opts) {
    return this._run(async () => ({ ok: true, link: await this.api.createLink(opts) }));
  }

  async endLink(token) {
    return this._run(async () => ({ ok: true, ...(await this.api.endLink(token)) }));
  }

  // ── Previews ─────────────────────────────────────────────

  /** The preview of `mediaId` → { ok, mime, data } (cached; a new version is a new mediaId). */
  async preview(mediaId, { large = false } = {}) {
    if (!drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    this._ensureScope();
    const key = `${mediaId}|${large ? 'l' : 's'}`;
    const hit = this._previews.get(key);
    if (hit) return { ok: true, ...hit };
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.preview(mediaId, { large }).then((r) => {
      this._previews.set(key, r);
      while (this._previews.size > this.timing.previewCache) this._previews.delete(this._previews.keys().next().value);
      return { ok: true, ...r };
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── The folder last picked ("In Drive speichern") ────────

  _scopeKey() {
    return crypto.createHash('sha256').update(this._scopeNow()).digest('hex').slice(0, 16);
  }

  /** → { ok, folderId } of this server, or folderId null. */
  lastFolder() {
    let v = null;
    try { v = this.store && this.store.get(STORE_KEY); } catch { v = null; }
    const ok = v && typeof v === 'object' && v.scope === this._scopeKey();
    return { ok: true, folderId: ok ? drive.posId(v.folderId) : null };
  }

  rememberFolder(folderId) {
    const id = drive.posId(folderId);
    if (!id) throw new DriveError('invalid folder', { code: 'invalid' });
    try { if (this.store) this.store.set(STORE_KEY, { v: 1, scope: this._scopeKey(), folderId: id }); } catch (err) { this.log.warn(`Drive folder not remembered: ${err.message}`); }
    return { ok: true, folderId: id };
  }

  // ── Transfers (the list on the page) ─────────────────────

  transfers() {
    return this._transfers.map((r) => ({ ...r }));
  }

  _row(row) {
    this._transfers.push(row);
    const done = (r) => !['queued', 'running', 'conflict'].includes(r.state);
    let extra = this._transfers.filter(done).length - this.timing.keepTransfers;
    if (extra > 0) this._transfers = this._transfers.filter((r) => !(done(r) && extra-- > 0));
    this._emitTransfers(true);
  }

  _set(id, patch, { progress = false } = {}) {
    const r = this._transfers.find((x) => x.id === id);
    if (!r) return;
    Object.assign(r, patch);
    this._emitTransfers(!progress);
  }

  _emitTransfers(now) {
    const fire = () => {
      this._emitTimer = null;
      this._lastEmit = Date.now();
      this.emit('transfers', this.transfers());
    };
    if (now) {
      clearTimeout(this._emitTimer);
      fire();
      return;
    }
    if (this._emitTimer) return;
    const wait = Math.max(0, this.timing.progressMs - (Date.now() - this._lastEmit));
    this._emitTimer = setTimeout(fire, wait);
    if (this._emitTimer.unref) this._emitTimer.unref();
  }

  /** Removes finished rows. */
  clearTransfers() {
    this._transfers = this._transfers.filter((r) => ['queued', 'running', 'conflict'].includes(r.state));
    this._emitTransfers(true);
    return { ok: true, transfers: this.transfers() };
  }

  // ── Upload ───────────────────────────────────────────────

  /** File dialog → { ok, paths } | { ok: false, code: 'cancelled' } */
  async pickFiles() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const opts = { properties: ['openFile', 'multiSelections'] };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, paths: r.filePaths.slice(0, MAX_PATHS) };
  }

  /**
   * Queues files from disk for the folder `parentId` → { ok, queued, rejected }.
   * Folders and unreadable paths are rejected ({ name, code }).
   */
  async upload(parentId, paths) {
    const folderId = drive.posId(parentId);
    if (!folderId) throw new DriveError('invalid folder', { code: 'invalid' });
    this._need();
    const list = Array.isArray(paths) ? paths.slice(0, MAX_PATHS) : [];
    const queued = [];
    const rejected = [];
    for (const p of list) {
      if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p)) continue;
      const base = path.basename(p);
      let st;
      try { st = await fs.promises.stat(p); } catch { rejected.push({ name: base, code: 'missing' }); continue; }
      if (st.isDirectory()) { rejected.push({ name: base, code: 'folder' }); continue; }
      if (!st.isFile()) { rejected.push({ name: base, code: 'missing' }); continue; }
      if (st.size > drive.MAX_FILE_BYTES) { rejected.push({ name: base, code: 'too_large' }); continue; }
      const name = drive.safeName(base);
      if (!name) { rejected.push({ name: base, code: 'invalid_name' }); continue; }
      const id = `u${++this._nextId}`;
      const job = { id, path: p, name, size: st.size, mtime: st.mtimeMs, folderId, choice: null, waiting: false, scope: this._scopeNow() };
      this._jobs.set(id, job);
      this._queue.push(job);
      this._row({ id, dir: 'up', name, folderId, total: st.size, sent: 0, state: 'queued', code: null, at: this.now() });
      queued.push(id);
    }
    this._pump();
    return { ok: true, queued, rejected };
  }

  /** The person's answer to a taken name: 'version' | 'rename' (keep both) | null (skip). */
  resolve(id, choice) {
    const job = this._jobs.get(id);
    if (!job || !job.waiting) throw new DriveError('no such upload', { code: 'not_found' });
    job.waiting = false;
    if (choice !== 'version' && choice !== 'rename') {
      this._jobs.delete(id);
      this._set(id, { state: 'skipped' });
      return { ok: true };
    }
    job.choice = choice;
    this._set(id, { state: 'queued' });
    this._queue.unshift(job);
    this._pump();
    return { ok: true };
  }

  async _pump() {
    if (this._pumping) return;
    this._pumping = true;
    try {
      while (this._queue.length) {
        const job = this._queue.shift();
        try {
          await this._runUpload(job);
        } catch (err) {
          const code = drive.errorCode(err);
          this.log.info(`Drive upload of a file failed: ${code}`);
          this._jobs.delete(job.id);
          this._set(job.id, { state: 'failed', code });
        }
      }
    } finally {
      this._pumping = false;
    }
  }

  async _runUpload(job) {
    if (job.scope !== this._scopeNow()) throw new DriveError('server changed', { code: 'drive_unavailable' });
    this._set(job.id, { state: 'running', sent: 0 });
    let st;
    try { st = await fs.promises.stat(job.path); } catch { throw new DriveError('file gone', { code: 'missing' }); }
    if (!st.isFile()) throw new DriveError('file gone', { code: 'missing' });
    if (st.size !== job.size) {
      job.size = st.size;
      this._set(job.id, { total: st.size });
    }
    if (!job.choice) {
      const sha = job.size <= drive.SHA_MAX_BYTES ? await sha256File(job.path).catch(() => null) : null;
      const c = await this.api.check({ parentId: job.folderId, name: job.name, sha256: sha, size: job.size });
      if (c.same) {
        this._jobs.delete(job.id);
        this._set(job.id, { state: 'same', sent: job.size, nodeId: c.node ? c.node.id : null });
        return;
      }
      if (c.exists) {
        job.waiting = true;
        this._set(job.id, { state: 'conflict' });
        return;
      }
    }
    let r;
    if (!job.size) {
      // GateControl takes no empty media; Drive 1.5 ('emptyFiles') makes an empty file without one
      if (!(await this.api.has('emptyFiles').catch(() => false))) throw new DriveError('empty file', { code: 'empty_file' });
      r = await this.api.commit({ empty: true, parentId: job.folderId, name: job.name, mtime: job.mtime, onConflict: job.choice || 'rename' });
    } else {
      const up = await this.api.upload({ path: job.path, size: job.size, mime: guessMime(job.name) }, {
        onProgress: (sent) => this._set(job.id, { sent }, { progress: true }),
      });
      r = await this.api.commit({ mediaId: up.mediaId, parentId: job.folderId, name: job.name, mtime: job.mtime, onConflict: job.choice || 'rename' });
    }
    this._jobs.delete(job.id);
    this._set(job.id, { state: 'done', sent: job.size, nodeId: r.node.id, name: r.node.name });
    this.emit('changed', { folderId: job.folderId });
  }

  // ── Download: open / save as ─────────────────────────────

  async _fetchTo(nodeId, versionId, file, row) {
    const c = await this.api.content(nodeId, versionId);
    const part = `${file}.${crypto.randomBytes(4).toString('hex')}.part`;
    await fs.promises.mkdir(path.dirname(file), { recursive: true });
    const out = fs.createWriteStream(part);
    try {
      // Drive 1.5: an empty file has no media
      if (c.empty) await new Promise((resolve, reject) => { out.on('error', reject); out.end(resolve); });
      else await this.api.download(c.mediaId, out, { onProgress: (got, total) => this._set(row.id, { sent: got, ...(total ? { total } : {}) }, { progress: true }) });
      await fs.promises.rm(file, { force: true });
      await fs.promises.rename(part, file);
    } catch (err) {
      out.destroy();
      await fs.promises.rm(part, { force: true }).catch(() => {});
      throw err;
    }
    return c;
  }

  _downloadRow(name, size) {
    const row = { id: `d${++this._nextId}`, dir: 'down', name, folderId: null, total: size || 0, sent: 0, state: 'running', code: null, at: this.now() };
    this._row(row);
    return row;
  }

  /**
   * Loads the file (or a version) into the temp folder and opens it with the
   * default program → { ok, path } | { ok: false, code: 'unsafe' } (executables:
   * "Speichern unter …" only).
   */
  async open(nodeId, { versionId = null } = {}) {
    if (!this.shell || typeof this.shell.openPath !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    return this._run(async () => {
      const node = await this.api.node(nodeId);
      if (node.isDir) throw new DriveError('a folder', { code: 'invalid' });
      const name = drive.safeName(node.name) || 'Datei';
      if (unsafeToOpen(name, node.mime)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
      const dir = path.join(this.tempDir(), `${node.id}-${versionId ? `v${drive.posId(versionId)}` : node.rev}`);
      // Windows device names (CON, NUL, COM1 …) cannot be files: open a renamed local copy.
      const file = path.join(dir, safeFileName(name, 'Datei'));
      let have = false;
      if (!versionId) {
        try { have = (await fs.promises.stat(file)).size === node.size && node.size > 0; } catch { have = false; }
      }
      if (have) {
        // Already loaded this revision: the server still learns that it was opened (a child's folder).
        await this.api.content(node.id).catch(() => {});
      } else {
        const row = this._downloadRow(name, node.size);
        try {
          await this._fetchTo(node.id, versionId, file, row);
          this._set(row.id, { state: 'done', sent: row.total, path: file });
        } catch (err) {
          this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
          throw err;
        }
      }
      const err = await this.shell.openPath(file);
      if (err) {
        this.log.warn(`Opening a Drive file failed: ${err}`);
        return { ok: false, code: 'open_failed', error: String(err) };
      }
      return { ok: true, path: file };
    });
  }

  /** "Speichern unter …": the file (or a version) into a path the person picks → { ok, path } | { ok: false, cancelled }. */
  async saveAs(nodeId, { versionId = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const node = await this.api.node(nodeId);
      if (node.isDir) throw new DriveError('a folder', { code: 'invalid' });
      const name = drive.safeName(node.name) || 'Datei';
      const win = this.getMainWindow();
      const res = win ? await this.dialog.showSaveDialog(win, { defaultPath: name }) : await this.dialog.showSaveDialog({ defaultPath: name });
      if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true, code: 'cancelled' };
      const row = this._downloadRow(path.basename(res.filePath), node.size);
      try {
        await this._fetchTo(node.id, versionId, res.filePath, row);
      } catch (err) {
        this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
        throw err;
      }
      this._set(row.id, { state: 'done', sent: row.total, path: res.filePath });
      return { ok: true, path: res.filePath };
    });
  }

  /** Shows a file this app saved / opened in the Explorer (rows of the transfer list only). */
  showItem(p) {
    if (!this.shell || typeof this.shell.showItemInFolder !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    if (!this._transfers.some((r) => r.path && r.path === p)) throw new DriveError('unknown file', { code: 'invalid' });
    this.shell.showItemInFolder(p);
    return { ok: true };
  }
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

DriveService.DEFAULT_TIMING = DEFAULT_TIMING;
DriveService.STORE_KEY = STORE_KEY;
DriveService.sha256File = sha256File;

module.exports = DriveService;
