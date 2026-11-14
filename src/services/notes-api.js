'use strict';

/**
 * GateControl – Notizen & Aufgaben API (Core service)
 *
 * REST calls of the plugin `gatecontrol-notizen` (README "API", plugin 1.0.0) over the device token of the existing
 * ApiClient. The only file that knows the plugin's paths; answers are cleaned by utils/notes.js:
 *
 *   GET    /api/v1/client/plugins                          is the plugin there (and licensed — else it is not listed)?
 *   GET    …/gatecontrol-notizen/api/me · nav?area · views/<name>?area · people · search?q&area · prefs · sources
 *   POST   …/api/parse { text, area } · PUT prefs · POST sources/<plugin>/sync
 *   GET|POST lists · PATCH|DELETE lists/<id> · PUT lists/<id>/members · POST groups · PATCH|DELETE groups/<id>
 *   POST   tasks · GET|PATCH|DELETE tasks/<id> · POST tasks/<id>/complete
 *   POST   tasks/<id>/move { to } · GET yesterday?area · POST yesterday { action, to?, ids?, area? }
 *          („Gestern offen geblieben“, plugin 1.3.0 — an older plugin answers 404)
 *   GET    items/<id> · POST items/<id>/complete · POST items/<id>/carry
 *   GET|POST notebooks · PATCH|DELETE notebooks/<id> · PUT notebooks/<id>/members
 *   GET|POST notes · GET|PATCH|DELETE notes/<id> · POST notes/<id>/check · POST notes/<id>/task
 *   POST   attachments · GET|DELETE attachments/<id> · PUT attachments/<id>/text
 *   GET|POST vaults · GET vaults/<id> · GET vaults/<id>/keys?deviceId · GET|PUT vaults/<id>/recovery
 *   GET|POST vaults/<id>/devices · POST …/devices/<did>/approve · DELETE …/devices/<did> · POST vaults/<id>/rotate
 *          (Drive's vault routes, the interface services/drive-vault.js uses — with the notebook instead of a node)
 *   GET    import/mstodo/accounts · POST import/mstodo/consent · GET import/mstodo/preview?accountId
 *   POST   import/mstodo/start · GET import/jobs/<id> · GET import/mstodo/links · DELETE import/mstodo/links/<id>
 *   POST   import/dsnote/start · POST import/dsnote/<job>/notebook · …/notes · …/finish
 *   PUT    …/gatecontrol-notizen/media                     an attachment's bytes (resumable above 50 MB) → { mediaId }
 *   GET    /plugin-media/<token>                           an attachment (the signed `url` of an Attachment, 1 h)
 *
 * Failures are thrown as MessengerApi's error class { status, code, message, body }.
 */

const MessengerApi = require('./messenger-api');
const GateDropApi = require('./gatedrop-api');
const N = require('../utils/notes');
const drive = require('../utils/drive');

const { MessengerError: NotesError } = MessengerApi;

const MAX_FILE_BYTES = 104857600;            // plugin.json media.maxBytes (100 MB)
const IMAGE_MAX = 16 * 1024 * 1024;          // a picture shown in a note
const IMPORT_TIMEOUT_MS = 120 * 1000;        // a batch of an import (the server copies attachments)
const MEDIA_URL_RE = /^\/plugin-media\/[A-Za-z0-9._~-]{10,600}$/;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class NotesApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {object} [opts.http] - MessengerApi-compatible transport (tests)
   */
  constructor({ apiClient, log, http = null } = {}) {
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.media = new GateDropApi({ http: this.http, log: this.log, mediaPath: N.MEDIA_PATH, maxFileBytes: MAX_FILE_BYTES, label: 'Notizen' });
  }

  scope() {
    return typeof this.http.scope === 'function' ? this.http.scope() : '';
  }

  api(method, path, opts) {
    return this.http._call(method, N.API_BASE + path, opts);
  }

  _id(v) {
    const id = N.posId(v);
    if (!id) throw new NotesError('invalid id', { code: 'invalid' });
    return id;
  }

  _vid(v) {
    const id = N.vaultIdOf(v);
    if (!id) throw new NotesError('invalid vault', { code: 'invalid' });
    return id;
  }

  // ── availability ─────────────────────────────────────────

  /** GET /api/v1/client/plugins → the plugin's entry or null (a plugin without licence is not listed). Throws on errors. */
  async plugin() {
    const data = await this.http._call('GET', N.PLUGINS_PATH);
    const list = Array.isArray(data.plugins) ? data.plugins : [];
    return list.find((x) => x && x.id === N.PLUGIN_ID) || null;
  }

  async me() { return N.normalizeMe(await this.api('GET', 'me')); }

  // ── menu, views, search ──────────────────────────────────

  async nav(area) { return N.normalizeNav(await this.api('GET', 'nav', { params: { area } })); }

  async view(name, area) {
    const v = N.viewName(name);
    if (!v) throw new NotesError('invalid view', { code: 'invalid' });
    return N.normalizeView(await this.api('GET', `views/${encodeURIComponent(v)}`, { params: area ? { area } : undefined }));
  }

  async parse(text, area) {
    const r = await this.api('POST', 'parse', { body: { text, ...(area ? { area } : {}) } });
    return N.normalizeParsed(r.parsed);
  }

  async people() { return N.normalizePeople(await this.api('GET', 'people')); }

  async search(q, area) { return N.normalizeSearch(await this.api('GET', 'search', { params: { q, ...(area ? { area } : {}) } })); }

  async prefs() { return N.normalizePrefs((await this.api('GET', 'prefs')).prefs); }

  async setPrefs(body) { return N.normalizePrefs((await this.api('PUT', 'prefs', { body })).prefs); }

  async sources() { return N.normalizeSources(await this.api('GET', 'sources')); }

  async syncSource(plugin) {
    const r = await this.api('POST', `sources/${encodeURIComponent(plugin)}/sync`, { body: {} });
    return { scheduled: r.scheduled === true, reason: N.line(r.reason, 40) };
  }

  // ── lists and groups ─────────────────────────────────────

  async lists(area) {
    const r = await this.api('GET', 'lists', { params: area ? { area } : undefined });
    return { lists: (r.lists || []).map(N.normalizeList).filter(Boolean), groups: (Array.isArray(r.groups) ? r.groups : []).map(N.normalizeGroup).filter(Boolean) };
  }

  async createList(body) { return N.normalizeList((await this.api('POST', 'lists', { body })).list); }

  async updateList(id, body) { return N.normalizeList((await this.api('PATCH', `lists/${this._id(id)}`, { body })).list); }

  async deleteList(id) { const r = await this.api('DELETE', `lists/${this._id(id)}`); return { left: r.left === true }; }

  async setListMembers(id, members) { return N.normalizeList((await this.api('PUT', `lists/${this._id(id)}/members`, { body: { members } })).list); }

  async createGroup(body) { return N.normalizeGroup((await this.api('POST', 'groups', { body })).group); }

  async updateGroup(id, body) { await this.api('PATCH', `groups/${this._id(id)}`, { body }); return {}; }

  async deleteGroup(id) { await this.api('DELETE', `groups/${this._id(id)}`); return {}; }

  // ── tasks and items ──────────────────────────────────────

  async createTask(body) {
    const r = await this.api('POST', 'tasks', { body });
    return { task: N.normalizeTask(r.task), parsed: r.parsed ? N.normalizeParsed(r.parsed) : null };
  }

  async task(id) { return N.normalizeTask((await this.api('GET', `tasks/${this._id(id)}`)).task); }

  async updateTask(id, body) { return N.normalizeTask((await this.api('PATCH', `tasks/${this._id(id)}`, { body })).task); }

  async completeTask(id, done) {
    const r = await this.api('POST', `tasks/${this._id(id)}/complete`, { body: { done } });
    return { task: N.normalizeTask(r.task), next: r.next ? N.normalizeTask(r.next) : null };
  }

  async deleteTask(id) { await this.api('DELETE', `tasks/${this._id(id)}`); return {}; }

  /** A task to another day ('today' | 'tomorrow' | 'weekend' | 'YYYY-MM-DD'); a second call with the same day changes nothing. */
  async moveTask(id, to) { return N.normalizeTask((await this.api('POST', `tasks/${this._id(id)}/move`, { body: { to } })).task); }

  // ── „Gestern offen geblieben“ ────────────────────────────

  async yesterday(area) { return N.normalizeYesterday(await this.api('GET', 'yesterday', { params: area ? { area } : undefined })); }

  /** Every task of the card (or `ids`) at once → { changed, failed: [{ id, code }], yesterday } */
  async decideYesterday(body) {
    const r = await this.api('POST', 'yesterday', { body });
    return {
      changed: N.count(r.changed) || 0,
      failed: (Array.isArray(r.failed) ? r.failed : []).slice(0, 200).map((f) => (f && N.posId(f.id) ? { id: f.id, code: N.errorCode(f) } : null)).filter(Boolean),
      yesterday: N.normalizeYesterday(r.yesterday),
    };
  }

  async item(id) {
    const r = await this.api('GET', `items/${this._id(id)}`);
    return { item: N.normalizeItem(r.item), taskId: N.posId(r.taskId) };
  }

  async completeItem(id, done) {
    const r = await this.api('POST', `items/${this._id(id)}/complete`, { body: { done } });
    return { item: N.normalizeItem(r.item), taskId: N.posId(r.taskId) };
  }

  async carryItem(id) { return N.normalizeTask((await this.api('POST', `items/${this._id(id)}/carry`, { body: {} })).task); }

  // ── notebooks and notes ──────────────────────────────────

  async notebooks(area) {
    const r = await this.api('GET', 'notebooks', { params: area ? { area } : undefined });
    return { notebooks: (r.notebooks || []).map(N.normalizeNotebook).filter(Boolean), total: N.count(r.total) || 0 };
  }

  async createNotebook(body) { return N.normalizeNotebook((await this.api('POST', 'notebooks', { body })).notebook); }

  async updateNotebook(id, body) { return N.normalizeNotebook((await this.api('PATCH', `notebooks/${this._id(id)}`, { body })).notebook); }

  async deleteNotebook(id) { const r = await this.api('DELETE', `notebooks/${this._id(id)}`); return { left: r.left === true }; }

  async setNotebookMembers(id, members) { return N.normalizeNotebook((await this.api('PUT', `notebooks/${this._id(id)}/members`, { body: { members } })).notebook); }

  async notes(params) {
    const r = await this.api('GET', 'notes', { params });
    return { notes: (r.notes || []).map(N.normalizeNoteSummary).filter(Boolean), next: typeof r.next === 'string' && /^\d{1,15}:\d{1,15}$/.test(r.next) ? r.next : null };
  }

  async note(id) { return this._note(this.api('GET', `notes/${this._id(id)}`)); }

  async _note(p) {
    const n = N.normalizeNote((await p).note);
    if (!n) throw new NotesError('bad note answer', { code: 'bad_response' });
    return n;
  }

  createNote(body) { return this._note(this.api('POST', 'notes', { body })); }

  updateNote(id, body) { return this._note(this.api('PATCH', `notes/${this._id(id)}`, { body })); }

  async deleteNote(id) { await this.api('DELETE', `notes/${this._id(id)}`); return {}; }

  checkNote(id, line, done) { return this._note(this.api('POST', `notes/${this._id(id)}/check`, { body: { line, done } })); }

  async noteToTask(id, body) {
    const r = await this.api('POST', `notes/${this._id(id)}/task`, { body });
    return { task: N.normalizeTask(r.task), note: r.note ? N.normalizeNote(r.note) : null };
  }

  // ── attachments ──────────────────────────────────────────

  async addAttachment(body) { return N.normalizeAttachment((await this.api('POST', 'attachments', { body })).attachment); }

  async attachment(id) { return N.normalizeAttachment((await this.api('GET', `attachments/${this._id(id)}`)).attachment); }

  async deleteAttachment(id) { await this.api('DELETE', `attachments/${this._id(id)}`); return {}; }

  async setAttachmentText(id, text) { await this.api('PUT', `attachments/${this._id(id)}/text`, { body: { text } }); return {}; }

  /** Uploads a file of this PC (or a temporary ciphertext) → { mediaId, mime, bytes }. */
  upload(file, opts) { return this.media.upload(file, opts); }

  _mediaUrl(url) {
    if (typeof url !== 'string' || !MEDIA_URL_RE.test(url) || url.includes('..')) throw new NotesError('invalid media url', { code: 'invalid' });
    return url;
  }

  /** The bytes of an attachment's signed URL (a picture in a note) → { mime, data }. */
  async mediaBytes(url, maxBytes = IMAGE_MAX) { return this.http._binary(this._mediaUrl(url), maxBytes, 60000); }

  /** Streams an attachment into `dest` (writable) → { bytes, mime }. */
  streamMedia(url, dest, opts = {}) { return this.media._stream(this._mediaUrl(url), dest, { maxBytes: MAX_FILE_BYTES, ...opts }); }

  // ── Tresor notebooks (the interface of services/drive-vault.js) ──

  async _vaultAnswer(p) {
    const v = N.normalizeVault((await p).vault);
    if (!v) throw new NotesError('bad vault answer', { code: 'bad_response' });
    return v;
  }

  async vaults() {
    const r = await this.api('GET', 'vaults');
    return (Array.isArray(r.vaults) ? r.vaults : []).slice(0, 1000).map(N.normalizeVault).filter(Boolean);
  }

  vault(id) { return this._vaultAnswer(this.api('GET', `vaults/${this._vid(id)}`)); }

  /** POST vaults { id, area, nameCipher, recoveryPub, recoveryAuth, recoveryWrap, device, wrap } → { vault, notebook } */
  async createVault(body) {
    const r = await this.api('POST', 'vaults', { body: { ...body, id: this._vid(body && body.id) } });
    const vault = N.normalizeVault(r.vault);
    const notebook = N.normalizeNotebook(r.notebook);
    if (!vault || !notebook) throw new NotesError('bad vault answer', { code: 'bad_response' });
    return { vault, notebook };
  }

  async vaultKeys(id, deviceId) {
    const r = drive.normalizeVaultKeys(await this.api('GET', `vaults/${this._vid(id)}/keys`, { params: { deviceId: this._vid(deviceId) } }));
    if (!r) throw new NotesError('bad keys answer', { code: 'bad_response' });
    return r;
  }

  async vaultRecovery(id) {
    const r = drive.normalizeVaultRecovery(await this.api('GET', `vaults/${this._vid(id)}/recovery`));
    if (!r) throw new NotesError('bad recovery answer', { code: 'bad_response' });
    return r;
  }

  setVaultRecovery(id, body) { return this._vaultAnswer(this.api('PUT', `vaults/${this._vid(id)}/recovery`, { body })); }

  async vaultDevices(id) {
    const r = await this.api('GET', `vaults/${this._vid(id)}/devices`);
    return (Array.isArray(r.devices) ? r.devices : []).slice(0, 500).map(drive.normalizeVaultDevice).filter(Boolean);
  }

  async _deviceAnswer(p) {
    const d = drive.normalizeVaultDevice((await p).device);
    if (!d) throw new NotesError('bad device answer', { code: 'bad_response' });
    return d;
  }

  askVault(id, { publicKey, name = null, platform = 'windows' }) {
    const body = { publicKey, platform };
    if (name) body.name = String(name).slice(0, 80);
    return this._deviceAnswer(this.api('POST', `vaults/${this._vid(id)}/devices`, { body }));
  }

  approveVaultDevice(id, deviceId, body) { return this._deviceAnswer(this.api('POST', `vaults/${this._vid(id)}/devices/${this._vid(deviceId)}/approve`, { body })); }

  revokeVaultDevice(id, deviceId) { return this._deviceAnswer(this.api('DELETE', `vaults/${this._vid(id)}/devices/${this._vid(deviceId)}`)); }

  rotateVault(id, body) { return this._vaultAnswer(this.api('POST', `vaults/${this._vid(id)}/rotate`, { body })); }

  // ── moving over ──────────────────────────────────────────

  async msAccounts() { return N.normalizeMsAccounts(await this.api('GET', 'import/mstodo/accounts')); }

  async msConsent(accountId, deviceId = null) {
    const r = N.normalizeConsent(await this.api('POST', 'import/mstodo/consent', { body: { accountId, ...(deviceId ? { deviceId } : {}) }, timeout: 30000 }));
    if (!r) throw new NotesError('bad consent answer', { code: 'bad_response' });
    return r;
  }

  async msPreview(accountId) { return N.normalizeMsPreview(await this.api('GET', 'import/mstodo/preview', { params: { accountId }, timeout: 90000 })); }

  async msStart(body) { return N.normalizeJob((await this.api('POST', 'import/mstodo/start', { body })).job); }

  async job(id) { return N.normalizeJob((await this.api('GET', `import/jobs/${this._id(id)}`)).job); }

  async msLinks() { return N.normalizeMsLinks(await this.api('GET', 'import/mstodo/links')); }

  async msUnlink(id) { await this.api('DELETE', `import/mstodo/links/${this._id(id)}`); return {}; }

  async dsStart(body) { return N.normalizeJob((await this.api('POST', 'import/dsnote/start', { body })).job); }

  async dsNotebook(job, body) {
    const r = await this.api('POST', `import/dsnote/${this._id(job)}/notebook`, { body });
    const id = N.posId(r.notebookId);
    if (!id) throw new NotesError('bad notebook answer', { code: 'bad_response' });
    return id;
  }

  async dsNotes(job, notebookId, notes) {
    const r = await this.api('POST', `import/dsnote/${this._id(job)}/notes`, { body: { notebookId, notes }, timeout: IMPORT_TIMEOUT_MS });
    return { imported: N.count(r.imported) || 0, skipped: N.count(r.skipped) || 0 };
  }

  async dsFinish(job, body) { return N.normalizeJob((await this.api('POST', `import/dsnote/${this._id(job)}/finish`, { body })).job); }
}

NotesApi.NotesError = NotesError;
NotesApi.MAX_FILE_BYTES = MAX_FILE_BYTES;

module.exports = NotesApi;
