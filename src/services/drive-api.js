'use strict';

/**
 * GateControl – Drive API (Core service)
 *
 * REST calls of the plugin `gatecontrol-drive` (README "API") over the device
 * token of the existing ApiClient. The only file that knows the plugin's
 * paths; answers are cleaned by utils/drive.js:
 *
 *   GET    /api/v1/client/plugins                                is the plugin there?
 *   GET    …/gatecontrol-drive/api/me                            seat, licence, areas
 *   GET    …/api/areas                                           areas with their storage
 *   GET    …/api/nodes/<id>  +  …/nodes/<id>/children            a folder (crumbs, role, content)
 *   GET    …/api/nodes/by-path?area&path                         a node by its path in an area
 *   GET    …/api/changes?since&limit                             the change log (folder sync)
 *   POST   …/api/nodes { parentId, name, rename? }               new folder
 *   PATCH  …/api/nodes/<id> { name?, parentId? }                 rename / move
 *   DELETE …/api/nodes/<id>                                      into the trash
 *   DELETE …/api/nodes/<id>?after=<s>&device=<id>                Drive 1.5 'deleteAfter': into the trash later (deleteAt)
 *   PATCH  …/api/nodes/<id> { deleteAt: null }                   Drive 1.5: not any more
 *   POST   …/api/guard/incidents/<id>/release | undo             Drive 1.6 'guard': free this device / undo its changes
 *   GET    …/api/nodes/<id>/content                              → { mediaId, name, mime, size }
 *   GET    …/api/nodes/<id>/versions                             older versions
 *   GET    …/api/nodes/<id>/versions/<vid>/content
 *   POST   …/api/nodes/<id>/versions/<vid>/restore
 *   POST   …/api/uploads/check { parentId, name, sha256?, size? }
 *   POST   …/api/uploads/commit { mediaId, parentId, name, baseRev?, mtime?, onConflict?, text?, entropy? }
 *          (no onConflict and a baseRev that is not the file's rev: 409 conflict { current })
 *   GET    …/api/trash · POST trash/<id>/restore · DELETE trash/<id>
 *   GET    …/api/search?q&area
 *   POST   …/api/links · GET links?nodeId · DELETE links/<token>
 *   PUT    …/gatecontrol-drive/media (resumable: ?uploadId&offset + Content-Range)  → { mediaId }
 *   GET    …/gatecontrol-drive/media/<mediaId>                   the file (streamed)
 *   GET    …/gatecontrol-drive/media/<mediaId>/preview[?size=large]   the preview picture (JPEG)
 *
 * The media upload / download is GateDropApi's code (same core media routes,
 * same resumable protocol) on Drive's media path. Failures are thrown as
 * MessengerApi's error class { status, code, message } (the plugin's code,
 * `http_<status>`, 'network', 'timeout').
 */

const MessengerApi = require('./messenger-api');
const GateDropApi = require('./gatedrop-api');
const drive = require('../utils/drive');

const { MessengerError: DriveError } = MessengerApi;

const JSON_TIMEOUT_MS = 25000;
const PREVIEW_MAX = 2 * 1024 * 1024;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class DriveApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {object} [opts.http] - MessengerApi-compatible transport (tests)
   * @param {() => string} [opts.getLang] - 'de' | 'en' for the plugin's texts
   * @param {(ms: number) => Promise<void>} [opts.sleep]
   * @param {number} [opts.resumableFrom] - larger uploads are resumable (8 MiB)
   * @param {number} [opts.partSize] - resumable part size (8 MiB)
   */
  constructor({ apiClient, log, http = null, getLang = null, sleep = null, resumableFrom = drive.RESUMABLE_FROM, partSize } = {}) {
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.getLang = typeof getLang === 'function' ? getLang : () => null;
    this.media = new GateDropApi({
      http: this.http, log: this.log, sleep, resumableFrom, ...(partSize ? { partSize } : {}),
      mediaPath: drive.MEDIA_PATH, maxFileBytes: drive.MAX_FILE_BYTES, label: 'Drive',
    });
  }

  scope() {
    return typeof this.http.scope === 'function' ? this.http.scope() : '';
  }

  _lang() {
    let l = null;
    try { l = this.getLang(); } catch { l = null; }
    return l === 'de' || l === 'en' ? { lang: l } : {};
  }

  /** JSON call below …/gatecontrol-drive/api/. */
  api(method, p, { body, params, timeout = JSON_TIMEOUT_MS } = {}) {
    return this.http._call(method, drive.API_BASE + p, { body, params: { ...(params || {}), ...this._lang() }, timeout });
  }

  _id(v) {
    const id = drive.posId(v);
    if (!id) throw new DriveError('invalid id', { code: 'invalid' });
    return id;
  }

  // ── Availability ─────────────────────────────────────────

  /** GET /api/v1/client/plugins → the plugin's entry ({ id, version, … }) or null. Throws on errors. */
  async plugin() {
    const data = await this.http._call('GET', drive.PLUGINS_PATH);
    const list = Array.isArray(data.plugins) ? data.plugins : [];
    return list.find((x) => x && x.id === drive.PLUGIN_ID) || null;
  }

  // ── Who, where ───────────────────────────────────────────

  async me() {
    const m = drive.normalizeMe(await this.api('GET', 'me'));
    this._features = { list: m.features, at: Date.now() };
    return m;
  }

  /**
   * Drive 1.5: can this Drive do `name` ('devices', 'deleteAfter', 'emptyFiles')?
   * From the last `me` (asked again after 10 min); false for older Drives.
   */
  async has(name) {
    const f = this._features;
    if (!f || Date.now() - f.at > 10 * 60 * 1000) {
      try { await this.me(); } catch { return !!(f && f.list.includes(name)); }
    }
    return this._features.list.includes(name);
  }

  async areas() { return drive.normalizeAreas(await this.api('GET', 'areas')); }

  // ── The tree ─────────────────────────────────────────────

  /** The folder `id`: its place (crumbs) and its content, folders first. */
  async folder(id, query = {}) {
    const n = this._id(id);
    const head = await this.api('GET', `nodes/${n}`);
    const children = await this.api('GET', `nodes/${n}/children`, { params: drive.childrenQuery(query) });
    const f = drive.normalizeFolder(head, children);
    if (!f) throw new DriveError('bad folder answer', { code: 'bad_response' });
    return f;
  }

  /**
   * One page of a folder's content (raw order of the plugin: folders first, by name)
   * → { items, total, next } (next: the offset of the following page, or null).
   */
  async children(id, { offset = 0, limit = 1000 } = {}) {
    const r = await this.api('GET', `nodes/${this._id(id)}/children`, { params: drive.childrenQuery({ sort: 'name', order: 'asc', offset, limit }) });
    if (!r || !Array.isArray(r.items)) throw new DriveError('bad children answer', { code: 'bad_response' });
    return { items: drive.normalizeItems(r, 1000), total: drive.count(r.total), next: drive.count(r.next), role: drive.ROLES.includes(r.role) ? r.role : null };
  }

  /** Every child of a folder (all pages, at most `max`). */
  async childrenAll(id, { max = 100000 } = {}) {
    const out = [];
    let offset = 0;
    for (;;) {
      const page = await this.children(id, { offset, limit: 1000 });
      out.push(...page.items);
      if (page.next === null || page.next <= offset || out.length >= max) break;
      offset = page.next;
    }
    return out;
  }

  /** GET nodes/by-path?area=&path= → the node, or null when nothing is there (404). */
  async byPath(area, p) {
    const a = drive.areaIdOf(area);
    if (!a || typeof p !== 'string') throw new DriveError('invalid path', { code: 'invalid' });
    try {
      return await this._nodeAnswer(this.api('GET', 'nodes/by-path', { params: { area: a, path: p } }));
    } catch (err) {
      if (err && err.status === 404 && err.code === 'not_found') return null;
      throw err;
    }
  }

  /** GET changes?since=&limit= → { changes, next, more } (utils/drive.js normalizeChanges). */
  async changes(since, { limit = 500 } = {}) {
    const s = drive.count(since) || 0;
    const r = drive.normalizeChanges(await this.api('GET', 'changes', { params: { since: s, limit: Math.min(1000, Math.max(1, limit)) } }));
    if (!r) throw new DriveError('bad changes answer', { code: 'bad_response' });
    if (r.next < s) r.next = s;
    return r;
  }

  async node(id) {
    const node = drive.normalizeNode((await this.api('GET', `nodes/${this._id(id)}`)).node);
    if (!node) throw new DriveError('bad node answer', { code: 'bad_response' });
    return node;
  }

  async _nodeAnswer(promise) {
    const node = drive.normalizeNode((await promise).node);
    if (!node) throw new DriveError('bad node answer', { code: 'bad_response' });
    return node;
  }

  /** A new folder; a taken name gets a free one (`rename`), else 409 exists. */
  mkdir(parentId, name, { rename = true } = {}) {
    return this._nodeAnswer(this.api('POST', 'nodes', { body: { parentId: this._id(parentId), name, rename: rename !== false } }));
  }

  rename(id, name) {
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { name } }));
  }

  move(id, parentId) {
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { parentId: this._id(parentId) } }));
  }

  /** Rename and / or move in one call (PATCH nodes/<id> { name?, parentId? }). */
  place(id, { name = null, parentId = null } = {}) {
    const body = {};
    if (name) body.name = name;
    if (parentId) body.parentId = this._id(parentId);
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body }));
  }

  /**
   * Into the trash → { id, trashed, deleteAt }.
   * Drive 1.5 ('deleteAfter'): with `after` (seconds) the file stays and goes into the trash then
   * (`deleteAt`); `device`: the device it was deleted on (its own folder id of PUT devices/<id>).
   */
  async trash(id, { after = null, device = null } = {}) {
    const params = {};
    if (Number.isSafeInteger(after) && after > 0) {
      params.after = after;
      if (typeof device === 'string' && drive.DEVICE_ID_RE.test(device)) params.device = device;
    }
    const r = await this.api('DELETE', `nodes/${this._id(id)}`, { params });
    const deleteAt = drive.msOf(r.deleteAt) || (r.node && drive.msOf(r.node.deleteAt)) || null;
    const out = { id: drive.posId(r.id) || this._id(id), trashed: params.after ? false : r.trashed !== false };
    if (deleteAt) out.deleteAt = deleteAt;
    return out;
  }

  /** Drive 1.5: a delayed delete is called off (PATCH nodes/<id> { deleteAt: null }) → node. */
  unmark(id) {
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { deleteAt: null } }));
  }

  // ── Guard (Drive 1.6, 'guard') ───────────────────────────

  /** POST guard/incidents/<id>/<'release' | 'undo'> → { incident, restored, trashed } */
  async guardDecide(incidentId, decision) {
    const id = drive.incidentIdOf(incidentId);
    if (!id || (decision !== 'release' && decision !== 'undo')) throw new DriveError('invalid incident', { code: 'invalid' });
    return drive.normalizeGuardAnswer(await this.api('POST', `guard/incidents/${encodeURIComponent(id)}/${decision}`, { body: {}, timeout: 120000 }));
  }

  async search(q, area = null) {
    const params = { q };
    if (area) {
      const a = drive.areaIdOf(area);
      if (!a) throw new DriveError('invalid area', { code: 'invalid' });
      params.area = a;
    }
    return drive.normalizeItems(await this.api('GET', 'search', { params }), 100);
  }

  // ── Versions, trash ──────────────────────────────────────

  async versions(id) {
    const v = drive.normalizeVersions(await this.api('GET', `nodes/${this._id(id)}/versions`));
    if (!v) throw new DriveError('bad versions answer', { code: 'bad_response' });
    return v;
  }

  restoreVersion(id, versionId) {
    return this._nodeAnswer(this.api('POST', `nodes/${this._id(id)}/versions/${this._id(versionId)}/restore`, { body: {} }));
  }

  async trashList(area = null) {
    const params = {};
    if (area) {
      const a = drive.areaIdOf(area);
      if (!a) throw new DriveError('invalid area', { code: 'invalid' });
      params.area = a;
    }
    return drive.normalizeItems(await this.api('GET', 'trash', { params }));
  }

  restore(id) {
    return this._nodeAnswer(this.api('POST', `trash/${this._id(id)}/restore`, { body: {} }));
  }

  /** Gone for good. */
  async purge(id) {
    await this.api('DELETE', `trash/${this._id(id)}`);
    return { id: this._id(id) };
  }

  // ── Links ────────────────────────────────────────────────

  async createLink(opts) {
    const body = drive.linkBody(opts);
    if (!body) throw new DriveError('invalid link', { code: 'invalid' });
    const link = drive.normalizeLink((await this.api('POST', 'links', { body })).link);
    if (!link) throw new DriveError('bad link answer', { code: 'bad_response' });
    return link;
  }

  async links(nodeId = null) {
    const params = nodeId ? { nodeId: this._id(nodeId) } : {};
    return drive.normalizeLinks(await this.api('GET', 'links', { params }));
  }

  async endLink(token) {
    if (!drive.isLinkToken(token)) throw new DriveError('invalid link', { code: 'invalid' });
    await this.api('DELETE', `links/${token}`);
    return { ended: true };
  }

  // ── Files ────────────────────────────────────────────────

  async check({ parentId, name, sha256 = null, size = null }) {
    const body = { parentId: this._id(parentId), name };
    if (drive.sha256Of(sha256)) body.sha256 = drive.sha256Of(sha256);
    if (drive.count(size) !== null) body.size = size;
    const c = drive.normalizeUploadCheck(await this.api('POST', 'uploads/check', { body }));
    if (!c) throw new DriveError('bad check answer', { code: 'bad_response' });
    return c;
  }

  /**
   * `onConflict`: 'rename' (default) | 'version' | null — null with `baseRev`: a new version only
   * while the file still has that rev, else 409 conflict (err.body.current: the file as it is now).
   */
  async commit({ mediaId, parentId, name, mtime = null, onConflict = 'rename', baseRev = null, empty = false, text = null, entropy = null }) {
    // Drive 1.5 ('emptyFiles'): an empty file goes without media as `size: 0`
    if (!empty && !drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    const body = empty ? { parentId: this._id(parentId), name, size: 0 } : { mediaId, parentId: this._id(parentId), name };
    if (onConflict !== null) body.onConflict = drive.ON_CONFLICT.includes(onConflict) ? onConflict : 'rename';
    if (drive.count(baseRev) !== null) body.baseRev = baseRev;
    if (Number.isFinite(mtime) && mtime > 0) body.mtime = Math.round(mtime);
    // the text layer of a PDF for the search (like the Android app), ≤ 100 000 characters
    if (typeof text === 'string' && text.trim()) body.text = text.slice(0, drive.TEXT_MAX);
    // Drive 1.6 ('guard'): the entropy of the first 64 KB (the caller sends it only to such Drives)
    if (Number.isFinite(entropy) && entropy >= 0 && entropy <= 8) body.entropy = Math.round(entropy * 1000) / 1000;
    const c = drive.normalizeCommit(await this.api('POST', 'uploads/commit', { body, timeout: 120000 }));
    if (!c) throw new DriveError('bad commit answer', { code: 'bad_response' });
    return c;
  }

  /**
   * GET nodes/<id>/content (or a version's) → { mediaId, name, mime, size }.
   * Comes first for every download: it names the media and tells a child that a parent looked.
   */
  async content(id, versionId = null) {
    const p = versionId ? `nodes/${this._id(id)}/versions/${this._id(versionId)}/content` : `nodes/${this._id(id)}/content`;
    const c = drive.normalizeContent(await this.api('GET', p));
    if (!c) throw new DriveError('bad content answer', { code: 'bad_response' });
    return c;
  }

  // ── Devices (Drive 1.5, 'devices') ───────────────────────

  /**
   * PUT devices/<id> { name, platform, version } → { id, name, platform, folder }: registers this PC
   * (or updates "last seen"); the Drive gives it its folder Meine Dateien › Geräte › <Name>
   * (names are unique per person: a second "PC" becomes "PC (2)").
   */
  async putDevice(id, { name, platform = 'windows', version = '' } = {}) {
    if (typeof id !== 'string' || !drive.DEVICE_ID_RE.test(id)) throw new DriveError('invalid device id', { code: 'invalid' });
    const body = { name: String(name || 'PC').slice(0, 100), platform: String(platform).slice(0, 20) };
    if (version) body.version = String(version).slice(0, 40);
    const d = drive.normalizeDevice(await this.api('PUT', `devices/${encodeURIComponent(id)}`, { body }));
    if (!d) throw new DriveError('bad device answer', { code: 'bad_response' });
    return d;
  }

  /** PUT devices/<id>/folders [{ localPath, mode, nodeId, lastBackup }]: the folders this PC backs up / syncs (portal "Geräte"). */
  async putDeviceFolders(id, folders) {
    if (typeof id !== 'string' || !drive.DEVICE_ID_RE.test(id)) throw new DriveError('invalid device id', { code: 'invalid' });
    const list = (Array.isArray(folders) ? folders : []).slice(0, 100).map((f) => ({
      localPath: String(f.localPath || '').slice(0, 1000),
      mode: f.mode === 'sync' ? 'sync' : 'backup',
      nodeId: drive.posId(f.nodeId),
      lastBackup: Number.isFinite(f.lastBackup) && f.lastBackup > 0 ? new Date(f.lastBackup).toISOString() : null,
    }));
    await this.api('PUT', `devices/${encodeURIComponent(id)}/folders`, { body: { folders: list } });
    return { ok: true };
  }

  /** Streams the media `mediaId` into `dest` → { bytes, mime }. */
  download(mediaId, dest, opts = {}) {
    if (!drive.isMediaId(mediaId)) return Promise.reject(new DriveError('invalid media id', { code: 'invalid' }));
    return this.media.streamTo(`${drive.MEDIA_PATH}/${mediaId}`, dest, opts);
  }

  /** Uploads a file from disk (resumable above 8 MiB) → { mediaId, mime, bytes }. */
  upload(file, opts) {
    return this.media.upload(file, opts);
  }

  /**
   * The preview picture of a file (`large`: 1280 px, else 320 px) → { mime, data }.
   * 503 `preview_pending` while GateControl still makes it; 404 none.
   */
  async preview(mediaId, { large = false } = {}) {
    if (!drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    const url = `${drive.MEDIA_PATH}/${mediaId}/preview${large ? '?size=large' : ''}`;
    const r = await this.http._binary(url, PREVIEW_MAX, JSON_TIMEOUT_MS);
    if (!/^image\/(jpeg|png|webp)$/.test(r.mime) || !r.data.length) throw new DriveError('not a picture', { code: 'bad_response' });
    return r;
  }
}

DriveApi.DriveError = DriveError;

module.exports = DriveApi;
