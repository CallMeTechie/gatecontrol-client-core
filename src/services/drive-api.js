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
 *   POST   …/api/nodes { parentId, name, rename? }               new folder
 *   PATCH  …/api/nodes/<id> { name?, parentId? }                 rename / move
 *   DELETE …/api/nodes/<id>                                      into the trash
 *   GET    …/api/nodes/<id>/content                              → { mediaId, name, mime, size }
 *   GET    …/api/nodes/<id>/versions                             older versions
 *   GET    …/api/nodes/<id>/versions/<vid>/content
 *   POST   …/api/nodes/<id>/versions/<vid>/restore
 *   POST   …/api/uploads/check { parentId, name, sha256?, size? }
 *   POST   …/api/uploads/commit { mediaId, parentId, name, mtime?, onConflict }
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

  async me() { return drive.normalizeMe(await this.api('GET', 'me')); }

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

  /** A new folder; a taken name gets a free one (`rename`). */
  mkdir(parentId, name) {
    return this._nodeAnswer(this.api('POST', 'nodes', { body: { parentId: this._id(parentId), name, rename: true } }));
  }

  rename(id, name) {
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { name } }));
  }

  move(id, parentId) {
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { parentId: this._id(parentId) } }));
  }

  /** Into the trash → { id, trashed }. */
  async trash(id) {
    const r = await this.api('DELETE', `nodes/${this._id(id)}`);
    return { id: drive.posId(r.id), trashed: r.trashed !== false };
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

  async commit({ mediaId, parentId, name, mtime = null, onConflict = 'rename' }) {
    if (!drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    const body = { mediaId, parentId: this._id(parentId), name, onConflict: drive.ON_CONFLICT.includes(onConflict) ? onConflict : 'rename' };
    if (Number.isFinite(mtime) && mtime > 0) body.mtime = Math.round(mtime);
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
