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
 *   GET    …/api/nodes/<id>/children?dirs=1                      Drive 1.11 'vaultsApart': its folders (hasDirs) for the menu
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
 *   GET    …/api/nodes/<id>/timetravel?at=<ISO>                  Drive 1.7 'timeTravel': what a time travel would do
 *   POST   …/api/nodes/<id>/timetravel { at }                    … and doing it
 *   GET    …/api/photos?area&before&limit · photos/months?area · photos/memories?date   Drive 1.7 'photos'
 *   GET/POST …/api/albums · PATCH/DELETE albums/<id> · GET albums/<id>?before&limit
 *   POST/DELETE …/api/albums/<id>/items { ids }                   Drive 1.7 'albums' ('frame': PATCH { frame })
 *   GET    …/api/storage[?all=1] · POST storage/versions/prune { areaId, keep }   Drive 1.7 'storage'
 *   GET|POST …/api/nodes/<id>/insight · POST nodes/<id>/insight/apply { name?, folder? }   Drive 1.8 'docAi'
 *   GET    …/api/deadlines?from&to · POST|DELETE deadlines/<id>/remind { daysBefore } · PATCH areas/<id> { docAi }
 *   POST   …/api/nodes/<id>/office                               Drive 1.9 'office' → { url, mode, expiresAt }
 *   GET|POST …/api/vaults · GET vaults/<id> · GET vaults/<id>/keys?deviceId · GET|PUT vaults/<id>/recovery
 *   GET|POST …/api/vaults/<id>/devices · POST …/devices/<did>/approve · DELETE …/devices/<did> · POST vaults/<id>/rotate
 *          (Drive 1.9 'vault'; POST nodes, uploads/commit and PATCH nodes/<id> take encrypted, nameCipher, keyVersion)
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
const isB64u = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && /^[A-Za-z0-9_-]+$/.test(v);

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

  /**
   * Drive 1.11: the subfolders of a folder for the menu's tree → { items: [{ id, name, hasDirs }], next }. With
   * 'vaultsApart' `children?dirs=1` (folders only, no vaults, `hasDirs`), else the plain children filtered here
   * (hasDirs null: unknown until opened).
   */
  async dirs(id, { offset = 0, limit = 1000, apart = false } = {}) {
    const params = drive.childrenQuery({ sort: 'name', order: 'asc', offset, limit });
    if (apart) params.dirs = 1;
    const r = await this.api('GET', `nodes/${this._id(id)}/children`, { params });
    if (!r || !Array.isArray(r.items)) throw new DriveError('bad children answer', { code: 'bad_response' });
    const d = drive.normalizeDirs(r, 1000);
    // an older Drive sends folders first: a page with files has all folders already
    if (!apart && d.next !== null && r.items.some((x) => x && x.isDir === false)) d.next = null;
    return d;
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
  async commit({ mediaId, parentId, name, mtime = null, onConflict = 'rename', baseRev = null, empty = false, text = null, entropy = null, takenAt = null, encrypted = null }) {
    // Drive 1.9 ('vault'): into a vault only the ciphertext with { nameCipher, keyVersion } (name: the opaque name of a
    // file of the vault for a new version) — never text, takenAt, entropy
    if (encrypted) return this._commitEncrypted({ mediaId, parentId, name, mtime, onConflict, baseRev, ...encrypted });
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
    // Drive 1.7 ('takenAt'): when the photo / video was taken (ISO with the offset; the caller sends it only to such Drives)
    if (typeof takenAt === 'string' && takenAt.length <= 40 && Number.isFinite(Date.parse(takenAt))) body.takenAt = takenAt;
    const c = drive.normalizeCommit(await this.api('POST', 'uploads/commit', { body, timeout: 120000 }));
    if (!c) throw new DriveError('bad commit answer', { code: 'bad_response' });
    return c;
  }

  async _commitEncrypted({ mediaId, parentId, name = null, mtime = null, onConflict = null, baseRev = null, nameCipher = null, keyVersion }) {
    if (!drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    const kv = drive.posId(keyVersion);
    if (!kv || (nameCipher !== null && !isB64u(nameCipher, 2000)) || (name !== null && !/^[0-9a-f]{32}$/.test(String(name)))) throw new DriveError('invalid', { code: 'invalid' });
    if (!nameCipher && !name) throw new DriveError('invalid', { code: 'invalid' });
    const body = { mediaId, parentId: this._id(parentId), encrypted: true, keyVersion: kv };
    if (nameCipher) body.nameCipher = nameCipher;
    if (name) body.name = name;
    if (onConflict === 'version' || onConflict === 'rename') body.onConflict = onConflict;
    if (drive.count(baseRev) !== null) body.baseRev = baseRev;
    if (Number.isFinite(mtime) && mtime > 0) body.mtime = Math.round(mtime);
    const c = drive.normalizeCommit(await this.api('POST', 'uploads/commit', { body, timeout: 120000 }));
    if (!c) throw new DriveError('bad commit answer', { code: 'bad_response' });
    return c;
  }

  /** Drive 1.9 ('vault'): a folder in a vault (POST nodes { parentId, encrypted, nameCipher, keyVersion }). */
  mkdirEncrypted(parentId, { nameCipher, keyVersion }) {
    if (!isB64u(nameCipher, 2000) || !drive.posId(keyVersion)) throw new DriveError('invalid', { code: 'invalid' });
    return this._nodeAnswer(this.api('POST', 'nodes', { body: { parentId: this._id(parentId), encrypted: true, nameCipher, keyVersion: drive.posId(keyVersion) } }));
  }

  /** Drive 1.9 ('vault'): a vault node's new name (PATCH nodes/<id> { nameCipher }). */
  renameEncrypted(id, nameCipher) {
    if (!isB64u(nameCipher, 2000)) throw new DriveError('invalid', { code: 'invalid' });
    return this._nodeAnswer(this.api('PATCH', `nodes/${this._id(id)}`, { body: { nameCipher } }));
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

  // ── Time travel (Drive 1.7, 'timeTravel') ───────────────

  _at(at) {
    const iso = drive.isoOf(at);
    if (!iso) throw new DriveError('invalid time', { code: 'invalid' });
    return iso;
  }

  /** GET nodes/<id>/timetravel?at= → { at, historySince, restore, revert, trash, move, total, sample, limited } (changes nothing) */
  async timeTravelPreview(id, at) {
    const r = drive.normalizeTimeTravelPreview(await this.api('GET', `nodes/${this._id(id)}/timetravel`, { params: { at: this._at(at) }, timeout: 120000 }));
    if (!r) throw new DriveError('bad time travel answer', { code: 'bad_response' });
    return r;
  }

  /** POST nodes/<id>/timetravel { at } → { at, before, restored, reverted, trashed, moved, failed } */
  async timeTravel(id, at) {
    const r = drive.normalizeTimeTravelResult(await this.api('POST', `nodes/${this._id(id)}/timetravel`, { body: { at: this._at(at) }, timeout: 300000 }));
    if (!r) throw new DriveError('bad time travel answer', { code: 'bad_response' });
    return r;
  }

  // ── Photos and albums (Drive 1.7, 'photos' / 'albums') ──

  _area(area) {
    if (area === null || area === undefined || area === '') return {};
    const a = drive.areaIdOf(area);
    if (!a) throw new DriveError('invalid area', { code: 'invalid' });
    return { area: a };
  }

  _page({ before = null, limit = 100 } = {}) {
    const params = { limit: Math.min(200, Math.max(1, drive.posId(limit) || 100)) };
    if (before !== null && before !== undefined && before !== '') {
      const c = drive.cursorOf(before);
      if (!c) throw new DriveError('invalid cursor', { code: 'invalid' });
      params.before = c;
    }
    return params;
  }

  _albumId(id) {
    const a = drive.albumIdOf(id);
    if (!a) throw new DriveError('invalid album', { code: 'invalid' });
    return encodeURIComponent(String(a));
  }

  _ids(ids) {
    const list = [...new Set((Array.isArray(ids) ? ids : []).map(drive.posId).filter(Boolean))];
    if (!list.length || list.length > 500) throw new DriveError('invalid ids', { code: 'invalid' });
    return list;
  }

  /** GET photos?area=&before=&limit= → { items, next } (newest first by takenAt) */
  async photos({ area = null, before = null, limit = 100 } = {}) {
    return drive.normalizePhotos(await this.api('GET', 'photos', { params: { ...this._area(area), ...this._page({ before, limit }) } }));
  }

  /** GET photos/months?area= → { months: [{ month, count }] } */
  async photoMonths(area = null) {
    return drive.normalizeMonths(await this.api('GET', 'photos/months', { params: this._area(area) }));
  }

  /** GET photos/memories?date=YYYY-MM-DD → { groups: [{ yearsAgo, date, items }] } */
  async memories(date = null) {
    const params = {};
    if (date) {
      if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new DriveError('invalid date', { code: 'invalid' });
      params.date = date;
    }
    return drive.normalizeMemories(await this.api('GET', 'photos/memories', { params }));
  }

  async albums() {
    return drive.normalizeAlbums(await this.api('GET', 'albums'));
  }

  async _albumAnswer(promise) {
    const a = drive.normalizeAlbum((await promise).album);
    if (!a) throw new DriveError('bad album answer', { code: 'bad_response' });
    return a;
  }

  /** POST albums { name, areaId? } → album */
  createAlbum({ name, areaId = null } = {}) {
    const body = { name: String(name || '').trim().slice(0, 200) };
    if (!body.name) throw new DriveError('invalid name', { code: 'invalid_name' });
    if (areaId) {
      const a = drive.areaIdOf(areaId);
      if (!a) throw new DriveError('invalid area', { code: 'invalid' });
      body.areaId = a;
    }
    return this._albumAnswer(this.api('POST', 'albums', { body }));
  }

  /** PATCH albums/<id> { name?, coverId?, frame? } → album */
  updateAlbum(id, { name, coverId, frame } = {}) {
    const body = {};
    if (name !== undefined) {
      body.name = String(name || '').trim().slice(0, 200);
      if (!body.name) throw new DriveError('invalid name', { code: 'invalid_name' });
    }
    if (coverId !== undefined) body.coverId = coverId === null ? null : this._id(coverId);
    if (frame !== undefined) body.frame = frame === true;
    if (!Object.keys(body).length) throw new DriveError('nothing to change', { code: 'invalid' });
    return this._albumAnswer(this.api('PATCH', `albums/${this._albumId(id)}`, { body }));
  }

  async deleteAlbum(id) {
    await this.api('DELETE', `albums/${this._albumId(id)}`);
    return { ok: true };
  }

  /** GET albums/<id>?before=&limit= → { album, items, next } */
  async album(id, { before = null, limit = 100 } = {}) {
    const r = drive.normalizeAlbumPage(await this.api('GET', `albums/${this._albumId(id)}`, { params: this._page({ before, limit }) }));
    if (!r) throw new DriveError('bad album answer', { code: 'bad_response' });
    return r;
  }

  /**
   * POST / DELETE albums/<id>/items { ids } (≤ 500, pictures and videos) → album.
   * DELETE also carries the ids as `?ids=1,2,3` (a body of a DELETE may not pass every proxy).
   */
  albumItems(id, ids, { remove = false } = {}) {
    const list = this._ids(ids);
    return this._albumAnswer(this.api(remove ? 'DELETE' : 'POST', `albums/${this._albumId(id)}/items`, { body: { ids: list }, ...(remove ? { params: { ids: list.join(',') } } : {}) }));
  }

  // ── Storage (Drive 1.7, 'storage') ───────────────────────

  /** GET storage[?all=1] → { total, limit, areas, people, largest, duplicates } */
  async storage({ all = false } = {}) {
    const r = drive.normalizeStorage(await this.api('GET', 'storage', { params: all ? { all: 1 } : {}, timeout: 120000 }));
    if (!r) throw new DriveError('bad storage answer', { code: 'bad_response' });
    return r;
  }

  /** POST storage/versions/prune { areaId, keep } → { removed, freedBytes, more } (more: there is more to remove, run it again) */
  async pruneVersions({ areaId, keep } = {}) {
    const a = drive.areaIdOf(areaId);
    const k = drive.count(keep);
    if (!a || k === null || k > 1000) throw new DriveError('invalid', { code: 'invalid' });
    const r = await this.api('POST', 'storage/versions/prune', { body: { areaId: a, keep: k }, timeout: 300000 });
    return { removed: drive.count(r.removed) || 0, freedBytes: drive.count(r.freedBytes) || 0, more: r.more === true };
  }

  // ── AI for documents (Drive 1.8, 'docAi') ────────────────

  async _insight(promise) {
    const r = drive.normalizeInsight(await promise);
    if (!r) throw new DriveError('bad insight answer', { code: 'bad_response' });
    return r;
  }

  /** GET nodes/<id>/insight → { status, kind, title, date, sender, amount, currency, error, at, suggestion, deadlines } */
  insight(id) {
    return this._insight(this.api('GET', `nodes/${this._id(id)}/insight`));
  }

  /** POST nodes/<id>/insight: recognise again (write right; 422 unsupported { reason: no_text | media_disabled }) */
  recognize(id) {
    return this._insight(this.api('POST', `nodes/${this._id(id)}/insight`, { body: {} }));
  }

  /** POST nodes/<id>/insight/apply { name?: true, folder?: true } → { node, insight } */
  async applyInsight(id, { name = false, folder = false } = {}) {
    const body = {};
    if (name === true) body.name = true;
    if (folder === true) body.folder = true;
    if (!Object.keys(body).length) throw new DriveError('nothing to apply', { code: 'invalid' });
    const r = await this.api('POST', `nodes/${this._id(id)}/insight/apply`, { body });
    const node = drive.normalizeNode(r && r.node);
    const insight = drive.normalizeInsight(r && r.insight);
    if (!node) throw new DriveError('bad apply answer', { code: 'bad_response' });
    return { node, insight };
  }

  /** GET deadlines?from=&to= (YYYY-MM-DD; default today … +365 days) → { deadlines } */
  async deadlines({ from = null, to = null } = {}) {
    const params = {};
    for (const [k, v] of [['from', from], ['to', to]]) {
      if (v === null || v === undefined || v === '') continue;
      if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) throw new DriveError('invalid date', { code: 'invalid' });
      params[k] = v;
    }
    return drive.normalizeDeadlines(await this.api('GET', 'deadlines', { params }));
  }

  async _deadline(promise) {
    const d = drive.normalizeDeadline((await promise).deadline);
    if (!d) throw new DriveError('bad deadline answer', { code: 'bad_response' });
    return d;
  }

  /** POST deadlines/<id>/remind { daysBefore: 0…90 } → deadline (the reminder is the person's own) */
  remind(id, daysBefore) {
    const days = drive.count(daysBefore);
    if (days === null || days > 90) throw new DriveError('invalid', { code: 'invalid' });
    return this._deadline(this.api('POST', `deadlines/${this._id(id)}/remind`, { body: { daysBefore: days } }));
  }

  /** DELETE deadlines/<id>/remind → deadline */
  unremind(id) {
    return this._deadline(this.api('DELETE', `deadlines/${this._id(id)}/remind`));
  }

  /** PATCH areas/<id> { docAi } → { id, docAi } */
  async setDocAi(areaId, on) {
    const a = drive.areaIdOf(areaId);
    if (!a || typeof on !== 'boolean') throw new DriveError('invalid', { code: 'invalid' });
    const r = await this.api('PATCH', `areas/${encodeURIComponent(a)}`, { body: { docAi: on } });
    const area = r && r.area && typeof r.area === 'object' ? r.area : {};
    return { id: drive.areaIdOf(area.id) || a, docAi: typeof area.docAi === 'boolean' ? area.docAi : on };
  }

  // ── Office in the browser (Drive 1.9, 'office') ─────────

  /** POST nodes/<id>/office → { url, mode: 'edit' | 'view', expiresAt } (409 encrypted / office_unavailable) */
  async office(id) {
    const r = drive.normalizeOffice(await this.api('POST', `nodes/${this._id(id)}/office`, { body: {} }));
    if (!r) throw new DriveError('bad office answer', { code: 'bad_response' });
    return r;
  }

  // ── Vault folders (Drive 1.9, 'vault') ───────────────────

  _vaultId(id) {
    const v = drive.vaultIdOf(id);
    if (!v) throw new DriveError('invalid vault', { code: 'invalid' });
    return v;
  }

  _deviceId(id) {
    const d = drive.vaultDeviceIdOf(id);
    if (!d) throw new DriveError('invalid device', { code: 'invalid' });
    return d;
  }

  async _vaultAnswer(promise) {
    const v = drive.normalizeVault((await promise).vault);
    if (!v) throw new DriveError('bad vault answer', { code: 'bad_response' });
    return v;
  }

  /** GET vaults → [vault] */
  async vaults() {
    const r = await this.api('GET', 'vaults');
    return (Array.isArray(r && r.vaults) ? r.vaults : []).slice(0, 1000).map(drive.normalizeVault).filter(Boolean);
  }

  vault(id) {
    return this._vaultAnswer(this.api('GET', `vaults/${this._vaultId(id)}`));
  }

  /** POST vaults { id, parentId, nameCipher, recoveryPub, recoveryAuth, recoveryWrap, device, wrap } → { vault, node } */
  async createVault(body) {
    const r = await this.api('POST', 'vaults', { body: { ...body, id: this._vaultId(body && body.id), parentId: this._id(body && body.parentId) } });
    const vault = drive.normalizeVault(r && r.vault);
    const node = drive.normalizeNode(r && r.node);
    if (!vault || !node) throw new DriveError('bad vault answer', { code: 'bad_response' });
    return { vault, node };
  }

  /** GET vaults/<id>/keys?deviceId= → { deviceId, state, keyVersion, keys } (404: this device never asked) */
  async vaultKeys(id, deviceId) {
    const r = drive.normalizeVaultKeys(await this.api('GET', `vaults/${this._vaultId(id)}/keys`, { params: { deviceId: this._deviceId(deviceId) } }));
    if (!r) throw new DriveError('bad keys answer', { code: 'bad_response' });
    return r;
  }

  /** GET vaults/<id>/recovery → { recoveryPub, keyVersion, keys } */
  async vaultRecovery(id) {
    const r = drive.normalizeVaultRecovery(await this.api('GET', `vaults/${this._vaultId(id)}/recovery`));
    if (!r) throw new DriveError('bad recovery answer', { code: 'bad_response' });
    return r;
  }

  /** PUT vaults/<id>/recovery { pub, auth, wraps } → vault */
  setVaultRecovery(id, body) {
    return this._vaultAnswer(this.api('PUT', `vaults/${this._vaultId(id)}/recovery`, { body }));
  }

  /** GET vaults/<id>/devices → [device] */
  async vaultDevices(id) {
    const r = await this.api('GET', `vaults/${this._vaultId(id)}/devices`);
    return (Array.isArray(r && r.devices) ? r.devices : []).slice(0, 500).map(drive.normalizeVaultDevice).filter(Boolean);
  }

  async _deviceAnswer(promise) {
    const d = drive.normalizeVaultDevice((await promise).device);
    if (!d) throw new DriveError('bad device answer', { code: 'bad_response' });
    return d;
  }

  /** POST vaults/<id>/devices { publicKey, name, platform } → device (the request; pending) */
  askVault(id, { publicKey, name = null, platform = 'windows' }) {
    const body = { publicKey, platform };
    if (name) body.name = String(name).slice(0, 80);
    return this._deviceAnswer(this.api('POST', `vaults/${this._vaultId(id)}/devices`, { body }));
  }

  /** POST vaults/<id>/devices/<did>/approve { wraps, via?, recoveryAuth? } → device */
  approveVaultDevice(id, deviceId, body) {
    return this._deviceAnswer(this.api('POST', `vaults/${this._vaultId(id)}/devices/${this._deviceId(deviceId)}/approve`, { body }));
  }

  /** DELETE vaults/<id>/devices/<did> → device (declined / removed) */
  revokeVaultDevice(id, deviceId) {
    return this._deviceAnswer(this.api('DELETE', `vaults/${this._vaultId(id)}/devices/${this._deviceId(deviceId)}`));
  }

  /** POST vaults/<id>/rotate { keyVersion, wraps, recoveryWrap | recovery } → vault */
  rotateVault(id, body) {
    return this._vaultAnswer(this.api('POST', `vaults/${this._vaultId(id)}/rotate`, { body }));
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
