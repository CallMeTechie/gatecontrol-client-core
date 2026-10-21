'use strict';

/**
 * GateControl – GateDrop API (Core service)
 *
 * REST calls of the plugin `gatecontrol-gatedrop` (contract B) over the
 * device token of the existing ApiClient. This is the only file that knows
 * the plugin's paths; answers are cleaned by utils/gatedrop.js, so contract
 * changes stay here:
 *
 *   GET    /api/v1/client/plugins                                   is the plugin there?
 *   GET    …/gatecontrol-gatedrop/api/targets                       people, own devices, NAS, links
 *   PUT    …/api/presence { lan, port, listening }                  LAN addresses of this PC
 *   POST   …/api/sends { items, text?, link?, note?, to }           → { id, deliveries, link?, direct }
 *   POST   …/api/sends/<id>/items { items }                         media after a failed direct transfer
 *   POST   …/api/transfers/<id>/result { ok, bytes?, error? }       → { fallback? }
 *   GET    …/api/transfers/<id>                                     ticket of a transfer (listener)
 *   GET    …/api/inbox?kind=received|sent|links
 *   GET    …/api/sends/<id>
 *   GET    …/api/items/<mediaId>                                    download (streamed)
 *   POST   …/api/sends/<id>/opened
 *   DELETE …/api/links/<token>
 *   PUT    …/gatecontrol-gatedrop/media                             raw upload (streamed)
 *          ?uploadId=&offset= + Content-Range                       resumable (> 50 MB, core ≥ 1.193)
 *   HEAD   …/gatecontrol-gatedrop/media/uploads/<uploadId>          → offset of a cut-off upload
 *
 * Failures are thrown as MessengerApi's error class { status, code,
 * message } (same mapping as the chats: plugin `code`, `http_<status>`,
 * 'network', 'timeout'), exported here as GateDropApi.GateDropError.
 */

const fs = require('fs');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const MessengerApi = require('./messenger-api');
const gd = require('../utils/gatedrop');

const { MessengerError: GateDropError, toMessengerError } = MessengerApi;

const UPLOAD_IDLE_MS = 5 * 60 * 1000;     // socket idle limit of uploads / downloads
const DOWNLOAD_IDLE_MS = 2 * 60 * 1000;
const RESUME_ATTEMPTS = 5;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Counts bytes going through (progress) without copying. */
function counter(onBytes) {
  return new Transform({
    transform(chunk, _e, cb) {
      try { onBytes(chunk.length); } catch { /* UI */ }
      cb(null, chunk);
    },
  });
}

class GateDropApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {object} [opts.http] - MessengerApi-compatible transport (tests)
   * @param {() => Promise<void>} [opts.sleep]
   * @param {number} [opts.resumableFrom] - uploads above this size are resumable (50 MB)
   */
  constructor({ apiClient, log, http = null, sleep = null, resumableFrom = gd.RESUMABLE_FROM } = {}) {
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.sleep = sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.resumableFrom = resumableFrom;
    this.resumable = null; // null = try, false = the server refused the resumable parameters
  }

  scope() {
    return typeof this.http.scope === 'function' ? this.http.scope() : '';
  }

  _client() {
    return this.http._client();
  }

  /** JSON call below …/gatecontrol-gatedrop/api/. */
  api(method, p, opts) {
    return this.http._call(method, gd.API_BASE + p, opts);
  }

  _id(v) {
    const id = gd.idOf(v);
    if (!id) throw new GateDropError('invalid id', { code: 'invalid' });
    return encodeURIComponent(id);
  }

  // ── Availability ─────────────────────────────────────────

  /** GET /api/v1/client/plugins → the plugin's entry ({ id, version, … }) or null. Throws on errors. */
  async plugin() {
    const data = await this.http._call('GET', gd.PLUGINS_PATH);
    const list = Array.isArray(data.plugins) ? data.plugins : [];
    return list.find((x) => x && x.id === gd.PLUGIN_ID) || null;
  }

  // ── JSON API ─────────────────────────────────────────────

  async targets() { return gd.normalizeTargets(await this.api('GET', 'targets')); }

  async presence({ lan, port, listening }) {
    return this.api('PUT', 'presence', { body: { lan: lan.map((a) => ({ ip: a.ip, prefix: a.prefix })), port, listening: listening === true } });
  }

  async createSend(body) { return gd.normalizeSendResult(await this.api('POST', 'sends', { body, timeout: 60000 })); }

  async addItems(sendId, items) { return this.api('POST', `sends/${this._id(sendId)}/items`, { body: { items }, timeout: 60000 }); }

  async transferResult(transferId, { ok, bytes, error } = {}) {
    if (!gd.isTransferId(transferId)) throw new GateDropError('invalid transfer', { code: 'invalid' });
    const body = { ok: ok === true };
    if (Number.isSafeInteger(bytes) && bytes >= 0) body.bytes = bytes;
    if (!body.ok && error) body.error = String(error).slice(0, 200);
    const r = await this.api('POST', `transfers/${transferId}/result`, { body });
    return { fallback: r && typeof r.fallback === 'string' ? r.fallback : null };
  }

  /** GET transfers/<id> → the same shape as the silent push (parsePushData), or null. */
  async transfer(transferId) {
    if (!gd.isTransferId(transferId)) throw new GateDropError('invalid transfer', { code: 'invalid' });
    const r = await this.api('GET', `transfers/${transferId}`);
    const t = r && typeof r === 'object' ? (r.transfer && typeof r.transfer === 'object' ? r.transfer : r) : null;
    if (!t) return null;
    return gd.parsePushData({ gatedrop: { transfer: transferId, ...t } });
  }

  async inbox(kind) {
    const k = gd.INBOX_KINDS.includes(kind) ? kind : 'received';
    return gd.normalizeInbox(await this.api('GET', 'inbox', { params: { kind: k } }), k);
  }

  async send(id) {
    const r = await this.api('GET', `sends/${this._id(id)}`);
    return gd.normalizeSend(r && r.send && typeof r.send === 'object' ? r.send : r);
  }

  async opened(id) { return this.api('POST', `sends/${this._id(id)}/opened`, { body: {} }); }

  async endLink(token) {
    if (!gd.isLinkToken(token)) throw new GateDropError('invalid link', { code: 'invalid' });
    return this.api('DELETE', `links/${token}`);
  }

  // ── Media ────────────────────────────────────────────────

  /**
   * Upload a file from disk (streamed) → { mediaId, mime, bytes }.
   * Files above 50 MB go up resumable: a cut connection continues at the
   * offset the server reports (HEAD media/uploads/<id>), up to 5 times.
   * @param {{ path: string, size: number, mime: string }} file
   * @param {{ onProgress?: (sent: number, total: number) => void }} [opts]
   */
  async upload(file, { onProgress } = {}) {
    const size = file && file.size;
    if (!file || typeof file.path !== 'string' || !Number.isSafeInteger(size) || size <= 0) throw new GateDropError('empty file', { code: 'length_required' });
    if (size > gd.MAX_FILE_BYTES) throw new GateDropError('file too large', { code: 'too_large' });
    const mime = typeof file.mime === 'string' && file.mime ? file.mime : 'application/octet-stream';
    const progress = typeof onProgress === 'function' ? onProgress : () => {};
    if (size <= this.resumableFrom || this.resumable === false) return this._put(file.path, { mime, size, start: 0, progress });

    const uploadId = crypto.randomBytes(18).toString('base64url');
    let offset = 0;
    for (let attempt = 0; ; attempt++) {
      try {
        return await this._put(file.path, { mime, size, start: offset, progress, uploadId });
      } catch (err) {
        if (err.status === 400 && offset === 0 && attempt === 0 && /upload/i.test(err.code || '')) {
          // A server without resumable uploads: plain PUT.
          this.resumable = false;
          return this._put(file.path, { mime, size, start: 0, progress });
        }
        if (!err.transient || attempt >= RESUME_ATTEMPTS - 1) throw err;
        await this.sleep(Math.min(30000, 1000 * 2 ** attempt));
        const at = await this.uploadOffset(uploadId).catch(() => null);
        offset = at !== null && at <= size ? at : 0;
        this.log.info(`GateDrop upload continues at ${offset} of ${size} bytes`);
      }
    }
  }

  async _put(filePath, { mime, size, start, progress, uploadId = null }) {
    const client = this._client();
    const params = {};
    const headers = { 'Content-Type': mime, 'Content-Length': String(size - start) };
    if (uploadId) {
      params.uploadId = uploadId;
      if (start > 0) {
        params.offset = start;
        headers['Content-Range'] = `bytes ${start}-${size - 1}/${size}`;
      }
    }
    let sent = start;
    const src = fs.createReadStream(filePath, { start });
    const body = src.pipe(counter((n) => { sent += n; progress(sent, size); }));
    src.on('error', (e) => body.destroy(e));
    try {
      const res = await client.request({
        method: 'PUT',
        url: gd.MEDIA_PATH,
        params,
        data: body,
        headers,
        timeout: UPLOAD_IDLE_MS,
        maxBodyLength: Infinity,
        maxContentLength: 1024 * 1024,
        maxRedirects: 0, // no redirect buffering of a 2 GB body
        transformRequest: [(d) => d],
      });
      const d = res.data || {};
      if (!gd.isMediaId(d.mediaId)) throw new GateDropError('bad upload answer', { status: res.status, code: 'bad_response' });
      return { mediaId: d.mediaId, mime: typeof d.mime === 'string' ? d.mime : mime, bytes: Number(d.bytes) || size };
    } catch (err) {
      src.destroy();
      throw toMessengerError(err);
    }
  }

  /** Bytes the server already holds of a resumable upload, or null. */
  async uploadOffset(uploadId) {
    const client = this._client();
    try {
      const res = await client.request({ method: 'HEAD', url: `${gd.MEDIA_PATH}/uploads/${encodeURIComponent(uploadId)}`, timeout: 15000 });
      const h = res.headers || {};
      const fromHeader = gd.nonNegInt(h['upload-offset'] || h['x-upload-offset'] || h['x-offset']);
      if (fromHeader !== null) return fromHeader;
    } catch (err) {
      const e = toMessengerError(err);
      if (e.status === 404) return 0;
    }
    // Servers answering the offset as JSON only (GET of the same path).
    try {
      const r = await this.http._call('GET', `${gd.MEDIA_PATH}/uploads/${encodeURIComponent(uploadId)}`);
      return gd.nonNegInt(r.offset);
    } catch {
      return null;
    }
  }

  /**
   * Download a received file (GET items/<mediaId>) into `dest` (writable
   * stream). Older plugin builds without the route: the core media route.
   * @returns {Promise<{ bytes: number, mime: string|null }>}
   */
  async download(mediaId, dest, { onProgress, maxBytes = gd.MAX_FILE_BYTES } = {}) {
    if (!gd.isMediaId(mediaId)) throw new GateDropError('invalid media id', { code: 'invalid' });
    try {
      return await this._stream(`${gd.API_BASE}items/${mediaId}`, dest, { onProgress, maxBytes });
    } catch (err) {
      if (err.status !== 404 || err.streamed) throw err;
      return this._stream(`${gd.MEDIA_PATH}/${mediaId}`, dest, { onProgress, maxBytes });
    }
  }

  async _stream(url, dest, { onProgress, maxBytes }) {
    const client = this._client();
    let res;
    try {
      res = await client.request({
        method: 'GET', url, responseType: 'stream', timeout: DOWNLOAD_IDLE_MS, maxRedirects: 3,
        maxContentLength: maxBytes, headers: { Accept: '*/*' },
      });
    } catch (err) {
      const e = toMessengerError(err);
      throw e;
    }
    const total = gd.nonNegInt(res.headers && res.headers['content-length']);
    if (total !== null && total > maxBytes) {
      res.data.destroy();
      throw new GateDropError('file too large', { code: 'too_large' });
    }
    let got = 0;
    const tap = counter((n) => {
      got += n;
      if (got > maxBytes) throw new GateDropError('file too large', { code: 'too_large' });
      if (typeof onProgress === 'function') onProgress(got, total);
    });
    try {
      await pipeline(res.data, tap, dest);
    } catch (err) {
      const e = err instanceof GateDropError ? err : toMessengerError(err);
      e.streamed = true;
      throw e;
    }
    if (total !== null && got !== total) {
      const e = new GateDropError('download cut off', { code: 'network' });
      e.streamed = true;
      throw e;
    }
    const ct = res.headers && res.headers['content-type'];
    return { bytes: got, mime: typeof ct === 'string' ? ct.split(';')[0].trim() : null };
  }
}

GateDropApi.GateDropError = GateDropError;

module.exports = GateDropApi;
