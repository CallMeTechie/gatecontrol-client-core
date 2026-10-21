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
 *          ?uploadId=&offset= + Content-Range                       resumable parts (> 50 MB, core ≥ 1.193)
 *   GET    …/gatecontrol-gatedrop/media/uploads/<id>                → { offset, total, mime } of a resumable upload
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
const PART_SIZE = 8 * 1024 * 1024;     // resumable parts: multiples of 64 KiB (core 1.193)

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
   * @param {number} [opts.partSize] - resumable part size (8 MiB, a multiple of 64 KiB)
   */
  constructor({ apiClient, log, http = null, sleep = null, resumableFrom = gd.RESUMABLE_FROM, partSize = PART_SIZE } = {}) {
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.sleep = sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.resumableFrom = resumableFrom;
    this.partSize = partSize; // multiple of 64 KiB
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
   * Files above 50 MB go up resumable (core 1.193): parts of 8 MiB
   *   PUT media?uploadId=<id>&offset=<n>, Content-Range: bytes n-end/total
   *   → 200 { complete: false, offset } … { complete: true, mediaId, mime, bytes }
   *   → 409 { code: offset_mismatch | upload_mismatch | busy, offset } → go on at offset
   * and a broken part continues where the server stands (GET media/uploads/<id>
   * → { offset, total, mime }); up to 5 failures in a row.
   * @param {{ path: string, size: number, mime: string }} file
   * @param {{ onProgress?: (sent: number, total: number) => void }} [opts]
   */
  async upload(file, { onProgress } = {}) {
    const size = file && file.size;
    if (!file || typeof file.path !== 'string' || !Number.isSafeInteger(size) || size <= 0) throw new GateDropError('empty file', { code: 'length_required' });
    if (size > gd.MAX_FILE_BYTES) throw new GateDropError('file too large', { code: 'too_large' });
    const mime = typeof file.mime === 'string' && file.mime ? file.mime : 'application/octet-stream';
    const progress = typeof onProgress === 'function' ? onProgress : () => {};
    if (size <= this.resumableFrom || this.resumable === false) {
      const r = await this._put(file.path, { mime, size, start: 0, end: size, progress });
      return this._media(r, mime, size);
    }

    const uploadId = crypto.randomBytes(18).toString('base64url'); // 24 chars of [A-Za-z0-9_-]
    let offset = 0;
    let failures = 0;
    while (offset < size) {
      const end = Math.min(size, offset + this.partSize);
      let r;
      try {
        r = await this._put(file.path, { mime, size, start: offset, end, progress, uploadId });
      } catch (err) {
        if (!err.transient || ++failures >= RESUME_ATTEMPTS) throw err;
        await this.sleep(Math.min(30000, 1000 * 2 ** (failures - 1)));
        const at = await this.uploadOffset(uploadId).catch(() => null);
        if (at !== null && at <= size) offset = at;
        this.log.info(`GateDrop upload continues at ${offset} of ${size} bytes`);
        continue;
      }
      const d = r.data || {};
      if (r.status === 409) {
        const at = gd.nonNegInt(d.offset);
        if (d.code === 'busy' || at === null) {
          if (++failures >= RESUME_ATTEMPTS) throw new GateDropError('upload busy', { status: 409, code: d.code || 'busy' });
          await this.sleep(Math.min(30000, 1000 * 2 ** (failures - 1)));
          const st = await this.uploadOffset(uploadId).catch(() => null);
          if (st !== null) offset = st;
        } else {
          offset = at;
        }
        continue;
      }
      failures = 0;
      if (d.complete === true || (gd.isMediaId(d.mediaId) && d.complete !== false)) {
        if (offset === 0 && end < size && d.complete !== true) {
          // A server without resumable uploads took the first part as a file: whole file in one.
          this.resumable = false;
          const whole = await this._put(file.path, { mime, size, start: 0, end: size, progress });
          return this._media(whole, mime, size);
        }
        return this._media(r, mime, size);
      }
      const next = gd.nonNegInt(d.offset);
      offset = next !== null && next > offset ? next : end;
    }
    // Every byte went up, but the server never answered `complete`.
    throw new GateDropError('upload not completed', { code: 'bad_response' });
  }

  _media(res, mime, size) {
    const d = (res && res.data) || {};
    if (!gd.isMediaId(d.mediaId)) throw new GateDropError('bad upload answer', { status: res && res.status, code: 'bad_response' });
    return { mediaId: d.mediaId, mime: typeof d.mime === 'string' ? d.mime : mime, bytes: Number(d.bytes) || size };
  }

  /** One PUT of bytes [start, end) → axios response (200, or 409 for resumable parts). */
  async _put(filePath, { mime, size, start, end, progress, uploadId = null }) {
    const client = this._client();
    const params = {};
    const headers = { 'Content-Type': mime, 'Content-Length': String(end - start) };
    if (uploadId) {
      params.uploadId = uploadId;
      params.offset = start;
      headers['Content-Range'] = `bytes ${start}-${end - 1}/${size}`;
    }
    let sent = start;
    const src = fs.createReadStream(filePath, { start, end: end - 1 });
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
        validateStatus: (st) => (st >= 200 && st < 300) || (!!uploadId && st === 409),
      });
      return res;
    } catch (err) {
      src.destroy();
      throw toMessengerError(err);
    }
  }

  /** Bytes the server already holds of a resumable upload (GET media/uploads/<id>), or null. */
  async uploadOffset(uploadId) {
    try {
      const r = await this.http._call('GET', `${gd.MEDIA_PATH}/uploads/${encodeURIComponent(uploadId)}`);
      return gd.nonNegInt(r.offset);
    } catch (err) {
      if (err.status === 404) return 0;
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
