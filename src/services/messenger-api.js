'use strict';

/**
 * GateControl – Messenger API (Core service)
 *
 * REST calls of the Messenger plugin for the Windows apps, over the device
 * token of the existing ApiClient (same headers, same axios instance; it is
 * re-read on every call because configure() replaces it):
 *
 *   GET  /api/v1/client/plugins                              usable plugins (is the messenger there?)
 *   ALL  /api/v1/client/plugins/gatecontrol-messenger/api/…  the chat API (plugin README "App-API")
 *   PUT  /api/v1/client/plugins/gatecontrol-messenger/media  raw upload → { mediaId, mime, bytes }
 *   GET  /api/v1/client/plugins/gatecontrol-messenger/media/<id>  download
 *   GET  /avatars/<file>                                     account pictures
 *
 * Every failure is thrown as a MessengerError { status, code, message }:
 * `code` is the plugin's code (`not_found`, `edit_window`, …), the host's
 * upload codes (`too_large`, `unsupported_type`, `quota_exceeded`, …),
 * 'network' (no answer), 'timeout' or `http_<status>`.
 */

const {
  PLUGIN_ID, API_BASE, MEDIA_BASE, PLUGINS_PATH, MEDIA_KINDS, isMediaId, isAvatarPath, isApiPath, posInt, baseMime, toBuffer,
} = require('../utils/messenger');

const JSON_TIMEOUT_MS = 15000;
const UPLOAD_TIMEOUT_MS = 10 * 60 * 1000;
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_MAX_DOWNLOAD = 64 * 1024 * 1024;
const AVATAR_MAX = 2 * 1024 * 1024;

class MessengerError extends Error {
  constructor(message, { status = null, code = 'failed' } = {}) {
    super(message);
    this.name = 'MessengerError';
    this.status = status;
    this.code = code;
  }

  /** Network trouble, timeouts, 5xx and 429: worth another try later. */
  get transient() {
    if (this.code === 'network' || this.code === 'timeout' || this.code === 'not_configured') return true;
    return this.status === 429 || this.status === 408 || (this.status >= 500 && this.status !== 507);
  }
}

/** axios error (or anything thrown) → MessengerError. */
function toMessengerError(err) {
  if (err instanceof MessengerError) return err;
  const res = err && err.response;
  if (res) {
    let data = res.data;
    if (Buffer.isBuffer(data) || data instanceof ArrayBuffer) {
      try { data = JSON.parse(Buffer.from(data).toString('utf8')); } catch { data = null; }
    }
    const code = data && typeof data === 'object' && typeof data.code === 'string' ? data.code
      : (data && typeof data === 'object' && typeof data.error === 'string' && /^[a-z_]{2,40}$/.test(data.error) ? data.error : `http_${res.status}`);
    const message = data && typeof data === 'object' && typeof data.error === 'string' ? data.error : `HTTP ${res.status}`;
    return new MessengerError(message, { status: res.status, code });
  }
  const c = err && err.code;
  if (c === 'ECONNABORTED' || c === 'ETIMEDOUT' || (err && /timeout/i.test(String(err.message)))) {
    return new MessengerError('timeout', { code: 'timeout' });
  }
  return new MessengerError((err && err.message) || 'network error', { code: 'network' });
}

class MessengerApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`)
   * @param {object} [opts.log]
   */
  constructor({ apiClient, log } = {}) {
    this.apiClient = apiClient;
    this.log = log || { info() {}, warn() {}, debug() {}, error() {} };
  }

  _client() {
    const c = this.apiClient && this.apiClient.client;
    if (!c) throw new MessengerError('not configured', { code: 'not_configured' });
    return c;
  }

  /** The configured server (origin + token) — changes reset the caches. */
  scope() {
    const a = this.apiClient || {};
    return a.serverUrl && a.apiKey ? `${String(a.serverUrl).replace(/\/+$/, '')}\n${a.apiKey}` : '';
  }

  async _call(method, path, { body, params, timeout = JSON_TIMEOUT_MS } = {}) {
    const client = this._client();
    try {
      const res = await client.request({ method, url: path, data: body, params, timeout });
      const data = res.data;
      if (data && typeof data === 'object' && data.ok === false) {
        throw new MessengerError(typeof data.error === 'string' ? data.error : 'refused', { status: res.status, code: data.code || 'failed' });
      }
      return data && typeof data === 'object' ? data : {};
    } catch (err) {
      throw toMessengerError(err);
    }
  }

  /** Plugin route below …/gatecontrol-messenger/api/. */
  api(method, path, opts) {
    return this._call(method, API_BASE + path, opts);
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * Is the messenger usable for this token? GET /api/v1/client/plugins
   * → { available, tab, version } ; available=false on servers without the
   * route (404) or without the plugin. Other failures throw.
   */
  async availability() {
    let data;
    try {
      data = await this._call('GET', PLUGINS_PATH);
    } catch (err) {
      if (err.status === 404) return { available: false, reason: 'unsupported', tab: null, version: null };
      throw err;
    }
    const list = Array.isArray(data.plugins) ? data.plugins : [];
    const p = list.find((x) => x && x.id === PLUGIN_ID);
    if (!p) return { available: false, reason: 'not_installed', tab: null, version: null };
    const tab = p.tab && typeof p.tab === 'object' ? { label: typeof p.tab.label === 'string' ? p.tab.label.slice(0, 40) : null } : null;
    return { available: !!tab, reason: tab ? null : 'hidden', tab, version: typeof p.version === 'string' ? p.version : null };
  }

  // ── Chat API ─────────────────────────────────────────────

  async me() { return this.api('GET', 'me'); }

  async setPrefs(prefs) {
    const body = {};
    for (const k of ['readReceipts', 'typing', 'preview']) if (typeof prefs[k] === 'boolean') body[k] = prefs[k];
    return this.api('PUT', 'prefs', { body });
  }

  async people() { return this.api('GET', 'people'); }

  async conversations({ since } = {}) {
    return this.api('GET', 'conversations', { params: since ? { since } : undefined });
  }

  async createConversation(body) { return this.api('POST', 'conversations', { body }); }

  async conversation(id) { return this.api('GET', `conversations/${this._id(id)}`); }

  async patchConversation(id, body) { return this.api('PATCH', `conversations/${this._id(id)}`, { body }); }

  /**
   * { limit, before | after | changedSince | around } — `around` (Messenger
   * ≥ 1.1.0) answers the page around a message with hasMoreBefore /
   * hasMoreAfter; every answer of 1.1.0 carries `serverTime`.
   */
  async messages(id, { limit, before, after, changedSince, around } = {}) {
    const params = {};
    if (Number.isSafeInteger(limit) && limit > 0) params.limit = Math.min(100, limit);
    if (posInt(before)) params.before = posInt(before);
    else if (posInt(after)) params.after = posInt(after);
    else if (posInt(around)) params.around = posInt(around);
    else if (typeof changedSince === 'string' && changedSince) params.changedSince = changedSince;
    return this.api('GET', `conversations/${this._id(id)}/messages`, { params });
  }

  async send(id, body) { return this.api('POST', `conversations/${this._id(id)}/messages`, { body }); }

  async edit(messageId, text) { return this.api('PATCH', `messages/${this._id(messageId)}`, { body: { text } }); }

  async remove(messageId, scope = 'me') {
    return this.api('DELETE', `messages/${this._id(messageId)}`, { params: { for: scope === 'all' ? 'all' : 'me' } });
  }

  async react(messageId, emoji) {
    return this.api('PUT', `messages/${this._id(messageId)}/reaction`, { body: { emoji: emoji == null ? null : emoji } });
  }

  async read(id, upTo) { return this.api('POST', `conversations/${this._id(id)}/read`, { body: { upTo: this._id(upTo) } }); }

  async typing(id, stop = false) { return this.api('POST', `conversations/${this._id(id)}/typing`, { body: stop ? { stop: true } : {} }); }

  async active(id, active = true) { return this.api('POST', `conversations/${this._id(id)}/active`, { body: active ? {} : { active: false } }); }

  async search(id, q) { return this.api('GET', `conversations/${this._id(id)}/search`, { params: { q } }); }

  async mediaList(id, { kind = 'all', before, limit } = {}) {
    const params = { kind: MEDIA_KINDS.includes(kind) ? kind : 'all' };
    if (posInt(before)) params.before = posInt(before);
    if (Number.isSafeInteger(limit) && limit > 0) params.limit = Math.min(100, limit);
    return this.api('GET', `conversations/${this._id(id)}/media`, { params });
  }

  /**
   * POST to a path of the plugin's client API from a push action
   * (`reply` / `mark_read`): relative, validated (no `..`, no query).
   */
  async postPath(path, body = {}) {
    const p = String(path || '').replace(/^\/+/, '');
    if (!isApiPath(p)) throw new MessengerError('invalid path', { code: 'invalid' });
    return this.api('POST', p, { body: body && typeof body === 'object' ? body : {} });
  }

  // ── Media ────────────────────────────────────────────────

  /**
   * Raw upload (no JSON, no multipart) → { mediaId, mime, bytes }.
   * @param {{ data: Buffer|Uint8Array|ArrayBuffer, mime: string, onProgress?: Function }} file
   */
  async upload({ data, mime, onProgress } = {}) {
    const buf = toBuffer(data);
    const type = baseMime(mime);
    if (!buf || !buf.length) throw new MessengerError('empty file', { code: 'length_required' });
    if (!type) throw new MessengerError('no type', { code: 'unsupported_type' });
    const client = this._client();
    try {
      const res = await client.request({
        method: 'PUT',
        url: MEDIA_BASE,
        data: buf,
        headers: { 'Content-Type': type, 'Content-Length': String(buf.length) },
        timeout: UPLOAD_TIMEOUT_MS,
        maxBodyLength: Infinity,
        maxContentLength: 1024 * 1024,
        transformRequest: [(d) => d],
        onUploadProgress: typeof onProgress === 'function' ? (e) => { try { onProgress({ loaded: e.loaded, total: e.total || buf.length }); } catch { /* UI */ } } : undefined,
      });
      const d = res.data || {};
      if (!isMediaId(d.mediaId)) throw new MessengerError('bad upload answer', { status: res.status, code: 'bad_response' });
      return { mediaId: d.mediaId, mime: typeof d.mime === 'string' ? d.mime : type, bytes: Number(d.bytes) || buf.length };
    } catch (err) {
      throw toMessengerError(err);
    }
  }

  /** Download a file of a message → { mime, data: Buffer }. */
  async download(mediaId, { maxBytes = DEFAULT_MAX_DOWNLOAD } = {}) {
    if (!isMediaId(mediaId)) throw new MessengerError('invalid media id', { code: 'invalid' });
    return this._binary(`${MEDIA_BASE}/${mediaId}`, maxBytes, DOWNLOAD_TIMEOUT_MS);
  }

  /** Account picture (/avatars/… of the own server) → { mime, data }. */
  async avatar(path) {
    if (!isAvatarPath(path)) throw new MessengerError('invalid avatar path', { code: 'invalid' });
    const r = await this._binary(path, AVATAR_MAX, JSON_TIMEOUT_MS);
    if (!/^image\/(png|jpeg|webp)$/.test(r.mime)) throw new MessengerError('not a picture', { code: 'bad_response' });
    return r;
  }

  async _binary(url, maxBytes, timeout) {
    const client = this._client();
    try {
      const res = await client.request({
        method: 'GET', url, responseType: 'arraybuffer', timeout, maxContentLength: maxBytes, maxBodyLength: maxBytes,
        headers: { Accept: '*/*' },
      });
      const data = Buffer.from(res.data);
      return { mime: baseMime(res.headers && res.headers['content-type']) || 'application/octet-stream', data };
    } catch (err) {
      throw toMessengerError(err);
    }
  }

  _id(v) {
    const n = posInt(v);
    if (!n) throw new MessengerError('invalid id', { code: 'invalid' });
    return n;
  }
}

MessengerApi.MessengerError = MessengerError;
MessengerApi.toMessengerError = toMessengerError;

module.exports = MessengerApi;
