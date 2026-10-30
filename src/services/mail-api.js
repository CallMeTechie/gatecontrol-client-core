'use strict';

/**
 * GateControl – Mail API (Core service)
 *
 * REST calls of the plugin `gatecontrol-mail` (client API "C2" of the Mail
 * contract) over the device token of the existing ApiClient. The only file
 * that knows the plugin's paths; answers are cleaned by utils/mail.js:
 *
 *   GET    /api/v1/client/plugins                                    is the plugin there?
 *   GET    …/gatecontrol-mail/api/me                                 features, limits, Microsoft, accounts, unread, settings
 *   PUT    …/api/settings { threads?, swipeLeft?, swipeRight? }
 *   GET    …/api/providers · POST accounts/discover { email }
 *   POST   …/api/accounts { provider, email, password, … }           (the server checks IMAP and SMTP first)
 *   POST   …/api/accounts/microsoft { code, codeVerifier, redirectUri, name?, color?, kind? }
 *   PATCH  …/api/accounts/<id> · POST accounts/<id>/microsoft · DELETE accounts/<id>
 *   GET    …/api/folders · GET messages?box&folder&tab&unread&flagged&attachments&before&limit · GET search?q&…
 *   GET    …/api/threads/<id> · GET messages/<id> · POST messages/<id>/images { allow }
 *   POST   …/api/messages/flags | move | archive | delete | junk | tab
 *   GET    …/api/messages/<id>/attachments/<aid>                     → { mediaId, name, mime, size }
 *   GET    …/api/img/<token> · GET cid/<messageId>/<attachmentId>    pictures of the reading frame (binary)
 *   POST   …/api/drafts · PUT/GET/DELETE drafts/<id> · POST drafts/<id>/send { sendAt? }
 *   POST   …/api/outbox/<id>/cancel · GET outbox · GET contacts?q
 *   GET|POST …/api/ai/<id> · POST ai/<id>/todo/<index> { action }
 *   POST   …/api/messages/<id>/attachments/<aid>/drive/suggest | drive/save · POST messages/<id>/drive/save-all
 *   GET    …/api/filing · POST filing/<id>/confirm | dismiss
 *   PUT    …/gatecontrol-mail/media (resumable like Drive)           → { mediaId }   attachments from this PC
 *   GET    …/gatecontrol-mail/media/<mediaId>                        an attachment (streamed)
 *
 * Failures are thrown as MessengerApi's error class { status, code, message }; the plugin's refusal
 * `{ error: { code, … } }` gives `code` and, as `detail`, the other short fields (hint, field, …).
 */

const MessengerApi = require('./messenger-api');
const GateDropApi = require('./gatedrop-api');
const mail = require('../utils/mail');

const { MessengerError: MailError } = MessengerApi;

const JSON_TIMEOUT_MS = 25000;
const ACCOUNT_TIMEOUT_MS = 90000;   // adding an account: the server logs in to IMAP and SMTP first
const IMAGE_TIMEOUT_MS = 20000;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** The plugin's refusal `{ error: { code, hint?, … } }` → code + detail on the error. */
function pluginError(err) {
  const e = err instanceof MailError ? err : MessengerApi.toMessengerError(err);
  const b = e.body;
  const inner = b && b.error && typeof b.error === 'object' && !Array.isArray(b.error) ? b.error : null;
  if (inner && mail.codeOf(inner.code)) {
    e.code = inner.code;
    const detail = {};
    for (const [k, v] of Object.entries(inner)) {
      if (k === 'code' || detail[k] !== undefined) continue;
      if (typeof v === 'string' && v.length <= 300) detail[k] = v.replace(/[\u0000-\u001F\u007F]/g, ' ');
      else if (typeof v === 'number' && Number.isFinite(v)) detail[k] = v;
      else if (k === 'hint' && v && typeof v === 'object') {
        const h = { de: typeof v.de === 'string' ? v.de.slice(0, 300) : null, en: typeof v.en === 'string' ? v.en.slice(0, 300) : null };
        if (h.de || h.en) detail.hint = h;
      }
    }
    if (Object.keys(detail).length) Object.defineProperty(e, 'detail', { value: detail, enumerable: false, configurable: true });
  } else if (b && typeof b.code !== 'string' && typeof b.error === 'string' && mail.codeOf(b.error)) {
    e.code = b.error;
  }
  return e;
}

class MailApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {object} [opts.http] - MessengerApi-compatible transport (tests)
   * @param {() => string} [opts.getLang] - 'de' | 'en' for the plugin's texts
   * @param {(ms: number) => Promise<void>} [opts.sleep]
   */
  constructor({ apiClient, log, http = null, getLang = null, sleep = null } = {}) {
    this.log = log || noopLog();
    this.http = http || new MessengerApi({ apiClient, log: this.log });
    this.getLang = typeof getLang === 'function' ? getLang : () => null;
    this.media = new GateDropApi({
      http: this.http, log: this.log, sleep,
      mediaPath: mail.MEDIA_PATH, maxFileBytes: mail.MAX_UPLOAD_BYTES, label: 'Mail',
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

  /** JSON call below …/gatecontrol-mail/api/. */
  async api(method, p, { body, params, timeout = JSON_TIMEOUT_MS } = {}) {
    try {
      return await this.http._call(method, mail.API_BASE + p, { body, params: { ...(params || {}), ...this._lang() }, timeout });
    } catch (err) {
      throw pluginError(err);
    }
  }

  _id(v) {
    const id = mail.posId(v);
    if (!id) throw new MailError('invalid id', { code: 'invalid' });
    return id;
  }

  _ids(v) {
    const ids = mail.idList(v);
    if (!ids) throw new MailError('invalid ids', { code: 'invalid' });
    return ids;
  }

  // ── Availability, account ────────────────────────────────

  /** GET /api/v1/client/plugins → the plugin's entry ({ id, version, … }) or null. Throws on errors. */
  async plugin() {
    const data = await this.http._call('GET', mail.PLUGINS_PATH);
    const list = Array.isArray(data.plugins) ? data.plugins : [];
    return list.find((x) => x && x.id === mail.PLUGIN_ID) || null;
  }

  async me() { return mail.normalizeMe(await this.api('GET', 'me')); }

  async settings(patch) {
    const body = mail.settingsPatch(patch);
    if (!body) throw new MailError('invalid settings', { code: 'invalid' });
    const r = await this.api('PUT', 'settings', { body });
    return mail.normalizeSettings(r.settings || r);
  }

  async providers() { return mail.normalizeProviders(await this.api('GET', 'providers')); }

  async discover(email) {
    if (!mail.isEmail(email)) throw new MailError('invalid email', { code: 'invalid' });
    return mail.normalizeDiscover(await this.api('POST', 'accounts/discover', { body: { email: email.trim() }, timeout: ACCOUNT_TIMEOUT_MS }));
  }

  _account(r) {
    const a = mail.normalizeAccount(r && (r.account || r));
    if (!a) throw new MailError('bad account answer', { code: 'bad_response' });
    return a;
  }

  async addAccount(input) {
    const body = mail.accountBody(input);
    if (!body) throw new MailError('invalid account', { code: 'invalid' });
    return this._account(await this.api('POST', 'accounts', { body, timeout: ACCOUNT_TIMEOUT_MS }));
  }

  /** POST accounts/microsoft (id: null) or accounts/<id>/microsoft (sign in again). */
  async microsoft(id, { code, codeVerifier, redirectUri, name, color, kind } = {}) {
    if (typeof code !== 'string' || !code || code.length > 4096 || typeof codeVerifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) {
      throw new MailError('invalid sign-in', { code: 'invalid' });
    }
    const body = { code, codeVerifier, redirectUri };
    if (id) return this._account(await this.api('POST', `accounts/${this._id(id)}/microsoft`, { body, timeout: ACCOUNT_TIMEOUT_MS }));
    const extra = mail.accountPatch({ name, color, kind }, { partial: true }) || {};
    return this._account(await this.api('POST', 'accounts/microsoft', { body: { ...body, ...extra }, timeout: ACCOUNT_TIMEOUT_MS }));
  }

  async updateAccount(id, patch) {
    const body = mail.accountPatch(patch);
    if (!body) throw new MailError('invalid patch', { code: 'invalid' });
    return this._account(await this.api('PATCH', `accounts/${this._id(id)}`, { body, timeout: body.password ? ACCOUNT_TIMEOUT_MS : JSON_TIMEOUT_MS }));
  }

  async deleteAccount(id) {
    await this.api('DELETE', `accounts/${this._id(id)}`);
    return { ok: true };
  }

  // ── Folders, lists ───────────────────────────────────────

  async folders() { return mail.normalizeFolders(await this.api('GET', 'folders')); }

  async messages(query) {
    const params = mail.listQuery(query);
    if (!params) throw new MailError('invalid list', { code: 'invalid' });
    return mail.normalizeList(await this.api('GET', 'messages', { params }));
  }

  async search(query) {
    const params = mail.searchQuery(query);
    if (!params) throw new MailError('invalid search', { code: 'invalid' });
    return mail.normalizeList(await this.api('GET', 'search', { params, timeout: 60000 }));
  }

  async thread(id) { return mail.normalizeThread(await this.api('GET', `threads/${this._id(id)}`)); }

  _message(r) {
    const m = mail.normalizeMessage(r && r.message ? r.message : r);
    if (!m) throw new MailError('bad message answer', { code: 'bad_response' });
    return m;
  }

  async message(id) { return this._message(await this.api('GET', `messages/${this._id(id)}`, { timeout: 60000 })); }

  async allowImages(id, allow) {
    if (allow !== 'once' && allow !== 'sender') throw new MailError('invalid allow', { code: 'invalid' });
    return this._message(await this.api('POST', `messages/${this._id(id)}/images`, { body: { allow }, timeout: 60000 }));
  }

  _items(r) {
    return { ok: true, items: Array.isArray(r && r.items) ? r.items.map(mail.normalizeSummary).filter(Boolean) : null };
  }

  async flags(ids, { unread, flagged } = {}) {
    const body = { ids: this._ids(ids) };
    if (typeof unread === 'boolean') body.unread = unread;
    if (typeof flagged === 'boolean') body.flagged = flagged;
    if (body.unread === undefined && body.flagged === undefined) throw new MailError('nothing to change', { code: 'invalid' });
    return this._items(await this.api('POST', 'messages/flags', { body }));
  }

  async move(ids, folderId) { return this._items(await this.api('POST', 'messages/move', { body: { ids: this._ids(ids), folderId: this._id(folderId) } })); }

  /** POST messages/archive | delete | junk { ids }. */
  async act(action, ids) {
    if (!['archive', 'delete', 'junk'].includes(action)) throw new MailError('invalid action', { code: 'invalid' });
    return this._items(await this.api('POST', `messages/${action}`, { body: { ids: this._ids(ids) } }));
  }

  async setTab(ids, tab) {
    if (!mail.TABS.includes(tab)) throw new MailError('invalid tab', { code: 'invalid' });
    return this._items(await this.api('POST', 'messages/tab', { body: { ids: this._ids(ids), tab } }));
  }

  async attachment(id, aid) {
    const m = mail.normalizeMedia(await this.api('GET', `messages/${this._id(id)}/attachments/${this._id(aid)}`, { timeout: 120000 }));
    if (!m) throw new MailError('bad attachment answer', { code: 'bad_response' });
    return m;
  }

  /**
   * A picture of the reading frame → { mime, data: Buffer }; only image/* (never SVG):
   * img/<token> answers { mime, size, data (base64, ≤ 700 KB) }, cid/<m>/<a> answers { mediaId, mime, size, url } and
   * the bytes come from the plugin's media route.
   */
  async picture(target) {
    const okMime = (m) => typeof m === 'string' && /^image\/[a-z0-9.+-]{1,40}$/.test(m.toLowerCase()) && m.toLowerCase() !== 'image/svg+xml';
    if (target && target.kind === 'img' && mail.isToken(target.token)) {
      const r = await this.api('GET', `img/${target.token}`, { timeout: IMAGE_TIMEOUT_MS });
      const mime = typeof r.mime === 'string' ? r.mime.split(';')[0].trim().toLowerCase() : '';
      if (!okMime(mime) || typeof r.data !== 'string' || r.data.length > Math.ceil(mail.IMAGE_MAX_BYTES / 3) * 4 + 8 || !/^[A-Za-z0-9+/=\s]+$/.test(r.data)) {
        throw new MailError('not a picture', { code: 'invalid' });
      }
      const data = Buffer.from(r.data, 'base64');
      if (!data.length || data.length > mail.IMAGE_MAX_BYTES) throw new MailError('not a picture', { code: 'invalid' });
      return { mime, data };
    }
    if (target && target.kind === 'cid') {
      const r = await this.api('GET', `cid/${this._id(target.messageId)}/${this._id(target.attachmentId)}`, { timeout: IMAGE_TIMEOUT_MS });
      const mime = typeof r.mime === 'string' ? r.mime.split(';')[0].trim().toLowerCase() : '';
      if (!mail.isMediaId(r.mediaId) || !okMime(mime)) throw new MailError('not a picture', { code: 'invalid' });
      const chunks = [];
      const { Writable } = require('stream');
      const sink = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
      const got = await this.media.streamTo(`${mail.MEDIA_PATH}/${r.mediaId}`, sink, { maxBytes: mail.IMAGE_MAX_BYTES });
      const real = got && got.mime ? got.mime.toLowerCase() : mime;
      if (real && real.startsWith('image/') && !okMime(real)) throw new MailError('not a picture', { code: 'invalid' });
      return { mime, data: Buffer.concat(chunks) };
    }
    throw new MailError('invalid picture', { code: 'invalid' });
  }

  // ── Writing ──────────────────────────────────────────────

  _draft(r) {
    const d = mail.normalizeDraft(r);
    if (!d) throw new MailError('bad draft answer', { code: 'bad_response' });
    return d;
  }

  async createDraft(input) {
    const body = mail.draftBody(input);
    if (!body) throw new MailError('invalid draft', { code: 'invalid' });
    return this._draft(await this.api('POST', 'drafts', { body, timeout: 120000 }));
  }

  async updateDraft(id, input) {
    const body = mail.draftBody(input);
    if (!body) throw new MailError('invalid draft', { code: 'invalid' });
    delete body.replyTo;
    delete body.mode;
    return this._draft(await this.api('PUT', `drafts/${this._id(id)}`, { body, timeout: 120000 }));
  }

  async draft(id) { return this._draft(await this.api('GET', `drafts/${this._id(id)}`)); }

  async deleteDraft(id) {
    await this.api('DELETE', `drafts/${this._id(id)}`);
    return { ok: true };
  }

  async send(id, sendAt = null) {
    const body = {};
    if (sendAt !== null && sendAt !== undefined) {
      const at = mail.msOf(sendAt);
      if (!at) throw new MailError('invalid time', { code: 'invalid' });
      body.sendAt = at;
    }
    const r = mail.normalizeSend(await this.api('POST', `drafts/${this._id(id)}/send`, { body }));
    if (!r) throw new MailError('bad send answer', { code: 'bad_response' });
    return r;
  }

  async cancelSend(outboxId) {
    const r = await this.api('POST', `outbox/${this._id(outboxId)}/cancel`, { body: {} });
    const draftId = mail.posId(r.draftId);
    if (!draftId) throw new MailError('bad cancel answer', { code: 'bad_response' });
    return { draftId };
  }

  async outbox() { return mail.normalizeOutbox(await this.api('GET', 'outbox')); }

  async contacts(q) {
    const s = typeof q === 'string' ? q.trim() : '';
    if (!s || s.length > 100) return { items: [] };
    return mail.normalizeContacts(await this.api('GET', 'contacts', { params: { q: s } }));
  }

  // ── AI ───────────────────────────────────────────────────

  async ai(id) { return mail.normalizeAi(await this.api('GET', `ai/${this._id(id)}`)); }

  /** POST ai/<id>: an existing result comes back as it is; `again` asks the AI anew ("Neu erstellen"). */
  async runAi(id, { again = false } = {}) { return mail.normalizeAi(await this.api('POST', `ai/${this._id(id)}`, { body: again ? { again: true } : {}, timeout: 120000 })); }

  async todo(id, index, action = 'family_calendar') {
    if (!Number.isSafeInteger(index) || index < 0 || index > 50 || action !== 'family_calendar') throw new MailError('invalid todo', { code: 'invalid' });
    const r = await this.api('POST', `ai/${this._id(id)}/todo/${index}`, { body: { action } });
    return { where: mail.line(r.where, 300) };
  }

  // ── Drive ────────────────────────────────────────────────

  async suggest(id, aid) {
    const r = await this.api('POST', `messages/${this._id(id)}/attachments/${this._id(aid)}/drive/suggest`, { body: {}, timeout: 120000 });
    return { suggestion: mail.normalizeSuggestion(r.suggestion), duplicate: r.duplicate === true };
  }

  _savedTo(v) {
    const o = v && typeof v === 'object' ? v : null;
    const nodeId = o && mail.posId(o.nodeId);
    return nodeId ? { nodeId, where: mail.line(o.where, 500) } : null;
  }

  async saveToDrive(id, aid, { folderId, name, remember } = {}) {
    const body = {};
    if (folderId !== undefined && folderId !== null) body.folderId = this._id(folderId);
    if (typeof name === 'string' && name.trim()) body.name = name.trim().slice(0, 255);
    if (typeof remember === 'boolean') body.remember = remember;
    const r = await this.api('POST', `messages/${this._id(id)}/attachments/${this._id(aid)}/drive/save`, { body, timeout: 300000 });
    const savedTo = this._savedTo(r.savedTo);
    if (!savedTo) throw new MailError('bad save answer', { code: 'bad_response' });
    return { savedTo };
  }

  async saveAll(id) {
    const r = await this.api('POST', `messages/${this._id(id)}/drive/save-all`, { body: {}, timeout: 600000 });
    const saved = (Array.isArray(r.saved) ? r.saved : []).map((x) => {
      const aid = mail.posId(x && x.attachmentId);
      const to = this._savedTo(x && x.savedTo);
      return aid && to ? { attachmentId: aid, savedTo: to } : null;
    }).filter(Boolean);
    const failed = (Array.isArray(r.failed) ? r.failed : []).map((x) => {
      const aid = mail.posId(x && x.attachmentId);
      return aid ? { attachmentId: aid, code: mail.codeOf(x.code) || 'failed' } : null;
    }).filter(Boolean);
    return { saved, failed };
  }

  async filing() { return mail.normalizeFiling(await this.api('GET', 'filing')); }

  async confirmFiling(id, { folderId, name } = {}) {
    const body = {};
    if (folderId !== undefined && folderId !== null) body.folderId = this._id(folderId);
    if (typeof name === 'string' && name.trim()) body.name = name.trim().slice(0, 255);
    const r = await this.api('POST', `filing/${this._id(id)}/confirm`, { body, timeout: 300000 });
    const savedTo = this._savedTo(r.savedTo);
    if (!savedTo) throw new MailError('bad filing answer', { code: 'bad_response' });
    return { savedTo };
  }

  async dismissFiling(id) {
    await this.api('POST', `filing/${this._id(id)}/dismiss`, { body: {} });
    return { ok: true };
  }

  // ── Media ────────────────────────────────────────────────

  /** A file of this PC as a media of the plugin → { mediaId, mime, bytes }. */
  async upload(file, opts) {
    try {
      return await this.media.upload(file, opts);
    } catch (err) {
      throw pluginError(err);
    }
  }

  /** The bytes of an attachment's media into `dest` (writable stream). */
  async download(mediaId, dest, { onProgress, maxBytes = 200 * 1024 * 1024 } = {}) {
    if (!mail.isMediaId(mediaId)) throw new MailError('invalid media id', { code: 'invalid' });
    return this.media.streamTo(`${mail.MEDIA_PATH}/${mediaId}`, dest, { onProgress, maxBytes });
  }
}

MailApi.MailError = MailError;
MailApi.pluginError = pluginError;

module.exports = MailApi;
