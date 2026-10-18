'use strict';

/**
 * GateControl – Messenger outbox (Core service)
 *
 * Messages written while offline (or while the server is unreachable) wait
 * here and go out in order as soon as the server answers again. Every entry
 * carries its `clientId`, the plugin's idempotency key: a retry after a lost
 * answer returns the stored message (`duplicate: true`) instead of sending it
 * twice — the outbox, notification replies and a restart in the middle of a
 * send are all safe.
 *
 *   - Persisted in the (encrypted) store under `messengerOutbox`, scoped to
 *     server + token; files to upload (pictures, voice, documents) are kept
 *     next to it in `<dataDir>/messenger-outbox/` until they are sent.
 *   - One send at a time, oldest first. Files are uploaded first (raw PUT;
 *     the preview before the file);
 *     the media id is kept, so a retry does not upload again. An upload that
 *     the server no longer knows (`media_invalid`, e.g. after 24 h) is
 *     uploaded once more.
 *   - Network errors, timeouts, 5xx, 429: retried with backoff (2 s → 5 min)
 *     and right away on kick() (stream reconnect, "Erneut senden").
 *     Refusals (4xx: readonly, not_found, too_large, …) mark the entry
 *     `failed`; the UI offers retry / discard.
 *
 * Events: 'sent' ({ entry, message, duplicate }), 'failed' ({ entry, error }),
 * 'change' ({ conversationId }) whenever the queue changed.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { isClientId, posInt, baseMime, byteLength, toBuffer } = require('../utils/messenger');
const { MessengerError } = require('./messenger-api');

const STORE_KEY = 'messengerOutbox';
const MAX_ENTRIES = 200;
const BACKOFF_MS = [2000, 5000, 15000, 30000, 60000, 120000, 300000];

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class MessengerOutbox extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.api - MessengerApi
   * @param {object} opts.store - electron-store compatible
   * @param {string} [opts.dataDir] - folder for files waiting to be uploaded (none → files are not persisted)
   * @param {object} [opts.log]
   * @param {object} [opts.fsp] - fs.promises (tests)
   * @param {() => number} [opts.now]
   * @param {number[]} [opts.backoffMs]
   */
  constructor({ api, store, dataDir = null, log, fsp = fs.promises, now = Date.now, backoffMs = BACKOFF_MS } = {}) {
    super();
    this.api = api;
    this.store = store;
    this.dir = dataDir ? path.join(dataDir, 'messenger-outbox') : null;
    this.log = log || noopLog();
    this.fsp = fsp;
    this.now = now;
    this.backoffMs = backoffMs;
    this._items = [];
    this._scope = '';
    this._running = false;
    this._busy = false;
    this._timer = null;
    this._memFiles = new Map(); // without dataDir: clientId → { main, thumb } buffers
    this._load();
  }

  // ── Public API ───────────────────────────────────────────

  start() {
    this._running = true;
    this._checkScope();
    this.kick();
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
  }

  /**
   * Queue a message. `files.main` / `files.thumb`: { data, mime, name } —
   * kept until sent. Returns the entry (pending message view: toPending()).
   * @param {object} req - { conversationId, clientId?, body (buildSendBody result), files? }
   */
  async add({ conversationId, clientId, body, files = {} } = {}) {
    const convId = posInt(conversationId);
    if (!convId || !body || typeof body !== 'object') throw new MessengerError('invalid message', { code: 'invalid' });
    const id = isClientId(clientId) ? clientId : crypto.randomUUID();
    const existing = this._items.find((e) => e.clientId === id);
    if (existing) return existing;
    if (this._items.length >= MAX_ENTRIES) throw new MessengerError('outbox full', { code: 'outbox_full' });
    this._checkScope();
    const entry = {
      clientId: id,
      conversationId: convId,
      body: { ...body },
      files: {},
      mediaId: null,
      thumbMediaId: null,
      state: 'queued',
      attempts: 0,
      error: null,
      createdAt: new Date(this.now()).toISOString(),
      nextAt: 0,
    };
    for (const role of ['main', 'thumb']) {
      const f = files[role];
      if (!f) continue;
      const data = toBuffer(f.data);
      const mime = baseMime(f.mime);
      if (!data || !data.length || !mime) throw new MessengerError('invalid file', { code: 'invalid' });
      entry.files[role] = { mime, bytes: byteLength(data), name: typeof f.name === 'string' ? f.name.slice(0, 200) : null, file: null };
      entry.files[role].file = await this._writeFile(id, role, data);
    }
    this._items.push(entry);
    this._save();
    this._changed(convId);
    this.kick();
    return entry;
  }

  /** Entries of one conversation (or all), oldest first. */
  list(conversationId = null) {
    const id = conversationId == null ? null : posInt(conversationId);
    return this._items.filter((e) => id == null || e.conversationId === id).map((e) => ({ ...e, body: { ...e.body }, files: { ...e.files } }));
  }

  get(clientId) {
    return this._items.find((e) => e.clientId === clientId) || null;
  }

  size() { return this._items.length; }

  /** Send again now (a failed entry, or skip the backoff of a queued one). */
  retry(clientId) {
    const e = this.get(clientId);
    if (!e) return false;
    e.state = 'queued';
    e.error = null;
    e.nextAt = 0;
    this._save();
    this._changed(e.conversationId);
    this.kick();
    return true;
  }

  /** Remove an entry that has not been sent (failed, or still waiting). */
  async discard(clientId) {
    const e = this.get(clientId);
    if (!e || e.state === 'sending') return false;
    await this._remove(e);
    return true;
  }

  /** Try now (stream connected again, app back online). */
  kick() {
    if (!this._running) return;
    for (const e of this._items) if (e.state === 'queued') e.nextAt = Math.min(e.nextAt, this.now());
    this._schedule(0);
  }

  /** New server / token: entries of the old one are dropped. */
  async reset() {
    const items = this._items.splice(0);
    this._scope = this.api && typeof this.api.scope === 'function' ? this._hash(this.api.scope()) : '';
    this._save();
    for (const e of items) await this._deleteFiles(e);
    for (const id of new Set(items.map((e) => e.conversationId))) this._changed(id);
  }

  // ── Processing ───────────────────────────────────────────

  _schedule(ms) {
    if (!this._running) return;
    if (this._timer) clearTimeout(this._timer);
    this._timer = setTimeout(() => { this._timer = null; this._process(); }, Math.max(0, ms));
    if (this._timer.unref) this._timer.unref();
  }

  async _process() {
    if (!this._running || this._busy) return;
    const now = this.now();
    const next = this._items.find((e) => e.state === 'queued');
    if (!next) return;
    if (next.nextAt > now) { this._schedule(next.nextAt - now); return; }
    this._busy = true;
    try {
      await this._sendOne(next);
    } finally {
      this._busy = false;
    }
    if (this._items.some((e) => e.state === 'queued')) this._schedule(0);
  }

  async _sendOne(e) {
    e.state = 'sending';
    e.attempts += 1;
    this._changed(e.conversationId);
    try {
      await this._uploadFiles(e);
      let res;
      try {
        res = await this.api.send(e.conversationId, this._body(e));
      } catch (err) {
        if (err && err.code === 'media_invalid' && Object.keys(e.files).length && !e.reuploaded) {
          // The upload expired or got lost: upload again once.
          e.reuploaded = true;
          e.mediaId = null;
          e.thumbMediaId = null;
          await this._uploadFiles(e);
          res = await this.api.send(e.conversationId, this._body(e));
        } else {
          throw err;
        }
      }
      if (!this._items.includes(e)) return; // discarded / reset meanwhile
      await this._remove(e, { silent: true });
      this.emit('sent', { entry: e, message: res && res.message ? res.message : null, duplicate: !!(res && res.duplicate) });
      this._changed(e.conversationId);
    } catch (err) {
      if (!this._items.includes(e)) return;
      const transient = err && typeof err.transient === 'boolean' ? err.transient : true;
      e.error = (err && err.code) || 'failed';
      if (transient) {
        e.state = 'queued';
        const ms = this.backoffMs[Math.min(e.attempts - 1, this.backoffMs.length - 1)];
        e.nextAt = this.now() + ms;
        this.log.debug(`Chat outbox: ${e.error}, next attempt in ${Math.round(ms / 1000)} s`);
      } else {
        e.state = 'failed';
        this.log.warn(`Chat message not sent: ${e.error}`);
        this.emit('failed', { entry: e, error: e.error });
      }
      this._save();
      this._changed(e.conversationId);
    }
  }

  async _uploadFiles(e) {
    // The preview first (small), then the file: a video or document whose
    // upload takes long already has its preview on the server.
    for (const role of ['thumb', 'main']) {
      const f = e.files[role];
      const key = role === 'main' ? 'mediaId' : 'thumbMediaId';
      if (!f || e[key]) continue;
      const data = await this._readFile(e.clientId, role, f);
      if (!data) throw new MessengerError('file gone', { code: 'file_missing' });
      try {
        const up = await this.api.upload({ data, mime: f.mime });
        e[key] = up.mediaId;
      } catch (err) {
        // A preview that cannot be uploaded is not worth failing the message.
        if (role === 'thumb' && err && !err.transient) { delete e.files.thumb; continue; }
        throw err;
      }
      this._save();
    }
  }

  _body(e) {
    const b = { ...e.body, clientId: e.clientId };
    if (e.mediaId) b.mediaId = e.mediaId;
    if (e.thumbMediaId) b.thumbMediaId = e.thumbMediaId;
    return b;
  }

  async _remove(e, { silent = false } = {}) {
    this._items = this._items.filter((x) => x !== e);
    this._save();
    await this._deleteFiles(e);
    if (!silent) this._changed(e.conversationId);
  }

  // ── Files ────────────────────────────────────────────────

  async _writeFile(clientId, role, data) {
    if (!this.dir) {
      const m = this._memFiles.get(clientId) || {};
      m[role] = data;
      this._memFiles.set(clientId, m);
      return null;
    }
    await this.fsp.mkdir(this.dir, { recursive: true });
    const name = `${clientId}-${role}.bin`;
    await this.fsp.writeFile(path.join(this.dir, name), data);
    return name;
  }

  async _readFile(clientId, role, f) {
    if (!f.file) {
      const m = this._memFiles.get(clientId);
      return m && m[role] ? m[role] : null;
    }
    if (!/^[A-Za-z0-9_-]{8,64}-(main|thumb)\.bin$/.test(f.file)) return null;
    try { return await this.fsp.readFile(path.join(this.dir, f.file)); } catch { return null; }
  }

  async _deleteFiles(e) {
    this._memFiles.delete(e.clientId);
    if (!this.dir) return;
    for (const f of Object.values(e.files || {})) {
      if (!f || !f.file || !/^[A-Za-z0-9_-]{8,64}-(main|thumb)\.bin$/.test(f.file)) continue;
      try { await this.fsp.unlink(path.join(this.dir, f.file)); } catch { /* gone */ }
    }
  }

  // ── Store ────────────────────────────────────────────────

  _hash(s) {
    return s ? crypto.createHash('sha256').update(s).digest('hex').slice(0, 16) : '';
  }

  /** Server / token changed since the entries were queued → drop them. */
  _checkScope() {
    const scope = this.api && typeof this.api.scope === 'function' ? this._hash(this.api.scope()) : '';
    if (!scope) return;
    if (this._scope && this._scope !== scope && this._items.length) {
      this.log.info('Chat outbox: new server or token — dropping unsent messages of the old one');
      this.reset().catch(() => {});
      return;
    }
    if (this._scope !== scope) {
      this._scope = scope;
      this._save();
    }
  }

  _load() {
    try {
      const raw = this.store && this.store.get(STORE_KEY);
      if (!raw || raw.v !== 1 || !Array.isArray(raw.items)) return;
      this._scope = typeof raw.scope === 'string' ? raw.scope : '';
      this._items = raw.items.filter((e) => e && isClientId(e.clientId) && posInt(e.conversationId) && e.body && typeof e.body === 'object')
        .slice(0, MAX_ENTRIES)
        .map((e) => ({ ...e, state: e.state === 'failed' ? 'failed' : 'queued', nextAt: 0, files: e.files && typeof e.files === 'object' ? e.files : {} }));
    } catch (err) {
      this.log.warn(`Chat outbox unreadable: ${err.message}`);
      this._items = [];
    }
  }

  _save() {
    try {
      this.store.set(STORE_KEY, {
        v: 1,
        scope: this._scope,
        items: this._items.map((e) => ({ ...e, nextAt: 0, state: e.state === 'sending' ? 'queued' : e.state })),
      });
    } catch (err) {
      this.log.warn(`Chat outbox could not be saved: ${err.message}`);
    }
  }

  _changed(conversationId) {
    this.emit('change', { conversationId });
  }

  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Chat outbox listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

MessengerOutbox.STORE_KEY = STORE_KEY;
MessengerOutbox.BACKOFF_MS = BACKOFF_MS;

module.exports = MessengerOutbox;
