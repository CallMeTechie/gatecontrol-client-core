'use strict';

/**
 * GateControl – Messenger client (Core service)
 *
 * The chat side of the Windows apps for the plugin `gatecontrol-messenger`
 * (contract: the plugin's README "App-API"; server: GateControl ≥ 1.177.0).
 * The apps draw the UI ("Chats"); this service holds the data:
 *
 *   - Availability: shown only when GET /api/v1/client/plugins lists the
 *     plugin with an app tab and `GET me` answers. Older servers (404),
 *     servers without the plugin and kiosk tokens → `unavailable`; checked
 *     again every 30 min, after a reconnect of the push stream and after a
 *     server setup.
 *   - Cache: conversations and the newest messages of each (in memory, and
 *     the newest 50 of the 40 most recent chats in the encrypted store,
 *     scoped to server + token) → the list and recent messages are readable
 *     offline.
 *   - Live: plugin events on the existing push stream (`event: plugin`,
 *     PushClient 'event') — message.new / update / delete, reaction, read,
 *     typing, conversation.update / remove. No replay: after every hello the
 *     service catches up (`conversations?since=`, `messages?after=`,
 *     `changedSince=`). Without the stream it polls (30 s while the chat page
 *     is open, 2 min otherwise).
 *   - Sending goes through the outbox (services/messenger-outbox.js,
 *     clientId idempotency); pending entries appear in the message list.
 *   - "Active": the open, visible conversation is reported every 20 s (no
 *     push for it) and read up to the newest message.
 *
 * Events: 'state' (status()), 'conversations' ({ ids, removed }),
 * 'messages' ({ conversationId, reason }), 'typing' ({ conversationId,
 * userIds }), 'unread' (total), 'outbox' ({ conversationId }),
 * 'read-local' ({ conversationId, upTo }) read on this device,
 * 'read-self' ({ conversationId, lastReadId }) read on another device,
 * 'send-failed' ({ conversationId, clientId, error, source }).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const MessengerApi = require('./messenger-api');
const MessengerOutbox = require('./messenger-outbox');
const {
  PLUGIN_ID, posInt, mergeMessages, sortConversations, buildSendBody, isMediaId, isAvatarPath, baseMime, byteLength,
  KINDS,
} = require('../utils/messenger');

const { MessengerError } = MessengerApi;
const CACHE_KEY = 'messengerCache';
const CACHE_CONVS = 40;
const CACHE_MSGS = 50;
const PAGE = 50;

const DEFAULT_TIMING = Object.freeze({
  recheckMs: 30 * 60 * 1000,      // unavailable → ask again
  errorRetryMs: [5000, 15000, 30000, 60000, 120000, 300000],
  pollOpenMs: 30000,              // no push stream, chat page open
  pollIdleMs: 120000,             // no push stream, chat page closed
  activeEveryMs: 20000,           // POST …/active while a chat is open and visible
  convDebounceMs: 150,            // GET conversations/:id after events
  persistDelayMs: 1500,
  typingEveryMs: 3000,            // plugin limits.typingEveryS
  typingValidMs: 6000,            // plugin limits.typingS
  peopleTtlMs: 5 * 60 * 1000,
  mediaCacheBytes: 48 * 1024 * 1024,
  avatarCacheBytes: 8 * 1024 * 1024,
});

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Small byte-bounded LRU for downloaded files. */
class ByteLru {
  constructor(maxBytes) { this.max = maxBytes; this.bytes = 0; this.map = new Map(); }
  get(k) {
    const v = this.map.get(k);
    if (!v) return null;
    this.map.delete(k);
    this.map.set(k, v);
    return v;
  }
  set(k, v) {
    const size = byteLength(v.data);
    if (size > this.max / 2) return;
    if (this.map.has(k)) { this.bytes -= byteLength(this.map.get(k).data); this.map.delete(k); }
    this.map.set(k, v);
    this.bytes += size;
    while (this.bytes > this.max && this.map.size) {
      const [ok, ov] = this.map.entries().next().value;
      this.map.delete(ok);
      this.bytes -= byteLength(ov.data);
    }
  }
  clear() { this.map.clear(); this.bytes = 0; }
}

class MessengerService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (device token)
   * @param {object} [opts.pushClient] - PushClient (live events, reconnects); without it: polling only
   * @param {object} opts.store - electron-store compatible (cache + outbox)
   * @param {string} [opts.dataDir] - folder for outbox files (app.getPath('userData'))
   * @param {object} [opts.log]
   * @param {object} [opts.api] - MessengerApi (tests)
   * @param {object} [opts.outbox] - MessengerOutbox (tests)
   * @param {() => boolean} [opts.isWindowVisible] - the app window is shown (not in the tray / minimized)
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing] - overrides of DEFAULT_TIMING (tests)
   */
  constructor({
    apiClient, pushClient = null, store, dataDir = null, log, api, outbox, isWindowVisible, now = Date.now, timing = {},
  } = {}) {
    super();
    this.apiClient = apiClient;
    this.pushClient = pushClient;
    this.store = store;
    this.log = log || noopLog();
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.isWindowVisible = typeof isWindowVisible === 'function' ? isWindowVisible : () => true;
    this.api = api || new MessengerApi({ apiClient, log: this.log });
    this.outbox = outbox || new MessengerOutbox({ api: this.api, store, dataDir, log: this.log, now });

    this._running = false;
    this._avail = { state: 'unknown', reason: null, version: null, label: null, checkedAt: null, stale: false };
    this._me = null;
    this._convs = new Map();
    this._msgs = new Map();          // id → { list, hasMore, loaded, syncedAt }
    this._typing = new Map();        // id → Map(userId → until ms)
    this._typingSent = new Map();    // id → last POST typing (ms)
    this._lastSync = null;           // serverTime of the last conversations answer
    this._open = { id: null, visible: false };
    this._viewOpen = false;
    this._timers = { check: null, poll: null, active: null, persist: null, typing: null };
    this._convTimers = new Map();
    this._removedAt = new Map();     // id → when it was dropped (late answers are ignored)
    this._checking = null;
    this._refreshing = null;
    this._refreshAgain = false;
    this._errorAttempt = 0;
    this._people = { at: 0, list: null };
    this._media = new ByteLru(this.timing.mediaCacheBytes);
    this._avatars = new ByteLru(this.timing.avatarCacheBytes);
    this._inflight = new Map();
    this._reading = new Map();
    this._unsub = [];
    this._lastUnread = 0;
    this._scope = '';

    this.outbox.on('sent', (e) => this._onSent(e));
    this.outbox.on('failed', ({ entry, error }) => {
      this.emit('send-failed', { conversationId: entry.conversationId, clientId: entry.clientId, error, source: entry.body && entry.body.source });
      this.emit('messages', { conversationId: entry.conversationId, reason: 'outbox' });
    });
    this.outbox.on('change', ({ conversationId }) => {
      this.emit('outbox', { conversationId });
      this.emit('messages', { conversationId, reason: 'outbox' });
    });

    this._loadCache();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._running) return;
    this._running = true;
    this._attachPush();
    this.outbox.start();
    this.check().catch(() => {});
  }

  stop() {
    this._running = false;
    for (const off of this._unsub.splice(0)) off();
    for (const k of Object.keys(this._timers)) this._clear(k);
    for (const t of this._convTimers.values()) clearTimeout(t);
    this._convTimers.clear();
    if (this._open.id && this._open.visible && this._avail.state === 'available') this.api.active(this._open.id, false).catch(() => {});
    this.outbox.stop();
    this._persistNow();
  }

  /** server:setup with another server or token: forget everything of the old one. */
  async resetForNewServer() {
    this._convs.clear();
    this._msgs.clear();
    this._typing.clear();
    this._typingSent.clear();
    this._media.clear();
    this._avatars.clear();
    this._people = { at: 0, list: null };
    this._me = null;
    this._lastSync = null;
    this._open = { id: null, visible: false };
    this._avail = { state: 'unknown', reason: null, version: null, label: null, checkedAt: null, stale: false };
    this._scope = this._hash(this.api.scope());
    try { this.store.delete ? this.store.delete(CACHE_KEY) : this.store.set(CACHE_KEY, null); } catch { /* ignore */ }
    await this.outbox.reset().catch(() => {});
    this._emitState();
    this.emit('conversations', { ids: null, removed: [] });
    this._emitUnread();
    if (this._running) this.check({ force: true }).catch(() => {});
  }

  _attachPush() {
    const pc = this.pushClient;
    if (!pc || typeof pc.on !== 'function') { this._schedulePoll(); return; }
    const on = (ev, fn) => { pc.on(ev, fn); this._unsub.push(() => pc.removeListener(ev, fn)); };
    on('event', (ev) => {
      if (!ev || ev.event !== 'plugin' || !ev.data || typeof ev.data !== 'object') return;
      if (ev.data.plugin !== PLUGIN_ID) return;
      this._onLive(String(ev.data.type || ''), ev.data.data && typeof ev.data.data === 'object' ? ev.data.data : {});
    });
    on('hello', () => this._onReconnect());
    on('status', () => { this._schedulePoll(); this._emitState(); });
    on('reset', () => { this.resetForNewServer().catch(() => {}); });
    this._schedulePoll();
  }

  _pushLive() {
    try { return !!this.pushClient && this.pushClient.status().state === 'connected'; } catch { return false; }
  }

  // ── Availability ─────────────────────────────────────────

  /**
   * Is the messenger usable? Updates status() and loads the chat list.
   * Coalesces parallel calls.
   */
  check({ force = false } = {}) {
    if (this._checking && !force) return this._checking;
    const run = this._doCheck().finally(() => { if (this._checking === run) this._checking = null; });
    this._checking = run;
    return run;
  }

  async _doCheck() {
    this._clear('check');
    if (!this.api.scope()) {
      this._setAvail({ state: 'unavailable', reason: 'not_configured' });
      return this.status();
    }
    this._checkScope();
    if (this._avail.state !== 'available') this._setAvail({ state: 'checking' });
    try {
      const a = await this.api.availability();
      if (!a.available) {
        this._setAvail({ state: 'unavailable', reason: a.reason, version: a.version });
        this._scheduleCheck(this.timing.recheckMs);
        return this.status();
      }
      const me = await this.api.me();
      this._me = this._normalizeMe(me);
      this._errorAttempt = 0;
      this._setAvail({ state: 'available', reason: null, version: a.version, label: a.tab && a.tab.label, stale: false });
      this._scheduleCheck(this.timing.recheckMs);
      await this.refreshConversations({ full: true }).catch((err) => this.log.debug(`Chat list not loaded: ${err.message}`));
      this.outbox.kick();
    } catch (err) {
      const e = MessengerApi.toMessengerError(err);
      if (e.status === 404 || e.status === 403) {
        // Plugin gone between the two calls, licence/kiosk refusal, token without owner.
        this._setAvail({ state: 'unavailable', reason: e.code || `http_${e.status}` });
        this._scheduleCheck(this.timing.recheckMs);
      } else {
        // Offline / server trouble: keep what we had (cached chats stay usable).
        const keep = this._avail.state === 'available';
        this._setAvail(keep ? { stale: true, reason: e.code } : { state: 'error', reason: e.code });
        const list = this.timing.errorRetryMs;
        this._scheduleCheck(list[Math.min(this._errorAttempt, list.length - 1)]);
        this._errorAttempt += 1;
      }
    }
    this._schedulePoll();
    return this.status();
  }

  _normalizeMe(me) {
    const m = me && typeof me === 'object' ? me : {};
    const user = m.user && typeof m.user === 'object' ? m.user : {};
    return {
      user: { id: posInt(user.id), name: typeof user.name === 'string' ? user.name : null, avatarUrl: isAvatarPath(user.avatarUrl) ? user.avatarUrl : null, initials: user.initials || null, colorHex: user.colorHex || null },
      prefs: { readReceipts: m.prefs ? m.prefs.readReceipts !== false : true, typing: m.prefs ? m.prefs.typing !== false : true, preview: m.prefs ? m.prefs.preview !== false : true },
      features: m.features && typeof m.features === 'object' ? { ...m.features } : {},
      limits: m.limits && typeof m.limits === 'object' ? { ...m.limits } : {},
      license: m.license && typeof m.license === 'object' ? { ...m.license } : null,
    };
  }

  _setAvail(patch) {
    const before = JSON.stringify(this._avail);
    this._avail = { ...this._avail, ...patch, checkedAt: new Date(this.now()).toISOString() };
    if (JSON.stringify({ ...this._avail, checkedAt: null }) !== JSON.stringify({ ...JSON.parse(before), checkedAt: null })) this._emitState();
  }

  _scheduleCheck(ms) {
    this._clear('check');
    if (!this._running) return;
    this._timers.check = this._timer(() => { this._timers.check = null; this.check().catch(() => {}); }, ms);
  }

  /**
   * { state: 'unknown'|'checking'|'available'|'unavailable'|'error', reason,
   *   stale, version, label, me: { user, prefs, features, limits, license } | null,
   *   unread, live, outbox }
   */
  status() {
    return {
      state: this._avail.state,
      reason: this._avail.reason,
      stale: !!this._avail.stale,
      version: this._avail.version,
      label: this._avail.label,
      checkedAt: this._avail.checkedAt,
      me: this._me ? JSON.parse(JSON.stringify(this._me)) : null,
      unread: this.unreadTotal(),
      live: this._pushLive(),
      outbox: this.outbox.size(),
    };
  }

  available() {
    return this._avail.state === 'available';
  }

  // ── Conversations ────────────────────────────────────────

  /** Cached conversations, newest activity first, with live typing ids. */
  listConversations() {
    const now = this.now();
    return sortConversations([...this._convs.values()]).map((c) => ({
      ...c,
      typing: this._typingIds(c.id, now),
      outbox: this.outbox.list(c.id).length,
    }));
  }

  getCachedConversation(id) {
    const c = this._convs.get(posInt(id));
    return c ? { ...c, typing: this._typingIds(c.id, this.now()) } : null;
  }

  /** Sum of unread messages of the chats that are not muted. */
  unreadTotal() {
    let n = 0;
    for (const c of this._convs.values()) if (!c.muted && Number.isFinite(c.unread)) n += c.unread;
    return n;
  }

  /**
   * GET conversations (full, or only the changes since the last answer).
   * Coalesces parallel calls (one more run when asked while running).
   */
  refreshConversations({ full = false } = {}) {
    if (this._refreshing) {
      if (full) this._refreshFull = true;
      this._refreshAgain = true;
      return this._refreshing;
    }
    const run = (async () => {
      let wantFull = full;
      do {
        this._refreshAgain = false;
        this._refreshFull = false;
        await this._refreshOnce(wantFull);
        wantFull = this._refreshFull;
      } while (this._refreshAgain);
    })().finally(() => { this._refreshing = null; });
    this._refreshing = run;
    return run;
  }

  async _refreshOnce(full) {
    const since = full ? null : this._lastSync;
    const r = await this.api.conversations({ since });
    const list = Array.isArray(r.conversations) ? r.conversations.filter((c) => c && posInt(c.id)) : [];
    const removed = (Array.isArray(r.removed) ? r.removed : []).map(posInt).filter(Boolean);
    if (!since) {
      const ids = new Set(list.map((c) => c.id));
      for (const id of [...this._convs.keys()]) if (!ids.has(id)) removed.push(id);
      this._convs.clear();
    }
    for (const c of list) this._convs.set(c.id, c);
    for (const id of new Set(removed)) this._drop(id, { emit: false });
    if (typeof r.serverTime === 'string') this._lastSync = r.serverTime;
    this.emit('conversations', { ids: list.map((c) => c.id), removed });
    this._emitUnread();
    this._persist();
    // The open conversation (and other loaded ones) may have new messages.
    for (const c of list) {
      const st = this._msgs.get(c.id);
      if (st && st.loaded && c.lastMessageId && c.lastMessageId > this._newestId(st)) {
        this._loadNewer(c.id).then(() => this._maybeRead(c.id)).catch(() => {});
      }
    }
  }

  /** GET conversations/:id → cached + returned (404 → dropped, null). */
  async getConversation(id, { refresh = true } = {}) {
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid id', { code: 'invalid' });
    if (!refresh && this._convs.has(cid)) return this.getCachedConversation(cid);
    const started = this.now();
    try {
      const r = await this.api.conversation(cid);
      // Removed while the answer was on its way (conversation.remove).
      if ((this._removedAt.get(cid) || 0) >= started) return null;
      if (r.conversation) this._upsert(r.conversation);
      return this.getCachedConversation(cid);
    } catch (err) {
      if (err.status === 404) { this._drop(cid); return null; }
      if (this._convs.has(cid)) return this.getCachedConversation(cid);
      throw err;
    }
  }

  _refreshConvSoon(id) {
    const cid = posInt(id);
    if (!cid) return;
    if (this._convTimers.has(cid)) clearTimeout(this._convTimers.get(cid));
    this._convTimers.set(cid, this._timer(() => {
      this._convTimers.delete(cid);
      this.getConversation(cid).catch(() => {});
    }, this.timing.convDebounceMs));
  }

  _upsert(c) {
    if (!c || !posInt(c.id)) return;
    this._convs.set(c.id, c);
    this.emit('conversations', { ids: [c.id], removed: [] });
    this._emitUnread();
    this._persist();
  }

  _drop(id, { emit = true } = {}) {
    if (this._convTimers.has(id)) { clearTimeout(this._convTimers.get(id)); this._convTimers.delete(id); }
    this._removedAt.set(id, this.now());
    if (this._removedAt.size > 200) this._removedAt.delete(this._removedAt.keys().next().value);
    const had = this._convs.delete(id);
    this._msgs.delete(id);
    this._typing.delete(id);
    if (this._open.id === id) this._open = { id: null, visible: false };
    if (emit && had) {
      this.emit('conversations', { ids: [], removed: [id] });
      this._emitUnread();
      this._persist();
    }
  }

  // ── Messages ─────────────────────────────────────────────

  /**
   * Messages of a conversation (cached + newest from the server), with the
   * pending outbox entries. `before` loads an older page.
   * → { conversationId, messages, pending, hasMore, offline }
   */
  async getMessages(id, { before = null } = {}) {
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid id', { code: 'invalid' });
    let st = this._msgs.get(cid);
    if (!st) { st = { list: [], hasMore: true, loaded: false, syncedAt: null }; this._msgs.set(cid, st); }
    let offline = false;
    try {
      if (posInt(before)) {
        const r = await this.api.messages(cid, { before: posInt(before), limit: PAGE });
        st.list = mergeMessages(st.list, r.messages);
        st.hasMore = r.hasMore === true;
        this._receipts(cid, r);
      } else if (!st.loaded) {
        await this._loadNewest(cid);
      } else {
        await this._loadNewer(cid);
      }
    } catch (err) {
      if (err.status === 404) { this._drop(cid); throw err; }
      if (!st.loaded && !st.list.length) throw err;
      offline = true;
    }
    return this.messagesView(cid, { offline });
  }

  /** Cached view without asking the server. */
  messagesView(id, { offline = false } = {}) {
    const cid = posInt(id);
    const st = this._msgs.get(cid) || { list: [], hasMore: true };
    const ids = new Set(st.list.map((m) => m.clientId).filter(Boolean));
    const pending = this.outbox.list(cid).filter((e) => !ids.has(e.clientId)).map((e) => this._pendingView(e));
    return { conversationId: cid, messages: st.list.slice(), pending, hasMore: st.hasMore !== false, offline };
  }

  async _loadNewest(cid) {
    const st = this._msgs.get(cid);
    const r = await this.api.messages(cid, { limit: PAGE });
    st.list = Array.isArray(r.messages) ? r.messages.slice() : [];
    st.hasMore = r.hasMore === true;
    st.loaded = true;
    st.syncedAt = this._lastSync || new Date(this.now() - 5000).toISOString();
    this._receipts(cid, r);
    this.emit('messages', { conversationId: cid, reason: 'load' });
    this._persist();
  }

  /** Fetch messages after the newest cached one (a few pages, else reload the newest page). */
  async _loadNewer(cid) {
    const st = this._msgs.get(cid);
    if (!st || !st.loaded) return;
    const key = `newer:${cid}`;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = (async () => {
      let after = this._newestId(st);
      if (!after) { await this._loadNewest(cid); return; }
      let got = 0;
      for (let page = 0; page < 5; page++) {
        const r = await this.api.messages(cid, { after, limit: 100 });
        const msgs = Array.isArray(r.messages) ? r.messages : [];
        st.list = mergeMessages(st.list, msgs);
        got += msgs.length;
        this._receipts(cid, r);
        if (!r.hasMore || !msgs.length) {
          if (got) this.emit('messages', { conversationId: cid, reason: 'new' });
          this._persist();
          return;
        }
        after = this._newestId(st);
      }
      // Far behind: start again from the newest page.
      await this._loadNewest(cid);
    })().finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  /** Edits, deletions and reactions since the last sync (after a reconnect). */
  async _loadChanged(cid) {
    const st = this._msgs.get(cid);
    if (!st || !st.loaded || !st.syncedAt) return;
    const since = st.syncedAt;
    st.syncedAt = this._lastSync || new Date(this.now() - 5000).toISOString();
    const r = await this.api.messages(cid, { changedSince: since, limit: 100 });
    const msgs = Array.isArray(r.messages) ? r.messages : [];
    if (!msgs.length) return;
    const known = new Set(st.list.map((m) => m.id));
    st.list = mergeMessages(st.list, msgs.filter((m) => known.has(m.id)));
    this.emit('messages', { conversationId: cid, reason: 'changed' });
    this._persist();
  }

  _receipts(cid, r) {
    const c = this._convs.get(cid);
    if (!c || !r) return;
    let changed = false;
    for (const k of ['readUpTo', 'deliveredUpTo']) {
      if (k in r && r[k] !== c[k]) { c[k] = r[k]; changed = true; }
    }
    if (Array.isArray(r.receipts)) { c.receipts = r.receipts; changed = true; }
    if (changed) this.emit('conversations', { ids: [cid], removed: [] });
  }

  _newestId(st) {
    let n = 0;
    for (const m of st.list) if (m.id > n) n = m.id;
    return n;
  }

  _pendingView(e) {
    const files = e.files || {};
    const main = files.main;
    const replyId = e.body.replyTo || null;
    let replyTo = null;
    if (replyId) {
      const st = this._msgs.get(e.conversationId);
      const q = st && st.list.find((m) => m.id === replyId);
      replyTo = q ? { id: q.id, senderId: q.senderId, kind: q.kind, text: q.text ? String(q.text).slice(0, 200) : null, deleted: !!q.deleted, missing: false }
        : { id: replyId, senderId: null, kind: 'text', text: null, deleted: false, missing: true };
    }
    return {
      id: null,
      clientId: e.clientId,
      conversationId: e.conversationId,
      pending: true,
      failed: e.state === 'failed',
      sending: e.state === 'sending',
      error: e.error || null,
      kind: e.body.kind || 'text',
      text: e.body.text || null,
      replyTo,
      meta: e.body.meta || null,
      location: e.body.location || null,
      media: main ? { id: null, mime: main.mime, bytes: main.bytes, local: true } : null,
      senderId: this._me && this._me.user ? this._me.user.id : null,
      mine: true,
      createdAt: e.createdAt,
      reactions: [],
      deleted: false,
    };
  }

  _findMessage(messageId) {
    for (const [cid, st] of this._msgs) {
      const m = st.list.find((x) => x.id === messageId);
      if (m) return { cid, st, m };
    }
    return null;
  }

  _replaceMessage(msg) {
    if (!msg || !posInt(msg.id)) return;
    const cid = posInt(msg.conversationId);
    const st = this._msgs.get(cid);
    if (st && st.loaded) st.list = mergeMessages(st.list, [msg]);
    const c = this._convs.get(cid);
    if (c && c.lastMessage && c.lastMessage.id === msg.id) c.lastMessage = msg;
    this.emit('messages', { conversationId: cid, reason: 'update' });
    this._persist();
  }

  // ── Sending and changing ─────────────────────────────────

  /**
   * Queue a message for sending (outbox). Files: `file` { data, mime, name }
   * (image / voice / file), `thumb` { data, mime } (image preview ≤ 64 KB).
   * → the pending message.
   */
  async send(req = {}) {
    const cid = posInt(req.conversationId);
    if (!cid) throw new MessengerError('invalid conversation', { code: 'invalid' });
    const c = this._convs.get(cid);
    if (c && c.can && c.can.send === false) throw new MessengerError('readonly', { code: c.readonly ? 'readonly' : 'forbidden' });
    const limits = (this._me && this._me.limits) || {};
    const body = buildSendBody(req, { textMax: limits.textMax || 4000 });
    const files = {};
    if (body.kind === 'image' || body.kind === 'voice' || body.kind === 'file') {
      files.main = this._checkFile(req.file, limits);
      if (body.kind === 'file') {
        body.meta = { ...(body.meta || {}), fileName: (body.meta && body.meta.fileName) || String(files.main.name || 'Datei').slice(0, 200) };
      }
      if (body.kind === 'image' && req.thumb) {
        try {
          const t = this._checkFile(req.thumb, limits);
          if (byteLength(t.data) <= (limits.thumbMaxBytes || 65536) && /^image\//.test(t.mime)) files.thumb = t;
        } catch { /* no preview */ }
      }
    } else if (req.file) {
      throw new MessengerError('file not allowed', { code: 'invalid' });
    }
    this._typingSent.delete(cid);
    const entry = await this.outbox.add({ conversationId: cid, clientId: req.clientId, body, files });
    return this._pendingView(entry);
  }

  _checkFile(f, limits) {
    if (!f || typeof f !== 'object') throw new MessengerError('file missing', { code: 'invalid' });
    const mime = baseMime(f.mime);
    const size = byteLength(f.data);
    if (!size) throw new MessengerError('empty file', { code: 'length_required' });
    if (!mime) throw new MessengerError('no type', { code: 'unsupported_type' });
    if (Number.isFinite(limits.maxBytes) && limits.maxBytes > 0 && size > limits.maxBytes) throw new MessengerError('too large', { code: 'too_large' });
    if (Array.isArray(limits.types) && limits.types.length && !limits.types.includes(mime)) throw new MessengerError('type', { code: 'unsupported_type' });
    return { data: f.data, mime, name: typeof f.name === 'string' ? f.name : null };
  }

  retrySend(clientId) { return this.outbox.retry(clientId); }

  discardSend(clientId) { return this.outbox.discard(clientId); }

  _onSent({ entry, message }) {
    const cid = entry.conversationId;
    if (message && posInt(message.id)) {
      const st = this._msgs.get(cid);
      if (st && st.loaded) st.list = mergeMessages(st.list, [message]);
      const c = this._convs.get(cid);
      if (c) {
        if (!c.lastMessageId || message.id >= c.lastMessageId) {
          c.lastMessageId = message.id;
          c.lastMessage = message;
          c.updatedAt = message.createdAt || c.updatedAt;
        }
        // Sending reads everything before it (plugin rule).
        if (c.me) c.me.lastReadId = Math.max(c.me.lastReadId || 0, message.id);
        if (c.unread) c.unread = 0;
        this.emit('conversations', { ids: [cid], removed: [] });
        this._emitUnread();
      } else {
        this._refreshConvSoon(cid);
      }
      this.emit('read-local', { conversationId: cid, upTo: message.id });
    }
    this.emit('messages', { conversationId: cid, reason: 'sent' });
    this._persist();
  }

  async edit(messageId, text) {
    const id = posInt(messageId);
    if (!id || typeof text !== 'string' || text.length > 4000) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.edit(id, text.replace(/\r\n?/g, '\n').trim());
    this._replaceMessage(r.message);
    return r.message || null;
  }

  async remove(messageId, scope = 'me') {
    const id = posInt(messageId);
    if (!id || !['me', 'all'].includes(scope)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.remove(id, scope);
    if (r.forAll && r.message) this._replaceMessage(r.message);
    else this._removeLocal([id]);
    return { forAll: !!r.forAll, message: r.message || null };
  }

  async react(messageId, emoji) {
    const id = posInt(messageId);
    if (!id || (emoji != null && (typeof emoji !== 'string' || !emoji.length || emoji.length > 16))) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.react(id, emoji);
    const hit = this._findMessage(id);
    if (hit && Array.isArray(r.reactions)) {
      hit.m.reactions = r.reactions;
      this.emit('messages', { conversationId: hit.cid, reason: 'reaction' });
      this._persist();
    }
    return r.reactions || [];
  }

  _removeLocal(ids, { conversationId = null } = {}) {
    const set = new Set(ids);
    for (const [cid, st] of this._msgs) {
      if (conversationId && cid !== conversationId) continue;
      const before = st.list.length;
      st.list = st.list.filter((m) => !set.has(m.id));
      if (st.list.length !== before) this.emit('messages', { conversationId: cid, reason: 'delete' });
    }
    this._persist();
  }

  _tombstone(cid, ids) {
    const st = this._msgs.get(cid);
    if (!st) return;
    const set = new Set(ids);
    st.list = st.list.map((m) => (set.has(m.id)
      ? { ...m, deleted: true, text: null, media: null, meta: null, location: null, replyTo: null, reactions: [] }
      : m));
    this.emit('messages', { conversationId: cid, reason: 'delete' });
    this._persist();
  }

  /**
   * Read up to `upTo` (default: the newest known message). Never moves back.
   * → { lastReadId, unread } | null
   */
  async markRead(id, upTo = null) {
    const cid = posInt(id);
    const c = this._convs.get(cid);
    if (!cid || !c) return null;
    const st = this._msgs.get(cid);
    const newest = posInt(upTo) || Math.max(st ? this._newestId(st) : 0, c.lastMessageId || 0);
    if (!newest) return null;
    const lastRead = c.me && Number.isSafeInteger(c.me.lastReadId) ? c.me.lastReadId : 0;
    this.emit('read-local', { conversationId: cid, upTo: newest });
    if (newest <= lastRead && (!c.unread || posInt(upTo))) return { lastReadId: lastRead, unread: c.unread || 0 };
    const key = `${cid}:${newest}`;
    if (this._reading.has(key)) return this._reading.get(key);
    const run = this.api.read(cid, newest).then((r) => {
      const cc = this._convs.get(cid);
      if (cc) {
        if (cc.me && Number.isSafeInteger(r.lastReadId)) cc.me.lastReadId = r.lastReadId;
        if (Number.isFinite(r.unread)) cc.unread = r.unread;
        this.emit('conversations', { ids: [cid], removed: [] });
        this._emitUnread();
        this._persist();
      }
      return { lastReadId: r.lastReadId, unread: r.unread };
    }).catch((err) => { this.log.debug(`Chat read mark not sent: ${err.message}`); return null; })
      .finally(() => this._reading.delete(key));
    this._reading.set(key, run);
    return run;
  }

  /** "schreibt …" while typing (≤ every 3 s), or stop. */
  async typing(id, { stop = false } = {}) {
    const cid = posInt(id);
    if (!cid || !this.available()) return false;
    if (this._me && this._me.prefs && this._me.prefs.typing === false) return false;
    const now = this.now();
    const last = this._typingSent.get(cid) || 0;
    if (stop) {
      if (!last || now - last > this.timing.typingValidMs) return false;
      this._typingSent.delete(cid);
      await this.api.typing(cid, true).catch(() => {});
      return true;
    }
    const every = ((this._me && this._me.limits && this._me.limits.typingEveryS) || this.timing.typingEveryMs / 1000) * 1000;
    if (now - last < every) return false;
    this._typingSent.set(cid, now);
    await this.api.typing(cid, false).catch(() => {});
    return true;
  }

  // ── Open conversation / view ─────────────────────────────

  /**
   * The conversation shown in the app ({ id: null } when none) and whether it
   * is visible (window shown, page active). Visible → "active" pings every
   * 20 s and read marks; the push for it is suppressed by the server.
   */
  setOpen({ id = null, visible = false } = {}) {
    const cid = posInt(id);
    const vis = !!cid && visible === true && this._safe(() => this.isWindowVisible(), true) !== false;
    const prev = this._open;
    this._open = { id: cid, visible: vis };
    if (prev.id && prev.visible && (prev.id !== cid || !vis) && this.available()) this.api.active(prev.id, false).catch(() => {});
    this._clear('active');
    if (cid && vis && this.available()) {
      const ping = () => { this.api.active(cid).catch(() => {}); };
      ping();
      this._timers.active = setInterval(ping, this.timing.activeEveryMs);
      if (this._timers.active.unref) this._timers.active.unref();
      this._maybeRead(cid);
    }
    return { ...this._open };
  }

  /** Is this conversation open and visible right now? */
  isOpenAndVisible(id) {
    return !!this._open.id && this._open.id === posInt(id) && this._open.visible && this._safe(() => this.isWindowVisible(), true) !== false;
  }

  /** The chat page is shown (polling cadence without push). */
  setViewOpen(open) {
    this._viewOpen = open === true;
    this._schedulePoll();
  }

  _maybeRead(cid) {
    if (this.isOpenAndVisible(cid)) this.markRead(cid).catch(() => {});
  }

  // ── Groups, people, prefs, search, media ─────────────────

  async people({ refresh = false } = {}) {
    if (!refresh && this._people.list && this.now() - this._people.at < this.timing.peopleTtlMs) return this._people.list.slice();
    const r = await this.api.people();
    this._people = { at: this.now(), list: Array.isArray(r.people) ? r.people : [] };
    return this._people.list.slice();
  }

  /**
   * New chat: { kind: 'direct', userIds: [id] } or { kind: 'group', userIds,
   * title, avatar?: { data, mime } } → { conversation, created }.
   */
  async createConversation({ kind, userIds, title, avatar } = {}) {
    const ids = Array.isArray(userIds) ? [...new Set(userIds.map(posInt).filter(Boolean))] : [];
    if (kind === 'direct') {
      if (ids.length !== 1) throw new MessengerError('invalid', { code: 'invalid' });
    } else if (kind === 'group') {
      if (!ids.length || ids.length > 255 || typeof title !== 'string' || !title.trim() || title.trim().length > 80) throw new MessengerError('invalid', { code: 'invalid' });
    } else {
      throw new MessengerError('invalid', { code: 'invalid' });
    }
    const body = { kind, userIds: ids };
    if (kind === 'group') {
      body.title = title.trim();
      if (avatar) body.avatarMediaId = await this._uploadAvatar(avatar);
    }
    const r = await this.api.createConversation(body);
    if (r.conversation) this._upsert(r.conversation);
    return { conversation: r.conversation ? this.getCachedConversation(r.conversation.id) : null, created: !!r.created };
  }

  /**
   * PATCH conversations/:id. patch: { title, avatarMediaId: null, disappearingS,
   * mutedUntil, notify, add, remove, role }; avatar: { data, mime } uploads a
   * new group picture. → { conversation, left }
   */
  async updateConversation(id, patch = {}, { avatar = null } = {}) {
    const cid = posInt(id);
    if (!cid || !patch || typeof patch !== 'object') throw new MessengerError('invalid', { code: 'invalid' });
    const body = {};
    if (typeof patch.title === 'string') body.title = patch.title.trim().slice(0, 80);
    if (patch.avatarMediaId === null) body.avatarMediaId = null;
    if (Number.isSafeInteger(patch.disappearingS) && patch.disappearingS >= 0) body.disappearingS = patch.disappearingS;
    if (patch.mutedUntil === null || (typeof patch.mutedUntil === 'string' && !Number.isNaN(Date.parse(patch.mutedUntil)))) body.mutedUntil = patch.mutedUntil;
    if (patch.notify === 'all' || patch.notify === 'none') body.notify = patch.notify;
    for (const k of ['add', 'remove']) {
      if (Array.isArray(patch[k])) body[k] = [...new Set(patch[k].map(posInt).filter(Boolean))].slice(0, 255);
    }
    if (patch.role && posInt(patch.role.userId) && ['admin', 'member'].includes(patch.role.role)) body.role = { userId: posInt(patch.role.userId), role: patch.role.role };
    if (avatar) body.avatarMediaId = await this._uploadAvatar(avatar);
    if (!Object.keys(body).length) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.patchConversation(cid, body);
    if (r.left || !r.conversation) {
      this._drop(cid);
      return { conversation: null, left: true };
    }
    this._upsert(r.conversation);
    return { conversation: this.getCachedConversation(cid), left: false };
  }

  async _uploadAvatar(avatar) {
    const limits = (this._me && this._me.limits) || {};
    const f = this._checkFile(avatar, limits);
    if (!/^image\//.test(f.mime)) throw new MessengerError('type', { code: 'unsupported_type' });
    const up = await this.api.upload({ data: f.data, mime: f.mime });
    return up.mediaId;
  }

  async setPrefs(patch = {}) {
    const r = await this.api.setPrefs(patch);
    if (this._me && r.prefs) this._me.prefs = { ...this._me.prefs, ...r.prefs };
    this._emitState();
    // Receipts / typing visibility change what the server sends for every chat.
    this.refreshConversations({ full: true }).catch(() => {});
    return this._me ? { ...this._me.prefs } : r.prefs;
  }

  async search(id, q) {
    const cid = posInt(id);
    const text = typeof q === 'string' ? q.trim() : '';
    if (!cid || text.length < 2 || text.length > 100) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.search(cid, text);
    return { results: Array.isArray(r.results) ? r.results : [], truncated: !!r.truncated, scanned: r.scanned || 0 };
  }

  async mediaList(id, opts = {}) {
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.mediaList(cid, opts);
    return { items: Array.isArray(r.items) ? r.items : [], counts: r.counts || { image: 0, voice: 0, file: 0 }, hasMore: !!r.hasMore };
  }

  /** A file of a message → { mime, data } (in-memory LRU, one download at a time per id). */
  async media(mediaId) {
    if (!isMediaId(mediaId)) throw new MessengerError('invalid', { code: 'invalid' });
    const hit = this._media.get(mediaId);
    if (hit) return hit;
    const key = `media:${mediaId}`;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const limits = (this._me && this._me.limits) || {};
    const max = Number.isFinite(limits.maxBytes) && limits.maxBytes > 0 ? limits.maxBytes + 1024 : undefined;
    const run = this.api.download(mediaId, max ? { maxBytes: max } : {}).then((r) => {
      this._media.set(mediaId, r);
      return r;
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  /** An account picture (/avatars/…) → { mime, data }. */
  async avatar(urlPath) {
    if (!isAvatarPath(urlPath)) throw new MessengerError('invalid', { code: 'invalid' });
    const hit = this._avatars.get(urlPath);
    if (hit) return hit;
    const key = `avatar:${urlPath}`;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.avatar(urlPath).then((r) => { this._avatars.set(urlPath, r); return r; })
      .finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── Live events ──────────────────────────────────────────

  _onLive(type, d) {
    if (!this.available()) {
      // Events prove the plugin is there (e.g. installed while running).
      if (this._avail.state !== 'checking') this.check().catch(() => {});
      return;
    }
    const cid = posInt(d.conversationId);
    switch (type) {
      case 'message.new': {
        if (!cid) return;
        const sender = posInt(d.senderId);
        if (sender) this._setTyping(cid, sender, null);
        this._refreshConvSoon(cid);
        const st = this._msgs.get(cid);
        if (st && st.loaded) this._loadNewer(cid).then(() => this._maybeRead(cid)).catch(() => {});
        break;
      }
      case 'message.update': {
        if (!cid) return;
        const st = this._msgs.get(cid);
        const mid = posInt(d.messageId);
        if (st && st.loaded && mid && st.list.some((m) => m.id === mid)) {
          const t = Date.parse(d.editedAt);
          const since = Number.isFinite(t) ? new Date(t - 1).toISOString() : (st.syncedAt || new Date(this.now() - 60000).toISOString());
          this.api.messages(cid, { changedSince: since, limit: 100 }).then((r) => {
            const known = new Set(st.list.map((m) => m.id));
            st.list = mergeMessages(st.list, (r.messages || []).filter((m) => known.has(m.id)));
            this.emit('messages', { conversationId: cid, reason: 'update' });
            this._persist();
          }).catch(() => {});
        }
        this._refreshConvSoon(cid);
        break;
      }
      case 'message.delete': {
        if (!cid) return;
        const ids = (Array.isArray(d.messageIds) ? d.messageIds : []).map(posInt).filter(Boolean);
        if (ids.length) {
          if (d.reason === 'deleted') this._tombstone(cid, ids);
          else this._removeLocal(ids, { conversationId: cid });
        }
        this._refreshConvSoon(cid);
        break;
      }
      case 'reaction': {
        const mid = posInt(d.messageId);
        const hit = mid ? this._findMessage(mid) : null;
        if (hit && Array.isArray(d.reactions)) {
          hit.m.reactions = d.reactions;
          this.emit('messages', { conversationId: hit.cid, reason: 'reaction' });
          this._persist();
        }
        break;
      }
      case 'read': {
        if (!cid) return;
        const c = this._convs.get(cid);
        if (d.self === true) {
          if (c) {
            if (c.me && Number.isSafeInteger(d.lastReadId)) c.me.lastReadId = Math.max(c.me.lastReadId || 0, d.lastReadId);
            if (Number.isFinite(d.unread)) c.unread = d.unread;
            this.emit('conversations', { ids: [cid], removed: [] });
            this._emitUnread();
            this._persist();
          }
          this.emit('read-self', { conversationId: cid, lastReadId: posInt(d.lastReadId) });
          // An answer in flight from before the event may carry the old count.
          this._refreshConvSoon(cid);
        } else {
          this._refreshConvSoon(cid);
        }
        break;
      }
      case 'typing': {
        const uid = posInt(d.userId);
        if (!cid || !uid) return;
        const t = Date.parse(d.until);
        this._setTyping(cid, uid, d.until && Number.isFinite(t) ? Math.min(t, this.now() + this.timing.typingValidMs + 2000) : null);
        break;
      }
      case 'conversation.update':
        this._refreshConvSoon(cid);
        break;
      case 'conversation.remove':
        if (cid) this._drop(cid);
        break;
      default:
        break;
    }
  }

  _setTyping(cid, uid, until) {
    let map = this._typing.get(cid);
    const had = !!(map && map.has(uid));
    if (until && until > this.now()) {
      if (!map) { map = new Map(); this._typing.set(cid, map); }
      map.set(uid, until);
    } else if (map) {
      map.delete(uid);
      if (!map.size) this._typing.delete(cid);
    }
    if (had || until) this.emit('typing', { conversationId: cid, userIds: this._typingIds(cid, this.now()) });
    this._scheduleTypingExpiry();
  }

  _typingIds(cid, now) {
    const map = this._typing.get(cid);
    if (!map) return [];
    return [...map.entries()].filter(([, u]) => u > now).map(([id]) => id);
  }

  _scheduleTypingExpiry() {
    this._clear('typing');
    let next = Infinity;
    for (const map of this._typing.values()) for (const u of map.values()) next = Math.min(next, u);
    if (!Number.isFinite(next)) return;
    this._timers.typing = this._timer(() => {
      this._timers.typing = null;
      const now = this.now();
      for (const [cid, map] of [...this._typing]) {
        let changed = false;
        for (const [uid, u] of [...map]) if (u <= now) { map.delete(uid); changed = true; }
        if (!map.size) this._typing.delete(cid);
        if (changed) this.emit('typing', { conversationId: cid, userIds: this._typingIds(cid, now) });
      }
      this._scheduleTypingExpiry();
    }, Math.max(50, next - this.now() + 20));
  }

  /** Push stream (re)connected: the events in between are lost — catch up. */
  _onReconnect() {
    this.outbox.kick();
    if (!this.available()) {
      if (this._avail.state !== 'checking') this.check().catch(() => {});
      return;
    }
    this._resync().catch(() => {});
  }

  async _resync() {
    await this.refreshConversations({ full: !this._lastSync });
    const ids = [...this._msgs.keys()].filter((id) => this._msgs.get(id).loaded);
    for (const id of ids) {
      if (id === this._open.id || ids.length <= 5) await this._loadChanged(id).catch(() => {});
    }
  }

  _schedulePoll() {
    this._clear('poll');
    if (!this._running) return;
    if (this._avail.state !== 'available' || this._pushLive()) return;
    const ms = this._viewOpen ? this.timing.pollOpenMs : this.timing.pollIdleMs;
    this._timers.poll = this._timer(() => {
      this._timers.poll = null;
      this._resync().catch(() => {}).finally(() => this._schedulePoll());
    }, ms);
  }

  // ── Cache ────────────────────────────────────────────────

  _hash(s) {
    return s ? crypto.createHash('sha256').update(s).digest('hex').slice(0, 16) : '';
  }

  _checkScope() {
    const scope = this._hash(this.api.scope());
    if (!scope || scope === this._scope) return;
    if (this._scope) {
      this._convs.clear();
      this._msgs.clear();
      this._me = null;
      this._lastSync = null;
      this.emit('conversations', { ids: null, removed: [] });
    }
    this._scope = scope;
  }

  _loadCache() {
    try {
      const raw = this.store && this.store.get(CACHE_KEY);
      const scope = this._hash(this.api.scope());
      this._scope = scope;
      if (!raw || raw.v !== 1 || !scope || raw.scope !== scope) return;
      for (const c of Array.isArray(raw.convs) ? raw.convs : []) if (c && posInt(c.id)) this._convs.set(c.id, c);
      for (const [id, st] of Object.entries(raw.msgs || {})) {
        const cid = posInt(id);
        if (!cid || !this._convs.has(cid) || !st || !Array.isArray(st.list)) continue;
        this._msgs.set(cid, { list: st.list.filter((m) => m && posInt(m.id)), hasMore: true, loaded: true, syncedAt: st.syncedAt || null });
      }
      if (raw.me) this._me = raw.me;
      if (this._convs.size || this._me) {
        this._avail = { ...this._avail, state: 'available', stale: true };
      }
      this._lastUnread = this.unreadTotal();
    } catch (err) {
      this.log.warn(`Chat cache unreadable: ${err.message}`);
    }
  }

  _persist() {
    if (this._timers.persist) return;
    this._timers.persist = this._timer(() => { this._timers.persist = null; this._persistNow(); }, this.timing.persistDelayMs);
  }

  _persistNow() {
    this._clear('persist');
    if (!this.store || !this._scope) return;
    try {
      const convs = sortConversations([...this._convs.values()]).slice(0, CACHE_CONVS);
      const msgs = {};
      for (const c of convs) {
        const st = this._msgs.get(c.id);
        if (st && st.loaded && st.list.length) msgs[c.id] = { list: st.list.slice(-CACHE_MSGS), syncedAt: st.syncedAt || null };
      }
      this.store.set(CACHE_KEY, { v: 1, scope: this._scope, me: this._me, convs, msgs });
    } catch (err) {
      this.log.warn(`Chat cache could not be saved: ${err.message}`);
    }
  }

  // ── Helpers ──────────────────────────────────────────────

  _emitState() {
    this.emit('state', this.status());
  }

  _emitUnread() {
    const n = this.unreadTotal();
    if (n === this._lastUnread) return;
    this._lastUnread = n;
    this.emit('unread', n);
  }

  _timer(fn, ms) {
    const t = setTimeout(fn, ms);
    if (t && t.unref) t.unref();
    return t;
  }

  _clear(name) {
    const t = this._timers[name];
    if (t) { clearTimeout(t); clearInterval(t); }
    this._timers[name] = null;
  }

  _safe(fn, fallback) {
    try { return fn(); } catch { return fallback; }
  }

  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Messenger listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

MessengerService.DEFAULT_TIMING = DEFAULT_TIMING;
MessengerService.CACHE_KEY = CACHE_KEY;
MessengerService.KINDS = KINDS;

module.exports = MessengerService;
