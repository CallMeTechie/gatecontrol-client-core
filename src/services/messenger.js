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
 *   - Jumps (Messenger ≥ 1.1.0): `messages?around=` loads the page around a
 *     search hit or quote that is not loaded; it is kept as a separate
 *     window (older / newer pages through before / after) until it reaches
 *     the cached newest messages, then both are joined.
 *   - Receipts: the `read` event of 1.1.0 carries readUpTo / deliveredUpTo
 *     → the ticks change without a GET (older plugins: GET conversations/:id).
 *   - `changedSince` uses the `serverTime` of the messages answers (1.1.0;
 *     before: the one of the conversation list).
 *   - Video files and file previews (Messenger 1.3.0): `video` and a
 *     `thumbMediaId` on file messages are sent only when `GET me` has the
 *     features `video_meta` / `file_thumbs` set to true.
 *   - Update hint: features the server switches on that this version does
 *     not know → status().updateHint (the Chats view shows a dismissible
 *     banner; dismissed per set of unknown features, never blocking).
 *   - Messenger 1.4.0 (each part only when `GET me` features has its key):
 *     status and stories (feed cached, refreshed on status.update /
 *     story.new / story.remove), polls, events, home actions and plugin
 *     cards (message kinds; poll.update / event.update / action.update /
 *     arrival.update → `changedSince`), chat tools (archive, pins, lists,
 *     blocks, export, reminders, suggestions → Familie), the prefs privacy /
 *     notify / chats. Windows sends no live arrival; it shows them and can
 *     stop an own one.
 *   - Messenger 1.4.1: a story's duration (`durationH`, feature
 *     `story_duration`); without the key it is left out (24 h).
 *   - Messenger 1.21 (feature `chat_people`, ?people=1): persons — one
 *     entry per human over several ways (`person`; its id is the lead
 *     conversation's, the other ways are `folded` out of the list). Their
 *     messages, read marks, search, mute and archive go through persons/:id/…
 *     (the shared history by time, `way` on each message, a source filter),
 *     sending through POST persons/:id/messages (the server picks the way).
 *     Live events of a way belong to its entry; suggestions, merging and
 *     „Trennen“ pass through. Without the word everything stays as it was.
 *
 * Events: 'state' (status()), 'conversations' ({ ids, removed }),
 * 'messages' ({ conversationId, reason }), 'typing' ({ conversationId,
 * userIds }), 'unread' (total), 'outbox' ({ conversationId }),
 * 'read-local' ({ conversationId, upTo }) read on this device,
 * 'read-self' ({ conversationId, lastReadId }) read on another device,
 * 'send-failed' ({ conversationId, clientId, error, source }),
 * 'feed' (status feed of 1.4.0), 'lists' (custom chat filters),
 * 'reminders' (own "remind me" list changed),
 * 'suggestions' (1.21: the open suggestions „… ist vielleicht …“ changed).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const MessengerApi = require('./messenger-api');
const MessengerOutbox = require('./messenger-outbox');
const {
  PLUGIN_ID, posInt, mergeMessages, sortConversations, buildSendBody, isMediaId, isAvatarPath, isNotifyMediaPath, baseMime, byteLength,
  KINDS, normalizeFeatures, hasFeature, unknownFeatures, isVideoMime, FEATURE_VIDEO_META, FEATURE_FILE_THUMBS,
  KIND_FEATURE, FEATURES_14, prefsBody, statusBody, storyBody, storyDurationsOf, listsBody, familieOf, normalizeEvent, safeFileName,
  FEATURE_LINKED, FEATURE_BRIDGE_CHATS, BRIDGE_FLOWS, isBridgeNet, isBridgeId, bridgePhone, normalizeBridges, normalizeBridgeLogin,
  FEATURE_BRIDGE_NEW_CHAT, bridgeNumber, normalizeResolve, bridgeMediaRefusal, FEATURE_BRIDGE_HISTORY, HISTORY_DAYS, normalizeBridgeHistory,
  FEATURE_BRIDGE_CONTACTS, CONTACTS_QUERY_MAX, normalizeNewChatContacts, contactChatBody,
  FEATURE_BRIDGE_CHANNELS, isChannel, normalizeChannelSummary,
  FEATURE_CHAT_PEOPLE, GC_WAY, byTimeOrder, isPerson, personWayIds, personReplyWay, wayOf, mergeBody, isSuggestionId, normalizeRecognition,
  normalizeHandoff, HANDOFF_TARGETS,
} = require('../utils/messenger');
const { savedOf: driveSavedOf } = require('../utils/drive');
const SC = require('../utils/scan');

const { MessengerError } = MessengerApi;
// Messenger 1.22: the levels of „Wer sieht dein Bild?“ in GateControl's profile
const AVATAR_LEVELS = Object.freeze(['all', 'contacts', 'family', 'self']);
const CACHE_KEY = 'messengerCache';
const HINT_KEY = 'messengerUpdateHint';
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
  feedTtlMs: 60 * 1000,           // status feed (1.4.0) without events
  feedDebounceMs: 300,            // status.update / story.* → GET status/feed
  actionsTtlMs: 60 * 1000,        // GET actions (attach menu)
  suggestTtlMs: 15 * 60 * 1000,   // 1.21: GET persons/suggestions at most every 15 min
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
  delete(k) {
    const v = this.map.get(k);
    if (!v) return;
    this.bytes -= byteLength(v.data);
    this.map.delete(k);
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
    this._msgs = new Map();          // id → { list, hasMore, loaded, syncedAt, window }
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
    // Messenger 1.4.0
    this._feed = { at: 0, data: null };
    this._chatLists = null;
    this._actions = { at: 0, list: null };
    // Messenger 1.14: contacts of a chat over a bridge who are typing (id → Map(contactId → { name, until })),
    // and whether this server showed a chat over a bridge (an event or a push named one)
    this._typingContacts = new Map();
    this._bridgeSeen = false;
    // Messenger 1.15: chats over a bridge just started by number — GET conversations lists them only once something
    // was said in them, so a full read of the list keeps them (id → since)
    this._freshBridge = new Map();
    // Messenger 1.20 (bridge_channels): the channels live in _convs as well, but on a page of their own — `channels`
    // { count, unread } of the last GET conversations, and whether GET channels was read since
    this._chanSum = null;
    this._chansLoaded = false;
    this._chanRefresh = null;
    // Messenger 1.21 (chat_people): the open suggestions of GET persons/suggestions
    this._sugg = { at: 0, list: null };

    this.outbox.on('sent', (e) => this._onSent(e));
    this.outbox.on('failed', ({ entry, error }) => {
      this.emit('send-failed', { conversationId: entry.conversationId, clientId: entry.clientId, error, source: entry.body && entry.body.source, ...(entry.finding ? { finding: entry.finding } : {}) });
      this.emit('messages', { conversationId: entry.conversationId, reason: 'outbox' });
    });
    this.outbox.on('change', ({ conversationId }) => {
      this.emit('outbox', { conversationId });
      this.emit('messages', { conversationId, reason: 'outbox' });
    });

    this._loadCache();
    this._syncBridged();
    this._checkPersonStates({ emit: false });
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
    if (this._feedTimer) { clearTimeout(this._feedTimer); this._feedTimer = null; }
    for (const t of this._convTimers.values()) clearTimeout(t);
    this._convTimers.clear();
    if (this._open.id && this._open.visible && this._avail.state === 'available') for (const w of this._open.ways || [this._open.id]) this.api.active(w, false).catch(() => {});
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
    this._feed = { at: 0, data: null };
    this._chatLists = null;
    this._actions = { at: 0, list: null };
    this._typingContacts.clear();
    this._freshBridge.clear();
    this._bridgeSeen = false;
    this._chanSum = null;
    this._chansLoaded = false;
    this._me = null;
    this._syncBridged();
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
      this._syncBridged();
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
      prefs: this._normalizePrefs(m.prefs),
      features: normalizeFeatures(m.features),
      // 1.4.0: what the Familie plugin offers right now (to-list, to-calendar, places)
      integrations: { familie: familieOf(m), drive: !!(m.integrations && m.integrations.drive === true) },
      limits: m.limits && typeof m.limits === 'object' ? { ...m.limits } : {},
      license: m.license && typeof m.license === 'object' ? { ...m.license } : null,
      // Messenger 1.22: „Wer sieht dein Bild?“ lives in GateControl's profile (prefs.privacy.avatarProfile is its level)
      avatarInProfile: m.avatarInProfile === true,
    };
  }

  /** prefs of `GET me` / `PUT prefs`: the 1.0 booleans plus (1.4.0) privacy / notify / chats when sent. */
  _normalizePrefs(p) {
    const src = p && typeof p === 'object' ? p : null;
    const out = { readReceipts: src ? src.readReceipts !== false : true, typing: src ? src.typing !== false : true, preview: src ? src.preview !== false : true };
    for (const k of ['privacy', 'notify', 'chats']) if (src && src[k] && typeof src[k] === 'object' && !Array.isArray(src[k])) out[k] = { ...src[k] };
    // Messenger 1.22: the level of the profile — a known one or none
    if (out.privacy && !AVATAR_LEVELS.includes(out.privacy.avatarProfile)) delete out.privacy.avatarProfile;
    return out;
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
   *   unread, live, outbox, updateHint: { features, key } | null }
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
      // Messenger 1.20: the entry „Kanäle“ ({ count, unread }), null without bridge_channels
      channels: this.channelSummary(),
      live: this._pushLive(),
      outbox: this.outbox.size(),
      updateHint: this._avail.state === 'available' ? this.updateHint() : null,
    };
  }

  available() {
    return this._avail.state === 'available';
  }

  /**
   * Update hint: the server has chat functions (features set to true) this
   * version does not know → { features: [keys], key } — null when there are
   * none or this very set was dismissed.
   */
  updateHint() {
    const list = unknownFeatures(this._me && this._me.features);
    if (!list.length) return null;
    const key = list.join(',');
    let dismissed = null;
    try { const v = this.store && this.store.get(HINT_KEY); dismissed = v && typeof v.dismissed === 'string' ? v.dismissed : null; } catch { /* store */ }
    return dismissed === key ? null : { features: list, key };
  }

  /** The banner was closed: hidden until the set of unknown features changes. */
  dismissUpdateHint() {
    const list = unknownFeatures(this._me && this._me.features);
    if (!list.length) return false;
    try { this.store.set(HINT_KEY, { dismissed: list.join(',') }); } catch (err) { this.log.warn(`Chat update hint not saved: ${err.message}`); }
    this._emitState();
    return true;
  }

  /** Does the server's messenger offer `feature` (`GET me` features)? */
  supports(feature) {
    return hasFeature(this._me && this._me.features, feature);
  }

  // ── Conversations ────────────────────────────────────────

  /** Messenger 1.20: are channels on a page of their own (the server names bridge_channels, ?channels=1 is sent)? */
  _channelsApart() {
    return !!this.api.channels;
  }

  /** Cached conversations, newest activity first, with live typing ids (Messenger 1.20: without the channels). */
  listConversations() {
    const apart = this._channelsApart();
    return this._view([...this._convs.values()].filter((c) => !apart || !isChannel(c)));
  }

  /** Messenger 1.20: the page „Kanäle“ — the cached channels with a post, the newest post first ([] without bridge_channels). */
  listChannels() {
    if (!this._channelsApart()) return [];
    return this._view([...this._convs.values()].filter((c) => isChannel(c) && (c.lastMessage || c.lastMessageId)));
  }

  /**
   * Messenger 1.20: the entry „Kanäle“ → { count, unread } — channels with a post and their new posts together; from the
   * channels themselves once GET channels was read, else as GET conversations named it. null without bridge_channels.
   */
  channelSummary() {
    if (!this._channelsApart()) return null;
    const list = this.listChannels();
    if (!this._chansLoaded && this._chanSum && !list.length) return { ...this._chanSum };
    return { count: list.length, unread: list.reduce((n, c) => n + (Number.isFinite(c.unread) ? c.unread : 0), 0) };
  }

  _view(list) {
    const now = this.now();
    return sortConversations(list).map((c) => ({
      ...c,
      typing: this._typingIds(c.id, now),
      ...(c.bridge || isPerson(c) ? { typingContacts: this._typingContactsOf(c.id, now) } : {}),
      outbox: this.outbox.list(c.id).length,
    }));
  }

  getCachedConversation(id) {
    const c = this._convs.get(posInt(id));
    return c ? { ...c, typing: this._typingIds(c.id, this.now()), ...(c.bridge || isPerson(c) ? { typingContacts: this._typingContactsOf(c.id, this.now()) } : {}) } : null;
  }

  // ── Messenger 1.21: persons ──────────────────────────────

  /** Does this app show persons (the server names chat_people, ?people=1 is sent)? */
  _peopleOn() {
    return !!this.api.persons;
  }

  /** The person id of an entry (null: none, or persons are off). */
  _pidOf(cid) {
    const c = this._convs.get(cid);
    return this._peopleOn() && isPerson(c) ? c.person.id : null;
  }

  /** The list entry a conversation belongs to: itself, or the entry of the person it is a way of. */
  _leadOf(id) {
    const cid = posInt(id);
    if (!cid || this._convs.has(cid) || !this._peopleOn()) return cid;
    for (const c of this._convs.values()) if (isPerson(c) && c.person.ways.some((w) => w && w.conversationId === cid)) return c.id;
    return cid;
  }

  /** Public: the entry (a person's lead id) a conversation id is shown as. */
  entryIdOf(id) {
    return this._leadOf(id);
  }

  /** Messages of a state sorted as shown: by time for a person (its ways are mixed), else by id. */
  _merge(st, list, incoming) {
    return mergeMessages(list, incoming, { byTime: !!(st && st.pid) });
  }

  /** The newest shown message of a state: the last by time for a person, else the highest id. */
  _newestOf(st) {
    if (st && st.pid) return st.list.length ? st.list[st.list.length - 1] : null;
    let top = null;
    for (const m of (st ? st.list : [])) if (!top || m.id > top.id) top = m;
    return top;
  }

  /** The entry has a newer message than the loaded state (the list or a live event says so). */
  _hasNewer(c, st) {
    if (!c || !st || !st.loaded) return false;
    if (st.pid) {
      const last = c.lastMessage && posInt(c.lastMessage.id);
      return !!last && !st.list.some((m) => m.id === last) && (!st.way || wayOf(c.lastMessage) === st.way);
    }
    return !!(c.lastMessageId && c.lastMessageId > this._newestId(st));
  }

  /**
   * The cached messages belong to what an entry is now: a chat that became a person (or a person split) loads anew —
   * its routes and order changed. → the ids that were reset.
   */
  _checkPersonStates({ emit = true } = {}) {
    const reset = [];
    for (const [cid, st] of [...this._msgs]) {
      if ((st.pid || null) === this._pidOf(cid)) continue;
      this._msgs.delete(cid);
      reset.push(cid);
    }
    if (emit) for (const cid of reset) this.emit('messages', { conversationId: cid, reason: 'person' });
    return reset;
  }

  /** A person's entry (of persons/… answers): its ways leave the list. */
  _putPerson(e) {
    if (!e || !posInt(e.id)) return;
    const removed = [];
    for (const id of personWayIds(e)) if (id !== e.id && this._convs.has(id)) { this._drop(id, { emit: false }); removed.push(id); }
    this._convs.set(e.id, e);
    if (this._open.id === e.id) this._open = { ...this._open, ways: personWayIds(e) };
    this._checkPersonStates();
    this.emit('conversations', { ids: [e.id], removed });
    this._emitUnread();
    this._persist();
    // a way had a message the open entry does not show yet (an event of a way the list did not know)
    if (this._hasNewer(e, this._msgs.get(e.id))) this._loadNewer(e.id).then(() => this._maybeRead(e.id)).catch(() => {});
  }

  /** GET persons/:id → the entry (cached); 404 (dissolved meanwhile) → the list again, null. */
  async _refreshPerson(pid) {
    try {
      const r = await this.api.person(pid);
      if (!r.conversation || !isPerson(r.conversation)) return null;
      this._putPerson(r.conversation);
      return this.getCachedConversation(r.conversation.id);
    } catch (err) {
      if (err.status === 404) { this.refreshConversations({ full: true }).catch(() => {}); return null; }
      throw err;
    }
  }

  /** Sum of unread messages of the chats that are neither muted nor archived (1.4.0); 1.20: never of a channel. */
  unreadTotal() {
    let n = 0;
    const apart = this._channelsApart();
    for (const c of this._convs.values()) if (!c.muted && !c.archived && Number.isFinite(c.unread) && !(apart && isChannel(c))) n += c.unread;
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
    // Messenger 1.15: a chat started by number stays until the list names it (or it is removed)
    const keep = [];
    for (const c of list) this._freshBridge.delete(c.id);
    // Messenger 1.20: with ?channels=1 the list has no channels — GET channels keeps them (the summary says when to read it)
    const apart = this._channelsApart();
    const sum = apart ? normalizeChannelSummary(r.channels) : null;
    if (!since) {
      const ids = new Set(list.map((c) => c.id));
      for (const id of [...this._convs.keys()]) {
        if (ids.has(id)) continue;
        const old = this._convs.get(id);
        if (apart && isChannel(old) && !removed.includes(id) && (!sum || sum.count > 0)) keep.push(old);
        else if (this._freshBridge.has(id) && !removed.includes(id)) keep.push(old);
        else removed.push(id);
      }
      this._convs.clear();
    }
    for (const c of keep) this._convs.set(c.id, c);
    for (const c of list) this._convs.set(c.id, c);
    // Messenger 1.21: the other ways of a person are no entries of their own (`folded`, and the ways of every entry)
    if (this._peopleOn()) {
      const entries = new Set(list.map((c) => c.id));
      for (const id of (Array.isArray(r.folded) ? r.folded : []).map(posInt).filter(Boolean)) if (!entries.has(id)) removed.push(id);
      for (const c of [...this._convs.values()]) if (isPerson(c)) for (const id of personWayIds(c)) if (id !== c.id && !entries.has(id)) removed.push(id);
    }
    for (const id of new Set(removed)) this._drop(id, { emit: false });
    this._checkPersonStates();
    if (typeof r.serverTime === 'string') this._lastSync = r.serverTime;
    if (sum) {
      this._chanSum = sum;
      const have = this.channelSummary();
      if (sum.count === 0) {
        // no channel (any more): the cached ones go
        const gone = [...this._convs.values()].filter((c) => isChannel(c) && !this._freshBridge.has(c.id)).map((c) => c.id);
        for (const id of gone) { this._drop(id, { emit: false }); if (!removed.includes(id)) removed.push(id); }
        this._chansLoaded = true;
      } else if (!this._chansLoaded || !have || have.count !== sum.count || have.unread !== sum.unread) {
        this.refreshChannels().catch((err) => this.log.debug(`Channels not loaded: ${err.message}`));
      }
    }
    this.emit('conversations', { ids: list.map((c) => c.id), removed });
    this._emitUnread();
    this._persist();
    // The open conversation (and other loaded ones) may have new messages.
    for (const c of list) {
      if (this._hasNewer(c, this._msgs.get(c.id))) this._loadNewer(c.id).then(() => this._maybeRead(c.id)).catch(() => {});
    }
  }

  /**
   * Messenger 1.20: GET channels — the page „Kanäle“ (only with bridge_channels; coalesced). Channels it does not list any
   * more are dropped. → listChannels()
   */
  refreshChannels() {
    if (!this._channelsApart()) return Promise.resolve([]);
    if (this._chanRefresh) { this._chanAgain = true; return this._chanRefresh; }
    const run = (async () => {
      do {
        this._chanAgain = false;
        const started = this.now();
        const r = await this.api.channelList();
        const list = (Array.isArray(r.channels) ? r.channels : []).filter((c) => c && posInt(c.id));
        const ids = new Set(list.map((c) => c.id));
        const removed = (Array.isArray(r.removed) ? r.removed : []).map(posInt).filter(Boolean);
        for (const c of this._convs.values()) if (isChannel(c) && !ids.has(c.id) && !this._freshBridge.has(c.id)) removed.push(c.id);
        for (const c of list) {
          // removed while the answer was on its way (conversation.remove)
          if ((this._removedAt.get(c.id) || 0) >= started) continue;
          this._convs.set(c.id, c);
        }
        for (const id of new Set(removed)) if (!ids.has(id)) this._drop(id, { emit: false });
        this._chansLoaded = true;
        this._chanSum = { count: list.length, unread: Number.isSafeInteger(r.unread) ? r.unread : list.reduce((n, c) => n + (c.unread || 0), 0) };
        this.emit('conversations', { ids: list.map((c) => c.id), removed: [...new Set(removed)].filter((id) => !ids.has(id)), channels: true });
        this._emitUnread();
        this._persist();
        // the open channel may have new posts (without the push stream nothing else says so)
        for (const c of list) {
          const st = this._msgs.get(c.id);
          if (st && st.loaded && c.lastMessageId && c.lastMessageId > this._newestId(st)) this._loadNewer(c.id).then(() => this._maybeRead(c.id)).catch(() => {});
        }
      } while (this._chanAgain);
      return this.listChannels();
    })().finally(() => { this._chanRefresh = null; });
    this._chanRefresh = run;
    return run;
  }

  /** GET conversations/:id → cached + returned (404 → dropped, null). */
  async getConversation(id, { refresh = true } = {}) {
    const asked = posInt(id);
    if (!asked) throw new MessengerError('invalid id', { code: 'invalid' });
    // Messenger 1.21: a way of a person stands for its entry
    const cid = this._leadOf(asked);
    if (!refresh && this._convs.has(cid)) return this.getCachedConversation(cid);
    const pid = this._pidOf(cid);
    if (pid) return this._refreshPerson(pid);
    const started = this.now();
    try {
      const r = await this.api.conversation(cid);
      // Removed while the answer was on its way (conversation.remove).
      if ((this._removedAt.get(cid) || 0) >= started) return null;
      // Messenger 1.21: a way of a person (`person`) — the app shows the person's entry (GET persons/:id)
      if (r.conversation && this._peopleOn() && isPerson(r.conversation)) return this._refreshPerson(r.conversation.person.id);
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
    // Messenger 1.21: the plain view of a conversation never replaces a person's entry (the answer of a change on its
    // lead or a way) — the entry is read again instead
    if (this._peopleOn()) {
      const had = this._convs.get(this._leadOf(c.id));
      if (isPerson(c) || isPerson(had)) {
        if (isPerson(c)) this._refreshPerson(c.person.id).catch(() => {});
        else this._refreshConvSoon(had.id);
        return;
      }
    }
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
    this._typingContacts.delete(id);
    this._freshBridge.delete(id);
    if (this._open.id === id) this._open = { id: null, visible: false, ways: [] };
    if (emit && had) {
      this.emit('conversations', { ids: [], removed: [id] });
      this._emitUnread();
      this._persist();
    }
  }

  // ── Messages ─────────────────────────────────────────────

  /**
   * Messages of a conversation (cached + newest from the server), with the
   * pending outbox entries. `before` loads an older page; `around` (a message
   * id, Messenger ≥ 1.1.0) the page around it — kept as a window apart from
   * the newest messages while there is a gap (`detached: true`, newer pages
   * with `after`); without arguments the window is closed again.
   * → { conversationId, messages, pending, hasMore, hasMoreAfter, detached, offline }
   * `around` on a plugin without it → MessengerError `unsupported`.
   */
  async getMessages(id, { before = null, after = null, around = null } = {}) {
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid id', { code: 'invalid' });
    const st = this._state(cid);
    let offline = false;
    try {
      if (posInt(around)) {
        await this._loadAround(cid, posInt(around));
      } else if (posInt(before)) {
        const r = await this._fetch(cid, { before: posInt(before), limit: PAGE });
        if (st.window) {
          st.window.list = this._merge(st, st.window.list, r.messages);
          st.window.hasMoreBefore = r.hasMore === true;
        } else {
          st.list = this._merge(st, st.list, r.messages);
          st.hasMore = r.hasMore === true;
        }
        this._receipts(cid, r);
      } else if (posInt(after) && st.window) {
        const r = await this._fetch(cid, { after: posInt(after), limit: PAGE });
        st.window.list = this._merge(st, st.window.list, r.messages);
        st.window.hasMoreAfter = r.hasMore === true;
        this._receipts(cid, r);
        this._joinWindow(cid);
      } else if (!st.loaded) {
        st.window = null;
        await this._loadNewest(cid);
      } else {
        st.window = null;
        await this._loadNewer(cid);
      }
    } catch (err) {
      if (err.status === 404) { this._drop(cid); throw err; }
      if (err.code === 'unsupported') throw err;
      if (!st.loaded && !st.list.length && !st.window) throw err;
      offline = true;
    }
    return this.messagesView(cid, { offline });
  }

  /** The message state of a conversation (made when there is none; 1.21: a person's knows its id and source filter). */
  _state(cid, way = null) {
    let st = this._msgs.get(cid);
    if (!st) {
      st = { list: [], hasMore: true, loaded: false, syncedAt: null, window: null, pid: this._pidOf(cid), way: way || null };
      this._msgs.set(cid, st);
    }
    return st;
  }

  /** GET …/messages of a conversation, or (1.21) of a person — with its source filter (?way=). */
  _fetch(cid, opts) {
    const st = this._msgs.get(cid);
    const pid = this._pidOf(cid);
    if (pid) return this.api.personMessages(pid, { ...opts, ...(st && st.way ? { way: st.way } : {}) });
    return this.api.messages(cid, opts);
  }

  /**
   * Messenger 1.21: the source chips of a person's shared history (Alle · GateControl · WhatsApp) — `way` null for all,
   * else one way of `person.ways`. A filter loads its own newest page (not kept in the store, nothing read there).
   * → messagesView
   */
  async setWay(id, way = null) {
    const cid = posInt(id);
    const pid = cid ? this._pidOf(cid) : null;
    if (!pid) throw new MessengerError('invalid', { code: 'invalid' });
    const c = this._convs.get(cid);
    const w = way == null || way === '' ? null : String(way);
    if (w && !c.person.ways.some((x) => x && x.way === w)) throw new MessengerError('invalid', { code: 'invalid' });
    const st = this._msgs.get(cid);
    if (st && (st.way || null) === w && st.loaded) return this.messagesView(cid);
    this._msgs.delete(cid);
    this._state(cid, w);
    return this.getMessages(cid);
  }

  /** Cached view without asking the server (the jump window while one is open). */
  messagesView(id, { offline = false } = {}) {
    const cid = posInt(id);
    const st = this._msgs.get(cid) || { list: [], hasMore: true, window: null };
    // Messenger 1.21: the source filter of a person's shared history (null: all ways)
    const way = st.way || null;
    if (st.window) {
      return {
        conversationId: cid, messages: st.window.list.slice(), pending: [], hasMore: st.window.hasMoreBefore, hasMoreAfter: st.window.hasMoreAfter, detached: true, offline, way,
      };
    }
    const ids = new Set(st.list.map((m) => m.clientId).filter(Boolean));
    const pending = way ? [] : this.outbox.list(cid).filter((e) => !ids.has(e.clientId)).map((e) => this._pendingView(e));
    return { conversationId: cid, messages: st.list.slice(), pending, hasMore: st.hasMore !== false, hasMoreAfter: false, detached: false, offline, way };
  }

  /** GET messages?around= → the jump window (joined with the cache when they meet). */
  async _loadAround(cid, messageId) {
    const st = this._msgs.get(cid);
    const r = await this._fetch(cid, { around: messageId, limit: PAGE });
    if (typeof r.hasMoreBefore !== 'boolean' && typeof r.hasMoreAfter !== 'boolean') {
      // Messenger 1.0.x ignores `around` and answers the newest page.
      throw new MessengerError('around not supported', { code: 'unsupported' });
    }
    this._receipts(cid, r);
    st.window = { list: this._merge(st, [], r.messages), hasMoreBefore: r.hasMoreBefore === true, hasMoreAfter: r.hasMoreAfter === true };
    if (!this._joinWindow(cid)) this.emit('messages', { conversationId: cid, reason: 'around' });
  }

  /**
   * The window reaches the cached messages (overlap, or nothing newer after
   * it): merge it into them and close it. → joined?
   */
  _joinWindow(cid) {
    const st = this._msgs.get(cid);
    const w = st && st.window;
    if (!w || !st.loaded) return false;
    // ids for a chat, the time for a person (1.21: its ways are mixed)
    const cmp = st.pid ? byTimeOrder : (a, b) => a.id - b.id;
    const oldest = st.list.length ? st.list[0] : null;
    const newest = w.list.length ? w.list[w.list.length - 1] : null;
    if (w.hasMoreAfter && (oldest === null || (newest ? cmp(newest, oldest) < 0 : true))) return false;
    const first = w.list.length ? w.list[0] : null;
    if (first !== null && (oldest === null || cmp(first, oldest) < 0)) st.hasMore = w.hasMoreBefore;
    st.list = this._merge(st, st.list, w.list);
    st.window = null;
    this.emit('messages', { conversationId: cid, reason: 'around' });
    this._persist();
    return true;
  }

  /** The cached list and the jump window of a conversation state (those that exist). */
  _lists(st) {
    return st.window ? [st.list, st.window.list] : [st.list];
  }

  /** Apply fn(list) → list to the cached list and the window. */
  _mapLists(st, fn) {
    st.list = fn(st.list);
    if (st.window) st.window.list = fn(st.window.list);
  }

  async _loadNewest(cid, reason = 'load') {
    const st = this._msgs.get(cid);
    const r = await this._fetch(cid, { limit: PAGE });
    st.list = this._merge(st, [], Array.isArray(r.messages) ? r.messages : []);
    st.hasMore = r.hasMore === true;
    st.loaded = true;
    st.syncedAt = this._syncTime(r);
    this._receipts(cid, r);
    this.emit('messages', { conversationId: cid, reason });
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
        const r = await this._fetch(cid, { after, limit: 100 });
        const msgs = Array.isArray(r.messages) ? r.messages : [];
        st.list = this._merge(st, st.list, msgs);
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

  /**
   * The next `changedSince` from a messages answer: its `serverTime`
   * (Messenger ≥ 1.1.0); older plugins: the conversation list's, else now − 5 s.
   */
  _syncTime(r, fallback = null) {
    if (r && typeof r.serverTime === 'string' && !Number.isNaN(Date.parse(r.serverTime))) return r.serverTime;
    return fallback || this._lastSync || new Date(this.now() - 5000).toISOString();
  }

  /** Edits, deletions and reactions since the last sync (after a reconnect). */
  async _loadChanged(cid) {
    const st = this._msgs.get(cid);
    if (!st || !st.loaded || !st.syncedAt) return;
    const since = st.syncedAt;
    const fallback = this._lastSync || new Date(this.now() - 5000).toISOString();
    const r = await this._fetch(cid, { changedSince: since, limit: 100 });
    if (r.hasMore === true) {
      // More changes than one page: the newest page is cheaper than paging.
      await this._loadNewest(cid);
      return;
    }
    st.syncedAt = this._syncTime(r, fallback);
    this._mergeKnown(st, r.messages);
    if (!(Array.isArray(r.messages) && r.messages.length)) return;
    this.emit('messages', { conversationId: cid, reason: 'changed' });
    this._persist();
  }

  /** Merge changed messages into the lists that hold them (no new ones). */
  _mergeKnown(st, incoming) {
    const msgs = Array.isArray(incoming) ? incoming : [];
    if (!msgs.length) return;
    this._mapLists(st, (list) => {
      const known = new Set(list.map((m) => m.id));
      return this._merge(st, list, msgs.filter((m) => known.has(m.id)));
    });
  }

  _receipts(cid, r) {
    const c = this._convs.get(cid);
    if (!c || !r) return;
    let changed = false;
    // Messenger 1.21: a person — the ticks of the messages inside GateControl come from that way's marks
    if (Array.isArray(r.ways)) {
      const gw = r.ways.find((w) => w && w.way === GC_WAY);
      if (gw) for (const k of ['readUpTo', 'deliveredUpTo']) if (k in gw && gw[k] !== c[k]) { c[k] = gw[k]; changed = true; }
      if (changed) this.emit('conversations', { ids: [cid], removed: [] });
      return;
    }
    for (const k of ['readUpTo', 'deliveredUpTo']) {
      if (k in r && r[k] !== c[k]) { c[k] = r[k]; changed = true; }
    }
    if (Array.isArray(r.receipts)) { c.receipts = r.receipts; changed = true; }
    if (changed) this.emit('conversations', { ids: [cid], removed: [] });
  }

  _newestId(st) {
    // Messenger 1.21: a person's history is ordered by time — the newest message shown is the cursor
    if (st.pid) return st.list.length ? st.list[st.list.length - 1].id : 0;
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
      video: e.body.video || null,
      thumb: !!files.thumb,
      conversationId: e.conversationId,
      pending: true,
      failed: e.state === 'failed',
      sending: e.state === 'sending',
      error: e.error || null,
      ...(e.finding ? { finding: e.finding } : {}),
      // Messenger 1.15: why a bridge refused it (bridge_media_type: image | voice | video); still being checked (423)
      ...(e.reason ? { reason: e.reason } : {}),
      ...(e.scanWaits && e.state !== 'failed' ? { scanWait: true } : {}),
      kind: e.body.kind || 'text',
      text: e.body.text || null,
      replyTo,
      meta: e.body.meta || null,
      location: e.body.location || null,
      poll: e.body.poll ? this._pendingPoll(e.body.poll) : null,
      event: e.body.event ? this._pendingEvent(e.body.event) : null,
      action: e.body.action ? { ...e.body.action, state: 'open', can: { run: false, approve: false, deny: false } } : null,
      media: main ? { id: null, mime: main.mime, bytes: main.bytes, local: true } : null,
      senderId: this._me && this._me.user ? this._me.user.id : null,
      mine: true,
      createdAt: e.createdAt,
      reactions: [],
      deleted: false,
    };
  }

  /** A poll as the server would show it before anyone voted (pending outbox entry). */
  _pendingPoll(p) {
    return {
      question: p.question, options: (p.options || []).map((text, i) => ({ id: `p${i}`, text, count: 0, voters: [], addedBy: null })),
      multi: !!p.multi, anonymous: !!p.anonymous, allowAdd: !!p.allowAdd, closesAt: p.closesAt || null, closed: false, closedAt: null,
      voterCount: 0, memberCount: 0, creatorId: this._me && this._me.user ? this._me.user.id : null, myVotes: [],
    };
  }

  /** An event as the server would show it before any answer (pending outbox entry). */
  _pendingEvent(e) {
    return {
      ...e, checklist: (e.checklist || []).map((text, i) => ({ id: `p${i}`, text, doneBy: null, doneAt: null })),
      rsvpEnabled: e.rsvp !== false, guests: !!e.guests, rsvp: { yes: [], maybe: [], no: [], mine: null, myGuests: 0 },
      cancelled: false, creatorId: this._me && this._me.user ? this._me.user.id : null,
    };
  }

  /** Set the reactions of a message wherever it is cached → its conversation id, or null. */
  _setReactions(messageId, reactions) {
    for (const [cid, st] of this._msgs) {
      let hit = false;
      for (const list of this._lists(st)) {
        const m = list.find((x) => x.id === messageId);
        if (m) { m.reactions = reactions; hit = true; }
      }
      if (hit) return cid;
    }
    return null;
  }

  _replaceMessage(msg) {
    if (!msg || !posInt(msg.id)) return;
    // Messenger 1.21: a message of a way is shown in its person's entry
    const cid = this._leadOf(posInt(msg.conversationId));
    const st = this._msgs.get(cid);
    if (st && st.loaded) st.list = this._merge(st, st.list, [msg]);
    if (st && st.window && st.window.list.some((m) => m.id === msg.id)) st.window.list = this._merge(st, st.window.list, [msg]);
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
    const entry = this._convs.get(cid);
    const limits = (this._me && this._me.limits) || {};
    const body = buildSendBody(req, { textMax: limits.textMax || 4000 });
    // Messenger 1.21: a person — the server picks the way (an answer goes back its message's way); what the composer
    // may send is that way's (its bridge, its can)
    const pid = this._pidOf(cid);
    const c = pid ? this._sendWayOf(entry, body.replyTo) : entry;
    if (c && c.can && c.can.send === false) throw new MessengerError('readonly', { code: c.readonly ? 'readonly' : 'forbidden' });
    // Messenger 1.14: only a text (maybe as an answer) crosses a bridge — refused here like the server would (409);
    // 1.15: and a picture, voice message or file of a kind and type the chat names (`bridge.supports`, `mediaTypes`)
    if (c && c.bridge) {
      const media = ['image', 'voice', 'file'].includes(body.kind) && req.file;
      if (body.replyStory || body.location || (!media && (body.kind !== 'text' || req.file || body.meta))) throw new MessengerError('text only', { code: 'bridge_text_only' });
      if (media) {
        const no = bridgeMediaRefusal(c.bridge, body.kind, req.file && req.file.mime);
        if (no === 'text_only') throw new MessengerError('text only', { code: 'bridge_text_only' });
        if (no) throw new MessengerError('type not taken by the bridge', { code: 'bridge_media_type', body: { reason: no } });
      }
    }
    // 1.4.0 kinds only to a server that offers them.
    if (KIND_FEATURE[body.kind] && !this.supports(KIND_FEATURE[body.kind])) throw new MessengerError('not supported by the server', { code: 'unsupported' });
    if (body.replyStory && !this.supports(FEATURES_14.stories)) delete body.replyStory;
    const files = {};
    if (body.kind === 'image' || body.kind === 'voice' || body.kind === 'file') {
      files.main = this._checkFile(req.file, limits);
      if (body.kind === 'file') {
        body.meta = { ...(body.meta || {}), fileName: (body.meta && body.meta.fileName) || String(files.main.name || 'Datei').slice(0, 200) };
        // Messenger 1.3.0: only to a server that knows the fields.
        if (body.video && !(isVideoMime(files.main.mime) && this.supports(FEATURE_VIDEO_META))) delete body.video;
        if (req.thumb && this.supports(FEATURE_FILE_THUMBS)) {
          const t = this._thumbFile(req.thumb, limits);
          if (t) files.thumb = t;
        }
      }
      if (body.kind === 'image' && req.thumb) {
        const t = this._thumbFile(req.thumb, limits);
        if (t) files.thumb = t;
      }
    } else if (req.file) {
      throw new MessengerError('file not allowed', { code: 'invalid' });
    }
    this._typingSent.delete(cid);
    const queued = await this.outbox.add({ conversationId: cid, clientId: req.clientId, body, files, ...(pid ? { personId: pid } : {}) });
    return this._pendingView(queued);
  }

  /**
   * Messenger 1.21: the way a message to a person goes — the way of the message it answers (while that way can send),
   * else `person.reply` → { bridge, can, readonly } as the composer checks it.
   */
  _sendWayOf(c, replyTo = null) {
    let w = null;
    const rid = posInt(replyTo);
    if (rid) {
      const st = this._msgs.get(c.id);
      const q = st && this._lists(st).flat().find((m) => m && m.id === rid);
      const qw = q ? c.person.ways.find((x) => x && x.conversationId === posInt(q.conversationId)) : null;
      if (qw && qw.can && qw.can.send) w = qw;
    }
    w = w || personReplyWay(c);
    if (!w) return { bridge: null, can: { send: true }, readonly: false };
    return { bridge: w.bridge || null, can: w.can || { send: true }, readonly: false };
  }

  /** Messenger 1.21: the way an answer to a person takes now (`person.reply` → its way), null for any other chat. */
  replyWay(id) {
    const c = this._convs.get(posInt(id));
    if (!this._peopleOn() || !isPerson(c)) return null;
    const w = personReplyWay(c);
    return w ? { way: w.way, label: w.label, conversationId: w.conversationId, bridge: w.bridge || null, can: w.can || null } : null;
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

  /** A preview picture (image/*, ≤ thumbMaxBytes) or null. */
  _thumbFile(f, limits) {
    try {
      const t = this._checkFile(f, limits);
      return byteLength(t.data) <= (limits.thumbMaxBytes || 65536) && /^image\//.test(t.mime) ? t : null;
    } catch {
      return null;
    }
  }

  retrySend(clientId) { return this.outbox.retry(clientId); }

  discardSend(clientId) { return this.outbox.discard(clientId); }

  _onSent({ entry, message }) {
    const cid = entry.conversationId;
    if (message && posInt(message.id)) {
      const st = this._msgs.get(cid);
      if (st && st.loaded && (!st.way || wayOf(message) === st.way)) st.list = this._merge(st, st.list, [message]);
      const c = this._convs.get(cid);
      if (c && entry.personId) {
        // Messenger 1.21: the person's newest message; the way of the next answer may change — the entry again
        c.lastMessage = message;
        c.updatedAt = message.createdAt || c.updatedAt;
        this.emit('conversations', { ids: [cid], removed: [] });
        this._refreshConvSoon(cid);
      } else if (c) {
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
    const cid = Array.isArray(r.reactions) ? this._setReactions(id, r.reactions) : null;
    if (cid) {
      this.emit('messages', { conversationId: cid, reason: 'reaction' });
      this._persist();
    }
    return r.reactions || [];
  }

  _removeLocal(ids, { conversationId = null } = {}) {
    const set = new Set(ids);
    for (const [cid, st] of this._msgs) {
      if (conversationId && cid !== conversationId) continue;
      const before = this._lists(st).reduce((n, l) => n + l.length, 0);
      this._mapLists(st, (list) => list.filter((m) => !set.has(m.id)));
      if (this._lists(st).reduce((n, l) => n + l.length, 0) !== before) this.emit('messages', { conversationId: cid, reason: 'delete' });
    }
    this._persist();
  }

  _tombstone(cid, ids) {
    const st = this._msgs.get(cid);
    if (!st) return;
    const set = new Set(ids);
    this._mapLists(st, (list) => list.map((m) => (set.has(m.id)
      ? { ...m, deleted: true, text: null, media: null, meta: null, location: null, replyTo: null, reactions: [], video: null }
      : m)));
    this.emit('messages', { conversationId: cid, reason: 'delete' });
    this._persist();
  }

  /**
   * Read up to `upTo` (default: the newest known message). Never moves back.
   * → { lastReadId, unread } | null
   */
  async markRead(id, upTo = null) {
    const asked = posInt(id);
    // Messenger 1.21: a person — every way up to the time of the newest message shown; a way (a push's „Gelesen“) alone
    const cid = this._leadOf(asked);
    const pc = this._pidOf(cid) ? this._convs.get(cid) : null;
    if (pc && asked !== cid) {
      if (!posInt(upTo)) return this._readPerson(pc, null);
      this.emit('read-local', { conversationId: asked, upTo: posInt(upTo) });
      return this.api.read(asked, upTo).then((r) => { this._refreshConvSoon(cid); return { lastReadId: r.lastReadId, unread: r.unread }; })
        .catch((err) => { this.log.debug(`Chat read mark not sent: ${err.message}`); return null; });
    }
    if (pc) return this._readPerson(pc, upTo);
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

  /**
   * Messenger 1.21: POST persons/:id/read { upTo } — up to the newest message shown of „Alle“ (not while a source
   * filter is on, unless `upTo` is given). → { lastReadId: null, unread } | null
   */
  _readPerson(c, upTo) {
    const st = this._msgs.get(c.id);
    if (st && st.way && !posInt(upTo)) return Promise.resolve(null);
    const newest = st && !st.way && !st.window ? this._newestOf(st) : null;
    // not loaded yet: the entry's newest message (of any way)
    const to = posInt(upTo) || (newest ? newest.id : null) || posInt(c.lastMessage && c.lastMessage.id);
    for (const w of personWayIds(c)) this.emit('read-local', { conversationId: w, upTo: to });
    if (!c.unread) return Promise.resolve({ lastReadId: null, unread: 0 });
    const key = `p${c.person.id}:${to || 'all'}`;
    if (this._reading.has(key)) return this._reading.get(key);
    const run = this.api.personRead(c.person.id, to).then((r) => {
      const cc = this._convs.get(c.id);
      if (cc && isPerson(cc)) {
        if (Number.isFinite(r.unread)) cc.unread = r.unread;
        for (const w of Array.isArray(r.ways) ? r.ways : []) {
          const way = w && cc.person.ways.find((x) => x.conversationId === w.conversationId);
          if (way && Number.isFinite(w.unread)) way.unread = w.unread;
        }
        this.emit('conversations', { ids: [c.id], removed: [] });
        this._emitUnread();
        this._persist();
      }
      return { lastReadId: null, unread: Number.isFinite(r.unread) ? r.unread : 0 };
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
    // Messenger 1.21: „schreibt …“ of a person goes to the way the answer takes
    const rw = this.replyWay(cid);
    const target = rw ? rw.conversationId : cid;
    const now = this.now();
    const last = this._typingSent.get(cid) || 0;
    if (stop) {
      if (!last || now - last > this.timing.typingValidMs) return false;
      this._typingSent.delete(cid);
      await this.api.typing(target, true).catch(() => {});
      return true;
    }
    const every = ((this._me && this._me.limits && this._me.limits.typingEveryS) || this.timing.typingEveryMs / 1000) * 1000;
    if (now - last < every) return false;
    this._typingSent.set(cid, now);
    await this.api.typing(target, false).catch(() => {});
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
    // Messenger 1.21: a person is active on every way (else its pushes come although it is open)
    this._open = { id: cid, visible: vis, ways: cid ? personWayIds(this._convs.get(cid) || { id: cid }) : [] };
    if (prev.id && prev.visible && (prev.id !== cid || !vis) && this.available()) for (const w of prev.ways || [prev.id]) this.api.active(w, false).catch(() => {});
    this._clear('active');
    if (cid && vis && this.available()) {
      // Only while the window is really shown (tray / minimized → no ping, the push comes).
      const ping = () => {
        if (this._safe(() => this.isWindowVisible(), true) === false) return;
        for (const w of this._open.id === cid && this._open.ways.length ? this._open.ways : [cid]) this.api.active(w).catch(() => {});
      };
      ping();
      this._timers.active = setInterval(ping, this.timing.activeEveryMs);
      if (this._timers.active.unref) this._timers.active.unref();
      this._maybeRead(cid);
    }
    return { ...this._open };
  }

  /** Is this conversation open and visible right now? */
  isOpenAndVisible(id) {
    // Messenger 1.21: a way of the open person counts as open
    return !!this._open.id && this._open.id === this._leadOf(posInt(id)) && this._open.visible && this._safe(() => this.isWindowVisible(), true) !== false;
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
    // Messenger 1.21: mute and notifications of a person hold for every way (PATCH persons/:id)
    const pid = this._pidOf(cid);
    if (pid && Object.keys(body).every((k) => k === 'notify' || k === 'mutedUntil')) {
      const rp = await this.api.patchPerson(pid, body);
      if (rp.conversation) this._putPerson(rp.conversation);
      return { conversation: this.getCachedConversation(cid) || this.getCachedConversation(rp.conversation && rp.conversation.id), left: false };
    }
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
    const body = prefsBody(patch);
    if (!Object.keys(body).length) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.setPrefs(body);
    if (this._me && r.prefs) this._me.prefs = this._normalizePrefs({ ...this._me.prefs, ...r.prefs });
    this._emitState();
    // Receipts / typing visibility change what the server sends for every chat.
    this.refreshConversations({ full: true }).catch(() => {});
    return this._me ? { ...this._me.prefs } : r.prefs;
  }

  async search(id, q) {
    const cid = posInt(id);
    const text = typeof q === 'string' ? q.trim() : '';
    if (!cid || text.length < 2 || text.length > 100) throw new MessengerError('invalid', { code: 'invalid' });
    // Messenger 1.21: a person's ways together (with its source filter)
    const pid = this._pidOf(cid);
    const st = this._msgs.get(cid);
    const r = pid ? await this.api.personSearch(pid, text, st && st.way) : await this.api.search(cid, text);
    return { results: Array.isArray(r.results) ? r.results : [], truncated: !!r.truncated, scanned: r.scanned || 0 };
  }

  async mediaList(id, opts = {}) {
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.mediaList(cid, opts);
    // counts.video only from a plugin that has it (1.3.0).
    const counts = { image: 0, voice: 0, file: 0, ...(r.counts && typeof r.counts === 'object' ? r.counts : {}) };
    return { items: Array.isArray(r.items) ? r.items : [], counts, hasMore: !!r.hasMore };
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

  /**
   * The picture of a notice card (Messenger 1.6 `card.imageUrl`, a
   * /notify-media/… path of the own server) → { mime, data } — kept in the
   * memory cache only (these pictures expire on the server).
   */
  async noticeImage(urlPath) {
    if (!isNotifyMediaPath(urlPath)) throw new MessengerError('invalid', { code: 'invalid' });
    const key = `notice:${urlPath}`;
    const hit = this._media.get(key);
    if (hit) return hit;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.noticeImage(urlPath).then((r) => { this._media.set(key, r); return r; })
      .finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── Messenger 1.4.0: status and stories ─────────────────

  _need(feature) {
    if (!this.supports(feature)) throw new MessengerError('not supported by the server', { code: 'unsupported' });
  }

  // ── Messenger 1.13 / 1.14: linked services and chats over a bridge ──

  /**
   * Chats over a bridge exist only for a client that says it knows them (?bridged=1 on its calls): said once the
   * server names `linked_services` or `bridge_chats`, or an event / a push named such a chat — never to an older
   * plugin. → true when the mark was just switched on (the chat list has to be read in full then).
   */
  _syncBridged() {
    const on = this._bridgeSeen || this.supports(FEATURE_LINKED) || this.supports(FEATURE_BRIDGE_CHATS);
    const turnedOn = on && !this.api.bridged;
    this.api.bridged = on;
    // Messenger 1.20: channels on their own page (?channels=1) — the list is read in full again when this changes
    const chans = on && this.supports(FEATURE_BRIDGE_CHANNELS);
    const chansChanged = chans !== !!this.api.channels;
    this.api.channels = chans;
    if (chansChanged && !chans) { this._chansLoaded = false; this._chanSum = null; }
    // Messenger 1.21: persons (?people=1) — the list is read in full again when this changes, the cached messages of
    // entries that are (no longer) persons are loaded anew
    const people = on && this.supports(FEATURE_CHAT_PEOPLE);
    const peopleChanged = people !== !!this.api.persons;
    this.api.persons = people;
    if (peopleChanged) {
      if (!people) this._sugg = { at: 0, list: null };
      this._checkPersonStates();
    }
    return turnedOn || chansChanged || peopleChanged;
  }

  /**
   * An event or a push of a chat over a bridge arrived. `features.bridge_chats` appears with a person's first such
   * chat, so `GET me` is read again when it is not known yet (the page hides its "nur auf deinem Server" then).
   */
  noteBridge() {
    this._bridgeSeen = true;
    const turnedOn = this._syncBridged();
    if (turnedOn && this.available()) this.refreshConversations({ full: true }).catch(() => {});
    if (!this.supports(FEATURE_BRIDGE_CHATS) && this.available() && !this._meRefresh) {
      this._meRefresh = this.api.me().then((me) => {
        this._me = this._normalizeMe(me);
        if (this._syncBridged() && this.available()) this.refreshConversations({ full: true }).catch(() => {});
        this._emitState();
        this._persist();
      }).catch(() => {}).finally(() => { this._meRefresh = null; });
    }
  }

  /** GET bridges → { available, location, networks } (the own links; README "Linked services"). */
  async bridges() {
    this._need(FEATURE_LINKED);
    const r = await this.api.bridges();
    return normalizeBridges(r.bridges);
  }

  /** The notes before the first link of a service were read and confirmed. */
  async bridgeConsent(network) {
    this._need(FEATURE_LINKED);
    if (!isBridgeNet(network)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.bridgeConsent(network);
    return { consent: !!r.consent };
  }

  /** Start linking ('phone': a pairing code, 'qr': a QR code) → normalizeBridgeLogin. */
  async bridgeLogin(network, flow) {
    this._need(FEATURE_LINKED);
    if (!isBridgeNet(network) || !BRIDGE_FLOWS.includes(flow)) throw new MessengerError('invalid', { code: 'invalid' });
    return this._bridgeLoginOf(network, await this.api.bridgeLogin(network, flow));
  }

  /**
   * The next step. `phone` (as typed) answers the step that asks for the number — checked here, sent once, never
   * kept or logged; without it the server waits for the phone (up to 15 s) → normalizeBridgeLogin.
   */
  async bridgeStep(network, processId, stepId, { phone = null, fieldId = null } = {}) {
    this._need(FEATURE_LINKED);
    if (!isBridgeNet(network) || !isBridgeId(processId) || !isBridgeId(stepId)) throw new MessengerError('invalid', { code: 'invalid' });
    let input = null;
    if (phone != null) {
      const number = bridgePhone(phone);
      if (!number) throw new MessengerError('invalid number', { code: 'phone_invalid' });
      input = { [isBridgeId(fieldId) ? fieldId : 'phone_number']: number };
    }
    return this._bridgeLoginOf(network, await this.api.bridgeStep(network, processId, stepId, input));
  }

  _bridgeLoginOf(network, r) {
    const login = normalizeBridgeLogin(r && r.login);
    if (!login) throw new MessengerError('bad login answer', { code: 'bad_response' });
    // linked: the chats of this service can arrive from now on, and the state of the ones there changed
    if (login.step && login.step.type === 'complete') this._afterLinkChange();
    return login;
  }

  /** Drop a login that was not finished (the page was left, another way chosen). Never throws. */
  async bridgeCancel(network, processId) {
    if (!isBridgeNet(network) || !isBridgeId(processId)) return false;
    try { await this.api.bridgeCancel(network, processId); return true; } catch { return false; }
  }

  /** Unlink the own account at a service (always allowed for one's own account). */
  async bridgeUnlink(network, loginId) {
    this._need(FEATURE_LINKED);
    if (!isBridgeNet(network) || !isBridgeId(loginId)) throw new MessengerError('invalid', { code: 'invalid' });
    await this.api.bridgeUnlink(network, loginId);
    this._afterLinkChange();
    return true;
  }

  /** The chats over a bridge carry the link's state (`bridge.state`, `can.send`): read them again. */
  _afterLinkChange() {
    if (!this.available()) return;
    this.refreshConversations({ full: true }).catch(() => {});
  }

  /**
   * Messenger 1.15 (`bridge_new_chat`): is this number at the service? `number` as typed, `cc` the country code of
   * the dialog (+49) — normalized here (bridgeNumber), sent once, never kept or logged
   * → { found, name, avatarMediaId, existing: { conversationId } | null }.
   */
  async bridgeResolve(network, number, cc) {
    const n = this._newChatNumber(network, number, cc);
    return normalizeResolve(await this.api.bridgeResolve(network, n));
  }

  /**
   * Messenger 1.15: the direct chat with this number, made or found → { conversation, created }. It is not in
   * GET conversations until something was said in it, so it is kept in the list from here on (opened directly).
   */
  async bridgeStartChat(network, number, cc) {
    const n = this._newChatNumber(network, number, cc);
    return this._startedBridgeChat(await this.api.bridgeChat(network, n));
  }

  /** A chat over a bridge just made or found (POST bridges/:network/chats) → { conversation, created }, kept in the list. */
  _startedBridgeChat(r) {
    const conv = r && r.conversation && typeof r.conversation === 'object' && posInt(r.conversation.id) ? r.conversation : null;
    if (!conv) throw new MessengerError('bad answer', { code: 'bad_response' });
    this._removedAt.delete(conv.id);
    this._freshBridge.set(conv.id, this.now());
    this._upsert(conv);
    this.noteBridge();
    return { conversation: this.getCachedConversation(conv.id), created: r.created === true };
  }

  /**
   * Messenger 1.18 (`bridge_contacts`): the people for „Neuer Chat“ — GateControl, the WhatsApp contacts and the
   * address book (GET contacts/new-chat) → normalizeNewChatContacts. `q` is the search as typed (≤ 100 characters);
   * listing and searching ask the service nothing. Neither the search nor a name or number is logged or kept.
   */
  async newChatContacts(network, q) {
    this._need(FEATURE_BRIDGE_CONTACTS);
    if (!isBridgeNet(network)) throw new MessengerError('invalid', { code: 'invalid' });
    const query = typeof q === 'string' ? q.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, CONTACTS_QUERY_MAX) : '';
    return normalizeNewChatContacts(await this.api.newChatContacts(network, query));
  }

  /**
   * Messenger 1.18: the direct chat with a contact of „Neuer Chat“ → { conversation, created }. `contact`:
   * { ref } — a WhatsApp contact, started at once (nothing checked, nothing counted); { contactId, phoneKind } — a number
   * of the address book, checked at the service now (counted in the brake; 404 not_found with reason not_on_network,
   * maybe remembered). 409 contact_expired: the reference ran out — load the list again.
   */
  async bridgeContactChat(network, contact) {
    this._need(FEATURE_BRIDGE_CONTACTS);
    if (!isBridgeNet(network)) throw new MessengerError('invalid', { code: 'invalid' });
    const body = contactChatBody(contact);
    if (!body) throw new MessengerError('invalid', { code: 'invalid' });
    return this._startedBridgeChat(await this.api.bridgeContactChat(network, body));
  }

  _newChatNumber(network, number, cc) {
    this._need(FEATURE_BRIDGE_NEW_CHAT);
    if (!isBridgeNet(network)) throw new MessengerError('invalid', { code: 'invalid' });
    const n = bridgeNumber(number, cc);
    if (!n) throw new MessengerError('invalid number', { code: 'invalid_number' });
    return n;
  }

  // ── Messenger 1.17: older history of chats over a bridge ──

  /**
   * „Älteren Verlauf laden“: what of the older messages comes over at the next link — 0 (nothing), 30 (days) or
   * -1 (everything) → normalizeBridgeHistory. Fewer days drop at once what still waits and is no longer wanted.
   */
  async setBridgeHistory(days) {
    this._need(FEATURE_BRIDGE_HISTORY);
    if (!HISTORY_DAYS.includes(days)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.bridgeHistory(days);
    return normalizeBridgeHistory(r && r.history);
  }

  /**
   * A file of the older history (placeholder state on_request), fetched now because the person asks for it →
   * the message (its placeholder then `loading`; the file follows with message.update { media: true }).
   */
  // ── Messenger 1.21: persons — suggestions, merging, „Trennen“, the name ──

  _needPeople() {
    if (!this._peopleOn()) throw new MessengerError('not supported by the server', { code: 'unsupported' });
  }

  /**
   * GET persons/suggestions — the open suggestions („„Schatzimausi 💕“ bei WhatsApp ist vielleicht Jenny Backes.“),
   * strong first; asked when „Chats“ opens and then at most every 15 minutes (`refresh`: now). → [suggestion]
   */
  async suggestions({ refresh = false } = {}) {
    if (!this._peopleOn()) return [];
    if (!refresh && this._sugg.list && this.now() - this._sugg.at < this.timing.suggestTtlMs) return this._copy(this._sugg.list);
    const key = 'suggestions';
    if (this._inflight.has(key)) return this._copy(await this._inflight.get(key));
    const run = this.api.personSuggestions().then((r) => {
      const list = (Array.isArray(r.suggestions) ? r.suggestions : []).filter((s) => s && isSuggestionId(s.id) && posInt(s.conversationId) && posInt(s.userId)
        && s.contact && typeof s.contact === 'object' && s.account && typeof s.account === 'object');
      const before = JSON.stringify(this._sugg.list);
      this._sugg = { at: this.now(), list };
      if (before !== JSON.stringify(list)) this.emit('suggestions', this._copy(list));
      return list;
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return this._copy(await run);
  }

  /** A merge or a split happened: the suggestions are asked again (a pair may be answered). */
  _suggestionsSoon() {
    if (!this._peopleOn()) return;
    this._sugg.at = 0;
    this.suggestions({ refresh: true }).catch(() => {});
  }

  _dropSuggestions(fn) {
    if (!this._sugg.list) return;
    const list = this._sugg.list.filter((s) => !fn(s));
    if (list.length === this._sugg.list.length) return;
    this._sugg = { ...this._sugg, list };
    this.emit('suggestions', this._copy(list));
  }

  /** „Nicht jetzt“ (later: 7 days) / „Nicht mehr vorschlagen“ (never) → { id, state, until } */
  async answerSuggestion(id, action) {
    this._needPeople();
    if (!isSuggestionId(id) || !['later', 'never'].includes(action)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.answerSuggestion(id, action);
    this._dropSuggestions((s) => s.id === id);
    return r.suggestion || { id, state: action, until: null };
  }

  /**
   * „Zusammenführen“: POST persons { conversationIds, userId?, name: 'account' | conversationId } → the person's entry
   * (cached, its ways leave the list). 409 cannot_merge (reason group | channel | not_direct | two_accounts | one_way).
   */
  async mergePersons(req = {}) {
    this._needPeople();
    const body = mergeBody(req);
    if (!body) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.mergePersons(body);
    const e = r.conversation;
    if (!e || !isPerson(e)) { this.refreshConversations({ full: true }).catch(() => {}); return null; }
    this._putPerson(e);
    const ways = new Set(personWayIds(e));
    this._dropSuggestions((s) => ways.has(s.conversationId) || (e.person.userId && s.userId === e.person.userId));
    return this.getCachedConversation(e.id);
  }

  /**
   * „Trennen“: DELETE persons/:id/ways/:conversationId (without a way: every way) — nothing is lost; the list is read
   * again (the way is its own chat once more). → { person: object | null, conversationIds }
   */
  async splitPerson(id, conversationId = null) {
    this._needPeople();
    const cid = posInt(id);
    const pid = cid ? this._pidOf(cid) : null;
    const way = conversationId == null ? null : posInt(conversationId);
    if (!pid || (conversationId != null && !way)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.splitPerson(pid, way);
    const ids = (Array.isArray(r.conversations) ? r.conversations : []).map((c) => c && posInt(c.id)).filter(Boolean);
    await this.refreshConversations({ full: true }).catch(() => {});
    this._suggestionsSoon();
    return { person: r.person && typeof r.person === 'object' ? r.person : null, conversationIds: ids };
  }

  /** „Name in deiner Liste“: 'account' or the conversation id of a way → the entry. */
  async renamePerson(id, name) {
    this._needPeople();
    const cid = posInt(id);
    const pid = cid ? this._pidOf(cid) : null;
    const n = name === 'account' ? 'account' : posInt(name);
    if (!pid || !n) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.patchPerson(pid, { name: n });
    if (r.conversation) this._putPerson(r.conversation);
    return r.conversation ? this.getCachedConversation(r.conversation.id) : null;
  }

  /**
   * „Mit Person zusammenführen …“ of a chat with one person (or of a person's entry): the accounts (when it has none
   * yet) and the other chats with one person. → { accounts, chats }
   */
  async personCandidates(id) {
    this._needPeople();
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid', { code: 'invalid' });
    const c = this._convs.get(cid);
    const of = isPerson(c) ? posInt(c.person.conversationId) || cid : cid;
    const r = await this.api.personCandidates(of);
    const s = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
    return {
      accounts: (Array.isArray(r.accounts) ? r.accounts : []).filter((a) => a && posInt(a.userId)).slice(0, 500).map((a) => ({
        userId: posInt(a.userId), name: s(a.name, 120) || '', avatarUrl: isAvatarPath(a.avatarUrl) ? a.avatarUrl : null, initials: s(a.initials, 4), colorHex: s(a.colorHex, 9), personId: posInt(a.personId),
      })),
      chats: (Array.isArray(r.chats) ? r.chats : []).filter((x) => x && posInt(x.conversationId)).slice(0, 200).map((x) => ({
        conversationId: posInt(x.conversationId), title: s(x.title, 120) || '', network: isBridgeNet(x.network) ? x.network : null, label: s(x.label, 40) || '',
        avatarUrl: isAvatarPath(x.avatarUrl) ? x.avatarUrl : null, avatarMediaId: isMediaId(x.avatarMediaId) ? x.avatarMediaId : null, personId: posInt(x.personId),
      })),
    };
  }

  /**
   * „Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?“ — PUT bridges/recognition { allowed } (GateControl
   * with gc.bridges version 9; 403 feature_off else) → recognition | null. Messenger 1.23: per service (`network`,
   * Signal with gc.bridges version 10) → the consent of that service (`recognitions[network]`).
   */
  async setRecognition(allowed, network = 'whatsapp') {
    this._need(FEATURE_LINKED);
    if (typeof allowed !== 'boolean' || !isBridgeNet(network)) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.bridgeRecognition(allowed, network);
    const all = r && r.recognitions && typeof r.recognitions === 'object' ? r.recognitions : null;
    if (network !== 'whatsapp') return normalizeRecognition(all ? all[network] : null, network);
    return normalizeRecognition(r.recognition);
  }

  /**
   * Messenger 1.23 „Im Portal fortsetzen“ / „Im Windows-Client fortsetzen“: the linking step of a service with the QR
   * code only (Signal) goes to a second screen → { network, target, expiresAt, portalPath }.
   */
  async bridgeHandoff(network, target) {
    this._need(FEATURE_LINKED);
    if (!isBridgeNet(network) || !HANDOFF_TARGETS.includes(target)) throw new MessengerError('invalid', { code: 'invalid' });
    const h = normalizeHandoff((await this.api.bridgeHandoff(network, target)).handoff);
    if (!h) throw new MessengerError('bad answer', { code: 'bad_response' });
    return h;
  }

  /** Messenger 1.23: the second screen is not needed any more (the link is shown here, done or given up). Never throws. */
  async bridgeHandoffEnd(network) {
    if (!isBridgeNet(network)) return false;
    try { await this.api.bridgeHandoffEnd(network); return true; } catch { return false; }
  }

  async fetchBridgeFile(messageId) {
    // 1.17: a file of the history (bridge_history); 1.19: once more, a file that failed (`placeholder.retry`) — every
    // client that shows chats over a bridge
    const id = posInt(messageId);
    if (!this.supports(FEATURE_BRIDGE_HISTORY) && !(id && this.api.bridged && this._retryable(id))) this._need(FEATURE_BRIDGE_HISTORY);
    if (!id) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.fetchFile(id);
    this._replaceMessage(r && r.message);
    return (r && r.message) || null;
  }

  /** Messenger 1.19: a cached message whose bridged file failed and may be asked for again (`placeholder.retry`). */
  _retryable(id) {
    for (const st of this._msgs.values()) {
      for (const l of this._lists(st)) {
        const m = l.find((x) => x && x.id === id);
        const ph = m && m.bridge && m.bridge.placeholder;
        if (m) return !!(ph && ph.state === 'failed' && ph.retry === true);
      }
    }
    return false;
  }

  /**
   * conversation.update { reason: history }: older messages came into the chat (at night, without push and without
   * message.new). The open chat loads its newest messages again (the view stays where it is); any other chat's
   * cached messages are dropped and loaded when it opens.
   */
  _historyArrived(cid) {
    const st = this._msgs.get(cid);
    if (!st) return;
    if (this._open.id === cid && st.loaded) {
      this._loadNewest(cid, 'history').catch(() => {});
      return;
    }
    this._msgs.delete(cid);
    this._persist();
  }

  /** Messenger 1.14: an own message the bridge did not take („Nicht gesendet“), once more → the message. */
  async resend(messageId) {
    const id = posInt(messageId);
    if (!id) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.resend(id);
    this._replaceMessage(r.message);
    return r.message || null;
  }

  _typingContactsOf(cid, now) {
    const map = this._typingContacts.get(cid);
    if (!map) return [];
    return [...map.entries()].filter(([, v]) => v.until > now).map(([contactId, v]) => ({ contactId, name: v.name }));
  }

  /** `typing` of contacts of a chat over a bridge: { contacts: [{ contactId, name }], until } (until null: stopped). */
  _setContactTyping(cid, contacts, until) {
    const had = this._typingContacts.has(cid);
    const list = (Array.isArray(contacts) ? contacts : []).filter((x) => x && posInt(x.contactId)).slice(0, 20);
    if (until && until > this.now() && list.length) {
      const map = new Map();
      for (const x of list) map.set(x.contactId, { name: typeof x.name === 'string' ? x.name.slice(0, 120) : null, until });
      this._typingContacts.set(cid, map);
    } else {
      this._typingContacts.delete(cid);
    }
    if (had || this._typingContacts.has(cid)) this.emit('typing', { conversationId: cid, userIds: this._typingIds(cid, this.now()), contacts: this._typingContactsOf(cid, this.now()) });
    this._scheduleTypingExpiry();
  }

  /**
   * GET status/feed → { items, me, serverTime } (cached for feedTtlMs;
   * refreshed by status.update / story.new / story.remove).
   */
  async statusFeed({ refresh = false } = {}) {
    this._need(FEATURES_14.status);
    if (!refresh && this._feed.data && this.now() - this._feed.at < this.timing.feedTtlMs) return this._copy(this._feed.data);
    const key = 'feed';
    if (this._inflight.has(key)) return this._inflight.get(key).then((d) => this._copy(d));
    const run = this.api.statusFeed().then((r) => {
      const data = { items: Array.isArray(r.items) ? r.items : [], me: r.me && typeof r.me === 'object' ? r.me : null, serverTime: r.serverTime || null };
      this._feed = { at: this.now(), data };
      this.emit('feed', this._copy(data));
      return data;
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run.then((d) => this._copy(d));
  }

  /** The feed changed on the server: fetch it once after a short pause. */
  _refreshFeedSoon() {
    if (!this.supports(FEATURES_14.status)) return;
    this._feed.at = 0;
    if (this._feedTimer) clearTimeout(this._feedTimer);
    this._feedTimer = this._timer(() => { this._feedTimer = null; this.statusFeed({ refresh: true }).catch(() => {}); }, this.timing.feedDebounceMs);
  }

  /** PUT status ({ preset, text, until, visibility, userIds, eta, destLabel }) → status. */
  async setStatus(req = {}) {
    this._need(FEATURES_14.status);
    const limits = (this._me && this._me.limits) || {};
    const r = await this.api.putStatus(statusBody(req, { textMax: limits.statusTextMax || 60, now: this.now() }));
    this._refreshFeedSoon();
    return r.status || null;
  }

  async clearStatus() {
    this._need(FEATURES_14.status);
    await this.api.deleteStatus();
    this._refreshFeedSoon();
    return null;
  }

  /**
   * POST status/stories. Text stories: { kind: 'text', text, bg, font };
   * picture / video: { kind, file: { data, mime }, thumb?, video?, text? }
   * — the files are uploaded first (preview before the file). `durationH`
   * (1/3/6/12/24) is sent only when the server offers `story_duration`
   * (Messenger 1.4.1), otherwise left out (24 h). → story
   */
  async createStory(req = {}) {
    this._need(FEATURES_14.stories);
    const limits = (this._me && this._me.limits) || {};
    const durations = this.supports(FEATURES_14.storyDuration) ? storyDurationsOf(limits) : null;
    const body = storyBody(req, { textMax: limits.storyTextMax || 700, durations });
    if (body.kind !== 'text') {
      const f = this._checkFile(req.file, limits);
      if (body.kind === 'image' ? !/^image\//.test(f.mime) : !isVideoMime(f.mime)) throw new MessengerError('type', { code: 'unsupported_type' });
      const t = req.thumb ? this._thumbFile(req.thumb, limits) : null;
      if (t) body.thumbMediaId = (await this.api.upload({ data: t.data, mime: t.mime })).mediaId;
      body.mediaId = (await this.api.upload({ data: f.data, mime: f.mime })).mediaId;
    } else if (req.file) {
      throw new MessengerError('file not allowed', { code: 'invalid' });
    }
    const r = await this.api.createStory(body);
    this._refreshFeedSoon();
    return r.story || null;
  }

  async deleteStory(id) {
    this._need(FEATURES_14.stories);
    await this.api.deleteStory(id);
    this._refreshFeedSoon();
    return true;
  }

  /** A story was shown: POST …/seen, and the cached feed marks it seen (ring off once all are). */
  async storySeen(id) {
    this._need(FEATURES_14.stories);
    const sid = posInt(id);
    await this.api.storySeen(sid);
    const d = this._feed.data;
    if (d) {
      let hit = false;
      for (const it of d.items) {
        for (const st of Array.isArray(it.stories) ? it.stories : []) if (st && st.id === sid && !st.seen) { st.seen = true; hit = true; }
        if (hit) it.unseen = (it.stories || []).some((st) => st && !st.seen);
      }
      if (hit) this.emit('feed', this._copy(d));
    }
    return true;
  }

  async storyViewers(id) {
    this._need(FEATURES_14.stories);
    const r = await this.api.storyViewers(id);
    return Array.isArray(r.viewers) ? r.viewers : [];
  }

  /** A reaction to a story → the direct message it became. */
  async storyReact(id, emoji) {
    this._need(FEATURES_14.stories);
    if (typeof emoji !== 'string' || !emoji || emoji.length > 16) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.storyReact(id, emoji);
    if (r.message && posInt(r.message.conversationId)) {
      if (!this._convs.has(r.message.conversationId)) this._refreshConvSoon(r.message.conversationId);
      this._replaceMessage(r.message);
    }
    return r.message || null;
  }

  // ── Messenger 1.4.0: chat tools ──────────────────────────

  async blocks() {
    this._need(FEATURES_14.tools);
    const r = await this.api.blocks();
    return Array.isArray(r.blocks) ? r.blocks : [];
  }

  /** Block (true) or unblock (false) a person → the block list; people, chats and the feed change. */
  async setBlocked(userId, blocked) {
    this._need(FEATURES_14.tools);
    const uid = posInt(userId);
    if (!uid) throw new MessengerError('invalid', { code: 'invalid' });
    const r = blocked ? await this.api.block(uid) : await this.api.unblock(uid);
    this._people = { at: 0, list: null };
    this._refreshFeedSoon();
    this.refreshConversations({ full: true }).catch(() => {});
    return Array.isArray(r.blocks) ? r.blocks : [];
  }

  async archive(id, archived) {
    this._need(FEATURES_14.tools);
    // Messenger 1.21: a person — every way
    const pid = this._pidOf(posInt(id));
    if (pid) {
      const rp = await this.api.archivePerson(pid, archived === true);
      if (rp.conversation) this._putPerson(rp.conversation);
      return rp.conversation ? this.getCachedConversation(rp.conversation.id) : null;
    }
    const r = await this.api.archive(id, archived === true);
    if (r.conversation) this._upsert(r.conversation);
    return r.conversation ? this.getCachedConversation(r.conversation.id) : null;
  }

  /** Pin (true) / unpin (false) a message in its chat → the conversation (pinned ids). */
  async pin(id, messageId, pinned) {
    this._need(FEATURES_14.tools);
    // Messenger 1.21: a message of a person is pinned in its way's conversation
    const st = this._pidOf(posInt(id)) ? this._msgs.get(posInt(id)) : null;
    const m = st ? this._lists(st).flat().find((x) => x && x.id === posInt(messageId)) : null;
    const target = m && posInt(m.conversationId) ? posInt(m.conversationId) : id;
    const r = pinned ? await this.api.pin(target, messageId) : await this.api.unpin(target, messageId);
    if (r.conversation) this._upsert(r.conversation);
    return r.conversation ? this.getCachedConversation(this._leadOf(r.conversation.id)) : null;
  }

  /** Custom chat filters (cached until lists.update). */
  async lists({ refresh = false } = {}) {
    this._need(FEATURES_14.tools);
    if (!refresh && this._chatLists) return this._copy(this._chatLists);
    const r = await this.api.lists();
    this._chatLists = Array.isArray(r.lists) ? r.lists : [];
    return this._copy(this._chatLists);
  }

  async saveLists(lists) {
    this._need(FEATURES_14.tools);
    const r = await this.api.putLists(listsBody(lists));
    this._chatLists = Array.isArray(r.lists) ? r.lists : [];
    this.emit('lists', this._copy(this._chatLists));
    return this._copy(this._chatLists);
  }

  /**
   * The whole chat as text (README "Export"): parts of ~800 KB, newest first,
   * each `truncated` part continued with `before` and put in front.
   * → { text, fileName, count, truncated (more than maxParts) }
   */
  async exportChat(id, { maxParts = 40 } = {}) {
    this._need(FEATURES_14.tools);
    const cid = posInt(id);
    if (!cid) throw new MessengerError('invalid', { code: 'invalid' });
    const parts = [];
    let before = null;
    let fileName = null;
    let count = 0;
    let more = false;
    for (let i = 0; i < maxParts; i++) {
      const r = await this.api.exportChat(cid, { before });
      if (!fileName && typeof r.fileName === 'string') fileName = r.fileName;
      parts.unshift(typeof r.text === 'string' ? r.text : '');
      count += Number(r.count) || 0;
      more = r.truncated === true && posInt(r.before) && posInt(r.before) !== before;
      if (!more) break;
      before = posInt(r.before);
    }
    return { text: parts.join(''), fileName: safeFileName(fileName || 'Chat.txt', 'Chat.txt'), count, truncated: !!more };
  }

  async remind(messageId, at) {
    this._need(FEATURES_14.tools);
    const t = Date.parse(at);
    if (!Number.isFinite(t) || t <= this.now()) throw new MessengerError('invalid', { code: 'invalid' });
    const r = await this.api.remind(messageId, new Date(t).toISOString());
    return r.reminder || null;
  }

  async reminders() {
    this._need(FEATURES_14.tools);
    const r = await this.api.reminders();
    return Array.isArray(r.reminders) ? r.reminders : [];
  }

  async deleteReminder(id) {
    this._need(FEATURES_14.tools);
    await this.api.deleteReminder(id);
    return true;
  }

  /** Shopping items and dates found in a message (server-side parser) → { items, dates }. */
  async suggest(messageId) {
    this._need(FEATURES_14.tools);
    const r = await this.api.suggest(messageId);
    return { items: Array.isArray(r.items) ? r.items.filter((x) => typeof x === 'string') : [], dates: Array.isArray(r.dates) ? r.dates : [] };
  }

  /** "Auf Einkaufsliste" (Familie) → { listId, listName, added, skipped }. */
  async toList(messageId, { items, list } = {}) {
    this._need(FEATURES_14.tools);
    const clean = (Array.isArray(items) ? items : []).map((x) => (typeof x === 'string' ? x.trim().slice(0, 120) : '')).filter(Boolean).slice(0, 50);
    if (!clean.length) throw new MessengerError('invalid', { code: 'invalid' });
    const body = { items: clean };
    if (typeof list === 'string' && list) body.list = list.slice(0, 64);
    const r = await this.api.toList(messageId, body);
    return { listId: r.listId == null ? null : r.listId, listName: r.listName || null, added: Number(r.added) || 0, skipped: Number(r.skipped) || 0 };
  }

  /** "Termin anlegen" (Familie calendar) → { eventId }. */
  async toCalendar(messageId, { title, startsAt, endsAt, allDay, place } = {}) {
    this._need(FEATURES_14.tools);
    const tt = typeof title === 'string' ? title.trim().slice(0, 80) : '';
    if (!tt || !Number.isFinite(Date.parse(startsAt))) throw new MessengerError('invalid', { code: 'invalid' });
    const body = { title: tt, startsAt: new Date(startsAt).toISOString(), allDay: allDay === true };
    if (endsAt && Number.isFinite(Date.parse(endsAt))) body.endsAt = new Date(endsAt).toISOString();
    if (typeof place === 'string' && place.trim()) body.place = place.trim().slice(0, 120);
    const r = await this.api.toCalendar(messageId, body);
    return { eventId: r.eventId == null ? null : r.eventId };
  }

  /**
   * "In Drive speichern" (Messenger 1.10, `GET me` → integrations.drive): the
   * picture / voice message / file of a message into Drive → { nodeId, name, where }.
   */
  async toDrive(messageId, folderId = null) {
    const r = await this.api.toDrive(messageId, folderId);
    return driveSavedOf(r);
  }

  /** Familie places (event place, arrival destination) → [{ id, name, lat, lon, radiusM }]. */
  async places() {
    const r = await this.api.familiePlaces();
    return Array.isArray(r.places) ? r.places : [];
  }

  // ── Messenger 1.4.0: polls, events, arrival ──────────────

  /** A route answering { message }: the message replaces the cached one. */
  async _messageOp(feature, call) {
    this._need(feature);
    const r = await call();
    if (r.message) this._replaceMessage(r.message);
    return r;
  }

  async vote(messageId, optionIds) {
    const ids = (Array.isArray(optionIds) ? optionIds : []).filter((x) => typeof x === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(x)).slice(0, 12);
    return (await this._messageOp(FEATURES_14.polls, () => this.api.vote(messageId, ids))).message || null;
  }

  async addPollOption(messageId, text) {
    const v = typeof text === 'string' ? text.replace(/\s+/g, ' ').trim().slice(0, 80) : '';
    if (!v) throw new MessengerError('invalid', { code: 'invalid' });
    return (await this._messageOp(FEATURES_14.polls, () => this.api.addPollOption(messageId, v))).message || null;
  }

  async closePoll(messageId) {
    return (await this._messageOp(FEATURES_14.polls, () => this.api.closePoll(messageId))).message || null;
  }

  /** → { message, nudged } */
  async nudgePoll(messageId) {
    const r = await this._messageOp(FEATURES_14.polls, () => this.api.nudgePoll(messageId));
    return { message: r.message || null, nudged: Number(r.nudged) || 0 };
  }

  /** answer: yes | maybe | no | null (withdraw); guests 0…20 with yes. */
  async rsvp(messageId, answer, guests) {
    if (![null, 'yes', 'maybe', 'no'].includes(answer)) throw new MessengerError('invalid', { code: 'invalid' });
    const body = { answer };
    if (answer === 'yes' && Number.isSafeInteger(guests) && guests >= 0 && guests <= 20) body.guests = guests;
    return (await this._messageOp(FEATURES_14.events, () => this.api.rsvp(messageId, body))).message || null;
  }

  async checkItem(messageId, itemId, done) {
    return (await this._messageOp(FEATURES_14.events, () => this.api.checkItem(messageId, itemId, done === true))).message || null;
  }

  /** PATCH messages/:id/event (the creator or a group admin): any send field, `cancelled: true`. */
  async editEvent(messageId, patch) {
    const body = normalizeEvent(patch, { partial: true });
    return (await this._messageOp(FEATURES_14.events, () => this.api.patchEvent(messageId, body))).message || null;
  }

  /** Stop an own live arrival (started on a phone). */
  async stopArrival(messageId) {
    return (await this._messageOp(FEATURES_14.arrival, () => this.api.stopArrival(messageId))).message || null;
  }

  // ── Messenger 1.4.0: home actions, plugin cards ──────────

  /** The quick actions the person may run (attach menu), cached for actionsTtlMs. */
  async actions({ refresh = false } = {}) {
    this._need(FEATURES_14.actions);
    if (!refresh && this._actions.list && this.now() - this._actions.at < this.timing.actionsTtlMs) return this._copy(this._actions.list);
    const r = await this.api.actions();
    const list = (Array.isArray(r.actions) ? r.actions : []).filter((a) => a && typeof a.id === 'string');
    this._actions = { at: this.now(), list };
    return this._copy(list);
  }

  /**
   * Run (op 'run', a card button with { actionId, plugin }), approve or deny
   * an action message → { message, result: { ok, message, state, error } | null }.
   */
  async actionOp(messageId, op, { actionId, plugin } = {}) {
    if (!['run', 'approve', 'deny'].includes(op)) throw new MessengerError('invalid', { code: 'invalid' });
    const body = {};
    if (op === 'run' && typeof actionId === 'string' && actionId) body.actionId = actionId.slice(0, 200);
    if (op === 'run' && typeof plugin === 'string' && /^[a-z0-9][a-z0-9-]{0,80}$/.test(plugin)) body.plugin = plugin;
    const r = await this._messageOp(FEATURES_14.actions, () => this.api.action(messageId, op, body));
    const res = r.result && typeof r.result === 'object' ? r.result : null;
    return { message: r.message || null, result: res ? { ok: res.ok === true, message: typeof res.message === 'string' ? res.message : null, state: res.state == null ? null : res.state, error: res.error || null } : null };
  }

  /** The picture of a plugin card (base64 from the server) → { mime, data: Buffer } (cached). */
  async cardImage(messageId) {
    const id = posInt(messageId);
    if (!id) throw new MessengerError('invalid', { code: 'invalid' });
    const key = `card:${id}`;
    const hit = this._media.get(key);
    if (hit) return hit;
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.cardImage(id).then((r) => {
      const mime = baseMime(r.mime);
      if (!/^image\/(png|jpeg|webp)$/.test(mime) || typeof r.data !== 'string' || !/^[A-Za-z0-9+/=\s]+$/.test(r.data)) throw new MessengerError('bad picture', { code: 'bad_response' });
      const data = Buffer.from(r.data, 'base64');
      if (!data.length) throw new MessengerError('bad picture', { code: 'bad_response' });
      const out = { mime, data };
      this._media.set(key, out);
      return out;
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── Storage ──────────────────────────────────────────────

  /**
   * What the chats use: the in-memory caches of this PC, the outbox and the
   * server's limits (`GET me`: maxBytes, quotaFull, retentionDays).
   */
  storage() {
    const limits = (this._me && this._me.limits) || {};
    let cachedMessages = 0;
    for (const st of this._msgs.values()) cachedMessages += st.list.length;
    return {
      mediaCacheBytes: this._media.bytes,
      avatarCacheBytes: this._avatars.bytes,
      cachedChats: this._convs.size,
      cachedMessages,
      outbox: this.outbox.size(),
      server: {
        maxBytes: Number.isFinite(limits.maxBytes) ? limits.maxBytes : null,
        quotaFull: limits.quotaFull === true,
        retentionDays: Number.isFinite(limits.retentionDays) ? limits.retentionDays : null,
      },
    };
  }

  /** Forget downloaded pictures and files of this session (they are loaded again when shown). */
  clearMediaCache() {
    this._media.clear();
    this._avatars.clear();
    return this.storage();
  }

  _copy(v) {
    return v == null ? v : JSON.parse(JSON.stringify(v));
  }

  // ── Live events ──────────────────────────────────────────

  _onLive(type, d) {
    if (!this.available()) {
      // Events prove the plugin is there (e.g. installed while running).
      if (this._avail.state !== 'checking') this.check().catch(() => {});
      return;
    }
    // Messenger 1.21: events come per way — a way of a person belongs to its entry
    const raw = posInt(d.conversationId);
    const cid = this._leadOf(raw);
    if (type === 'conversation.update' && String(d.reason || '').split(',').includes('person')) {
      // merged, renamed or split: the list again (and the suggestions, a merged pair is answered)
      this.refreshConversations({ full: true }).catch(() => {});
      this._suggestionsSoon();
      return;
    }
    switch (type) {
      case 'message.new': {
        if (!cid) return;
        // Messenger 1.14: a message of a chat over a bridge (`bridge: "whatsapp"`)
        if (isBridgeNet(d.bridge)) {
          this.noteBridge();
          this._setContactTyping(cid, [], null);
        }
        const sender = posInt(d.senderId);
        if (sender) this._setTyping(cid, sender, null);
        this._refreshConvSoon(cid);
        const st = this._msgs.get(cid);
        if (st && st.loaded) this._loadNewer(cid).then(() => this._maybeRead(cid)).catch(() => {});
        break;
      }
      case 'message.update': {
        if (!cid) return;
        // Messenger 1.11: the virus scan of the message's file changed (`scan`; its own editedAt stays — no "edited");
        // a blocked file's bytes loaded before are dropped, the change is loaded from editedAt − 1 s
        const scan = SC.normalizeScan(d.scan);
        if (scan && SC.isBlocked(scan)) this._dropMediaOf(cid, posInt(d.messageId));
        this._fetchChanged(cid, posInt(d.messageId), d.editedAt, scan ? 1000 : 1);
        this._refreshConvSoon(cid);
        break;
      }
      // 1.4.0: a poll, event, action or live arrival changed → changedSince.
      case 'poll.update':
      case 'event.update':
      case 'action.update':
      case 'arrival.update': {
        if (!cid) return;
        this._fetchChanged(cid, posInt(d.messageId), d.updatedAt);
        // nextEvent of the conversation (events) and the list preview
        if (type === 'event.update' || this._isLast(cid, posInt(d.messageId))) this._refreshConvSoon(cid);
        break;
      }
      case 'status.update':
      case 'story.new':
      case 'story.remove':
        this._refreshFeedSoon();
        break;
      case 'lists.update':
        if (this.supports(FEATURES_14.tools)) {
          this.lists({ refresh: true }).then((l) => this.emit('lists', l)).catch(() => {});
        }
        break;
      case 'reminders.update':
        this.emit('reminders', {});
        break;
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
        const hitCid = mid && Array.isArray(d.reactions) ? this._setReactions(mid, d.reactions) : null;
        if (hitCid) {
          this.emit('messages', { conversationId: hitCid, reason: 'reaction' });
          this._persist();
        }
        break;
      }
      case 'read': {
        if (!cid) return;
        const c = this._convs.get(cid);
        // Messenger 1.21: a way of a person — the ticks of the GateControl way, the unread count of the whole entry
        if (this._pidOf(cid)) {
          const way = c.person.ways.find((w) => w && w.conversationId === raw);
          const direct = !!way && way.way === GC_WAY && this._applyReadEvent(c, d);
          if (d.self === true) {
            this._refreshConvSoon(cid);
            for (const id of new Set([raw, cid])) this.emit('read-self', { conversationId: id, lastReadId: posInt(d.lastReadId) });
          } else if (direct) {
            this.emit('conversations', { ids: [cid], removed: [] });
            this._persist();
          }
          break;
        }
        // Messenger ≥ 1.1.0: readUpTo / deliveredUpTo as GET conversations/:id
        // would give them to this device's account → the ticks without a GET.
        const direct = !!c && this._applyReadEvent(c, d);
        if (d.self === true) {
          if (c) {
            if (c.me && Number.isSafeInteger(d.lastReadId)) c.me.lastReadId = Math.max(c.me.lastReadId || 0, d.lastReadId);
            if (Number.isFinite(d.unread)) c.unread = d.unread;
            this.emit('conversations', { ids: [cid], removed: [] });
            this._emitUnread();
            this._persist();
          }
          this.emit('read-self', { conversationId: cid, lastReadId: posInt(d.lastReadId) });
          // Older plugins (or no unread count): an answer in flight from before
          // the event may carry the old count — ask once more.
          if (!direct || !Number.isFinite(d.unread)) this._refreshConvSoon(cid);
        } else if (direct) {
          this.emit('conversations', { ids: [cid], removed: [] });
          this._persist();
        } else {
          this._refreshConvSoon(cid);
        }
        break;
      }
      case 'typing': {
        const uid = posInt(d.userId);
        // Messenger 1.14: contacts of a chat over a bridge (`userId: null`, `contacts`)
        if (cid && !uid && d.userId === null && Array.isArray(d.contacts)) {
          const tc = Date.parse(d.until);
          this._setContactTyping(cid, d.contacts, d.until && Number.isFinite(tc) ? Math.min(tc, this.now() + this.timing.typingValidMs + 2000) : null);
          return;
        }
        if (!cid || !uid) return;
        const t = Date.parse(d.until);
        this._setTyping(cid, uid, d.until && Number.isFinite(t) ? Math.min(t, this.now() + this.timing.typingValidMs + 2000) : null);
        break;
      }
      // Messenger 1.23: another device of the person sent the linking step of Signal here („Im Windows-Client
      // fortsetzen“) or took it back (`target: null`) — the page „Verknüpfte Dienste“ opens it (event `handoff`)
      case 'bridge.handoff': {
        const h = normalizeHandoff(d);
        if (h) this.emit('handoff', h);
        break;
      }
      case 'conversation.update':
        // Every reason (and unknown ones) → GET conversations/:id. `released`
        // (1.1.0): the managed group became a normal one — managedBy, can.*
        // and the info pane change; the system message comes as message.new.
        // 1.4.0: archive, pins, blocks (blocks: people and the feed as well).
        this._refreshConvSoon(cid);
        // Messenger 1.17: older messages of a chat over a bridge came in (no toast, no sound)
        if (cid && String(d.reason || '').split(',').includes('history')) this._historyArrived(cid);
        if (String(d.reason || '').split(',').includes('blocks')) {
          this._people = { at: 0, list: null };
          this._refreshFeedSoon();
        }
        break;
      case 'conversation.remove':
        // Messenger 1.21: a way of a person went — the entry is built again from the list
        if (cid && this._pidOf(cid)) this.refreshConversations({ full: true }).catch(() => {});
        else if (cid) this._drop(cid);
        break;
      default:
        break;
    }
  }

  /**
   * A cached message changed (edit, reactions, 1.4.0 polls / events / actions /
   * arrivals): GET messages?changedSince=<at − 1 ms> and merge what is cached.
   */
  _fetchChanged(cid, mid, at, backMs = 1) {
    const st = this._msgs.get(cid);
    if (!st || !st.loaded || !mid || !this._lists(st).some((l) => l.some((m) => m.id === mid))) return;
    const t = Date.parse(at);
    const since = Number.isFinite(t) ? new Date(t - backMs).toISOString() : (st.syncedAt || new Date(this.now() - 60000).toISOString());
    this._fetch(cid, { changedSince: since, limit: 100 }).then((r) => {
      this._mergeKnown(st, r.messages);
      const c = this._convs.get(cid);
      const fresh = Array.isArray(r.messages) && c && c.lastMessage ? r.messages.find((m) => m && m.id === c.lastMessage.id) : null;
      if (fresh) c.lastMessage = fresh;
      this.emit('messages', { conversationId: cid, reason: 'update' });
      this._persist();
    }).catch(() => {});
  }

  /** The files of a cached message (main, thumbnail) out of the in-memory cache (Messenger 1.11: blocked by the scan). */
  _dropMediaOf(cid, mid) {
    const st = this._msgs.get(cid);
    if (!st || !mid) return;
    for (const l of this._lists(st)) {
      const m = l.find((x) => x && x.id === mid);
      if (!m) continue;
      const media = m.media && typeof m.media === 'object' ? m.media : {};
      for (const id of [m.mediaId, m.thumbMediaId, media.id, media.mediaId, media.thumbId, media.thumbMediaId]) {
        if (isMediaId(id)) this._media.delete(id);
      }
    }
  }

  _isLast(cid, mid) {
    const c = this._convs.get(cid);
    return !!(c && c.lastMessage && c.lastMessage.id === mid);
  }

  /**
   * readUpTo / deliveredUpTo (and the reader's receipt) from a `read` event
   * of Messenger ≥ 1.1.0. → false when the event has neither (older plugin).
   */
  _applyReadEvent(c, d) {
    if (!('readUpTo' in d) && !('deliveredUpTo' in d)) return false;
    const val = (v) => (v === null ? null : posInt(v));
    for (const k of ['readUpTo', 'deliveredUpTo']) {
      if (!(k in d)) continue;
      const v = val(d[k]);
      if (v !== null || d[k] === null) c[k] = v;
    }
    const uid = posInt(d.userId);
    const meId = this._me && this._me.user ? this._me.user.id : null;
    if (uid && uid !== meId && d.self !== true) {
      const list = Array.isArray(c.receipts) ? c.receipts.slice() : [];
      const i = list.findIndex((x) => x && x.userId === uid);
      const entry = { ...(i >= 0 ? list[i] : { userId: uid }), lastReadId: val(d.lastReadId) };
      if ('lastDeliveredId' in d) entry.lastDeliveredId = val(d.lastDeliveredId);
      if (i >= 0) list[i] = entry; else list.push(entry);
      c.receipts = list;
    }
    return true;
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
    for (const map of this._typingContacts.values()) for (const v of map.values()) next = Math.min(next, v.until);
    if (!Number.isFinite(next)) return;
    this._timers.typing = this._timer(() => {
      this._timers.typing = null;
      const now = this.now();
      for (const [cid, map] of [...this._typingContacts]) {
        let changed = false;
        for (const [k, v] of [...map]) if (v.until <= now) { map.delete(k); changed = true; }
        if (!map.size) this._typingContacts.delete(cid);
        if (changed) this.emit('typing', { conversationId: cid, userIds: this._typingIds(cid, now), contacts: this._typingContactsOf(cid, now) });
      }
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
    // 1.4.0: status / story events of the gap are lost as well.
    if (this._feed.data) this._refreshFeedSoon();
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
      this._bridgeSeen = false;
      this._freshBridge.clear();
      this._chanSum = null;
      this._chansLoaded = false;
      this._sugg = { at: 0, list: null };
      this._syncBridged();
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
        // Messenger 1.21: a person's messages (its id; checked against the feature once GET me is known)
        const conv = this._convs.get(cid);
        this._msgs.set(cid, { list: st.list.filter((m) => m && posInt(m.id)), hasMore: true, loaded: true, syncedAt: st.syncedAt || null, pid: isPerson(conv) ? conv.person.id : null, way: null });
      }
      if (raw.me) this._me = raw.me;
      this._chanSum = normalizeChannelSummary(raw.chanSum);
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
        // Messenger 1.21: a source filter's page is not kept
        if (st && st.loaded && st.list.length && !st.way) msgs[c.id] = { list: st.list.slice(-CACHE_MSGS), syncedAt: st.syncedAt || null };
      }
      this.store.set(CACHE_KEY, { v: 1, scope: this._scope, me: this._me, convs, msgs, ...(this._chanSum ? { chanSum: this._chanSum } : {}) });
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
MessengerService.HINT_KEY = HINT_KEY;
MessengerService.KINDS = KINDS;

module.exports = MessengerService;
