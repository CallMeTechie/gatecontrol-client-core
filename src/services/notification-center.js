/**
 * GateControl – Notification center (Core service)
 *
 * Shared wrapper around Electron's Notification for push messages
 * (services/push-client.js) and for the apps' own local notifications:
 *
 *   - priority → sound / urgency (info silent, critical "urgent" toast),
 *     `silent:true` → inbox only, no banner, no sound;
 *   - collapse_key: a new message replaces the toast with the same key;
 *     `read` (other device) and `revoke` (withdrawn) close the toast;
 *   - Windows toasts via `toastXml`, action buttons via protocol activation
 *     (see utils/toast-xml.js) → ack with action, open an app route, open the
 *     portal (one-time login link) or mute the topic for 1 h;
 *   - click → show the app window on the inbox entry (event 'navigate'),
 *     or on an app page that claimed the entry (addClickRoute, e.g. Schule);
 *     openTarget() does the same for a notification shown as a notice card
 *     in a chat (Messenger 1.6);
 *   - where each kind of notification appears (core 1.191 push routes:
 *     GateControl, family chat or an own chat) — routes() / setRoute();
 *   - "Nicht stören bis" (notifications.dndUntil); critical still shows when
 *     notifications.criticalBypass is on;
 *   - local inbox cache (last 100, encrypted store key `notificationsInbox`),
 *     synchronised with the server inbox on every connect;
 *   - unread counter + change events for the tray badge;
 *   - the person's quiet hours (hello.quiet, or GET …/push/prefs on servers
 *     without it) for the settings page — read-only, the server applies
 *     them (`silent:true`) and the portal changes them
 *     (openQuietHoursInPortal → /portal#benachrichtigungen).
 *
 * Events (EventEmitter):
 *   'new'      (entry)                     a push message arrived (also when no toast was shown)
 *   'update'   ({ reason, ids, unread })   inbox changed: read | revoke | sync | clear | action
 *   'unread'   (count)                     unread count changed (tray badge)
 *   'status'   (status())                  push / DND state changed
 *   'navigate' ({ route, id, context? })   show this app route ('inbox' + id = entry;
 *                                          context: what addClickRoute's resolver returned)
 *   'portal'   ({ path })                  portal path requested (when no openPortal is given)
 *   'action'   ({ id, seq, action, type }) an action was performed
 *   'data'     ({ topic, data })           a data push (`kind: "data"`) no handler took; never shown
 *
 * Electron-free when `Notification` is injected (tests); otherwise Electron's
 * Notification is required lazily.
 */

'use strict';

const EventEmitter = require('events');
const crypto = require('crypto');
const { t } = require('../i18n');
const { readNotificationSettings } = require('../utils/notify-schema');
const { buildToastXml, parseActionUrl } = require('../utils/toast-xml');
const notifyRoutes = require('../utils/notify-routes');

const PRIORITIES = ['info', 'normal', 'high', 'critical'];
const APP_ROUTE_RE = /^(?:vpn|services|gateways|inbox|plg-[a-z0-9]+(?:-[a-z0-9]+)*)$/;
const PORTAL_PATH_RE = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]{0,300}$/;
const TOPIC_RE = /^(?:security|devices|services|system|admin_notice|plugin:[a-z0-9]+(?:-[a-z0-9]+)*:[a-z][a-z0-9_-]{0,31})$/;
const MAX_ITEMS = 100;
const MUTE_MS = 60 * 60 * 1000;
const MAX_TOASTS = 50; // toast references kept for close() (Action Center)
const QUIET_PORTAL_TARGET = '/portal#benachrichtigungen'; // portal tab "Meine Benachrichtigungen"

const URGENCY = { info: 'low', normal: 'normal', high: 'normal', critical: 'critical' };

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
const isoOrNull = (v) => (typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? v : null);

/** Clean inbox entry from a server payload (contract "notification" + state). */
function normalizeEntry(n, extra = {}) {
  if (!n || typeof n !== 'object') return null;
  const seq = Number(n.seq);
  const id = Number(n.id);
  if (!Number.isSafeInteger(seq) || seq <= 0 || !Number.isSafeInteger(id) || id <= 0) return null;
  const data = n.data && typeof n.data === 'object' && !Array.isArray(n.data) ? n.data : null;
  const state = n.state === 'read' || n.state === 'dismissed' ? n.state : 'delivered';
  return {
    seq,
    id,
    event_id: str(n.event_id, 120) || null,
    topic: str(n.topic, 120) || null,
    priority: PRIORITIES.includes(n.priority) ? n.priority : 'normal',
    title: str(n.title, 120),
    body: str(n.body, 1000),
    created_at: isoOrNull(n.created_at),
    expires_at: isoOrNull(n.expires_at),
    collapse_key: str(n.collapse_key, 120) || null,
    silent: n.silent === true,
    data,
    state,
    received_at: isoOrNull(extra.received_at || n.received_at) || new Date().toISOString(),
    via: (extra.via || n.via) === 'tunnel' ? 'tunnel' : (extra.via || n.via) === 'direct' ? 'direct' : null,
  };
}

/** Actions of an entry that the client can perform (fixed list). */
function entryActions(entry) {
  const list = entry && entry.data && Array.isArray(entry.data.actions) ? entry.data.actions : [];
  const out = [];
  for (const a of list.slice(0, 4)) {
    if (!a || typeof a !== 'object') continue;
    const id = str(a.id, 40);
    const type = str(a.type, 20);
    if (!/^[A-Za-z0-9_.:-]{1,40}$/.test(id)) continue;
    if (type === 'open_app_route' && !APP_ROUTE_RE.test(String(a.target || ''))) continue;
    if (type === 'open_portal' && !PORTAL_PATH_RE.test(String(a.target || ''))) continue;
    if (!['open_app_route', 'open_portal', 'mute_1h', 'ack', 'done'].includes(type)) continue;
    out.push({ id, type, label: str(a.label, 40) || id, target: a.target != null ? String(a.target) : null });
  }
  return out;
}

/**
 * Should this entry raise a toast? → { show, silent, reason }
 * (pure; exported for tests and for the apps' own decisions).
 */
function toastDecision(entry, settings, now = Date.now()) {
  if (!entry) return { show: false, silent: true, reason: 'invalid' };
  if (entry.expires_at && Date.parse(entry.expires_at) <= now) return { show: false, silent: true, reason: 'expired' };
  if (!settings.enabled) return { show: false, silent: true, reason: 'off' };
  if (!settings.toasts) return { show: false, silent: true, reason: 'toasts_off' };
  if (entry.silent) return { show: false, silent: true, reason: 'silent' };
  const bypass = entry.priority === 'critical' && settings.criticalBypass;
  const muteUntil = entry.topic && settings.muteUntil ? Number(settings.muteUntil[entry.topic]) : 0;
  const muted = !!entry.topic && (settings.mutedTopics.includes(entry.topic) || (Number.isFinite(muteUntil) && muteUntil > now));
  if (muted && !bypass) return { show: false, silent: true, reason: 'muted' };
  const dnd = Number.isFinite(settings.dndUntil) && settings.dndUntil > now;
  if (dnd && !bypass) return { show: false, silent: true, reason: 'dnd' };
  return { show: true, silent: entry.priority === 'info', reason: null };
}

class NotificationCenter extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.store - electron-store compatible (dot paths)
   * @param {object} [opts.log]
   * @param {object} [opts.pushClient] - PushClient; attached right away
   * @param {Function} [opts.Notification] - Electron Notification class (injectable)
   * @param {string} [opts.platform=process.platform]
   * @param {string} [opts.protocol] - URL scheme registered by the app
   *   (app.setAsDefaultProtocolClient) for toast buttons, e.g. 'gatecontrol-pro'
   * @param {*} [opts.icon] - NativeImage or path for non-Windows notifications
   * @param {string} [opts.toastImagePath] - absolute path of the toast logo
   * @param {() => void} [opts.showWindow] - bring the main window up
   * @param {(path: string) => (boolean|Promise<boolean>)} [opts.openPortal] - opens the
   *   portal (core createPortalOpener().open({ path }))
   * @param {string} [opts.storeKey='notifications']
   * @param {string} [opts.inboxKey='notificationsInbox']
   * @param {number} [opts.maxItems=100]
   * @param {number} [opts.staleToastMs=6h] - older messages (replay after a long offline phase) get no toast
   * @param {number} [opts.burstLimit=5] - at most this many toasts …
   * @param {number} [opts.burstWindowMs=10000] - … per window (inbox gets everything)
   * @param {() => number} [opts.now=Date.now]
   */
  constructor({
    store, log, pushClient, Notification, platform = process.platform, protocol = null, icon = null,
    toastImagePath = null, showWindow, openPortal, storeKey = 'notifications', inboxKey = 'notificationsInbox',
    maxItems = MAX_ITEMS, staleToastMs = 6 * 60 * 60 * 1000, burstLimit = 5, burstWindowMs = 10000, now = Date.now,
  } = {}) {
    super();
    this.store = store;
    this.log = log || noopLog();
    this._Notification = Notification || null;
    this.platform = platform;
    this.protocol = protocol;
    this.icon = icon;
    this.toastImagePath = toastImagePath;
    this.showWindow = typeof showWindow === 'function' ? showWindow : null;
    this.openPortal = typeof openPortal === 'function' ? openPortal : null;
    this.storeKey = storeKey;
    this.inboxKey = inboxKey;
    this.maxItems = maxItems;
    this.staleToastMs = staleToastMs;
    this.burstLimit = burstLimit;
    this.burstWindowMs = burstWindowMs;
    this.now = now;

    this.pushClient = null;
    this._chat = null;
    this._clickRoutes = new Map(); // app route → resolver(entry) (addClickRoute)
    this._pushHandlers = [];       // services that take over some pushes (addPushHandler, e.g. GateDrop)
    this._unsub = [];
    this._toasts = new Map();     // notification id → { notification, collapseKey }
    this._byCollapse = new Map(); // collapse_key → notification id
    this._nonces = new Map();     // nonce → { id, actionId }
    this._recentToasts = [];
    this._pendingRead = new Map(); // seq → { state, action }
    this._topics = [];
    this._quiet = { known: false, value: null, source: null, at: null };
    this._quietFetch = null;
    this._items = this._loadInbox();
    this._lastUnread = this.unreadCount();
    this._dndTimer = null;
    this._applied = this._settingsSnapshot();
    this._scheduleDndEnd();
    this._storeUnsub = null;
    this._watchStore();

    if (pushClient) this.attach(pushClient);
  }

  /**
   * Settings may also change through config:set (CONFIG_WRITABLE_KEYS):
   * electron-store's onDidChange brings them here as well.
   */
  _watchStore() {
    if (!this.store || typeof this.store.onDidChange !== 'function') return;
    try {
      const off = this.store.onDidChange(this.storeKey, () => { if (!this._writing) this._syncSettings(); });
      this._storeUnsub = typeof off === 'function' ? off : null;
    } catch (err) {
      this.log.debug(`Notification settings watcher unavailable: ${err.message}`);
    }
  }

  _settingsSnapshot() {
    const s = this._settings();
    return { server: JSON.stringify([s.enabled, s.direct, s.mutedTopics]), dnd: s.dndUntil, local: JSON.stringify([s.toasts, s.criticalBypass, s.muteUntil]) };
  }

  /** Apply changed settings once (idempotent): server prefs, DND timer, status. */
  _syncSettings() {
    const snap = this._settingsSnapshot();
    const prev = this._applied;
    this._applied = snap;
    if (snap.server !== prev.server && this.pushClient) this.pushClient.applySettings();
    if (snap.dnd !== prev.dnd) this._scheduleDndEnd();
    if (snap.server !== prev.server || snap.dnd !== prev.dnd || snap.local !== prev.local) this.emit('status', this.status());
  }

  // ── Wiring ───────────────────────────────────────────────

  /** Listen to a PushClient (replaces a previous one). */
  attach(pushClient) {
    this.detach();
    this.pushClient = pushClient;
    const on = (ev, fn) => { pushClient.on(ev, fn); this._unsub.push(() => pushClient.removeListener(ev, fn)); };
    on('notification', (n) => this.handleNotification(n));
    on('read', ({ ids }) => this._markLocal(ids, 'read', 'read'));
    on('revoke', ({ ids }) => this._revoke(ids));
    on('hello', (hello) => this._onHello(hello));
    on('status', () => this.emit('status', this.status()));
    on('reset', () => this.clear());
  }

  detach() {
    for (const off of this._unsub.splice(0)) off();
    this.pushClient = null;
  }

  /** Start the push client (when attached). */
  start() {
    if (this.pushClient) this.pushClient.start();
  }

  /** Stop the push client and timers; the inbox cache stays. */
  stop() {
    if (this.pushClient) this.pushClient.stop();
    if (this._dndTimer) clearTimeout(this._dndTimer);
    this._dndTimer = null;
  }

  /** stop() and release the store watcher and push listeners (end of life). */
  dispose() {
    this.stop();
    if (this._storeUnsub) { try { this._storeUnsub(); } catch { /* ignore */ } }
    this._storeUnsub = null;
    this.detach();
  }

  /**
   * New server / token (server:setup): drop the cache of the old server and
   * reconnect without resume position.
   */
  resetForNewServer() {
    this.clear();
    if (this.pushClient) this.pushClient.restart({ resetSeq: true });
  }

  /** Forget the inbox cache (and the quiet hours of the old server) and close all toasts. */
  clear() {
    for (const id of [...this._toasts.keys()]) this._closeToast(id);
    this._quiet = { known: false, value: null, source: null, at: null };
    this._items = [];
    this._pendingRead.clear();
    this._nonces.clear();
    this._saveInbox();
    this._changed('clear', []);
  }

  // ── Incoming ─────────────────────────────────────────────

  /**
   * A push message (PushClient 'notification'). Stores it in the inbox,
   * shows a toast when allowed. Returns the entry (or null when invalid).
   */
  handleNotification(n) {
    // Chat messages (`kind: "message"`, never part of the inbox) go to the
    // chat handler (services/chat-notifier.js) when the app has one.
    if (n && n.kind === 'message' && this._chat && typeof this._chat.notification === 'function') {
      try {
        if (this._chat.notification(n) !== false) return null;
      } catch (err) {
        this.log.warn(`Chat notification failed: ${err.message}`);
        return null;
      }
    }
    // A service that handles some pushes itself (e.g. GateDrop: silent data
    // pushes, files to fetch): 'consumed' → no inbox entry, no toast;
    // 'quiet' → inbox entry without a toast (the service shows its own).
    // Data pushes (`kind: "data"`, GateControl 1.193) are never shown or
    // stored: only the handlers see them.
    const dataOnly = !!n && n.kind === 'data';
    let quiet = false;
    for (const h of this._pushHandlers) {
      let r = false;
      try { r = h.notification(n); } catch (err) { this.log.warn(`Push handler failed: ${err.message}`); }
      if (r === 'consumed' || r === true) return null;
      if (r === 'quiet') { quiet = true; break; }
    }
    if (dataOnly) {
      this.emit('data', { topic: typeof n.topic === 'string' ? n.topic : null, data: n.data && typeof n.data === 'object' ? n.data : null });
      return null;
    }
    const entry = normalizeEntry(n);
    if (!entry) return null;
    const now = this.now();
    if (entry.expires_at && Date.parse(entry.expires_at) <= now) return null;

    const prev = this._items.find((e) => e.id === entry.id);
    this._items = this._items.filter((e) => e.id !== entry.id);
    // A bundled update of an already read message is new again.
    this._items.unshift(entry);
    this._trim();
    this._saveInbox();

    const settings = this._settings();
    const decision = quiet ? { show: false, silent: true, reason: 'handled' } : toastDecision(entry, settings, now);
    const stale = entry.created_at && now - Date.parse(entry.created_at) > this.staleToastMs;
    if (decision.show && !stale && this._burstAllows(now)) {
      this._showToast(entry, decision);
    } else if (entry.collapse_key && this._byCollapse.has(entry.collapse_key)) {
      // Silent update of a collapsed message: the old banner is outdated.
      this._closeToast(this._byCollapse.get(entry.collapse_key));
    }
    this.emit('new', { ...entry, updated: !!prev, toast: decision.show && !stale });
    this._emitUnread();
    return entry;
  }

  _onHello(hello) {
    if (hello && Array.isArray(hello.topics)) this._topics = hello.topics.slice();
    // hello.quiet (normalized by PushClient; undefined = server without it).
    if (hello && hello.quiet !== undefined) this._setQuiet(hello.quiet, 'hello');
    else this.refreshQuiet().catch(() => {});
    this._flushPendingRead().finally(() => this.refresh());
  }

  // ── Quiet hours (read-only) ──────────────────────────────

  _setQuiet(value, source) {
    const q = value && typeof value === 'object' ? { ...value } : null;
    const before = JSON.stringify(this._quiet.value);
    const wasKnown = this._quiet.known;
    this._quiet = { known: true, value: q, source, at: new Date(this.now()).toISOString() };
    if (!wasKnown || JSON.stringify(q) !== before) this.emit('status', this.status());
  }

  /**
   * Quiet hours for the settings page: { known, quiet: { from, to, tz,
   * criticalBypass } | null, source: 'hello'|'prefs'|null, at }.
   * known=false: not learned yet (no connection, or a server without them).
   */
  quietState() {
    return { known: this._quiet.known, quiet: this._quiet.value ? { ...this._quiet.value } : null, source: this._quiet.source, at: this._quiet.at };
  }

  /**
   * Ask the server (GET …/push/prefs) — on hello from servers that do not
   * send hello.quiet, and when the settings page opens.
   * → { ok, known, quiet, … } | { ok: false, error, known, quiet, … } (last known kept)
   */
  async refreshQuiet() {
    if (!this.pushClient || typeof this.pushClient.fetchPrefs !== 'function') return { ok: false, error: 'not_attached', ...this.quietState() };
    if (!this._quietFetch) {
      this._quietFetch = this.pushClient.fetchPrefs().finally(() => { this._quietFetch = null; });
    }
    const r = await this._quietFetch;
    if (r.ok && r.hasQuiet !== false) this._setQuiet(r.quiet, 'prefs');
    return r.ok ? { ok: true, ...this.quietState() } : { ok: false, error: r.error, ...this.quietState() };
  }

  // ── Where notifications appear (core 1.191 push routes) ──

  /**
   * GateControl, the family chat or an own chat per kind of notification
   * (PushClient.fetchRoutes): { ok, routes: { sink, canFamily, groups } } or
   * { ok: false, error } — 'unsupported' on servers without the route.
   */
  async routes() {
    if (!this.pushClient || typeof this.pushClient.fetchRoutes !== 'function') return { ok: false, error: 'not_attached' };
    return this.pushClient.fetchRoutes();
  }

  /**
   * Set where `topic` appears ('inbox' | 'own' | 'family') → { ok, routes, chat }
   * | { ok: false, error } — chat: the own chat on 'own' (PushClient.setRoute), else null.
   */
  async setRoute(topic, dest) {
    if (!this.pushClient || typeof this.pushClient.setRoute !== 'function') return { ok: false, error: 'not_attached' };
    return this.pushClient.setRoute(topic, dest);
  }

  /**
   * Open what a click on a notification would open, for a notification that
   * is shown somewhere else — a notice card in a chat (Messenger 1.6, its
   * `notice { topic, data }` and the card link's route): an app page that
   * claimed such entries (addClickRoute, e.g. Schule on the school message)
   * gets 'navigate' { route, id: null, context } like a toast click, and the
   * answer is { ok: true, route }. Nothing claims it → { ok: false } and the
   * app opens the route itself (its page, or the plugin's portal tab).
   */
  openTarget({ route = null, topic = null, data = null } = {}) {
    const base = typeof route === 'string' ? route.split('/')[0] : '';
    const d = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    const entry = {
      id: null,
      topic: notifyRoutes.isTopic(topic) ? topic : null,
      data: APP_ROUTE_RE.test(base) && typeof d.route !== 'string' ? { ...d, route: base } : d,
    };
    if (!entry.topic && !APP_ROUTE_RE.test(base)) return { ok: false };
    const target = this.clickTarget(entry);
    if (!target) return { ok: false };
    this.emit('navigate', { route: target.route, id: null, context: target.context });
    return { ok: true, route: target.route };
  }

  /** "Im Portal ändern": the portal tab "Meine Benachrichtigungen" (auto-login). */
  async openQuietHoursInPortal() {
    return this._openPortal(QUIET_PORTAL_TARGET);
  }

  async _openPortal(target) {
    if (!this.openPortal) {
      this.emit('portal', { path: target });
      return false;
    }
    try {
      return (await this.openPortal(target)) === true;
    } catch (err) {
      this.log.warn(`Opening the portal failed: ${err.message}`);
      return false;
    }
  }

  /**
   * Replace the cache with the server inbox (source of truth). Keeps
   * received_at / via of known entries. → { ok, unread } | { ok:false, error }
   */
  async refresh() {
    if (!this.pushClient) return { ok: false, error: 'not_attached' };
    const r = await this.pushClient.fetchInbox({ limit: this.maxItems });
    if (!r.ok) return r;
    const known = new Map(this._items.map((e) => [e.id, e]));
    const items = [];
    for (const raw of r.items) {
      const k = known.get(Number(raw && raw.id));
      const e = normalizeEntry(raw, k ? { received_at: k.received_at, via: k.via } : { received_at: raw && raw.created_at });
      if (!e) continue;
      const pending = this._pendingRead.get(e.seq);
      if (pending) e.state = pending.state;
      items.push(e);
    }
    const removed = this._items.filter((e) => !items.some((x) => x.id === e.id)).map((e) => e.id);
    for (const id of removed) this._closeToast(id);
    this._items = items;
    this._trim();
    this._saveInbox();
    this._changed('sync', removed);
    return { ok: true, unread: this.unreadCount() };
  }

  _revoke(ids) {
    const set = new Set(ids);
    for (const id of set) this._closeToast(id);
    const before = this._items.length;
    this._items = this._items.filter((e) => !set.has(e.id));
    if (this._items.length !== before) this._saveInbox();
    this._changed('revoke', [...set]);
  }

  /** Local state change (read sync from another device, own read). */
  _markLocal(ids, state, reason) {
    const set = new Set(ids);
    const changed = [];
    for (const e of this._items) {
      if (!set.has(e.id)) continue;
      this._closeToast(e.id);
      if (e.state === 'delivered' || (state === 'dismissed' && e.state !== 'dismissed')) {
        e.state = state;
        changed.push(e);
      }
    }
    if (changed.length) this._saveInbox();
    this._changed(reason, [...set]);
    return changed;
  }

  // ── Inbox API (IPC) ──────────────────────────────────────

  /**
   * Cached inbox, newest first.
   * @param {{ filter?: 'all'|'unread'|string, limit?: number, before?: number }} [opts]
   *   filter: 'all', 'unread' or a topic id; before: seq
   * @returns {{ items: object[], unread: number, topics: object[] }}
   */
  list({ filter = 'all', limit = MAX_ITEMS, before = null } = {}) {
    const now = this.now();
    let items = this._items.filter((e) => !e.expires_at || Date.parse(e.expires_at) > now);
    if (filter === 'unread') items = items.filter((e) => e.state === 'delivered');
    else if (filter && filter !== 'all') items = items.filter((e) => e.topic === filter);
    if (Number.isSafeInteger(before)) items = items.filter((e) => e.seq < before);
    const n = Number.isSafeInteger(limit) && limit > 0 ? Math.min(limit, MAX_ITEMS) : MAX_ITEMS;
    return {
      items: items.slice(0, n).map((e) => ({ ...e, actions: entryActions(e) })),
      unread: this.unreadCount(),
      topics: this.topics(),
    };
  }

  /** One entry by notification id (with its actions) or null. */
  get(id) {
    const e = this._items.find((x) => x.id === Number(id));
    return e ? { ...e, actions: entryActions(e) } : null;
  }

  /** Topics of the last hello with the local mute state. */
  topics() {
    const s = this._settings();
    return this._topics.map((tp) => ({
      id: tp.id,
      label: tp.label,
      muted: s.mutedTopics.includes(tp.id),
      mutedUntil: Number(s.muteUntil[tp.id]) > this.now() ? Number(s.muteUntil[tp.id]) : null,
    }));
  }

  unreadCount() {
    const now = this.now();
    return this._items.filter((e) => e.state === 'delivered' && (!e.expires_at || Date.parse(e.expires_at) > now)).length;
  }

  /**
   * Mark entries read here and on the server (other devices follow).
   * @param {number[]|'all'} ids - notification ids, or 'all'
   * @returns {Promise<{ ok: boolean, updated: number, unread: number, error?: string }>}
   */
  async markRead(ids, { state = 'read', action = null } = {}) {
    const target = ids === 'all'
      ? this._items.filter((e) => e.state === 'delivered').map((e) => e.id)
      : (Array.isArray(ids) ? ids : [ids]).map(Number).filter((x) => Number.isSafeInteger(x) && x > 0);
    const entries = this._items.filter((e) => target.includes(e.id));
    const changed = this._markLocal(entries.map((e) => e.id), state, 'read');
    const seqs = (action ? entries : changed).map((e) => e.seq);
    let res = { ok: true };
    if (seqs.length && this.pushClient) {
      for (const s of seqs) this._pendingRead.set(s, { state, action });
      res = await this.pushClient.ack(seqs, state, action);
      if (res.ok) for (const s of seqs) this._pendingRead.delete(s);
    }
    this._emitUnread();
    return { ok: res.ok, updated: changed.length, unread: this.unreadCount(), ...(res.ok ? {} : { error: res.error }) };
  }

  async _flushPendingRead() {
    if (!this.pushClient || !this._pendingRead.size) return;
    const groups = new Map();
    for (const [seq, { state, action }] of this._pendingRead) {
      const k = `${state}|${action || ''}`;
      if (!groups.has(k)) groups.set(k, { state, action, seqs: [] });
      groups.get(k).seqs.push(seq);
    }
    for (const g of groups.values()) {
      const r = await this.pushClient.ack(g.seqs, g.state, g.action);
      if (r.ok) for (const s of g.seqs) this._pendingRead.delete(s);
    }
  }

  /**
   * Perform an action of an entry (toast button or the inbox detail view).
   * @returns {Promise<{ ok: boolean, error?: string }>}
   */
  async performAction(id, actionId) {
    const entry = this._items.find((e) => e.id === Number(id));
    if (!entry) return { ok: false, error: 'not_found' };
    const action = entryActions(entry).find((a) => a.id === actionId);
    if (!action) return { ok: false, error: 'unknown_action' };
    switch (action.type) {
      case 'open_app_route':
        this._show();
        this.emit('navigate', { route: action.target, id: entry.id });
        break;
      case 'open_portal':
        // target goes to the portal as `next` (one-time login link, utils/portal.js).
        await this._openPortal(action.target);
        break;
      case 'mute_1h':
        if (entry.topic) this.muteTopic(entry.topic, MUTE_MS);
        break;
      default:
        break; // ack / done: only the confirmation below
    }
    this.emit('action', { id: entry.id, seq: entry.seq, action: action.id, type: action.type });
    const r = await this.markRead([entry.id], { state: action.type === 'done' ? 'dismissed' : 'read', action: action.id });
    return { ok: r.ok, ...(r.ok ? {} : { error: r.error }) };
  }

  /** Mute a topic locally for `ms` (toast button "1 h stumm"). */
  muteTopic(topic, ms = MUTE_MS) {
    if (!TOPIC_RE.test(String(topic))) return false;
    const s = this._settings();
    const now = this.now();
    const muteUntil = {};
    for (const [k, v] of Object.entries(s.muteUntil)) if (Number(v) > now) muteUntil[k] = Number(v);
    muteUntil[topic] = now + ms;
    this._set('muteUntil', muteUntil);
    this._syncSettings();
    return true;
  }

  // ── Preferences / DND ────────────────────────────────────

  /** { enabled, direct, toasts, criticalBypass, mutedTopics, dndUntil, topics } */
  getPrefs() {
    const s = this._settings();
    return {
      enabled: s.enabled, direct: s.direct, toasts: s.toasts, criticalBypass: s.criticalBypass,
      mutedTopics: s.mutedTopics.slice(), dndUntil: this._dndActive(s) ? s.dndUntil : null,
      topics: this.topics(),
    };
  }

  /**
   * Change preferences (partial). Invalid values are rejected as a whole.
   * enabled / direct / mutedTopics go to the server and (re)connect.
   * @returns {{ ok: boolean, prefs?: object, error?: string }}
   */
  setPrefs(patch = {}) {
    if (!patch || typeof patch !== 'object') return { ok: false, error: 'invalid' };
    const next = {};
    for (const k of ['enabled', 'direct', 'toasts', 'criticalBypass']) {
      if (patch[k] === undefined) continue;
      if (typeof patch[k] !== 'boolean') return { ok: false, error: `invalid_${k}` };
      next[k] = patch[k];
    }
    if (patch.mutedTopics !== undefined) {
      const m = patch.mutedTopics;
      if (!Array.isArray(m) || m.length > 100 || !m.every((x) => typeof x === 'string' && TOPIC_RE.test(x))) {
        return { ok: false, error: 'invalid_mutedTopics' };
      }
      next.mutedTopics = [...new Set(m)];
    }
    this._writing = true;
    try {
      for (const [k, v] of Object.entries(next)) this._set(k, v);
    } finally {
      this._writing = false;
    }
    this._syncSettings();
    return { ok: true, prefs: this.getPrefs() };
  }

  /**
   * "Nicht stören bis": { minutes } | { until: epoch ms | ISO } | null (off).
   * @returns {{ ok: boolean, active: boolean, until: ?number, error?: string }}
   */
  setDnd(arg) {
    let until = null;
    if (arg != null) {
      if (typeof arg === 'object' && Number.isFinite(arg.minutes) && arg.minutes > 0 && arg.minutes <= 7 * 24 * 60) {
        until = this.now() + Math.round(arg.minutes * 60000);
      } else if (typeof arg === 'object' && arg.until != null) {
        until = typeof arg.until === 'number' ? arg.until : Date.parse(arg.until);
      } else if (typeof arg === 'number') {
        until = arg;
      }
      if (!Number.isFinite(until) || until <= this.now()) return { ok: false, ...this.dndState(), error: 'invalid_dnd' };
    }
    this._set('dndUntil', until);
    this._syncSettings();
    return { ok: true, ...this.dndState() };
  }

  dndState() {
    const s = this._settings();
    const active = this._dndActive(s);
    return { active, until: active ? s.dndUntil : null };
  }

  _dndActive(s) {
    return Number.isFinite(s.dndUntil) && s.dndUntil > this.now();
  }

  _scheduleDndEnd() {
    if (this._dndTimer) clearTimeout(this._dndTimer);
    this._dndTimer = null;
    const { active, until } = this.dndState();
    if (!active) return;
    // setTimeout caps at ~24.8 days; re-armed on the next change anyway.
    const ms = Math.min(until - this.now() + 50, 0x7fffffff);
    this._dndTimer = setTimeout(() => {
      this._dndTimer = null;
      this.emit('status', this.status());
    }, ms);
    if (this._dndTimer.unref) this._dndTimer.unref();
  }

  /** Push status plus unread / DND / quiet hours for the settings page and the tray. */
  status() {
    const push = this.pushClient ? this.pushClient.status() : { state: 'stopped', reason: null };
    const s = this._settings();
    return {
      ...push, unread: this.unreadCount(), dnd: this.dndState(), toasts: s.toasts, enabled: s.enabled,
      quiet: this._quiet.value ? { ...this._quiet.value } : null, quietKnown: this._quiet.known,
    };
  }

  // ── Chat messages ────────────────────────────────────────

  /**
   * Hand chat notifications (`kind: "message"`) to the messenger's notifier
   * instead of the inbox: { notification(n) → false to fall back to a
   * normal entry, protocol(nonce) → true when it was one of its toast
   * buttons }. null removes it (chat pushes then show as normal entries,
   * like on apps without chats).
   */
  setChatHandler(handler) {
    this._chat = handler && typeof handler === 'object' ? handler : null;
  }

  /**
   * Let a service handle some pushes itself (GateDrop: silent data pushes and
   * "files for you"): handler.notification(n) → 'consumed' (not stored, no
   * toast), 'quiet' (stored without toast) or anything else (as usual);
   * handler.protocol(nonce) → true when it was one of its toast buttons.
   * @returns {() => void} removes the handler again
   */
  addPushHandler(handler) {
    if (!handler || typeof handler.notification !== 'function') throw new TypeError('addPushHandler: notification(n) required');
    this._pushHandlers.push(handler);
    return () => { this._pushHandlers = this._pushHandlers.filter((h) => h !== handler); };
  }

  /**
   * The toast rules for a message the center does not store itself (chat):
   * toastDecision with the current settings, plus the replay (stale) and
   * burst caps. A positive answer counts towards the burst limit.
   * @param {{ priority?, silent?, topic?, expires_at?, created_at? }} entry
   * @returns {{ show: boolean, silent: boolean, reason: ?string }}
   */
  decideToast(entry) {
    const now = this.now();
    const e = { priority: 'normal', silent: false, topic: null, ...entry };
    const d = toastDecision(e, this._settings(), now);
    if (!d.show) return d;
    if (e.created_at && now - Date.parse(e.created_at) > this.staleToastMs) return { show: false, silent: true, reason: 'stale' };
    if (!this._burstAllows(now)) return { show: false, silent: true, reason: 'burst' };
    this._recentToasts.push(now);
    return d;
  }

  /** Electron's Notification class (injected or required lazily), or null. */
  notificationClass() {
    return this._NotificationClass();
  }

  // ── Toasts ───────────────────────────────────────────────

  /**
   * Show a local notification through the same wrapper (the apps' own
   * "VPN verbunden" etc.). Respects DND and the toast setting unless
   * opts.force. Returns the Notification or null.
   * @param {{ title: string, body?: string, priority?: string, silent?: boolean,
   *   collapseKey?: string, force?: boolean, onClick?: Function }} opts
   */
  notify({ title, body = '', priority = 'normal', silent = false, collapseKey = null, force = false, onClick = null } = {}) {
    if (!title) return null;
    const entry = {
      id: -1, seq: 0, title: str(title, 120), body: str(body, 1000),
      priority: PRIORITIES.includes(priority) ? priority : 'normal', silent: false,
      collapse_key: collapseKey ? `local:${collapseKey}` : null, topic: null, data: null,
    };
    const decision = force ? { show: true, silent: priority === 'info' } : toastDecision(entry, this._settings(), this.now());
    if (!decision.show) return null;
    return this._showToast(entry, { ...decision, silent: decision.silent || silent }, onClick);
  }

  _NotificationClass() {
    if (this._Notification) return this._Notification;
    try {
      this._Notification = require('electron').Notification;
    } catch {
      this._Notification = null;
    }
    return this._Notification;
  }

  _showToast(entry, decision, onClick = null) {
    const N = this._NotificationClass();
    if (!N || (typeof N.isSupported === 'function' && !N.isSupported())) return null;

    // Same collapse key (or same message, e.g. bundled update): replace.
    const key = entry.collapse_key;
    if (key && this._byCollapse.has(key)) this._closeToast(this._byCollapse.get(key));
    if (entry.id > 0 && this._toasts.has(entry.id)) this._closeToast(entry.id);

    const title = entry.title;
    const prefix = entry.priority === 'critical' || entry.priority === 'high' ? t(`push.priority.${entry.priority}`) : '';
    const body = prefix ? (entry.body ? `${prefix} · ${entry.body}` : prefix) : entry.body;
    const topic = entry.topic ? this._topics.find((x) => x.id === entry.topic) : null;
    const attribution = topic ? topic.label : '';

    let options;
    if (this.platform === 'win32') {
      const buttons = [];
      if (this.protocol && entry.id > 0) {
        for (const a of entryActions(entry)) {
          const nonce = crypto.randomBytes(12).toString('base64url');
          this._nonces.set(nonce, { id: entry.id, actionId: a.id });
          buttons.push({ label: a.label, nonce });
        }
      }
      options = {
        toastXml: buildToastXml({
          title, body, attribution, priority: entry.priority, silent: decision.silent,
          buttons, scheme: this.protocol, imagePath: this.toastImagePath,
        }),
      };
    } else {
      options = {
        title, body, silent: decision.silent, urgency: URGENCY[entry.priority] || 'normal',
        ...(entry.priority === 'critical' ? { timeoutType: 'never' } : {}),
        ...(this.icon ? { icon: this.icon } : {}),
      };
    }

    let n;
    try {
      n = new N(options);
    } catch (err) {
      this.log.warn(`Notification could not be created: ${err.message}`);
      return null;
    }
    const id = entry.id > 0 ? entry.id : `local:${crypto.randomBytes(6).toString('hex')}`;
    this._toasts.set(id, { notification: n, collapseKey: key });
    if (key) this._byCollapse.set(key, id);
    // References stay after the banner disappeared: close() also removes a
    // toast from the Action Center (revoke / read elsewhere / collapse).
    while (this._toasts.size > MAX_TOASTS) {
      const [oldId, old] = this._toasts.entries().next().value;
      this._forgetToast(oldId, old.notification);
    }

    n.on('click', () => {
      if (onClick) { try { onClick(); } catch { /* app callback */ } return; }
      if (entry.id > 0) this._onToastClick(entry.id);
    });
    n.on('failed', (_e, error) => {
      this.log.warn(`Toast failed: ${error}`);
      this._forgetToast(id, n);
    });
    try { n.show(); } catch (err) { this.log.warn(`Notification could not be shown: ${err.message}`); }
    this._recentToasts.push(this.now());
    return n;
  }

  /** Show the app window on the inbox (tray entry "Mitteilungen"). */
  openInbox(id = null) {
    this._show();
    this.emit('navigate', { route: 'inbox', id: Number.isSafeInteger(id) ? id : null });
  }

  _onToastClick(id) {
    this._show();
    const entry = this._items.find((e) => e.id === id);
    const target = entry ? this.clickTarget(entry) : null;
    this.emit('navigate', target ? { route: target.route, id, context: target.context } : { route: 'inbox', id });
    this.markRead([id]).catch(() => {});
  }

  // ── App pages that open their own entries ────────────────

  /**
   * A click on the toast of an entry normally opens it in the inbox. An app
   * page with its own view of a plugin (e.g. Schule) can claim its entries:
   * `resolve(entry)` → a context object (or true) when the page should open
   * — navigate { route, id, context } — and null / false otherwise (the
   * page is not available, the entry is not one of its own; the inbox opens
   * as before). The route must be an app route (`plg-<id>`, …).
   * @returns {() => void} removes the resolver again
   */
  addClickRoute(route, resolve) {
    if (!APP_ROUTE_RE.test(String(route)) || route === 'inbox' || typeof resolve !== 'function') {
      throw new TypeError('addClickRoute: app route and resolver required');
    }
    this._clickRoutes.set(route, resolve);
    return () => { if (this._clickRoutes.get(route) === resolve) this._clickRoutes.delete(route); };
  }

  /**
   * Where a click on this entry leads: { route, context } of the first
   * resolver that claims it, or null (inbox). Resolver errors count as null.
   */
  clickTarget(entry) {
    if (!entry || !this._clickRoutes.size) return null;
    for (const [route, resolve] of this._clickRoutes) {
      let ctx = null;
      try { ctx = resolve(entry); } catch (err) { this.log.warn(`Click route ${route} failed: ${err.message}`); }
      if (ctx) return { route, context: ctx && typeof ctx === 'object' ? ctx : null };
    }
    return null;
  }

  _show() {
    if (this.showWindow) { try { this.showWindow(); } catch (err) { this.log.warn(`showWindow failed: ${err.message}`); } }
  }

  _closeToast(id) {
    const t0 = this._toasts.get(id);
    if (!t0) return;
    this._forgetToast(id, t0.notification);
    try { t0.notification.close(); } catch { /* already gone */ }
  }

  _forgetToast(id, n) {
    const cur = this._toasts.get(id);
    if (!cur || cur.notification !== n) return;
    this._toasts.delete(id);
    if (cur.collapseKey && this._byCollapse.get(cur.collapseKey) === id) this._byCollapse.delete(cur.collapseKey);
    for (const [nonce, v] of this._nonces) if (v.id === id) this._nonces.delete(nonce);
  }

  _burstAllows(now) {
    this._recentToasts = this._recentToasts.filter((ts) => now - ts < this.burstWindowMs);
    return this._recentToasts.length < this.burstLimit;
  }

  /**
   * Toast button activation: the app passes the URL (or the whole argv of
   * `second-instance`). Returns true when it was a notification action.
   */
  handleArgv(argv) {
    const list = Array.isArray(argv) ? argv : [argv];
    for (const arg of list) {
      if (typeof arg !== 'string' || !this.protocol || !arg.toLowerCase().startsWith(`${this.protocol}:`)) continue;
      return this.handleProtocolUrl(arg);
    }
    return false;
  }

  handleProtocolUrl(url) {
    const nonce = parseActionUrl(url, this.protocol);
    if (!nonce) return false;
    const hit = this._nonces.get(nonce);
    if (!hit && this._chat && typeof this._chat.protocol === 'function') {
      try {
        if (this._chat.protocol(nonce) === true) return true;
      } catch (err) {
        this.log.warn(`Chat toast action failed: ${err.message}`);
      }
    }
    if (!hit) {
      for (const h of this._pushHandlers) {
        if (typeof h.protocol !== 'function') continue;
        try {
          if (h.protocol(nonce) === true) return true;
        } catch (err) {
          this.log.warn(`Toast action failed: ${err.message}`);
        }
      }
    }
    if (!hit) {
      // Stale button (e.g. from before a restart): just open the inbox.
      this._show();
      this.emit('navigate', { route: 'inbox', id: null });
      return true;
    }
    this._nonces.delete(nonce);
    this._closeToast(hit.id);
    this.performAction(hit.id, hit.actionId).catch((err) => this.log.warn(`Notification action failed: ${err.message}`));
    return true;
  }

  // ── Store ────────────────────────────────────────────────

  _settings() {
    return readNotificationSettings(this.store, this.storeKey);
  }

  _set(key, value) {
    try {
      this.store.set(`${this.storeKey}.${key}`, value);
    } catch (err) {
      this.log.warn(`Notification setting ${key} could not be saved: ${err.message}`);
    }
  }

  _loadInbox() {
    try {
      const raw = this.store && this.store.get(this.inboxKey);
      const list = raw && Array.isArray(raw.items) ? raw.items : [];
      return list.map((e) => normalizeEntry(e)).filter(Boolean).slice(0, this.maxItems);
    } catch (err) {
      this.log.warn(`Notification inbox cache unreadable: ${err.message}`);
      return [];
    }
  }

  _saveInbox() {
    try {
      this.store.set(this.inboxKey, { v: 1, items: this._items });
    } catch (err) {
      this.log.warn(`Notification inbox cache could not be saved: ${err.message}`);
    }
  }

  _trim() {
    this._items.sort((a, b) => b.seq - a.seq);
    if (this._items.length > this.maxItems) this._items.length = this.maxItems;
  }

  _changed(reason, ids) {
    this.emit('update', { reason, ids, unread: this.unreadCount() });
    this._emitUnread();
  }

  _emitUnread() {
    const n = this.unreadCount();
    if (n === this._lastUnread) return;
    this._lastUnread = n;
    this.emit('unread', n);
  }

  /** EventEmitter: listener errors must not break message handling. */
  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Notification listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

NotificationCenter.toastDecision = toastDecision;
NotificationCenter.normalizeEntry = normalizeEntry;
NotificationCenter.entryActions = entryActions;

module.exports = NotificationCenter;
