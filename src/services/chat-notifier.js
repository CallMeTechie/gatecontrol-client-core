'use strict';

/**
 * GateControl – Chat notifications on Windows (Core service)
 *
 * Chat pushes of the Messenger (`kind: "message"`, GateControl
 * docs/feature-notification-center.md "Chat-Benachrichtigungen") are not
 * inbox entries: the NotificationCenter hands them here
 * (setChatHandler) and this module shows one toast per conversation:
 *
 *   - Header: the group's title or the sender, text: the message (group:
 *     "Anna: …"), the sender's picture as round logo (else the app icon),
 *     Tag `chat-<id>` + Group `chats` — a new message replaces the toast of
 *     the same chat.
 *   - Reply field + "Gelesen" when Electron reports toast activations
 *     (Notification.handleActivation, Electron ≥ 39 on Windows): the reply
 *     goes through the messenger outbox (clientId, `source: "notification"`)
 *     and then reads the chat like `mark_read`. Without it: "Gelesen" as a
 *     protocol button (the app's toast protocol), or no button; a click
 *     always opens the chat.
 *   - mark_read: POST …/read { upTo } and ack every shown `seq` of the
 *     chat as `read` (action `mark_read`); read here (chat opened) → ack
 *     `read`; `read`/`revoke` from the stream and the messenger's `read`
 *     event of one's own devices close the toast.
 *   - Messenger 1.4.0: polls, events, live arrivals, home actions and plugin
 *     cards come as chat messages with the server's texts ("📊 Umfrage: …",
 *     "Bittet um: …"); pushes with `data.kind` (reminder, event_reminder,
 *     event_departure, poll_nudge, arrived, action_approved / _denied,
 *     reaction) show the server's title and body as they are, in a toast of
 *     their own per kind (tag `chat-<id>-<kind>`) that a new message of the
 *     chat does not replace; they are acked with the chat.
 *   - The rules of the other toasts apply (on/off, "Windows-Benachrichtigung
 *     anzeigen", topic muted, "Nicht stören", quiet hours = silent → no
 *     toast, replay/burst caps); no toast for the chat that is open and
 *     visible (its seqs are acked as read right away).
 *
 * Events: 'navigate' ({ conversationId }) — show the chat in the app.
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { t } = require('../i18n');
const { parseChatNotification, posInt, isAvatarPath } = require('../utils/messenger');
const { buildChatToastXml, parseChatArgs } = require('../utils/toast-xml');

const AVATAR_TIMEOUT_MS = 1500;
const OPEN_DEDUPE_MS = 1500;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class ChatNotifier extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.messenger - MessengerService
   * @param {object} opts.notificationCenter - NotificationCenter (setChatHandler, decideToast, notify)
   * @param {object} [opts.pushClient] - PushClient (ack, read/revoke events); default notificationCenter.pushClient
   * @param {object} [opts.log]
   * @param {string} [opts.platform=process.platform]
   * @param {string} [opts.protocol] - the app's toast protocol (fallback buttons)
   * @param {string} [opts.toastImagePath] - app icon (logo when the sender has no picture)
   * @param {string} [opts.tmpDir] - folder for sender pictures of toasts
   * @param {() => void} [opts.showWindow]
   * @param {Function} [opts.Notification] - Electron Notification (injectable)
   * @param {() => number} [opts.now]
   */
  constructor({
    messenger, notificationCenter, pushClient, log, platform = process.platform, protocol = null, toastImagePath = null,
    tmpDir = null, showWindow, Notification, now = Date.now, fsp = fs.promises,
  } = {}) {
    super();
    this.messenger = messenger;
    this.nc = notificationCenter;
    this.pushClient = pushClient || (notificationCenter && notificationCenter.pushClient) || null;
    this.log = log || noopLog();
    this.platform = platform;
    this.protocol = protocol;
    this.toastImagePath = toastImagePath;
    this.tmpDir = tmpDir ? path.join(tmpDir, 'chat-avatars') : null;
    this.showWindow = typeof showWindow === 'function' ? showWindow : null;
    this._Notification = Notification || null;
    this.now = now;
    this.fsp = fsp;

    this._convs = new Map();       // conversationId → { seqs: Map(id → seq), latest, toast, nonce }
    this._nonces = new Map();      // nonce → conversationId (input-mode toasts)
    this._protoNonces = new Map(); // nonce → { conversationId, messageId } ("Gelesen" protocol buttons)
    this._avatarFiles = new Map();
    this._pendingAcks = [];        // { seqs, state, action } to retry after the next hello
    this._lastOpen = { id: null, at: 0 };
    this._pending = new Set();     // toasts being prepared (sender picture)
    this._unsub = [];
    this._started = false;
    this.mode = 'none';
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    this.mode = this._detectMode();
    if (this.nc && typeof this.nc.setChatHandler === 'function') {
      this.nc.setChatHandler({
        notification: (n) => this.handle(n),
        protocol: (nonce) => this.handleProtocol(nonce),
      });
    }
    const on = (emitter, ev, fn) => {
      if (!emitter || typeof emitter.on !== 'function') return;
      emitter.on(ev, fn);
      this._unsub.push(() => emitter.removeListener(ev, fn));
    };
    on(this.pushClient, 'read', ({ ids }) => this._dropIds(ids));
    on(this.pushClient, 'revoke', ({ ids }) => this._dropIds(ids));
    on(this.pushClient, 'hello', () => this._flushAcks());
    on(this.messenger, 'read-local', ({ conversationId }) => this.conversationRead(conversationId));
    on(this.messenger, 'read-self', ({ conversationId }) => this._forget(conversationId, { close: true }));
    on(this.messenger, 'send-failed', ({ conversationId, source }) => {
      if (source !== 'notification') return;
      this._notifyLocal(t('chat.toast.replyFailedTitle'), t('chat.toast.replyFailed'), conversationId);
    });
    if (this.mode === 'input') {
      try {
        this._NotificationClass().handleActivation((details) => this.handleActivation(details));
      } catch (err) {
        this.log.warn(`Chat toast activation unavailable: ${err.message}`);
        this.mode = this.protocol ? 'protocol' : 'none';
      }
    }
  }

  stop() {
    this._started = false;
    if (this.nc && typeof this.nc.setChatHandler === 'function') this.nc.setChatHandler(null);
    for (const off of this._unsub.splice(0)) off();
  }

  _NotificationClass() {
    if (this._Notification) return this._Notification;
    if (this.nc && typeof this.nc.notificationClass === 'function') return this.nc.notificationClass();
    try { return require('electron').Notification; } catch { return null; }
  }

  /** 'input' (reply field), 'protocol' ("Gelesen" button) or 'none'. */
  _detectMode() {
    if (this.platform !== 'win32') return 'none';
    const N = this._NotificationClass();
    if (N && typeof N.handleActivation === 'function') return 'input';
    return this.protocol ? 'protocol' : 'none';
  }

  // ── Incoming ─────────────────────────────────────────────

  /**
   * A chat push (NotificationCenter chat handler). → true when handled
   * (false: malformed → the center shows it as a normal entry).
   */
  handle(n) {
    const p = parseChatNotification(n);
    if (!p) return false;
    if (p.expiresAt && Date.parse(p.expiresAt) <= this.now()) return true;
    const cid = p.conversationId;
    let rec = this._convs.get(cid);
    if (!rec) { rec = { seqs: new Map(), latest: null, toast: null, nonce: null, extras: new Map() }; this._convs.set(cid, rec); }
    rec.seqs.set(p.id, p.seq);
    if (p.pushKind) rec.extras.set(p.pushKind, { latest: p, toast: (rec.extras.get(p.pushKind) || {}).toast || null });
    else rec.latest = p;

    // The chat is on screen: nothing to show, it is read.
    if (this.messenger && typeof this.messenger.isOpenAndVisible === 'function' && this.messenger.isOpenAndVisible(cid)) {
      this.conversationRead(cid);
      return true;
    }
    const decision = this.nc && typeof this.nc.decideToast === 'function'
      ? this.nc.decideToast({ priority: p.priority, silent: p.silent, topic: p.topic, expires_at: p.expiresAt, created_at: p.createdAt })
      : { show: !p.silent, silent: false };
    if (decision.show) {
      const job = this._showToast(rec, p, decision)
        .catch((err) => this.log.warn(`Chat toast failed: ${err.message}`))
        .finally(() => this._pending.delete(job));
      this._pending.add(job);
    } else if (p.pushKind) {
      this._closeExtra(rec, p.pushKind);
    } else if (rec.toast) {
      // Silent update: the old banner of this chat is outdated.
      this._closeToast(rec);
    }
    return true;
  }

  async _showToast(rec, p, decision) {
    const N = this._NotificationClass();
    if (!N || (typeof N.isSupported === 'function' && !N.isSupported())) return;
    const cid = p.conversationId;
    const sender = p.sender.name || '';
    const kind = p.pushKind;
    let title = p.title || sender || 'GateControl';
    let body = p.body || '';
    if (p.isGroup && !kind) {
      title = p.conversationTitle || title;
      body = p.body ? (sender ? `${sender}: ${p.body}` : p.body) : p.title;
    }
    const imagePath = (await this._avatarFile(p.sender.avatarUrl)) || this.toastImagePath;
    // Superseded while the picture loaded (a newer message / push of this kind).
    const slot = kind ? rec.extras.get(kind) : null;
    if (kind ? (!slot || slot.latest !== p || this._convs.get(cid) !== rec) : rec.latest !== p) return;

    if (kind) this._closeExtra(rec, kind);
    else this._closeToast(rec);
    const nonce = crypto.randomBytes(12).toString('base64url');
    if (!kind) rec.nonce = nonce;
    this._nonces.set(nonce, cid);
    const ids = { conversationId: cid, messageId: p.messageId, seq: p.seq, nonce };
    let options;
    if (this.platform === 'win32') {
      let readNonce = null;
      if (this.mode === 'protocol') {
        readNonce = crypto.randomBytes(12).toString('base64url');
        this._protoNonces.set(readNonce, { conversationId: cid, messageId: p.messageId });
      }
      options = {
        toastXml: buildChatToastXml({
          title,
          body,
          imagePath,
          silent: decision.silent,
          mode: this.mode,
          ids,
          canReply: !!p.reply,
          scheme: this.protocol,
          readNonce,
          labels: {
            placeholder: t('chat.toast.placeholder'),
            send: (p.reply && p.reply.label) || t('chat.toast.send'),
            read: (p.markRead && p.markRead.label) || t('chat.toast.read'),
          },
        }),
        id: kind ? `chat-${cid}-${kind}`.slice(0, 64) : `chat-${cid}`,
        groupId: 'chats',
      };
    } else {
      options = { title, body, silent: decision.silent, ...(imagePath ? { icon: imagePath } : {}) };
    }
    let n;
    try {
      n = new N(options);
    } catch (err) {
      this.log.warn(`Chat toast could not be created: ${err.message}`);
      return;
    }
    if (kind) slot.toast = n;
    else rec.toast = n;
    n.on('click', () => this.open(cid));
    n.on('failed', (_e, error) => this.log.warn(`Chat toast failed: ${error}`));
    try { n.show(); } catch (err) { this.log.warn(`Chat toast could not be shown: ${err.message}`); }
  }

  async _avatarFile(urlPath) {
    if (!urlPath || !isAvatarPath(urlPath) || !this.tmpDir || !this.messenger || typeof this.messenger.avatar !== 'function') return null;
    if (this._avatarFiles.has(urlPath)) return this._avatarFiles.get(urlPath);
    const load = (async () => {
      const r = await this.messenger.avatar(urlPath);
      const ext = r.mime === 'image/png' ? 'png' : r.mime === 'image/webp' ? 'webp' : 'jpg';
      const file = path.join(this.tmpDir, `${crypto.createHash('sha256').update(urlPath).digest('hex').slice(0, 24)}.${ext}`);
      await this.fsp.mkdir(this.tmpDir, { recursive: true });
      await this.fsp.writeFile(file, r.data);
      this._avatarFiles.set(urlPath, file);
      return file;
    })();
    let timer;
    const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), AVATAR_TIMEOUT_MS); });
    try {
      return await Promise.race([load.catch(() => null), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Activation (toast buttons, reply field, click) ───────

  /**
   * Notification.handleActivation callback: { arguments, type, reply,
   * userInputs }. Only chat toasts (`gcchat|…`) are handled here.
   * @returns {boolean} true when it was a chat toast
   */
  handleActivation(details) {
    const args = parseChatArgs(details && details.arguments);
    if (!args) return false;
    this._nonces.delete(args.nonce);
    const cid = args.conversationId;
    if (args.action === 'open') {
      this.open(cid);
    } else if (args.action === 'read') {
      this.markRead(cid, args.messageId).catch(() => {});
    } else if (args.action === 'reply') {
      const inputs = details && details.userInputs && typeof details.userInputs === 'object' ? details.userInputs : {};
      const text = String(inputs.reply != null ? inputs.reply : (details && details.reply) || '').trim();
      if (text) this.reply(cid, text, args.messageId).catch(() => {});
      else this.open(cid);
    }
    return true;
  }

  /** "Gelesen" protocol button (NotificationCenter.handleProtocolUrl → here). */
  handleProtocol(nonce) {
    const hit = this._protoNonces.get(nonce);
    if (!hit) return false;
    this._protoNonces.delete(nonce);
    this.markRead(hit.conversationId, hit.messageId).catch(() => {});
    return true;
  }

  /** Show the app on this chat. */
  open(conversationId) {
    const cid = posInt(conversationId);
    if (!cid) return;
    const now = this.now();
    if (this._lastOpen.id === cid && now - this._lastOpen.at < OPEN_DEDUPE_MS) return;
    this._lastOpen = { id: cid, at: now };
    if (this.showWindow) { try { this.showWindow(); } catch (err) { this.log.warn(`showWindow failed: ${err.message}`); } }
    this.emit('navigate', { conversationId: cid });
  }

  /**
   * Reply from the toast: queued in the outbox (clientId, retries), then the
   * chat counts as read (the server's own rule for replies).
   */
  async reply(conversationId, text, messageId = null) {
    const cid = posInt(conversationId);
    if (!cid || !this.messenger) return false;
    const rec = this._convs.get(cid);
    this._closeToast(rec);
    try {
      await this.messenger.send({ conversationId: cid, kind: 'text', text: String(text).slice(0, 4000), source: 'notification' });
    } catch (err) {
      this.log.warn(`Chat reply not queued: ${err.code || err.message}`);
      this._notifyLocal(t('chat.toast.replyFailedTitle'), t('chat.toast.replyFailed'), cid);
      return false;
    }
    await this.markRead(cid, messageId, { action: 'reply' });
    return true;
  }

  /**
   * mark_read: POST …/read { upTo } (the action's path, or the messenger's
   * own call), ack the chat's seqs as read and close its toast.
   */
  async markRead(conversationId, messageId = null, { action = 'mark_read' } = {}) {
    const cid = posInt(conversationId);
    if (!cid) return false;
    const rec = this._convs.get(cid);
    const p = rec && rec.latest;
    const seqs = rec ? [...rec.seqs.values()] : [];
    // Forget first: the messenger's own read event must not ack them without the action.
    this._forget(cid, { close: true });
    const upTo = posInt(messageId) || (p && p.messageId) || null;
    const canonical = `conversations/${cid}/read`;
    try {
      if (p && p.markRead && p.markRead.path !== canonical && this.messenger && this.messenger.api) {
        await this.messenger.api.postPath(p.markRead.path, p.markRead.body);
      } else if (this.messenger) {
        const body = p && p.markRead && p.markRead.body && posInt(p.markRead.body.upTo);
        if (upTo || body) await this.messenger.markRead(cid, body || upTo);
      }
    } catch (err) {
      this.log.debug(`Chat read mark failed: ${err.message}`);
    }
    if (seqs.length) this._ack(seqs, 'read', action);
    return true;
  }

  /** The chat was read on this device (opened in the app). */
  conversationRead(conversationId) {
    const cid = posInt(conversationId);
    if (!cid || !this._convs.has(cid)) return;
    this._ackAndForget(cid, null);
  }

  _ackAndForget(cid, action) {
    const rec = this._convs.get(cid);
    if (!rec) return;
    const seqs = [...rec.seqs.values()];
    this._forget(cid, { close: true });
    if (seqs.length) this._ack(seqs, 'read', action);
  }

  _ack(seqs, state, action) {
    if (!this.pushClient || typeof this.pushClient.ack !== 'function') return;
    this.pushClient.ack(seqs, state, action).then((r) => {
      if (r && r.ok === false) this._pendingAcks.push({ seqs, state, action });
    }).catch(() => this._pendingAcks.push({ seqs, state, action }));
  }

  _flushAcks() {
    const list = this._pendingAcks.splice(0);
    for (const a of list) this._ack(a.seqs, a.state, a.action);
  }

  /** Notification ids read / withdrawn elsewhere: drop them, close a toast that showed them. */
  _dropIds(ids) {
    const set = new Set(Array.isArray(ids) ? ids : []);
    if (!set.size) return;
    for (const [cid, rec] of [...this._convs]) {
      let hit = false;
      for (const id of [...rec.seqs.keys()]) if (set.has(id)) { rec.seqs.delete(id); hit = true; }
      if (!hit) continue;
      if (!rec.seqs.size || (rec.latest && set.has(rec.latest.id))) this._forget(cid, { close: true });
    }
  }

  _forget(conversationId, { close = false } = {}) {
    const cid = posInt(conversationId);
    const rec = cid ? this._convs.get(cid) : null;
    if (!rec) return;
    if (close) {
      this._closeToast(rec);
      for (const k of [...(rec.extras || new Map()).keys()]) this._closeExtra(rec, k);
    }
    this._convs.delete(cid);
    for (const [nonce, v] of this._nonces) if (v === cid) this._nonces.delete(nonce);
    for (const [nonce, v] of this._protoNonces) if (v.conversationId === cid) this._protoNonces.delete(nonce);
  }

  /** Close the toast of a 1.4.0 push kind (reminder, event_reminder, …) of a chat. */
  _closeExtra(rec, kind) {
    const slot = rec && rec.extras ? rec.extras.get(kind) : null;
    if (!slot || !slot.toast) return;
    const n = slot.toast;
    slot.toast = null;
    try { n.close(); } catch { /* gone */ }
  }

  _closeToast(rec) {
    if (!rec || !rec.toast) return;
    const n = rec.toast;
    rec.toast = null;
    try { n.close(); } catch { /* gone */ }
  }

  _notifyLocal(title, body, conversationId) {
    if (!this.nc || typeof this.nc.notify !== 'function') return;
    try {
      this.nc.notify({ title, body, force: true, collapseKey: `chat-error:${conversationId}`, onClick: () => this.open(conversationId) });
    } catch (err) {
      this.log.warn(`Chat error notice failed: ${err.message}`);
    }
  }

  /** Resolves when the toasts being prepared are shown (tests). */
  whenIdle() {
    return Promise.all([...this._pending]).then(() => undefined);
  }

  /** Chats with a shown / tracked notification (tests, diagnostics). */
  tracked() {
    return [...this._convs.entries()].map(([cid, rec]) => ({ conversationId: cid, seqs: [...rec.seqs.values()], toast: !!rec.toast }));
  }

  /** Shown toasts of 1.4.0 push kinds per chat (tests, diagnostics) → [{ conversationId, kinds }]. */
  trackedExtras() {
    return [...this._convs.entries()]
      .map(([cid, rec]) => ({ conversationId: cid, kinds: [...(rec.extras || new Map()).entries()].filter(([, v]) => v.toast).map(([k]) => k) }))
      .filter((x) => x.kinds.length);
  }

  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Chat notifier listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

module.exports = ChatNotifier;
