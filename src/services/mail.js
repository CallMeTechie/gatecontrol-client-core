'use strict';

/**
 * GateControl – Mail (Core service)
 *
 * The data side of the page "Mail" in the Windows Pro app (plugin
 * `gatecontrol-mail`, Phase 1: the person's mail accounts on the own server,
 * client API "C2"), over the device token of the existing ApiClient
 * (services/mail-api.js):
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins lists
 *   `gatecontrol-mail` and `GET me` lets the person in (403 → not unlocked
 *   for them: no page). Asked at start, every 30 min, after a push reconnect
 *   and on check(); network errors are retried (5 s … 5 min).
 * - Accounts: providers, discover, add (password / app password / IMAP),
 *   change, sign in again, remove; settings (threads, swipe actions).
 * - Microsoft: authorization code with PKCE in the default browser, loopback
 *   redirect http://localhost:<free port> (services/mail-loopback.js), then
 *   POST accounts/microsoft — client id, authority and scopes from `GET me`;
 *   the refresh token stays on the server.
 * - Read: folders, lists (Alle Posteingänge / an account, Relevant / Sonstige),
 *   search, threads, a mail (marked read when opened) with its HTML as the
 *   document of a sandboxed frame (utils/mail.js mailDocument: no scripts, own
 *   CSP, pictures only through gcmail:) — as sent (doc) and with its colours
 *   for the dark app (docDark, utils/mail-dark.js; the page picks one).
 *   handleProtocol() serves gcmail://img/<token> and gcmail://cid/<message>/
 *   <attachment> with the client's sign-in.
 * - Act: read / unread, flag, move, archive, delete, junk, Relevant / Sonstige.
 * - Write: drafts (reply / reply all / forward filled by the server), files
 *   of this PC as attachments (media upload), Drive files (copy or link), send
 *   with 10 s to undo, send later, the outbox, recipient suggestions.
 * - AI: "Kurz gesagt", to-dos (deadline / event into the family calendar),
 *   reply suggestions. Drive: suggestion and "In Drive speichern" of an
 *   attachment, all at once, "Zum Ablegen".
 * - Attachments: opened from %TEMP%\gatecontrol-mail (executables only
 *   "Speichern unter …") or saved where the person picks.
 * - Offline (services/mail-cache.js): `me`, folders, the lists loaded (an
 *   inbox at least 30 days back: filled in the background) and the mails
 *   opened, encrypted with DPAPI; used when the server cannot be reached;
 *   removed with a new server, a refused token and when Mail goes away.
 * - Live: the plugin's realtime event `mail { kind: 'changed', accountId,
 *   folderId }` → 'changed' (since Mail 1.1.2 also with messageId, threadId,
 *   attachmentId: a body / an attachment the provider sent later); a click on a Mail push (topic `mail`, data
 *   { mail: { messageId, accountId } }; `mail_failed` { mail: { outboxId } })
 *   opens the mail / the outbox on the page (NotificationCenter.addClickRoute).
 *
 * - Loading later (Mail 1.1.2): a mail whose body the provider has not sent
 *   yet comes with bodyMissing (the snippet as text, a full copy of the cache
 *   is kept); an embedded picture still on its way (409 busy, reason
 *   'loading') → 'loading' ({ messageId, attachmentId, retryAfter }).
 * - Account pictures (Microsoft): avatar(mediaId) → a data: URL, kept by
 *   media id.
 *
 * Phase 2 — calendar and contacts (client API "C3"):
 * - Calendar: the calendars with the overlays and settings (the device's
 *   time zone is set when it differs), own calendars and iCal subscriptions,
 *   the occurrences of a range, an event (its HTML description as a frame
 *   document like a mail), new / change / delete (one occurrence or the
 *   series), answers, invitations (the card in a mail).
 * - Contacts: address books, groups, every contact as a summary (loaded once,
 *   then only the changes with `since`; searched on this PC), a contact, its
 *   photo (a picture of this PC made 512 px JPEG with nativeImage), lookup of
 *   a sender, its mails and events, "Als Kontakt speichern", duplicates and
 *   merge, vCard import / export through the file dialogs, calls (tel:).
 * - Offline read only (services/mail-cache.js pim.bin): calendars, the
 *   occurrences −30 … +90 days, the events and contacts opened, all contact
 *   summaries, photos; changes need the server.
 * - Live: `calendar` and `contacts` events of the plugin → 'calendar' /
 *   'contacts'; a reminder push opens the event, an internal invitation the
 *   invitation (pushTarget).
 *
 * Events: 'state' (status()), 'changed' ({ accountId, folderId, messageId,
 * threadId, attachmentId }) lists to reload, 'outbox' ({}) the outbox
 * changed, 'loading' ({ messageId, attachmentId, retryAfter }) an embedded
 * picture the frame should ask for again, 'calendar' ({ kind, … } see
 * utils/mail-pim.js normalizeCalendarLive), 'contacts' ({ kind, … }).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const MailApi = require('./mail-api');
const MailCache = require('./mail-cache');
const MessengerApi = require('./messenger-api');
const mail = require('../utils/mail');
const { startCodeListener } = require('./mail-loopback');
const { unsafeToOpen, safeFileName } = require('../utils/messenger');
const { guessMime } = require('../utils/gatedrop');
const { openExternalSafely } = require('../utils/external-url');

const { MessengerError: MailError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,
  retryMinMs: 5000,
  retryMaxMs: 5 * 60 * 1000,
  fillPages: 6,            // an inbox is filled at most this many pages further back for the offline cache
};
const MAX_PATHS = 20;
const PICTURE_CACHE = 300;
const PICTURE_CACHE_BYTES = 30 * 1024 * 1024;
const AVATAR_CACHE = 30;
const CARD_PAGES = 60;                       // ≤ 60 × 200 contacts in the summary list
const CARD_SYNC_MS = 20 * 1000;              // the list is asked for changes at most this often (live events: at once)
const FILL_MS = 15 * 60 * 1000;              // the offline window of the calendar is filled at most this often
const PHOTO_PX = 512;
const DAY_MS = 24 * 60 * 60 * 1000;
const PLACEHOLDER = { de: 'Nachricht schreiben …', en: 'Write your message …' };

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }
const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

class MailService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.api] - MailApi (tests)
   * @param {object} [opts.shell] - Electron shell (open attachments, the browser for Microsoft)
   * @param {object} [opts.dialog] - Electron dialog (pick files, save as)
   * @param {Function} [opts.getMainWindow]
   * @param {() => string} [opts.tempDir] - folder for opened attachments (%TEMP%\gatecontrol-mail)
   * @param {() => string|null} [opts.cacheDir] - folder of the offline cache (%APPDATA%\…\mail-cache)
   * @param {object} [opts.protect] - DPAPI (DriveService.safeStorageProtect(safeStorage)); without it no cache on disk
   * @param {() => string} [opts.getLang] - 'de' | 'en'
   * @param {object} [opts.pushClient] - PushClient: live events, a reconnect asks for the plugin again
   * @param {object} [opts.notificationCenter] - a click on a Mail push opens the mail on the page
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   * @param {(url: string) => Promise<boolean>} [opts.openExternal] - the default browser (tests)
   * @param {Function} [opts.startListener] - loopback receiver of the Microsoft sign-in (tests)
   * @param {(n: number) => Buffer} [opts.random]
   * @param {object} [opts.nativeImage] - Electron nativeImage: a contact's photo made 512 px JPEG
   * @param {() => string} [opts.timeZone] - the device's IANA time zone (tests)
   */
  constructor({
    apiClient, log, api = null, shell = null, dialog = null, getMainWindow = null, tempDir = null, cacheDir = null,
    protect = null, getLang = null, pushClient = null, notificationCenter = null, timing = {}, now = Date.now,
    openExternal = null, startListener = null, random = null, nativeImage = null, timeZone = null,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.apiClient = apiClient || null;
    this.api = api || new MailApi({ apiClient, log: this.log, getLang });
    this.shell = shell;
    this.dialog = dialog;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.tempDir = typeof tempDir === 'function' ? tempDir : () => path.join(os.tmpdir(), 'gatecontrol-mail');
    this.getLang = typeof getLang === 'function' ? getLang : () => 'de';
    this.pushClient = pushClient;
    this.notificationCenter = notificationCenter;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;
    this.openExternal = typeof openExternal === 'function' ? openExternal
      : (url) => openExternalSafely(this.shell, url, { log: this.log, label: 'Mail Microsoft sign-in' });
    this.startListener = typeof startListener === 'function' ? startListener : startCodeListener;
    this.random = typeof random === 'function' ? random : crypto.randomBytes;
    this.cache = new MailCache({ dir: typeof cacheDir === 'function' ? cacheDir : () => null, protect, log: this.log, now });

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this._scopeNow();
    this.cache.setScope(this._scope);
    this._me = null;
    this._signin = null;
    this._pictures = new Map();   // gcmail URL → { mime, data }
    this._avatars = new Map();    // media id → data: URL
    this._pictureBytes = 0;
    this._filling = new Set();
    this.nativeImage = nativeImage;
    this.timeZone = typeof timeZone === 'function' ? timeZone : () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch { return null; } };
    this._zoneSet = false;
    this._calFillAt = 0;
    this._cardSync = null;
    this._cardSyncAt = 0;
    this._cardsStale = true;
    this._photoWaiting = new Map();
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onHello = () => {
        if (this._state.state !== 'available') { this.check().catch(() => {}); return; }
        this.emit('changed', { accountId: null, folderId: null });
        // what changed while the push channel was gone: the calendar and the contacts load again
        this._cardsStale = true;
        this.emit('calendar', { kind: 'calendars' });
        this.emit('contacts', { kind: 'addressbooks' });
      };
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== mail.PLUGIN_ID) return;
        const d = ev.data.data && typeof ev.data.data === 'object' ? ev.data.data : ev.data;
        if (ev.data.type === 'mail' && (d.kind === undefined || d.kind === 'changed')) {
          this.emit('changed', mail.normalizeChanged(d));
        } else if (ev.data.type === 'outbox' || ev.data.type === 'mail_failed') {
          this.emit('outbox', {});
        } else if (ev.data.type === 'calendar') {
          const c = mail.normalizeCalendarLive(d);
          if (c && c.kind === 'changed') this._calFillAt = 0;
          if (c) this.emit('calendar', c);
        } else if (ev.data.type === 'contacts') {
          const c = mail.normalizeContactsLive(d);
          if (!c) return;
          this._cardsStale = true;
          if (c.kind === 'addressbooks') this.cache.resetCards().catch(() => {});
          this.emit('contacts', c);
        }
      };
      pc.on('hello', onHello);
      pc.on('event', onEvent);
      this._unsub.push(() => { pc.removeListener('hello', onHello); pc.removeListener('event', onEvent); });
    }
    const nc = this.notificationCenter;
    if (nc && typeof nc.addClickRoute === 'function') {
      this._unsub.push(nc.addClickRoute(mail.APP_ROUTE, (entry) => this.clickContext(entry)));
    }
    if (nc && typeof nc.on === 'function') {
      // a failed send arrives as a push (topic mail_failed): the outbox on the page is refreshed
      const onNew = (entry) => { if (entry && entry.topic === mail.FAILED_TOPIC) this.emit('outbox', {}); };
      nc.on('new', onNew);
      this._unsub.push(() => nc.removeListener('new', onNew));
    }
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    this._timer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    this.cancelSignIn();
    this.cache.flush().catch(() => {});
  }

  /** A click on a Mail push while the page exists → { kind: 'message', messageId, accountId } | { kind: 'outbox', outboxId } | null. */
  clickContext(entry) {
    if (!this.available() || !entry || typeof entry !== 'object') return null;
    return mail.pushTarget(entry.topic, entry.data);
  }

  /** server:setup: the old server's state and its offline cache go, the new one is asked. */
  resetForNewServer() {
    this.cancelSignIn();
    this._me = null;
    this._pictures.clear();
    this._pictureBytes = 0;
    this._avatars.clear();
    this._retry = 0;
    this._resetPim();
    this._scope = this._scopeNow();
    this.cache.setScope(this._scope);
    this.cache.clear().catch(() => {});
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /** { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt } */
  status() {
    return { ...this._state };
  }

  available() {
    return this._state.state === 'available';
  }

  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    this._ensureScope();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    const gone = (reason) => {
      this._retry = 0;
      this._me = null;
      this.cache.clear().catch(() => {});
      this._setState({ state: 'unavailable', reason, version: null, checkedAt: this.now() });
    };
    try {
      const p = await this.api.plugin();
      if (!p) {
        gone('not_installed');
      } else {
        const version = typeof p.version === 'string' ? p.version.slice(0, 40) : null;
        try {
          this._me = await this.api.me();
          this.cache.putMe(this._me).catch(() => {});
          this._retry = 0;
          this._setState({ state: 'available', reason: null, version, checkedAt: this.now() });
        } catch (err) {
          if (err && err.status === 403) gone(err.code === 'not_allowed' ? 'not_allowed' : 'forbidden');
          else if (err && err.status === 404) gone('unsupported');
          else throw err;
        }
      }
    } catch (err) {
      if (err && err.status === 404) {
        gone('unsupported');
      } else if (err && (err.status === 401 || err.status === 403)) {
        // the device's token is refused (removed, wiped): nothing of Mail stays on this PC
        gone(err.status === 401 ? 'auth' : 'forbidden');
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        // Network / 5xx: keep "available" (the page stays, works from the cache and says it is offline).
        const keep = this._state.state === 'available' || !!(await this.cache.getMe().catch(() => null));
        this._setState({ ...this._state, state: keep ? 'available' : 'error', reason: (err && err.code) || 'network', checkedAt: this.now() });
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._started) {
      this._timer = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timer.unref) this._timer.unref();
    }
    return this.status();
  }

  _setState(s) {
    const key = () => JSON.stringify([this._state.state, this._state.reason, this._state.version]);
    const before = key();
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    if (key() !== before) this.emit('state', this.status());
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._me = null;
    this._pictures.clear();
    this._pictureBytes = 0;
    this._avatars.clear();
    this._resetPim();
    this.cache.setScope(s);
  }

  _resetPim() {
    this._zoneSet = false;
    this._calFillAt = 0;
    this._cardSyncAt = 0;
    this._cardsStale = true;
    this._photoWaiting.clear();
  }

  _need() {
    if (this._state.state === 'unavailable') throw new MailError('Mail is not available', { code: 'mail_unavailable' });
  }

  async _run(fn) {
    this._need();
    this._ensureScope();
    try {
      return await fn();
    } catch (err) {
      const e = err instanceof MailError ? err : MessengerApi.toMessengerError(err);
      if ((e.status === 404 && /^http_/.test(e.code)) || e.status === 401) this.check().catch(() => {});
      throw e;
    }
  }

  /** Online first; without a connection (network, timeout, 5xx) what the cache has, marked `offline`. */
  async _orCache(online, cached) {
    try {
      return await this._run(online);
    } catch (err) {
      const e = err instanceof MailError ? err : MessengerApi.toMessengerError(err);
      if (!e.transient || e.status === 429) throw e;
      const c = await cached().catch(() => null);
      if (!c) throw e;
      return { ...c, offline: true };
    }
  }

  _lang() {
    let l = null;
    try { l = this.getLang(); } catch { l = null; }
    return l === 'en' ? 'en' : 'de';
  }

  // ── Account, settings ────────────────────────────────────

  /** GET me → { ok, features, limits, microsoft, accounts, unread, settings, offline? } */
  async me() {
    return this._orCache(async () => {
      const m = await this.api.me();
      this._me = m;
      this.cache.putMe(m).catch(() => {});
      return { ok: true, ...m };
    }, async () => {
      const m = await this.cache.getMe();
      return m ? { ok: true, ...m } : null;
    });
  }

  async _meFresh() {
    if (this._me) return this._me;
    this._me = await this.api.me();
    return this._me;
  }

  async settings(patch) {
    return this._run(async () => {
      const settings = await this.api.settings(patch);
      if (this._me) this._me = { ...this._me, settings };
      return { ok: true, settings };
    });
  }

  async providers() { return this._run(async () => ({ ok: true, providers: await this.api.providers() })); }

  async discover(email) { return this._run(async () => ({ ok: true, ...(await this.api.discover(email)) })); }

  async addAccount(input) {
    return this._run(async () => {
      const account = await this.api.addAccount(input);
      this._me = null;
      this.emit('changed', { accountId: account.id, folderId: null });
      return { ok: true, account };
    });
  }

  async updateAccount(id, patch) {
    return this._run(async () => {
      const account = await this.api.updateAccount(id, patch);
      this._me = null;
      return { ok: true, account };
    });
  }

  async deleteAccount(id) {
    return this._run(async () => {
      await this.api.deleteAccount(id);
      this._me = null;
      // the account's lists go from the cache with the next load
      this.emit('changed', { accountId: mail.posId(id), folderId: null });
      return { ok: true };
    });
  }

  // ── Microsoft sign-in ────────────────────────────────────

  /**
   * "Mit Microsoft anmelden" (accountId: sign the account in again) → { ok, account }. Fails with
   * ms_unavailable (no client id on the server), browser_failed, busy, cancelled, timeout, access_denied, … .
   */
  async signInMicrosoft({ accountId = null, name, color, kind } = {}) {
    return this._run(async () => {
      if (this._signin) throw new MailError('a sign-in is running', { code: 'busy' });
      const me = accountId ? await this.api.me().then((x) => { this._me = x; return x; }) : await this._meFresh();
      if (!me.features.includes('microsoft') || !me.microsoft.clientId) throw new MailError('Microsoft sign-in not set up', { code: 'ms_unavailable' });
      // signing in again (Phase 2 "Neu anmelden"): the account's address is the hint, the scopes come fresh from me
      const again = accountId ? me.accounts.find((a) => a.id === mail.posId(accountId)) : null;
      const { verifier, challenge } = mail.pkcePair(this.random);
      const state = b64u(this.random(24));
      const listener = await this.startListener({ state, getLang: () => this._lang(), log: this.log });
      this._signin = listener;
      try {
        const url = mail.msAuthorizeUrl({
          authority: me.microsoft.authority, clientId: me.microsoft.clientId, redirectUri: listener.redirectUri,
          scopes: me.microsoft.scopes, state, challenge, loginHint: again ? again.email : null,
        });
        if (!url || !(await this.openExternal(url))) {
          listener.close('browser_failed');
          throw new MailError('browser not opened', { code: 'browser_failed' });
        }
        const r = await listener.result;
        if (!r || !r.code) throw new MailError((r && r.error) || 'failed', { code: (r && r.error) || 'failed' });
        const account = await this.api.microsoft(accountId, { code: r.code, codeVerifier: verifier, redirectUri: listener.redirectUri, name, color, kind });
        this._me = null;
        this.emit('changed', { accountId: account.id, folderId: null });
        return { ok: true, account };
      } finally {
        if (this._signin === listener) this._signin = null;
      }
    });
  }

  /** Ends a waiting Microsoft sign-in (the browser's answer no longer counts). */
  cancelSignIn() {
    const l = this._signin;
    this._signin = null;
    if (l) { try { l.close('cancelled'); } catch { /* closed */ } }
    return { ok: true };
  }

  // ── Folders, lists, mails ────────────────────────────────

  async folders() {
    return this._orCache(async () => {
      const f = await this.api.folders();
      this.cache.putFolders(f).catch(() => {});
      return { ok: true, ...f };
    }, async () => {
      const f = await this.cache.getFolders();
      return f ? { ok: true, ...f } : null;
    });
  }

  /** A page of a list (GET messages) → { ok, items, next, counts, offline? }. */
  async list(query) {
    const params = mail.listQuery(query);
    if (!params) throw new MailError('invalid list', { code: 'invalid' });
    const key = mail.listKey(params);
    return this._orCache(async () => {
      const page = await this.api.messages(params);
      await this.cache.putList(key, page, { append: !!params.before });
      if (!params.before && mail.isInboxKey(params) && page.next) this._fill(params, key);
      return { ok: true, items: page.items, next: page.next, counts: page.counts };
    }, async () => {
      if (params.before) return { ok: true, items: [], next: null, counts: null };
      const l = await this.cache.getList(key);
      return l ? { ok: true, items: l.items, next: null, counts: l.counts, cachedAt: l.at } : null;
    });
  }

  /** The offline cache of an inbox reaches back at least 30 days (more pages in the background). */
  _fill(params, key) {
    if (this._filling.has(key)) return;
    this._filling.add(key);
    (async () => {
      const limit = this.now() - MailCache.KEEP_MS;
      for (let i = 0; i < this.timing.fillPages; i += 1) {
        if (await this.cache.reaches(key, limit)) break;
        const l = await this.cache.getList(key);
        if (!l || !l.next) break;
        const page = await this.api.messages({ ...params, before: l.next });
        await this.cache.putList(key, page, { append: true });
        if (!page.next) break;
      }
    })().catch((err) => this.log.debug(`Mail offline fill stopped: ${err.code || err.message}`))
      .finally(() => this._filling.delete(key));
  }

  async search(query) {
    return this._run(async () => ({ ok: true, ...(await this.api.search(query)) }));
  }

  async thread(threadId) {
    return this._run(async () => {
      const t = await this.api.thread(threadId);
      return { ok: true, items: t.items.map((m) => ({ ...m, ...this._docs(m) })) };
    });
  }

  /** The frame documents of a mail: doc (as sent, light) and docDark (its colours for the dark app, utils/mail-dark.js). */
  _docs(m) {
    const lang = this._lang();
    return { doc: mail.mailDocument(m, { lang }), docDark: mail.mailDocument(m, { lang, dark: true }) };
  }

  _withDoc(m, extra = {}) {
    return { ok: true, message: m, ...this._docs(m), ...extra };
  }

  /** A mail with its frame documents → { ok, message, doc, docDark, offline? }; an unread one is marked read (markRead). */
  async message(id, { markRead = true } = {}) {
    const mid = mail.posId(id);
    if (!mid) throw new MailError('invalid id', { code: 'invalid' });
    return this._orCache(async () => {
      let m = await this.api.message(mid);
      if (m.bodyMissing) {
        // the provider has not sent the body yet (the snippet stands in): a full copy kept earlier is shown instead
        const kept = await this.cache.getMessage(mid).catch(() => null);
        if (kept && !kept.bodyMissing && (kept.html || kept.text)) m = { ...kept, unread: m.unread, flagged: m.flagged };
      }
      if (m.unread && markRead) {
        try {
          await this.api.flags([mid], { unread: false });
          m = { ...m, unread: false };
          await this.cache.patch([mid], (x) => ({ ...x, unread: false }));
        } catch (err) {
          this.log.debug(`Mail: marking read failed: ${err.code || err.message}`);
        }
      }
      if (!m.bodyMissing) await this.cache.putMessage(m);
      return this._withDoc(m);
    }, async () => {
      const m = await this.cache.getMessage(mid);
      return m ? this._withDoc(m) : null;
    });
  }

  /** "Bilder laden" (once / always for this sender) → the mail again with its pictures. */
  async allowImages(id, allow) {
    return this._run(async () => {
      const m = await this.api.allowImages(id, allow);
      await this.cache.putMessage(m);
      return this._withDoc(m);
    });
  }

  async flags(ids, patch) {
    return this._run(async () => {
      const r = await this.api.flags(ids, patch || {});
      const p = {};
      if (patch && typeof patch.unread === 'boolean') p.unread = patch.unread;
      if (patch && typeof patch.flagged === 'boolean') p.flagged = patch.flagged;
      await this.cache.patch(mail.idList(ids), (m) => ({ ...m, ...p }));
      return r;
    });
  }

  /** archive | delete | junk | move (folderId) | tab (tab) of mails → { ok, items? }; they leave the cached lists. */
  async act(action, ids, { folderId = null, tab = null } = {}) {
    return this._run(async () => {
      let r;
      if (action === 'move') r = await this.api.move(ids, folderId);
      else if (action === 'tab') r = await this.api.setTab(ids, tab);
      else r = await this.api.act(action, ids);
      const list = mail.idList(ids);
      if (action === 'tab') await this.cache.patch(list, (m) => ({ ...m, tab }));
      else await this.cache.patch(list, () => null);
      if (action === 'delete') await this.cache.dropMessages(list);
      return r;
    });
  }

  // ── Attachments ──────────────────────────────────────────

  async _attachmentFile(messageId, attachmentId, file) {
    const media = await this.api.attachment(messageId, attachmentId);
    await fs.promises.mkdir(path.dirname(file), { recursive: true });
    const part = `${file}.${crypto.randomBytes(4).toString('hex')}.part`;
    const out = fs.createWriteStream(part);
    try {
      await this.api.download(media.mediaId, out);
      await fs.promises.rm(file, { force: true });
      await fs.promises.rename(part, file);
    } catch (err) {
      out.destroy();
      await fs.promises.rm(part, { force: true }).catch(() => {});
      throw err;
    }
    return media;
  }

  /** Loads an attachment into %TEMP%\gatecontrol-mail and opens it → { ok, path } | { ok: false, code: 'unsafe' }. */
  async openAttachment(messageId, attachmentId, { name = null, mime = null } = {}) {
    if (!this.shell || typeof this.shell.openPath !== 'function') throw new MailError('no shell', { code: 'unsupported' });
    return this._run(async () => {
      const mid = mail.posId(messageId);
      const aid = mail.posId(attachmentId);
      if (!mid || !aid) throw new MailError('invalid id', { code: 'invalid' });
      const fname = safeFileName(name || 'Anhang', 'Anhang');
      if (unsafeToOpen(fname, mime)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
      const file = path.join(this.tempDir(), `${mid}-${aid}`, fname);
      let have = false;
      try { have = (await fs.promises.stat(file)).size > 0; } catch { have = false; }
      if (!have) {
        const media = await this._attachmentFile(mid, aid, file);
        if (unsafeToOpen(fname, media.mime)) {
          await fs.promises.rm(path.dirname(file), { recursive: true, force: true }).catch(() => {});
          return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
        }
      }
      const err = await this.shell.openPath(file);
      if (err) {
        this.log.warn(`Opening a mail attachment failed: ${err}`);
        return { ok: false, code: 'open_failed', error: String(err) };
      }
      return { ok: true, path: file };
    });
  }

  /** "Speichern unter …" of an attachment → { ok, path } | { ok: false, code: 'cancelled' }. */
  async saveAttachment(messageId, attachmentId, { name = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new MailError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const mid = mail.posId(messageId);
      const aid = mail.posId(attachmentId);
      if (!mid || !aid) throw new MailError('invalid id', { code: 'invalid' });
      const win = this.getMainWindow();
      const opts = { defaultPath: safeFileName(name || 'Anhang', 'Anhang') };
      const res = win ? await this.dialog.showSaveDialog(win, opts) : await this.dialog.showSaveDialog(opts);
      if (!res || res.canceled || !res.filePath) return { ok: false, code: 'cancelled', cancelled: true };
      await this._attachmentFile(mid, aid, res.filePath);
      return { ok: true, path: res.filePath };
    });
  }

  /** File dialog for attachments → { ok, paths } | { ok: false, code: 'cancelled' } */
  async pickFiles() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new MailError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const opts = { properties: ['openFile', 'multiSelections'] };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, paths: r.filePaths.slice(0, MAX_PATHS) };
  }

  /**
   * Files of this PC as media of the plugin (for a draft: { mediaId }) → { ok, items: [{ mediaId, name, size, mime }],
   * rejected: [{ name, code }] } — missing, empty or larger than 50 MB files are rejected.
   */
  async uploadFiles(paths) {
    return this._run(async () => {
      const items = [];
      const rejected = [];
      for (const p of (Array.isArray(paths) ? paths : []).slice(0, MAX_PATHS)) {
        if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p)) continue;
        const name = safeFileName(path.basename(p), 'Datei');
        let st;
        try { st = await fs.promises.stat(p); } catch { rejected.push({ name, code: 'missing' }); continue; }
        if (!st.isFile()) { rejected.push({ name, code: 'missing' }); continue; }
        if (st.size <= 0) { rejected.push({ name, code: 'empty' }); continue; }
        if (st.size > mail.MAX_UPLOAD_BYTES) { rejected.push({ name, code: 'too_large' }); continue; }
        const mime = guessMime(name);
        try {
          const r = await this.api.upload({ path: p, size: st.size, mime });
          items.push({ mediaId: r.mediaId, name, size: st.size, mime: r.mime || mime });   // the draft takes { mediaId, name }
        } catch (err) {
          rejected.push({ name, code: mail.errorCode(err) });
        }
      }
      return { ok: true, items, rejected };
    });
  }

  // ── Writing ──────────────────────────────────────────────

  /** The editor frame's document for `html` (contenteditable, sandboxed without scripts). */
  editorDoc(html) {
    return { ok: true, doc: mail.editorDocument(typeof html === 'string' ? html : '', { lang: this._lang(), placeholder: PLACEHOLDER[this._lang()] }) };
  }

  async createDraft(input) { return this._run(async () => ({ ok: true, draft: await this.api.createDraft(input) })); }

  async updateDraft(id, input) { return this._run(async () => ({ ok: true, draft: await this.api.updateDraft(id, input) })); }

  async draft(id) { return this._run(async () => ({ ok: true, draft: await this.api.draft(id) })); }

  async deleteDraft(id) { return this._run(async () => this.api.deleteDraft(id)); }

  /** Sends a draft (10 s to undo) or at `sendAt` → { ok, outboxId, undoUntil, sendAt }. */
  async send(id, sendAt = null) {
    return this._run(async () => {
      const r = await this.api.send(id, sendAt);
      this.emit('outbox', {});
      return { ok: true, ...r, undoUntil: r.undoUntil || this.now() + 10000 };
    });
  }

  /** "Rückgängig" / a planned mail back → { ok, draftId, draft } (the draft opens again). */
  async cancelSend(outboxId) {
    return this._run(async () => {
      const { draftId } = await this.api.cancelSend(outboxId);
      this.emit('outbox', {});
      let draft = null;
      try { draft = await this.api.draft(draftId); } catch (err) { this.log.debug(`Mail draft after cancel: ${err.code || err.message}`); }
      return { ok: true, draftId, draft };
    });
  }

  async outbox() { return this._run(async () => ({ ok: true, ...(await this.api.outbox()) })); }

  async contacts(q) { return this._run(async () => ({ ok: true, ...(await this.api.contacts(q)) })); }

  // ── AI ───────────────────────────────────────────────────

  async ai(id) { return this._run(async () => ({ ok: true, ai: await this.api.ai(id) })); }

  /** The AI's result (an existing one as it is; `again`: "Neu erstellen"). */
  async runAi(id, { again = false } = {}) { return this._run(async () => ({ ok: true, ai: await this.api.runAi(id, { again }) })); }

  /** A to-do into the family calendar, or (`action: 'calendar'`) into the person's own calendar. */
  async todo(id, index, { action = 'family_calendar', calendarId = null } = {}) {
    return this._run(async () => {
      const r = await this.api.todo(id, index, action, calendarId);
      if (action === 'calendar') this.emit('calendar', { kind: 'changed', calendarId: mail.posId(calendarId), accountId: null, from: null, to: null });
      return { ok: true, ...r };
    });
  }

  // ── Drive ────────────────────────────────────────────────

  async suggest(id, aid) { return this._run(async () => ({ ok: true, ...(await this.api.suggest(id, aid)) })); }

  async saveToDrive(id, aid, opts) {
    return this._run(async () => {
      const r = await this.api.saveToDrive(id, aid, opts || {});
      await this.cache.patch([mail.posId(id)].filter(Boolean), (m) => ({ ...m, savedToDrive: true }));
      return { ok: true, ...r };
    });
  }

  async saveAll(id) { return this._run(async () => ({ ok: true, ...(await this.api.saveAll(id)) })); }

  async filing() { return this._run(async () => ({ ok: true, ...(await this.api.filing()) })); }

  async confirmFiling(id, opts) { return this._run(async () => ({ ok: true, ...(await this.api.confirmFiling(id, opts || {})) })); }

  async dismissFiling(id) { return this._run(async () => this.api.dismissFiling(id)); }

  // ── Calendar (Phase 2) ───────────────────────────────────

  /** GET calendars → { ok, calendars, overlays, prefs, consent, offline? }; the device's time zone is set when it differs. */
  async calendars() {
    return this._orCache(async () => {
      let c = await this.api.calendars();
      const zone = this.timeZone();
      if (!this._zoneSet && zone && c.prefs.timeZone !== zone && mail.calSettingsPatch({ timeZone: zone })) {
        this._zoneSet = true;
        try { c = { ...c, prefs: await this.api.calSettings({ timeZone: zone }) }; } catch (err) { this.log.debug(`Mail time zone not set: ${err.code || err.message}`); }
      }
      this._zoneSet = true;
      await this.cache.putCalendars(c);
      this._fillCalendar(c);
      return { ok: true, ...c };
    }, async () => {
      const c = await this.cache.getCalendars();
      return c ? { ok: true, ...c } : null;
    });
  }

  /** The offline window (−30 … +90 days) of the visible calendars, in the background (at most every 15 min). */
  _fillCalendar(c) {
    if (this.now() - this._calFillAt < FILL_MS) return;
    this._calFillAt = this.now();
    const day = new Date(this.now());
    day.setHours(0, 0, 0, 0);
    const start = day.getTime() - 30 * DAY_MS;
    const parts = [[start, start + 60 * DAY_MS], [start + 60 * DAY_MS, start + 120 * DAY_MS]];
    const calendars = [...c.calendars.filter((x) => x.visible).map((x) => x.id), ...c.overlays.filter((x) => x.visible).map((x) => x.id)];
    if (!calendars.length) return;
    (async () => {
      for (const [from, to] of parts) {
        const p = mail.eventsQuery({ from, to, calendars });
        if (!p) continue;
        const r = await this.api.events(p);
        await this.cache.putRange(mail.eventsKey(p), from, to, r);
      }
    })().catch((err) => { this._calFillAt = 0; this.log.debug(`Mail calendar offline fill stopped: ${err.code || err.message}`); });
  }

  async _calChanged(fn, calendarId = null) {
    const r = await this._run(fn);
    this._calFillAt = 0;
    this.emit('calendar', calendarId ? { kind: 'changed', calendarId, accountId: null, from: null, to: null } : { kind: 'calendars' });
    return r;
  }

  async createCalendar(input) { return this._calChanged(async () => ({ ok: true, calendar: await this.api.createCalendar(input || {}) })); }

  async updateCalendar(id, patch) { return this._calChanged(async () => ({ ok: true, calendar: await this.api.updateCalendar(id, patch || {}) })); }

  async deleteCalendar(id) { return this._calChanged(async () => this.api.deleteCalendar(id)); }

  async subscribe(input) { return this._calChanged(async () => ({ ok: true, calendar: await this.api.subscribe(input || {}) })); }

  async updateOverlay(id, patch) { return this._calChanged(async () => ({ ok: true, overlay: await this.api.updateOverlay(id, patch || {}) })); }

  async calSettings(patch) { return this._run(async () => ({ ok: true, prefs: await this.api.calSettings(patch || {}) })); }

  /** GET events → { ok, items, overlays, pending, offline? } (offline: what the cached ranges hold of it). */
  async events(query) {
    const params = mail.eventsQuery(query);
    if (!params) throw new MailError('invalid range', { code: 'invalid' });
    const key = mail.eventsKey(params);
    return this._orCache(async () => {
      const r = await this.api.events(params);
      await this.cache.putRange(key, params.from, params.to, r);
      return { ok: true, ...r };
    }, async () => {
      const r = await this.cache.getRange(key, params.from, params.to, params.calendars || null);
      return r ? { ok: true, items: r.items, overlays: r.overlays, pending: [], cachedAt: r.at } : null;
    });
  }

  /** The description of an event as a frame document (its HTML like a mail's: no scripts, own CSP), light and dark. */
  _eventDocs(ev) {
    if (!ev.descriptionHtml) return { doc: null, docDark: null };
    const lang = this._lang();
    const m = { id: null, html: ev.descriptionHtml, text: ev.description, attachments: [], imagesBlocked: true };
    return { doc: mail.mailDocument(m, { lang }), docDark: mail.mailDocument(m, { lang, dark: true }) };
  }

  /** GET events/<id>?occurrence → { ok, event, doc, docDark, offline? }. */
  async event(id, occurrence = null) {
    const eid = mail.posId(id);
    const occ = occurrence ? mail.occOf(occurrence) : null;
    if (!eid || (occurrence && !occ)) throw new MailError('invalid id', { code: 'invalid' });
    const key = occ ? `${eid}:${occ}` : String(eid);
    return this._orCache(async () => {
      const ev = await this.api.event(eid, occ);
      await this.cache.putEvent(key, ev);
      return { ok: true, event: ev, ...this._eventDocs(ev) };
    }, async () => {
      const ev = await this.cache.getEvent(key);
      return ev ? { ok: true, event: ev, ...this._eventDocs(ev) } : null;
    });
  }

  async _eventChanged(fn, calendarId) {
    const r = await this._run(fn);
    const ev = r && r.event;
    if (ev) await this.cache.dropEvent(ev.eventId);
    this._calFillAt = 0;
    this.emit('calendar', { kind: 'changed', calendarId: (ev && ev.calendarId) || mail.posId(calendarId), accountId: null, from: null, to: null });
    return r;
  }

  /** POST events → { ok, event, sent }. */
  async createEvent(input) { return this._eventChanged(async () => ({ ok: true, ...(await this.api.createEvent(input || {})) }), input && input.calendarId); }

  /** PATCH events/<id> → { ok, event, sent }; a changed event elsewhere: { ok: false, code: 'conflict', detail: … } with `current`. */
  async updateEvent(id, input) {
    try {
      return await this._eventChanged(async () => ({ ok: true, ...(await this.api.updateEvent(id, input || {})) }), input && input.calendarId);
    } catch (err) {
      if (err && err.code === 'conflict') {
        const b = err.body && err.body.error && typeof err.body.error === 'object' ? err.body.error : {};
        const current = mail.normalizeEvent(b.current);
        await this.cache.dropEvent(mail.posId(id)).catch(() => {});
        return { ok: false, code: 'conflict', error: 'conflict', status: 409, current };
      }
      throw err;
    }
  }

  async deleteEvent(id, opts) {
    return this._run(async () => {
      const r = await this.api.deleteEvent(id, opts || {});
      await this.cache.dropEvent(mail.posId(id));
      this._calFillAt = 0;
      this.emit('calendar', { kind: 'changed', calendarId: null, accountId: null, from: null, to: null });
      return r;
    });
  }

  async respondEvent(id, input) { return this._eventChanged(async () => ({ ok: true, event: await this.api.respondEvent(id, input || {}) })); }

  async invitations(state = 'open') { return this._run(async () => ({ ok: true, ...(await this.api.invitations(state)) })); }

  async invitation(id) { return this._run(async () => ({ ok: true, invitation: await this.api.invitation(id) })); }

  async _inviteChanged(fn) {
    const r = await this._run(fn);
    this._calFillAt = 0;
    if (r.event) await this.cache.dropEvent(r.event.eventId);
    this.emit('calendar', { kind: 'changed', calendarId: r.event ? r.event.calendarId : null, accountId: null, from: null, to: null });
    return r;
  }

  async respondInvitation(id, input) { return this._inviteChanged(async () => ({ ok: true, ...(await this.api.respondInvitation(id, input || {})) })); }

  async applyInvitation(id) { return this._inviteChanged(async () => ({ ok: true, ...(await this.api.applyInvitation(id)) })); }

  async dismissInvitation(id, opts) { return this._inviteChanged(async () => this.api.dismissInvitation(id, opts || {})); }

  // ── Contacts (Phase 2) ───────────────────────────────────

  async addressbooks() {
    return this._orCache(async () => {
      const b = await this.api.addressbooks();
      await this.cache.putBooks(b);
      return { ok: true, ...b };
    }, async () => {
      const b = await this.cache.getBooks();
      return b ? { ok: true, ...b } : null;
    });
  }

  async updateAddressbook(id, patch) {
    return this._run(async () => {
      const book = await this.api.updateAddressbook(id, patch || {});
      // shown or hidden: the summaries of all contacts load anew
      await this.cache.resetCards();
      this._cardsStale = true;
      return { ok: true, addressbook: book };
    });
  }

  async cardSettings(patch) {
    return this._run(async () => {
      const prefs = await this.api.cardSettings(patch || {});
      if (patch && (patch.sort !== undefined || patch.show !== undefined)) { await this.cache.resetCards(); this._cardsStale = true; }
      return { ok: true, prefs };
    });
  }

  /** All CardSummaries on this PC: the whole list the first time, then the changes since its version. */
  _syncCards() {
    if (this._cardSync) return this._cardSync;
    this._cardSync = (async () => {
      const have = await this.cache.getCards();
      const since = have && !this._cardsStale && this.now() - this._cardSyncAt < CARD_SYNC_MS ? null : have;
      if (have && !since) return have;
      const all = [];
      let deleted = [];
      let version = 0;
      let cursor = null;
      for (let i = 0; i < CARD_PAGES; i += 1) {
        const page = await this.api.cards({ book: 'all', limit: 200, cursor: cursor || undefined, since: have ? have.version : undefined });
        all.push(...page.items);
        deleted = deleted.concat(page.deleted);
        version = Math.max(version, page.version);
        cursor = page.next;
        if (!cursor) break;
      }
      this._cardsStale = false;
      this._cardSyncAt = this.now();
      await this.cache.putCards({ version, items: all, deleted, full: !have });
      return this.cache.getCards();
    })().finally(() => { this._cardSync = null; });
    return this._cardSync;
  }

  /**
   * The contacts list ({ q, book: 'all' | id, group }) → { ok, items, version, offline? }: searched on this PC in the
   * summaries kept current (offline the ones kept).
   */
  async cards(query = {}) {
    const q = query && typeof query === 'object' ? query : {};
    if (!mail.cardsQuery({ q: q.q, book: q.book, group: q.group })) throw new MailError('invalid query', { code: 'invalid' });
    return this._orCache(async () => {
      const all = await this._syncCards();
      return { ok: true, items: mail.filterCards(all ? all.items : [], q), version: all ? all.version : 0 };
    }, async () => {
      const all = await this.cache.getCards();
      return all ? { ok: true, items: mail.filterCards(all.items, q), version: all.version, cachedAt: all.at } : null;
    });
  }

  async card(id) {
    const cid = mail.posId(id);
    if (!cid) throw new MailError('invalid id', { code: 'invalid' });
    return this._orCache(async () => {
      const card = await this.api.card(cid);
      await this.cache.putCard(card);
      return { ok: true, card };
    }, async () => {
      const card = await this.cache.getCard(cid);
      return card ? { ok: true, card } : null;
    });
  }

  async _cardChanged(card) {
    await this.cache.putCard(card);
    this._cardsStale = true;
    this.emit('contacts', { kind: 'changed', addressbookId: card.addressbookId, contactIds: [card.id] });
  }

  async createCard(input) { return this._run(async () => { const card = await this.api.createCard(input || {}); await this._cardChanged(card); return { ok: true, card }; }); }

  /** PATCH cards/<id> → { ok, card }; changed elsewhere: { ok: false, code: 'conflict', current }. */
  async updateCard(id, input) {
    try {
      return await this._run(async () => { const card = await this.api.updateCard(id, input || {}); await this._cardChanged(card); return { ok: true, card }; });
    } catch (err) {
      if (err && err.code === 'conflict') {
        const b = err.body && err.body.error && typeof err.body.error === 'object' ? err.body.error : {};
        return { ok: false, code: 'conflict', error: 'conflict', status: 409, current: mail.normalizeCard(b.current) };
      }
      throw err;
    }
  }

  async deleteCard(id) {
    return this._run(async () => {
      await this.api.deleteCard(id);
      await this.cache.dropCard(mail.posId(id));
      this._cardsStale = true;
      this.emit('contacts', { kind: 'changed', addressbookId: null, contactIds: [mail.posId(id)] });
      return { ok: true };
    });
  }

  /** A contact's photo → { ok, mime, url (data:) } (kept by its etag; offline the one kept). */
  async cardPhoto(id, etag = null) {
    const cid = mail.posId(id);
    if (!cid) throw new MailError('invalid id', { code: 'invalid' });
    const tag = typeof etag === 'string' && etag.length <= 120 ? etag : null;
    const out = (p) => ({ ok: true, mime: p.mime, url: `data:${p.mime};base64,${p.data}` });
    const hit = await this.cache.getPhoto(cid, tag);
    if (hit) return out(hit);
    if (this._photoWaiting.has(cid)) return this._photoWaiting.get(cid);
    const p = this._orCache(async () => {
      const ph = await this.api.cardPhoto(cid);
      await this.cache.putPhoto(cid, tag, ph);
      return out(ph);
    }, async () => {
      const ph = await this.cache.getPhoto(cid, null);
      return ph ? out(ph) : null;
    }).finally(() => this._photoWaiting.delete(cid));
    this._photoWaiting.set(cid, p);
    return p;
  }

  /** A picture of this PC as the contact's photo (file dialog; made 512 px JPEG) → { ok, card } | { ok: false, code: 'cancelled' }. */
  async setCardPhoto(id) {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new MailError('no dialog', { code: 'unsupported' });
    const cid = mail.posId(id);
    if (!cid) throw new MailError('invalid id', { code: 'invalid' });
    return this._run(async () => {
      const win = this.getMainWindow();
      const opts = { properties: ['openFile'], filters: [{ name: 'Bilder', extensions: ['jpg', 'jpeg', 'png', 'webp', 'bmp', 'gif'] }] };
      const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
      if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', cancelled: true };
      const photo = await this._photoFile(r.filePaths[0]);
      const card = await this.api.putCardPhoto(cid, photo);
      await this.cache.putPhoto(cid, card.photo ? card.photo.etag : null, { mime: photo.mime, data: photo.data.toString('base64') });
      await this._cardChanged(card);
      return { ok: true, card };
    });
  }

  /** A picture file → { mime, data } as JPEG of at most 512 px (nativeImage), else the file as it is when small enough. */
  async _photoFile(file) {
    const st = await fs.promises.stat(file);
    if (!st.isFile() || st.size <= 0 || st.size > 30 * 1024 * 1024) throw new MailError('not a picture', { code: 'invalid' });
    const buf = await fs.promises.readFile(file);
    if (this.nativeImage && typeof this.nativeImage.createFromBuffer === 'function') {
      let img = this.nativeImage.createFromBuffer(buf);
      if (img && !img.isEmpty()) {
        const { width, height } = img.getSize();
        if (width > PHOTO_PX || height > PHOTO_PX) {
          img = width >= height ? img.resize({ width: PHOTO_PX, quality: 'good' }) : img.resize({ height: PHOTO_PX, quality: 'good' });
        }
        for (const q of [85, 70, 55]) {
          const jpeg = img.toJPEG(q);
          if (jpeg.length && jpeg.length <= mail.PHOTO_MAX_BYTES) return { mime: 'image/jpeg', data: jpeg };
        }
      }
      throw new MailError('not a picture', { code: 'invalid' });
    }
    const mime = buf[0] === 0xFF && buf[1] === 0xD8 ? 'image/jpeg' : (buf.subarray(1, 4).toString() === 'PNG' ? 'image/png' : null);
    if (!mime) throw new MailError('not a picture', { code: 'invalid' });
    if (buf.length > mail.PHOTO_MAX_BYTES) throw new MailError('photo too large', { code: 'too_large' });
    return { mime, data: buf };
  }

  async deleteCardPhoto(id) {
    return this._run(async () => {
      const card = await this.api.deleteCardPhoto(id);
      await this._cardChanged(card);
      return { ok: true, card };
    });
  }

  /** The sender's page: GET cards/lookup → { ok, card, person, recent } (the card kept for offline). */
  async lookup(email) {
    return this._run(async () => {
      const r = await this.api.lookup(email);
      if (r.card) await this.cache.putCard(r.card);
      return { ok: true, ...r };
    });
  }

  async activity(id) { return this._run(async () => ({ ok: true, ...(await this.api.activity(id)) })); }

  async cardDraft(input) { return this._run(async () => ({ ok: true, ...(await this.api.cardDraft(input || {})) })); }

  async duplicates() { return this._run(async () => ({ ok: true, ...(await this.api.duplicates()) })); }

  async merge(input) {
    return this._run(async () => {
      const card = await this.api.merge(input || {});
      // others went or were linked: the whole list again
      await this.cache.resetCards();
      this._cardsStale = true;
      await this._cardChanged(card);
      return { ok: true, card };
    });
  }

  async ignoreDuplicates(ids) { return this._run(async () => this.api.ignoreDuplicates(ids)); }

  /** "vCard importieren": a .vcf of this PC (file dialog, ≤ 5 MB) → { ok, imported, updated, skipped } | { ok: false, code: 'cancelled' }. */
  async importVcf({ addressbookId = null } = {}) {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new MailError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const win = this.getMainWindow();
      const opts = { properties: ['openFile'], filters: [{ name: 'vCard', extensions: ['vcf', 'vcard'] }] };
      const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
      if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', cancelled: true };
      const st = await fs.promises.stat(r.filePaths[0]);
      if (!st.isFile() || st.size <= 0) throw new MailError('empty file', { code: 'empty' });
      if (st.size > mail.VCF_MAX_BYTES) throw new MailError('file too large', { code: 'too_large' });
      const vcf = (await fs.promises.readFile(r.filePaths[0])).toString('utf8').replace(/^\uFEFF/, '');
      if (!/BEGIN:VCARD/i.test(vcf)) throw new MailError('not a vCard', { code: 'invalid_vcard' });
      const out = await this.api.importVcf(vcf, addressbookId);
      this._cardsStale = true;
      this.emit('contacts', { kind: 'addressbooks' });
      return { ok: true, ...out };
    });
  }

  /** "vCard exportieren" ({ book, group }) → save dialog → { ok, path } | { ok: false, code: 'cancelled' }. */
  async exportVcf({ book = 'all', group = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new MailError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const out = await this.api.exportVcf({ book, group });
      const win = this.getMainWindow();
      const opts = { defaultPath: safeFileName(out.name, 'kontakte.vcf'), filters: [{ name: 'vCard', extensions: ['vcf'] }] };
      const r = win ? await this.dialog.showSaveDialog(win, opts) : await this.dialog.showSaveDialog(opts);
      if (!r || r.canceled || !r.filePath) return { ok: false, code: 'cancelled', cancelled: true };
      await fs.promises.writeFile(r.filePath, Buffer.from(out.data, 'base64'));
      return { ok: true, path: r.filePath };
    });
  }

  async _groupsChanged(fn) {
    const r = await this._run(fn);
    this._cardsStale = true;
    this.emit('contacts', { kind: 'groups' });
    return r;
  }

  async createGroup(input) { return this._groupsChanged(async () => ({ ok: true, group: await this.api.createGroup(input || {}) })); }

  async updateGroup(id, input) { return this._groupsChanged(async () => ({ ok: true, group: await this.api.updateGroup(id, input || {}) })); }

  async deleteGroup(id) { return this._groupsChanged(async () => this.api.deleteGroup(id)); }

  async group(id) { return this._run(async () => ({ ok: true, ...(await this.api.group(id)) })); }

  async groupMembers(id, input) { return this._groupsChanged(async () => ({ ok: true, ...(await this.api.groupMembers(id, input || {})) })); }

  /** "Anrufen": tel:<number> to the system (digits, + and the usual separators only). */
  async call(number) {
    const n = typeof number === 'string' ? number.trim() : '';
    if (!n || n.length > 40 || !/^\+?[0-9 ()/.-]{3,40}$/.test(n) || (n.match(/\d/g) || []).length < 3) throw new MailError('invalid number', { code: 'invalid' });
    if (!this.shell || typeof this.shell.openExternal !== 'function') throw new MailError('no shell', { code: 'unsupported' });
    const tel = `tel:${n.replace(/[^\d+]/g, '')}`;
    try {
      await this.shell.openExternal(tel);
      return { ok: true };
    } catch (err) {
      this.log.warn(`tel: not opened: ${err.message}`);
      return { ok: false, code: 'open_failed', error: 'no app for calls' };
    }
  }

  // ── Pictures of the reading frame (protocol gcmail:) ─────

  /**
   * gcmail://img/<token> | gcmail://cid/<message>/<attachment> → { status, mime, data } fetched with the client's
   * sign-in (kept in memory: 300 pictures / 30 MB); anything else 404.
   */
  async picture(url) {
    const target = mail.parseSchemeUrl(url);
    if (!target || this._state.state === 'unavailable') return { status: 404, mime: 'text/plain', data: Buffer.alloc(0) };
    this._ensureScope();
    const key = target.kind === 'img' ? `img/${target.token}` : `cid/${target.messageId}/${target.attachmentId}`;
    const hit = this._pictures.get(key);
    if (hit) {
      this._pictures.delete(key);
      this._pictures.set(key, hit);
      return { status: 200, mime: hit.mime, data: hit.data };
    }
    try {
      const p = await this.api.picture(target);
      this._pictures.set(key, p);
      this._pictureBytes += p.data.length;
      while (this._pictures.size > PICTURE_CACHE || this._pictureBytes > PICTURE_CACHE_BYTES) {
        const [k, v] = this._pictures.entries().next().value;
        this._pictures.delete(k);
        this._pictureBytes -= v.data.length;
      }
      return { status: 200, mime: p.mime, data: p.data };
    } catch (err) {
      this.log.debug(`Mail picture not loaded: ${err.code || err.message}`);
      const busy = mail.busyOf(err);
      if (busy && target.kind === 'cid') {
        // still on its way from the provider: the page asks again (after retryAfter or with the live event)
        this.emit('loading', { messageId: target.messageId, attachmentId: target.attachmentId, retryAfter: busy.retryAfter });
        return { status: 503, mime: 'text/plain', data: Buffer.alloc(0) };
      }
      return { status: err && err.status === 403 ? 403 : 404, mime: 'text/plain', data: Buffer.alloc(0) };
    }
  }

  // ── Account pictures ─────────────────────────────────────

  /** An account's picture (`Account.avatar`) → { ok, mime, url (data:) }, kept by its media id (a new picture has a new one). */
  async avatar(mediaId) {
    if (!mail.isMediaId(mediaId)) throw new MailError('invalid media id', { code: 'invalid' });
    return this._run(async () => {
      const hit = this._avatars.get(mediaId);
      if (hit) return { ok: true, ...hit };
      const acc = ((this._me && this._me.accounts) || []).find((a) => a.avatar && a.avatar.mediaId === mediaId);
      const p = await this.api.avatar(mediaId, acc ? acc.avatar.mime : null);
      const v = { mime: p.mime, url: `data:${p.mime};base64,${p.data.toString('base64')}` };
      this._avatars.set(mediaId, v);
      while (this._avatars.size > AVATAR_CACHE) this._avatars.delete(this._avatars.keys().next().value);
      return { ok: true, ...v };
    });
  }

  /** Electron protocol.handle('gcmail', (req) => mail.handleProtocol(req)) → a Response (no caching, no sniffing). */
  async handleProtocol(request) {
    const url = request && typeof request.url === 'string' ? request.url : '';
    const method = request && request.method ? String(request.method).toUpperCase() : 'GET';
    const r = method === 'GET' ? await this.picture(url) : { status: 405, mime: 'text/plain', data: Buffer.alloc(0) };
    return new Response(r.data, {
      status: r.status,
      headers: { 'Content-Type': r.mime, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'" },
    });
  }
}

MailService.SCHEME = mail.SCHEME;
MailService.SCHEME_PRIVILEGES = Object.freeze({ standard: true, secure: true, supportFetchAPI: false, corsEnabled: false, stream: false });

module.exports = MailService;
