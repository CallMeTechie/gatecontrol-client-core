'use strict';

/**
 * Medien-Plugin (Teilstufe W1): the sources of Medien from the GateControl server — the plugin `gatecontrol-medien`,
 * app API v1 (contract: plugin README "App-API v1"), over the device token of the existing ApiClient:
 *
 *   GET  /api/v1/client/plugins                          the plugin there, its `tab` (the entry "Medien" shows only then)
 *   GET  …/gatecontrol-medien/api/v1/sources[?since=rev]  the list the person sees now (no passwords)
 *   GET  …/v1/sources/{id}/secret                         a share's name and password (once per secretRev)
 *   POST …/v1/jellyfin/pair { sourceId, code }            the Quick Connect code of this PC confirmed by the plugin
 *   POST …/v1/jellyfin/paired { sourceId, jellyfinDeviceId }
 *   POST …/v1/shares/{id}/checked { protocol: 'smb', ok, problem? }
 *   POST …/v1/sources/{id}/report { way, ok, problem? }   the way to a source (only on a change)
 *   DELETE …/v1/jellyfin/device                           this PC signed out of Jellyfin ("Medien zurücksetzen")
 *   GET  /api/v1/client/home-network?local=…              at home? GateControl's home-network detection (homeNetwork())
 *
 * - When: at start, after a push reconnect, after the event `media.changed` (event `plugin` of the push stream), after
 *   the silent signal `media.revoke`, when Medien is opened (refresh()), else every 15 minutes — with `?since=<rev>`.
 * - The list is merged into MediaStore (utils/media-server.js merge: `managed: true`, the plugin's source ids), kept
 *   encrypted (safeStorage / DPAPI) with the plugin's last answer: without the server the last list counts. Sources set
 *   up on this PC before are taken over once when the server has the same (decision 33 a), the rest is removed and
 *   named in a note (`status().notice`).
 * - No setup on this PC: a Jellyfin source signs in by itself (pair(): Quick Connect with the device id and name of the
 *   list, the code to the plugin, never shown; Jellyfin's 401 → again without asking; `user.id` changed → again);
 *   a share's password comes from the plugin (secret, when `secretRev` is newer).
 * - Widerruf: `media.revoke` (signal topic media_signal, silent) or 403 no_access → the access, the password (and the
 *   stream addresses) of those sources go, then the list again. 404 plugin_unavailable / 403 license_required: hidden
 *   at once, everything of the server's sources deleted when it stays so for 24 h (decision 37 a).
 * - Offline (decision 36 a): `offlineHintDays` (30) without the list → a note; `maxOfflineDays` (90) → the NAS
 *   passwords on this PC are deleted.
 *
 * Events: 'state' (status()).
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');
const { PLUGINS_PATH } = require('../utils/messenger');
const MSV = require('../utils/media-server');
const MS = require('../utils/media-sources');

const DEFAULT_TIMING = Object.freeze({
  refreshMs: 15 * 60 * 1000,     // the list at the latest every 15 minutes
  retryMinMs: 10 * 1000,          // network errors: 10 s …
  retryMaxMs: 15 * 60 * 1000,     // … 15 min
  pairWaitMs: 60 * 1000,          // the plugin's confirmation holds for a minute
  pairPollMs: 1000,
  pairRetryMs: 2 * 60 * 1000,     // a failed sign-in is not tried again before (the plugin: 10 per hour)
  changedDelayMs: 300,            // several media.changed in a row → one list
});

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }
const no = (code, extra = {}) => ({ ok: false, code, ...extra });

class MediaServerSources extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.media - MediaService (its store, the way of the network rule, Quick Connect)
   * @param {object} [opts.apiClient] - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.pushClient] - PushClient: 'event' (media.changed), 'hello' (reconnect)
   * @param {object} [opts.notificationCenter] - NotificationCenter: the silent signal media.revoke (addPushHandler)
   * @param {object} [opts.api] - MessengerApi-compatible transport (_call) (tests)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing]
   * @param {(ms: number) => Promise<void>} [opts.sleep]
   */
  constructor({ media, apiClient = null, pushClient = null, notificationCenter = null, api = null, log = null, now = Date.now, timing = {}, sleep = null } = {}) {
    super();
    this.media = media;
    this.store = media.store;
    this.api = api || new MessengerApi({ apiClient, log });
    this.pushClient = pushClient;
    this.notificationCenter = notificationCenter;
    this.log = log || noopLog();
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.sleep = sleep || ((ms) => new Promise((r) => { const t = setTimeout(r, ms); if (t.unref) t.unref(); }));
    this._state = { state: 'unknown', reason: null };
    this._cache = null;
    this._refreshing = null;
    this._again = false;
    this._timer = null;
    this._changedTimer = null;
    this._retry = 0;
    this._started = false;
    this._unsub = [];
    this._pairing = new Map(); // id → Promise
    this._pairFails = new Map(); // id → { at, code }
    this._reports = new Map(); // `${sid}|${way}` → 'ok' | problem (sent)
    this._smbFails = new Set();
    media.setServerSources(this);
  }

  // ── lifecycle ───────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== MSV.PLUGIN_ID) return;
        if (ev.data.type === 'media.changed') this._changedSoon();
        else if (ev.data.type === 'media.revoke') this._job(this.revoke(MSV.revokeOf({ ...(ev.data.data || {}), kind: 'media.revoke' })));
      };
      const onHello = () => this._job(this.refresh());
      pc.on('event', onEvent);
      pc.on('hello', onHello);
      this._unsub.push(() => { pc.removeListener('event', onEvent); pc.removeListener('hello', onHello); });
    }
    const nc = this.notificationCenter;
    if (nc && typeof nc.addPushHandler === 'function') {
      this._unsub.push(nc.addPushHandler({ notification: (n) => this._onPush(n) }));
    }
    this._enforceTimes();
    this._job(this.refresh());
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    clearTimeout(this._changedTimer);
    this._timer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
  }

  /** Another server / person (MediaService.forgetAll): nothing of the old list is kept. */
  reset() {
    this._cache = null;
    this._reports.clear();
    this._pairFails.clear();
    this._smbFails.clear();
    this._setState('unknown', null);
    if (this._started) this._job(this.refresh({ full: true }));
  }

  _job(p) { Promise.resolve(p).catch((err) => this.log.debug(`Medien (Server): ${err && err.message}`)); }

  _changedSoon() {
    clearTimeout(this._changedTimer);
    this._changedTimer = setTimeout(() => this._job(this.refresh()), this.timing.changedDelayMs);
    if (this._changedTimer.unref) this._changedTimer.unref();
  }

  _schedule(ms) {
    clearTimeout(this._timer);
    this._timer = null;
    if (!this._started) return;
    this._timer = setTimeout(() => this._job(this.refresh()), ms);
    if (this._timer.unref) this._timer.unref();
  }

  // ── the cache (MediaStore serverCache: encrypted) ───────────

  cache() {
    if (!this._cache) this._cache = this.store.serverCache() || {};
    return this._cache;
  }

  _saveCache(patch) {
    this._cache = { ...this.cache(), ...patch };
    try { this.store.setServerCache(this._cache); } catch (err) { this.log.warn(`Medien: server list not kept (${err.message})`); }
  }

  /**
   * At home? (MediaService._home) GateControl's own home-network detection, asked now: GET /api/v1/client/home-network
   * with this PC's private LAN addresses (`local`, at most four, never the VPN adapter's) → true / false
   * (utils/media-server.js homeNetworkOf; any failure: false).
   */
  async homeNetwork({ local = [], tunnelUp = false } = {}) {
    const list = Array.isArray(local) ? local.filter((a) => typeof a === 'string' && a).slice(0, 4) : [];
    try {
      const raw = await this.api._call('GET', MSV.HOME_NETWORK_PATH, { params: list.length ? { local: list.join(',') } : undefined, timeout: 5000 });
      return MSV.homeNetworkOf(raw, { tunnelUp });
    } catch (err) {
      this.log.debug(`Medien: home network not known (${(err && (err.code || err.status)) || 'failed'})`);
      return false;
    }
  }

  /** The plugin's home probes (kept with the list; they do not decide "at home": homeNetwork()). */
  probes() {
    const n = this.cache().network;
    return n && Array.isArray(n.probes) ? n.probes : [];
  }

  // ── status ──────────────────────────────────────────────────

  /**
   * { state: 'unknown' | 'available' | 'unavailable' | 'error', reason, visible (the entry "Medien": the plugin gives a
   *   `tab` and is usable), tab, version, media (the person's right), rev, fetchedAt, lastContactAt, offline: { days,
   *   hint, expired }, unavailableSince, network: { rule, vpnRequiredAway }, cast, notice: { adopted, dropped, at } }
   */
  status() {
    const c = this.cache();
    const plugin = c.plugin || { installed: false, tab: null, version: null };
    const unavailable = !!c.unavailableSince;
    const off = MSV.offline(this.now(), c.lastContactAt, c.offlineHintDays, c.maxOfflineDays);
    return {
      state: this._state.state,
      reason: this._state.reason,
      visible: !!plugin.tab && !unavailable && c.media !== false,
      tab: plugin.tab || null,
      version: plugin.version || null,
      media: c.media !== false,
      rev: c.rev || null,
      fetchedAt: c.fetchedAt || null,
      lastContactAt: c.lastContactAt || null,
      offline: off,
      unavailableSince: c.unavailableSince || null,
      network: c.network ? { rule: c.network.rule, vpnRequiredAway: c.network.vpnRequiredAway === true } : null,
      cast: { enabled: !!(c.cast && c.cast.enabled) },
      notice: c.notice || null,
    };
  }

  _setState(state, reason) {
    const before = JSON.stringify(this.status());
    this._state = { state, reason: reason || null };
    if (JSON.stringify(this.status()) !== before) this._emitState();
  }

  _emitState() {
    const st = this.status();
    this.emit('state', st);
    this.media.emit('server', st);
    this.media._emitState();
  }

  // ── the list ────────────────────────────────────────────────

  /** The list now (`full`: without ?since) → status(). One at a time; asked again meanwhile → once more after it. */
  refresh({ full = false } = {}) {
    if (this._refreshing) {
      this._again = true;
      return this._refreshing;
    }
    this._refreshing = this._refresh(full).finally(() => {
      this._refreshing = null;
      if (this._again) { this._again = false; this._job(this.refresh()); }
    });
    return this._refreshing;
  }

  async _refresh(full) {
    let next = this.timing.refreshMs;
    try {
      const plugin = await this._plugin();
      if (!plugin) { next = this._retryMs(); return this.status(); }
      if (!plugin.installed) { this._unavailable('not_installed'); return this.status(); }
      const c = this.cache();
      let raw;
      try {
        raw = await this.api._call('GET', `${MSV.API_BASE}v1/sources`, { params: !full && c.rev ? { since: c.rev } : undefined });
      } catch (err) {
        const kind = MSV.refusalOf(err);
        if (kind === 'unavailable') { this._unavailable(err.code === 'license_required' ? 'license_required' : 'plugin_unavailable'); return this.status(); }
        this._setState('error', err.code || 'network');
        next = this._retryMs();
        return this.status();
      }
      const list = MSV.normalizeList(raw);
      if (!list) { this._setState('error', 'invalid'); next = this._retryMs(); return this.status(); }
      this._retry = 0;
      const now = this.now();
      if (list.unchanged) {
        this._saveCache({ lastContactAt: now, fetchedAt: now, unavailableSince: null });
      } else {
        this._apply(list, now);
      }
      this._setState('available', null);
      this._emitState();
      await this._secrets();
      this._job(this._pairAll());
      return this.status();
    } finally {
      this._enforceTimes();
      this._schedule(next);
    }
  }

  _retryMs() {
    const ms = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
    this._retry = Math.min(this._retry + 1, 10);
    return ms;
  }

  /** GET /api/v1/client/plugins → { installed, tab, version } (kept), null on a network error. */
  async _plugin() {
    let data;
    try {
      data = await this.api._call('GET', PLUGINS_PATH);
    } catch (err) {
      if (err && err.status === 404) data = { plugins: [] }; // a server without the route
      else {
        this._setState('error', (err && err.code) || 'network');
        return null;
      }
    }
    const plugin = MSV.pluginOf(data);
    this._saveCache({ plugin });
    return plugin;
  }

  /** The server's list merged in: kept, new, gone, taken over (decision 33 a). */
  _apply(list, now) {
    const before = this.store.sources();
    const m = MSV.merge(before, list.sources);
    for (const a of m.adopted) if (a.kind !== 'jellyfin' && a.from !== a.to) this.store.moveProgress(a.from, a.to);
    this.store.replaceAll(m.list);
    const goneIds = m.removed.map((x) => x.id).concat(m.dropped.map((x) => x.id)).filter((id) => !m.list.some((x) => x.id === id));
    if (goneIds.length) this.store.removeMany(goneIds);
    const changedIds = new Set([...goneIds, ...m.repair, ...m.adopted.map((a) => a.from)]);
    this.media.sourcesChanged([...changedIds]);
    for (const x of m.logout) this._job(this.media.logoutOld(x));
    const notice = m.adopted.length || m.dropped.length
      ? { adopted: m.adopted.map((a) => ({ id: a.to, name: a.name, kind: a.kind })), dropped: m.dropped, at: now }
      : this.cache().notice || null;
    for (const id of m.repair) this._pairFails.delete(id);
    this._saveCache({
      rev: list.rev, at: list.at, fetchedAt: now, lastContactAt: now, unavailableSince: null, media: list.media,
      maxOfflineDays: list.maxOfflineDays, offlineHintDays: list.offlineHintDays, network: list.network, cast: list.cast, notice,
    });
    if (m.adopted.length || m.dropped.length) this.log.info(`Medien: ${m.adopted.length} source(s) taken over by the server's, ${m.dropped.length} removed`);
  }

  /** 404 plugin_unavailable / 403 license_required / not installed: hidden at once, deleted after 24 h (37 a). */
  _unavailable(reason) {
    const c = this.cache();
    this._saveCache({ unavailableSince: c.unavailableSince || this.now() });
    this._setState('unavailable', reason);
    this._enforceTimes();
  }

  /** The 24 hours of 37 a and the 90 days of 36 a. */
  _enforceTimes() {
    const c = this.cache();
    const now = this.now();
    if (c.unavailableSince && now - c.unavailableSince >= MSV.UNAVAILABLE_GRACE_MS) {
      const ids = this.store.sources().filter((x) => x.managed).map((x) => x.id);
      if (ids.length) {
        this.log.info('Medien: the plugin has been unavailable for 24 h — its sources and their access are deleted');
        try { this.store.removeMany(ids); } catch (err) { this.log.warn(`Medien: not deleted (${err.message})`); }
        this.media.sourcesChanged(ids);
      }
      if (c.rev || c.network) this._saveCache({ rev: null, network: null, notice: null });
    }
    const off = MSV.offline(now, c.lastContactAt, c.offlineHintDays, c.maxOfflineDays);
    if (off.expired) {
      const withPw = this.store.sources().filter((x) => x.managed && MS.isShare(x.kind) && x.password);
      if (withPw.length) {
        this.log.info(`Medien: ${off.days} days without the server — the NAS passwords on this PC are deleted`);
        for (const x of withPw) { try { this.store.update(x.id, { password: null, pwRev: null }); } catch { /* kept */ } }
        this.media.sourcesChanged(withPw.map((x) => x.id));
      }
    }
  }

  // ── a share's password ──────────────────────────────────────

  /** GET secret for every share whose password is missing or older than secretRev. */
  async _secrets() {
    const need = new Map();
    for (const x of this.store.sources()) {
      if (!x.managed || !MS.isShare(x.kind) || !x.userName) continue;
      if (x.password && x.pwRev === x.secretRev) continue;
      need.set(x.sid, true);
    }
    for (const sid of need.keys()) await this.secret(sid);
  }

  /** The password of share `sid` from the plugin → { ok } (no_access: the source is removed). */
  async secret(sid) {
    let r;
    try {
      r = await this.api._call('GET', `${MSV.API_BASE}v1/sources/${encodeURIComponent(sid)}/secret`);
    } catch (err) {
      if (MSV.refusalOf(err) === 'no_access') { this.dropSource(sid); return no('no_access'); }
      this.log.debug(`Medien: password of ${sid} not fetched (${err.code})`);
      return no(err.code || 'failed');
    }
    const password = r && typeof r.password === 'string' ? r.password : null;
    const user = r && typeof r.user === 'string' && r.user.trim() ? r.user.trim().slice(0, 128) : null;
    const rev = r && Number.isSafeInteger(r.rev) ? r.rev : null;
    if (password === null) return no('failed');
    for (const x of this.store.sources()) {
      if (x.sid !== sid || !MS.isShare(x.kind)) continue;
      this.store.update(x.id, { password, userName: user || x.userName, pwRev: rev !== null ? rev : x.secretRev, ...(rev !== null ? { secretRev: Math.max(rev, x.secretRev || 0) } : {}) });
    }
    this.media.sourcesChanged(this.store.sources().filter((x) => x.sid === sid).map((x) => x.id));
    return { ok: true };
  }

  // ── Jellyfin: signed in by itself (Quick Connect, confirmed by the plugin) ──

  /**
   * Every Jellyfin source without access signed in. In the background the VPN is not started (`startVpn` false: away
   * it waits for Medien to be opened); opening Medien (MediaService.serverRefresh) starts it when the rule needs it.
   */
  async pairPending({ startVpn = false } = {}) {
    const out = [];
    for (const x of this.store.sources()) {
      if (x.managed && x.kind === 'jellyfin' && !x.token && !x.problem && x.jfDeviceId) out.push({ id: x.id, ...(await this.pair(x.id, { startVpn })) });
    }
    return out;
  }

  _pairAll() { return this.pairPending({ startVpn: false }); }

  /**
   * Sign source `id` in (contract "Ablauf A"): Quick Connect with the device id and name of the list (URL-encoded
   * header), the code to v1/jellyfin/pair (never shown), Jellyfin asked until it is confirmed, the access of this PC
   * (AuthenticateWithQuickConnect, kept under DPAPI), then v1/jellyfin/paired. code_invalid / an expired request /
   * device_mismatch: once more. → { ok } | { ok: false, code }. Starts the VPN only with `startVpn` (opening Medien).
   */
  pair(id, { startVpn = false } = {}) {
    if (this._pairing.has(id)) return this._pairing.get(id);
    const fail = this._pairFails.get(id);
    if (fail && this.now() - fail.at < this.timing.pairRetryMs) return Promise.resolve(no(fail.code));
    const p = this._pair(id, startVpn).then((r) => {
      if (r.ok) this._pairFails.delete(id);
      else if (r.code !== 'vpn_required') this._pairFails.set(id, { at: this.now(), code: r.code });
      return r;
    }).finally(() => this._pairing.delete(id));
    this._pairing.set(id, p);
    return p;
  }

  async _pair(id, startVpn) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const src = this.store.source(id);
      if (!src || !src.managed || src.kind !== 'jellyfin') return no('not_found');
      if (src.token) return { ok: true };
      if (src.problem) return no(src.problem);
      if (!src.jfDeviceId) return no('no_device');
      const b = await this.media._ready(id, { startVpn });
      if (b) return b;
      const si = this.media.signInClient(id);
      const q = await si.quickConnect();
      if (!q.ok) {
        if (q.code === 'unauthorized') { this._problem(id, 'quick_connect_off'); return no('quick_connect_off'); }
        return no(q.code);
      }
      try {
        await this.api._call('POST', `${MSV.API_BASE}v1/jellyfin/pair`, { body: { sourceId: src.sid, code: q.value.code } });
      } catch (err) {
        const kind = MSV.refusalOf(err);
        if (err.code === 'code_invalid' && attempt === 0) continue;
        if (err.code === 'device_mismatch' && attempt === 0) { await this.refresh({ full: true }); continue; }
        if (kind === 'no_access') { this.dropSource(src.sid); return no('no_access'); }
        if (kind === 'unavailable') { this._unavailable(err.code); return no(err.code); }
        if (kind === 'problem') this._problem(id, err.code);
        return no(err.code || 'failed');
      }
      // Jellyfin: confirmed? (the plugin's confirmation holds for a minute)
      const until = this.now() + this.timing.pairWaitMs;
      let confirmed = false;
      let expired = false;
      while (this.now() < until) {
        const c = await si.confirmed(q.value);
        if (c.ok && c.value) { confirmed = true; break; }
        if (!c.ok && (c.code === 'unauthorized' || c.code === 'not_found')) { expired = true; break; }
        if (!c.ok && c.code === 'vpn_required') return no('vpn_required');
        await this.sleep(this.timing.pairPollMs);
      }
      if (!confirmed) {
        if (attempt === 0) continue;
        return no(expired ? 'expired' : 'timeout');
      }
      const a = await si.signInQuick(q.value);
      if (!a.ok) {
        if (attempt === 0) continue;
        return no(a.code);
      }
      const now = this.store.source(id);
      if (!now) return no('not_found');
      this.store.update(id, { token: a.value.token, userId: a.value.userId, userName: a.value.userName, pairedUserId: now.mapUserId || a.value.userId });
      this.media.sourcesChanged([id]);
      // signed in: the way once more (away the line is measured now, with the access)
      if (this.media.link(id).atHome === false) this._job(this.media.check(id, { force: true }));
      this.log.info(`Medien: signed in at Jellyfin (${src.sid}) as the linked user`);
      try {
        await this.api._call('POST', `${MSV.API_BASE}v1/jellyfin/paired`, { body: { sourceId: src.sid, jellyfinDeviceId: src.jfDeviceId } });
      } catch (err) { this.log.debug(`Medien: paired not told (${err.code})`); }
      return { ok: true };
    }
    return no('failed');
  }

  _problem(id, code) {
    try { this.store.update(id, { problem: code }); } catch { /* kept */ }
    this.media._emitState();
  }

  // ── Widerruf ────────────────────────────────────────────────

  _onPush(n) {
    if (!MSV.isSignal(n)) return false;
    const r = MSV.revokeOf(n && n.data);
    if (r) {
      this._job(this.revoke(r));
      return 'consumed';
    }
    return false;
  }

  /**
   * media.revoke { sourceIds | null, reason }: the Jellyfin access, the passwords (and the stream addresses) of those
   * sources go (the plugin deleted this PC in Jellyfin already), then the whole list again — still allowed, the source
   * signs in anew.
   */
  async revoke(r) {
    if (!r) return this.status();
    const all = r.sourceIds === null;
    const ids = [];
    for (const x of this.store.sources()) {
      if (!x.managed || (!all && !r.sourceIds.includes(x.sid))) continue;
      ids.push(x.id);
      try {
        this.store.update(x.id, x.kind === 'jellyfin' ? { token: null, userId: null, userName: null, pairedUserId: null } : { password: null, pwRev: null, checkedRev: null });
      } catch { /* kept */ }
      this._pairFails.delete(x.id);
    }
    this.log.info(`Medien: access withdrawn by the server (${r.reason}, ${all ? 'all sources' : r.sourceIds.join(', ')})`);
    this.media.sourcesChanged(ids);
    return this.refresh({ full: true });
  }

  /** 403 no_access for one source: it is not the person's any more — it goes with its access and progress. */
  dropSource(sid) {
    const ids = this.store.sources().filter((x) => x.managed && x.sid === sid).map((x) => x.id);
    if (!ids.length) return;
    try { this.store.removeMany(ids); } catch (err) { this.log.warn(`Medien: source not removed (${err.message})`); }
    this.media.sourcesChanged(ids);
  }

  // ── reports to the plugin ───────────────────────────────────

  /** The way to source `sid` (home / away) — sent only when it changed. */
  report(sid, way, ok, problem = null) {
    const key = `${sid}|${way}`;
    const v = ok ? 'ok' : String(problem || 'failed');
    if (this._reports.get(key) === v) return;
    this._reports.set(key, v);
    this._job(this.api._call('POST', `${MSV.API_BASE}v1/sources/${encodeURIComponent(sid)}/report`, { body: { way, ok: ok === true, ...(ok ? {} : { problem: v }) } })
      .catch((err) => { this._reports.delete(key); throw err; }));
  }

  /** The first SMB sign-in with the plugin's password → "SMB geprüft" on the plugin's pages (once per password). */
  smbChecked(entryId, ok, problem = null) {
    const x = this.store.source(entryId);
    if (!x || !x.managed || x.kind !== 'smb' || !x.password || !Number.isSafeInteger(x.pwRev)) return;
    if (ok && x.checkedRev === x.pwRev) return;
    const failKey = `${entryId}|${x.pwRev}`;
    if (!ok && this._smbFails.has(failKey)) return;
    if (ok) { try { this.store.update(entryId, { checkedRev: x.pwRev }); } catch { /* kept */ } } else this._smbFails.add(failKey);
    this._job(this.api._call('POST', `${MSV.API_BASE}v1/shares/${encodeURIComponent(x.sid)}/checked`, { body: { protocol: 'smb', ok: ok === true, ...(ok ? {} : { problem: String(problem || 'failed') }) } }));
  }

  /** "Medien zurücksetzen" / the app signed out: the plugin deletes this PC in Jellyfin (all its access). */
  async signOutDevice() {
    try {
      await this.api._call('DELETE', `${MSV.API_BASE}v1/jellyfin/device`);
      return { ok: true };
    } catch (err) {
      return no(err.code || 'failed');
    }
  }
}

MediaServerSources.DEFAULT_TIMING = DEFAULT_TIMING;

module.exports = MediaServerSources;
