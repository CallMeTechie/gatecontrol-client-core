'use strict';

/**
 * Medien (Stufe 4e, Windows: Medien-Kern): Jellyfin and the NAS shares of this PC — the services the pages of 4f
 * (Medien, Quellen), the player of 4g and the folders of 4h build on. No page here.
 *
 * Decisions of Stufe 4 (21–29 a): Jellyfin first, at home straight from the NAS, away through the own tunnel; away
 * converted only when the measured bandwidth needs it ("immer Original" per source); the progress lives in Jellyfin
 * (all devices), a share's progress on this PC; a share at home over SMB, away over WebDAV (one pair); every device
 * signs in on its own (its own Jellyfin device id, "Gerät anmelden" confirms the Quick Connect code of another one);
 * the access encrypted on this PC (DPAPI) — nothing of it goes to the GateControl server or the page.
 *
 * The way (Netzwahl, check()): a source is "at home" when its host lies in the subnet of a real LAN adapter of this
 * PC and answers there — bound to that adapter's address (Jellyfin: its server id checked, so a hotel's 192.168.1.x
 * is not taken for home). Then every connection is bound to the LAN address, and for SMB (Windows' own redirector)
 * the route is checked and, where the tunnel would carry the NAS, a host route through the LAN set (Plan B,
 * services/media-lan-route.js). Away: through the tunnel, the bandwidth measured (every 5 minutes at most).
 *
 * Every method resolves { ok: true, … } or { ok: false, code, … }; nothing throws to the IPC.
 */

const EventEmitter = require('events');
const os = require('os');
const crypto = require('crypto');
const J = require('../utils/media-jellyfin');
const MA = require('../utils/media-address');
const MQ = require('../utils/media-quality');
const MT = require('../utils/media-tracks');
const MS = require('../utils/media-sources');
const MSH = require('../utils/media-share');
const MP = require('../utils/media-playable');
const L = require('../utils/media-lan');
const { normalizeFingerprint } = require('../utils/home-cache');
const MediaNet = require('./media-net');
const MediaDiscovery = require('./media-discovery');
const MediaLanRoute = require('./media-lan-route');
const MediaStreamService = require('./media-stream');
const { JellyfinClient, JellyfinLibrary, JellyfinSignIn, idOk } = require('./media-jellyfin');
const { SmbShare, WebDavShare } = require('./media-share');

const DEFAULT_TIMING = Object.freeze({
  measureEveryMs: 5 * 60 * 1000, homeProbeMs: 2500, quickConnectMs: 10 * 60 * 1000, sniffBytes: 2 * 1024 * 1024, moovBytes: 8 * 1024 * 1024,
});
const MAX_FLOWS = 4;
const MAX_PLAYS = 8;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }
const no = (code, extra = {}) => ({ ok: false, code, ...extra });

class MediaService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.store - MediaStore
   * @param {string} [opts.client] - the app's name for Jellyfin ('GateControl Pro')
   * @param {string} [opts.version] - the app's version
   * @param {() => string} [opts.deviceName] - this PC's name in Jellyfin's device list (os.hostname())
   * @param {() => object} [opts.networkInterfaces] - os.networkInterfaces (tests)
   * @param {object} [opts.net] - MediaNet
   * @param {object} [opts.discovery] - MediaDiscovery
   * @param {object} [opts.lanRoute] - MediaLanRoute (Windows: GetBestRoute2, host routes)
   * @param {object} [opts.shares] - { smb(source) → SmbShare, webdav(source, way) → WebDavShare } (tests)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing]
   */
  constructor({
    store, client = 'GateControl Pro', version = '0.0.0', deviceName = null, networkInterfaces = os.networkInterfaces,
    net = null, discovery = null, lanRoute = null, shares = null, log = null, now = Date.now, timing = {},
  }) {
    super();
    this.store = store;
    this.appName = client;
    this.version = version;
    this.deviceName = typeof deviceName === 'function' ? deviceName : () => os.hostname();
    this.networkInterfaces = networkInterfaces;
    this.log = log || noopLog();
    this.net = net || new MediaNet({ log: this.log });
    this.discovery = discovery || new MediaDiscovery({ networkInterfaces, log: this.log });
    this.lanRoute = lanRoute || new MediaLanRoute({ log: this.log });
    this.shareFactory = shares || {
      smb: (source) => new SmbShare({ source, log: this.log }),
      webdav: (source, way) => new WebDavShare({ source, net: this.net, way, log: this.log }),
    };
    this.now = now;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this._caps = J.capsOf({}, this.appName);
    this._links = new Map();   // source id → { atHome, via, localAddress, bps, measuredAt, checkedAt, route }
    this._pins = new Map();    // origin → fingerprint, confirmed in the sign-in before a source exists
    this._flows = new Map();   // Quick Connect of this PC: flow → { address, q, server, exp }
    this._plays = new Map();   // play id → { sourceId, kind, plan | path, library }
    this._shares = new Map();  // `${id}|${atHome}` → SmbShare / WebDavShare
    this._checking = new Map();
    this.stream = new MediaStreamService({
      jellyfin: (id) => this._client(id),
      share: (id) => this._shareFor(id),
      log: this.log,
      now,
    });
  }

  // ── who and how ─────────────────────────────────────────────

  info() {
    let device = 'PC';
    try { device = String(this.deviceName() || 'PC').slice(0, 64); } catch { /* PC */ }
    return { client: this.appName, device, deviceId: this.store.deviceId(), version: this.version };
  }

  _ifaces() {
    try { return this.networkInterfaces() || {}; } catch { return {}; }
  }

  link(id) { return this._links.get(id) || { atHome: null, via: null, localAddress: null, bps: null, measuredAt: 0, checkedAt: 0, route: null }; }

  /**
   * The way of a source's connections now: at home bound to the LAN address (found by check()), away bound to the
   * tunnel's own address (a hotel's network with the home's addresses never gets the access); while a source is set
   * up (no id yet) the LAN when its host is in it.
   */
  _way(src) {
    const pin = src.tlsPin || this._pinOf(src.address);
    const l = src.id ? this.link(src.id) : { atHome: null };
    if (l.atHome === true) return { localAddress: l.localAddress, pin };
    if (l.atHome === false) return { localAddress: L.tunnelAddress(this._ifaces()), pin };
    const b = src.id ? null : L.lanBinding(MA.host(src.address), this._ifaces());
    return { localAddress: b ? b.localAddress : null, pin };
  }

  _pinOf(address) {
    try { return this._pins.get(new URL(address).origin) || null; } catch { return null; }
  }

  _client(id, { token = true } = {}) {
    const src = this.store.source(id);
    if (!src || src.kind !== 'jellyfin') return null;
    return new JellyfinClient({ base: src.address, info: this.info(), token: token ? src.token : null, net: this.net, way: () => this._way(src), log: this.log });
  }

  _library(id) {
    const src = this.store.source(id);
    if (!src || src.kind !== 'jellyfin' || !src.token) return null;
    return new JellyfinLibrary({ source: src, client: this._client(id), caps: () => this._caps, log: this.log });
  }

  _signInClient(address) {
    const src = { id: '', address, tlsPin: this._pinOf(address) };
    return new JellyfinClient({ base: address, info: this.info(), net: this.net, way: () => this._way(src), log: this.log });
  }

  /** A share's files now: of a pair at home the SMB source, away the WebDAV one (the titles stay under `id`). */
  _shareFor(id) {
    const src = this.store.source(id);
    if (!src || !MS.isShare(src.kind)) return null;
    const pair = MS.pairOf(src, this.store.sources());
    const atHome = this.link(id).atHome;
    const use = MS.shareFor(pair.smb, pair.webdav, atHome) || src;
    const key = `${use.id}|${use.address}|${use.userName || ''}|${crypto.createHash('sha256').update(String(use.password || '')).digest('hex').slice(0, 16)}|${use.tlsPin || ''}|${atHome}`;
    let s = this._shares.get(key);
    if (!s) {
      s = use.kind === 'smb' ? this.shareFactory.smb(use) : this.shareFactory.webdav(use, () => this._way(use));
      this._shares.set(key, s);
    }
    return s;
  }

  _dropShares(id = null) {
    for (const [k, s] of this._shares) {
      if (id === null || k.startsWith(`${id}|`)) { this._shares.delete(k); Promise.resolve(s.close()).catch(() => {}); }
    }
  }

  // ── status ──────────────────────────────────────────────────

  _publicSource(s) {
    const l = this.link(s.id);
    return { ...MS.publicSource(s), link: { atHome: l.atHome, via: l.via, bps: l.bps, measuredAt: l.measuredAt || null, route: l.route } };
  }

  status() {
    const all = this.store.sources();
    const visible = all.filter((s) => s.kind === 'jellyfin').concat(MS.shares(all));
    return {
      ok: true,
      supported: this.store.canProtect(),
      deviceName: this.info().device,
      quality: this.store.quality(),
      caps: this._caps,
      sources: visible.map((s) => this._publicSource(s)),
    };
  }

  _emitState() { this.emit('state', this.status()); }

  /** What the page's Chromium plays (canPlayType / MediaCapabilities of the renderer, 4g). */
  setCaps(probe) {
    this._caps = J.capsOf(probe, this.appName);
    return { ok: true, caps: this._caps };
  }

  setQuality(v) { return { ok: true, quality: this.store.setQuality(v) }; }

  // ── the way: home or away ───────────────────────────────────

  /** Home or away now for source `id`, away the bandwidth (at most every 5 minutes unless `force`). */
  async check(id, { force = false } = {}) {
    if (this._checking.has(id)) return this._checking.get(id);
    const p = this._check(id, force).finally(() => this._checking.delete(id));
    this._checking.set(id, p);
    return p;
  }

  async _check(id, force) {
    const src = this.store.source(id);
    if (!src) return no('not_found');
    const pair = MS.isShare(src.kind) ? MS.pairOf(src, this.store.sources()) : null;
    const homeSrc = pair ? (pair.smb || pair.webdav) : src;
    const host = MA.host(homeSrc.address);
    const bind = L.lanBinding(host, this._ifaces());
    const old = this.link(id);
    let atHome = false;
    if (bind) atHome = await this._probeHome(homeSrc, bind.localAddress);
    const now = this.now();
    let next;
    if (atHome) {
      const route = await this._route(homeSrc, host, bind.localAddress);
      next = { atHome: true, via: 'lan', localAddress: bind.localAddress, bps: null, measuredAt: 0, checkedAt: now, route };
    } else {
      const fresh = old.atHome === false && old.bps && now - old.measuredAt < this.timing.measureEveryMs;
      let bps = old.atHome === false ? old.bps : null;
      let measuredAt = old.atHome === false ? old.measuredAt : 0;
      if ((force || !fresh) && src.kind === 'jellyfin' && src.token) {
        this._links.set(id, { ...old, atHome: false, via: 'tunnel', localAddress: null });
        const m = await this._library(id).measure();
        if (m) { bps = m; measuredAt = now; }
      }
      next = { atHome: false, via: 'tunnel', localAddress: null, bps, measuredAt, checkedAt: now, route: null };
    }
    if (old.atHome !== next.atHome) { this._dropShares(id); this.net.reset(); }
    this._links.set(id, next);
    this.emit('link', { sourceId: id, link: next });
    return { ok: true, link: next };
  }

  /** The source answers at its LAN address bound to this PC's LAN adapter (Jellyfin: the same server). */
  async _probeHome(src, localAddress) {
    const host = MA.host(src.address);
    if (src.kind === 'jellyfin') {
      const c = new JellyfinClient({ base: src.address, info: this.info(), net: this.net, way: () => ({ localAddress, pin: src.tlsPin }), log: this.log });
      const r = await c.call('GET', 'System/Info/Public', {}, undefined, { timeout: this.timing.homeProbeMs });
      const s = r.ok && r.value && typeof r.value === 'object' ? J.serverInfo(r.value) : null;
      return !!s && (!src.serverId || s.id === src.serverId);
    }
    return this.net.reachable(host, MA.portOf(src.kind, src.address), { localAddress, timeoutMs: this.timing.homeProbeMs });
  }

  /** How the NAS is reached at home (the spike): bound HTTP holds? SMB through the tunnel → the host route (Plan B). */
  async _route(src, host, localAddress) {
    if (!this.lanRoute || !this.lanRoute.supported || !MA.isPrivateIpv4(host)) return null;
    const d = this.lanRoute.diagnose(host, localAddress);
    const needsRoute = d.tunnel && (src.kind === 'smb' || !d.bindingHolds);
    if (!needsRoute) return { tunnel: !!d.tunnel, bindingHolds: !!d.bindingHolds, hostRoute: false };
    const r = await this.lanRoute.ensureHostRoute(host, localAddress);
    return { tunnel: true, bindingHolds: !!d.bindingHolds, hostRoute: r.ok && r.added === true, hostRouteFailed: !r.ok };
  }

  /** The network changed (another Wi-Fi, the tunnel up or down): home and away are found again. */
  networkChanged() {
    this._links.clear();
    this._dropShares();
    this.net.reset();
    this._emitState();
    return { ok: true };
  }

  async measure(id) { return this.check(id, { force: true }); }

  // ── Quellen: the server search, Jellyfin, shares ────────────

  async discover() {
    try { return { ok: true, servers: await this.discovery.discover() }; } catch { return { ok: true, servers: [] }; }
  }

  async _certificateOf(address) {
    try {
      const src = { id: '', address };
      return await this.net.certificate(address, { localAddress: this._way(src).localAddress });
    } catch { return null; }
  }

  /** "Zertifikat der NAS einmal bestätigen": the certificate the person saw is trusted for that server from now on. */
  trust({ address, fingerprint }) {
    const fp = normalizeFingerprint(fingerprint);
    let origin;
    try { origin = new URL(address).origin; } catch { return no('invalid'); }
    if (!fp || !origin.startsWith('https://')) return no('invalid');
    this._pins.set(origin, fp);
    for (const s of this.store.sources()) {
      try { if (new URL(s.address).origin === origin) this.store.update(s.id, { tlsPin: fp }); } catch { /* skip */ }
    }
    this.net.reset();
    return { ok: true };
  }

  /** A Jellyfin server typed or found → its name, version and whether Quick Connect is on. */
  async server(input) {
    const address = MA.normalize(String(input || ''));
    if (!address) return no('invalid');
    const si = new JellyfinSignIn({ client: this._signInClient(address) });
    const r = await si.server();
    if (!r.ok) {
      if (r.code === 'cert_untrusted' || r.code === 'cert_changed') return no(r.code, { address, certificate: await this._certificateOf(address) });
      return no(r.code, { address });
    }
    if (!r.value.supported) return no('unsupported_version', { address, server: r.value });
    return { ok: true, address, server: r.value, quickConnect: await si.quickConnectEnabled() };
  }

  /** Quick Connect of this PC: the code to confirm in Jellyfin or on another GateControl device. */
  async quickConnectStart(input) {
    const address = MA.normalize(String(input || ''));
    if (!address) return no('invalid');
    const si = new JellyfinSignIn({ client: this._signInClient(address) });
    const s = await si.server();
    if (!s.ok) return no(s.code);
    const q = await si.quickConnect();
    if (!q.ok) return no(q.code === 'unauthorized' ? 'quick_connect_off' : q.code);
    for (const [k, f] of this._flows) if (f.exp <= this.now()) this._flows.delete(k);
    while (this._flows.size >= MAX_FLOWS) this._flows.delete(this._flows.keys().next().value);
    const flow = crypto.randomBytes(12).toString('base64url');
    this._flows.set(flow, { address, q: q.value, server: s.value, exp: this.now() + this.timing.quickConnectMs });
    return { ok: true, flow, code: q.value.code, server: s.value };
  }

  /** Confirmed yet? → { ok, state: 'waiting' } | { ok, state: 'done', source }. */
  async quickConnectPoll(flow) {
    const f = typeof flow === 'string' ? this._flows.get(flow) : null;
    if (!f) return no('not_found');
    if (f.exp <= this.now()) { this._flows.delete(flow); return no('expired'); }
    const si = new JellyfinSignIn({ client: this._signInClient(f.address) });
    const c = await si.confirmed(f.q);
    if (!c.ok && (c.code === 'unauthorized' || c.code === 'not_found')) {
      this._flows.delete(flow);
      return no('expired');
    }
    if (!c.ok) return no(c.code);
    if (!c.value) return { ok: true, state: 'waiting' };
    const a = await si.signInQuick(f.q);
    this._flows.delete(flow);
    if (!a.ok) return no(a.code);
    return this._saveJellyfin(f.address, f.server, a.value);
  }

  quickConnectCancel(flow) {
    if (typeof flow === 'string') this._flows.delete(flow);
    return { ok: true };
  }

  /** Name and password (sent once to Jellyfin, never kept). */
  async signIn({ address: input, user, password }) {
    const address = MA.normalize(String(input || ''));
    if (!address || typeof user !== 'string' || !user.trim() || user.length > 128 || typeof password !== 'string' || password.length > 512) return no('invalid');
    const si = new JellyfinSignIn({ client: this._signInClient(address) });
    const s = await si.server();
    if (!s.ok) return no(s.code);
    const a = await si.signIn(user.trim(), password);
    if (!a.ok) return no(a.code);
    return this._saveJellyfin(address, s.value, a.value);
  }

  _saveJellyfin(address, server, a) {
    let saved;
    try {
      saved = this.store.save({
        kind: 'jellyfin', name: server.name, address, userId: a.userId, userName: a.userName, token: a.token,
        serverId: a.serverId || server.id, tlsPin: this._pinOf(address),
      });
    } catch (err) { return no(err.code || 'failed'); }
    this._emitState();
    return { ok: true, state: 'done', source: this._publicSource(saved) };
  }

  /** "Gerät anmelden": the Quick Connect code of the TV or another PC confirmed with this PC's access. */
  async authorizeDevice({ sourceId, code }) {
    const lib = this._library(sourceId);
    if (!lib) return no('not_found');
    const r = await lib.authorize(code);
    return r.ok ? { ok: true } : this._fail(sourceId, r);
  }

  /**
   * A share: `\\192.168.1.20\filme` (SMB) or `https://192.168.1.20:5006/filme` (WebDAV) with name and password; its
   * root read once with this access before it is kept. SMB error 1219 → 'smb_conflict' (useExisting: true takes the
   * Explorer's own connection); a self-signed certificate → 'cert_untrusted' with the certificate to confirm (trust()).
   */
  async addShare({ kind, address: input, user = null, password = null, useExisting = false }) {
    if (kind !== 'smb' && kind !== 'webdav') return no('invalid');
    const address = MA.normalizeShare(kind, String(input || ''));
    if (!address) return no('invalid');
    if ((user !== null && (typeof user !== 'string' || user.length > 128)) || (password !== null && (typeof password !== 'string' || password.length > 512))) return no('invalid');
    const smb = kind === 'smb' ? MA.parseSmb(address) : null;
    if (smb && smb.port !== MA.SMB_PORT) return no('unsupported');
    const candidate = {
      id: '', kind, name: smb ? smb.host : MA.host(address), address, userName: user ? user.trim() : null,
      password: user ? password : null, useExisting: useExisting === true, tlsPin: kind === 'webdav' ? this._pinOf(address) : null,
    };
    const share = kind === 'smb' ? this.shareFactory.smb(candidate) : this.shareFactory.webdav(candidate, () => this._way(candidate));
    const r = await share.check();
    await Promise.resolve(share.close()).catch(() => {});
    if (!r.ok) {
      if (r.code === 'cert_untrusted' || r.code === 'cert_changed') return no(r.code, { address, certificate: await this._certificateOf(address) });
      return no(r.code, { address, ...(r.winError !== undefined ? { winError: r.winError } : {}) });
    }
    let saved;
    try { saved = this.store.save(candidate); } catch (err) { return no(err.code || 'failed'); }
    this._dropShares(saved.id);
    this._emitState();
    return { ok: true, source: this._publicSource(saved) };
  }

  /** "Abmelden" / "Entfernen": a Jellyfin source signs this device out of the server first. */
  async removeSource(id) {
    const src = this.store.source(id);
    if (!src) return no('not_found');
    if (src.kind === 'jellyfin' && src.token) {
      const c = this._client(id);
      await c.post('Sessions/Logout').catch(() => null);
    }
    this.stream.revokeSource(id);
    this._dropShares(id);
    for (const [k, p] of this._plays) if (p.sourceId === id) this._plays.delete(k);
    try { this.store.remove(id); } catch (err) { return no(err.code || 'failed'); }
    this._links.delete(id);
    this._emitState();
    return { ok: true };
  }

  setAlwaysOriginal(id, on) {
    if (!this.store.source(id)) return no('not_found');
    try { this.store.setAlwaysOriginal(id, on === true); } catch (err) { return no(err.code || 'failed'); }
    this._emitState();
    return { ok: true };
  }

  // ── the library of a Jellyfin source ────────────────────────

  /** A 401: the access is gone (signed out in Jellyfin) — the source stays to sign in again. */
  _fail(id, r) {
    if (r.code === 'unauthorized') {
      try { this.store.dropToken(id); } catch { /* kept */ }
      this.stream.revokeSource(id);
      this._emitState();
      return no('signed_out');
    }
    return no(r.code, r.status ? { status: r.status } : {});
  }

  _decorate(t) {
    return {
      ...t,
      poster: this.stream.imageUrl(t.sourceId, J.imagePath(t, false, 450)),
      backdrop: this.stream.imageUrl(t.sourceId, J.imagePath(t, true, 720)),
      resumable: J.resumable(t),
      leftMs: J.leftMs(t),
      progress: J.progressOf(t),
    };
  }

  async _rows(id, fn) {
    const lib = this._library(id);
    if (!lib) return no(this.store.source(id) ? 'signed_out' : 'not_found');
    if (!this.link(id).checkedAt) await this.check(id);
    const r = await fn(lib);
    if (!r.ok) return this._fail(id, r);
    const v = r.value;
    if (Array.isArray(v)) return { ok: true, items: v.map((t) => this._decorate(t)) };
    return { ok: true, ...v, items: v.items.map((t) => this._decorate(t)) };
  }

  resume(id, limit = 12) { return this._rows(id, (l) => l.resume(clampInt(limit, 1, 50, 12))); }

  latest(id, limit = 16) { return this._rows(id, (l) => l.latest(clampInt(limit, 1, 50, 16))); }

  movies(id, o = {}) { return this._rows(id, (l) => l.movies(clampInt(o.start, 0, 1e6, 0), clampInt(o.limit, 1, 200, 60), pageOpts(o))); }

  series(id, o = {}) { return this._rows(id, (l) => l.series(clampInt(o.start, 0, 1e6, 0), clampInt(o.limit, 1, 200, 60), pageOpts(o))); }

  seasons(id, seriesId) { return this._rows(id, (l) => l.seasons(seriesId)); }

  episodes(id, seriesId, seasonId = null) { return this._rows(id, (l) => l.episodes(seriesId, seasonId)); }

  search(id, q) { return this._rows(id, (l) => l.search(q)); }

  /** The detail: the title, its versions, what Chromium does with each sound, the quality on this line, the tracks. */
  async detail(id, itemId) {
    const lib = this._library(id);
    if (!lib) return no(this.store.source(id) ? 'signed_out' : 'not_found');
    if (!this.link(id).checkedAt) await this.check(id);
    const r = await lib.detail(itemId);
    if (!r.ok) return this._fail(id, r);
    const src = this.store.source(id);
    const l = this.link(id);
    const { title, versions } = r.value;
    const choice = title.seriesId ? this.store.trackChoice(title.seriesId) : null;
    return {
      ok: true,
      title: this._decorate(title),
      versions: versions.map((v) => ({
        ...publicVersion(v),
        videoLabel: MQ.videoLabel(J.videoOf(v)),
        hdr: MQ.hdrLabel(J.videoOf(v)),
        audio: J.audioOf(v).map((s) => ({ ...publicStream(s), label: MT.audioLabel(s), languageName: s.language ? MT.languageName(s.language) : null, fate: MT.fate(s, this._caps) })),
        subtitles: J.subtitlesOf(v).map((s) => ({ ...publicStream(s), codecLabel: MT.codecLabel(s.codec), languageName: s.language ? MT.languageName(s.language) : null, burnIn: s.picture })),
        pick: { audioIndex: MT.pickAudio(v, choice), subtitleIndex: MT.pickSubtitle(v, choice) },
        quality: MQ.offer({ atHome: l.atHome !== false, measuredBps: l.bps, originalBps: v.bitrate, alwaysOriginal: src.alwaysOriginal }),
      })),
      link: l,
    };
  }

  /**
   * Play a title: { sourceId, itemId, versionId?, startMs?, audioIndex?, subtitleIndex? (-1: off), quality? }
   * → { ok, playId, url (gcmedia:), hls, method, converted, bitrate, audioIndex, subtitleIndex, subtitles, link }.
   * A series' sound and subtitle are remembered (by language) for its next episodes.
   */
  async play(o = {}) {
    const id = o.sourceId;
    const src = this.store.source(id);
    if (!src) return no('not_found');
    if (src.kind !== 'jellyfin') return this.shareOpen({ sourceId: id, path: o.path });
    const lib = this._library(id);
    if (!lib) return no('signed_out');
    if (!this.link(id).checkedAt) await this.check(id);
    const l = this.link(id);
    const audioIndex = Number.isInteger(o.audioIndex) ? o.audioIndex : undefined;
    const subtitleIndex = Number.isInteger(o.subtitleIndex) ? o.subtitleIndex : undefined;
    const maxBitrate = MQ.cap({
      setting: o.quality !== undefined ? o.quality : this.store.quality(),
      atHome: l.atHome !== false, measuredBps: l.bps, originalBps: Number.isFinite(o.originalBps) ? o.originalBps : null,
      alwaysOriginal: src.alwaysOriginal,
    });
    const r = await lib.play({ itemId: o.itemId, versionId: o.versionId || null, startMs: clampInt(o.startMs, 0, 1e9, 0), audioIndex, subtitleIndex, maxBitrate });
    if (!r.ok) return this._fail(id, r);
    const plan = r.value;
    const playId = crypto.randomBytes(12).toString('base64url');
    const url = this.stream.openJellyfin(id, plan.url, { play: playId });
    if (!url) return no('failed');
    const subtitles = plan.sideSubtitles.map((s) => ({ ...s, url: this.stream.openJellyfin(id, s.url, { play: playId }) })).filter((s) => s.url);
    this._remember({ playId, sourceId: id, kind: 'jellyfin', plan, seriesId: typeof o.seriesId === 'string' ? o.seriesId : null });
    if (typeof o.seriesId === 'string' && (audioIndex !== undefined || subtitleIndex !== undefined)) {
      this.store.setTrackChoice(o.seriesId, MT.choiceOf(plan.version, plan.audioIndex, plan.subtitleIndex));
    }
    return {
      ok: true, playId, url, hls: plan.hls, method: plan.method, converted: plan.converted, bitrate: plan.bitrate,
      audioIndex: plan.audioIndex, subtitleIndex: plan.subtitleIndex, subtitles, transcodeReasons: plan.version.transcodeReasons, link: l,
    };
  }

  _remember(p) {
    while (this._plays.size >= MAX_PLAYS) {
      const [k] = this._plays.keys();
      this._plays.delete(k);
      this.stream.revoke(k);
    }
    this._plays.set(p.playId, p);
  }

  /**
   * The player's progress: { playId, event: 'start' | 'progress' | 'stop', positionMs, paused, durationMs? }.
   * Jellyfin gets it (Sessions/Playing…); a share's file is kept on this PC. 'stop' ends the play's addresses.
   */
  async report({ playId, event, positionMs, paused = false, durationMs = 0 } = {}) {
    const p = typeof playId === 'string' ? this._plays.get(playId) : null;
    if (!p) return no('not_found');
    const pos = clampInt(positionMs, 0, 1e10, 0);
    if (p.kind === 'share') {
      const dur = clampInt(durationMs, 0, 1e10, 0);
      const played = dur > 0 && pos >= dur * 0.9;
      this.store.setProgress(p.key, { positionMs: played ? 0 : pos, durationMs: dur, played });
    } else {
      const lib = this._library(p.sourceId);
      if (lib) {
        const prog = { plan: p.plan, positionMs: pos, paused: paused === true };
        const r = event === 'start' ? await lib.started(prog) : event === 'stop' ? await lib.stopped(prog) : await lib.progress(prog);
        if (!r.ok && r.code === 'unauthorized') this._fail(p.sourceId, r);
      }
    }
    if (event === 'stop') {
      this._plays.delete(playId);
      this.stream.revoke(playId);
    }
    return { ok: true };
  }

  async setPlayed(id, itemId, played) {
    const lib = this._library(id);
    if (!lib) return no('not_found');
    const r = await lib.setPlayed(itemId, played === true);
    return r.ok ? { ok: true } : this._fail(id, r);
  }

  trackChoice(seriesId) { return { ok: true, choice: this.store.trackChoice(seriesId) }; }

  setTrackChoice(seriesId, choice) {
    this.store.setTrackChoice(seriesId, choice && typeof choice === 'object' ? choice : {});
    return { ok: true };
  }

  // ── the folders of a share ──────────────────────────────────

  _progressKey(id, path) { return `${id}|${path}`; }

  /** The entries of folder `dir` ("" the root), the files with their progress on this PC. */
  async shareList({ sourceId, dir = '' }) {
    const src = this.store.source(sourceId);
    if (!src || !MS.isShare(src.kind)) return no('not_found');
    if (!this.link(sourceId).checkedAt) await this.check(sourceId);
    const fsx = this._shareFor(sourceId);
    const r = await fsx.list(dir);
    if (!r.ok) return no(r.code, r.winError !== undefined ? { winError: r.winError } : {});
    const progress = this.store.all(`${sourceId}|`);
    const items = r.value.map((e) => ({ ...e, progress: e.directory ? null : progress[this._progressKey(sourceId, e.path)] || null }));
    items.sort((a, b) => (a.directory === b.directory ? a.name.localeCompare(b.name, 'de', { numeric: true, sensitivity: 'base' }) : a.directory ? -1 : 1));
    return { ok: true, dir: MSH.clean(dir), via: fsx.kind, items, link: this.link(sourceId) };
  }

  /** The start of a file read for the check: what it says (Matroska / MP4) and whether Chromium can play it. */
  async shareCheck(fsx, path, size) {
    const head = await fsx.read(path, 0, Math.min(this.timing.sniffBytes, size || this.timing.sniffBytes));
    if (!head.ok) return MP.verdict({ name: path }, this._caps);
    let info = MP.sniff(head.value, path);
    if (info && Number.isFinite(info.moovAt) && info.moovAt < size) {
      const tail = await fsx.read(path, info.moovAt, Math.min(this.timing.moovBytes, size - info.moovAt));
      if (tail.ok) info = { ...MP.sniffMp4(tail.value, info.moovAt), container: info.container };
    }
    return { ...MP.verdict(info || { name: path }, this._caps), streams: info ? { video: info.video, audio: info.audio, subtitles: info.subtitles } : null };
  }

  /**
   * A file of a share for the player: → { ok, playId, url (gcmedia:), mime, size, check: { verdict, reasons, … },
   * progress } (always the original; check.external: "In VLC öffnen" is the better way).
   */
  async shareOpen({ sourceId, path }) {
    const src = this.store.source(sourceId);
    const clean = MSH.clean(path);
    if (!src || !MS.isShare(src.kind) || !clean) return no('not_found');
    if (!this.link(sourceId).checkedAt) await this.check(sourceId);
    const fsx = this._shareFor(sourceId);
    const st = await fsx.stat(clean);
    if (!st.ok) return no(st.code);
    const check = await this.shareCheck(fsx, clean, st.value.size);
    const playId = crypto.randomBytes(12).toString('base64url');
    const mime = MSH.mimeOf(clean);
    const url = this.stream.openShare(sourceId, clean, { mime, play: playId });
    const key = this._progressKey(sourceId, clean);
    this._remember({ playId, sourceId, kind: 'share', path: clean, key });
    return { ok: true, playId, url, mime, size: st.value.size, via: fsx.kind, check, progress: this.store.progress(key) };
  }

  // ── the end ─────────────────────────────────────────────────

  /** Signed out of GateControl / another server: nothing of Medien is left on this PC. */
  async forgetAll() {
    this.stream.clear();
    this._plays.clear();
    this._flows.clear();
    this._pins.clear();
    this._links.clear();
    this._dropShares();
    this.store.forgetAll();
    await this.lanRoute.removeHostRoutes().catch(() => {});
    this._emitState();
    return { ok: true };
  }

  /** The app quits: the host routes and the SMB connections of this session go. */
  async close() {
    this._dropShares();
    this.net.reset();
    await this.lanRoute.removeHostRoutes().catch(() => {});
  }
}

function clampInt(v, min, max, def) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.floor(n))) : def;
}

function pageOpts(o) {
  return { sort: ['name', 'added', 'year'].includes(o.sort) ? o.sort : 'name', unplayed: o.unplayed === true, genre: typeof o.genre === 'string' ? o.genre : null };
}

/** A stream for the page: without its delivery URL (it may carry the server's api_key). */
function publicStream(s) {
  const { deliveryUrl: _url, ...rest } = s;
  return rest;
}

/** A version for the page: no converting URL (it carries the server's api_key), no delivery URLs. */
function publicVersion(v) {
  return {
    id: v.id, container: v.container, bitrate: v.bitrate, runtimeMs: v.runtimeMs, defaultAudio: v.defaultAudio, defaultSubtitle: v.defaultSubtitle,
    supportsDirectPlay: v.supportsDirectPlay, supportsDirectStream: v.supportsDirectStream, supportsTranscoding: v.supportsTranscoding,
    video: (() => { const x = J.videoOf(v); return x ? { codec: x.codec, width: x.width, height: x.height, videoRange: x.videoRange, videoRangeType: x.videoRangeType } : null; })(),
  };
}

MediaService.DEFAULT_TIMING = DEFAULT_TIMING;
MediaService.idOk = idOk;

module.exports = MediaService;
