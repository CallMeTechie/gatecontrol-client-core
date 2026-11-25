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
 * Shares (Stufe 4h): the rows, grids, detail and play of Jellyfin take a share's id as well — its films and series
 * come from the folders (services/media-share-library.js: the file names and the pictures beside them), always the
 * original, the progress on this PC; ids `f:<path>` (a file), `s:<key>` (a series), `s:<key>:<n>` (a season). Every
 * title carries `key` / `sortKey` (utils/media-share-names.js) so the page can show a title Jellyfin has too once and
 * mix the sources A–Z. Before a file plays, its start is read (`check`: what Chromium plays, utils/media-playable.js);
 * what it cannot goes to VLC (a loopback address, services/media-external.js) or Windows' app for the file.
 *
 * Medien-Plugin (W1): the sources come from the GateControl server (services/media-server-sources.js, `managed`). For
 * them the network rule of the plugin is binding (utils/media-server.js wayOf):
 *   - at home (GateControl's own home-network detection says so: the server's GET /api/v1/client/home-network, see
 *     _home(); a private address alone is no proof, the plugin's `network.home.probes` never decide it): straight to
 *     the home address, bound to the LAN, the host route for SMB where the tunnel would carry the NAS (Plan B) — also
 *     with the VPN on;
 *   - away, `awayMode` 'vpn': only through the own tunnel. Is it down, opening or playing a title starts it
 *     (`tunnel.connect()`, event 'vpn': connecting / up / failed); without it nothing is sent (code 'vpn_required',
 *     every connection refused before a byte leaves: MediaNet `blocked`);
 *   - away, `awayMode` 'direct' (the admin allowed it for this source): over its https:// address, the usual TLS check.
 * A Jellyfin source without access signs in on its own (Quick Connect confirmed by the plugin, `pair`); a 401 signs in
 * again without asking. SMB error 1219 (the Explorer is connected with another user) takes the WebDAV half at once.
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
const N = require('../utils/media-share-names');
const SI = require('../utils/media-share-index');
const MP = require('../utils/media-playable');
const L = require('../utils/media-lan');
const MSV = require('../utils/media-server');
const { normalizeFingerprint, localAddresses } = require('../utils/home-cache');
const MediaNet = require('./media-net');
const MediaDiscovery = require('./media-discovery');
const MediaLanRoute = require('./media-lan-route');
const MediaStreamService = require('./media-stream');
const { JellyfinClient, JellyfinLibrary, JellyfinSignIn, idOk } = require('./media-jellyfin');
const { SmbShare, WebDavShare } = require('./media-share');
const ShareLibrary = require('./media-share-library');
const MediaExternal = require('./media-external');

const DEFAULT_TIMING = Object.freeze({
  measureEveryMs: 5 * 60 * 1000, homeProbeMs: 2500, quickConnectMs: 10 * 60 * 1000, sniffBytes: 2 * 1024 * 1024, moovBytes: 8 * 1024 * 1024,
});
const MAX_FLOWS = 4;
const MAX_PLAYS = 8;
const MAX_CHECKS = 200;

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
   * @param {(target: string) => Promise<string>} [opts.openPath] - Electron's shell.openPath ("In anderer App öffnen")
   * @param {object} [opts.external] - MediaExternal (tests)
   * @param {object} [opts.log]
   * @param {() => number} [opts.now]
   * @param {object} [opts.timing]
   * @param {object} [opts.tunnel] - the app's GateControl tunnel: { up() → boolean, connect() → Promise<boolean> }
   *   (the network rule: away a server source goes only through it; opening Medien starts it)
   */
  constructor({
    store, client = 'GateControl Pro', version = '0.0.0', deviceName = null, networkInterfaces = os.networkInterfaces,
    net = null, discovery = null, lanRoute = null, shares = null, openPath = null, external = null, log = null, now = Date.now, timing = {},
    tunnel = null,
  }) {
    super();
    this.tunnel = tunnel;
    this._server = null;   // MediaServerSources (setServerSources): home network, pair, report, smbChecked, status
    this._homeCache = null; // GateControl's home-network answer: { key (tunnel, LAN addresses), p: Promise<{ atHome, localAddress }> }
    this._vpn = null;      // the tunnel being started for Medien
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
    this.external = external || new MediaExternal({ stream: this.stream, openPath, log: this.log });
    this._libs = new Map();    // share id → ShareLibrary (its index of films and series)
    this._checks = new Map();  // `${id}|${path}|${size}` → the format check of a file
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

  link(id) { return this._links.get(id) || { atHome: null, via: null, localAddress: null, bps: null, measuredAt: 0, checkedAt: 0, route: null, blocked: false }; }

  /** media:sources:status — the server's list (services/media-server-sources.js status()), null without one. */
  serverStatus() {
    return { ok: true, server: this._server ? this._server.status() : null };
  }

  /**
   * media:sources:refresh — opening Medien: the server's list asked now, then a Jellyfin source without access signed
   * in (away the VPN started for it: the network rule). Reads only, sets nothing up.
   */
  async serverRefresh() {
    if (!this._server) return { ok: true, server: null };
    const server = await this._server.refresh();
    if (typeof this._server.pairPending === 'function') await this._server.pairPending({ startVpn: true });
    return { ok: true, server: this._server.status ? this._server.status() : server };
  }

  /** The server's sources (services/media-server-sources.js): at home or not, the sign-in, the reports to the plugin. */
  setServerSources(ss) {
    this._server = ss || null;
    this._homeCache = null;
  }

  _tunnelUp() {
    if (this.tunnel && typeof this.tunnel.up === 'function') {
      try { return !!this.tunnel.up(); } catch { return false; }
    }
    return !!L.tunnelAddress(this._ifaces());
  }

  /** Who asks Jellyfin: for a server source the device id and name the plugin gives (its device list shows them). */
  _infoOf(src) {
    const i = this.info();
    if (src && src.managed && src.jfDeviceId) return { client: 'GateControl', device: src.jfDeviceName || i.device, deviceId: src.jfDeviceId, version: this.version };
    return i;
  }

  /** The base of a source now: away with the admin's exception its https:// address, else its home address. */
  _base(src) {
    if (src && src.managed && src.id && this.link(src.id).via === 'direct' && src.awayAddress) return src.awayAddress;
    return src.address;
  }

  /**
   * The way of a source's connections now: at home bound to the LAN address (found by check()), away bound to the
   * tunnel's own address (a hotel's network with the home's addresses never gets the access); while a source is set
   * up (no id yet) the LAN when its host is in it.
   */
  _way(src) {
    if (src.managed) return this._managedWay(src);
    const pin = src.tlsPin || this._pinOf(src.address);
    const l = src.id ? this.link(src.id) : { atHome: null };
    if (l.atHome === true) return { localAddress: l.localAddress, pin };
    if (l.atHome === false) return { localAddress: L.tunnelAddress(this._ifaces()), pin };
    const b = src.id ? null : L.lanBinding(MA.host(src.address), this._ifaces());
    return { localAddress: b ? b.localAddress : null, pin };
  }

  /**
   * The network rule for a server source: at home bound to the LAN; away through the tunnel (bound to its address) or
   * over the admin's https:// address (no pin: the usual TLS check); else nothing goes out (blocked) — also while the
   * way is not known yet.
   */
  _managedWay(src) {
    const l = this.link(src.id);
    if (l.atHome === true) return { localAddress: l.localAddress, pin: src.tlsPin || null };
    if (l.atHome === false && l.via === 'direct') return { localAddress: null, pin: null };
    if (l.atHome === false && l.via === 'tunnel' && this._tunnelUp()) return { localAddress: L.tunnelAddress(this._ifaces()), pin: src.tlsPin || null };
    return { localAddress: null, pin: null, blocked: true };
  }

  _pinOf(address) {
    try { return this._pins.get(new URL(address).origin) || null; } catch { return null; }
  }

  _client(id, { token = true } = {}) {
    const src = this.store.source(id);
    if (!src || src.kind !== 'jellyfin') return null;
    return new JellyfinClient({ base: this._base(src), info: this._infoOf(src), token: token ? src.token : null, net: this.net, way: () => this._way(src), log: this.log });
  }

  /** Quick Connect of a server source (its own device id, the way of the network rule): media-server-sources.js pair. */
  signInClient(id) {
    const src = this.store.source(id);
    if (!src || src.kind !== 'jellyfin') return null;
    return new JellyfinSignIn({ client: this._client(id, { token: false }) });
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
    const l = this.link(id);
    const atHome = l.atHome;
    let use = MS.shareFor(pair.smb, pair.webdav, atHome) || src;
    // SMB error 1219 (the Explorer is connected to the NAS with another user): the WebDAV half instead, no question
    if (use.kind === 'smb' && l.smbConflict && pair.webdav) use = pair.webdav;
    // away with the admin's exception: the WebDAV half over its https:// address (same path below it)
    if (use.managed && l.via === 'direct') {
      const dav = pair.webdav || (use.kind === 'webdav' ? use : null);
      if (dav && dav.awayAddress) use = { ...dav, address: dav.awayAddress, tlsPin: null };
    }
    const key = `${use.id}|${use.address}|${use.userName || ''}|${crypto.createHash('sha256').update(String(use.password || '')).digest('hex').slice(0, 16)}|${use.tlsPin || ''}|${atHome}`;
    let s = this._shares.get(key);
    if (!s) {
      const ref = use;
      s = use.kind === 'smb' ? this.shareFactory.smb(use) : this.shareFactory.webdav(use, () => this._way(ref));
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
    const way = s.managed && l.checkedAt ? (l.blocked ? 'blocked' : l.atHome ? 'home' : l.via === 'direct' ? 'direct' : 'vpn') : null;
    return {
      ...MS.publicSource(s),
      link: { atHome: l.atHome, via: l.via, bps: l.bps, measuredAt: l.measuredAt || null, route: l.route, blocked: l.blocked === true, way, smbConflict: l.smbConflict === true },
    };
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
      server: this._server && typeof this._server.status === 'function' ? this._server.status() : null,
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
    if (src.managed) return this._checkManaged(id, src, force);
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

  /** The network rule for a server source (utils/media-server.js wayOf): home, away through the VPN, direct, blocked. */
  async _checkManaged(id, src, force) {
    const pair = MS.isShare(src.kind) ? MS.pairOf(src, this.store.sources()) : null;
    const homeSrc = pair ? (pair.smb || pair.webdav) : src;
    const host = MA.host(homeSrc.address);
    const old = this.link(id);
    const home = await this._home();
    const now = this.now();
    // the admin's exception is a WebDAV address (https): a share with SMB alone goes away only through the VPN
    const awayMode = pair && !pair.webdav ? 'vpn' : src.awayMode;
    const way = MSV.wayOf({ atHome: home.atHome, awayMode, tunnelUp: this._tunnelUp() });
    let next;
    if (way === 'home') {
      const bind = L.lanBinding(host, this._ifaces());
      const localAddress = bind ? bind.localAddress : home.localAddress;
      const route = await this._route(homeSrc, host, localAddress);
      next = { atHome: true, via: 'lan', localAddress, bps: null, measuredAt: 0, checkedAt: now, route, blocked: false };
    } else if (way === 'blocked') {
      next = { atHome: false, via: null, localAddress: null, bps: null, measuredAt: 0, checkedAt: now, route: null, blocked: true };
    } else {
      const via = way === 'direct' ? 'direct' : 'tunnel';
      const same = old.atHome === false && old.via === via;
      const fresh = same && old.bps && now - old.measuredAt < this.timing.measureEveryMs;
      let bps = same ? old.bps : null;
      let measuredAt = same ? old.measuredAt : 0;
      next = { atHome: false, via, localAddress: null, bps, measuredAt, checkedAt: now, route: null, blocked: false };
      if ((force || !fresh) && src.kind === 'jellyfin' && src.token) {
        this._links.set(id, next);
        const m = await this._library(id).measure();
        if (m) { bps = m; measuredAt = now; }
        next = { ...next, bps, measuredAt };
      }
    }
    if (old.atHome !== next.atHome || old.via !== next.via) { this._dropShares(id); this.net.reset(); } else if (old.smbConflict) next.smbConflict = true;
    this._links.set(id, next);
    this.emit('link', { sourceId: id, link: next });
    return { ok: true, link: next };
  }

  /**
   * At home? GateControl's own home-network detection decides it — the server's (GET /api/v1/client/home-network with
   * this PC's LAN addresses, MediaServerSources.homeNetwork, utils/media-server.js homeNetworkOf): the same one as for
   * the trusted network, Familie's presence and the home cache. With the VPN off the server can confirm only a gateway
   * site (the PC's public address is an online gateway's and a LAN address lies in a subnet it reports); else "away"
   * — opening Medien then starts the tunnel and asks again through it (its own LAN: the peer's WireGuard endpoint in
   * the server's LAN). The plugin's probes never decide it. No real LAN adapter: away, nothing asked. Kept until the
   * network changes, the tunnel goes up or down or the LAN addresses change.
   */
  _home() {
    const ifaces = this._ifaces();
    const links = L.lanLinks(ifaces);
    const local = localAddresses(ifaces);
    const tunnelUp = this._tunnelUp();
    const key = `${tunnelUp}|${local.join(',')}`;
    if (!this._homeCache || this._homeCache.key !== key) {
      const p = this._askHome({ links, local, tunnelUp }).catch(() => ({ atHome: false, localAddress: null }));
      this._homeCache = { key, p };
      p.then((r) => { if (this._homeCache && this._homeCache.p === p) this.emit('home', r); });
    }
    return this._homeCache.p;
  }

  async _askHome({ links, local, tunnelUp }) {
    if (!links.length || !local.length || !this._server || typeof this._server.homeNetwork !== 'function') return { atHome: false, localAddress: null };
    const atHome = (await this._server.homeNetwork({ local, tunnelUp })) === true;
    return atHome ? { atHome: true, localAddress: links[0].address } : { atHome: false, localAddress: null };
  }

  /**
   * Before a source is opened or played: the way known, and for a server source the network rule kept — away through
   * the VPN only: is it down, it is started ("VPN wird verbunden …"); without it → { ok: false, code: 'vpn_required' }.
   * → null when the source may be used now.
   */
  async _ready(id, { startVpn = true } = {}) {
    let l = this.link(id);
    if (!l.checkedAt) {
      const c = await this.check(id);
      if (!c.ok) return no(c.code);
      l = c.link;
    }
    if (!l.blocked) return null;
    if (!startVpn || !(await this._connectVpn())) return no('vpn_required');
    this._links.delete(id);
    const c = await this.check(id);
    if (!c.ok) return no(c.code);
    return c.link.blocked ? no('vpn_required') : null;
  }

  /** The tunnel started for Medien (one start for all who wait); events 'vpn' { state: connecting | up | failed }. */
  _connectVpn() {
    if (this._tunnelUp()) return Promise.resolve(true);
    if (!this.tunnel || typeof this.tunnel.connect !== 'function') return Promise.resolve(false);
    if (!this._vpn) {
      this.emit('vpn', { state: 'connecting' });
      this._vpn = Promise.resolve()
        .then(() => this.tunnel.connect())
        .then((r) => r !== false && this._tunnelUp(), (err) => { this.log.warn(`Medien: VPN not started (${(err && err.message) || 'failed'})`); return false; })
        .then((up) => {
          this._vpn = null;
          this.emit('vpn', { state: up ? 'up' : 'failed' });
          return up;
        });
    }
    return this._vpn;
  }

  /** A server source's way told to the plugin (only on a change): "NAS durch den Tunnel nicht erreichbar". */
  _report(id, r) {
    const src = this.store.source(id);
    if (!src || !src.managed || !this._server || typeof this._server.report !== 'function') return;
    const l = this.link(id);
    if (!l.checkedAt || l.blocked) return;
    const way = l.atHome ? 'home' : 'away';
    if (r.ok) this._server.report(src.sid || id, way, true);
    else if (r.code === 'offline') this._server.report(src.sid || id, way, false, l.atHome ? 'home_unreachable' : l.via === 'direct' ? 'direct_unreachable' : 'tunnel_unreachable');
  }

  /**
   * A call on a share: SMB error 1219 → the WebDAV half at once (when there is one) and the call again; the first SMB
   * sign-in of a server share told to the plugin ("SMB geprüft").
   */
  async _viaShare(id, fn) {
    let r = await fn();
    const src = this.store.source(id);
    if (!src) return r;
    const pair = MS.pairOf(src, this.store.sources());
    if (!r.ok && r.code === 'smb_conflict' && pair.webdav && !this.link(id).smbConflict) {
      this.log.info('Medien: SMB in use with another Windows access (1219) — WebDAV instead');
      if (pair.smb && pair.smb.managed && this._server) this._server.smbChecked(pair.smb.id, false, 'smb_conflict');
      this._links.set(id, { ...this.link(id), smbConflict: true });
      this._dropShares(id);
      r = await fn();
    } else if (pair.smb && pair.smb.managed && this._server) {
      const fsx = this._shareFor(id);
      if (fsx && fsx.kind === 'smb') {
        if (r.ok) this._server.smbChecked(pair.smb.id, true);
        else if (r.code === 'unauthorized' || r.code === 'smb_conflict') this._server.smbChecked(pair.smb.id, false, r.code);
      }
    }
    this._report(id, r);
    return r;
  }

  /**
   * The library of a Jellyfin source, ready: the way kept (_ready); a server source without access signs in on its own
   * (the plugin confirms its Quick Connect). → { lib } | { fail }.
   */
  async _jellyfin(id) {
    const src = this.store.source(id);
    if (!src) return { fail: no('not_found') };
    const b = await this._ready(id);
    if (b) return { fail: b };
    let lib = this._library(id);
    if (!lib && src.managed && this._server && typeof this._server.pair === 'function') {
      const r = await this._server.pair(id);
      lib = this._library(id);
      if (!lib) return { fail: no((r && r.code) || 'signed_out') };
    }
    return lib ? { lib } : { fail: no('signed_out') };
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
    this._homeCache = null;
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
    this._libs.clear();
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
    this._libs.clear();
    for (const [k, p] of this._plays) if (p.sourceId === id) this._plays.delete(k);
    try { this.store.remove(id); } catch (err) { return no(err.code || 'failed'); }
    this._links.delete(id);
    this._emitState();
    return { ok: true };
  }

  /**
   * The server's list changed these sources (gone, signed out, another password, taken over): their stream addresses,
   * connections, indexes and plays end; the page hears it.
   */
  sourcesChanged(ids = []) {
    for (const id of ids) {
      this.stream.revokeSource(id);
      this._dropShares(id);
      this._libs.delete(id);
      // the way stays known while the source does (a new password or access does not change it)
      if (!this.store.source(id)) this._links.delete(id);
      for (const [k, p] of this._plays) if (p.sourceId === id) this._plays.delete(k);
    }
    this._emitState();
  }

  /** The Jellyfin access of a source set up on this PC before, replaced by the server's: signed out (best effort). */
  async logoutOld(src) {
    if (!src || src.kind !== 'jellyfin' || !src.token) return { ok: true };
    const way = { localAddress: null, pin: src.tlsPin || null };
    const l = L.lanBinding(MA.host(src.address), this._ifaces());
    if (l) way.localAddress = l.localAddress;
    else if (this._tunnelUp()) way.localAddress = L.tunnelAddress(this._ifaces());
    else return { ok: false, code: 'offline' }; // not through a hotel's network with the old access
    // its own connections: a change of the way of the server's sources (net.reset) must not cut this one
    const net = this.net instanceof MediaNet ? new MediaNet({ log: this.log }) : this.net;
    const c = new JellyfinClient({ base: src.address, info: this.info(), token: src.token, net, way: () => way, log: this.log });
    const r = await c.post('Sessions/Logout').catch(() => ({ ok: false }));
    if (net !== this.net) net.reset();
    return { ok: !!r.ok };
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
      const src = this.store.source(id);
      try { this.store.dropToken(id); } catch { /* kept */ }
      this.stream.revokeSource(id);
      this._emitState();
      // a server source signs in again on its own, without asking (the plugin confirms)
      if (src && src.managed && this._server && typeof this._server.pair === 'function') Promise.resolve(this._server.pair(id)).catch(() => {});
      return no('signed_out');
    }
    this._report(id, r);
    return no(r.code, r.status ? { status: r.status } : {});
  }

  _decorate(t) {
    const share = t.fromShare === true;
    return {
      ...t,
      poster: share ? (t.posterId ? this.stream.shareImageUrl(t.sourceId, t.posterId) : null) : this.stream.imageUrl(t.sourceId, J.imagePath(t, false, 450)),
      backdrop: share ? (t.backdropId ? this.stream.shareImageUrl(t.sourceId, t.backdropId) : null) : this.stream.imageUrl(t.sourceId, J.imagePath(t, true, 720)),
      key: N.key(t.kind === 'episode' ? t.seriesName || t.name : t.name),
      sortKey: N.sortKey(t.name),
      resumable: J.resumable(t),
      leftMs: J.leftMs(t),
      progress: J.progressOf(t),
    };
  }

  /** The library of a share's films and series (of a pair the one under its visible id). */
  _shareLib(id) {
    const src = this.store.source(id);
    if (!src || !MS.isShare(src.kind)) return null;
    let lib = this._libs.get(id);
    if (!lib) {
      lib = new ShareLibrary({ sourceId: id, fs: () => this._shareFor(id), store: this.store, now: this.now });
      this._libs.set(id, lib);
    }
    return lib;
  }

  _isShare(id) {
    const src = this.store.source(id);
    return !!src && MS.isShare(src.kind);
  }

  async _shareRows(id, fn) {
    const lib = this._shareLib(id);
    if (!lib) return no('not_found');
    const b = await this._ready(id);
    if (b) return b;
    const r = await this._viaShare(id, () => fn(lib));
    if (!r.ok) return no(r.code, r.winError !== undefined ? { winError: r.winError } : {});
    const v = r.value;
    if (Array.isArray(v)) return { ok: true, items: v.map((t) => this._decorate(t)) };
    return { ok: true, ...v, items: v.items.map((t) => this._decorate(t)) };
  }

  async _rows(id, fn, shareFn = null) {
    if (shareFn && this._isShare(id)) return this._shareRows(id, shareFn);
    const j = await this._jellyfin(id);
    if (j.fail) return j.fail;
    let r = await fn(j.lib);
    const src = this.store.source(id);
    if (!r.ok && r.code === 'unauthorized' && src && src.managed && this._server) {
      // signed out in Jellyfin (the plugin made a new device, the access expired): signed in again once, silently
      try { this.store.dropToken(id); } catch { /* kept */ }
      this.stream.revokeSource(id);
      const again = await this._jellyfin(id);
      if (again.fail) return again.fail;
      r = await fn(again.lib);
    }
    if (!r.ok) return this._fail(id, r);
    this._report(id, r);
    const v = r.value;
    if (Array.isArray(v)) return { ok: true, items: v.map((t) => this._decorate(t)) };
    return { ok: true, ...v, items: v.items.map((t) => this._decorate(t)) };
  }

  resume(id, limit = 12) { const n = clampInt(limit, 1, 50, 12); return this._rows(id, (l) => l.resume(n), (l) => l.resume(n)); }

  latest(id, limit = 16) { const n = clampInt(limit, 1, 50, 16); return this._rows(id, (l) => l.latest(n), (l) => l.latest(n)); }

  movies(id, o = {}) {
    const [start, limit] = [clampInt(o.start, 0, 1e6, 0), clampInt(o.limit, 1, 200, 60)];
    return this._rows(id, (l) => l.movies(start, limit, pageOpts(o)), (l) => l.movies(start, limit, pageOpts(o)));
  }

  series(id, o = {}) {
    const [start, limit] = [clampInt(o.start, 0, 1e6, 0), clampInt(o.limit, 1, 200, 60)];
    return this._rows(id, (l) => l.series(start, limit, pageOpts(o)), (l) => l.series(start, limit, pageOpts(o)));
  }

  seasons(id, seriesId) { return this._rows(id, (l) => l.seasons(seriesId), (l) => l.seasons(seriesId)); }

  episodes(id, seriesId, seasonId = null) { return this._rows(id, (l) => l.episodes(seriesId, seasonId), (l) => l.episodes(seriesId, seasonId)); }

  search(id, q) { return this._rows(id, (l) => l.search(q), (l) => l.search(q)); }

  /** A share's title: its one version (the file as it is) and, when read before, what Chromium does with it. */
  async _shareDetail(id, itemId) {
    const lib = this._shareLib(id);
    if (!lib) return no('not_found');
    const b = await this._ready(id);
    if (b) return b;
    const r = await this._viaShare(id, () => lib.detail(itemId));
    if (!r.ok) return no(r.code);
    const { title, path, size, container } = r.value;
    const versions = path ? [{
      id: itemId, container, bitrate: null, runtimeMs: title.runtimeMs, supportsDirectPlay: true, supportsDirectStream: false, supportsTranscoding: false,
      video: null, videoLabel: null, hdr: null, audio: [], subtitles: [], pick: { audioIndex: null, subtitleIndex: null }, quality: null,
    }] : [];
    const check = path ? this._checks.get(`${id}|${path}|${size}`) || null : null;
    const fsx = this._shareFor(id);
    return { ok: true, title: this._decorate(title), versions, link: this.link(id), share: path ? { path, size, via: fsx ? fsx.kind : null, check } : null };
  }

  /** The detail: the title, its versions, what Chromium does with each sound, the quality on this line, the tracks. */
  async detail(id, itemId) {
    if (this._isShare(id)) return this._shareDetail(id, itemId);
    const j = await this._jellyfin(id);
    if (j.fail) return j.fail;
    const lib = j.lib;
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
    if (src.kind !== 'jellyfin') return this.shareOpen({ sourceId: id, path: o.path || SI.pathOf(o.itemId) });
    const j = await this._jellyfin(id);
    if (j.fail) return j.fail;
    const lib = j.lib;
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
      // a play given up before it started (another one asked meanwhile) keeps the place it had
      if (event === 'start') p.started = true;
      if (p.started || pos > 0) {
        const lib = this._shareLib(p.sourceId);
        if (lib) lib.keep(p.path, pos, clampInt(durationMs, 0, 1e10, 0));
      }
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
    if (this._isShare(id)) {
      const lib = this._shareLib(id);
      const path = SI.pathOf(itemId);
      if (lib && path) return lib.setPlayed(path, played === true).ok ? { ok: true } : no('failed');
      if (!lib) return no('not_found');
      // a series or season: all its episodes
      const eps = await lib.episodes(itemId.replace(/:\d{1,3}$/, ''), /:\d{1,3}$/.test(itemId) ? itemId : null);
      if (!eps.ok) return no(eps.code);
      for (const e of eps.value) lib.setPlayed(SI.pathOf(e.id), played === true);
      return { ok: true };
    }
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

  /**
   * The entries of folder `dir` ("" the root), the files with their progress on this PC; a video with what its name
   * says (title, year, season, episode: utils/media-share-names.js), its picture beside it (gcmedia://image/…) and
   * its id for detail / play (`itemId`: f:<path>).
   */
  async shareList({ sourceId, dir = '' }) {
    const src = this.store.source(sourceId);
    if (!src || !MS.isShare(src.kind)) return no('not_found');
    const clean = MSH.clean(dir);
    if (clean === null) return no('not_found');
    const b = await this._ready(sourceId);
    if (b) return b;
    const r = await this._viaShare(sourceId, () => this._shareFor(sourceId).list(clean));
    const fsx = this._shareFor(sourceId);
    if (!r.ok) return no(r.code, r.winError !== undefined ? { winError: r.winError } : {});
    const progress = this.store.all(`${sourceId}|`);
    const names = clean ? clean.split('/') : [];
    const above = names.length && N.seasonOfDir(names[names.length - 1]) !== null ? await fsx.list(MSH.parent(clean)).catch(() => null) : null;
    const videos = new Map(SI.videosOf(names, r.value, above && above.ok ? SI.imagesOf(above.value) : null).map((v) => [v.path, v]));
    const items = r.value.map((e) => {
      const out = { ...e, progress: e.directory ? null : progress[this._progressKey(sourceId, e.path)] || null };
      const v = videos.get(e.path);
      if (v) {
        const pic = v.poster || v.seriesPoster;
        Object.assign(out, {
          itemId: SI.fileId(e.path), title: v.parsed.isEpisode ? v.parsed.episodeName || v.parsed.title : v.parsed.title,
          seriesName: v.parsed.isEpisode ? v.parsed.title : null, year: v.parsed.year, season: v.parsed.season, episode: v.parsed.episode,
          poster: pic ? this.stream.shareImageUrl(sourceId, pic) : null,
        });
      }
      return out;
    });
    items.sort((a, b) => (a.directory === b.directory ? a.name.localeCompare(b.name, 'de', { numeric: true, sensitivity: 'base' }) : a.directory ? -1 : 1));
    return { ok: true, dir: clean, via: fsx.kind, items, link: this.link(sourceId) };
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
    const b = await this._ready(sourceId);
    if (b) return b;
    const st = await this._viaShare(sourceId, () => this._shareFor(sourceId).stat(clean));
    if (!st.ok) return no(st.code);
    const fsx = this._shareFor(sourceId);
    const check = await this._checked(sourceId, fsx, clean, st.value.size);
    const playId = crypto.randomBytes(12).toString('base64url');
    const mime = MSH.mimeOf(clean);
    const url = this.stream.openShare(sourceId, clean, { mime, play: playId });
    const key = this._progressKey(sourceId, clean);
    this._remember({ playId, sourceId, kind: 'share', path: clean, key, started: false });
    return {
      ok: true, playId, url, mime, size: st.value.size, via: fsx.kind, check, progress: this.store.progress(key),
      // as media:play answers for Jellyfin: always the original, no converting, no tracks to choose
      itemId: SI.fileId(clean), hls: false, method: 'direct', converted: false, bitrate: null, audioIndex: null, subtitleIndex: null,
      subtitles: [], transcodeReasons: [], link: this.link(sourceId),
    };
  }

  /** The check of a file, read once per size (a file replaced on the NAS is read again). */
  async _checked(sourceId, fsx, path, size) {
    const k = `${sourceId}|${path}|${size}`;
    if (this._checks.has(k)) return this._checks.get(k);
    const check = await this.shareCheck(fsx, path, size);
    this._checks.set(k, check);
    while (this._checks.size > MAX_CHECKS) this._checks.delete(this._checks.keys().next().value);
    return check;
  }

  _sharePath(sourceId, o) {
    const src = this.store.source(sourceId);
    if (!src || !MS.isShare(src.kind)) return null;
    return MSH.clean(o.path || SI.pathOf(o.itemId)) || null;
  }

  /** "Prüfung vor dem Start" without playing: { ok, check, size, via } (the detail column marks the file with it). */
  async shareInspect({ sourceId, path = null, itemId = null }) {
    const clean = this._sharePath(sourceId, { path, itemId });
    if (!clean) return no('not_found');
    const b = await this._ready(sourceId);
    if (b) return b;
    const st = await this._viaShare(sourceId, () => this._shareFor(sourceId).stat(clean));
    if (!st.ok) return no(st.code);
    const fsx = this._shareFor(sourceId);
    return { ok: true, check: await this._checked(sourceId, fsx, clean, st.value.size), size: st.value.size, via: fsx.kind };
  }

  /** VLC there? ("In VLC öffnen" / "In anderer App öffnen") */
  externalInfo() { return this.external.info(); }

  /**
   * A share's file in another app: `app` 'vlc' (a loopback address of this PC, works for SMB and WebDAV) or 'default'
   * (Windows' app for the file type, with the UNC path: SMB only) → { ok, app } | { ok: false, code: 'no_vlc' |
   * 'unsupported' | … }.
   */
  async shareExternal({ sourceId, path = null, itemId = null, app = 'vlc', title = null }) {
    const clean = this._sharePath(sourceId, { path, itemId });
    if (!clean) return no('not_found');
    const b = await this._ready(sourceId);
    if (b) return b;
    const fsx = this._shareFor(sourceId);
    if (app === 'default') {
      const unc = fsx && fsx.kind === 'smb' && typeof fsx.uncOf === 'function' ? fsx.uncOf(clean) : null;
      if (!unc) return no('unsupported');
      const c = await fsx.connect();
      if (!c.ok) return no(c.code);
      return this.external.openWithDefault(unc);
    }
    const url = this.stream.openShare(sourceId, clean, { mime: MSH.mimeOf(clean), play: `x${crypto.randomBytes(9).toString('base64url')}` });
    if (!url) return no('not_found');
    return this.external.openInVlc(url, { title: typeof title === 'string' ? title : MSH.baseName(clean) });
  }

  // ── the end ─────────────────────────────────────────────────

  /** Another server / token is about to be configured: the server signed in now is kept for forgetAll(). */
  serverChanging() {
    if (this._server && typeof this._server.serverChanging === 'function') { try { this._server.serverChanging(); } catch { /* gone */ } }
  }

  /** Signed out of GateControl / another server: nothing of Medien is left on this PC. */
  async forgetAll() {
    // first the plugin of the server signed in before deletes this PC in its Jellyfin servers (best effort, not awaited)
    if (this._server && typeof this._server.signOutAll === 'function') { try { this._server.signOutAll(); } catch { /* gone */ } }
    this.stream.clear();
    this._plays.clear();
    this._flows.clear();
    this._pins.clear();
    this._links.clear();
    this._homeCache = null;
    this._dropShares();
    this._libs.clear();
    this._checks.clear();
    this.external.forget();
    this.store.forgetAll();
    // the server's list, its times and the plugin's state belong to the person signed in before
    if (this._server && typeof this._server.reset === 'function') { try { this._server.reset(); } catch { /* gone */ } }
    await this.lanRoute.removeHostRoutes().catch(() => {});
    this._emitState();
    return { ok: true };
  }

  /** The app quits: the host routes and the SMB connections of this session go. */
  async close() {
    this._dropShares();
    this.external.close();
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
