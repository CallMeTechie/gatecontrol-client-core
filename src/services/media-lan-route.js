'use strict';

/**
 * Medien (Stufe 4e, Risiko 6 / spike): which way Windows sends a connection to the NAS, and — where the VPN would
 * carry it — the host route that keeps it in the LAN (Plan B). Windows only; elsewhere everything answers
 * "unsupported" and changes nothing.
 *
 *   diagnose(nas, lanAddress) → { free: { ifIndex, source, nextHop, metric }, bound: { … }, tunnel, bindingHolds,
 *     hostRoute }   GetBestRoute2 (iphlpapi through koffi) asked twice: as Windows picks on its own (SMB, the
 *     Explorer) and with the LAN address as the source (our bound HTTP sockets). Nothing is sent to the NAS.
 *   ensureHostRoute(nas, lanAddress) → { ok, added }   when the way on its own goes through another adapter (the
 *     tunnel): `netsh interface ipv4 add route <nas>/32 interface=<LAN> nexthop=<gateway or on-link> metric=1
 *     store=active` — only in memory (gone with a restart), only for the NAS's address, only while Medien needs it.
 *   removeHostRoutes() → removes every route this service added (the app quits, the source goes, the tunnel is down).
 *
 * The app runs elevated (it creates the WireGuard adapter), so netsh may change routes; a failure is reported, never
 * thrown, and Medien then plays through the tunnel as before.
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const HC = require('../utils/home-cache');
const L = require('../utils/media-lan');

const execFileAsync = promisify(execFile);

const AF_INET = 2;
const SOCKADDR_INET_SIZE = 28;
// MIB_IPFORWARD_ROW2 (netioapi.h, x64): InterfaceLuid 0, InterfaceIndex 8, DestinationPrefix 12 (28 + 1, padded to 32),
// NextHop 44 (SOCKADDR_INET 28), SitePrefixLength 72, ValidLifetime 76, PreferredLifetime 80, Metric 84, Protocol 88,
// Loopback 92 … Origin 100 → 104 bytes.
const ROW_SIZE = 104;
const OFF_IFINDEX = 8;
const OFF_NEXTHOP = 44;
const OFF_METRIC = 84;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** SOCKADDR_IN in a SOCKADDR_INET (28 bytes): family 2, port 0, the address. */
function sockaddr(ip) {
  const b = Buffer.alloc(SOCKADDR_INET_SIZE);
  if (!ip) return b;
  b.writeUInt16LE(AF_INET, 0);
  ip.split('.').forEach((p, k) => { b[4 + k] = Number(p); });
  return b;
}

function ipOf(buf, off = 0) {
  if (buf.readUInt16LE(off) !== AF_INET) return null;
  return `${buf[off + 4]}.${buf[off + 5]}.${buf[off + 6]}.${buf[off + 7]}`;
}

let iphlp;

/** iphlpapi through koffi → { bestRoute(dest, source?) → { error, ifIndex, nextHop, metric, source } }; null when not. */
function loadIphlp(koffi = null) {
  if (iphlp !== undefined && !koffi) return iphlp;
  let api = null;
  try {
    if (process.platform !== 'win32' && !koffi) throw new Error('not Windows');
    const k = koffi || require('koffi');
    const lib = k.load('iphlpapi.dll');
    const getBestRoute2 = lib.func('GetBestRoute2', 'uint32_t', ['void *', 'uint32_t', 'void *', 'void *', 'uint32_t', 'void *', 'void *']);
    api = {
      bestRoute(dest, source = null) {
        const row = Buffer.alloc(ROW_SIZE + 24);
        const best = Buffer.alloc(SOCKADDR_INET_SIZE);
        const error = getBestRoute2(null, 0, source ? sockaddr(source) : null, sockaddr(dest), 0, row, best);
        if (error !== 0) return { error };
        return {
          error: 0,
          ifIndex: row.readUInt32LE(OFF_IFINDEX),
          nextHop: ipOf(row, OFF_NEXTHOP),
          metric: row.readUInt32LE(OFF_METRIC),
          source: ipOf(best, 0),
        };
      },
    };
  } catch {
    api = null;
  }
  if (!koffi) iphlp = api;
  return api;
}

class MediaLanRoute {
  /**
   * @param {object} [opts]
   * @param {object} [opts.api] - loadIphlp() (tests: a fake)
   * @param {Function} [opts.run] - (file, args) → Promise (tests: a fake netsh)
   * @param {object} [opts.log]
   */
  constructor({ api = undefined, run = null, log = null } = {}) {
    this.api = api === undefined ? loadIphlp() : api;
    this.run = typeof run === 'function' ? run : (file, args) => execFileAsync(file, args, { windowsHide: true });
    this.log = log || noopLog();
    this._routes = new Map(); // nas → { ifIndex, nextHop }
  }

  get supported() { return !!this.api; }

  _best(dest, source) {
    try {
      const r = this.api.bestRoute(dest, source);
      return r && r.error === 0 ? { ifIndex: r.ifIndex, source: r.source, nextHop: r.nextHop, metric: r.metric } : null;
    } catch {
      return null;
    }
  }

  /** How a connection to `nas` goes on its own and bound to `lanAddress` (see above). */
  diagnose(nas, lanAddress) {
    if (!this.api) return { supported: false };
    if (!HC.isPrivateV4(nas) || !HC.isPrivateV4(lanAddress)) return { supported: true, error: 'invalid' };
    const free = this._best(nas, null);
    const bound = this._best(nas, lanAddress);
    return { supported: true, free, bound, ...L.routeVerdict(lanAddress, free, bound) };
  }

  /** Plan B: the route for `nas` alone through the LAN adapter, when the way on its own is the tunnel. */
  async ensureHostRoute(nas, lanAddress) {
    const d = this.diagnose(nas, lanAddress);
    if (!d.supported) return { ok: false, code: 'unsupported' };
    if (d.error) return { ok: false, code: d.error };
    if (!d.tunnel) return { ok: true, added: false, diagnosis: d };
    if (!d.bound || d.bound.source !== lanAddress) return { ok: false, code: 'no_lan_route', diagnosis: d };
    const ifIndex = d.bound.ifIndex;
    const nextHop = d.bound.nextHop && d.bound.nextHop !== '0.0.0.0' && HC.isPrivateV4(d.bound.nextHop) ? d.bound.nextHop : '0.0.0.0';
    if (!Number.isInteger(ifIndex) || ifIndex <= 0) return { ok: false, code: 'no_lan_route', diagnosis: d };
    try {
      await this.run('netsh', ['interface', 'ipv4', 'add', 'route', `${nas}/32`, `interface=${ifIndex}`, `nexthop=${nextHop}`, 'metric=1', 'store=active']);
    } catch (err) {
      const out = `${(err && err.stdout) || ''}`;
      // already there (an earlier start of the app): it is ours to remove as well
      if (!/exist|bereits|vorhanden/i.test(out)) {
        this.log.warn(`Medien: host route for the NAS not added (${(err && err.code) || 'netsh'})`);
        return { ok: false, code: 'failed', diagnosis: d };
      }
    }
    this._routes.set(nas, { ifIndex, nextHop });
    const after = this.diagnose(nas, lanAddress);
    this.log.info(`Medien: NAS ${nas} through the LAN (interface ${ifIndex}), not the tunnel`);
    return { ok: !after.tunnel, added: true, diagnosis: after };
  }

  async removeHostRoute(nas) {
    const r = this._routes.get(nas);
    if (!r) return { ok: true, removed: false };
    this._routes.delete(nas);
    try {
      await this.run('netsh', ['interface', 'ipv4', 'delete', 'route', `${nas}/32`, `interface=${r.ifIndex}`, `nexthop=${r.nextHop}`, 'store=active']);
    } catch { /* gone already */ }
    return { ok: true, removed: true };
  }

  async removeHostRoutes() {
    for (const nas of [...this._routes.keys()]) await this.removeHostRoute(nas);
  }

  routes() { return [...this._routes.keys()]; }
}

MediaLanRoute.loadIphlp = loadIphlp;
MediaLanRoute.sockaddr = sockaddr;
MediaLanRoute.ipOf = ipOf;

module.exports = MediaLanRoute;
