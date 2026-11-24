'use strict';

/**
 * Medien (Stufe 4e): the server search of Medien › Quellen — Jellyfin answers the UDP broadcast
 * "who is JellyfinServer?" on port 7359 with `{"Address":"http://192.168.1.20:8096","Id":"…","Name":"DS918+"}`
 * (as Android's JellyfinDiscovery).
 *
 * Only over the real adapters, never over the VPN: one socket per own LAN address (utils/media-lan.js lanLinks — no
 * WireGuard / GateControl / virtual adapter), bound to that address, asking its subnet's broadcast and
 * 255.255.255.255 (a socket bound to an address sends the limited broadcast out of that adapter only). The same server
 * is listed once; at most 16; never throws.
 *
 * discover({ timeoutMs?, port?, targets? }) → [{ address, id, name }]
 */

const dgram = require('dgram');
const os = require('os');
const J = require('../utils/media-jellyfin');
const L = require('../utils/media-lan');

const TIMEOUT_MS = 2500;
const MAX_SERVERS = 16;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class MediaDiscovery {
  /**
   * @param {object} [opts]
   * @param {() => object} [opts.networkInterfaces] - os.networkInterfaces (tests)
   * @param {object} [opts.dgram]
   * @param {object} [opts.log]
   */
  constructor({ networkInterfaces = os.networkInterfaces, dgram: dg = dgram, log = null } = {}) {
    this.networkInterfaces = networkInterfaces;
    this.dgram = dg;
    this.log = log || noopLog();
  }

  /** The ways to ask: [{ bind: own LAN address, targets: [subnet broadcast, 255.255.255.255] }]. */
  plan() {
    let ifaces = {};
    try { ifaces = this.networkInterfaces() || {}; } catch { ifaces = {}; }
    const seen = new Set();
    const out = [];
    for (const l of L.lanLinks(ifaces)) {
      if (seen.has(l.address)) continue;
      seen.add(l.address);
      const b = J.broadcastOf(l.address, l.prefix);
      out.push({ bind: l.address, targets: [b, '255.255.255.255'].filter(Boolean) });
    }
    return out;
  }

  /**
   * opts.ways: [{ bind, targets }] instead of plan() (tests: 127.0.0.1 and a fake server). → the servers found.
   */
  async discover({ timeoutMs = TIMEOUT_MS, port = J.DISCOVERY_PORT, ways = null } = {}) {
    const list = Array.isArray(ways) ? ways : this.plan();
    if (!list.length) return [];
    const found = new Map();
    const sockets = [];
    const question = Buffer.from(J.DISCOVERY_MESSAGE, 'utf8');
    await Promise.all(list.map((w) => new Promise((resolve) => {
      let s;
      try { s = this.dgram.createSocket({ type: 'udp4', reuseAddr: false }); } catch (err) { this.log.debug(`Jellyfin search: no socket (${err.code || 'error'})`); resolve(); return; }
      sockets.push(s);
      s.on('error', (err) => { this.log.debug(`Jellyfin search: ${err.code || 'error'}`); resolve(); });
      s.on('message', (msg, rinfo) => {
        if (found.size >= MAX_SERVERS || msg.length > 4096) return;
        const hint = J.parseDiscovery(msg.toString('utf8'), rinfo && rinfo.address);
        if (hint && !found.has(hint.id)) found.set(hint.id, hint);
      });
      s.bind({ address: w.bind, port: 0 }, () => {
        try { s.setBroadcast(true); } catch { /* not every adapter */ }
        for (const t of [...new Set(w.targets)]) {
          s.send(question, port, t, (err) => { if (err) this.log.debug(`Jellyfin search: not sent (${err.code || 'error'})`); });
        }
        resolve();
      });
    })));
    await new Promise((r) => setTimeout(r, Math.max(1, timeoutMs)));
    for (const s of sockets) { try { s.close(); } catch { /* closed */ } }
    return [...found.values()];
  }
}

MediaDiscovery.TIMEOUT_MS = TIMEOUT_MS;

module.exports = MediaDiscovery;
