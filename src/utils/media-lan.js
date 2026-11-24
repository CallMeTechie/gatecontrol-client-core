'use strict';

/**
 * Medien (Stufe 4e): which way a connection to the NAS takes — pure, unit-tested.
 *
 * At home the PC talks to the NAS straight through the LAN, also when the GateControl VPN is on. When the tunnel
 * carries the home network as well (split routes with 192.168.1.0/24, the home gateway's LAN in the tunnel), Windows
 * would send the film the long way round through the server. Two means (spike of Stufe 4e, docs/media.md):
 *
 *   1. HTTP (Jellyfin, WebDAV): the socket is bound to the LAN adapter's own address (`localAddress`). Windows' strong
 *      host model (the default for IPv4 since Vista) then looks up the route only among the routes of that adapter —
 *      its on-link subnet, else its default gateway — whatever the tunnel claims.
 *   2. SMB goes through Windows' own redirector (UNC paths), no socket of ours to bind: a host route for the NAS's
 *      address alone through the LAN adapter (`<nas>/32`, metric 1, store=active) while Medien uses it
 *      (services/media-lan-route.js). The same is the fallback when the binding does not hold (weakhostsend on).
 *
 * lanBinding(host, ifaces) → { localAddress, iface, prefix, network } when `host` is a private IPv4 address inside the
 * subnet of a real adapter (os.networkInterfaces(), never the VPN / virtual ones of utils/home-cache.js), else null.
 */

const HC = require('./home-cache');

const toNum = (ip) => ip.split('.').reduce((acc, p) => acc * 256 + Number(p), 0);
const fromNum = (n) => [24, 16, 8, 0].map((sh) => Math.floor(n / 2 ** sh) % 256).join('.');

function prefixOf(entry) {
  if (entry && typeof entry.cidr === 'string') {
    const m = /\/(\d{1,2})$/.exec(entry.cidr);
    if (m) return Number(m[1]);
  }
  if (entry && typeof entry.netmask === 'string') {
    const parts = entry.netmask.split('.').map(Number);
    if (parts.length === 4 && parts.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
      let bits = 0;
      for (const p of parts) bits += (p >>> 0).toString(2).replace(/0/g, '').length;
      return bits;
    }
  }
  return null;
}

/** The real adapters' private IPv4 addresses: [{ iface, address, prefix, network }] (no VPN, no virtual switch). */
function lanLinks(ifaces) {
  const out = [];
  const src = ifaces && typeof ifaces === 'object' ? ifaces : {};
  for (const [name, list] of Object.entries(src)) {
    if (HC.VPN_IF_RE.test(name)) continue;
    for (const a of Array.isArray(list) ? list : []) {
      if (!a || a.internal || (a.family !== 'IPv4' && a.family !== 4) || !HC.isPrivateV4(a.address)) continue;
      const prefix = prefixOf(a);
      if (!Number.isInteger(prefix) || prefix < 8 || prefix > 32) continue;
      const size = 2 ** (32 - prefix);
      const net = toNum(a.address) - (toNum(a.address) % size);
      out.push({ iface: name, address: a.address, prefix, network: `${fromNum(net)}/${prefix}` });
    }
  }
  return out;
}

function inSubnet(ip, link) {
  const size = 2 ** (32 - link.prefix);
  const net = toNum(link.address) - (toNum(link.address) % size);
  const n = toNum(ip);
  return n >= net && n < net + size;
}

/** The LAN adapter to bind a connection to `host` to; null when the host is not in the subnet of a real adapter. */
function lanBinding(host, ifaces) {
  if (!HC.isPrivateV4(host)) return null;
  const links = lanLinks(ifaces).filter((l) => l.address !== host && inSubnet(host, l));
  if (!links.length) return null;
  // the narrowest subnet first (a /24 of the LAN before a /16 of something else)
  links.sort((a, b) => b.prefix - a.prefix);
  const l = links[0];
  return { localAddress: l.address, iface: l.iface, prefix: l.prefix, network: l.network };
}

/**
 * What the route diagnosis (services/media-lan-route.js, GetBestRoute2) found → the way:
 *   free: { ifIndex, source } — the route Windows takes on its own; bound: the same with the LAN address as source.
 * → { tunnel: the NAS goes through another adapter than the LAN on its own, bindingHolds: bound to the LAN address
 *   it takes the LAN adapter, hostRoute: SMB needs the host route (Plan B) }
 */
function routeVerdict(lanAddress, free, bound) {
  const tunnel = !!free && free.source !== lanAddress;
  const bindingHolds = !!bound && bound.source === lanAddress && (!free || !tunnel || bound.ifIndex !== free.ifIndex);
  return { tunnel, bindingHolds, hostRoute: tunnel };
}

const TUNNEL_IF_RE = /gatecontrol|wireguard|\bwg/i;

/**
 * Away: the own address in the GateControl tunnel (the WireGuard adapter), to bind to — a hotel's network may use the
 * same private addresses as the home network; bound to the tunnel's address the connection cannot go to a device of
 * the hotel (strong host model, as above). Null without a tunnel.
 */
function tunnelAddress(ifaces) {
  const src = ifaces && typeof ifaces === 'object' ? ifaces : {};
  for (const [name, list] of Object.entries(src)) {
    if (!TUNNEL_IF_RE.test(name)) continue;
    for (const a of Array.isArray(list) ? list : []) {
      if (a && !a.internal && (a.family === 'IPv4' || a.family === 4) && HC.isPrivateV4(a.address)) return a.address;
    }
  }
  return null;
}

module.exports = { lanLinks, lanBinding, inSubnet, routeVerdict, prefixOf, tunnelAddress };
