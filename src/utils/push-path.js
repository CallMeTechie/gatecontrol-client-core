'use strict';

/**
 * Kill-switch awareness of the push channel.
 *
 * Outside the tunnel the kill switch only lets TCP 443 to the WireGuard
 * endpoint IP(s) through (services/killswitch.js, rule "Allow_API"). The push
 * stream goes to the server URL. When that URL resolves to other addresses
 * than the endpoint, or uses another port than 443, push only works through
 * the tunnel while the kill switch is on — the settings page warns about it
 * ("Push nur durch den Tunnel").
 *
 * Electron-free; DNS lookup is injectable for tests.
 */

const dnsPromises = require('dns').promises;
const net = require('net');

/** Endpoint (host, port) of the first [Peer] of a WireGuard config, or null. */
function parseWgEndpoint(config) {
  if (typeof config !== 'string') return null;
  for (const raw of config.split(/\r?\n/)) {
    const m = raw.trim().match(/^Endpoint\s*=\s*(.+)$/i);
    if (!m) continue;
    const v = m[1].trim();
    const bracket = v.match(/^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/);
    if (bracket) return { host: bracket[1], port: Number(bracket[2]) };
    const plain = v.match(/^([A-Za-z0-9.-]{1,253}):(\d{1,5})$/);
    if (plain) return { host: plain[1], port: Number(plain[2]) };
    return null;
  }
  return null;
}

async function resolveAll(host, lookup) {
  if (net.isIP(host)) return [host];
  const res = await lookup(host, { all: true });
  const list = (Array.isArray(res) ? res : [res]).map((r) => (typeof r === 'string' ? r : r && r.address)).filter(Boolean);
  return [...new Set(list)];
}

/**
 * Compare the push target (server URL) with the WireGuard endpoint.
 *
 * @param {object} opts
 * @param {string} opts.serverUrl - https://host[:port]
 * @param {string|null} opts.wgConfig - WireGuard config text (null = unknown)
 * @param {Function} [opts.lookup] - dns.promises.lookup compatible
 * @returns {Promise<{ serverHost: ?string, serverPort: ?number, endpointHost: ?string,
 *   serverIps: string[], endpointIps: string[], sameHost: ?boolean, port443: ?boolean,
 *   coveredByKillSwitch: ?boolean }>} null fields = could not be determined
 */
async function checkPushPath({ serverUrl, wgConfig, lookup } = {}) {
  const dnsLookup = lookup || ((h, o) => dnsPromises.lookup(h, o));
  const out = {
    serverHost: null, serverPort: null, endpointHost: null,
    serverIps: [], endpointIps: [], sameHost: null, port443: null, coveredByKillSwitch: null,
  };
  let url;
  try { url = new URL(serverUrl); } catch { return out; }
  out.serverHost = url.hostname.replace(/^\[|\]$/g, '');
  out.serverPort = url.port ? Number(url.port) : (url.protocol === 'http:' ? 80 : 443);
  out.port443 = out.serverPort === 443;

  const ep = parseWgEndpoint(wgConfig);
  if (!ep) return out;
  out.endpointHost = ep.host;
  out.sameHost = ep.host.toLowerCase() === out.serverHost.toLowerCase();

  try {
    out.serverIps = await resolveAll(out.serverHost, dnsLookup);
    out.endpointIps = out.sameHost ? out.serverIps.slice() : await resolveAll(ep.host, dnsLookup);
  } catch {
    // DNS unavailable: only a literal host match can be judged.
    if (out.sameHost) out.coveredByKillSwitch = out.port443;
    return out;
  }
  if (!out.serverIps.length || !out.endpointIps.length) return out;
  const endpointSet = new Set(out.endpointIps);
  out.coveredByKillSwitch = out.port443 && out.serverIps.every((ip) => endpointSet.has(ip));
  return out;
}

/**
 * Push runs only through the tunnel: kill switch on and the push target is
 * not covered by its exception.
 */
function isTunnelOnly(path, killSwitchActive) {
  return killSwitchActive === true && !!path && path.coveredByKillSwitch === false;
}

module.exports = { parseWgEndpoint, checkPushPath, isTunnelOnly };
