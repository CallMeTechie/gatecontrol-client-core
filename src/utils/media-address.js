'use strict';

/**
 * Medien (Stufe 4e): the address of a media server or share as typed in Medien › Quellen or found in the home
 * network — `192.168.1.20`, `192.168.1.20:8096`, `http://nas.local:8096/jellyfin`, `\\192.168.1.20\filme`,
 * `https://192.168.1.20:5006/filme`. Pure, unit-tested; the same cases as Android's MediaAddress (:core:media).
 *
 * Plain HTTP only in the home network (a private IPv4 address, a `.local` / `.lan` / `.home.arpa` name or a name
 * without dots): Jellyfin runs on HTTP there, and away the connection goes through the WireGuard tunnel. Any other
 * host needs HTTPS — the access token never goes unencrypted over the internet.
 */

const { isPrivateV4 } = require('./home-cache');

const JELLYFIN_HTTP_PORT = 8096;
const SMB_PORT = 445;
const KINDS = Object.freeze(['jellyfin', 'smb', 'webdav']);
const LOCAL_SUFFIXES = ['.local', '.lan', '.home.arpa', '.fritz.box', '.internal'];
const SMB_HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;
const BAD_SHARE_CHARS = /["<>|?*:]/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;

/** 10/8, 172.16/12, 192.168/16, strict dotted form. */
function isPrivateIpv4(address) {
  return isPrivateV4(address);
}

/** A host of the home network: private IPv4, a local name or a single label ("nas"). */
function isHomeHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (isPrivateIpv4(h)) return true;
  if (!h || h.includes(':') || h.startsWith('[')) return false;
  if (/^[\d.]+$/.test(h)) return false;
  if (!h.includes('.')) return true;
  return LOCAL_SUFFIXES.some((s) => h.endsWith(s));
}

function parseUrl(s) {
  try { return new URL(s); } catch { return null; }
}

/** The base URL without a trailing slash, or null when `input` is not a usable address. */
function normalize(input, defaultPort = JELLYFIN_HTTP_PORT) {
  const raw = String(input == null ? '' : input).trim().replace(/\/+$/, '');
  if (!raw || raw.length > 512 || /\s/.test(raw) || CONTROL_RE.test(raw)) return null;
  const hasScheme = raw.includes('://');
  const withScheme = hasScheme ? raw : `http://${raw}`;
  const u = parseUrl(withScheme);
  if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return null;
  if (u.username || u.password || u.search || u.hash || withScheme.includes('?') || withScheme.includes('#')) return null;
  if (!u.hostname) return null;
  const explicitPort = /^[a-zA-Z]+:\/\/[^/]+:(\d+)/.test(withScheme);
  const scheme = u.protocol.slice(0, -1);
  if (scheme === 'http' && !isHomeHost(u.hostname)) return null;
  let port = u.port;
  if (!explicitPort && !hasScheme) port = String(defaultPort);
  const defaultOf = scheme === 'https' ? '443' : '80';
  const portPart = port && port !== defaultOf ? `:${port}` : '';
  const path = u.pathname.replace(/\/+$/, '');
  return `${scheme}://${u.hostname}${portPart}${path}`;
}

/**
 * A WebDAV folder as typed: `https://192.168.1.20:5006/filme` (without a scheme HTTPS is meant). Plain HTTP only in
 * the home network, as normalize(); the port stays as given (443 for HTTPS without one).
 */
function normalizeWebDav(input) {
  const raw = String(input == null ? '' : input).trim();
  if (!raw) return null;
  const n = normalize(raw.includes('://') ? raw : `https://${raw}`);
  return n && (n.startsWith('https://') || n.startsWith('http://')) ? n : null;
}

/**
 * An SMB share as typed: `\\nas\filme`, `\\nas\filme\Neu`, `smb://192.168.1.20/filme`, `nas/filme`. Only a host of
 * the home network: SMB never goes over the internet (away it goes through the tunnel).
 * → { host, port, share, path, url: 'smb://nas/filme/Neu', unc: '\\\\nas\\filme\\Neu' } or null.
 */
function parseSmb(input) {
  let raw = String(input == null ? '' : input).trim().replace(/\\/g, '/');
  if (!raw || raw.length > 512 || CONTROL_RE.test(raw)) return null;
  if (/^smb:\/\//i.test(raw)) raw = raw.slice(6);
  else if (raw.includes('://')) return null;
  else raw = raw.replace(/^\/+/, '');
  const parts = raw.split('/').map((p) => p.trim()).filter(Boolean);
  if (parts.length < 2) return null;
  if (parts.some((p) => p === '.' || p === '..' || p.includes('@'))) return null;
  const hostPort = parts[0];
  const colon = hostPort.indexOf(':');
  const host = colon >= 0 ? hostPort.slice(0, colon) : hostPort;
  let port = SMB_PORT;
  if (colon >= 0) {
    const p = hostPort.slice(colon + 1);
    if (!/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535) return null;
    port = Number(p);
  }
  if (!SMB_HOST_RE.test(host) || !isHomeHost(host)) return null;
  const share = parts[1];
  if (share.length > 80 || BAD_SHARE_CHARS.test(share)) return null;
  const path = parts.slice(2).join('/');
  if (BAD_SHARE_CHARS.test(path)) return null;
  return smb(host.toLowerCase(), port, share, path);
}

function smb(host, port, share, path) {
  return {
    host, port, share, path,
    url: `smb://${host}${port !== SMB_PORT ? `:${port}` : ''}/${share}${path ? `/${path}` : ''}`,
    unc: `\\\\${host}\\${share}${path ? `\\${path.replace(/\//g, '\\')}` : ''}`,
  };
}

/** A share's address as the store keeps it; null when it is not one of `kind`. */
function normalizeShare(kind, input) {
  if (kind === 'smb') { const s = parseSmb(input); return s ? s.url : null; }
  if (kind === 'webdav') return normalizeWebDav(input);
  if (kind === 'jellyfin') return normalize(input);
  return null;
}

/** The last folder of a share's address ("filme" of `\\nas\filme` and of `https://nas:5006/filme`), lower case. */
function folderName(kind, address) {
  let name = null;
  if (kind === 'smb') {
    const s = parseSmb(address);
    if (s) name = s.path ? s.path.split('/').pop() : s.share;
  } else if (kind === 'webdav') {
    const u = parseUrl(address);
    if (u) {
      const segs = u.pathname.split('/').filter(Boolean);
      name = segs.length ? decodeSegment(segs[segs.length - 1]) : null;
    }
  }
  return name ? name.toLowerCase() : null;
}

function decodeSegment(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** The host of a base URL ("192.168.1.20"), of an SMB address its server; null when it is not one. */
function host(address) {
  const s = String(address || '');
  if (/^smb:\/\//i.test(s)) { const p = parseSmb(s); return p ? p.host : null; }
  const u = parseUrl(s);
  return u && u.hostname ? u.hostname.replace(/^\[|\]$/g, '') : null;
}

/** The TCP port a source is reached at: Jellyfin/WebDAV from its URL, SMB 445 (or the one given). */
function portOf(kind, address) {
  if (kind === 'smb') { const p = parseSmb(address); return p ? p.port : null; }
  const u = parseUrl(address);
  if (!u) return null;
  if (u.port) return Number(u.port);
  return u.protocol === 'https:' ? 443 : 80;
}

module.exports = {
  JELLYFIN_HTTP_PORT,
  SMB_PORT,
  KINDS,
  isPrivateIpv4,
  isHomeHost,
  normalize,
  normalizeWebDav,
  parseSmb,
  normalizeShare,
  folderName,
  host,
  portOf,
};
