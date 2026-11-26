'use strict';

/**
 * Medien (Stufe 4e): the sources of Medien › Quellen as the store keeps them — pure, unit-tested with the cases of
 * Android's MediaSourceStore.
 *
 * A source: { id, kind: 'jellyfin' | 'smb' | 'webdav', name, address, userId?, userName?, token?, serverId?,
 * alwaysOriginal, password?, pairWith?, tlsPin?, useExisting? }. `token` (Jellyfin's access of this PC) and
 * `password` (a share's) are secrets: never logged, never sent to the page (publicSource), kept only encrypted
 * (services/media-store.js: safeStorage / DPAPI). `tlsPin`: the SHA-256 of a self-signed certificate confirmed once
 * (WebDAV of a Synology, a Jellyfin on HTTPS). `useExisting`: SMB with the Explorer's own connection to that server
 * ("Mit dem Explorer-Zugang verwenden" after Windows' error 1219).
 *
 * The same share set up as SMB and as WebDAV (the same folder name) is one pair: at home SMB, away WebDAV (decision 9).
 *
 * Medien-Plugin (W1): a source of the server (`managed: true`, utils/media-server.js) carries besides `sid` (the
 * plugin's source id), `awayMode` ('vpn' | 'direct') and `awayAddress` (https, the admin's exception), a Jellyfin
 * source `mapUserId` / `mapUserName` (the user the plugin links), `problem`, `jfDeviceId` / `jfDeviceName` (the device id
 * and name the plugin gives this PC), `quickConnect`, `pairedUserId` (whose access `token` is); a share `secretRev`
 * (the server's), `pwRev` (the one of the password kept) and `checkedRev` ("SMB geprüft" reported for it).
 */

const MA = require('./media-address');
const { normalizeFingerprint } = require('./home-cache');

const MAX_SOURCES = 8;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const isShare = (kind) => kind === 'smb' || kind === 'webdav';

const s = (v, max = 200) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

/** Can be asked: a Jellyfin source signed in, a share always (its password goes along on each connection). */
function ready(src) {
  return !!src && (isShare(src.kind) || !!src.token);
}

/** The share of the other protocol with the same folder name that is not paired yet. */
function partnerOf(src, list) {
  const other = src.kind === 'smb' ? 'webdav' : src.kind === 'webdav' ? 'smb' : null;
  if (!other) return null;
  const folder = MA.folderName(src.kind, src.address);
  if (!folder) return null;
  return list.find((x) => x.id !== src.id && x.kind === other && !x.pairWith && MA.folderName(x.kind, x.address) === folder) || null;
}

/**
 * Adds `src` to `list`, or replaces the one of the same server and person (signed in again) or the same share; a
 * share is paired with its partner. → { list, kept } (the source as stored, with the id it keeps).
 */
function save(list, src) {
  const same = list.find((x) => x.id === src.id)
    || list.find((x) => src.serverId && x.serverId === src.serverId && x.userId === src.userId)
    || list.find((x) => isShare(src.kind) && x.kind === src.kind && x.address === src.address);
  let kept = same ? { ...src, id: same.id, alwaysOriginal: same.alwaysOriginal, pairWith: same.pairWith || null } : { ...src };
  let next = same ? list.map((x) => (x.id === same.id ? kept : x)) : [...list, kept];
  if (isShare(kept.kind) && !kept.pairWith) {
    const partner = partnerOf(kept, next);
    if (partner) {
      kept = { ...kept, pairWith: partner.id };
      next = next.map((x) => (x.id === kept.id ? kept : x.id === partner.id ? { ...x, pairWith: kept.id } : x));
    }
  }
  return { list: next, kept };
}

/** Removes `id`; its partner (SMB ↔ WebDAV) stays alone. */
function remove(list, id) {
  return list.filter((x) => x.id !== id).map((x) => (x.pairWith === id ? { ...x, pairWith: null } : x));
}

/** The shares the page shows, a pair once (as its SMB source). */
function shares(all) {
  return all.filter((x) => isShare(x.kind)).filter((x) => !(x.kind === 'webdav'
    && all.some((o) => o.id === x.pairWith && o.pairWith === x.id && o.kind === 'smb')));
}

/**
 * Which of a pair is used (decision 9): at home SMB (fastest), away WebDAV (HTTP with ranges bears the latency of the
 * tunnel better than the chatty SMB). Not known yet: as at home. One of them alone is used anywhere.
 */
function shareFor(smb, webdav, atHome) {
  return atHome === false ? (webdav || smb || null) : (smb || webdav || null);
}

/** The pair of `src` in `list`: { smb, webdav } (one of them may be null). */
function pairOf(src, list) {
  const partner = src.pairWith ? list.find((x) => x.id === src.pairWith && x.pairWith === src.id) : null;
  const both = [src, partner].filter(Boolean);
  return { smb: both.find((x) => x.kind === 'smb') || null, webdav: both.find((x) => x.kind === 'webdav') || null };
}

function encode(list) {
  return JSON.stringify({
    sources: list.slice(0, MAX_SOURCES).map((x) => {
      const o = { id: x.id, kind: x.kind, name: x.name, address: x.address };
      for (const k of ['userId', 'userName', 'token', 'serverId', 'password', 'pairWith', 'tlsPin']) if (x[k]) o[k] = x[k];
      o.alwaysOriginal = x.alwaysOriginal === true;
      if (x.useExisting === true) o.useExisting = true;
      if (x.managed === true) {
        o.managed = true;
        for (const k of MANAGED_TEXT) if (x[k]) o[k] = x[k];
        for (const k of MANAGED_NUM) if (Number.isSafeInteger(x[k])) o[k] = x[k];
        if (typeof x.quickConnect === 'boolean') o.quickConnect = x.quickConnect;
      }
      return o;
    }),
  });
}

const MANAGED_TEXT = ['sid', 'awayMode', 'awayAddress', 'mapUserId', 'mapUserName', 'problem', 'jfDeviceId', 'jfDeviceName', 'pairedUserId'];
const MANAGED_NUM = ['secretRev', 'pwRev', 'checkedRev'];

function managedOf(x) {
  const o = { managed: true };
  for (const k of MANAGED_TEXT) o[k] = s(x[k], k === 'awayAddress' ? 512 : 128);
  for (const k of MANAGED_NUM) o[k] = Number.isSafeInteger(x[k]) && x[k] >= 0 ? x[k] : null;
  o.awayMode = o.awayMode === 'direct' && o.awayAddress && /^https:\/\//.test(o.awayAddress) ? 'direct' : 'vpn';
  o.quickConnect = typeof x.quickConnect === 'boolean' ? x.quickConnect : null;
  return o;
}

/** The stored text → the sources; broken or foreign entries are left out, a partner that is gone is none. */
function decode(text) {
  let o;
  try { o = JSON.parse(typeof text === 'string' ? text : ''); } catch { return []; }
  const raw = o && Array.isArray(o.sources) ? o.sources : [];
  const seen = new Set();
  const list = [];
  for (const x of raw) {
    if (!x || typeof x !== 'object') continue;
    const kind = MA.KINDS.includes(x.kind) ? x.kind : null;
    const id = typeof x.id === 'string' && ID_RE.test(x.id) ? x.id : null;
    const address = kind && typeof x.address === 'string' ? MA.normalizeShare(kind, x.address) : null;
    if (!kind || !id || !address || seen.has(id)) continue;
    seen.add(id);
    list.push({
      id,
      kind,
      name: s(x.name, 64) || 'Jellyfin',
      address,
      userId: s(x.userId, 64),
      userName: s(x.userName, 128),
      token: s(x.token, 256),
      serverId: s(x.serverId, 64),
      alwaysOriginal: x.alwaysOriginal === true,
      // a password is taken as it is (spaces of a typed password are its own)
      password: typeof x.password === 'string' && x.password ? x.password : null,
      pairWith: s(x.pairWith, 64),
      tlsPin: normalizeFingerprint(x.tlsPin),
      useExisting: x.useExisting === true,
      ...(x.managed === true ? managedOf(x) : {}),
    });
    if (list.length >= MAX_SOURCES) break;
  }
  return list.map((x) => (x.pairWith && !list.some((p) => p.id === x.pairWith && p.pairWith === x.id && p.kind !== x.kind && isShare(p.kind) && isShare(x.kind))
    ? { ...x, pairWith: null } : x));
}

/** A source for the page and the logs: no token, no password — only whether there is one. */
function publicSource(x) {
  if (!x) return null;
  return {
    id: x.id,
    kind: x.kind,
    name: x.name,
    address: x.address,
    unc: x.kind === 'smb' ? (MA.parseSmb(x.address) || {}).unc || null : null,
    userId: x.userId || null,
    userName: x.userName || null,
    serverId: x.serverId || null,
    alwaysOriginal: x.alwaysOriginal === true,
    pairWith: x.pairWith || null,
    signedIn: x.kind === 'jellyfin' ? !!x.token : null,
    hasPassword: isShare(x.kind) ? !!x.password : null,
    pinned: !!x.tlsPin,
    useExisting: x.useExisting === true,
    ready: ready(x),
    // Medien-Plugin: a source of the server (no secret here either)
    managed: x.managed === true,
    sid: x.managed ? x.sid || null : null,
    awayMode: x.managed ? x.awayMode || 'vpn' : null,
    awayAddress: x.managed ? x.awayAddress || null : null,
    problem: x.managed ? x.problem || null : null,
    mapUserName: x.managed && x.kind === 'jellyfin' ? x.mapUserName || null : null,
    deviceName: x.managed && x.kind === 'jellyfin' ? x.jfDeviceName || null : null,
    quickConnect: x.managed && x.kind === 'jellyfin' && typeof x.quickConnect === 'boolean' ? x.quickConnect : null,
    smbChecked: x.managed && x.kind === 'smb' ? Number.isSafeInteger(x.checkedRev) && x.checkedRev === x.pwRev : null,
  };
}

module.exports = { MAX_SOURCES, ID_RE, isShare, ready, partnerOf, save, remove, shares, shareFor, pairOf, encode, decode, publicSource };
