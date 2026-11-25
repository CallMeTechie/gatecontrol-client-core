'use strict';

/**
 * Medien-Plugin (Teilstufe W1): the sources of Medien come from the GateControl server — the plugin
 * `gatecontrol-medien`, app API v1 (plugin README "App-API v1"). Pure, unit-tested; the service is
 * services/media-server-sources.js.
 *
 *   normalizeList(raw)      GET v1/sources → { rev, at, media, maxOfflineDays, offlineHintDays, network, cast, sources }
 *                           (unknown fields left out, broken sources skipped; `unchanged: true` for ?since=<rev>)
 *   entriesOf(src)          one server source → the entries MediaStore keeps (a share: its SMB and its WebDAV half)
 *   merge(stored, list)     the stored sources with the server's list: kept (their access), new, gone, taken over
 *                           from the sources set up on this PC before (decision 33 a)
 *   offline(…)              30 / 90 days without the server (decision 36 a)
 *   wayOf(…)                the network rule: home direct, away only through the VPN (or the admin's HTTPS exception)
 *   revokeOf(data)          the silent signal media.revoke
 *
 * An entry of a server source carries `managed: true`, `sid` (the plugin's source id, the same on every device of every
 * person) and the network rule's fields (`awayMode`, `awayAddress`). Its secrets (Jellyfin's access of this PC, a
 * share's password) never come from the list: the access is made on this PC (Quick Connect, confirmed by the plugin),
 * the password is asked once per `secretRev` (GET v1/sources/{id}/secret).
 */

const MA = require('./media-address');
const { normalizeFingerprint } = require('./home-cache');

const PLUGIN_ID = 'gatecontrol-medien';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const SIGNAL_TOPIC = `plugin:${PLUGIN_ID}:media_signal`;
const SOURCE_RE = /^(?:jf|sh)-[1-9][0-9]{0,8}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{4,64}$/;
const WEBDAV_SUFFIX = '_w';
const DAY_MS = 24 * 60 * 60 * 1000;
const UNAVAILABLE_GRACE_MS = DAY_MS; // decision 37 a: hidden at once, deleted after 24 h
const DEFAULT_MAX_OFFLINE_DAYS = 90;
const DEFAULT_HINT_DAYS = 30;
const PROBLEMS = new Set(['no_mapping', 'quick_connect_off']);
const REVOKE_REASONS = new Set(['admin', 'right', 'mapping', 'source', 'user', 'device_removed', 'app']);
const MAX_SOURCES = 8; // utils/media-sources.js MAX_SOURCES: a share takes two entries

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v, max = 200) => (typeof v === 'string' && v.trim() ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : null);
const dayCount = (v, def, min, max) => (Number.isInteger(v) && v >= min && v <= max ? v : def);

/** An https:// base without user, query or fragment (the admin's address for away without VPN), else null. */
function httpsBase(v) {
  const s = str(v, 512);
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || !u.hostname) return null;
  return `https://${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

/**
 * `away` of a source: { mode: 'vpn' } (the default, also for anything unknown or broken: fail closed) or
 * { mode: 'direct', address: 'https://…' } (the admin's exception "Unterwegs ohne VPN erlauben").
 */
function awayOf(a) {
  if (isObj(a) && a.mode === 'direct') {
    const address = httpsBase(a.address);
    if (address) return { mode: 'direct', address };
  }
  return { mode: 'vpn', address: null };
}

function probeOf(p) {
  if (!isObj(p)) return null;
  let u;
  try { u = new URL(String(p.url || '')); } catch { return null; }
  if (u.username || u.password || !MA.isPrivateIpv4(u.hostname)) return null;
  if (p.kind === 'jellyfin' && (u.protocol === 'http:' || u.protocol === 'https:')) {
    const serverId = str(p.serverId, 64);
    return serverId ? { kind: 'jellyfin', url: u.toString(), serverId: serverId.toLowerCase() } : null;
  }
  if (p.kind === 'tls' && u.protocol === 'https:') {
    const certSha256 = normalizeFingerprint(p.certSha256);
    return certSha256 ? { kind: 'tls', url: u.toString(), certSha256 } : null;
  }
  return null;
}

function jellyfinOf(x) {
  const address = MA.normalize((isObj(x.home) && x.home.address) || x.address);
  if (!address) return null;
  const user = isObj(x.user) && str(x.user.id, 64) ? { id: str(x.user.id, 64), name: str(x.user.name, 128) } : null;
  const device = isObj(x.device) && typeof x.device.id === 'string' && DEVICE_ID_RE.test(x.device.id)
    ? { id: x.device.id, name: str(x.device.name, 120) || 'GateControl' } : null;
  return {
    id: x.id, kind: 'jellyfin', name: str(x.name, 64) || 'Jellyfin',
    serverId: str(x.serverId, 64), version: str(x.version, 32),
    home: { address }, away: awayOf(x.away), user,
    problem: PROBLEMS.has(x.problem) ? x.problem : user ? null : 'no_mapping',
    device, paired: x.paired === true,
    quickConnect: typeof x.quickConnect === 'boolean' ? x.quickConnect : null,
    downloads: x.downloads !== false, alwaysOriginal: x.alwaysOriginal === true,
  };
}

function shareOf(x) {
  const smb = isObj(x.smb) ? MA.normalizeShare('smb', x.smb.address) : null;
  const webdav = isObj(x.webdav) ? MA.normalizeShare('webdav', x.webdav.address) : null;
  if (!smb && !webdav) return null;
  return {
    id: x.id, kind: 'share', name: str(x.name, 64) || str(x.folder, 64) || 'NAS', folder: str(x.folder, 128),
    smb: smb ? { address: smb } : null,
    webdav: webdav ? { address: webdav, certSha256: normalizeFingerprint(x.webdav.certSha256) } : null,
    user: str(x.user, 128), secretRev: Number.isSafeInteger(x.secretRev) && x.secretRev >= 0 ? x.secretRev : 0,
    away: awayOf(x.away),
  };
}

/**
 * GET v1/sources → the list, or null when it is none (no `v: 1`). A source that is broken (an id that is not the
 * plugin's, an address that is none) is left out; at most MAX_SOURCES entries' worth.
 */
function normalizeList(raw) {
  if (!isObj(raw) || raw.ok === false || raw.v !== 1) return null;
  const rev = str(raw.rev, 64);
  const at = str(raw.at, 40);
  if (raw.unchanged === true) return rev ? { unchanged: true, rev, at } : null;
  const media = raw.media !== false;
  const out = [];
  let entries = 0;
  const seen = new Set();
  for (const x of media && Array.isArray(raw.sources) ? raw.sources : []) {
    if (!isObj(x) || typeof x.id !== 'string' || !SOURCE_RE.test(x.id) || seen.has(x.id)) continue;
    const s = x.kind === 'jellyfin' ? jellyfinOf(x) : x.kind === 'share' ? shareOf(x) : null;
    if (!s) continue;
    const n = s.kind === 'share' && s.smb && s.webdav ? 2 : 1;
    if (entries + n > MAX_SOURCES) break;
    entries += n;
    seen.add(s.id);
    out.push(s);
  }
  const net = isObj(raw.network) ? raw.network : {};
  const probes = (isObj(net.home) && Array.isArray(net.home.probes) ? net.home.probes : []).map(probeOf).filter(Boolean).slice(0, 10);
  return {
    unchanged: false,
    rev,
    at,
    media,
    maxOfflineDays: dayCount(raw.maxOfflineDays, DEFAULT_MAX_OFFLINE_DAYS, 1, 3650),
    offlineHintDays: dayCount(raw.offlineHintDays, DEFAULT_HINT_DAYS, 1, 3650),
    network: { rule: str(net.rule, 40) || 'home_direct_away_vpn', vpnRequiredAway: out.some((s) => s.away.mode === 'vpn'), probes },
    cast: { enabled: isObj(raw.cast) && raw.cast.enabled === true },
    sources: out,
  };
}

/** The ids the entries of server source `sid` have: a share's SMB half under `sid`, its WebDAV half beside it. */
function entryIds(src) {
  if (src.kind !== 'share') return { main: src.id, webdav: null };
  return src.smb ? { main: src.id, webdav: src.webdav ? `${src.id}${WEBDAV_SUFFIX}` : null } : { main: null, webdav: src.id };
}

/** The visible id (a share's SMB half, else its WebDAV half) of an entry id. */
function visibleId(entryId) {
  return typeof entryId === 'string' && entryId.endsWith(WEBDAV_SUFFIX) ? entryId.slice(0, -WEBDAV_SUFFIX.length) : entryId;
}

/**
 * One server source → the entries MediaStore keeps (without secrets). A Jellyfin source: one entry with the device id
 * and name the plugin gives (not this PC's own); a share: its SMB half and its WebDAV half as one pair
 * (utils/media-sources.js `pairWith`: at home SMB, away WebDAV).
 */
function entriesOf(src) {
  const away = { awayMode: src.away.mode, awayAddress: src.away.address || null };
  const base = { managed: true, sid: src.id, name: src.name, ...away };
  if (src.kind === 'jellyfin') {
    return [{
      ...base, id: src.id, kind: 'jellyfin', address: src.home.address, serverId: src.serverId,
      mapUserId: src.user ? src.user.id : null, mapUserName: src.user ? src.user.name : null, problem: src.problem,
      jfDeviceId: src.device ? src.device.id : null, jfDeviceName: src.device ? src.device.name : null,
      quickConnect: src.quickConnect, alwaysOriginal: src.alwaysOriginal,
    }];
  }
  const ids = entryIds(src);
  const out = [];
  const share = { userName: src.user, secretRev: src.secretRev };
  if (src.smb) out.push({ ...base, ...share, id: ids.main, kind: 'smb', address: src.smb.address, pairWith: ids.webdav });
  if (src.webdav) {
    out.push({
      ...base, ...share, id: ids.webdav, kind: 'webdav', address: src.webdav.address, pairWith: src.smb ? ids.main : null,
      tlsPin: src.webdav.certSha256 || null,
    });
  }
  return out;
}

const SECRET_KEYS = ['token', 'userId', 'userName', 'password', 'pwRev', 'pairedUserId', 'tlsPin', 'alwaysOriginal', 'checkedRev'];

/**
 * The stored sources with the server's list (`sources` of normalizeList) →
 *   { list, removed: [entries gone: their access, progress and stream end], adopted: [{ from, to, name }],
 *     dropped: [{ id, name, kind }] (set up on this PC, not on the server: removed after the note), logout: [entries
 *     whose old Jellyfin access is to be signed out], repair: [ids whose Jellyfin access belongs to another user now] }
 *
 * Kept per entry: the access made on this PC (token while it belongs to the user the plugin links now), a share's
 * password (until `secretRev` says there is a newer one), "Immer Original". Taken over once (decision 33 a): a source
 * set up on this PC with the same Jellyfin server (serverId) or the same share address — the progress of its files
 * goes to the server's id, its old Jellyfin access is signed out (the plugin's device replaces it).
 */
function merge(stored, sources) {
  const list = Array.isArray(stored) ? stored : [];
  const managed = new Map(list.filter((x) => x.managed).map((x) => [x.id, x]));
  const legacy = list.filter((x) => !x.managed);
  const taken = new Set();
  const out = [];
  const adopted = [];
  const logout = [];
  const repair = [];
  for (const src of sources) {
    for (const e of entriesOf(src)) {
      const old = managed.get(e.id);
      const next = { ...e };
      if (old) {
        for (const k of SECRET_KEYS) if (old[k] !== undefined && old[k] !== null) next[k] = old[k];
        if (e.kind === 'webdav' && e.tlsPin) next.tlsPin = e.tlsPin; // the admin's pin wins
        if (e.kind === 'jellyfin' && next.token && next.pairedUserId !== e.mapUserId) {
          // the plugin links another Jellyfin user now (or none): the access goes, the device signs in again
          next.token = null; next.userId = null; next.userName = null; next.pairedUserId = null;
          repair.push(e.id);
        }
        if (e.kind === 'jellyfin' && old.jfDeviceId && e.jfDeviceId && old.jfDeviceId !== e.jfDeviceId && next.token) {
          next.token = null; next.pairedUserId = null;
          repair.push(e.id);
        }
        managed.delete(e.id);
      } else {
        // taken over from this PC (decision 33 a)?
        const match = legacy.find((x) => !taken.has(x.id) && (e.kind === 'jellyfin'
          ? x.kind === 'jellyfin' && e.serverId && x.serverId && x.serverId.toLowerCase() === e.serverId.toLowerCase()
          : x.kind === e.kind && x.address === e.address));
        if (match) {
          taken.add(match.id);
          next.alwaysOriginal = match.alwaysOriginal === true;
          if (e.kind === 'webdav' && !next.tlsPin && match.tlsPin) next.tlsPin = match.tlsPin;
          if (e.kind === 'jellyfin' && match.token) logout.push(match);
          adopted.push({ from: match.id, to: visibleId(e.id), name: e.name, kind: e.kind });
        } else if (e.kind === 'jellyfin') next.alwaysOriginal = e.alwaysOriginal === true;
      }
      if (e.kind === 'jellyfin' && !next.alwaysOriginal) next.alwaysOriginal = false;
      out.push(next);
    }
  }
  const dropped = legacy.filter((x) => !taken.has(x.id));
  for (const x of dropped) if (x.kind === 'jellyfin' && x.token) logout.push(x);
  return {
    list: out,
    removed: [...managed.values()],
    adopted,
    dropped: dropped.map((x) => ({ id: x.id, name: x.name, kind: x.kind })),
    logout,
    repair: [...new Set(repair)],
  };
}

/** Days without the server (decision 36 a): { days, hint (≥ offlineHintDays), expired (≥ maxOfflineDays: passwords go) }. */
function offline(now, lastContactAt, hintDays = DEFAULT_HINT_DAYS, maxDays = DEFAULT_MAX_OFFLINE_DAYS) {
  if (!Number.isFinite(lastContactAt) || lastContactAt <= 0) return { days: 0, hint: false, expired: false };
  const days = Math.max(0, Math.floor((now - lastContactAt) / DAY_MS));
  return { days, hint: days >= hintDays, expired: days >= maxDays };
}

/**
 * The network rule (verbindlich): → 'home' (straight in the LAN, bound to the LAN adapter, never through the tunnel),
 * 'vpn' (away through the own tunnel), 'direct' (away over the admin's HTTPS address) or 'blocked' (away, only
 * through the VPN, none up: nothing is sent).
 */
function wayOf({ atHome, awayMode, tunnelUp }) {
  if (atHome) return 'home';
  if (awayMode === 'direct') return 'direct';
  return tunnelUp ? 'vpn' : 'blocked';
}

/** The silent signal (topic media_signal, kind data): { sourceIds: [..] | null (all), reason } or null. */
function revokeOf(data) {
  if (!isObj(data) || data.kind !== 'media.revoke') return null;
  const ids = Array.isArray(data.sourceIds) ? data.sourceIds.filter((x) => typeof x === 'string' && SOURCE_RE.test(x)) : null;
  if (Array.isArray(data.sourceIds) && !ids.length) return null;
  return { sourceIds: ids, reason: REVOKE_REASONS.has(data.reason) ? data.reason : 'admin' };
}

/** Does a push belong to the plugin's signal? */
function isSignal(n) {
  return isObj(n) && n.topic === SIGNAL_TOPIC;
}

/** `GET /api/v1/client/plugins` → { installed, tab: { label } | null, version }. */
function pluginOf(data) {
  const list = isObj(data) && Array.isArray(data.plugins) ? data.plugins : [];
  const p = list.find((x) => isObj(x) && x.id === PLUGIN_ID);
  if (!p) return { installed: false, tab: null, version: null };
  const tab = isObj(p.tab) ? { label: str(p.tab.label, 40) } : null;
  return { installed: true, tab, version: str(p.version, 40) };
}

/**
 * What a refusal of the plugin means for this PC:
 *   'unavailable' (plugin off, not installed, no licence: hide at once, delete after 24 h), 'no_access' (this source is
 *   not the person's any more: delete it), 'problem' (an admin's matter: shown, asked again later), 'retry' (later),
 *   'invalid' (a mistake of the app).
 */
function refusalOf(err) {
  const code = err && err.code;
  const reason = err && err.body && err.body.reason;
  if ((code === 'not_found' && reason === 'plugin_unavailable') || code === 'license_required' || code === 'plugin_unavailable') return 'unavailable';
  if (code === 'no_access') return 'no_access';
  if (['no_mapping', 'quick_connect_off', 'admin_user', 'user_disabled', 'not_configured'].includes(code)) return 'problem';
  if (code === 'invalid' || code === 'no_device') return 'invalid';
  return 'retry';
}

module.exports = {
  PLUGIN_ID, API_BASE, SIGNAL_TOPIC, SOURCE_RE, WEBDAV_SUFFIX, DAY_MS, UNAVAILABLE_GRACE_MS, DEFAULT_MAX_OFFLINE_DAYS, DEFAULT_HINT_DAYS,
  httpsBase, awayOf, probeOf, normalizeList, entryIds, visibleId, entriesOf, merge, offline, wayOf, revokeOf, isSignal, pluginOf, refusalOf,
};
