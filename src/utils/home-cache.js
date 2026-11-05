'use strict';

/**
 * GateControl – Zwischenspeicher im Heimnetz (Gateways Phase 3b), reine Helfer.
 *
 * Ein Heim-Gateway hält App-Updates und Drive-Dateien vor. Ist der PC im
 * Heimnetz eines Gateways, das die Datei hat, legt der Server seiner Antwort
 * (GET /api/v1/client/update/check, Drive GET nodes/<id>/content) zusätzlich
 *   lan: { url, sha256, tlsSha256, exp }
 * bei. Ob der PC dort ist, entscheidet der Server (seine Heimnetz-Erkennung,
 * services/homeNetwork.js: gleiche öffentliche Adresse wie das Gateway und
 * eine eigene LAN-Adresse im LAN des Gateways). Dafür schickt die App ihre
 * privaten IPv4-Adressen (RFC 1918) der echten Netzwerkadapter mit – Kopfzeile
 * `X-GC-Local: 192.168.1.23[,…]`, höchstens vier, nie die des VPN-Adapters.
 *
 * `lan.url` zeigt auf den HTTPS-Endpunkt des Gateways im LAN
 * (`https://<LAN-IPv4>:<Port>/blob/<sha256>?exp=…&sig=…`, selbstsigniertes
 * Zertifikat ohne Namen). Geladen wird nur mit Zertifikats-Pinning auf
 * `tlsSha256` (SHA-256 des DER-Zertifikats) und mit Prüfung des SHA-256 der
 * Bytes; jeder Fehler fällt still auf den normalen Download zurück
 * (services/home-cache.js).
 */

/** Adapter, die nie „das Heimnetz“ sind: VPN, virtuelle Switches, Loopback (auch utils/drive-sync.js). */
const VPN_IF_RE = /wireguard|gatecontrol|\bwg|tun|tap|vpn|virtual|vethernet|hyper-v|vmware|virtualbox|loopback|docker/i;

const MAX_LOCAL = 4;
const MAX_URL = 2048;
const SHA256_RE = /^[0-9a-f]{64}$/;
const V4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Strikte Punktschreibweise ohne führende Nullen → [a, b, c, d] oder null. */
function v4Parts(ip) {
  const m = V4_RE.exec(typeof ip === 'string' ? ip : '');
  return m ? [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] : null;
}

/** 10/8, 172.16/12, 192.168/16 (RFC 1918) – sonst false. */
function isPrivateV4(ip) {
  const p = v4Parts(ip);
  if (!p) return false;
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168);
}

/**
 * Die eigenen privaten IPv4-Adressen der echten Adapter aus
 * os.networkInterfaces(): nicht intern, kein VPN-/virtueller Adapter
 * (WireGuard, GateControl, Hyper-V, VMware …), nur RFC 1918, höchstens vier.
 * os.networkInterfaces() listet nur Adapter, die verbunden sind.
 */
function localAddresses(ifaces, max = MAX_LOCAL) {
  const out = [];
  const src = ifaces && typeof ifaces === 'object' ? ifaces : {};
  for (const [name, list] of Object.entries(src)) {
    if (VPN_IF_RE.test(name)) continue;
    for (const a of Array.isArray(list) ? list : []) {
      if (!a || a.internal || (a.family !== 'IPv4' && a.family !== 4) || !isPrivateV4(a.address)) continue;
      if (!out.includes(a.address)) out.push(a.address);
      if (out.length >= max) return out;
    }
  }
  return out;
}

/** Wert der Kopfzeile X-GC-Local oder null (keine passende Adresse). */
function localHeader(ifaces) {
  const list = localAddresses(ifaces);
  return list.length ? list.join(',') : null;
}

/** { 'X-GC-Local': '…' } für eine Anfrage (getInterfaces = os.networkInterfaces) oder {} ohne passende Adresse. */
function localHeaders(getInterfaces) {
  let ifaces = {};
  try { ifaces = (typeof getInterfaces === 'function' ? getInterfaces() : null) || {}; } catch { ifaces = {}; }
  const v = localHeader(ifaces);
  return v ? { 'X-GC-Local': v } : {};
}

/** Fingerabdruck → 64 Hex-Zeichen klein (Doppelpunkte, Großschreibung, „sha256:“ egal) oder null. */
function normalizeFingerprint(raw) {
  if (typeof raw !== 'string') return null;
  const hex = raw.trim().toLowerCase().replace(/^sha256:/, '').replace(/[\s:-]/g, '');
  return SHA256_RE.test(hex) ? hex : null;
}

/**
 * `lan` einer Server-Antwort → { url, sha256, tlsSha256, exp } oder null.
 * Verlangt: https, kein Benutzer/Passwort, Host eine private IPv4 (RFC 1918;
 * `hostOk` nur für Tests), Pfad genau /blob/<sha256>, sha256 64 Hex,
 * Fingerabdruck gültig, `exp` (Unix-Sekunden) positiv. `expectSha256`: der
 * Hash, den der Aufrufer sonst erwartet (signiertes Update-Manifest) – muss
 * übereinstimmen.
 */
function normalizeLan(raw, { expectSha256 = null, hostOk = isPrivateV4 } = {}) {
  const r = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
  if (!r || typeof r.url !== 'string' || !r.url || r.url.length > MAX_URL) return null;
  const sha256 = typeof r.sha256 === 'string' ? r.sha256.toLowerCase() : '';
  if (!SHA256_RE.test(sha256)) return null;
  if (expectSha256 !== null && String(expectSha256).toLowerCase() !== sha256) return null;
  const tlsSha256 = normalizeFingerprint(r.tlsSha256);
  if (!tlsSha256) return null;
  if (!Number.isSafeInteger(r.exp) || r.exp <= 0) return null;
  let u;
  try {
    u = new URL(r.url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash) return null;
  if (typeof hostOk !== 'function' || !hostOk(u.hostname)) return null;
  if (u.pathname !== `/blob/${sha256}`) return null;
  return { url: u.toString(), sha256, tlsSha256, exp: r.exp };
}

/** Für Protokolle: nur Host und Port, nie die Signatur der Adresse. */
function lanWhere(lan) {
  try {
    const u = new URL(lan.url);
    return u.host;
  } catch {
    return '?';
  }
}

module.exports = {
  MAX_LOCAL,
  VPN_IF_RE,
  isPrivateV4,
  localAddresses,
  localHeader,
  localHeaders,
  normalizeFingerprint,
  normalizeLan,
  lanWhere,
};
