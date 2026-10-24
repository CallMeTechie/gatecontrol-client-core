'use strict';

/**
 * GateControl – Wi-Fi scan (Core service, Windows)
 *
 * Lists the Wi-Fi networks nearby for Vault's Wi-Fi entries ("WLAN in der
 * Nähe suchen"), through the Native Wifi API of wlanapi.dll via koffi:
 *
 *   WlanOpenHandle → WlanEnumInterfaces → WlanScan (every interface)
 *   → wait (a driver finishes a scan within 4 s) → WlanGetAvailableNetworkList
 *   (+ WlanGetNetworkBssList for the security of each access point)
 *   → WlanFreeMemory / WlanCloseHandle
 *
 * Locale-independent (no `netsh` output is parsed). koffi and the DLL are
 * only loaded when a scan runs on Windows, so requiring this module is safe
 * anywhere (tests on Linux). Everything that reads the API's memory works on
 * a copied Buffer (parse* below) and is unit-tested with synthetic buffers.
 *
 * scanWifi() → [{ ssid, security, signal, connected }]
 *   ssid      decoded as UTF-8 (latin1 when the bytes are not UTF-8);
 *             hidden networks (no / all-zero SSID) are left out
 *   security  'WPA3' | 'WPA2/WPA3' | 'WPA2' | 'WPA' | 'WEP' | 'Offen' | ''
 *             (the strings the Vault entries and the portal's QR codes use;
 *             '' when unknown)
 *   signal    0–100 (Windows' link quality)
 *   connected this PC is connected to it
 * One row per SSID (the strongest), connected first, then by signal.
 *
 * Failures: WifiScanError { code }:
 *   no_adapter       not Windows, no wlanapi.dll / WLAN service, no adapter
 *   service_off      the WLAN AutoConfig service is not running
 *   radio_off        the adapter's radio is off
 *   location_denied  ERROR_ACCESS_DENIED: Windows 11 24H2+ gives scan results
 *                    only with location access ("Standortdienste" and
 *                    "Desktop-Apps Zugriff auf Ihren Standort erlauben")
 *   failed           anything else (`win32` carries the Windows error code)
 */

// ── Windows constants ──────────────────────────────────────

const WLAN_CLIENT_VERSION = 2;                    // Vista and later

const ERROR_ACCESS_DENIED = 5;
const ERROR_SERVICE_DOES_NOT_EXIST = 1060;
const ERROR_SERVICE_NOT_ACTIVE = 1062;
const ERROR_SERVICE_DISABLED = 1058;
const ERROR_NDIS_DOT11_POWER_STATE_INVALID = 0x80342002;

// DOT11_AUTH_ALGORITHM
const AUTH = {
  OPEN: 1, SHARED_KEY: 2, WPA: 3, WPA_PSK: 4, WPA_NONE: 5, RSNA: 6, RSNA_PSK: 7,
  WPA3_ENT_192: 8, WPA3_SAE: 9, OWE: 10, WPA3_ENT: 11,
};
// DOT11_CIPHER_ALGORITHM
const CIPHER = { NONE: 0x00, WEP40: 0x01, WEP104: 0x05, WEP: 0x101 };

const WLAN_AVAILABLE_NETWORK_CONNECTED = 0x1;
const DOT11_BSS_TYPE_ANY = 3;

// Struct layouts (all members 4-byte aligned except WLAN_BSS_ENTRY's ULONGLONGs;
// the same on x86, x64 and ARM64; test/wifi-scan.test.js checks them with koffi).
const LIST_HEADER = 8;               // DWORD dwNumberOfItems (dwTotalSize for BSS), DWORD dwIndex (dwNumberOfItems)
const IFACE_SIZE = 532;              // WLAN_INTERFACE_INFO: GUID, WCHAR[256], state
const IFACE = { guid: 0, description: 16, state: 528 };
const NET_SIZE = 628;                // WLAN_AVAILABLE_NETWORK
const NET = {
  ssidLength: 512, ssid: 516, connectable: 556, signal: 604, securityEnabled: 608, auth: 612, cipher: 616, flags: 620,
};
const BSS_SIZE = 360;                // WLAN_BSS_ENTRY
const BSS = { ssidLength: 0, ssid: 4, rssi: 56, linkQuality: 60, capability: 88, ieOffset: 352, ieSize: 356 };

const MAX_ITEMS = 1024;              // sanity bound for counts read from the API's memory
const MAX_NETWORKS = 100;            // rows handed to the page

const SECURITY = { WPA3: 'WPA3', MIXED: 'WPA2/WPA3', WPA2: 'WPA2', WPA: 'WPA', WEP: 'WEP', OPEN: 'Offen' };

class WifiScanError extends Error {
  constructor(code, { win32 = null, fn = null } = {}) {
    super(fn ? `${fn} failed (${code}${win32 != null ? `, ${win32}` : ''})` : code);
    this.name = 'WifiScanError';
    this.code = code;
    this.win32 = win32;
  }
}

/** Windows error code → WifiScanError code. */
function errorCode(win32) {
  switch (win32 >>> 0) {
    case ERROR_ACCESS_DENIED: return 'location_denied';
    case ERROR_SERVICE_NOT_ACTIVE:
    case ERROR_SERVICE_DISABLED: return 'service_off';
    case ERROR_SERVICE_DOES_NOT_EXIST: return 'no_adapter';
    case ERROR_NDIS_DOT11_POWER_STATE_INVALID: return 'radio_off';
    default: return 'failed';
  }
}

// ── SSID ───────────────────────────────────────────────────

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** SSID bytes (≤ 32) → text: UTF-8, latin1 when not valid UTF-8; trailing zero bytes dropped; '' for none / all zero bytes (hidden). */
function decodeSsid(bytes) {
  let b = Buffer.from(bytes || []).subarray(0, 32);
  let end = b.length;
  while (end > 0 && b[end - 1] === 0) end--;
  b = b.subarray(0, end);
  if (!b.length) return '';
  try {
    return utf8.decode(b);
  } catch {
    return b.toString('latin1');
  }
}

// ── Security ───────────────────────────────────────────────
// Kinds found for a network: 'sae', 'rsn-psk', 'wpa-psk', 'wpa3-eap', 'rsn-eap', 'wpa-eap', 'wep', 'owe', 'open'.

/** dot11DefaultAuthAlgorithm / dot11DefaultCipherAlgorithm of WLAN_AVAILABLE_NETWORK → kinds. */
function kindsOfAuth(auth, cipher) {
  switch (auth) {
    case AUTH.OPEN: return [[CIPHER.WEP, CIPHER.WEP40, CIPHER.WEP104].includes(cipher) ? 'wep' : 'open'];
    case AUTH.SHARED_KEY: return ['wep'];
    case AUTH.WPA: return ['wpa-eap'];
    case AUTH.WPA_PSK:
    case AUTH.WPA_NONE: return ['wpa-psk'];
    case AUTH.RSNA: return ['rsn-eap'];
    case AUTH.RSNA_PSK: return ['rsn-psk'];
    case AUTH.WPA3_SAE: return ['sae'];
    case AUTH.WPA3_ENT:
    case AUTH.WPA3_ENT_192: return ['wpa3-eap'];
    case AUTH.OWE: return ['owe'];
    default: return [];
  }
}

// AKM suite types (IEEE 802.11, OUI 00-0F-AC) → kind
const RSN_AKM = {
  1: 'rsn-eap', 3: 'rsn-eap', 5: 'rsn-eap',
  2: 'rsn-psk', 4: 'rsn-psk', 6: 'rsn-psk',
  8: 'sae', 9: 'sae', 24: 'sae', 25: 'sae',
  11: 'wpa3-eap', 12: 'wpa3-eap', 13: 'wpa3-eap',
  18: 'owe',
};
const WPA_AKM = { 1: 'wpa-eap', 2: 'wpa-psk' };   // OUI 00-50-F2

/** The AKM suites of an RSN / WPA element body (after version and group cipher) → kinds. */
function akmKinds(body, start, oui, table) {
  const out = [];
  let p = start + 4;                                       // group cipher suite
  if (p + 2 > body.length) return out;
  const pairwise = body.readUInt16LE(p);
  p += 2 + pairwise * 4;
  if (p + 2 > body.length) return out;
  const akms = body.readUInt16LE(p);
  p += 2;
  for (let i = 0; i < akms && p + 4 <= body.length; i++, p += 4) {
    if (body[p] === oui[0] && body[p + 1] === oui[1] && body[p + 2] === oui[2] && table[body[p + 3]]) out.push(table[body[p + 3]]);
  }
  return out;
}

/**
 * Information elements of a beacon / probe response → kinds: the RSN element (48)
 * and the WPA vendor element (221, 00-50-F2 type 1); none of them: 'wep' when
 * the capability field's Privacy bit is set, else 'open'.
 */
function kindsOfIes(ies, capability = 0) {
  const b = Buffer.from(ies || []);
  const kinds = new Set();
  let rsnOrWpa = false;
  for (let p = 0; p + 2 <= b.length;) {
    const id = b[p];
    const len = b[p + 1];
    const body = b.subarray(p + 2, p + 2 + len);
    if (body.length < len) break;
    if (id === 48 && len >= 2) {
      rsnOrWpa = true;
      for (const k of akmKinds(body, 2, [0x00, 0x0f, 0xac], RSN_AKM)) kinds.add(k);
    } else if (id === 221 && len >= 6 && body[0] === 0x00 && body[1] === 0x50 && body[2] === 0xf2 && body[3] === 1) {
      rsnOrWpa = true;
      for (const k of akmKinds(body, 6, [0x00, 0x50, 0xf2], WPA_AKM)) kinds.add(k);
    }
    p += 2 + len;
  }
  if (!rsnOrWpa) kinds.add(capability & 0x10 ? 'wep' : 'open');
  return [...kinds];
}

/** Kinds of one network (all its entries and access points) → the security text of a Vault Wi-Fi entry. */
function securityOf(kinds) {
  const k = new Set(kinds || []);
  if (k.has('sae') && (k.has('rsn-psk') || k.has('wpa-psk'))) return SECURITY.MIXED;
  if (k.has('sae')) return SECURITY.WPA3;
  if (k.has('rsn-psk')) return SECURITY.WPA2;
  if (k.has('wpa-psk')) return SECURITY.WPA;
  if (k.has('wpa3-eap')) return SECURITY.WPA3;
  if (k.has('rsn-eap')) return SECURITY.WPA2;
  if (k.has('wpa-eap')) return SECURITY.WPA;
  if (k.has('wep')) return SECURITY.WEP;
  if (k.has('owe') || k.has('open')) return SECURITY.OPEN;
  return '';
}

// ── Reading the API's lists (copied into Buffers) ─────────

function count(buf, at, size) {
  if (!Buffer.isBuffer(buf) || buf.length < LIST_HEADER) return 0;
  const n = buf.readUInt32LE(at);
  return Math.min(n, MAX_ITEMS, Math.floor((buf.length - LIST_HEADER) / size));
}

/** WLAN_INTERFACE_INFO_LIST → [{ guid: Buffer(16), description, state }] */
function parseInterfaceList(buf) {
  const out = [];
  for (let i = 0, n = count(buf, 0, IFACE_SIZE); i < n; i++) {
    const o = LIST_HEADER + i * IFACE_SIZE;
    const desc = buf.subarray(o + IFACE.description, o + IFACE.description + 512).toString('utf16le');
    out.push({
      guid: Buffer.from(buf.subarray(o + IFACE.guid, o + IFACE.guid + 16)),
      description: desc.slice(0, desc.indexOf('\0') === -1 ? desc.length : desc.indexOf('\0')),
      state: buf.readUInt32LE(o + IFACE.state),
    });
  }
  return out;
}

function ssidAt(buf, o, lenAt, bytesAt) {
  const len = Math.min(buf.readUInt32LE(o + lenAt), 32);
  return decodeSsid(buf.subarray(o + bytesAt, o + bytesAt + len));
}

/** WLAN_AVAILABLE_NETWORK_LIST → [{ ssid, signal, connected, kinds }] (hidden networks included as ssid ''). */
function parseNetworkList(buf) {
  const out = [];
  for (let i = 0, n = count(buf, 0, NET_SIZE); i < n; i++) {
    const o = LIST_HEADER + i * NET_SIZE;
    out.push({
      ssid: ssidAt(buf, o, NET.ssidLength, NET.ssid),
      signal: Math.max(0, Math.min(100, buf.readUInt32LE(o + NET.signal))),
      connected: (buf.readUInt32LE(o + NET.flags) & WLAN_AVAILABLE_NETWORK_CONNECTED) !== 0,
      kinds: kindsOfAuth(buf.readInt32LE(o + NET.auth), buf.readInt32LE(o + NET.cipher)),
    });
  }
  return out;
}

/** WLAN_BSS_LIST → [{ ssid, kinds }] (one per access point; kinds from its information elements). */
function parseBssList(buf) {
  const out = [];
  for (let i = 0, n = count(buf, 4, BSS_SIZE); i < n; i++) {
    const o = LIST_HEADER + i * BSS_SIZE;
    const ieAt = o + buf.readUInt32LE(o + BSS.ieOffset);
    const ieEnd = ieAt + buf.readUInt32LE(o + BSS.ieSize);
    const ies = ieAt >= o && ieEnd <= buf.length && ieEnd >= ieAt ? buf.subarray(ieAt, ieEnd) : Buffer.alloc(0);
    out.push({ ssid: ssidAt(buf, o, BSS.ssidLength, BSS.ssid), kinds: kindsOfIes(ies, buf.readUInt16LE(o + BSS.capability)) });
  }
  return out;
}

/**
 * Networks (of every interface) and access points → one row per SSID: the
 * strongest signal, connected when any entry is, the security of all entries
 * and access points of that name. Hidden networks are left out. Connected
 * first, then by signal, then by name.
 */
function mergeNetworks(networks, bss = []) {
  const by = new Map();
  for (const n of networks || []) {
    if (!n || !n.ssid) continue;
    const row = by.get(n.ssid) || { ssid: n.ssid, signal: 0, connected: false, kinds: new Set() };
    row.signal = Math.max(row.signal, Number(n.signal) || 0);
    row.connected = row.connected || n.connected === true;
    for (const k of n.kinds || []) row.kinds.add(k);
    by.set(n.ssid, row);
  }
  for (const b of bss || []) {
    const row = b && b.ssid ? by.get(b.ssid) : null;
    if (row) for (const k of b.kinds || []) row.kinds.add(k);
  }
  return [...by.values()]
    .map((r) => ({ ssid: r.ssid, security: securityOf(r.kinds), signal: r.signal, connected: r.connected }))
    .sort((a, b) => (b.connected - a.connected) || (b.signal - a.signal) || a.ssid.localeCompare(b.ssid, 'de', { sensitivity: 'base' }))
    .slice(0, MAX_NETWORKS);
}

// ── Native layer (Windows only, loaded on first use) ──────

let native = null;

/**
 * Copies n bytes of native memory into a Buffer. koffi.decode copies; koffi.view would wrap
 * the memory in an external ArrayBuffer, which Electron's V8 sandbox forbids (the app crashes).
 */
function copyNative(koffi, ptr, n) {
  return n > 0 ? Buffer.from(koffi.decode(ptr, 'uint8_t', n)) : Buffer.alloc(0);
}

/**
 * Binds wlanapi.dll. Each method throws WifiScanError on a non-zero result;
 * lists come back as copied Buffers (the API's memory is freed right away).
 */
function loadNative() {
  if (native) return native;
  const koffi = require('koffi');
  const lib = koffi.load('wlanapi.dll');
  const f = {
    open: lib.func('uint32_t __stdcall WlanOpenHandle(uint32_t dwClientVersion, void *pReserved, _Out_ uint32_t *pdwNegotiatedVersion, _Out_ void **phClientHandle)'),
    close: lib.func('uint32_t __stdcall WlanCloseHandle(void *hClientHandle, void *pReserved)'),
    enum: lib.func('uint32_t __stdcall WlanEnumInterfaces(void *hClientHandle, void *pReserved, _Out_ void **ppInterfaceList)'),
    scan: lib.func('uint32_t __stdcall WlanScan(void *hClientHandle, const void *pInterfaceGuid, const void *pDot11Ssid, const void *pIeData, void *pReserved)'),
    networks: lib.func('uint32_t __stdcall WlanGetAvailableNetworkList(void *hClientHandle, const void *pInterfaceGuid, uint32_t dwFlags, void *pReserved, _Out_ void **ppAvailableNetworkList)'),
    bss: lib.func('uint32_t __stdcall WlanGetNetworkBssList(void *hClientHandle, const void *pInterfaceGuid, const void *pDot11Ssid, int dot11BssType, int bSecurityEnabled, void *pReserved, _Out_ void **ppWlanBssList)'),
    free: lib.func('void __stdcall WlanFreeMemory(void *pMemory)'),
  };
  const check = (rc, fn) => {
    if (rc !== 0) throw new WifiScanError(errorCode(rc), { win32: rc >>> 0, fn });
  };
  /** Copies a list the API allocated (size from its header), then frees it. */
  const take = (ptr, size) => {
    try {
      return copyNative(koffi, ptr, size(ptr));
    } finally {
      f.free(ptr);
    }
  };
  const items = (ptr, at, itemSize) => LIST_HEADER + Math.min(koffi.decode(ptr, at, 'uint32_t'), MAX_ITEMS) * itemSize;
  native = {
    open() {
      const version = [0];
      const handle = [null];
      check(f.open(WLAN_CLIENT_VERSION, null, version, handle), 'WlanOpenHandle');
      return handle[0];
    },
    close(h) { f.close(h, null); },
    interfaces(h) {
      const out = [null];
      check(f.enum(h, null, out), 'WlanEnumInterfaces');
      return take(out[0], (p) => items(p, 0, IFACE_SIZE));
    },
    scan(h, guid) { check(f.scan(h, guid, null, null, null), 'WlanScan'); },
    networks(h, guid) {
      const out = [null];
      check(f.networks(h, guid, 0, null, out), 'WlanGetAvailableNetworkList');
      return take(out[0], (p) => items(p, 0, NET_SIZE));
    },
    bss(h, guid) {
      const out = [null];
      check(f.bss(h, guid, null, DOT11_BSS_TYPE_ANY, 0, null, out), 'WlanGetNetworkBssList');
      // dwTotalSize covers the entries and their information elements
      return take(out[0], (p) => Math.min(koffi.decode(p, 0, 'uint32_t'), LIST_HEADER + MAX_ITEMS * (BSS_SIZE + 2048)));
    },
  };
  return native;
}

// ── Scan ───────────────────────────────────────────────────

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let running = null;

/**
 * Scans on every Wi-Fi interface, waits for the results and lists the
 * networks. Concurrent calls share one scan.
 *
 * @param {object} [opts]
 * @param {string} [opts.platform] - process.platform (tests)
 * @param {object} [opts.native] - the native layer (tests): { open, close, interfaces, scan, networks, bss }
 * @param {number} [opts.waitMs] - time the drivers get for the scan (default 3500)
 * @param {object} [opts.log]
 * @returns {Promise<Array<{ ssid: string, security: string, signal: number, connected: boolean }>>}
 */
function scanWifi(opts = {}) {
  if (!running) {
    running = runScan(opts || {}).finally(() => { running = null; });
  }
  return running;
}

async function runScan(opts) {
  try {
    return await scanOnce(opts);
  } catch (err) {
    if (err instanceof WifiScanError) throw err;
    if (opts.log) opts.log.warn(`Wi-Fi scan failed: ${err && err.message}`);
    throw new WifiScanError('failed');
  }
}

async function scanOnce({ platform = process.platform, native: api = null, waitMs = 3500, log = null } = {}) {
  if (platform !== 'win32') throw new WifiScanError('no_adapter');
  let w = api;
  if (!w) {
    try {
      w = loadNative();
    } catch (err) {
      if (log) log.warn(`Wi-Fi scan: wlanapi.dll not available: ${err.message}`);
      throw new WifiScanError('no_adapter');
    }
  }
  const h = w.open();
  try {
    const ifaces = parseInterfaceList(w.interfaces(h));
    if (!ifaces.length) throw new WifiScanError('no_adapter');

    // a fresh scan on every interface; the cached list stays usable when a scan cannot start (busy, not ready)
    let started = 0;
    let lastErr = null;
    for (const i of ifaces) {
      try {
        w.scan(h, i.guid);
        started++;
      } catch (err) {
        lastErr = err;
        if (log) log.debug(`Wi-Fi scan: WlanScan on "${i.description}": ${err.message}`);
      }
    }
    if (!started && lastErr && ['location_denied', 'radio_off', 'service_off'].includes(lastErr.code)) throw lastErr;
    if (started && waitMs > 0) await sleep(waitMs);

    const networks = [];
    const bss = [];
    let listed = 0;
    for (const i of ifaces) {
      try {
        networks.push(...parseNetworkList(w.networks(h, i.guid)));
        listed++;
      } catch (err) {
        lastErr = err;
        if (log) log.debug(`Wi-Fi scan: network list of "${i.description}": ${err.message}`);
        continue;
      }
      try {
        bss.push(...parseBssList(w.bss(h, i.guid)));
      } catch (err) {
        // the networks' own security fields are enough
        if (log) log.debug(`Wi-Fi scan: BSS list of "${i.description}": ${err.message}`);
      }
    }
    if (!listed) throw lastErr instanceof WifiScanError ? lastErr : new WifiScanError('failed');
    return mergeNetworks(networks, bss);
  } finally {
    try { w.close(h); } catch { /* closing is best effort */ }
  }
}

module.exports = {
  scanWifi,
  WifiScanError,
  SECURITY,
  // pure parts (tests)
  copyNative,
  errorCode,
  decodeSsid,
  kindsOfAuth,
  kindsOfIes,
  securityOf,
  parseInterfaceList,
  parseNetworkList,
  parseBssList,
  mergeNetworks,
  LAYOUT: { LIST_HEADER, IFACE_SIZE, IFACE, NET_SIZE, NET, BSS_SIZE, BSS },
};
