'use strict';

// Wi-Fi scan for Vault's Wi-Fi entries (services/wifi-scan.js): SSID decoding, security from the Native Wifi
// API's auth / cipher fields and from the access points' RSN / WPA elements, the lists read from (synthetic)
// API memory, one row per SSID (strongest, connected first), the error codes, the scan flow over a fake native
// layer, and that the struct offsets match what koffi computes for the Windows structs.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const ws = require('../src/services/wifi-scan');

const { LAYOUT: L } = ws;

// ── synthetic API memory ──────────────────────────────────

function interfaceList(ifaces) {
  const buf = Buffer.alloc(L.LIST_HEADER + ifaces.length * L.IFACE_SIZE);
  buf.writeUInt32LE(ifaces.length, 0);
  ifaces.forEach((x, i) => {
    const o = L.LIST_HEADER + i * L.IFACE_SIZE;
    Buffer.alloc(16, i + 1).copy(buf, o + L.IFACE.guid);
    buf.write(x.description || 'WLAN', o + L.IFACE.description, 'utf16le');
    buf.writeUInt32LE(x.state == null ? 1 : x.state, o + L.IFACE.state);
  });
  return buf;
}

function networkList(nets) {
  const buf = Buffer.alloc(L.LIST_HEADER + nets.length * L.NET_SIZE);
  buf.writeUInt32LE(nets.length, 0);
  nets.forEach((n, i) => {
    const o = L.LIST_HEADER + i * L.NET_SIZE;
    const ssid = Buffer.isBuffer(n.ssid) ? n.ssid : Buffer.from(n.ssid || '', 'utf8');
    buf.writeUInt32LE(n.ssidLength == null ? ssid.length : n.ssidLength, o + L.NET.ssidLength);
    ssid.copy(buf, o + L.NET.ssid, 0, Math.min(32, ssid.length));
    buf.writeUInt32LE(n.signal || 0, o + L.NET.signal);
    buf.writeInt32LE(n.auth || 1, o + L.NET.auth);
    buf.writeInt32LE(n.cipher || 0, o + L.NET.cipher);
    buf.writeUInt32LE(n.connected ? 1 : 0, o + L.NET.flags);
  });
  return buf;
}

// RSN element: version 1, group CCMP, pairwise CCMP, the AKM suites given
const rsn = (...akms) => Buffer.from([48, 2 + 4 + 2 + 4 + 2 + akms.length * 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4,
  akms.length, 0, ...akms.flatMap((a) => [0x00, 0x0f, 0xac, a])]);
// WPA (vendor) element: OUI 00-50-F2 type 1, version 1, group TKIP, pairwise TKIP, the AKM suites given
const wpa = (...akms) => Buffer.from([221, 4 + 2 + 4 + 2 + 4 + 2 + akms.length * 4, 0x00, 0x50, 0xf2, 1, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 2,
  akms.length, 0, ...akms.flatMap((a) => [0x00, 0x50, 0xf2, a])]);
const ssidIe = (s) => Buffer.from([0, Buffer.byteLength(s), ...Buffer.from(s)]);

function bssList(entries) {
  const ies = entries.map((e) => Buffer.concat(e.ies || []));
  const total = L.LIST_HEADER + entries.length * L.BSS_SIZE + ies.reduce((a, b) => a + b.length, 0);
  const buf = Buffer.alloc(total);
  buf.writeUInt32LE(total, 0);
  buf.writeUInt32LE(entries.length, 4);
  let ieAt = L.LIST_HEADER + entries.length * L.BSS_SIZE;
  entries.forEach((e, i) => {
    const o = L.LIST_HEADER + i * L.BSS_SIZE;
    const ssid = Buffer.from(e.ssid, 'utf8');
    buf.writeUInt32LE(ssid.length, o + L.BSS.ssidLength);
    ssid.copy(buf, o + L.BSS.ssid);
    buf.writeUInt16LE(e.capability || 0, o + L.BSS.capability);
    buf.writeUInt32LE(ieAt - o, o + L.BSS.ieOffset);
    buf.writeUInt32LE(ies[i].length, o + L.BSS.ieSize);
    ies[i].copy(buf, ieAt);
    ieAt += ies[i].length;
  });
  return buf;
}

describe('wifi-scan: SSID', () => {
  it('decodes UTF-8, falls back to latin1, drops hidden ones', () => {
    assert.equal(ws.decodeSsid(Buffer.from('FRITZ!Box 7590 XY', 'utf8')), 'FRITZ!Box 7590 XY');
    assert.equal(ws.decodeSsid(Buffer.from('Café Müller 🚀', 'utf8')), 'Café Müller 🚀');
    assert.equal(ws.decodeSsid(Buffer.from([0x4d, 0xfc, 0x6c, 0x6c, 0x65, 0x72])), 'Müller', 'latin1 byte 0xFC is not UTF-8');
    assert.equal(ws.decodeSsid(Buffer.alloc(0)), '');
    assert.equal(ws.decodeSsid(Buffer.alloc(8)), '', 'all zero bytes: hidden');
    assert.equal(ws.decodeSsid(null), '');
    assert.equal(ws.decodeSsid(Buffer.alloc(40, 0x41)).length, 32, 'at most 32 bytes');
    assert.equal(ws.decodeSsid(Buffer.from('<img src=x onerror=alert(1)>')), '<img src=x onerror=alert(1)>', 'kept as text (the page uses textContent)');
  });
});

describe('wifi-scan: security', () => {
  it('maps auth / cipher of WLAN_AVAILABLE_NETWORK', () => {
    const sec = (auth, cipher = 0) => ws.securityOf(ws.kindsOfAuth(auth, cipher));
    assert.equal(sec(9, 4), 'WPA3', 'WPA3-SAE');
    assert.equal(sec(7, 4), 'WPA2', 'RSNA-PSK');
    assert.equal(sec(6, 4), 'WPA2', 'RSNA (enterprise)');
    assert.equal(sec(4, 2), 'WPA', 'WPA-PSK');
    assert.equal(sec(3, 2), 'WPA', 'WPA (enterprise)');
    assert.equal(sec(11, 4), 'WPA3', 'WPA3 enterprise');
    assert.equal(sec(1, 0x101), 'WEP', 'open + WEP');
    assert.equal(sec(1, 0x1), 'WEP', 'open + WEP40');
    assert.equal(sec(1, 0x5), 'WEP', 'open + WEP104');
    assert.equal(sec(2, 0x101), 'WEP', 'shared key');
    assert.equal(sec(1, 0), 'Offen');
    assert.equal(sec(10, 4), 'Offen', 'OWE (Enhanced Open) needs no password');
    assert.equal(sec(0x80000001, 0), '', 'vendor specific: unknown');
  });

  it('a network with both SAE and PSK is "WPA2/WPA3"', () => {
    assert.equal(ws.securityOf(['sae', 'rsn-psk']), 'WPA2/WPA3');
    assert.equal(ws.securityOf(['rsn-psk', 'wpa-psk']), 'WPA2', 'WPA/WPA2 mixed');
    assert.equal(ws.securityOf(['open', 'rsn-psk']), 'WPA2', 'secured wins');
    assert.equal(ws.securityOf([]), '');
  });

  it('reads the RSN / WPA elements of an access point', () => {
    assert.deepEqual(ws.kindsOfIes(Buffer.concat([ssidIe('x'), rsn(2)])), ['rsn-psk']);
    assert.deepEqual(ws.kindsOfIes(Buffer.concat([ssidIe('x'), rsn(2, 8)])).sort(), ['rsn-psk', 'sae']);
    assert.deepEqual(ws.kindsOfIes(rsn(8)), ['sae']);
    assert.deepEqual(ws.kindsOfIes(rsn(24)), ['sae'], 'SAE-EXT-KEY (Wi-Fi 7)');
    assert.deepEqual(ws.kindsOfIes(rsn(1)), ['rsn-eap']);
    assert.deepEqual(ws.kindsOfIes(rsn(18)), ['owe']);
    assert.deepEqual(ws.kindsOfIes(Buffer.concat([wpa(2), rsn(2)])).sort(), ['rsn-psk', 'wpa-psk']);
    assert.deepEqual(ws.kindsOfIes(wpa(2)), ['wpa-psk']);
    assert.deepEqual(ws.kindsOfIes(ssidIe('x'), 0x0011), ['wep'], 'no RSN / WPA, Privacy bit');
    assert.deepEqual(ws.kindsOfIes(ssidIe('x'), 0x0001), ['open']);
    assert.deepEqual(ws.kindsOfIes(Buffer.from([48, 40, 1, 0])), ['open'], 'truncated element is ignored');
    assert.deepEqual(ws.kindsOfIes(Buffer.from([48, 4, 1, 0, 0, 0x0f])), [], 'RSN without AKM list: secured, kind unknown');
  });
});

describe('wifi-scan: lists from the API', () => {
  it('interfaces', () => {
    const list = ws.parseInterfaceList(interfaceList([{ description: 'Intel(R) Wi-Fi 6 AX201' }, { description: 'USB WLAN', state: 0 }]));
    assert.equal(list.length, 2);
    assert.equal(list[0].description, 'Intel(R) Wi-Fi 6 AX201');
    assert.equal(list[0].guid.length, 16);
    assert.deepEqual([list[0].state, list[1].state], [1, 0]);
    assert.deepEqual(ws.parseInterfaceList(Buffer.alloc(3)), []);
    const lying = interfaceList([{}]);
    lying.writeUInt32LE(5000, 0);
    assert.equal(ws.parseInterfaceList(lying).length, 1, 'count bounded by the buffer');
  });

  it('networks', () => {
    const nets = ws.parseNetworkList(networkList([
      { ssid: 'Heim', signal: 88, auth: 7, cipher: 4, connected: true },
      { ssid: '', signal: 70, auth: 7 },
      { ssid: 'Lang', ssidLength: 99, signal: 120, auth: 9 },
    ]));
    assert.deepEqual(nets[0], { ssid: 'Heim', signal: 88, connected: true, kinds: ['rsn-psk'] });
    assert.equal(nets[1].ssid, '');
    assert.equal(nets[2].signal, 100, 'bounded to 0–100');
    assert.equal(nets[2].ssid, 'Lang', 'length bounded to 32');
  });

  it('access points with their elements', () => {
    const bss = ws.parseBssList(bssList([
      { ssid: 'Heim', ies: [ssidIe('Heim'), rsn(2, 8)] },
      { ssid: 'Alt', capability: 0x10, ies: [ssidIe('Alt')] },
    ]));
    assert.deepEqual(bss.map((b) => [b.ssid, b.kinds.sort()]), [['Heim', ['rsn-psk', 'sae']], ['Alt', ['wep']]]);
    const broken = bssList([{ ssid: 'X', ies: [rsn(2)] }]);
    broken.writeUInt32LE(1e6, L.LIST_HEADER + L.BSS.ieSize);
    assert.deepEqual(ws.parseBssList(broken)[0].kinds, ['open'], 'elements outside the buffer are not read');
  });
});

describe('wifi-scan: one row per SSID', () => {
  it('strongest signal, connected first, security of all entries, hidden ones left out', () => {
    const rows = ws.mergeNetworks([
      { ssid: 'Nachbar', signal: 91, kinds: ['rsn-psk'] },
      { ssid: 'Heim', signal: 40, kinds: ['rsn-psk'], connected: true },
      { ssid: 'Heim', signal: 62, kinds: ['sae'] },
      { ssid: 'Café', signal: 55, kinds: ['open'] },
      { ssid: 'Büro', signal: 55, kinds: ['rsn-psk'] },
      { ssid: '', signal: 99, kinds: ['rsn-psk'] },
    ], [{ ssid: 'Nachbar', kinds: ['sae'] }, { ssid: 'Fremd', kinds: ['sae'] }]);
    assert.deepEqual(rows, [
      { ssid: 'Heim', security: 'WPA2/WPA3', signal: 62, connected: true },
      { ssid: 'Nachbar', security: 'WPA2/WPA3', signal: 91, connected: false },
      { ssid: 'Büro', security: 'WPA2', signal: 55, connected: false },
      { ssid: 'Café', security: 'Offen', signal: 55, connected: false },
    ]);
  });

  it('at most 100 rows', () => {
    const many = Array.from({ length: 150 }, (_, i) => ({ ssid: `N${i}`, signal: i % 100, kinds: ['rsn-psk'] }));
    assert.equal(ws.mergeNetworks(many).length, 100);
  });
});

describe('wifi-scan: errors', () => {
  it('maps Windows error codes', () => {
    assert.equal(ws.errorCode(5), 'location_denied');
    assert.equal(ws.errorCode(1062), 'service_off');
    assert.equal(ws.errorCode(1058), 'service_off');
    assert.equal(ws.errorCode(1060), 'no_adapter');
    assert.equal(ws.errorCode(0x80342002), 'radio_off');
    assert.equal(ws.errorCode(-2144067582), 'radio_off', 'the same code read as signed');
    assert.equal(ws.errorCode(87), 'failed');
  });
});

describe('wifi-scan: scan flow (fake native layer)', () => {
  const winErr = (code, win32) => new ws.WifiScanError(code, { win32, fn: 'Wlan…' });

  function fake(over = {}) {
    const calls = [];
    const api = {
      calls,
      open: () => { calls.push('open'); return 'h'; },
      close: (h) => calls.push(`close:${h}`),
      interfaces: () => interfaceList([{ description: 'WLAN' }]),
      scan: () => calls.push('scan'),
      networks: () => networkList([
        { ssid: 'Heim', signal: 80, auth: 9, connected: true },
        { ssid: 'Heim', signal: 80, auth: 7 },
        { ssid: 'Gast', signal: 60, auth: 1 },
      ]),
      bss: () => bssList([{ ssid: 'Gast', ies: [ssidIe('Gast')] }]),
      ...over,
    };
    return api;
  }
  const run = (api, extra = {}) => ws.scanWifi({ platform: 'win32', native: api, waitMs: 0, ...extra });

  it('scans, lists, closes the handle', async () => {
    const api = fake();
    assert.deepEqual(await run(api), [
      { ssid: 'Heim', security: 'WPA2/WPA3', signal: 80, connected: true },
      { ssid: 'Gast', security: 'Offen', signal: 60, connected: false },
    ]);
    assert.deepEqual(api.calls, ['open', 'scan', 'close:h']);
  });

  it('not Windows / no adapter', async () => {
    await assert.rejects(ws.scanWifi({ platform: 'linux' }), { code: 'no_adapter' });
    await assert.rejects(run(fake({ interfaces: () => interfaceList([]) })), { code: 'no_adapter' });
    await assert.rejects(run(fake({ open: () => { throw winErr('service_off', 1062); } })), { code: 'service_off' });
  });

  it('location access off (Windows 11 24H2+): location_denied, the handle is closed', async () => {
    const api = fake({ scan: () => { throw winErr('location_denied', 5); }, networks: () => { throw winErr('location_denied', 5); } });
    await assert.rejects(run(api), { code: 'location_denied' });
    assert.deepEqual(api.calls, ['open', 'close:h']);
    await assert.rejects(run(fake({ networks: () => { throw winErr('location_denied', 5); } })), { code: 'location_denied' });
  });

  it('radio off; a busy scan still gives the cached list; a broken BSS list is not fatal', async () => {
    await assert.rejects(run(fake({ scan: () => { throw winErr('radio_off', 0x80342002); } })), { code: 'radio_off' });
    assert.equal((await run(fake({ scan: () => { throw winErr('failed', 170); } }))).length, 2);
    const rows = await run(fake({ bss: () => { throw winErr('failed', 87); } }));
    assert.equal(rows.find((r) => r.ssid === 'Gast').security, 'Offen');
  });

  it('anything unexpected becomes failed; concurrent calls share one scan', async () => {
    await assert.rejects(run(fake({ interfaces: () => { throw new TypeError('boom'); } })), { code: 'failed' });
    let scans = 0;
    const api = fake({ scan: () => { scans++; } });
    const [a, b] = await Promise.all([run(api, { waitMs: 20 }), run(api, { waitMs: 20 })]);
    assert.equal(scans, 1);
    assert.deepEqual(a, b);
  });
});

describe('wifi-scan: struct layout', () => {
  let koffi = null;
  try { koffi = require('koffi'); } catch { /* not installed for this platform */ }

  it('offsets match the Windows structs (computed by koffi)', { skip: koffi ? false : 'koffi not available' }, () => {
    const u = (n) => koffi.array('uint8_t', n);
    const iface = koffi.struct('GC_TEST_WLAN_INTERFACE_INFO', { guid: u(16), description: koffi.array('uint16_t', 256), state: 'int32_t' });
    const ssid = koffi.struct('GC_TEST_DOT11_SSID', { len: 'uint32_t', bytes: u(32) });
    const net = koffi.struct('GC_TEST_WLAN_AVAILABLE_NETWORK', {
      profile: koffi.array('uint16_t', 256), ssid, bssType: 'int32_t', bssids: 'uint32_t', connectable: 'int32_t', reason: 'uint32_t',
      phyCount: 'uint32_t', phy: koffi.array('int32_t', 8), morePhy: 'int32_t', signal: 'uint32_t', securityEnabled: 'int32_t',
      auth: 'int32_t', cipher: 'int32_t', flags: 'uint32_t', reserved: 'uint32_t',
    });
    const bss = koffi.struct('GC_TEST_WLAN_BSS_ENTRY', {
      ssid, phyId: 'uint32_t', bssid: u(6), bssType: 'int32_t', phyType: 'int32_t', rssi: 'int32_t', linkQuality: 'uint32_t',
      inRegDomain: 'uint8_t', beaconPeriod: 'uint16_t', timestamp: 'uint64_t', hostTimestamp: 'uint64_t', capability: 'uint16_t',
      chCenterFrequency: 'uint32_t', rateSet: koffi.struct('GC_TEST_WLAN_RATE_SET', { len: 'uint32_t', rates: koffi.array('uint16_t', 126) }),
      ieOffset: 'uint32_t', ieSize: 'uint32_t',
    });
    assert.equal(koffi.sizeof(iface), L.IFACE_SIZE);
    assert.equal(koffi.offsetof(iface, 'description'), L.IFACE.description);
    assert.equal(koffi.offsetof(iface, 'state'), L.IFACE.state);
    assert.equal(koffi.sizeof(net), L.NET_SIZE);
    assert.equal(koffi.offsetof(net, 'ssid'), L.NET.ssidLength);
    assert.equal(koffi.offsetof(net, 'ssid') + 4, L.NET.ssid);
    for (const k of ['connectable', 'signal', 'securityEnabled', 'auth', 'cipher', 'flags']) assert.equal(koffi.offsetof(net, k), L.NET[k], k);
    assert.equal(koffi.sizeof(bss), L.BSS_SIZE);
    for (const k of ['rssi', 'linkQuality', 'capability', 'ieOffset', 'ieSize']) assert.equal(koffi.offsetof(bss, k), L.BSS[k], k);
  });
});
