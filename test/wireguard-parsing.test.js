'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// WireGuardNative constructor requires koffi DLLs (Windows only).
// We test the pure methods via prototype — no instantiation needed.
const WireGuardNative = require('../src/services/wireguard-native');
const proto = WireGuardNative.prototype;

// ── _parseConfig ─────────────────────────────────────────────

describe('WireGuard _parseConfig', () => {
  it('parses a minimal valid config', () => {
    const config = proto._parseConfig(`
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.8.0.2/32
DNS = 10.8.0.1

[Peer]
PublicKey = c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Ng==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
`);

    assert.equal(config.privateKey, 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=');
    assert.equal(config.address, '10.8.0.2/32');
    assert.equal(config.dns, '10.8.0.1');
    assert.equal(config.mtu, null);
    assert.equal(config.peers.length, 1);
    assert.equal(config.peers[0].PublicKey, 'c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Ng==');
    assert.equal(config.peers[0].Endpoint, 'vpn.example.com:51820');
    assert.equal(config.peers[0].AllowedIPs, '0.0.0.0/0, ::/0');
  });

  it('parses MTU when present', () => {
    const config = proto._parseConfig(`
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.8.0.5/32
MTU = 1280

[Peer]
PublicKey = c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Ng==
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`);

    assert.equal(config.mtu, 1280);
  });

  it('handles multiple peers', () => {
    const config = proto._parseConfig(`
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.8.0.2/32

[Peer]
PublicKey = cGVlcjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0

[Peer]
PublicKey = cGVlcjIyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg=
Endpoint = 5.6.7.8:51820
AllowedIPs = 10.0.0.0/8
`);

    assert.equal(config.peers.length, 2);
    assert.equal(config.peers[0].Endpoint, '1.2.3.4:51820');
    assert.equal(config.peers[1].Endpoint, '5.6.7.8:51820');
  });

  it('skips comments and blank lines', () => {
    const config = proto._parseConfig(`
# This is a comment
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
# Another comment
Address = 10.8.0.2/32

[Peer]
PublicKey = c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Ng==
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`);

    assert.equal(config.privateKey, 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=');
    assert.equal(config.peers.length, 1);
  });

  it('handles optional PresharedKey and PersistentKeepalive', () => {
    const config = proto._parseConfig(`
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.8.0.2/32

[Peer]
PublicKey = c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ1Ng==
PresharedKey = cHJlc2hhcmVkMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`);

    assert.equal(config.peers[0].PresharedKey, 'cHJlc2hhcmVkMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=');
    assert.equal(config.peers[0].PersistentKeepalive, '25');
  });

  it('returns empty peers for Interface-only config', () => {
    const config = proto._parseConfig(`
[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.8.0.2/32
`);

    assert.equal(config.peers.length, 0);
  });

  it('returns nulls for empty input', () => {
    const config = proto._parseConfig('');
    assert.equal(config.privateKey, null);
    assert.equal(config.address, null);
    assert.equal(config.dns, null);
    assert.equal(config.peers.length, 0);
  });
});

// ── _decodeKey ───────────────────────────────────────────────

describe('WireGuard _decodeKey', () => {
  it('decodes a valid 32-byte base64 key', () => {
    // 32 bytes of zeros in base64
    const key = Buffer.alloc(32, 0).toString('base64');
    const result = proto._decodeKey(key);
    assert.equal(result.length, 32);
  });

  it('throws on invalid key length', () => {
    const shortKey = Buffer.alloc(16, 0).toString('base64');
    assert.throws(() => proto._decodeKey(shortKey), /32 Bytes/);
  });

  it('throws on too-long key', () => {
    const longKey = Buffer.alloc(64, 0).toString('base64');
    assert.throws(() => proto._decodeKey(longKey), /32 Bytes/);
  });
});

// ── _expandIPv6 ──────────────────────────────────────────────

describe('WireGuard _expandIPv6', () => {
  it('expands :: to all zeros', () => {
    const groups = proto._expandIPv6('::');
    assert.deepEqual(groups, [0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('expands ::1 (loopback)', () => {
    const groups = proto._expandIPv6('::1');
    assert.deepEqual(groups, [0, 0, 0, 0, 0, 0, 0, 1]);
  });

  it('expands fe80::1', () => {
    const groups = proto._expandIPv6('fe80::1');
    assert.deepEqual(groups, [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  });

  it('expands full address without ::', () => {
    const groups = proto._expandIPv6('2001:db8:0:0:0:0:0:1');
    assert.deepEqual(groups, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
  });

  it('expands address with :: in the middle', () => {
    const groups = proto._expandIPv6('2001:db8::ff00:42:8329');
    assert.deepEqual(groups, [0x2001, 0x0db8, 0, 0, 0, 0xff00, 0x42, 0x8329]);
  });
});

// ── _cidrToMask ──────────────────────────────────────────────

describe('WireGuard _cidrToMask', () => {
  it('converts /0 to 0.0.0.0', () => {
    assert.equal(proto._cidrToMask(0), '0.0.0.0');
  });

  it('converts /8 to 255.0.0.0', () => {
    assert.equal(proto._cidrToMask(8), '255.0.0.0');
  });

  it('converts /16 to 255.255.0.0', () => {
    assert.equal(proto._cidrToMask(16), '255.255.0.0');
  });

  it('converts /24 to 255.255.255.0', () => {
    assert.equal(proto._cidrToMask(24), '255.255.255.0');
  });

  it('converts /32 to 255.255.255.255', () => {
    assert.equal(proto._cidrToMask(32), '255.255.255.255');
  });

  it('converts /25 to 255.255.255.128', () => {
    assert.equal(proto._cidrToMask(25), '255.255.255.128');
  });
});

// ── _decodeEndpoint ──────────────────────────────────────────

describe('WireGuard _decodeEndpoint', () => {
  it('decodes IPv4 endpoint', () => {
    const buf = Buffer.alloc(28, 0);
    buf.writeUInt16LE(2, 0);      // AF_INET
    buf.writeUInt16BE(51820, 2);   // port
    buf[4] = 1; buf[5] = 2; buf[6] = 3; buf[7] = 4; // IP 1.2.3.4
    assert.equal(proto._decodeEndpoint(buf), '1.2.3.4:51820');
  });

  it('returns null for zero endpoint', () => {
    const buf = Buffer.alloc(28, 0);
    buf.writeUInt16LE(2, 0); // AF_INET but 0.0.0.0:0
    assert.equal(proto._decodeEndpoint(buf), null);
  });

  it('returns null for non-IPv4 family', () => {
    const buf = Buffer.alloc(28, 0);
    buf.writeUInt16LE(23, 0); // AF_INET6
    assert.equal(proto._decodeEndpoint(buf), null);
  });
});

// ── _filetimeToUnix ──────────────────────────────────────────

describe('WireGuard _filetimeToUnix', () => {
  it('returns 0 for zero filetime', () => {
    assert.equal(proto._filetimeToUnix(0n), 0);
  });

  it('converts known filetime correctly', () => {
    // Verify round-trip: pick a known Unix timestamp, convert to FILETIME, verify back
    // FILETIME = (unixSeconds + 11644473600) * 10000000
    const knownUnix = 1700000000; // 2023-11-14T22:13:20Z
    const ft = BigInt(knownUnix + 11644473600) * 10000000n;
    assert.equal(proto._filetimeToUnix(ft), knownUnix);
  });

  it('returns 0 for pre-epoch filetime', () => {
    assert.equal(proto._filetimeToUnix(1n), 0);
  });
});

// ── _formatAge ───────────────────────────────────────────────

describe('WireGuard _formatAge', () => {
  it('formats seconds', () => {
    assert.equal(proto._formatAge(30), 'vor 30s');
  });

  it('formats minutes', () => {
    assert.equal(proto._formatAge(120), 'vor 2m');
  });

  it('formats hours', () => {
    assert.equal(proto._formatAge(7200), 'vor 2h');
  });

  it('formats days', () => {
    assert.equal(proto._formatAge(172800), 'vor 2d');
  });

  it('formats boundary: 59 seconds', () => {
    assert.equal(proto._formatAge(59), 'vor 59s');
  });

  it('formats boundary: 60 seconds → 1m', () => {
    assert.equal(proto._formatAge(60), 'vor 1m');
  });

  it('formats boundary: 3599 → 59m', () => {
    assert.equal(proto._formatAge(3599), 'vor 59m');
  });

  it('formats boundary: 3600 → 1h', () => {
    assert.equal(proto._formatAge(3600), 'vor 1h');
  });
});
