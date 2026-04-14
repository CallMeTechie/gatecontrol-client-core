'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// KillSwitch constructor requires netsh (Windows only).
// Test pure methods via prototype.
const KillSwitch = require('../src/services/killswitch');
const proto = KillSwitch.prototype;

// ── _ipToNum / _numToIp ──────────────────────────────────────

describe('KillSwitch _ipToNum', () => {
  it('converts 0.0.0.0', () => {
    assert.equal(proto._ipToNum('0.0.0.0'), 0);
  });

  it('converts 255.255.255.255', () => {
    assert.equal(proto._ipToNum('255.255.255.255'), 0xFFFFFFFF);
  });

  it('converts 10.8.0.1', () => {
    assert.equal(proto._ipToNum('10.8.0.1'), 0x0A080001);
  });

  it('converts 192.168.1.100', () => {
    assert.equal(proto._ipToNum('192.168.1.100'), 0xC0A80164);
  });

  it('converts 127.0.0.1', () => {
    assert.equal(proto._ipToNum('127.0.0.1'), 0x7F000001);
  });
});

describe('KillSwitch _numToIp', () => {
  it('converts 0 → 0.0.0.0', () => {
    assert.equal(proto._numToIp(0), '0.0.0.0');
  });

  it('converts 0xFFFFFFFF → 255.255.255.255', () => {
    assert.equal(proto._numToIp(0xFFFFFFFF), '255.255.255.255');
  });

  it('converts 0x0A080001 → 10.8.0.1', () => {
    assert.equal(proto._numToIp(0x0A080001), '10.8.0.1');
  });

  it('round-trips with _ipToNum', () => {
    const ip = '172.16.32.5';
    assert.equal(proto._numToIp(proto._ipToNum(ip)), ip);
  });
});

// ── _maskToPrefix ────────────────────────────────────────────

describe('KillSwitch _maskToPrefix', () => {
  it('converts /0 mask', () => {
    assert.equal(proto._maskToPrefix(0x00000000), 0);
  });

  it('converts /8 mask', () => {
    assert.equal(proto._maskToPrefix(0xFF000000), 8);
  });

  it('converts /16 mask', () => {
    assert.equal(proto._maskToPrefix(0xFFFF0000), 16);
  });

  it('converts /24 mask', () => {
    assert.equal(proto._maskToPrefix(0xFFFFFF00), 24);
  });

  it('converts /32 mask', () => {
    assert.equal(proto._maskToPrefix(0xFFFFFFFF), 32);
  });

  it('converts /25 mask', () => {
    assert.equal(proto._maskToPrefix(0xFFFFFF80), 25);
  });

  it('converts /12 mask', () => {
    assert.equal(proto._maskToPrefix(0xFFF00000), 12);
  });
});

// ── _parseConfig ─────────────────────────────────────────────

describe('KillSwitch _parseConfig', () => {
  it('extracts endpoint, vpnSubnet, and vpnLocalIp', () => {
    const result = proto._parseConfig(`
[Interface]
PrivateKey = somekey
Address = 10.8.0.2/32

[Peer]
PublicKey = serverpub
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`);

    assert.equal(result.endpoint.host, 'vpn.example.com');
    assert.equal(result.endpoint.port, '51820');
    assert.equal(result.endpoint.needsResolve, true);
    assert.equal(result.vpnLocalIp, '10.8.0.2');
    assert.equal(result.vpnSubnet, '10.8.0.0/24'); // /32 expanded to /24
  });

  it('parses IP literal endpoint (no resolve needed)', () => {
    const result = proto._parseConfig(`
[Interface]
Address = 10.8.0.5/32

[Peer]
Endpoint = 1.2.3.4:51820
`);

    assert.equal(result.endpoint.host, '1.2.3.4');
    assert.equal(result.endpoint.needsResolve, false);
  });

  it('expands /32 address to /24 subnet', () => {
    const result = proto._parseConfig(`
[Interface]
Address = 10.8.0.15/32

[Peer]
Endpoint = 1.2.3.4:51820
`);

    assert.equal(result.vpnSubnet, '10.8.0.0/24');
    assert.equal(result.vpnLocalIp, '10.8.0.15');
  });

  it('preserves subnet mask <= 24', () => {
    const result = proto._parseConfig(`
[Interface]
Address = 10.8.0.15/16

[Peer]
Endpoint = 1.2.3.4:51820
`);

    assert.equal(result.vpnSubnet, '10.8.0.0/16');
  });

  it('handles multiple addresses (takes first)', () => {
    const result = proto._parseConfig(`
[Interface]
Address = 10.8.0.2/32, fd00::2/128

[Peer]
Endpoint = 1.2.3.4:51820
`);

    assert.equal(result.vpnLocalIp, '10.8.0.2');
  });

  it('returns nulls for empty config', () => {
    const result = proto._parseConfig('');
    assert.equal(result.endpoint, null);
    assert.equal(result.vpnSubnet, null);
    assert.equal(result.vpnLocalIp, null);
  });

  it('returns null endpoint for config without Peer section', () => {
    const result = proto._parseConfig(`
[Interface]
Address = 10.8.0.2/32
`);

    assert.equal(result.endpoint, null);
    assert.equal(result.vpnLocalIp, '10.8.0.2');
  });
});
