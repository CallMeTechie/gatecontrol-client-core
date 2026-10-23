'use strict';

// DnsPolicy.ruleFor: the NRPT rule for peer hostnames follows the server's
// settings (GET /client/config → internalDns) instead of a fixed
// .gc.internal → 10.8.0.1, with a fallback for servers that do not say.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const DnsPolicy = require('../src/services/dns-policy');

const wg = (address, dns) => [
  '[Interface]',
  'PrivateKey = x',
  `Address = ${address}`,
  dns ? `DNS = ${dns}` : '',
  '',
  '[Peer]',
  'PublicKey = y',
  'AllowedIPs = 0.0.0.0/0',
  'Endpoint = gate.example.com:51820',
].join('\n');

describe('DnsPolicy.ruleFor', () => {
  it('takes domain and resolver from the server', () => {
    assert.deepEqual(
      DnsPolicy.ruleFor({ internalDns: { domain: 'VPN.Home', server: '10.44.0.1' }, wgConfig: wg('10.8.0.5/32', '10.8.0.1') }),
      { namespace: '.vpn.home', nameServer: '10.44.0.1' });
  });

  it('no rule when the server has internal DNS off', () => {
    assert.equal(DnsPolicy.ruleFor({ internalDns: null, wgConfig: wg('10.8.0.5/32', '10.8.0.1') }), null);
  });

  it('older server: default domain, resolver from the tunnel config', () => {
    assert.deepEqual(DnsPolicy.ruleFor({ wgConfig: wg('10.20.30.7/32', '10.20.30.1, 1.1.1.1') }),
      { namespace: '.gc.internal', nameServer: '10.20.30.1' });
    // Public resolvers only: the gateway (first address of the subnet).
    assert.deepEqual(DnsPolicy.ruleFor({ wgConfig: wg('172.22.5.9/32', '1.1.1.1, 8.8.8.8') }),
      { namespace: '.gc.internal', nameServer: '172.22.5.1' });
    assert.deepEqual(DnsPolicy.ruleFor({ wgConfig: wg('10.8.0.5/32') }),
      { namespace: '.gc.internal', nameServer: '10.8.0.1' });
  });

  it('no usable config: the previous fixed values', () => {
    assert.deepEqual(DnsPolicy.ruleFor({}), { namespace: '.gc.internal', nameServer: '10.8.0.1' });
    assert.deepEqual(DnsPolicy.ruleFor(), { namespace: '.gc.internal', nameServer: '10.8.0.1' });
  });

  it('values that would break the PowerShell command are not taken from the server', () => {
    for (const internalDns of [
      { domain: "x'; Remove-Item C:\\ -Recurse; '", server: '10.8.0.1' },
      { domain: 'gc.internal', server: "10.8.0.1'; calc; '" },
      { domain: 'gc.internal', server: '300.1.1.1' },
      { domain: '', server: '10.8.0.1' },
    ]) {
      assert.deepEqual(DnsPolicy.ruleFor({ internalDns, wgConfig: wg('10.8.0.5/32', '10.8.0.1') }),
        { namespace: '.gc.internal', nameServer: '10.8.0.1' });
    }
  });
});

describe('DnsPolicy.add', () => {
  it('refuses an invalid namespace or name server without running PowerShell', async () => {
    const policy = new DnsPolicy({ info() {}, warn() {}, debug() {} });
    let ran = 0;
    policy._runPs = async () => { ran++; return { err: null }; };
    await policy.add(".x'; calc; '", '10.8.0.1');
    await policy.add('.gc.internal', 'not-an-ip');
    assert.equal(ran, 0);
    await policy.add('.gc.internal', '10.8.0.1');
    assert.equal(ran, 2);
    assert.ok(policy.applied.has('.gc.internal'));
  });
});
