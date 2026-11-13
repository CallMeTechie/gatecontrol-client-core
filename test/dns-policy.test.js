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

// „Namen im VPN“: the server answers several zones (internalDns.domains,
// GateControl >= 1.271) — one NRPT rule each, kept in step with the list.
describe('DnsPolicy.rulesFor', () => {
  const config = wg('10.8.0.5/32', '10.8.0.1');

  it('one rule per zone of the server, all to its resolver', () => {
    assert.deepEqual(
      DnsPolicy.rulesFor({
        internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains: ['VPN.Example.com', 'gc.internal'], primary: 'vpn.example.com' },
        wgConfig: config,
      }),
      [
        { namespace: '.vpn.example.com', nameServer: '10.8.0.1' },
        { namespace: '.gc.internal', nameServer: '10.8.0.1' },
      ]);
  });

  it('an older server without `domains`: the one rule for `domain`, as before', () => {
    assert.deepEqual(DnsPolicy.rulesFor({ internalDns: { domain: 'vpn.home', server: '10.44.0.1' }, wgConfig: config }),
      [{ namespace: '.vpn.home', nameServer: '10.44.0.1' }]);
    assert.deepEqual(DnsPolicy.rulesFor({ wgConfig: wg('10.20.30.7/32', '10.20.30.1') }),
      [{ namespace: '.gc.internal', nameServer: '10.20.30.1' }]);
    assert.deepEqual(DnsPolicy.rulesFor(), [{ namespace: '.gc.internal', nameServer: '10.8.0.1' }]);
  });

  it('no rule while the internal DNS is off', () => {
    assert.deepEqual(DnsPolicy.rulesFor({ internalDns: null, wgConfig: config }), []);
  });

  it('drops entries that are no plain DNS names, and doubles', () => {
    const rules = DnsPolicy.rulesFor({
      internalDns: {
        domain: 'gc.internal',
        server: '10.8.0.1',
        domains: ["x'; calc; '", 'a b.example.com', '$(calc).example.com', '*.example.com', '.example.com', 'example.com.',
          '', null, 42, { toString: () => 'evil.example.com' }, ['nested.example.com'], 'a'.repeat(64) + '.example.com',
          Array(60).fill('abcd').join('.'), 'vpn.example.com', 'VPN.example.com', 'gc.internal'],
      },
      wgConfig: config,
    });
    assert.deepEqual(rules.map((r) => r.namespace), ['.vpn.example.com', '.gc.internal']);
  });

  it('a list without a usable entry falls back to `domain`', () => {
    for (const domains of [[], ['bad zone'], 'gc.internal', { 0: 'vpn.example.com', length: 1 }]) {
      assert.deepEqual(DnsPolicy.rulesFor({ internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains }, wgConfig: config }),
        [{ namespace: '.gc.internal', nameServer: '10.8.0.1' }]);
    }
  });

  it('caps the number of zones', () => {
    const domains = Array.from({ length: 500 }, (_, i) => `zone${i}.example.com`);
    const rules = DnsPolicy.rulesFor({ internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains }, wgConfig: config });
    assert.equal(rules.length, 8);
    assert.equal(rules[0].namespace, '.zone0.example.com');
  });

  it('an unusable resolver: no rule to it for any zone', () => {
    assert.deepEqual(
      DnsPolicy.rulesFor({ internalDns: { domain: 'gc.internal', server: "10.8.0.1'; calc; '", domains: ['vpn.example.com', 'gc.internal'] }, wgConfig: config }),
      [{ namespace: '.gc.internal', nameServer: '10.8.0.1' }]);
  });

  it('ruleFor keeps answering with the one rule for `domain`', () => {
    assert.deepEqual(
      DnsPolicy.ruleFor({ internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains: ['vpn.example.com', 'gc.internal'] }, wgConfig: config }),
      { namespace: '.gc.internal', nameServer: '10.8.0.1' });
  });
});

describe('DnsPolicy.sync', () => {
  // A stand-in for the NRPT of Windows: rules as { namespace, server, comment },
  // changed by the three PowerShell commands the policy runs.
  function fakeNrpt(initial = []) {
    const table = initial.map((r) => ({ ...r }));
    const scripts = [];
    const policy = new DnsPolicy({ info() {}, warn() {}, debug() {} });
    policy._runPs = async (script) => {
      scripts.push(script);
      const add = /^Add-DnsClientNrptRule -Namespace '([^']+)' -NameServers '([^']+)' -Comment '([^']+)'$/.exec(script);
      if (add) { table.push({ namespace: add[1], server: add[2], comment: add[3] }); return { err: null }; }
      const own = (r) => r.comment.startsWith('GateControl');
      let doomed;
      const keep = /^\$keep = @\(([^)]*)\); Get-DnsClientNrptRule \| Where-Object \{ \$_\.Comment -like 'GateControl\*' -and \$keep -notcontains \$_\.Comment \}/.exec(script);
      const one = /Where-Object \{ \$_\.Namespace -contains '([^']+)' -and \$_\.Comment -like 'GateControl\*' \}/.exec(script);
      if (keep) {
        const kept = keep[1] ? keep[1].split(',').map((c) => c.replace(/^'|'$/g, '')) : [];
        doomed = (r) => own(r) && !kept.includes(r.comment);
      } else if (one) doomed = (r) => own(r) && r.namespace === one[1];
      else if (/Where-Object \{ \$_\.Comment -like 'GateControl\*' \}/.test(script)) doomed = own;
      else throw new Error('unexpected PowerShell: ' + script);
      for (let i = table.length - 1; i >= 0; i--) if (doomed(table[i])) table.splice(i, 1);
      return { err: null };
    };
    const rules = () => table.map((r) => `${r.namespace}>${r.server}`).sort();
    return { policy, table, scripts, rules };
  }
  const rule = (zone, nameServer = '10.8.0.1') => ({ namespace: '.' + zone, nameServer });
  const foreign = { namespace: '.corp.example', server: '192.0.2.53', comment: 'Company VPN' };

  it('installs one rule per zone', async () => {
    const { policy, rules } = fakeNrpt([foreign]);
    const applied = await policy.sync([rule('vpn.example.com'), rule('gc.internal')], { force: true });
    assert.deepEqual(applied, ['.vpn.example.com', '.gc.internal']);
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53', '.gc.internal>10.8.0.1', '.vpn.example.com>10.8.0.1']);
  });

  it('a new zone is added, a zone no longer listed is removed — rules of others stay', async () => {
    const { policy, rules } = fakeNrpt([foreign]);
    await policy.sync([rule('vpn.example.com'), rule('gc.internal')], { force: true });
    await policy.sync([rule('names.example.org'), rule('gc.internal')]);
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53', '.gc.internal>10.8.0.1', '.names.example.org>10.8.0.1']);
    assert.equal(policy.coversName('laptop.vpn.example.com'), false);
    // back to the old zone alone
    await policy.sync([rule('gc.internal')]);
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53', '.gc.internal>10.8.0.1']);
  });

  it('runs nothing while the rules already match', async () => {
    const { policy, scripts } = fakeNrpt();
    await policy.sync([rule('vpn.example.com'), rule('gc.internal')], { force: true });
    const before = scripts.length;
    await policy.sync([rule('gc.internal'), rule('vpn.example.com')]);
    assert.equal(scripts.length, before);
  });

  it('a changed resolver replaces the rule', async () => {
    const { policy, rules } = fakeNrpt();
    await policy.sync([rule('gc.internal')], { force: true });
    await policy.sync([rule('gc.internal', '10.9.0.1')]);
    assert.deepEqual(rules(), ['.gc.internal>10.9.0.1']);
  });

  it('on connect: rules left by a killed process (also the old bare tag) are replaced', async () => {
    const { policy, rules } = fakeNrpt([
      { namespace: '.old.example.com', server: '10.8.0.1', comment: 'GateControl:.old.example.com' },
      { namespace: '.gc.internal', server: '10.7.0.1', comment: 'GateControl' },
      foreign,
    ]);
    await policy.sync([rule('gc.internal')], { force: true });
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53', '.gc.internal>10.8.0.1']);
  });

  it('an empty list removes the own rules (internal DNS switched off)', async () => {
    const { policy, rules } = fakeNrpt([foreign]);
    await policy.sync([rule('gc.internal')], { force: true });
    assert.deepEqual(await policy.sync([]), []);
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53']);
  });

  it('nothing from an invalid rule reaches PowerShell', async () => {
    const { policy, scripts, rules } = fakeNrpt();
    await policy.sync([
      { namespace: ".x'; Remove-Item C:\\ -Recurse; '", nameServer: '10.8.0.1' },
      { namespace: '.ok.example.com', nameServer: "10.8.0.1'; calc; '" },
      { namespace: '.a`b.example.com', nameServer: '10.8.0.1' },
      null, 'gc.internal', {},
      rule('gc.internal'),
    ], { force: true });
    assert.deepEqual(rules(), ['.gc.internal>10.8.0.1']);
    for (const script of scripts) assert.ok(!/calc|Remove-Item|`/.test(script), script);
    assert.deepEqual(await policy.sync('gc.internal'), []);
  });

  it('never more rules than the cap', async () => {
    const { policy, table } = fakeNrpt();
    await policy.sync(Array.from({ length: 50 }, (_, i) => rule(`zone${i}.example.com`)), { force: true });
    assert.equal(table.length, 8);
  });

  it('a failed add is not counted as a rule', async () => {
    const { policy } = fakeNrpt();
    const run = policy._runPs;
    policy._runPs = async (script) => (script.startsWith('Add-') && script.includes('.vpn.example.com')
      ? { err: new Error('access denied'), stderr: '' } : run(script));
    assert.deepEqual(await policy.sync([rule('vpn.example.com'), rule('gc.internal')], { force: true }), ['.gc.internal']);
    assert.equal(policy.coversName('laptop.vpn.example.com'), false);
    assert.equal(policy.coversName('laptop.gc.internal'), true);
  });

  it('removeAll after a running sync leaves no rule behind', async () => {
    const { policy, rules } = fakeNrpt([foreign]);
    const syncing = policy.sync([rule('vpn.example.com'), rule('gc.internal')], { force: true });
    const removing = policy.removeAll();
    await Promise.all([syncing, removing]);
    assert.deepEqual(rules(), ['.corp.example>192.0.2.53']);
    assert.equal(policy.applied.size, 0);
  });

  it('remove() refuses a namespace that is no DNS name', async () => {
    const { policy, scripts } = fakeNrpt();
    await policy.remove(".x'; calc; '");
    assert.equal(scripts.length, 0);
  });
});

describe('DnsPolicy.coversName', () => {
  it('true only for names inside a zone with an installed rule', async () => {
    const policy = new DnsPolicy({ info() {}, warn() {}, debug() {} });
    policy._runPs = async () => ({ err: null });
    assert.equal(policy.coversName('laptop.vpn.example.com'), false);
    await policy.sync([{ namespace: '.vpn.example.com', nameServer: '10.8.0.1' }], { force: true });
    assert.equal(policy.coversName('laptop.vpn.example.com'), true);
    assert.equal(policy.coversName('Laptop.VPN.Example.com'), true);
    assert.equal(policy.coversName('laptop.gc.internal'), false);
    assert.equal(policy.coversName('vpn.example.com'), false);
    assert.equal(policy.coversName('laptop.notvpn.example.com'), false);
    assert.equal(policy.coversName("x'.vpn.example.com"), false);
    assert.equal(policy.coversName(null), false);
    await policy.removeAll();
    assert.equal(policy.coversName('laptop.vpn.example.com'), false);
  });
});
