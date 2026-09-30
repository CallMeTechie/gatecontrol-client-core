'use strict';

// Kill-switch flow against a simulated Windows Firewall: per-profile policy
// backup/restore, crash state in userData, stale-state recovery, prefix-based
// rule cleanup, netsh argument validation and error propagation.
// netsh is replaced by an in-memory fake (runs on Linux CI).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const KillSwitch = require('../src/services/killswitch');

const PROFILE_LABEL = { domain: 'Domain', private: 'Private', public: 'Public' };
const pretty = (v) => v.split(',').map(s => s
  .replace('blockinboundalways', 'BlockInboundAlways')
  .replace('blockinbound', 'BlockInbound')
  .replace('allowinbound', 'AllowInbound')
  .replace('allowoutbound', 'AllowOutbound')
  .replace('blockoutbound', 'BlockOutbound')
  .replace('notconfigured', 'NotConfigured')).join(',');

// Minimal netsh advfirewall simulator
class FakeFirewall {
  constructor(policy) {
    this.policy = { ...policy };
    this.rules = []; // { name, dir, args }
    this.calls = [];
    this.failOn = null; // (args) => Error|null
  }

  netsh = async (args) => {
    this.calls.push(args);
    if (this.failOn) {
      const err = this.failOn(args);
      if (err) throw err;
    }
    const [ctx, verb, a, b, c] = args;
    assert.equal(ctx, 'advfirewall');
    if (verb === 'show' && a.endsWith('profile') && b === 'firewallpolicy') {
      const profile = a.replace('profile', '');
      return { stdout: `\n${PROFILE_LABEL[profile]} Profile Settings:\n----------------------------------------------------------------------\nFirewall Policy                       ${pretty(this.policy[profile])}\nOk.\n\n` };
    }
    if (verb === 'set' && a.endsWith('profile') && b === 'firewallpolicy') {
      this.policy[a.replace('profile', '')] = c;
      return { stdout: 'Ok.\n' };
    }
    if (verb === 'firewall' && a === 'add' && b === 'rule') {
      const name = args.find(x => x.startsWith('name=')).slice(5);
      const dir = args.find(x => x.startsWith('dir=')).slice(4);
      this.rules.push({ name, dir, args });
      return { stdout: 'Ok.\n' };
    }
    if (verb === 'firewall' && a === 'delete' && b === 'rule') {
      const name = c.slice(5);
      const before = this.rules.length;
      this.rules = this.rules.filter(r => r.name !== name);
      if (before === this.rules.length) {
        const err = new Error('No rules match the specified criteria.');
        err.stdout = '\nNo rules match the specified criteria.\n';
        throw err;
      }
      return { stdout: `\nDeleted ${before - this.rules.length} rule(s).\nOk.\n` };
    }
    if (verb === 'firewall' && a === 'show' && b === 'rule') {
      const sel = c.slice(5);
      const shown = sel === 'all' ? [
        { name: 'Core Networking - DHCP (DHCP-In)', dir: 'in' },
        ...this.rules,
      ] : this.rules.filter(r => r.name === sel);
      if (shown.length === 0) {
        const err = new Error('No rules match');
        err.stdout = 'No rules match the specified criteria.';
        throw err;
      }
      return { stdout: shown.map(r => `\nRule Name:                            ${r.name}\n----------------------------------------------------------------------\nEnabled:                              Yes\nDirection:                            ${r.dir === 'in' ? 'In' : 'Out'}\n`).join('') };
    }
    throw new Error(`unexpected netsh call: ${args.join(' ')}`);
  };

  ksRules() { return this.rules.filter(r => r.name.startsWith('GateControl_Pro_KS_')); }
}

const silentLog = { info() {}, warn() {}, error() {}, debug() {} };

const CONFIG = `[Interface]
PrivateKey = aaaa
Address = 10.8.0.5/32
DNS = 10.8.0.1

[Peer]
PublicKey = bbbb
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
`;

const USER_POLICY = {
  domain: 'blockinbound,allowoutbound',
  private: 'allowinbound,allowoutbound',
  public: 'blockinboundalways,allowoutbound',
};

let tmp;
let configPath;
let stateFile;

function makeKs(fw, extra = {}) {
  return new KillSwitch(silentLog, {
    edition: 'pro',
    otherEditionPresent: async () => false,
    netsh: fw.netsh,
    stateFile,
    networkInterfaces: () => ({}),
    dnsLookup: async () => [{ address: '203.0.113.10', family: 4 }],
    ...extra,
  });
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-ks-'));
  configPath = path.join(tmp, 'gatecontrol0.conf');
  fs.writeFileSync(configPath, CONFIG);
  stateFile = path.join(tmp, 'userData', 'killswitch-state.json');
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('KillSwitch.parsePolicyOutput', () => {
  it('parses English output', () => {
    assert.equal(KillSwitch.parsePolicyOutput('Firewall Policy    BlockInbound,AllowOutbound'), 'blockinbound,allowoutbound');
  });
  it('parses localized output (values are not translated)', () => {
    assert.equal(KillSwitch.parsePolicyOutput('Domänenprofil-Einstellungen:\n-----\nFirewallrichtlinie   BlockInboundAlways,BlockOutbound\nOK.'), 'blockinboundalways,blockoutbound');
  });
  it('returns null for unparsable output', () => {
    assert.equal(KillSwitch.parsePolicyOutput('Access is denied.'), null);
  });
});

describe('KillSwitch enable/disable', () => {
  it('saves the per-profile policy, blocks outbound and restores exactly the saved policy', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw);

    await ks.enable(configPath);
    assert.equal(ks.enabled, true);
    assert.deepEqual(fw.policy, {
      domain: 'blockinbound,blockoutbound',
      private: 'blockinbound,blockoutbound',
      public: 'blockinboundalways,blockoutbound',
    });

    const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
    assert.deepEqual(state.savedPolicy, USER_POLICY);
    assert.equal(state.engaged, true);
    assert.ok(state.rules.includes('GateControl_Pro_KS_Allow_WG_Endpoint'));
    assert.equal(state.rules.length, fw.ksRules().length);

    await ks.disable();
    assert.equal(ks.enabled, false);
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fw.ksRules().length, 0);
    assert.equal(fs.existsSync(stateFile), false);
    // Non-GateControl rules must never be touched
    assert.ok(!fw.calls.some(c => c[2] === 'delete' && !c[4].startsWith('name=GateControl_Pro_KS_')));
  });

  it('creates all allow rules before the block policy is set', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    await makeKs(fw).enable(configPath);
    const firstBlock = fw.calls.findIndex(c => c[1] === 'set' && c[4].includes('blockoutbound'));
    const lastAdd = fw.calls.map(c => c[2]).lastIndexOf('add');
    assert.ok(firstBlock > lastAdd);
    const names = fw.ksRules().map(r => r.name);
    for (const n of ['GateControl_Pro_KS_Allow_WG_Endpoint', 'GateControl_Pro_KS_Allow_WG_Endpoint_In',
      'GateControl_Pro_KS_Allow_VPN_Out', 'GateControl_Pro_KS_Allow_VPN_DNS', 'GateControl_Pro_KS_Allow_DHCP',
      'GateControl_Pro_KS_Allow_DHCP_In', 'GateControl_Pro_KS_Allow_Loopback']) {
      assert.ok(names.includes(n), n);
    }
    const wg = fw.ksRules().find(r => r.name === 'GateControl_Pro_KS_Allow_WG_Endpoint');
    assert.ok(wg.args.includes('remoteip=203.0.113.10'));
    assert.ok(wg.args.includes('remoteport=51820'));
    assert.ok(wg.args.includes('protocol=udp'));
  });

  it('allows every resolved address of a hostname endpoint', async () => {
    fs.writeFileSync(configPath, CONFIG.replace('203.0.113.10:51820', 'vpn.example.com:51820'));
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw, {
      dnsLookup: async (host, opts) => {
        assert.equal(host, 'vpn.example.com');
        assert.equal(opts.all, true);
        return [{ address: '198.51.100.1', family: 4 }, { address: '198.51.100.2', family: 4 }];
      },
    });
    await ks.enable(configPath);
    const wg = fw.ksRules().find(r => r.name === 'GateControl_Pro_KS_Allow_WG_Endpoint');
    assert.ok(wg.args.includes('remoteip=198.51.100.1,198.51.100.2'));
  });

  it('disable() without an active kill-switch does not touch the user policy', async () => {
    const fw = new FakeFirewall({ ...USER_POLICY, domain: 'blockinbound,blockoutbound' });
    await makeKs(fw).disable();
    assert.ok(!fw.calls.some(c => c[1] === 'set'));
    assert.equal(fw.policy.domain, 'blockinbound,blockoutbound');
  });

  it('rolls back policy and rules when a rule cannot be added', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    fw.failOn = (args) => (args[2] === 'add' && args[4] === 'name=GateControl_Pro_KS_Allow_Loopback'
      ? Object.assign(new Error('boom'), { stdout: 'The requested operation requires elevation.' }) : null);
    const ks = makeKs(fw);
    await assert.rejects(ks.enable(configPath), /boom/);
    assert.equal(ks.enabled, false);
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fw.ksRules().length, 0);
    assert.equal(fs.existsSync(stateFile), false);
  });

  it('refuses to enable when the current policy cannot be read', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    fw.failOn = (args) => (args[1] === 'show' && args[2] === 'publicprofile' ? new Error('denied') : null);
    const ks = makeKs(fw);
    await assert.rejects(ks.enable(configPath), /denied/);
    assert.ok(!fw.calls.some(c => c[1] === 'set'));
    assert.equal(fw.ksRules().length, 0);
  });

  it('surfaces a failed policy restore and keeps the state for a retry', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw);
    await ks.enable(configPath);

    fw.failOn = (args) => (args[1] === 'set' && args[2] === 'privateprofile' ? new Error('set failed') : null);
    await assert.rejects(ks.disable(), /Kill-Switch konnte nicht vollständig deaktiviert werden.*set failed/);
    assert.equal(ks.enabled, true);
    assert.ok(fs.existsSync(stateFile));
    assert.equal(fw.policy.domain, USER_POLICY.domain); // other profiles restored anyway

    fw.failOn = null;
    await ks.disable();
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fs.existsSync(stateFile), false);
  });

  it('surfaces rules that could not be deleted', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw);
    await ks.enable(configPath);
    fw.failOn = (args) => (args[2] === 'delete' && args[4] === 'name=GateControl_Pro_KS_Allow_API' ? new Error('locked') : null);
    await assert.rejects(ks.disable(), /GateControl_Pro_KS_Allow_API/);
    assert.ok(fs.existsSync(stateFile));
  });

  it('serializes concurrent enable/disable calls', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw);
    await Promise.all([ks.enable(configPath), ks.enable(configPath), ks.disable()]);
    assert.equal(ks.enabled, false);
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fw.ksRules().length, 0);
  });
});

describe('KillSwitch crash recovery', () => {
  async function crashWhileEngaged(fw) {
    // Simulates a hard kill: state file + rules + block policy stay behind
    await makeKs(fw).enable(configPath);
  }

  it('cleans up rules and restores the saved policy after a crash', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    await crashWhileEngaged(fw);
    // Leftover from an older build, found only by prefix
    fw.rules.push({ name: 'GateControl_Pro_KS_Allow_PhysNet_198_51_100_0_24', dir: 'out', args: [] });

    const ks = makeKs(fw);
    assert.equal(await ks.isActive(), true);
    assert.equal(await ks.recoverStaleState({ keepActive: false }), 'cleaned');
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fw.ksRules().length, 0);
    assert.equal(fw.rules.length, 0);
    assert.equal(fs.existsSync(stateFile), false);
    assert.equal(ks.enabled, false);
  });

  it('keeps the kill-switch when the setting is on and the tunnel is up', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    await crashWhileEngaged(fw);
    const ks = makeKs(fw);
    assert.equal(await ks.recoverStaleState({ keepActive: true }), 'kept');
    assert.equal(ks.enabled, true);
    await ks.disable();
    assert.deepEqual(fw.policy, USER_POLICY);
  });

  it('returns none when nothing is left over', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    assert.equal(await makeKs(fw).recoverStaleState(), 'none');
    assert.ok(!fw.calls.some(c => c[1] === 'set'));
  });

  it('re-enabling after a crash keeps the originally saved policy', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    await crashWhileEngaged(fw);
    const ks = makeKs(fw);
    await ks.enable(configPath);
    await ks.disable();
    assert.deepEqual(fw.policy, USER_POLICY);
  });

  it('repairs blockoutbound left by an old version without state file', async () => {
    const fw = new FakeFirewall({
      domain: 'blockinbound,blockoutbound',
      private: 'allowinbound,blockoutbound',
      public: 'blockinbound,blockoutbound',
    });
    fw.rules.push({ name: 'GateControl_Pro_KS_Allow_WG_Endpoint', dir: 'out', args: [] });
    const ks = makeKs(fw);
    assert.equal(await ks.recoverStaleState(), 'cleaned');
    assert.deepEqual(fw.policy, {
      domain: 'blockinbound,allowoutbound',
      private: 'allowinbound,allowoutbound',
      public: 'blockinbound,allowoutbound',
    });
    assert.equal(fw.ksRules().length, 0);
  });

  it('treats a corrupt state file as stale and cleans up', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, '{not json');
    assert.equal(await makeKs(fw).recoverStaleState(), 'cleaned');
    assert.deepEqual(fw.policy, USER_POLICY);
    assert.equal(fs.existsSync(stateFile), false);
  });

  it('ignores invalid policy values from a tampered state file', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, JSON.stringify({
      savedPolicy: { domain: 'allowinbound,allowoutbound & calc.exe', private: 'x', public: 'y' },
      rules: ['GateControl_Pro_KS_Allow_API', 'evil rule'],
    }));
    await makeKs(fw).recoverStaleState();
    assert.ok(!fw.calls.some(c => c.join(' ').includes('calc.exe') || c.join(' ').includes('evil')));
    assert.deepEqual(fw.policy, USER_POLICY);
  });
});

describe('KillSwitch input validation', () => {
  it('rejects endpoint ports outside 1-65535', async () => {
    fs.writeFileSync(configPath, CONFIG.replace(':51820', ':99999'));
    const fw = new FakeFirewall(USER_POLICY);
    await assert.rejects(makeKs(fw).enable(configPath), /Port/);
    assert.equal(fw.calls.length, 0);
  });

  it('does not accept a hostname with netsh metacharacters', () => {
    const r = KillSwitch.prototype._parseConfig(CONFIG.replace('203.0.113.10:51820', 'evil.com remoteip=any:51820'));
    assert.equal(r.endpoint, null);
  });

  it('rejects a DNS answer that is not a valid IPv4 address', async () => {
    fs.writeFileSync(configPath, CONFIG.replace('203.0.113.10:51820', 'vpn.example.com:51820'));
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw, { dnsLookup: async () => [{ address: '1.2.3.4 remoteip=any', family: 4 }] });
    await assert.rejects(ks.enable(configPath), /Ungültige IP/);
    assert.ok(!fw.calls.some(c => c[2] === 'add'));
  });

  it('_addRule validates names, protocol and addresses', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const ks = makeKs(fw);
    await assert.rejects(ks._addRule({ name: 'Other_Rule', dir: 'out', action: 'allow' }), /Regelname/);
    await assert.rejects(ks._addRule({ name: 'GateControl_Pro_KS_X', dir: 'out', action: 'block' }), /Aktion/);
    await assert.rejects(ks._addRule({ name: 'GateControl_Pro_KS_X', dir: 'out', action: 'allow', protocol: 'icmp any' }), /Protokoll/);
    await assert.rejects(ks._addRule({ name: 'GateControl_Pro_KS_X', dir: 'out', action: 'allow', remoteip: 'any' }), /IP/);
    await assert.rejects(ks._addRule({ name: 'GateControl_Pro_KS_X', dir: 'out', action: 'allow', remoteip: '10.0.0.0/8,x' }), /IP/);
    assert.equal(fw.calls.length, 0);
  });

  it('skips APIPA and private interfaces when allowing the physical subnet', () => {
    const ks = makeKs(new FakeFirewall(USER_POLICY), {
      networkInterfaces: () => ({
        eth0: [{ family: 'IPv4', address: '198.51.100.23', netmask: '255.0.0.0', internal: false }],
        apipa: [{ family: 'IPv4', address: '169.254.3.4', netmask: '255.255.0.0', internal: false }],
        lan: [{ family: 'IPv4', address: '192.168.1.5', netmask: '255.255.255.0', internal: false }],
      }),
    });
    assert.deepEqual(ks._getLocalSubnets('10.8.0.5'), ['198.51.100.0/24']);
  });
});

describe('KillSwitch per-edition rule prefix', () => {
  const editions = require('../src/services/editions');

  function makeEditionKs(fw, edition, extra = {}) {
    return new KillSwitch(silentLog, {
      edition,
      otherEditionPresent: async () => true,
      netsh: fw.netsh,
      stateFile: path.join(tmp, edition, 'killswitch-state.json'),
      networkInterfaces: () => ({}),
      dnsLookup: async () => [{ address: '203.0.113.10', family: 4 }],
      ...extra,
    });
  }
  const deletes = (fw) => fw.calls.filter(c => c[2] === 'delete').map(c => c[4].slice(5));

  it('derives one prefix per edition from the edition option', () => {
    assert.equal(KillSwitch.rulePrefixFor('pro'), 'GateControl_Pro_KS');
    assert.equal(KillSwitch.rulePrefixFor('community'), 'GateControl_Community_KS');
    assert.equal(KillSwitch.LEGACY_RULE_PREFIX, 'GateControl_KS');
    assert.equal(makeEditionKs(new FakeFirewall(USER_POLICY), 'pro').rulePrefix, 'GateControl_Pro_KS');
    assert.equal(makeEditionKs(new FakeFirewall(USER_POLICY), 'community').rulePrefix, 'GateControl_Community_KS');
    assert.throws(() => new KillSwitch(silentLog, {}), /Edition/);
    assert.throws(() => new KillSwitch(silentLog, { edition: 'enterprise' }), /Edition/);
  });

  it('no edition prefix is a prefix of another one (no cross-matching)', () => {
    const prefixes = [...Object.keys(editions.EDITIONS).map(editions.killSwitchRulePrefix), editions.LEGACY_KILLSWITCH_RULE_PREFIX]
      .map(p => p + '_');
    for (const a of prefixes) {
      for (const b of prefixes) {
        if (a !== b) assert.ok(!b.startsWith(a) && !b.includes(a), `${a} matches ${b}`);
      }
    }
  });

  for (const [mine, other] of [['pro', 'community'], ['community', 'pro']]) {
    it(`${mine} enable/disable never touches ${other} rules`, async () => {
      const fw = new FakeFirewall(USER_POLICY);
      const otherKs = makeEditionKs(fw, other);
      const ks = makeEditionKs(fw, mine);
      await otherKs.enable(configPath);
      const otherRules = fw.rules.map(r => r.name);
      assert.ok(otherRules.length > 0 && otherRules.every(n => n.startsWith(KillSwitch.rulePrefixFor(other) + '_')));

      fw.calls = [];
      await ks.enable(configPath);
      assert.ok(fw.rules.some(r => r.name.startsWith(KillSwitch.rulePrefixFor(mine) + '_')));
      await ks.disable();
      assert.equal(await ks.recoverStaleState(), 'none');

      assert.deepEqual(fw.rules.map(r => r.name), otherRules);
      assert.ok(deletes(fw).length > 0);
      for (const n of deletes(fw)) assert.ok(n.startsWith(KillSwitch.rulePrefixFor(mine) + '_'), n);
    });
  }

  it('does not save the other edition\'s block policy as the user policy', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    const pro = makeEditionKs(fw, 'pro');
    const community = makeEditionKs(fw, 'community');
    await pro.enable(configPath);
    await community.enable(configPath);
    await pro.disable();
    await community.disable();
    for (const p of ['domain', 'private', 'public']) assert.ok(fw.policy[p].endsWith(',allowoutbound'), p);
    assert.equal(fw.rules.length, 0);
  });

  it('removes legacy GateControl_KS_ rules when no other edition is present', async () => {
    const fw = new FakeFirewall({ ...USER_POLICY, public: 'blockinbound,blockoutbound' });
    fw.rules.push({ name: 'GateControl_KS_Allow_API', dir: 'out', args: [] });
    fw.rules.push({ name: 'GateControl_KS_Allow_PhysNet_198_51_100_0_24', dir: 'out', args: [] });
    fw.rules.push({ name: 'MyGateControl_KS_Other', dir: 'out', args: [] });
    const ks = makeEditionKs(fw, 'pro', { otherEditionPresent: async () => false });
    assert.equal(await ks.recoverStaleState(), 'cleaned');
    assert.deepEqual(fw.rules.map(r => r.name), ['MyGateControl_KS_Other']);
    assert.equal(fw.policy.public, 'blockinbound,allowoutbound');
  });

  it('keeps legacy rules when another edition is present or detection fails', async () => {
    for (const otherEditionPresent of [async () => true, async () => { throw new Error('reg failed'); }]) {
      const fw = new FakeFirewall(USER_POLICY);
      fw.rules.push({ name: 'GateControl_KS_Allow_API', dir: 'out', args: [] });
      const ks = makeEditionKs(fw, 'community', { otherEditionPresent });
      assert.equal(await ks.recoverStaleState(), 'none');
      await ks.enable(configPath);
      await ks.disable();
      assert.deepEqual(fw.rules.map(r => r.name), ['GateControl_KS_Allow_API']);
      assert.ok(!deletes(fw).some(n => n.startsWith('GateControl_KS_')));
      assert.deepEqual(fw.policy, USER_POLICY);
    }
  });

  it('only asks for the other edition when legacy rules exist', async () => {
    const fw = new FakeFirewall(USER_POLICY);
    let asked = 0;
    const ks = makeEditionKs(fw, 'pro', { otherEditionPresent: async () => { asked++; return false; } });
    await ks.enable(configPath);
    await ks.disable();
    assert.equal(asked, 0);
  });
});

describe('editions.isEditionPresent', () => {
  const editions = require('../src/services/editions');
  const community = editions.EDITIONS.community;
  const notFound = () => Object.assign(new Error('not found'), { code: 1 });
  const env = { ProgramW6432: 'C:\\Program Files', ProgramFiles: 'C:\\Program Files', LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' };

  it('is false on non-Windows and when nothing is found', async () => {
    assert.equal(await editions.isEditionPresent(community, { platform: 'linux' }), false);
    assert.equal(await editions.isEditionPresent(community, {
      platform: 'win32', env, exists: () => false,
      execFile: async (cmd) => { if (cmd === 'reg') throw notFound(); return { stdout: 'INFO: No tasks are running which match the specified criteria.\r\n' }; },
    }), false);
  });

  it('detects the NSIS registry key of the other edition', async () => {
    const queried = [];
    assert.equal(await editions.isEditionPresent(community, {
      platform: 'win32', env, exists: () => false,
      execFile: async (cmd, args) => { queried.push(args[1]); if (args[1].startsWith('HKCU')) return { stdout: '' }; throw notFound(); },
    }), true);
    assert.deepEqual(queried, [`HKLM\\Software\\${community.guid}`, `HKCU\\Software\\${community.guid}`]);
  });

  it('detects the exe in Program Files and a running (portable) instance', async () => {
    assert.equal(await editions.isEditionPresent(community, {
      platform: 'win32', env,
      exists: (p) => p === 'C:\\Program Files\\GateControl Community Client\\GateControl Community Client.exe',
      execFile: async () => { throw notFound(); },
    }), true);
    assert.equal(await editions.isEditionPresent(community, {
      platform: 'win32', env, exists: () => false,
      execFile: async (cmd) => { if (cmd === 'reg') throw notFound(); return { stdout: '"GateControl Community Client.exe","1234","Console","1","90,000 K"\r\n' }; },
    }), true);
  });

  it('assumes present when detection itself fails', async () => {
    assert.equal(await editions.isEditionPresent(community, {
      platform: 'win32', env, exists: () => false,
      execFile: async () => { throw Object.assign(new Error('spawn reg ENOENT'), { code: 'ENOENT' }); },
    }), true);
  });

  it('isOtherEditionPresent checks only the other edition', async () => {
    const seen = [];
    await editions.isOtherEditionPresent('pro', {
      platform: 'win32', env, exists: (p) => { seen.push(p); return false; },
      execFile: async (cmd) => { if (cmd === 'reg') throw notFound(); return { stdout: '' }; },
    });
    assert.ok(seen.length > 0 && seen.every(p => p.includes('GateControl Community Client')));
  });
});
