'use strict';

// RdpAllow: per-edition rule name, legacy rule handling, startup reconcile.
// netsh is replaced by an in-memory fake (runs on Linux CI).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RdpAllow = require('../src/services/rdp-allow');
const editions = require('../src/services/editions');

const PRO_RULE = 'GateControl_Pro_RDP_Allow_In_3389';
const COMMUNITY_RULE = 'GateControl_Community_RDP_Allow_In_3389';
const LEGACY_RULE = 'GateControl_RDP_Allow_In_3389';

const log = { info() {}, warn() {}, error() {}, debug() {} };

// Minimal netsh advfirewall simulator (rules keyed by display name)
function fakeFirewall(initial = []) {
  const rules = new Map(initial.map(n => [n, { name: n }]));
  const calls = [];
  const netsh = async (args) => {
    calls.push(args.join(' '));
    const [, , verb, , nameArg, ...rest] = args;
    assert.equal(args[0], 'advfirewall');
    assert.equal(args[1], 'firewall');
    assert.match(nameArg, /^name=/);
    const name = nameArg.slice(5);
    if (verb === 'show') {
      if (!rules.has(name)) {
        const err = new Error('No rules match the specified criteria.');
        err.code = 1;
        throw err;
      }
      return { stdout: `\nRule Name:                            ${name}\n` };
    }
    if (verb === 'delete') {
      if (!rules.has(name)) {
        const err = new Error('No rules match the specified criteria.');
        err.code = 1;
        throw err;
      }
      rules.delete(name);
      return { stdout: 'Deleted 1 rule(s).\nOk.\n' };
    }
    if (verb === 'add') {
      const opts = Object.fromEntries(rest.map(a => a.split('=')));
      rules.set(name, { name, ...opts });
      return { stdout: 'Ok.\n' };
    }
    throw new Error(`unexpected netsh call: ${args.join(' ')}`);
  };
  return { rules, calls, netsh };
}

function make(fw, edition, otherEditionPresent = async () => false) {
  return new RdpAllow(log, { edition, netsh: fw.netsh, otherEditionPresent });
}

let tmp;
let configPath;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-rdp-'));
  configPath = path.join(tmp, 'wg.conf');
  fs.writeFileSync(configPath, '[Interface]\nPrivateKey = x\nAddress = 10.8.0.5/32\n');
});
afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe('editions: RDP allow rule names', () => {
  it('derives a distinct rule name per edition', () => {
    assert.equal(editions.rdpAllowRuleName('pro'), PRO_RULE);
    assert.equal(editions.rdpAllowRuleName('community'), COMMUNITY_RULE);
    assert.equal(editions.LEGACY_RDP_ALLOW_RULE_NAME, LEGACY_RULE);
    assert.throws(() => editions.rdpAllowRuleName('enterprise'), /Unbekannte GateControl-Edition/);
  });
});

describe('RdpAllow per edition', () => {
  it('requires an edition', () => {
    assert.throws(() => new RdpAllow(log), /Unbekannte GateControl-Edition/);
    assert.throws(() => new RdpAllow(log, { edition: 'x' }), /Unbekannte GateControl-Edition/);
  });

  it('creates only its own rule with the VPN subnet', async () => {
    for (const [edition, own] of [['pro', PRO_RULE], ['community', COMMUNITY_RULE]]) {
      const fw = fakeFirewall();
      const rdp = make(fw, edition);
      await rdp.enable(configPath);
      assert.deepEqual([...fw.rules.keys()], [own]);
      assert.deepEqual(fw.rules.get(own), {
        name: own, dir: 'in', action: 'allow', protocol: 'tcp',
        localport: '3389', remoteip: '10.8.0.0/24', enable: 'yes',
      });
      assert.equal(rdp.enabled, true);
      assert.equal(await rdp.isActive(), true);
    }
  });

  it('enable/disable never touch the other edition\'s rule', async () => {
    const fw = fakeFirewall([COMMUNITY_RULE]);
    const pro = make(fw, 'pro', async () => true);
    await pro.enable(configPath);
    assert.ok(fw.rules.has(COMMUNITY_RULE));
    await pro.disable();
    assert.deepEqual([...fw.rules.keys()], [COMMUNITY_RULE]);
    assert.ok(!fw.calls.some(c => c.includes(COMMUNITY_RULE)), 'Pro called netsh for the Community rule');

    const fw2 = fakeFirewall([PRO_RULE]);
    const community = make(fw2, 'community', async () => true);
    await community.enable(configPath);
    await community.disable();
    assert.deepEqual([...fw2.rules.keys()], [PRO_RULE]);
    assert.ok(!fw2.calls.some(c => c.includes(PRO_RULE)));
  });

  it('isActive ignores the other edition\'s and the legacy rule', async () => {
    const fw = fakeFirewall([COMMUNITY_RULE, LEGACY_RULE]);
    assert.equal(await make(fw, 'pro').isActive(), false);
  });

  it('refuses to add a rule under a foreign name', async () => {
    const fw = fakeFirewall();
    const rdp = make(fw, 'pro');
    await assert.rejects(rdp._addRule({ name: COMMUNITY_RULE, dir: 'in', action: 'allow', protocol: 'tcp' }), /Ungültiger Regelname/);
    await assert.rejects(rdp._addRule({ name: LEGACY_RULE, dir: 'in', action: 'allow', protocol: 'tcp' }), /Ungültiger Regelname/);
    assert.equal(fw.rules.size, 0);
  });
});

describe('RdpAllow legacy rule GateControl_RDP_Allow_In_3389', () => {
  it('is removed when no other edition is present', async () => {
    for (const edition of ['pro', 'community']) {
      const fw = fakeFirewall([LEGACY_RULE]);
      const rdp = make(fw, edition, async () => false);
      assert.equal(await rdp.removeLegacyRule(), true);
      assert.equal(fw.rules.size, 0);
    }
  });

  it('is kept when the other edition is present or detection fails', async () => {
    const detections = [
      async () => true,
      async () => { throw new Error('reg failed'); },
      async () => undefined,
    ];
    for (const otherEditionPresent of detections) {
      const fw = fakeFirewall([LEGACY_RULE]);
      const rdp = make(fw, 'pro', otherEditionPresent);
      assert.equal(await rdp.removeLegacyRule(), false);
      await rdp.enable(configPath);
      await rdp.disable();
      assert.deepEqual([...fw.rules.keys()], [LEGACY_RULE]);
      assert.ok(!fw.calls.some(c => c.startsWith('advfirewall firewall delete rule name=' + LEGACY_RULE)));
    }
  });

  it('does not run edition detection when there is no legacy rule', async () => {
    let asked = 0;
    const fw = fakeFirewall();
    const rdp = make(fw, 'community', async () => { asked++; return false; });
    await rdp.enable(configPath);
    await rdp.disable();
    assert.equal(await rdp.removeLegacyRule(), false);
    assert.equal(asked, 0);
  });

  it('is migrated by enable() when no other edition is present', async () => {
    const fw = fakeFirewall([LEGACY_RULE]);
    const rdp = make(fw, 'pro', async () => false);
    await rdp.enable(configPath);
    assert.deepEqual([...fw.rules.keys()], [PRO_RULE]);
  });
});

describe('RdpAllow.reconcile (app start)', () => {
  it('removes an orphaned own rule when the setting is off', async () => {
    const fw = fakeFirewall([PRO_RULE, COMMUNITY_RULE]);
    const rdp = make(fw, 'pro', async () => true);
    assert.equal(await rdp.reconcile({ wanted: false, configPath }), false);
    assert.deepEqual([...fw.rules.keys()], [COMMUNITY_RULE]);
  });

  it('adopts an existing own rule when the setting is on', async () => {
    const fw = fakeFirewall([COMMUNITY_RULE]);
    const rdp = make(fw, 'community');
    assert.equal(await rdp.reconcile({ wanted: true, configPath }), true);
    assert.equal(rdp.enabled, true);
    assert.deepEqual([...fw.rules.keys()], [COMMUNITY_RULE]);
    assert.ok(!fw.calls.some(c => c.startsWith('advfirewall firewall delete')));
  });

  it('migrates the legacy rule to the own rule when the setting is on', async () => {
    const fw = fakeFirewall([LEGACY_RULE]);
    const rdp = make(fw, 'community', async () => false);
    assert.equal(await rdp.reconcile({ wanted: true, configPath }), true);
    assert.deepEqual([...fw.rules.keys()], [COMMUNITY_RULE]);
  });

  it('keeps the legacy rule next to the new one if the other edition is present', async () => {
    const fw = fakeFirewall([LEGACY_RULE]);
    const rdp = make(fw, 'community', async () => true);
    assert.equal(await rdp.reconcile({ wanted: true, configPath }), true);
    assert.deepEqual([...fw.rules.keys()].sort(), [COMMUNITY_RULE, LEGACY_RULE].sort());
  });

  it('removes a stale legacy rule when the setting is off and it is safe', async () => {
    const fw = fakeFirewall([LEGACY_RULE]);
    assert.equal(await make(fw, 'pro', async () => false).reconcile({ wanted: false, configPath }), false);
    assert.equal(fw.rules.size, 0);

    const fw2 = fakeFirewall([LEGACY_RULE]);
    await make(fw2, 'pro', async () => true).reconcile({ wanted: false, configPath });
    assert.deepEqual([...fw2.rules.keys()], [LEGACY_RULE]);
  });

  it('does not throw when the rule cannot be restored', async () => {
    const fw = fakeFirewall();
    const rdp = make(fw, 'pro');
    assert.equal(await rdp.reconcile({ wanted: true, configPath: path.join(tmp, 'missing.conf') }), false);
    assert.equal(fw.rules.size, 0);
  });
});
