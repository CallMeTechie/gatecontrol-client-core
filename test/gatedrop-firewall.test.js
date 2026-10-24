'use strict';

// GateDrop firewall check (services/gatedrop-firewall.js): which Windows
// Firewall state blocks the LAN listener, what gets repaired (block rules of
// the own exe from the "Windows-Sicherheitswarnung", the allow rule) and
// what only the user can change. PowerShell is replaced by a fake.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const GateDropFirewall = require('../src/services/gatedrop-firewall');
const editions = require('../src/services/editions');

const { planFirewall } = GateDropFirewall;
const EXE = 'C:\\Program Files\\GateControl Pro Client\\GateControl Pro Client.exe';
const RULE = 'GateControl Pro GateDrop';

const profiles = (over = {}) => ['Domain', 'Private', 'Public'].map((name) => ({
  name, enabled: 'True', allowInboundRules: 'True', defaultInbound: 'NotConfigured', ...(over[name] || {}),
}));
const allowRule = (over = {}) => ({
  id: '{a1}', name: RULE, enabled: 'True', action: 'Allow', direction: 'Inbound', profile: 'Any', store: 'Local', protocol: 'TCP', localPort: '47731', ...over,
});
// What the security prompt leaves behind after "Abbrechen" on a public network.
const promptBlocks = () => [
  { id: 'TCP Query User{1B2C}C:\\program files\\gatecontrol pro client\\gatecontrol pro client.exe', name: 'GateControl Pro Client', enabled: 'True', action: 'Block', direction: 'Inbound', profile: 'Public', store: 'Local', protocol: 'TCP', localPort: 'Any' },
  { id: 'UDP Query User{3D4E}C:\\program files\\gatecontrol pro client\\gatecontrol pro client.exe', name: 'GateControl Pro Client', enabled: 'True', action: 'Block', direction: 'Inbound', profile: 'Public', store: 'Local', protocol: 'UDP', localPort: 'Any' },
];
const inspect = (over = {}) => ({ ok: true, rules: [allowRule()], named: ['{a1}'], profiles: profiles(), nets: [{ alias: 'WLAN', category: 'Public' }], ...over });

describe('planFirewall', () => {
  it('installer rule present, nothing blocks: no issue', () => {
    assert.deepEqual(planFirewall(inspect(), { ruleName: RULE }), { issues: [], addRule: false, removeIds: [] });
  });

  it('block rules of the security prompt beat the allow rule: removed (TCP only)', () => {
    const p = planFirewall(inspect({ rules: [allowRule(), ...promptBlocks()] }), { ruleName: RULE });
    assert.deepEqual(p.removeIds, [promptBlocks()[0].id]);
    assert.equal(p.addRule, false);
    assert.deepEqual(p.issues, [{ code: 'firewall_blocked', detail: 'GateControl Pro Client' }]);
  });

  it('block rules of a group policy stay and are reported', () => {
    const gpo = { ...promptBlocks()[0], id: 'gpo1', name: 'Firma: GateControl sperren', store: 'GroupPolicy' };
    const p = planFirewall(inspect({ rules: [allowRule(), gpo] }), { ruleName: RULE });
    assert.deepEqual(p.removeIds, []);
    assert.deepEqual(p.issues, [{ code: 'firewall_blocked', detail: 'Firma: GateControl sperren' }]);
  });

  it('a block rule for another profile or port does not count', () => {
    const p = planFirewall(inspect({ rules: [allowRule(), { ...promptBlocks()[0], profile: 'Domain' }, { ...promptBlocks()[0], id: 'x2', profile: 'Public', localPort: '3389' }] }), { ruleName: RULE });
    assert.deepEqual(p, { issues: [], addRule: false, removeIds: [] });
  });

  it('allow rule missing (portable), only private (old installer) or for another exe: created', () => {
    for (const rules of [[], [allowRule({ profile: 'Private' })], [allowRule({ enabled: 'False' })], [allowRule({ localPort: '8080' })]]) {
      const p = planFirewall(inspect({ rules }), { ruleName: RULE });
      assert.equal(p.addRule, true, JSON.stringify(rules));
      assert.deepEqual(p.issues, [{ code: 'firewall_rule', detail: RULE }]);
    }
    // an allow rule of the prompt (any port, all needed profiles) is enough
    assert.equal(planFirewall(inspect({ rules: [allowRule({ name: 'GateControl Pro Client', localPort: 'Any', profile: 'Private, Public' })] }), { ruleName: RULE }).addRule, false);
    // profile with "allow inbound by default": no rule needed
    assert.equal(planFirewall(inspect({ rules: [], profiles: profiles({ Public: { defaultInbound: 'Allow' } }) }), { ruleName: RULE }).addRule, false);
  });

  it('"block all incoming connections" on the WLAN profile: only the user can change it', () => {
    const p = planFirewall(inspect({ profiles: profiles({ Public: { allowInboundRules: 'False' } }) }), { ruleName: RULE });
    assert.deepEqual(p.issues, [{ code: 'firewall_shields_up', detail: 'Public' }]);
    // on another profile than the one of the WLAN it does not matter
    assert.deepEqual(planFirewall(inspect({ profiles: profiles({ Domain: { allowInboundRules: 'False' } }) }), { ruleName: RULE }).issues, []);
  });

  it('firewall off: nothing to do; unreadable: unknown', () => {
    assert.deepEqual(planFirewall(inspect({ rules: [], profiles: profiles({ Domain: { enabled: 'False' }, Private: { enabled: 'False' }, Public: { enabled: 'False' } }) }), { ruleName: RULE }).issues, []);
    assert.deepEqual(planFirewall({ ok: false, error: 'timeout' }, { ruleName: RULE }).issues, [{ code: 'firewall_unknown', detail: 'timeout' }]);
    assert.deepEqual(planFirewall(null, { ruleName: RULE }).issues, [{ code: 'firewall_unknown', detail: null }]);
  });

  it('accepts the array shapes of Windows PowerShell 5.1', () => {
    const p = planFirewall(inspect({ rules: { value: [allowRule(), promptBlocks()[0]], Count: 2 }, nets: { alias: 'WLAN', category: 'Public' } }), { ruleName: RULE });
    assert.deepEqual(p.removeIds, [promptBlocks()[0].id]);
    assert.equal(planFirewall(inspect({ rules: allowRule() }), { ruleName: RULE }).addRule, false);
  });

  it('port ranges and lists', () => {
    assert.equal(planFirewall(inspect({ rules: [allowRule({ localPort: '47000-48000' })] }), { ruleName: RULE }).addRule, false);
    assert.equal(planFirewall(inspect({ rules: [allowRule({ localPort: '80,47731' })] }), { ruleName: RULE }).addRule, false);
    assert.equal(planFirewall(inspect({ rules: [allowRule({ protocol: 'UDP' })] }), { ruleName: RULE }).addRule, true);
  });
});

describe('GateDropFirewall.ensure', () => {
  function fake(sequence) {
    const runs = [];
    const run = async (script, env) => {
      runs.push({ repair: script === GateDropFirewall.REPAIR_PS, env });
      const next = sequence.shift();
      return { err: null, stdout: JSON.stringify(next), stderr: '' };
    };
    return { run, runs };
  }

  it('removes the prompt block rules, recreates the rule and checks again', async () => {
    const f = fake([
      inspect({ rules: [allowRule({ profile: 'Private' }), ...promptBlocks()] }),
      ['removed', 'added'],
      inspect(),
    ]);
    const fw = new GateDropFirewall({ edition: 'pro', exePath: EXE, platform: 'win32', run: f.run });
    const r = await fw.ensure();
    assert.deepEqual(r, { checked: true, issues: [], repaired: ['removed', 'added'] });
    assert.equal(f.runs.length, 3);
    assert.equal(f.runs[1].repair, true);
    assert.equal(f.runs[1].env.GC_GD_ADD, '1');
    assert.equal(f.runs[1].env.GC_GD_REMOVE, promptBlocks()[0].id);
    assert.equal(f.runs[1].env.GC_GD_EXE, EXE);
    assert.equal(f.runs[1].env.GC_GD_RULE, 'GateControl Pro GateDrop');
    assert.equal(f.runs[1].env.GC_GD_PORT, '47731');
  });

  it('without admin rights the issue stays (and is logged)', async () => {
    const warns = [];
    const f = fake([inspect({ rules: [] }), ['add_failed: Zugriff verweigert'], inspect({ rules: [] })]);
    const fw = new GateDropFirewall({ ruleName: RULE, exePath: EXE, platform: 'win32', run: f.run, log: { info() {}, warn: (m) => warns.push(m), debug() {} } });
    const r = await fw.ensure();
    assert.deepEqual(r.issues, [{ code: 'firewall_rule', detail: RULE }]);
    assert.ok(warns.some((w) => w.includes('Zugriff verweigert')));
  });

  it('healthy: one read, no repair; other platforms: not checked', async () => {
    const f = fake([inspect()]);
    const fw = new GateDropFirewall({ ruleName: RULE, exePath: EXE, platform: 'win32', run: f.run });
    assert.deepEqual(await fw.ensure(), { checked: true, issues: [], repaired: [] });
    assert.equal(f.runs.length, 1);
    const linux = new GateDropFirewall({ ruleName: RULE, platform: 'linux', run: () => { throw new Error('no'); } });
    assert.deepEqual(await linux.ensure(), { checked: false, issues: [], repaired: [] });
  });

  it('no answer from PowerShell: unknown', async () => {
    const fw = new GateDropFirewall({ ruleName: RULE, platform: 'win32', run: async () => ({ err: Object.assign(new Error('x'), { killed: true }), stdout: '', stderr: '' }) });
    assert.deepEqual((await fw.ensure()).issues, [{ code: 'firewall_unknown', detail: 'timeout' }]);
  });

  it('rule names per edition match the installers', () => {
    assert.equal(editions.gatedropRuleName('pro'), 'GateControl Pro GateDrop');
    assert.equal(editions.gatedropRuleName('community'), 'GateControl Community GateDrop');
  });

  it('the scripts get their values only through the environment (no quoting of paths)', () => {
    for (const script of [GateDropFirewall.INSPECT_PS, GateDropFirewall.REPAIR_PS]) {
      assert.match(script, /\$env:GC_GD_EXE/);
      assert.doesNotMatch(script, /Program Files/);
    }
    assert.match(GateDropFirewall.REPAIR_PS, /-RemoteAddress LocalSubnet -Profile Any -Program \$exe/);
    assert.match(GateDropFirewall.REPAIR_PS, /Remove-NetFirewallRule -Name \$id -PolicyStore PersistentStore/);
  });
});
