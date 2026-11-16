'use strict';

// Fernzugriff stage 2 (the Windows switch): RemoteHost registers the PC with the plugin, shows codes,
// asks the person here, opens 3389 per session for exactly one address and reports it.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const RemoteHost = require('../src/services/remote-host');
const RemoteHostApi = require('../src/services/remote-host-api');
const RdpSessionFirewall = require('../src/services/rdp-session-firewall');
const WindowsRdpInfo = require('../src/services/windows-rdp-info');

const KEY = 'fw_abcdefghijklmnop';
const RQ = 'rq_abcdefghijklmnop';

function fakeApi(over = {}) {
  const calls = [];
  let n = 0;
  const api = {
    calls,
    register: async (b) => { calls.push(['register', b]); return { host: { deviceId: 100001, shareMode: 'code', allowOpen: true, state: 'ready' }, codeRequired: true }; },
    state: async (b) => { calls.push(['state', b]); return { shareMode: 'code', allowOpen: true, pending: [] }; },
    share: async (m) => { calls.push(['share', m]); return { shareMode: m }; },
    unregister: async () => { calls.push(['unregister']); return { removed: true }; },
    code: async () => { n++; calls.push(['code']); return { code: `482-913-07${n}`, expiresAt: new Date(Date.now() + 600000).toISOString() }; },
    decide: async (id, d, m) => { calls.push(['decide', id, d, m]); return { request: { id, state: d === 'allow' ? 'allowed' : 'denied' } }; },
    firewallList: async () => { calls.push(['firewallList']); return { open: [] }; },
    firewallReport: async (k, s, r) => { calls.push(['report', k, s, r]); return { ok: true }; },
    ...over,
  };
  return api;
}

function fakeFirewall() {
  const fw = { rules: new Map(), cleaned: 0 };
  fw.open = async (k, ip) => { fw.rules.set(k, ip); };
  fw.close = async (k) => { fw.rules.delete(k); };
  fw.closeAll = async () => { fw.cleaned++; const n = fw.rules.size; fw.rules.clear(); return n; };
  fw.builtInOpen = async () => false;
  return fw;
}

const info = (x = {}) => ({ detect: async () => ({ edition: 'pro', editionId: 'Professional', rdpAvailable: true, rdpEnabled: true, osUser: 'marc', ...x }), enable: async () => {} });

function make(o = {}) {
  let handler = null;
  const timers = [];
  const host = new RemoteHost({
    api: o.api || fakeApi(), firewall: o.firewall || fakeFirewall(), info: o.info || info(), name: 'PC-MARC', appVersion: '1.95.0',
    notificationCenter: { addPushHandler: (h) => { handler = h; return () => {}; } },
    setTimer: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; }, clearTimer: (t) => { t.cleared = true; },
  });
  const push = (data) => handler.notification({ kind: 'data', topic: RemoteHost.SIGNAL_TOPIC, data });
  const tick = () => new Promise((r) => setImmediate(r));
  return { host, push, tick, timers };
}

test('enable: register, clean rules, code; disable signs off and removes every rule', async () => {
  const api = fakeApi();
  const fw = fakeFirewall();
  const { host } = make({ api, firewall: fw });
  await host.start(false);
  assert.equal(fw.cleaned, 1);
  const s = await host.enable();
  assert.equal(s.status, 'ready');
  assert.equal(s.deviceId, 100001);
  assert.match(s.code, /^\d{3}-\d{3}-\d{3}$/);
  assert.deepEqual(api.calls[0], ['register', { name: 'PC-MARC', edition: 'pro', rdp: { available: true, enabled: true, port: 3389, offered: true }, osUser: 'marc', appVersion: '1.95.0' }]);
  const off = await host.disable();
  assert.equal(off.status, 'off');
  assert.equal(off.code, null);
  assert.ok(api.calls.some((c) => c[0] === 'unregister'));
});

test('Home, no right, a server without the plugin, offline', async () => {
  assert.equal((await make({ info: info({ edition: 'home', rdpAvailable: false }) }).host.enable()).status, 'home');
  const err = (code, status) => async () => { throw new RemoteHostApi.RemoteHostError(code, { code, status }); };
  assert.equal((await make({ api: fakeApi({ register: err('no_share_right', 403) }) }).host.enable()).status, 'no_right');
  assert.equal((await make({ api: fakeApi({ register: err('not_found', 404) }) }).host.enable()).status, 'unavailable');
  const m = make({ api: fakeApi({ register: err('network', null) }) });
  assert.equal((await m.host.enable()).status, 'offline');
  assert.ok(m.timers.some((t) => t.ms === RemoteHost.HEARTBEAT_MS && !t.cleared), 'tries again');
});

test('a request: the dialog, allow with "nur ansehen"; deny gives a new code', async () => {
  const api = fakeApi();
  const { host, push, tick } = make({ api });
  await host.enable();
  const seen = [];
  host.on('request', (r) => seen.push(r));
  assert.equal(push({ type: 'remote.request', requestId: RQ, from: { userId: 3, name: 'Sabine' }, mode: 'control', via: 'browser', expiresAt: new Date(Date.now() + 30000).toISOString() }), 'consumed');
  await tick();
  assert.equal(seen[0].from.name, 'Sabine');
  await host.decide(RQ, 'allow', 'view');
  assert.deepEqual(api.calls.find((c) => c[0] === 'decide'), ['decide', RQ, 'allow', 'view']);
  assert.equal(host.status().request, null);
  const codesBefore = api.calls.filter((c) => c[0] === 'code').length;
  push({ type: 'remote.request', requestId: 'rq_zyxwvutsrqponm', from: { name: 'Tom' }, mode: 'control', via: 'app' });
  await tick();
  await host.decide('rq_zyxwvutsrqponm', 'deny');
  await tick();
  assert.equal(api.calls.filter((c) => c[0] === 'code').length, codesBefore + 1, 'a new code after deny');
  await assert.rejects(host.decide(RQ, 'allow'), (e) => e.code === 'request_expired');
});

test('firewall per session: open for exactly one address, report, close with a new code', async () => {
  const api = fakeApi();
  const fw = fakeFirewall();
  const { host, push, tick } = make({ api, firewall: fw });
  await host.enable();
  push({ type: 'remote.firewall.open', sessionKey: KEY, allow: '10.8.0.1', port: 3389, until: new Date(Date.now() + 3600000).toISOString() });
  await tick(); await tick();
  assert.equal(fw.rules.get(KEY), '10.8.0.1');
  assert.deepEqual(api.calls.find((c) => c[0] === 'report'), ['report', KEY, 'open', undefined]);
  assert.equal(host.status().sessions, 1);
  push({ type: 'remote.firewall.close', sessionKey: KEY });
  await tick(); await tick(); await tick();
  assert.equal(fw.rules.size, 0);
  assert.ok(api.calls.some((c) => c[0] === 'report' && c[2] === 'closed'));
  // anything else than an IPv4 address, another port: refused
  push({ type: 'remote.firewall.open', sessionKey: KEY, allow: '10.8.0.0/24', port: 3389 });
  await tick(); await tick();
  assert.equal(fw.rules.size, 0);
  assert.ok(api.calls.some((c) => c[0] === 'report' && c[2] === 'failed'));
  // other pushes are not ours
  const other = make();
  assert.equal(other.host._push({ kind: 'data', topic: 'plugin:gatecontrol-gatedrop:received', data: {} }), false);
});

test('the rules still open after a restart of the app come back', async () => {
  const api = fakeApi({ firewallList: async () => ({ open: [{ sessionKey: KEY, allow: '10.8.0.62', port: 3389, until: new Date(Date.now() + 60000).toISOString() }] }) });
  const fw = fakeFirewall();
  const { host } = make({ api, firewall: fw });
  await host.start(true);
  assert.equal(fw.rules.get(KEY), '10.8.0.62');
});

test('session firewall: rule names and arguments, never anything else than an IPv4 address', async () => {
  const runs = [];
  const fw = new RdpSessionFirewall({ netsh: async (a) => { runs.push(a); return { stdout: '' }; }, powershell: async () => ({ stdout: '2\n' }) });
  await fw.open(KEY, '10.8.0.1');
  assert.deepEqual(runs[1], ['advfirewall', 'firewall', 'add', 'rule', `name=GateControl RDP ${KEY}`, 'dir=in', 'action=allow', 'protocol=tcp', 'localport=3389', 'remoteip=10.8.0.1', 'profile=any', 'enable=yes']);
  await assert.rejects(fw.open(KEY, '10.8.0.1 any'));
  await assert.rejects(fw.open('fw_x" & calc', '10.8.0.1'));
  assert.equal(await fw.closeAll(), 2);
  assert.equal(await fw.builtInOpen(), true);
});

test('Windows: edition and Remote Desktop from the registry', async () => {
  assert.equal(WindowsRdpInfo.editionOf('Core'), 'home');
  assert.equal(WindowsRdpInfo.editionOf('CoreSingleLanguage'), 'home');
  assert.equal(WindowsRdpInfo.editionOf('Professional'), 'pro');
  assert.equal(WindowsRdpInfo.editionOf('Enterprise'), 'enterprise');
  assert.equal(WindowsRdpInfo.editionOf('Education'), 'education');
  const reg = async (a) => ({ stdout: a.includes('EditionID') ? '\r\nHKEY…\r\n    EditionID    REG_SZ    Professional\r\n' : '\r\n    fDenyTSConnections    REG_DWORD    0x1\r\n' });
  const d = await new WindowsRdpInfo({ reg, platform: 'win32' }).detect();
  assert.deepEqual([d.edition, d.rdpAvailable, d.rdpEnabled], ['pro', true, false]);
  const added = [];
  await new WindowsRdpInfo({ reg: async (a) => { added.push(a); return { stdout: '' }; }, platform: 'win32' }).enable();
  assert.deepEqual(added[0].slice(-6), ['fDenyTSConnections', '/t', 'REG_DWORD', '/d', '0', '/f']);
});
