'use strict';

// Fernzugriff stage 3 (SSH terminal of the apps): RemoteTerm with the real ApiClient and Node's WebSocket against
// the test server of test/fixtures/term-server.js — devices, tmux, the ticket's body, the token in the subprotocol
// (never in the URL), hello, bytes both ways, resize, the host key, a lost socket coming back with a new token,
// shell_refused for good, an expired ticket, bye.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const RemoteTerm = require('../src/services/remote-term');
const { termServer } = require('./fixtures/term-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function setup() {
  const srv = await termServer();
  const apiClient = new ApiClient(srv.url, 'gc_token', log, null, { clientType: 'pro' });
  // the backoff runs 50× faster here
  const term = new RemoteTerm({ apiClient, serverUrl: () => srv.url, log, setTimer: (fn, ms) => setTimeout(fn, ms / 50) });
  const statuses = [];
  const data = [];
  term.on('status', (s) => statuses.push(s));
  term.on('data', (d) => data.push(d));
  cleanups.push(async () => { term.closeAll(); await srv.close(); });
  return { srv, term, statuses, data };
}

async function until(what, cond, ms = 4000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('timed out: ' + what);
}

describe('RemoteTerm: pure parts', () => {
  it('error verdicts, names, frames, bodies', () => {
    for (const c of ['host_key_rejected', 'auth_failed', 'credential_unreadable', 'recording_unavailable', 'plugin_unavailable', 'shell_refused']) assert.equal(RemoteTerm.verdict(c), 'final', c);
    assert.equal(RemoteTerm.verdict('host_key_mismatch'), 'locked');
    for (const c of ['unreachable', 'timeout', 'listener_required', 'hello_timeout', 'network']) assert.equal(RemoteTerm.verdict(c), 'retry', c);
    assert.equal(RemoteTerm.verdict('limit_reached'), 'limit');
    assert.equal(RemoteTerm.verdict('not_found'), 'expired');
    assert.deepEqual(RemoteTerm.BACKOFF, [1000, 2000, 4000, 8000, 15000]);
    assert.equal(RemoteTerm.suggestName([]), 'tmux');
    assert.equal(RemoteTerm.suggestName(['tmux', 'tmux-2']), 'tmux-3');
    assert.equal(RemoteTerm.groups('q7Xv2mL0cR9s='), 'q7Xv 2mL0 cR9s');
    assert.deepEqual(RemoteTerm.connectBody({ tmux: { attach: 'build' }, recording: 'off', record: true }), { via: 'app', protocol: 'ssh', tmux: { attach: 'build' } });
    assert.deepEqual(RemoteTerm.connectBody({ recording: 'always' }), { via: 'app', protocol: 'ssh', record: true });
    assert.deepEqual(RemoteTerm.connectBody({ tmux: { create: 'tmux-2' }, recording: 'optional' }), { via: 'app', protocol: 'ssh', tmux: { create: 'tmux-2' }, record: false });
    assert.throws(() => RemoteTerm.connectBody({ tmux: { attach: 'a.b' } }), (e) => e.code === 'invalid');
    assert.deepEqual(RemoteTerm.parseFrame('{"t":"exit","code":null,"reason":"<x>"}'), { t: 'exit', code: null, reason: 'closed' });
    assert.equal(RemoteTerm.parseFrame('{"t":"hostkey","hostKey":{"alg":"a b","sha256":"x"}}'), null);
    assert.equal(RemoteTerm.parseFrame('nope'), null);
    assert.equal(RemoteTerm.deviceOf({ id: 4, name: 'x', protocol: 'ssh', engine: 'term', tmux: 'a:b' }).tmux, null);
  });

  it('tmux lists: windows and ids only with kill, the others to end, tmux seconds as times', () => {
    const { tmuxSessions } = require('./fixtures/term-server');
    const old = RemoteTerm.tmuxOf({ sessions: tmuxSessions(), tmux: 'tmux', hostKey: 'pinned' });
    assert.equal(old.kill, false);
    assert.equal(old.others, undefined);
    assert.equal(old.sessions[0].windowList, undefined, 'an older GateControl: no windows, nothing to end');
    assert.equal(old.hidden, 1);
    const l = RemoteTerm.tmuxOf({ sessions: [...tmuxSessions(), { id: '$3', name: 'dup', windows: 1, attachable: true }, { id: 'x', name: 'bad id', attachable: false }],
      tmux: 'tmux', hostKey: 'pinned', kill: true });
    assert.equal(l.kill, true);
    assert.deepEqual(l.sessions.map((s) => [s.id, s.name]), [['$2', 'tmux'], ['$1', 'build'], [undefined, 'dup']]);
    assert.deepEqual(l.sessions[0].windowList.map((w) => [w.id, w.index, w.name, w.active, w.command]),
      [['@2', 0, 'bash', false, 'bash'], ['@3', 1, 'logs', true, 'journalctl'], ['@4', 2, 'htop', false, 'htop']]);
    assert.equal(l.sessions[0].created, 1763380000000);
    assert.deepEqual(l.others.map((s) => [s.id, s.name, s.created]), [['$3', 'backup.alt', 1763200000000]], 'without an id it cannot be ended');
    assert.equal(RemoteTerm.tmuxOf({ sessions: [{ name: 'a', attachable: true, activity: 1763384000 }] }).sessions[0].activity, 1763384000000);
    const ids = RemoteTerm.identitiesOf({ kill: true, sessions: tmuxSessions() });
    assert.deepEqual(ids.get('$3'), { id: '$3', name: 'backup.alt', created: '1763200000', attached: 0, windows: new Map([['@5', 0]]) });
    assert.equal(RemoteTerm.identitiesOf({ sessions: tmuxSessions() }).size, 0);
  });
});

describe('RemoteTerm against the test server', () => {
  it('devices and tmux sessions', async () => {
    const { term } = await setup();
    const d = await term.devices();
    assert.deepEqual(d.devices.map((x) => [x.id, x.native]), [[2, true], [3, false]]);
    assert.equal(d.devices[0].recording, 'optional');
    assert.equal(d.sshRight, true);
    const t = await term.tmux(2);
    assert.deepEqual(t.sessions.map((s) => s.name), ['tmux', 'build'], 'the most recently active first');
    assert.equal(t.hidden, 1);
    assert.equal(t.hostKey, 'pinned');
  });

  it('tmux with windows: end a window, the last window, a session, all detached ones; quiet reload codes', async () => {
    const { srv, term } = await setup();
    srv.tmuxKill = true;
    const t = await term.tmux(2);
    assert.equal(t.kill, true);
    assert.deepEqual(t.others.map((s) => s.id), ['$3']);

    // one window: the body carries the session exactly as listed and the window's index
    const w = await term.tmuxKill(2, { session: '$2', window: '@4' });
    assert.deepEqual(srv.kills[0], { path: 'kill', body: { session: { id: '$2', name: 'tmux', created: 1763380000 }, window: { id: '@4', index: 2 } } });
    assert.equal(w.killed, 'window');
    assert.equal(w.sessions.find((s) => s.id === '$2').windowList.length, 2, 'the answer is the new list');

    // the session's created comes back as text when tmux sent text
    const s3 = await term.tmuxKill(2, { session: '$3' });
    assert.deepEqual(srv.kills[1].body, { session: { id: '$3', name: 'backup.alt', created: '1763200000' } });
    assert.equal(s3.killed, 'session');
    assert.deepEqual(s3.others, []);

    // gone since the last list: tmux_gone without asking GateControl; changed on the device: tmux_changed
    await assert.rejects(term.tmuxKill(2, { session: '$3' }), (e) => e.code === 'tmux_gone');
    assert.equal(srv.kills.length, 2);
    srv.tmuxSessions.find((s) => s.id === '$2').created = 1;
    await assert.rejects(term.tmuxKill(2, { session: '$2' }), (e) => e.code === 'tmux_changed');
    await assert.rejects(term.tmuxKill(2, { session: 'tmux' }), (e) => e.code === 'invalid');
    await assert.rejects(term.tmuxKill(2, { session: '$2', window: '2' }), (e) => e.code === 'invalid');

    // all detached ones: the attached one is skipped by GateControl
    srv.tmuxSessions = require('./fixtures/term-server').tmuxSessions();
    await term.tmux(2);
    const all = await term.tmuxKillDetached(2, ['$2', '$3', '$1']);
    assert.deepEqual(srv.kills.at(-1).body.sessions.map((s) => s.id), ['$2', '$3', '$1']);
    assert.deepEqual(all.killed, ['$2', '$3']);
    assert.deepEqual(all.skipped, [{ id: '$1', reason: 'attached' }]);
    assert.deepEqual(all.sessions.map((s) => s.name), ['build']);
    await assert.rejects(term.tmuxKillDetached(2, []), (e) => e.code === 'invalid');
    await assert.rejects(term.tmuxKillDetached(2, ['$9']), (e) => e.code === 'tmux_gone');
  });

  it('an older GateControl: kill false, no windows, nothing can be ended', async () => {
    const { term } = await setup();
    const t = await term.tmux(2);
    assert.equal(t.kill, false);
    assert.equal(t.sessions[0].windowList, undefined);
    await assert.rejects(term.tmuxKill(2, { session: '$2' }), (e) => e.code === 'tmux_gone');
  });

  it('connect, bytes both ways, resize, a lost socket comes back with a new token, shell_refused ends for good', async () => {
    const { srv, term, statuses, data } = await setup();
    const st = await term.open({ deviceId: 2, tmux: { attach: 'tmux' }, recording: 'optional', record: true, cols: 100, rows: 30 });
    assert.match(st.id, /^term_/);
    assert.deepEqual(srv.connects[0], { via: 'app', protocol: 'ssh', tmux: { attach: 'tmux' }, record: true });
    await until('ready', () => term.status(st.id).state === 'ready');
    assert.equal(srv.urls[0], '/api/v1/remote/ssh-tunnel', 'no token in the URL');
    assert.deepEqual(srv.protocols[0], ['gc-term.v1', 'token.T1'.padEnd(49, 'x')]);
    assert.deepEqual(srv.received[0], { t: 'hello', cols: 100, rows: 30, term: 'xterm-256color' });
    assert.ok(!JSON.stringify(statuses).includes(srv.REF), 'the ref never reaches the renderer');

    srv.sockets[0].send(Buffer.from('pi@pi-werkstatt:~ $ '));
    await until('output', () => data.length > 0);
    assert.equal(Buffer.from(data[0].data).toString(), 'pi@pi-werkstatt:~ $ ');
    assert.equal(term.input(st.id, 'ls\r'), true);
    term.resize(st.id, 90, 25);
    await until('input and resize', () => srv.received.some((m) => m.bin === 'ls\r') && srv.received.some((m) => m.t === 'resize'));
    assert.deepEqual(srv.received.find((m) => m.t === 'resize'), { t: 'resize', cols: 90, rows: 25 });

    // a dead spot: gone without exit → reconnecting, then a new token and hello with the current size
    srv.sockets[0].drop();
    await until('reconnecting', () => statuses.some((s) => s.state === 'reconnecting'));
    assert.equal(statuses.find((s) => s.state === 'reconnecting').attempt, 1);
    await until('ready again', () => srv.tokens === 2 && term.status(st.id).state === 'ready');
    assert.deepEqual(srv.received.filter((m) => m.t === 'hello').pop(), { t: 'hello', cols: 90, rows: 25, term: 'xterm-256color' });

    // the device refuses the shell: final (design question 9), no further token
    srv.onHello = (sock) => { sock.send({ t: 'error', code: 'shell_refused' }); sock.close(); };
    srv.sockets[1].drop();
    await until('failed', () => term.status(st.id).state === 'failed');
    assert.deepEqual([term.status(st.id).code, term.status(st.id).verdict], ['shell_refused', 'final']);
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(srv.tokens, 3);
    assert.equal(term.input(st.id, 'x'), false);
  });

  it('host key: asked, trusted; distrust ends; bye on close', async () => {
    const { srv, term } = await setup();
    srv.onHello = (sock) => sock.send({ t: 'hostkey', hostKey: { alg: 'ssh-ed25519', sha256: 'q7Xv2mL0cR9sT4bN8kW1zE5yH3gJ6uA0pD2fK9iO7lM' } });
    const st = await term.open({ deviceId: 2 });
    await until('host key', () => term.status(st.id).state === 'hostkey');
    assert.equal(term.status(st.id).hostKey.groups, 'q7Xv 2mL0 cR9s T4bN 8kW1 zE5y H3gJ 6uA0 pD2f K9iO 7lM');
    term.trust(st.id, true);
    await until('trust sent', () => srv.received.some((m) => m.t === 'trust'));
    srv.sockets[0].send({ t: 'ready', tmux: { available: false, session: null }, recording: true, mode: 'control' });
    await until('ready', () => term.status(st.id).state === 'ready');
    assert.equal(term.status(st.id).tmuxMissing, true);
    assert.equal(term.status(st.id).recording, true);
    term.close(st.id);
    await until('bye', () => srv.received.some((m) => m.t === 'bye'));
    assert.equal(term.status(st.id), null);

    const two = await term.open({ deviceId: 2 });
    await until('host key 2', () => term.status(two.id).state === 'hostkey');
    term.trust(two.id, false);
    assert.deepEqual([term.status(two.id).state, term.status(two.id).code], ['failed', 'host_key_rejected']);
    await until('distrust', () => srv.received.some((m) => m.t === 'distrust'));
  });

  it('an expired ticket, a limit, the plugin refusing the ticket', async () => {
    const { srv, term } = await setup();
    srv.fail('/api/v1/client/remote/term-token', 404, 'not_found');
    const st = await term.open({ deviceId: 2 });
    await until('expired', () => term.status(st.id).state === 'failed');
    assert.equal(term.status(st.id).verdict, 'expired');

    srv.fail('/api/v1/client/remote/term-token', 429, 'limit_reached');
    const b = await term.open({ deviceId: 2 });
    await until('limit', () => term.status(b.id).state === 'failed');
    assert.equal(term.status(b.id).verdict, 'limit');
    term.reconnect(b.id);
    await until('ready after limit', () => term.status(b.id).state === 'ready');

    srv.fail('/api/v1/client/plugins/gatecontrol-remote/api/devices/2/connect', 409, 'recording_required');
    await assert.rejects(term.open({ deviceId: 2, recording: 'always' }), (e) => e.code === 'recording_required');
  });

  it('five failed attempts → offline; reconnect starts again', async () => {
    const { srv, term } = await setup();
    const st = await term.open({ deviceId: 2 });
    await until('ready', () => term.status(st.id).state === 'ready');
    srv.fail('/api/v1/client/remote/term-token', 502, 'unreachable', 5);
    srv.sockets[0].drop();
    await until('offline', () => term.status(st.id).state === 'offline', 8000);
    term.reconnect(st.id);
    await until('ready again', () => term.status(st.id).state === 'ready');
  });
});
