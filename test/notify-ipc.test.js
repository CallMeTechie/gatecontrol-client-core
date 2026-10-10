'use strict';

// IPC of the notification center (registerBaseHandlers with ctx.notificationCenter):
// opt-in registration, argument checks, renderer events, config keys,
// reset after server:setup, shutdown.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const EventEmitter = require('node:events');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { registerBaseHandlers, CONFIG_WRITABLE_KEYS, NOTIFY_EVENTS } = require('../src/ipc/base-handlers');
const { performCleanShutdown } = require('../src/lifecycle/app-events');
const NotificationCenter = require('../src/services/notification-center');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, error() {}, debug() {} };
const NOTIFY_CHANNELS = ['notify:action', 'notify:dnd', 'notify:list', 'notify:prefs:get', 'notify:prefs:set', 'notify:read', 'notify:status', 'notify:test'];

function fakePush() {
  const p = new EventEmitter();
  p.acks = [];
  p.restarts = [];
  p.ack = async (seqs, state, action) => { p.acks.push({ seqs, state, action }); return { ok: true }; };
  p.fetchInbox = async () => ({ ok: true, items: [], unread: 0 });
  p.requestTest = async () => ({ ok: true, seq: 130 });
  p.status = () => ({ state: 'connected', via: 'direct' });
  p.applySettings = () => {};
  p.restart = (o) => p.restarts.push(o);
  p.start = () => {};
  p.stop = () => { p.stopped = true; };
  return p;
}

function setup(extra = {}) {
  const handlers = {};
  const sent = [];
  const store = createMemoryStore({ notifications: {} });
  const push = fakePush();
  const win = { isDestroyed: () => false, webContents: { send: (ch, payload) => sent.push([ch, payload]) } };
  const center = extra.center === null ? null : new NotificationCenter({
    store, log, pushClient: push, Notification: class { on() {} show() {} close() {} static isSupported() { return true; } },
    platform: 'win32', now: () => Date.parse('2026-10-10T21:45:00Z'),
  });
  let window = win;
  const ctx = {
    app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
    dialog: {},
    getMainWindow: () => window,
    store,
    wgService: { writeConfig: async () => {} },
    apiClient: {
      clientVersion: '1.0.0', clientPlatform: 'windows',
      configure() {}, setPeerId() {},
      register: async () => ({ peerId: 7 }),
      ping: async () => ({ ok: true }),
    },
    log,
    connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
    wgConfigFile: 'wg.conf',
    ...(center ? { notificationCenter: center } : {}),
    ...extra.ctx,
  };
  const registered = registerBaseHandlers({ handle: (ch, fn) => { handlers[ch] = fn; }, on() {} }, ctx);
  return { handlers, registered, center, push, store, sent, setWindow: (w) => { window = w; } };
}

const n = (seq, extra = {}) => ({ seq, id: seq + 10, topic: 'devices', priority: 'normal', title: `T${seq}`, body: '', silent: true,
  created_at: '2026-10-10T21:42:03Z', expires_at: '2026-10-13T21:42:03Z', data: { actions: [{ id: 'ack', label: 'OK', type: 'ack' }] }, ...extra });

describe('notify IPC', () => {
  it('is opt-in: no notify channels without a NotificationCenter', () => {
    const { registered } = setup({ center: null });
    assert.equal(registered.filter((c) => c.startsWith('notify:')).length, 0);
  });

  it('registers all notify channels once', () => {
    const { registered } = setup();
    assert.deepEqual(registered.filter((c) => c.startsWith('notify:')).sort(), NOTIFY_CHANNELS);
  });

  it('respects skip and overrides like every core channel', () => {
    const custom = async () => 'custom';
    const { handlers, registered } = setup({ ctx: { skip: ['notify:test'], overrides: { 'notify:status': custom } } });
    assert.ok(!registered.includes('notify:test'));
    assert.equal(handlers['notify:status'], custom);
  });

  it('notify:list / notify:read / notify:action', async () => {
    const { handlers, center, push } = setup();
    center.handleNotification(n(1));
    center.handleNotification(n(2, { topic: 'security' }));
    const all = await handlers['notify:list']({}, { refresh: false });
    assert.deepEqual(all.items.map((e) => e.seq), [2, 1]);
    assert.equal(all.unread, 2);
    assert.deepEqual((await handlers['notify:list']({}, { filter: 'security' })).items.map((e) => e.seq), [2]);
    assert.deepEqual((await handlers['notify:list']({}, null)).items.length, 2);

    assert.equal((await handlers['notify:read']({}, { ids: ['x'] })).error, 'invalid_ids');
    assert.equal((await handlers['notify:read']({}, 'all-of-them')).error, 'invalid_ids');
    assert.deepEqual(await handlers['notify:read']({}, { ids: [11] }), { ok: true, updated: 1, unread: 1 });
    assert.deepEqual(await handlers['notify:read']({}, { all: true }), { ok: true, updated: 1, unread: 0 });
    assert.deepEqual(push.acks.map((a) => a.seqs), [[1], [2]]);

    assert.deepEqual(await handlers['notify:action']({}, { id: 11, action: 'a b' }), { ok: false, error: 'invalid' });
    assert.deepEqual(await handlers['notify:action']({}, { id: 11, action: 'ack' }), { ok: true });
    assert.deepEqual(push.acks[2], { seqs: [1], state: 'read', action: 'ack' });
  });

  it('notify:list with refresh asks the server first', async () => {
    const { handlers, push } = setup();
    let fetched = 0;
    push.fetchInbox = async () => { fetched++; return { ok: true, items: [{ ...n(5), state: 'read' }], unread: 0 }; };
    const r = await handlers['notify:list']({}, { refresh: true });
    assert.equal(fetched, 1);
    assert.deepEqual(r.items.map((e) => [e.seq, e.state]), [[5, 'read']]);
  });

  it('notify:prefs:get/set, notify:dnd, notify:status, notify:test', async () => {
    const { handlers } = setup();
    const p = await handlers['notify:prefs:get']({});
    assert.deepEqual([p.enabled, p.direct, p.toasts, p.criticalBypass, p.mutedTopics, p.dndUntil], [true, true, true, true, [], null]);
    assert.deepEqual(await handlers['notify:prefs:set']({}, { toasts: 1 }), { ok: false, error: 'invalid_toasts' });
    assert.equal((await handlers['notify:prefs:set']({}, { toasts: false })).prefs.toasts, false);
    assert.deepEqual(await handlers['notify:dnd']({}), { ok: true, active: false, until: null });
    const on = await handlers['notify:dnd']({}, { minutes: 60 });
    assert.equal(on.active, true);
    assert.deepEqual(await handlers['notify:dnd']({}, null), { ok: true, active: false, until: null });
    assert.equal((await handlers['notify:dnd']({}, { minutes: -1 })).ok, false);
    const st = await handlers['notify:status']({});
    assert.deepEqual([st.state, st.via, st.unread], ['connected', 'direct', 0]);
    assert.deepEqual(await handlers['notify:test']({}), { ok: true, seq: 130 });
  });

  it('notify:test without push client answers not_configured', async () => {
    const { handlers, center } = setup();
    center.detach();
    assert.deepEqual(await handlers['notify:test']({}), { ok: false, error: 'not_configured' });
  });

  it('forwards center events to the main window, skips a destroyed window', () => {
    const { center, sent, setWindow } = setup();
    center.handleNotification(n(1));
    center.emit('navigate', { route: 'inbox', id: 11 });
    const channels = sent.map((s) => s[0]);
    assert.ok(channels.includes('notify:new'));
    assert.ok(channels.includes('notify:navigate'));
    assert.equal(sent.find((s) => s[0] === 'notify:new')[1].seq, 1);
    assert.deepEqual(Object.values(NOTIFY_EVENTS).sort(), ['notify:navigate', 'notify:new', 'notify:status', 'notify:update']);
    const before = sent.length;
    setWindow({ isDestroyed: () => true, webContents: { send: () => { throw new Error('destroyed'); } } });
    center.handleNotification(n(2));
    setWindow(null);
    center.handleNotification(n(3));
    assert.equal(sent.length, before);
  });

  it('config:set accepts the notifications keys of the schema, not the internal ones', async () => {
    for (const k of ['notifications.enabled', 'notifications.direct', 'notifications.toasts', 'notifications.criticalBypass', 'notifications.mutedTopics', 'notifications.dndUntil']) {
      assert.ok(CONFIG_WRITABLE_KEYS.has(k), k);
    }
    const { handlers, store } = setup();
    await handlers['config:set']({}, 'notifications.toasts', false);
    await handlers['config:set']({}, 'notifications.lastSeq', 5);
    assert.equal(store.get('notifications.toasts'), false);
    assert.equal(store.get('notifications.lastSeq'), undefined);
  });

  it('server:setup resets the push state of the old server', async () => {
    const { handlers, center, push } = setup();
    center.handleNotification(n(1));
    const r = await handlers['server:setup']({}, { url: 'https://gc.example.com', apiKey: 'gc_new' });
    assert.equal(r.success, true);
    assert.deepEqual(push.restarts, [{ resetSeq: true }]);
    assert.equal(center.list().items.length, 0);
  });

  it('performCleanShutdown stops the push stream', async () => {
    const { center, push } = setup();
    const app = { quit() {} };
    await performCleanShutdown(app, { store: { set() {} }, tunnelState: { connected: false }, notificationCenter: center });
    assert.equal(push.stopped, true);
  });
});
