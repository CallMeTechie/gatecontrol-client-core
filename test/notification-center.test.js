'use strict';

// Notification center (services/notification-center.js) with a fake Electron
// Notification and a fake push client: toasts by priority, collapse_key
// replacement, DND with critical bypass, local mutes, toast actions via
// protocol activation, click → inbox, read/revoke sync, inbox cache and
// server sync, settings.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const NotificationCenter = require('../src/services/notification-center');
const { buildToastXml, parseActionUrl, xmlEscape } = require('../src/utils/toast-xml');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const T0 = Date.parse('2026-10-10T21:45:00Z');

function fakeNotification() {
  const created = [];
  class FakeNotification extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; this.shown = false; this.closed = false; created.push(this); }
    show() { this.shown = true; }
    close() { this.closed = true; this.emit('close'); }
    static isSupported() { return true; }
  }
  FakeNotification.created = created;
  return FakeNotification;
}

function fakePush({ inbox = [], ackOk = true } = {}) {
  const p = new EventEmitter();
  p.acks = [];
  p.calls = { start: 0, stop: 0, restart: [], apply: 0, fetch: 0 };
  p.ackOk = ackOk;
  p.inbox = inbox;
  p.ack = async (seqs, state, action) => {
    p.acks.push({ seqs, state, action });
    if (!p.ackOk) return { ok: false, error: 'ECONNRESET' };
    p.inbox = p.inbox.map((n) => (seqs.includes(n.seq) ? { ...n, state } : n)); // like the server
    return { ok: true };
  };
  p.fetchInbox = async () => { p.calls.fetch++; return { ok: true, items: p.inbox, unread: 0 }; };
  p.start = () => { p.calls.start++; };
  p.stop = () => { p.calls.stop++; };
  p.restart = (o) => { p.calls.restart.push(o); };
  p.applySettings = () => { p.calls.apply++; };
  p.status = () => ({ state: 'connected', reason: null, via: 'tunnel' });
  p.requestTest = async () => ({ ok: true, seq: 1 });
  return p;
}

function note(seq, extra = {}) {
  return {
    seq, id: seq + 1000, event_id: 'gateway_state', topic: 'devices', priority: 'normal',
    title: `Gateway ${seq}`, body: 'Seit 2 Minuten kein Lebenszeichen', created_at: '2026-10-10T21:42:03Z',
    expires_at: '2026-10-13T21:42:03Z', collapse_key: null, silent: false,
    data: { route: 'gateways', actions: [
      { id: 'details', label: 'Details', type: 'open_app_route', target: 'gateways' },
      { id: 'mute_1h', label: '1 h stumm', type: 'mute_1h' },
    ] },
    received_at: '2026-10-10T21:42:04Z', via: 'direct', ...extra,
  };
}

function setup(opts = {}) {
  let now = opts.now || T0;
  const store = opts.store || createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } });
  const N = fakeNotification();
  const push = opts.push || fakePush();
  const shown = [];
  const portal = [];
  const center = new NotificationCenter({
    store, log, pushClient: push, Notification: N, platform: opts.platform || 'win32',
    protocol: opts.protocol === undefined ? 'gatecontrol-pro' : opts.protocol,
    showWindow: () => shown.push(1),
    openPortal: opts.noPortal ? undefined : async (path) => { portal.push(path); return true; },
    now: () => now, ...(opts.extra || {}),
  });
  const events = { new: [], update: [], unread: [], navigate: [], action: [], portal: [], status: [] };
  for (const k of Object.keys(events)) center.on(k, (x) => events[k].push(x));
  return { center, store, N, push, shown, portal, events, setNow: (v) => { now = v; } };
}

const tick = () => new Promise((r) => setImmediate(r));

describe('NotificationCenter toasts', () => {
  it('shows a Windows toast and stores the message in the inbox', () => {
    const { center, N, events } = setup();
    const entry = center.handleNotification(note(1, { priority: 'critical', title: 'Gateway „Zuhause“ <offline>' }));
    assert.equal(entry.id, 1001);
    assert.equal(N.created.length, 1);
    const xml = N.created[0].opts.toastXml;
    assert.ok(N.created[0].shown);
    assert.match(xml, /<text hint-maxLines="2">Gateway „Zuhause“ &lt;offline&gt;<\/text>/);
    assert.match(xml, /<text>Kritisch · Seit 2 Minuten kein Lebenszeichen<\/text>/);
    assert.match(xml, /scenario="urgent"/);
    assert.match(xml, /Notification\.Reminder/);
    assert.equal(events.new.length, 1);
    assert.equal(events.new[0].toast, true);
    assert.deepEqual(events.unread, [1]);
    assert.equal(center.unreadCount(), 1);
    assert.equal(center.list().items[0].actions.length, 2);
  });

  it('maps priority to sound: info is silent, normal has the default sound', () => {
    const { center, N } = setup();
    center.handleNotification(note(1, { priority: 'info' }));
    center.handleNotification(note(2, { priority: 'normal' }));
    assert.match(N.created[0].opts.toastXml, /<audio silent="true"\/>/);
    assert.match(N.created[1].opts.toastXml, /Notification\.Default/);
    assert.doesNotMatch(N.created[1].opts.toastXml, /scenario=/);
  });

  it('uses plain options with urgency outside Windows', () => {
    const { center, N } = setup({ platform: 'linux' });
    center.handleNotification(note(1, { priority: 'critical' }));
    center.handleNotification(note(2, { priority: 'info' }));
    assert.equal(N.created[0].opts.toastXml, undefined);
    assert.equal(N.created[0].opts.urgency, 'critical');
    assert.equal(N.created[0].opts.timeoutType, 'never');
    assert.equal(N.created[0].opts.body, 'Kritisch · Seit 2 Minuten kein Lebenszeichen');
    assert.deepEqual([N.created[1].opts.urgency, N.created[1].opts.silent], ['low', true]);
  });

  it('replaces the toast with the same collapse_key, keeps both in the inbox', () => {
    const { center, N } = setup();
    center.handleNotification(note(1, { collapse_key: 'gateway:3' }));
    center.handleNotification(note(2, { collapse_key: 'gateway:3' }));
    center.handleNotification(note(3, { collapse_key: 'gateway:4' }));
    assert.deepEqual(N.created.map((n) => n.closed), [true, false, false]);
    assert.deepEqual(center.list().items.map((e) => e.seq), [3, 2, 1]);
  });

  it('a bundled update (same id, new seq) replaces entry and toast', () => {
    const { center, N } = setup();
    center.handleNotification(note(1, { id: 77, title: 'Login failed' }));
    center.handleNotification(note(5, { id: 77, title: '3× Login failed' }));
    assert.equal(N.created[0].closed, true);
    const items = center.list().items;
    assert.equal(items.length, 1);
    assert.deepEqual([items[0].seq, items[0].title], [5, '3× Login failed']);
  });

  it('silent messages go to the inbox only', () => {
    const { center, N, events } = setup();
    center.handleNotification(note(1, { silent: true }));
    assert.equal(N.created.length, 0);
    assert.equal(events.new[0].toast, false);
    assert.equal(center.unreadCount(), 1);
  });

  it('DND suppresses toasts, critical passes with criticalBypass, ends on time', () => {
    const { center, N, store, setNow } = setup();
    assert.deepEqual(center.setDnd({ minutes: 60 }), { ok: true, active: true, until: T0 + 3600000 });
    center.handleNotification(note(1));
    center.handleNotification(note(2, { priority: 'critical' }));
    assert.equal(N.created.length, 1);
    assert.match(N.created[0].opts.toastXml, /Gateway 2/);
    store.set('notifications.criticalBypass', false);
    center.handleNotification(note(3, { priority: 'critical' }));
    assert.equal(N.created.length, 1);
    setNow(T0 + 3600001);
    assert.equal(center.dndState().active, false);
    center.handleNotification(note(4));
    assert.equal(N.created.length, 2);
    assert.equal(center.unreadCount(), 4);
  });

  it('setDnd accepts until (ms / ISO), null switches off, rejects the past', () => {
    const { center } = setup();
    assert.equal(center.setDnd({ until: new Date(T0 + 60000).toISOString() }).until, T0 + 60000);
    assert.equal(center.setDnd(T0 + 120000).until, T0 + 120000);
    assert.equal(center.setDnd({ until: T0 - 1 }).ok, false);
    assert.equal(center.dndState().until, T0 + 120000, 'unchanged after an invalid call');
    assert.deepEqual(center.setDnd(null), { ok: true, active: false, until: null });
  });

  it('toasts off / muted topics → inbox only; old replays and bursts are capped', () => {
    const { center, N, store, setNow } = setup();
    store.set('notifications.mutedTopics', ['devices']);
    center.handleNotification(note(1));
    assert.equal(N.created.length, 0);
    store.set('notifications.mutedTopics', []);
    store.set('notifications.toasts', false);
    center.handleNotification(note(2));
    assert.equal(N.created.length, 0);
    store.set('notifications.toasts', true);
    setNow(T0 + 7 * 3600 * 1000);
    center.handleNotification(note(3)); // created 7 h ago → replay, no toast
    assert.equal(N.created.length, 0);
    for (let i = 10; i < 17; i++) center.handleNotification(note(i, { created_at: new Date(T0 + 7 * 3600 * 1000).toISOString() }));
    assert.equal(N.created.length, 5, 'burst limit');
    assert.equal(center.unreadCount(), 10);
  });

  it('keeps at most 50 toast references (for close() from the Action Center)', () => {
    const { center, N } = setup({ extra: { burstLimit: 1000 } });
    for (let i = 1; i <= 55; i++) center.handleNotification(note(i));
    assert.equal(N.created.length, 55);
    assert.equal(center._toasts.size, 50);
    center._revoke([1055]);
    assert.equal(N.created[54].closed, true);
  });

  it('drops expired messages', () => {
    const { center, N } = setup();
    assert.equal(center.handleNotification(note(1, { expires_at: '2026-10-10T21:00:00Z' })), null);
    assert.equal(N.created.length, 0);
    assert.equal(center.list().items.length, 0);
  });

  it('notify() wraps local app notifications with the same rules', () => {
    const { center, N } = setup({ platform: 'win32' });
    assert.ok(center.notify({ title: 'VPN verbunden', body: 'ok' }));
    center.setDnd({ minutes: 10 });
    assert.equal(center.notify({ title: 'VPN getrennt' }), null);
    assert.ok(center.notify({ title: 'Update nötig', force: true }));
    assert.equal(N.created.length, 2);
    assert.equal(center.list().items.length, 0, 'local notifications are not in the inbox');
  });
});

describe('NotificationCenter actions', () => {
  function buttonUrls(n) {
    return [...n.opts.toastXml.matchAll(/arguments="([^"]+)"/g)].map((m) => m[1].replace(/&amp;/g, '&'));
  }

  it('toast buttons use single-use protocol URLs; open_app_route shows the route and acks', async () => {
    const { center, N, push, shown, events } = setup();
    center.handleNotification(note(1));
    const urls = buttonUrls(N.created[0]);
    assert.equal(urls.length, 2);
    assert.match(urls[0], /^gatecontrol-pro:\/\/notify\/action\?t=[A-Za-z0-9_-]{16}$/);
    assert.equal(center.handleArgv(['GateControl.exe', '--minimized', urls[0]]), true);
    await tick();
    assert.equal(shown.length, 1);
    assert.deepEqual(events.navigate, [{ route: 'gateways', id: 1001 }]);
    assert.deepEqual(events.action[0], { id: 1001, seq: 1, action: 'details', type: 'open_app_route' });
    assert.deepEqual(push.acks, [{ seqs: [1], state: 'read', action: 'details' }]);
    assert.equal(N.created[0].closed, true);
    // the second button belonged to the same toast: gone as well → just the inbox
    assert.equal(center.handleProtocolUrl(urls[1]), true);
    assert.deepEqual(events.navigate[1], { route: 'inbox', id: null });
  });

  it('ignores foreign schemes, forged and malformed URLs', () => {
    const { center, events } = setup();
    center.handleNotification(note(1));
    assert.equal(center.handleArgv(['other://notify/action?t=AAAAAAAAAAAAAAAA']), false);
    assert.equal(center.handleProtocolUrl('gatecontrol-pro://evil/action?t=AAAAAAAAAAAAAAAA'), false);
    assert.equal(center.handleProtocolUrl('gatecontrol-pro://notify/action?t=<script>'), false);
    // well-formed but unknown nonce: opens the inbox, performs nothing
    assert.equal(center.handleProtocolUrl('gatecontrol-pro://notify/action?t=AAAAAAAAAAAAAAAA'), true);
    assert.equal(events.action.length, 0);
  });

  it('without a protocol there are no buttons (click still works)', () => {
    const { center, N } = setup({ protocol: null });
    center.handleNotification(note(1));
    assert.doesNotMatch(N.created[0].opts.toastXml, /<actions>/);
    assert.equal(center.handleArgv(['gatecontrol-pro://notify/action?t=AAAAAAAAAAAAAAAA']), false);
  });

  it('mute_1h mutes the topic locally for an hour (critical still passes)', async () => {
    const { center, N, push, store, setNow } = setup();
    center.handleNotification(note(1));
    assert.deepEqual(await center.performAction(1001, 'mute_1h'), { ok: true });
    assert.equal(store.get('notifications.muteUntil').devices, T0 + 3600000);
    assert.deepEqual(push.acks[0], { seqs: [1], state: 'read', action: 'mute_1h' });
    assert.equal(center.topics().length, 0);
    center.handleNotification(note(2));
    assert.equal(N.created.length, 1);
    center.handleNotification(note(3, { priority: 'critical' }));
    assert.equal(N.created.length, 2);
    setNow(T0 + 3600001);
    center.handleNotification(note(4));
    assert.equal(N.created.length, 3);
  });

  it('open_portal opens the portal path (or emits portal), done dismisses, unknown actions fail', async () => {
    const data = { actions: [
      { id: 'portal', label: 'Im Portal öffnen', type: 'open_portal', target: '/portal/notify' },
      { id: 'done', label: 'Erledigt', type: 'done' },
      { id: 'evil', label: 'x', type: 'open_url', target: 'https://evil.example' },
      { id: 'bad', label: 'x', type: 'open_portal', target: '//evil.example' },
    ] };
    const { center, push, portal } = setup();
    center.handleNotification(note(1, { data }));
    assert.deepEqual(center.get(1001).actions.map((a) => a.id), ['portal', 'done']);
    assert.deepEqual(await center.performAction(1001, 'portal'), { ok: true });
    assert.deepEqual(portal, ['/portal/notify']);
    assert.deepEqual(await center.performAction(1001, 'done'), { ok: true });
    assert.deepEqual(push.acks[1], { seqs: [1], state: 'dismissed', action: 'done' });
    assert.deepEqual(await center.performAction(1001, 'evil'), { ok: false, error: 'unknown_action' });
    assert.deepEqual(await center.performAction(9, 'done'), { ok: false, error: 'not_found' });

    const b = setup({ noPortal: true });
    b.center.handleNotification(note(1, { data }));
    await b.center.performAction(1001, 'portal');
    assert.deepEqual(b.events.portal, [{ path: '/portal/notify' }]);
  });

  it('openInbox() shows the window on the inbox', () => {
    const { center, shown, events } = setup();
    center.openInbox();
    center.openInbox(1001);
    assert.equal(shown.length, 2);
    assert.deepEqual(events.navigate, [{ route: 'inbox', id: null }, { route: 'inbox', id: 1001 }]);
  });

  it('a click on the toast opens the inbox entry and marks it read', async () => {
    const { center, N, push, shown, events } = setup();
    center.handleNotification(note(1));
    N.created[0].emit('click');
    await tick();
    assert.equal(shown.length, 1);
    assert.deepEqual(events.navigate, [{ route: 'inbox', id: 1001 }]);
    assert.deepEqual(push.acks, [{ seqs: [1], state: 'read', action: null }]);
    assert.equal(center.unreadCount(), 0);
  });
});

describe('NotificationCenter inbox and sync', () => {
  it('read (other device) and revoke update the inbox and close toasts', () => {
    const { center, N, push, events } = setup();
    center.handleNotification(note(1));
    center.handleNotification(note(2));
    push.emit('read', { ids: [1001] });
    assert.equal(N.created[0].closed, true);
    assert.equal(center.get(1001).state, 'read');
    assert.equal(center.unreadCount(), 1);
    push.emit('revoke', { ids: [1002] });
    assert.equal(N.created[1].closed, true);
    assert.equal(center.get(1002), null);
    assert.deepEqual(events.unread, [1, 2, 1, 0]);
    assert.deepEqual(events.update.map((u) => u.reason), ['read', 'revoke']);
  });

  it('markRead(ids|all) acks read on the server; failed acks are retried after hello', async () => {
    const push = fakePush({ ackOk: false });
    const { center } = setup({ push });
    for (let i = 1; i <= 3; i++) center.handleNotification(note(i));
    const r = await center.markRead([1001]);
    assert.deepEqual(r, { ok: false, updated: 1, unread: 2, error: 'ECONNRESET' });
    push.ackOk = true;
    // server inbox still says delivered — the pending read wins locally
    push.inbox = [note(3), note(2), note(1)].map((n) => ({ ...n, state: 'delivered' }));
    push.emit('hello', { topics: [{ id: 'devices', label: 'Geräte & Gateways' }] });
    await new Promise((r2) => setTimeout(r2, 10));
    assert.deepEqual(push.acks[1], { seqs: [1], state: 'read', action: null });
    assert.equal(center.get(1001).state, 'read');
    assert.deepEqual(center.topics(), [{ id: 'devices', label: 'Geräte & Gateways', muted: false, mutedUntil: null }]);
    const all = await center.markRead('all');
    assert.deepEqual(all, { ok: true, updated: 2, unread: 0 });
    assert.deepEqual(push.acks[2].seqs.sort(), [2, 3]);
  });

  it('a read that could not be confirmed yet survives the server sync', async () => {
    const push = fakePush({ ackOk: false });
    const { center } = setup({ push });
    center.handleNotification(note(1));
    await center.markRead([1001]);
    push.inbox = [{ ...note(1), state: 'delivered' }];
    push.emit('hello', { topics: [] });
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(push.acks.length, 2, 'retried at hello');
    assert.equal(center.get(1001).state, 'read');
    assert.equal(center.unreadCount(), 0);
  });

  it('refresh() replaces the cache with the server inbox, keeping received_at/via', async () => {
    const push = fakePush();
    const { center, N } = setup({ push });
    center.handleNotification(note(1, { via: 'tunnel' }));
    center.handleNotification(note(2));
    push.inbox = [{ ...note(1), state: 'read', via: undefined, received_at: undefined }, { ...note(9), state: 'delivered' }];
    assert.deepEqual(await center.refresh(), { ok: true, unread: 1 });
    const items = center.list().items;
    assert.deepEqual(items.map((e) => [e.seq, e.state]), [[9, 'delivered'], [1, 'read']]);
    assert.equal(items[1].via, 'tunnel');
    assert.equal(N.created[1].closed, true, 'entry 2 vanished on the server → toast closed');
  });

  it('list() filters by unread/topic/before and hides expired entries', () => {
    const { center, setNow } = setup();
    center.handleNotification(note(1, { topic: 'security' }));
    center.handleNotification(note(2, { expires_at: '2026-10-10T22:00:00Z' }));
    center.handleNotification(note(3));
    center.handleNotification(note(4));
    center.markRead([1004]);
    assert.deepEqual(center.list({ filter: 'unread' }).items.map((e) => e.seq), [3, 2, 1]);
    assert.deepEqual(center.list({ filter: 'security' }).items.map((e) => e.seq), [1]);
    assert.deepEqual(center.list({ before: 3, limit: 1 }).items.map((e) => e.seq), [2]);
    setNow(Date.parse('2026-10-10T22:30:00Z'));
    assert.deepEqual(center.list().items.map((e) => e.seq), [4, 3, 1]);
    assert.equal(center.unreadCount(), 2);
  });

  it('keeps the last 100 and persists the cache in the store', () => {
    const { center, store } = setup();
    for (let i = 1; i <= 105; i++) center.handleNotification(note(i, { silent: true }));
    assert.equal(center.list().items.length, 100);
    assert.equal(center.list().items[99].seq, 6);
    const saved = store.get('notificationsInbox');
    assert.equal(saved.v, 1);
    assert.equal(saved.items.length, 100);
    const again = new NotificationCenter({ store, log, Notification: fakeNotification(), now: () => T0 });
    assert.equal(again.list().items.length, 100);
    assert.equal(again.unreadCount(), 100);
  });

  it('reset (new server) clears the cache; resetForNewServer restarts without seq', () => {
    const { center, push, store } = setup();
    center.handleNotification(note(1));
    push.emit('reset');
    assert.equal(center.list().items.length, 0);
    assert.deepEqual(store.get('notificationsInbox').items, []);
    center.handleNotification(note(2));
    center.resetForNewServer();
    assert.equal(center.unreadCount(), 0);
    assert.deepEqual(push.calls.restart, [{ resetSeq: true }]);
  });
});

describe('NotificationCenter preferences', () => {
  it('setPrefs validates and syncs server-side changes once', () => {
    const { center, push } = setup();
    assert.deepEqual(center.setPrefs({ toasts: 'yes' }), { ok: false, error: 'invalid_toasts' });
    assert.deepEqual(center.setPrefs({ mutedTopics: ['devices', '../etc'] }), { ok: false, error: 'invalid_mutedTopics' });
    const r = center.setPrefs({ toasts: false, criticalBypass: false });
    assert.equal(r.ok, true);
    assert.equal(push.calls.apply, 0, 'local-only settings do not touch the server');
    center.setPrefs({ direct: false, mutedTopics: ['plugin:skoda:charging', 'plugin:skoda:charging'] });
    assert.equal(push.calls.apply, 1);
    center.setPrefs({ direct: false });
    assert.equal(push.calls.apply, 1, 'no change, no sync');
    const p = center.getPrefs();
    assert.deepEqual(
      [p.enabled, p.direct, p.toasts, p.criticalBypass, p.mutedTopics, p.dndUntil],
      [true, false, false, false, ['plugin:skoda:charging'], null],
    );
  });

  it('config:set writes (store watcher) reach the push client too', () => {
    const { push, store, events } = setup();
    store.set('notifications.enabled', false);
    assert.equal(push.calls.apply, 1);
    store.set('notifications.lastSeq', 99); // internal key: no re-sync
    assert.equal(push.calls.apply, 1);
    store.set('notifications.dndUntil', T0 + 1000);
    assert.ok(events.status.length >= 2);
  });

  it('status() combines push state, unread and DND', () => {
    const { center } = setup();
    center.handleNotification(note(1, { silent: true }));
    const s = center.status();
    assert.deepEqual([s.state, s.via, s.unread, s.dnd.active, s.toasts, s.enabled], ['connected', 'tunnel', 1, false, true, true]);
  });

  it('start/stop/dispose drive the push client and release listeners', () => {
    const { center, push } = setup();
    center.start();
    center.stop();
    assert.deepEqual([push.calls.start, push.calls.stop], [1, 1]);
    center.dispose();
    assert.equal(push.listenerCount('notification'), 0);
  });
});

describe('toastDecision', () => {
  const base = { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [], muteUntil: {}, dndUntil: null };
  const e = (x = {}) => ({ priority: 'normal', topic: 'devices', silent: false, expires_at: null, ...x });
  const d = NotificationCenter.toastDecision;
  it('covers the rules', () => {
    assert.deepEqual(d(e(), base, T0), { show: true, silent: false, reason: null });
    assert.deepEqual(d(e({ priority: 'info' }), base, T0), { show: true, silent: true, reason: null });
    assert.equal(d(e(), { ...base, enabled: false }, T0).reason, 'off');
    assert.equal(d(e({ silent: true, priority: 'critical' }), base, T0).reason, 'silent');
    assert.equal(d(e(), { ...base, dndUntil: T0 + 1 }, T0).reason, 'dnd');
    assert.equal(d(e({ priority: 'critical' }), { ...base, dndUntil: T0 + 1 }, T0).show, true);
    assert.equal(d(e({ priority: 'critical' }), { ...base, dndUntil: T0 + 1, criticalBypass: false }, T0).reason, 'dnd');
    assert.equal(d(e(), { ...base, muteUntil: { devices: T0 + 5 } }, T0).reason, 'muted');
    assert.equal(d(e(), { ...base, muteUntil: { devices: T0 - 5 } }, T0).show, true);
    assert.equal(d(e({ expires_at: '2000-01-01T00:00:00Z' }), base, T0).reason, 'expired');
  });
});

describe('toast XML', () => {
  it('escapes text and strips XML-invalid characters', () => {
    assert.equal(xmlEscape('a<b>&"\'\u0001c'), 'a&lt;b&gt;&amp;&quot;&apos;c');
    const xml = buildToastXml({ title: '<x>', body: 'b&', attribution: 'Geräte', priority: 'high', buttons: [{ label: 'D"x', nonce: 'abcdefgh12345678' }], scheme: 'gatecontrol-pro' });
    assert.match(xml, /<text hint-maxLines="2">&lt;x&gt;<\/text><text>b&amp;<\/text><text placement="attribution">Geräte<\/text>/);
    assert.match(xml, /<action content="D&quot;x" activationType="protocol" arguments="gatecontrol-pro:\/\/notify\/action\?t=abcdefgh12345678"\/>/);
  });

  it('drops buttons for an invalid scheme and caps them at five', () => {
    const buttons = Array.from({ length: 7 }, (_, i) => ({ label: `b${i}`, nonce: `nonce000${i}` }));
    assert.doesNotMatch(buildToastXml({ title: 't', buttons, scheme: 'javascript:alert(1)//' }), /<actions>/);
    assert.equal((buildToastXml({ title: 't', buttons, scheme: 'gc' }).match(/<action /g) || []).length, 5);
  });

  it('parseActionUrl only accepts the own action URL', () => {
    assert.equal(parseActionUrl('gc://notify/action?t=abcdefgh', 'gc'), 'abcdefgh');
    assert.equal(parseActionUrl('gc://notify/action?t=abc', 'gc'), null);
    assert.equal(parseActionUrl('gc://notify/other?t=abcdefgh', 'gc'), null);
    assert.equal(parseActionUrl('https://notify/action?t=abcdefgh', 'gc'), null);
    assert.equal(parseActionUrl(42, 'gc'), null);
  });
});
