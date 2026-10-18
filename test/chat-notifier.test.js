'use strict';

// Chat notifications (services/chat-notifier.js) with the real
// NotificationCenter: chat pushes skip the inbox, one toast per chat with a
// reply field (Electron's Notification.handleActivation) or a protocol
// "Gelesen" button, reply through the messenger, mark_read + acks, toasts
// closed by read/revoke and by reading in the app, the usual toast rules.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const NotificationCenter = require('../src/services/notification-center');
const ChatNotifier = require('../src/services/chat-notifier');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
let current = null;
const tick = async () => { await new Promise((r) => setTimeout(r, 5)); if (current) await current.whenIdle(); };
const tmpDirs = [];
after(() => { for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true }); });

function fakeNotification({ activation = true } = {}) {
  const created = [];
  class FakeNotification extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; this.shown = false; this.closed = false; created.push(this); }
    show() { this.shown = true; }
    close() { this.closed = true; }
    static isSupported() { return true; }
  }
  FakeNotification.created = created;
  if (activation) FakeNotification.handleActivation = (cb) => { FakeNotification.activate = cb; };
  return FakeNotification;
}

function fakePush() {
  const p = new EventEmitter();
  p.acks = [];
  p.ack = async (seqs, state, action) => { p.acks.push({ seqs, state, action }); return { ok: true }; };
  p.fetchInbox = async () => ({ ok: true, items: [], unread: 0 });
  p.status = () => ({ state: 'connected' });
  p.start = () => {};
  p.stop = () => {};
  p.applySettings = () => {};
  return p;
}

function fakeMessenger() {
  const m = new EventEmitter();
  m.sent = [];
  m.reads = [];
  m.posts = [];
  m.open = null;
  m.failSend = false;
  m.send = async (req) => { if (m.failSend) throw Object.assign(new Error('x'), { code: 'invalid' }); m.sent.push(req); return { pending: true }; };
  m.markRead = async (id, upTo) => { m.reads.push({ id, upTo }); m.emit('read-local', { conversationId: id, upTo }); return { lastReadId: upTo, unread: 0 }; };
  m.isOpenAndVisible = (id) => m.open === id;
  m.avatar = async () => ({ mime: 'image/webp', data: Buffer.from('RIFF') });
  m.api = { postPath: async (p, b) => { m.posts.push({ p, b }); return { ok: true }; } };
  return m;
}

const chatPush = (seq, extra = {}) => ({
  seq, id: seq + 1000, topic: 'plugin:gatecontrol-messenger:message', priority: 'normal', kind: 'message',
  title: 'Anna', body: `Text ${seq}`, created_at: new Date().toISOString(), expires_at: '2099-01-01T00:00:00Z',
  collapse_key: 'plugin:gatecontrol-messenger:chat:12', silent: false,
  data: {
    route: 'plg-gatecontrol-messenger', messageId: 4700 + seq,
    conversation: { id: '12', title: 'Familie', isGroup: true },
    sender: { id: 8, name: 'Anna', avatarUrl: '/avatars/annaAvatarFile0001.webp' },
    actions: [
      { id: 'reply', label: 'Antworten', type: 'reply', path: 'conversations/12/messages' },
      { id: 'mark_read', label: 'Gelesen', type: 'mark_read', path: 'conversations/12/read', body: { upTo: 4700 + seq } },
    ],
  },
  ...extra,
});

function setup({ activation = true, protocol = 'gatecontrol-pro', settings = {} } = {}) {
  const N = fakeNotification({ activation });
  const push = fakePush();
  const store = createMemoryStore({ notifications: { enabled: true, direct: true, toasts: true, criticalBypass: true, mutedTopics: [], dndUntil: null, ...settings } });
  const nc = new NotificationCenter({ store, log, pushClient: push, Notification: N, platform: 'win32', protocol, burstLimit: 50 });
  const messenger = fakeMessenger();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-chat-'));
  tmpDirs.push(tmp);
  const shown = [];
  const notifier = new ChatNotifier({ messenger, notificationCenter: nc, log, platform: 'win32', protocol, tmpDir: tmp, showWindow: () => shown.push(1), Notification: N });
  const nav = [];
  notifier.on('navigate', (e) => nav.push(e));
  notifier.start();
  current = notifier;
  return { N, push, nc, messenger, notifier, nav, shown, tmp };
}

describe('ChatNotifier', () => {
  it('chat pushes skip the inbox and raise one toast with a reply field', async () => {
    const { N, push, nc, notifier } = setup();
    const newEvents = [];
    nc.on('new', (e) => newEvents.push(e));
    push.emit('notification', chatPush(1));
    await tick();
    assert.equal(nc.list().items.length, 0, 'not in the inbox');
    assert.equal(newEvents.length, 0);
    assert.equal(notifier.mode, 'input');
    assert.equal(N.created.length, 1);
    const xml = N.created[0].opts.toastXml;
    assert.match(xml, /<text hint-maxLines="1">Familie<\/text>/);
    assert.match(xml, /<text>Anna: Text 1<\/text>/);
    assert.match(xml, /<input id="reply"/);
    assert.match(xml, /hint-crop="circle"/);
    assert.equal(N.created[0].opts.id, 'chat-12');
    assert.equal(N.created[0].opts.groupId, 'chats');
    // the next message of the chat replaces the toast
    push.emit('notification', chatPush(2));
    await tick();
    assert.equal(N.created.length, 2);
    assert.equal(N.created[0].closed, true);
    assert.deepEqual(notifier.tracked(), [{ conversationId: 12, seqs: [1, 2], toast: true }]);
  });

  it('reply from the toast: sent through the messenger, then read + acked', async () => {
    const { N, push, messenger, notifier } = setup();
    push.emit('notification', chatPush(1));
    push.emit('notification', chatPush(2));
    await tick();
    const args = /arguments="(gcchat\|reply\|[^"]+)"/.exec(N.created.at(-1).opts.toastXml)[1];
    assert.equal(N.activate({ arguments: args, type: 'reply', userInputs: { reply: '  Bin gleich da  ' } }), true);
    await tick();
    assert.deepEqual(messenger.sent, [{ conversationId: 12, kind: 'text', text: 'Bin gleich da', source: 'notification' }]);
    assert.deepEqual(messenger.reads, [{ id: 12, upTo: 4702 }]);
    assert.deepEqual(push.acks, [{ seqs: [1, 2], state: 'read', action: 'reply' }]);
    assert.equal(N.created.at(-1).closed, true);
    assert.deepEqual(notifier.tracked(), []);
  });

  it('"Gelesen" posts the read mark and acks every shown seq with mark_read', async () => {
    const { N, push, messenger } = setup();
    push.emit('notification', chatPush(5));
    await tick();
    const args = /arguments="(gcchat\|read\|[^"]+)"/.exec(N.created[0].opts.toastXml)[1];
    N.activate({ arguments: args, type: 'action' });
    await tick();
    assert.deepEqual(messenger.reads, [{ id: 12, upTo: 4705 }]);
    assert.deepEqual(push.acks, [{ seqs: [5], state: 'read', action: 'mark_read' }]);
  });

  it('click opens the chat (once), an empty reply opens it as well', async () => {
    const { N, push, nav, shown } = setup();
    push.emit('notification', chatPush(1));
    await tick();
    const open = /launch="([^"]+)"/.exec(N.created[0].opts.toastXml)[1];
    N.activate({ arguments: open, type: 'click' });
    N.created[0].emit('click');
    assert.deepEqual(nav, [{ conversationId: 12 }]);
    assert.equal(shown.length, 1);
    const reply = /arguments="(gcchat\|reply\|[^"]+)"/.exec(N.created[0].opts.toastXml)[1];
    await new Promise((r) => setTimeout(r, 5));
    N.activate({ arguments: reply.replace('|12|', '|13|'), type: 'reply', userInputs: { reply: '   ' } });
    assert.deepEqual(nav.at(-1), { conversationId: 13 });
    assert.equal(N.activate({ arguments: 'gatecontrol-notify', type: 'click' }), false);
  });

  it('cold start: an activation for an unknown toast still replies to that chat', async () => {
    const { N, messenger, push } = setup();
    N.activate({ arguments: 'gcchat|reply|44|900|77|unknownnonce1', type: 'reply', reply: 'ok' });
    await tick();
    assert.deepEqual(messenger.sent, [{ conversationId: 44, kind: 'text', text: 'ok', source: 'notification' }]);
    assert.deepEqual(messenger.reads, [{ id: 44, upTo: 900 }]);
    assert.deepEqual(push.acks, []);
  });

  it('without toast activation support: "Gelesen" as protocol button through the center', async () => {
    const { N, push, nc, messenger, notifier } = setup({ activation: false });
    assert.equal(notifier.mode, 'protocol');
    push.emit('notification', chatPush(3));
    await tick();
    const xml = N.created[0].opts.toastXml;
    assert.doesNotMatch(xml, /<input/);
    const url = /arguments="(gatecontrol-pro:\/\/notify\/action\?t=[^"]+)"/.exec(xml)[1];
    assert.equal(nc.handleArgv(['app.exe', url]), true);
    await tick();
    assert.deepEqual(messenger.reads, [{ id: 12, upTo: 4703 }]);
    assert.deepEqual(push.acks, [{ seqs: [3], state: 'read', action: 'mark_read' }]);
  });

  it('respects the toast rules: DND, muted topic, quiet hours (silent), toasts off', async () => {
    for (const settings of [
      { dndUntil: Date.now() + 60000 },
      { mutedTopics: ['plugin:gatecontrol-messenger:message'] },
      { toasts: false },
    ]) {
      const { N, push, notifier } = setup({ settings });
      push.emit('notification', chatPush(1));
      await tick();
      assert.equal(N.created.length, 0, JSON.stringify(settings));
      assert.equal(notifier.tracked().length, 1, 'still tracked for the read ack');
    }
    const { N, push } = setup();
    push.emit('notification', chatPush(1, { silent: true }));
    await tick();
    assert.equal(N.created.length, 0, 'quiet hours: no banner');
  });

  it('the open, visible chat gets no toast and is acked as read', async () => {
    const { N, push, messenger } = setup();
    messenger.open = 12;
    push.emit('notification', chatPush(9));
    await tick();
    assert.equal(N.created.length, 0);
    assert.deepEqual(push.acks, [{ seqs: [9], state: 'read', action: null }]);
  });

  it('read/revoke from the stream and reading elsewhere close the toast', async () => {
    const { N, push, messenger, notifier } = setup();
    push.emit('notification', chatPush(1));
    await tick();
    push.emit('read', { ids: [1001] });
    assert.equal(N.created[0].closed, true);
    assert.deepEqual(notifier.tracked(), []);

    push.emit('notification', chatPush(2));
    await tick();
    messenger.emit('read-self', { conversationId: 12 });
    assert.equal(N.created[1].closed, true);
    assert.deepEqual(push.acks, [], 'the other device acked');

    push.emit('notification', chatPush(3));
    await tick();
    messenger.emit('read-local', { conversationId: 12 });
    assert.equal(N.created[2].closed, true);
    assert.deepEqual(push.acks, [{ seqs: [3], state: 'read', action: null }]);
  });

  it('a failed notification reply shows a local notice', async () => {
    const { N, messenger } = setup();
    messenger.emit('send-failed', { conversationId: 12, clientId: 'x', error: 'readonly', source: 'notification' });
    assert.equal(N.created.length, 1);
    assert.match(N.created[0].opts.toastXml, /Antwort nicht gesendet/);
    messenger.emit('send-failed', { conversationId: 12, clientId: 'y', error: 'readonly', source: undefined });
    assert.equal(N.created.length, 1, 'only for notification replies');
  });

  it('normal notifications still go to the inbox; malformed chat pushes too', async () => {
    const { push, nc } = setup();
    push.emit('notification', { seq: 50, id: 60, topic: 'devices', title: 'Gateway offline', body: '', priority: 'high', created_at: new Date().toISOString() });
    push.emit('notification', { seq: 51, id: 61, kind: 'message', topic: 'plugin:gatecontrol-messenger:message', title: 'x', data: {} });
    await tick();
    assert.deepEqual(nc.list().items.map((e) => e.id).sort(), [60, 61]);
  });

  it('Messenger 1.4.0 push kinds: the server texts as they are, a toast of their own, acked with the chat', async () => {
    const { N, push, messenger, notifier } = setup();
    push.emit('notification', chatPush(1, { title: 'Lena', body: '📊 Umfrage: Pizza oder Pasta?' }));
    await tick();
    assert.match(N.created[0].opts.toastXml, /<text>Anna: 📊 Umfrage: Pizza oder Pasta\?<\/text>/);
    // a reminder (data.kind) — no "Sender: …", no reply field, own tag
    push.emit('notification', chatPush(2, {
      title: 'Erinnerung', body: 'Erinnerung: Milch kaufen', collapse_key: 'reminder:12:4701',
      data: { messageId: 4701, conversationId: 12, kind: 'reminder', reminderId: 5, conversation: { id: '12', title: 'Familie', isGroup: true }, sender: { id: 'gatecontrol', name: 'GateControl', avatarUrl: null } },
    }));
    await tick();
    assert.equal(N.created.length, 2);
    const xml = N.created[1].opts.toastXml;
    assert.match(xml, /<text hint-maxLines="1">Erinnerung<\/text>/);
    assert.match(xml, /<text>Erinnerung: Milch kaufen<\/text>/);
    assert.doesNotMatch(xml, /<input id="reply"/);
    assert.equal(N.created[1].opts.id, 'chat-12-reminder');
    assert.equal(N.created[0].closed, false, 'the chat toast stays');
    assert.deepEqual(notifier.trackedExtras(), [{ conversationId: 12, kinds: ['reminder'] }]);
    // a new message replaces only the chat toast
    push.emit('notification', chatPush(3));
    await tick();
    assert.equal(N.created[0].closed, true);
    assert.equal(N.created[1].closed, false);
    // reading the chat closes both and acks every seq
    messenger.emit('read-local', { conversationId: 12 });
    assert.equal(N.created[1].closed, true);
    assert.deepEqual(push.acks, [{ seqs: [1, 2, 3], state: 'read', action: null }]);
    assert.deepEqual(notifier.trackedExtras(), []);
  });

  it('stop() hands chat pushes back to the inbox', async () => {
    const { push, nc, notifier } = setup();
    notifier.stop();
    push.emit('notification', chatPush(1));
    await tick();
    assert.equal(nc.list().items.length, 1);
  });
});
