'use strict';

// IPC of the messenger (registerBaseHandlers with ctx.messenger): opt-in,
// argument checks, answers, events to the window, reset on server:setup,
// "Speichern unter" / "Öffnen" of chat files (unsafe types refused).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, error() {}, debug() {} };
const MEDIA = '0123456789abcdef0123456789abcdef';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-chat-ipc-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function fakeMessenger() {
  const m = new EventEmitter();
  m.calls = [];
  const rec = (name) => (...args) => { m.calls.push([name, ...args]); return undefined; };
  m.status = () => ({ state: 'available' });
  m.check = async () => ({ state: 'available' });
  m.available = () => true;
  m.refreshConversations = async (o) => { m.calls.push(['refresh', o]); };
  m.listConversations = () => [{ id: 12 }];
  m.unreadTotal = () => 3;
  m.getConversation = async (id) => ({ id });
  m.getMessages = async (id, o) => { m.calls.push(['messages', id, o]); return { conversationId: id, messages: [], pending: [], hasMore: false, offline: false }; };
  m.messagesView = (id) => ({ conversationId: id, messages: [], pending: [], hasMore: true, offline: false });
  m.send = async (req) => { m.calls.push(['send', req]); return { pending: true, clientId: 'c' }; };
  m.retrySend = (id) => { m.calls.push(['retry', id]); return true; };
  m.discardSend = async () => true;
  m.edit = async (id, text) => ({ id, text });
  m.remove = async (id, scope) => ({ forAll: scope === 'all', message: null });
  m.react = async () => [{ emoji: '👍', count: 1, userIds: [7] }];
  m.markRead = async (id, upTo) => ({ lastReadId: upTo || 1, unread: 0 });
  m.typing = async () => true;
  m.setOpen = (o) => { m.calls.push(['open', o]); return o; };
  m.setViewOpen = rec('view');
  m.people = async () => [{ id: 8, name: 'Anna' }];
  m.createConversation = async (o) => { m.calls.push(['create', o]); return { conversation: { id: 13 }, created: true }; };
  m.updateConversation = async (id, patch, o) => { m.calls.push(['update', id, patch, o]); return { conversation: { id }, left: false }; };
  m.setPrefs = async (p) => ({ readReceipts: true, typing: true, preview: true, ...p });
  m.search = async () => ({ results: [], truncated: false });
  m.mediaList = async () => ({ items: [], counts: {}, hasMore: false });
  m.media = async () => ({ mime: 'application/pdf', data: Buffer.from('%PDF') });
  m.avatar = async () => ({ mime: 'image/webp', data: Buffer.from('RIFF') });
  m.resetForNewServer = async () => { m.calls.push(['reset']); };
  return m;
}

function setup(extra = {}) {
  const handlers = {};
  const sent = [];
  const messenger = extra.messenger === null ? null : fakeMessenger();
  const notifier = new EventEmitter();
  const opened = [];
  const ctx = {
    app: { getVersion: () => '1.0.0', setLoginItemSettings() {}, getPath: () => tmp },
    dialog: { showSaveDialog: async () => ({ canceled: false, filePath: path.join(tmp, 'saved.pdf') }) },
    getMainWindow: () => ({ isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } }),
    store: createMemoryStore(),
    wgService: { writeConfig: async () => {} },
    apiClient: { configure() {}, setPeerId() {}, register: async () => ({ peerId: 7 }), ping: async () => ({ ok: true }) },
    shell: { openPath: async (p) => { opened.push(p); return ''; }, openExternal() {}, showItemInFolder() {} },
    log,
    connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
    wgConfigFile: path.join(tmp, 'wg.conf'),
    ...(messenger ? { messenger, chatNotifier: notifier } : {}),
  };
  registerBaseHandlers({ handle: (ch, fn) => { handlers[ch] = fn; }, on() {} }, ctx);
  const call = (ch, arg) => handlers[ch]({}, arg);
  return { handlers, call, messenger, notifier, sent, opened };
}

describe('messenger IPC', () => {
  it('is opt-in', () => {
    const { handlers } = setup({ messenger: null });
    assert.equal(Object.keys(handlers).some((c) => c.startsWith('chat:')), false);
  });

  it('answers and validates arguments', async () => {
    const { call, messenger } = setup();
    assert.deepEqual(await call('chat:conversations', { refresh: true }), { ok: true, conversations: [{ id: 12 }], unread: 3 });
    assert.deepEqual(messenger.calls.at(-1), ['refresh', { full: false }]);
    assert.equal((await call('chat:messages', { id: 'x' })).code, 'invalid');
    assert.equal((await call('chat:messages', { id: 12, cached: true })).hasMore, true);
    await call('chat:messages', { id: 12, before: 400 });
    assert.deepEqual(messenger.calls.at(-1), ['messages', 12, { before: 400 }]);

    const file = { name: 'a.pdf', mime: 'application/pdf', data: new Uint8Array([1, 2]) };
    assert.equal((await call('chat:send', { conversationId: 12, kind: 'file', file })).ok, true);
    const req = messenger.calls.find((c) => c[0] === 'send')[1];
    assert.equal(req.file.name, 'a.pdf');
    assert.equal((await call('chat:send', { conversationId: 12, kind: 'file', file: { data: 'not bytes' } })).code, 'invalid');
    assert.equal((await call('chat:send', { conversationId: 0, text: 'x' })).code, 'invalid');
    assert.equal((await call('chat:outbox:retry', { clientId: 'bad id!' })).code, 'invalid');
    assert.equal((await call('chat:outbox:retry', { clientId: 'client-0001' })).ok, true);
    assert.equal((await call('chat:delete', { id: 5, scope: 'everyone' })).code, 'invalid');
    assert.equal((await call('chat:delete', { id: 5, scope: 'all' })).forAll, true);
    assert.equal((await call('chat:react', { id: 5, emoji: 'x'.repeat(17) })).code, 'invalid');
    assert.equal((await call('chat:react', { id: 5, emoji: null })).ok, true);
    assert.equal((await call('chat:prefs', {})).code, 'invalid');
    assert.equal((await call('chat:prefs', { preview: false })).prefs.preview, false);
    await call('chat:open', { id: 12, visible: true });
    assert.deepEqual(messenger.calls.find((c) => c[0] === 'open')[1], { id: 12, visible: true });
    await call('chat:update', { id: 12, patch: { title: 'Neu' }, avatar: { mime: 'image/webp', data: new Uint8Array([1]) } });
    const upd = messenger.calls.find((c) => c[0] === 'update');
    assert.deepEqual(upd[2], { title: 'Neu' });
    assert.equal(upd[3].avatar.mime, 'image/webp');
    assert.equal((await call('chat:media', { mediaId: '../x' })).code, 'invalid');
    const media = await call('chat:media', { mediaId: MEDIA });
    assert.ok(media.data instanceof Uint8Array);
    assert.equal(Buffer.from(media.data).toString(), '%PDF');
    assert.equal((await call('chat:avatar', { url: 'https://evil.example/a.png' })).code, 'invalid');
  });

  it('turns service errors into { ok: false, code }', async () => {
    const { call, messenger } = setup();
    messenger.edit = async () => { throw Object.assign(new Error('window'), { code: 'edit_window', status: 403 }); };
    assert.deepEqual(await call('chat:edit', { id: 5, text: 'x' }), { ok: false, code: 'edit_window', error: 'window', status: 403 });
  });

  it('forwards service events and toast navigation to the window', () => {
    const { messenger, notifier, sent } = setup();
    messenger.emit('messages', { conversationId: 12, reason: 'new' });
    messenger.emit('unread', 4);
    notifier.emit('navigate', { conversationId: 12 });
    assert.deepEqual(sent, [['chat:messages', { conversationId: 12, reason: 'new' }], ['chat:unread', 4], ['chat:navigate', { conversationId: 12 }]]);
  });

  it('saves a chat file and opens safe types only', async () => {
    const { call, messenger, opened } = setup();
    const saved = await call('chat:media:save', { mediaId: MEDIA, fileName: 'Brief.pdf' });
    assert.equal(saved.ok, true);
    assert.equal(fs.readFileSync(saved.path, 'utf8'), '%PDF');
    const ok = await call('chat:media:open', { mediaId: MEDIA, fileName: '..\\..\\Brief.pdf' });
    assert.equal(ok.ok, true);
    assert.equal(path.basename(opened[0]), 'Brief.pdf');
    assert.ok(opened[0].startsWith(tmp), 'written below the temp folder');
    const unsafe = await call('chat:media:open', { mediaId: MEDIA, fileName: 'rechnung.pdf.exe' });
    assert.equal(unsafe.code, 'unsafe');
    assert.equal(opened.length, 1);
    messenger.media = async () => ({ mime: 'text/html', data: Buffer.from('<script>') });
    assert.equal((await call('chat:media:open', { mediaId: MEDIA })).code, 'unsafe');
  });

  it('resets the messenger after a server setup', async () => {
    const { call, messenger } = setup();
    const r = await call('server:setup', { url: 'https://gate.example', apiKey: 'gc_abc' });
    assert.equal(r.success, true);
    await new Promise((res) => setTimeout(res, 5));
    assert.ok(messenger.calls.some((c) => c[0] === 'reset'));
  });
});
