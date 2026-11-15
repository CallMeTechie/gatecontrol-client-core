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
  m.dismissUpdateHint = () => { m.calls.push(['dismissHint']); return true; };
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
    ...(extra.maps !== undefined ? { maps: extra.maps } : {}),
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
    await call('chat:messages', { id: 12, around: 4711 });
    assert.deepEqual(messenger.calls.at(-1), ['messages', 12, { around: 4711 }]);
    await call('chat:messages', { id: 12, after: 4720, around: 'x' });
    assert.deepEqual(messenger.calls.at(-1), ['messages', 12, { after: 4720 }]);
    assert.deepEqual(await call('chat:update-hint:dismiss'), { ok: true });
    assert.deepEqual(messenger.calls.at(-1), ['dismissHint']);

    const file = { name: 'a.pdf', mime: 'application/pdf', data: new Uint8Array([1, 2]) };
    assert.equal((await call('chat:send', { conversationId: 12, kind: 'file', file })).ok, true);
    const req = messenger.calls.find((c) => c[0] === 'send')[1];
    assert.equal(req.file.name, 'a.pdf');
    const clip = { name: 'clip.mp4', mime: 'video/mp4', data: new Uint8Array([1, 2]) };
    const thumb = { mime: 'image/webp', data: new Uint8Array([3]) };
    await call('chat:send', { conversationId: 12, kind: 'file', file: clip, thumb, video: { durationMs: 1400, width: 640, height: 360 } });
    const vreq = messenger.calls.filter((c) => c[0] === 'send').at(-1)[1];
    assert.deepEqual(vreq.video, { durationMs: 1400, width: 640, height: 360 });
    assert.equal(vreq.thumb.mime, 'image/webp');
    await call('chat:send', { conversationId: 12, kind: 'file', file: clip, video: [1] });
    assert.equal(messenger.calls.filter((c) => c[0] === 'send').at(-1)[1].video, undefined);
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

  it('map: tiles as bytes, address search and reverse with checked arguments', async () => {
    const asked = [];
    const maps = {
      tile: async (z, x, y) => { asked.push(['tile', z, x, y]); return { mime: 'image/png', data: Buffer.from('PNG') }; },
      search: async (q, o) => { asked.push(['search', q, o]); return [{ lat: 48.1, lon: 11.5, label: 'Marienplatz, 80331 München' }]; },
      reverse: async (lat, lon, o) => { asked.push(['reverse', lat, lon, o]); return { label: 'Zuhause' }; },
    };
    const { call } = setup({ maps });
    const tile = await call('chat:map:tile', { z: 3, x: 4, y: 2 });
    assert.equal(tile.ok, true);
    assert.equal(tile.mime, 'image/png');
    assert.ok(tile.data instanceof Uint8Array);
    assert.equal(Buffer.from(tile.data).toString(), 'PNG');
    assert.equal((await call('chat:map:tile', { z: '3', x: 4, y: 2 })).code, 'invalid');
    assert.equal((await call('chat:map:tile', { z: 3, x: -1, y: 2 })).code, 'invalid');
    assert.deepEqual((await call('chat:map:search', { q: 'Marienplatz', lang: 'en' })).results[0].label, 'Marienplatz, 80331 München');
    assert.equal((await call('chat:map:search', { q: 5 })).code, 'invalid');
    assert.deepEqual(await call('chat:map:reverse', { lat: 48.1, lon: 11.5, lang: 'xx' }), { ok: true, label: 'Zuhause' });
    assert.equal((await call('chat:map:reverse', { lat: 'a', lon: 11.5 })).code, 'invalid');
    assert.deepEqual(asked.map((a) => a[0]), ['tile', 'search', 'reverse']);
    assert.deepEqual(asked[1][2], { lang: 'en' });
    assert.deepEqual(asked[2][3], { lang: undefined });
    maps.tile = async () => { throw Object.assign(new Error('down'), { code: 'network' }); };
    assert.equal((await call('chat:map:tile', { z: 1, x: 0, y: 0 })).code, 'network');
  });

  it('map: a default MapService named after the app', () => {
    const { handlers } = setup();
    for (const ch of ['chat:map:tile', 'chat:map:search', 'chat:map:reverse']) assert.equal(typeof handlers[ch], 'function');
  });

  it('resets the messenger after a server setup', async () => {
    const { call, messenger } = setup();
    const r = await call('server:setup', { url: 'https://gate.example', apiKey: 'gc_abc' });
    assert.equal(r.success, true);
    await new Promise((res) => setTimeout(res, 5));
    assert.ok(messenger.calls.some((c) => c[0] === 'reset'));
  });
  it('Messenger 1.13 / 1.14: linked services and resend pass through, a refusal keeps its reason', async () => {
    const { call, messenger } = setup();
    const calls = [];
    messenger.bridges = async () => ({ available: true, location: 'server', networks: [] });
    messenger.bridgeConsent = async (n) => { calls.push(['consent', n]); return { consent: true }; };
    messenger.bridgeLogin = async (n, f) => { calls.push(['login', n, f]); return { processId: 'p1', step: { id: 's1', type: 'phone', fieldId: 'phone_number' } }; };
    messenger.bridgeStep = async (n, p, st, o) => {
      calls.push(['step', n, p, st, o]);
      if (st === 'gone') throw Object.assign(new Error('bridge_failed'), { code: 'bridge_failed', status: 502, body: { reason: 'timeout' } });
      return { processId: p, waiting: true };
    };
    messenger.bridgeCancel = async (n, p) => { calls.push(['cancel', n, p]); return true; };
    messenger.bridgeUnlink = async (n, l) => { calls.push(['unlink', n, l]); return true; };
    messenger.resend = async (id) => ({ id, bridge: { state: 'sent' } });
    assert.deepEqual(await call('chat:bridges'), { ok: true, bridges: { available: true, location: 'server', networks: [] } });
    assert.deepEqual(await call('chat:bridge:consent', { network: 'whatsapp' }), { ok: true, consent: true });
    assert.equal((await call('chat:bridge:login', { network: 'whatsapp', flow: 'phone' })).login.step.type, 'phone');
    assert.deepEqual(await call('chat:bridge:step', { network: 'whatsapp', processId: 'p1', stepId: 's1', phone: '+49 1512 0000000', fieldId: 'phone_number' }), { ok: true, login: { processId: 'p1', waiting: true } });
    assert.deepEqual(await call('chat:bridge:step', { network: 'whatsapp', processId: 'p1', stepId: 'c1', phone: 4915 }), { ok: true, login: { processId: 'p1', waiting: true } });
    const gone = await call('chat:bridge:step', { network: 'whatsapp', processId: 'p1', stepId: 'gone' });
    assert.deepEqual([gone.ok, gone.code, gone.reason, gone.status], [false, 'bridge_failed', 'timeout', 502]);
    assert.deepEqual(await call('chat:bridge:cancel', { network: 'whatsapp', processId: 'p1' }), { ok: true });
    assert.deepEqual(await call('chat:bridge:unlink', { network: 'whatsapp', loginId: 'login1' }), { ok: true });
    assert.deepEqual(calls, [
      ['consent', 'whatsapp'], ['login', 'whatsapp', 'phone'],
      ['step', 'whatsapp', 'p1', 's1', { phone: '+49 1512 0000000', fieldId: 'phone_number' }],
      ['step', 'whatsapp', 'p1', 'c1', {}], ['step', 'whatsapp', 'p1', 'gone', {}],
      ['cancel', 'whatsapp', 'p1'], ['unlink', 'whatsapp', 'login1'],
    ]);
    assert.deepEqual(await call('chat:resend', { id: 4711 }), { ok: true, message: { id: 4711, bridge: { state: 'sent' } } });
    assert.equal((await call('chat:resend', { id: 'x' })).code, 'invalid');
  });

  it('Messenger 1.15: a new chat by number passes through; rate_limited keeps retryAfterS', async () => {
    const { call, messenger } = setup();
    const calls = [];
    messenger.bridgeResolve = async (n, num, cc) => {
      calls.push(['resolve', n, num, cc]);
      if (num === 'many') throw Object.assign(new Error('rate_limited'), { code: 'rate_limited', status: 429, body: { retryAfterS: 840, perHour: 10 } });
      return { found: true, name: 'Lena Berger', avatarMediaId: null, existing: null };
    };
    messenger.bridgeStartChat = async (n, num, cc) => { calls.push(['chat', n, num, cc]); return { conversation: { id: 77 }, created: true }; };
    assert.deepEqual(await call('chat:bridge:resolve', { network: 'whatsapp', number: '0151 23456789', cc: '+49' }), { ok: true, found: true, name: 'Lena Berger', avatarMediaId: null, existing: null });
    const many = await call('chat:bridge:resolve', { network: 'whatsapp', number: 'many' });
    assert.deepEqual([many.ok, many.code, many.retryAfterS, many.perHour, many.status], [false, 'rate_limited', 840, 10, 429]);
    assert.deepEqual(await call('chat:bridge:chat', { network: 'whatsapp', number: '+49 151 23456789', cc: 49 }), { ok: true, conversation: { id: 77 }, created: true });
    assert.deepEqual(calls, [['resolve', 'whatsapp', '0151 23456789', '+49'], ['resolve', 'whatsapp', 'many', ''], ['chat', 'whatsapp', '+49 151 23456789', '']]);
  });

  it('Messenger 1.18: „Neuer Chat“ with contacts passes through; not_found keeps reason and remembered', async () => {
    const { call, messenger } = setup();
    const calls = [];
    const REF = `k${'a'.repeat(48)}`;
    messenger.newChatContacts = async (n, q) => { calls.push(['list', n, q]); return { network: n, query: q, gatecontrol: [], whatsapp: null, addressBook: null, number: null, numberEntry: false, limit: null }; };
    messenger.bridgeContactChat = async (n, c) => {
      calls.push(['chat', n, c]);
      if (c.contactId === 13) throw Object.assign(new Error('not_found'), { code: 'not_found', status: 404, body: { reason: 'not_on_network', remembered: true } });
      if (c.ref === 'old') throw Object.assign(new Error('contact_expired'), { code: 'contact_expired', status: 409, body: {} });
      return { conversation: { id: 78 }, created: true };
    };
    assert.equal((await call('chat:bridge:contacts', { network: 'whatsapp', q: 'ber' })).query, 'ber');
    await call('chat:bridge:contacts', { network: 'whatsapp', q: 5 });
    assert.deepEqual(await call('chat:bridge:contact-chat', { network: 'whatsapp', contact: { ref: REF } }), { ok: true, conversation: { id: 78 }, created: true });
    const none = await call('chat:bridge:contact-chat', { network: 'whatsapp', contact: { contactId: 13, phoneKind: 'mobile' } });
    assert.deepEqual([none.ok, none.code, none.reason, none.remembered, none.status], [false, 'not_found', 'not_on_network', true, 404]);
    const old = await call('chat:bridge:contact-chat', { network: 'whatsapp', contact: { ref: 'old' } });
    assert.deepEqual([old.ok, old.code, old.remembered], [false, 'contact_expired', undefined]);
    assert.deepEqual(calls, [
      ['list', 'whatsapp', 'ber'], ['list', 'whatsapp', ''],
      ['chat', 'whatsapp', { ref: REF }], ['chat', 'whatsapp', { contactId: 13, phoneKind: 'mobile' }], ['chat', 'whatsapp', { ref: 'old' }],
    ]);
  });

  it('Messenger 1.17: „Älteren Verlauf laden“ and a file of the history pass through; a refusal keeps its code', async () => {
    const { call, messenger } = setup();
    const calls = [];
    messenger.setBridgeHistory = async (d) => {
      calls.push(['history', d]);
      if (d === 7) throw Object.assign(new Error('invalid'), { code: 'invalid', status: 400 });
      return { available: true, days: d, default: 30, options: [0, 30, -1], pending: 0 };
    };
    messenger.fetchBridgeFile = async (id) => {
      calls.push(['fetch', id]);
      if (id === 5) throw Object.assign(new Error('invalid'), { code: 'invalid', status: 400 });
      return { id, bridge: { placeholder: { kind: 'image', state: 'loading' } } };
    };
    assert.deepEqual(await call('chat:bridge:history', { days: -1 }), { ok: true, history: { available: true, days: -1, default: 30, options: [0, 30, -1], pending: 0 } });
    const bad = await call('chat:bridge:history', { days: 7 });
    assert.deepEqual([bad.ok, bad.code, bad.status], [false, 'invalid', 400]);
    assert.deepEqual(await call('chat:fetch', { id: 4711 }), { ok: true, message: { id: 4711, bridge: { placeholder: { kind: 'image', state: 'loading' } } } });
    assert.equal((await call('chat:fetch', { id: 'x' })).code, 'invalid');
    assert.equal((await call('chat:fetch', { id: 5 })).code, 'invalid');
    assert.deepEqual(calls, [['history', -1], ['history', 7], ['fetch', 4711], ['fetch', 5]]);
  });
});
