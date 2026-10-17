'use strict';

// Pure helpers of the messenger client (utils/messenger.js) and the chat
// toast XML (utils/toast-xml.js).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const u = require('../src/utils/messenger');
const { buildChatToastXml, chatArgs, parseChatArgs } = require('../src/utils/toast-xml');

const chatPush = (extra = {}) => ({
  seq: 130, id: 52, event_id: 'plugin:gatecontrol-messenger:message', topic: 'plugin:gatecontrol-messenger:message',
  priority: 'normal', title: 'Anna', body: 'Bist du schon unterwegs?', kind: 'message',
  created_at: '2026-10-17T18:02:11Z', expires_at: '2099-10-20T18:02:11Z',
  collapse_key: 'plugin:gatecontrol-messenger:chat:12', silent: false,
  data: {
    route: 'plg-gatecontrol-messenger', messageId: 4711,
    conversation: { id: '12', title: 'Familie', isGroup: true },
    sender: { id: 7, name: 'Anna', avatarUrl: '/avatars/Xk3abcdefghijklmnop.webp' },
    actions: [
      { id: 'reply', label: 'Antworten', type: 'reply', path: 'conversations/12/messages' },
      { id: 'mark_read', label: 'Gelesen', type: 'mark_read', path: 'conversations/12/read', body: { upTo: 4711 } },
    ],
  },
  ...extra,
});

describe('messenger helpers', () => {
  it('client ids are UUIDs the plugin accepts', () => {
    const id = u.newClientId();
    assert.ok(u.isClientId(id));
    assert.match(id, u.CLIENT_ID_RE);
    assert.notEqual(id, u.newClientId());
    assert.equal(u.isClientId('short'), false);
    assert.equal(u.isClientId('has space in it'), false);
  });

  it('validates ids and paths', () => {
    assert.equal(u.posInt('12'), 12);
    assert.equal(u.posInt(12), 12);
    assert.equal(u.posInt('12a'), null);
    assert.equal(u.posInt(0), null);
    assert.equal(u.posInt(-3), null);
    assert.ok(u.isMediaId('0123456789abcdef0123456789abcdef'));
    assert.equal(u.isMediaId('../etc/passwd'), false);
    assert.ok(u.isAvatarPath('/avatars/Xk3abcdefghijklmnop.webp'));
    assert.equal(u.isAvatarPath('/avatars/../secret.webp'), false);
    assert.equal(u.isAvatarPath('https://evil.example/avatars/abcdefghijklmnopq.webp'), false);
    assert.ok(u.isApiPath('conversations/12/read'));
    for (const bad of ['../me', 'conversations/../../x', '/abs', 'a?b=c', 'https://x', 'a//b', '']) assert.equal(u.isApiPath(bad), false, bad);
  });

  it('refuses to open executables and active content, allows documents', () => {
    for (const n of ['setup.exe', 'run.BAT', 'x.ps1', 'link.lnk', 'a.js', 'page.html', 'pic.svg', 'macro.docm', 'evil.pdf.exe', 'trailing.exe. ']) {
      assert.equal(u.unsafeToOpen(n, 'application/octet-stream'), true, n);
    }
    for (const n of ['brief.pdf', 'foto.jpg', 'liste.xlsx', 'notiz.txt', 'song.mp3']) assert.equal(u.unsafeToOpen(n, 'application/pdf'), false, n);
    assert.equal(u.unsafeToOpen('noext', 'text/html'), true);
  });

  it('makes file names safe for Windows', () => {
    assert.equal(u.safeFileName('..\\..\\Windows\\evil.pdf'), 'evil.pdf');
    assert.equal(u.safeFileName('a<b>:c?.pdf'), 'a_b__c_.pdf');
    assert.equal(u.safeFileName('CON.txt'), '_CON.txt');
    assert.equal(u.safeFileName('   ', 'fallback.bin'), 'fallback.bin');
    const long = u.safeFileName(`${'x'.repeat(300)}.pdf`);
    assert.ok(long.length <= 120 && long.endsWith('.pdf'));
  });

  it('derives the status of own messages from the receipts', () => {
    const conv = { readUpTo: 10, deliveredUpTo: 12 };
    assert.equal(u.messageStatus({ id: 9, mine: true, kind: 'text' }, conv), 'read');
    assert.equal(u.messageStatus({ id: 11, mine: true, kind: 'text' }, conv), 'delivered');
    assert.equal(u.messageStatus({ id: 13, mine: true, kind: 'text' }, conv), 'sent');
    assert.equal(u.messageStatus({ id: 13, mine: false, kind: 'text' }, conv), null);
    assert.equal(u.messageStatus({ pending: true }, conv), 'pending');
    assert.equal(u.messageStatus({ pending: true, failed: true }, conv), 'failed');
    // receipts switched off: readUpTo null → the message's own status
    assert.equal(u.messageStatus({ id: 9, mine: true, kind: 'text', status: 'delivered' }, { readUpTo: null, deliveredUpTo: null }), 'delivered');
  });

  it('merges message pages by id', () => {
    const a = [{ id: 1, text: 'a' }, { id: 3, text: 'c' }];
    const b = [{ id: 2, text: 'b' }, { id: 3, text: 'C' }];
    assert.deepEqual(u.mergeMessages(a, b).map((m) => `${m.id}${m.text}`), ['1a', '2b', '3C']);
  });

  it('sorts conversations by newest activity', () => {
    const list = u.sortConversations([
      { id: 1, createdAt: '2026-10-01T00:00:00Z' },
      { id: 2, lastMessage: { createdAt: '2026-10-17T10:00:00Z' } },
      { id: 3, lastMessage: { createdAt: '2026-10-16T10:00:00Z' } },
    ]);
    assert.deepEqual(list.map((c) => c.id), [2, 3, 1]);
  });

  it('builds send bodies like the plugin expects', () => {
    assert.deepEqual(u.buildSendBody({ text: '  Hallo\r\nDu  ' }), { kind: 'text', text: 'Hallo\nDu' });
    assert.throws(() => u.buildSendBody({ text: '   ' }), /invalid/);
    assert.throws(() => u.buildSendBody({ kind: 'system', text: 'x' }), /invalid/);
    assert.throws(() => u.buildSendBody({ text: 'x'.repeat(4001) }), /invalid/);
    const voice = u.buildSendBody({ kind: 'voice', meta: { durationMs: 1400.4, waveform: [-5, 300, 12.6, ...Array(80).fill(1)] }, replyTo: '4711' });
    assert.equal(voice.meta.durationMs, 1400);
    assert.equal(voice.meta.waveform.length, 64);
    assert.deepEqual(voice.meta.waveform.slice(0, 3), [0, 255, 13]);
    assert.equal(voice.replyTo, 4711);
    assert.deepEqual(u.buildSendBody({ kind: 'location', location: { lat: 48.1, lon: 11.5, label: 'Zuhause' } }).location, { lat: 48.1, lon: 11.5, label: 'Zuhause' });
    assert.throws(() => u.buildSendBody({ kind: 'location', location: { lat: 99, lon: 0 } }), /invalid/);
    assert.equal(u.buildSendBody({ text: 'x', source: 'notification' }).source, 'notification');
  });

  it('parses chat pushes of the contract', () => {
    const p = u.parseChatNotification(chatPush());
    assert.equal(p.conversationId, 12);
    assert.equal(p.messageId, 4711);
    assert.equal(p.isGroup, true);
    assert.equal(p.conversationTitle, 'Familie');
    assert.equal(p.sender.name, 'Anna');
    assert.equal(p.sender.avatarUrl, '/avatars/Xk3abcdefghijklmnop.webp');
    assert.deepEqual(p.reply, { id: 'reply', label: 'Antworten', path: 'conversations/12/messages', body: {} });
    assert.deepEqual(p.markRead.body, { upTo: 4711 });
    assert.equal(u.parseChatNotification({ ...chatPush(), kind: undefined }), null);
    assert.equal(u.parseChatNotification(chatPush({ data: { conversation: { id: 'x' } } })), null);
    // a foreign avatar URL and a path escaping the plugin API are dropped
    const evil = chatPush();
    evil.data.sender.avatarUrl = 'https://evil.example/a.png';
    evil.data.actions[0].path = '../../push/ack';
    const q = u.parseChatNotification(evil);
    assert.equal(q.sender.avatarUrl, null);
    assert.equal(q.reply, null);
  });

  it('converts IPC payloads to buffers', () => {
    const arr = new Uint8Array([1, 2, 3]);
    assert.deepEqual([...u.toBuffer(arr)], [1, 2, 3]);
    assert.deepEqual([...u.toBuffer(arr.buffer)], [1, 2, 3]);
    assert.equal(u.toBuffer('nope'), null);
    assert.equal(u.byteLength(arr), 3);
    assert.equal(u.baseMime('Audio/Ogg; codecs=opus'), 'audio/ogg');
    assert.equal(u.baseMime('nonsense'), '');
  });
});

describe('chat toast XML', () => {
  const ids = { conversationId: 12, messageId: 4711, seq: 130, nonce: 'abcdefghijkl' };

  it('input mode: reply field with send button and "Gelesen", round sender logo', () => {
    const xml = buildChatToastXml({
      title: 'Familie', body: 'Anna: <b>Hi</b> & "du"', imagePath: 'C:\\tmp\\a.png', mode: 'input', ids,
      labels: { placeholder: 'Antworten …', send: 'Senden', read: 'Gelesen' },
    });
    assert.match(xml, /<toast launch="gcchat\|open\|12\|4711\|130\|abcdefghijkl" activationType="foreground">/);
    assert.match(xml, /<input id="reply" type="text" placeHolderContent="Antworten …"\/>/);
    assert.match(xml, /<action content="Senden" arguments="gcchat\|reply\|12\|4711\|130\|abcdefghijkl" activationType="foreground" hint-inputId="reply"\/>/);
    assert.match(xml, /<action content="Gelesen" arguments="gcchat\|read\|12/);
    assert.match(xml, /hint-crop="circle" src="C:\\tmp\\a.png"/);
    assert.match(xml, /Anna: &lt;b&gt;Hi&lt;\/b&gt; &amp; &quot;du&quot;/);
  });

  it('read-only channel: no reply field', () => {
    const xml = buildChatToastXml({ title: 'GateControl', body: 'x', mode: 'input', ids, canReply: false });
    assert.doesNotMatch(xml, /<input/);
    assert.match(xml, /gcchat\|read/);
  });

  it('protocol mode: "Gelesen" as a protocol button, no input', () => {
    const xml = buildChatToastXml({ title: 'Anna', body: 'x', mode: 'protocol', ids, scheme: 'gatecontrol-pro', readNonce: 'nonce123456' });
    assert.doesNotMatch(xml, /<input/);
    assert.match(xml, /activationType="protocol" arguments="gatecontrol-pro:\/\/notify\/action\?t=nonce123456"/);
  });

  it('none: text only, silent when asked', () => {
    const xml = buildChatToastXml({ title: 'Anna', body: 'x', mode: 'none', ids, silent: true });
    assert.doesNotMatch(xml, /<actions>/);
    assert.match(xml, /<audio silent="true"\/>/);
  });

  it('activation arguments round-trip and reject anything else', () => {
    assert.deepEqual(parseChatArgs(chatArgs('reply', ids)), { action: 'reply', conversationId: 12, messageId: 4711, seq: 130, nonce: 'abcdefghijkl' });
    assert.deepEqual(parseChatArgs(chatArgs('open', { conversationId: 3, nonce: 'abcdefghijkl' })), { action: 'open', conversationId: 3, messageId: null, seq: null, nonce: 'abcdefghijkl' });
    for (const bad of ['gatecontrol-notify', 'gcchat|delete|1|2|3|abcdefghijkl', 'gcchat|open|x|2|3|abcdefghijkl', 'gcchat|open|1|2|3|<script>', null]) {
      assert.equal(parseChatArgs(bad), null, String(bad));
    }
  });
});
