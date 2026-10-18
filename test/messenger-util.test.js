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

describe('messenger util – Messenger 1.3.0 features and video files', () => {
  it('features as a list or as flags', () => {
    assert.deepEqual(u.normalizeFeatures(['video_meta', 'file_thumbs', 7, '']), { video_meta: true, file_thumbs: true });
    assert.deepEqual(u.normalizeFeatures({ files: true, e2e: false }), { files: true, e2e: false });
    assert.deepEqual(u.normalizeFeatures(null), {});
    assert.equal(u.hasFeature(['video_meta'], 'video_meta'), true);
    assert.equal(u.hasFeature({ video_meta: true }, 'video_meta'), true);
    assert.equal(u.hasFeature({ video_meta: 'yes' }, 'video_meta'), false);
    assert.equal(u.hasFeature(undefined, 'file_thumbs'), false);
    assert.equal(u.FEATURE_VIDEO_META, 'video_meta');
    assert.equal(u.FEATURE_FILE_THUMBS, 'file_thumbs');
    assert.ok(u.MEDIA_KINDS.includes('video'));
  });

  it('video mime types', () => {
    assert.equal(u.isVideoMime('video/mp4'), true);
    assert.equal(u.isVideoMime('VIDEO/WebM; codecs=vp9'), true);
    assert.equal(u.isVideoMime('audio/mp4'), false);
    assert.equal(u.isVideoMime(''), false);
    assert.equal(u.extForMime('video/quicktime'), 'mov');
  });

  it('buildSendBody: video only on file messages, cleaned', () => {
    assert.deepEqual(u.buildSendBody({ kind: 'file', video: { durationMs: 1500.4, width: 640, height: 360, extra: 1 } }).video, { durationMs: 1500, width: 640, height: 360 });
    assert.equal(u.buildSendBody({ kind: 'file', video: { width: -1 } }).video, undefined);
    assert.throws(() => u.buildSendBody({ kind: 'image', video: { durationMs: 1 } }), (e) => e.code === 'invalid');
    assert.throws(() => u.buildSendBody({ kind: 'file', video: [1] }), (e) => e.code === 'invalid');
  });
});

describe('messenger util – update hint (unknown features)', () => {
  it('lists keys switched on that this client does not know', () => {
    const known = { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false, video_meta: true, file_thumbs: true };
    assert.deepEqual(u.unknownFeatures(known), []);
    assert.deepEqual(u.unknownFeatures({ ...known, stickers: true, calls: true, polls: true, video_calls: false }), ['calls', 'stickers']);
    assert.deepEqual(u.unknownFeatures({ bridges: true, e2e: true }), [], 'known keys never count, whatever their value');
    assert.deepEqual(u.unknownFeatures({ weird: 'yes', other: 1 }), [], 'only true counts');
    assert.deepEqual(u.unknownFeatures(['video_meta', 'calls']), ['calls']);
    assert.deepEqual(u.unknownFeatures(null), []);
    assert.deepEqual(u.unknownFeatures({ 'bad key!': true }), []);
    for (const k of Object.keys(known)) assert.ok(u.KNOWN_FEATURES.includes(k), k);
  });
});

describe('messenger utils – Messenger 1.4.0', () => {
  const u = require('../src/utils/messenger');

  it('knows the 1.4.0 feature keys (no update hint for them)', () => {
    assert.deepEqual(u.unknownFeatures({ status: true, stories: true, polls: true, events: true, arrival: true, actions: true, msg_tools: true, privacy2: true }), []);
    assert.deepEqual(u.unknownFeatures({ polls: true, calls: true }), ['calls']);
    assert.equal(u.hasFeature({ polls: true }, 'polls'), true);
    assert.equal(u.hasFeature({}, 'polls'), false);
  });

  it('send bodies of polls, events and actions; text / meta dropped; replyStory', () => {
    const p = u.buildSendBody({ kind: 'poll', text: 'x', meta: { w: 2 }, poll: { question: ' Q ', options: ['a', 'A', 'b'], closesAt: '2030-01-01T10:00:00Z' } });
    assert.deepEqual(p, { kind: 'poll', poll: { question: 'Q', options: ['a', 'b'], multi: false, anonymous: false, allowAdd: false, closesAt: '2030-01-01T10:00:00.000Z' } });
    assert.throws(() => u.buildSendBody({ kind: 'poll', poll: { question: 'Q', options: ['a'] } }), { code: 'invalid' });
    assert.throws(() => u.buildSendBody({ kind: 'poll', poll: { question: '', options: ['a', 'b'] } }), { code: 'invalid' });
    const e = u.buildSendBody({ kind: 'event', event: { title: 'Grillen', startsAt: '2030-05-01T16:00:00Z', endsAt: '2030-05-01T20:00:00Z', place: 'Garten', rsvp: false, reminderMin: 60, checklist: ['Kohle', { text: 'Salat' }] } });
    assert.deepEqual(e.event, { title: 'Grillen', startsAt: '2030-05-01T16:00:00.000Z', endsAt: '2030-05-01T20:00:00.000Z', place: { label: 'Garten' }, checklist: ['Kohle', 'Salat'], rsvp: false, reminderMin: 60 });
    assert.throws(() => u.buildSendBody({ kind: 'event', event: { title: 'x', startsAt: '2030-05-01T16:00:00Z', endsAt: '2030-05-01T10:00:00Z' } }), { code: 'invalid' });
    assert.deepEqual(u.normalizeEvent({ cancelled: true }, { partial: true }), { cancelled: true });
    assert.throws(() => u.normalizeEvent({}, { partial: true }), { code: 'invalid' });
    const a = u.buildSendBody({ kind: 'action', action: { mode: 'grant', actionId: 'light.living', label: 'Licht', grant: { toUserId: 9, until: '2030-01-01T22:00:00Z' }, approverIds: [8] } });
    assert.deepEqual(a.action, { mode: 'grant', actionId: 'light.living', label: 'Licht', grant: { toUserId: 9, until: '2030-01-01T22:00:00.000Z' } });
    assert.throws(() => u.buildSendBody({ kind: 'action', action: { mode: 'open', actionId: 'x' } }), { code: 'invalid' });
    assert.deepEqual(u.buildSendBody({ kind: 'text', text: '👏', replyStory: { storyId: 4 } }).replyStory, { storyId: 4 });
    assert.throws(() => u.buildSendBody({ kind: 'image', replyStory: { storyId: 4 } }), { code: 'invalid' });
    assert.throws(() => u.buildSendBody({ kind: 'arrival' }), { code: 'invalid' }, 'Windows sends no live arrival');
  });

  it('prefs, status, story and list bodies', () => {
    assert.deepEqual(u.prefsBody({ preview: false, privacy: { lastSeen: 'nobody', groupAdd: 'x', defaultDisappearingS: 86400 }, notify: { reactions: 'yes', statusDigest: true }, chats: {}, junk: 1 }), { preview: false, privacy: { lastSeen: 'nobody', defaultDisappearingS: 86400 }, notify: { statusDigest: true } });
    const now = Date.parse('2030-01-01T10:00:00Z');
    assert.deepEqual(u.statusBody({ preset: 'away', text: 'Unterwegs', eta: '2030-01-01T10:40:00Z', destLabel: 'Zuhause', visibility: 'custom', userIds: [8, '9', 8] }, { now }), { preset: 'away', text: 'Unterwegs', visibility: 'custom', userIds: [8, 9], eta: '2030-01-01T10:40:00.000Z', destLabel: 'Zuhause' });
    assert.deepEqual(u.statusBody({ preset: 'dnd', until: '2030-01-01T11:00:00Z' }, { now }), { preset: 'dnd', until: '2030-01-01T11:00:00.000Z' });
    assert.throws(() => u.statusBody({ preset: 'none' }, { now }), { code: 'invalid' });
    assert.throws(() => u.statusBody({ preset: 'dnd', visibility: 'custom' }, { now }), { code: 'invalid' });
    assert.equal(u.statusBody({ text: 'x'.repeat(100) }, { now }).text.length, 60);
    assert.deepEqual(u.storyBody({ kind: 'text', text: 'Hi', bg: '#123456', font: 'mono', eventMessageId: '12' }), { kind: 'text', text: 'Hi', bg: '#123456', font: 'mono', eventMessageId: 12 });
    assert.deepEqual(u.storyBody({ kind: 'image', bg: 'red', font: 'comic' }), { kind: 'image' });
    assert.throws(() => u.storyBody({ kind: 'text' }), { code: 'invalid' });
    assert.deepEqual(u.listsBody({ lists: [{ id: 'a', name: 'A', conversationIds: [1, 1, -2] }] }), [{ id: 'a', name: 'A', conversationIds: [1] }]);
    assert.throws(() => u.listsBody(Array.from({ length: 21 }, (_, i) => ({ id: `l${i}`, name: 'x' }))), { code: 'invalid' });
  });

  it('Familie integrations and card routes', () => {
    assert.deepEqual(u.familieOf({ integrations: { familie: { lists: true, calendar: 'yes' } } }), { lists: true, calendar: false, places: false });
    assert.deepEqual(u.familieOf({}), { lists: false, calendar: false, places: false });
    assert.equal(u.cardRoute({ route: 'plg-gatecontrol-door' }), 'plg-gatecontrol-door');
    assert.equal(u.cardRoute({ route: 'https://evil' }), null);
    assert.equal(u.cardRoute(null), null);
  });

  it('chat pushes of 1.4.0 carry their kind, deep link and reminder id', () => {
    const n = u.parseChatNotification({ seq: 3, id: 9, kind: 'message', title: 'Abfahrt?', body: 'Grillen beginnt in 45 Min.', data: { conversationId: 12, messageId: 4711, kind: 'event_departure', deepLink: 'arrival', reminderId: '5' } });
    assert.equal(n.pushKind, 'event_departure');
    assert.equal(n.deepLink, 'arrival');
    assert.equal(n.reminderId, 5);
    const plain = u.parseChatNotification({ seq: 3, id: 9, kind: 'message', title: 'Anna', body: 'Hi', data: { conversationId: 12, kind: '<script>' } });
    assert.equal(plain.pushKind, null);
  });
});
