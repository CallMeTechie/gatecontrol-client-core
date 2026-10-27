'use strict';

// Messenger 1.4.0 in the core: IPC (ipc/messenger-handlers.js) → MessengerService
// → MessengerApi → the in-memory messenger server. Status and stories, the
// prefs privacy / notify / chats, chat tools (archive, pins, lists, blocks,
// export, reminders, suggestions to Familie), polls, events, live arrival
// (stop), home actions and plugin cards, live events, feature gates.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerService = require('../src/services/messenger');
const { registerMessengerHandlers } = require('../src/ipc/messenger-handlers');
const { messengerServer, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, feedDebounceMs: 5 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };

const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function setup({ features = FEATURES_14, familie = true, push = false, saveTo = null } = {}) {
  const srv = await messengerServer({ features, familie });
  cleanups.push(() => srv.close());
  const store = createMemoryStore();
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  let pushClient = null;
  if (push) {
    pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: PUSH_FAST });
    cleanups.push(() => pushClient.stop());
  }
  const m = new MessengerService({ apiClient, pushClient, store, log, timing: FAST });
  cleanups.push(() => m.stop());
  const handlers = new Map();
  const sent = [];
  const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push({ ch, p }) } };
  const written = [];
  const fsp = { writeFile: async (file, data, enc) => { written.push({ file, data, enc }); }, mkdir: async () => {} };
  const dialog = { showSaveDialog: async (_w, opts) => { dialog.last = opts; return saveTo ? { canceled: false, filePath: saveTo } : { canceled: true }; } };
  registerMessengerHandlers((ch, fn) => handlers.set(ch, fn), { messenger: m, getMainWindow: () => win, log, dialog, fsp, platform: 'linux' });
  const ipc = (ch, arg) => handlers.get(ch)({}, arg);
  m.start();
  if (pushClient) pushClient.start();
  await waitFor(() => m.status().state === 'available', 3000, 'available');
  return { srv, m, ipc, sent, written, dialog, handlers };
}

describe('Messenger 1.4.0 – me, prefs, feature gates', () => {
  it('keeps prefs sections and integrations; PUT prefs sends only known keys', async () => {
    const { srv, m, ipc } = await setup();
    const st = m.status();
    assert.deepEqual(st.me.integrations, { familie: { lists: true, calendar: true, places: true }, drive: false });
    assert.equal(st.updateHint, null, 'all 1.4.0 keys are known');
    const r = await ipc('chat:prefs', { privacy: { lastSeen: 'family', bogus: 1, avatar: 'everyone' }, notify: { eventReminderMin: 15 }, chats: { keepArchived: false } });
    assert.equal(r.ok, true);
    const put = srv.state.requests.filter((x) => x.path.endsWith('/prefs')).at(-1);
    assert.deepEqual(put.body, { privacy: { lastSeen: 'family' }, notify: { eventReminderMin: 15 }, chats: { keepArchived: false } });
    assert.equal(m.status().me.prefs.privacy.lastSeen, 'family');
    assert.equal(m.status().me.prefs.readReceipts, true);
    assert.equal((await ipc('chat:prefs', { privacy: { lastSeen: 'nobodyx' } })).code, 'invalid');
  });

  it('features absent → every 1.4.0 call answers unsupported, poll sends are refused', async () => {
    const { srv, ipc } = await setup({ features: { direct: true, groups: true }, familie: false });
    for (const [ch, arg] of [['chat:status:feed', {}], ['chat:actions', {}], ['chat:lists', {}], ['chat:blocks', {}]]) {
      assert.equal((await ipc(ch, arg)).code, 'unsupported', ch);
    }
    const id = srv.addConv();
    const r = await ipc('chat:send', { conversationId: id, kind: 'poll', poll: { question: 'Pizza?', options: ['Ja', 'Nein'] } });
    assert.equal(r.code, 'unsupported');
  });
});

describe('Messenger 1.4.0 – status and stories', () => {
  it('set / clear the own status, the feed, seen marks, viewers, reactions', async () => {
    const { srv, m, ipc } = await setup();
    srv.state.statuses.set(8, { preset: 'homeoffice', text: null, place: null, until: null, eta: null, destLabel: null, updatedAt: new Date().toISOString() });
    srv.state.stories.push({ id: 1, userId: 8, kind: 'text', text: 'Mathe geschafft', bg: '#0F766E', createdAt: Date.now(), seen: new Set(), reactions: new Map() });

    const feed = await ipc('chat:status:feed', { refresh: true });
    assert.equal(feed.ok, true);
    assert.equal(feed.items.length, 1);
    assert.equal(feed.items[0].unseen, true);

    const set = await ipc('chat:status:set', { preset: 'none', text: '  Im Garten  ', until: new Date(Date.now() + 3600000).toISOString(), visibility: 'family' });
    assert.equal(set.ok, true);
    assert.equal(set.status.text, 'Im Garten');
    assert.equal((await ipc('chat:status:set', { preset: 'none', text: '' })).code, 'invalid');
    assert.equal((await ipc('chat:status:set', { preset: 'dnd', until: '2001-01-01T00:00:00Z' })).code, 'invalid');

    const feeds = [];
    m.on('feed', (f) => feeds.push(f));
    assert.equal((await ipc('chat:story:seen', { id: 1 })).ok, true);
    assert.equal(feeds.at(-1).items[0].unseen, false, 'the ring goes off');
    assert.ok(srv.state.stories[0].seen.has(7));

    const react = await ipc('chat:story:react', { id: 1, emoji: '👏' });
    assert.equal(react.ok, true);
    assert.equal(react.message.replyStory.storyId, 1);
    assert.equal((await ipc('chat:status:clear')).ok, true);
    assert.equal(srv.state.statuses.has(7), false);
  });

  it('text and picture stories (preview uploaded before the picture), viewers, delete', async () => {
    const { srv, ipc } = await setup();
    const text = await ipc('chat:story:create', { kind: 'text', text: 'Grillen ab 18 Uhr', bg: '#0F766E', font: 'serif', visibility: 'family' });
    assert.equal(text.ok, true);
    const body = srv.state.requests.filter((x) => x.path.endsWith('/status/stories')).at(-1).body;
    assert.deepEqual(body, { kind: 'text', text: 'Grillen ab 18 Uhr', bg: '#0F766E', font: 'serif', visibility: 'family' });

    const img = await ipc('chat:story:create', { kind: 'image', text: 'Garten', file: { mime: 'image/webp', data: new Uint8Array([1, 2, 3, 4]) }, thumb: { mime: 'image/webp', data: new Uint8Array([5, 6]) } });
    assert.equal(img.ok, true);
    const puts = srv.state.requests.filter((x) => x.method === 'PUT' && x.path.endsWith('/media'));
    assert.deepEqual(puts.map((x) => x.bytes), [2, 4], 'preview first');
    assert.equal(img.story.mediaId.length, 32);
    assert.equal((await ipc('chat:story:create', { kind: 'image', file: { mime: 'application/pdf', data: new Uint8Array([1]) } })).code, 'unsupported_type');
    assert.equal((await ipc('chat:story:create', { kind: 'text', text: '' })).code, 'invalid');

    srv.state.stories[0].seen.add(8);
    const v = await ipc('chat:story:viewers', { id: text.story.id });
    assert.deepEqual(v.viewers.map((x) => x.user.name), ['Anna']);
    assert.equal((await ipc('chat:story:delete', { id: text.story.id })).ok, true);
    assert.equal(srv.state.stories.length, 1);
  });

  it('story duration (1.4.1): durationH sent only with story_duration, one of limits.storyDurationsH', async () => {
    const { srv, ipc } = await setup({ features: { ...FEATURES_14, story_duration: true } });
    const lastBody = () => srv.state.requests.filter((x) => x.method === 'POST' && x.path.endsWith('/status/stories')).at(-1).body;
    const r = await ipc('chat:story:create', { kind: 'text', text: 'Kurz', durationH: 3 });
    assert.equal(r.ok, true);
    assert.deepEqual(lastBody(), { kind: 'text', text: 'Kurz', durationH: 3 });
    const left = Date.parse(r.story.expiresAt) - Date.parse(r.story.createdAt);
    assert.equal(left, 3 * 3600000);
    const img = await ipc('chat:story:create', { kind: 'image', durationH: 12, file: { mime: 'image/webp', data: new Uint8Array([1, 2]) } });
    assert.equal(img.ok, true);
    assert.equal(lastBody().durationH, 12);
    const n = srv.state.requests.length;
    assert.equal((await ipc('chat:story:create', { kind: 'text', text: 'Zu lang', durationH: 48 })).code, 'invalid');
    assert.equal((await ipc('chat:story:create', { kind: 'text', text: 'Krumm', durationH: 2 })).code, 'invalid');
    assert.equal(srv.state.requests.length, n, 'refused without asking the server');
    assert.equal((await ipc('chat:story:create', { kind: 'text', text: 'Standard' })).ok, true);
    assert.equal(lastBody().durationH, undefined, 'no choice → the server default (24 h)');
  });

  it('story duration: a 1.4.0 server (no story_duration) gets no durationH', async () => {
    const { srv, ipc } = await setup();
    const r = await ipc('chat:story:create', { kind: 'text', text: 'Alt', durationH: 3 });
    assert.equal(r.ok, true);
    assert.deepEqual(srv.state.requests.filter((x) => x.path.endsWith('/status/stories')).at(-1).body, { kind: 'text', text: 'Alt' });
    assert.equal(Date.parse(r.story.expiresAt) - Date.parse(r.story.createdAt), 24 * 3600000);
  });

  it('status.update / story.new on the stream → the feed is fetched again (event chat:feed)', async () => {
    const { srv, sent, ipc } = await setup({ push: true });
    await ipc('chat:status:feed', {});
    await waitFor(() => srv.streams.size > 0, 3000, 'stream');
    srv.state.stories.push({ id: 9, userId: 9, kind: 'text', text: 'Hallo', createdAt: Date.now(), seen: new Set(), reactions: new Map() });
    const before = sent.filter((x) => x.ch === 'chat:feed').length;
    srv.event('story.new', { userId: 9, storyId: 9 });
    await waitFor(() => sent.filter((x) => x.ch === 'chat:feed').length > before, 3000, 'chat:feed');
    assert.equal(sent.filter((x) => x.ch === 'chat:feed').at(-1).p.items[0].user.name, 'Lena');
  });
});

describe('Messenger 1.4.0 – chat tools', () => {
  it('archive (out of the unread total), pins, lists, blocks', async () => {
    const { srv, m, ipc } = await setup();
    const anna = srv.addConv();
    const msg = srv.addMsg(anna, { text: 'Hallo' });
    await m.refreshConversations({ full: true });
    assert.equal(m.unreadTotal(), 1);
    const a = await ipc('chat:archive', { id: anna, archived: true });
    assert.equal(a.conversation.archived, true);
    assert.equal(m.unreadTotal(), 0, 'archived chats do not count');
    const p = await ipc('chat:pin', { id: anna, messageId: msg.id, pinned: true });
    assert.deepEqual(p.conversation.pinned, [msg.id]);
    assert.deepEqual((await ipc('chat:pin', { id: anna, messageId: msg.id, pinned: false })).conversation.pinned, []);

    const lists = await ipc('chat:lists:save', { lists: [{ id: 'arbeit', name: ' Arbeit ', conversationIds: [anna, 'x'] }, { id: 'bad id!', name: 'x' }] });
    assert.deepEqual(lists.lists, [{ id: 'arbeit', name: 'Arbeit', conversationIds: [anna] }]);
    assert.deepEqual((await ipc('chat:lists', {})).lists, lists.lists);

    const b = await ipc('chat:block', { userId: 8, blocked: true });
    assert.deepEqual(b.blocks.map((x) => x.userId), [8]);
    await waitFor(() => m.getCachedConversation(anna).can.send === false, 3000, 'can.send false');
    assert.deepEqual((await ipc('chat:block', { userId: 8, blocked: false })).blocks, []);
  });

  it('export: parts joined oldest first, saved as UTF-8 text with the server name', async () => {
    const out = path.join(os.tmpdir(), 'gc-export-test.txt');
    const { srv, ipc, written, dialog } = await setup({ saveTo: out });
    const anna = srv.addConv();
    srv.addMsg(anna, { text: 'Erste' });
    srv.addMsg(anna, { text: 'Zweite' });
    srv.addMsg(anna, { senderId: 7, text: 'Dritte' });
    const r = await ipc('chat:export', { id: anna });
    assert.equal(r.ok, true);
    assert.equal(r.path, out);
    assert.equal(r.count, 3);
    assert.equal(dialog.last.defaultPath, 'WhatsApp Chat Anna.txt');
    assert.equal(srv.state.exportCalls.length, 2);
    const text = written[0].data;
    assert.ok(text.startsWith('﻿'));
    assert.deepEqual(text.slice(1).trim().split('\r\n').map((l) => l.split(': ')[1]), ['Erste', 'Zweite', 'Dritte']);
  });

  it('remind me, reminders, suggestions to the Familie list and calendar, places', async () => {
    const { srv, ipc } = await setup();
    const anna = srv.addConv();
    const msg = srv.addMsg(anna, { text: 'Bring Milch und Brot mit, Samstag 15 Uhr Grillen' });
    const at = new Date(Date.now() + 3600000).toISOString();
    const r = await ipc('chat:remind', { id: msg.id, at });
    assert.equal(r.reminder.messageId, msg.id);
    assert.equal((await ipc('chat:remind', { id: msg.id, at: '2000-01-01T00:00:00Z' })).code, 'invalid');
    assert.equal((await ipc('chat:reminders')).reminders.length, 1);
    assert.equal((await ipc('chat:reminder:delete', { id: r.reminder.id })).ok, true);
    assert.equal(srv.state.reminders.length, 0);

    srv.state.suggest = { items: ['Milch', 'Brot'], dates: [{ startsAt: '2026-10-24T13:00:00.000Z', label: 'Sa., 24.10. 15:00', title: 'Grillen', allDay: false }] };
    const sg = await ipc('chat:suggest', { id: msg.id });
    assert.deepEqual(sg.items, ['Milch', 'Brot']);
    const tl = await ipc('chat:to-list', { id: msg.id, items: [' Milch ', '', 'Brot'] });
    assert.deepEqual({ added: tl.added, listName: tl.listName }, { added: 2, listName: 'Einkaufsliste' });
    assert.deepEqual(srv.state.toList[0].items, ['Milch', 'Brot']);
    const tc = await ipc('chat:to-calendar', { id: msg.id, title: 'Grillen', startsAt: sg.dates[0].startsAt });
    assert.equal(tc.eventId, 77);
    assert.equal((await ipc('chat:places')).places[0].name, 'Zuhause');
  });

  it('without Familie: to-list answers unavailable', async () => {
    const { srv, ipc } = await setup({ familie: false });
    const anna = srv.addConv();
    const msg = srv.addMsg(anna, { text: 'Milch' });
    assert.equal((await ipc('chat:to-list', { id: msg.id, items: ['Milch'] })).code, 'unavailable');
  });
});

describe('Messenger 1.4.0 – polls, events, arrival', () => {
  it('poll: send (outbox, pending view), vote, add an option, close, nudge', async () => {
    const { srv, m, ipc } = await setup();
    const fam = srv.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    await m.refreshConversations({ full: true });
    await ipc('chat:messages', { id: fam });
    const s = await ipc('chat:send', { conversationId: fam, kind: 'poll', text: 'ignored', poll: { question: 'Was essen wir?', options: ['Grillen', 'Lasagne', 'grillen'], multi: true, allowAdd: true } });
    assert.equal(s.ok, true);
    assert.equal(s.message.poll.question, 'Was essen wir?');
    assert.deepEqual(s.message.poll.options.map((o) => o.text), ['Grillen', 'Lasagne']);
    await waitFor(() => srv.state.lastSendBody && srv.state.lastSendBody.kind === 'poll', 3000, 'poll sent');
    assert.equal(srv.state.lastSendBody.text, undefined, 'no text with a poll');
    const id = srv.state.msgs.get(fam).at(-1).id;
    await waitFor(async () => (await ipc('chat:messages', { id: fam, cached: true })).messages.some((x) => x.id === id), 3000, 'poll listed');

    let r = await ipc('chat:poll', { id, op: 'vote', optionIds: ['o1', 'o2'] });
    assert.deepEqual(r.message.poll.myVotes, ['o1', 'o2']);
    r = await ipc('chat:poll', { id, op: 'option', text: '  Pizza  ' });
    assert.equal(r.message.poll.options.at(-1).text, 'Pizza');
    assert.equal((await ipc('chat:poll', { id, op: 'nudge' })).nudged, 2);
    r = await ipc('chat:poll', { id, op: 'close' });
    assert.equal(r.message.poll.closed, true);
    assert.equal((await ipc('chat:poll', { id, op: 'vote', optionIds: [] })).code, 'closed');
    const cached = await ipc('chat:messages', { id: fam, cached: true });
    assert.equal(cached.messages.find((x) => x.id === id).poll.closed, true, 'the cached message is replaced');
    assert.equal((await ipc('chat:poll', { id, op: 'bogus' })).code, 'invalid');
  });

  it('event: send with checklist and rsvp flag, rsvp with guests, checklist, edit, cancel', async () => {
    const { srv, ipc } = await setup();
    const fam = srv.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const starts = new Date(Date.now() + 86400000).toISOString();
    const s = await ipc('chat:send', { conversationId: fam, kind: 'event', event: { title: 'Sonntagsessen', startsAt: starts, place: { label: 'Oma Gisela', familiePlaceId: 'oma' }, checklist: ['Salat', '', 'Nachtisch'], rsvp: true, guests: true, reminderMin: 120 } });
    assert.equal(s.ok, true);
    assert.equal(s.message.event.rsvpEnabled, true);
    assert.deepEqual(s.message.event.rsvp, { yes: [], maybe: [], no: [], mine: null, myGuests: 0 });
    await waitFor(() => srv.state.lastSendBody && srv.state.lastSendBody.kind === 'event', 3000, 'event sent');
    assert.deepEqual(srv.state.lastSendBody.event.checklist, ['Salat', 'Nachtisch']);
    assert.equal((await ipc('chat:send', { conversationId: fam, kind: 'event', event: { title: 'x', startsAt: starts, reminderMin: 7 } })).code, 'invalid');
    const id = srv.state.msgs.get(fam).at(-1).id;

    let r = await ipc('chat:event', { id, op: 'rsvp', answer: 'yes', guests: 1 });
    assert.equal(r.message.event.rsvp.mine, 'yes');
    assert.deepEqual(r.message.event.rsvp.yes, [{ userId: 7, guests: 1 }]);
    r = await ipc('chat:event', { id, op: 'check', itemId: 'c1', done: true });
    assert.equal(r.message.event.checklist[0].doneBy, 7);
    r = await ipc('chat:event', { id, op: 'edit', patch: { title: 'Sonntagsessen bei Oma', bogus: 1 } });
    assert.equal(r.message.event.title, 'Sonntagsessen bei Oma');
    r = await ipc('chat:event', { id, op: 'edit', patch: { cancelled: true } });
    assert.equal(r.message.event.cancelled, true);
    assert.equal((await ipc('chat:event', { id, op: 'rsvp', answer: 'perhaps' })).code, 'invalid');
  });

  it('poll.update / arrival.update on the stream → changedSince for that message', async () => {
    const { srv, m, ipc } = await setup({ push: true });
    const fam = srv.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const arr = srv.addMsg(fam, { kind: 'arrival', text: null, arrival: { dest: { label: 'Zuhause', lat: 50, lon: 7, radiusM: 150 }, state: 'live', etaAt: new Date(Date.now() + 600000).toISOString(), distanceM: 3100, progress: 0.4 } });
    await m.refreshConversations({ full: true });
    await ipc('chat:messages', { id: fam });
    await waitFor(() => srv.streams.size > 0, 3000, 'stream');
    arr.arrival.state = 'arrived';
    arr.changedAt = Date.now();
    srv.event('arrival.update', { conversationId: fam, messageId: arr.id, state: 'arrived', updatedAt: new Date(arr.changedAt).toISOString() });
    await waitFor(async () => (await ipc('chat:messages', { id: fam, cached: true })).messages.find((x) => x.id === arr.id).arrival.state === 'arrived', 3000, 'arrival updated');
    assert.ok(srv.state.requests.some((x) => x.query.changedSince));
    const stop = await ipc('chat:arrival:stop', { id: arr.id });
    assert.equal(stop.message.arrival.state, 'stopped');
  });
});

describe('Messenger 1.4.0 – home actions and plugin cards', () => {
  it('actions list (cached), send a request, approve; deny another; card button and picture', async () => {
    const { srv, ipc } = await setup();
    const fam = srv.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const acts = await ipc('chat:actions', {});
    assert.deepEqual(acts.actions.map((a) => a.id), ['garage.open', 'door.open']);
    await ipc('chat:actions', {});
    assert.equal(srv.state.requests.filter((x) => x.path.endsWith('/api/actions')).length, 1, 'cached');

    const s = await ipc('chat:send', { conversationId: fam, kind: 'action', action: { mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', approverIds: [8, 8, 'x'] } });
    assert.equal(s.ok, true);
    await waitFor(() => srv.state.lastSendBody && srv.state.lastSendBody.kind === 'action', 3000, 'action sent');
    assert.deepEqual(srv.state.lastSendBody.action, { mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', approverIds: [8] });
    assert.equal((await ipc('chat:send', { conversationId: fam, kind: 'action', action: { mode: 'grant', actionId: 'x' } })).code, 'invalid', 'a grant needs toUserId and until');

    const req = srv.addMsg(fam, { senderId: 8, kind: 'action', text: null, action: { mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', state: 'open', can: { run: false, approve: true, deny: true } } });
    let r = await ipc('chat:action', { id: req.id, op: 'approve' });
    assert.equal(r.message.action.state, 'done');
    assert.equal(r.result.ok, true);
    assert.equal((await ipc('chat:action', { id: req.id, op: 'deny' })).code, 'closed');
    const req2 = srv.addMsg(fam, { senderId: 8, kind: 'action', text: null, action: { mode: 'request', actionId: 'garage.open', label: 'Garage öffnen', state: 'open', can: { run: false, approve: true, deny: true } } });
    r = await ipc('chat:action', { id: req2.id, op: 'deny' });
    assert.equal(r.message.action.state, 'denied');
    assert.equal(r.result, null);

    const png = Buffer.from('89504e470d0a1a0a0000', 'hex');
    const card = srv.addMsg(fam, { senderId: null, kind: 'card', text: 'Paketbote', card: { kind: 'doorbell', title: 'Klingel', text: 'Haustür', image: { mime: 'image/png', bytes: png.length }, link: { label: 'Live-Bild', route: 'plg-gatecontrol-door', kind: 'live_view' }, actions: [{ plugin: 'gatecontrol-door', actionId: 'door.open', label: 'Tür öffnen', icon: null, needsConfirm: true, canRun: true }], lastRun: null } });
    srv.state.cardImages.set(card.id, { mime: 'image/png', data: png });
    const img = await ipc('chat:card:image', { id: card.id });
    assert.equal(img.mime, 'image/png');
    assert.ok(img.data instanceof Uint8Array);
    assert.deepEqual(Buffer.from(img.data), png, 'bytes from base64');
    r = await ipc('chat:action', { id: card.id, op: 'run', actionId: 'door.open', plugin: 'gatecontrol-door' });
    assert.equal(r.result.message, 'Geöffnet');
    assert.deepEqual(srv.state.actionRuns.at(-1).body, { actionId: 'door.open', plugin: 'gatecontrol-door' });
  });

  it('a card picture that is not an image is refused', async () => {
    const { srv, ipc } = await setup();
    const fam = srv.addConv({ kind: 'group', members: [7, 8], title: 'F' });
    const card = srv.addMsg(fam, { senderId: null, kind: 'card', text: null, card: { kind: 'notice', title: 'x', text: 'y', image: { mime: 'text/html', bytes: 3 }, link: null, actions: [], lastRun: null } });
    srv.state.cardImages.set(card.id, { mime: 'text/html', data: Buffer.from('<b>') });
    assert.equal((await ipc('chat:card:image', { id: card.id })).code, 'bad_response');
  });
});

describe('Messenger 1.4.0 – storage', () => {
  it('reports caches and the server limits; clearing empties the media cache', async () => {
    const { m, ipc } = await setup();
    m._media.set('x', { mime: 'image/png', data: Buffer.alloc(100) });
    const st = await ipc('chat:storage');
    assert.equal(st.mediaCacheBytes, 100);
    assert.deepEqual(st.server, { maxBytes: 1024 * 1024, quotaFull: false, retentionDays: 0 });
    assert.equal((await ipc('chat:cache:clear')).mediaCacheBytes, 0);
  });
});

// keep fs referenced for the export path cleanup on platforms where it was written
afterEach(() => { try { fs.rmSync(path.join(os.tmpdir(), 'gc-export-test.txt'), { force: true }); } catch { /* none */ } });
