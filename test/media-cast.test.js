'use strict';

// "Auf TV/PC abspielen" — this PC as the receiver (cast contract v1, as Android's CastWire / CastInbox /
// CastReceiverRules / TvCast): the messages and the envelope, each delivery once and only for this PC (its id learned
// from the silent signal), the receiver's rules (age, controller, seq, when a state is worth a message), the own source
// by the plugin's id, and MediaCastReceiver against a fake plugin API: start → detail by the network rule → 'play',
// commands, states, the end, taking over, refusals (source_missing, signed_out, unsupported, blocked).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');

const C = require('../src/utils/media-cast');
const MediaCastReceiver = require('../src/services/media-cast');
const MSV = require('../src/utils/media-server');
const { MessengerError } = require('../src/services/messenger-api');

const NOW = 1_800_000_000_000;
const SESSION = 'a1b2c3d4e5f6a7b8c9d0e1f2';
const PHONE = '17';
const PC = '42';

function playBody(over = {}) {
  return {
    v: 1, type: 'cast.play', session: SESSION, seq: 0, at: NOW - 1000,
    source: { id: 'jf-1', kind: 'jellyfin', serverId: '4f1ca9', name: 'DS918+' },
    item: { id: 'm1', name: 'Kobaltnacht', kind: 'movie', runtimeMs: 7_200_000 },
    positionMs: 754_000, audio: 2, subtitle: -1, from: 'Pixel 8',
    ...over,
  };
}
const cmdBody = (seq, cmd, extra = {}) => ({ v: 1, type: 'cast.cmd', session: SESSION, seq, at: NOW, cmd, ...extra });
const envelope = (body, over = {}) => ({ kind: 'media.cast', from: PHONE, fromName: 'Pixel 8', to: PC, session: body.session, body, ...over });

describe('media-cast: the messages', () => {
  it('a start, a command and a state of version 1 are read; unknown fields ignored', () => {
    const p = C.parse({ ...playBody(), extra: true });
    assert.equal(p.type, 'cast.play');
    assert.equal(p.source.id, 'jf-1');
    assert.deepEqual([p.item.id, p.item.name, p.item.kind, p.item.runtimeMs], ['m1', 'Kobaltnacht', 'movie', 7_200_000]);
    assert.deepEqual([p.positionMs, p.audio, p.subtitle, p.from], [754_000, 2, -1, 'Pixel 8']);
    const c = C.parse(cmdBody(3, 'seekBy', { deltaMs: -10_000 }));
    assert.deepEqual([c.cmd, c.deltaMs, c.seq], ['seekBy', -10_000, 3]);
    const s = C.parse({ v: 1, type: 'cast.state', session: SESSION, seq: 1, at: NOW, state: 'playing', positionMs: 5, durationMs: 9, audio: [{ id: 'a1', label: 'DE', selected: true }, { id: 'bad id' }] });
    assert.deepEqual(s.audio, [{ id: 'a1', label: 'DE', selected: true }]);
  });

  it('refused: another version, a broken session, a command without its value, a way up in a share path', () => {
    assert.equal(C.parse({ ...playBody(), v: 2 }), null);
    assert.equal(C.parse({ ...playBody(), session: 'short' }), null);
    assert.equal(C.parse({ ...playBody(), seq: -1 }), null);
    assert.equal(C.parse(cmdBody(1, 'seek')), null);
    assert.equal(C.parse(cmdBody(1, 'audio', { track: 'a b' })), null);
    assert.equal(C.parse(cmdBody(1, 'reboot')), null);
    assert.equal(C.parse(playBody({ item: { id: 'x', name: 'x', path: '../geheim.mkv' } })), null);
    assert.equal(C.parse(playBody({ item: { id: 'x', name: 'x', path: '/abs.mkv' } })), null);
    assert.equal(C.parse(playBody({ source: { id: 'JF 1' } })), null);
    assert.equal(C.parse('{not json'), null);
  });

  it('a state to JSON and back; made smaller for the plugin (the chosen tracks stay)', () => {
    const audio = Array.from({ length: 30 }, (_, i) => ({ id: `a${i}`, label: `Ton ${i} `.repeat(6), selected: i === 29 }));
    const subtitles = [{ id: 'off', label: 'Aus', selected: true }, ...Array.from({ length: 30 }, (_, i) => ({ id: `s${i}`, label: `Untertitel ${i} `.repeat(6), selected: false }))];
    const m = { type: 'cast.state', session: SESSION, seq: 4, at: NOW, phase: 'playing', positionMs: 1, durationMs: 2, title: 'Kobaltnacht', audio, subtitles, device: 'BUERO-PC' };
    assert.ok(C.bytes(m) > C.MAX_BYTES);
    const f = C.fit(m);
    assert.ok(C.bytes(f) <= C.MAX_BYTES);
    assert.ok(f.audio.some((t) => t.id === 'a29' && t.selected));
    assert.ok(f.subtitles.some((t) => t.id === 'off'));
    const back = C.parse(C.toJson(f));
    assert.equal(back.phase, 'playing');
    assert.equal(back.device, 'BUERO-PC');
    assert.equal(C.fit({ ...cmdBody(1, 'pause'), type: 'cast.cmd', track: null }, 10), null);
  });

  it('the envelope: from, to, the same session in the body; never from == to', () => {
    const e = C.envelopeOf(envelope(playBody(), { from: 17 }));
    assert.deepEqual([e.from, e.to, e.fromName, e.session], [PHONE, PC, 'Pixel 8', SESSION]);
    assert.equal(C.envelopeOf(envelope(playBody(), { to: PHONE })), null);
    assert.equal(C.envelopeOf(envelope(playBody(), { session: 'b1b2c3d4e5f6a7b8' })), null);
    assert.equal(C.envelopeOf({ ...envelope(playBody()), kind: 'media.revoke' }), null);
  });
});

describe('media-cast: the inbox', () => {
  it('a signal tells this PC its id; events only for it; each message once', () => {
    const inbox = new C.Inbox();
    const learned = [];
    const play = C.envelopeOf(envelope(playBody()));
    // before the id is known: an event of a start is not taken
    assert.equal(inbox.take(play, { push: false }), 'not_mine');
    assert.equal(inbox.take(play, { push: true, onSelf: (id) => learned.push(id) }), 'take');
    assert.deepEqual(learned, [PC]);
    assert.equal(inbox.take(play, { push: false }), 'duplicate');
    const other = C.envelopeOf(envelope(cmdBody(1, 'pause'), { to: '99' }));
    assert.equal(inbox.take(other, { push: false }), 'not_mine');
  });

  it('without the id: a command of an own session counts', () => {
    const inbox = new C.Inbox();
    const c = C.envelopeOf(envelope(cmdBody(1, 'pause')));
    assert.equal(inbox.take(c, { push: false, mine: () => false }), 'not_mine');
    assert.equal(inbox.take(c, { push: false, mine: (s) => s === SESSION }), 'take');
  });
});

describe('media-cast: the receiver rules', () => {
  it('a start older than 120 s is not played; a command only of the session, its controller, newer and fresh', () => {
    const p = C.parse(playBody({ at: NOW - 121_000 }));
    assert.equal(C.freshPlay(p, NOW), false);
    assert.equal(C.freshPlay(C.parse(playBody()), NOW), true);
    const s = C.begin(C.parse(playBody()), PHONE);
    assert.equal(s.controllerName, 'Pixel 8');
    const c = C.parse(cmdBody(1, 'pause'));
    assert.equal(C.accept(s, c, '99', NOW), null);
    assert.equal(C.accept(s, { ...c, seq: 0 }, PHONE, NOW), null);
    assert.equal(C.accept(s, { ...c, at: NOW - 61_000 }, PHONE, NOW), null);
    assert.equal(C.accept(s, c, PHONE, NOW).lastSeq, 1);
  });

  it('a state is worth a message on a change, a jump, the volume, and every 5 minutes while it plays', () => {
    const a = C.snapshotOf({ phase: 'playing', positionMs: 10_000, durationMs: 100_000 });
    assert.equal(C.shouldReport(null, 0, a, NOW), true);
    assert.equal(C.shouldReport(a, NOW, { ...a, positionMs: 20_000 }, NOW + 10_000), false);
    assert.equal(C.shouldReport(a, NOW, { ...a, positionMs: 60_000 }, NOW + 10_000), true);
    assert.equal(C.shouldReport(a, NOW, { ...a, phase: 'paused' }, NOW + 1), true);
    assert.equal(C.shouldReport(a, NOW, { ...a, volume: 30 }, NOW + 1), true);
    assert.equal(C.shouldReport(a, NOW, { ...a, positionMs: 310_000 }, NOW + 300_000), true);
    assert.equal(C.seekTarget(5000, -10_000, 0), 0);
    assert.equal(C.seekTarget(95_000, 30_000, 100_000), 99_000);
  });

  it('the own source by the plugin id: Jellyfin, a share by its SMB half (WebDAV alone too)', () => {
    const sources = [
      { id: 'jf-1', sid: 'jf-1', managed: true, kind: 'jellyfin' },
      { id: 'sh-2', sid: 'sh-2', managed: true, kind: 'smb' },
      { id: 'sh-2_w', sid: 'sh-2', managed: true, kind: 'webdav' },
      { id: 'sh-3', sid: 'sh-3', managed: true, kind: 'webdav' },
      { id: 'local1', kind: 'jellyfin' },
    ];
    assert.deepEqual(C.match({ id: 'jf-1' }, sources), { sourceId: 'jf-1', kind: 'jellyfin' });
    assert.deepEqual(C.match({ id: 'sh-2' }, sources), { sourceId: 'sh-2', kind: 'share' });
    assert.deepEqual(C.match({ id: 'sh-3' }, sources), { sourceId: 'sh-3', kind: 'share' });
    assert.equal(C.match({ id: 'jf-9' }, sources), null);
    assert.equal(C.itemIdOf('share', { id: 'x', path: 'Filme/Kobaltnacht.mkv' }), 'f:Filme/Kobaltnacht.mkv');
    assert.equal(C.itemIdOf('share', { id: 'x' }), null);
    assert.equal(C.itemIdOf('jellyfin', { id: 'Items/../x' }), null);
  });

  it('tracks: Jellyfin stream index as id, the subtitle "off"; back to the index', () => {
    const v = { audio: [{ index: 1, label: 'Deutsch · AC3 5.1' }, { index: 2, label: 'English' }], subtitles: [{ index: 5, displayTitle: 'Deutsch (SRT)' }] };
    const t = C.tracksOf(v, { audioIndex: 2, subtitleIndex: -1 });
    assert.deepEqual(t.audio, [{ id: 'a1', label: 'Deutsch · AC3 5.1', selected: false }, { id: 'a2', label: 'English', selected: true }]);
    assert.deepEqual(t.subtitles, [{ id: 'off', label: 'Aus', selected: true }, { id: 's5', label: 'Deutsch (SRT)', selected: false }]);
    assert.equal(C.trackIndex('audio', 'a2'), 2);
    assert.equal(C.trackIndex('subtitle', 'off'), -1);
    assert.equal(C.trackIndex('subtitle', 's5'), 5);
    assert.equal(C.trackIndex('audio', 's5'), null);
    assert.equal(C.errorOf('vpn_required'), 'offline');
    assert.equal(C.errorOf('signed_out'), 'signed_out');
  });
});

// ── the service ─────────────────────────────────────────────

function fakeMedia({ sources, detail, inspect } = {}) {
  const kv = {};
  const m = {
    calls: [],
    store: {
      sources: () => sources || [{ id: 'jf-1', sid: 'jf-1', managed: true, kind: 'jellyfin' }, { id: 'sh-2', sid: 'sh-2', managed: true, kind: 'smb' }],
      castSelf: () => kv.self || null,
      setCastSelf: (id) => { kv.self = id; },
    },
    kv,
    info: () => ({ device: 'BUERO-PC' }),
    setCastReceiver(r) { this.cast = r; },
    async detail(sourceId, itemId) {
      m.calls.push(['detail', sourceId, itemId]);
      if (detail) return detail(sourceId, itemId);
      return { ok: true, title: { sourceId, id: itemId, name: 'Kobaltnacht', kind: 'movie', runtimeMs: 7_200_000 }, versions: [{ audio: [{ index: 2, label: 'Deutsch' }], subtitles: [] }] };
    },
    async shareInspect(o) { m.calls.push(['inspect', o]); return inspect ? inspect(o) : { ok: true, check: { verdict: 'yes' } }; },
  };
  return m;
}

function fakeApi(fail = null) {
  const calls = [];
  return {
    calls,
    async _call(method, path, opts) {
      calls.push({ method, path, opts });
      if (fail) { const code = fail(calls.length); if (code) throw new MessengerError(code, { status: 429, code }); }
      return { ok: true, v: 1, via: ['event'] };
    },
  };
}

function setup({ media = fakeMedia(), api = fakeApi(), timing = {} } = {}) {
  let now = NOW;
  const pushClient = new EventEmitter();
  const handlers = [];
  const nc = { addPushHandler: (h) => { handlers.push(h); return () => handlers.splice(handlers.indexOf(h), 1); } };
  const r = new MediaCastReceiver({ media, api, pushClient, notificationCenter: nc, now: () => now, timing: { openTimeoutMs: 30, retryMs: 20, ...timing } });
  const events = [];
  for (const ev of ['play', 'command', 'session']) r.on(ev, (p) => events.push([ev, p]));
  r.start();
  const signal = (data) => handlers.map((h) => h.notification({ topic: MSV.SIGNAL_TOPIC, data }));
  const event = (data) => pushClient.emit('event', { event: 'plugin', data: { plugin: MSV.PLUGIN_ID, type: 'media.cast', data } });
  const sent = () => api.calls.map((c) => ({ path: c.path, to: c.opts.body.to, ...C.parse(c.opts.body.body) }));
  const tick = () => new Promise((res) => setImmediate(res));
  const wait = (ms) => new Promise((res) => setTimeout(res, ms));
  return { r, media, api, events, signal, event, sent, tick, wait, advance: (ms) => { now += ms; }, pushClient, handlers };
}

const until = async (fn, tries = 50) => { for (let i = 0; i < tries && !fn(); i++) await new Promise((r) => setImmediate(r)); };

describe('MediaCastReceiver', () => {
  it('a start by the signal: this PC learns its id, plays from its own source, the page gets play; states go to the phone', async () => {
    const t = setup();
    assert.deepEqual(t.signal(envelope(playBody())), ['consumed']);
    assert.equal(t.media.kv.self, PC);
    await until(() => t.events.some(([e]) => e === 'play'));
    const play = t.events.find(([e]) => e === 'play')[1];
    assert.deepEqual([play.session, play.sourceId, play.itemId, play.startMs, play.audioIndex, play.subtitleIndex, play.controllerName],
      [SESSION, 'jf-1', 'm1', 754_000, 2, -1, 'Pixel 8']);
    assert.equal(play.item.sourceId, 'jf-1');
    assert.deepEqual(t.media.calls[0], ['detail', 'jf-1', 'm1']);
    // the same start again as the event: once only
    t.event(envelope(playBody()));
    await t.tick();
    assert.equal(t.events.filter(([e]) => e === 'play').length, 1);
    await until(() => t.api.calls.length >= 1);
    const first = t.sent()[0];
    assert.equal(first.path, `/api/v1/client/plugins/gatecontrol-medien/api/v1/cast/${SESSION}/message`);
    assert.deepEqual([first.to, first.type, first.phase, first.seq, first.device], [PHONE, 'cast.state', 'loading', 1, 'BUERO-PC']);
    assert.deepEqual(t.r.opened(SESSION), { ok: true });
    assert.equal(t.r.state(SESSION, { phase: 'playing', positionMs: 754_000, durationMs: 7_200_000, audio: [{ id: 'a2', label: 'Deutsch', selected: true }] }).sent, true);
    // a little later at the expected place: no message
    t.advance(10_000);
    assert.equal(t.r.state(SESSION, { phase: 'playing', positionMs: 764_000, durationMs: 7_200_000, audio: [{ id: 'a2', label: 'Deutsch', selected: true }] }).sent, false);
    await until(() => t.api.calls.length >= 2);
    assert.deepEqual(t.sent().map((s) => [s.phase, s.seq]), [['loading', 1], ['playing', 2]]);
    await t.wait(40);
    assert.equal(t.sent().some((s) => s.error === 'blocked'), false, 'opened in time');
    t.r.stop();
  });

  it('commands of the controller go to the page (tracks as Jellyfin index); others, old and repeated ones not', async () => {
    const t = setup();
    t.signal(envelope(playBody()));
    await until(() => t.events.some(([e]) => e === 'play'));
    t.r.opened(SESSION);
    t.event(envelope(cmdBody(1, 'pause')));
    t.event(envelope(cmdBody(1, 'pause')));
    t.event(envelope(cmdBody(2, 'seekBy', { deltaMs: 30_000 }), { from: '99' }));
    t.event(envelope(cmdBody(3, 'audio', { track: 'a1' })));
    t.event(envelope(cmdBody(4, 'subtitle', { track: 'off' })));
    t.event(envelope(cmdBody(5, 'volume', { volume: 35 })));
    t.event(envelope(cmdBody(6, 'seek', { positionMs: 60_000, at: NOW - 70_000 })));
    t.event(envelope(cmdBody(7, 'status')));
    const cmds = t.events.filter(([e]) => e === 'command').map(([, c]) => c);
    assert.deepEqual(cmds, [
      { session: SESSION, cmd: 'pause' },
      { session: SESSION, cmd: 'audio', audioIndex: 1 },
      { session: SESSION, cmd: 'subtitle', subtitleIndex: -1 },
      { session: SESSION, cmd: 'volume', volume: 35 },
      { session: SESSION, cmd: 'status' },
    ]);
    t.r.stop();
  });

  it('the end: "Stopp" of the phone → stopped without error; closed on this PC → closed; at the end → ended', async () => {
    for (const [how, phase, error] of [[{ byRemote: true }, 'stopped', null], [{}, 'stopped', 'closed'], [{ ended: true }, 'ended', null], [{ failed: true }, 'failed', 'failed']]) {
      const t = setup();
      t.signal(envelope(playBody()));
      await until(() => t.events.some(([e]) => e === 'play'));
      t.r.opened(SESSION);
      assert.deepEqual(t.r.closed(SESSION, { positionMs: 800_000, durationMs: 7_200_000, ...how }), { ok: true });
      await until(() => t.api.calls.length >= 2);
      const last = t.sent().pop();
      assert.deepEqual([last.phase, last.error, last.seq], [phase, error, 2]);
      assert.equal(t.r.status().session, null);
      // nothing more for this session
      assert.equal(t.r.state(SESSION, { phase: 'playing' }).ok, false);
      t.r.stop();
    }
  });

  it('refusals: no own source, signed out, Chromium cannot play the file, the page did not open it', async () => {
    const cases = [
      [{ sources: [] }, playBody(), 'source_missing'],
      [{ detail: () => ({ ok: false, code: 'signed_out' }) }, playBody(), 'signed_out'],
      [{ detail: () => ({ ok: false, code: 'vpn_required' }) }, playBody(), 'offline'],
      [{ detail: (s, i) => ({ ok: true, title: { sourceId: s, id: i, name: 'x', fromShare: true }, share: { path: 'Filme/a.avi' } }), inspect: () => ({ ok: true, check: { verdict: 'no' } }) },
        playBody({ source: { id: 'sh-2' }, item: { id: 'f1', name: 'a', path: 'Filme/a.avi' } }), 'unsupported'],
      [{}, playBody(), 'blocked'],
    ];
    for (const [m, body, error] of cases) {
      const t = setup({ media: fakeMedia(m) });
      t.signal(envelope(body));
      await t.wait(60);
      const last = t.sent().pop();
      assert.deepEqual([last.phase, last.error], ['failed', error], error);
      assert.equal(t.r.status().session, null);
      t.r.stop();
    }
  });

  it('a share plays by its path (f:<path>), without tracks', async () => {
    const media = fakeMedia({ detail: (s, i) => ({ ok: true, title: { sourceId: s, id: i, name: 'Kobaltnacht', fromShare: true }, share: { path: 'Filme/Kobaltnacht.mkv' } }) });
    const t = setup({ media });
    t.signal(envelope(playBody({ source: { id: 'sh-2' }, item: { id: 'Filme/Kobaltnacht.mkv', name: 'Kobaltnacht', path: 'Filme/Kobaltnacht.mkv' } })));
    await until(() => t.events.some(([e]) => e === 'play'));
    const play = t.events.find(([e]) => e === 'play')[1];
    assert.deepEqual([play.sourceId, play.itemId, play.item.fromShare, play.audioIndex, play.subtitleIndex], ['sh-2', 'f:Filme/Kobaltnacht.mkv', true, null, null]);
    t.r.stop();
  });

  it('a new start takes over: the phone before hears stopped / taken_over, the page stops the old one', async () => {
    const t = setup();
    t.signal(envelope(playBody()));
    await until(() => t.events.some(([e]) => e === 'play'));
    t.r.opened(SESSION);
    const other = 'z9y8x7w6v5u4t3s2r1q0p9o8';
    t.signal(envelope(playBody({ session: other }), { from: '18', session: other }));
    await until(() => t.events.filter(([e]) => e === 'play').length >= 2);
    assert.ok(t.events.some(([e, c]) => e === 'command' && c.session === SESSION && c.cmd === 'stop' && c.takenOver));
    await until(() => t.api.calls.length >= 3);
    const toOld = t.sent().find((s) => s.session === SESSION && s.phase === 'stopped');
    assert.deepEqual([toOld.to, toOld.error], [PHONE, 'taken_over']);
    assert.equal(t.r.status().session.session, other);
    t.r.stop();
  });

  it('an old start (the PC was off) is not played; "Stopp" while it still loads ends it at once', async () => {
    const t = setup();
    t.signal(envelope(playBody({ at: NOW - 200_000 })));
    await t.tick();
    assert.equal(t.events.length, 0);
    const t2 = setup({ media: fakeMedia({ detail: () => new Promise(() => {}) }) });
    t2.signal(envelope(playBody()));
    await t2.tick();
    t2.event(envelope(cmdBody(1, 'stop')));
    await until(() => t2.api.calls.length >= 2);
    assert.deepEqual(t2.sent().map((s) => s.phase), ['loading', 'stopped']);
    assert.equal(t2.r.status().session, null);
    t.r.stop(); t2.r.stop();
  });

  it('rate limited at the end: sent once more after the plugin minute', async () => {
    const api = fakeApi((n) => (n === 2 ? 'rate_limited' : null));
    const t = setup({ api });
    t.signal(envelope(playBody()));
    await until(() => t.events.some(([e]) => e === 'play'));
    t.r.opened(SESSION);
    t.r.closed(SESSION, { byRemote: true });
    await t.wait(50);
    const stopped = t.sent().filter((s) => s.phase === 'stopped');
    assert.equal(stopped.length, 2);
    assert.equal(stopped[0].seq, stopped[1].seq);
    t.r.stop();
  });

  it('reset (another person): the page stops, the id is forgotten', async () => {
    const t = setup();
    t.signal(envelope(playBody()));
    await until(() => t.events.some(([e]) => e === 'play'));
    t.media.kv.self = null;
    t.r.reset();
    assert.ok(t.events.some(([e, c]) => e === 'command' && c.cmd === 'stop'));
    assert.equal(t.r.self, null);
    assert.equal(t.media.cast, t.r, 'MediaService knows the receiver');
    t.r.stop();
  });

  it('other pushes are left to the others', () => {
    const t = setup();
    assert.deepEqual(t.handlers.map((h) => h.notification({ topic: MSV.SIGNAL_TOPIC, data: { kind: 'media.revoke' } })), [false]);
    assert.deepEqual(t.handlers.map((h) => h.notification({ topic: 'other', data: envelope(playBody()) })), [false]);
    t.r.stop();
  });
});

describe('MediaCastReceiver with MediaService and MediaStore', () => {
  it('this PC\'s id is kept in Medien\'s store and goes with forgetAll (another person), the cast ends', async () => {
    const { createMemoryStore } = require('./fixtures/memory-store');
    const MediaStore = require('../src/services/media-store');
    const MediaService = require('../src/services/media');
    const protect = { available: () => true, encrypt: (b) => Buffer.from(b), decrypt: (b) => Buffer.from(b) };
    const store = new MediaStore({ store: createMemoryStore(), protect });
    const media = new MediaService({ store, deviceName: () => 'BUERO-PC', networkInterfaces: () => ({}), lanRoute: { supported: false, removeHostRoutes: async () => {} } });
    const r = new MediaCastReceiver({ media, api: fakeApi(), now: () => NOW, timing: { openTimeoutMs: 10_000 } });
    const stops = [];
    r.on('command', (c) => stops.push(c.cmd));
    media.detail = async () => new Promise(() => {});
    assert.equal(r.receive(envelope(playBody()), { push: true }), true);
    assert.equal(store.castSelf(), PC);
    assert.equal(new C.Inbox(store.castSelf()).self, PC, 'known after a restart');
    assert.equal(media._cast, r);
    await media.forgetAll();
    assert.equal(store.castSelf(), null);
    assert.deepEqual(stops, ['stop']);
    r.stop();
  });
});
