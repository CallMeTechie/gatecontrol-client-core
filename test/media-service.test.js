'use strict';

// Medien (Stufe 4e): MediaStore (DPAPI blob, device id, progress, tracks) and MediaService against a fake Jellyfin
// and fake shares — the setup (Quick Connect, name and password, "Gerät anmelden"), the rows with gcmedia:// pictures,
// play → gcmedia:// and the progress to Jellyfin, a 401, SMB error 1219, the SMB ↔ WebDAV pair and the way (home:
// bound to the LAN, the host route when the tunnel would carry the NAS; away: measured).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createMemoryStore } = require('./fixtures/memory-store');
const { createMediaServer } = require('./fixtures/media-server');
const MediaStore = require('../src/services/media-store');
const MediaService = require('../src/services/media');
const MediaNet = require('../src/services/media-net');
const { SmbShare } = require('../src/services/media-share');

// safeStorage stand-in: reversible, but never the plain text in the store
const protect = {
  available: () => true,
  encrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
  decrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
};

describe('MediaStore', () => {
  it('sources only encrypted, the device id made once, nothing without safeStorage', () => {
    const mem = createMemoryStore();
    const store = new MediaStore({ store: mem, protect });
    const id = store.deviceId();
    assert.match(id, /^[0-9a-f-]{36}$/);
    assert.equal(new MediaStore({ store: mem, protect }).deviceId(), id);
    const s = store.save({ kind: 'jellyfin', name: 'DS918+', address: 'http://192.168.1.20:8096', userId: 'u1', token: 'tok-secret', serverId: 'srv1' });
    assert.ok(s.id);
    assert.ok(!JSON.stringify(mem.get('media')).includes('tok-secret'), 'never plain in electron-store');
    assert.equal(new MediaStore({ store: mem, protect }).source(s.id).token, 'tok-secret');
    store.setAlwaysOriginal(s.id, true);
    store.dropToken(s.id);
    const re = new MediaStore({ store: mem, protect }).source(s.id);
    assert.equal(re.token, null);
    assert.equal(re.alwaysOriginal, true);
    const none = new MediaStore({ store: createMemoryStore(), protect: { available: () => false } });
    assert.throws(() => none.save({ kind: 'smb', name: 'n', address: 'smb://nas/filme', password: 'x' }), { code: 'no_protect' });
    assert.deepEqual(none.sources(), []);
  });

  it('progress of share files: the newest 500, gone with the source; tracks per series; forgetAll', () => {
    const mem = createMemoryStore();
    const store = new MediaStore({ store: mem, protect, now: () => 1000 });
    const smb = store.save({ kind: 'smb', name: 'nas', address: 'smb://nas/filme' });
    store.setProgress(`${smb.id}|a.mkv`, { positionMs: 60000, durationMs: 6000000, at: 10 });
    store.setProgress('other|c.mkv', { positionMs: 1, durationMs: 2, at: 12 });
    assert.deepEqual(store.progress(`${smb.id}|a.mkv`), { positionMs: 60000, durationMs: 6000000, played: false, at: 10 });
    assert.deepEqual(Object.keys(store.all(`${smb.id}|`)), [`${smb.id}|a.mkv`]);
    for (let i = 0; i < MediaStore.MAX_PROGRESS; i++) store.setProgress(`x|${i}`, { positionMs: 1, at: 100 + i });
    assert.equal(store.progress(`${smb.id}|a.mkv`), null, 'the oldest went first');
    assert.equal(Object.keys(store.all('')).length, MediaStore.MAX_PROGRESS);
    store.setProgress('__proto__', { positionMs: 1 });
    assert.equal(({}).p, undefined);
    store.setTrackChoice('s9', { audioLanguage: 'ger', subtitleLanguage: null, subtitlesOff: true });
    assert.deepEqual(new MediaStore({ store: mem, protect }).trackChoice('s9'), { audioLanguage: 'ger', subtitleLanguage: null, subtitlesOff: true });
    assert.equal(store.trackChoice('other'), null);
    assert.equal(store.setQuality('8'), '8');
    assert.equal(store.setQuality('bogus'), 'auto');
    store.forgetAll();
    assert.deepEqual(new MediaStore({ store: mem, protect }).sources(), []);
    assert.equal(mem.get('media'), undefined);
  });
});

const authAnswer = { AccessToken: 'tok-secret', ServerId: 'srv1', User: { Id: 'u1', Name: 'Mila' } };
const serverAnswer = { ServerName: 'DS918+', Version: '10.10.3', Id: 'srv1' };
const movie = { Id: 'm1', Name: 'Kobaltnacht', Type: 'Movie', RunTimeTicks: 64800000000, ImageTags: { Primary: 'p1' }, UserData: { PlaybackPositionTicks: 25300000000 } };

describe('MediaService with a fake Jellyfin', () => {
  let srv;
  let media;
  let mem;
  beforeEach(async () => {
    srv = await createMediaServer().start();
    mem = createMemoryStore();
    media = new MediaService({
      store: new MediaStore({ store: mem, protect }), client: 'GateControl Pro', version: '1.9.2', deviceName: () => 'Büro-PC',
      networkInterfaces: () => ({}), lanRoute: { supported: false, removeHostRoutes: async () => {} },
    });
  });
  afterEach(async () => { await media.close(); await srv.close(); });

  it('Quick Connect of this PC: the code, waiting, signed in — the token never leaves the main process', async () => {
    srv.json(serverAnswer).json({ Secret: 'sec', Code: '482913' });
    const start = await media.quickConnectStart(srv.homeBase);
    assert.equal(start.ok, true);
    assert.equal(start.code, '482913');
    assert.ok(!JSON.stringify(start).includes('sec'));
    srv.json({ Authenticated: false });
    assert.deepEqual(await media.quickConnectPoll(start.flow), { ok: true, state: 'waiting' });
    srv.json({ Authenticated: true }).json(authAnswer);
    const done = await media.quickConnectPoll(start.flow);
    assert.equal(done.state, 'done');
    assert.equal(done.source.userName, 'Mila');
    assert.equal(done.source.signedIn, true);
    const status = media.status();
    assert.equal(status.sources.length, 1);
    assert.ok(!JSON.stringify(status).includes('tok-secret'));
    assert.equal(status.deviceName, 'Büro-PC');
    assert.equal((await media.quickConnectPoll(start.flow)).code, 'not_found', 'a flow once');
    const auth = srv.requests[0].headers.authorization;
    assert.ok(auth.includes('Device="B%C3%BCro-PC"'));
    assert.ok(auth.includes(`DeviceId="${media.store.deviceId()}"`), 'its own device id');
  });

  it('name and password; then rows with gcmedia:// pictures, play, progress, a 401', async () => {
    srv.json(serverAnswer).json(authAnswer);
    const r = await media.signIn({ address: srv.homeBase, user: 'mila', password: 'geheim' });
    assert.equal(r.ok, true);
    const id = r.source.id;
    srv.take();
    assert.equal(JSON.parse(srv.take().body).Pw, 'geheim');
    assert.ok(!JSON.stringify(mem.get('media')).includes('geheim'), 'the password is never kept');

    // the first call finds the way (away: "localhost" is no LAN address here) and measures
    srv.enqueue({ status: 200, body: Buffer.alloc(100000) });
    srv.json({ Items: [movie] });
    const rows = await media.resume(id);
    assert.equal(rows.ok, true);
    assert.equal(srv.take().path, '/Playback/BitrateTest');
    assert.match(rows.items[0].poster, /^gcmedia:\/\/image\/[A-Za-z0-9_-]{24}\/Items\/m1\/Images\/Primary\?maxHeight=450&quality=85&tag=p1$/);
    assert.equal(rows.items[0].resumable, true);
    assert.equal(media.link(id).atHome, false);
    assert.ok(media.link(id).bps > 0);
    srv.take();

    srv.json({ MediaSources: [{ Id: 'v1', SupportsDirectPlay: false, TranscodingSubProtocol: 'hls', TranscodingUrl: '/videos/m1/master.m3u8?MediaSourceId=v1&api_key=tok-secret&TranscodeReasons=AudioCodecNotSupported', MediaStreams: [] }], PlaySessionId: 'ps1' });
    const play = await media.play({ sourceId: id, itemId: 'm1', startMs: 2530000 });
    assert.equal(play.ok, true);
    assert.equal(play.hls, true);
    assert.match(play.url, /^gcmedia:\/\/media\/[A-Za-z0-9_-]{24}\/master\.m3u8\?MediaSourceId=v1&TranscodeReasons=AudioCodecNotSupported$/);
    assert.deepEqual(play.transcodeReasons, ['AudioCodecNotSupported']);
    const body = JSON.parse(srv.take().body);
    assert.ok(body.MaxStreamingBitrate < 200000000, 'away: the measured line decides');
    srv.enqueue({ status: 204 });
    assert.deepEqual(await media.report({ playId: play.playId, event: 'progress', positionMs: 42000, paused: true }), { ok: true });
    const p = srv.take();
    assert.equal(p.path, '/Sessions/Playing/Progress');
    assert.equal(JSON.parse(p.body).PositionTicks, 420000000);
    srv.enqueue({ status: 204 });
    await media.report({ playId: play.playId, event: 'stop', positionMs: 60000 });
    assert.equal(srv.take().path, '/Sessions/Playing/Stopped');
    assert.equal((await media.stream.handleProtocol({ url: play.url, method: 'GET', headers: new Headers() })).status, 404, 'its addresses end with the play');

    srv.json({}, 401);
    assert.equal((await media.latest(id)).code, 'signed_out');
    assert.equal(media.status().sources[0].signedIn, false, 'the access dropped, the source stays');
  });

  it('"Ordner": the libraries of Jellyfin and what one holds, with gcmedia:// pictures', async () => {
    srv.json(serverAnswer).json(authAnswer);
    const { source } = await media.signIn({ address: srv.homeBase, user: 'mila', password: 'x' });
    srv.take(); srv.take();
    srv.enqueue({ status: 200, body: Buffer.alloc(100000) });
    srv.json({ Items: [{ Id: 'v1', Name: 'Filme', Type: 'CollectionFolder', CollectionType: 'movies' }, { Id: 'v2', Name: 'Musik', CollectionType: 'music' }] });
    const libs = await media.libraries(source.id);
    assert.equal(libs.ok, true);
    assert.deepEqual(libs.folders, [{ id: 'v1', name: 'Filme' }]);
    assert.deepEqual(libs.items, []);
    srv.take();
    assert.equal(srv.take().path, '/UserViews');
    srv.json({ Items: [{ Id: 'f1', Name: 'Klassiker', Type: 'Folder', IsFolder: true }, movie], TotalRecordCount: 2 });
    const inside = await media.libraryItems(source.id, 'v1');
    assert.equal(inside.ok, true);
    assert.deepEqual(inside.folders, [{ id: 'f1', name: 'Klassiker' }]);
    assert.equal(inside.items[0].id, 'm1');
    assert.match(inside.items[0].poster, /^gcmedia:\/\/image\//);
    assert.equal(inside.total, 2);
    assert.equal(srv.take().query.get('parentId'), 'v1');
    assert.equal((await media.libraries('nope')).code, 'not_found');
  });

  it('the overview "Ergänzt": Als Nächstes, Neue Folgen, Genres, the heart over the service', async () => {
    srv.json(serverAnswer).json(authAnswer);
    const { source } = await media.signIn({ address: srv.homeBase, user: 'mila', password: 'x' });
    srv.take(); srv.take();
    srv.enqueue({ status: 200, body: Buffer.alloc(100000) });
    srv.json({ Items: [{ Id: 'e5', Name: 'Folge 5', Type: 'Episode', SeriesId: 's9', SeriesName: 'Graufeld', ParentIndexNumber: 1, IndexNumber: 5 }], TotalRecordCount: 4 });
    const next = await media.nextUp(source.id, 8);
    assert.equal(next.ok, true);
    assert.equal(next.total, 4);
    assert.equal(next.items[0].seriesName, 'Graufeld');
    srv.take();
    assert.equal(srv.take().path, '/Shows/NextUp');
    srv.json([{ Id: 's9', Name: 'Graufeld', Type: 'Series', ChildCount: 3, ImageTags: { Primary: 'p' } }]);
    const eps = await media.latestEpisodes(source.id);
    assert.equal(eps.items[0].newCount, 3);
    assert.match(eps.items[0].poster, /^gcmedia:\/\/image\//);
    srv.take();
    srv.json({ Items: [{ Name: 'Drama' }, { Name: 'Krimi' }] });
    assert.deepEqual(await media.genres(source.id, true), { ok: true, genres: ['Drama', 'Krimi'] });
    srv.take();
    srv.json({ IsFavorite: true });
    assert.deepEqual(await media.setFavorite(source.id, 'm1', true), { ok: true, favorite: true });
    assert.equal(srv.take().path, '/UserFavoriteItems/m1');
    assert.equal((await media.setFavorite('nope', 'm1', true)).code, 'not_found');
  });

  it('"Gerät anmelden" confirms the code of the TV; Abmelden signs this device out', async () => {
    srv.json(serverAnswer).json(authAnswer);
    const { source } = await media.signIn({ address: srv.homeBase, user: 'mila', password: 'x' });
    srv.take(); srv.take();
    srv.enqueue({ status: 200, body: Buffer.alloc(1000) });
    await media.check(source.id);
    srv.take();
    srv.json(true);
    assert.deepEqual(await media.authorizeDevice({ sourceId: source.id, code: '731 205' }), { ok: true });
    assert.equal(srv.take().query.get('code'), '731205');
    srv.enqueue({ status: 204 });
    assert.deepEqual(await media.removeSource(source.id), { ok: true });
    assert.equal(srv.take().path, '/Sessions/Logout');
    assert.deepEqual(media.status().sources, []);
  });

  it('an old Jellyfin, an address that is none', async () => {
    srv.json({ ServerName: 'Alt', Version: '10.8.13', Id: 'srv2' });
    assert.equal((await media.server(srv.homeBase)).code, 'unsupported_version');
    assert.equal((await media.server('http://media.example.test')).code, 'invalid');
    srv.json(serverAnswer).json(true);
    const s = await media.server(srv.homeBase);
    assert.equal(s.ok, true);
    assert.equal(s.quickConnect, true);
  });
});

describe('MediaService with shares', () => {
  let dir;
  let media;
  let wnetAnswer;
  let routeCalls;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-media-svc-'));
    fs.writeFileSync(path.join(dir, 'Kobaltnacht (2025).mp4'), Buffer.alloc(4096));
    fs.mkdirSync(path.join(dir, 'Serien'));
    wnetAnswer = 0;
    routeCalls = [];
    const net = new MediaNet();
    net.reachable = async () => true;
    media = new MediaService({
      store: new MediaStore({ store: createMemoryStore(), protect }),
      networkInterfaces: () => ({ Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }] }),
      net,
      lanRoute: {
        supported: true,
        diagnose: () => ({ supported: true, tunnel: true, bindingHolds: true }),
        ensureHostRoute: async (nas, lan) => { routeCalls.push([nas, lan]); return { ok: true, added: true }; },
        removeHostRoutes: async () => { routeCalls.push(['removed']); },
      },
      shares: {
        smb: (source) => new SmbShare({ source, wnet: { add: () => wnetAnswer, cancel: () => 0 }, localRoot: dir }),
        webdav: (source) => ({ kind: 'webdav', source, check: async () => ({ ok: true, value: true }), close: async () => {} }),
      },
    });
  });
  afterEach(async () => { await media.close(); fs.rmSync(dir, { recursive: true, force: true }); });

  it('SMB error 1219 → smb_conflict; with the Explorer\'s access it is kept', async () => {
    wnetAnswer = 1219;
    const r = await media.addShare({ kind: 'smb', address: '\\\\192.168.1.20\\filme', user: 'medien-lesen', password: 'pw' });
    assert.deepEqual(r, { ok: false, code: 'smb_conflict', address: 'smb://192.168.1.20/filme', winError: 1219 });
    const ok = await media.addShare({ kind: 'smb', address: '\\\\192.168.1.20\\filme', user: 'medien-lesen', password: 'pw', useExisting: true });
    assert.equal(ok.ok, true);
    assert.equal(ok.source.unc, '\\\\192.168.1.20\\filme');
    assert.equal(ok.source.useExisting, true);
    assert.equal(ok.source.hasPassword, true);
    assert.ok(!JSON.stringify(ok).includes('"pw"'));
  });

  it('SMB and WebDAV of one folder are one; at home over SMB, bound to the LAN, the host route set', async () => {
    const smb = (await media.addShare({ kind: 'smb', address: '\\\\192.168.1.20\\filme', user: 'kino', password: 'pw' })).source;
    const dav = (await media.addShare({ kind: 'webdav', address: 'https://192.168.1.20:5006/filme', user: 'kino', password: 'pw' })).source;
    assert.equal(dav.pairWith, smb.id);
    assert.deepEqual(media.status().sources.map((s) => s.kind), ['smb'], 'a pair once');
    const c = await media.check(smb.id);
    assert.deepEqual(c.link.route, { tunnel: true, bindingHolds: true, hostRoute: true, hostRouteFailed: false });
    assert.equal(c.link.atHome, true);
    assert.equal(c.link.localAddress, '192.168.1.37');
    assert.deepEqual(routeCalls, [['192.168.1.20', '192.168.1.37']]);
    const list = await media.shareList({ sourceId: smb.id });
    assert.equal(list.via, 'smb');
    assert.deepEqual(list.items.map((e) => [e.name, e.directory]), [['Serien', true], ['Kobaltnacht (2025).mp4', false]]);
    const open = await media.shareOpen({ sourceId: smb.id, path: 'Kobaltnacht (2025).mp4' });
    assert.equal(open.ok, true);
    assert.match(open.url, /^gcmedia:\/\/media\/[A-Za-z0-9_-]{24}\/Kobaltnacht%20\(2025\)\.mp4$/);
    assert.equal(open.size, 4096);
    assert.equal(open.check.verdict, 'unknown', 'zeros: nothing to read from');
    await media.report({ playId: open.playId, event: 'stop', positionMs: 30000, durationMs: 100000 });
    const again = await media.shareList({ sourceId: smb.id });
    assert.equal(again.items[1].progress.positionMs, 30000, 'the progress of a share on this PC');
    await media.close();
    assert.deepEqual(routeCalls[routeCalls.length - 1], ['removed']);
  });
});
