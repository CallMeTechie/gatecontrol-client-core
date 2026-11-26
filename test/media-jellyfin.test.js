'use strict';

// Medien (Stufe 4e): the Jellyfin client against a fake server — the cases of Android's JellyfinLibraryTest and
// JellyfinSignInTest: the rows, the details, how a title is played, the progress, Quick Connect (also confirming the
// code of another device), the bandwidth; plus the LAN binding (localAddress) and the server search over UDP.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');

const J = require('../src/utils/media-jellyfin');
const MediaNet = require('../src/services/media-net');
const MediaDiscovery = require('../src/services/media-discovery');
const { JellyfinClient, JellyfinLibrary, JellyfinSignIn } = require('../src/services/media-jellyfin');
const { createMediaServer } = require('./fixtures/media-server');

const info = { client: 'GateControl Pro', device: 'Büro-PC', deviceId: 'dev-1234', version: '1.9.2' };

const movie = {
  Id: 'm1', Name: 'Kobaltnacht', Type: 'Movie', ProductionYear: 2025, RunTimeTicks: 64800000000,
  UserData: { PlaybackPositionTicks: 25300000000, Played: false }, ImageTags: { Primary: 'p1' },
  BackdropImageTags: ['b1'], Genres: ['Drama'], OfficialRating: 'FSK-12', DateCreated: '2026-11-20T18:00:00.0000000Z',
};
const episode = {
  Id: 'e4', Name: 'Folge 4', Type: 'Episode', SeriesId: 's9', SeriesName: 'Station Eisvogel', SeasonId: 'se2',
  ParentIndexNumber: 2, IndexNumber: 4, RunTimeTicks: 27000000000, UserData: { PlaybackPositionTicks: 16200000000 },
  SeriesPrimaryImageTag: 'sp', ParentBackdropItemId: 's9', ParentBackdropImageTags: ['sb'],
};
const version = {
  Id: 'v1', Container: 'mkv', Bitrate: 52000000, RunTimeTicks: 64800000000, SupportsDirectPlay: true, SupportsDirectStream: true,
  SupportsTranscoding: true, DefaultAudioStreamIndex: 1,
  MediaStreams: [
    { Index: 0, Type: 'Video', Codec: 'hevc', Width: 3840, Height: 2160, VideoRange: 'HDR', VideoRangeType: 'HDR10' },
    { Index: 1, Type: 'Audio', Codec: 'dts', Language: 'ger', Channels: 6, IsDefault: true },
    { Index: 2, Type: 'Audio', Codec: 'truehd', Language: 'eng', Channels: 8 },
    { Index: 3, Type: 'Subtitle', Codec: 'subrip', Language: 'ger', IsTextSubtitleStream: true, IsExternal: true, DeliveryMethod: 'External', DeliveryUrl: '/Videos/m1/v1/Subtitles/3/0/Stream.vtt' },
    { Index: 4, Type: 'Subtitle', Codec: 'PGSSUB', Language: 'eng', IsTextSubtitleStream: false },
  ],
};

describe('JellyfinLibrary against a fake server', () => {
  let srv;
  let net;
  let library;
  beforeEach(async () => {
    srv = await createMediaServer().start();
    net = new MediaNet();
    const source = { id: 's1', kind: 'jellyfin', name: 'DS918+', address: srv.base, userId: 'u1', token: 'tok-secret' };
    library = new JellyfinLibrary({ source, client: new JellyfinClient({ base: srv.base, info, token: 'tok-secret', net }), caps: () => J.capsOf({}) });
  });
  afterEach(async () => { net.reset(); await srv.close(); });

  it('Weiterschauen with the access and the person', async () => {
    srv.json({ Items: [movie, episode, { Id: 'x', Name: 'Album', Type: 'MusicAlbum' }], TotalRecordCount: 3 });
    const r = await library.resume(12);
    assert.ok(r.ok);
    assert.deepEqual(r.value.map((t) => t.id), ['m1', 'e4']);
    const req = srv.take();
    assert.equal(req.path, '/UserItems/Resume');
    assert.equal(req.query.get('userId'), 'u1');
    const auth = req.headers.authorization;
    assert.ok(auth.startsWith('MediaBrowser '), auth);
    assert.ok(auth.includes('Client="GateControl%20Pro"'));
    assert.ok(auth.includes('DeviceId="dev-1234"'));
    assert.ok(auth.includes('Token="tok-secret"'));
    assert.ok(!req.url.includes('tok-secret'), 'the token never in the URL');
  });

  it('Filme A-Z in pages, Zuletzt hinzugefuegt as a bare list', async () => {
    srv.json({ Items: [movie], TotalRecordCount: 412, StartIndex: 40 });
    const page = (await library.movies(40, 1)).value;
    assert.equal(page.total, 412);
    assert.equal(page.next, 41);
    const req = srv.take();
    assert.equal(req.path, '/Items');
    assert.equal(req.query.get('includeItemTypes'), 'Movie');
    assert.equal(req.query.get('sortBy'), 'SortName');
    assert.equal(req.query.get('startIndex'), '40');
    srv.json([movie]);
    assert.equal((await library.latest(16)).value.length, 1);
    assert.equal(srv.take().query.get('includeItemTypes'), 'Movie,Series');
    srv.json({ Items: [], TotalRecordCount: 0 });
    await library.series(0, 60, { sort: 'added', unplayed: true });
    const s = srv.take();
    assert.equal(s.query.get('sortBy'), 'DateCreated,SortName');
    assert.equal(s.query.get('filters'), 'IsUnplayed');
  });

  it('seasons and episodes of a series, search; an id that is a path is refused', async () => {
    srv.json({ Items: [{ Id: 'se2', Name: 'Staffel 2', Type: 'Season', IndexNumber: 2, SeriesId: 's9' }] });
    assert.equal((await library.seasons('s9')).value[0].name, 'Staffel 2');
    assert.equal(srv.take().path, '/Shows/s9/Seasons');
    srv.json({ Items: [episode] });
    assert.equal((await library.episodes('s9', 'se2')).value[0].id, 'e4');
    const r = srv.take();
    assert.equal(r.path, '/Shows/s9/Episodes');
    assert.equal(r.query.get('seasonId'), 'se2');
    srv.json({ Items: [movie] });
    assert.equal((await library.search('kobalt')).value.length, 1);
    assert.equal(srv.take().query.get('searchTerm'), 'kobalt');
    assert.deepEqual(await library.seasons('../Users'), { ok: false, code: 'not_found', status: null });
    assert.equal(srv.requests.length, 3);
  });

  it("the detail page with the file's streams", async () => {
    srv.json({ ...movie, Overview: 'Eine Funkerin …', MediaSources: [version] });
    const d = (await library.detail('m1')).value;
    assert.equal(d.title.overview, 'Eine Funkerin …');
    assert.equal(d.versions[0].container, 'mkv');
    assert.equal(srv.take().path, '/Items/m1');
  });

  it('at home the file itself, with the device profile and the start', async () => {
    srv.json({ MediaSources: [version], PlaySessionId: 'ps1' });
    const plan = (await library.play({ itemId: 'm1', startMs: 2530000, subtitleIndex: 3 })).value;
    assert.equal(plan.method, 'DirectPlay');
    assert.ok(plan.url.includes('/Videos/m1/stream?static=true&mediaSourceId=v1&playSessionId=ps1'), plan.url);
    assert.ok(!plan.url.includes('tok-secret'));
    assert.equal(plan.sideSubtitles[0].url, `${srv.base}/Videos/m1/v1/Subtitles/3/0/Stream.vtt`);
    const req = srv.take();
    assert.equal(req.method, 'POST');
    assert.equal(req.path, '/Items/m1/PlaybackInfo');
    const body = JSON.parse(req.body);
    assert.equal(body.MaxStreamingBitrate, J.ORIGINAL_BPS);
    assert.equal(body.StartTimeTicks, 25300000000);
    assert.equal(body.SubtitleStreamIndex, 3);
    const direct = body.DeviceProfile.DirectPlayProfiles[0];
    assert.ok(!direct.AudioCodec.split(',').includes('dts'), 'Chromium: no DTS');
    assert.equal(body.DeviceProfile.TranscodingProfiles[0].Protocol, 'hls');
  });

  it('away the NAS converts at the bit rate asked for', async () => {
    const converting = {
      ...version, SupportsDirectPlay: false, TranscodingSubProtocol: 'hls',
      TranscodingUrl: '/videos/m1/master.m3u8?MediaSourceId=v1&VideoBitrate=7616000&TranscodeReasons=ContainerBitrateExceedsLimit',
    };
    srv.json({ MediaSources: [converting], PlaySessionId: 'ps2' });
    const plan = (await library.play({ itemId: 'm1', maxBitrate: 8000000 })).value;
    assert.equal(plan.method, 'Transcode');
    assert.ok(plan.hls);
    assert.equal(plan.bitrate, 8000000);
    assert.equal(plan.url.split('?')[0], `${srv.base}/videos/m1/master.m3u8`);
    const body = JSON.parse(srv.take().body);
    assert.equal(body.MaxStreamingBitrate, 8000000);
    assert.equal(body.DeviceProfile.MaxStreamingBitrate, 8000000);
  });

  it('a refused playback and an unknown title', async () => {
    srv.json({ MediaSources: [], ErrorCode: 'NoCompatibleStream' });
    assert.equal((await library.play({ itemId: 'm1' })).code, 'failed');
    srv.json({}, 404);
    assert.equal((await library.detail('zz')).code, 'not_found');
  });

  it('the progress goes to Jellyfin', async () => {
    srv.json({ MediaSources: [version], PlaySessionId: 'ps1' });
    const plan = (await library.play({ itemId: 'm1' })).value;
    srv.take();
    for (let i = 0; i < 3; i++) srv.enqueue({ status: 204 });
    await library.started({ plan, positionMs: 0, paused: false });
    await library.progress({ plan, positionMs: 42000, paused: true });
    await library.stopped({ plan, positionMs: 60000, paused: false });
    assert.equal(srv.take().path, '/Sessions/Playing');
    const progress = srv.take();
    assert.equal(progress.path, '/Sessions/Playing/Progress');
    const p = JSON.parse(progress.body);
    assert.equal(p.PositionTicks, 420000000);
    assert.equal(p.IsPaused, true);
    assert.equal(p.PlayMethod, 'DirectPlay');
    assert.equal(p.PlaySessionId, 'ps1');
    assert.equal(p.MediaSourceId, 'v1');
    const stopped = srv.take();
    assert.equal(stopped.path, '/Sessions/Playing/Stopped');
    assert.equal(JSON.parse(stopped.body).Failed, false);
  });

  it('seen and not seen', async () => {
    srv.json({ Played: true });
    assert.ok((await library.setPlayed('m1', true)).ok);
    const r = srv.take();
    assert.equal(r.method, 'POST');
    assert.equal(r.path, '/UserPlayedItems/m1');
    srv.json({ Played: false });
    await library.setPlayed('m1', false);
    assert.equal(srv.take().method, 'DELETE');
  });

  it('"Gerät anmelden": the code of another device confirmed with this access', async () => {
    srv.json(true);
    assert.deepEqual(await library.authorize('731 205'), { ok: true, value: true });
    const r = srv.take();
    assert.equal(r.method, 'POST');
    assert.equal(r.path, '/QuickConnect/Authorize');
    assert.equal(r.query.get('code'), '731205');
    assert.equal(r.query.get('userId'), 'u1');
    assert.ok(r.headers.authorization.includes('Token="tok-secret"'));
    srv.json(false);
    assert.equal((await library.authorize('731205')).code, 'not_found');
    assert.equal((await library.authorize('12')).code, 'invalid');
  });

  it('signed out, unreachable', async () => {
    srv.json({}, 401);
    assert.equal((await library.resume(12)).code, 'unauthorized');
    await srv.close();
    assert.equal((await library.resume(12)).code, 'offline');
  });

  it('the bandwidth from the server', async () => {
    srv.enqueue({ status: 200, body: Buffer.alloc(200000) });
    const bps = await library.measure();
    assert.ok(bps > 0);
    const r = srv.take();
    assert.equal(r.path, '/Playback/BitrateTest');
    assert.equal(r.query.get('size'), String(J.MEASURE_BYTES));
    srv.json({}, 500);
    assert.equal(await library.measure(), null);
  });
});

describe('JellyfinSignIn', () => {
  let srv;
  let signIn;
  let net;
  beforeEach(async () => {
    srv = await createMediaServer().start();
    net = new MediaNet();
    signIn = new JellyfinSignIn({ client: new JellyfinClient({ base: srv.base, info, net }) });
  });
  afterEach(async () => { net.reset(); await srv.close(); });

  const authAnswer = { AccessToken: 'tok', ServerId: 'srv1', User: { Id: 'u1', Name: 'Anna' } };

  it("the server's public info", async () => {
    srv.json({ ServerName: 'DS918+', Version: '10.10.3', Id: 'srv1', StartupWizardCompleted: true });
    const s = (await signIn.server()).value;
    assert.equal(s.name, 'DS918+');
    assert.ok(s.supported);
    assert.equal(srv.take().path, '/System/Info/Public');
    srv.json({ ServerName: 'Alt', Version: '10.8.13', Id: 'srv2' });
    assert.equal((await signIn.server()).value.supported, false);
    srv.json({ nope: 1 });
    assert.equal((await signIn.server()).code, 'failed');
  });

  it('Quick Connect - code, wait, signed in', async () => {
    srv.json(true);
    assert.ok(await signIn.quickConnectEnabled());
    srv.json({ Secret: 'sec', Code: '482913', Authenticated: false });
    const q = (await signIn.quickConnect()).value;
    assert.equal(q.code, '482913');
    srv.json({ Authenticated: false });
    assert.equal((await signIn.confirmed(q)).value, false);
    srv.json({ Authenticated: true });
    assert.equal((await signIn.confirmed(q)).value, true);
    srv.json(authAnswer);
    const auth = (await signIn.signInQuick(q)).value;
    assert.deepEqual([auth.token, auth.userId, auth.serverId], ['tok', 'u1', 'srv1']);
    srv.take();
    assert.equal(srv.take().method, 'POST');
    assert.equal(srv.take().query.get('secret'), 'sec');
    srv.take();
    const last = srv.take();
    assert.equal(last.path, '/Users/AuthenticateWithQuickConnect');
    assert.equal(JSON.parse(last.body).Secret, 'sec');
    assert.ok(!last.headers.authorization.includes('Token='), 'no token before the sign-in');
  });

  it('Quick Connect switched off on the server', async () => {
    srv.json(false);
    assert.equal(await signIn.quickConnectEnabled(), false);
    srv.json({}, 401);
    assert.equal((await signIn.quickConnect()).code, 'unauthorized');
  });

  it('name and password, a wrong password', async () => {
    srv.json(authAnswer);
    assert.equal((await signIn.signIn('anna', 'geheim')).value.userId, 'u1');
    const body = JSON.parse(srv.take().body);
    assert.equal(body.Username, 'anna');
    assert.equal(body.Pw, 'geheim');
    srv.enqueue({ status: 401, body: '' });
    assert.equal((await signIn.signIn('anna', 'falsch')).code, 'unauthorized');
  });
});

describe('the LAN binding (localAddress) of the connections', () => {
  it('a connection bound to an own address leaves from it (Linux: 127.0.0.2 is loopback too)', { skip: process.platform !== 'linux' ? 'needs 127.0.0.2' : false }, async () => {
    const srv = await createMediaServer().start();
    const net = new MediaNet();
    try {
      const c = new JellyfinClient({ base: srv.base, info, net, way: () => ({ localAddress: '127.0.0.2' }) });
      srv.json({ ServerName: 'DS918+', Version: '10.10.3', Id: 'srv1' });
      assert.ok((await c.get('System/Info/Public')).ok);
      assert.equal(srv.take().remoteAddress.replace(/^::ffff:/, ''), '127.0.0.2');
      const free = new JellyfinClient({ base: srv.base, info, net });
      srv.json({ Id: 'srv1' });
      await free.get('System/Info/Public');
      assert.equal(srv.take().remoteAddress.replace(/^::ffff:/, ''), '127.0.0.1');
      assert.ok(await net.reachable('127.0.0.1', srv.port, { localAddress: '127.0.0.2' }));
      await srv.close();
      assert.equal(await net.reachable('127.0.0.1', srv.port), false);
    } finally {
      net.reset();
      await srv.close();
    }
  });
});

describe('MediaDiscovery', () => {
  it('a search finds the server once, ignores anything else', async () => {
    const fake = dgram.createSocket('udp4');
    await new Promise((r) => fake.bind(0, '127.0.0.1', r));
    const questions = [];
    fake.on('message', (msg, rinfo) => {
      questions.push(msg.toString());
      const answer = Buffer.from(JSON.stringify({ Address: 'http://192.168.1.20:8096', Id: 'a1', Name: 'DS918+' }));
      // the same server answers twice (two networks), and something else answers too
      fake.send(answer, rinfo.port, rinfo.address);
      fake.send(answer, rinfo.port, rinfo.address);
      fake.send(Buffer.from('hello'), rinfo.port, rinfo.address);
    });
    const d = new MediaDiscovery();
    const found = await d.discover({ ways: [{ bind: '127.0.0.1', targets: ['127.0.0.1', '127.0.0.1'] }], port: fake.address().port, timeoutMs: 400 });
    fake.close();
    assert.deepEqual(questions, ['who is JellyfinServer?']);
    assert.deepEqual(found.map((s) => s.name), ['DS918+']);
  });

  it('asks only over the real adapters, never the VPN', () => {
    const d = new MediaDiscovery({
      networkInterfaces: () => ({
        Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }],
        gatecontrol0: [{ address: '10.8.0.2', family: 'IPv4', internal: false, cidr: '10.8.0.2/24' }],
        'vEthernet (WSL)': [{ address: '172.20.0.1', family: 'IPv4', internal: false, cidr: '172.20.0.1/20' }],
        'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
      }),
    });
    assert.deepEqual(d.plan(), [{ bind: '192.168.1.37', targets: ['192.168.1.255', '255.255.255.255'] }]);
  });
});
