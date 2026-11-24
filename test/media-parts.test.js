'use strict';

// Medien (Stufe 4e): the pure parts — the same cases as Android's :core:media tests (MediaPartsTest,
// MediaQualityTest, JellyfinDiscoveryTest), adapted where the PC differs (no AV receiver: DTS/TrueHD never direct).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const MA = require('../src/utils/media-address');
const J = require('../src/utils/media-jellyfin');
const MQ = require('../src/utils/media-quality');
const MT = require('../src/utils/media-tracks');
const MS = require('../src/utils/media-sources');

describe('media-address', () => {
  it('addresses of the home network', () => {
    assert.equal(MA.normalize('192.168.1.20'), 'http://192.168.1.20:8096');
    assert.equal(MA.normalize(' 192.168.1.20:8096/ '), 'http://192.168.1.20:8096');
    assert.equal(MA.normalize('http://nas.local:8096/jellyfin'), 'http://nas.local:8096/jellyfin');
    assert.equal(MA.normalize('nas'), 'http://nas:8096');
    assert.equal(MA.normalize('https://media.example.test'), 'https://media.example.test');
    // plain HTTP only in the home network: the token never goes unencrypted over the internet
    assert.equal(MA.normalize('http://media.example.test:8096'), null);
    assert.equal(MA.normalize('8.8.8.8:8096'), null);
    assert.equal(MA.normalize('http://user:pw@192.168.1.20:8096'), null);
    assert.equal(MA.normalize('192.168.1.20:8096?x=1'), null);
    assert.equal(MA.normalize(''), null);
    assert.equal(MA.normalize('nas filme'), null);
    assert.equal(MA.isHomeHost('172.20.1.1'), true);
    assert.equal(MA.isHomeHost('172.32.1.1'), false);
  });

  it('SMB and WebDAV shares as typed', () => {
    const s = MA.parseSmb('\\\\nas\\filme\\Neu');
    assert.equal(s.url, 'smb://nas/filme/Neu');
    assert.equal(s.unc, '\\\\nas\\filme\\Neu');
    assert.equal(MA.parseSmb('smb://192.168.1.20/filme').unc, '\\\\192.168.1.20\\filme');
    assert.equal(MA.parseSmb('nas/filme').url, 'smb://nas/filme');
    assert.equal(MA.parseSmb('\\\\media.example.test\\filme'), null, 'SMB never over the internet');
    assert.equal(MA.parseSmb('\\\\nas'), null);
    assert.equal(MA.parseSmb('\\\\nas\\filme\\..\\x'), null);
    assert.equal(MA.parseSmb('\\\\nas\\fil:me'), null);
    assert.equal(MA.normalizeWebDav('192.168.1.20:5006/filme'), 'https://192.168.1.20:5006/filme');
    assert.equal(MA.normalizeWebDav('http://dav.example.test/filme'), null);
    assert.equal(MA.folderName('smb', 'smb://nas/Filme'), 'filme');
    assert.equal(MA.folderName('webdav', 'https://192.168.1.20:5006/Filme'), 'filme');
    assert.equal(MA.portOf('webdav', 'https://192.168.1.20/filme'), 443);
    assert.equal(MA.portOf('smb', 'smb://nas/filme'), 445);
  });
});

describe('media-jellyfin: the device profile of Chromium', () => {
  it('DTS and TrueHD never, AC3 only when Chromium says so, HEVC only with the hardware decoder', () => {
    const plain = J.directAudio(J.capsOf({}));
    assert.ok(!plain.includes('dts') && !plain.includes('truehd') && !plain.includes('ac3'));
    assert.deepEqual(plain, ['aac', 'mp3', 'opus', 'flac']);
    assert.ok(J.directAudio(J.capsOf({ ac3: true, eac3: true })).includes('eac3'));
    const p = J.profile(J.capsOf({ hevc: false }), 8000000);
    assert.equal(p.MaxStreamingBitrate, 8000000);
    const mp4 = p.DirectPlayProfiles[0];
    assert.equal(mp4.Container, 'mp4,m4v,mov');
    assert.ok(!mp4.VideoCodec.includes('hevc'));
    assert.ok(mp4.VideoCodec.split(',').includes('h264'));
    assert.ok(J.profile(J.capsOf({ hevc: true }), 1).DirectPlayProfiles[0].VideoCodec.includes('hevc'));
    // no Matroska unless the page's Chromium plays it (then Jellyfin only remuxes)
    assert.ok(!p.DirectPlayProfiles.some((d) => d.Container.includes('mkv')));
    assert.ok(J.profile(J.capsOf({ mkv: true }), 1).DirectPlayProfiles.some((d) => d.Container === 'mkv'));
    const t = p.TranscodingProfiles[0];
    assert.equal(t.Protocol, 'hls');
    assert.equal(t.Container, 'mp4', 'HLS in fMP4 for hls.js');
    assert.equal(t.AudioCodec.split(',')[0], 'aac');
    assert.equal(t.MaxAudioChannels, '6');
    const subs = p.SubtitleProfiles.map((x) => `${x.Format}:${x.Method}`);
    assert.ok(subs.includes('vtt:External'));
    assert.ok(subs.includes('pgssub:Encode'));
    // an SDR screen: HDR tone-mapped on the NAS
    assert.equal(J.profile(J.capsOf({ hdr: true }), 1).CodecProfiles.length, 0);
    assert.equal(J.profile(J.capsOf({ hdr: false }), 1).CodecProfiles.length, 1);
  });

  it('capsOf takes only true, keeps the channels in 2..8, the name plain', () => {
    const c = J.capsOf({ hevc: 'yes', av1: false, maxAudioChannels: 12, mkv: true }, 'Büro-PC\u0007');
    assert.equal(c.hevc, false);
    assert.equal(c.av1, false);
    assert.equal(c.mkv, true);
    assert.equal(c.maxAudioChannels, 8);
    assert.equal(c.name, 'Büro-PC');
  });

  it('the header of every call: who asks, the token never in a URL', () => {
    const h = J.authorization({ client: 'GateControl Pro', device: 'Büro "PC", 2', deviceId: 'dev-1234', version: '1.0.0' }, 'tok-secret');
    assert.ok(h.startsWith('MediaBrowser '));
    assert.ok(h.includes('Client="GateControl Pro"'));
    assert.ok(h.includes('Device="Büro PC  2"'));
    assert.ok(h.includes('DeviceId="dev-1234"'));
    assert.ok(h.includes('Token="tok-secret"'));
    assert.ok(!J.authorization({ client: 'x', device: 'y', deviceId: 'z', version: '1' }).includes('Token'));
  });

  it("a server's URLs stay on the server", () => {
    const base = 'http://192.168.1.20:8096/jellyfin';
    assert.equal(J.absolute(base, '/videos/m1/master.m3u8?a=1'), 'http://192.168.1.20:8096/jellyfin/videos/m1/master.m3u8?a=1');
    assert.equal(J.absolute(base, '/jellyfin/videos/m1/master.m3u8'), 'http://192.168.1.20:8096/jellyfin/videos/m1/master.m3u8');
    // another host: only its path and query, the access never leaves for it
    assert.equal(J.absolute(base, 'http://media.example.test/x/y?z=1'), 'http://192.168.1.20:8096/jellyfin/x/y?z=1');
    assert.equal(J.url(base, 'Items/m1/Images/Primary', { maxHeight: 300, tag: null }), 'http://192.168.1.20:8096/jellyfin/Items/m1/Images/Primary?maxHeight=300');
  });

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

  it("titles: Weiterschauen, an episode with its series' pictures, music left out", () => {
    const items = J.items({ Items: [movie, episode, { Id: 'x', Name: 'Album', Type: 'MusicAlbum' }] }, 's1');
    assert.deepEqual(items.map((t) => t.id), ['m1', 'e4']);
    const m = items[0];
    assert.equal(m.kind, 'movie');
    assert.equal(m.year, 2025);
    assert.equal(m.runtimeMs, 6480000);
    assert.equal(m.positionMs, 2530000);
    assert.ok(J.resumable(m));
    assert.equal(J.leftMs(m), 3950000);
    assert.deepEqual([m.posterId, m.posterTag], ['m1', 'p1']);
    assert.equal(m.rating, 'FSK-12');
    assert.ok(m.addedAt > 0);
    const e = items[1];
    assert.deepEqual([e.posterId, e.posterTag], ['s9', 'sp']);
    assert.deepEqual([e.backdropId, e.backdropTag], ['s9', 'sb']);
    assert.deepEqual([e.season, e.episode], [2, 4]);
    assert.equal(J.items([movie], 's1').length, 1, 'a bare list (Items/Latest)');
    const t = { runtimeMs: 100000, positionMs: 25000, played: false, kind: 'movie' };
    assert.equal(J.progressOf(t), 0.25);
    assert.ok(J.playable(t));
    assert.ok(!J.resumable({ ...t, played: true }));
    assert.equal(J.nextOf({ items: [t], total: 1, start: 0 }), null);
    assert.equal(J.nextOf({ items: [t], total: 5, start: 0 }), 1);
    assert.equal(J.imagePath(m, false, 300), 'Items/m1/Images/Primary?maxHeight=300&quality=85&tag=p1');
    assert.equal(J.imagePath({ ...m, backdropId: null }, true, 540), null);
  });

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

  it("the detail's version with the file's streams", () => {
    const v = J.version(version);
    assert.equal(v.container, 'mkv');
    assert.equal(v.bitrate, 52000000);
    assert.equal(MQ.videoLabel(J.videoOf(v)), '4K HDR10');
    assert.deepEqual(J.audioOf(v).map((s) => s.index), [1, 2]);
    assert.ok(J.subtitlesOf(v)[1].picture);
    assert.equal(J.subtitlesOf(v)[1].codec, 'pgssub');
  });

  it('at home the file itself, with the device profile and the start', () => {
    const body = J.playbackBody({ itemId: 'm1', startMs: 2530000, subtitleIndex: 3 }, J.capsOf({}), 'u1');
    assert.equal(body.MaxStreamingBitrate, J.ORIGINAL_BPS);
    assert.equal(body.StartTimeTicks, 25300000000);
    assert.equal(body.SubtitleStreamIndex, 3);
    assert.equal(body.DeviceProfile.TranscodingProfiles[0].Protocol, 'hls');
    const plan = J.plan('http://192.168.1.20:8096', { itemId: 'm1', subtitleIndex: 3 }, J.version(version), 'ps1', 'dev-1234');
    assert.equal(plan.method, 'DirectPlay');
    assert.equal(plan.converted, false);
    assert.equal(plan.hls, false);
    assert.ok(plan.url.includes('/Videos/m1/stream?static=true&mediaSourceId=v1&playSessionId=ps1'), plan.url);
    assert.equal(plan.audioIndex, 1);
    assert.equal(plan.subtitleIndex, 3);
    const side = plan.sideSubtitles[0];
    assert.equal(side.mime, 'text/vtt');
    assert.equal(side.url, 'http://192.168.1.20:8096/Videos/m1/v1/Subtitles/3/0/Stream.vtt');
  });

  it('away the NAS converts at the bit rate asked for; only the container: DirectStream', () => {
    const converting = {
      ...version, SupportsDirectPlay: false, TranscodingSubProtocol: 'hls',
      TranscodingUrl: '/videos/m1/master.m3u8?MediaSourceId=v1&VideoBitrate=7616000&api_key=tok&TranscodeReasons=ContainerBitrateExceedsLimit,AudioCodecNotSupported',
    };
    const plan = J.plan('http://192.168.1.20:8096', { itemId: 'm1', maxBitrate: 8000000 }, J.version(converting), 'ps2', 'd');
    assert.equal(plan.method, 'Transcode');
    assert.ok(plan.converted && plan.hls);
    assert.equal(plan.bitrate, 8000000);
    assert.equal(plan.url.split('?')[0], 'http://192.168.1.20:8096/videos/m1/master.m3u8');
    assert.deepEqual(plan.version.transcodeReasons, ['ContainerBitrateExceedsLimit', 'AudioCodecNotSupported']);
    const remux = { ...converting, TranscodingUrl: '/videos/m1/master.m3u8?TranscodeReasons=ContainerNotSupported' };
    assert.equal(J.plan('http://192.168.1.20:8096', { itemId: 'm1' }, J.version(remux), null, 'd').method, 'DirectStream');
    assert.equal(J.plan('http://x:1', { itemId: 'm1' }, J.version({ Id: 'v', SupportsDirectPlay: false }), null, 'd'), null);
  });

  it('the progress body', () => {
    const plan = J.plan('http://192.168.1.20:8096', { itemId: 'm1' }, J.version(version), 'ps1', 'd');
    const p = J.progressBody({ plan, positionMs: 42000, paused: true });
    assert.equal(p.PositionTicks, 420000000);
    assert.equal(p.IsPaused, true);
    assert.equal(p.PlayMethod, 'DirectPlay');
    assert.equal(p.PlaySessionId, 'ps1');
    assert.equal(p.MediaSourceId, 'v1');
    assert.equal(p.SubtitleStreamIndex, J.SUBTITLES_OFF);
    assert.equal(J.progressBody({ plan, positionMs: 1, paused: false }, true).Failed, false);
  });

  it('the answers of a sign-in and Quick Connect, the code of another device', () => {
    assert.deepEqual(J.auth({ AccessToken: 'tok', ServerId: 'srv1', User: { Id: 'u1', Name: 'Anna' } }), { token: 'tok', userId: 'u1', userName: 'Anna', serverId: 'srv1' });
    assert.equal(J.auth({ AccessToken: 'tok' }), null);
    assert.deepEqual(J.quickConnect({ Secret: 'sec', Code: '482913' }), { code: '482913', secret: 'sec' });
    const s = J.serverInfo({ ServerName: 'DS918+', Version: '10.10.3', Id: 'srv1' });
    assert.equal(s.supported, true);
    assert.equal(J.serverInfo({ ServerName: 'Alt', Version: '10.8.13', Id: 'srv2' }).supported, false);
    assert.equal(J.serverInfo({ nope: 1 }), null);
    assert.equal(J.quickConnectCode('482 913'), '482913');
    assert.equal(J.quickConnectCode('48291'), null);
    assert.equal(J.quickConnectCode('48291a'), null);
  });
});

describe('media-jellyfin: the server search', () => {
  it('an answer of a server in the home network', () => {
    assert.deepEqual(J.parseDiscovery('{"Address":"http://192.168.1.20:8096","Id":"a1b2c3","Name":"DS918+","EndpointAddress":null}'),
      { address: 'http://192.168.1.20:8096', id: 'a1b2c3', name: 'DS918+' });
  });

  it('a server naming its public address is taken where it answered from', () => {
    assert.equal(J.parseDiscovery('{"Address":"https://media.example.test","Id":"a1","Name":"NAS"}', '192.168.1.20').address, 'http://192.168.1.20:8096');
    assert.equal(J.parseDiscovery('{"Address":"https://media.example.test","Id":"a1","Name":"NAS"}', '203.0.113.5'), null);
  });

  it('no answer from anything else', () => {
    assert.equal(J.parseDiscovery('who is JellyfinServer?'), null);
    assert.equal(J.parseDiscovery('[1,2]'), null);
    assert.equal(J.parseDiscovery('{"Address":"http://192.168.1.20:8096","Name":"no id"}'), null);
    assert.equal(J.parseDiscovery('{"Address":"http://192.168.1.20:8096","Id":"bad id; drop","Name":"x"}'), null);
    assert.equal(J.parseDiscovery('x'.repeat(5000)), null);
  });

  it('a long name is cut, control characters are dropped', () => {
    const hint = J.parseDiscovery(JSON.stringify({ Address: 'http://nas.local:8096', Id: 'a1', Name: `N\u0007AS${'x'.repeat(100)}` }));
    assert.equal(hint.name.length, 64);
    assert.equal(hint.name.slice(0, 3), 'NAS');
    assert.equal(hint.address, 'http://nas.local:8096');
  });

  it('the broadcast address of a home network', () => {
    assert.equal(J.broadcastOf('192.168.1.37', 24), '192.168.1.255');
    assert.equal(J.broadcastOf('10.0.3.4', 16), '10.0.255.255');
    assert.equal(J.broadcastOf('192.168.0.100', 25), '192.168.0.127');
    assert.equal(J.broadcastOf('8.8.8.8', 24), null);
    assert.equal(J.broadcastOf('192.168.1.37', 32), null);
  });
});

describe('media-quality (decision 10)', () => {
  const original = MQ.ORIGINAL_BPS;
  it('at home always the original', () => {
    assert.equal(MQ.cap({ atHome: true, measuredBps: 5000000, originalBps: 52000000 }), original);
    const o = MQ.offer({ atHome: true, measuredBps: null, originalBps: 52000000 });
    assert.ok(o.originalFits);
    assert.equal(o.adaptedBps, null);
    assert.equal(o.suggestAdapted, false);
  });
  it('away 4K over 18 Mbit/s - the NAS converts to 8', () => {
    assert.equal(MQ.cap({ atHome: false, measuredBps: 18000000, originalBps: 52000000 }), 8000000);
    const o = MQ.offer({ atHome: false, measuredBps: 18000000, originalBps: 52000000 });
    assert.equal(o.originalFits, false);
    assert.equal(o.adaptedBps, 8000000);
    assert.ok(o.suggestAdapted);
    assert.equal(MQ.resolution(8000000), '1080p');
  });
  it('away a small file goes as it is', () => {
    assert.equal(MQ.cap({ atHome: false, measuredBps: 40000000, originalBps: 9000000 }), original);
    const o = MQ.offer({ atHome: false, measuredBps: 40000000, originalBps: 9000000 });
    assert.ok(o.originalFits);
    assert.equal(o.adaptedBps, null);
  });
  it('immer Original and a fixed step', () => {
    assert.equal(MQ.cap({ atHome: false, measuredBps: 3000000, originalBps: 52000000, alwaysOriginal: true }), original);
    assert.equal(MQ.cap({ setting: 'original', atHome: false, measuredBps: 3000000, originalBps: 52000000 }), original);
    assert.equal(MQ.cap({ setting: '4', atHome: true, originalBps: 52000000 }), 4000000);
    assert.equal(MQ.offer({ atHome: false, measuredBps: 18000000, originalBps: 52000000, alwaysOriginal: true }).suggestAdapted, false);
  });
  it('a share cannot convert', () => {
    assert.equal(MQ.cap({ setting: '2', atHome: false, measuredBps: 1000000, originalBps: 52000000, canConvert: false }), original);
    assert.equal(MQ.offer({ atHome: false, measuredBps: 1000000, originalBps: 52000000, canConvert: false }).adaptedBps, null);
  });
  it('away without a measurement a careful start', () => {
    assert.equal(MQ.cap({ atHome: false, originalBps: 52000000 }), MQ.UNMEASURED_BPS);
    assert.equal(MQ.cap({ atHome: false }), MQ.UNMEASURED_BPS);
    assert.equal(MQ.cap({ atHome: false, originalBps: 3000000 }), original);
    assert.ok(MQ.offer({ atHome: false, originalBps: 52000000 }).suggestAdapted);
  });
  it('the steps of the ladder', () => {
    assert.equal(MQ.step(100000000), 20000000);
    assert.equal(MQ.step(25000000), 12000000);
    assert.equal(MQ.step(7000000), 4000000);
    assert.equal(MQ.step(500000), 1000000);
    assert.equal(MQ.fits(null, 100000000), false);
  });
  it('labels', () => {
    assert.equal(MQ.label(18400000), '18 Mbit/s');
    assert.equal(MQ.label(8000000), '8 Mbit/s');
    assert.equal(MQ.label(2500000), '2,5 Mbit/s');
    assert.equal(MQ.label(2500000, 'en'), '2.5 Mbit/s');
    assert.equal(MQ.label(800000), '800 kbit/s');
    assert.equal(MQ.resolution(4000000), '720p');
    assert.equal(MQ.resolution(1000000), '480p');
    assert.equal(MQ.videoLabel({ width: 1920, height: 800 }), '1080p');
    assert.equal(MQ.videoLabel({ height: 2160, videoRangeType: 'DOVIWithHDR10' }), '4K Dolby Vision');
    assert.equal(MQ.hdrLabel({ height: 1080, videoRange: 'SDR', videoRangeType: 'SDR' }), null);
    assert.equal(MQ.settingOf('8'), '8');
    assert.equal(MQ.settingOf('bogus'), 'auto');
  });
});

describe('media-tracks', () => {
  const v = J.version({
    Id: 'v1', DefaultAudioStreamIndex: 1,
    MediaStreams: [
      { Index: 0, Type: 'Video', Codec: 'hevc' },
      { Index: 1, Type: 'Audio', Codec: 'dts', Language: 'ger', Channels: 6, IsDefault: true },
      { Index: 2, Type: 'Audio', Codec: 'truehd', Language: 'eng', Channels: 8 },
      { Index: 3, Type: 'Audio', Codec: 'aac', Language: 'ger', Channels: 2 },
      { Index: 4, Type: 'Subtitle', Codec: 'subrip', Language: 'ger', IsTextSubtitleStream: true, IsForced: true },
      { Index: 5, Type: 'Subtitle', Codec: 'subrip', Language: 'ger', IsTextSubtitleStream: true },
      { Index: 6, Type: 'Subtitle', Codec: 'subrip', Language: 'eng', IsTextSubtitleStream: true, IsExternal: true },
    ],
  });

  it('sound and subtitles - labels, fate on the PC, remembered per series', () => {
    assert.equal(MT.languageName('ger', 'de'), 'Deutsch');
    assert.equal(MT.languageName('deu', 'de'), 'Deutsch');
    assert.equal(MT.languageName('eng', 'en'), 'English');
    assert.equal(MT.languageName('und'), null);
    assert.equal(MT.languageName('qqq'), null);
    const audio = J.audioOf(v);
    assert.equal(MT.audioLabel(audio[0]), 'DTS 5.1');
    assert.equal(MT.audioLabel(audio[1]), 'TrueHD 7.1');
    // no AV receiver on a PC: DTS and TrueHD are converted, AAC played
    assert.equal(MT.fate(audio[0]), 'converted');
    assert.equal(MT.fate(audio[1]), 'converted');
    assert.equal(MT.fate(audio[2]), 'decoded');
    assert.equal(MT.pickAudio(v, null), 1);
    assert.equal(MT.pickAudio(v, { audioLanguage: 'eng' }), 2);
    assert.equal(MT.pickSubtitle(v, null), null);
    assert.equal(MT.pickSubtitle(v, { subtitlesOff: true }), J.SUBTITLES_OFF);
    assert.equal(MT.pickSubtitle(v, { audioLanguage: 'ger', subtitleLanguage: 'ger' }), 5, 'not the forced one');
    assert.deepEqual(MT.choiceOf(v, 2, 6), { audioLanguage: 'eng', subtitleLanguage: 'eng', subtitlesOff: false });
    assert.equal(MT.ordinal(v, 2), 1);
    assert.equal(MT.ordinal(v, 4), 0);
    assert.equal(MT.ordinal(v, 6), null);
    assert.equal(MT.ordinal(v, 99), null);
  });
});

describe('media-sources', () => {
  it('kept, replaced when signed in again, the token never in the public view', () => {
    let list = [];
    const a = { id: 'a', kind: 'jellyfin', name: 'DS918+', address: 'http://192.168.1.20:8096', userId: 'u1', userName: 'Anna', token: 'tok1', serverId: 'srv1', alwaysOriginal: false };
    ({ list } = MS.save(list, a));
    list = list.map((s) => ({ ...s, alwaysOriginal: true }));
    const r = MS.save(list, { ...a, id: 'b', token: 'tok2', alwaysOriginal: false });
    assert.equal(r.kept.id, 'a');
    assert.equal(r.kept.alwaysOriginal, true);
    assert.deepEqual(r.list.map((s) => s.token), ['tok2']);
    assert.ok(!JSON.stringify(MS.publicSource(r.kept)).includes('tok2'));
    assert.deepEqual(MS.decode(MS.encode(r.list)).map((s) => s.token), ['tok2']);
  });

  it('SMB and WebDAV of one folder paired, unpaired when one goes; at home SMB, away WebDAV', () => {
    let list = MS.save([], { id: 'smb1', kind: 'smb', name: 'nas', address: 'smb://nas/filme', userName: 'kino', password: 'geheim pw' }).list;
    assert.equal(list[0].pairWith || null, null);
    assert.ok(MS.ready(list[0]));
    assert.ok(!JSON.stringify(MS.publicSource(list[0])).includes('geheim'));
    list = MS.save(list, { id: 'dav0', kind: 'webdav', name: 'x', address: 'https://192.168.1.20:5006/serien', userName: 'kino', password: 'pw' }).list;
    const r = MS.save(list, { id: 'dav1', kind: 'webdav', name: 'x', address: 'https://192.168.1.20:5006/Filme', userName: 'kino', password: 'pw' });
    list = r.list;
    assert.equal(r.kept.pairWith, 'smb1');
    assert.equal(list.find((s) => s.id === 'smb1').pairWith, 'dav1');
    assert.equal(list.find((s) => s.id === 'dav0').pairWith || null, null);
    const reread = MS.decode(MS.encode(list));
    assert.equal(reread.find((s) => s.id === 'smb1').password, 'geheim pw');
    assert.equal(reread.find((s) => s.id === 'smb1').pairWith, 'dav1');
    const again = MS.save(reread, { id: 'smb2', kind: 'smb', name: 'n', address: 'smb://nas/filme', userName: 'kino', password: 'neu' });
    assert.equal(again.kept.id, 'smb1');
    assert.equal(again.kept.pairWith, 'dav1');
    assert.deepEqual(MS.shares(again.list).map((s) => s.id), ['smb1', 'dav0'], 'a pair once, as its SMB source');
    const pair = MS.pairOf(again.kept, again.list);
    assert.equal(MS.shareFor(pair.smb, pair.webdav, true).id, 'smb1');
    assert.equal(MS.shareFor(pair.smb, pair.webdav, false).id, 'dav1');
    assert.equal(MS.shareFor(pair.smb, pair.webdav, null).id, 'smb1');
    const removed = MS.remove(again.list, 'dav1');
    assert.equal(removed.find((s) => s.id === 'smb1').pairWith, null);
  });

  it('broken or foreign entries are left out', () => {
    assert.deepEqual(MS.decode('not json'), []);
    const list = MS.decode(JSON.stringify({ sources: [
      { id: 'a', kind: 'jellyfin', name: 'N', address: 'http://192.168.1.20:8096' },
      { id: 'b', kind: 'nfs', name: 'N', address: 'http://192.168.1.21' },
      { id: 'c', kind: 'jellyfin', name: 'N', address: 'http://media.example.test' },
      { id: 'd', kind: 'smb', name: 'N', address: 'smb://media.example.test/filme' },
      { id: 'e', kind: 'smb', name: 'N', address: 'smb://nas/filme', pairWith: 'gone' },
      { id: 'f', kind: 'webdav', name: 'N', address: 'http://dav.example.test/filme' },
    ] }));
    assert.deepEqual(list.map((s) => s.id), ['a', 'e']);
    assert.equal(list[1].pairWith, null, 'a partner that is not there is none');
  });
});
