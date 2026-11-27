'use strict';

// Medien (Stufe 4h): the folders of a share as films and series — the file names (Android's ShareNamesTest cases),
// the index with the pictures beside the videos (ShareLibraryTest), the library with the progress of this PC, the
// service's rows / detail / play under a share's id, the pictures through gcmedia://image/, the folder view, the
// check before the start and "In VLC öffnen" through the loopback relay.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { EventEmitter } = require('node:events');

const N = require('../src/utils/media-share-names');
const SI = require('../src/utils/media-share-index');
const ShareLibrary = require('../src/services/media-share-library');
const MediaExternal = require('../src/services/media-external');
const MediaStreamService = require('../src/services/media-stream');
const MediaStore = require('../src/services/media-store');
const MediaService = require('../src/services/media');
const MediaNet = require('../src/services/media-net');
const { SmbShare } = require('../src/services/media-share');
const { registerMediaHandlers } = require('../src/ipc/media-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');

const protect = {
  available: () => true,
  encrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
  decrypt: (buf) => Buffer.from(Buffer.from(buf).map((b) => b ^ 0x5a)),
};

/** A share in memory: { 'Filme/a.mkv': Buffer } → list(dir) / stat / read / bytes as SmbShare and WebDavShare answer. */
function fakeShare(files, { kind = 'smb', modified = {} } = {}) {
  const fsx = {
    kind,
    listed: [],
    answer: null,
    async list(dir) {
      if (fsx.answer) return fsx.answer;
      fsx.listed.push(dir);
      const prefix = dir ? `${dir}/` : '';
      const seen = new Map();
      for (const p of Object.keys(files)) {
        if (!p.startsWith(prefix)) continue;
        const rest = p.slice(prefix.length).split('/');
        const name = rest[0];
        if (seen.has(name)) continue;
        const directory = rest.length > 1;
        seen.set(name, { name, path: prefix + name, directory, size: directory ? 0 : files[p].length, modifiedAt: modified[p] || null });
      }
      if (dir && !seen.size) return { ok: false, code: 'not_found' };
      return { ok: true, value: [...seen.values()] };
    },
    async stat(p) { return files[p] ? { ok: true, value: { size: files[p].length, modifiedAt: 0 } } : { ok: false, code: 'not_found' }; },
    async read(p, start, length) { return files[p] ? { ok: true, value: files[p].subarray(start, start + length) } : { ok: false, code: 'not_found' }; },
    async bytes(p, max) { return files[p] && files[p].length <= max ? files[p] : null; },
    async close() {},
  };
  return fsx;
}

const b = Buffer.alloc(10);
const FILES = {
  'Filme/Kobaltnacht (2025)/Kobaltnacht (2025).mkv': Buffer.from(Array.from({ length: 1000 }, (_, i) => i & 0xff)),
  'Filme/Kobaltnacht (2025)/poster.jpg': Buffer.from([1, 2, 3]),
  'Filme/Kobaltnacht (2025)/fanart.jpg': Buffer.from([4]),
  'Filme/Kupferstadt.2025.1080p.mkv': b,
  'Filme/Kupferstadt.2025.1080p-poster.png': b,
  'Filme/Achterwasser (2019).mp4': b,
  'Filme/Notizen.txt': b,
  'Filme/@eaDir/Kupferstadt.2025.1080p.mkv/SYNOVIDEO_VIDEO_SCREENSHOT.jpg': b,
  'Serien/Graufeld/poster.jpg': b,
  'Serien/Graufeld/Staffel 1/Graufeld.S01E02.Ebbe.mkv': b,
  'Serien/Graufeld/Staffel 1/Graufeld.S01E01.Flut.mkv': b,
  'Serien/Graufeld/Staffel 2/01 - Nebel.mkv': b,
  '#recycle/Alt.mkv': b,
};
const MODIFIED = { 'Filme/Kupferstadt.2025.1080p.mkv': 2000, 'Filme/Achterwasser (2019).mp4': 1000 };

describe('ShareNames (the cases of Android)', () => {
  const P = (title, year = null, season = null, episode = null, episodeName = null) => ({ title, year, season, episode, episodeName, isEpisode: season !== null && episode !== null });

  it('films: title and year from the file name', () => {
    assert.deepEqual(N.parse('Kobaltnacht (2025).mkv'), P('Kobaltnacht', 2025));
    assert.deepEqual(N.parse('Die.letzte.Fähre.nach.Mirow.2022.1080p.BluRay.x265.mkv'), P('Die letzte Fähre nach Mirow', 2022));
    assert.deepEqual(N.parse('Moorlicht.mp4'), P('Moorlicht'));
    assert.deepEqual(N.parse('Wolkenbruch & Söhne [2023] German DL.mkv'), P('Wolkenbruch & Söhne', 2023));
    assert.deepEqual(N.parse('2012.mkv'), P('2012'), 'a title that is only a year stays a title');
    assert.deepEqual(N.parse('Sternwarte_9_2026_2160p_HDR.mkv'), P('Sternwarte 9', 2026));
  });

  it('episodes: SxxEyy, 1x02 and numbers in a season folder', () => {
    const a = N.parse('Graufeld.S02E04.Die.Fähre.1080p.WEB-DL.mkv');
    assert.deepEqual(a, P('Graufeld', null, 2, 4, 'Die Fähre'));
    assert.equal(a.isEpisode, true);
    assert.deepEqual(N.parse('Die Lindqvist-Akten - s01e07.mkv'), P('Die Lindqvist-Akten', null, 1, 7));
    assert.deepEqual(N.parse('Ankerplatz 12 1x02 Ebbe.mp4'), P('Ankerplatz 12', null, 1, 2, 'Ebbe'));
    assert.deepEqual(N.parse('03 - Nebel.mkv', ['Serien', 'Graufeld', 'Staffel 1']), P('Graufeld', null, 1, 3, 'Nebel'));
    assert.deepEqual(N.parse('S04E01.mkv', ['Hofgeflüster (2019)', 'Season 04']), P('Hofgeflüster', null, 4, 1));
    assert.equal(N.parse('12 Monkeys.mkv', ['Filme']).isEpisode, false, 'a number in front without a season folder is a film');
  });

  it('what is a video, what is left out', () => {
    assert.equal(N.isVideo('Kobaltnacht.MKV'), true);
    assert.equal(N.isVideo('a.m2ts'), true);
    assert.equal(N.isVideo('Kobaltnacht.nfo'), false);
    assert.equal(N.isVideo('._Kobaltnacht.mkv'), false);
    assert.equal(N.isVideo('Kobaltnacht-sample.mkv'), false);
    assert.equal(N.isImage('poster.JPG'), true);
    assert.equal(N.skipDir('@eaDir'), true);
    assert.equal(N.skipDir('#recycle'), true);
    assert.equal(N.skipDir('Extras'), true);
    assert.equal(N.skipDir('Filme'), false);
    assert.equal(N.seasonOfDir('Staffel 2'), 2);
    assert.equal(N.seasonOfDir('Season 10'), 10);
    assert.equal(N.seasonOfDir('Graufeld'), null);
  });

  it('keys: the same title written differently, A to Z as Jellyfin', () => {
    assert.equal(N.key('Die letzte Fähre nach Mirow'), N.key('die.letzte.fähre.nach.mirow'));
    assert.equal(N.sortKey('Letzte Fähre'), 'letzte fahre');
    assert.equal(N.sortKey('The Pegelwart'), 'pegelwart');
    assert.equal(N.sortKey('Der Pegelwart'), 'der pegelwart');
    assert.equal(N.sortKey('Straße'), 'strasse');
  });

  it('share item ids: files and series, nothing else', () => {
    assert.equal(SI.isItemId('f:Filme/Kobaltnacht (2025).mkv'), true);
    assert.equal(SI.isItemId('s:graufeld'), true);
    assert.equal(SI.isItemId('s:graufeld:2'), true);
    assert.equal(SI.isItemId(SI.seriesId('!!!')), true, 'a name without letters: a hash');
    assert.equal(SI.isItemId('f:a\u0000b'), false);
    assert.equal(SI.isItemId('x:graufeld'), false);
    assert.equal(SI.pathOf('f:Filme/../../etc/passwd'), null, 'no way out of the share');
    assert.equal(SI.pathOf('f:/Filme//a.mkv'), 'Filme/a.mkv');
  });
});

describe('ShareLibrary (the cases of Android)', () => {
  let store;
  let now;
  let share;
  let lib;
  beforeEach(() => {
    now = 1000000;
    store = new MediaStore({ store: createMemoryStore(), protect, now: () => now });
    share = fakeShare(FILES, { modified: MODIFIED });
    lib = new ShareLibrary({ sourceId: 'nas1', fs: () => share, store, now: () => now });
  });

  it('films and series from the folders, pictures beside them', async () => {
    const movies = (await lib.movies(0, 100)).value;
    assert.deepEqual(movies.items.map((t) => t.name), ['Achterwasser', 'Kobaltnacht', 'Kupferstadt']);
    assert.equal(movies.total, 3);
    assert.equal(movies.next, null);
    const kobalt = movies.items[1];
    assert.equal(kobalt.year, 2025);
    assert.equal(kobalt.fromShare, true);
    assert.equal(kobalt.sourceId, 'nas1');
    assert.equal(kobalt.posterId, 'Filme/Kobaltnacht (2025)/poster.jpg');
    assert.equal(kobalt.backdropId, 'Filme/Kobaltnacht (2025)/fanart.jpg');
    assert.equal(movies.items[2].posterId, 'Filme/Kupferstadt.2025.1080p-poster.png');
    assert.equal(movies.items[0].posterId, null, 'a folder of several films: its folder.jpg would not be its');

    const series = (await lib.series(0, 100)).value.items;
    assert.equal(series.length, 1);
    assert.equal(series[0].name, 'Graufeld');
    assert.equal(series[0].kind, 'series');
    assert.equal(series[0].childCount, 2);
    assert.equal(series[0].posterId, 'Serien/Graufeld/poster.jpg');
    const seasons = (await lib.seasons(series[0].id)).value;
    assert.deepEqual(seasons.map((s) => [s.name, s.episode]), [['Staffel 1', 1], ['Staffel 2', 2]]);
    const first = (await lib.episodes(series[0].id, seasons[0].id)).value;
    assert.deepEqual(first.map((e) => e.name), ['Flut', 'Ebbe']);
    assert.equal(first[0].posterId, 'Serien/Graufeld/poster.jpg', 'an episode without its own picture shows its series\'');
    assert.deepEqual((await lib.episodes(series[0].id, seasons[1].id)).value.map((e) => e.name), ['Nebel']);
    assert.equal((await lib.episodes(series[0].id)).value.length, 3);
    assert.ok(!share.listed.some((d) => d.includes('@eaDir') || d.includes('#recycle')), 'hidden folders and recycle bins are not read');
    assert.equal((await lib.latest(16)).value[0].name, 'Kupferstadt', 'newest first');
    assert.deepEqual((await lib.search('kupfer')).value.map((t) => t.name), ['Kupferstadt']);
    assert.deepEqual((await lib.movies(0, 100, { sort: 'year' })).value.items.map((t) => t.name), ['Kobaltnacht', 'Kupferstadt', 'Achterwasser']);
    assert.deepEqual((await lib.movies(1, 1)).value, { items: [movies.items[1]], total: 3, start: 1, next: 2 });
  });

  it('the progress on this PC: 90 % is "gesehen", under 30 s no place, a short look keeps "gesehen"', async () => {
    const kobalt = (await lib.movies(0, 100)).value.items[1];
    const p = SI.pathOf(kobalt.id);
    lib.keep(p, 2530000, 6480000);
    now += 1000;
    const resume = (await lib.resume(12)).value;
    assert.deepEqual(resume.map((t) => [t.name, t.positionMs, t.runtimeMs, t.playedAt]), [['Kobaltnacht', 2530000, 6480000, now - 1000]]);
    assert.equal((await lib.detail(kobalt.id)).value.title.positionMs, 2530000);
    lib.keep(p, 6000000, 6480000);
    assert.deepEqual((await lib.resume(12)).value, []);
    assert.equal((await lib.detail(kobalt.id)).value.title.played, true);
    lib.keep(p, 10000, 0);
    assert.equal((await lib.detail(kobalt.id)).value.title.played, true, 'a short look into a watched file');
    lib.keep(p, 20000, 6480000);
    assert.equal(store.progress(`nas1|${p}`).positionMs, 0, 'under 30 s from the start');
    lib.setPlayed(p, false);
    assert.equal((await lib.detail(kobalt.id)).value.title.played, false);
    assert.deepEqual(Object.keys(store.all('nas1|')), [`nas1|${p}`]);
  });

  it('a series knows its unwatched episodes; offline the index found before stays', async () => {
    const series = (await lib.series(0, 100)).value.items[0];
    const eps = (await lib.episodes(series.id)).value;
    lib.setPlayed(SI.pathOf(eps[0].id), true);
    assert.equal((await lib.series(0, 100)).value.items[0].unplayed, 2);
    assert.equal((await lib.movies(0, 10, { unplayed: true })).value.total, 3);
    share.answer = { ok: false, code: 'offline' };
    now += ShareLibrary.INDEX_MS + 1;
    assert.equal((await lib.movies(0, 10)).value.total, 3, 'found before: still shown');
    assert.deepEqual(await lib.detail('f:nope.mkv'), { ok: false, code: 'not_found' });
    const locked = fakeShare({});
    locked.answer = { ok: false, code: 'unauthorized' };
    const refused = new ShareLibrary({ sourceId: 'x', fs: () => locked, store, now: () => now });
    assert.deepEqual(await refused.resume(12), { ok: false, code: 'unauthorized' });
  });
});

describe('MediaService: a share\'s films, series and folders', () => {
  let dir;
  let media;
  let spawned;
  let opened;
  let vlcHere;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-media-4h-'));
    for (const [p, buf] of Object.entries(FILES)) {
      fs.mkdirSync(path.join(dir, path.dirname(p)), { recursive: true });
      fs.writeFileSync(path.join(dir, p), buf);
    }
    spawned = [];
    opened = [];
    vlcHere = true;
    const net = new MediaNet();
    net.reachable = async () => true;
    const store = new MediaStore({ store: createMemoryStore(), protect });
    media = new MediaService({
      store,
      networkInterfaces: () => ({ Ethernet: [{ address: '192.168.1.37', family: 'IPv4', internal: false, cidr: '192.168.1.37/24' }] }),
      net,
      lanRoute: { supported: false, removeHostRoutes: async () => {} },
      shares: { smb: (source) => new SmbShare({ source, wnet: { add: () => 0, cancel: () => 0 }, localRoot: dir }), webdav: () => null },
      openPath: async (p) => { opened.push(p); return ''; },
      log: null,
    });
    media.external = new MediaExternal({
      stream: media.stream,
      openPath: async (p) => { opened.push(p); return ''; },
      platform: 'win32',
      env: { ProgramFiles: 'C:\\Program Files' },
      fs: { statSync: (p) => { if (vlcHere && p === 'C:\\Program Files\\VideoLAN\\VLC\\vlc.exe') return { isFile: () => true }; throw new Error('ENOENT'); } },
      execFile: (_cmd, _args, _o, cb) => cb(new Error('no reg')),
      spawn: (cmd, args) => { spawned.push([cmd, args]); const c = new EventEmitter(); c.unref = () => {}; return c; },
    });
  });
  afterEach(async () => { await media.close(); fs.rmSync(dir, { recursive: true, force: true }); });

  async function addSmb() {
    return (await media.addShare({ kind: 'smb', address: '\\\\192.168.1.20\\filme', user: 'kino', password: 'pw' })).source;
  }

  it('rows, grids, series and search take the share\'s id; pictures through gcmedia://image/', async () => {
    const smb = await addSmb();
    const movies = await media.movies(smb.id, { start: 0, limit: 60 });
    assert.equal(movies.ok, true);
    assert.deepEqual(movies.items.map((t) => [t.name, t.key, t.sortKey]), [['Achterwasser', 'achterwasser', 'achterwasser'], ['Kobaltnacht', 'kobaltnacht', 'kobaltnacht'], ['Kupferstadt', 'kupferstadt', 'kupferstadt']]);
    const kobalt = movies.items[1];
    assert.match(kobalt.poster, /^gcmedia:\/\/image\/[A-Za-z0-9_-]{24}\/Filme\/Kobaltnacht%20\(2025\)\/poster\.jpg$/);
    assert.equal(kobalt.poster.split('/')[3], movies.items[2].poster.split('/')[3], 'one token per share');
    const pic = await media.stream.handleProtocol({ url: kobalt.poster, method: 'GET', headers: {} });
    assert.equal(pic.status, 200);
    assert.equal(pic.headers.get('content-type'), 'image/jpeg');
    assert.deepEqual([...Buffer.from(await pic.arrayBuffer())], [1, 2, 3]);
    const base = kobalt.poster.split('/').slice(0, 4).join('/');
    for (const bad of ['Filme/Kupferstadt.2025.1080p.mkv', 'Filme/Notizen.txt', '..%2F..%2Fetc%2Fpasswd.jpg', 'Filme/%40eaDir/x.jpg']) {
      assert.equal((await media.stream.handleProtocol({ url: `${base}/${bad}`, method: 'GET', headers: {} })).status, 404, bad);
    }
    const series = await media.series(smb.id, {});
    assert.equal(series.items[0].name, 'Graufeld');
    const seasons = await media.seasons(smb.id, series.items[0].id);
    assert.deepEqual(seasons.items.map((s) => s.id), ['s:graufeld:1', 's:graufeld:2']);
    const eps = await media.episodes(smb.id, 's:graufeld', 's:graufeld:1');
    assert.deepEqual(eps.items.map((e) => [e.name, e.key, e.season, e.episode]), [['Flut', 'graufeld', 1, 1], ['Ebbe', 'graufeld', 1, 2]]);
    assert.deepEqual((await media.search(smb.id, 'grau')).items.map((t) => t.kind), ['series']);
    assert.deepEqual((await media.resume(smb.id)).items, []);
    assert.equal((await media.latest(smb.id)).items.length, 4);
    // the overview "Ergänzt": a share's newest films and series apart; no Als Nächstes, Favoriten, Sammlungen, Genres, heart
    const lm = await media.latestMovies(smb.id);
    assert.ok(lm.items.length > 0 && lm.items.every((t) => t.kind === 'movie'));
    const le = await media.latestEpisodes(smb.id);
    assert.deepEqual(le.items.map((t) => t.kind), ['series']);
    assert.deepEqual(await media.nextUp(smb.id), { ok: true, items: [], total: 0 });
    assert.deepEqual(await media.favorites(smb.id), { ok: true, items: [], total: 0 });
    assert.deepEqual(await media.collections(smb.id), { ok: true, items: [], total: 0 });
    assert.deepEqual(await media.genres(smb.id), { ok: true, genres: [] });
    assert.equal((await media.setFavorite(smb.id, 'f:x.mkv', true)).code, 'unsupported');
    assert.equal((await media.libraries(smb.id)).code, 'not_found');
  });

  it('detail and play of a file, the progress, "gesehen" of a series; a play given up keeps its place', async () => {
    const smb = await addSmb();
    const id = 'f:Filme/Kobaltnacht (2025)/Kobaltnacht (2025).mkv';
    const d = await media.detail(smb.id, id);
    assert.equal(d.ok, true);
    assert.equal(d.title.name, 'Kobaltnacht');
    assert.deepEqual(d.versions.map((v) => [v.container, v.audio.length, v.supportsDirectPlay]), [['mkv', 0, true]]);
    assert.equal(d.share.via, 'smb');
    assert.equal(d.share.check, null, 'not read yet');
    const p = await media.play({ sourceId: smb.id, itemId: id });
    assert.equal(p.ok, true);
    assert.equal(p.hls, false);
    assert.equal(p.converted, false);
    assert.deepEqual(p.subtitles, []);
    assert.match(p.url, /^gcmedia:\/\/media\//);
    assert.ok(p.check && p.check.verdict);
    assert.deepEqual((await media.detail(smb.id, id)).share.check, p.check, 'the check is kept');
    await media.report({ playId: p.playId, event: 'stop', positionMs: 0 });
    assert.equal(media.store.progress(`${smb.id}|${SI.pathOf(id)}`), null, 'given up before it started: nothing written');
    const p2 = await media.play({ sourceId: smb.id, itemId: id });
    await media.report({ playId: p2.playId, event: 'start', positionMs: 0, durationMs: 6480000 });
    await media.report({ playId: p2.playId, event: 'stop', positionMs: 2530000, durationMs: 6480000 });
    const resume = await media.resume(smb.id);
    assert.deepEqual(resume.items.map((t) => [t.name, t.resumable, t.leftMs]), [['Kobaltnacht', true, 6480000 - 2530000]]);
    assert.equal((await media.setPlayed(smb.id, 's:graufeld', true)).ok, true);
    assert.equal((await media.series(smb.id, {})).items[0].played, true);
    assert.equal((await media.setPlayed(smb.id, 's:graufeld:2', false)).ok, true);
    assert.equal((await media.series(smb.id, {})).items[0].unplayed, 1);
  });

  it('the folder view: titles and pictures from the names, the check without playing', async () => {
    const smb = await addSmb();
    const root = await media.shareList({ sourceId: smb.id });
    assert.deepEqual(root.items.map((e) => e.name), ['Filme', 'Serien'], 'hidden folders and recycle bins left out');
    const filme = await media.shareList({ sourceId: smb.id, dir: 'Filme' });
    const kupfer = filme.items.find((e) => e.name === 'Kupferstadt.2025.1080p.mkv');
    assert.equal(kupfer.title, 'Kupferstadt');
    assert.equal(kupfer.year, 2025);
    assert.equal(kupfer.itemId, 'f:Filme/Kupferstadt.2025.1080p.mkv');
    assert.match(kupfer.poster, /Kupferstadt\.2025\.1080p-poster\.png$/);
    assert.equal(filme.items.find((e) => e.name === 'Notizen.txt').itemId, undefined);
    const season = await media.shareList({ sourceId: smb.id, dir: 'Serien/Graufeld/Staffel 1' });
    assert.deepEqual(season.items.map((e) => [e.title, e.seriesName, e.season, e.episode]), [['Flut', 'Graufeld', 1, 1], ['Ebbe', 'Graufeld', 1, 2]]);
    assert.match(season.items[0].poster, /Serien\/Graufeld\/poster\.jpg$/, 'a season folder: the series\' picture above');
    assert.deepEqual(await media.shareList({ sourceId: smb.id, dir: '../x' }), { ok: false, code: 'not_found' });
    const c = await media.shareInspect({ sourceId: smb.id, itemId: kupfer.itemId });
    assert.equal(c.ok, true);
    assert.equal(c.size, 10);
    assert.equal(c.via, 'smb');
  });

  it('"In VLC öffnen" through the loopback, "In anderer App öffnen" with the UNC path', async () => {
    const smb = await addSmb();
    assert.deepEqual(await media.externalInfo(), { ok: true, vlc: true, openPath: true });
    const id = 'f:Filme/Kobaltnacht (2025)/Kobaltnacht (2025).mkv';
    const r = await media.shareExternal({ sourceId: smb.id, itemId: id, app: 'vlc', title: 'Kobaltnacht' });
    assert.deepEqual(r, { ok: true, app: 'vlc' });
    const [cmd, args] = spawned[0];
    assert.equal(cmd, 'C:\\Program Files\\VideoLAN\\VLC\\vlc.exe');
    assert.match(args[0], /^http:\/\/127\.0\.0\.1:\d+\/[A-Za-z0-9_-]{24}\/Kobaltnacht%20\(2025\)\.mkv$/);
    assert.equal(args[1], ':meta-title=Kobaltnacht');
    assert.ok(!args.join(' ').includes('pw'), 'no access in the arguments');
    const u = new URL(args[0]);
    const get = (headers = {}, target = u.pathname) => new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: u.port, path: target, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      });
      req.on('error', reject);
      req.end();
    });
    const part = await get({ Range: 'bytes=990-' });
    assert.equal(part.status, 206);
    assert.equal(part.headers['content-range'], 'bytes 990-999/1000');
    assert.deepEqual([...part.body], [222, 223, 224, 225, 226, 227, 228, 229, 230, 231]);
    assert.equal(part.headers['access-control-allow-origin'], undefined);
    assert.equal((await get({ Host: 'evil.example.test' })).status, 403, 'no DNS rebinding');
    assert.equal((await get({}, `/${'A'.repeat(24)}/x.mkv`)).status, 404, 'only tokens made for VLC');
    const def = await media.shareExternal({ sourceId: smb.id, itemId: id, app: 'default' });
    assert.deepEqual(def, { ok: true, app: 'default' });
    assert.deepEqual(opened, ['\\\\192.168.1.20\\filme\\Filme\\Kobaltnacht (2025)\\Kobaltnacht (2025).mkv']);
    vlcHere = false;
    assert.deepEqual(await media.shareExternal({ sourceId: smb.id, itemId: id, app: 'vlc' }), { ok: false, code: 'no_vlc' });
    assert.deepEqual(await media.shareExternal({ sourceId: smb.id, itemId: 'f:../a.mkv', app: 'vlc' }), { ok: false, code: 'not_found' });
  });
});

describe('MediaExternal', () => {
  it('where VLC is: the registry first, then the usual folders', () => {
    assert.equal(MediaExternal.parseRegistry('\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\VideoLAN\\VLC\r\n    (Default)    REG_SZ    D:\\Apps\\VLC\\vlc.exe\r\n    Version    REG_SZ    3.0.21\r\n'), 'D:\\Apps\\VLC');
    assert.equal(MediaExternal.parseRegistry('    InstallDir    REG_SZ    E:\\VLC\r\n    (Default)    REG_SZ    D:\\Apps\\VLC\\vlc.exe'), 'E:\\VLC');
    assert.equal(MediaExternal.parseRegistry('nothing'), null);
    const c = MediaExternal.vlcCandidates({ ProgramFiles: 'C:\\Program Files', 'ProgramFiles(x86)': 'C:\\Program Files (x86)', LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local' }, 'D:\\Apps\\VLC');
    assert.equal(c[0], 'D:\\Apps\\VLC\\vlc.exe');
    assert.ok(c.includes('C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe'));
    assert.ok(c.includes('C:\\Users\\a\\AppData\\Local\\Microsoft\\WindowsApps\\vlc.exe'));
  });

  it('not on Windows: no VLC; another app only with a UNC path', async () => {
    const x = new MediaExternal({ stream: new MediaStreamService({}), platform: 'linux', openPath: async () => '' });
    assert.equal(await x.vlcPath(), null);
    assert.deepEqual(await x.openWithDefault('https://192.168.1.20/a.mkv'), { ok: false, code: 'unsupported' });
    assert.deepEqual(await x.openInVlc('gcmedia://media/x/y'), { ok: false, code: 'no_vlc' });
    x.close();
  });
});

describe('media:* of the folders (IPC)', () => {
  it('share ids pass, anything else is refused', async () => {
    const h = {};
    const calls = [];
    const m = new Proxy(new EventEmitter(), {
      get(target, prop) {
        if (prop in target) return typeof target[prop] === 'function' ? target[prop].bind(target) : target[prop];
        return async (arg) => { calls.push([prop, arg]); return { ok: true, name: prop }; };
      },
    });
    registerMediaHandlers((ch, fn) => { h[ch] = fn; }, { media: m, getMainWindow: () => null, log: { debug() {} } });
    const call = (ch, arg) => h[ch]({}, arg);
    assert.equal((await call('media:detail', { id: 's1', itemId: 'f:Filme/Kobaltnacht (2025).mkv' })).name, 'detail');
    assert.equal((await call('media:episodes', { id: 's1', seriesId: 's:graufeld', seasonId: 's:graufeld:1' })).name, 'episodes');
    assert.equal((await call('media:share:check', { id: 's1', itemId: 'f:a.mkv' })).name, 'shareInspect');
    assert.deepEqual(calls[calls.length - 1], ['shareInspect', { sourceId: 's1', itemId: 'f:a.mkv' }]);
    assert.equal((await call('media:share:check', { id: 's1', itemId: 's:graufeld' })).code, 'invalid', 'a series is no file');
    assert.equal((await call('media:share:external', { id: 's1', itemId: 'f:a.mkv', app: 'mpv' })).code, 'invalid');
    assert.equal((await call('media:share:external', { id: 's1', path: 'a.mkv', app: 'vlc', title: 'Kobaltnacht' })).name, 'shareExternal');
    assert.deepEqual(calls[calls.length - 1], ['shareExternal', { sourceId: 's1', path: 'a.mkv', app: 'vlc', title: 'Kobaltnacht' }]);
    assert.equal((await call('media:external:info', {})).name, 'externalInfo');
    assert.equal((await call('media:play', { id: 's1', itemId: 'f:a\u0001.mkv' })).code, 'invalid');
  });
});
