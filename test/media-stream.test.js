'use strict';

// Medien (Stufe 4e): the scheme gcmedia: — the page gets a random token only; the main process fetches with the
// Jellyfin token (in the header, never in a URL or a playlist the page sees) or the share's access, passes Range on
// and gives the type; nothing outside the play's folder of the server; CORS only for the app's page.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const MediaNet = require('../src/services/media-net');
const MediaStreamService = require('../src/services/media-stream');
const { JellyfinClient } = require('../src/services/media-jellyfin');
const { SmbShare } = require('../src/services/media-share');
const { createMediaServer } = require('./fixtures/media-server');

const info = { client: 'GateControl Pro', device: 'PC', deviceId: 'dev-1', version: '1.0.0' };
const req = (url, headers = {}, method = 'GET') => ({ url, method, headers: new Headers(headers) });

describe('gcmedia: Jellyfin', () => {
  let srv;
  let net;
  let stream;
  beforeEach(async () => {
    srv = await createMediaServer().start();
    net = new MediaNet();
    const client = new JellyfinClient({ base: srv.base, info, token: 'tok-secret', net });
    stream = new MediaStreamService({ jellyfin: (id) => (id === 's1' ? client : null), share: () => null });
  });
  afterEach(async () => { stream.clear(); net.reset(); await srv.close(); });

  it('the file itself: Range passed on, the token in the header only, the type of the server', async () => {
    const url = stream.openJellyfin('s1', `${srv.base}/Videos/m1/stream?static=true&mediaSourceId=v1&api_key=leak`);
    assert.match(url, /^gcmedia:\/\/media\/[A-Za-z0-9_-]{24}\/stream\?static=true&mediaSourceId=v1$/);
    srv.enqueue({ status: 206, headers: { 'Content-Type': 'video/x-matroska', 'Content-Range': 'bytes 0-3/10', 'Content-Length': '4', 'Accept-Ranges': 'bytes' }, body: 'abcd' });
    const res = await stream.handleProtocol(req(`${url}&api_key=from-page`, { range: 'bytes=0-3', origin: 'null' }));
    assert.equal(res.status, 206);
    assert.equal(res.headers.get('content-type'), 'video/x-matroska');
    assert.equal(res.headers.get('content-range'), 'bytes 0-3/10');
    assert.equal(res.headers.get('access-control-allow-origin'), 'null');
    assert.equal(await res.text(), 'abcd');
    const up = srv.take();
    assert.equal(up.path, '/Videos/m1/stream');
    assert.equal(up.headers.range, 'bytes=0-3');
    assert.ok(up.headers.authorization.includes('Token="tok-secret"'));
    assert.equal(up.query.get('api_key'), null, 'no api_key from the page');
  });

  it('an HLS playlist without its api_key; what it names stays under the token; nothing outside the folder', async () => {
    const url = stream.openJellyfin('s1', `${srv.base}/videos/m1/master.m3u8?MediaSourceId=v1&api_key=tok-secret`);
    assert.ok(!url.includes('tok-secret'));
    srv.enqueue({
      status: 200, headers: { 'Content-Type': 'application/vnd.apple.mpegurl' },
      body: `#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=8000000\nmain.m3u8?MediaSourceId=v1&api_key=tok-secret\n#EXT-X-MEDIA:TYPE=SUBTITLES,URI="subs/0.m3u8?api_key=tok-secret"\n${srv.base}/videos/m1/hls1/main/0.mp4?api_key=tok-secret\nhttp://media.example.test/other.ts\n/Users/u1/x\n`,
    });
    const res = await stream.handleProtocol(req(url));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/vnd.apple.mpegurl');
    const text = await res.text();
    assert.ok(!text.includes('tok-secret'), text);
    assert.ok(text.includes('\nmain.m3u8?MediaSourceId=v1\n'));
    assert.ok(text.includes('URI="subs/0.m3u8"'));
    assert.ok(text.includes('\nhls1/main/0.mp4\n'));
    assert.ok(!text.includes('media.example.test') && !text.includes('/Users/'), 'nothing outside the play\'s folder');
    // a segment below the folder: same token
    const seg = new URL('hls1/main/0.mp4', url).toString();
    srv.enqueue({ status: 200, headers: { 'Content-Type': 'video/mp4' }, body: 'seg' });
    const r2 = await stream.handleProtocol(req(seg));
    assert.equal(r2.status, 200);
    assert.equal(await r2.text(), 'seg');
    srv.take();
    assert.equal(srv.take().path, '/videos/m1/hls1/main/0.mp4');
    // a way out of the folder or another token: 404
    const token = MediaStreamService.parseUrl(url).token;
    assert.equal((await stream.handleProtocol(req(`gcmedia://media/${token}/..%2F..%2FUsers`))).status, 404);
    assert.equal((await stream.handleProtocol(req(`gcmedia://media/${'x'.repeat(24)}/stream`))).status, 404);
    assert.equal((await stream.handleProtocol(req(url, {}, 'POST'))).status, 405);
  });

  it('a type a page could run never goes out; 416 stays, the rest is 404 / 502', async () => {
    const url = stream.openJellyfin('s1', `${srv.base}/Videos/m1/stream?static=true`);
    srv.enqueue({ status: 200, headers: { 'Content-Type': 'text/html' }, body: '<script>x</script>' });
    const r = await stream.handleProtocol(req(url));
    assert.equal(r.headers.get('content-type'), 'application/octet-stream');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    srv.enqueue({ status: 416 });
    assert.equal((await stream.handleProtocol(req(url))).status, 416);
    srv.enqueue({ status: 500 });
    assert.equal((await stream.handleProtocol(req(url))).status, 502);
    stream.revoke(url);
    assert.equal((await stream.handleProtocol(req(url))).status, 404);
  });

  it('pictures: only a picture path of an item, only its query', async () => {
    const img = stream.imageUrl('s1', 'Items/m1/Images/Primary?maxHeight=300&quality=85&tag=p1');
    assert.equal(stream.imageBase('s1'), img.slice(0, img.indexOf('Items/')), 'one token per source');
    srv.enqueue({ status: 200, headers: { 'Content-Type': 'image/jpeg' }, body: 'jpg' });
    const r = await stream.handleProtocol(req(`${img}&api_key=x&evil=1`));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'image/jpeg');
    const up = srv.take();
    assert.equal(up.path, '/Items/m1/Images/Primary');
    assert.deepEqual([...up.query.keys()].sort(), ['maxHeight', 'quality', 'tag']);
    const base = stream.imageBase('s1');
    assert.equal((await stream.handleProtocol(req(`${base}Users/u1`))).status, 404);
    assert.equal((await stream.handleProtocol(req(`${base}Items/m1/Download`))).status, 404);
  });
});

describe('gcmedia: a share file', () => {
  let dir;
  let stream;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-media-stream-'));
    fs.writeFileSync(path.join(dir, 'Kobaltnacht (2025).mp4'), '0123456789');
    const smb = new SmbShare({ source: { address: 'smb://nas/filme' }, wnet: null, localRoot: dir });
    stream = new MediaStreamService({ jellyfin: () => null, share: async (id) => (id === 'smb1' ? smb : null) });
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('the whole file, a range, past the end', async () => {
    const url = stream.openShare('smb1', 'Kobaltnacht (2025).mp4');
    assert.match(url, /\/Kobaltnacht%20\(2025\)\.mp4$/);
    const all = await stream.handleProtocol(req(url));
    assert.equal(all.status, 200);
    assert.equal(all.headers.get('content-type'), 'video/mp4');
    assert.equal(all.headers.get('accept-ranges'), 'bytes');
    assert.equal(await all.text(), '0123456789');
    const part = await stream.handleProtocol(req(url, { range: 'bytes=4-6' }));
    assert.equal(part.status, 206);
    assert.equal(part.headers.get('content-range'), 'bytes 4-6/10');
    assert.equal(part.headers.get('content-length'), '3');
    assert.equal(await part.text(), '456');
    const end = await stream.handleProtocol(req(url, { range: 'bytes=10-' }));
    assert.equal(end.status, 416);
    assert.equal(end.headers.get('content-range'), 'bytes */10');
    assert.equal(stream.openShare('smb1', '../x'), null);
    const head = await stream.handleProtocol(req(url, {}, 'HEAD'));
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), '10');
  });

  it('the scheme: CORS for the fetch of hls.js, only the app\'s page', async () => {
    assert.deepEqual({ ...MediaStreamService.SCHEME_PRIVILEGES }, { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true });
    const url = stream.openShare('smb1', 'Kobaltnacht (2025).mp4');
    const r = await stream.handleProtocol(req(url, { origin: 'https://evil.example.test' }));
    assert.equal(r.headers.get('access-control-allow-origin'), null);
    const pre = await stream.handleProtocol(req(url, { origin: 'null' }, 'OPTIONS'));
    assert.equal(pre.status, 204);
    assert.equal(pre.headers.get('access-control-allow-headers'), 'Range');
  });
});
