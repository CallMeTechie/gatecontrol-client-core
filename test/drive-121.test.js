'use strict';

// Drive 1.21 — the viewer of pictures and videos: DriveStreamService (services/drive-stream.js) hands the page a
// gcdrive: address after GET nodes/<id> and GET nodes/<id>/content, and serves it from the own server's media route
// with the Range of the request (206 / 416), the content's type, nothing cached; a file the virus scan holds back,
// a folder, a vault file or a document gets no address; tokens end with stream:end, their time and a new server.
// The IPC drive:stream / drive:stream:end and the bridge.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const DriveApi = require('../src/services/drive-api');
const DriveService = require('../src/services/drive');
const DriveStreamService = require('../src/services/drive-stream');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { driveServer } = require('./fixtures/drive-server');
const { createMemoryStore } = require('./fixtures/memory-store');
const fs = require('node:fs');
const path = require('node:path');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

const VIDEO = Buffer.from('....ftypisom' + 'v'.repeat(5000));

async function setup(opts = {}) {
  const srv = await driveServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  let now = 1_800_000_000_000;
  const stream = new DriveStreamService({ drive: svc, log, now: () => now });
  return { srv, svc, stream, clock: { set: (t) => { now = t; }, get: () => now } };
}

const req = (url, headers = {}, method = 'GET') => ({ url, method, headers: new Headers(headers) });
const bytes = async (res) => Buffer.from(await res.arrayBuffer());

describe('Drive 1.21: the viewer streams over gcdrive:', () => {
  it('a video: an address after content, Range 206 with the stored type, an open end, 416, HEAD', async () => {
    const { srv, stream } = await setup();
    const v = srv.mutate.photo(1, 'Urlaub.mp4', { content: VIDEO, mime: 'video/mp4' });
    const before = srv.state.requests.length;
    const r = await stream.open(v.id);
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'video');
    assert.equal(r.mime, 'video/mp4');
    assert.equal(r.size, VIDEO.length);
    assert.match(r.url, /^gcdrive:\/\/media\/[A-Za-z0-9_-]{24}$/);
    assert.ok(!r.url.includes(v.mediaId), 'the media id stays in the main process');
    const asked = srv.state.requests.slice(before).map((x) => x.path || x.url || x);
    assert.ok(asked.some((p) => /nodes\/\d+\/content/.test(JSON.stringify(p))), 'GET content first (rights, "Zuletzt geöffnet")');

    const head = await stream.handleProtocol(req(r.url, { Range: 'bytes=0-11' }));
    assert.equal(head.status, 206);
    assert.equal(head.headers.get('content-type'), 'video/mp4');
    assert.equal(head.headers.get('content-range'), `bytes 0-11/${VIDEO.length}`);
    assert.equal(head.headers.get('content-length'), '12');
    assert.equal(head.headers.get('accept-ranges'), 'bytes');
    assert.equal(head.headers.get('cache-control'), 'no-store');
    assert.equal(head.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(String(await bytes(head)), '....ftypisom');
    assert.deepEqual(srv.state.mediaGets.at(-1), { mediaId: v.mediaId, range: 'bytes=0-11' });

    const mid = await stream.handleProtocol(req(r.url, { Range: 'bytes=4000-' }));
    assert.equal(mid.status, 206);
    assert.equal((await bytes(mid)).length, VIDEO.length - 4000);
    const out = await stream.handleProtocol(req(r.url, { Range: `bytes=${VIDEO.length}-` }));
    assert.equal(out.status, 416);
    const all = await stream.handleProtocol(req(r.url));
    assert.equal(all.status, 200);
    assert.equal((await bytes(all)).length, VIDEO.length);
    // a Range of several parts is not passed on (the whole file)
    await stream.handleProtocol(req(r.url, { Range: 'bytes=0-1,5-6' }));
    assert.equal(srv.state.mediaGets.at(-1).range, null);
    const h = await stream.handleProtocol(req(r.url, {}, 'HEAD'));
    assert.equal(h.status, 200);
    assert.equal((await stream.handleProtocol(req(r.url, {}, 'POST'))).status, 405);
  });

  it('the type comes from Drive, never from the answer; a picture and a sound get one too', async () => {
    const { srv, stream } = await setup();
    const p = srv.mutate.photo(1, 'Bild.png', { content: 'png!', mime: 'image/png' });
    // the server's media answer says something else: the page still gets image/png
    srv.state.media.get(p.mediaId).mime = 'text/html';
    const r = await stream.open(p.id);
    assert.equal(r.kind, 'image');
    const res = await stream.handleProtocol(req(r.url));
    assert.equal(res.headers.get('content-type'), 'image/png');
    assert.equal(res.headers.get('content-security-policy'), "default-src 'none'");
    const a = srv.mutate.photo(1, 'Ton.m4a', { content: 'm4a', mime: 'audio/mp4' });
    assert.equal((await stream.open(a.id)).kind, 'audio');
  });

  it('no address for a folder, a document, a vault file or what the virus scan holds back', async () => {
    const { srv, stream } = await setup();
    await assert.rejects(stream.open(10), (e) => e.code === 'invalid', 'a folder');
    await assert.rejects(stream.open(12), (e) => e.code === 'invalid', 'a PDF');
    const v = srv.mutate.photo(1, 'Neu.mp4', { content: VIDEO, mime: 'video/mp4' });
    srv.state.nodes.get(v.id).scan = { state: 'pending', blocked: true, finding: null };
    const before = srv.state.requests.length;
    await assert.rejects(stream.open(v.id), (e) => e.status === 423 && e.code === 'scan_pending');
    assert.ok(!srv.state.requests.slice(before).some((x) => /\/content/.test(JSON.stringify(x))), 'no content asked for');
    srv.state.nodes.get(v.id).scan = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };
    await assert.rejects(stream.open(v.id), (e) => e.status === 423 && e.code === 'quarantined');
    // marked only (not blocked): the page asks first, then it plays
    srv.state.nodes.get(v.id).scan = { state: 'infected', blocked: false, finding: 'Eicar' };
    assert.equal((await stream.open(v.id)).ok, true);
    // the server refuses the bytes later (a re-check): 423 stays 423
    const r = await stream.open(v.id);
    srv.mediaStatus = 423;
    assert.equal((await stream.handleProtocol(req(r.url, { Range: 'bytes=0-1' }))).status, 423);
    srv.mediaStatus = 500;
    assert.equal((await stream.handleProtocol(req(r.url))).status, 502);
  });

  it('tokens: unknown, ended, expired, another server → 404; the last 40 only', async () => {
    const { srv, stream, clock } = await setup();
    const v = srv.mutate.photo(1, 'Film.mp4', { content: VIDEO, mime: 'video/mp4' });
    const r = await stream.open(v.id);
    assert.equal((await stream.handleProtocol(req('gcdrive://media/' + 'x'.repeat(24)))).status, 404);
    assert.equal((await stream.handleProtocol(req('gcdrive://other/' + r.url.split('/').pop()))).status, 404);
    assert.equal((await stream.handleProtocol(req(r.url + '?a=1'))).status, 404);
    assert.equal(stream.revoke(r.url).ok, true);
    assert.equal((await stream.handleProtocol(req(r.url))).status, 404, 'ended');
    const r2 = await stream.open(v.id);
    clock.set(clock.get() + DriveStreamService.DEFAULT_TIMING.ttlMs + 1);
    assert.equal((await stream.handleProtocol(req(r2.url))).status, 404, 'expired');
    const r3 = await stream.open(v.id);
    stream.clear();
    assert.equal((await stream.handleProtocol(req(r3.url))).status, 404, 'a new server');
    const urls = [];
    for (let i = 0; i < 41; i++) urls.push((await stream.open(v.id)).url);
    assert.equal((await stream.handleProtocol(req(urls[0]))).status, 404, 'the oldest went');
    assert.equal((await stream.handleProtocol(req(urls[40], { Range: 'bytes=0-0' }))).status, 206);
  });

  it('IPC drive:stream / drive:stream:end; without the service "unsupported"; exported by the core', async () => {
    const { srv, svc, stream } = await setup();
    const v = srv.mutate.photo(1, 'Clip.webm', { content: VIDEO, mime: 'video/webm' });
    const handlers = {};
    const handle = (ch, fn) => { handlers[ch] = fn; };
    registerDriveHandlers(handle, { drive: svc, stream, getMainWindow: () => null, log });
    const r = await handlers['drive:stream'](null, { id: v.id });
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'video');
    assert.equal((await handlers['drive:stream'](null, { id: 'x' })).code, 'invalid');
    const blocked = await handlers['drive:stream'](null, { id: 12 });
    assert.equal(blocked.ok, false);
    assert.equal((await handlers['drive:stream:end'](null, { url: r.url })).ok, true);
    assert.equal((await stream.handleProtocol(req(r.url))).status, 404);
    const bare = {};
    registerDriveHandlers((ch, fn) => { bare[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await bare['drive:stream'](null, { id: v.id })).code, 'unsupported');
    assert.match(fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8'), /\bDriveStreamService,/, 'exported by the core');
    assert.equal(DriveStreamService.SCHEME, 'gcdrive');
    assert.deepEqual({ ...DriveStreamService.SCHEME_PRIVILEGES }, { standard: true, secure: true, supportFetchAPI: false, corsEnabled: false, stream: true });
    assert.equal(DriveStreamService.mediaKind('video/quicktime'), 'video');
    assert.equal(DriveStreamService.mediaKind('text/html'), null);
    assert.equal(DriveStreamService.mediaKind('image/svg+xml'), null, 'SVG can carry scripts');
  });
});
