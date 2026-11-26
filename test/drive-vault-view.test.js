'use strict';

// Drive plugin 1.22: the viewer of vault files on Windows (services/drive-vault-view.js). A vault file is shown
// through gcvault://v/<token>: only its ciphertext lies on the disk, every request decrypts the chunks of its Range
// in memory; nothing in plain text in %TEMP% (the whole temp folder is searched), office files load nothing, closing
// and the vault lock revoke the token (404 afterwards), delete the ciphertext and overwrite the file key.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const V = require('../src/utils/drive-vault');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveVaultViews = require('../src/services/drive-vault-view');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 15));
  }
}

function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0xa5));
  return { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]), decrypt: (b) => x(Buffer.from(b).subarray(6)) };
}

/** Every file below `dir` (recursively) → [{ path, data }]. */
function filesIn(dir) {
  const out = [];
  const walk = (d) => {
    if (!fs.existsSync(d)) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push({ path: p, data: fs.readFileSync(p) });
    }
  };
  walk(dir);
  return out;
}

const req = (url, headers = {}, method = 'GET') => ({ url, method, headers: new Headers(headers) });
const bytesOf = async (res) => Buffer.from(await res.arrayBuffer());

async function setup() {
  const srv = await driveServer({ features: ['devices', 'emptyFiles', 'links', 'vault', 'office'] });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('dvv-tmp-');
  const opened = [];
  const svc = new DriveService({
    apiClient, api, log, store: createMemoryStore(), protect: fakeProtect(), deviceName: () => 'PC', tempDir: () => tmp, timing: { progressMs: 0 },
    shell: { openPath: async (p) => { opened.push(p); return ''; }, openExternal: async () => {} },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  await svc.vaultLockSettings({ hello: false });
  const made = await svc.vaultCreate(1, 'Privat');
  return { srv, svc, tmp, opened, made };
}

/** Uploads `files` ({ name: Buffer }) into the vault → name → node id. */
async function put(svc, vaultNodeId, files) {
  const src = tmpDir('dvv-src-');
  const ids = {};
  for (const [name, data] of Object.entries(files)) {
    fs.writeFileSync(path.join(src, name), data);
    const q = await svc.upload(vaultNodeId, [path.join(src, name)]);
    await until(() => svc.transfers().some((t) => t.id === q.queued[0] && t.state === 'done'));
    ids[name] = svc.transfers().find((t) => t.id === q.queued[0]).nodeId;
  }
  return ids;
}

describe('utils/drive-vault: random access to a content', () => {
  it('every chunk on its own, the last one shorter; another vault, a changed chunk and a closed content refused', () => {
    const tk = V.newVaultKey();
    const vid = V.newVaultId();
    const pt = crypto.randomBytes(3 * 1024 + 100);
    const ct = V.encryptBuffer(tk, vid, 2, pt, { chunkSize: 1024 });
    const c = V.openContent({ 2: tk }, vid, ct.subarray(0, V.HEADER), ct.length);
    assert.deepEqual([c.chunks, c.chunkSize, c.plainSize, c.keyVersion], [4, 1024, pt.length, 2]);
    const parts = [];
    for (let i = c.chunks - 1; i >= 0; i--) {
      const r = c.range(i);
      parts[i] = c.decrypt(i, ct.subarray(r.offset, r.offset + r.length));
    }
    assert.ok(Buffer.concat(parts).equals(pt));
    assert.equal(c.chunkOf(0), 0);
    assert.equal(c.chunkOf(2047), 1);
    assert.equal(c.chunkOf(pt.length + 99), 3);
    const r1 = c.range(1);
    const bad = Buffer.from(ct.subarray(r1.offset, r1.offset + r1.length));
    bad[5] ^= 1;
    assert.throws(() => c.decrypt(1, bad), (e) => e.code === 'decrypt');
    // chunk 2's bytes as chunk 1: the index is bound
    const r2 = c.range(2);
    assert.throws(() => c.decrypt(1, ct.subarray(r2.offset, r2.offset + r2.length)), (e) => e.code === 'decrypt');
    assert.throws(() => V.openContent({ 2: tk }, V.newVaultId(), ct.subarray(0, V.HEADER), ct.length).decrypt(0, ct.subarray(V.HEADER, V.HEADER + 1040)), (e) => e.code === 'decrypt');
    assert.throws(() => V.openContent({ 1: tk }, vid, ct.subarray(0, V.HEADER), ct.length), (e) => e.code === 'decrypt');
    assert.throws(() => V.openContent({ 2: tk }, vid, ct.subarray(0, V.HEADER), V.HEADER + 3 * 1040 + 5), (e) => e.code === 'invalid');
    c.close();
    assert.equal(c.closed, true);
    assert.throws(() => c.decrypt(0, ct.subarray(V.HEADER, V.HEADER + 1040)), (e) => e.code === 'invalid');
  });

  it('kinds, types, ranges and tokens of the viewer', () => {
    assert.deepEqual(['a.JPG', 'b.pdf', 'c.md', 'd.txt', 'e.mp4', 'f.docx', 'g.heic', 'h.zip', 'i.mp3'].map(DriveVaultViews.kindOf),
      ['image', 'pdf', 'markdown', 'text', 'video', 'office', 'heic', 'other', 'audio']);
    assert.equal(DriveVaultViews.mimeOf('x.html'), 'text/plain; charset=utf-8', 'HTML of a file never renders');
    assert.equal(DriveVaultViews.mimeOf('x.mov'), 'video/mp4');
    assert.deepEqual(DriveVaultViews.rangeOf('bytes=0-99', 1000), { start: 0, end: 99 });
    assert.deepEqual(DriveVaultViews.rangeOf('bytes=900-', 1000), { start: 900, end: 999 });
    assert.deepEqual(DriveVaultViews.rangeOf('bytes=-10', 1000), { start: 990, end: 999 });
    assert.deepEqual(DriveVaultViews.rangeOf('bytes=0-5000', 1000), { start: 0, end: 999 });
    assert.equal(DriveVaultViews.rangeOf('bytes=1000-', 1000), false);
    assert.equal(DriveVaultViews.rangeOf(null, 1000), null);
    assert.equal(DriveVaultViews.tokenOf('gcvault://v/' + 'a'.repeat(32)), 'a'.repeat(32));
    assert.equal(DriveVaultViews.tokenOf('gcvault://v/../etc'), null);
    assert.equal(DriveVaultViews.tokenOf('https://v/' + 'a'.repeat(32)), null);
    assert.equal(DriveVaultViews.SCHEME, 'gcvault');
    assert.equal(DriveVaultViews.SCHEME_PRIVILEGES.stream, true);
  });
});

describe('DriveService: the viewer of vault files (Drive plugin 1.22)', () => {
  it('fileInfo / fileCopy of a vault file: its real name, a decrypted copy in a folder of its own that dispose() removes', async () => {
    const { svc, tmp, opened, made } = await setup();
    const SECRET = 'Geheimnis 4711 im Tresor';
    const ids = await put(svc, made.node.id, { 'Pass.txt': Buffer.from(SECRET) });
    const info = await svc.fileInfo(ids['Pass.txt']);
    assert.deepEqual([info.name, info.encrypted], ['Pass.txt', true]);
    const c = await svc.fileCopy(ids['Pass.txt']);
    assert.ok(c.path.startsWith(path.join(tmp, 'vault')), c.path);
    assert.equal(path.basename(c.path), 'Pass.txt');
    assert.equal(fs.readFileSync(c.path, 'utf8'), SECRET);
    assert.equal(c.size, SECRET.length);
    assert.deepEqual(opened, [], 'nothing is opened');
    await c.dispose();
    assert.equal(fs.existsSync(path.dirname(c.path)), false);
  });

  it('a picture, a text, a video by ranges — decrypted in memory; only ciphertext in %TEMP%; close revokes the token', async () => {
    const { svc, tmp, opened, made } = await setup();
    const SECRET = 'Geheimnis 4711 im Tresor';
    const video = Buffer.concat([Buffer.from(SECRET), crypto.randomBytes(2 * 1048576 + 12345)]);
    const pic = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.from(SECRET)]);
    const ids = await put(svc, made.node.id, { 'Notiz.txt': Buffer.from(SECRET), 'Bild.png': pic, 'Film.mp4': video });

    const t = await svc.vaultView(ids['Notiz.txt']);
    assert.equal(t.ok, true);
    assert.equal(t.kind, 'text');
    assert.equal(t.mime, 'text/plain; charset=utf-8');
    assert.match(t.url, /^gcvault:\/\/v\/[0-9a-f]{32}$/);
    const text = await svc.handleVaultProtocol(req(t.url));
    assert.equal(text.status, 200);
    assert.equal(text.headers.get('cache-control'), 'no-store');
    assert.equal(text.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await bytesOf(text)).toString(), SECRET);

    const p = await svc.vaultView(ids['Bild.png']);
    assert.equal(p.kind, 'image');
    assert.equal(p.mime, 'image/png');
    assert.ok((await bytesOf(await svc.handleVaultProtocol(req(p.url)))).equals(pic));

    const v = await svc.vaultView(ids['Film.mp4']);
    assert.equal(v.kind, 'video');
    assert.equal(v.size, video.length);
    // ranges across chunk borders, from the end, beyond the end
    for (const [a, b] of [[0, 99], [1048570, 1048600], [2 * 1048576 - 3, 2 * 1048576 + 5], [video.length - 10, video.length - 1]]) {
      const r = await svc.handleVaultProtocol(req(v.url, { Range: `bytes=${a}-${b}` }));
      assert.equal(r.status, 206);
      assert.equal(r.headers.get('content-range'), `bytes ${a}-${b}/${video.length}`);
      assert.ok((await bytesOf(r)).equals(video.subarray(a, b + 1)), `${a}-${b}`);
    }
    const whole = await svc.handleVaultProtocol(req(v.url));
    assert.equal(whole.headers.get('content-length'), String(video.length));
    assert.ok((await bytesOf(whole)).equals(video));
    assert.equal((await svc.handleVaultProtocol(req(v.url, { Range: `bytes=${video.length}-` }))).status, 416);
    assert.equal((await svc.handleVaultProtocol(req(v.url, {}, 'POST'))).status, 405);
    assert.equal((await svc.handleVaultProtocol(req('gcvault://v/' + '0'.repeat(32)))).status, 404, 'an unknown token');
    // fetch(): only the app's own page (file:// — Origin null) may read it; any other origin gets no CORS answer
    assert.equal((await svc.handleVaultProtocol(req(t.url, { Origin: 'null' }))).headers.get('access-control-allow-origin'), 'null');
    assert.equal((await svc.handleVaultProtocol(req(t.url, { Origin: 'https://evil.example' }))).headers.get('access-control-allow-origin'), null);

    // on the disk: only ciphertext — nothing of the plaintext anywhere in the temp folder, no program was started
    const disk = filesIn(tmp);
    assert.ok(disk.length >= 3, 'the ciphertexts wait in vault-view');
    for (const f of disk) {
      assert.ok(f.path.startsWith(path.join(tmp, 'vault-view')), f.path);
      assert.equal(f.data.includes(Buffer.from(SECRET)), false, 'no plaintext in ' + f.path);
    }
    assert.deepEqual(opened, [], 'no other program');

    // close: the token answers 404, its ciphertext is gone
    assert.deepEqual(await svc.vaultViewClose(t.token), { ok: true });
    assert.equal((await svc.handleVaultProtocol(req(t.url))).status, 404);
    assert.equal(svc.vaultViews.has(t.token), false);
    assert.equal(filesIn(tmp).length, disk.length - 1);
  });

  it('the vault locks: every token revoked, a running stream ends, the ciphertexts deleted; office files load nothing', async () => {
    const { srv, svc, tmp, made } = await setup();
    const ids = await put(svc, made.node.id, { 'Film.mp4': crypto.randomBytes(3 * 1048576), 'Plan.xlsx': Buffer.from('PK office') });
    const before = srv.state.requests.length;
    const o = await svc.vaultView(ids['Plan.xlsx']);
    assert.deepEqual([o.ok, o.kind, o.note, o.token], [true, 'office', 'office', undefined]);
    assert.equal(srv.state.requests.slice(before).some((r) => /content/.test(r.path)), false, 'an office file is not even downloaded');

    const v = await svc.vaultView(ids['Film.mp4']);
    const res = await svc.handleVaultProtocol(req(v.url));
    const reader = res.body.getReader();
    const first = await reader.read();
    assert.equal(first.done, false);
    const events = [];
    svc.on('vaultLock', (e) => events.push(e));
    svc.vaultLockNow();
    await until(() => events.some((e) => e.locked));
    await until(() => svc.vaultViews.size === 0);
    let got = first.value.length;
    const ended = await (async () => { try { for (;;) { const r = await reader.read(); if (r.done) return 'done'; got += r.value.length; } } catch (e) { return 'error'; } })();
    assert.equal(ended, 'error');
    assert.equal((await svc.handleVaultProtocol(req(v.url))).status, 404);
    await until(() => filesIn(path.join(tmp, 'vault-view')).length === 0);
  });

  it('IPC: arguments checked; content protection of the window while the viewer shows', async () => {
    const { svc, made } = await setup();
    const ids = await put(svc, made.node.id, { 'a.txt': Buffer.from('x') });
    const h = {};
    const prot = [];
    const win = { isDestroyed: () => false, setContentProtection: (on) => prot.push(on), webContents: { send() {} } };
    registerDriveHandlers((ch, fn) => { h[ch] = fn; }, { drive: svc, getMainWindow: () => win, log });
    assert.equal((await h['drive:vault:view'](null, { id: 'x' })).code, 'invalid');
    assert.equal((await h['drive:vault:view'](null, { id: ids['a.txt'], versionId: 'x' })).code, 'invalid');
    const r = await h['drive:vault:view'](null, { id: ids['a.txt'] });
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'text');
    assert.equal((await h['drive:vault:view:close'](null, { token: '../x' })).code, 'invalid');
    assert.equal((await h['drive:vault:view:close'](null, { token: r.token })).ok, true);
    assert.equal((await h['drive:vault:protect'](null, { on: 'yes' })).code, 'invalid');
    await h['drive:vault:protect'](null, { on: true });
    await h['drive:vault:protect'](null, { on: false });
    assert.deepEqual(prot, [true, false]);
  });
});
