'use strict';

// The viewer of PDFs, texts and Markdown of normal Drive files (not of a vault): DriveService.docView() loads the
// file as open() does (the copy of this revision in the temp folder, else a download — a row of the transfer list),
// hands a PDF as bytes and a text decoded; too large ones, folders, vault files, Office files and files the virus scan
// holds back are not loaded. The rules (services/drive-doc-view.js), the IPC drive:doc-view and the bridge.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ApiClient = require('../src/services/api-client');
const DriveApi = require('../src/services/drive-api');
const DriveService = require('../src/services/drive');
const DocView = require('../src/services/drive-doc-view');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { driveServer } = require('./fixtures/drive-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(opts = {}, { shell = null } = {}) {
  const srv = await driveServer(opts);
  cleanup.push(() => srv.close());
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive-doc-'));
  cleanup.push(() => fs.rmSync(temp, { recursive: true, force: true }));
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), shell, tempDir: () => temp, timing: { progressMs: 0 } });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, temp };
}

const MB = 1048576;

describe('drive-doc-view: the rules', () => {
  it('PDFs, texts and Markdown by name, else by the stored type; never Office, pictures, videos', () => {
    assert.equal(DocView.kindOf('Brief.pdf', 'application/pdf'), 'pdf');
    assert.equal(DocView.kindOf('Scan', 'application/pdf'), 'pdf');
    assert.equal(DocView.kindOf('notiz.txt', 'text/plain'), 'text');
    assert.equal(DocView.kindOf('config.yaml', 'application/octet-stream'), 'text');
    assert.equal(DocView.kindOf('README', 'text/plain; charset=utf-8'), 'text');
    assert.equal(DocView.kindOf('Plan.md', null), 'markdown');
    assert.equal(DocView.kindOf('Notes', 'text/markdown'), 'markdown');
    assert.equal(DocView.kindOf('Bericht.docx', 'text/plain'), null, 'an Office file by its name');
    assert.equal(DocView.kindOf('Foto.jpg', 'image/jpeg'), null);
    assert.equal(DocView.kindOf('Film.mp4', 'video/mp4'), null);
    assert.equal(DocView.kindOf('archiv.zip', 'application/zip'), null);
    assert.equal(DocView.kindOf('seite', 'text/html'), null, 'no page of a server type');
  });

  it('limits: 100 MB for a PDF, 2 MB for a text', () => {
    assert.equal(DocView.tooLarge('pdf', 100 * MB), false);
    assert.equal(DocView.tooLarge('pdf', 100 * MB + 1), true);
    assert.equal(DocView.tooLarge('text', 2 * MB + 1), true);
    assert.equal(DocView.tooLarge('markdown', 10), false);
    assert.equal(DocView.limitMb('pdf'), 100);
    assert.equal(DocView.limitMb('text'), 2);
  });

  it('a text: UTF-8, a BOM, UTF-16, else Windows-1252', () => {
    assert.equal(DocView.decodeText(Buffer.from('Größe: 3 €', 'utf8')), 'Größe: 3 €');
    assert.equal(DocView.decodeText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('Hallo')])), 'Hallo');
    assert.equal(DocView.decodeText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Übung', 'utf16le')])), 'Übung');
    const be = Buffer.from('Übung', 'utf16le').swap16();
    assert.equal(DocView.decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), be])), 'Übung');
    assert.equal(DocView.decodeText(Buffer.from([0x47, 0x72, 0xfc, 0xdf, 0x65, 0x20, 0x35, 0x20, 0x80])), 'Grüße 5 €');
    assert.equal(DocView.decodeText(Buffer.alloc(0)), '');
  });
});

describe('DriveService.docView', () => {
  it('a PDF: its bytes from the copy open() uses — loaded once, then from the temp folder', async () => {
    const opened = [];
    const shell = { openPath: async (p) => { opened.push(p); return ''; } };
    const { srv, svc, temp } = await setup({}, { shell });
    const r = await svc.docView(12);
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'pdf');
    assert.equal(r.name, 'Brief.pdf');
    assert.ok(r.data instanceof Uint8Array);
    assert.equal(Buffer.from(r.data).toString(), '%PDF-1.4 brief');
    assert.equal(r.size, 14);
    assert.equal(fs.readFileSync(path.join(temp, '12-1', 'Brief.pdf'), 'utf8'), '%PDF-1.4 brief');
    assert.equal(svc.transfers().filter((t) => t.state === 'done').length, 1, 'a row of the transfer list');
    const gets = srv.state.requests.length;
    const again = await svc.docView(12);
    assert.equal(Buffer.from(again.data).toString(), '%PDF-1.4 brief');
    assert.equal(svc.transfers().length, 1, 'no second download');
    assert.ok(srv.state.requests.slice(gets).some((x) => /nodes\/12\/content/.test(x.path)), 'the server still learns it was opened');
    // "Mit anderem Programm öffnen" afterwards: the same copy
    const o = await svc.open(12);
    assert.equal(o.path, path.join(temp, '12-1', 'Brief.pdf'));
    assert.equal(svc.transfers().length, 1);
  });

  it('a text decoded, Markdown as Markdown', async () => {
    const { srv, svc } = await setup();
    const t = srv.mutate.file(10, 'Notiz.txt', Buffer.from([0x47, 0x72, 0xfc, 0xdf, 0x65]));
    const r = await svc.docView(t.id);
    assert.deepEqual({ ok: r.ok, kind: r.kind, text: r.text, data: r.data }, { ok: true, kind: 'text', text: 'Grüße', data: undefined });
    const m = srv.mutate.file(10, 'Plan.md', '# Plan\n- eins');
    const md = await svc.docView(m.id);
    assert.equal(md.kind, 'markdown');
    assert.equal(md.text, '# Plan\n- eins');
  });

  it('too large: a note, nothing loaded', async () => {
    const { srv, svc } = await setup();
    const t = srv.mutate.file(10, 'gross.log', 'x');
    srv.state.nodes.get(t.id).size = 3 * MB;
    const before = srv.state.mediaGets ? srv.state.mediaGets.length : 0;
    const r = await svc.docView(t.id);
    assert.deepEqual(r, { ok: true, kind: 'text', name: 'gross.log', note: 'too_large', limitMb: 2 });
    assert.equal(svc.transfers().length, 0);
    if (srv.state.mediaGets) assert.equal(srv.state.mediaGets.length, before);
  });

  it('a folder, a vault file, an Office file, a picture: invalid; blocked by the scan: 423, the old copy gone', async () => {
    const { srv, svc, temp } = await setup();
    await assert.rejects(svc.docView(10), (e) => e.code === 'invalid');
    await assert.rejects(svc.docView(11), (e) => e.code === 'invalid', 'a picture has the media viewer');
    const doc = srv.mutate.file(10, 'Bericht.docx', 'PK');
    await assert.rejects(svc.docView(doc.id), (e) => e.code === 'invalid');
    const v = srv.mutate.file(10, 'geheim.pdf', 'ct');
    Object.assign(srv.state.nodes.get(v.id), { vaultId: 'v1', encrypted: true });
    await assert.rejects(svc.docView(v.id), (e) => e.code === 'invalid');
    await svc.docView(12);
    assert.ok(fs.existsSync(path.join(temp, '12-1', 'Brief.pdf')));
    srv.state.nodes.get(12).scan = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };
    await assert.rejects(svc.docView(12), (e) => e.status === 423);
    assert.equal(fs.existsSync(path.join(temp, '12-1')), false, 'a copy loaded before is not shown again');
    // marked only (not blocked): the page asks first, then it shows
    srv.state.nodes.get(12).scan = { state: 'infected', blocked: false, finding: 'Eicar' };
    assert.equal((await svc.docView(12)).kind, 'pdf');
  });

  it('IPC drive:doc-view; the bridge', async () => {
    const { svc } = await setup();
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    const r = await handlers['drive:doc-view'](null, { id: 12 });
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'pdf');
    assert.equal((await handlers['drive:doc-view'](null, { id: 'x' })).code, 'invalid');
    assert.equal((await handlers['drive:doc-view'](null, { id: 10 })).code, 'invalid');
    assert.match(fs.readFileSync(path.join(__dirname, '..', 'src', 'preload', 'bridge.js'), 'utf8'), /docView: +\(id\) => ipcRenderer\.invoke\('drive:doc-view', \{ id \}\)/);
  });
});
