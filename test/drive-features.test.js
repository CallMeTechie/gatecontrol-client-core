'use strict';

// Drive features of the Windows Pro app (Drive 1.5 'deleteAfter', Drive 1.6
// 'links' / 'guard'): the pure helpers (utils/drive.js links, guard, delayed
// deletes; utils/drive-guard.js entropy and the thresholds; utils/pdf-text.js),
// the API calls, DriveService (whole folders, the text of PDFs, the entropy,
// "Im Portal öffnen", live events, the guard) and DriveSync ("Nur sichern"
// with Drive's 30 days, the local ransomware check, Drive stopping the device,
// "Rückgängig machen") against the fake Drive server, and the IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
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

const drive = require('../src/utils/drive');
const S = require('../src/utils/drive-sync');
const G = require('../src/utils/drive-guard');
const { pdfText, isPdf, cleanText } = require('../src/utils/pdf-text');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createBridgeApi } = require('../src/preload/bridge');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const DAY = 86400000;

const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

function write(root, rel, content, mtime = null) {
  const p = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  if (mtime) fs.utimesSync(p, new Date(mtime), new Date(mtime));
  return p;
}
const read = (root, rel) => fs.readFileSync(path.join(root, ...rel.split('/')), 'utf8');
const exists = (root, rel) => fs.existsSync(path.join(root, ...rel.split('/')));

async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 15));
  }
}

/** A one-page PDF with a text layer (Helvetica). */
function makePdf(text) {
  const stream = `BT /F1 18 Tf 20 100 Td (${text}) Tj ET`;
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const x = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offs.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${x}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

const lowText = (i) => `Zeile ${i}: Das ist ein ganz normaler Brief mit Text.\n`.repeat(400);
const commits = (srv) => srv.state.requests.filter((r) => r.path.endsWith('uploads/commit'));
const childNamed = (srv, parentId, name) => [...srv.state.nodes.values()].find((n) => n.parentId === parentId && !n.deleted && n.name === name);

async function serviceSetup(opts = {}, { shell = null, dialog = null, pushClient = null, readPdfText = undefined, portalUrl = null } = {}) {
  const srv = await driveServer(opts);
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  if (portalUrl) apiClient.portalUrl = portalUrl;
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, shell, dialog, pushClient, tempDir: () => tmpDir('drive-tmp-'), timing: { progressMs: 0 }, ...(readPdfText !== undefined ? { readPdfText } : {}) });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api, apiClient };
}

async function syncSetup({ srv, now = () => Date.now(), store = createMemoryStore(), dir = null, extra = {} } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store, timing: { progressMs: 0 } });
  await svc.check();
  const stateDir = dir || tmpDir('drive-sync-state-');
  const sync = new DriveSync({
    drive: svc, api, store, dir: stateDir, log, now,
    hostname: () => 'Desktop-PC',
    getDeviceKey: () => 'ab12cd34',
    trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); },
    timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 },
    readPdfText: async () => null,
    ...extra,
  });
  sync.start();
  cleanup.push(() => sync.stop());
  return { svc, api, sync, store, stateDir };
}

// ── Pure helpers ───────────────────────────────────────────

describe('utils/drive: Drive 1.5 / 1.6 answers', () => {
  it('reads links, the guard and incidents of me; delayed deletes on nodes and in the change log', () => {
    const m = drive.normalizeMe({
      features: ['links', 'guard', 'deleteAfter', 'bad feature!'],
      links: { node: 'https://gc.example.com/portal#plg-gatecontrol-drive/node/{id}', drive: 'https://gc.example.com/portal#plg-gatecontrol-drive' },
      guard: { locked: true, incident: { id: 12, at: '2026-10-28T08:00:00Z', device: 'pc-1', deviceName: 'Büro-PC', files: 80, sample: ['a.docx', { path: 'Steuer/b.xlsx' }, 7] } },
      incidents: [{ id: 'inc_1', files: 3 }, { id: '../x' }],
    });
    assert.deepEqual(m.features, ['links', 'guard', 'deleteAfter']);
    assert.equal(m.links.node, 'https://gc.example.com/portal#plg-gatecontrol-drive/node/{id}');
    assert.deepEqual(m.guard.incident.sample, ['a.docx', 'Steuer/b.xlsx']);
    assert.equal(m.guard.locked, true);
    assert.equal(m.guard.incident.at, Date.parse('2026-10-28T08:00:00Z'));
    assert.deepEqual(m.incidents.map((i) => i.id), ['inc_1']);
    // older Drives: none of it
    const old = drive.normalizeMe({});
    assert.equal(old.links, null);
    assert.equal(old.guard, null);
    assert.deepEqual(old.incidents, []);
    // only https templates with {id}
    assert.equal(drive.normalizeMe({ links: { node: 'http://gc.example.com/{id}' } }).links, null);
    assert.equal(drive.normalizeMe({ links: { node: 'https://gc.example.com/node' } }).links, null);
    assert.equal(drive.normalizeMe({ links: { node: 'javascript:alert({id})' } }).links, null);

    const n = drive.normalizeNode({ id: 5, areaId: 'mine:2', name: 'a.jpg', deleteAt: '2026-11-27T10:00:00Z', deletedOnDevice: 'pc-ab12cd34' });
    assert.equal(n.deleteAt, Date.parse('2026-11-27T10:00:00Z'));
    assert.equal(n.deletedOnDevice, 'pc-ab12cd34');
    const ch = drive.normalizeChanges({ changes: [{ seq: 3, op: 'mark', nodeId: 5, areaId: 'mine:2', node: { id: 5, areaId: 'mine:2', name: 'a.jpg', parentId: 1, deleteAt: '2026-11-27T10:00:00Z' } }, { seq: 4, op: 'unmark', nodeId: 5 }, { seq: 5, op: 'weird', nodeId: 5 }], next: 5 });
    assert.deepEqual(ch.changes.map((c) => c.op), ['mark', 'unmark']);
    // a marked node is not deleted: it stays in the tree of a synced folder
    const tree = { 5: { id: 5, parentId: 1, name: 'a.jpg', isDir: false, size: 1, sha256: null, rev: 1, mtime: null } };
    const r = S.applyChanges(tree, 1, [ch.changes[0]]);
    assert.ok(tree[5]);
    assert.equal(r.rootGone, false);
  });

  it('builds portal links of nodes only on the allowed hosts', () => {
    const tpl = 'https://gc.example.com/portal#plg-gatecontrol-drive/node/{id}';
    assert.equal(drive.nodeLink(tpl, 812, ['gc.example.com']), 'https://gc.example.com/portal#plg-gatecontrol-drive/node/812');
    assert.equal(drive.nodeLink(tpl, 812, ['GC.EXAMPLE.COM']), 'https://gc.example.com/portal#plg-gatecontrol-drive/node/812');
    assert.equal(drive.nodeLink(tpl, 812, ['other.example.com']), null);
    assert.equal(drive.nodeLink(tpl, 812), 'https://gc.example.com/portal#plg-gatecontrol-drive/node/812');
    assert.equal(drive.nodeLink(tpl, 0, ['gc.example.com']), null);
    assert.equal(drive.nodeLink(tpl, '1; drop', ['gc.example.com']), null);
    assert.equal(drive.nodeLink('https://evil.example/{id}', 1, ['gc.example.com']), null);
    assert.equal(drive.allowedLink('https://gc.example.com/x', ['gc.example.com']), 'https://gc.example.com/x');
    assert.equal(drive.allowedLink('https://user:pw@gc.example.com/x', ['gc.example.com']), null);
    assert.equal(drive.incidentIdOf(7), 7);
    assert.equal(drive.incidentIdOf('inc_7'), 'inc_7');
    assert.equal(drive.incidentIdOf('../7'), null);
  });
});

describe('utils/drive-guard', () => {
  it('measures the entropy: text low, random bytes close to 8', () => {
    assert.equal(G.entropyOf(Buffer.alloc(0)), null);
    assert.equal(G.entropyOf(Buffer.alloc(1000, 65)), 0);
    assert.ok(G.entropyOf(Buffer.from(lowText(1))) < 5);
    assert.ok(G.entropyOf(crypto.randomBytes(65536)) > 7.9);
  });

  it('reads only the first 64 KB of a file', async () => {
    const dir = tmpDir('ent-');
    const p = path.join(dir, 'x.bin');
    fs.writeFileSync(p, Buffer.concat([Buffer.alloc(65536, 0), crypto.randomBytes(200000)]));
    assert.equal(await G.fileEntropy(p), 0);
    assert.equal(await G.fileEntropy(path.join(dir, 'gone')), null);
  });

  it('a change is suspicious when it became high-entropy; compressed types and known entropies count', () => {
    assert.equal(G.suspiciousChange('Brief.txt', 7.99, null), true);
    assert.equal(G.suspiciousChange('Brief.txt', 7.99, 4.2), true);
    assert.equal(G.suspiciousChange('Brief.txt', 7.99, 7.9), false); // it was like that before
    assert.equal(G.suspiciousChange('Brief.txt', 6.1, null), false);
    assert.equal(G.suspiciousChange('Foto.JPG', 7.99, null), false);
    assert.equal(G.suspiciousChange('Bericht.docx', 7.95, null), false);
    assert.equal(G.suspiciousChange('Bericht.docx', 7.95, 5.0), true); // was low: an encrypted .docx
    assert.equal(G.suspiciousChange('Brief.txt', null, null), false);
  });

  it('recognises a file renamed to a ransomware extension', () => {
    assert.equal(G.ransomRename('brief.docx.locked', ['brief.docx']), true);
    assert.equal(G.ransomRename('Brief.docx.id-1E2D.[x@y].eking', ['brief.docx']), true);
    assert.equal(G.ransomRename('brief.docx.locked', ['andere.docx']), false);
    assert.equal(G.ransomRename('brief.docx.bak', ['brief.docx']), false);
    assert.equal(G.ransomRename('notes.enc', []), false);
  });

  it('trips at 50 suspicious files, or at 20 % of a folder with at least 20 files', () => {
    const many = (n, dir = 'a') => Array.from({ length: n }, (_, i) => ({ dir, name: `f${i}` }));
    assert.equal(G.guardTrips(many(50), () => 100000).trip, true);
    assert.equal(G.guardTrips(many(49), () => 100000).trip, false);
    assert.equal(G.guardTrips(many(4), () => 20).trip, true);
    assert.equal(G.guardTrips(many(3), () => 20).trip, false);
    assert.equal(G.guardTrips(many(5), () => 19).trip, false); // a folder of fewer than 20 files
    const r = G.guardTrips([...many(3, 'x'), ...many(3, 'y')], (d) => (d === 'x' ? 15 : 15));
    assert.equal(r.trip, false);
    assert.equal(r.count, 6);
    assert.equal(G.guardTrips(many(10), () => 20).sample.length, 5);
  });
});

describe('utils/pdf-text', () => {
  it('reads the text layer of a PDF in a worker; broken files, other files and timeouts give null', async () => {
    const dir = tmpDir('pdf-');
    const p = path.join(dir, 'Brief.pdf');
    fs.writeFileSync(p, makePdf('Hallo Drive Miete Oktober'));
    assert.equal(await pdfText(p), 'Hallo Drive Miete Oktober');
    const bad = path.join(dir, 'kaputt.pdf');
    fs.writeFileSync(bad, '%PDF-1.4 kaputt');
    assert.equal(await pdfText(bad), null);
    assert.equal(await pdfText(p, { timeoutMs: 1 }), null);
    assert.equal(await pdfText(p, { maxBytes: 10 }), null);
    assert.equal(await pdfText('relative.pdf'), null);
    assert.equal(await pdfText(path.join(dir, 'gone.pdf')), null);
    assert.equal(isPdf('a.PDF'), true);
    assert.equal(isPdf('a.txt', 'application/pdf'), true);
    assert.equal(isPdf('a.txt'), false);
    assert.equal(cleanText('  a\u0000b \n\n  c  '), 'a b\nc');
    assert.equal(cleanText('x'.repeat(200000)).length, drive.TEXT_MAX);
    assert.equal(cleanText('   '), null);
  });
});

// ── API ────────────────────────────────────────────────────

describe('Drive API: delayed deletes, guard, commit extras', () => {
  it('sends after / device, calls a delete off, decides incidents, commits text and entropy', async () => {
    const { srv, api } = await serviceSetup({ features: ['deleteAfter', 'guard'] });
    const r = await api.trash(12, { after: 2592000, device: 'pc-ab12cd34' });
    assert.equal(r.trashed, false);
    assert.ok(r.deleteAt > Date.now() + 29 * DAY);
    const del = srv.state.requests.filter((x) => x.method === 'DELETE').at(-1);
    assert.deepEqual([del.query.after, del.query.device], ['2592000', 'pc-ab12cd34']);
    assert.ok(srv.state.nodes.get(12).deleteAt);
    assert.equal(srv.state.nodes.get(12).deleted, false);
    assert.equal(srv.state.log.at(-1).op, 'mark');
    const n = await api.unmark(12);
    assert.equal(n.deleteAt, null);
    assert.deepEqual(srv.state.requests.at(-1).body, { deleteAt: null });
    // a bad device id does not go out
    await api.trash(11, { after: 60, device: 'a b' });
    assert.equal(srv.state.requests.filter((x) => x.method === 'DELETE').at(-1).query.device, undefined);
    // a plain delete as before
    assert.deepEqual(await api.trash(13), { id: 13, trashed: true });

    const inc = srv.lock();
    await assert.rejects(api.mkdir(1, 'Neu'), (e) => e.status === 423 && e.code === 'device_locked' && e.body.incident.id === inc.id);
    const me = await api.me();
    assert.equal(me.guard.locked, true);
    assert.equal(me.guard.incident.id, inc.id);
    const d = await api.guardDecide(inc.id, 'release');
    assert.equal(d.incident.state, 'released');
    assert.equal((await api.me()).guard.locked, false);
    await assert.rejects(api.guardDecide(inc.id, 'delete'), (e) => e.code === 'invalid');

    await api.commit({ mediaId: 'docMedia00000001', parentId: 10, name: 'Kopie.pdf', text: 'Miete Oktober', entropy: 7.12345 });
    assert.deepEqual([commits(srv).at(-1).body.text, commits(srv).at(-1).body.entropy], ['Miete Oktober', 7.123]);
    await api.commit({ mediaId: 'toolMedia0000001', parentId: 10, name: 'Kopie2.pdf', text: '  ', entropy: 9 });
    assert.equal('text' in commits(srv).at(-1).body, false);
    assert.equal('entropy' in commits(srv).at(-1).body, false);
  });
});

// ── DriveService ───────────────────────────────────────────

describe('DriveService: folders, PDFs, portal, live, guard', () => {
  it('uploads whole folders: structure first, temporary files and node_modules left out', async () => {
    const { srv, svc } = await serviceSetup({ features: [] });
    const base = tmpDir('drive-folder-');
    const top = path.join(base, 'Urlaub');
    write(top, 'Strand.jpg', 'jpg-bytes');
    write(top, 'Tag 2/Notizen.txt', 'notizen');
    write(top, 'Tag 2/Abend/Bild.png', 'png');
    write(top, '~$Liste.docx', 'lock');
    write(top, 'Thumbs.db', 'x');
    write(top, 'app/node_modules/m.js', 'x');
    write(top, 'leer.txt', '');
    const r = await svc.upload(1, [top]);
    assert.equal(r.ok, true);
    assert.equal(r.queued.length, 3);
    assert.equal(r.folders, 4); // Urlaub, app, Tag 2, Abend
    assert.equal(r.skipped, 2); // node_modules, the empty file (Drive without 'emptyFiles')
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    const u = childNamed(srv, 1, 'Urlaub');
    assert.ok(u && u.isDir);
    assert.ok(childNamed(srv, u.id, 'Strand.jpg'));
    const tag2 = childNamed(srv, u.id, 'Tag 2');
    assert.ok(childNamed(srv, tag2.id, 'Notizen.txt'));
    assert.ok(childNamed(srv, childNamed(srv, tag2.id, 'Abend').id, 'Bild.png'));
    assert.equal(childNamed(srv, u.id, '~$Liste.docx'), undefined);
    assert.equal(childNamed(srv, u.id, 'Thumbs.db'), undefined);
    assert.equal(childNamed(srv, childNamed(srv, u.id, 'app').id, 'node_modules'), undefined);
    const row = svc.transfers().find((t) => t.folder);
    assert.deepEqual([row.name, row.state, row.files], ['Urlaub', 'done', 3]);
    // the same folder again: a free name, nothing mixed into the first
    const again = await svc.upload(1, [top]);
    assert.equal(again.queued.length, 3);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.ok(childNamed(srv, 1, 'Urlaub (2)'));
  });

  it('empty files of a folder go to Drives with emptyFiles', async () => {
    const { srv, svc } = await serviceSetup({ features: ['emptyFiles'] });
    const top = path.join(tmpDir('drive-folder-'), 'Leer');
    write(top, 'leer.txt', '');
    const r = await svc.upload(1, [top]);
    assert.equal(r.queued.length, 1);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    const n = childNamed(srv, childNamed(srv, 1, 'Leer').id, 'leer.txt');
    assert.ok(n && n.size === 0);
  });

  it('sends the text of PDFs and (Drive 1.6 guard) the entropy with the commit', async () => {
    const { srv, svc } = await serviceSetup({ features: ['guard'] });
    const dir = tmpDir('drive-pdf-');
    const pdf = write(dir, 'Mietvertrag.pdf', makePdf('Mietvertrag Wohnung Hauptstrasse'));
    const txt = write(dir, 'Notiz.txt', lowText(1));
    await svc.upload(1, [pdf, txt]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    const [a, b] = commits(srv).slice(-2).map((c) => c.body);
    assert.equal(a.name, 'Mietvertrag.pdf');
    assert.equal(a.text, 'Mietvertrag Wohnung Hauptstrasse');
    assert.ok(a.entropy > 0 && a.entropy < 8);
    assert.equal(b.text, undefined);
    assert.ok(b.entropy < 5);
  });

  it('a Drive without guard gets no entropy; a failing text reader does not stop the upload', async () => {
    const { srv, svc } = await serviceSetup({}, { readPdfText: async () => { throw new Error('boom'); } });
    const pdf = write(tmpDir('drive-pdf-'), 'Scan.pdf', '%PDF-1.4 scan');
    await svc.upload(1, [pdf]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    const c = commits(srv).at(-1).body;
    assert.equal(c.name, 'Scan.pdf');
    assert.equal('entropy' in c, false);
    assert.equal('text' in c, false);
    assert.equal(svc.transfers().at(-1).state, 'done');
  });

  it('"Im Portal öffnen": the node link of me.links on the server / portal host only', async () => {
    const opened = [];
    const shell = { openExternal: async (u) => { opened.push(u); } };
    const { svc } = await serviceSetup({ features: ['links'] }, { shell, portalUrl: 'https://gc.example.com' });
    assert.deepEqual(await svc.openInPortal(812), { ok: true });
    assert.deepEqual(opened, ['https://gc.example.com/portal#plg-gatecontrol-drive/node/812']);
    assert.deepEqual(await svc.portalLink(null), { ok: true, url: 'https://gc.example.com/portal#plg-gatecontrol-drive' });
    // a link to another host is not opened
    const other = await serviceSetup({ features: ['links'] }, { shell, portalUrl: 'https://portal.other.example' });
    assert.equal((await other.svc.openInPortal(812)).code, 'unsupported');
    assert.equal(opened.length, 1);
    // an older Drive: no links
    const old = await serviceSetup({}, { shell, portalUrl: 'https://gc.example.com' });
    assert.equal((await old.svc.openInPortal(812)).code, 'unsupported');
  });

  it('passes the live event changed on and asks for the guard on the event guard', async () => {
    const pushClient = new EventEmitter();
    const { srv, svc } = await serviceSetup({ features: ['guard'] }, { pushClient });
    const remote = [];
    const guards = [];
    svc.on('remote', (r) => remote.push(r));
    svc.on('guard', (g) => guards.push(g));
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-drive', type: 'changed', data: { areas: ['mine:2', 'bad area!'], seq: 41 } } });
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-messenger', type: 'changed', data: {} } });
    assert.deepEqual(remote, [{ areas: ['mine:2'], seq: 41 }]);
    const inc = srv.lock();
    pushClient.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-drive', type: 'guard', data: { incident: { id: inc.id } } } });
    await until(() => guards.some((g) => g.locked));
    const g = await svc.guard();
    assert.deepEqual([g.supported, g.locked, g.incident.id, g.incident.files], [true, true, inc.id, 60]);
  });

  it('a stopped device: the upload fails with device_locked, the next does not even start; release goes on', async () => {
    const { srv, svc } = await serviceSetup({ features: ['guard'] });
    const dir = tmpDir('drive-locked-');
    const a = write(dir, 'a.txt', 'aaa');
    const inc = srv.lock();
    await svc.upload(1, [a]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.equal(svc.transfers().at(-1).code, 'device_locked');
    await until(async () => (await svc.guard()).locked);
    const puts = srv.state.uploadCalls.length;
    await svc.upload(1, [write(dir, 'b.txt', 'bbb')]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.equal(svc.transfers().at(-1).code, 'device_locked');
    assert.equal(srv.state.uploadCalls.length, puts);
    const guards = [];
    svc.on('guard', (g) => guards.push(g));
    const r = await svc.guardDecide(inc.id, 'release');
    assert.equal(r.ok, true);
    assert.equal(r.guard.locked, false);
    assert.equal(guards.at(-1).decided, 'release');
    await svc.upload(1, [write(dir, 'c.txt', 'ccc')]);
    await until(() => svc.transfers().every((t) => !['queued', 'running'].includes(t.state)));
    assert.equal(svc.transfers().at(-1).state, 'done');
    await assert.rejects(svc.guardDecide(inc.id, 'maybe'), (e) => e.code === 'invalid');
  });
});

// ── DriveSync ──────────────────────────────────────────────

describe('DriveSync: Drive keeps the 30 days (deleteAfter)', () => {
  it('marks files deleted on the PC in Drive, calls it off when they are back, forgets them when Drive deleted them', async () => {
    const srv = await driveServer({ features: ['devices', 'deleteAfter'] });
    cleanup.push(() => srv.close());
    const { sync } = await syncSetup({ srv });
    const root = tmpDir('pc-bilder-');
    write(root, 'a.jpg', 'aaa');
    write(root, 'b.jpg', 'bbb');
    write(root, 'Alt/c.jpg', 'ccc');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const top = sync._folder(folder.id).target.nodeId;
    const a = childNamed(srv, top, 'a.jpg');
    const alt = childNamed(srv, top, 'Alt');
    fs.rmSync(path.join(root, 'a.jpg'));
    fs.rmSync(path.join(root, 'Alt'), { recursive: true });
    sync.sync(folder.id);
    await sync.idle();
    const dels = srv.state.requests.filter((x) => x.method === 'DELETE');
    assert.equal(dels.length, 2);
    for (const d of dels) assert.deepEqual([d.query.after, d.query.device], ['2592000', 'pc-ab12cd34']);
    assert.equal(srv.state.nodes.get(a.id).deleted, false);
    assert.ok(srv.state.nodes.get(a.id).deleteAt);
    let f = sync.status().folders[0];
    assert.equal(f.pendingDeletes, 2);
    assert.ok(Math.abs(f.pendingUntil - (Date.now() + 30 * DAY)) < 60000);
    // the next runs do not mark again
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.requests.filter((x) => x.method === 'DELETE').length, 2);
    // a.jpg is back (the same bytes): Drive calls the delete off
    write(root, 'a.jpg', 'aaa');
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(a.id).deleteAt, null);
    assert.deepEqual(srv.state.requests.filter((x) => x.method === 'PATCH').at(-1).body, { deleteAt: null });
    assert.equal(sync.status().folders[0].pendingDeletes, 1);
    // Drive's time is up: Drive deletes Alt, the PC forgets it
    srv.expireMarks(Date.now() + 31 * DAY);
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(alt.id).deleted, true);
    f = sync.status().folders[0];
    assert.equal(f.pendingDeletes, 0);
    assert.equal(f.pendingUntil, null);
    assert.equal(exists(root, 'Alt'), false);
    assert.equal(childNamed(srv, top, 'Alt'), undefined);
  });

  it('a list kept by an older version goes to Drive with the time left; a new version of a marked file calls it off', async () => {
    const features = ['devices'];
    const srv = await driveServer({ features });
    cleanup.push(() => srv.close());
    let t = Date.now();
    const { sync, api } = await syncSetup({ srv, now: () => t });
    const root = tmpDir('pc-alt-');
    write(root, 'a.txt', 'aaa');
    write(root, 'b.txt', 'bbb');
    write(root, 'c.txt', 'ccc');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    fs.rmSync(path.join(root, 'b.txt'));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.requests.filter((x) => x.method === 'DELETE').length, 0);
    assert.equal(sync.status().folders[0].pendingDeletes, 1);
    // ten days later the Drive can keep the time
    t += 10 * DAY;
    features.push('deleteAfter');
    api._features = null;
    sync.sync(folder.id);
    await sync.idle();
    const del = srv.state.requests.filter((x) => x.method === 'DELETE').at(-1);
    assert.ok(Math.abs(Number(del.query.after) - 20 * 86400) < 120, del.query.after);
    assert.equal(sync.status().folders[0].pendingDeletes, 1);
    // removing the folder deletes nothing: the delete is called off
    const top = sync._folder(folder.id).target.nodeId;
    const b = childNamed(srv, top, 'b.txt');
    assert.ok(srv.state.nodes.get(b.id).deleteAt);
    await sync.removeFolder(folder.id);
    assert.equal(srv.state.nodes.get(b.id).deleteAt, null);
  });
});

describe('DriveSync: the local ransomware check', () => {
  async function backedUp(n = 25, features = []) {
    const srv = await driveServer({ features });
    cleanup.push(() => srv.close());
    const s = await syncSetup({ srv });
    const root = tmpDir('pc-docs-');
    for (let i = 0; i < n; i++) write(root, `Briefe/brief${i}.txt`, lowText(i));
    const { folder } = await s.sync.addFolder({ path: root, mode: 'backup' });
    await s.sync.idle();
    return { srv, root, folder, ...s };
  }

  it('many files turned into high-entropy content: nothing goes up, "Pausiert lassen" / "Hochladen"', async () => {
    const { srv, sync, root, folder } = await backedUp(25);
    const before = commits(srv).length;
    for (let i = 0; i < 6; i++) write(root, `Briefe/brief${i}.txt`, crypto.randomBytes(70000));
    sync.sync(folder.id);
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(f.state, 'confirm');
    assert.equal(f.reason, 'suspect');
    assert.equal(f.suspect.count, 6);
    assert.equal(f.suspect.why, 'entropy');
    assert.equal(f.suspect.sample.length, 5);
    assert.equal(commits(srv).length, before);
    assert.equal(srv.state.uploadCalls.length, 25);
    // "Pausiert lassen"
    sync.confirmSuspect(folder.id, 'keep');
    f = sync.status().folders[0];
    assert.equal(f.state, 'paused');
    assert.equal(f.paused, true);
    // going on asks again
    sync.setPaused(folder.id, false);
    await sync.idle();
    assert.equal(sync.status().folders[0].reason, 'suspect');
    assert.throws(() => sync.confirmSuspect(folder.id, 'maybe'), (e) => e.code === 'invalid');
    // "Hochladen": they are the person's changes
    sync.confirmSuspect(folder.id, 'upload');
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.equal(commits(srv).length, before + 6);
    // the next run does not ask again (the new state is the agreed one)
    for (let i = 0; i < 6; i++) write(root, `Briefe/brief${i}.txt`, crypto.randomBytes(70000));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.throws(() => sync.confirmSuspect(folder.id, 'upload'), (e) => e.code === 'not_found');
  });

  it('files renamed to a ransomware extension trip it too; a few changes do not', async () => {
    const { srv, sync, root, folder } = await backedUp(25);
    const before = commits(srv).length;
    for (let i = 0; i < 3; i++) write(root, `Briefe/brief${i}.txt`, crypto.randomBytes(70000));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.equal(commits(srv).length, before + 3);
    for (let i = 10; i < 16; i++) {
      fs.writeFileSync(path.join(root, 'Briefe', `brief${i}.txt.locked`), crypto.randomBytes(1000));
      fs.rmSync(path.join(root, 'Briefe', `brief${i}.txt`));
    }
    sync.sync(folder.id);
    await sync.idle();
    const f = sync.status().folders[0];
    assert.equal(f.reason, 'suspect');
    assert.equal(f.suspect.why, 'extension');
    assert.equal(commits(srv).length, before + 3);
    assert.equal(srv.state.requests.filter((x) => x.method === 'DELETE').length, 0);
  });

  it('a compressed type that changes is no sign; the entropy goes with commits to Drive 1.6', async () => {
    const { srv, sync, root, folder } = await backedUp(0, ['guard']);
    for (let i = 0; i < 25; i++) write(root, `Fotos/f${i}.jpg`, crypto.randomBytes(70000));
    sync.sync(folder.id);
    await sync.idle();
    const n = commits(srv).length;
    assert.ok(commits(srv).at(-1).body.entropy > 7.9);
    for (let i = 0; i < 25; i++) write(root, `Fotos/f${i}.jpg`, crypto.randomBytes(70000));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.equal(commits(srv).length, n + 25);
  });
});

describe('DriveSync: Drive stops this device (guard)', () => {
  it('a 423 stops every folder at once; "War ich – freigeben" goes on', async () => {
    const srv = await driveServer({ features: ['guard'] });
    cleanup.push(() => srv.close());
    const { sync, svc } = await syncSetup({ srv });
    const root = tmpDir('pc-guard-');
    write(root, 'a.txt', 'aaa');
    write(root, 'b.txt', 'bbb');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const inc = srv.lock();
    write(root, 'a.txt', 'aaa neu');
    write(root, 'b.txt', 'bbb neu');
    write(root, 'c.txt', 'ccc');
    const before = commits(srv).length;
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(commits(srv).length, before + 1); // the first refused, then nothing more
    let st = sync.status();
    assert.equal(st.state, 'locked');
    assert.equal(st.folders[0].state, 'locked');
    assert.equal(st.folders[0].reason, 'guard_locked');
    assert.equal(st.guard.incident.id, inc.id);
    // runs wait
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(commits(srv).length, before + 1);
    // "War ich – freigeben"
    await svc.guardDecide(inc.id, 'release');
    await until(async () => { await sync.idle(); return sync.status().folders[0].state === 'idle'; });
    st = sync.status();
    assert.equal(st.guard, null);
    const top = sync._folder(folder.id).target.nodeId;
    assert.ok(childNamed(srv, top, 'c.txt'));
  });

  it('a device that is stopped already does not write at all', async () => {
    const srv = await driveServer({ features: ['guard'] });
    cleanup.push(() => srv.close());
    srv.lock();
    const { sync } = await syncSetup({ srv });
    const root = tmpDir('pc-guard0-');
    write(root, 'a.txt', 'aaa');
    await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'locked');
    assert.equal(srv.state.requests.filter((x) => x.method !== 'GET').length, 0);
  });

  it('"Rückgängig machen": the files come back from Drive, the PC\'s copies stay as held-back conflict copies', async () => {
    const srv = await driveServer({ features: ['guard'] });
    cleanup.push(() => srv.close());
    const { sync, svc } = await syncSetup({ srv });
    const root = tmpDir('pc-undo-');
    write(root, 'Brief.txt', lowText(1));
    write(root, 'Steuer.txt', lowText(2));
    write(root, 'Ruhe.txt', lowText(3));
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const snapshot = srv.snapshot();
    // "the malware": one file encrypted, one renamed (two changes, below the local check)
    write(root, 'Brief.txt', crypto.randomBytes(5000));
    fs.writeFileSync(path.join(root, 'Steuer.txt.locked'), crypto.randomBytes(5000));
    fs.rmSync(path.join(root, 'Steuer.txt'));
    sync.sync(folder.id);
    await sync.idle();
    const top = sync._folder(folder.id).target.nodeId;
    assert.ok(childNamed(srv, top, 'Steuer.txt.locked'));
    const inc = srv.lock({ snapshot });
    const before = commits(srv).length;
    const r = await svc.guardDecide(inc.id, 'undo');
    assert.equal(r.restored, 1);
    assert.equal(r.trashed, 1);
    await until(async () => { await sync.idle(); return sync.status().folders[0].state === 'idle' && exists(root, 'Brief.txt') && read(root, 'Brief.txt') === lowText(1); });
    // Drive's (old) bytes are back, the PC's are kept next to them
    assert.equal(read(root, 'Brief.txt'), lowText(1));
    const names = fs.readdirSync(root);
    const copy = names.find((x) => /^Brief \(Konflikt Desktop-PC .*\)\.txt$/.test(x));
    assert.ok(copy, names.join(', '));
    assert.ok(exists(root, 'Steuer.txt.locked'));
    assert.equal(read(root, 'Ruhe.txt'), lowText(3));
    // held back: nothing of it goes up again
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(commits(srv).length, before);
    assert.equal(childNamed(srv, top, copy), undefined);
    assert.equal(childNamed(srv, top, 'Steuer.txt.locked'), undefined);
    assert.equal(sync.status().folders[0].held, 2);
    // a held-back file the person changes again goes up as usual
    write(root, copy, 'neu geschrieben');
    sync.sync(folder.id);
    await sync.idle();
    assert.ok(childNamed(srv, top, copy));
    assert.equal(sync.status().folders[0].held, 1);
  });
});

// ── IPC ────────────────────────────────────────────────────

describe('drive IPC: new channels', () => {
  it('checks arguments and the bridge has the channels', async () => {
    const handlers = {};
    const calls = [];
    const svc = Object.assign(new EventEmitter(), {
      status: () => ({}),
      pickFolders: async () => { calls.push(['pickFolders']); return { ok: true, paths: [] }; },
      openInPortal: async (id) => { calls.push(['portal', id]); return { ok: true }; },
      guard: async (o) => { calls.push(['guard', o]); return { ok: true }; },
      guardDecide: async (id, d) => { calls.push(['decide', id, d]); return { ok: true }; },
    });
    const sync = Object.assign(new EventEmitter(), {
      confirmSuspect: (id, d) => { calls.push(['suspect', id, d]); return { ok: true }; },
    });
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, sync, getMainWindow: () => win, log });
    await handlers['drive:pick-folders']();
    await handlers['drive:portal'](null, { id: 12 });
    await handlers['drive:portal'](null, {});
    assert.equal((await handlers['drive:portal'](null, { id: 'x' })).code, 'invalid');
    await handlers['drive:guard'](null, { fresh: true });
    await handlers['drive:guard:decide'](null, { id: 7001, decision: 'undo' });
    assert.equal((await handlers['drive:guard:decide'](null, { id: 7001, decision: 'nope' })).code, 'invalid');
    assert.equal((await handlers['drive:guard:decide'](null, { id: '../x', decision: 'undo' })).code, 'invalid');
    const fid = 'abcdef0123456789';
    await handlers['drive:sync:suspect'](null, { id: fid, decision: 'keep' });
    assert.equal((await handlers['drive:sync:suspect'](null, { id: fid, decision: 'all' })).code, 'invalid');
    assert.deepEqual(calls, [['pickFolders'], ['portal', 12], ['portal', null], ['guard', { fresh: true }], ['decide', 7001, 'undo'], ['suspect', fid, 'keep']]);
    svc.emit('remote', { areas: ['mine:2'], seq: 3 });
    svc.emit('guard', { locked: true });
    assert.deepEqual(sent.slice(-2), [['drive:remote', { areas: ['mine:2'], seq: 3 }], ['drive:guard', { locked: true }]]);

    const invoked = [];
    const bridge = createBridgeApi({ invoke: (ch, a) => { invoked.push([ch, a]); return Promise.resolve(); }, on() {}, removeListener() {} }, { t: () => '', setLocale() {}, getLocale: () => 'de', onLocaleChange() {}, getSupportedLocales: () => [] });
    const d = bridge.drive;
    d.pickFolders(); d.openInPortal(5); d.guard(true); d.guardDecide(7001, 'release'); d.sync.suspect(fid, 'upload');
    assert.deepEqual(invoked, [
      ['drive:pick-folders', undefined], ['drive:portal', { id: 5 }], ['drive:guard', { fresh: true }],
      ['drive:guard:decide', { id: 7001, decision: 'release' }], ['drive:sync:suspect', { id: fid, decision: 'upload' }],
    ]);
    for (const ch of invoked.map((x) => x[0])) assert.ok(handlers[ch], ch);
    assert.equal(typeof d.onRemote, 'function');
    assert.equal(typeof d.onGuard, 'function');
  });
});
