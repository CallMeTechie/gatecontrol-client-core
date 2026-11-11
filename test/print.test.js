'use strict';

// "Drucken" (plugin gatecontrol-print): the pure helpers (utils/print.js —
// file types by name and content, cleaned answers, the options of a print
// call, push context), the service (services/print.js — the page while the
// plugin is listed, overview with cache and offline copy, jobs of older
// plugins, files only by token: file dialog, dropped, Drive with the vault
// question and the virus scan, the transfer upload → POST print with its
// retries and refusals, "Erneut drucken", pushes and toast click → page),
// its IPC (print:*) and the print.* texts.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const P = require('../src/utils/print');
const PrintService = require('../src/services/print');
const MessengerApi = require('../src/services/messenger-api');
const NotificationCenter = require('../src/services/notification-center');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const { MessengerError } = MessengerApi;
const tick = () => new Promise((r) => setImmediate(r));
const ms = (iso) => Date.parse(iso);
const NOW = ms('2026-11-11T16:52:10Z');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-print-test-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
function file(name, content) {
  const p = path.join(tmp, name);
  fs.writeFileSync(p, content);
  return p;
}
const PDF = (pages) => Buffer.from(`%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count ${pages} >>\nendobj\n%%EOF\n`, 'latin1');
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64, 1)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32, 1)]);
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(64, 2)]);

const HP = {
  id: 'u:0a1b2c3d4e5f', name: 'HP OfficeJet 8020', location: 'Wohnzimmer', online: true, problem: null, address: '192.168.1.70',
  printer: { state: 'idle', color: true, duplex: true, copiesMax: 99, formats: ['application/pdf'], office: true, media: { sizes: ['iso_a4_210x297mm', 'na_index-4x6_4x6in', '../x'], default: 'iso_a4_210x297mm', sources: ['main', 'photo', 'BAD'], sourceDefault: 'main' } },
  scanner: null,
};
const BROTHER = {
  id: 'h:1234567890abcdef', name: 'Brother HL-L2350DW\u0007', location: 'Arbeitszimmer', online: false, problem: 'cert_changed',
  printer: { state: 'offline', color: false, duplex: true, copiesMax: 500 },
};
const job = (id, state, extra = {}) => ({
  kind: 'print', id, user: 2, userName: 'Anna', device: 'HP OfficeJet 8020', deviceId: HP.id, name: `${id}.pdf`, pages: 2, copies: 1, color: true, duplex: true,
  media: null, source: null, via: 'app', state, error: null, message: null, at: '2026-11-11T16:49:00.000Z', updatedAt: '2026-11-11T16:50:00.000Z',
  expiresAt: '2026-11-12T16:49:00.000Z', doneAt: null, open: ['queued', 'sending', 'printing', 'waiting'].includes(state), ...extra,
});
const OVERVIEW = {
  ok: true,
  rights: { print: true, scan: true, pagesPerDay: 20, bwOnly: false },
  pagesLeft: 14,
  printers: [HP, BROTHER, { id: '../evil', name: 'x', printer: {} }, { id: 'u:scanner', name: 'Scanner', printer: null }, HP],
  scanners: [],
  jobs: [job('j1', 'printing', { message: 'media-empty' }), job('j2', 'waiting', { error: 'printer_offline' }), job('j3', 'done', { doneAt: '2026-11-11T08:41:00Z' }), { kind: 'scan', id: 's1', state: 'done' }, { id: 'bad id', state: 'done' }],
};

describe('utils/print: file types', () => {
  it('the type a file goes up as: by name, and its content must fit', () => {
    assert.equal(P.uploadType('Rechnung.pdf', null, PDF(2)), 'application/pdf');
    assert.equal(P.uploadType('Foto.JPG', null, JPEG), 'image/jpeg');
    assert.equal(P.uploadType('Bild.png', null, PNG), 'image/png');
    assert.equal(P.uploadType('Brief.docx', null, ZIP), P.OFFICE_TYPES[0]);
    assert.equal(P.uploadType('Tabelle.ods', null, ZIP), P.OFFICE_TYPES[4]);
    assert.equal(P.uploadType('Text.rtf', null, Buffer.from('{\\rtf1 hallo}')), 'application/rtf');
    assert.equal(P.uploadType('Liste.txt', null, Buffer.from('Zahnbürste\nSocken\n')), 'text/plain');
    // a PDF or picture under another name is what its content says
    assert.equal(P.uploadType('scan', null, PDF(1)), 'application/pdf');
    assert.equal(P.uploadType('falsch.pdf', null, JPEG), 'image/jpeg');
    // … everything else must be what it claims
    assert.equal(P.uploadType('falsch.pdf', null, Buffer.from('MZ\u0090\u0000binary')), null);
    assert.equal(P.uploadType('falsch.docx', null, Buffer.from('just text')), null);
    assert.equal(P.uploadType('falsch.docx', null, PDF(1)), null);
    assert.equal(P.uploadType('binary.txt', null, Buffer.from([0x41, 0x00, 0x42, 0x00, 0x43])), null);
    assert.equal(P.uploadType('setup.exe', null, Buffer.from('MZ\u0090\u0000')), null);
    assert.equal(P.uploadType('Film.mp4', 'video/mp4'), null);
    assert.equal(P.uploadType('Anim.gif', 'image/gif'), null);
    // a file of Drive before it is loaded: the name, else Drive's type
    assert.equal(P.uploadType('Rechnung.pdf'), 'application/pdf');
    assert.equal(P.uploadType('Scan vom Handy', 'Application/PDF; x=1'), 'application/pdf');
    assert.equal(P.uploadType('Foto', 'image/jpg'), 'image/jpeg');
    assert.equal(P.uploadType('Notiz', 'text/rtf'), 'application/rtf');
    assert.deepEqual(['application/pdf', 'image/heic', 'text/plain', P.OFFICE_TYPES[1], 'video/mp4'].map(P.kindOf), ['pdf', 'image', 'text', 'office', null]);
    assert.equal(P.MAX_BYTES, 52428800);
    assert.equal(P.UPLOAD_TYPES.length, 14, 'plugin.json media.types');
  });

  it('the pages of a PDF, when its page tree is readable', () => {
    assert.equal(P.pdfPages(PDF(2)), 2);
    assert.equal(P.pdfPages(Buffer.from('%PDF-1.4\n2 0 obj\n<< /Count 12 /Kids [3 0 R 4 0 R] /Type /Pages >>\nendobj\n4 0 obj\n<< /Type /Pages /Count 5 /Parent 2 0 R >>\nendobj', 'latin1')), 12);
    assert.equal(P.pdfPages(Buffer.from('%PDF-1.7\n5 0 obj\n<< /Type /ObjStm /N 3 >>\nstream\n…\nendstream', 'latin1')), null);
    assert.equal(P.pdfPages(Buffer.alloc(0)), null);
    assert.equal(P.pdfPages(null), null);
  });

  it('the options of a print call', () => {
    assert.deepEqual(P.printOptions({ deviceId: HP.id }), { deviceId: HP.id, copies: 1, color: false, duplex: false });
    assert.deepEqual(P.printOptions({ deviceId: HP.id, copies: 99, color: true, duplex: true, media: 'iso_a4_210x297mm', source: 'photo', evil: 1 }),
      { deviceId: HP.id, copies: 99, color: true, duplex: true, media: 'iso_a4_210x297mm', source: 'photo' });
    assert.deepEqual(P.printOptions({ deviceId: HP.id, media: '', source: null }), { deviceId: HP.id, copies: 1, color: false, duplex: false });
    for (const bad of [{}, { deviceId: '../x' }, { deviceId: HP.id, copies: 0 }, { deviceId: HP.id, copies: 100 }, { deviceId: HP.id, copies: '2' }, { deviceId: HP.id, copies: 1.5 },
      { deviceId: HP.id, media: 'A4' }, { deviceId: HP.id, source: 'Main Tray' }, null]) assert.equal(P.printOptions(bad), null, JSON.stringify(bad));
    assert.equal(P.jobName('  Rechnung\n2026.pdf '), 'Rechnung 2026.pdf');
    assert.equal(P.jobName(''), 'GateControl');
  });
});

describe('utils/print: answers', () => {
  it('overview: rights, printers without address, the print jobs', () => {
    const o = P.normalizeOverview(OVERVIEW);
    assert.deepEqual(o.rights, { print: true, pagesPerDay: 20, bwOnly: false });
    assert.equal(o.pagesLeft, 14);
    assert.deepEqual(o.printers.map((p) => p.id), [HP.id, BROTHER.id]);
    const [hp, br] = o.printers;
    assert.equal('address' in hp, false);
    assert.deepEqual(hp.media, { sizes: ['iso_a4_210x297mm', 'na_index-4x6_4x6in'], default: 'iso_a4_210x297mm', sources: ['main', 'photo'], sourceDefault: 'main' });
    assert.deepEqual([hp.state, hp.color, hp.duplex, hp.office, hp.copiesMax], ['idle', true, true, true, 99]);
    // a plugin before paper / tray / office (1.1.0)
    assert.deepEqual([br.name, br.online, br.problem, br.state, br.office, br.copiesMax], ['Brother HL-L2350DW', false, 'cert_changed', 'offline', false, 99]);
    assert.deepEqual(br.media, { sizes: [], default: null, sources: [], sourceDefault: null });
    assert.deepEqual(o.jobs.map((j) => j.id), ['j1', 'j2', 'j3']);
    assert.deepEqual([o.jobs[0].message, o.jobs[0].open, o.jobs[1].error, o.jobs[2].open], ['media-empty', true, 'printer_offline', false]);
    assert.equal(o.jobs[2].doneAt, ms('2026-11-11T08:41:00Z'));
    assert.equal(o.jobs[0].expiresAt, ms('2026-11-12T16:49:00Z'));
  });

  it('overview: no right → no printers; no limit → pagesLeft null; not an answer → null', () => {
    const none = P.normalizeOverview({ ...OVERVIEW, rights: { print: false, scan: true, pagesPerDay: 0, bwOnly: false }, pagesLeft: null });
    assert.deepEqual([none.rights.print, none.printers, none.pagesLeft, none.jobs.length], [false, [], null, 3]);
    assert.equal(P.normalizeOverview({ ...OVERVIEW, rights: { print: true, pagesPerDay: 0 }, pagesLeft: null }).pagesLeft, null);
    assert.equal(P.normalizeOverview({ ok: true }), null);
    assert.equal(P.normalizeOverview(null), null);
  });

  it('a job of a plugin before 1.1.1 (no expiresAt / doneAt) and before 1.1.0 (no media, no message)', () => {
    const j = P.normalizeJob({ id: 'old1', device: 'HP', name: 'a.pdf', pages: 3, copies: 2, color: 1, duplex: 0, state: 'waiting', error: 'printer_offline', at: '2026-11-11T16:00:00Z', updatedAt: '2026-11-11T16:30:00Z' });
    assert.deepEqual([j.expiresAt, j.doneAt, j.media, j.source, j.message, j.deviceId], [null, null, null, null, null, null]);
    assert.deepEqual([j.pages, j.copies, j.color, j.duplex, j.open, j.at], [3, 2, true, false, true, ms('2026-11-11T16:00:00Z')]);
    assert.equal(P.normalizeJob({ id: 'x', state: 'Done!' }), null);
    assert.equal(P.normalizeJob({ id: 'x', state: 'done', message: '<b>' }).message, null);
    assert.equal(P.normalizeJob({ id: 'x', state: 'future_state' }).open, false);
  });

  it('push context: only "Druck fertig" / "Druck fehlgeschlagen"', () => {
    assert.deepEqual(P.pushContext({ topic: 'plugin:gatecontrol-print:print_done', collapse_key: 'print-j1' }), { type: 'print', kind: 'done', jobId: 'j1' });
    assert.deepEqual(P.pushContext({ topic: 'plugin:gatecontrol-print:print_failed', collapse_key: 'plugin:gatecontrol-print:print-ab_c-9' }), { type: 'print', kind: 'failed', jobId: 'ab_c-9' });
    assert.deepEqual(P.pushContext({ topic: 'plugin:gatecontrol-print:print_done' }), { type: 'print', kind: 'done', jobId: null });
    assert.equal(P.pushContext({ topic: 'plugin:gatecontrol-print:scan_done' }), null);
    assert.equal(P.pushContext({ topic: 'plugin:gatecontrol-drive:print_done' }), null);
    assert.equal(P.pushContext(null), null);
  });
});

// ── the service ──────────────────────────────────────────

function fakeApi(routes = {}) {
  const api = { calls: [], routes, scopeValue: 'https://gc.example\nkey' };
  api.scope = () => api.scopeValue;
  api._call = async (method, p, opts = {}) => {
    const key = p.replace(P.API_BASE, '');
    api.calls.push([method, key, opts.body === undefined ? null : opts.body]);
    let r = api.routes[`${method} ${key}`];
    if (r === undefined && method === 'GET') r = api.routes[key];
    if (typeof r === 'function') r = r(opts.body);
    if (r instanceof Error) throw r;
    if (r === undefined) throw new MessengerError('HTTP 404', { status: 404, code: 'http_404' });
    return JSON.parse(JSON.stringify(r));
  };
  return api;
}

const plugins = (version = '1.1.1') => ({ ok: true, plugins: [{ id: 'gatecontrol-drive', version: '1.29.0' }, { id: 'gatecontrol-print', name: 'Drucken & Scannen', version, tab: null }] });
const refusal = (status, code, body = {}) => new MessengerError(code, { status, code, body: { ok: false, code, ...body } });

function fakeMedia() {
  const m = { uploads: [], next: null, gate: null };
  m.upload = async (f, { onProgress } = {}) => {
    m.uploads.push({ ...f, bytes: fs.readFileSync(f.path).length });
    if (onProgress) { onProgress(Math.floor(f.size / 2), f.size); onProgress(f.size, f.size); }
    if (m.gate) await m.gate;
    if (m.next instanceof Error) { const e = m.next; m.next = null; throw e; }
    const r = m.next || {};
    m.next = null;
    return { mediaId: 'a'.repeat(32), mime: f.mime, bytes: f.size, ...r };
  };
  return m;
}

function fakeDrive(nodes = {}) {
  const d = { nodes, copies: [], disposed: 0 };
  d.fileInfo = async (id) => {
    const n = d.nodes[id];
    if (!n) throw new MessengerError('gone', { status: 404, code: 'not_found' });
    if (n.isDir) throw new MessengerError('not a file', { code: 'invalid' });
    if (n.blocked) throw new MessengerError('blocked by the virus scan', { status: 423, code: n.blocked });
    if (n.locked) throw new MessengerError('locked', { code: 'vault_locked' });
    return { ok: true, id, name: n.name, size: n.content.length, mime: n.mime || null, encrypted: !!n.encrypted, parentId: 1 };
  };
  d.fileCopy = async (id) => {
    const n = d.nodes[id];
    const p = file(`drive-${id}-${d.copies.length}`, n.content);
    d.copies.push(id);
    return { ok: true, path: p, name: n.name, size: n.content.length, dispose: async () => { d.disposed++; } };
  };
  return d;
}

function service(routes = {}, opts = {}) {
  let now = NOW;
  const api = fakeApi({ '/api/v1/client/plugins': plugins(), overview: OVERVIEW, ...routes });
  const media = fakeMedia();
  const slept = [];
  const s = new PrintService({
    api, media, log, timing: { recheckMs: 1e9, retryMinMs: 1e9 }, now: () => now, sleep: async (n) => { slept.push(n); }, ...opts,
  });
  const events = { state: [], push: [], transfers: [], job: [] };
  for (const k of Object.keys(events)) s.on(k, (x) => events[k].push(x));
  /** Resolves when the queue of transfers is through. */
  const settled = async () => { for (let i = 0; i < 5000 && (s._pumping || s.transfers().some((t) => t.phase === 'waiting')); i++) await new Promise((r) => setTimeout(r, 2)); await tick(); };
  return { s, api, media, events, slept, settled, setNow: (v) => { now = v; } };
}

describe('PrintService: availability and overview', () => {
  it('the page exists while the server lists the plugin for the apps', async () => {
    const { s, api, events } = service();
    assert.equal(s.status().state, 'unknown');
    assert.deepEqual([(await s.check()).state, s.status().version], ['available', '1.1.1']);
    assert.equal(events.state.length, 1);
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [{ id: 'gatecontrol-drive', version: '1.29.0' }] };
    assert.deepEqual([(await s.check()).state, s.status().reason], ['unavailable', 'not_installed']);
    // a server before plugins for the apps, a refused token, no connection
    delete api.routes['/api/v1/client/plugins'];
    assert.equal((await s.check()).reason, 'unsupported');
    api.routes['/api/v1/client/plugins'] = refusal(401, 'unauthorized');
    assert.equal((await s.check()).reason, 'auth');
    api.routes['/api/v1/client/plugins'] = new MessengerError('down', { code: 'network' });
    assert.deepEqual([(await s.check()).state, s.status().reason], ['error', 'network']);
    api.routes['/api/v1/client/plugins'] = plugins('1.0.1');
    await s.check();
    api.routes['/api/v1/client/plugins'] = new MessengerError('down', { code: 'timeout' });
    assert.equal((await s.check()).state, 'available', 'a network error keeps the page');
  });

  it('overview: cleaned, cached for a moment, the last copy without a connection', async () => {
    const { s, api, setNow } = service();
    const o = await s.overview();
    assert.deepEqual([o.ok, o.stale, o.fetchedAt, o.printers.length, o.jobs.length, o.pagesLeft], [true, false, NOW, 2, 3, 14]);
    await s.overview();
    assert.equal(api.calls.filter((c) => c[1] === 'overview').length, 1, 'from the cache');
    await s.overview({ refresh: true });
    assert.equal(api.calls.filter((c) => c[1] === 'overview').length, 2);
    setNow(NOW + 60000);
    api.routes.overview = new MessengerError('down', { code: 'network' });
    const old = await s.overview();
    assert.deepEqual([old.ok, old.stale, old.error, old.fetchedAt, old.jobs.length], [true, true, 'network', NOW, 3]);
    // answers do not share objects with the cache
    old.jobs.length = 0;
    assert.equal((await s.overview()).jobs.length, 3);
  });

  it('overview: the plugin gone for the apps → "unavailable" and the plugin list is asked again; other refusals as they are', async () => {
    const { s, api } = service();
    await s.check();
    delete api.routes.overview;
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    await assert.rejects(s.overview(), (e) => e.code === 'unavailable' && e.status === 404);
    await tick();
    assert.equal(s.status().state, 'unavailable');
    api.routes.overview = refusal(403, 'forbidden');
    await assert.rejects(s.overview(), (e) => e.code === 'forbidden');
    api.routes.overview = { ok: true, something: 'else' };
    await assert.rejects(s.overview(), (e) => e.code === 'bad_response');
    api.routes.overview = new MessengerError('down', { code: 'network' });
    await assert.rejects(s.overview(), (e) => e.code === 'network', 'no copy to fall back on');
  });

  it('a job: fresh from jobs/<id>; gone → null', async () => {
    const { s, api } = service({ 'jobs/j1': { ok: true, job: job('j1', 'done', { doneAt: '2026-11-11T16:53:00Z' }) } });
    const r = await s.job('j1');
    assert.deepEqual([r.job.state, r.job.doneAt, r.job.open], ['done', ms('2026-11-11T16:53:00Z'), false]);
    api.routes['jobs/j9'] = refusal(404, 'not_found');
    assert.deepEqual(await s.job('j9'), { ok: true, job: null });
    assert.equal(api.calls.filter((c) => c[1] === 'overview').length, 0, 'the route is known: no detour');
    await assert.rejects(s.job('../x'), (e) => e.code === 'invalid');
    api.routes['jobs/j1'] = new MessengerError('down', { code: 'network' });
    await assert.rejects(s.job('j1'), (e) => e.code === 'network');
  });

  it('a plugin before 1.1.0 (no jobs/<id>): the job comes from the overview, without an error', async () => {
    const old = { ...OVERVIEW, jobs: OVERVIEW.jobs.map((j) => { const { expiresAt, doneAt, message, media, source, ...rest } = j; return rest; }) };
    const { s, api } = service({ overview: old });
    const r = await s.job('j2');
    assert.deepEqual([r.ok, r.job.state, r.job.expiresAt, r.job.doneAt], [true, 'waiting', null, null]);
    const n = api.calls.length;
    assert.equal((await s.job('j1')).job.state, 'printing');
    assert.deepEqual(api.calls.slice(n).map((c) => c[1]), [], 'the route is not asked again, the overview is young enough');
    assert.deepEqual(await s.job('nope'), { ok: true, job: null });
  });

  it('cancel: the answer, and the list is asked again', async () => {
    const { s, api } = service({ 'POST jobs/j2/cancel': { ok: true, canceled: true }, 'POST jobs/j1/cancel': { ok: true, canceled: false } });
    await s.overview();
    assert.deepEqual(await s.cancel('j2'), { ok: true, canceled: true });
    assert.deepEqual(api.calls.at(-1), ['POST', 'jobs/j2/cancel', {}]);
    await s.overview();
    assert.equal(api.calls.filter((c) => c[1] === 'overview').length, 2);
    assert.deepEqual(await s.cancel('j1'), { ok: true, canceled: false });
    await assert.rejects(s.cancel('j/1'), (e) => e.code === 'invalid');
  });

  it('another server: answers, picked files and jobs in the making are dropped', async () => {
    const { s, api, events } = service();
    await s.check();
    await s.overview();
    const { files } = await s.addPaths([file('a.pdf', PDF(1))]);
    api.scopeValue = 'https://other.example\nkey2';
    await s.resetForNewServer();
    assert.equal(events.state.at(-1).state, 'unknown');
    await assert.rejects(s.submit({ tokens: [files[0].token], deviceId: HP.id }), (e) => e.code === 'not_picked');
    const n = api.calls.length;
    await s.overview();
    assert.equal(api.calls.length, n + 1);
  });
});

describe('PrintService: files only by token', () => {
  it('files of this PC: checked by name, content and size', async () => {
    const { s } = service();
    const big = path.join(tmp, 'gross.pdf');
    fs.writeFileSync(big, PDF(1));
    fs.truncateSync(big, P.MAX_BYTES + 1);
    fs.mkdirSync(path.join(tmp, 'Ordner.pdf'), { recursive: true });
    const r = await s.addPaths([
      file('Stromrechnung 2026-10.pdf', PDF(2)), file('Urlaub.jpg', JPEG), file('Elternbrief.docx', ZIP), file('Packliste.txt', 'Socken\n'),
      file('leer.pdf', ''), big, file('setup.exe', 'MZ'), file('falsch.pdf', 'MZ\u0000\u0001'), path.join(tmp, 'Ordner.pdf'), path.join(tmp, 'gibt-es-nicht.pdf'), 'relativ.pdf', 42,
    ]);
    assert.equal(r.ok, true);
    assert.deepEqual(r.files.map((f) => [f.name, f.kind, f.from, f.vault, f.pages]), [
      ['Stromrechnung 2026-10.pdf', 'pdf', 'pc', false, 2], ['Urlaub.jpg', 'image', 'pc', false, 1], ['Elternbrief.docx', 'office', 'pc', false, null], ['Packliste.txt', 'text', 'pc', false, null],
    ]);
    assert.equal(r.files[0].size, PDF(2).length);
    for (const f of r.files) {
      assert.match(f.token, /^[A-Za-z0-9_-]{24}$/);
      assert.equal('path' in f, false, 'the page never sees a path');
    }
    assert.deepEqual(r.rejected, [
      { name: 'leer.pdf', code: 'empty' }, { name: 'gross.pdf', code: 'too_large' }, { name: 'setup.exe', code: 'format' }, { name: 'falsch.pdf', code: 'format' },
      { name: 'Ordner.pdf', code: 'folder' }, { name: 'gibt-es-nicht.pdf', code: 'missing' }, { name: '', code: 'missing' }, { name: '', code: 'missing' },
    ]);
    // more than 20 at once
    const many = await s.addPaths(Array.from({ length: 22 }, () => path.join(tmp, 'Urlaub.jpg')));
    assert.deepEqual([many.files.length, many.rejected.map((x) => x.code)], [20, ['too_many', 'too_many']]);
  });

  it('the file dialog: its own filter, cancelled, picked', async () => {
    const asked = [];
    const dialog = { showOpenDialog: async (...a) => { asked.push(a); return dialog.answer; } };
    const win = {};
    const { s } = service({}, { dialog, getMainWindow: () => win, dialogPath: () => 'C:\\Users\\anna\\Documents' });
    dialog.answer = { canceled: true, filePaths: [] };
    assert.deepEqual(await s.pick(), { ok: false, code: 'cancelled', error: 'cancelled' });
    assert.equal(asked[0][0], win);
    assert.deepEqual(asked[0][1].properties, ['openFile', 'multiSelections']);
    assert.equal(asked[0][1].defaultPath, 'C:\\Users\\anna\\Documents');
    assert.ok(asked[0][1].filters[0].extensions.includes('docx'));
    dialog.answer = { canceled: false, filePaths: [file('b.png', PNG)] };
    const r = await s.pick();
    assert.deepEqual([r.files.length, r.files[0].type], [1, 'image/png']);
    await assert.rejects(service().s.pick(), (e) => e.code === 'unsupported');
  });

  it('files of Drive: no folders, nothing the virus scan blocks, vault files only after the yes', async () => {
    const drive = fakeDrive({
      11: { name: 'Mietvertrag Scan.pdf', content: PDF(6), mime: 'application/pdf' },
      12: { name: 'Finanzen', isDir: true },
      13: { name: 'Virus.pdf', content: PDF(1), blocked: 'quarantined' },
      14: { name: 'Wird geprüft.pdf', content: PDF(1), blocked: 'scan_pending' },
      15: { name: 'Film.mp4', content: Buffer.alloc(10, 1), mime: 'video/mp4' },
      16: { name: 'Pass.jpg', content: JPEG, encrypted: true, mime: 'application/octet-stream' },
      17: { name: 'Geheim.pdf', content: PDF(1), locked: true },
      18: { name: 'Scan ohne Endung', content: PDF(1), mime: 'application/pdf' },
    });
    const { s } = service({}, { drive });
    const r = await s.addDrive([11, 12, 13, 14, 15, 16, 17, 18, 99, 'x']);
    assert.deepEqual(r.files.map((f) => [f.name, f.kind, f.from, f.vault, f.pages]), [['Mietvertrag Scan.pdf', 'pdf', 'drive', false, null], ['Scan ohne Endung', 'pdf', 'drive', false, null]]);
    assert.deepEqual(r.rejected, [
      { name: '', code: 'folder' }, { name: '', code: 'quarantined' }, { name: '', code: 'scan_pending' }, { name: 'Film.mp4', code: 'format' },
      { name: 'Pass.jpg', code: 'vault_confirm' }, { name: '', code: 'vault_locked' }, { name: '', code: 'not_found' },
    ]);
    assert.equal(drive.copies.length, 0, 'nothing is loaded before printing');
    const yes = await s.addDrive([16], { vault: true });
    assert.deepEqual([yes.files[0].vault, yes.files[0].kind, yes.files[0].pages, yes.rejected], [true, 'image', 1, []]);
    await assert.rejects(service().s.addDrive([11]), (e) => e.code === 'unsupported');
  });

  it('submit takes tokens once, never paths', async () => {
    const { s, settled } = service({ 'POST print': (b) => ({ ok: true, job: job('n1', 'queued', { name: b.name }), pagesLeft: 12 }) });
    const { files } = await s.addPaths([file('c.pdf', PDF(2))]);
    await assert.rejects(s.submit({ tokens: [path.join(tmp, 'c.pdf')], deviceId: HP.id }), (e) => e.code === 'invalid');
    await assert.rejects(s.submit({ tokens: ['A'.repeat(24)], deviceId: HP.id }), (e) => e.code === 'not_picked');
    await assert.rejects(s.submit({ tokens: [files[0].token], deviceId: '../x' }), (e) => e.code === 'invalid');
    await assert.rejects(s.submit({ tokens: [files[0].token], deviceId: HP.id, copies: 100 }), (e) => e.code === 'invalid');
    await assert.rejects(s.submit({ tokens: [], deviceId: HP.id }), (e) => e.code === 'invalid');
    assert.equal((await s.submit({ tokens: [files[0].token], deviceId: HP.id })).ok, true);
    await settled();
    await assert.rejects(s.submit({ tokens: [files[0].token], deviceId: HP.id }), (e) => e.code === 'not_picked', 'a token prints once');
    const again = await s.addPaths([path.join(tmp, 'c.pdf')]);
    assert.deepEqual(s.forget([again.files[0].token]), { ok: true });
    await assert.rejects(s.submit({ tokens: [again.files[0].token], deviceId: HP.id }), (e) => e.code === 'not_picked');
  });
});

describe('PrintService: printing', () => {
  it('a file of this PC: upload with progress, POST print, then it is a job', async () => {
    const store = createMemoryStore();
    const { s, api, media, events, settled } = service({ 'POST print': (b) => ({ ok: true, job: job('n1', 'queued', { name: b.name, copies: b.copies }), pagesLeft: 10 }) }, { store });
    await s.overview();
    const { files } = await s.addPaths([file('Stromrechnung.pdf', PDF(2))]);
    const r = await s.submit({ tokens: [files[0].token], deviceId: HP.id, copies: 2, color: true, duplex: true, media: 'iso_a4_210x297mm', source: 'main' });
    assert.deepEqual(r.transfers.map((t) => [t.id, t.name, t.phase, t.device, t.copies, t.from]), [['t1', 'Stromrechnung.pdf', 'waiting', 'HP OfficeJet 8020', 2, 'pc']]);
    assert.equal('src' in r.transfers[0] || 'path' in r.transfers[0], false);
    await settled();
    assert.deepEqual(media.uploads.map((u) => [path.basename(u.path), u.mime, u.size]), [['Stromrechnung.pdf', 'application/pdf', PDF(2).length]]);
    assert.deepEqual(api.calls.at(-1), ['POST', 'print', { deviceId: HP.id, copies: 2, color: true, duplex: true, media: 'iso_a4_210x297mm', source: 'main', mediaId: 'a'.repeat(32), name: 'Stromrechnung.pdf' }]);
    const phases = events.transfers.map((l) => (l[0] ? `${l[0].phase}:${l[0].sent}` : 'gone'));
    assert.deepEqual([phases[0], phases.at(-2), phases.at(-1)], ['waiting:0', `sending:${PDF(2).length}`, 'gone']);
    assert.ok(phases.includes('uploading:0'));
    assert.deepEqual(events.job.map((j) => [j.job.id, j.job.state, j.job.copies, j.pagesLeft, j.transferId]), [['n1', 'queued', 2, 10, 't1']]);
    assert.deepEqual(s.transfers(), []);
    // the list is asked again, and the file is remembered for "Erneut drucken" — by the server's address, never its token
    const n = api.calls.filter((c) => c[1] === 'overview').length;
    await s.overview();
    assert.equal(api.calls.filter((c) => c[1] === 'overview').length, n + 1);
    assert.deepEqual(s.sources(), { ok: true, ids: ['n1'] });
    assert.deepEqual(store.get('printSources'), [{ jobId: 'n1', scope: 'https://gc.example', kind: 'pc', path: path.join(tmp, 'Stromrechnung.pdf') }]);
    assert.ok(!JSON.stringify(store.get('printSources')).includes('key'));
  });

  it('several files: one after the other, each a job with the same options', async () => {
    let n = 0;
    const { s, media, events, settled } = service({ 'POST print': (b) => ({ ok: true, job: job(`n${++n}`, 'queued', { name: b.name }), pagesLeft: null }) });
    await s.overview();
    const { files } = await s.addPaths([file('eins.pdf', PDF(1)), file('zwei.jpg', JPEG), file('drei.txt', 'x')]);
    const r = await s.submit({ tokens: files.map((f) => f.token), deviceId: BROTHER.id });
    assert.deepEqual(r.transfers.map((t) => t.id), ['t1', 't2', 't3']);
    await settled();
    // the printer's name stays known for the next jobs although every job made drops the list
    const more = await s.addPaths([path.join(tmp, 'eins.pdf')]);
    assert.equal((await s.submit({ tokens: [more.files[0].token], deviceId: BROTHER.id })).transfers[0].device, 'Brother HL-L2350DW');
    await settled();
    media.uploads.pop();
    events.job.pop();
    assert.deepEqual(media.uploads.map((u) => u.mime), ['application/pdf', 'image/jpeg', 'text/plain']);
    assert.deepEqual(events.job.map((j) => [j.job.name, j.pagesLeft]), [['eins.pdf', null], ['zwei.jpg', null], ['drei.txt', null]]);
  });

  it('a file of Drive: loaded, checked by its content, sent, and the copy of a vault file goes again', async () => {
    const drive = fakeDrive({
      11: { name: 'Mietvertrag.pdf', content: PDF(6), mime: 'application/pdf' },
      16: { name: 'Pass.jpg', content: JPEG, encrypted: true },
      19: { name: 'Getarnt.pdf', content: Buffer.from('MZ\u0000\u0001\u0002'), mime: 'application/pdf' },
    });
    let n = 0;
    const { s, media, events, settled } = service({ 'POST print': (b) => ({ ok: true, job: job(`d${++n}`, 'queued', { name: b.name }), pagesLeft: 8 }) }, { drive });
    const a = await s.addDrive([11, 19]);
    const b = await s.addDrive([16], { vault: true });
    await s.submit({ tokens: [...a.files, ...b.files].map((f) => f.token), deviceId: HP.id });
    await settled();
    assert.deepEqual(drive.copies, [11, 19, 16]);
    assert.equal(drive.disposed, 3, 'every copy is given back (a vault file is removed)');
    assert.deepEqual(media.uploads.map((u) => u.mime), ['application/pdf', 'image/jpeg']);
    assert.deepEqual(events.job.map((j) => j.job.name), ['Mietvertrag.pdf', 'Pass.jpg']);
    assert.ok(events.transfers.some((l) => l.some((t) => t.phase === 'loading')));
    // what Drive called a PDF was none
    assert.deepEqual(s.transfers().map((t) => [t.name, t.phase, t.code]), [['Getarnt.pdf', 'failed', 'format']]);
  });

  it('print_failed right after the upload (the virus scan holds the file) is asked twice more', async () => {
    let tries = 0;
    const { s, api, slept, settled } = service({ 'POST print': () => (++tries < 3 ? refusal(502, 'print_failed') : { ok: true, job: job('r1', 'queued'), pagesLeft: 5 }) });
    const { files } = await s.addPaths([file('d.pdf', PDF(1))]);
    await s.submit({ tokens: [files[0].token], deviceId: HP.id });
    await settled();
    assert.deepEqual(slept, [4000, 8000]);
    assert.equal(api.calls.filter((c) => c[1] === 'print').length, 3);
    assert.deepEqual(s.transfers(), []);
    // … and not for ever
    api.routes['POST print'] = refusal(502, 'print_failed');
    const again = await s.addPaths([path.join(tmp, 'd.pdf')]);
    await s.submit({ tokens: [again.files[0].token], deviceId: HP.id });
    await settled();
    assert.equal(api.calls.filter((c) => c[1] === 'print').length, 6);
    assert.deepEqual(s.transfers().map((t) => [t.phase, t.code]), [['failed', 'print_failed']]);
  });

  it('refusals stay in the list with their reason: page limit, office off, virus scan, no connection', async () => {
    const { s, api, media, events, settled } = service({ 'POST print': refusal(409, 'limit', { error: 'Das wären 25 Seiten – heute gehen noch 14.', left: 14, pages: 25 }) });
    const print1 = async (name, content) => {
      const { files } = await s.addPaths([file(name, content)]);
      await s.submit({ tokens: [files[0].token], deviceId: HP.id, copies: 25 });
      await settled();
      return s.transfers().at(-1);
    };
    const lim = await print1('e.pdf', PDF(1));
    assert.deepEqual([lim.phase, lim.code, lim.left, lim.pages, lim.error], ['failed', 'limit', 14, 25, 'Das wären 25 Seiten – heute gehen noch 14.']);
    assert.equal(events.job.length, 0);
    api.routes['POST print'] = refusal(409, 'office_off', { error: 'office_off' });
    const off = await print1('f.docx', ZIP);
    assert.deepEqual([off.code, off.error], ['office_off', null]);
    media.next = refusal(423, 'quarantined');
    assert.equal((await print1('g.pdf', PDF(1))).code, 'quarantined');
    media.next = { scan: { state: 'infected', blocked: true } };
    assert.equal((await print1('h.pdf', PDF(1))).code, 'quarantined');
    media.next = refusal(413, 'too_large');
    assert.equal((await print1('i.pdf', PDF(1))).code, 'too_large');
    media.next = new MessengerError('down', { code: 'network' });
    const net = await print1('k.pdf', PDF(1));
    assert.deepEqual([net.code, net.error], ['network', null]);
    // the file went away between the dialog and the upload
    const { files } = await s.addPaths([file('weg.pdf', PDF(1))]);
    fs.rmSync(path.join(tmp, 'weg.pdf'));
    await s.submit({ tokens: [files[0].token], deviceId: HP.id });
    await settled();
    assert.equal(s.transfers().at(-1).code, 'missing');
    // "Entfernen"
    assert.equal(s.transfers().length, 7);
    s.cancelTransfer(s.transfers()[0].id);
    assert.equal(s.transfers().length, 6);
    assert.deepEqual(s.cancelTransfer('t999'), { ok: true });
  });

  it('"Abbrechen" while the file goes up: no job is made', async () => {
    const { s, api, media, events, settled } = service({ 'POST print': { ok: true, job: job('x1', 'queued'), pagesLeft: 1 } });
    let open;
    media.gate = new Promise((r) => { open = r; });
    const { files } = await s.addPaths([file('l.pdf', PDF(1)), file('m.pdf', PDF(1))]);
    await s.submit({ tokens: files.map((f) => f.token), deviceId: HP.id });
    for (let i = 0; i < 2000 && !media.uploads.length; i++) await new Promise((r) => setTimeout(r, 2));
    assert.equal(s.transfers()[0].phase, 'uploading');
    s.cancelTransfer('t1');
    assert.deepEqual(s.transfers().map((t) => t.id), ['t2']);
    media.gate = null;
    open();
    await settled();
    assert.equal(api.calls.filter((c) => c[1] === 'print').length, 1, 'only the second file became a job');
    assert.deepEqual(events.job.map((j) => j.transferId), ['t2']);
  });

  it('"Erneut drucken": the file again while it lies where it was; a failed one with its options', async () => {
    const store = createMemoryStore();
    const drive = fakeDrive({ 11: { name: 'Mietvertrag.pdf', content: PDF(6), mime: 'application/pdf' } });
    let n = 0;
    const { s, api, settled } = service({ 'POST print': (b) => ({ ok: true, job: job(`a${++n}`, 'queued', { name: b.name }), pagesLeft: 3 }) }, { store, drive });
    const pc = await s.addPaths([file('n.pdf', PDF(1))]);
    const dr = await s.addDrive([11]);
    await s.submit({ tokens: [pc.files[0].token, dr.files[0].token], deviceId: HP.id, copies: 3 });
    await settled();
    const a = await s.again({ jobId: 'a1' });
    assert.deepEqual([a.ok, a.files[0].name, a.files[0].from, a.options], [true, 'n.pdf', 'pc', null]);
    assert.equal((await s.again({ jobId: 'a2' })).files[0].from, 'drive');
    assert.deepEqual(await s.again({ jobId: 'unknown' }), { ok: false, code: 'source_gone', error: 'the file is not known any more' });
    fs.rmSync(path.join(tmp, 'n.pdf'));
    assert.equal((await s.again({ jobId: 'a1' })).code, 'source_gone');
    // a new service (the app started again) still knows the files — of this server only
    const s2 = new PrintService({ api, media: fakeMedia(), log, store, drive });
    assert.deepEqual(s2.sources().ids, ['a1', 'a2']);
    api.scopeValue = 'https://other.example\nkey';
    assert.deepEqual(new PrintService({ api, media: fakeMedia(), log, store, drive }).sources().ids, []);
    api.scopeValue = 'https://gc.example\nkey';
    // a failed job in the making: its file and its options
    api.routes['POST print'] = refusal(409, 'limit', { left: 0, pages: 3 });
    const f = await s.addPaths([file('o.pdf', PDF(1))]);
    await s.submit({ tokens: [f.files[0].token], deviceId: BROTHER.id, copies: 3, duplex: true });
    await settled();
    const t = s.transfers()[0];
    const b = await s.again({ transferId: t.id });
    assert.deepEqual([b.files[0].name, b.options], ['o.pdf', { deviceId: BROTHER.id, copies: 3, color: false, duplex: true }]);
  });
});

// ── notifications ────────────────────────────────────────

function center() {
  class N extends EventEmitter { constructor(o) { super(); this.opts = o; N.created.push(this); } show() {} close() {} static isSupported() { return true; } }
  N.created = [];
  const push = new EventEmitter();
  Object.assign(push, { ack: async () => ({ ok: true }), fetchInbox: async () => ({ ok: true, items: [], unread: 0 }), start() {}, stop() {}, restart() {}, applySettings() {}, status: () => ({ state: 'connected' }) });
  const store = createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } });
  const nc = new NotificationCenter({ store, log, pushClient: push, Notification: N, platform: 'win32', protocol: 'gatecontrol-pro', showWindow() {}, now: () => Date.parse('2026-11-11T17:53:00Z') });
  const navigate = [];
  nc.on('navigate', (x) => navigate.push(x));
  return { nc, N, push, navigate };
}

const printPush = (seq, ok, jobId = 'j1') => ({
  seq, id: seq + 700, topic: `plugin:gatecontrol-print:${ok ? 'print_done' : 'print_failed'}`, priority: ok ? 'info' : 'normal',
  title: ok ? 'Druck fertig' : 'Druck fehlgeschlagen', body: ok ? '„Stromrechnung 2026-10.pdf“ liegt im HP OfficeJet 8020.' : '„Urlaub Ostsee 014.jpg“: Der Drucker hat den Auftrag abgelehnt.',
  created_at: '2026-11-11T17:53:00Z', expires_at: '2026-11-13T17:53:00Z', silent: false, collapse_key: `print-${jobId}`, data: { route: 'plg-gatecontrol-print' },
});

describe('PrintService and the notification center', () => {
  it('"Druck fertig" / "Druck fehlgeschlagen" drop the list and tell the page', async () => {
    const { nc } = center();
    const { s, api, events } = service({}, { notificationCenter: nc });
    s.start();
    await tick();
    await tick();
    await s.overview();
    nc.handleNotification(printPush(1, true));
    nc.handleNotification({ ...printPush(2, true), topic: 'plugin:gatecontrol-print:scan_done' });
    nc.handleNotification(printPush(3, false, 'j4'));
    assert.deepEqual(events.push, [
      { type: 'print', kind: 'done', jobId: 'j1', notificationId: 701 },
      { type: 'print', kind: 'failed', jobId: 'j4', notificationId: 703 },
    ]);
    const n = api.calls.length;
    await s.overview();
    assert.equal(api.calls.length, n + 1, 'asked again');
    s.stop();
  });

  it('toast click opens the page while it exists, else the inbox', async () => {
    const { nc, N, navigate } = center();
    const { s, api } = service({}, { notificationCenter: nc });
    s.start();
    await tick();
    await tick();
    nc.handleNotification(printPush(1, false, 'j4'));
    N.created[0].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'plg-gatecontrol-print', id: 701, context: { type: 'print', kind: 'failed', jobId: 'j4' } });
    // the plugin gone → the inbox again
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    await s.check();
    nc.handleNotification(printPush(2, true));
    N.created[1].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 702 });
    s.stop();
    assert.equal(nc.clickTarget(printPush(3, true)), null, 'stop() gives the route back');
  });

  it('a push reconnect asks for the plugin again while it is not there', async () => {
    const pc = new EventEmitter();
    const { s, api } = service({ '/api/v1/client/plugins': { ok: true, plugins: [] } }, { pushClient: pc });
    s.start();
    await tick();
    await tick();
    assert.equal(s.status().state, 'unavailable');
    api.routes['/api/v1/client/plugins'] = plugins();
    pc.emit('hello');
    await tick();
    await tick();
    assert.equal(s.status().state, 'available');
    s.stop();
  });
});

// ── IPC ──────────────────────────────────────────────────

describe('print:* IPC', () => {
  function register(s) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', print: s,
    });
    return { handlers, sent };
  }
  const INVALID = { ok: false, code: 'invalid', error: 'invalid argument', status: null, left: null, pages: null };

  it('channels, argument checks and events', async () => {
    const drive = fakeDrive({ 11: { name: 'Mietvertrag.pdf', content: PDF(6), mime: 'application/pdf' }, 16: { name: 'Pass.jpg', content: JPEG, encrypted: true } });
    const { s, api, settled } = service({
      'jobs/j1': { ok: true, job: job('j1', 'printing', { message: 'media-jam' }) },
      'POST jobs/j2/cancel': { ok: true, canceled: true },
      'POST print': refusal(409, 'limit', { left: 14, pages: 25 }),
    }, { drive });
    const { handlers, sent } = register(s);
    for (const ch of ['print:status', 'print:check', 'print:overview', 'print:job', 'print:cancel', 'print:pick', 'print:dropped', 'print:drive', 'print:forget',
      'print:submit', 'print:transfers', 'print:transfer:cancel', 'print:again', 'print:sources']) assert.ok(handlers[ch], ch);
    assert.equal((await handlers['print:check']()).state, 'available');
    assert.equal(sent.at(-1)[0], 'print:state');
    assert.equal((await handlers['print:overview'](null, {})).printers.length, 2);
    assert.equal((await handlers['print:job'](null, { id: 'j1' })).job.message, 'media-jam');
    assert.deepEqual(await handlers['print:job'](null, { id: '../overview' }), INVALID);
    assert.deepEqual(await handlers['print:cancel'](null, null), INVALID);
    assert.deepEqual(await handlers['print:cancel'](null, { id: 'j2' }), { ok: true, canceled: true });
    // no dialog in this test: a clean refusal
    assert.equal((await handlers['print:pick']()).code, 'unsupported');
    assert.deepEqual(await handlers['print:dropped'](null, { paths: 'C:\\x.pdf' }), INVALID);
    assert.deepEqual(await handlers['print:dropped'](null, { paths: [42] }), INVALID);
    const dropped = await handlers['print:dropped'](null, { paths: [file('p.pdf', PDF(1))] });
    assert.equal(dropped.files[0].name, 'p.pdf');
    assert.deepEqual(await handlers['print:drive'](null, { ids: ['11'] }), INVALID);
    assert.equal((await handlers['print:drive'](null, { ids: [16], vault: 'yes' })).rejected[0].code, 'vault_confirm');
    assert.equal((await handlers['print:drive'](null, { ids: [16], vault: true })).files.length, 1);
    // submit: tokens only
    assert.deepEqual(await handlers['print:submit'](null, { tokens: [path.join(tmp, 'p.pdf')], deviceId: HP.id }), INVALID);
    assert.deepEqual(await handlers['print:submit'](null, { tokens: [dropped.files[0].token], deviceId: HP.id, copies: 0 }), INVALID);
    assert.equal((await handlers['print:submit'](null, { tokens: ['B'.repeat(24)], deviceId: HP.id })).code, 'not_picked');
    const sub = await handlers['print:submit'](null, { tokens: [dropped.files[0].token], deviceId: HP.id, copies: 25, evil: true });
    assert.deepEqual([sub.ok, sub.transfers[0].copies], [true, 25]);
    await settled();
    assert.equal(sent.at(-1)[0], 'print:transfers');
    const list = await handlers['print:transfers']();
    assert.deepEqual(list.transfers.map((t) => [t.phase, t.code, t.left, t.pages]), [['failed', 'limit', 14, 25]]);
    assert.deepEqual(api.calls.at(-1)[2], { deviceId: HP.id, copies: 25, color: false, duplex: false, mediaId: 'a'.repeat(32), name: 'p.pdf' });
    assert.equal((await handlers['print:again'](null, { transferId: list.transfers[0].id })).options.copies, 25);
    assert.deepEqual(await handlers['print:again'](null, {}), INVALID);
    assert.equal((await handlers['print:again'](null, { jobId: 'nope' })).code, 'source_gone');
    assert.deepEqual(await handlers['print:transfer:cancel'](null, { id: 'x' }), INVALID);
    assert.deepEqual(await handlers['print:transfer:cancel'](null, { id: list.transfers[0].id }), { ok: true });
    assert.deepEqual(await handlers['print:forget'](null, { tokens: ['short'] }), INVALID);
    assert.deepEqual(await handlers['print:sources'](), { ok: true, ids: [] });
    s.emit('push', { type: 'print', kind: 'done', jobId: 'j1' });
    assert.deepEqual(sent.at(-1), ['print:push', { type: 'print', kind: 'done', jobId: 'j1' }]);
    s.emit('job', { job: { id: 'j1' }, pagesLeft: 3, transferId: 't1' });
    assert.equal(sent.at(-1)[0], 'print:job');
  });

  it('no print service → no print:* channels', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.ok(!Object.keys(handlers).some((c) => c.startsWith('print:')));
  });
});

describe('i18n print.* (de / en)', () => {
  function flatten(obj, prefix = '', out = {}) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
      else out[key] = String(v);
    }
    return out;
  }
  const placeholders = (s) => [...String(s).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort();

  it('same keys and placeholders, no empty strings', () => {
    const d = flatten(de.print, 'print');
    const e = flatten(en.print, 'print');
    assert.deepEqual(Object.keys(d).filter((k) => !(k in e)), []);
    assert.deepEqual(Object.keys(e).filter((k) => !(k in d)), []);
    for (const k of Object.keys(d)) {
      assert.deepEqual(placeholders(e[k]), placeholders(d[k]), k);
      assert.ok(d[k].trim() && e[k].trim(), k);
    }
    assert.equal(d['print.title'], 'Drucken');
    assert.equal(d['print.dialog.go'], 'Zu Hause drucken');
    assert.equal(d['print.menu.one'], 'Drucken …');
    for (const k of Object.keys(d)) assert.ok(!/zuhause/i.test(d[k]), k);
  });

  it('a text for every state, reason and code the page shows', () => {
    const d = flatten(de.print, 'print');
    for (const c of ['queued', 'sending', 'converting', 'convertingOffice', 'printing', 'stopped', 'waiting', 'done', 'failed', 'expired', 'canceled', 'loading', 'uploading', 'creating']) assert.ok(d[`print.state.${c}`], c);
    for (const c of ['network', 'timeout', 'too_large', 'format', 'damaged', 'printer_format', 'gateway_update', 'convert_off', 'office_off', 'office_missing', 'limit', 'no_right',
      'unavailable', 'offline', 'cert_changed', 'not_found', 'vault_locked', 'source_gone', 'empty', 'folder', 'too_many', 'failed']) assert.ok(d[`print.err.${c}`], c);
    for (const c of ['pdf', 'image', 'text', 'office', ...Object.keys(P.EXTENSIONS).filter((x) => P.OFFICE_TYPES.includes(P.EXTENSIONS[x]))]) assert.ok(d[`print.kind.${c}`], c);
  });
});
