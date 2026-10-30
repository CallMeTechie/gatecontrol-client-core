'use strict';

// Drive 1.14 in the Windows Pro app: deadlines into the family calendar ('deadlineCalendar', the new kinds warranty /
// renewal), questions to the documents ('docAsk'), photos by what is on them ('photoSearch') and "In Dokument
// umwandeln" ('scanDocs': classify with the text read on this PC, the searchable PDF made here, Word / Excel by Drive,
// "Original-Scan behalten") — only with the features `me` reports — the searchable PDF itself and the IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { buildSearchablePdf, pagesText, winAnsi, pageGeometry, jpegComponents } = require('../src/utils/searchable-pdf');
const { pdfText } = require('../src/utils/pdf-text');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

// a real JPEG (48 × 12, RGB) for the PDF's pages
const JPEG = Buffer.from('/9j/4AAQSkZJRgABAQAAAAAAAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4pLSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAMADADASIAAhEBAxEB/8QAGQAAAgMBAAAAAAAAAAAAAAAAAAMBAgQH/8QAJRAAAQMDAwQDAQAAAAAAAAAAAQIEEQADEhMhMSJBYZEUUfDh/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AOgXbjjWWLTxukAxiobjbioK3IxBetxPEjn9NaFM2yrhuKsIKzuVEbmoSwaJAAbogGQI4Pj0KDOVuck4vW8g4qBT39+KYkPVDoc2FR3x/tN+G2gjRRuZO377NMtWbdkEWkJQDzAigLOppJ1sdSOrHiavRRQf/9k=', 'base64');

const LINES = [
  { text: 'Stadtwerke Rechnung', words: [{ text: 'Stadtwerke', x: 4, y: 1, w: 20, h: 4 }, { text: 'Rechnung', x: 26, y: 1, w: 18, h: 4 }] },
  { text: 'Betrag 84,20 €', words: [{ text: 'Betrag', x: 4, y: 7, w: 12, h: 4 }, { text: '84,20', x: 18, y: 7, w: 10, h: 4 }, { text: '€', x: 30, y: 7, w: 3, h: 4 }] },
];

/** The OCR of Windows as the tests need it (what it was given is kept). */
function fakeOcr({ available = true, fail = false } = {}) {
  const o = {
    seen: [],
    available: async () => (available ? { available: true, reason: null } : { available: false, reason: 'no_language' }),
    recognize: async (bytes) => {
      o.seen.push(Buffer.from(bytes).toString());
      if (fail) throw Object.assign(new Error('bad'), { code: 'bad_image' });
      return { width: 48, height: 12, lines: LINES, text: LINES.map((l) => l.text).join('\n') };
    },
    image: () => ({ width: 48, height: 12, jpeg: JPEG }),
  };
  return o;
}

async function setup(features, { ocr = null } = {}) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive114-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({ apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp, ocr });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const changed = [];
  svc.on('changed', (c) => changed.push(c.folderId));
  return { srv, svc, api, tmp, changed };
}

describe('utils/drive: Drive 1.14 answers', () => {
  it('cleans answers, scan kinds, converted documents, the new deadline kinds and photo terms', () => {
    const a = drive.normalizeAsk({
      status: 'answered', answer: 'Die Kfz-Versicherung läuft bis 31.12.2026.\r\nKündigen bis 30.11.2026.', terms: ['Kfz', 'Versicherung', 7, ''],
      sources: [{ nodeId: 5, name: 'Versicherungsschein Kfz 2026.pdf', path: 'Versicherungen', page: 1, quote: '„Vertragslaufzeit …“' }, { nodeId: 'x', name: 'weg.pdf' }],
    });
    assert.equal(a.status, 'answered');
    assert.equal(a.answer, 'Die Kfz-Versicherung läuft bis 31.12.2026.\nKündigen bis 30.11.2026.');
    assert.deepEqual(a.sources, [{ nodeId: 5, name: 'Versicherungsschein Kfz 2026.pdf', path: 'Versicherungen', page: 1, quote: '„Vertragslaufzeit …“' }]);
    assert.deepEqual(a.terms, ['Kfz', 'Versicherung', '7']);
    // an answer without text is "nothing found"; nothing else
    assert.deepEqual(drive.normalizeAsk({ status: 'answered', answer: '  ', sources: [{ nodeId: 1, name: 'a' }], terms: ['x'] }), { status: 'not_found', answer: null, sources: [], terms: ['x'] });
    assert.equal(drive.normalizeAsk({ status: 'maybe' }), null);

    assert.deepEqual(drive.normalizeScanClass({ kind: 'table', confidence: 1.4, summary: '3 Spalten\n12 Zeilen' }), { kind: 'table', confidence: 1, summary: '3 Spalten 12 Zeilen' });
    assert.equal(drive.normalizeScanClass({ kind: 'poster' }), null);
    const conv = drive.normalizeScanConvert({ node: { id: 9, areaId: 'mine:2', name: 'Zähler.xlsx' }, original: null });
    assert.equal(conv.node.name, 'Zähler.xlsx');
    assert.equal(conv.original, null);
    assert.equal(drive.normalizeScanConvert({ node: { id: 'x' } }), null);

    const w = drive.normalizeDeadline({ id: 3, kind: 'warranty', date: '2026-12-12', label: 'Geschirrspüler', calendar: { eventId: 'ev-3', at: '2026-11-01T10:00:00Z' } });
    assert.deepEqual(w.calendar, { eventId: 'ev-3', at: Date.parse('2026-11-01T10:00:00Z') });
    assert.equal(drive.normalizeDeadline({ id: 4, kind: 'renewal', date: '2027-01-31' }).calendar, null);
    assert.equal(drive.normalizeDeadline({ id: 4, kind: 'birthday', date: '2027-01-31' }), null);

    const ph = drive.normalizePhotos({ items: [{ id: 1, name: 'a.jpg' }], next: null, terms: [{ term: 'Meer', count: 12 }, 'Sonnenuntergang', 'meer', { label: 'Sand' }], total: 38 });
    assert.deepEqual(ph.terms, [{ term: 'Meer', count: 12 }, { term: 'Sonnenuntergang', count: null }, { term: 'Sand', count: null }]);
    assert.equal(ph.total, 38);
    assert.equal(drive.normalizePhotos({ items: [] }).terms, undefined);
  });
});

describe('utils/searchable-pdf', () => {
  it('a page per scan: the picture over the page, the words invisible and searchable (WinAnsi), A4 wide', async () => {
    const pdf = buildSearchablePdf([{ jpeg: JPEG, width: 48, height: 12, lines: LINES }, { jpeg: JPEG, width: 48, height: 12, lines: [{ words: [{ text: 'Größe „ok“', x: 1, y: 1, w: 20, h: 4 }] }] }], { title: 'Scan', now: Date.parse('2026-10-30T10:00:00Z') });
    const s = pdf.toString('latin1');
    assert.match(s, /^%PDF-1\.4/);
    assert.match(s, /\/Count 2/);
    assert.match(s, /\/Filter \/DCTDecode/);
    assert.match(s, /\/BaseFont \/Courier \/Encoding \/WinAnsiEncoding/);
    assert.match(s, /\/CreationDate \(D:20261030100000Z\)/);
    // the xref points at the objects
    const start = Number(/startxref\n(\d+)/.exec(s)[1]);
    assert.equal(s.slice(start, start + 4), 'xref');
    const first = /0000000000 65535 f \n(\d{10}) 00000 n/.exec(s);
    assert.equal(s.slice(Number(first[1]), Number(first[1]) + 7), '1 0 obj');
    const file = path.join(os.tmpdir(), `gc-scan-${process.pid}.pdf`);
    cleanup.push(() => fs.rmSync(file, { force: true }));
    fs.writeFileSync(file, pdf);
    const text = await pdfText(file);
    assert.match(text, /Stadtwerke Rechnung/);
    assert.match(text, /Betrag 84,20 €/);
    assert.match(text, /Größe „ok“/);
    assert.equal(pagesText([{ lines: LINES }, { lines: [] }, { lines: [{ words: [{ text: 'a' }, { text: 'b' }] }] }]), 'Stadtwerke Rechnung\nBetrag 84,20 €\n\na b');
  });

  it('sizes, encodings and what it refuses', () => {
    assert.deepEqual(winAnsi('Aä€„✓'), Buffer.from([0x41, 0xe4, 0x80, 0x84, 0x3f]));
    const portrait = pageGeometry(1000, 1414);
    assert.equal(Math.round(portrait.w), 595);
    assert.equal(Math.round(portrait.h), 842);
    assert.equal(Math.round(pageGeometry(1414, 1000).h), 595);
    assert.equal(jpegComponents(JPEG), 3);
    assert.throws(() => buildSearchablePdf([]), /no pages/);
    assert.throws(() => buildSearchablePdf([{ jpeg: Buffer.from('png?'), width: 1, height: 1 }]), /JPEG/);
    assert.throws(() => buildSearchablePdf([{ jpeg: JPEG, width: 0, height: 1 }]), /size/);
  });
});

describe('DriveService: Drive 1.14', () => {
  it('deadlineCalendar: into the family calendar; Familie not there → familie_unavailable', async () => {
    const { srv, svc } = await setup(['docAi', 'deadlineCalendar']);
    srv.setInsight(12, { kind: 'warranty', deadlines: [{ kind: 'warranty', date: '2099-12-12', label: 'Geschirrspüler' }, { kind: 'renewal', date: '2099-01-31', label: 'Fitnessstudio' }] });
    const list = (await svc.deadlines({ from: '2026-01-01', to: '2099-12-31' })).deadlines;
    assert.deepEqual(list.map((d) => d.kind), ['renewal', 'warranty']);
    const r = await svc.calendar(list[1].id);
    assert.equal(r.ok, true);
    assert.equal(r.deadline.calendar.eventId, `ev-${list[1].id}`);
    srv.familie = false;
    await assert.rejects(svc.calendar(list[0].id), (e) => e.code === 'familie_unavailable');
    assert.deepEqual(srv.state.calendarCalls, [list[1].id, list[0].id]);
  });

  it('docAsk: the answer with its sources; nothing found with the words searched; the limit', async () => {
    const { srv, svc } = await setup(['docAsk']);
    srv.answer = (q) => (/Kfz/.test(q) ? { status: 'answered', answer: 'Bis 31.12.2026.', sources: [{ nodeId: 12, name: 'Brief.pdf', path: 'Dokumente', page: 1, quote: 'Laufzeit bis 31.12.2026' }], terms: ['Kfz'] } : null);
    const a = await svc.ask('Wann läuft die Kfz-Versicherung ab?');
    assert.equal(a.status, 'answered');
    assert.equal(a.sources[0].quote, 'Laufzeit bis 31.12.2026');
    const n = await svc.ask('Wo ist der Mietvertrag?', 'family:1');
    assert.equal(n.status, 'not_found');
    assert.deepEqual(n.terms, ['Mietvertrag?']);
    assert.deepEqual(srv.state.askCalls[1], { q: 'Wo ist der Mietvertrag?', area: 'family:1' });
    srv.askLimited = true;
    await assert.rejects(svc.ask('noch eine Frage'), (e) => e.code === 'rate_limited' && e.status === 429);
    await assert.rejects(svc.ask('x'), (e) => e.code === 'invalid');
  });

  it('photoSearch: photos by their labels with the hit chips; without the feature not asked', async () => {
    const { srv, svc } = await setup(['photos', 'photoSearch']);
    const beach = srv.mutate.photo(1, 'Strand.jpg', { takenAt: Date.parse('2025-07-01T10:00:00Z') });
    const sunset = srv.mutate.photo(1, 'Abend.jpg', { takenAt: Date.parse('2025-07-02T20:00:00Z') });
    srv.mutate.photo(1, 'Hund.jpg');
    srv.state.labels.set(beach.id, ['Strand', 'Meer']);
    srv.state.labels.set(sunset.id, ['Strand', 'Meer', 'Sonnenuntergang']);
    const r = await svc.photos({ q: 'strand' });
    assert.deepEqual(r.items.map((p) => p.name), ['Abend.jpg', 'Strand.jpg']);
    assert.deepEqual(r.terms, [{ term: 'Meer', count: 2 }, { term: 'Sonnenuntergang', count: 1 }]);
    assert.equal(r.total, 2);
    assert.deepEqual(srv.state.requests.filter((x) => x.path.endsWith('/api/photos')).pop().query.q, 'strand');
    const { svc: old } = await setup(['photos']);
    await assert.rejects(old.photos({ q: 'strand' }), (e) => e.code === 'unsupported');
  });

  it('scanDocs: printed text → classify with the text read here, the searchable PDF made here, the original kept', async () => {
    const ocr = fakeOcr();
    const { srv, svc, changed } = await setup(['scanDocs'], { ocr });
    srv.scanKind = 'printed';
    assert.deepEqual(await svc.scanStatus(), { ok: true, supported: true, local: true, reason: null });
    const p = await svc.scanPrepare([11]);
    assert.equal(p.ok, true);
    assert.equal(p.kind, 'printed');
    assert.equal(p.local, true);
    assert.equal(p.words, 5);
    assert.equal(p.name, 'Foto');
    assert.equal(p.folderId, 1);
    assert.deepEqual(ocr.seen, ['jpeg-bytes']);
    // text first: the words read here go along
    assert.deepEqual(srv.state.classifyCalls[0], { mediaIds: ['photoMedia000001'], text: 'Stadtwerke Rechnung\nBetrag 84,20 €' });
    const r = await svc.scanSave(p.scanId, { target: 'pdf', folderId: 10, name: 'Stadtwerke Rechnung', keepOriginal: true });
    assert.equal(r.ok, true);
    assert.equal(r.local, true);
    assert.equal(r.node.name, 'Stadtwerke Rechnung.pdf');
    assert.equal(r.node.parentId, 10);
    assert.equal(srv.state.convertCalls.length, 0);
    const c = srv.state.commits.pop();
    assert.equal(c.text, 'Stadtwerke Rechnung\nBetrag 84,20 €');
    assert.equal(c.onConflict, 'rename');
    const pdf = srv.state.media.get(c.mediaId).data.toString('latin1');
    assert.match(pdf, /^%PDF-1\.4/);
    assert.equal(srv.state.nodes.get(11).deleted, false);
    assert.ok(changed.includes(10));
    // the prepared scan is gone
    await assert.rejects(svc.scanSave(p.scanId, { target: 'pdf' }), (e) => e.code === 'not_found');
  });

  it('scanDocs: Excel / Word by Drive (no second original), "Original-Scan behalten" off, "Nur Bild", without the OCR of Windows', async () => {
    const { srv, svc, changed } = await setup(['scanDocs', 'docAi']);
    srv.setInsight(11, { kind: 'statement', suggestion: { folderId: 10, folderPath: 'Dokumente', name: '2026 Zählerstände.jpg' } });
    const p = await svc.scanPrepare([11]);
    assert.equal(p.kind, 'table');
    assert.equal(p.local, false);
    assert.equal(p.summary, '3 Spalten, 12 Zeilen, Summenzeile');
    assert.deepEqual(p.suggestion, { folderId: 10, folderPath: 'Dokumente', name: '2026 Zählerstände.jpg' });
    assert.deepEqual(srv.state.classifyCalls[0], { mediaIds: ['photoMedia000001'] });
    const r = await svc.scanSave(p.scanId, { target: 'xlsx', folderId: 10, name: '2026 Zählerstände.jpg', keepOriginal: false });
    assert.equal(r.node.name, '2026 Zählerstände.xlsx');
    assert.deepEqual(srv.state.convertCalls[0], { mediaIds: ['photoMedia000001'], target: 'xlsx', kind: 'table', keepOriginal: false, folderId: 10, name: '2026 Zählerstände.xlsx' });
    assert.equal(srv.state.nodes.get(11).deleted, true);
    assert.ok(changed.includes(1) && changed.includes(10));

    // printed text without the OCR of Windows: Drive makes the PDF
    const two = srv.mutate.photo(1, 'Brief.png', { mime: 'image/png' });
    srv.scanKind = 'printed';
    const q = await svc.scanPrepare([two.id]);
    const pdf = await svc.scanSave(q.scanId, { target: 'pdf', keepOriginal: true });
    assert.equal(pdf.local, false);
    assert.equal(srv.state.convertCalls[1].target, 'pdf');
    assert.equal(pdf.node.name, 'Brief.pdf');

    // "Nur Bild": the picture stays, renamed and moved
    const img = await svc.scanPrepare([two.id]);
    const kept = await svc.scanSave(img.scanId, { target: 'image', folderId: 10, name: 'Brief vom Amt', keepOriginal: true });
    assert.equal(kept.node.name, 'Brief vom Amt.png');
    assert.equal(kept.node.parentId, 10);
    assert.equal(srv.state.convertCalls.length, 2);
  });

  it('scanDocs: several pages; the AI refused → PDF here and "Nur Bild" still; what it refuses', async () => {
    const ocr = fakeOcr();
    const { srv, svc } = await setup(['scanDocs'], { ocr });
    const a = srv.mutate.photo(1, 'Seite 1.jpg');
    const b = srv.mutate.photo(1, 'Seite 2.jpg');
    srv.classifyRefused = true;
    const p = await svc.scanPrepare([a.id, b.id]);
    assert.equal(p.pages, 2);
    assert.equal(p.classified, false);
    assert.equal(p.classifyError, 'unsupported');
    assert.equal(p.kind, 'printed');
    const r = await svc.scanSave(p.scanId, { target: 'pdf', keepOriginal: true });
    assert.match(srv.state.media.get(srv.state.commits.pop().mediaId).data.toString('latin1'), /\/Count 2/);
    assert.equal(r.node.name, 'Seite 1.pdf');
    await assert.rejects(svc.scanPrepare([12]), (e) => e.code === 'not_picture');
    await assert.rejects(svc.scanPrepare([10]), (e) => e.code === 'invalid');
    await assert.rejects(svc.scanPrepare([]), (e) => e.code === 'invalid');
    const two = await svc.scanPrepare([a.id, b.id]);
    await assert.rejects(svc.scanSave(two.scanId, { target: 'image' }), (e) => e.code === 'invalid');
    await assert.rejects(svc.scanSave(two.scanId, { target: 'pptx' }), (e) => e.code === 'invalid');
    assert.deepEqual(svc.scanDiscard(two.scanId), { ok: true });
    // the OCR failing on this PC: Drive gets no text, the PDF is Drive's
    const bad = fakeOcr({ fail: true });
    const { svc: svc2, srv: srv2 } = await setup(['scanDocs'], { ocr: bad });
    const q = await svc2.scanPrepare([11]);
    assert.equal(q.local, false);
    assert.deepEqual(srv2.state.classifyCalls[0], { mediaIds: ['photoMedia000001'] });
    // without the feature
    const { svc: none } = await setup(['photos'], { ocr });
    await assert.rejects(none.scanPrepare([11]), (e) => e.code === 'unsupported');
    assert.equal((await none.scanStatus()).supported, false);
  });

  it('IPC: the Drive 1.14 channels check their arguments', async () => {
    const { srv, svc } = await setup(['scanDocs', 'docAsk', 'docAi', 'deadlineCalendar', 'photos', 'photoSearch'], { ocr: fakeOcr() });
    srv.setInsight(12, { kind: 'warranty', deadlines: [{ kind: 'warranty', date: '2099-01-01' }] });
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    const bad = [
      ['drive:deadline:calendar', { id: 'x' }], ['drive:ask', { q: '' }], ['drive:ask', { q: 'x'.repeat(501) }], ['drive:ask', { q: 'Frage?', area: 'a b' }],
      ['drive:photos', { q: 5 }], ['drive:scan:prepare', { ids: [] }], ['drive:scan:prepare', { ids: new Array(21).fill(11) }],
      ['drive:scan:save', { scanId: 'nope', target: 'pdf', keepOriginal: true }], ['drive:scan:save', { scanId: 'a'.repeat(24), target: 'pptx', keepOriginal: true }],
      ['drive:scan:save', { scanId: 'a'.repeat(24), target: 'pdf' }], ['drive:scan:discard', { scanId: 1 }],
    ];
    for (const [ch, a] of bad) assert.equal((await handlers[ch](null, a)).code, 'invalid', `${ch} ${JSON.stringify(a)}`);
    const dl = (await handlers['drive:deadlines'](null, { from: '2026-01-01', to: '2099-12-31' })).deadlines[0];
    assert.equal((await handlers['drive:deadline:calendar'](null, { id: dl.id })).deadline.calendar.eventId, `ev-${dl.id}`);
    assert.equal((await handlers['drive:ask'](null, { q: 'Wann läuft das ab?' })).status, 'not_found');
    assert.equal((await handlers['drive:scan:status'](null, {})).local, true);
    const p = await handlers['drive:scan:prepare'](null, { ids: [11] });
    assert.equal(p.ok, true);
    assert.equal((await handlers['drive:scan:save'](null, { scanId: p.scanId, target: 'docx', keepOriginal: true })).node.name, 'Foto.docx');
    assert.deepEqual(await handlers['drive:scan:discard'](null, { scanId: p.scanId }), { ok: true });
    assert.equal((await handlers['drive:photos'](null, { q: 'Hund' })).ok, true);
  });
});
