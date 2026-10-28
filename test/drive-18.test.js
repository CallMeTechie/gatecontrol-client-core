'use strict';

// Drive 1.8 / 1.9 in the Windows Pro app (besides the vault folders, test/drive-vault.test.js): AI for documents
// (node.insight, the full insight, "Erneut erkennen", taking the suggestion, deadlines and reminders, the switch per
// area), the click on a deadline push, the import page of the portal ('cloudImport') and office in the browser
// ('office') — only with the features `me` reports — and the IPC.

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
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const cleanup = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) { try { await fn(); } catch { /* ignore */ } }
});

async function setup(features, { allowedHosts = () => ['gc.example.com'] } = {}) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  apiClient.portalUrl = 'https://gc.example.com/portal';
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const external = [];
  const routes = new Map();
  const nc = { addClickRoute: (route, fn) => { routes.set(route, fn); return () => routes.delete(route); } };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drive18-'));
  cleanup.push(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const svc = new DriveService({
    apiClient, api, log, store: createMemoryStore(), tempDir: () => tmp, allowedHosts, notificationCenter: nc,
    shell: { openExternal: async (u) => { external.push(u); }, openPath: async () => '' },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { srv, svc, api, external, routes };
}

describe('utils/drive: Drive 1.8 / 1.9 answers', () => {
  it('cleans insights, deadlines, office answers, vault nodes and areas', () => {
    const ins = drive.normalizeInsight({
      status: 'ready', kind: 'invoice', title: 'Stadtwerke\nRechnung', date: '2026-03-14', sender: 'Stadtwerke', amount: 89.5, currency: 'EUR',
      error: null, at: '2026-03-15T08:00:00Z', suggestion: { folderId: 10, folderPath: 'Rechnungen/2026', name: '2026-03-14 Stadtwerke Rechnung.pdf' },
      deadlines: [{ id: 3, kind: 'payment', date: '2026-03-28', label: 'Zahlung', reminder: { at: '2026-03-25T07:00:00Z', daysBefore: 3, sent: false } }, { id: 4, kind: 'x', date: '2026-01-01' }],
    });
    assert.equal(ins.title, 'Stadtwerke Rechnung');
    assert.deepEqual(ins.suggestion, { folderId: 10, folderPath: 'Rechnungen/2026', name: '2026-03-14 Stadtwerke Rechnung.pdf' });
    assert.deepEqual(ins.deadlines, [{ id: 3, kind: 'payment', date: '2026-03-28', label: 'Zahlung', reminder: { at: Date.parse('2026-03-25T07:00:00Z'), daysBefore: 3, sent: false } }]);
    assert.equal(drive.normalizeInsight({ status: 'ready', suggestion: { folderId: 2, folderPath: '' } }).suggestion.folderPath, '');
    assert.equal(drive.normalizeInsight({ status: 'weird' }), null);
    assert.equal(drive.normalizeInsight({ status: 'ready', amount: 5, currency: 'eur' }).currency, null);
    assert.deepEqual(drive.normalizeNode({ id: 1, areaId: 'mine:2', name: 'a.pdf', insight: { status: 'ready', kind: 'nope' } }).insight, { status: 'ready', kind: null });
    assert.equal(drive.normalizeNode({ id: 1, areaId: 'mine:2', name: 'a.pdf' }).insight, null);
    assert.equal(drive.normalizeNode({ id: 1, areaId: 'mine:2', name: 'a.pdf' }).encrypted, false);
    assert.equal(drive.normalizeArea({ id: 'mine:2', rootId: 1, docAi: false }).docAi, false);
    assert.equal(drive.normalizeArea({ id: 'mine:2', rootId: 1 }).docAi, null);
    assert.deepEqual(drive.normalizeOffice({ url: 'https://gc.example.com/x?access_token=1', mode: 'edit', expiresAt: '2026-10-28T10:00:00Z' }), { url: 'https://gc.example.com/x?access_token=1', mode: 'edit', expiresAt: Date.parse('2026-10-28T10:00:00Z') });
    assert.equal(drive.normalizeOffice({ url: 'http://gc.example.com/x' }), null);
    assert.equal(drive.normalizeOffice({ url: 'javascript:alert(1)' }), null);
    assert.equal(drive.isOfficeName('Plan.XLSX'), true);
    assert.equal(drive.isOfficeName('Brief.pdf'), false);
    assert.equal(drive.importLink('https://gc.example.com/portal#plg-gatecontrol-drive'), 'https://gc.example.com/portal?drive=import#plg-gatecontrol-drive');
    assert.equal(drive.importLink('http://gc.example.com/'), null);
    assert.equal(drive.normalizeDeadlines({ deadlines: [{ id: 1, kind: 'payment', date: '2026-01-01' }] }).deadlines.length, 0, 'a deadline without its file');
  });
});

describe('DriveService: AI for documents (docAi)', () => {
  it('insight, "Erneut erkennen", the suggestion taken, deadlines and reminders, the switch per area', async () => {
    const { srv, svc } = await setup(['docAi', 'links']);
    srv.setInsight(12, {
      kind: 'contract', title: 'Mietvertrag', date: '2026-01-02', sender: 'Hausverwaltung', amount: 950, currency: 'EUR',
      suggestion: { folderId: 1, folderPath: '', name: '2026-01-02 Mietvertrag.pdf' },
      deadlines: [{ kind: 'cancellation', date: '2099-03-31', label: 'Kündigung' }],
    });
    const f = await svc.folder(10);
    assert.deepEqual(f.items.find((n) => n.id === 12).insight, { status: 'ready', kind: 'contract' });
    const me = await svc.me();
    assert.equal(me.areas.find((a) => a.id === 'mine:2').docAi, true);
    const r = await svc.insight(12);
    assert.equal(r.insight.title, 'Mietvertrag');
    assert.equal(r.insight.deadlines.length, 1);
    // a reminder 7 days before, then none
    const dl = r.insight.deadlines[0];
    const rem = await svc.remind(dl.id, 7);
    assert.equal(rem.deadline.reminder.daysBefore, 7);
    assert.equal((await svc.remind(dl.id, null)).deadline.reminder, null);
    // the overview of deadlines with their files
    const all = await svc.deadlines({});
    assert.deepEqual(all.deadlines.map((d) => [d.kind, d.node.id]), [['cancellation', 12]]);
    // taking the suggestion: renamed and moved
    const changed = [];
    svc.on('changed', (c) => changed.push(c.folderId));
    const ap = await svc.applyInsight(12, { name: true, folder: true });
    assert.equal(ap.node.name, '2026-01-02 Mietvertrag.pdf');
    assert.equal(ap.node.parentId, 1);
    assert.equal(ap.insight.suggestion, null);
    assert.deepEqual(changed.sort(), [1, 10]);
    // "Erneut erkennen": a PDF goes in the queue, other files cannot be read
    assert.equal((await svc.recognize(12)).insight.status, 'pending');
    await assert.rejects(svc.recognize(11), (e) => e.code === 'unsupported' && e.body.reason === 'no_text');
    // the switch of an area
    assert.deepEqual((await svc.setDocAi('mine:2', false)).area, { id: 'mine:2', docAi: false });
    assert.equal((await svc.insight(12)).insight.status, 'off');
  });

  it('a click on a deadline push opens the file on the page; other pushes are not taken', async () => {
    const { svc, routes } = await setup(['docAi']);
    const resolve = routes.get(drive.APP_ROUTE);
    assert.equal(typeof resolve, 'function');
    assert.deepEqual(resolve({ topic: 'plugin:gatecontrol-drive:deadline', data: { drive: { node: 12, area: 'mine:2', deadline: 3 } } }), { kind: 'deadline', nodeId: 12, deadlineId: 3, areaId: 'mine:2' });
    assert.deepEqual(resolve({ topic: 'plugin:gatecontrol-drive:vault', data: { drive: { vault: 'Vt9bJm0n2QwErTyUiOpAsD', node: 5, area: 'mine:2', event: 'request' } } }),
      { kind: 'vault', vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', nodeId: 5, areaId: 'mine:2', event: 'request' });
    assert.equal(resolve({ topic: 'plugin:gatecontrol-schule:message', data: { drive: { node: 1 } } }), null);
    assert.equal(resolve({ topic: 'plugin:gatecontrol-drive:deadline', data: {} }), null);
    svc.stop();
    assert.equal(routes.has(drive.APP_ROUTE), false);
  });

  it('nothing of it on Drives without the feature', async () => {
    const { srv, svc } = await setup(['links']);
    await assert.rejects(svc.insight(12), (e) => e.code === 'unsupported');
    await assert.rejects(svc.deadlines(), (e) => e.code === 'unsupported');
    await assert.rejects(svc.office(12), (e) => e.code === 'unsupported');
    await assert.rejects(svc.openImport(), (e) => e.code === 'unsupported');
    assert.equal(srv.state.requests.some((r) => /insight|deadlines|office/.test(r.path)), false);
    assert.equal((await svc.folder(10)).items[0].insight, null);
  });
});

describe('DriveService: the import page and office in the browser', () => {
  it('cloudImport: the portal\'s import page on the portal\'s host (https only)', async () => {
    const { svc, external } = await setup(['links', 'cloudImport']);
    assert.deepEqual(await svc.openImport(), { ok: true });
    assert.deepEqual(external, ['https://gc.example.com/portal?drive=import#plg-gatecontrol-drive']);
    const other = await setup(['links', 'cloudImport'], { allowedHosts: () => ['nas.local'] });
    assert.equal((await other.svc.openImport()).code, 'unsupported');
    assert.deepEqual(other.external, []);
  });

  it('office: POST nodes/<id>/office, the address in the default browser; not for other files', async () => {
    const { srv, svc, external } = await setup(['office']);
    const doc = srv.mutate.file(10, 'Plan.xlsx', 'x');
    const r = await svc.office(doc.id);
    assert.deepEqual([r.ok, r.mode], [true, 'edit']);
    assert.deepEqual(external, [`https://gc.example.com/plugin-public/gatecontrol-drive/office/open/${doc.id}?access_token=tok`]);
    await assert.rejects(svc.office(12), (e) => e.code === 'office_unavailable');
    const ro = srv.mutate.file(3, 'Zeugnis.docx', 'x');
    assert.equal((await svc.office(ro.id)).mode, 'view');
  });

  it('IPC: the new channels check their arguments', async () => {
    const { srv, svc } = await setup(['docAi', 'office', 'cloudImport', 'links']);
    srv.setInsight(12, { kind: 'invoice', suggestion: { folderId: 1, folderPath: '', name: 'Neu.pdf' }, deadlines: [{ kind: 'payment', date: '2099-01-01' }] });
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    const bad = [
      ['drive:insight', { id: 'x' }], ['drive:insight:apply', { id: 12 }], ['drive:deadlines', { from: '1.1.2026' }],
      ['drive:deadline:remind', { id: 1, daysBefore: 91 }], ['drive:deadline:remind', { id: 1, daysBefore: '3' }], ['drive:area:docai', { areaId: 'mine:2', on: 'ja' }],
      ['drive:office', { id: 0 }],
    ];
    for (const [ch, a] of bad) assert.equal((await handlers[ch](null, a)).code, 'invalid', `${ch} ${JSON.stringify(a)}`);
    assert.equal((await handlers['drive:insight'](null, { id: 12 })).insight.kind, 'invoice');
    const dls = (await handlers['drive:deadlines'](null, { from: '2026-01-01', to: '2099-12-31' })).deadlines;
    assert.equal(dls.length, 1);
    assert.equal((await handlers['drive:deadline:remind'](null, { id: dls[0].id, daysBefore: 0 })).deadline.reminder.daysBefore, 0);
    assert.equal((await handlers['drive:insight:apply'](null, { id: 12, name: true })).node.name, 'Neu.pdf');
    assert.equal((await handlers['drive:import'](null, {})).ok, true);
  });
});
