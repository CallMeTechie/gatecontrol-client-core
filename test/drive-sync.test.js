'use strict';

// "Ordner sichern" (Drive's folder backup / sync): the pure helpers
// (utils/drive-sync.js — what is left out, conflict names, the mass-delete
// guard, the home network, the remote tree from the change log, moves and
// the planner), the bandwidth limit (utils/throttle.js), the new Drive API
// calls (changes, by-path, baseRev), the service (services/drive-sync.js)
// against the fake Drive server — "Nur sichern" and "Abgleichen" with
// conflicts, moves, deletes, the 30 days, pause / home network — and its IPC.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { PassThrough, Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const S = require('../src/utils/drive-sync');
const drive = require('../src/utils/drive');
const { createLimiter } = require('../src/utils/throttle');
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
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

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

// ── Pure helpers ───────────────────────────────────────────

describe('utils/drive-sync', () => {
  it('leaves out temporary files, node_modules / .git, large files and names Drive does not take', () => {
    const st = S.normalizeSettings({});
    assert.equal(S.excluded('Dokumente/~$Brief.docx', {}, st), 'temp');
    assert.equal(S.excluded('a/b.tmp', {}, st), 'temp');
    assert.equal(S.excluded('Thumbs.db', {}, st), 'temp');
    assert.equal(S.excluded('x/desktop.ini', {}, st), 'temp');
    assert.equal(S.excluded('.DS_Store', {}, st), 'temp');
    assert.equal(S.excluded('.~lock.Brief.odt#', {}, st), 'temp');
    assert.equal(S.excluded('Brief.pdf.gcdownload', {}, st), 'temp');
    assert.equal(S.excluded('app/node_modules/x/index.js', {}, st), 'dev');
    assert.equal(S.excluded('app/node_modules', { dir: true }, st), 'dev');
    assert.equal(S.excluded('repo/.git/HEAD', {}, st), 'dev');
    assert.equal(S.excluded('node_modules.txt', {}, st), null);
    assert.equal(S.excluded('app/node_modules/x.js', {}, { ...st, skipDev: false }), null);
    assert.equal(S.excluded('Film.mkv', { size: 11 * 1024 ** 3 }, st), 'too_large');
    assert.equal(S.excluded('Film.mkv', { size: 11 * 1024 ** 3 }, { ...st, maxFileBytes: 0 }), null);
    assert.equal(S.excluded('Ordner./x.txt', {}, st), 'name');
    assert.equal(S.excluded('Fotos/Urlaub 2026/Strand.jpg', { size: 10 }, st), null);
  });

  it('names conflict copies with the PC and the time, keeps the extension', () => {
    const at = new Date(2026, 9, 27, 14, 5).getTime();
    assert.equal(S.conflictName('Bericht.docx', 'Desktop-PC', at), 'Bericht (Konflikt Desktop-PC 2026-10-27 14-05).docx');
    assert.equal(S.conflictName('README', 'PC:1', at), 'README (Konflikt PC_1 2026-10-27 14-05)');
    const long = S.conflictName(`${'x'.repeat(300)}.pdf`, 'PC', at);
    assert.ok(long.length <= 255 && long.endsWith(').pdf'));
    assert.equal(S.freeName('Dokumente', new Set(['dokumente', 'dokumente (2)'])), 'Dokumente (3)');
    assert.equal(S.deviceName('MARC-PC'), 'MARC-PC');
    assert.equal(S.deviceName(''), 'PC');
  });

  it('asks before mass deletes: more than 500, or more than 20 % (at least 10 files)', () => {
    assert.equal(S.massDelete(501, 100000), true);
    assert.equal(S.massDelete(500, 100000), false);
    assert.equal(S.massDelete(21, 100), true);
    assert.equal(S.massDelete(20, 100), false);
    assert.equal(S.massDelete(3, 3), false);
    assert.equal(S.massDelete(10, 10), true);
  });

  it('cleans settings, folders and the config', () => {
    const s = S.normalizeSettings({ upKBs: '512', downKBs: -3, maxFileBytes: 5, homeNets: ['zz', 'a'.repeat(32)], skipDev: 'no', paused: true, extra: 1 });
    assert.deepEqual(s, { deviceName: null, paused: true, skipDev: true, maxFileBytes: 5, upKBs: 512, downKBs: 0, homeOnly: false, homeNets: ['a'.repeat(32)], vpnOnly: false });
    const cfg = S.normalizeConfig({
      settings: { deviceName: 'Büro:PC' },
      folders: [
        { id: 'abcdef0123456789', path: 'C:\\Users\\Marc\\Documents', mode: 'backup', remoteName: 'Documents' },
        { id: 'abcdef0123456789', path: 'C:\\x', mode: 'backup' },
        { id: 'bad', path: 'C:\\y', mode: 'backup' },
        { id: '0123456789abcdef', path: 'D:\\Projekte', mode: 'sync', target: { nodeId: 0 } },
        { id: '1123456789abcdef', path: 'D:\\Hausbau', mode: 'sync', target: { nodeId: 55, areaId: 'family:1', label: 'Familie › Hausbau' } },
      ],
    });
    assert.equal(cfg.settings.deviceName, 'Büro_PC');
    assert.deepEqual(cfg.folders.map((f) => f.path), ['C:\\Users\\Marc\\Documents', 'D:\\Hausbau']);
    assert.equal(S.overlaps('C:\\Users\\Marc\\Documents\\Briefe', cfg.folders), true);
    assert.equal(S.overlaps('c:\\users\\marc', cfg.folders), true);
    assert.equal(S.overlaps('C:\\Users\\Marc\\Desktop', cfg.folders), false);
  });

  it('home network: private networks of real adapters, fingerprints', () => {
    const ifaces = {
      WLAN: [{ family: 'IPv4', address: '192.168.178.23', netmask: '255.255.255.0', internal: false }, { family: 'IPv6', address: 'fe80::1', netmask: 'ffff::', internal: false }],
      'GateControl Pro': [{ family: 'IPv4', address: '10.8.0.5', netmask: '255.255.255.0', internal: false }],
      'vEthernet (WSL)': [{ family: 'IPv4', address: '172.20.0.1', netmask: '255.255.240.0', internal: false }],
      Ethernet: [{ family: 'IPv4', address: '84.10.1.2', netmask: '255.255.255.0', internal: false }],
      lo: [{ family: 'IPv4', address: '127.0.0.1', netmask: '255.0.0.0', internal: true }],
    };
    assert.deepEqual(S.localNetworks(ifaces), ['192.168.178.0/24']);
    const fp = S.networkFingerprints(['192.168.178.0/24']);
    assert.match(fp[0], /^[0-9a-f]{32}$/);
    assert.notEqual(S.networkFingerprints(['192.168.178.0/24'], { '192.168.178.0/24': 'AA:BB:CC:00:11:22' })[0], fp[0]);
    assert.equal(S.atHome(fp, [fp[0]]), true);
    assert.equal(S.atHome(fp, []), false);
  });

  it('applies the change log to the tree below the folder', () => {
    const tree = {
      20: { id: 20, parentId: 1, name: 'Sub', isDir: true, rev: 1 },
      21: { id: 21, parentId: 20, name: 'a.txt', isDir: false, rev: 1 },
    };
    const n = (o) => ({ areaId: 'mine:2', isDir: false, rev: 1, size: 1, deleted: false, ...o });
    const r = S.applyChanges(tree, 1, [
      { seq: 10, op: 'create', nodeId: 22, node: n({ id: 22, parentId: 20, name: 'b.txt' }) },       // inside
      { seq: 11, op: 'create', nodeId: 30, node: n({ id: 30, parentId: 99, name: 'elsewhere.txt' }) }, // outside
      { seq: 12, op: 'move', nodeId: 40, node: n({ id: 40, parentId: 1, name: 'Neu', isDir: true }) }, // a folder came in
      { seq: 13, op: 'update', nodeId: 21, node: n({ id: 21, parentId: 20, name: 'a.txt', rev: 2 }) },
      { seq: 14, op: 'delete', nodeId: 50, node: null },
    ]);
    assert.equal(r.touched, true);
    assert.deepEqual(r.rescan, [40]);
    assert.equal(tree[21].rev, 2);
    assert.ok(tree[22] && !tree[30]);
    const paths = [...S.remoteByPath(tree, 1).values()].map((x) => x.path).sort();
    assert.deepEqual(paths, ['Neu', 'Sub', 'Sub/a.txt', 'Sub/b.txt']);
    // moved out of the folder, deleted (with what is below), the folder itself gone
    S.applyChanges(tree, 1, [{ seq: 15, op: 'move', nodeId: 20, node: n({ id: 20, parentId: 99, name: 'Sub', isDir: true }) }]);
    assert.deepEqual(Object.keys(tree), ['40']);
    S.applyChanges(tree, 1, [{ seq: 16, op: 'delete', nodeId: 40, node: n({ id: 40, parentId: 1, name: 'Neu', isDir: true, deleted: true }) }]);
    assert.deepEqual(Object.keys(tree), []);
    assert.equal(S.applyChanges(tree, 1, [{ seq: 17, op: 'delete', nodeId: 1, node: null }]).rootGone, true);
  });

  const B = (p, o = {}) => [S.keyOf(p), { path: p, dir: false, size: 5, mtime: 1000, sha256: null, nodeId: 1, rev: 1, ...o }];
  const L = (p, o = {}) => [S.keyOf(p), { path: p, dir: false, size: 5, mtime: 1000, ...o }];
  const R = (p, o = {}) => [S.keyOf(p), { path: p, dir: false, nodeId: 1, parentId: 0, rev: 1, size: 5, sha256: null, mtime: 1000, ...o }];
  const ops = (r) => r.actions.map((a) => `${a.op} ${a.path || a.key}`);

  it('plans "Abgleichen": new, changed, deleted on either side, both changed', () => {
    const base = Object.fromEntries([
      B('same.txt', { nodeId: 1 }), B('local-changed.txt', { nodeId: 2 }), B('remote-changed.txt', { nodeId: 3 }),
      B('both.txt', { nodeId: 4 }), B('local-deleted.txt', { nodeId: 5 }), B('remote-deleted.txt', { nodeId: 6 }),
      B('gone-both.txt', { nodeId: 7 }), B('deleted-but-changed.txt', { nodeId: 8 }),
    ]);
    const local = new Map([
      L('same.txt'), L('local-changed.txt', { size: 9 }), L('remote-changed.txt'), L('both.txt', { mtime: 2000 }),
      L('remote-deleted.txt'), L('new-local.txt'), L('Neu', { dir: true }), L('Neu/x.txt'),
    ]);
    const remote = new Map([
      R('same.txt', { nodeId: 1 }), R('local-changed.txt', { nodeId: 2 }), R('remote-changed.txt', { nodeId: 3, rev: 2 }),
      R('both.txt', { nodeId: 4, rev: 2 }), R('local-deleted.txt', { nodeId: 5 }), R('new-remote.txt', { nodeId: 9 }),
      R('deleted-but-changed.txt', { nodeId: 8, rev: 3 }),
    ]);
    const r = S.plan({ mode: 'sync', base, local, remote });
    assert.deepEqual(ops(r).sort(), [
      'deleteLocal remote-deleted.txt',
      'download deleted-but-changed.txt',
      'download new-remote.txt',
      'download remote-changed.txt',
      'forget gone-both.txt',
      'merge both.txt',
      'mkdirRemote Neu',
      'trashRemote local-deleted.txt',
      'upload Neu/x.txt',
      'upload local-changed.txt',
      'upload new-local.txt',
    ]);
    assert.equal(r.deletes, 1);
    assert.equal(r.files, 8);
    assert.equal(r.actions[0].op, 'mkdirRemote');
    assert.equal(r.actions.find((a) => a.path === 'local-changed.txt').baseRev, 1);
    // "Wiederherstellen": what was deleted on the PC comes back
    const back = S.plan({ mode: 'sync', base, local, remote, restoreDeleted: true });
    assert.ok(ops(back).includes('download local-deleted.txt'));
    assert.equal(back.deletes, 0);
  });

  it('plans "Nur sichern": one way, deletes wait, Drive changes are not written back', () => {
    const base = Object.fromEntries([B('a.txt', { nodeId: 1 }), B('b.txt', { nodeId: 2 }), B('c.txt', { nodeId: 3 }), B('d.txt', { nodeId: 4 })]);
    const local = new Map([L('a.txt'), L('b.txt', { size: 7 }), L('c.txt'), L('e.txt')]);
    const remote = new Map([R('a.txt', { nodeId: 1, rev: 5 }), R('b.txt', { nodeId: 2 }), R('d.txt', { nodeId: 4 }), R('other.txt', { nodeId: 8 })]);
    const r = S.plan({ mode: 'backup', base, local, remote });
    assert.deepEqual(ops(r).sort(), ['pendingDelete d.txt', 'record a.txt', 'upload b.txt', 'upload c.txt', 'upload e.txt']);
  });

  it('plans folders: a folder deleted on the PC goes as one, one deleted in Drive goes to the recycle bin', () => {
    const base = Object.fromEntries([
      B('Alt', { dir: true, nodeId: 10, size: 0, mtime: 0 }), B('Alt/1.txt', { nodeId: 11 }), B('Alt/2.txt', { nodeId: 12 }),
      B('Weg', { dir: true, nodeId: 20, size: 0, mtime: 0 }), B('Weg/1.txt', { nodeId: 21 }),
    ]);
    const local = new Map([L('Weg', { dir: true, size: 0, mtime: 0 }), L('Weg/1.txt')]);
    const remote = new Map([R('Alt', { dir: true, nodeId: 10, size: 0, mtime: 0 }), R('Alt/1.txt', { nodeId: 11 }), R('Alt/2.txt', { nodeId: 12 })]);
    const r = S.plan({ mode: 'sync', base, local, remote });
    assert.deepEqual(ops(r).sort(), ['deleteLocal Weg', 'trashRemote Alt']);
    assert.equal(r.deletes, 2);
    // a file of the folder changed in Drive meanwhile: the folder comes back with it
    remote.set(S.keyOf('Alt/2.txt'), R('Alt/2.txt', { nodeId: 12, rev: 2 })[1]);
    const r2 = S.plan({ mode: 'sync', base, local, remote });
    assert.deepEqual(ops(r2).filter((x) => x.includes('Alt')).sort(), ['download Alt/2.txt', 'mkdirLocal Alt', 'trashRemote Alt/1.txt']);
    // backup: the folder waits as a whole
    const r3 = S.plan({ mode: 'backup', base, local: new Map([L('Weg', { dir: true }), L('Weg/1.txt')]), remote: new Map([R('Alt', { dir: true, nodeId: 10 }), R('Alt/1.txt', { nodeId: 11 }), R('Alt/2.txt', { nodeId: 12 })]) });
    assert.ok(ops(r3).includes('pendingDelete Alt'));
    assert.ok(ops(r3).includes('mkdirRemote Weg'));
  });

  it('finds sure moves on either side', () => {
    const base = Object.fromEntries([
      B('Projekt', { dir: true, nodeId: 10, size: 0, mtime: 0 }), B('Projekt/a.txt', { nodeId: 11, mtime: 1 }), B('Projekt/b.txt', { nodeId: 12, mtime: 2 }),
      B('Brief.pdf', { nodeId: 20, size: 50, mtime: 9 }),
    ]);
    const remote = new Map([R('Projekt', { dir: true, nodeId: 10 }), R('Projekt/a.txt', { nodeId: 11 }), R('Projekt/b.txt', { nodeId: 12 }), R('Brief.pdf', { nodeId: 20, size: 50 })]);
    // the PC renamed the folder
    let local = new Map([L('Projekt 2026', { dir: true }), L('Projekt 2026/a.txt', { mtime: 1 }), L('Projekt 2026/b.txt', { mtime: 2 }), L('Brief.pdf', { size: 50, mtime: 9 })]);
    let m = S.planMoves({ base, local, remote, mode: 'sync' });
    assert.deepEqual(m.map((x) => [x.op, x.from, x.to, x.nodeId]), [['moveRemote', 'Projekt', 'Projekt 2026', 10]]);
    const moved = S.rebase(base, 'projekt', 'Projekt 2026');
    assert.deepEqual(Object.keys(moved).sort(), ['brief.pdf', 'projekt 2026', 'projekt 2026/a.txt', 'projekt 2026/b.txt']);
    assert.equal(moved['projekt 2026/a.txt'].path, 'Projekt 2026/a.txt');
    // the PC renamed a file
    local = new Map([L('Projekt', { dir: true }), L('Projekt/a.txt', { mtime: 1 }), L('Projekt/b.txt', { mtime: 2 }), L('Projekt/Brief 2.pdf', { size: 50, mtime: 9 })]);
    m = S.planMoves({ base, local, remote, mode: 'sync' });
    assert.deepEqual(m.map((x) => [x.op, x.from, x.to]), [['moveRemote', 'Brief.pdf', 'Projekt/Brief 2.pdf']]);
    // Drive renamed a file
    local = new Map([L('Projekt', { dir: true }), L('Projekt/a.txt', { mtime: 1 }), L('Projekt/b.txt', { mtime: 2 }), L('Brief.pdf', { size: 50, mtime: 9 })]);
    const r2 = new Map(remote);
    r2.delete('brief.pdf');
    r2.set('projekt/brief.pdf', R('Projekt/Brief.pdf', { nodeId: 20, size: 50 })[1]);
    m = S.planMoves({ base, local, remote: r2, mode: 'sync' });
    assert.deepEqual(m.map((x) => [x.op, x.from, x.to]), [['moveLocal', 'Brief.pdf', 'Projekt/Brief.pdf']]);
    assert.deepEqual(S.planMoves({ base, local, remote: r2, mode: 'backup' }), []);
    // two files of the same size and time went: not sure which is which
    const twins = Object.fromEntries([B('x.txt', { nodeId: 1 }), B('y.txt', { nodeId: 2 })]);
    m = S.planMoves({ base: twins, local: new Map([L('z.txt')]), remote: new Map([R('x.txt', { nodeId: 1 }), R('y.txt', { nodeId: 2 })]), mode: 'sync' });
    assert.deepEqual(m, []);
  });
});

describe('utils/throttle', () => {
  it('keeps a stream to the limit and passes through when unlimited', async () => {
    let t = 0;
    let rate = 10; // KB/s
    const waits = [];
    const lim = createLimiter(() => rate, { now: () => t, sleep: async (ms) => { waits.push(ms); t += ms; } });
    const data = Buffer.alloc(30 * 1024, 1);
    const out = [];
    await pipeline(Readable.from([data]), lim.stream(), new PassThrough().on('data', (c) => out.push(c)));
    assert.equal(Buffer.concat(out).length, data.length);
    // 30 KB at 10 KB/s: about three seconds
    const total = waits.reduce((a, b) => a + b, 0);
    assert.ok(total >= 2500 && total <= 3600, `waited ${total} ms`);
    rate = 0;
    waits.length = 0;
    await pipeline(Readable.from([data]), lim.stream(), new PassThrough().resume());
    assert.equal(waits.length, 0);
  });
});

// ── Drive API ──────────────────────────────────────────────

describe('Drive API for the sync', () => {
  it('reads the change log, a node by path, pages of children; commits with baseRev', async () => {
    const srv = await driveServer();
    cleanup.push(() => srv.close());
    const api = new DriveApi({ apiClient: new ApiClient(srv.url, 'gc_token', log), log, getLang: () => 'de' });
    const before = (await api.changes(0)).next;
    srv.mutate.file(10, 'Neu.txt', 'neu');
    const c = await api.changes(before);
    assert.equal(c.changes.length, 1);
    assert.equal(c.changes[0].op, 'create');
    assert.equal(c.changes[0].node.name, 'Neu.txt');
    assert.equal(c.changes[0].device, '77');
    assert.equal(c.next, before + 1);
    assert.equal(drive.normalizeChanges({ changes: [{ seq: 'x' }, { seq: 3, op: 'teleport', nodeId: 1 }] }).changes.length, 0);
    assert.equal(drive.normalizeChanges({}), null);

    assert.equal((await api.byPath('mine:2', 'Dokumente/Brief.pdf')).id, 12);
    assert.equal(await api.byPath('mine:2', 'Dokumente/Fehlt.pdf'), null);

    srv.pageMax = 2;
    const all = await api.childrenAll(1);
    assert.deepEqual(all.map((n) => n.name), ['Dokumente', 'Foto.jpg', 'setup.exe']);
    srv.pageMax = 1000;

    const up = await api.upload({ path: write(tmpDir('api-'), 'x.txt', 'xx'), size: 2, mime: 'text/plain' });
    await assert.rejects(api.commit({ mediaId: up.mediaId, parentId: 10, name: 'Brief.pdf', onConflict: null, baseRev: 7 }), (e) => e.status === 409 && e.code === 'conflict' && e.body.current.id === 12);
    const ok = await api.commit({ mediaId: up.mediaId, parentId: 10, name: 'Brief.pdf', onConflict: null, baseRev: 1 });
    assert.equal(ok.node.rev, 2);
    const body = srv.state.requests.filter((r) => r.path.endsWith('uploads/commit')).at(-1).body;
    assert.equal(body.baseRev, 1);
    assert.equal('onConflict' in body, false);
  });
});

// ── The service ────────────────────────────────────────────

async function syncSetup({ now = () => Date.now(), timing = {}, store = createMemoryStore(), dir = null, srv = null, ifaces = {}, vpn = true } = {}) {
  if (!srv) {
    srv = await driveServer();
    cleanup.push(() => srv.close());
  }
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({ apiClient, api, log, store, timing: { progressMs: 0 } });
  await svc.check();
  const stateDir = dir || tmpDir('drive-sync-state-');
  const trashed = [];
  const sync = new DriveSync({
    drive: svc, api, store, dir: stateDir, log, now,
    hostname: () => 'Desktop-PC',
    getDeviceKey: () => 'ab12cd34',
    getInterfaces: () => ifaces,
    isVpnUp: () => vpn,
    trashItem: async (p) => { trashed.push(p); await fs.promises.rm(p, { recursive: true, force: true }); },
    timing: { watch: false, settleMs: 0, emitMs: 0, ...timing },
  });
  cleanup.push(() => sync.stop());
  return { srv, svc, api, sync, store, stateDir, trashed };
}

const childNamed = (srv, parentId, name) => [...srv.state.nodes.values()].find((n) => n.parentId === parentId && !n.deleted && n.name === name);
const uploads = (srv) => srv.state.requests.filter((r) => r.path.endsWith('uploads/commit')).length;

describe('DriveSync: "Nur sichern"', () => {
  it('backs a folder up into Meine Dateien › Geräte › <PC> › <Ordner>, leaves out what it should', async () => {
    const { srv, sync } = await syncSetup();
    const root = path.join(tmpDir('pc-'), 'Dokumente');
    write(root, 'Brief.txt', 'Hallo Welt');
    write(root, 'Steuer/2026/Beleg.pdf', 'pdf-bytes');
    write(root, '~$Brief.docx', 'lock');
    write(root, 'Thumbs.db', 'x');
    write(root, 'app/node_modules/x/index.js', 'module');
    write(root, 'leer.txt', '');
    const r = await sync.addFolder({ path: root, mode: 'backup' });
    assert.equal(r.ok, true);
    assert.equal(r.folder.target.label, 'Meine Dateien › Geräte › Desktop-PC › Dokumente');
    await sync.idle();
    const geraete = childNamed(srv, 1, 'Geräte');
    const pc = childNamed(srv, geraete.id, 'Desktop-PC');
    const top = childNamed(srv, pc.id, 'Dokumente');
    assert.ok(top && top.isDir);
    const brief = childNamed(srv, top.id, 'Brief.txt');
    assert.equal(srv.state.media.get(brief.mediaId).data.toString(), 'Hallo Welt');
    const beleg = childNamed(srv, childNamed(srv, childNamed(srv, top.id, 'Steuer').id, '2026').id, 'Beleg.pdf');
    assert.ok(beleg);
    assert.equal(childNamed(srv, top.id, '~$Brief.docx'), undefined);
    assert.equal(childNamed(srv, top.id, 'Thumbs.db'), undefined);
    assert.equal(childNamed(srv, childNamed(srv, top.id, 'app').id, 'node_modules'), undefined);
    const st = sync.status();
    assert.equal(st.folders[0].state, 'idle');
    assert.equal(st.folders[0].files, 2);
    assert.equal(st.folders[0].skipped, 2); // node_modules, the empty file
    assert.ok(st.folders[0].lastSyncAt);
    assert.equal(st.device.name, 'Desktop-PC');
    assert.equal(st.device.id, '42');
    assert.equal(st.device.key, 'ab12cd34');

    // nothing changed: nothing goes up again
    const n = uploads(srv);
    sync.sync(r.folder.id);
    await sync.idle();
    assert.equal(uploads(srv), n);

    // a changed file becomes a new version; Drive's change is not written back
    write(root, 'Brief.txt', 'Hallo Welt, neu');
    srv.mutate.change(beleg.id, 'changed in Drive');
    sync.sync(r.folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(brief.id).rev, 2);
    assert.equal(srv.state.media.get(srv.state.nodes.get(brief.id).mediaId).data.toString(), 'Hallo Welt, neu');
    assert.equal(read(root, 'Steuer/2026/Beleg.pdf'), 'pdf-bytes');
  });

  it('keeps files deleted on the PC for 30 days, then they go into the trash', async () => {
    let t = Date.now();
    const { srv, sync } = await syncSetup({ now: () => t });
    const root = tmpDir('pc-bilder-');
    write(root, 'a.jpg', 'aaa');
    write(root, 'b.jpg', 'bbb');
    write(root, 'Alt/c.jpg', 'ccc');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const top = srv.state.nodes.get(sync._folder(folder.id).target.nodeId);
    const a = childNamed(srv, top.id, 'a.jpg');
    const alt = childNamed(srv, top.id, 'Alt');
    fs.rmSync(path.join(root, 'a.jpg'));
    fs.rmSync(path.join(root, 'Alt'), { recursive: true });
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(a.id).deleted, false);
    assert.equal(sync.status().folders[0].pendingDeletes, 2);
    // 29 days later: still there
    t += 29 * DAY;
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(a.id).deleted, false);
    // back on the PC before the time: nothing goes
    write(root, 'a.jpg', 'aaa');
    t += 2 * DAY;
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(srv.state.nodes.get(a.id).deleted, false);
    assert.equal(srv.state.nodes.get(alt.id).deleted, true);
    assert.equal(sync.status().folders[0].pendingDeletes, 0);
  });

  it('asks before many deletes; "Wiederherstellen" brings them back, "Löschen übertragen" marks them', async () => {
    const { srv, sync } = await syncSetup();
    const root = tmpDir('pc-viele-');
    for (let i = 0; i < 12; i++) write(root, `f${i}.txt`, `datei ${i}`);
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    for (let i = 0; i < 12; i++) fs.rmSync(path.join(root, `f${i}.txt`));
    sync.sync(folder.id);
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(f.state, 'confirm');
    assert.deepEqual(f.confirm, { count: 12, total: 12, from: 'pc' });
    assert.equal(f.pendingDeletes, 0);
    sync.confirmDeletes(folder.id, 'restore');
    await sync.idle();
    assert.equal(read(root, 'f3.txt'), 'datei 3');
    assert.equal(sync.status().folders[0].state, 'idle');

    for (let i = 0; i < 12; i++) fs.rmSync(path.join(root, `f${i}.txt`));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'confirm');
    sync.confirmDeletes(folder.id, 'apply');
    await sync.idle();
    f = sync.status().folders[0];
    assert.equal(f.state, 'idle');
    assert.equal(f.pendingDeletes, 12);
    // the next run does not ask again for the same files
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.throws(() => sync.confirmDeletes(folder.id, 'apply'), (e) => e.code === 'not_found');
    assert.ok(childNamed(srv, sync._folder(folder.id).target.nodeId, 'f1.txt'));
  });

  it('uploads again what was deleted in Drive', async () => {
    const { srv, sync } = await syncSetup();
    const root = tmpDir('pc-again-');
    write(root, 'wichtig.txt', 'wichtig');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    const top = sync._folder(folder.id).target.nodeId;
    srv.mutate.remove(childNamed(srv, top, 'wichtig.txt').id);
    sync.sync(folder.id);
    await sync.idle();
    const again = childNamed(srv, top, 'wichtig.txt');
    assert.ok(again && !again.deleted);
    assert.equal(read(root, 'wichtig.txt'), 'wichtig');
  });

  it('a file still being written waits (at most three runs)', async () => {
    const { srv, sync } = await syncSetup({ timing: { settleMs: 60000, watchMs: 60000 } });
    const root = tmpDir('pc-busy-');
    write(root, 'log.txt', 'zeile 1');
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(f.state, 'syncing');
    assert.equal(f.reason, 'settling');
    const top = sync._folder(folder.id).target.nodeId;
    assert.equal(childNamed(srv, top, 'log.txt'), undefined);
    for (let i = 0; i < 3; i++) { sync.sync(folder.id); await sync.idle(); }
    f = sync.status().folders[0];
    assert.equal(f.state, 'idle');
    assert.ok(childNamed(srv, top, 'log.txt'));
  });

  it('a missing folder (an unplugged disk) is an error and deletes nothing', async () => {
    const { srv, sync } = await syncSetup();
    const parent = tmpDir('pc-usb-');
    const root = path.join(parent, 'USB');
    write(root, 'a.txt', 'aaa');
    const { folder } = await sync.addFolder({ path: root, mode: 'sync', targetId: 10 });
    await sync.idle();
    fs.rmSync(root, { recursive: true });
    const before = srv.state.requests.filter((r) => r.method === 'DELETE').length;
    sync.sync(folder.id);
    await sync.idle();
    const f = sync.status().folders[0];
    assert.equal(f.state, 'error');
    assert.equal(f.reason, 'folder_missing');
    assert.equal(srv.state.requests.filter((r) => r.method === 'DELETE').length, before);
  });
});

describe('DriveSync: "Abgleichen"', () => {
  async function synced() {
    const env = await syncSetup();
    const root = tmpDir('pc-sync-');
    write(root, 'Lokal.txt', 'vom PC');
    const { folder } = await env.sync.addFolder({ path: root, mode: 'sync', targetId: 10 });
    await env.sync.idle();
    return { ...env, root, folder };
  }

  it('asks before many files deleted in Drive leave the PC; "Wiederherstellen" uploads them again', async () => {
    const { srv, sync, root, folder } = await synced();
    for (let i = 0; i < 12; i++) write(root, `g${i}.txt`, `datei ${i}`);
    sync.sync(folder.id);
    await sync.idle();
    const ids = [];
    for (let i = 0; i < 12; i++) ids.push(childNamed(srv, 10, `g${i}.txt`).id);
    for (const id of ids) srv.mutate.remove(id);
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(f.state, 'confirm');
    assert.equal(f.confirm.from, 'drive');
    assert.equal(f.confirm.count, 12);
    assert.equal(read(root, 'g4.txt'), 'datei 4'); // nothing left the PC yet
    sync.confirmDeletes(folder.id, 'restore');
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.equal(read(root, 'g4.txt'), 'datei 4');
    const back = childNamed(srv, 10, 'g4.txt');
    assert.ok(back && !back.deleted);

    for (let i = 0; i < 12; i++) srv.mutate.remove(childNamed(srv, 10, `g${i}.txt`).id);
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'confirm');
    sync.confirmDeletes(folder.id, 'apply');
    await sync.idle();
    f = sync.status().folders[0];
    assert.equal(f.state, 'idle');
    assert.equal(exists(root, 'g4.txt'), false);
    assert.equal(read(root, 'Lokal.txt'), 'vom PC');
  });

  it('merges both sides on the first run and follows the change log of Drive', async () => {
    const { srv, sync, root, folder } = await synced();
    assert.equal(folder.target.label, 'Meine Dateien › Dokumente');
    assert.equal(read(root, 'Brief.pdf'), '%PDF-1.4 brief');
    const lokal = childNamed(srv, 10, 'Lokal.txt');
    assert.equal(srv.state.media.get(lokal.mediaId).data.toString(), 'vom PC');

    // another device: a new file, a change, a new folder with a file
    const n = srv.mutate.file(10, 'Von Laptop.txt', 'laptop');
    srv.mutate.change(12, '%PDF-1.4 brief v2', { mtime: Date.parse('2026-10-01T10:00:00Z') });
    const d = srv.mutate.dir(10, 'Fotos');
    srv.mutate.file(d.id, 'Strand.jpg', 'jpeg');
    const changes = srv.state.requests.filter((r) => r.path.endsWith('/changes')).length;
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    assert.ok(srv.state.requests.filter((r) => r.path.endsWith('/changes')).length > changes);
    assert.equal(read(root, 'Von Laptop.txt'), 'laptop');
    assert.equal(read(root, 'Brief.pdf'), '%PDF-1.4 brief v2');
    assert.equal(fs.statSync(path.join(root, 'Brief.pdf')).mtimeMs, Date.parse('2026-10-01T10:00:00Z'));
    assert.equal(read(root, 'Fotos/Strand.jpg'), 'jpeg');

    // a change on the PC: a new version with baseRev
    write(root, 'Von Laptop.txt', 'laptop, am PC geändert');
    sync.sync(folder.id);
    await sync.idle();
    const commit = srv.state.requests.filter((r) => r.path.endsWith('uploads/commit')).at(-1).body;
    assert.equal(commit.baseRev, 1);
    assert.equal(srv.state.nodes.get(n.id).rev, 2);

    // deleted in Drive → into the recycle bin; deleted on the PC → into Drive's trash
    srv.mutate.remove(n.id);
    fs.rmSync(path.join(root, 'Lokal.txt'));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(exists(root, 'Von Laptop.txt'), false);
    assert.equal(srv.state.nodes.get(lokal.id).deleted, true);
    assert.equal(sync.status().folders[0].state, 'idle');
  });

  it('keeps the bytes of the PC as a conflict copy when both sides changed', async () => {
    const { srv, sync, root, folder } = await synced();
    write(root, 'Brief.pdf', 'am PC bearbeitet');
    srv.mutate.change(12, 'im Drive bearbeitet');
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(read(root, 'Brief.pdf'), 'im Drive bearbeitet');
    const copies = fs.readdirSync(root).filter((x) => x.startsWith('Brief (Konflikt Desktop-PC '));
    assert.equal(copies.length, 1);
    assert.equal(read(root, copies[0]), 'am PC bearbeitet');
    const remoteCopy = childNamed(srv, 10, copies[0]);
    assert.equal(srv.state.media.get(remoteCopy.mediaId).data.toString(), 'am PC bearbeitet');
    assert.equal(sync.status().folders[0].conflicts, 1);
    // the next run has nothing to do
    const n = uploads(srv);
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(uploads(srv), n);
  });

  it('a 409 of the commit (Drive changed after the plan) ends in a conflict copy too', async () => {
    const { srv, sync, root, folder } = await synced();
    // Drive changes without a change-log entry the PC could have seen
    const node = srv.state.nodes.get(12);
    const data = Buffer.from('heimlich geändert');
    srv.state.media.set('hiddenMedia00001', { data, mime: 'application/pdf' });
    Object.assign(node, { rev: node.rev + 5, mediaId: 'hiddenMedia00001', size: data.length, sha256: sha('heimlich geändert') });
    write(root, 'Brief.pdf', 'PC-Fassung');
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(read(root, 'Brief.pdf'), 'heimlich geändert');
    const copy = fs.readdirSync(root).find((x) => x.includes('(Konflikt '));
    assert.equal(read(root, copy), 'PC-Fassung');
    assert.ok(childNamed(srv, 10, copy));
  });

  it('renames and moves as moves, without uploading again', async () => {
    const { srv, sync, root, folder } = await synced();
    write(root, 'Projekt/a.txt', 'aaaa');
    write(root, 'Projekt/b.txt', 'bbbbb');
    sync.sync(folder.id);
    await sync.idle();
    const projekt = childNamed(srv, 10, 'Projekt');
    const n = uploads(srv);
    fs.renameSync(path.join(root, 'Projekt'), path.join(root, 'Projekt 2026'));
    fs.renameSync(path.join(root, 'Lokal.txt'), path.join(root, 'Lokal umbenannt.txt'));
    sync.sync(folder.id);
    await sync.idle();
    assert.equal(uploads(srv), n);
    assert.equal(srv.state.nodes.get(projekt.id).name, 'Projekt 2026');
    assert.equal(srv.state.nodes.get(projekt.id).deleted, false);
    assert.ok(childNamed(srv, 10, 'Lokal umbenannt.txt'));
    // Drive renames: the PC follows (no download)
    const downloads = srv.state.requests.filter((r) => /\/content$/.test(r.path)).length;
    srv.mutate.place(12, { name: 'Brief (alt).pdf', parentId: projekt.id });
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    assert.equal(read(root, 'Projekt 2026/Brief (alt).pdf'), '%PDF-1.4 brief');
    assert.equal(exists(root, 'Brief.pdf'), false);
    assert.equal(srv.state.requests.filter((r) => /\/content$/.test(r.path)).length, downloads);
  });

  it('a folder moved into the synced folder in Drive comes with its content; temporary files stay out', async () => {
    const { srv, sync, root, folder } = await synced();
    const outside = srv.mutate.dir(1, 'Woanders');
    srv.mutate.file(outside.id, 'drin.txt', 'drin');
    srv.mutate.file(10, 'Thumbs.db', 'thumbs');
    srv.mutate.place(outside.id, { parentId: 10 });
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    assert.equal(read(root, 'Woanders/drin.txt'), 'drin');
    assert.equal(exists(root, 'Thumbs.db'), false);
    // moved out again: gone from the PC (into the recycle bin)
    srv.mutate.place(outside.id, { parentId: 1 });
    sync.sync(folder.id, { full: false, remote: true });
    await sync.idle();
    assert.equal(exists(root, 'Woanders'), false);
  });

  it('a file on one side and a folder of the same name on the other: the PC item moves aside', async () => {
    const { srv, sync, root, folder } = await synced();
    write(root, 'Plan', 'eine Datei');
    const d = srv.mutate.dir(10, 'Plan');
    srv.mutate.file(d.id, 'inhalt.txt', 'inhalt');
    sync.sync(folder.id);
    await sync.idle();
    await sync.idle();
    const end = Date.now() + 5000;
    while (!exists(root, 'Plan/inhalt.txt') && Date.now() < end) { await new Promise((r) => setTimeout(r, 50)); await sync.idle(); }
    assert.equal(read(root, 'Plan/inhalt.txt'), 'inhalt');
    const aside = fs.readdirSync(root).find((x) => x.startsWith('Plan (Konflikt '));
    assert.equal(read(root, aside), 'eine Datei');
  });

  it('remembers its state over a restart (nothing is transferred again)', async () => {
    const store = createMemoryStore();
    const { srv, sync, stateDir, root, folder } = await (async () => {
      const env = await syncSetup({ store });
      const r = tmpDir('pc-restart-');
      write(r, 'x.txt', 'xxx');
      const { folder: f } = await env.sync.addFolder({ path: r, mode: 'sync', targetId: 10 });
      await env.sync.idle();
      return { ...env, root: r, folder: f };
    })();
    sync.stop();
    assert.ok(fs.existsSync(path.join(stateDir, `${folder.id}.json`)));
    const raw = fs.readFileSync(path.join(stateDir, `${folder.id}.json`), 'utf8');
    assert.equal(/gc_token/.test(raw), false);
    assert.equal(/gc_token/.test(JSON.stringify(store.store)), false);
    const again = await syncSetup({ store, dir: stateDir, srv });
    const n = uploads(srv);
    const content = srv.state.requests.filter((r) => /\/content$/.test(r.path)).length;
    again.sync.sync(folder.id);
    await again.sync.idle();
    assert.equal(uploads(srv), n);
    assert.equal(srv.state.requests.filter((r) => /\/content$/.test(r.path)).length, content);
    assert.equal(read(root, 'x.txt'), 'xxx');
    // a broken state file starts fresh: compared by content, nothing deleted
    fs.writeFileSync(path.join(stateDir, `${folder.id}.json`), '{broken');
    const third = await syncSetup({ store, dir: stateDir, srv });
    third.sync.sync(folder.id);
    await third.sync.idle();
    assert.equal(third.sync.status().folders[0].state, 'idle');
    assert.equal(srv.state.nodes.get(12).deleted, false);
    assert.equal(read(root, 'Brief.pdf'), '%PDF-1.4 brief');
  });

  it('checks the folders it is given', async () => {
    const { sync } = await syncSetup();
    const root = tmpDir('pc-check-');
    await assert.rejects(sync.addFolder({ path: root, mode: 'sync', targetId: 4 }), (e) => e.code === 'forbidden'); // archived team
    await assert.rejects(sync.addFolder({ path: root, mode: 'magic' }), (e) => e.code === 'invalid');
    await assert.rejects(sync.addFolder({ path: 'relative', mode: 'backup' }), (e) => e.code === 'invalid');
    await assert.rejects(sync.addFolder({ path: path.join(root, 'fehlt'), mode: 'backup' }), (e) => e.code === 'folder_missing');
    await sync.addFolder({ path: root, mode: 'sync', targetId: 10 });
    await assert.rejects(sync.addFolder({ path: path.join(root, 'innen'), mode: 'backup' }).catch((e) => { throw e; }), (e) => e.code === 'folder_missing' || e.code === 'overlap');
    fs.mkdirSync(path.join(root, 'innen'));
    await assert.rejects(sync.addFolder({ path: path.join(root, 'innen'), mode: 'backup' }), (e) => e.code === 'overlap');
    const other = tmpDir('pc-check2-');
    await assert.rejects(sync.addFolder({ path: other, mode: 'sync', targetId: 10 }), (e) => e.code === 'target_taken');
    await sync.idle();
  });
});

describe('DriveSync: control', () => {
  it('pause, home network, VPN and removing a folder', async () => {
    const ifaces = { WLAN: [{ family: 'IPv4', address: '192.168.178.23', netmask: '255.255.255.0', internal: false }] };
    const env = await syncSetup({ ifaces, vpn: false });
    const { sync, srv } = env;
    const root = tmpDir('pc-ctl-');
    write(root, 'a.txt', 'aaa');
    sync.setSettings({ paused: true });
    const { folder } = await sync.addFolder({ path: root, mode: 'backup' });
    await sync.idle();
    assert.equal(sync.status().state, 'paused');
    assert.equal(uploads(srv), 0);

    assert.throws(() => sync.setSettings({ homeOnly: true }), (e) => e.code === 'no_home');
    sync.setHome(true);
    assert.equal(sync.status().network.home, true);
    sync.setSettings({ paused: false, homeOnly: true, vpnOnly: true, upKBs: 2048 });
    await sync.idle();
    let f = sync.status().folders[0];
    assert.equal(f.state, 'waiting');
    assert.equal(f.reason, 'no_vpn');
    assert.equal(sync.status().settings.upKBs, 2048);
    assert.equal(sync.status().settings.homeNets, undefined);
    sync.setSettings({ vpnOnly: false });
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');
    assert.equal(uploads(srv), 1);

    // another network: waits
    env.sync.getInterfaces = () => ({ WLAN: [{ family: 'IPv4', address: '10.1.2.3', netmask: '255.255.0.0', internal: false }] });
    sync.sync(folder.id);
    await sync.idle();
    f = sync.status().folders[0];
    assert.equal(f.state, 'waiting');
    assert.equal(f.reason, 'not_home');

    // one folder paused
    sync.setHome(false);
    sync.setPaused(folder.id, true);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'paused');
    sync.setPaused(folder.id, false);
    await sync.idle();
    assert.equal(sync.status().folders[0].state, 'idle');

    // removing stops it: nothing deleted here or there
    const node = sync._folder(folder.id).target.nodeId;
    await sync.removeFolder(folder.id);
    assert.equal(sync.status().folders.length, 0);
    assert.equal(read(root, 'a.txt'), 'aaa');
    assert.equal(srv.state.nodes.get(node).deleted, false);
    assert.equal(fs.existsSync(path.join(env.stateDir, `${folder.id}.json`)), false);
  });

  it('waits while Drive is not reachable and for another server', async () => {
    const env = await syncSetup();
    const root = tmpDir('pc-off-');
    write(root, 'a.txt', 'aaa');
    const { folder } = await env.sync.addFolder({ path: root, mode: 'backup' });
    await env.sync.idle();
    env.srv.state.fail['GET changes'] = { status: 503, code: 'unavailable' };
    write(root, 'b.txt', 'bbb');
    env.sync.sync(folder.id);
    await env.sync.idle();
    assert.equal(env.sync.status().folders[0].state, 'waiting');
    assert.equal(env.sync.status().folders[0].reason, 'offline');
    delete env.srv.state.fail['GET changes'];
    // another server / token
    env.api.http.apiClient.apiKey = 'other_token';
    assert.equal(env.sync.status().folders[0].reason, 'other_server');
  });

  it('watches the folder and runs after a change', async () => {
    const env = await syncSetup({ timing: { watch: true, watchMs: 50 } });
    const root = tmpDir('pc-watch-');
    const { folder } = await env.sync.addFolder({ path: root, mode: 'backup' });
    await env.sync.idle();
    if (!env.sync.status().folders[0].watching) return; // no recursive fs.watch here
    write(root, 'neu.txt', 'neu');
    const top = env.sync._folder(folder.id).target.nodeId;
    const end = Date.now() + 5000;
    while (!childNamed(env.srv, top, 'neu.txt') && Date.now() < end) await new Promise((r) => setTimeout(r, 25));
    assert.ok(childNamed(env.srv, top, 'neu.txt'));
  });
});

describe('drive:sync:* IPC', () => {
  it('checks arguments, passes events on, and the bridge has the channels', async () => {
    const handlers = {};
    const sent = [];
    const fake = new EventEmitter();
    const calls = [];
    const syncFake = Object.assign(new EventEmitter(), {
      status: () => ({ ok: true, folders: [] }),
      pickFolder: async () => ({ ok: true, path: 'C:\\X' }),
      addFolder: async (a) => { calls.push(['add', a]); return { ok: true }; },
      removeFolder: async (id) => { calls.push(['remove', id]); return { ok: true }; },
      setPaused: (id, p) => { calls.push(['pause', id, p]); return { ok: true }; },
      setSettings: (p) => { calls.push(['settings', p]); return { ok: true }; },
      setHome: (on) => { calls.push(['home', on]); return { ok: true }; },
      sync: (id) => { calls.push(['run', id]); return { ok: true }; },
      syncAll: () => { calls.push(['runAll']); return { ok: true }; },
      confirmDeletes: (id, d) => { calls.push(['deletes', id, d]); return { ok: true }; },
      openFolder: async (id) => { calls.push(['open', id]); return { ok: true }; },
    });
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: fake, sync: syncFake, getMainWindow: () => win, log });
    const id = 'abcdef0123456789';
    assert.deepEqual(await handlers['drive:sync:status'](), { ok: true, folders: [] });
    assert.equal((await handlers['drive:sync:add'](null, { path: 'C:\\X', mode: 'nope' })).code, 'invalid');
    assert.equal((await handlers['drive:sync:add'](null, { path: 'C:\\X', mode: 'sync' })).code, 'invalid');
    assert.equal((await handlers['drive:sync:add'](null, { path: 'C:\\X', mode: 'sync', targetId: 10 })).ok, true);
    assert.equal((await handlers['drive:sync:remove'](null, { id: 'x' })).code, 'invalid');
    await handlers['drive:sync:remove'](null, { id });
    await handlers['drive:sync:pause'](null, { id: null, paused: true });
    assert.equal((await handlers['drive:sync:pause'](null, { id, paused: 'ja' })).code, 'invalid');
    await handlers['drive:sync:settings'](null, { upKBs: 100, evil: true });
    assert.equal((await handlers['drive:sync:settings'](null, { upKBs: 'viel' })).code, 'invalid');
    await handlers['drive:sync:home'](null, { on: true });
    await handlers['drive:sync:run'](null, { id });
    await handlers['drive:sync:run'](null, {});
    assert.equal((await handlers['drive:sync:deletes'](null, { id, decision: 'all' })).code, 'invalid');
    await handlers['drive:sync:deletes'](null, { id, decision: 'restore' });
    await handlers['drive:sync:open'](null, { id });
    assert.deepEqual(calls, [
      ['add', { path: 'C:\\X', mode: 'sync', targetId: 10 }], ['remove', id], ['pause', null, true],
      ['settings', { upKBs: 100 }], ['home', true], ['run', id], ['runAll'], ['deletes', id, 'restore'], ['open', id],
    ]);
    syncFake.emit('change', { ok: true, state: 'idle' });
    assert.deepEqual(sent.at(-1), ['drive:sync', { ok: true, state: 'idle' }]);

    const invoked = [];
    const bridge = createBridgeApi({ invoke: (ch, a) => { invoked.push([ch, a]); return Promise.resolve(); }, on() {}, removeListener() {} }, { t: () => '', setLocale() {}, getLocale: () => 'de', onLocaleChange() {}, getSupportedLocales: () => [] });
    const sy = bridge.drive.sync;
    sy.status(); sy.pick(); sy.add({ path: 'C:\\X', mode: 'backup' }); sy.remove(id); sy.pause(null, true); sy.settings({ upKBs: 1 }); sy.home(false); sy.run(id); sy.deletes(id, 'apply'); sy.open(id);
    assert.deepEqual(invoked.map((x) => x[0]), ['drive:sync:status', 'drive:sync:pick', 'drive:sync:add', 'drive:sync:remove', 'drive:sync:pause', 'drive:sync:settings', 'drive:sync:home', 'drive:sync:run', 'drive:sync:deletes', 'drive:sync:open']);
    for (const ch of invoked.map((x) => x[0])) assert.ok(handlers[ch], ch);
    assert.equal(typeof sy.onChange, 'function');
  });
});
