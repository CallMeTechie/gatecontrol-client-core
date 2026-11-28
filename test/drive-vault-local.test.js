'use strict';

// Drive 1.32 'vaultLocal' („Tresor: Nur auf diesem Gerät“) on Windows — only shown here: a vault folder whose content
// lies only on one device of the person is a placeholder. The field `local` read (nodes, children, changes; also
// without the feature), the change op `local` kept, writes into a placeholder refused with 409 local_only /
// local_moving and the device's name (the IPC passes it on), "Platzhalter entfernen" with this PC's vault device and no
// proof, "Ordner sichern" leaves placeholders out. Against the fake Drive server (test/fixtures/drive-server.js).

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
const S = require('../src/utils/drive-sync');
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

function tmpDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanup.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0xa5));
  return { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]), decrypt: (b) => x(Buffer.from(b).subarray(6)) };
}

const LOCAL = {
  nodeId: 41, vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', deviceId: 'PixelDevice00000000000A', deviceName: 'Pixel 8', platform: 'android',
  deviceState: 'approved', state: 'local', since: '2026-11-27T10:00:00.000Z', mine: true, undo: false, purgeAt: null,
};

describe('utils/drive: the field local (Drive 1.32)', () => {
  it('normalizeLocal: the placeholder read, anything else null', () => {
    const l = drive.normalizeLocal(LOCAL);
    assert.equal(l.state, 'local');
    assert.equal(l.deviceName, 'Pixel 8');
    assert.equal(l.platform, 'android');
    assert.equal(l.since, Date.parse(LOCAL.since));
    assert.equal(l.mine, true);
    assert.equal(l.undo, false);
    assert.equal(l.thisDevice, false);
    assert.equal(drive.normalizeLocal({ ...LOCAL, state: 'gone' }), null);
    assert.equal(drive.normalizeLocal(null), null);
    assert.equal(drive.normalizeLocal({ ...LOCAL, deviceName: null, platform: 'Win dows!' }).platform, null);
    assert.equal(drive.normalizeLocal({ ...LOCAL, deviceName: 'Pixel\n8' }).deviceName, 'Pixel 8');
    assert.equal(drive.normalizeLocal({ ...LOCAL, undo: undefined }).undo, null);
  });

  it('on vault folders only; a node without it as before', () => {
    const base = { id: 41, areaId: 'mine:2', parentId: 40, name: 'f'.repeat(32), isDir: true, encrypted: true, vaultId: LOCAL.vaultId, nameCipher: 'AAAA', keyVersion: 1 };
    assert.equal(drive.normalizeNode({ ...base, local: LOCAL }).local.deviceName, 'Pixel 8');
    assert.equal('local' in drive.normalizeNode(base), false);
    assert.equal('local' in drive.normalizeNode({ ...base, encrypted: false, local: LOCAL }), false);
    assert.equal('local' in drive.normalizeNode({ ...base, isDir: false, local: LOCAL }), false);
  });

  it('the change op local is kept; the children of a placeholder carry local at the top', () => {
    assert.ok(drive.CHANGE_OPS.includes('local'));
    const c = drive.normalizeChanges({ changes: [{ seq: 12, op: 'local', areaId: 'mine:2', nodeId: 41, node: { id: 41, areaId: 'mine:2', parentId: 40, name: 'x'.repeat(32), isDir: true, encrypted: true, local: LOCAL } }] });
    assert.equal(c.changes.length, 1);
    assert.equal(c.changes[0].op, 'local');
    assert.equal(c.changes[0].node.local.state, 'local');
    const head = { node: { id: 41, areaId: 'mine:2', parentId: 40, name: 'x'.repeat(32), isDir: true, encrypted: true, crumbs: [{ id: 1, name: '' }] } };
    const f = drive.normalizeFolder(head, { items: [], total: 0, local: LOCAL });
    assert.equal(f.node.local.deviceName, 'Pixel 8');
    assert.deepEqual(f.items, []);
    assert.equal(drive.normalizeFolder(head, { items: [] }).node.local, undefined);
  });
});

async function setup({ features = ['devices', 'vault', 'vaultsApart', 'bulk', 'offline'] } = {}) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('dvl-tmp-');
  const svc = new DriveService({
    apiClient, api, log, store: createMemoryStore(), protect: fakeProtect(), deviceName: () => 'Desktop-PC', tempDir: () => tmp, timing: { progressMs: 0 },
    shell: { openPath: async () => '', openExternal: async () => {} },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const made = await svc.vaultCreate(1, 'Privat');
  assert.equal(made.ok, true);
  const sub = await svc.mkdir(made.node.id, 'Steuer 2025');
  assert.equal(sub.ok, true);
  return { srv, svc, api, vault: made.vault, vaultNode: made.node, sub: sub.node };
}

describe('DriveService: placeholders of a vault (Drive 1.32)', () => {
  it('listed with local and the decrypted name; the placeholder itself is empty with local', async () => {
    const { srv, svc, vaultNode, sub } = await setup();
    srv.setLocal(sub.id, { deviceName: 'Pixel 8' });
    const f = await svc.folder(vaultNode.id);
    const row = f.items.find((n) => n.id === sub.id);
    assert.equal(row.name, 'Steuer 2025');
    assert.equal(row.local.state, 'local');
    assert.equal(row.local.deviceName, 'Pixel 8');
    assert.equal(row.local.platform, 'android');
    const inside = await svc.folder(sub.id);
    assert.deepEqual(inside.items, []);
    assert.equal(inside.node.local.deviceName, 'Pixel 8');
    // the change log names it with the op local
    const ch = await svc.api.changes(0);
    assert.ok(ch.changes.some((c) => c.op === 'local' && c.nodeId === sub.id && c.node.local.state === 'local'));
    // without a placeholder (an older plugin): no local at all
    srv.clearLocal(sub.id);
    const again = await svc.folder(vaultNode.id);
    assert.equal('local' in again.items.find((n) => n.id === sub.id), false);
  });

  it('uploads, new folders, moves and copies into a placeholder are refused with the device', async () => {
    const { srv, svc, vaultNode, sub } = await setup();
    const other = await svc.mkdir(vaultNode.id, 'Andere');
    srv.setLocal(sub.id, { deviceName: 'Pixel 8' });
    const src = tmpDir('dvl-src-');
    fs.writeFileSync(path.join(src, 'a.txt'), 'a');
    await assert.rejects(svc.upload(sub.id, [path.join(src, 'a.txt')]), (e) => e.code === 'local_only' && e.status === 409 && e.body.deviceName === 'Pixel 8');
    assert.equal(fs.existsSync(path.join(src, 'a.txt')), true, 'the original stays');
    await assert.rejects(svc.mkdir(sub.id, 'Neu'), (e) => e.code === 'local_only' && /Pixel 8/.test(e.message));
    await assert.rejects(svc.opsStart({ op: 'move', ids: [other.node.id], target: sub.id }), (e) => e.code === 'local_only');
    // moving to the device: local_moving
    srv.setLocal(sub.id, { deviceName: 'Pixel 8', state: 'moving' });
    await assert.rejects(svc.upload(sub.id, [path.join(src, 'a.txt')]), (e) => e.code === 'local_moving');
    // the IPC passes the device on
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    srv.setLocal(sub.id, { deviceName: 'Pixel 8' });
    const r = await handlers['drive:upload'](null, { parentId: sub.id, paths: [path.join(src, 'a.txt')] });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'local_only');
    assert.equal(r.deviceName, 'Pixel 8');
    const m = await handlers['drive:mkdir'](null, { parentId: sub.id, name: 'Neu' });
    assert.equal(m.code, 'local_only');
    assert.equal(m.deviceName, 'Pixel 8');
    assert.match(m.error, /Pixel 8/);
  });

  it('a check of a job: a placeholder is never put into the trash; a move into it is refused', async () => {
    const { srv, svc, vaultNode, sub } = await setup();
    const other = await svc.mkdir(vaultNode.id, 'Andere');
    srv.setLocal(sub.id);
    const c = await svc.opsCheck({ op: 'trash', ids: [sub.id, other.node.id] });
    assert.deepEqual(c.blocked.map((b) => [b.id, b.reason]), [[sub.id, 'local_only']]);
    await assert.rejects(svc.opsCheck({ op: 'move', ids: [other.node.id], target: sub.id }), (e) => e.code === 'local_only' && e.body.deviceName === 'Pixel 8');
  });

  it('"Platzhalter entfernen": this PC\'s vault device, no proof; 409 purge_pending; IPC checks its arguments', async () => {
    const { srv, svc, vault, vaultNode, sub } = await setup();
    srv.setLocal(sub.id, { undo: false });
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await handlers['drive:vault:local:forget'](null, { vaultId: vault.id, nodeId: 'x' })).code, 'invalid');
    assert.equal((await handlers['drive:vault:local:forget'](null, { vaultId: '../x', nodeId: sub.id })).code, 'invalid');
    srv.localPurgePending = true;
    const early = await handlers['drive:vault:local:forget'](null, { vaultId: vault.id, nodeId: sub.id });
    assert.equal(early.ok, false);
    assert.equal(early.reason, 'purge_pending');
    assert.ok(Number.isFinite(Date.parse(early.purgeAt)));
    srv.localPurgePending = false;
    const r = await handlers['drive:vault:local:forget'](null, { vaultId: vault.id, nodeId: sub.id });
    assert.equal(r.ok, true);
    assert.equal(r.forgotten, true);
    const dev = await svc.vault.device({ create: false });
    assert.deepEqual(srv.state.localForgets, [{ nodeId: sub.id, deviceId: dev.id, proof: null }]);
    const f = await svc.folder(vaultNode.id);
    assert.equal(f.items.some((n) => n.id === sub.id), false, 'the placeholder is in the trash');
  });
});

describe('DriveSync: placeholders are never part of the tree', () => {
  it('a change with op local (a vault folder) does not reach the tree', () => {
    const tree = { 7: { id: 7 } };
    const n = drive.normalizeNode({ id: 41, areaId: 'mine:2', parentId: 7, name: 'f'.repeat(32), isDir: true, encrypted: true, local: LOCAL });
    const r = S.applyChanges(tree, 7, [{ seq: 1, op: 'local', nodeId: 41, node: n }]);
    assert.equal(r.touched, false);
    assert.equal(tree[41], undefined);
  });
});
