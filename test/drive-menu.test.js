'use strict';

// Drive 1.11 in the Windows Pro app (core): the menu's folder tree (folders only, `hasDirs`, lazily per folder), vault
// folders only in the menu ("Tresore") — never in a folder listing, the search or the folder pickers (they list
// folders) —, a new vault always in the top folder of the area picked, the vault lock (Windows Hello before the keys
// are unwrapped; locking after a time without use, when the window is hidden, when Windows locks, by hand — keys wiped,
// names forgotten, decrypted copies removed), the cache on this PC, and "Ordner sichern" unchanged on a Drive with
// 'vaultsApart'. Against the fake Drive server (fixtures/drive-server.js) with and without 'vaultsApart'.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const drive = require('../src/utils/drive');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const DriveVaultLock = require('../src/services/drive-vault-lock');
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
    await new Promise((r) => setTimeout(r, 10));
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0xa5));
  return { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]), decrypt: (b) => x(Buffer.from(b).subarray(6)) };
}

/** Windows Hello (createConsentVerifier) stand-in: the next answers, every prompt listed. */
function fakeConsent() {
  const c = { avail: { available: true, reason: null }, answers: [], prompts: [] };
  c.available = async () => ({ ...c.avail });
  c.verify = async (message, { window = null } = {}) => {
    c.prompts.push({ message, window });
    if (!c.avail.available) return { status: c.avail.reason };
    return { status: c.answers.length ? c.answers.shift() : 'verified' };
  };
  return c;
}

const WINDOW = Buffer.from([0x42, 0x42, 0, 0, 0, 0, 0, 0]);

async function service(srv, { consent, powerMonitor = null, minuteMs = 60000, store = createMemoryStore() } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('dm-tmp-');
  const opened = [];
  const win = { isDestroyed: () => false, getNativeWindowHandle: () => WINDOW };
  const svc = new DriveService({
    apiClient, api, log, store, protect: fakeProtect(), deviceName: () => 'Desktop-PC', tempDir: () => tmp,
    timing: { progressMs: 0, minuteMs }, getMainWindow: () => win, getLang: () => 'de',
    shell: { openPath: async (p) => { opened.push({ path: p, content: fs.readFileSync(p) }); return ''; }, openExternal: async (u) => { opened.push({ url: u }); } },
    ...(consent !== undefined ? { consent } : {}), powerMonitor,
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { svc, api, tmp, opened, store };
}

async function setup(features, opts) {
  const srv = await driveServer({ features });
  cleanup.push(() => srv.close());
  return { srv, ...(await service(srv, opts)) };
}

const APART = ['devices', 'emptyFiles', 'vault', 'vaultsApart'];
const OLD = ['devices', 'emptyFiles', 'vault'];

// ── the tree ───────────────────────────────────────────────

describe('Drive 1.11: the menu\'s folder tree', () => {
  it("with 'vaultsApart': children?dirs=1, folders only with hasDirs, never a vault", async () => {
    const { srv, svc } = await setup(APART, { consent: null });
    srv.mutate.dir(10, 'Steuern');
    const vault = await svc.vaultLockSettings({ hello: false }).then(() => svc.vaultCreate(1, 'Geheim'));
    assert.equal(vault.ok, true);
    const t = await svc.tree(1);
    assert.deepEqual(t.items, [{ id: 10, name: 'Dokumente', hasDirs: true }]);
    assert.equal(t.more, false);
    const req = srv.state.requests.filter((r) => r.path.endsWith('/nodes/1/children')).pop();
    assert.equal(req.query.dirs, '1');
    const sub = await svc.tree(10);
    assert.deepEqual(sub.items.map((x) => [x.name, x.hasDirs]), [['Steuern', false]]);
  });

  it('an older Drive: the plain children, folders kept, vaults left out, hasDirs unknown; all pages', async () => {
    const { srv, svc } = await setup(OLD, { consent: null });
    await svc.vaultLockSettings({ hello: false });
    await svc.vaultCreate(1, 'Geheim');
    for (const n of ['A', 'B', 'C', 'D']) srv.mutate.dir(1, n);
    srv.pageMax = 2;
    const t = await svc.tree(1);
    assert.deepEqual(t.items.map((x) => x.name), ['A', 'B', 'C', 'D', 'Dokumente']);
    assert.ok(t.items.every((x) => x.hasDirs === null));
    assert.equal(srv.state.requests.some((r) => r.query.dirs), false, 'no dirs=1 to an older Drive');
  });

  it('IPC: drive:tree checks its id', async () => {
    const { svc } = await setup(APART, { consent: null });
    const h = {};
    registerDriveHandlers((ch, fn) => { h[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await h['drive:tree'](null, { id: 'x' })).code, 'invalid');
    assert.equal((await h['drive:tree'](null, { id: 1 })).items[0].name, 'Dokumente');
  });
});

// ── vaults only in the menu ────────────────────────────────

describe('Drive 1.11: vault folders only in the menu', () => {
  it('an older Drive: left out of every folder listing (total too) and the search; the vault itself lists its content', async () => {
    const { srv, svc } = await setup(OLD, { consent: null });
    await svc.vaultLockSettings({ hello: false });
    const made = await svc.vaultCreate(1, 'Geheim');
    // one an older app made inside a folder
    const old = await svc.vaultCreate(1, 'Alt');
    srv.state.nodes.get(old.node.id).parentId = 10;
    const root = await svc.folder(1);
    assert.deepEqual(root.items.map((n) => n.name), ['Dokumente', 'Foto.jpg', 'setup.exe']);
    assert.equal(root.total, 3);
    assert.deepEqual((await svc.folder(10)).items.map((n) => n.name), ['Brief.pdf']);
    const src = tmpDir('dm-src-');
    fs.writeFileSync(path.join(src, 'x.txt'), 'x');
    await svc.upload(made.node.id, [path.join(src, 'x.txt')]);
    await until(() => svc.transfers().some((t) => t.state === 'done'));
    assert.deepEqual((await svc.folder(made.node.id)).items.map((n) => n.name), ['x.txt']);
    // the search: an older plugin's answer with a vault's node is cleaned here
    const real = svc.api.search.bind(svc.api);
    svc.api.search = async (...a) => [...(await real(...a)), drive.normalizeNode({ id: made.node.id, areaId: 'mine:2', parentId: 1, name: 'f'.repeat(32), isDir: true, encrypted: true, vaultId: made.vault.id })];
    const found = await svc.search('Foto');
    assert.deepEqual(found.items.map((n) => n.name), ['Foto.jpg']);
    // the menu lists both
    assert.deepEqual((await svc.vaults()).vaults.map((v) => v.name).sort(), ['Alt', 'Geheim']);
  });

  it("with 'vaultsApart' the server leaves them out; a vault folder cannot be moved", async () => {
    const { srv, svc } = await setup(APART, { consent: null });
    await svc.vaultLockSettings({ hello: false });
    const made = await svc.vaultCreate(10, 'Geheim');
    assert.equal(srv.state.nodes.get(made.node.id).parentId, 1);
    assert.equal((await svc.folder(1)).items.some((n) => n.encrypted), false);
    await assert.rejects(svc.move(made.node.id, 10), (e) => e.status === 400);
  });

  it('a new vault always in the top folder of the area picked; read-only areas refused; IPC by area', async () => {
    const { srv, svc } = await setup(OLD, { consent: null });
    await svc.vaultLockSettings({ hello: false });
    const a = await svc.vaultCreate(10, 'Aus Unterordner');
    assert.equal(srv.state.nodes.get(a.node.id).parentId, 1, 'parentId names only the area');
    const fam = await svc.vaultCreate(null, 'Familie', { areaId: 'family:1' });
    assert.equal(srv.state.nodes.get(fam.node.id).parentId, 2);
    await assert.rejects(svc.vaultCreate(null, 'Kind', { areaId: 'child:7' }), (e) => e.code === 'forbidden');
    await assert.rejects(svc.vaultCreate(null, 'X', { areaId: 'team:9' }), (e) => e.code === 'not_found');
    const h = {};
    registerDriveHandlers((ch, fn) => { h[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await h['drive:vault:create'](null, { name: 'x' })).code, 'invalid');
    assert.equal((await h['drive:vault:create'](null, { areaId: '../x', name: 'x' })).code, 'invalid');
    const r = await h['drive:vault:create'](null, { areaId: 'mine:2', name: 'Per IPC' });
    assert.equal(r.ok, true);
    assert.equal(srv.state.nodes.get(r.node.id).parentId, 1);
  });
});

// ── the vault lock ─────────────────────────────────────────

describe('Drive 1.11: the vault lock (Windows Hello)', () => {
  it('locked until Windows Hello: no key unwrapped; unlock opens it; locking wipes keys, names and the decrypted copies', async () => {
    const consent = fakeConsent();
    const { svc, tmp, opened } = await setup(APART, { consent });
    const events = [];
    svc.on('vaultLock', (e) => events.push(e));
    // a vault made here holds its own key until the next lock
    const made = await svc.vaultCreate(null, 'Steuer', { areaId: 'mine:2' });
    const vid = made.vault.id;
    const src = tmpDir('dm-src-');
    fs.writeFileSync(path.join(src, 'Beleg.txt'), 'GEHEIM');
    await svc.upload(made.node.id, [path.join(src, 'Beleg.txt')]);
    await until(() => svc.transfers().some((t) => t.state === 'done'));
    const file = (await svc.folder(made.node.id)).items[0];
    assert.equal(file.name, 'Beleg.txt');

    svc.vaultLockNow();
    assert.equal(svc.vault.isOpen(vid), false);
    assert.deepEqual(events.pop(), { locked: true, reason: 'manual' });
    const st = await svc.vaultLockStatus();
    assert.equal(st.enforced, true);
    assert.equal(st.unlocked, false);
    assert.deepEqual(st.settings, { hello: true, autoLockMinutes: 3, lockOnLeave: true });
    // the menu: locked, no name; the folder: the card, opaque names; opening refused
    const vs = (await svc.vaults()).vaults;
    assert.deepEqual(vs.map((v) => [v.state, v.name]), [['locked', null]]);
    const f = await svc.folder(made.node.id);
    assert.equal(f.vault.state, 'locked');
    assert.equal(f.node.locked, true);
    assert.equal(f.items[0].locked, true);
    assert.equal(svc.vault.knownName(file.id), null, 'names forgotten');
    await assert.rejects(svc.open(file.id), (e) => e.code === 'vault_locked');
    assert.equal(consent.prompts.length, 0, 'never asked without the person');

    // Windows Hello (owned by the app window), then open
    const u = await svc.vaultUnlock(vid);
    assert.deepEqual(u, { ok: true, unlocked: true, state: 'open' });
    assert.equal(consent.prompts.length, 1);
    assert.equal(consent.prompts[0].message, 'GateControl Drive: Tresore entsperren');
    assert.ok(consent.prompts[0].window.equals(WINDOW));
    assert.deepEqual(events.pop(), { locked: false, reason: null });
    assert.equal((await svc.folder(made.node.id)).items[0].name, 'Beleg.txt');
    const o = await svc.open(file.id);
    assert.equal(opened.pop().content.toString(), 'GEHEIM');
    assert.ok(fs.existsSync(o.path));

    // a key captured before a lock never encrypts anything afterwards
    const cur = svc.vault.current(vid);
    svc.vaultLockNow();
    assert.throws(() => svc.vault.encryptName(vid, 'x', cur), (e) => e.code === 'vault_locked');
    assert.ok(cur.tk.every((b) => b === 0), 'the key bytes are wiped');
    await until(() => !fs.existsSync(o.path));
    assert.deepEqual(fs.readdirSync(path.join(tmp, 'vault')), []);
  });

  it('refused, not set up, policy: the reason, no keys; remote / no provider: unavailable', async () => {
    const consent = fakeConsent();
    const { svc } = await setup(APART, { consent });
    const made = await svc.vaultCreate(null, 'X', { areaId: 'mine:2' });
    svc.vaultLockNow();
    consent.answers.push('cancelled');
    await assert.rejects(svc.vaultUnlock(made.vault.id), (e) => e.code === 'hello_cancelled');
    consent.answers.push('retries_exhausted');
    await assert.rejects(svc.vaultUnlock(), (e) => e.code === 'hello_retries');
    consent.avail = { available: false, reason: 'not_set_up' };
    const before = consent.prompts.length;
    await assert.rejects(svc.vaultUnlock(), (e) => e.code === 'hello_not_set_up');
    assert.equal(consent.prompts.length, before, 'no dialog while Hello is not set up');
    assert.deepEqual((await svc.vaultLockStatus()).hello, { available: false, reason: 'not_set_up' });
    consent.avail = { available: false, reason: 'disabled_by_policy' };
    await assert.rejects(svc.vaultUnlock(), (e) => e.code === 'hello_policy');
    assert.equal(svc.vault.isOpen(made.vault.id), false);
    // null provider (Windows Hello not available in this build)
    const { svc: none } = await setup(APART, { consent: null });
    await assert.rejects(none.vaultUnlock(), (e) => e.code === 'hello_unavailable');
  });

  it('time without use (touch postpones, a vault transfer waits), the window hidden, Windows locked', async () => {
    const consent = fakeConsent();
    const pm = new EventEmitter();
    const { svc } = await setup(APART, { consent, powerMonitor: pm, minuteMs: 40 });
    await svc.vaultLockSettings({ autoLockMinutes: 1 });
    const reasons = [];
    svc.on('vaultLock', (e) => { if (e.locked) reasons.push(e.reason); });
    await svc.vaultUnlock();
    await sleep(25);
    svc.vaultTouch();
    await sleep(25);
    assert.equal(svc.vaultLock.isUnlocked(), true, 'touched in between');
    await until(() => !svc.vaultLock.isUnlocked(), 2000);
    assert.equal(reasons.pop(), 'timeout');
    // a vault transfer running: the lock waits for it
    await svc.vaultUnlock();
    svc._vaultActive = 1;
    await sleep(120);
    assert.equal(svc.vaultLock.isUnlocked(), true);
    svc._vaultActive = 0;
    await until(() => !svc.vaultLock.isUnlocked(), 2000);
    // minimized / into the tray
    await svc.vaultUnlock();
    svc.windowHidden();
    assert.equal(reasons.pop(), 'hidden');
    await svc.vaultLockSettings({ lockOnLeave: false, autoLockMinutes: 0 });
    await svc.vaultUnlock();
    svc.windowHidden();
    await sleep(60);
    assert.equal(svc.vaultLock.isUnlocked(), true, '"Beim Verlassen sperren" off, "Nie"');
    // Windows locks the session: always
    pm.emit('lock-screen');
    assert.equal(reasons.pop(), 'system');
    await svc.vaultUnlock();
    pm.emit('suspend');
    assert.equal(svc.vaultLock.isUnlocked(), false);
  });

  it('"Mit Windows Hello öffnen" off only after Windows Hello; then no prompt; on again locks', async () => {
    const consent = fakeConsent();
    const { svc, store } = await setup(APART, { consent });
    consent.answers.push('cancelled');
    await assert.rejects(svc.vaultLockSettings({ hello: false }), (e) => e.code === 'hello_cancelled');
    assert.equal((await svc.vaultLockStatus()).settings.hello, true);
    const r = await svc.vaultLockSettings({ hello: false });
    assert.equal(r.settings.hello, false);
    assert.match(consent.prompts.pop().message, /ohne Windows Hello/);
    assert.deepEqual(store.get(DriveVaultLock.STORE_KEY), { hello: false, autoLockMinutes: 3, lockOnLeave: true });
    const n = consent.prompts.length;
    await svc.vaultUnlock();
    assert.equal(consent.prompts.length, n, 'no dialog with the switch off');
    await svc.vaultLockSettings({ hello: true });
    assert.equal(svc.vaultLock.isUnlocked(), false);
    // invalid values
    await assert.rejects(svc.vaultLockSettings({ autoLockMinutes: 7 }), (e) => e.code === 'invalid');
    const h = {};
    registerDriveHandlers((ch, fn) => { h[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    assert.equal((await h['drive:vault:lock-settings'](null, { autoLockMinutes: 2 })).code, 'invalid');
    assert.equal((await h['drive:vault:lock-settings'](null, {})).code, 'invalid');
    assert.equal((await h['drive:vault:unlock'](null, { vaultId: '../x' })).code, 'invalid');
    assert.equal((await h['drive:vault:lock-settings'](null, { autoLockMinutes: 15 })).settings.autoLockMinutes, 15);
    assert.equal((await h['drive:vault:lock'](null)).unlocked, false);
    assert.equal((await h['drive:vault:touch'](null)).ok, true);
    assert.equal((await h['drive:hello-settings'](null)).ok, true);
  });

  it('a vault made here keeps its key only until the time without use runs out (no Hello needed for that)', async () => {
    const consent = fakeConsent();
    const { svc } = await setup(APART, { consent, minuteMs: 30 });
    await svc.vaultLockSettings({ autoLockMinutes: 1 });
    const made = await svc.vaultCreate(null, 'Neu', { areaId: 'mine:2' });
    assert.equal(svc.vault.isOpen(made.vault.id), true);
    assert.equal(svc.vaultLock.isUnlocked(), false, 'making a vault unlocks no other vault');
    await until(() => !svc.vault.isOpen(made.vault.id), 2000);
    assert.equal(consent.prompts.length, 0);
    // the window hidden wipes such keys, too
    const again = await svc.vaultRecover(made.vault.id, made.recoveryKey);
    assert.equal(again.state, 'open');
    svc.windowHidden();
    assert.equal(svc.vault.isOpen(made.vault.id), false);
  });

  it('without a consent option (an app that does not wire it): nothing enforced, as before', async () => {
    const { svc } = await setup(APART, {});
    const st = await svc.vaultLockStatus();
    assert.equal(st.enforced, false);
    assert.equal(st.unlocked, true);
    const made = await svc.vaultCreate(null, 'Alt', { areaId: 'mine:2' });
    svc.vaultLockNow();
    assert.equal((await svc.vaults()).vaults[0].name, 'Alt', 'opened again quietly');
    assert.equal(made.ok, true);
  });
});

// ── the cache ──────────────────────────────────────────────

describe('Drive 1.11: the cache on this PC', () => {
  it('size of the opened files and previews; clearing leaves running uploads alone', async () => {
    const { svc, tmp } = await setup(APART, { consent: null });
    await svc.open(12);
    await svc.preview('photoMedia000001');
    fs.mkdirSync(path.join(tmp, 'vault-up'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'vault-up', 'u1.enc'), 'cipher');
    const info = await svc.cacheInfo();
    assert.ok(info.bytes >= 14, JSON.stringify(info));
    assert.equal(info.files, 1);
    assert.equal(info.previews, 1);
    const r = await svc.clearCache();
    assert.equal(r.ok, true);
    assert.equal(r.removed, 1);
    assert.deepEqual(fs.readdirSync(tmp), ['vault-up']);
    assert.deepEqual(await svc.cacheInfo(), { ok: true, bytes: 0, files: 0, previews: 0 });
  });
});

// ── "Ordner sichern" on a Drive with 'vaultsApart' ─────────

describe("Drive 1.11: 'Ordner sichern' unchanged", () => {
  it('a synced folder with a vault in it: the vault never comes down, nothing goes into it, plain children (no dirs=1)', async () => {
    const { srv, svc, api } = await setup(APART, { consent: null });
    await svc.vaultLockSettings({ hello: false });
    const made = await svc.vaultCreate(null, 'Geheim', { areaId: 'mine:2' });
    const src = tmpDir('dm-src-');
    fs.writeFileSync(path.join(src, 'v.txt'), 'v');
    await svc.upload(made.node.id, [path.join(src, 'v.txt')]);
    await until(() => svc.transfers().some((t) => t.state === 'done'));
    const sync = new DriveSync({
      drive: svc, api, store: createMemoryStore(), dir: tmpDir('dm-state-'), log, hostname: () => 'Desktop-PC', getDeviceKey: () => 'ab12cd34',
      trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); }, timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 }, readPdfText: async () => null,
    });
    sync.start();
    cleanup.push(async () => { sync.stop(); await sync.idle(); });
    const pc = tmpDir('dm-pc-');
    fs.writeFileSync(path.join(pc, 'neu.txt'), 'vom PC');
    const f = await sync.addFolder({ path: pc, mode: 'sync', targetId: 1 });
    sync.sync(f.folder.id, { full: true });
    await sync.idle();
    assert.deepEqual(fs.readdirSync(pc).sort(), ['Dokumente', 'Foto.jpg', 'neu.txt', 'setup.exe']);
    assert.ok(fs.existsSync(path.join(pc, 'Dokumente', 'Brief.pdf')));
    const up = [...srv.state.nodes.values()].find((n) => n.name === 'neu.txt');
    assert.equal(up.parentId, 1);
    assert.ok([...srv.state.nodes.values()].filter((n) => n.parentId === made.node.id).every((n) => n.encrypted));
    assert.equal(srv.state.requests.some((r) => r.query.dirs), false, 'the sync reads the plain children');
    // again: still nothing of the vault, no errors
    sync.sync(f.folder.id, { full: true });
    await sync.idle();
    const st = sync.status().folders.find((x) => x.id === f.folder.id);
    assert.equal(st.error || null, null);
  });
});
