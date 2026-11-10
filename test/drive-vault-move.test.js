'use strict';

// "In Tresor verschieben" (Drive 1.9 vault folders): a file put into a vault from this PC is moved — its original is
// deleted for good once the vault's commit answer is the very ciphertext sent (size and SHA-256), never after a failed,
// skipped or partial upload; kept and reported when it is locked / read-only, changed while it went up, or the answer
// differs; a dropped folder loses only the folders that are empty afterwards, and nothing outside it (links,
// junctions). The helpers of services/drive-vault-move.js on their own, then DriveService against the fake Drive.

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
const VM = require('../src/services/drive-vault-move');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers, DRIVE_EVENTS } = require('../src/ipc/drive-handlers');
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

/** A vault "Tresor" on the fake Drive, this PC holding its key; `moves`: the 'vaultMove' events. */
async function vaultSetup() {
  const srv = await driveServer({ features: ['devices', 'emptyFiles', 'links', 'vault'] });
  cleanup.push(() => srv.close());
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const svc = new DriveService({
    apiClient, api, log, store: createMemoryStore(), protect: fakeProtect(), deviceName: () => 'Desktop-PC', tempDir: () => tmpDir('dvm-tmp-'), timing: { progressMs: 0 },
    shell: { openPath: async () => '', openExternal: async () => {} },
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  const made = await svc.vaultCreate(1, 'Tresor');
  const moves = [];
  svc.on('vaultMove', (m) => moves.push(m));
  const moved = (q) => until(() => moves.find((m) => m.id === q.move));
  const row = (id) => svc.transfers().find((t) => t.id === id);
  const names = async (id) => (await svc.folder(id)).items.map((n) => n.name).sort();
  return { srv, svc, api, vaultId: made.node.id, moves, moved, row, names };
}

const write = (p, text) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); return p; };

// ── the helpers ────────────────────────────────────────────

describe('drive-vault-move: the helpers', () => {
  it('verified: the size, and the SHA-256 when the server gives one', () => {
    const sent = { cipherSize: 60, sha256: 'ab'.repeat(32) };
    assert.equal(VM.verified({ isDir: false, size: 60, sha256: 'AB'.repeat(32) }, sent), true);
    assert.equal(VM.verified({ isDir: false, size: 60, sha256: null }, sent), true, 'no SHA-256 in the answer: the size');
    assert.equal(VM.verified({ isDir: false, size: 61, sha256: null }, sent), false);
    assert.equal(VM.verified({ isDir: false, size: 60, sha256: 'cd'.repeat(32) }, sent), false);
    assert.equal(VM.verified({ isDir: false, size: 0, sha256: null }, { cipherSize: 0 }), false);
    assert.equal(VM.verified({ isDir: true, size: 60 }, sent), false);
    assert.equal(VM.verified(null, sent), false);
    assert.equal(VM.verified({ isDir: false, size: 60 }, null), false);
  });

  it('inside / keep: the folder and every one above it, up to the root, nothing outside', () => {
    const root = path.resolve(os.tmpdir(), 'r');
    assert.equal(VM.inside(root, root), true);
    assert.equal(VM.inside(root, path.join(root, 'a', 'b')), true);
    assert.equal(VM.inside(root, path.join(root, '..dots')), true);
    assert.equal(VM.inside(root, path.join(root, '..', 'x')), false);
    assert.equal(VM.inside(root, path.resolve(os.tmpdir(), 'rr')), false);
    const tree = VM.newTree(root, root);
    VM.keep(tree, path.join(root, 'a', 'b'));
    VM.keep(tree, path.resolve(os.tmpdir(), 'elsewhere'));
    assert.deepEqual([...tree.keep].sort(), [root, path.join(root, 'a'), path.join(root, 'a', 'b')].sort());
  });

  it('encryptFile: the SHA-256 of the ciphertext written and the mtime read', async () => {
    const dir = tmpDir('dvm-enc-');
    const src = write(path.join(dir, 'p'), crypto.randomBytes(3000));
    const r = await V.encryptFile(V.newVaultKey(), V.newVaultId(), 1, src, path.join(dir, 'c'), { chunkSize: 1024, sha256: true });
    assert.equal(r.sha256, crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, 'c'))).digest('hex'));
    assert.equal(r.mtimeMs, fs.statSync(src).mtimeMs);
    assert.equal(r.size, 3000);
    const plain = await V.encryptFile(V.newVaultKey(), V.newVaultId(), 1, src, path.join(dir, 'd'));
    assert.equal(plain.sha256, null);
  });

  it('removeOriginal: deleted; changed (size, mtime, a link) kept; locked kept; gone counts as deleted', async () => {
    const dir = tmpDir('dvm-rm-');
    const read = (p) => { const st = fs.statSync(p); return { size: st.size, mtimeMs: st.mtimeMs }; };
    const a = write(path.join(dir, 'a.txt'), 'a');
    assert.deepEqual(await VM.removeOriginal(a, read(a)), { original: 'deleted' });
    assert.equal(fs.existsSync(a), false);
    const b = write(path.join(dir, 'b.txt'), 'b');
    const rb = read(b);
    fs.appendFileSync(b, 'more');
    assert.deepEqual(await VM.removeOriginal(b, rb), { original: 'kept', reason: 'changed' });
    const c = write(path.join(dir, 'c.txt'), 'c');
    const rc = read(c);
    fs.utimesSync(c, new Date(), new Date(Date.now() + 5000));
    assert.deepEqual(await VM.removeOriginal(c, rc), { original: 'kept', reason: 'changed' });
    for (const code of ['EBUSY', 'EPERM', 'EACCES']) {
      const d = write(path.join(dir, `d-${code}.txt`), 'd');
      const fsp = { ...fs.promises, lstat: fs.promises.lstat, unlink: async () => { throw Object.assign(new Error(code), { code }); } };
      assert.deepEqual(await VM.removeOriginal(d, read(d), { fsp }), { original: 'kept', reason: 'locked' }, code);
      assert.equal(fs.existsSync(d), true);
    }
    // read-only: kept (on Windows unlink would clear the attribute and delete it)
    const ro = write(path.join(dir, 'schreibgeschuetzt.txt'), 'ro');
    fs.chmodSync(ro, 0o444);
    cleanup.push(() => { try { fs.chmodSync(ro, 0o644); } catch { /* gone */ } });
    assert.deepEqual(await VM.removeOriginal(ro, read(ro)), { original: 'kept', reason: 'locked' });
    assert.equal(fs.existsSync(ro), true);
    assert.deepEqual(await VM.removeOriginal(path.join(dir, 'gone.txt'), { size: 1, mtimeMs: 1 }), { original: 'deleted' });
    assert.deepEqual(await VM.removeOriginal('relative.txt', { size: 1, mtimeMs: 1 }), { original: 'kept', reason: 'error' });
    // a file of a dropped folder: never outside it
    const root = path.join(dir, 'root');
    const e = write(path.join(dir, 'outside.txt'), 'e');
    assert.deepEqual(await VM.removeOriginal(e, read(e), { tree: VM.newTree(root, root) }), { original: 'kept', reason: 'changed' });
    assert.equal(fs.existsSync(e), true);
  });
});

// ── DriveService ───────────────────────────────────────────

describe('DriveService: "In Tresor verschieben"', () => {
  it('a verified upload deletes the original for good; the event and the rows say so', async () => {
    const { svc, vaultId, moved, row, names } = await vaultSetup();
    const src = tmpDir('dvm-src-');
    const a = write(path.join(src, 'Steuer.pdf'), '%PDF-1.4 Steuer');
    const b = write(path.join(src, 'Lohn.txt'), 'Lohn 2025');
    const q = await svc.upload(vaultId, [a, b]);
    assert.equal(q.queued.length, 2);
    const m = await moved(q);
    assert.deepEqual({ moved: m.moved, deleted: m.deleted, kept: m.kept, notMoved: m.notMoved, keptFiles: m.keptFiles, folderId: m.folderId },
      { moved: 2, deleted: 2, kept: 0, notMoved: 0, keptFiles: [], folderId: vaultId });
    assert.equal(fs.existsSync(a), false);
    assert.equal(fs.existsSync(b), false);
    assert.deepEqual(q.queued.map((id) => [row(id).state, row(id).move, row(id).original]), [['done', true, 'deleted'], ['done', true, 'deleted']]);
    assert.deepEqual(await names(vaultId), ['Lohn.txt', 'Steuer.pdf']);
    // nothing in the recycle bin: there is none here, the file is simply gone (fs.unlink)
    assert.deepEqual(fs.readdirSync(src), []);
  });

  it('outside a vault an upload stays a copy', async () => {
    const { svc } = await vaultSetup();
    const src = tmpDir('dvm-plain-');
    const a = write(path.join(src, 'Foto-Liste.txt'), 'bleibt');
    const q = await svc.upload(1, [a]);
    assert.equal(q.move, null);
    await until(() => svc.transfers().some((t) => t.id === q.queued[0] && t.state === 'done'));
    assert.equal(fs.existsSync(a), true);
    assert.equal(svc.transfers().find((t) => t.id === q.queued[0]).original, undefined);
  });

  it('a failed upload keeps the original; in a batch only the ones that went up go', async () => {
    const { svc, api, vaultId, moved, row } = await vaultSetup();
    const src = tmpDir('dvm-fail-');
    const files = ['1.txt', '2.txt', '3.txt'].map((n) => write(path.join(src, n), `Inhalt ${n}`));
    const commit = api.commit.bind(api);
    let n = 0;
    api.commit = async (...args) => {
      if (++n === 2) throw Object.assign(new Error('the server went away'), { code: 'network' });
      return commit(...args);
    };
    const q = await svc.upload(vaultId, files);
    const m = await moved(q);
    assert.equal(m.moved, 2);
    assert.equal(m.deleted, 2);
    assert.equal(m.notMoved, 1);
    assert.deepEqual(files.map((f) => fs.existsSync(f)), [false, true, false]);
    assert.equal(row(q.queued[1]).state, 'failed');
    assert.equal(row(q.queued[1]).original, undefined);
    // the media upload failing: the same
    api.commit = commit;
    const upload = api.upload.bind(api);
    api.upload = async () => { throw Object.assign(new Error('cut'), { code: 'network' }); };
    const q2 = await svc.upload(vaultId, [files[1]]);
    const m2 = await moved(q2);
    assert.deepEqual([m2.moved, m2.notMoved], [0, 1]);
    assert.equal(fs.existsSync(files[1]), true);
    api.upload = upload;
  });

  it('skipped at a taken name ("Überspringen") keeps the original; "Beide behalten" moves it', async () => {
    const { svc, vaultId, moved } = await vaultSetup();
    const src = tmpDir('dvm-skip-');
    await svc.upload(vaultId, [write(path.join(src, 'Vertrag.txt'), 'v1')]).then(moved);
    const again = write(path.join(src, 'Vertrag.txt'), 'v2');
    const q = await svc.upload(vaultId, [again]);
    await until(() => svc.transfers().some((t) => t.id === q.queued[0] && t.state === 'conflict'));
    svc.resolve(q.queued[0], null);
    const m = await moved(q);
    assert.deepEqual([m.moved, m.notMoved], [0, 1]);
    assert.equal(fs.readFileSync(again, 'utf8'), 'v2');
    const q2 = await svc.upload(vaultId, [again]);
    await until(() => svc.transfers().some((t) => t.id === q2.queued[0] && t.state === 'conflict'));
    svc.resolve(q2.queued[0], 'rename');
    assert.equal((await moved(q2)).deleted, 1);
    assert.equal(fs.existsSync(again), false);
  });

  it('a locked (open) or read-only original stays and is reported', async () => {
    const { svc, vaultId, moved, row } = await vaultSetup();
    const src = tmpDir('dvm-lock-');
    const locked = write(path.join(src, 'offen.docx'), 'in Word geöffnet');
    const free = write(path.join(src, 'frei.txt'), 'frei');
    const ro = write(path.join(src, 'schreibgeschuetzt.pdf'), 'nur lesen');
    fs.chmodSync(ro, 0o444);
    cleanup.push(() => { try { fs.chmodSync(ro, 0o644); } catch { /* gone */ } });
    const unlink = fs.promises.unlink;
    fs.promises.unlink = async (p) => {
      if (p === locked) throw Object.assign(new Error('resource busy or locked'), { code: 'EBUSY' });
      return unlink(p);
    };
    cleanup.push(() => { fs.promises.unlink = unlink; });
    const q = await svc.upload(vaultId, [locked, free, ro]);
    const m = await moved(q);
    assert.deepEqual([m.moved, m.deleted, m.kept], [3, 1, 2]);
    assert.deepEqual(m.keptFiles, [{ id: q.queued[0], name: 'offen.docx', reason: 'locked' }, { id: q.queued[2], name: 'schreibgeschuetzt.pdf', reason: 'locked' }]);
    assert.equal(fs.existsSync(locked), true);
    assert.equal(fs.existsSync(ro), true);
    assert.equal(fs.existsSync(free), false);
    assert.deepEqual([row(q.queued[0]).state, row(q.queued[0]).original, row(q.queued[0]).originalReason], ['done', 'kept', 'locked']);
  });

  it('a file changed while it went up stays; so does one whose answer differs from the ciphertext sent', async () => {
    const { svc, api, vaultId, moved, row } = await vaultSetup();
    const src = tmpDir('dvm-chg-');
    const edited = write(path.join(src, 'Liste.txt'), 'Zeile 1');
    const upload = api.upload.bind(api);
    api.upload = async (...args) => {
      const r = await upload(...args);
      fs.appendFileSync(edited, '\nZeile 2');   // saved again in the editor meanwhile
      return r;
    };
    const q = await svc.upload(vaultId, [edited]);
    const m = await moved(q);
    assert.deepEqual(m.keptFiles.map((f) => f.reason), ['changed']);
    assert.equal(fs.readFileSync(edited, 'utf8'), 'Zeile 1\nZeile 2');
    api.upload = upload;
    // only the mtime touched (same size): kept as well
    const touched = write(path.join(src, 'Notiz.txt'), 'gleich lang');
    api.upload = async (...args) => {
      const r = await upload(...args);
      fs.utimesSync(touched, new Date(), new Date(Date.now() + 60000));
      return r;
    };
    const qt = await svc.upload(vaultId, [touched]);
    assert.deepEqual((await moved(qt)).keptFiles.map((f) => f.reason), ['changed']);
    assert.equal(fs.existsSync(touched), true);
    api.upload = upload;
    // the vault's answer is not the ciphertext sent (another SHA-256, another size)
    const commit = api.commit.bind(api);
    for (const patch of [{ sha256: 'ee'.repeat(32) }, { size: 1 }]) {
      api.commit = async (...args) => { const r = await commit(...args); return { ...r, node: { ...r.node, ...patch } }; };
      const f = write(path.join(src, `Beleg-${Object.keys(patch)[0]}.txt`), 'Beleg');
      const qv = await svc.upload(vaultId, [f]);
      const mv = await moved(qv);
      assert.deepEqual(mv.keptFiles.map((x) => x.reason), ['verify'], JSON.stringify(patch));
      assert.equal(row(qv.queued[0]).originalReason, 'verify');
      assert.equal(fs.existsSync(f), true);
    }
    api.commit = commit;
  });

  it('a whole folder: its files deleted, its emptied folders removed bottom-up; what stays keeps its folders', async () => {
    const { svc, vaultId, moved, names } = await vaultSetup();
    const src = tmpDir('dvm-dir-');
    // all of it goes
    const all = path.join(src, 'Belege');
    write(path.join(all, 'a.txt'), 'a');
    write(path.join(all, '2024', 'b.txt'), 'b');
    write(path.join(all, '2024', 'Q1', 'c.txt'), 'c');
    fs.mkdirSync(path.join(all, 'leer'));
    const q = await svc.upload(vaultId, [all]);
    const m = await moved(q);
    assert.deepEqual([m.moved, m.deleted, m.kept, m.notMoved], [3, 3, 0, 0]);
    assert.deepEqual(m.folders, { removed: 4, kept: 0 });
    assert.equal(fs.existsSync(all), false, 'the folder itself is gone');
    assert.ok((await names(vaultId)).includes('Belege'));

    // some of it stays: a temporary file, a link, a locked file, a file left out (node_modules)
    const part = path.join(src, 'Projekt');
    write(path.join(part, 'fertig', 'x.txt'), 'x');
    write(path.join(part, 'offen', 'y.txt'), 'y');
    write(path.join(part, 'offen', 'z.txt'), 'z');
    write(path.join(part, 'temp', '~$Brief.docx'), 'lock');
    write(path.join(part, 'node_modules', 'pkg', 'i.js'), 'i');
    const outside = write(path.join(src, 'draussen', 'geheim.txt'), 'nicht anfassen');
    fs.symlinkSync(path.dirname(outside), path.join(part, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
    const lockedFile = path.join(part, 'offen', 'y.txt');
    const unlink = fs.promises.unlink;
    fs.promises.unlink = async (p) => {
      if (p === lockedFile) throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
      return unlink(p);
    };
    cleanup.push(() => { fs.promises.unlink = unlink; });
    const q2 = await svc.upload(vaultId, [part]);
    const m2 = await moved(q2);
    assert.deepEqual([m2.moved, m2.deleted, m2.kept], [3, 2, 1]);
    assert.deepEqual(m2.keptFiles.map((f) => [f.name, f.reason]), [['y.txt', 'locked']]);
    assert.equal(fs.existsSync(path.join(part, 'fertig')), false, 'a folder all of whose files went: removed');
    assert.deepEqual(fs.readdirSync(path.join(part, 'offen')), ['y.txt']);
    assert.equal(fs.existsSync(path.join(part, 'temp', '~$Brief.docx')), true);
    assert.equal(fs.existsSync(path.join(part, 'node_modules', 'pkg', 'i.js')), true);
    assert.equal(fs.lstatSync(path.join(part, 'link')).isSymbolicLink(), true);
    assert.equal(fs.readFileSync(outside, 'utf8'), 'nicht anfassen', 'nothing behind a link is touched');
    assert.deepEqual(fs.readdirSync(part).sort(), ['link', 'node_modules', 'offen', 'temp']);
    assert.equal(m2.folders.removed, 1);
  });

  it('a folder on the way that became a link out of the folder picked: its file stays (and the one outside too)', async () => {
    const { svc, api, vaultId, moved } = await vaultSetup();
    const src = tmpDir('dvm-junction-');
    const top = path.join(src, 'Ordner');
    const inner = write(path.join(top, 'Unter', 'datei.txt'), 'innen');
    const T = 1700000000;   // whole seconds: the same mtime on both files, to the nanosecond
    fs.utimesSync(inner, T, T);
    const elsewhere = path.join(src, 'anderswo');
    const upload = api.upload.bind(api);
    let swapped = false;
    api.upload = async (...args) => {
      const r = await upload(...args);
      if (!swapped) {
        swapped = true;
        // the folder "Unter" is replaced by a link to another folder holding a file of the same name, size and mtime
        fs.renameSync(path.join(top, 'Unter'), path.join(src, 'Unter-alt'));
        write(path.join(elsewhere, 'datei.txt'), 'innen');
        fs.utimesSync(path.join(elsewhere, 'datei.txt'), T, T);
        assert.equal(fs.statSync(path.join(elsewhere, 'datei.txt')).mtimeMs, fs.statSync(path.join(src, 'Unter-alt', 'datei.txt')).mtimeMs);
        fs.symlinkSync(elsewhere, path.join(top, 'Unter'), process.platform === 'win32' ? 'junction' : 'dir');
      }
      return r;
    };
    const q = await svc.upload(vaultId, [top]);
    const m = await moved(q);
    assert.deepEqual(m.keptFiles.map((f) => [f.name, f.reason]), [['datei.txt', 'changed']]);
    assert.equal(fs.readFileSync(path.join(elsewhere, 'datei.txt'), 'utf8'), 'innen', 'the file behind the link stays');
    assert.equal(fs.existsSync(path.join(src, 'Unter-alt', 'datei.txt')), true);
    assert.equal(fs.lstatSync(path.join(top, 'Unter')).isSymbolicLink(), true);
  });

  it('a folder upload that fails on its way removes no folder; its files that went up still go', async () => {
    const { svc, api, vaultId, moved } = await vaultSetup();
    const src = tmpDir('dvm-dirfail-');
    const top = path.join(src, 'Archiv');
    const first = write(path.join(top, 'a', 'eins.txt'), '1');
    write(path.join(top, 'b', 'zwei.txt'), '2');
    const mkdir = api.mkdirEncrypted.bind(api);
    let n = 0;
    api.mkdirEncrypted = async (...args) => {
      // the top folder and "a" are made, "b" fails
      if (++n === 3) throw Object.assign(new Error('gone'), { code: 'network' });
      return mkdir(...args);
    };
    const q = await svc.upload(vaultId, [top]);
    const m = await moved(q);
    assert.deepEqual([m.moved, m.deleted], [1, 1]);
    assert.deepEqual(m.folders, { removed: 0, kept: 0 });
    assert.equal(fs.existsSync(first), false);
    assert.equal(fs.existsSync(path.join(top, 'a')), true, 'no folder removed after a failed walk');
    assert.equal(fs.existsSync(path.join(top, 'b', 'zwei.txt')), true);
  });

  it('the event reaches the window as drive:vault-move', async () => {
    const { svc, vaultId, moved } = await vaultSetup();
    const sent = [];
    registerDriveHandlers(() => {}, { drive: svc, getMainWindow: () => ({ isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } }), log });
    assert.equal(DRIVE_EVENTS.vaultMove, 'drive:vault-move');
    const src = tmpDir('dvm-ipc-');
    const q = await svc.upload(vaultId, [write(path.join(src, 'x.txt'), 'x')]);
    await moved(q);
    const ev = await until(() => sent.find(([ch, p]) => ch === 'drive:vault-move' && p.id === q.move));
    assert.equal(ev[1].deleted, 1);
  });
});
