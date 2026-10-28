'use strict';

// Drive 1.9 vault folders (Tresor-Ordner) in the Windows Pro app: the format against the plugin's frozen vectors
// (test/fixtures/drive-vault-vectors.json, a copy of plugins/gatecontrol-drive/test/vault-vectors.json) and the RFC 9180
// vector, files chunk by chunk from disk to disk (tampering, reordering, cutting refused), and DriveService against the
// fake Drive server: make a vault (recovery key once), names decrypted in listings, uploads only as ciphertext,
// opening into a temporary folder, renaming, new folders, a second device asks and is approved after the safety number,
// the recovery key, stale keys, a new key — the device key never plain in the store; "Ordner sichern" leaves vaults out.

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
const drive = require('../src/utils/drive');
const S = require('../src/utils/drive-sync');
const DriveService = require('../src/services/drive');
const DriveApi = require('../src/services/drive-api');
const DriveSync = require('../src/services/drive-sync');
const ApiClient = require('../src/services/api-client');
const { registerDriveHandlers } = require('../src/ipc/drive-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const { driveServer } = require('./fixtures/drive-server');
const vectors = require('./fixtures/drive-vault-vectors.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const H = (s) => Buffer.from(s, 'hex');
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

/** safeStorage stand-in: never the plain bytes in the store. */
function fakeProtect() {
  const x = (b) => Buffer.from(Buffer.from(b).map((c) => c ^ 0xa5));
  return {
    available: () => true,
    encrypt: (b) => Buffer.concat([Buffer.from('DPAPI:'), x(b)]),
    decrypt: (b) => x(Buffer.from(b).subarray(6)),
  };
}

// ── the format ─────────────────────────────────────────────

describe('utils/drive-vault: the format (the plugin\'s vectors)', () => {
  it('device key, device id, safety number, wrap, name, content and recovery key bit for bit', async () => {
    const dev = V.publicFromPrivate(H(vectors.input.deviceSeed));
    assert.equal(V.b64u(dev), vectors.device.publicKey);
    assert.equal(V.deviceId(dev), vectors.device.deviceId);
    assert.equal(V.safetyNumber(dev), vectors.device.safetyNumber);
    const eph = { privateRaw: H(vectors.input.ephemeralSeed), publicRaw: V.publicFromPrivate(H(vectors.input.ephemeralSeed)) };
    assert.equal(V.b64u(eph.publicRaw), vectors.ephemeralPublicKey);
    const tk = H(vectors.input.vaultKey);
    const vid = vectors.input.vaultId;
    assert.equal(V.wrapKey(tk, dev, vid, 1, { ephemeral: eph }), vectors.wrap);
    assert.deepEqual(V.unwrapKey(vectors.wrap, H(vectors.input.deviceSeed), dev, vid, 1), tk);
    assert.equal(V.encryptName(tk, vid, 1, vectors.input.name, { nonce: H(vectors.input.nameNonce) }), vectors.nameCipher);
    assert.equal(V.decryptName(new Map([[1, tk]]), vid, vectors.nameCipher), vectors.input.name);
    assert.equal(V.nameVersion(vectors.nameCipher), 1);
    const pt = Buffer.from(Array.from({ length: vectors.input.content.length }, (_, i) => (i * 7 + 3) & 255));
    const ct = V.encryptBuffer(tk, vid, 1, pt, { chunkSize: vectors.input.content.chunkSize, salt: H(vectors.input.content.salt) });
    assert.equal(ct.length, vectors.content.size);
    assert.equal(ct.subarray(0, V.HEADER).toString('hex'), vectors.content.header);
    assert.equal(crypto.createHash('sha256').update(ct).digest('hex'), vectors.content.sha256);
    assert.equal(ct.toString('base64url'), vectors.content.base64url);
    assert.deepEqual(V.decryptBuffer({ 1: tk }, vid, Buffer.from(vectors.content.base64url, 'base64url')), pt);
    const rk = H(vectors.input.recoveryKey);
    assert.equal(await V.formatRecoveryKey(rk), vectors.recovery.text);
    assert.equal(V.b64u(V.recoveryKeyPair(rk).publicRaw), vectors.recovery.publicKey);
    assert.equal(V.recoveryAuth(rk), vectors.recovery.auth);
    assert.equal(V.wrapKey(tk, V.recoveryKeyPair(rk).publicRaw, vid, 1, { ephemeral: eph }), vectors.recovery.wrap);
    assert.deepEqual(V.unwrapKey(vectors.recovery.wrap, V.recoveryKeyPair(rk).privateRaw, V.recoveryKeyPair(rk).publicRaw, vid, 1), tk);
    assert.deepEqual(await V.parseRecoveryKey('r30w 5gy4 rq3c fj69 sb5w skee sz8d 3mpk tkax dnyr v7dd qq6x vvfj 63zj'), rk);
    assert.deepEqual(await V.parseRecoveryKey(vectors.recovery.text.replace(/0/g, 'O').replace(/1/g, 'l')), rk);
    await assert.rejects(V.parseRecoveryKey(vectors.recovery.text.replace('R30W', 'R30X')), (e) => e.code === 'recovery_key');
  });

  it('HPKE: the RFC 9180 vector A.1.1 (DHKEM(X25519), HKDF-SHA256, AES-128-GCM)', () => {
    const ephPriv = H('52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736');
    const eph = { privateRaw: ephPriv, publicRaw: V.publicFromPrivate(ephPriv) };
    assert.equal(eph.publicRaw.toString('hex'), '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431');
    const skR = H('4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8');
    const pkR = V.publicFromPrivate(skR);
    const info = H('4f6465206f6e2061204772656369616e2055726e');
    const aad = H('436f756e742d30');
    const pt = H('4265617574792069732074727574682c20747275746820626561757479');
    const sealed = V.hpkeSeal(pkR, info, aad, pt, { aeadId: 1, ephemeral: eph });
    assert.equal(sealed.subarray(32).toString('hex'), 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a');
    assert.deepEqual(V.hpkeOpen(skR, pkR, info, aad, sealed, { aeadId: 1 }), pt);
  });

  it('names: padded to 32 bytes, bound to the vault, NFC; wrong key or vault refused', () => {
    const tk = V.newVaultKey();
    const vid = V.newVaultId();
    assert.equal(Buffer.from(V.encryptName(tk, vid, 2, 'a'), 'base64url').length, Buffer.from(V.encryptName(tk, vid, 2, 'a'.repeat(31)), 'base64url').length);
    assert.equal(V.decryptName({ 2: tk }, vid, V.encryptName(tk, vid, 2, 'Café.txt')), 'Café.txt');
    assert.throws(() => V.decryptName({ 2: tk }, V.newVaultId(), V.encryptName(tk, vid, 2, 'x')), (e) => e.code === 'decrypt');
    assert.throws(() => V.decryptName({ 1: tk }, vid, V.encryptName(tk, vid, 2, 'x')), (e) => e.code === 'decrypt');
    assert.throws(() => V.unwrapKey(V.wrapKey(tk, V.generateKeyPair().publicRaw, vid, 1), V.generateKeyPair().privateRaw, V.generateKeyPair().publicRaw, vid, 1), (e) => e.code === 'decrypt');
  });

  it('files chunk by chunk from disk to disk: sizes around the chunk, empty files; tampering, reordering, cutting refused', async () => {
    const dir = tmpDir('dv-files-');
    const tk = V.newVaultKey();
    const vid = V.newVaultId();
    for (const size of [0, 1, 1023, 1024, 1025, 5000]) {
      const pt = crypto.randomBytes(size);
      fs.writeFileSync(path.join(dir, 'p'), pt);
      const r = await V.encryptFile(tk, vid, 3, path.join(dir, 'p'), path.join(dir, 'c'), { chunkSize: 1024 });
      const ct = fs.readFileSync(path.join(dir, 'c'));
      assert.equal(ct.length, V.cipherSize(size, 1024), `size ${size}`);
      assert.equal(r.cipherSize, ct.length);
      assert.equal(V.plainSize(ct.length, 1024), size);
      assert.deepEqual(V.decryptBuffer({ 3: tk }, vid, ct), pt, `buffer ${size}`);
      await V.decryptFile({ 3: tk }, vid, path.join(dir, 'c'), path.join(dir, 'o'));
      assert.deepEqual(fs.readFileSync(path.join(dir, 'o')), pt, `file ${size}`);
    }
    // the default chunk of 1 MiB
    const big = crypto.randomBytes(V.CHUNK * 2 + 17);
    fs.writeFileSync(path.join(dir, 'big'), big);
    await V.encryptFile(tk, vid, 1, path.join(dir, 'big'), path.join(dir, 'big.enc'));
    assert.equal(fs.statSync(path.join(dir, 'big.enc')).size, V.cipherSize(big.length));
    assert.equal(V.parseHeader(fs.readFileSync(path.join(dir, 'big.enc')).subarray(0, 29)).chunkSize, V.CHUNK);
    await V.decryptFile({ 1: tk }, vid, path.join(dir, 'big.enc'), path.join(dir, 'big.out'));
    assert.deepEqual(fs.readFileSync(path.join(dir, 'big.out')), big);

    const pt = crypto.randomBytes(3000);
    const ct = V.encryptBuffer(tk, vid, 3, pt, { chunkSize: 1024 });
    const step = 1024 + 16;
    const bad = Buffer.from(ct); bad[100] ^= 1;
    const swapped = Buffer.concat([ct.subarray(0, 29), ct.subarray(29 + step, 29 + 2 * step), ct.subarray(29, 29 + step), ct.subarray(29 + 2 * step)]);
    const cut = ct.subarray(0, 29 + 2 * step);
    for (const [what, data] of [['tampered', bad], ['reordered', swapped], ['cut', cut]]) {
      fs.writeFileSync(path.join(dir, 'x'), data);
      await assert.rejects(V.decryptFile({ 3: tk }, vid, path.join(dir, 'x'), path.join(dir, 'y')), (e) => e.code === 'decrypt', what);
    }
    fs.writeFileSync(path.join(dir, 'x'), ct);
    await assert.rejects(V.decryptFile({ 3: tk }, V.newVaultId(), path.join(dir, 'x'), path.join(dir, 'y')), (e) => e.code === 'decrypt');
    await assert.rejects(V.decryptFile({ 1: tk }, vid, path.join(dir, 'x'), path.join(dir, 'y')), (e) => e.code === 'decrypt');
  });
});

// ── DriveService against the fake Drive ────────────────────

const FEATURES = ['devices', 'emptyFiles', 'links', 'vault', 'office'];

async function service(srv, { store = createMemoryStore(), protect = fakeProtect(), name = 'Desktop-PC', shell = null, dialog = null } = {}) {
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  const api = new DriveApi({ apiClient, log, getLang: () => 'de', sleep: async () => {} });
  const tmp = tmpDir('dv-tmp-');
  const opened = [];
  const svc = new DriveService({
    apiClient, api, log, store, protect, deviceName: () => name, tempDir: () => tmp, timing: { progressMs: 0 },
    shell: shell || { openPath: async (p) => { opened.push({ path: p, content: fs.readFileSync(p) }); return ''; }, openExternal: async () => {} },
    dialog,
  });
  svc.start();
  cleanup.push(() => svc.stop());
  await svc.check();
  return { svc, api, store, tmp, opened };
}

async function setup() {
  const srv = await driveServer({ features: FEATURES });
  cleanup.push(() => srv.close());
  return { srv, ...(await service(srv)) };
}

describe('DriveService: vault folders', () => {
  it('make a vault, list it with its name, upload only ciphertext, open it decrypted, rename, new folder', async () => {
    const { srv, svc, store, tmp, opened } = await setup();
    const made = await svc.vaultCreate(1, 'Steuer 2025');
    assert.equal(made.ok, true);
    assert.match(made.recoveryKey, /^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.equal(made.node.name, 'Steuer 2025');
    const vnode = srv.state.nodes.get(made.node.id);
    assert.match(vnode.name, /^[0-9a-f]{32}$/, 'the server has an opaque name');
    // the device key: protected in the store, never plain
    const rec = Object.values(store.get('driveVault').devices)[0];
    const req = srv.state.requests.find((r) => r.path.endsWith('/api/vaults') && r.method === 'POST');
    assert.equal(req.body.device.publicKey, rec.pub);
    assert.equal(req.body.device.platform, 'windows');
    assert.ok(Buffer.from(rec.enc, 'base64').subarray(0, 6).equals(Buffer.from('DPAPI:')));
    assert.equal(JSON.stringify(store.get('driveVault')).includes(made.recoveryKey), false);

    // the listing shows the vault by its name
    const root = await svc.folder(1);
    const row = root.items.find((n) => n.id === made.node.id);
    assert.equal(row.name, 'Steuer 2025');
    assert.equal(row.vaultRoot, true);
    assert.equal(row.locked, false);
    assert.equal(root.vault, null);

    // an upload into the vault: ciphertext only, no text / takenAt / entropy
    const src = tmpDir('dv-src-');
    const SECRET = 'Kontoauszug mit IBAN DE02 1203 0000 0000 2020 51';
    fs.writeFileSync(path.join(src, 'Kontoauszug.txt'), SECRET);
    const q = await svc.upload(made.node.id, [path.join(src, 'Kontoauszug.txt')]);
    assert.equal(q.queued.length, 1);
    await until(() => svc.transfers().some((t) => t.state === 'done'));
    const commit = srv.state.requests.find((r) => r.path.endsWith('uploads/commit'));
    assert.equal(commit.body.encrypted, true);
    assert.equal(commit.body.keyVersion, 1);
    assert.equal(commit.body.text, undefined);
    assert.equal(commit.body.name, undefined);
    for (const m of srv.state.media.values()) assert.equal(m.data.includes(Buffer.from('IBAN')), false, 'no plaintext on the server');
    const file = [...srv.state.nodes.values()].find((n) => n.parentId === made.node.id && !n.isDir);
    assert.equal(file.mime, 'application/octet-stream');
    assert.equal(fs.readdirSync(path.join(tmp, 'vault-up')).length, 0, 'the ciphertext copy is gone');

    // inside: the folder with its names and crumbs
    const inside = await svc.folder(made.node.id);
    assert.equal(inside.vault.state, 'open');
    assert.equal(inside.node.name, 'Steuer 2025');
    assert.deepEqual(inside.crumbs.map((c) => c.name), ['Meine Dateien', 'Steuer 2025']);
    assert.deepEqual(inside.items.map((n) => n.name), ['Kontoauszug.txt']);

    // open: decrypted into %TEMP%\gatecontrol-drive\vault\<random>\<name>
    const o = await svc.open(file.id);
    assert.equal(o.ok, true);
    assert.equal(path.basename(o.path), 'Kontoauszug.txt');
    assert.ok(o.path.startsWith(path.join(tmp, 'vault')));
    assert.equal(opened[0].content.toString(), SECRET);
    // the copy goes at stop
    svc.stop();
    await until(() => !fs.existsSync(path.join(tmp, 'vault')));
    svc.start();

    // the same name again: asks; "Neue Version" sends the opaque name
    fs.writeFileSync(path.join(src, 'Kontoauszug.txt'), 'Fassung 2');
    const q2 = await svc.upload(made.node.id, [path.join(src, 'Kontoauszug.txt')]);
    await until(() => svc.transfers().some((t) => t.id === q2.queued[0] && t.state === 'conflict'));
    svc.resolve(q2.queued[0], 'version');
    await until(() => svc.transfers().some((t) => t.id === q2.queued[0] && t.state === 'done'));
    const c2 = srv.state.requests.filter((r) => r.path.endsWith('uploads/commit')).pop();
    assert.equal(c2.body.name, file.name);
    assert.equal(c2.body.onConflict, 'version');
    assert.equal(srv.state.nodes.get(file.id).rev, 2);
    // "Beide behalten": a free name
    const q3 = await svc.upload(made.node.id, [path.join(src, 'Kontoauszug.txt')]);
    await until(() => svc.transfers().some((t) => t.id === q3.queued[0] && t.state === 'conflict'));
    svc.resolve(q3.queued[0], 'rename');
    await until(() => svc.transfers().some((t) => t.id === q3.queued[0] && t.state === 'done'));
    assert.deepEqual((await svc.folder(made.node.id)).items.map((n) => n.name).sort(), ['Kontoauszug (2).txt', 'Kontoauszug.txt']);

    // rename and a new folder: encrypted names
    const ren = await svc.rename(file.id, 'Oktober.txt');
    assert.equal(ren.node.name, 'Oktober.txt');
    assert.equal(srv.state.nodes.get(file.id).name, file.name, 'the opaque name stays');
    const sub = await svc.mkdir(made.node.id, 'Belege');
    assert.equal(sub.node.name, 'Belege');
    assert.equal(srv.state.nodes.get(sub.node.id).encrypted, true);
    // a whole folder into the vault
    fs.mkdirSync(path.join(src, 'Scans', 'Alt'), { recursive: true });
    fs.writeFileSync(path.join(src, 'Scans', 'Alt', 'a.txt'), 'alt');
    await svc.upload(sub.node.id, [path.join(src, 'Scans')]);
    await until(() => svc.transfers().some((t) => t.name === 'a.txt' && t.state === 'done'));
    const scans = (await svc.folder(sub.node.id)).items.find((n) => n.name === 'Scans');
    const alt = (await svc.folder(scans.id)).items.find((n) => n.name === 'Alt');
    assert.deepEqual((await svc.folder(alt.id)).items.map((n) => n.name), ['a.txt']);

    // what a vault never does: links, office
    await assert.rejects(svc.createLink({ nodeId: file.id, mode: 'view', expires: '7d' }), (e) => e.code === 'encrypted');
    fs.writeFileSync(path.join(src, 'Plan.xlsx'), 'x');
    const xl = await svc.upload(made.node.id, [path.join(src, 'Plan.xlsx')]);
    await until(() => svc.transfers().some((t) => t.id === xl.queued[0] && t.state === 'done'));
    const xlId = svc.transfers().find((t) => t.id === xl.queued[0]).nodeId;
    await assert.rejects(svc.office(xlId), (e) => e.code === 'encrypted');

    // nothing readable anywhere on the server
    const dump = JSON.stringify([...srv.state.nodes.values()]) + JSON.stringify(srv.state.requests);
    for (const n of ['Steuer 2025', 'Kontoauszug', 'Oktober', 'Belege', made.recoveryKey]) assert.equal(dump.includes(n), false, n);
  });

  it('a second device asks; the first approves after the safety number; decline; the recovery key opens it', async () => {
    const { srv, svc } = await setup();
    const made = await svc.vaultCreate(1, 'Familie');
    const other = await service(srv, { name: 'Laptop' });
    // the other PC sees the vault locked and may ask
    const list = await other.svc.folder(1);
    const row = list.items.find((n) => n.id === made.node.id);
    assert.equal(row.locked, true);
    assert.equal(row.vaultState, 'none');
    const vs = await other.svc.vaults();
    assert.equal(vs.vaults[0].state, 'none');
    assert.equal(vs.vaults[0].name, null);
    const asked = await other.svc.vaultRequest(made.vault.id);
    assert.equal(asked.state, 'pending');
    assert.match(asked.safetyNumber, /^\d{5} \d{5} \d{5} \d{5}$/);
    // an upload is refused while locked
    await assert.rejects(other.svc.upload(made.node.id, [__filename]), (e) => e.code === 'vault_locked');
    // the first PC lists the request with the same safety number and approves it
    const devs = await svc.vaultDevices(made.vault.id);
    const req = devs.devices.find((d) => d.state === 'pending');
    assert.equal(req.safetyNumber, asked.safetyNumber);
    assert.equal(devs.vault.pending, 1);
    await assert.rejects(svc.vaultApprove(made.vault.id, req.deviceId, '00000 00000 00000 00000'), (e) => e.code === 'safety');
    const ok = await svc.vaultApprove(made.vault.id, req.deviceId, req.safetyNumber);
    assert.equal(ok.device.state, 'approved');
    assert.equal((await other.svc.vaultOpen(made.vault.id)).state, 'open');
    assert.equal((await other.svc.folder(1)).items.find((n) => n.id === made.node.id).name, 'Familie');

    // a third device: declined
    const third = await service(srv, { name: 'Tablet' });
    await third.svc.vaultRequest(made.vault.id);
    const t = (await svc.vaultDevices(made.vault.id)).devices.find((d) => d.state === 'pending');
    assert.equal((await svc.vaultDecline(made.vault.id, t.deviceId)).device.state, 'revoked');

    // a fourth device opens it with the recovery key (and approves itself)
    const fourth = await service(srv, { name: 'Neu' });
    await assert.rejects(fourth.svc.vaultRecover(made.vault.id, 'R30W-5GY4-RQ3C-FJ69-SB5W-SKEE-SZ8D-3MPK-TKAX-DNYR-V7DD-QQ6X-VVFJ-63ZJ'), (e) => e.code === 'recovery_key');
    const r = await fourth.svc.vaultRecover(made.vault.id, made.recoveryKey.toLowerCase().replace(/-/g, ' '));
    assert.equal(r.state, 'open');
    const approveReq = srv.state.requests.filter((x) => x.path.endsWith('/approve')).pop();
    assert.equal(approveReq.body.via, 'recovery');
    assert.equal(approveReq.body.recoveryAuth.length, 43);
    assert.equal((await fourth.svc.folder(1)).items.find((n) => n.id === made.node.id).name, 'Familie');
  });

  it('a stale key (another device made a new one): the keys again, then the upload; a new key with a new recovery key', async () => {
    const { srv, svc } = await setup();
    const made = await svc.vaultCreate(1, 'Projekt');
    const other = await service(srv, { name: 'Laptop' });
    await other.svc.vaultRequest(made.vault.id);
    const req = (await svc.vaultDevices(made.vault.id)).devices.find((d) => d.state === 'pending');
    await svc.vaultApprove(made.vault.id, req.deviceId, req.safetyNumber);
    await other.svc.vaultOpen(made.vault.id);
    // the other PC makes a new key (version 2) — this one still writes with 1
    srv.state.vaults.get(made.vault.id).needsRotation = true;
    const rot = await other.svc.vaultRotate(made.vault.id);
    assert.equal(rot.vault.keyVersion, 2);
    assert.equal(rot.recoveryKey, null);
    const src = tmpDir('dv-src-');
    fs.writeFileSync(path.join(src, 'neu.txt'), 'neu');
    await svc.upload(made.node.id, [path.join(src, 'neu.txt')]);
    await until(() => svc.transfers().some((t) => t.state === 'done' || t.state === 'failed'));
    assert.equal(svc.transfers()[0].state, 'done', JSON.stringify(svc.transfers()));
    const commits = srv.state.requests.filter((r) => r.path.endsWith('uploads/commit'));
    assert.equal(commits.length, 2, 'once refused (stale_key), once with version 2');
    assert.equal(commits[1].body.keyVersion, 2);
    // the old and the new file open on both
    const items = (await other.svc.folder(made.node.id)).items;
    assert.deepEqual(items.map((n) => n.name), ['neu.txt']);
    // Drive asks for a new recovery key (its holder left): shown once
    srv.recoveryRequired = true;
    const rot2 = await svc.vaultRotate(made.vault.id);
    assert.equal(rot2.vault.keyVersion, 3);
    assert.match(rot2.recoveryKey, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
    const body = srv.state.requests.filter((r) => r.path.endsWith('/rotate')).pop().body;
    assert.deepEqual(body.recovery.wraps.map((w) => w.keyVersion), [1, 2, 3]);
    const fresh = await service(srv, { name: 'Neu' });
    assert.equal((await fresh.svc.vaultRecover(made.vault.id, rot2.recoveryKey)).state, 'open');
    assert.deepEqual((await fresh.svc.folder(made.node.id)).items.map((n) => n.name), ['neu.txt']);
  });

  it('without safeStorage no vault; Drives without the feature are not asked', async () => {
    const { srv } = await setup();
    const none = await service(srv, { protect: { available: () => false, encrypt() { throw new Error('x'); }, decrypt() { throw new Error('x'); } } });
    const st = await none.svc.vaultStatus();
    assert.equal(st.supported, false);
    await assert.rejects(none.svc.vaultCreate(1, 'X'), (e) => e.code === 'vault_unsupported');
    const old = await driveServer({ features: ['devices'] });
    cleanup.push(() => old.close());
    const o = await service(old);
    await assert.rejects(o.svc.vaults(), (e) => e.code === 'unsupported');
    const before = old.state.requests.length;
    await o.svc.mkdir(1, 'Normal');
    assert.equal(old.state.requests.slice(before).some((r) => /\/nodes\/1$/.test(r.path)), false, 'no extra GET of the parent');
  });

  it('IPC: arguments checked', async () => {
    const { svc } = await setup();
    const handlers = {};
    registerDriveHandlers((ch, fn) => { handlers[ch] = fn; }, { drive: svc, getMainWindow: () => null, log });
    for (const [ch, a] of [['drive:vault:open', { vaultId: '../x' }], ['drive:vault:create', { parentId: 1, name: '' }], ['drive:vault:approve', { vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', deviceId: 'x', safetyNumber: '1' }],
      ['drive:vault:recover', { vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', recoveryKey: '' }]]) {
      assert.equal((await handlers[ch](null, a)).code, 'invalid', ch);
    }
    const made = await handlers['drive:vault:create'](null, { parentId: 1, name: 'IPC' });
    assert.equal(made.ok, true);
    assert.equal((await handlers['drive:vaults'](null, {})).vaults[0].name, 'IPC');
  });
});

describe('DriveSync: vault folders are left out', () => {
  it('never in Drive\'s tree, never a sync target, nothing of the PC goes into one', async () => {
    const { srv, svc, api } = await setup();
    const sync = new DriveSync({
      drive: svc, api, store: createMemoryStore(), dir: tmpDir('dv-state-'), log, hostname: () => 'Desktop-PC', getDeviceKey: () => 'ab12cd34',
      trashItem: async (p) => { await fs.promises.rm(p, { recursive: true, force: true }); }, timing: { watch: false, settleMs: 0, emitMs: 0, startMs: 600000 }, readPdfText: async () => null,
    });
    sync.start();
    // a run still going would write its state again into dv-state-… after the cleanup removed it
    cleanup.push(async () => { sync.stop(); await sync.idle(); });
    const target = srv.mutate.dir(1, 'Abgleich');
    const made = await svc.vaultCreate(target.id, 'Geheim');
    const src = tmpDir('dv-src-');
    fs.writeFileSync(path.join(src, 'a.txt'), 'a');
    await svc.upload(made.node.id, [path.join(src, 'a.txt')]);
    await until(() => svc.transfers().some((t) => t.state === 'done'));
    await assert.rejects(sync.addFolder({ path: tmpDir('dv-pc0-'), mode: 'sync', targetId: made.node.id }), (e) => e.code === 'encrypted');
    const pc = tmpDir('dv-pc-');
    fs.writeFileSync(path.join(pc, 'b.txt'), 'b');
    // a folder of the PC named like the vault's opaque folder: never uploaded into it
    fs.mkdirSync(path.join(pc, srv.state.nodes.get(made.node.id).name));
    fs.writeFileSync(path.join(pc, srv.state.nodes.get(made.node.id).name, 'c.txt'), 'c');
    const f = await sync.addFolder({ path: pc, mode: 'sync', targetId: target.id });
    sync.sync(f.folder.id, { full: true });
    await sync.idle();
    assert.equal(fs.readdirSync(pc).includes('a.txt'), false);
    assert.deepEqual(fs.readdirSync(pc).sort(), ['b.txt', srv.state.nodes.get(made.node.id).name].sort());
    const vaultKids = [...srv.state.nodes.values()].filter((n) => n.parentId === made.node.id && !n.deleted);
    assert.ok(vaultKids.every((n) => n.encrypted), 'nothing plain in the vault');
    // a change in the vault (another device) does not reach the tree
    const tree = { [target.id]: { id: target.id } };
    const r = S.applyChanges(tree, target.id, [{ seq: 1, op: 'create', nodeId: 999, node: drive.normalizeNode({ id: 999, areaId: 'mine:2', parentId: target.id, name: 'f'.repeat(32), isDir: true, encrypted: true }) }]);
    assert.equal(r.touched, false);
    assert.equal(tree[999], undefined);
  });
});
