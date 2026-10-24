'use strict';

// "Vault" (plugin gatecontrol-vault): VaultService against an in-memory plugin (fixtures/vault-server.js) with the
// real crypto (utils/vault-crypto.js, Argon2id at the server's smallest bounds to stay fast): setup → unlock, saves
// and sync, the offline outbox and copy on disk, conflicts, stale_key, tombstones, key changes in batches,
// recovery, password change, "remember unlock", auto-lock, the clipboard, import, emergency access, pushes and the
// vault:* IPC.

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

const VaultService = require('../src/services/vault');
const vault = require('../src/utils/vault');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { vaultServer, API } = require('./fixtures/vault-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const KDF = { m: 19456, t: 2 };
const PW = 'Sonnenblume-Kanu-Turm-47';
const PW2 = 'Leuchtturm-Mond-Fahrrad-92';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-vault-'));
  dirs.push(d);
  return d;
}

/** A device of person `uid`: its own folder (or `dir`), the server's transport. */
function device(srv, uid, name = 'pc', extra = {}) {
  const dir = extra.dir || tmpDir();
  const s = new VaultService({
    api: srv.transport(uid, name), dir, kdf: KDF, deviceName: name, log,
    timing: { recheckMs: 1e9, retryMinMs: 1e9, syncMs: 1e9, ...(extra.timing || {}) },
    ...extra, dir,
  });
  s.dir = dir;
  return s;
}

async function setUp(s, password = PW) {
  await s.check();
  const { recoveryKey } = await s.setup({ password });
  await s.confirmSetup();
  await s.sync();
  return recoveryKey;
}

const personal = (s) => s._state.vaults.find((v) => v.kind === 'personal').id;
const login = (title, password = 'Geheim-123!', extra = {}) => ({ type: 'login', title, urls: ['https://bank.example.de'], fields: { username: 'anna', password }, ...extra });
const titles = async (s, opts) => (await s.entries(opts)).entries.map((e) => e.title).sort();
const code = (c) => (e) => e && e.code === c;

describe('VaultService: availability, setup, unlock', () => {
  it('is available while the plugin list names gatecontrol-vault', async () => {
    const srv = vaultServer({ plugin: false });
    const s = device(srv, 2);
    let st = await s.check();
    assert.deepEqual([st.state, st.reason], ['unavailable', 'not_installed']);
    srv.plugin = true;
    st = await s.check();
    assert.equal(st.state, 'available');
    assert.equal(st.version, '1.0.0');
    assert.equal(st.account, 'none', 'GET account answered: not set up yet');
    assert.equal(st.unlocked, false);
  });

  it('setup: the recovery key first, the account only after confirming; lock / unlock', async () => {
    const srv = vaultServer();
    const s = device(srv, 2);
    await s.check();
    await assert.rejects(s.setup({ password: 'kurz' }), code('weak_password'));
    const { recoveryKey } = await s.setup({ password: PW });
    assert.match(recoveryKey, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
    assert.equal(srv.accounts.size, 0, 'nothing sent before the person confirmed keeping the key');
    assert.equal(s.status().setupPending, true);
    const st = await s.confirmSetup();
    assert.ok(srv.accounts.has(2));
    assert.equal(st.unlocked, true);
    assert.equal(st.account, 'ready');
    assert.equal(st.myUserId, null, 'known after the first sync');
    await s.sync();
    assert.equal(s.status().myUserId, 2);
    assert.match(s.status().safetyNumber, /^(\d{5} ){7}\d{5}$/);
    const { vaults } = await s.vaults();
    assert.deepEqual(vaults.map((v) => [v.kind, v.name, v.role]), [['personal', 'Persönlich', 'manage']]);
    await assert.rejects(s.setup({ password: PW }), code('exists'));

    s.lock();
    assert.equal(s.status().unlocked, false);
    assert.deepEqual(s.status().lastLock.reason, 'manual');
    await assert.rejects(s.entries(), code('locked'));
    await assert.rejects(s.unlock({ password: 'Falsch-Falsch-Falsch-1' }), code('wrong_password'));
    await s.unlock({ password: PW });
    assert.equal(s.status().unlocked, true);
    assert.deepEqual((await s.entries()).entries, []);
  });

  it('a refused setup starts over; offline keeps it for another try', async () => {
    const srv = vaultServer();
    const s = device(srv, 2);
    await s.check();
    await s.setup({ password: PW });
    srv.offline = true;
    await assert.rejects(s.confirmSetup(), code('network'));
    assert.equal(s.status().setupPending, true);
    srv.offline = false;
    await s.confirmSetup();
    assert.equal(s.status().unlocked, true);
    s.cancelSetup();
    assert.equal(s.status().setupPending, false);
  });
});

describe('VaultService: entries and sync', () => {
  it('save → sync → a second device reads it; lists carry no secrets; the copy on disk is encrypted', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc');
    await setUp(a);
    const { id } = await a.save({ vaultId: personal(a), data: login('Bank', 'Geheim-123!') });
    assert.ok(vault.isId(id));
    await a.sync();
    assert.equal(srv.items.get(id).rev, 1);
    assert.equal(a.status().pending, 0);
    const list = await a.entries();
    assert.deepEqual(list.entries.map((e) => [e.title, e.username, e.host, e.hasPassword, e.pending]), [['Bank', 'anna', 'bank.example.de', true, false]]);
    assert.ok(!JSON.stringify(list).includes('Geheim-123!'));
    assert.equal((await a.entry(id)).data.fields.password, 'Geheim-123!');
    assert.equal(list.vaults[0].count, 1);

    const b = device(srv, 2, 'laptop');
    await b.check();
    await b.unlock({ password: PW });
    await b.sync();
    assert.deepEqual(await titles(b), ['Bank']);
    assert.equal((await b.entry(id)).data.fields.password, 'Geheim-123!');
    assert.equal(srv.items.get(id).device, 'pc');

    await a.flush();
    const files = fs.readdirSync(a.dir);
    assert.ok(files.some((f) => /^vault-[0-9a-f]{32}\.json$/.test(f)), files.join());
    const disk = files.map((f) => fs.readFileSync(path.join(a.dir, f), 'utf8')).join('\n');
    for (const plain of ['Geheim-123!', 'Bank', 'anna', 'bank.example.de', PW, 'Persönlich']) assert.ok(!disk.includes(plain), `${plain} on disk`);
  });

  it('offline: saves wait in the outbox, survive a restart and go out later', async () => {
    const srv = vaultServer();
    const a = device(srv, 2);
    await setUp(a);
    srv.offline = true;
    const { id } = await a.save({ vaultId: personal(a), data: login('Offline') });
    assert.equal((await a.sync()).state, 'offline');
    assert.equal(a.status().pending, 1);
    assert.equal(a.status().sync.state, 'offline');
    await a.flush();
    a.lock();

    const again = device(srv, 2, 'pc', { dir: a.dir });
    await again.unlock({ password: PW });
    const list = await again.entries();
    assert.deepEqual(list.entries.map((e) => [e.id, e.title, e.pending]), [[id, 'Offline', true]]);
    srv.offline = false;
    assert.equal((await again.sync()).state, 'done');
    assert.ok(srv.items.has(id));
    assert.equal(again.status().pending, 0);
  });

  it('a conflict keeps both versions: the other one as the entry, ours as a copy "(Konflikt)"', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc');
    await setUp(a);
    const { id } = await a.save({ vaultId: personal(a), data: login('Konto') });
    await a.sync();
    const b = device(srv, 2, 'laptop');
    await b.check();
    await b.unlock({ password: PW });
    await b.sync();

    srv.offline = true;
    await a.save({ id, vaultId: personal(a), data: login('Von A') });
    await a.sync();
    srv.offline = false;
    await b.save({ id, vaultId: personal(b), data: login('Von B') });
    await b.sync();
    assert.equal(srv.items.get(id).rev, 2);

    await a.sync();
    assert.deepEqual(await titles(a), ['Von A (Konflikt)', 'Von B']);
    assert.equal((await a.entry(id)).title, 'Von B');
    assert.equal(a.status().notices.at(-1).code, 'conflict');
    assert.equal(a.status().pending, 0);
    await b.sync();
    assert.deepEqual(await titles(b), ['Von A (Konflikt)', 'Von B']);
    a.clearNotices();
    assert.deepEqual(a.status().notices, []);
  });

  it('changed again while being sent: the newer save is bound to the new revision', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc');
    await setUp(a);
    const api = a.api;
    const orig = api._call.bind(api);
    let id = null;
    let hit = false;
    api._call = async (m, p, o) => {
      const r = await orig(m, p, o);
      if (!hit && m === 'POST' && p === `${API}items` && id) {
        hit = true;
        await a.save({ id, vaultId: personal(a), data: login('Zweite') });
      }
      return r;
    };
    ({ id } = await a.save({ vaultId: personal(a), data: login('Erste') }));
    await a.sync();
    await a.sync();
    assert.ok(hit);
    assert.equal(srv.items.get(id).rev, 2);
    const b = device(srv, 2, 'laptop');
    await b.check();
    await b.unlock({ password: PW });
    await b.sync();
    assert.deepEqual(await titles(b), ['Zweite']);
    assert.equal(b.status().unreadable, 0);
  });

  it('a purge elsewhere drops the entry and its unsent change; trash, restore, history', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc');
    await setUp(a);
    const pv = personal(a);
    const { id } = await a.save({ vaultId: pv, data: login('V1') });
    await a.sync();
    await a.save({ id, vaultId: pv, data: login('V2') });
    await a.sync();
    await a.save({ id, vaultId: pv, data: login('V3') });
    await a.sync();
    const h = await a.history(id);
    assert.deepEqual(h.map((x) => [x.rev, x.data.title]), [[2, 'V2'], [1, 'V1']]);
    await a.trash(id);
    assert.deepEqual(await titles(a), []);
    assert.deepEqual(await titles(a, { trash: true }), ['V3']);
    await a.restore(id);
    assert.deepEqual(await titles(a), ['V3']);

    const b = device(srv, 2, 'laptop');
    await b.check();
    await b.unlock({ password: PW });
    await b.sync();
    // a change on b waits (locked: the outbox goes out only while unlocked)
    srv.offline = true;
    await b.save({ id, vaultId: pv, data: login('V4 von b') });
    await b.sync();
    b.lock();
    srv.offline = false;
    await a.purge(id);
    assert.equal(srv.items.get(id).state, 'purged');
    await b.sync();
    assert.equal(b._state.outbox.length, 0, 'the tombstone dropped the unsent change');
    assert.equal(b._state.items.has(id), false);
    await b.unlock({ password: PW });
    assert.deepEqual(await titles(b), []);
  });
});

describe('VaultService: shared vaults and key changes', () => {
  async function family() {
    const srv = vaultServer();
    const anna = device(srv, 2, 'anna');
    const marc = device(srv, 3, 'marc');
    const lena = device(srv, 4, 'lena');
    await setUp(anna);
    await setUp(marc);
    await setUp(lena);
    const people = await anna.people();
    assert.deepEqual(people.map((p) => [p.id, p.name, p.hasVault]), [[3, 'Marc', true], [4, 'Lena', true]]);
    assert.equal(people[0].safetyNumber, marc.status().safetyNumber, 'the number Anna sees is the one on Marc\'s device');
    const fam = await anna.createVault('Familie');
    assert.equal(fam.name, 'Familie');
    await anna.addMember(fam.id, 3, 'write');
    const v = await anna.addMember(fam.id, 4, 'read');
    assert.deepEqual(v.members.map((m) => [m.userId, m.role]), [[2, 'manage'], [3, 'write'], [4, 'read']]);
    assert.deepEqual(srv.pushes.map((p) => [p.to, p.topic]), [[3, 'share'], [4, 'share']]);
    return { srv, anna, marc, lena, fam };
  }

  it('sharing: members read and write; read-only members cannot save', async () => {
    const { anna, marc, lena, fam } = await family();
    await anna.save({ vaultId: fam.id, data: login('WLAN-Router') });
    await anna.sync();
    await marc.sync();
    await lena.sync();
    assert.deepEqual(await titles(marc), ['WLAN-Router']);
    assert.deepEqual((await marc.vaults()).vaults.map((v) => [v.name, v.role]), [['Persönlich', 'manage'], ['Familie', 'write']]);
    await assert.rejects(lena.save({ vaultId: fam.id, data: login('Nope') }), code('read_only'));
    await marc.save({ vaultId: fam.id, data: login('Netflix') });
    await marc.sync();
    await anna.sync();
    assert.deepEqual(await titles(anna), ['Netflix', 'WLAN-Router']);
    const r = await anna.renameVault(fam.id, 'Familie Müller');
    assert.equal(r.name, 'Familie Müller');
  });

  it('removing a member changes the key in batches ≤ 100 entries / ≤ 48 KB; a save on the old key is encrypted again (stale_key)', async () => {
    const { srv, anna, marc, lena, fam } = await family();
    const list = [];
    for (let i = 0; i < 130; i++) list.push(login(`Eintrag ${String(i).padStart(3, '0')}`, `pw-${i}`, i % 4 === 0 ? { notes: 'x'.repeat(3000) } : {}));
    assert.equal(await anna.saveMany(fam.id, list), 130);
    await anna.sync();
    assert.equal([...srv.items.values()].filter((it) => it.vaultId === fam.id).length, 130);
    await marc.sync();
    await lena.sync();
    assert.equal((await marc.entries({ vaultId: fam.id })).entries.length, 130);

    const before = srv.calls.length;
    await anna.removeMember(fam.id, 4);
    assert.equal(srv.vaults.get(fam.id).needsRekey, true);
    await anna.sync();
    const v = srv.vaults.get(fam.id);
    assert.equal(v.keyRev, 2);
    assert.equal(v.needsRekey, false);
    assert.equal(v.pendingKeyRev, null);
    assert.ok([...srv.items.values()].filter((it) => it.vaultId === fam.id).every((it) => it.keyRev === 2 && it.rev === 2));
    const calls = srv.calls.slice(before).filter((c) => c.uid === 2);
    const steps = calls.map((c) => `${c.method} ${c.path.replace(API, '')}`);
    const start = steps.indexOf(`POST vaults/${fam.id}/rekey/start`);
    const finish = steps.indexOf(`POST vaults/${fam.id}/rekey/finish`);
    assert.ok(start >= 0 && finish > start, steps.join('\n'));
    const posts = calls.slice(start, finish).filter((c) => c.method === 'POST' && c.path.endsWith('/items'));
    assert.ok(posts.length >= 3, `${posts.length} batches`);
    for (const p of posts) {
      assert.ok(p.body.items.length <= 100);
      assert.ok(JSON.stringify(p.body).length <= 52000, `${JSON.stringify(p.body).length} bytes`);
    }
    assert.equal(posts.reduce((n, p) => n + p.body.items.length, 0), 130);
    assert.equal(anna.status().unreadable, 0);
    assert.equal((await anna.entries({ vaultId: fam.id })).entries.length, 130);
    assert.equal((await anna.vaults()).vaults.find((x) => x.id === fam.id).name, 'Familie');

    // Marc saves a new entry with the key he knows (generation 1): stale_key → the sync brings 2 → again
    const { id } = await marc.save({ vaultId: fam.id, data: login('Von Marc') });
    await marc.sync();
    const it = srv.items.get(id);
    assert.equal(it.keyRev, 2);
    assert.ok(srv.calls.some((c) => c.uid === 3 && c.path.endsWith('/items') && c.body.items.some((x) => x.id === id && x.keyRev === 1)), 'first sent on the old key');
    assert.equal(marc.status().pending, 0);
    await anna.sync();
    assert.ok((await titles(anna, { vaultId: fam.id })).includes('Von Marc'));
    assert.equal(marc.status().unreadable, 0);
    assert.equal((await marc.entries({ vaultId: fam.id })).entries.length, 131);

    // Lena is out: the vault left her list, and her copy
    await lena.sync();
    assert.deepEqual((await lena.vaults()).vaults.map((x) => x.kind), ['personal']);
    assert.deepEqual(await titles(lena), []);
  });

  it('leaving a vault drops it; deleting a vault removes it for everyone', async () => {
    const { anna, marc, fam } = await family();
    await marc.sync();
    assert.equal(await marc.removeMember(fam.id, 3), null);
    assert.deepEqual((await marc.vaults()).vaults.map((x) => x.kind), ['personal']);
    await assert.rejects(anna.deleteVault(personal(anna)), code('forbidden'));
    await anna.deleteVault(fam.id);
    assert.deepEqual((await anna.vaults()).vaults.map((x) => x.kind), ['personal']);
  });
});

describe('VaultService: account', () => {
  it('recovery: the recovery key unlocks, then a new password and a new recovery key', async () => {
    const srv = vaultServer();
    const a = device(srv, 2);
    const rk = await setUp(a);
    const { id } = await a.save({ vaultId: personal(a), data: login('Bleibt') });
    await a.sync();
    a.lock();
    await assert.rejects(a.recover({ recoveryKey: 'AAAA-BBBB' }), code('recovery_key'));
    const st = await a.recover({ recoveryKey: rk.toLowerCase().replace(/-/g, ' ') });
    assert.equal(st.unlocked, true);
    assert.equal(st.recovering, true);
    await assert.rejects(a.completeRecovery({ password: 'kurz' }), code('weak_password'));
    const { recoveryKey } = await a.completeRecovery({ password: PW2 });
    assert.notEqual(recoveryKey, rk);
    assert.equal(a.status().recovering, false);
    a.lock();
    await assert.rejects(a.unlock({ password: PW }), code('wrong_password'));
    await a.unlock({ password: PW2 });
    assert.equal((await a.entry(id)).title, 'Bleibt');
    a.lock();
    await assert.rejects(a.recover({ recoveryKey: rk }), code('wrong_password'));
    await a.recover({ recoveryKey });
  });

  it('a new password; another device changed it meanwhile (conflict → again on top)', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc');
    await setUp(a);
    const b = device(srv, 2, 'laptop');
    await b.check();
    await b.unlock({ password: PW });
    await assert.rejects(a.changePassword({ current: 'Falsch-Falsch-Falsch-1', password: PW2 }), code('wrong_password'));
    await b.changePassword({ current: PW, password: 'Anderes-Passwort-Von-B-7' });
    assert.equal(srv.accounts.get(2).rev, 2);
    await a.changePassword({ current: PW, password: PW2 });
    assert.equal(srv.accounts.get(2).rev, 3);
    // b's copy still has the old wrapping: a wrong password there asks the server once
    b.lock();
    await b.unlock({ password: PW2 });
    assert.equal(b.status().unlocked, true);
  });

  it('remember unlock (DPAPI stub): only when turned on, never the raw key on disk', async () => {
    const srv = vaultServer();
    const xor = (buf) => Buffer.from(Buffer.from(buf).map((x) => x ^ 0x5a));
    const protect = { available: () => true, encrypt: (b) => Buffer.concat([Buffer.from('DPAPI'), xor(b)]), decrypt: (b) => { if (b.subarray(0, 5).toString() !== 'DPAPI') throw new Error('bad'); return xor(b.subarray(5)); } };
    const a = device(srv, 2, 'pc', { protect });
    await setUp(a);
    assert.equal(a.status().rememberAvailable, true);
    assert.equal(a.settings().remember, false);
    a.lock();
    await assert.rejects(a.unlockRemembered(), code('not_remembered'));
    await assert.rejects(a.setSettings({ remember: true }), code('locked'));
    await a.unlock({ password: PW });
    const userKey = Buffer.from(a._keys.userKey);
    await a.setSettings({ remember: true });
    assert.equal(a.status().remember, true);
    const file = fs.readdirSync(a.dir).find((f) => f.startsWith('remember-'));
    assert.ok(file);
    assert.ok(!fs.readFileSync(path.join(a.dir, file)).includes(userKey));
    a.lock();
    await a.unlockRemembered();
    assert.equal(a.status().unlocked, true);
    // a damaged file: turned off
    fs.writeFileSync(path.join(a.dir, file), 'garbage');
    a.lock();
    await assert.rejects(a.unlockRemembered(), code('remember_failed'));
    assert.equal(a.status().remember, false);
    await a.unlock({ password: PW });
    await a.setSettings({ remember: true });
    await a.setSettings({ remember: false });
    assert.ok(!fs.readdirSync(a.dir).some((f) => f.startsWith('remember-')));
    const none = device(srv, 2, 'other', { protect: null });
    assert.equal(none.status().rememberAvailable, false);
  });

  it('delete account: the copy and the remembered key go', async () => {
    const srv = vaultServer();
    const protect = { available: () => true, encrypt: (b) => Buffer.from(b), decrypt: (b) => Buffer.from(b) };
    const a = device(srv, 2, 'pc', { protect });
    await setUp(a);
    await a.setSettings({ remember: true });
    await a.save({ vaultId: personal(a), data: login('Weg') });
    await a.sync();
    await assert.rejects(a.deleteAccount({ confirm: 'yes' }), code('invalid'));
    const st = await a.deleteAccount({ confirm: 'DELETE' });
    assert.equal(st.account, 'none');
    assert.equal(st.unlocked, false);
    assert.equal(srv.accounts.size, 0);
    await a.flush();
    assert.deepEqual(fs.readdirSync(a.dir).filter((f) => f.startsWith('vault-') || f.startsWith('remember-')), []);
  });

  it('a new server locks and loads that login\'s copy', async () => {
    const srv = vaultServer();
    const a = device(srv, 2);
    await setUp(a);
    const other = vaultServer();
    a.api = other.transport(3, 'pc');
    const st = await a.resetForNewServer();
    assert.equal(st.unlocked, false);
    await a.check();
    assert.equal(a.status().account, 'none');
  });
});

describe('VaultService: auto-lock, clipboard, generator, import, emergency, pushes', () => {
  it('auto-lock after the chosen minutes; touch() starts again; 0 locks when the window is hidden', async () => {
    const srv = vaultServer();
    const a = device(srv, 2, 'pc', { timing: { minuteMs: 40 } });
    await setUp(a);
    await assert.rejects(a.setSettings({ autoLockMinutes: 7 }), code('invalid'));
    await a.setSettings({ autoLockMinutes: 1 });
    for (let i = 0; i < 4; i++) {
      await wait(20);
      a.touch();
    }
    assert.equal(a.status().unlocked, true, 'activity keeps it open');
    await wait(80);
    assert.equal(a.status().unlocked, false);
    assert.equal(a.status().lastLock.reason, 'timeout');
    await a.setSettings({ autoLockMinutes: 0 });
    await a.unlock({ password: PW });
    a.windowHidden();
    assert.equal(a.status().lastLock.reason, 'hidden');
    const again = device(srv, 2, 'pc', { dir: a.dir });
    assert.equal(again.settings().autoLockMinutes, 0, 'kept in settings.json');
    assert.deepEqual(again.settings().choices, [0, 1, 5, 15, 60]);
  });

  it('copy: the clipboard is cleared after the time — only when it still holds the secret', async () => {
    const srv = vaultServer();
    const clip = { text: '', writeText(t) { this.text = t; }, readText() { return this.text; }, clear() { this.text = ''; } };
    const a = device(srv, 2, 'pc', { clipboard: clip, timing: { clipboardMs: 30 } });
    await setUp(a);
    const secret = 'JBSWY3DPEHPK3PXP';
    const { id } = await a.save({ vaultId: personal(a), data: login('Mail', 'Pass-wort-1', { fields: { username: 'anna', password: 'Pass-wort-1', totp: secret } }) });
    const r = await a.copy({ id, field: 'password' });
    assert.equal(r.clearsInMs, 30);
    assert.equal(clip.text, 'Pass-wort-1');
    await wait(60);
    assert.equal(clip.text, '');
    await a.copy({ id, field: 'username' });
    clip.text = 'was anderes';
    await wait(60);
    assert.equal(clip.text, 'was anderes', 'the person copied something else meanwhile');
    await a.copy({ id, field: 'totp' });
    assert.match(clip.text, /^\d{6}$/);
    const t = await a.totp({ id });
    assert.equal(t.digits, 6);
    assert.equal(t.period, 30);
    await assert.rejects(a.copy({ id, field: 'cvc' }), code('empty'));
    await a.copy({ text: 'generiert' });
    assert.equal(clip.text, 'generiert');
    const none = device(srv, 2, 'x');
    await assert.rejects(none.copy({ text: 'x' }), code('unsupported'));
    // locking clears it at once (still only when it holds our copy)
    await a.copy({ id, field: 'password' });
    a.lock();
    assert.equal(clip.text, '');
  });

  it('copy: the asynchronous clipboard of Electron 44 (readText / writeText return Promises) is cleared too', async () => {
    const srv = vaultServer();
    let text = '';
    const clip = {
      writeText: async (t) => { await wait(1); text = t; },
      readText: async () => { await wait(1); return text; },
      clear: () => { text = ''; },
    };
    const a = device(srv, 2, 'pc', { clipboard: clip, timing: { clipboardMs: 30 } });
    await setUp(a);
    await a.copy({ text: 'Geheim-async-1' });
    assert.equal(text, 'Geheim-async-1', 'written before copy() answers');
    await wait(80);
    assert.equal(text, '', 'cleared after the time');
    await a.copy({ text: 'Geheim-async-2' });
    text = 'was anderes';
    await wait(80);
    assert.equal(text, 'was anderes', 'the person copied something else meanwhile');
    await a.copy({ text: 'Geheim-async-3' });
    a.lock();
    await wait(10);
    assert.equal(text, '', 'locking clears it');
  });

  it('a check while setting up keeps the setup (there was no account to lock)', async () => {
    const s = device(vaultServer(), 2, 'pc');
    await s.check();
    const { recoveryKey } = await s.setup({ password: PW });
    assert.ok(recoveryKey);
    await s.check();
    assert.equal(s.status().setupPending, true);
    await s.confirmSetup();
    assert.equal(s.status().account, 'ready');
  });

  it('a setup not yet confirmed does not survive a lock', async () => {
    const s = device(vaultServer(), 2, 'pc');
    await s.check();
    await s.setup({ password: PW });
    assert.equal(s.status().setupPending, true);
    s.lock('system');
    assert.equal(s.status().setupPending, false);
    await assert.rejects(s.confirmSetup(), code('no_setup'));
  });

  it('generator and strength', () => {
    const a = device(vaultServer(), 2);
    const g = a.generate({ length: 24 });
    assert.equal(g.password.length, 24);
    assert.ok(['strong', 'very_strong'].includes(g.strength));
    assert.equal(a.generate({ words: true, wordCount: 5 }).password.split('-').length, 5);
    assert.deepEqual(a.strength(PW), { strength: 'very_strong', bits: Math.round(vault.passwordBits(PW)), good: true, words: 4 });
  });

  it('import: a preview without secrets, duplicates left out', async () => {
    const srv = vaultServer();
    const a = device(srv, 2);
    await setUp(a);
    const csv = 'name,url,username,password,note\nBank,https://bank.de,anna,Bank-Geheim-1,\nShop,https://shop.de,bob,Shop-Geheim-2,\n,,,,Nur eine Notiz\n';
    await assert.rejects(a.importParse('{"encrypted":true}'), code('import_encrypted'));
    await assert.rejects(a.importParse('hallo'), code('import_unknown'));
    const p = await a.importParse(csv, { vaultId: personal(a) });
    assert.equal(p.source, 'Chrome / Edge');
    assert.deepEqual(p.counts, { total: 3, logins: 2, withTotp: 0, notes: 1, cards: 0 });
    assert.equal(p.duplicates, 0);
    assert.ok(!JSON.stringify(p).includes('Geheim'));
    assert.deepEqual(await a.importSave(personal(a)), { saved: 3, skipped: 0 });
    await a.sync();
    assert.equal(srv.items.size, 3);
    await assert.rejects(a.importSave(personal(a)), code('no_import'));
    const again = await a.importParse(csv);
    assert.equal(again.duplicates, 3);
    assert.ok(again.preview.every((x) => x.duplicate));
    assert.deepEqual(await a.importSave(personal(a)), { saved: 0, skipped: 3 });
  });

  it('emergency access: request, approve, open read-only', async () => {
    const srv = vaultServer();
    const anna = device(srv, 2, 'anna');
    const marc = device(srv, 3, 'marc');
    await setUp(anna);
    await setUp(marc);
    const { id: entryId } = await anna.save({ vaultId: personal(anna), data: login('Testament', 'Sehr-Geheim-9') });
    await anna.sync();
    await assert.rejects(anna.emergencyAdd(3, 0), code('invalid'));
    const e = await anna.emergencyAdd(3, 48);
    assert.deepEqual([e.grantee.name, e.status, e.waitHours], ['Marc', 'ready', 48]);
    const got = await marc.emergency();
    assert.deepEqual(got.received.map((x) => [x.grantor.name, x.status]), [['Anna', 'ready']]);
    await assert.rejects(marc.emergencyOpen(e.id), code('forbidden'));
    assert.equal((await marc.emergencyStep(e.id, 'request')).status, 'requested');
    assert.equal((await anna.emergencyStep(e.id, 'approve')).status, 'granted');
    const view = await marc.emergencyOpen(e.id);
    assert.equal(view.grantor.name, 'Anna');
    assert.deepEqual(view.vaults.map((v) => [v.kind, v.name]), [['personal', 'Persönlich']]);
    assert.deepEqual(view.entries.map((x) => x.title), ['Testament']);
    assert.ok(!JSON.stringify(view).includes('Sehr-Geheim-9'));
    assert.equal((await marc.entry(entryId, { emergencyId: e.id })).data.fields.password, 'Sehr-Geheim-9');
    marc.lock();
    await marc.unlock({ password: PW });
    await assert.rejects(marc.entry(entryId, { emergencyId: e.id }), code('not_found'), 'gone with the lock');
    await anna.emergencyRemove(e.id);
    assert.deepEqual((await anna.emergency()).granted, []);
  });

  it('pushes start a sync and reach the page; a toast click opens it while the plugin is there', async () => {
    const srv = vaultServer();
    const nc = new EventEmitter();
    const routes = new Map();
    nc.addClickRoute = (route, fn) => { routes.set(route, fn); return () => routes.delete(route); };
    const a = device(srv, 2, 'pc', { notificationCenter: nc });
    await setUp(a);
    const pushes = [];
    a.on('push', (p) => pushes.push(p));
    a.start();
    await a.sync();
    const n = srv.calls.filter((c) => c.path.endsWith('/sync')).length;
    const entry = { id: 77, topic: 'plugin:gatecontrol-vault:share', data: { route: 'plg-gatecontrol-vault', vault: { topic: 'share', event: 'shared', vault: personal(a) } } };
    nc.emit('new', entry);
    nc.emit('new', { id: 78, topic: 'devices', data: {} });
    await a.sync();
    assert.deepEqual(pushes, [{ topic: 'share', event: 'shared', vaultId: personal(a), emergencyId: null, page: 'home', notificationId: 77 }]);
    assert.ok(srv.calls.filter((c) => c.path.endsWith('/sync')).length > n, 'synced');
    assert.equal(routes.get('plg-gatecontrol-vault')(entry).page, 'home');
    srv.plugin = false;
    await a.check();
    assert.equal(routes.get('plg-gatecontrol-vault')(entry), null, 'plugin gone → the inbox');
    a.stop();
    assert.equal(routes.size, 0);
  });
});

describe('vault:* IPC', () => {
  function register(s) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', vault: s,
    });
    return { handlers, sent };
  }

  it('channels, argument checks, secrets only on request, events', async () => {
    const srv = vaultServer();
    const clip = { text: '', writeText(t) { this.text = t; }, readText() { return this.text; } };
    const s = device(srv, 2, 'pc', { clipboard: clip });
    const { handlers, sent } = register(s);
    const call = (ch, arg) => handlers[ch](null, arg);
    assert.equal((await call('vault:check')).status.state, 'available');
    assert.equal(sent.at(-1)[0], 'vault:state');
    assert.equal((await call('vault:setup', { password: 42 })).code, 'invalid');
    assert.equal((await call('vault:setup', { password: 'kurz' })).code, 'weak_password');
    const su = await call('vault:setup', { password: PW });
    assert.equal(su.ok, true);
    assert.ok(su.recoveryKey);
    assert.equal((await call('vault:setup:confirm')).status.unlocked, true);
    assert.equal((await call('vault:sync')).ok, true);
    const pv = (await call('vault:vaults')).vaults[0].id;
    assert.equal((await call('vault:save', { vaultId: pv, data: { type: 'spaceship' } })).code, 'invalid');
    const saved = await call('vault:save', { vaultId: pv, data: login('IPC', 'Ipc-Geheim-1') });
    assert.equal(saved.ok, true);
    await call('vault:sync');
    const list = await call('vault:entries', {});
    assert.equal(list.entries.length, 1);
    assert.ok(!JSON.stringify(list).includes('Ipc-Geheim-1'));
    assert.equal((await call('vault:entry', { id: saved.id })).entry.data.fields.password, 'Ipc-Geheim-1');
    assert.equal((await call('vault:entry', { id: '../x' })).code, 'invalid');
    assert.deepEqual((await call('vault:match', { domain: 'https://login.bank.example.de/x' })).entries.map((e) => e.title), ['IPC']);
    assert.deepEqual((await call('vault:match', { domain: 'evil.de' })).entries, []);
    assert.equal((await call('vault:copy', { id: saved.id, field: 'password' })).ok, true);
    assert.equal(clip.text, 'Ipc-Geheim-1');
    assert.equal((await call('vault:generate', { length: 16 })).password.length, 16);
    assert.equal((await call('vault:strength', { password: PW })).good, true);
    assert.equal((await call('vault:totp', { uri: 'JBSWY3DPEHPK3PXP' })).digits, 6);
    assert.equal((await call('vault:settings:set', { autoLockMinutes: 3 })).code, 'invalid');
    assert.equal((await call('vault:settings:set', { autoLockMinutes: 15 })).autoLockMinutes, 15);
    assert.equal((await call('vault:settings:get')).autoLockMinutes, 15);
    assert.equal((await call('vault:emergencyStep', { id: 'a'.repeat(24), step: 'explode' })).code, 'invalid');
    assert.equal((await call('vault:deleteAccount', { confirm: 'ja' })).code, 'invalid');
    assert.equal((await call('vault:lock')).status.unlocked, false);
    assert.equal((await call('vault:entries')).code, 'locked');
    assert.equal((await call('vault:unlock', { password: 'Falsch-Falsch-Falsch-1' })).code, 'wrong_password');
    assert.equal((await call('vault:unlock', { password: PW })).ok, true);
    assert.equal(call('vault:status').unlocked, true);
    s.emit('push', { topic: 'share' });
    assert.deepEqual(sent.at(-1), ['vault:push', { topic: 'share' }]);
  });

  it('vault:wifi-scan: unlocked only, counts as activity, codes of the scan', async () => {
    const srv = vaultServer();
    let answer = [{ ssid: 'Heim', security: 'WPA2/WPA3', signal: 80, connected: true }];
    let scans = 0;
    const wifiScan = async () => {
      scans++;
      if (answer instanceof Error) throw answer;
      return answer;
    };
    const s = device(srv, 2, 'pc', { wifiScan });
    const { handlers } = register(s);
    const call = (ch, arg) => handlers[ch](null, arg);
    await setUp(s);
    s.lock('manual');
    assert.equal((await call('vault:wifi-scan')).code, 'locked');
    assert.equal(scans, 0, 'no scan while locked');
    await s.unlock({ password: PW });
    let touched = 0;
    const touch = s.touch.bind(s);
    s.touch = () => { touched++; touch(); };
    assert.deepEqual(await call('vault:wifi-scan'), { ok: true, networks: answer });
    assert.equal(touched, 1, 'the person asked for it: activity');
    for (const code of ['no_adapter', 'service_off', 'radio_off', 'location_denied']) {
      answer = Object.assign(new Error(code), { code, win32: 5 });
      const r = await call('vault:wifi-scan');
      assert.deepEqual([r.ok, r.code], [false, code]);
    }
    answer = Object.assign(new Error('boom'), { code: 'EWHATEVER' });
    assert.equal((await call('vault:wifi-scan')).code, 'failed');
    answer = new TypeError('boom');
    assert.equal((await call('vault:wifi-scan')).code, 'failed');
  });

  it('vault:totp-qr: unlocked only, counts as activity, sources checked, codes, URIs never logged', async () => {
    const srv = vaultServer();
    const URI = 'otpauth://totp/Example:anna@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    let answer = [URI];
    const scans = [];
    const totpQr = async (opts) => {
      scans.push(opts);
      if (answer instanceof Error) throw answer;
      return answer;
    };
    const lines = [];
    const qrLog = { info: (m) => lines.push(m), warn: (m) => lines.push(m), debug: (m) => lines.push(m), error: (m) => lines.push(m) };
    const s = device(srv, 2, 'pc', { totpQr, log: qrLog });
    const { handlers } = register(s);
    const call = (ch, arg) => handlers[ch](null, arg);
    await setUp(s);
    s.lock('manual');
    assert.equal((await call('vault:totp-qr', { source: 'screen' })).code, 'locked');
    assert.equal(scans.length, 0, 'no scan while locked');
    await s.unlock({ password: PW });
    for (const bad of [undefined, {}, { source: 'camera' }, { source: 1 }, { source: 'SCREEN' }]) {
      assert.equal((await call('vault:totp-qr', bad)).code, 'invalid', JSON.stringify(bad));
    }
    assert.equal(scans.length, 0);
    let touched = 0;
    const touch = s.touch.bind(s);
    s.touch = () => { touched++; touch(); };
    for (const source of ['screen', 'clipboard', 'file']) {
      assert.deepEqual(await call('vault:totp-qr', { source }), { ok: true, uris: [URI] });
      assert.equal(scans.at(-1).source, source);
      assert.equal(typeof scans.at(-1).getWindow, 'function', 'the main window for the dialog / hiding');
    }
    assert.equal(touched, 3, 'the person asked for it: activity');
    for (const c of ['none_found', 'hotp', 'invalid_code', 'no_image', 'unsupported', 'cancelled']) {
      answer = Object.assign(new Error(c), { code: c });
      const r = await call('vault:totp-qr', { source: 'clipboard' });
      assert.deepEqual([r.ok, r.code], [false, c]);
    }
    answer = [];
    assert.equal((await call('vault:totp-qr', { source: 'screen' })).code, 'none_found');
    answer = Object.assign(new Error('boom'), { code: 'EWHATEVER' });
    assert.equal((await call('vault:totp-qr', { source: 'screen' })).code, 'failed');
    answer = new TypeError('boom');
    assert.equal((await call('vault:totp-qr', { source: 'screen' })).code, 'failed');
    // locked while the scan ran (auto-lock): the keys found do not leave
    answer = [URI];
    const slow = s._totpQr;
    s._totpQr = async (o) => { const r = await slow(o); s.lock('manual'); return r; };
    assert.equal((await call('vault:totp-qr', { source: 'screen' })).code, 'locked');
    s._totpQr = slow;
    assert.ok(lines.length > 0);
    assert.ok(!lines.some((l) => /otpauth|JBSWY3DP/i.test(String(l))), 'no URI / secret in the log');
  });

  it('vault:totp-qr: one scan at a time (a second call waits for the first)', async () => {
    const srv = vaultServer();
    let running = 0;
    let most = 0;
    const totpQr = async ({ source }) => {
      running++;
      most = Math.max(most, running);
      await new Promise((r) => setTimeout(r, 20));
      running--;
      return [`otpauth://totp/${source}?secret=JBSWY3DPEHPK3PXP`];
    };
    const s = device(srv, 2, 'pc', { totpQr });
    await setUp(s);
    const [a, b] = await Promise.all([s.totpQr({ source: 'screen' }), s.totpQr({ source: 'file' })]);
    assert.equal(most, 1);
    assert.deepEqual([a.uris[0], b.uris[0]], ['otpauth://totp/screen?secret=JBSWY3DPEHPK3PXP', 'otpauth://totp/file?secret=JBSWY3DPEHPK3PXP']);
  });

  it('VaultService.wifiScan uses services/wifi-scan by default (no_adapter off Windows)', { skip: process.platform === 'win32' ? 'Windows: a real scan' : false }, async () => {
    const srv = vaultServer();
    const s = device(srv, 2);
    await setUp(s);
    await assert.rejects(s.wifiScan(), code('no_adapter'));
  });

  it('nothing is registered without a VaultService', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.ok(!Object.keys(handlers).some((c) => c.startsWith('vault:')));
  });
});
