'use strict';

// Vault "Mit Windows Hello entsperren": the wrapping (utils/vault-hello.js) and VaultService's state machine with a
// fake Hello provider (RSA keys of node:crypto, PKCS#1 v1.5 like Windows; answers chosen per test) — turning it on
// (unlocked + master password, then the prompt), unlocking, failed / cancelled tries and the fallback to the master
// password, a Hello key that is gone or changed, password change / recovery (the user key stays), delete account,
// account gone, the DPAPI record on disk, IPC — and once end to end through services/windows-hello.js on the fake
// WinRT (fixtures/fake-winrt.js).

const { describe, it, after, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
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
const vc = require('../src/utils/vault-crypto');
const vh = require('../src/utils/vault-hello');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { vaultServer } = require('./fixtures/vault-server');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const KDF = { m: 19456, t: 2 };
const PW = 'Sonnenblume-Kanu-Turm-47';
const PW2 = 'Leuchtturm-Mond-Fahrrad-92';
const code = (c) => (e) => e && e.code === c;

const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });
before(() => vc.ready());

function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-hello-'));
  dirs.push(d);
  return d;
}

const xor = (buf) => Buffer.from(Buffer.from(buf).map((x) => x ^ 0x5a));
function dpapi() {
  return {
    on: true,
    calls: 0,
    available() { return this.on; },
    encrypt(b) { this.calls++; return Buffer.concat([Buffer.from('DPAPI'), xor(b)]); },
    decrypt(b) { if (b.subarray(0, 5).toString() !== 'DPAPI') throw new Error('bad'); return xor(b.subarray(5)); },
  };
}

const KEYS = [];
function rsa() {
  if (!KEYS.length) for (let i = 0; i < 3; i++) KEYS.push(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }));
  return KEYS[Math.floor(Math.random() * KEYS.length)];
}
const pkcs1 = (privateKey, data) => crypto.sign('sha256', data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });

/** A Windows Hello provider: keys by name, the next prompt's answer in `next`, every prompt in `prompts`. */
function fakeHello() {
  const f = {
    avail: { available: true, reason: null },
    next: [],
    prompts: [],
    removed: [],
    keys: new Map(),
    scheme: 'pkcs1',   // 'pkcs1' | 'hmac' (deterministic, other scheme) | 'random' (not deterministic)
    answer() { return f.next.length ? f.next.shift() : 'ok'; },
    sig(key, data) {
      if (f.scheme === 'hmac') return Buffer.from(crypto.hkdfSync('sha256', key.secret, data, 'other-scheme', 256));
      if (f.scheme === 'random') return crypto.randomBytes(256);
      return pkcs1(key.privateKey, data);
    },
    async available() { return f.avail; },
    async create(name, challenge) {
      f.prompts.push(['create', name]);
      const a = f.answer();
      if (a !== 'ok') return { status: a };
      const { privateKey, publicKey } = rsa();
      const key = { privateKey, spki: publicKey.export({ type: 'spki', format: 'der' }), secret: crypto.randomBytes(32) };
      f.keys.set(name, key);
      return { status: 'ok', publicKey: Buffer.from(key.spki), signature: f.sig(key, challenge) };
    },
    async sign(name, challenge) {
      const key = f.keys.get(name);
      if (!key) return { status: 'not_found' };
      f.prompts.push(['sign', name]);
      const a = f.answer();
      if (a !== 'ok') return { status: a };
      return { status: 'ok', signature: f.sig(key, challenge) };
    },
    async remove(name) {
      f.removed.push(name);
      return { status: f.keys.delete(name) ? 'ok' : 'not_found' };
    },
  };
  return f;
}

function device(srv, uid, extra = {}) {
  const dir = extra.dir || tmpDir();
  const hello = 'hello' in extra ? extra.hello : fakeHello();
  const protect = 'protect' in extra ? extra.protect : dpapi();
  const s = new VaultService({
    api: srv.transport(uid, extra.name || 'pc'), dir, kdf: KDF, deviceName: 'pc', log, protect, hello,
    timing: { recheckMs: 1e9, retryMinMs: 1e9, syncMs: 1e9 }, helloName: extra.helloName,
  });
  return { s, hello, protect, dir };
}

async function setUp(s, password = PW) {
  await s.check();
  const { recoveryKey } = await s.setup({ password });
  await s.confirmSetup();
  await s.sync();
  return recoveryKey;
}

const helloFile = (dir) => fs.readdirSync(dir).find((f) => f.startsWith('hello-'));

describe('vault-hello: wrapping', () => {
  it('seal / open: the user key comes back only with the signature of the same key and challenge', () => {
    const { privateKey, publicKey } = rsa();
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const challenge = vh.newChallenge();
    const userKey = crypto.randomBytes(32);
    const sig = pkcs1(privateKey, challenge);
    const name = vh.keyName('GateControl Pro Vault', 'a'.repeat(32));
    assert.equal(name, `GateControl Pro Vault ${'a'.repeat(32)}`);
    const rec = vh.seal({ keyName: name, challenge, publicKey: spki, signature: sig, check: 'pkcs1', userKey: new Uint8Array(userKey) });
    const json = vh.encodeRecord(rec).toString();
    for (const secret of [userKey, sig, Buffer.from(vh.wrappingKey(sig, challenge))]) {
      assert.ok(!json.includes(secret.toString('base64url')), 'no key material in the record');
      assert.ok(!json.includes(secret.toString('base64')));
      assert.ok(!json.includes(secret.toString('hex')));
    }
    assert.deepEqual(Buffer.from(vh.open(JSON.parse(json), sig)), userKey);

    // another Hello key (Hello reset), another challenge, a tampered record
    const other = KEYS.find((k) => k.privateKey !== privateKey) || crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    assert.throws(() => vh.open(rec, pkcs1(other.privateKey, challenge)), (e) => e.code === 'signature');
    assert.throws(() => vh.open({ ...rec, check: 'repeat' }, pkcs1(other.privateKey, challenge)), (e) => e.code === 'invalid');
    assert.throws(() => vh.open({ ...rec, keyName: 'GateControl Pro Vault b' }, sig), (e) => e.code === 'invalid', 'the AD binds the key name');
    const w = Buffer.from(rec.wrapped, 'base64url');
    w[w.length - 1] ^= 1;
    assert.throws(() => vh.open({ ...rec, wrapped: w.toString('base64url') }, sig), (e) => e.code === 'invalid');
    assert.throws(() => vh.open({ v: 2 }, sig), (e) => e.code === 'invalid');
  });

  it('the wrapping key: HKDF-SHA256 of the signature, salted by the challenge (fixed vector)', () => {
    const sig = Buffer.alloc(256, 7);
    const challenge = Buffer.alloc(32, 1);
    const expected = crypto.hkdfSync('sha256', sig, challenge, 'gcv1:hello-wrap-key', 32);
    assert.deepEqual(Buffer.from(vh.wrappingKey(sig, challenge)), Buffer.from(expected));
    assert.equal(Buffer.from(vh.wrappingKey(sig, challenge)).toString('hex'), Buffer.from(expected).toString('hex'));
    assert.throws(() => vh.wrappingKey(Buffer.alloc(10), challenge), (e) => e.code === 'signature');
  });

  it('only RSA ≥ 2048 public keys, only PKCS#1 v1.5 / SHA-256 signatures', () => {
    const { privateKey, publicKey } = rsa();
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const c = vh.newChallenge();
    assert.equal(vh.verifies(spki, c, pkcs1(privateKey, c)), true);
    const pss = crypto.sign('sha256', c, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
    assert.equal(vh.verifies(spki, c, pss), false);
    const small = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    assert.equal(vh.rsaKey(small.publicKey.export({ type: 'spki', format: 'der' })), null);
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    assert.equal(vh.rsaKey(ec.publicKey.export({ type: 'spki', format: 'der' })), null);
    assert.equal(vh.rsaKey(Buffer.from('junk')), null);
    assert.throws(() => vh.seal({ keyName: 'k', challenge: c, publicKey: spki, signature: pss, check: 'pkcs1', userKey: new Uint8Array(32) }), (e) => e.code === 'signature');
    assert.throws(() => vh.keyName('x', 'not-hex'), (e) => e.code === 'invalid');
  });

  it('parseRecord accepts only the known shape', () => {
    assert.equal(vh.parseRecord('nope'), null);
    assert.equal(vh.parseRecord(Buffer.from('{"v":1}')), null);
    assert.equal(vh.parseRecord({ v: 1, keyName: 'k', challenge: 'AA', publicKey: 'AA', check: 'pkcs1', wrapped: 'A+' }), null);
    assert.deepEqual(vh.parseRecord({ v: 1, keyName: 'k', challenge: 'AA', publicKey: 'AA', check: 'repeat', wrapped: 'AA', extra: 1 }),
      { v: 1, keyName: 'k', challenge: 'AA', publicKey: 'AA', check: 'repeat', wrapped: 'AA' });
  });
});

describe('VaultService: Windows Hello', () => {
  it('without a provider or DPAPI: not offered, with a reason', async () => {
    const srv = vaultServer();
    const { s } = device(srv, 2, { hello: null });
    await setUp(s);
    const st = s.status();
    assert.deepEqual([st.hello, st.helloAvailable, st.helloReason], [false, false, 'unsupported_os']);
    await assert.rejects(s.setHello({ on: true, password: PW }), code('unsupported'));
    assert.deepEqual(await s.checkHello(), { available: false, reason: 'unsupported_os' });

    const d = device(srv, 2, { name: 'b', protect: { available: () => false } });
    await d.s.check();
    await d.s.checkHello();
    assert.deepEqual([d.s.status().helloAvailable, d.s.status().helloReason], [false, 'no_protect']);

    const n = device(srv, 2, { name: 'c' });
    n.hello.avail = { available: false, reason: 'remote_session' };
    await n.s.checkHello();
    assert.deepEqual([n.s.settings().helloAvailable, n.s.settings().helloReason], [false, 'remote_session']);
  });

  it('turning on: unlocked, the master password, then Hello; the record on disk is DPAPI-protected, no raw key', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2, { helloName: 'GateControl Pro Vault' });
    await setUp(s);
    await s.checkHello();
    assert.deepEqual([s.status().hello, s.status().helloAvailable, s.status().helloReason], [false, true, null]);
    s.lock();
    await assert.rejects(s.setHello({ on: true, password: PW }), code('locked'));
    await s.unlock({ password: PW });
    await assert.rejects(s.setHello({ on: true }), code('invalid'));
    await assert.rejects(s.setHello({ on: true, password: 'Falsch-Falsch-Falsch-1' }), code('wrong_password'));
    assert.equal(hello.prompts.length, 0, 'no prompt before the password is right');

    hello.next = ['cancelled'];
    await assert.rejects(s.setHello({ on: true, password: PW }), code('hello_cancelled'));
    assert.equal(helloFile(dir), undefined);
    assert.equal(s.status().hello, false);

    await s.setSettings({ remember: true });
    const userKey = Buffer.from(s._keys.userKey);
    const st = await s.setHello({ on: true, password: PW });
    assert.equal(st.hello, true);
    assert.equal(st.remember, false, 'replaces "remember unlock"');
    assert.ok(!fs.readdirSync(dir).some((f) => f.startsWith('remember-')));
    assert.deepEqual(hello.prompts.map((p) => p[0]), ['create', 'create']);
    assert.match(hello.prompts[1][1], /^GateControl Pro Vault [0-9a-f]{32}$/);
    const raw = fs.readFileSync(path.join(dir, helloFile(dir)));
    assert.equal(raw.subarray(0, 5).toString(), 'DPAPI');
    assert.ok(!raw.includes(userKey));
    assert.ok(!xor(raw.subarray(5)).includes(userKey));
    assert.ok(!xor(raw.subarray(5)).toString().includes(userKey.toString('base64url')));
    assert.equal(vh.parseRecord(xor(raw.subarray(5))).check, 'pkcs1');
    await assert.rejects(s.setSettings({ remember: true }), code('hello_on'));
  });

  it('unlock: one prompt, the keys open; auto-lock still applies; a second call shares the prompt', async () => {
    const srv = vaultServer();
    const { s, hello } = device(srv, 2);
    await setUp(s);
    await s.save({ vaultId: s._state.vaults[0].id, data: { type: 'login', title: 'Bank', fields: { username: 'a', password: 'x' } } });
    await s.setHello({ on: true, password: PW });
    s.lock();
    await assert.rejects(s.unlockRemembered(), code('not_remembered'));
    const before = hello.prompts.length;
    const [a, b] = await Promise.all([s.unlockHello(), s.unlockHello()]);
    assert.equal(a.unlocked, true);
    assert.equal(b.unlocked, true);
    assert.equal(hello.prompts.length - before, 1);
    assert.deepEqual((await s.entries()).entries.map((e) => e.title), ['Bank']);
    assert.ok(s._lockTimer, 'the auto-lock timer runs');
    // already open: no prompt
    await s.unlockHello();
    assert.equal(hello.prompts.length - before, 1);
  });

  it(`after ${vh.MAX_FAILS} failed or cancelled tries only the master password; it resets the count`, async () => {
    const srv = vaultServer();
    const { s, hello } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    s.lock();
    hello.next = ['cancelled', 'failed', 'locked'];
    await assert.rejects(s.unlockHello(), code('hello_cancelled'));
    assert.equal(s.status().helloBlocked, false);
    await assert.rejects(s.unlockHello(), code('hello_failed'));
    await assert.rejects(s.unlockHello(), code('hello_locked'));
    assert.equal(s.status().helloBlocked, true);
    const prompts = hello.prompts.length;
    await assert.rejects(s.unlockHello(), code('hello_blocked'));
    assert.equal(hello.prompts.length, prompts, 'no further prompt');
    assert.equal(s.status().hello, true, 'still on');
    await s.unlock({ password: PW });
    assert.equal(s.status().helloBlocked, false);
    s.lock();
    // "use the password instead" in the Hello dialog: straight to the password
    hello.next = ['prefers_password'];
    await assert.rejects(s.unlockHello(), code('hello_cancelled'));
    assert.equal(s.status().helloBlocked, true);
    await s.unlock({ password: PW });
    s.lock();
    await s.unlockHello();
    assert.equal(s.status().unlocked, true);
  });

  it('the Hello key is gone (Hello reset, PIN removed) or another one answers: turned off, master password', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    s.lock();
    hello.keys.clear();
    await assert.rejects(s.unlockHello(), code('hello_invalid'));
    assert.equal(s.status().hello, false);
    assert.equal(helloFile(dir), undefined);
    await assert.rejects(s.unlockHello(), code('hello_off'));

    await s.unlock({ password: PW });
    await s.setHello({ on: true, password: PW });
    const name = [...hello.keys.keys()][0];
    s.lock();
    // a new key under the same name (made again outside of this app)
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    hello.keys.set(name, { privateKey: other.privateKey, spki: other.publicKey.export({ type: 'spki', format: 'der' }) });
    await assert.rejects(s.unlockHello(), code('hello_invalid'));
    assert.equal(s.status().hello, false);
    assert.ok(hello.removed.includes(name));
  });

  it('a damaged record or one DPAPI cannot open: turned off', async () => {
    const srv = vaultServer();
    const { s, dir } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    s.lock();
    fs.writeFileSync(path.join(dir, helloFile(dir)), 'garbage');
    await assert.rejects(s.unlockHello(), code('hello_invalid'));
    assert.equal(s.status().hello, false);
  });

  it('a signature scheme that is not PKCS#1: kept only when it repeats; random signatures are refused', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2);
    await setUp(s);
    hello.scheme = 'random';
    await assert.rejects(s.setHello({ on: true, password: PW }), code('hello_failed'));
    assert.equal(helloFile(dir), undefined);
    assert.equal(hello.keys.size, 0, 'the unusable key is deleted');
    hello.scheme = 'hmac';
    await s.setHello({ on: true, password: PW });
    assert.equal(vh.parseRecord(xor(fs.readFileSync(path.join(dir, helloFile(dir))).subarray(5))).check, 'repeat');
    s.lock();
    await s.unlockHello();
    assert.equal(s.status().unlocked, true);
  });

  it('a new master password and a recovery keep Hello working (the user key does not change)', async () => {
    const srv = vaultServer();
    const { s } = device(srv, 2);
    const rk = await setUp(s);
    await s.setHello({ on: true, password: PW });
    await s.changePassword({ current: PW, password: PW2 });
    s.lock();
    await s.unlockHello();
    assert.equal(s.status().unlocked, true);
    s.lock();
    await s.recover({ recoveryKey: rk });
    await s.completeRecovery({ password: PW });
    s.lock();
    await s.unlockHello();
    assert.equal(s.status().unlocked, true);
    assert.equal(s.status().hello, true);
    // turning it on again checks the current password
    await assert.rejects(s.setHello({ on: true, password: PW2 }), code('wrong_password'));
  });

  it('turning off: the record and the Windows Hello key go, also while locked', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    s.lock();
    const st = await s.setHello({ on: false });
    assert.equal(st.hello, false);
    assert.equal(helloFile(dir), undefined);
    assert.equal(hello.keys.size, 0);
    await assert.rejects(s.unlockHello(), code('hello_off'));
    await assert.rejects(s.setHello({ on: 'yes' }), code('invalid'));
  });

  it('delete account / account deleted on another device: record and key go', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    await s.deleteAccount({ confirm: 'DELETE' });
    await s.flush();
    assert.equal(helloFile(dir), undefined);
    assert.equal(hello.keys.size, 0);
    assert.equal(s.status().hello, false);

    const b = device(srv, 3);
    await setUp(b.s);
    await b.s.setHello({ on: true, password: PW });
    srv.accounts.delete(3);
    await b.s.refreshAccount();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(b.s.status().account, 'none');
    assert.equal(b.s.status().hello, false);
    assert.equal(helloFile(b.dir), undefined);
    assert.equal(b.hello.keys.size, 0);
  });

  it('a record of another account (deleted and set up again meanwhile): turned off, never opened', async () => {
    const srv = vaultServer();
    const { s, hello, dir } = device(srv, 2);
    await setUp(s);
    await s.setHello({ on: true, password: PW });
    const record = fs.readFileSync(path.join(dir, helloFile(dir)));
    const keys = new Map(hello.keys);
    await s.deleteAccount({ confirm: 'DELETE' });
    await setUp(s);
    // the old record and key back on disk / in Windows
    fs.writeFileSync(path.join(dir, `hello-${s._owner}.bin`), record);
    for (const [k, v] of keys) hello.keys.set(k, v);
    s._helloOn = true;
    s.lock();
    await assert.rejects(s.unlockHello(), code('hello_invalid'));
    assert.equal(s.status().unlocked, false);
    assert.equal(s.status().hello, false);
  });

  it('vault:* IPC: hello:check, hello:set (argument checks), unlockHello', async () => {
    const srv = vaultServer();
    const { s } = device(srv, 2);
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', vault: s,
    });
    const call = (ch, arg) => handlers[ch](null, arg);
    await setUp(s);
    assert.deepEqual(await call('vault:hello:check'), { ok: true, available: true, reason: null });
    assert.equal((await call('vault:hello:set', { on: true })).code, 'invalid');
    assert.equal((await call('vault:hello:set', { on: 1, password: PW })).code, 'invalid');
    assert.equal((await call('vault:hello:set', { on: true, password: 'x'.repeat(2000) })).code, 'invalid');
    const on = await call('vault:hello:set', { on: true, password: PW });
    assert.deepEqual([on.ok, on.hello], [true, true]);
    assert.equal((await call('vault:settings:get')).hello, true);
    await call('vault:lock');
    const r = await call('vault:unlockHello');
    assert.deepEqual([r.ok, r.status.unlocked], [true, true]);
    const off = await call('vault:hello:set', { on: false });
    assert.deepEqual([off.ok, off.hello], [true, false]);
    await call('vault:lock');
    assert.equal((await call('vault:unlockHello')).code, 'hello_off');
  });

  it('end to end through services/windows-hello.js on the fake WinRT (koffi COM objects)', async () => {
    const koffi = require('koffi');
    const { fakeWinRt } = require('./fixtures/fake-winrt');
    const { createWindowsHello } = require('../src/services/windows-hello');
    const rt = fakeWinRt(koffi);
    try {
      const hello = createWindowsHello({ platform: 'win32', koffi, api: rt.api, timing: { pollMs: 1 } });
      const srv = vaultServer();
      const { s } = device(srv, 2, { hello, helloName: 'GateControl Community Vault' });
      await setUp(s);
      assert.deepEqual(await s.checkHello(), { available: true, reason: null });
      // cancelled at the second prompt (the signature): the key just made is deleted again
      rt.next = ['ok', 'cancel'];
      await assert.rejects(s.setHello({ on: true, password: PW }), code('hello_cancelled'));
      assert.equal(rt.keys.size, 0);
      rt.prompts.length = 0;
      await s.setHello({ on: true, password: PW });
      assert.deepEqual(rt.prompts.map((p) => p.kind), ['create', 'sign']);
      // on again: nothing to do, no prompt (a new key would void the record)
      await s.setHello({ on: true, password: PW });
      assert.equal(rt.prompts.length, 2);
      s.lock();
      rt.next = 'cancel';
      await assert.rejects(s.unlockHello(), code('hello_cancelled'));
      await s.unlockHello();
      assert.equal(s.status().unlocked, true);
      rt.remote = true;
      await s.checkHello();
      assert.deepEqual([s.status().helloAvailable, s.status().helloReason, s.status().hello], [false, 'remote_session', true]);
      s.lock();
      await assert.rejects(s.unlockHello(), code('hello_unavailable'));
      rt.remote = false;
      await s.setHello({ on: false });
      assert.equal(rt.keys.size, 0);
      assert.deepEqual(rt.live(), []);
      assert.equal(rt.strings(), 0);
    } finally {
      rt.dispose();
    }
  });
});
