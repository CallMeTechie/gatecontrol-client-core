'use strict';

// Vault end-to-end encryption (plugin README "Kryptoformat"): the fixed vectors (Android checks the same file), the
// same bytes again from an independent implementation (OpenSSL's ChaCha20-Poly1305 and X25519 + HChaCha20 written
// here), and the flows: setup, unlock, wrong password, recovery, a new password, shared vault keys during a key
// change, entries bound to vault / id / revision, emergency access.

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vc = require('../src/utils/vault-crypto');
const V = require('./fixtures/vault-vectors.json');

const hex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const unb64 = (s) => Buffer.from(s, 'base64url');
let sodium;

before(async () => { sodium = await vc.ready(); });

const decryptError = (code) => (e) => e instanceof vc.VaultCryptoError && e.code === code;

describe('vault-crypto: fixed vectors', () => {
  it('master key: Argon2id; the same password in NFD gives the same key', () => {
    const m = V.masterKey;
    assert.equal(toHex(vc.masterKey(m.password, m.kdf)), m.key);
    assert.notEqual(m.passwordNfd, m.password);
    assert.equal(toHex(vc.masterKey(m.passwordNfd, m.kdf)), m.key);
  });

  it('wrap, vault name, entry, recovery key', () => {
    const { wrap, name, item, recoveryKey } = V;
    assert.equal(vc.b64(vc.wrap(hex(wrap.key), hex(wrap.plaintext), wrap.ad, hex(wrap.nonce))), wrap.wrapped);
    assert.equal(toHex(vc.unwrap(hex(wrap.key), wrap.wrapped, wrap.ad)), wrap.plaintext);
    assert.equal(vc.encryptName(hex(name.key), name.vaultId, name.name, hex(name.nonce)), name.nameEnc);
    assert.equal(vc.decryptName(hex(name.key), name.vaultId, name.nameEnc), name.name);
    const at = { vaultId: item.vaultId, itemId: item.itemId, rev: item.rev };
    assert.equal(vc.encryptItemBytes(hex(item.key), at, sodium.from_string(item.json), hex(item.nonce)), item.blob);
    assert.deepEqual(vc.decryptItem(hex(item.key), { id: item.itemId, vaultId: item.vaultId, rev: item.rev, blob: item.blob }), JSON.parse(item.json));
    assert.equal(vc.formatRecoveryKey(hex(recoveryKey.key)), recoveryKey.text);
    assert.equal(toHex(vc.parseRecoveryKey(recoveryKey.text)), recoveryKey.key);
  });

  it('a sealed box from the vector opens with the seeded key pair', () => {
    const s = V.sealed;
    const pair = sodium.crypto_box_seed_keypair(hex(s.seed));
    assert.deepEqual([toHex(pair.publicKey), toHex(pair.privateKey)], [s.publicKey, s.secretKey]);
    assert.equal(toHex(vc.openSealed(s.sealed, hex(s.publicKey), hex(s.secretKey))), s.key);
  });

  it('the whole account body', () => {
    const a = V.account;
    const r = a.rnd;
    const rnd = { userKey: hex(r.userKey), recoveryKey: hex(r.recoveryKey), keySeed: hex(r.keySeed), personalId: r.personalId,
      personalKey: hex(r.personalKey), nonces: r.nonces.map(hex) };
    const acc = vc.createAccount(a.password, a.personalName, { kdf: a.kdf, rnd });
    const { sealedKey, ...personal } = acc.body.personal;
    assert.deepEqual({ ...acc.body, personal }, a.body);
    assert.equal(acc.recoveryKey, a.recoveryKey);
    assert.equal(toHex(rnd.recoveryKey), r.recoveryKey, 'the caller\'s buffers stay as they were');
    assert.equal(toHex(vc.openSealed(sealedKey, acc.keys.publicKey, acc.keys.secretKey)), r.personalKey);
    const keys = vc.unlock({ ...a.body, rev: 1 }, a.password);
    assert.equal(toHex(keys.userKey), r.userKey);
    assert.equal(toHex(vc.unlockWithRecovery(a.body, a.recoveryKey).userKey), r.userKey);
  });
});

// ── an independent implementation: OpenSSL + HChaCha20 (RFC draft-irtf-cfrg-xchacha §2.2) ──

function hchacha20(key, nonce16) {
  const x = new Uint32Array(16);
  x.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) x[4 + i] = Buffer.from(key).readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) x[12 + i] = Buffer.from(nonce16).readUInt32LE(i * 4);
  const rotl = (v, c) => ((v << c) | (v >>> (32 - c))) >>> 0;
  const qr = (a, b, c, d) => {
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((w, i) => out.writeUInt32LE(x[w], i * 4));
  return out;
}

function opensslWrap(key, nonce, plaintext, ad) {
  const c = crypto.createCipheriv('chacha20-poly1305', hchacha20(key, nonce.subarray(0, 16)),
    Buffer.concat([Buffer.alloc(4), Buffer.from(nonce.subarray(16))]), { authTagLength: 16 });
  c.setAAD(Buffer.from(ad));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([Buffer.from([1]), Buffer.from(nonce), ct, c.getAuthTag()]);
}

// ISO/IEC 7816-4 (sodium_pad): 0x80, then zeros up to the block
const isoPad = (b, blk) => {
  const p = Buffer.concat([Buffer.from(b), Buffer.from([0x80])]);
  return Buffer.concat([p, Buffer.alloc((blk - (p.length % blk)) % blk)]);
};

describe('vault-crypto: the vectors from a second implementation (OpenSSL)', () => {
  it('HChaCha20 test vector of the XChaCha draft', () => {
    const key = hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const nonce = hex('000000090000004a0000000031415927');
    assert.equal(hchacha20(key, nonce).toString('hex'), '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc');
  });

  it('wrap, name, entry and the account fields are standard XChaCha20-Poly1305 with the documented AD', () => {
    const { wrap, name, item, account: a } = V;
    assert.deepEqual(opensslWrap(hex(wrap.key), hex(wrap.nonce), hex(wrap.plaintext), wrap.ad), unb64(wrap.wrapped));
    assert.deepEqual(opensslWrap(hex(name.key), hex(name.nonce), Buffer.from(name.name), `gcv1:vault-name:${name.vaultId}`), unb64(name.nameEnc));
    assert.deepEqual(opensslWrap(hex(item.key), hex(item.nonce), isoPad(Buffer.from(item.json), 256), `gcv1:item:${item.vaultId}:${item.itemId}:${item.rev}`), unb64(item.blob));
    const r = a.rnd;
    const sk = crypto.createHash('sha512').update(hex(r.keySeed)).digest().subarray(0, 32); // crypto_box_seed_keypair
    assert.deepEqual(opensslWrap(hex(V.masterKey.key), hex(r.nonces[0]), hex(r.userKey), 'gcv1:user-key:pw'), unb64(a.body.userKeyPw));
    assert.deepEqual(opensslWrap(hex(r.recoveryKey), hex(r.nonces[1]), hex(r.userKey), 'gcv1:user-key:rk'), unb64(a.body.userKeyRk));
    assert.deepEqual(opensslWrap(hex(r.userKey), hex(r.nonces[2]), sk, 'gcv1:private-key'), unb64(a.body.privateKeyEnc));
    assert.deepEqual(opensslWrap(hex(r.personalKey), hex(r.nonces[3]), Buffer.from(a.personalName), `gcv1:vault-name:${r.personalId}`), unb64(a.body.personal.nameEnc));
    // the public key is X25519 of that secret key
    const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), sk]), format: 'der', type: 'pkcs8' });
    const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
    assert.deepEqual(pub, unb64(a.body.publicKey));
    assert.equal(pub.toString('hex'), V.sealed.publicKey);
  });
});

// ── flows ──

const KDF = () => ({ ...vc.newKdf(), m: 19456, t: 2 }); // the server's minimum — fast tests

describe('vault-crypto: account', () => {
  it('setup → unlock; a wrong password, a tampered field', () => {
    const { body, keys, recoveryKey } = vc.createAccount('geheim 123', 'Persönlich', { kdf: KDF() });
    assert.match(recoveryKey, /^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.equal(unb64(body.userKeyPw).length, 73);
    assert.equal(unb64(body.personal.sealedKey).length, 80);
    assert.match(body.personal.id, /^[A-Za-z0-9_-]{22}$/);
    const k = vc.unlock(body, 'geheim 123');
    assert.deepEqual([k.userKey, k.secretKey], [keys.userKey, keys.secretKey]);
    assert.throws(() => vc.unlock(body, 'geheim 124'), decryptError('decrypt'));
    // the server swaps the two wrapped user keys: the AD tells
    assert.throws(() => vc.unlock({ ...body, userKeyPw: body.userKeyRk }, 'geheim 123'), decryptError('decrypt'));
    // a foreign key pair under the right user key would not match the public key
    const other = vc.createAccount('x', 'P', { kdf: KDF() });
    assert.throws(() => vc.unlock({ ...body, publicKey: other.body.publicKey }, 'geheim 123'), decryptError('decrypt'));
    assert.equal(vc.decryptName(keys.personalKey, body.personal.id, body.personal.nameEnc), 'Persönlich');
  });

  it('recovery key: typing it loosely works, a typo is caught by the check bytes', () => {
    const { body, keys, recoveryKey } = vc.createAccount('pw', 'P', { kdf: KDF() });
    const loose = recoveryKey.toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o').replace(/1/g, 'l');
    assert.deepEqual(vc.unlockWithRecovery(body, loose).userKey, keys.userKey);
    const i = recoveryKey.search(/[A-Z2-9]/);
    const typo = recoveryKey.slice(0, i) + (recoveryKey[i] === 'A' ? 'B' : 'A') + recoveryKey.slice(i + 1);
    assert.throws(() => vc.unlockWithRecovery(body, typo), decryptError('recovery_key'));
    assert.throws(() => vc.unlockWithRecovery(body, recoveryKey.slice(5)), decryptError('recovery_key'));
    assert.throws(() => vc.parseRecoveryKey(recoveryKey.replace(/.$/, 'U')), decryptError('recovery_key'));
  });

  it('a new password keeps the user key; recovery sets a new password and a new recovery key', () => {
    const { body, keys, recoveryKey } = vc.createAccount('alt', 'P', { kdf: KDF() });
    const account = { ...body, rev: 4 };
    const put = vc.changePassword(account, keys, 'neu', { m: 19456, t: 2 });
    assert.equal(put.rev, 4);
    assert.notEqual(put.kdf.salt, body.kdf.salt);
    assert.equal(put.userKeyRk, undefined);
    assert.deepEqual(vc.unlock({ ...account, ...put }, 'neu').userKey, keys.userKey);
    assert.throws(() => vc.unlock({ ...account, ...put }, 'alt'), decryptError('decrypt'));
    const k = vc.unlockWithRecovery(account, recoveryKey);
    const rec = vc.recover(account, k, 'ganz neu', { m: 19456, t: 2 });
    assert.notEqual(rec.recoveryKey, recoveryKey);
    const after = { ...account, ...rec.body };
    assert.deepEqual(vc.unlock(after, 'ganz neu').userKey, keys.userKey);
    assert.deepEqual(vc.unlockWithRecovery(after, rec.recoveryKey).userKey, keys.userKey);
    assert.throws(() => vc.unlockWithRecovery(after, recoveryKey), decryptError('decrypt'), 'the old recovery key is spent');
  });

  it('kdf bounds are the server\'s; the default is 64 MiB, 3 passes', () => {
    assert.deepEqual([vc.newKdf().m, vc.newKdf().t, vc.newKdf().p], [65536, 3, 1]);
    for (const bad of [{ m: 1024 }, { t: 1 }, { p: 2 }, { alg: 'scrypt' }, { salt: 'AAAA' }]) {
      assert.throws(() => vc.masterKey('pw', { ...KDF(), ...bad }), decryptError('invalid'), JSON.stringify(bad));
    }
    assert.throws(() => vc.masterKey('', KDF()), decryptError('invalid'));
  });
});

describe('vault-crypto: vaults and entries', () => {
  it('a shared vault: sealed to each member, the new key during a change', () => {
    const anna = vc.createAccount('a', 'P', { kdf: KDF() }).keys;
    const marc = vc.createAccount('m', 'P', { kdf: KDF() }).keys;
    const k1 = vc.newVaultKey();
    const k2 = vc.newVaultKey();
    const vault = { id: vc.newId(), keyRev: 1, sealedKey: vc.sealKey(k1, marc.publicKey), pending: { keyRev: 2, sealedKey: vc.sealKey(k2, marc.publicKey) } };
    const keys = vc.vaultKeys(vault, marc);
    assert.deepEqual([keys[1], keys[2]], [k1, k2]);
    assert.deepEqual(Object.keys(vc.vaultKeys({ ...vault, pending: null }, marc)), ['1']);
    assert.throws(() => vc.vaultKeys(vault, anna), decryptError('decrypt'), 'sealed to Marc, not Anna');
  });

  it('an entry is bound to its vault, id and revision; sizes are padded; 32 KiB at most', () => {
    const key = vc.newVaultKey();
    const vaultId = vc.newId();
    const id = vc.newId();
    const entry = { v: 1, type: 'login', title: 'Bank', fields: { username: 'anna', password: 'pa55' } };
    const blob = vc.encryptItem(key, { vaultId, itemId: id, rev: 2 }, entry);
    const item = { id, vaultId, rev: 2, blob };
    assert.deepEqual(vc.decryptItem(key, item), entry);
    for (const moved of [{ rev: 3 }, { rev: 1 }, { vaultId: vc.newId() }, { id: vc.newId() }]) {
      assert.throws(() => vc.decryptItem(key, { ...item, ...moved }), decryptError('decrypt'), JSON.stringify(moved));
    }
    assert.throws(() => vc.decryptItem(vc.newVaultKey(), item), decryptError('decrypt'));
    const short = vc.encryptItem(key, { vaultId, itemId: id, rev: 1 }, { v: 1, type: 'note', title: 'a' });
    const longer = vc.encryptItem(key, { vaultId, itemId: id, rev: 1 }, { v: 1, type: 'note', title: 'a'.repeat(150) });
    assert.equal(unb64(short).length, unb64(longer).length, 'padded to 256-byte blocks');
    assert.equal((unb64(short).length - 41) % 256, 0);
    assert.throws(() => vc.encryptItem(key, { vaultId, itemId: id, rev: 1 }, { v: 1, type: 'note', title: 'x', fields: { text: 'x'.repeat(33000) } }), decryptError('too_large'));
    assert.ok(unb64(vc.encryptItem(key, { vaultId, itemId: id, rev: 1 }, { v: 1, type: 'note', fields: { text: 'x'.repeat(32000) } })).length <= 32768);
    for (const bad of [{ v: 2, type: 'note' }, { v: 1, type: 'pdf' }, null]) {
      assert.throws(() => vc.encryptItem(key, { vaultId, itemId: id, rev: 1 }, bad), decryptError('invalid'));
    }
    assert.throws(() => vc.encryptItem(key, { vaultId, itemId: id, rev: 0 }, entry), decryptError('invalid'));
  });

  it('emergency access: the trusted person reads the grantor\'s vaults with the released key', () => {
    const anna = vc.createAccount('a', 'P', { kdf: KDF() });
    const marc = vc.createAccount('m', 'P', { kdf: KDF() }).keys;
    const access = {
      sealedKey: vc.sealForEmergency(anna.keys, marc.publicKey),
      grantor: { publicKey: anna.body.publicKey, privateKeyEnc: anna.body.privateKeyEnc },
    };
    const grantor = vc.openEmergency(access, marc);
    assert.deepEqual(grantor.secretKey, anna.keys.secretKey);
    const personal = { keyRev: 1, sealedKey: anna.body.personal.sealedKey };
    assert.deepEqual(vc.vaultKeys(personal, grantor)[1], anna.keys.personalKey);
    assert.throws(() => vc.openEmergency(access, anna.keys), decryptError('decrypt'), 'only the trusted person');
  });

  it('wipe zeroes the keys held in memory', () => {
    const { keys } = vc.createAccount('a', 'P', { kdf: KDF() });
    const k = keys.userKey;
    vc.wipe(keys);
    assert.ok(k.every((b) => b === 0));
  });

  it('garbage in → invalid, never a crash', () => {
    assert.throws(() => vc.unwrap(vc.newVaultKey(), 'not base64!', 'x'), decryptError('invalid'));
    assert.throws(() => vc.unwrap(vc.newVaultKey(), 'AAAA', 'x'), decryptError('invalid'));
    const w = vc.b64(vc.wrap(vc.newVaultKey(), new Uint8Array(4), 'x'));
    assert.throws(() => vc.unwrap(vc.newVaultKey(), 'Ag' + w.slice(2), 'x'), decryptError('invalid'), 'an unknown version');
  });
});
