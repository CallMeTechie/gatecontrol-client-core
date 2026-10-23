'use strict';

// Vault (gatecontrol-vault): the end-to-end encryption every app does the same way, bit for bit. The plugin README
// "Kryptoformat" is the contract; test/fixtures/vault-vectors.json pins it (Android checks the same vectors).
//
//   master key    Argon2id(master password, kdf.salt; kdf.m KiB, kdf.t passes, 1 lane) → 32 B, memory only
//   user key      32 B random, stored twice: wrapped by the master key (userKeyPw) and the recovery key (userKeyRk)
//   key pair      X25519 (crypto_box); the secret key wrapped by the user key (privateKeyEnc)
//   vault key     32 B random per vault and key generation, sealed (crypto_box_seal) to each member's public key
//   wrapped       0x01 ‖ nonce (24 B) ‖ XChaCha20-Poly1305-IETF(plaintext, AD) — the AD binds it to its place
//   encoding      base64url without padding
//   safety number SHA-256("gcv1:fingerprint:" ‖ public key) → 8 groups of 5 digits, compared between two devices
//
// Everything is synchronous once ready() resolved; Argon2id takes ~0.3–1 s at 64 MiB — call it off the UI thread.

const sodium = require('libsodium-wrappers-sumo');

const VERSION = 1;
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const SALT_BYTES = 16;
const PAD_BLOCK = 256;
const MAX_BLOB = 32768; // the server's limit for one entry (decoded bytes)
const DEFAULT_KDF = { m: 65536, t: 3, p: 1 };
// the server's bounds (account.js KDF): an account outside them could not be stored
const KDF_BOUNDS = { m: [19456, 1048576], t: [2, 10], p: [1, 1] };
const ITEM_TYPES = ['login', 'totp', 'note', 'card', 'wifi', 'identity'];

const AD = {
  userKeyPw: 'gcv1:user-key:pw',
  userKeyRk: 'gcv1:user-key:rk',
  privateKey: 'gcv1:private-key',
  vaultName: (vaultId) => `gcv1:vault-name:${vaultId}`,
  item: (vaultId, itemId, rev) => `gcv1:item:${vaultId}:${itemId}:${rev}`,
};

class VaultCryptoError extends Error {
  /** code: 'decrypt' (wrong key, tampered, or not where it belongs) · 'invalid' (malformed input) · 'recovery_key' ·
   * 'too_large' (an entry over 32 KiB encrypted) */
  constructor(code, message) {
    super(message || code);
    this.name = 'VaultCryptoError';
    this.code = code;
  }
}

let readyPromise = null;
/** libsodium is WebAssembly: await this once before any other call. */
function ready() {
  if (!readyPromise) readyPromise = sodium.ready.then(() => sodium);
  return readyPromise;
}

// ── encoding ────────────────────────────────────────────────

const b64 = (bytes) => sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
function unb64(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) throw new VaultCryptoError('invalid', 'not base64url');
  try {
    return sodium.from_base64(text, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new VaultCryptoError('invalid', 'not base64url');
  }
}
const utf8 = (s) => sodium.from_string(s);
const fromUtf8 = (b) => sodium.to_string(b);

function bytes(v, len, what) {
  const b = typeof v === 'string' ? unb64(v) : v;
  if (!(b instanceof Uint8Array) || (len != null && b.length !== len)) throw new VaultCryptoError('invalid', `${what}: ${len} bytes expected`);
  return b;
}

/** A new id for a vault or an entry: 16 random bytes, base64url (22 characters). */
const newId = () => b64(sodium.randombytes_buf(16));

// ── primitives ──────────────────────────────────────────────

/** 0x01 ‖ nonce ‖ ciphertext+tag. `nonce` only for test vectors. */
function wrap(key, plaintext, ad, nonce) {
  const n = nonce ? bytes(nonce, NONCE_BYTES, 'nonce') : sodium.randombytes_buf(NONCE_BYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, utf8(ad), null, n, bytes(key, KEY_BYTES, 'key'));
  const out = new Uint8Array(1 + NONCE_BYTES + ct.length);
  out[0] = VERSION;
  out.set(n, 1);
  out.set(ct, 1 + NONCE_BYTES);
  return out;
}

function unwrap(key, data, ad) {
  const d = bytes(data, null, 'wrapped');
  if (d.length < 1 + NONCE_BYTES + 16 || d[0] !== VERSION) throw new VaultCryptoError('invalid', 'unknown format');
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, d.subarray(1 + NONCE_BYTES), utf8(ad), d.subarray(1, 1 + NONCE_BYTES), bytes(key, KEY_BYTES, 'key'));
  } catch {
    throw new VaultCryptoError('decrypt');
  }
}

/** crypto_box_seal: only the holder of the recipient's secret key opens it. */
const seal = (key, publicKey) => sodium.crypto_box_seal(bytes(key, KEY_BYTES, 'key'), bytes(publicKey, 32, 'publicKey'));

function openSealed(sealed, publicKey, secretKey) {
  let out;
  try {
    out = sodium.crypto_box_seal_open(bytes(sealed, null, 'sealed'), bytes(publicKey, 32, 'publicKey'), bytes(secretKey, 32, 'secretKey'));
  } catch {
    throw new VaultCryptoError('decrypt');
  }
  if (out.length !== KEY_BYTES) throw new VaultCryptoError('decrypt');
  return out;
}

// ── master key ──────────────────────────────────────────────

/** A new kdf for the account: Argon2id, 64 MiB, 3 passes, a fresh salt. */
const newKdf = (opts = {}) => ({ alg: 'argon2id', m: opts.m || DEFAULT_KDF.m, t: opts.t || DEFAULT_KDF.t, p: 1, salt: b64(sodium.randombytes_buf(SALT_BYTES)) });

function checkKdf(kdf) {
  if (!kdf || kdf.alg !== 'argon2id') throw new VaultCryptoError('invalid', 'kdf');
  for (const k of ['m', 't', 'p']) {
    const n = kdf[k];
    if (!Number.isSafeInteger(n) || n < KDF_BOUNDS[k][0] || n > KDF_BOUNDS[k][1]) throw new VaultCryptoError('invalid', `kdf.${k}`);
  }
  return bytes(kdf.salt, SALT_BYTES, 'kdf.salt');
}

/** Argon2id(password) → the 32-byte master key. The password is used as UTF-8 after NFC normalization. */
function masterKey(password, kdf) {
  if (typeof password !== 'string' || !password.length) throw new VaultCryptoError('invalid', 'password');
  const salt = checkKdf(kdf);
  return sodium.crypto_pwhash(KEY_BYTES, utf8(password.normalize('NFC')), salt, kdf.t, kdf.m * 1024, sodium.crypto_pwhash_ALG_ARGON2ID13);
}

// ── recovery key ────────────────────────────────────────────
// 32 random bytes + 3 check bytes (BLAKE2b-256 of the key) = 35 bytes = 56 Crockford base32 characters, shown in
// 14 groups of 4: "7KQ2-M9ZD-…". Reading accepts lower case, spaces, missing dashes and O/I/L for 0/1/1.

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function checkBytes(key) {
  return sodium.crypto_generichash(32, key, null).subarray(0, 3);
}

function formatRecoveryKey(key) {
  const k = bytes(key, KEY_BYTES, 'recovery key');
  const all = new Uint8Array(35);
  all.set(k);
  all.set(checkBytes(k), 32);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of all) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return out.match(/.{4}/g).join('-');
}

function parseRecoveryKey(text) {
  if (typeof text !== 'string') throw new VaultCryptoError('recovery_key');
  const s = text.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== 56) throw new VaultCryptoError('recovery_key');
  const all = new Uint8Array(35);
  let bits = 0;
  let acc = 0;
  let i = 0;
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new VaultCryptoError('recovery_key');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      all[i++] = (acc >> bits) & 255;
    }
    acc &= (1 << bits) - 1;
  }
  const key = all.slice(0, 32);
  if (!sodium.memcmp(checkBytes(key), all.subarray(32))) throw new VaultCryptoError('recovery_key');
  return key;
}

// ── account ─────────────────────────────────────────────────

/**
 * Everything for POST account. Returns { body, keys, recoveryKey }: body goes to the server; keys
 * ({ userKey, publicKey, secretKey, personalKey }) stay in memory; recoveryKey (text) is shown to the person once —
 * the setup ends only after they confirmed keeping it. `personalName`: the personal vault's name ("Persönlich").
 * `rnd` only for test vectors.
 */
function createAccount(password, personalName, opts = {}) {
  const rnd = opts.rnd || {};
  const kdf = opts.kdf || newKdf(opts);
  const mk = masterKey(password, kdf);
  const userKey = rnd.userKey ? bytes(rnd.userKey, KEY_BYTES, 'userKey') : sodium.randombytes_buf(KEY_BYTES);
  const recovery = rnd.recoveryKey ? bytes(rnd.recoveryKey, KEY_BYTES, 'recoveryKey').slice() : sodium.randombytes_buf(KEY_BYTES);
  const pair = rnd.keySeed ? sodium.crypto_box_seed_keypair(bytes(rnd.keySeed, 32, 'keySeed')) : sodium.crypto_box_keypair();
  const personalId = rnd.personalId || newId();
  const personalKey = rnd.personalKey ? bytes(rnd.personalKey, KEY_BYTES, 'personalKey') : sodium.randombytes_buf(KEY_BYTES);
  const n = rnd.nonces || [];
  const body = {
    kdf,
    userKeyPw: b64(wrap(mk, userKey, AD.userKeyPw, n[0])),
    userKeyRk: b64(wrap(recovery, userKey, AD.userKeyRk, n[1])),
    publicKey: b64(pair.publicKey),
    privateKeyEnc: b64(wrap(userKey, pair.privateKey, AD.privateKey, n[2])),
    personal: {
      id: personalId,
      nameEnc: encryptName(personalKey, personalId, personalName, n[3]),
      sealedKey: b64(seal(personalKey, pair.publicKey)),
    },
  };
  sodium.memzero(mk);
  const recoveryKey = formatRecoveryKey(recovery);
  sodium.memzero(recovery);
  return { body, keys: { userKey, publicKey: pair.publicKey, secretKey: pair.privateKey, personalKey }, recoveryKey };
}

/** The account's keys from the user key (after either unlock). */
function keysFrom(account, userKey) {
  const publicKey = bytes(account.publicKey, 32, 'publicKey');
  const secretKey = unwrap(userKey, account.privateKeyEnc, AD.privateKey);
  if (secretKey.length !== 32 || !sodium.memcmp(sodium.crypto_scalarmult_base(secretKey), publicKey)) throw new VaultCryptoError('decrypt');
  return { userKey, publicKey, secretKey };
}

/** GET account's `account` + the master password → keys, or VaultCryptoError 'decrypt' (wrong password). */
function unlock(account, password) {
  const mk = masterKey(password, account.kdf);
  try {
    return keysFrom(account, unwrap(mk, account.userKeyPw, AD.userKeyPw));
  } finally {
    sodium.memzero(mk);
  }
}

/** The recovery key (text) → keys, or VaultCryptoError 'recovery_key' / 'decrypt'. */
function unlockWithRecovery(account, recoveryText) {
  const rk = parseRecoveryKey(recoveryText);
  try {
    return keysFrom(account, unwrap(rk, account.userKeyRk, AD.userKeyRk));
  } finally {
    sodium.memzero(rk);
  }
}

/** PUT account body for a new master password (the user key stays; a fresh salt). */
function changePassword(account, keys, newPassword, opts = {}) {
  const kdf = opts.kdf || newKdf(opts);
  const mk = masterKey(newPassword, kdf);
  const body = { rev: account.rev, kdf, userKeyPw: b64(wrap(mk, keys.userKey, AD.userKeyPw, opts.nonce)) };
  sodium.memzero(mk);
  return body;
}

/**
 * After a recovery: a new master password and a new recovery key (the old one was used). Returns { body, recoveryKey }
 * — PUT body, and the new recovery key to show once.
 */
function recover(account, keys, newPassword, opts = {}) {
  const body = changePassword(account, keys, newPassword, opts);
  const rk = opts.recoveryKey ? bytes(opts.recoveryKey, KEY_BYTES, 'recoveryKey').slice() : sodium.randombytes_buf(KEY_BYTES);
  body.userKeyRk = b64(wrap(rk, keys.userKey, AD.userKeyRk, opts.rkNonce));
  const recoveryKey = formatRecoveryKey(rk);
  sodium.memzero(rk);
  return { body, recoveryKey };
}

// ── vaults ──────────────────────────────────────────────────

const newVaultKey = () => sodium.randombytes_buf(KEY_BYTES);

/** A vault key sealed to a public key (base64url) — for POST vaults, members, rekey/start. */
const sealKey = (vaultKey, publicKey) => b64(seal(vaultKey, publicKey));

/**
 * The keys of a vault from the sync's Vault: { [keyRev]: key } — the current one and, during a key change, the new
 * one (`pending`). `keys`: the account keys (or a grantor's, for emergency access).
 */
function vaultKeys(vault, keys) {
  const out = { [vault.keyRev]: openSealed(vault.sealedKey, keys.publicKey, keys.secretKey) };
  if (vault.pending && vault.pending.sealedKey) out[vault.pending.keyRev] = openSealed(vault.pending.sealedKey, keys.publicKey, keys.secretKey);
  return out;
}

function encryptName(vaultKey, vaultId, name, nonce) {
  if (typeof name !== 'string' || name.length > 200) throw new VaultCryptoError('invalid', 'name');
  return b64(wrap(vaultKey, utf8(name), AD.vaultName(vaultId), nonce));
}

const decryptName = (vaultKey, vaultId, nameEnc) => fromUtf8(unwrap(vaultKey, nameEnc, AD.vaultName(vaultId)));

// ── entries ─────────────────────────────────────────────────

/**
 * An entry → its blob. `at`: { vaultId, itemId, rev } where rev is the revision this save creates (baseRev + 1;
 * 1 for a new entry). The JSON is padded to 256-byte blocks so the size gives little away.
 */
function encryptItem(vaultKey, at, item, nonce) {
  if (!item || typeof item !== 'object' || item.v !== 1 || !ITEM_TYPES.includes(item.type)) throw new VaultCryptoError('invalid', 'item');
  return encryptItemBytes(vaultKey, at, utf8(JSON.stringify(item)), nonce);
}

function encryptItemBytes(vaultKey, at, plain, nonce) {
  if (!Number.isSafeInteger(at.rev) || at.rev < 1) throw new VaultCryptoError('invalid', 'rev');
  const padded = sodium.pad(plain, PAD_BLOCK);
  if (1 + NONCE_BYTES + padded.length + 16 > MAX_BLOB) throw new VaultCryptoError('too_large');
  return b64(wrap(vaultKey, padded, AD.item(at.vaultId, at.itemId, at.rev), nonce));
}

/** The sync's Item → the entry object; `rev` and ids from the Item itself, so a moved or replayed blob fails. */
function decryptItem(vaultKey, item) {
  const padded = unwrap(vaultKey, item.blob, AD.item(item.vaultId, item.id, item.rev));
  let obj;
  try {
    obj = JSON.parse(fromUtf8(sodium.unpad(padded, PAD_BLOCK)));
  } catch {
    throw new VaultCryptoError('decrypt');
  }
  if (!obj || typeof obj !== 'object' || obj.v !== 1) throw new VaultCryptoError('decrypt');
  return obj;
}

// ── safety number ───────────────────────────────────────────

/**
 * A person's safety number: 40 digits in 8 groups of 5 from SHA-256("gcv1:fingerprint:" ‖ public key), each group
 * a 4-byte big-endian word mod 100000. Shown on their own device (Vault › Profil) and next to them when sharing or
 * naming a trusted person — equal numbers mean the server handed out the right key.
 */
function safetyNumber(publicKey) {
  const h = require('node:crypto').createHash('sha256').update(utf8('gcv1:fingerprint:')).update(bytes(publicKey, 32, 'publicKey')).digest();
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(String(h.readUInt32BE(i * 4) % 100000).padStart(5, '0'));
  return groups.join(' ');
}

// ── emergency access ────────────────────────────────────────

/** POST emergency's sealedKey: the grantor's user key sealed to the trusted person's public key. */
const sealForEmergency = (keys, granteePublicKey) => b64(seal(keys.userKey, granteePublicKey));

/** GET emergency/<id>/access + the trusted person's keys → the grantor's keys (read their vaults with vaultKeys). */
function openEmergency(access, myKeys) {
  const userKey = openSealed(access.sealedKey, myKeys.publicKey, myKeys.secretKey);
  return keysFrom({ publicKey: access.grantor.publicKey, privateKeyEnc: access.grantor.privateKeyEnc }, userKey);
}

/** Forget keys held in memory (lock). */
function wipe(...keys) {
  for (const k of keys) {
    if (k instanceof Uint8Array) sodium.memzero(k);
    else if (k && typeof k === 'object') for (const v of Object.values(k)) if (v instanceof Uint8Array) sodium.memzero(v);
  }
}

module.exports = {
  ready, VaultCryptoError, AD, ITEM_TYPES, DEFAULT_KDF, KDF_BOUNDS,
  b64, unb64, newId, wrap, unwrap, seal, openSealed,
  newKdf, masterKey, formatRecoveryKey, parseRecoveryKey,
  createAccount, unlock, unlockWithRecovery, changePassword, recover,
  newVaultKey, sealKey, vaultKeys, encryptName, decryptName, safetyNumber,
  encryptItem, encryptItemBytes, decryptItem,
  sealForEmergency, openEmergency, wipe,
};
