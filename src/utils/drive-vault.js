'use strict';

/**
 * Drive vault folders (Tresor-Ordner, Drive 1.9 feature `vault`): the end-to-end encryption every client builds bit
 * for bit (plugin README "Tresor-Ordner – Kryptografie", reference ui/vaultcrypto.js, fixed vectors
 * test/fixtures/drive-vault-vectors.json) — with Node's crypto only (X25519, HKDF-SHA256, AES-256-GCM); the recovery
 * key's text is the Vault plugin's format (utils/vault-crypto.js: Crockford base32 with BLAKE2b-256 check bytes).
 *
 *   device key     X25519 per device; publicKey = the raw 32 bytes (the private key: DPAPI / safeStorage, never plain)
 *   device id      b64u(SHA-256("gcdrive-v1:device:" ‖ pub)[0..16])
 *   safety number  SHA-256("gcdrive-v1:fingerprint:" ‖ pub) → 4 uint32 (BE), each mod 100000, 5 digits
 *   vault key TK   32 random bytes per key version
 *   wrap           0x01 ‖ HPKE base mode (RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) of TK:
 *                  enc (32) ‖ ct (48); info "gcdrive-v1:tk:<vaultId>:<keyVersion>", aad empty
 *   nameCipher     0x01 ‖ kv (u32) ‖ nonce (12) ‖ AES-256-GCM(nameKey, aad = the first 5 bytes, pad(NFC UTF-8))
 *                  nameKey = HKDF(TK, salt empty, "gcdrive-v1:name:<vaultId>"); pad: 0x80, zeros to a multiple of 32
 *   content        header "GCDV" ‖ 0x01 ‖ kv (u32) ‖ chunkSize (u32) ‖ salt (16) = 29 bytes, then chunk i =
 *                  AES-256-GCM(fileKey, nonce 0^8 ‖ u32(i), aad = header ‖ u32(i) ‖ last (1 byte), piece);
 *                  fileKey = HKDF(TK, salt, "gcdrive-v1:content:<vaultId>"); an empty file: one empty last chunk
 *   recovery key   32 bytes; X25519 private key HKDF(key, salt empty, "gcdrive-v1:recovery"); its proof
 *                  recoveryAuth = b64u(HKDF(key, salt empty, "gcdrive-v1:recovery-auth"))
 *
 * HKDF with an empty salt is HMAC with a key of 32 zero bytes (HMAC pads the key) — the same as Node's hkdf with an
 * empty salt. Files are encrypted and decrypted chunk by chunk from disk to disk (at most one chunk in memory).
 * Errors: DriveVaultError with `code` 'decrypt' (wrong key, tampered, another vault) · 'invalid' · 'recovery_key'.
 */

const crypto = require('crypto');
const fs = require('fs');
const VC = require('./vault-crypto');

const VERSION = 1;
const CHUNK = 1048576;
const HEADER = 29;
const TAG = 16;
const KEY_BYTES = 32;
const WRAP_BYTES = 81;
const MAGIC = Buffer.from('GCDV', 'latin1');
const CHUNK_MIN = 1024;
const CHUNK_MAX = 16777216;
const NAME_MAX_BYTES = 1024;

const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');

class DriveVaultError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'DriveVaultError';
    this.code = code;
  }
}

// ── bytes ───────────────────────────────────────────────────

const buf = (v) => (Buffer.isBuffer(v) ? v : Buffer.from(v));
const b64u = (v) => buf(v).toString('base64url');

/** base64url without padding → Buffer (`bytes`: the exact length), else 'invalid'. */
function unb64u(text, bytes = null, what = 'value') {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new DriveVaultError('invalid', `${what}: not base64url`);
  const out = Buffer.from(text, 'base64url');
  if (out.toString('base64url') !== text || (bytes !== null && out.length !== bytes)) throw new DriveVaultError('invalid', what);
  return out;
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

/** Overwrites a key in memory (best effort). */
function wipe(b) {
  if (b && typeof b.fill === 'function') b.fill(0);
}

function key32(v, what = 'key') {
  const k = buf(v);
  if (k.length !== KEY_BYTES) throw new DriveVaultError('invalid', what);
  return k;
}

function hkdf(ikm, salt, info, len = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', buf(ikm), buf(salt), Buffer.from(info), len));
}

function gcmSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv(key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm', key, nonce, { authTagLength: TAG });
  c.setAAD(aad);
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}

function gcmOpen(key, nonce, aad, data) {
  if (data.length < TAG) throw new DriveVaultError('decrypt');
  try {
    const d = crypto.createDecipheriv(key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm', key, nonce, { authTagLength: TAG });
    d.setAAD(aad);
    d.setAuthTag(data.subarray(data.length - TAG));
    return Buffer.concat([d.update(data.subarray(0, data.length - TAG)), d.final()]);
  } catch {
    throw new DriveVaultError('decrypt');
  }
}

// ── X25519 ──────────────────────────────────────────────────

const privateKeyOf = (raw) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, key32(raw, 'private key')]), format: 'der', type: 'pkcs8' });
const publicKeyOf = (raw) => crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, key32(raw, 'public key')]), format: 'der', type: 'spki' });

/** The raw public key of a raw X25519 private key (any 32 bytes; X25519 clamps them). */
function publicFromPrivate(privRaw) {
  return Buffer.from(crypto.createPublicKey(privateKeyOf(privRaw)).export({ format: 'der', type: 'spki' }).subarray(SPKI_X25519.length));
}

/** A new X25519 key pair → { privateRaw, publicRaw } (32 bytes each). */
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateRaw: Buffer.from(privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(PKCS8_X25519.length)),
    publicRaw: Buffer.from(publicKey.export({ format: 'der', type: 'spki' }).subarray(SPKI_X25519.length)),
  };
}

function dh(privRaw, pubRaw) {
  try {
    return crypto.diffieHellman({ privateKey: privateKeyOf(privRaw), publicKey: publicKeyOf(pubRaw) });
  } catch (err) {
    if (err instanceof DriveVaultError) throw err;
    throw new DriveVaultError('decrypt', 'key agreement');
  }
}

// ── device id, safety number ────────────────────────────────

const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts.map(buf))).digest();

/** b64u(SHA-256("gcdrive-v1:device:" ‖ pub)[0..16]) — 22 characters (the server computes the same). */
function deviceId(pubRaw) {
  return b64u(sha256(Buffer.from('gcdrive-v1:device:'), key32(pubRaw, 'public key')).subarray(0, 16));
}

/** "44626 75008 87340 28578" — compared on both devices before a device is approved. */
function safetyNumber(pubRaw) {
  const h = sha256(Buffer.from('gcdrive-v1:fingerprint:'), key32(pubRaw, 'public key'));
  const out = [];
  for (let i = 0; i < 4; i++) out.push(String(h.readUInt32BE(i * 4) % 100000).padStart(5, '0'));
  return out.join(' ');
}

// ── HPKE (RFC 9180, mode base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-GCM) ──

const HPKE_V1 = Buffer.from('HPKE-v1');
const i2osp = (n, w) => { const b = Buffer.alloc(w); b.writeUIntBE(n, 0, w); return b; };
const extract = (salt, ikm) => crypto.createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
/** HKDF-Expand for L ≤ 32 (one block is all HPKE needs here). */
const expand = (prk, info, len) => crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([1])])).digest().subarray(0, len);

function suites(aeadId) {
  return {
    kem: Buffer.concat([Buffer.from('KEM'), i2osp(0x20, 2)]),
    hpke: Buffer.concat([Buffer.from('HPKE'), i2osp(0x20, 2), i2osp(1, 2), i2osp(aeadId, 2)]),
  };
}
const labeledExtract = (suite, salt, label, ikm) => extract(salt, Buffer.concat([HPKE_V1, suite, Buffer.from(label), ikm]));
const labeledExpand = (suite, prk, label, info, len) => expand(prk, Buffer.concat([i2osp(len, 2), HPKE_V1, suite, Buffer.from(label), info]), len);

function keySchedule(su, shared, info, nk) {
  const empty = Buffer.alloc(0);
  const ctx = Buffer.concat([Buffer.from([0]), labeledExtract(su.hpke, empty, 'psk_id_hash', empty), labeledExtract(su.hpke, empty, 'info_hash', buf(info))]);
  const secret = labeledExtract(su.hpke, shared, 'secret', empty);
  return { key: labeledExpand(su.hpke, secret, 'key', ctx, nk), nonce: labeledExpand(su.hpke, secret, 'base_nonce', ctx, 12) };
}

function sharedSecret(su, dhBytes, enc, pkR) {
  return labeledExpand(su.kem, labeledExtract(su.kem, Buffer.alloc(0), 'eae_prk', dhBytes), 'shared_secret', Buffer.concat([enc, pkR]), 32);
}

/**
 * HPKE single-shot seal to `pkR` → enc ‖ ct. o.aeadId 2 (AES-256-GCM) by default, 1 (AES-128-GCM) for the RFC's
 * vectors; o.ephemeral { privateRaw, publicRaw } only for test vectors.
 */
function hpkeSeal(pkR, info, aad, pt, o = {}) {
  const aeadId = o.aeadId || 2;
  const su = suites(aeadId);
  const e = o.ephemeral || generateKeyPair();
  const pk = key32(pkR, 'public key');
  const shared = sharedSecret(su, dh(e.privateRaw, pk), buf(e.publicRaw), pk);
  const ks = keySchedule(su, shared, info, aeadId === 1 ? 16 : 32);
  return Buffer.concat([buf(e.publicRaw), gcmSeal(ks.key, ks.nonce, buf(aad), buf(pt))]);
}

/** HPKE single-shot open of enc ‖ ct with the recipient's raw private and public key. */
function hpkeOpen(skR, pkR, info, aad, data, o = {}) {
  const aeadId = o.aeadId || 2;
  const su = suites(aeadId);
  const d = buf(data);
  if (d.length < 32 + TAG) throw new DriveVaultError('decrypt');
  const enc = d.subarray(0, 32);
  const shared = sharedSecret(su, dh(skR, enc), enc, key32(pkR, 'public key'));
  const ks = keySchedule(su, shared, info, aeadId === 1 ? 16 : 32);
  return gcmOpen(ks.key, ks.nonce, buf(aad), d.subarray(32));
}

// ── the vault key ───────────────────────────────────────────

const newVaultKey = () => crypto.randomBytes(KEY_BYTES);
const newVaultId = () => b64u(crypto.randomBytes(16));
const wrapInfo = (vaultId, keyVersion) => Buffer.from(`gcdrive-v1:tk:${vaultId}:${keyVersion}`);

/** TK → its wrap for the raw public key `pubRaw` (base64url, 108 characters). o.ephemeral only for test vectors. */
function wrapKey(tk, pubRaw, vaultId, keyVersion, o = {}) {
  return b64u(Buffer.concat([Buffer.from([VERSION]), hpkeSeal(pubRaw, wrapInfo(vaultId, keyVersion), Buffer.alloc(0), key32(tk, 'vault key'), o)]));
}

/** A wrap → TK, with the device's (or the recovery key's) raw private and public key. */
function unwrapKey(wrap, privRaw, pubRaw, vaultId, keyVersion) {
  const b = unb64u(wrap, WRAP_BYTES, 'wrap');
  if (b[0] !== VERSION) throw new DriveVaultError('invalid', 'wrap');
  const tk = hpkeOpen(privRaw, pubRaw, wrapInfo(vaultId, keyVersion), Buffer.alloc(0), b.subarray(1));
  if (tk.length !== KEY_BYTES) throw new DriveVaultError('decrypt');
  return tk;
}

// ── names ───────────────────────────────────────────────────

function pad(bytes) {
  const out = Buffer.alloc(Math.ceil((bytes.length + 1) / 32) * 32);
  bytes.copy(out);
  out[bytes.length] = 0x80;
  return out;
}

function unpad(b) {
  let i = b.length - 1;
  while (i >= 0 && b[i] === 0) i--;
  if (i < 0 || b[i] !== 0x80) throw new DriveVaultError('decrypt');
  return b.subarray(0, i);
}

const nameKey = (tk, vaultId) => hkdf(key32(tk, 'vault key'), Buffer.alloc(0), `gcdrive-v1:name:${vaultId}`);

/** A name → nameCipher (base64url). o.nonce only for test vectors. */
function encryptName(tk, vaultId, keyVersion, name, o = {}) {
  const text = Buffer.from(String(name).normalize('NFC'), 'utf8');
  if (!text.length || text.length > NAME_MAX_BYTES) throw new DriveVaultError('invalid', 'name');
  const head = Buffer.concat([Buffer.from([VERSION]), u32(keyVersion)]);
  const nonce = o.nonce ? buf(o.nonce) : crypto.randomBytes(12);
  const k = nameKey(tk, vaultId);
  try {
    return b64u(Buffer.concat([head, nonce, gcmSeal(k, nonce, head, pad(text))]));
  } finally {
    wipe(k);
  }
}

function nameBytes(cipher) {
  const b = unb64u(cipher, null, 'name');
  if (b.length < 65 || b[0] !== VERSION || (b.length - 33) % 32 !== 0) throw new DriveVaultError('invalid', 'name');
  return b;
}

/** The key version of a nameCipher (its header). */
function nameVersion(cipher) {
  return nameBytes(cipher).readUInt32BE(1);
}

/** keys: keyVersion → TK (a Map, an object or a function). */
function keyOf(keys, v) {
  if (!keys) return null;
  if (typeof keys === 'function') return keys(v) || null;
  if (typeof keys.get === 'function') return keys.get(v) || null;
  return keys[v] || null;
}

/** nameCipher → the name (no key for its version: 'decrypt'). */
function decryptName(keys, vaultId, cipher) {
  const b = nameBytes(cipher);
  const tk = keyOf(keys, b.readUInt32BE(1));
  if (!tk) throw new DriveVaultError('decrypt', 'no key for this version');
  const k = nameKey(tk, vaultId);
  try {
    const name = unpad(gcmOpen(k, b.subarray(5, 17), b.subarray(0, 5), b.subarray(17)));
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(name);
    } catch {
      throw new DriveVaultError('decrypt');
    }
  } finally {
    wipe(k);
  }
}

// ── content ─────────────────────────────────────────────────

function header(keyVersion, chunkSize, salt) {
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), u32(keyVersion), u32(chunkSize), buf(salt)]);
}

const chunkNonce = (i) => Buffer.concat([Buffer.alloc(8), u32(i)]);
const chunkAad = (head, i, last) => Buffer.concat([head, u32(i), Buffer.from([last ? 1 : 0])]);
const fileKey = (tk, vaultId, salt) => hkdf(key32(tk, 'vault key'), salt, `gcdrive-v1:content:${vaultId}`);

/** The size of the ciphertext of `size` plaintext bytes. */
function cipherSize(size, chunkSize = CHUNK) {
  return HEADER + size + TAG * Math.max(1, Math.ceil(size / chunkSize));
}

/** The plaintext size of a ciphertext of `total` bytes with `chunkSize`, or null when that is no valid size. */
function plainSize(total, chunkSize = CHUNK) {
  const step = chunkSize + TAG;
  if (!Number.isSafeInteger(total) || total < HEADER + TAG) return null;
  const n = Math.ceil((total - HEADER) / step);
  const lastLen = total - HEADER - (n - 1) * step;
  if (n < 1 || lastLen < TAG || lastLen > step) return null;
  return total - HEADER - n * TAG;
}

/** The header of a content's first bytes → { keyVersion, chunkSize, salt, head }. */
function parseHeader(b) {
  if (!b || b.length < HEADER || !b.subarray(0, 4).equals(MAGIC) || b[4] !== VERSION) throw new DriveVaultError('invalid', 'not a vault file');
  const cs = b.readUInt32BE(9);
  if (cs < CHUNK_MIN || cs > CHUNK_MAX) throw new DriveVaultError('invalid', 'chunk size');
  return { keyVersion: b.readUInt32BE(5), chunkSize: cs, salt: Buffer.from(b.subarray(13, 29)), head: Buffer.from(b.subarray(0, HEADER)) };
}

/** Encrypts a whole buffer → the ciphertext (tests, small contents). o: { chunkSize, salt } */
function encryptBuffer(tk, vaultId, keyVersion, data, o = {}) {
  const cs = o.chunkSize || CHUNK;
  const pt = buf(data);
  const salt = o.salt ? buf(o.salt) : crypto.randomBytes(16);
  const head = header(keyVersion, cs, salt);
  const key = fileKey(tk, vaultId, salt);
  const n = Math.max(1, Math.ceil(pt.length / cs));
  const parts = [head];
  try {
    for (let i = 0; i < n; i++) parts.push(gcmSeal(key, chunkNonce(i), chunkAad(head, i, i === n - 1), pt.subarray(i * cs, Math.min(pt.length, (i + 1) * cs))));
  } finally {
    wipe(key);
  }
  return Buffer.concat(parts);
}

/** Decrypts a whole ciphertext → the plaintext (tests, small contents). keys: keyVersion → TK. */
function decryptBuffer(keys, vaultId, data) {
  const ct = buf(data);
  const h = parseHeader(ct);
  const tk = keyOf(keys, h.keyVersion);
  if (!tk) throw new DriveVaultError('decrypt', 'no key for this version');
  const step = h.chunkSize + TAG;
  if (plainSize(ct.length, h.chunkSize) === null) throw new DriveVaultError('invalid', 'size');
  const n = Math.ceil((ct.length - HEADER) / step);
  const key = fileKey(tk, vaultId, h.salt);
  const out = [];
  try {
    for (let i = 0; i < n; i++) out.push(gcmOpen(key, chunkNonce(i), chunkAad(h.head, i, i === n - 1), ct.subarray(HEADER + i * step, Math.min(ct.length, HEADER + (i + 1) * step))));
  } finally {
    wipe(key);
  }
  return Buffer.concat(out);
}

async function readFully(fh, b, pos) {
  let got = 0;
  while (got < b.length) {
    const { bytesRead } = await fh.read(b, got, b.length - got, pos + got);
    if (!bytesRead) break;
    got += bytesRead;
  }
  return got;
}

/**
 * Encrypts the file `src` chunk by chunk into `dest` (created / replaced) → { size, cipherSize, keyVersion }.
 * o: { chunkSize, salt (test vectors), onProgress(done, total), signal: { aborted } }. A file that changes its size
 * while it is read fails with 'changed'.
 */
async function encryptFile(tk, vaultId, keyVersion, src, dest, o = {}) {
  const cs = o.chunkSize || CHUNK;
  const salt = o.salt ? buf(o.salt) : crypto.randomBytes(16);
  const head = header(keyVersion, cs, salt);
  const inp = await fs.promises.open(src, 'r');
  let out = null;
  const key = fileKey(tk, vaultId, salt);
  try {
    const size = (await inp.stat()).size;
    out = await fs.promises.open(dest, 'w');
    await out.write(head, 0, head.length, null);
    const n = Math.max(1, Math.ceil(size / cs));
    const piece = Buffer.alloc(Math.min(cs, Math.max(size, 1)));
    let done = 0;
    for (let i = 0; i < n; i++) {
      if (o.signal && o.signal.aborted) throw new DriveVaultError('cancelled');
      const want = Math.min(cs, size - i * cs);
      const got = want > 0 ? await readFully(inp, piece.subarray(0, want), i * cs) : 0;
      if (got !== want) throw new DriveVaultError('changed', 'the file changed while it was read');
      const ct = gcmSeal(key, chunkNonce(i), chunkAad(head, i, i === n - 1), piece.subarray(0, want));
      await out.write(ct, 0, ct.length, null);
      done += want;
      if (typeof o.onProgress === 'function') { try { o.onProgress(done, size); } catch { /* the caller's */ } }
    }
    wipe(piece);
    await out.sync().catch(() => {});
    return { size, cipherSize: cipherSize(size, cs), keyVersion };
  } finally {
    wipe(key);
    await inp.close().catch(() => {});
    if (out) await out.close().catch(() => {});
  }
}

/**
 * Decrypts the vault file `src` chunk by chunk into `dest` (created / replaced) → { size, keyVersion }.
 * keys: keyVersion → TK. Tampered, reordered, cut or another vault's content: 'decrypt' (dest may hold a part then —
 * the caller removes it).
 */
async function decryptFile(keys, vaultId, src, dest, o = {}) {
  const inp = await fs.promises.open(src, 'r');
  let out = null;
  let key = null;
  try {
    const total = (await inp.stat()).size;
    const hb = Buffer.alloc(HEADER);
    if (await readFully(inp, hb, 0) !== HEADER) throw new DriveVaultError('invalid', 'too short');
    const h = parseHeader(hb);
    const tk = keyOf(keys, h.keyVersion);
    if (!tk) throw new DriveVaultError('decrypt', 'no key for this version');
    const size = plainSize(total, h.chunkSize);
    if (size === null) throw new DriveVaultError('decrypt', 'size');
    const step = h.chunkSize + TAG;
    const n = Math.ceil((total - HEADER) / step);
    key = fileKey(tk, vaultId, h.salt);
    out = await fs.promises.open(dest, 'w');
    const chunk = Buffer.alloc(Math.min(step, total - HEADER));
    let done = 0;
    for (let i = 0; i < n; i++) {
      if (o.signal && o.signal.aborted) throw new DriveVaultError('cancelled');
      const len = i === n - 1 ? total - HEADER - (n - 1) * step : step;
      if (await readFully(inp, chunk.subarray(0, len), HEADER + i * step) !== len) throw new DriveVaultError('decrypt', 'short read');
      const pt = gcmOpen(key, chunkNonce(i), chunkAad(h.head, i, i === n - 1), chunk.subarray(0, len));
      await out.write(pt, 0, pt.length, null);
      done += pt.length;
      wipe(pt);
      if (typeof o.onProgress === 'function') { try { o.onProgress(done, size); } catch { /* the caller's */ } }
    }
    return { size, keyVersion: h.keyVersion };
  } finally {
    wipe(key);
    await inp.close().catch(() => {});
    if (out) await out.close().catch(() => {});
  }
}

// ── recovery key ────────────────────────────────────────────

/** A new recovery key → { key, text } (text: "R30W-5GY4-…", shown once). */
async function newRecoveryKey() {
  await VC.ready();
  const key = crypto.randomBytes(KEY_BYTES);
  return { key, text: VC.formatRecoveryKey(new Uint8Array(key)) };
}

async function formatRecoveryKey(key) {
  await VC.ready();
  return VC.formatRecoveryKey(new Uint8Array(key32(key, 'recovery key')));
}

/** The typed text → the 32 bytes (lower case, spaces, dashes, O/I/L fine); a wrong check: 'recovery_key'. */
async function parseRecoveryKey(text) {
  await VC.ready();
  try {
    return Buffer.from(VC.parseRecoveryKey(String(text || '')));
  } catch {
    throw new DriveVaultError('recovery_key');
  }
}

/** The recovery key's X25519 key pair → { privateRaw, publicRaw }. */
function recoveryKeyPair(key) {
  const privateRaw = hkdf(key32(key, 'recovery key'), Buffer.alloc(0), 'gcdrive-v1:recovery');
  return { privateRaw, publicRaw: publicFromPrivate(privateRaw) };
}

/** The recovery key's proof (base64url) — the server keeps its SHA-256. */
function recoveryAuth(key) {
  return b64u(hkdf(key32(key, 'recovery key'), Buffer.alloc(0), 'gcdrive-v1:recovery-auth'));
}

const VAULT_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const OPAQUE_RE = /^[0-9a-f]{32}$/;

module.exports = {
  VERSION, CHUNK, HEADER, TAG, WRAP_BYTES, VAULT_ID_RE, DEVICE_ID_RE, OPAQUE_RE,
  DriveVaultError,
  b64u, unb64u, wipe, hkdf,
  generateKeyPair, publicFromPrivate, deviceId, safetyNumber,
  hpkeSeal, hpkeOpen,
  newVaultKey, newVaultId, wrapKey, unwrapKey,
  encryptName, decryptName, nameVersion, keyOf,
  header, parseHeader, cipherSize, plainSize, encryptBuffer, decryptBuffer, encryptFile, decryptFile,
  newRecoveryKey, formatRecoveryKey, parseRecoveryKey, recoveryKeyPair, recoveryAuth,
};
