'use strict';

// Vault: "Mit Windows Hello entsperren" — the user key wrapped by a key that only a Windows Hello signature gives.
//
//   challenge    32 random bytes, made when Hello is turned on
//   signature    the Hello key credential's RSA PKCS#1 v1.5 / SHA-256 signature of the challenge (face, fingerprint
//                or PIN; the private key stays in Windows, in the TPM when there is one). PKCS#1 v1.5 is
//                deterministic: the same key signs the same challenge to the same bytes every time.
//   wrapping key HKDF-SHA256(ikm = signature, salt = challenge, info = "gcv1:hello-wrap-key") → 32 B
//   wrapped      vault-crypto wrap(): 0x01 ‖ nonce ‖ XChaCha20-Poly1305(user key, AD = "gcv1:user-key:hello:" ‖ key name)
//   record       JSON { v, keyName, challenge, publicKey (SPKI), check, wrapped }, stored DPAPI-protected (safeStorage)
//                in <dir>/hello-<owner>.bin — never the signature, the wrapping key or the user key.
//
// `check` says how turning it on made sure the signature is stable: 'pkcs1' (it verifies as RSA PKCS#1 v1.5 /
// SHA-256 under the credential's public key — checked again before every unwrap) or 'repeat' (two signatures were
// equal). Local only (no server, no other platform reads it): not part of the plugin's "Kryptoformat".

const crypto = require('node:crypto');
const vc = require('./vault-crypto');

const RECORD_VERSION = 1;
const CHALLENGE_BYTES = 32;
const KEY_BYTES = 32;
const MIN_RSA_BITS = 2048;
const HKDF_INFO = 'gcv1:hello-wrap-key';
const AD_PREFIX = 'gcv1:user-key:hello:';
/** Failed or cancelled Windows Hello unlocks in a row before only the master password is offered. */
const MAX_FAILS = 3;
const CHECKS = ['pkcs1', 'repeat'];

class VaultHelloError extends Error {
  /** code: 'invalid' (record / key unusable) · 'signature' (not the signature of this record's key) */
  constructor(code) {
    super(code);
    this.name = 'VaultHelloError';
    this.code = code;
  }
}

const b64 = (b) => Buffer.from(b).toString('base64url');
function unb64(s, what) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new VaultHelloError('invalid', what);
  return Buffer.from(s, 'base64url');
}

/** The Windows Hello key's name for an app and a login (owner = vault.ownerKey, 32 hex). */
function keyName(prefix, owner) {
  const p = String(prefix || 'GateControl Vault').replace(/[^A-Za-z0-9 ._-]/g, '').slice(0, 60) || 'GateControl Vault';
  if (typeof owner !== 'string' || !/^[0-9a-f]{8,64}$/.test(owner)) throw new VaultHelloError('invalid');
  return `${p} ${owner}`;
}

const newChallenge = () => crypto.randomBytes(CHALLENGE_BYTES);

/** The credential's public key (X.509 SubjectPublicKeyInfo, DER) → KeyObject, RSA ≥ 2048 bits; else null. */
function rsaKey(spki) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'rsa') return null;
    const bits = key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength;
    return bits >= MIN_RSA_BITS ? key : null;
  } catch {
    return null;
  }
}

/** Is `signature` the RSA PKCS#1 v1.5 / SHA-256 signature of `challenge` under `spki`? */
function verifies(spki, challenge, signature) {
  const key = rsaKey(spki);
  if (!key || !signature || !signature.length) return false;
  try {
    return crypto.verify('sha256', Buffer.from(challenge), { key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** HKDF-SHA256(signature, challenge) → the 32-byte wrapping key (Uint8Array; wipe it after use). */
function wrappingKey(signature, challenge) {
  if (!signature || signature.length < 64) throw new VaultHelloError('signature');
  return new Uint8Array(crypto.hkdfSync('sha256', Buffer.from(signature), Buffer.from(challenge), HKDF_INFO, KEY_BYTES));
}

const ad = (name) => `${AD_PREFIX}${name}`;

/**
 * A new record for the user key. `signature` must be the Hello signature of `challenge`; `check` how it was
 * found stable ('pkcs1' | 'repeat'). Needs vault-crypto ready().
 */
function seal({ keyName: name, challenge, publicKey, signature, check, userKey }) {
  if (!CHECKS.includes(check) || !(userKey instanceof Uint8Array) || userKey.length !== KEY_BYTES) throw new VaultHelloError('invalid');
  if (check === 'pkcs1' && !verifies(publicKey, challenge, signature)) throw new VaultHelloError('signature');
  const k = wrappingKey(signature, challenge);
  try {
    return {
      v: RECORD_VERSION,
      keyName: name,
      challenge: b64(challenge),
      publicKey: b64(publicKey),
      check,
      wrapped: b64(vc.wrap(k, userKey, ad(name))),
    };
  } finally {
    k.fill(0);
  }
}

/**
 * The record + a fresh Hello signature of its challenge → the user key (Uint8Array, 32 B).
 * VaultHelloError 'signature' (another key signed: Hello was reset) or 'invalid' (does not open).
 */
function open(record, signature) {
  const r = parseRecord(record);
  if (!r) throw new VaultHelloError('invalid');
  const challenge = unb64(r.challenge, 'challenge');
  if (r.check === 'pkcs1' && !verifies(unb64(r.publicKey, 'publicKey'), challenge, signature)) throw new VaultHelloError('signature');
  const k = wrappingKey(signature, challenge);
  try {
    const key = vc.unwrap(k, unb64(r.wrapped, 'wrapped'), ad(r.keyName));
    if (key.length !== KEY_BYTES) throw new VaultHelloError('invalid');
    return key;
  } catch (err) {
    if (err instanceof VaultHelloError) throw err;
    throw new VaultHelloError('invalid');
  } finally {
    k.fill(0);
  }
}

/** A record object (or its JSON) → the record when well-formed, else null. */
function parseRecord(x) {
  let r = x;
  if (Buffer.isBuffer(x) || x instanceof Uint8Array) {
    try { r = JSON.parse(Buffer.from(x).toString('utf8')); } catch { return null; }
  } else if (typeof x === 'string') {
    try { r = JSON.parse(x); } catch { return null; }
  }
  if (!r || typeof r !== 'object' || r.v !== RECORD_VERSION || !CHECKS.includes(r.check)) return null;
  if (typeof r.keyName !== 'string' || !r.keyName || r.keyName.length > 200) return null;
  for (const f of ['challenge', 'publicKey', 'wrapped']) if (typeof r[f] !== 'string' || !/^[A-Za-z0-9_-]+$/.test(r[f]) || r[f].length > 8192) return null;
  return { v: r.v, keyName: r.keyName, challenge: r.challenge, publicKey: r.publicKey, check: r.check, wrapped: r.wrapped };
}

const encodeRecord = (r) => Buffer.from(JSON.stringify(r), 'utf8');

module.exports = {
  VaultHelloError,
  RECORD_VERSION,
  CHALLENGE_BYTES,
  MAX_FAILS,
  HKDF_INFO,
  AD_PREFIX,
  keyName,
  newChallenge,
  rsaKey,
  verifies,
  wrappingKey,
  seal,
  open,
  parseRecord,
  encodeRecord,
};
