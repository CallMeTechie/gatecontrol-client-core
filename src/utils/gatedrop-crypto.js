'use strict';

/**
 * GateDrop direct transfer encryption (contract C, protocol v1):
 *
 *   AES-256-GCM with the transfer key (32 bytes from the plugin), the file
 *   cut into blocks of 1 MiB plaintext; block i is sealed with
 *     nonce = first 4 bytes of SHA-256(transferId) ‖ i as 8-byte big-endian
 *   and sent as ciphertext ‖ tag (16 bytes). Every block but the last holds
 *   exactly 1 MiB; an empty file is an empty body.
 *
 * The block counter in the nonce keeps blocks in order (reordering / reuse
 * fails the tag); a cut-off stream is caught by comparing the plaintext
 * length with the announced size (DecryptStream `expectedSize`).
 *
 * Node streams only (Transform), unit-tested directly.
 */

const crypto = require('crypto');
const { Transform } = require('stream');

const BLOCK_SIZE = 1024 * 1024;
const TAG_SIZE = 16;
const SEALED_BLOCK = BLOCK_SIZE + TAG_SIZE;

class GateDropCryptoError extends Error {
  constructor(message, code = 'crypto') {
    super(message);
    this.name = 'GateDropCryptoError';
    this.code = code;
  }
}

/** First 4 bytes of SHA-256(transferId) (UTF-8). */
function transferSalt(transferId) {
  return crypto.createHash('sha256').update(String(transferId), 'utf8').digest().subarray(0, 4);
}

/** 12-byte GCM nonce of block `counter`. */
function blockNonce(salt, counter) {
  const n = Buffer.alloc(12);
  salt.copy(n, 0, 0, 4);
  n.writeBigUInt64BE(BigInt(counter), 4);
  return n;
}

function checkKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new GateDropCryptoError('transfer key must be 32 bytes', 'key');
}

/** Seal one block → ciphertext ‖ tag. */
function sealBlock(key, salt, counter, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', key, blockNonce(salt, counter));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}

/** Open one block (ciphertext ‖ tag) → plaintext; throws on a wrong tag. */
function openBlock(key, salt, counter, sealed) {
  if (sealed.length < TAG_SIZE) throw new GateDropCryptoError('block too short', 'truncated');
  const d = crypto.createDecipheriv('aes-256-gcm', key, blockNonce(salt, counter));
  d.setAuthTag(sealed.subarray(sealed.length - TAG_SIZE));
  try {
    return Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG_SIZE)), d.final()]);
  } catch {
    throw new GateDropCryptoError('block authentication failed', 'auth');
  }
}

/** Collects chunks without copying until a block is complete. */
class Chunks {
  constructor() { this.list = []; this.length = 0; }
  push(b) { if (b.length) { this.list.push(b); this.length += b.length; } }
  take(n) {
    const out = Buffer.allocUnsafe(n);
    let off = 0;
    while (off < n) {
      const head = this.list[0];
      const need = n - off;
      if (head.length <= need) {
        head.copy(out, off);
        off += head.length;
        this.list.shift();
      } else {
        head.copy(out, off, 0, need);
        this.list[0] = head.subarray(need);
        off += need;
      }
    }
    this.length -= n;
    return out;
  }
}

/** plaintext in → sealed blocks out. */
class EncryptStream extends Transform {
  constructor({ key, transferId, blockSize = BLOCK_SIZE } = {}) {
    super();
    checkKey(key);
    this.key = key;
    this.salt = transferSalt(transferId);
    this.blockSize = blockSize;
    this.counter = 0;
    this.buf = new Chunks();
  }

  _transform(chunk, _enc, cb) {
    this.buf.push(chunk);
    try {
      while (this.buf.length >= this.blockSize) this.push(sealBlock(this.key, this.salt, this.counter++, this.buf.take(this.blockSize)));
      cb();
    } catch (err) { cb(err); }
  }

  _flush(cb) {
    try {
      if (this.buf.length) this.push(sealBlock(this.key, this.salt, this.counter++, this.buf.take(this.buf.length)));
      cb();
    } catch (err) { cb(err); }
  }
}

/**
 * sealed blocks in → plaintext out. `expectedSize` (announced plaintext
 * length): more data fails at once, less fails at the end. `maxBytes`
 * caps the plaintext when no size is known.
 */
class DecryptStream extends Transform {
  constructor({ key, transferId, expectedSize = null, maxBytes = Infinity, blockSize = BLOCK_SIZE } = {}) {
    super();
    checkKey(key);
    this.key = key;
    this.salt = transferSalt(transferId);
    this.sealedBlock = blockSize + TAG_SIZE;
    this.counter = 0;
    this.expected = Number.isSafeInteger(expectedSize) && expectedSize >= 0 ? expectedSize : null;
    this.maxBytes = this.expected !== null ? this.expected : maxBytes;
    this.plainBytes = 0;
    this.buf = new Chunks();
  }

  _emit(plain) {
    this.plainBytes += plain.length;
    if (this.plainBytes > this.maxBytes) throw new GateDropCryptoError('more data than announced', 'size');
    if (plain.length) this.push(plain);
  }

  _transform(chunk, _enc, cb) {
    this.buf.push(chunk);
    try {
      // Every block but the last is full: a full block can be opened at once.
      while (this.buf.length >= this.sealedBlock) {
        this._emit(openBlock(this.key, this.salt, this.counter++, this.buf.take(this.sealedBlock)));
      }
      cb();
    } catch (err) { cb(err); }
  }

  _flush(cb) {
    try {
      if (this.buf.length) this._emit(openBlock(this.key, this.salt, this.counter++, this.buf.take(this.buf.length)));
      if (this.expected !== null && this.plainBytes !== this.expected) throw new GateDropCryptoError('transfer cut off', 'size');
      cb();
    } catch (err) { cb(err); }
  }
}

/** Whole buffer helpers (tests, small payloads). */
function encryptBuffer(key, transferId, plain, blockSize = BLOCK_SIZE) {
  checkKey(key);
  const salt = transferSalt(transferId);
  const out = [];
  for (let off = 0, i = 0; off < plain.length; off += blockSize, i++) out.push(sealBlock(key, salt, i, plain.subarray(off, off + blockSize)));
  return Buffer.concat(out);
}

function decryptBuffer(key, transferId, sealed, blockSize = BLOCK_SIZE) {
  checkKey(key);
  const salt = transferSalt(transferId);
  const out = [];
  const sb = blockSize + TAG_SIZE;
  for (let off = 0, i = 0; off < sealed.length; off += sb, i++) out.push(openBlock(key, salt, i, sealed.subarray(off, off + sb)));
  return Buffer.concat(out);
}

module.exports = {
  BLOCK_SIZE, TAG_SIZE, SEALED_BLOCK,
  GateDropCryptoError, transferSalt, blockNonce, sealBlock, openBlock,
  EncryptStream, DecryptStream, encryptBuffer, decryptBuffer,
};
