'use strict';

// GateDrop direct transfer encryption (contract C): AES-256-GCM in 1 MiB
// blocks, nonce = SHA-256(transferId)[0..4] ‖ block counter (8 bytes BE),
// block = ciphertext ‖ tag. Round trips, tampering, reordering, truncation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable, Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const c = require('../src/utils/gatedrop-crypto');
const gd = require('../src/utils/gatedrop');

const KEY = crypto.randomBytes(32);
const TID = 'tr_7f3a9c';

async function through(transform, input, chunk = 65536) {
  const out = [];
  const src = Readable.from((function* () { for (let i = 0; i < input.length; i += chunk) yield input.subarray(i, i + chunk); })());
  await pipeline(src, transform, new Writable({ write(b, _e, cb) { out.push(b); cb(); } }));
  return Buffer.concat(out);
}

describe('GateDrop crypto', () => {
  it('nonce = first 4 bytes of SHA-256(transferId) ‖ counter big-endian', () => {
    const salt = c.transferSalt(TID);
    assert.deepEqual(salt, crypto.createHash('sha256').update(TID).digest().subarray(0, 4));
    const n = c.blockNonce(salt, 258);
    assert.equal(n.length, 12);
    assert.deepEqual(n.subarray(0, 4), salt);
    assert.equal(n.subarray(4).toString('hex'), '0000000000000102');
  });

  it('one block equals a plain AES-256-GCM seal with that nonce (interop)', () => {
    const plain = Buffer.from('hallo GateDrop');
    const sealed = c.encryptBuffer(KEY, TID, plain);
    const cipher = crypto.createCipheriv('aes-256-gcm', KEY, Buffer.concat([c.transferSalt(TID), Buffer.alloc(8)]));
    const expected = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
    assert.deepEqual(sealed, expected);
    assert.equal(sealed.length, gd.encryptedSize(plain.length));
  });

  it('round trip through the streams for sizes around the block border', async () => {
    for (const size of [0, 1, c.BLOCK_SIZE - 1, c.BLOCK_SIZE, c.BLOCK_SIZE + 1, 2 * c.BLOCK_SIZE + 12345]) {
      const plain = crypto.randomBytes(size);
      const sealed = await through(new c.EncryptStream({ key: KEY, transferId: TID }), plain, 100000);
      assert.equal(sealed.length, gd.encryptedSize(size), `size ${size}`);
      assert.deepEqual(sealed, c.encryptBuffer(KEY, TID, plain));
      const back = await through(new c.DecryptStream({ key: KEY, transferId: TID, expectedSize: size }), sealed, 77777);
      assert.deepEqual(back, plain, `size ${size}`);
    }
  });

  it('every block holds 1 MiB of plaintext except the last', () => {
    const sealed = c.encryptBuffer(KEY, TID, Buffer.alloc(c.BLOCK_SIZE + 10));
    assert.equal(sealed.length, c.BLOCK_SIZE + 16 + 10 + 16);
    assert.deepEqual(c.openBlock(KEY, c.transferSalt(TID), 1, sealed.subarray(c.SEALED_BLOCK)), Buffer.alloc(10));
  });

  it('a changed byte fails the tag', async () => {
    const plain = crypto.randomBytes(3000);
    const sealed = c.encryptBuffer(KEY, TID, plain, 1024);
    for (const at of [0, 1500, sealed.length - 1]) {
      const bad = Buffer.from(sealed);
      bad[at] ^= 0x01;
      await assert.rejects(through(new c.DecryptStream({ key: KEY, transferId: TID, blockSize: 1024, expectedSize: 3000 }), bad), (e) => e.code === 'auth');
    }
  });

  it('a wrong key or another transfer id fails', () => {
    const sealed = c.encryptBuffer(KEY, TID, Buffer.from('x'.repeat(100)));
    assert.throws(() => c.decryptBuffer(crypto.randomBytes(32), TID, sealed), (e) => e.code === 'auth');
    assert.throws(() => c.decryptBuffer(KEY, 'tr_other', sealed), (e) => e.code === 'auth');
  });

  it('swapped blocks fail (counter in the nonce)', () => {
    const plain = crypto.randomBytes(2048);
    const sealed = c.encryptBuffer(KEY, TID, plain, 1024);
    const sb = 1024 + 16;
    const swapped = Buffer.concat([sealed.subarray(sb, 2 * sb), sealed.subarray(0, sb)]);
    assert.throws(() => c.decryptBuffer(KEY, TID, swapped, 1024), (e) => e.code === 'auth');
  });

  it('a stream cut at a block border is caught by the announced size', async () => {
    const plain = crypto.randomBytes(3 * 1024);
    const sealed = c.encryptBuffer(KEY, TID, plain, 1024);
    const cut = sealed.subarray(0, 2 * (1024 + 16));
    await assert.rejects(through(new c.DecryptStream({ key: KEY, transferId: TID, blockSize: 1024, expectedSize: plain.length }), cut), (e) => e.code === 'size');
  });

  it('more data than announced is refused at once', async () => {
    const sealed = c.encryptBuffer(KEY, TID, crypto.randomBytes(2048), 1024);
    await assert.rejects(through(new c.DecryptStream({ key: KEY, transferId: TID, blockSize: 1024, expectedSize: 1000 }), sealed), (e) => e.code === 'size');
  });

  it('refuses keys that are not 32 bytes', () => {
    assert.throws(() => new c.EncryptStream({ key: Buffer.alloc(16), transferId: TID }), (e) => e.code === 'key');
  });
});
