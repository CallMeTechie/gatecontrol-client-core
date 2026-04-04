'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const E2EEHandler = require('../src/utils/e2ee');

/**
 * Simulate the server-side ecdhEncrypt() to test the client handler in isolation.
 * This mirrors the server's implementation exactly.
 */
function serverEncrypt(plaintext, clientPublicKeyBase64) {
  const clientPubBuf = Buffer.from(clientPublicKeyBase64, 'base64');
  const serverEcdh = crypto.createECDH('prime256v1');
  serverEcdh.generateKeys();

  const sharedSecret = serverEcdh.computeSecret(clientPubBuf);
  const salt = Buffer.concat([clientPubBuf, serverEcdh.getPublicKey()]);
  const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, 'gatecontrol-rdp-e2ee-v1', 32);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aesKey), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    data: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    serverPublicKey: serverEcdh.getPublicKey('base64'),
  };
}

describe('E2EEHandler', () => {
  it('generates a valid P-256 public key', () => {
    const handler = new E2EEHandler();
    const pubKey = handler.generateKeyPair();

    assert.ok(pubKey);
    const buf = Buffer.from(pubKey, 'base64');
    assert.equal(buf.length, 65); // uncompressed P-256 point
    assert.equal(buf[0], 0x04); // uncompressed prefix

    handler.clear();
  });

  it('decrypts server-encrypted credentials', () => {
    const handler = new E2EEHandler();
    const pubKey = handler.generateKeyPair();

    const credentials = JSON.stringify({
      username: 'admin',
      password: 'Secret123!',
      domain: 'CORP',
    });

    const encrypted = serverEncrypt(credentials, pubKey);
    const decrypted = handler.decrypt(encrypted);

    assert.equal(decrypted, credentials);
    handler.clear();
  });

  it('decryptCredentials() returns parsed object', () => {
    const handler = new E2EEHandler();
    const pubKey = handler.generateKeyPair();

    const encrypted = serverEncrypt(JSON.stringify({
      username: 'user1',
      password: 'pass',
      domain: null,
    }), pubKey);

    const creds = handler.decryptCredentials(encrypted);
    assert.equal(creds.username, 'user1');
    assert.equal(creds.password, 'pass');
    assert.equal(creds.domain, null);

    handler.clear();
  });

  it('throws without generateKeyPair()', () => {
    const handler = new E2EEHandler();
    assert.throws(
      () => handler.decrypt({ data: 'a', iv: 'b', authTag: 'c', serverPublicKey: 'd' }),
      /No keypair generated/
    );
  });

  it('throws on missing encrypted fields', () => {
    const handler = new E2EEHandler();
    handler.generateKeyPair();
    assert.throws(() => handler.decrypt({}), /Invalid encrypted payload/);
    assert.throws(() => handler.decrypt(null), /Invalid encrypted payload/);
    handler.clear();
  });

  it('clear() removes key material', () => {
    const handler = new E2EEHandler();
    handler.generateKeyPair();
    assert.ok(handler.ready);

    handler.clear();
    assert.ok(!handler.ready);
    assert.throws(() => handler.decrypt({
      data: 'a', iv: 'b', authTag: 'c', serverPublicKey: 'd',
    }), /No keypair generated/);
  });

  it('fails with tampered data', () => {
    const handler = new E2EEHandler();
    const pubKey = handler.generateKeyPair();

    const encrypted = serverEncrypt('secret', pubKey);
    encrypted.data = Buffer.from('tampered').toString('base64');

    assert.throws(() => handler.decrypt(encrypted));
    handler.clear();
  });

  it('fails when different keypair decrypts', () => {
    const handler1 = new E2EEHandler();
    const pubKey1 = handler1.generateKeyPair();

    const handler2 = new E2EEHandler();
    handler2.generateKeyPair();

    const encrypted = serverEncrypt('secret', pubKey1);

    // handler2 has a different keypair — decryption must fail
    assert.throws(() => handler2.decrypt(encrypted));

    handler1.clear();
    handler2.clear();
  });

  it('handles unicode', () => {
    const handler = new E2EEHandler();
    const pubKey = handler.generateKeyPair();

    const encrypted = serverEncrypt('Pässwörd! €äüß', pubKey);
    assert.equal(handler.decrypt(encrypted), 'Pässwörd! €äüß');

    handler.clear();
  });

  it('each generateKeyPair() creates fresh keys', () => {
    const handler = new E2EEHandler();
    const key1 = handler.generateKeyPair();
    const key2 = handler.generateKeyPair();
    assert.notEqual(key1, key2);
    handler.clear();
  });
});
