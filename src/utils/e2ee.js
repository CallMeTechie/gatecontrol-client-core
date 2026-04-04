'use strict';

const crypto = require('node:crypto');

/**
 * E2EE Handler for GateControl Client.
 *
 * Uses ephemeral ECDH (prime256v1) + HKDF-SHA256 + AES-256-GCM
 * to decrypt credentials received from the server.
 *
 * Usage:
 *   const handler = new E2EEHandler();
 *   const publicKey = handler.generateKeyPair();
 *   // send publicKey as query param, receive encrypted response
 *   const plaintext = handler.decrypt(encrypted);
 *   handler.clear();
 */
class E2EEHandler {
  constructor() {
    this._ecdh = null;
  }

  /**
   * Generate an ephemeral ECDH keypair.
   * Call this once per credential request.
   *
   * @returns {string} Base64-encoded public key (65 bytes uncompressed P-256 point)
   */
  generateKeyPair() {
    this._ecdh = crypto.createECDH('prime256v1');
    this._ecdh.generateKeys();
    return this._ecdh.getPublicKey('base64');
  }

  /**
   * Decrypt an E2EE response from the server.
   *
   * @param {{ data: string, iv: string, authTag: string, serverPublicKey: string }} encrypted
   *   All fields are base64-encoded.
   * @returns {string} Decrypted plaintext (typically JSON with username/password/domain)
   */
  decrypt(encrypted) {
    if (!this._ecdh) {
      throw new Error('No keypair generated — call generateKeyPair() first');
    }
    if (!encrypted || !encrypted.data || !encrypted.iv || !encrypted.authTag || !encrypted.serverPublicKey) {
      throw new Error('Invalid encrypted payload — missing required fields');
    }

    const serverPubBuf = Buffer.from(encrypted.serverPublicKey, 'base64');

    // 1. Derive shared secret
    const sharedSecret = this._ecdh.computeSecret(serverPubBuf);

    // 2. Derive AES-256 key via HKDF (must match server parameters exactly)
    const clientPubBuf = this._ecdh.getPublicKey();
    const salt = Buffer.concat([clientPubBuf, serverPubBuf]);
    const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, 'gatecontrol-rdp-e2ee-v1', 32);

    // 3. AES-256-GCM decrypt
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(aesKey),
      Buffer.from(encrypted.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted.data, 'base64')),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Parse and decrypt an E2EE credential response.
   * Convenience wrapper that returns the parsed credentials object.
   *
   * @param {{ data: string, iv: string, authTag: string, serverPublicKey: string }} encrypted
   * @returns {{ username: string|null, password: string|null, domain: string|null }}
   */
  decryptCredentials(encrypted) {
    const json = this.decrypt(encrypted);
    return JSON.parse(json);
  }

  /**
   * Clear all key material from memory.
   * Always call this after decryption is complete.
   */
  clear() {
    this._ecdh = null;
  }

  /**
   * Whether a keypair has been generated and is ready for use.
   * @returns {boolean}
   */
  get ready() {
    return this._ecdh !== null;
  }
}

module.exports = E2EEHandler;
