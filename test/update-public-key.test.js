'use strict';

// Loader for the Ed25519 update-signing public key (shared by Pro and
// Community). The apps keep their own tests for the committed key file, the
// extraResources entry and scripts/sign-update.js.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadUpdatePublicKey, updatePublicKeyPaths, PLACEHOLDER } = require('../src/utils/update-public-key');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gc-pubkey-test-'));
}

function publicPem() {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return publicKey.export({ type: 'spki', format: 'pem' });
}

describe('loadUpdatePublicKey', () => {
  it('loads a real key and treats placeholder / missing / non-PEM as no key', () => {
    const dir = tmpDir();
    const pub = publicPem();
    fs.writeFileSync(path.join(dir, 'real.pub'), pub);
    fs.writeFileSync(path.join(dir, 'placeholder.pub'), `${PLACEHOLDER}\n`);
    fs.writeFileSync(path.join(dir, 'junk.pub'), 'hello');
    assert.equal(loadUpdatePublicKey([path.join(dir, 'real.pub')]), pub);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'missing.pub'), path.join(dir, 'real.pub')]), pub);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'placeholder.pub')]), null);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'junk.pub')]), null);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'missing.pub')]), null);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('prefers resources/update-signing.pub over the repo build/ copy', () => {
    const dir = tmpDir();
    const resources = path.join(dir, 'resources');
    const appRoot = path.join(dir, 'app');
    fs.mkdirSync(resources);
    fs.mkdirSync(path.join(appRoot, 'build'), { recursive: true });
    const installed = publicPem();
    const repo = publicPem();
    fs.writeFileSync(path.join(resources, 'update-signing.pub'), installed);
    fs.writeFileSync(path.join(appRoot, 'build', 'update-signing.pub'), repo);

    assert.deepEqual(updatePublicKeyPaths({ resourcesPath: resources, appRoot }), [
      path.join(resources, 'update-signing.pub'),
      path.join(appRoot, 'build', 'update-signing.pub'),
    ]);
    assert.equal(loadUpdatePublicKey({ resourcesPath: resources, appRoot }), installed);
    // development: no installed copy → build/ in the app repo
    assert.equal(loadUpdatePublicKey({ resourcesPath: path.join(dir, 'nope'), appRoot }), repo);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('without an app root only the installed location is used', () => {
    assert.deepEqual(updatePublicKeyPaths({ resourcesPath: '/x' }), [path.join('/x', 'update-signing.pub')]);
    assert.deepEqual(updatePublicKeyPaths({ resourcesPath: '' }), []);
  });
});
