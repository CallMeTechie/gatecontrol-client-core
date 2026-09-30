'use strict';

// Signed auto-updates: the updater only installs installers whose SHA-256,
// size, file name, product and version are covered by an Ed25519 signature
// made with the release key. electron is replaced by a stub, axios.get is
// replaced per test; a throwaway key pair is generated here.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'electron') return require.resolve('./fixtures/electron-stub');
  return realResolve.call(this, request, ...rest);
};

const electron = require('electron');
const axios = require('axios');
const Updater = require('../src/services/updater');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB_PEM = publicKey.export({ type: 'spki', format: 'pem' });
const other = crypto.generateKeyPairSync('ed25519');

const SERVER = 'https://gate.example.com';
const INSTALLER = Buffer.from('MZ fake installer bytes '.repeat(1000));
const SHA = crypto.createHash('sha256').update(INSTALLER).digest('hex');
const FILE = 'GateControl.Pro.Client.Setup.1.1.0.exe';

function makeManifest(over = {}) {
  return JSON.stringify({
    schema: 1, product: 'pro', version: '1.1.0', fileName: FILE, sha256: SHA, size: INSTALLER.length, ...over,
  });
}
function sign(manifest, key = privateKey) {
  return crypto.sign(null, Buffer.from(manifest, 'utf8'), key).toString('base64');
}

function makeLog() {
  const lines = { info: [], warn: [], error: [], debug: [] };
  const log = {};
  for (const lvl of Object.keys(lines)) log[lvl] = (msg) => lines[lvl].push(String(msg));
  log.lines = lines;
  return log;
}

let tmp;
let calls;
let checkResponse;
let downloadBody;
const realGet = axios.get;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-updater-test-'));
  electron.__state.version = '1.0.0';
  electron.__state.opened = [];
  calls = [];
  const manifest = makeManifest();
  checkResponse = {
    ok: true, available: true, version: '1.1.0',
    downloadUrl: `https://github.com/CallMeTechie/x/releases/download/v1.1.0/${FILE}`,
    fileName: FILE, fileSize: INSTALLER.length, releaseNotes: 'notes',
    manifest, signature: sign(manifest),
  };
  downloadBody = INSTALLER;
  axios.get = async (url, opts = {}) => {
    calls.push({ url, opts });
    if (url.endsWith('/api/v1/client/update/check')) return { data: checkResponse };
    return { data: Readable.from([downloadBody.subarray(0, 100), downloadBody.subarray(100)]) };
  };
});

afterEach(() => {
  axios.get = realGet;
  fs.rmSync(tmp, { recursive: true, force: true });
});

function makeUpdater(over = {}) {
  const log = makeLog();
  const u = new Updater({
    serverUrl: SERVER, apiKey: 'secret-token', log, product: 'pro', publicKey: PUB_PEM, downloadDir: tmp, ...over,
  });
  return { u, log };
}

const downloads = () => calls.filter((c) => !c.url.endsWith('/check'));
const rejected = (log) => log.lines.error.some((l) => l.includes('Update nicht signiert/ungültig – abgelehnt'));

describe('Updater: signed updates', () => {
  it('accepts a valid signed update, verifies the download and installs it', async () => {
    const { u, log } = makeUpdater();
    let ready = null;
    u.onUpdateReady = (r) => { ready = r; };
    const info = await u.check();
    assert.deepEqual(info, { version: '1.1.0', releaseNotes: 'notes' });
    assert.equal(ready.installerPath, path.join(tmp, FILE));
    assert.deepEqual(fs.readFileSync(path.join(tmp, FILE)), INSTALLER);
    assert.equal(fs.existsSync(path.join(tmp, `${FILE}.part`)), false);
    assert.equal(rejected(log), false);
    // GitHub link: no API token leaves for a foreign origin
    assert.equal(downloads().length, 1);
    assert.equal(downloads()[0].opts.headers['X-API-Token'], undefined);
    assert.equal(u.install(), true);
    assert.deepEqual(electron.__state.opened, [path.join(tmp, FILE)]);
  });

  it('sends the token (without redirects) only to the configured server origin', async () => {
    checkResponse.downloadUrl = `${SERVER}/api/v1/client/update/download?client=pro`;
    const { u } = makeUpdater();
    await u.check();
    assert.equal(downloads()[0].opts.headers['X-API-Token'], 'secret-token');
    assert.equal(downloads()[0].opts.maxRedirects, 0);
    assert.ok(u.isUpdateReady());
  });

  it('does not send the token to a look-alike origin', async () => {
    checkResponse.downloadUrl = 'https://gate.example.com.evil.test/x.exe';
    const { u } = makeUpdater();
    await u.check();
    assert.equal(downloads()[0].opts.headers['X-API-Token'], undefined);
  });

  it('rejects a response without manifest/signature (no unsigned fallback)', async () => {
    delete checkResponse.manifest;
    delete checkResponse.signature;
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.equal(downloads().length, 0);
    assert.ok(rejected(log));
  });

  it('rejects a tampered manifest', async () => {
    checkResponse.manifest = checkResponse.manifest.replace(SHA, 'a'.repeat(64));
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.equal(downloads().length, 0);
    assert.ok(rejected(log));
  });

  it('rejects a tampered signature and a signature by another key', async () => {
    const sig = Buffer.from(checkResponse.signature, 'base64');
    sig[0] ^= 1;
    checkResponse.signature = sig.toString('base64');
    const a = makeUpdater();
    assert.equal(await a.u.check(), null);
    assert.ok(rejected(a.log));

    checkResponse.signature = sign(checkResponse.manifest, other.privateKey);
    const b = makeUpdater();
    assert.equal(await b.u.check(), null);
    assert.ok(rejected(b.log));
    assert.equal(downloads().length, 0);
  });

  it('rejects a manifest for the other product', async () => {
    const m = makeManifest({ product: 'community' });
    Object.assign(checkResponse, { manifest: m, signature: sign(m) });
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.ok(rejected(log));
  });

  it('rejects downgrades, same version and a version differing from the offer', async () => {
    for (const [ver, offered, current] of [['0.9.0', '0.9.0', '1.0.0'], ['1.0.0', '1.0.0', '1.0.0'], ['1.1.0', '1.2.0', '1.0.0']]) {
      electron.__state.version = current;
      const m = makeManifest({ version: ver });
      Object.assign(checkResponse, { version: offered, manifest: m, signature: sign(m) });
      const { u, log } = makeUpdater();
      assert.equal(await u.check(), null, `${ver}/${offered}/${current}`);
      assert.ok(rejected(log));
    }
    assert.equal(downloads().length, 0);
  });

  it('rejects bad file names (traversal, wrong extension)', async () => {
    for (const fileName of ['../evil.exe', '..\\evil.exe', 'sub/evil.exe', 'C:evil.exe', 'evil.bat', '.exe', 'a\u0000.exe']) {
      const m = makeManifest({ fileName });
      Object.assign(checkResponse, { manifest: m, signature: sign(m) });
      const { u, log } = makeUpdater();
      assert.equal(await u.check(), null, fileName);
      assert.ok(rejected(log), fileName);
    }
    assert.equal(downloads().length, 0);
  });

  it('rejects malformed hash, size and schema', async () => {
    for (const over of [{ sha256: 'xyz' }, { size: 0 }, { size: '12' }, { schema: 2 }]) {
      const m = makeManifest(over);
      Object.assign(checkResponse, { manifest: m, signature: sign(m) });
      const { u, log } = makeUpdater();
      assert.equal(await u.check(), null, JSON.stringify(over));
      assert.ok(rejected(log));
    }
  });

  it('rejects a plain http download URL', async () => {
    checkResponse.downloadUrl = `http://gate.example.com/api/v1/client/update/download`;
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.equal(downloads().length, 0);
    assert.ok(rejected(log));
  });

  it('discards a download with the wrong hash or size', async () => {
    downloadBody = Buffer.from(INSTALLER);
    downloadBody[5] ^= 0xff;
    const a = makeUpdater();
    assert.equal(await a.u.check(), null);
    assert.ok(rejected(a.log));
    assert.deepEqual(fs.readdirSync(tmp), []);

    downloadBody = Buffer.concat([INSTALLER, Buffer.from('extra')]);
    const b = makeUpdater();
    assert.equal(await b.u.check(), null);
    assert.deepEqual(fs.readdirSync(tmp), []);
    assert.equal(b.u.install(), false);
  });

  it('re-hashes a cached file before reuse', async () => {
    fs.writeFileSync(path.join(tmp, FILE), 'stale junk');
    const { u } = makeUpdater();
    await u.check();
    assert.equal(downloads().length, 1);
    assert.deepEqual(fs.readFileSync(path.join(tmp, FILE)), INSTALLER);

    calls.length = 0;
    const second = makeUpdater();
    assert.ok(await second.u.check());
    assert.equal(downloads().length, 0, 'verified cache reused');
  });

  it('refuses to install a file modified after the download (TOCTOU)', async () => {
    const { u, log } = makeUpdater();
    await u.check();
    fs.writeFileSync(path.join(tmp, FILE), Buffer.concat([INSTALLER.subarray(0, 10), Buffer.from('X'), INSTALLER.subarray(11)]));
    assert.equal(u.install(), false);
    assert.deepEqual(electron.__state.opened, []);
    assert.ok(rejected(log));
  });

  it('stays disabled without a (valid) public key', async () => {
    for (const publicKey of [undefined, '', 'REPLACE_WITH_UPDATE_PUBLIC_KEY\n', 'garbage',
      crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' })]) {
      const { u, log } = makeUpdater({ publicKey });
      assert.equal(u.disabled, true);
      assert.ok(log.lines.warn.some((l) => l.includes('deaktiviert')));
      u.start(() => {});
      assert.equal(u.checkTimer, null);
      assert.equal(await u.check(), null);
      assert.equal(u.install(), false);
    }
    assert.equal(calls.length, 0);
  });

  it('isNewerVersion compares numerically', () => {
    assert.equal(Updater.isNewerVersion('1.10.0', '1.9.9'), true);
    assert.equal(Updater.isNewerVersion('1.9.9', '1.10.0'), false);
    assert.equal(Updater.isNewerVersion('1.0.0', '1.0.0'), false);
    assert.equal(Updater.isNewerVersion('x', '1.0.0'), false);
  });
});
