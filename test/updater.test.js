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
const EventEmitter = require('node:events');

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
let spawned;
let calls;
let checkResponse;
let downloadBody;
const realGet = axios.get;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-updater-test-'));
  electron.__state.version = '1.0.0';
  electron.__state.opened = [];
  spawned = [];
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

/**
 * child_process.spawn double: 'ok' (starts and keeps running), 'error'
 * (CreateProcess refused), 'exit' (starts and quits right away).
 */
function fakeSpawn(behavior = 'ok') {
  return (file, args, opts) => {
    const child = new EventEmitter();
    child.pid = 4242;
    child.unref = () => { child.unrefed = true; };
    spawned.push({ file, args, opts, child });
    setImmediate(() => {
      if (behavior === 'error') {
        child.emit('error', Object.assign(new Error('spawn UNKNOWN'), { code: 'UNKNOWN', errno: -4094 }));
        return;
      }
      child.emit('spawn');
      if (behavior === 'exit') setImmediate(() => child.emit('exit', 2, null));
    });
    return child;
  };
}

function makeUpdater(over = {}) {
  const log = makeLog();
  const u = new Updater({
    serverUrl: SERVER, apiKey: 'secret-token', log, product: 'pro', publicKey: PUB_PEM, downloadDir: tmp,
    spawn: fakeSpawn(), launchGraceMs: 30, ...over,
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
    assert.deepEqual(info, { version: '1.1.0', releaseNotes: 'notes', mandatory: false, channel: null, minVersion: null });
    assert.equal(ready.installerPath, path.join(tmp, FILE));
    assert.deepEqual(fs.readFileSync(path.join(tmp, FILE)), INSTALLER);
    assert.equal(fs.existsSync(path.join(tmp, `${FILE}.part`)), false);
    assert.equal(rejected(log), false);
    // GitHub link: no API token leaves for a foreign origin
    assert.equal(downloads().length, 1);
    assert.equal(downloads()[0].opts.headers['X-API-Token'], undefined);
    assert.deepEqual(await u.install(), { ok: true, via: 'spawn' });
    // started directly (no shell), detached so it outlives the app, in update mode
    assert.equal(spawned.length, 1);
    assert.equal(spawned[0].file, path.join(tmp, FILE));
    assert.deepEqual(spawned[0].args, ['--updated']);
    assert.equal(spawned[0].opts.detached, true);
    assert.equal(spawned[0].opts.stdio, 'ignore');
    assert.equal(spawned[0].child.unrefed, true);
    assert.deepEqual(electron.__state.opened, []);
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
    assert.equal((await b.u.install()).code, 'not_ready');
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
    assert.deepEqual((await u.install()).code, 'verify_failed');
    assert.deepEqual(spawned, []);
    assert.deepEqual(electron.__state.opened, []);
    assert.ok(rejected(log));
    assert.equal(u.isUpdateReady(), false, 'the changed file is dropped');
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
      assert.equal((await u.install()).ok, false);
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

describe('Updater: one download at a time (race of two checks)', () => {
  // Download whose bytes the test releases: the first check is still
  // downloading when the second one comes (log 1.43.1: two downloads into
  // the same .part/target, the second overwrote the verified installer →
  // "Installer wurde nach dem Download verändert", then ENOENT on rename).
  function slowDownloads() {
    const gates = [];
    axios.get = async (url, opts = {}) => {
      calls.push({ url, opts });
      if (url.endsWith('/api/v1/client/update/check')) return { data: checkResponse };
      const body = downloadBody;
      const stream = new Readable({ read() {} });
      gates.push(() => { stream.push(body.subarray(0, 100)); stream.push(body.subarray(100)); stream.push(null); });
      return { data: stream };
    };
    return {
      release: async () => {
        while (!gates.length) await new Promise((r) => setImmediate(r));
        gates.shift()();
      },
      pending: () => gates.length,
    };
  }
  const partFiles = () => fs.readdirSync(tmp).filter((n) => n.endsWith('.part'));

  it('two parallel checks download once; the installer starts with the verified file', async () => {
    const dl = slowDownloads();
    const { u, log } = makeUpdater();
    let readyCount = 0;
    u.onUpdateReady = () => { readyCount += 1; };
    const first = u.check();
    const second = u.check();
    await dl.release();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(a.version, '1.1.0');
    assert.deepEqual(a, b);
    assert.equal(downloads().length, 1, 'one download');
    assert.equal(calls.filter((c) => c.url.endsWith('/check')).length, 1, 'the second check joined the first');
    assert.equal(readyCount, 1);
    assert.deepEqual(partFiles(), []);
    assert.deepEqual(fs.readFileSync(path.join(tmp, FILE)), INSTALLER);
    assert.deepEqual(await u.install(), { ok: true, via: 'spawn' });
    assert.equal(rejected(log), false);
    assert.ok(!log.lines.warn.some((l) => l.includes('Update-Download fehlgeschlagen')));
  });

  it('a timer check and a manual check (_check) racing: still one download', async () => {
    const dl = slowDownloads();
    const { u, log } = makeUpdater();
    const p1 = u._check();
    await new Promise((r) => setImmediate(r));
    const p2 = u._check();
    await dl.release();
    await Promise.all([p1, p2]);
    assert.equal(downloads().length, 1);
    assert.equal(dl.pending(), 0);
    assert.ok(u.isUpdateReady());
    assert.equal(rejected(log), false);
  });

  it('a ready, verified update is not downloaded again by the next check', async () => {
    const { u } = makeUpdater();
    await u.check();
    await u.check();
    await u.check();
    assert.equal(downloads().length, 1);
    assert.ok(u.isUpdateReady());
  });

  it('install while the download runs waits for it instead of failing', async () => {
    const dl = slowDownloads();
    const { u, log } = makeUpdater();
    const checking = u.check();
    while (!u.isDownloading()) await new Promise((r) => setImmediate(r));
    const prep = u.prepareInstall();
    await dl.release();
    assert.deepEqual(await prep, { ok: true, version: '1.1.0' });
    await checking;
    assert.equal(downloads().length, 1);
    assert.equal(rejected(log), false);
  });

  it('ensureUpdate(): nothing ready → check and download; afterwards ready', async () => {
    const { u } = makeUpdater();
    assert.equal(u.isUpdateReady(), false);
    assert.equal(await u.ensureUpdate(), true);
    assert.equal(downloads().length, 1);
    assert.equal(await u.ensureUpdate(), true);
    assert.equal(downloads().length, 1, 'ready update reused');
  });

  it('each download writes its own .part file; leftovers of earlier runs are removed', async () => {
    fs.writeFileSync(path.join(tmp, `${FILE}.part`), 'old leftover');
    fs.writeFileSync(path.join(tmp, `${FILE}.123-abc.part`), 'old leftover');
    const dl = slowDownloads();
    const { u } = makeUpdater();
    const checking = u.check();
    while (!u.isDownloading() || !partFiles().length) await new Promise((r) => setImmediate(r));
    const parts = partFiles();
    assert.equal(parts.length, 1);
    assert.match(parts[0], new RegExp(`^${FILE.replace(/\./g, '\\.')}\\.\\d+-[0-9a-f]{12}\\.part$`));
    await dl.release();
    await checking;
    assert.deepEqual(partFiles(), []);
    assert.ok(u.isUpdateReady());
  });

  it('a download overtaken by a newer offer is discarded, not marked ready', async () => {
    const dl = slowDownloads();
    const { u } = makeUpdater();
    const checking = u.check();
    while (!u.isDownloading()) await new Promise((r) => setImmediate(r));
    // A new offer arrives while the old file is still downloading.
    u.latestRelease = { ...u.latestRelease, sha256: 'b'.repeat(64) };
    await dl.release();
    await checking;
    assert.equal(u.downloadPath, null);
    assert.equal(fs.existsSync(path.join(tmp, FILE)), false);
    assert.deepEqual(partFiles(), []);
  });
});

describe('Updater: starting the installer', () => {
  it('prepareInstall only verifies: nothing is started', async () => {
    const { u } = makeUpdater();
    await u.check();
    assert.deepEqual(await u.prepareInstall(), { ok: true, version: '1.1.0' });
    assert.deepEqual(spawned, []);
    assert.deepEqual(electron.__state.opened, []);
  });

  it('a refused direct start falls back to the shell (UAC) and reports its error', async () => {
    const { u, log } = makeUpdater({ spawn: fakeSpawn('error') });
    await u.check();
    assert.deepEqual(await u.install(), { ok: true, via: 'shell' });
    assert.deepEqual(electron.__state.opened, [path.join(tmp, FILE)]);
    assert.ok(log.lines.warn.some((l) => l.includes('spawn UNKNOWN')));

    const b = makeUpdater({ spawn: fakeSpawn('error'), openPath: async () => 'Failed to open path' });
    await b.u.check();
    const r = await b.u.install();
    assert.equal(r.ok, false);
    assert.equal(r.code, 'launch_failed');
    assert.match(r.message, /UNKNOWN.*Failed to open path/);
    assert.ok(b.log.lines.error.some((l) => l.includes('Installer konnte nicht gestartet werden')));
  });

  it('an installer that quits right away is a failure (no silent success)', async () => {
    const { u } = makeUpdater({ spawn: fakeSpawn('exit') });
    await u.check();
    const r = await u.install();
    assert.deepEqual(r, { ok: false, code: 'exited', message: 'Exit-Code 2' });
    assert.deepEqual(electron.__state.opened, [], 'no second start through the shell');
  });

  it('a spawn that throws synchronously is reported as well', async () => {
    const { u } = makeUpdater({
      spawn: () => { throw Object.assign(new Error('bad'), { code: 'EINVAL' }); },
      openPath: async () => 'Failed to open path',
    });
    await u.check();
    const r = await u.install();
    assert.equal(r.code, 'launch_failed');
    assert.match(r.message, /EINVAL/);
  });

  it('a second start while one runs is refused', async () => {
    const { u } = makeUpdater({ launchGraceMs: 80 });
    await u.check();
    const first = u.launchInstaller();
    assert.equal((await u.launchInstaller()).code, 'busy');
    assert.equal((await u.prepareInstall()).code, 'busy');
    assert.equal((await first).ok, true);
    assert.equal(spawned.length, 1);
  });
});

describe('Updater: server policy (channel / minVersion / mandatory)', () => {
  it('passes channel, minVersion and mandatory through for a verified, newer update', async () => {
    Object.assign(checkResponse, { channel: 'beta', minVersion: '1.0.5', mandatory: true });
    const { u, log } = makeUpdater();
    let ready = null;
    const seen = [];
    u.start((r) => { ready = r; }, { onPolicyChange: (p) => seen.push(p) });
    u.stop();
    const info = await u.check();
    assert.deepEqual(info, { version: '1.1.0', releaseNotes: 'notes', mandatory: true, channel: 'beta', minVersion: '1.0.5' });
    assert.equal(ready.mandatory, true);
    assert.equal(ready.channel, 'beta');
    assert.equal(u.isMandatory(), true);
    assert.equal(u.isBelowMinimum(), true);
    assert.deepEqual(u.getUpdatePolicy(), {
      channel: 'beta', minVersion: '1.0.5', belowMinimum: true, mandatory: true, updateReady: true, version: '1.1.0',
    });
    assert.equal(seen[seen.length - 1].mandatory, true);
    assert.equal(rejected(log), false);
  });

  it('mandatory never bypasses the signature check', async () => {
    Object.assign(checkResponse, { mandatory: true, minVersion: '1.1.0', channel: 'stable' });
    checkResponse.signature = sign(checkResponse.manifest, other.privateKey);
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.ok(rejected(log));
    assert.equal(downloads().length, 0);
    assert.equal(u.isMandatory(), false);
    assert.equal((await u.install()).ok, false);
    // the hint itself is kept for display only
    assert.equal(u.getUpdatePolicy().belowMinimum, true);
    assert.equal(u.getUpdatePolicy().mandatory, false);
  });

  it('mandatory never allows a downgrade or a reinstall', async () => {
    electron.__state.version = '1.2.0';
    Object.assign(checkResponse, { mandatory: true, minVersion: '1.5.0' });
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.ok(log.lines.error.some((l) => l.includes('nicht neuer')));
    assert.equal(downloads().length, 0);
    assert.equal(u.isMandatory(), false);
    assert.equal((await u.install()).ok, false);
  });

  it('mandatory never skips the hash check of the download', async () => {
    Object.assign(checkResponse, { mandatory: true });
    downloadBody = Buffer.concat([INSTALLER.subarray(0, 10), Buffer.from('X'), INSTALLER.subarray(11)]);
    const { u, log } = makeUpdater();
    assert.equal(await u.check(), null);
    assert.ok(rejected(log));
    assert.equal(u.isUpdateReady(), false);
    assert.equal(u.isMandatory(), false);
  });

  it('minVersion alone makes a ready update mandatory; above it the update stays optional', async () => {
    Object.assign(checkResponse, { minVersion: '1.0.1' });
    let { u } = makeUpdater();
    await u.check();
    assert.equal(u.isMandatory(), true);

    Object.assign(checkResponse, { minVersion: '1.0.0', mandatory: false });
    ({ u } = makeUpdater());
    await u.check();
    assert.equal(u.isUpdateReady(), true);
    assert.equal(u.isMandatory(), false);
  });

  it('sanitizes the unsigned fields', () => {
    assert.deepEqual(Updater.sanitizeUpdatePolicy({ channel: 'nightly', minVersion: '1.2', mandatory: 'true' }),
      { channel: null, minVersion: null, mandatory: false });
    assert.deepEqual(Updater.sanitizeUpdatePolicy({ channel: 'beta', minVersion: '2.0.0', mandatory: true }),
      { channel: 'beta', minVersion: '2.0.0', mandatory: true });
    assert.deepEqual(Updater.sanitizeUpdatePolicy(null), { channel: null, minVersion: null, mandatory: false });
  });

  it('keeps the channel from a check without update (old servers: none)', async () => {
    checkResponse = { ok: true, available: false, channel: 'beta', minVersion: null, mandatory: false };
    const { u } = makeUpdater();
    await u.check();
    assert.equal(u.getUpdatePolicy().channel, 'beta');
    checkResponse = { ok: true, available: false };
    await u.check();
    assert.equal(u.getUpdatePolicy().channel, null);
  });
});
