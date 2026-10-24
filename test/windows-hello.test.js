'use strict';

// Windows Hello (services/windows-hello.js): the WinRT calls through koffi against fake COM objects
// (fixtures/fake-winrt.js — vtables of koffi callbacks, called exactly like the real ones): availability, creating
// a key (public key + signature of the challenge), signing, deleting, the person's answers, async errors, the
// Hello dialog brought to the front, every object released, every HSTRING deleted, every CoTaskMem copy wiped.
// The real WinRT runs in windows-hello.win.test.js (Windows only).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const koffi = require('koffi');

const { createWindowsHello, guidBytes, WinRt, SLOT, KEY_STATUS } = require('../src/services/windows-hello');
const { fakeWinRt } = require('./fixtures/fake-winrt');

const runtimes = [];
after(() => { for (const rt of runtimes) rt.dispose(); });

function setup(opts = {}) {
  const rt = fakeWinRt(koffi, opts);
  runtimes.push(rt);
  const hello = createWindowsHello({ platform: 'win32', koffi, api: rt.api, timing: { pollMs: 1, quickMs: 2000, promptMs: 2000, focusMs: 2000, ...(opts.timing || {}) } });
  return { rt, hello };
}

function clean(rt) {
  assert.deepEqual(rt.live(), [], 'every COM object released');
  assert.equal(rt.strings(), 0, 'every HSTRING deleted');
  assert.equal(rt.leakedMemory(), 0, 'every CoTaskMem block freed');
  assert.ok(rt.freed.every(Boolean), 'CoTaskMem copies wiped before freeing');
}

const challenge = () => crypto.randomBytes(32);

describe('windows-hello: GUIDs and layout', () => {
  it('GUID text → the bytes of a GUID in memory', () => {
    assert.equal(guidBytes('00000036-0000-0000-C000-000000000046').toString('hex'), '3600000000000000c000000000000046');
    assert.equal(guidBytes('{6AAC468B-0EF1-4CE0-8290-4106DA6A63B5}').toString('hex'), '8b46ac6af10ee04c82904106da6a63b5');
    assert.throws(() => guidBytes('nope'));
  });

  it('vtable slots and statuses as in the Windows SDK headers', () => {
    assert.deepEqual([SLOT.isSupportedAsync, SLOT.requestCreateAsync, SLOT.openAsync, SLOT.deleteAsync], [6, 8, 9, 10]);
    assert.deepEqual([SLOT.asyncStatus, SLOT.asyncErrorCode, SLOT.asyncCancel, SLOT.asyncClose, SLOT.getResults], [7, 8, 9, 10, 8]);
    assert.deepEqual([SLOT.credentialPublicKey, SLOT.credentialSign, SLOT.bufferFromBytes, SLOT.bufferToBytes], [7, 9, 9, 10]);
    assert.deepEqual(KEY_STATUS, ['ok', 'failed', 'not_found', 'cancelled', 'prefers_password', 'exists', 'locked']);
  });
});

describe('windows-hello: availability', () => {
  it('not Windows: unsupported_os without loading anything', async () => {
    const hello = createWindowsHello({ platform: 'linux', koffi: { load() { throw new Error('must not load'); } } });
    assert.deepEqual(await hello.available(), { available: false, reason: 'unsupported_os' });
    assert.deepEqual(await hello.sign('x', challenge()), { status: 'unavailable' });
  });

  it('set up → available; not set up → not_set_up; remote desktop → remote_session; COM initialized once', async () => {
    const { rt, hello } = setup();
    assert.deepEqual(await hello.available(), { available: true, reason: null });
    assert.equal(rt.roInit, 1, 'plain Node: RoInitialize(MTA)');
    rt.supported = false;
    assert.deepEqual(await hello.available(), { available: false, reason: 'not_set_up' });
    rt.remote = true;
    assert.deepEqual(await hello.available(), { available: false, reason: 'remote_session' });
    assert.deepEqual(await hello.sign('x', challenge()), { status: 'unavailable' });
    assert.equal(rt.roInit, 1);
    clean(rt);
  });

  it('an STA thread (Electron main) keeps its apartment', async () => {
    const { rt, hello } = setup();
    rt.apartment = 0;
    assert.equal((await hello.available()).available, true);
    assert.equal(rt.roInit, 0);
  });

  it('a buffer round trip that does not match → error (never used with a wrong layout)', async () => {
    const { rt, hello } = setup();
    rt.badBuffer = true;
    assert.deepEqual(await hello.available(), { available: false, reason: 'error' });
    clean(rt);
  });

  it('IsSupportedAsync failing → error; koffi missing → unsupported_os', async () => {
    const { rt, hello } = setup();
    rt.asyncError = 0x80070005 | 0;
    assert.deepEqual(await hello.available(), { available: false, reason: 'error' });
    clean(rt);
    const broken = createWindowsHello({ platform: 'win32', koffi: { load() { throw new Error('no dll'); }, proto() {}, sizeof: () => 8 } });
    assert.deepEqual(await broken.available(), { available: false, reason: 'unsupported_os' });
  });
});

describe('windows-hello: keys', () => {
  it('create → RSA 2048 public key and a PKCS#1 v1.5 signature of the challenge; sign gives the same bytes', async () => {
    const { rt, hello } = setup();
    const c = challenge();
    const made = await hello.create('GateControl Vault abc', c);
    assert.equal(made.status, 'ok');
    assert.deepEqual(rt.prompts.map((p) => [p.kind, p.name, p.option]), [['create', 'GateControl Vault abc', 0], ['sign', 'GateControl Vault abc', undefined]]);
    const key = crypto.createPublicKey({ key: made.publicKey, format: 'der', type: 'spki' });
    assert.equal(key.asymmetricKeyDetails.modulusLength, 2048);
    assert.ok(crypto.verify('sha256', c, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, made.signature));
    const again = await hello.sign('GateControl Vault abc', c);
    assert.equal(again.status, 'ok');
    assert.ok(again.signature.equals(made.signature), 'deterministic');
    clean(rt);
  });

  it("the person's answers: cancelled, prefers_password, locked; a missing key: not_found", async () => {
    const { rt, hello } = setup();
    const c = challenge();
    rt.next = 'cancel';
    assert.deepEqual(await hello.create('k', c), { status: 'cancelled' });
    assert.equal(rt.created, 0);
    await hello.create('k', c);
    rt.next = 'password';
    assert.deepEqual(await hello.sign('k', c), { status: 'prefers_password' });
    rt.next = 'locked';
    assert.deepEqual(await hello.sign('k', c), { status: 'locked' });
    rt.next = 'cancel';
    assert.deepEqual(await hello.sign('k', c), { status: 'cancelled' });
    assert.deepEqual(await hello.sign('other', c), { status: 'not_found' });
    assert.equal(rt.prompts.filter((p) => p.name === 'other').length, 0, 'no prompt for a key that does not exist');
    clean(rt);
  });

  it('remove deletes the key (no prompt); a missing key is not_found', async () => {
    const { rt, hello } = setup();
    await hello.create('k', challenge());
    assert.equal(await hello.exists('k'), 'ok');
    const prompts = rt.prompts.length;
    assert.deepEqual(await hello.remove('k'), { status: 'ok' });
    assert.equal(rt.keys.has('k'), false);
    assert.equal(rt.prompts.length, prompts);
    assert.deepEqual(await hello.remove('k'), { status: 'not_found' });
    assert.equal(await hello.exists('k'), 'not_found');
    clean(rt);
  });

  it('an async error or a timeout → failed (operation cancelled), nothing leaks', async () => {
    const { rt, hello } = setup({ timing: { promptMs: 30 } });
    rt.asyncError = 0x80090029 | 0;
    assert.deepEqual(await hello.create('k', challenge()), { status: 'failed' });
    rt.polls = 1e9;
    assert.deepEqual(await hello.create('k', challenge()), { status: 'failed' });
    rt.polls = 2;
    clean(rt);
  });

  it('bad arguments never reach Windows', async () => {
    const { rt, hello } = setup();
    assert.deepEqual(await hello.create('', challenge()), { status: 'failed' });
    assert.deepEqual(await hello.sign('k', Buffer.alloc(0)), { status: 'failed' });
    assert.deepEqual(await hello.sign('k', 'text'), { status: 'failed' });
    assert.deepEqual(await hello.remove('x'.repeat(201)), { status: 'failed' });
    assert.equal(rt.prompts.length, 0);
  });

  it('the Hello dialog is brought to the front once it exists', async () => {
    const { rt, hello } = setup({ polls: 5 });
    rt.dialog = 0x4242n;
    await hello.create('k', challenge());
    assert.ok(rt.focused.length >= 1);
    assert.equal(rt.focused[0], 0x4242n);
  });

  it('one prompt at a time: concurrent calls run one after another', async () => {
    const { rt, hello } = setup({ polls: 3 });
    await hello.create('k', challenge());
    const c = challenge();
    const [a, b] = await Promise.all([hello.sign('k', c), hello.sign('k', c)]);
    assert.equal(a.status, 'ok');
    assert.ok(a.signature.equals(b.signature));
    clean(rt);
  });

  it('WinRt.finish releases the operation and its IAsyncInfo when results throw', async () => {
    const { rt } = setup();
    const w = new WinRt({ koffi, api: rt.api, timing: { pollMs: 1 } });
    const op = [null];
    w.check(w.invoke(w.manager(), SLOT.isSupportedAsync, w.P.outPtr, op), 'IsSupportedAsync');
    await assert.rejects(w.finish(op[0], () => { throw new Error('boom'); }), /boom/);
    clean(rt);
  });
});
