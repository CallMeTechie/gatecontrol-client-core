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

  it("without koffi.view (Electron's V8 sandbox forbids external buffers): everything still works", async () => {
    const rt = fakeWinRt(koffi);
    runtimes.push(rt);
    const noView = new Proxy(koffi, { get: (o, k) => (k === 'view' ? () => { throw new Error('external buffers are not allowed'); } : o[k]) });
    const hello = createWindowsHello({ platform: 'win32', koffi: noView, api: rt.api, timing: { pollMs: 1 } });
    assert.deepEqual(await hello.available(), { available: true, reason: null });
    const c = challenge();
    const made = await hello.create('k', c);
    assert.equal(made.status, 'ok');
    assert.ok((await hello.sign('k', c)).signature.equals(made.signature));
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

// ── UserConsentVerifier (Drive vault folders: "Mit Windows Hello öffnen") ──

const { createConsentVerifier, pinterfaceIid, hwndOf, IID, CONSENT_RESULT, CONSENT_AVAILABILITY } = require('../src/services/windows-hello');

function setupConsent(opts = {}) {
  const rt = fakeWinRt(koffi, opts);
  runtimes.push(rt);
  const consent = createConsentVerifier({ platform: 'win32', koffi, api: rt.api, timing: { pollMs: 1, quickMs: 2000, promptMs: 2000, focusMs: 2000 } });
  return { rt, consent };
}

describe('windows-hello: UserConsentVerifier', () => {
  it('parameterized IIDs as Windows computes them (IAsyncOperation<bool>, <HSTRING>, <UserConsentVerificationResult>)', () => {
    const op = '{9fc2b0bb-e446-44e2-aa61-9cab8f636af2}';
    assert.equal(pinterfaceIid(`pinterface(${op};b1)`), 'CDB5EFB3-5788-509D-9BE1-71CCB8A3362A');
    assert.equal(pinterfaceIid(`pinterface(${op};string)`), '3E1FE603-F897-5263-B328-0806426B8A79');
    assert.equal(IID.IAsyncVerificationResult, 'FD596FFD-2318-558F-9DBE-D21DF43764A5');
    assert.deepEqual(CONSENT_AVAILABILITY, ['available', 'device_not_present', 'not_set_up', 'disabled_by_policy', 'device_busy']);
    assert.deepEqual(CONSENT_RESULT, ['verified', 'device_not_present', 'not_set_up', 'disabled_by_policy', 'device_busy', 'retries_exhausted', 'cancelled']);
  });

  it('a window handle from getNativeWindowHandle(), a BigInt or a number; anything else → null', () => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(0x1a2b3cn);
    assert.equal(hwndOf(b), 0x1a2b3cn);
    assert.equal(hwndOf(7n), 7n);
    assert.equal(hwndOf(9), 9n);
    for (const x of [null, undefined, 0, -1, 0n, 'x', Buffer.alloc(3), Buffer.alloc(8)]) assert.equal(hwndOf(x), null);
  });

  it('not Windows: unsupported_os / unavailable without loading anything', async () => {
    const consent = createConsentVerifier({ platform: 'linux', koffi: { load() { throw new Error('must not load'); } } });
    assert.deepEqual(await consent.available(), { available: false, reason: 'unsupported_os' });
    assert.deepEqual(await consent.verify('Tresor öffnen'), { status: 'unavailable' });
  });

  it('availability: available, not set up, disabled by policy — no prompt', async () => {
    const { rt, consent } = setupConsent();
    assert.deepEqual(await consent.available(), { available: true, reason: null });
    rt.consent.avail = 'not_set_up';
    assert.deepEqual(await consent.available(), { available: false, reason: 'not_set_up' });
    rt.consent.avail = 'disabled_by_policy';
    assert.deepEqual(await consent.available(), { available: false, reason: 'disabled_by_policy' });
    assert.equal(rt.consentPrompts.length, 0);
    clean(rt);
  });

  it('verify with the app window: the dialog owned by it (interop); the answers come back', async () => {
    const { rt, consent } = setupConsent();
    const hwnd = Buffer.alloc(8);
    hwnd.writeBigUInt64LE(0x4242n);
    assert.deepEqual(await consent.verify('GateControl Drive: Tresore entsperren', { window: hwnd }), { status: 'verified' });
    assert.deepEqual(rt.consentPrompts[0], { kind: 'window', message: 'GateControl Drive: Tresore entsperren', hwnd: 0x4242n });
    rt.consent.next = 'cancelled';
    assert.deepEqual(await consent.verify('x', { window: hwnd }), { status: 'cancelled' });
    rt.consent.next = 'retries_exhausted';
    assert.deepEqual(await consent.verify('x', { window: hwnd }), { status: 'retries_exhausted' });
    clean(rt);
  });

  it('without a window, without the interop or when the window is refused: the plain call, dialog to the front', async () => {
    const { rt, consent } = setupConsent();
    rt.dialog = 0x77n;
    assert.deepEqual(await consent.verify('Tresor'), { status: 'verified' });
    assert.equal(rt.consentPrompts[0].kind, 'plain');
    assert.ok(rt.focused.length >= 1);
    rt.consent.windowFails = true;
    assert.deepEqual(await consent.verify('Tresor', { window: 5n }), { status: 'verified' });
    assert.equal(rt.consentPrompts[1].kind, 'plain');
    clean(rt);
    const b = setupConsent();
    b.rt.consent.interop = false;
    assert.deepEqual(await b.consent.verify('Tresor', { window: 5n }), { status: 'verified' });
    assert.equal(b.rt.consentPrompts[0].kind, 'plain');
    clean(b.rt);
  });

  it('not set up: no dialog, the reason; an async error → failed; empty message never reaches Windows', async () => {
    const { rt, consent } = setupConsent();
    rt.consent.avail = 'not_set_up';
    assert.deepEqual(await consent.verify('Tresor', { window: 5n }), { status: 'not_set_up' });
    assert.equal(rt.consentPrompts.length, 0);
    rt.consent.avail = 'available';
    rt.asyncError = 0x80004005 | 0;
    assert.deepEqual(await consent.verify('Tresor', { window: 5n }), { status: 'failed' });
    assert.deepEqual(await consent.verify('   '), { status: 'failed' });
    clean(rt);
  });

  it('one dialog at a time', async () => {
    const { rt, consent } = setupConsent();
    rt.consent.next = ['verified', 'cancelled'];
    const [a, b] = await Promise.all([consent.verify('a', { window: 5n }), consent.verify('b', { window: 5n })]);
    assert.deepEqual([a.status, b.status], ['verified', 'cancelled']);
    assert.deepEqual(rt.consentPrompts.map((p) => p.message), ['a', 'b']);
    clean(rt);
  });
});
