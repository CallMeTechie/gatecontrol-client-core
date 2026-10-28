'use strict';

// Windows Hello against the real Windows Runtime (Windows only; skipped elsewhere). Never opens a prompt — CI runners
// have no Hello: availability detection answers with a known reason and does not crash, the WinRT layout of this
// code is right (CryptographicBuffer round trip, KeyCredentialManager activation, IsSupportedAsync, OpenAsync of a
// name that does not exist, every object released). The Hello dialog itself needs a person: see docs/vault.md.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { createWindowsHello, createConsentVerifier, WinRt, loadApi, IID, SLOT } = require('../src/services/windows-hello');

const win = process.platform === 'win32';

describe('windows-hello on Windows (no prompt)', { skip: win ? false : 'Windows only' }, () => {
  it('available() answers with a known reason', async () => {
    const hello = createWindowsHello();
    const a = await hello.available();
    assert.equal(typeof a.available, 'boolean');
    assert.ok(a.available ? a.reason === null : ['unsupported_os', 'remote_session', 'not_set_up', 'error'].includes(a.reason), JSON.stringify(a));
    // a second call reuses the loaded runtime
    assert.deepEqual(await hello.available(), a);
    console.log(`Windows Hello here: ${JSON.stringify(a)}`);
  });

  it('the WinRT layout: buffers round trip, KeyCredentialManager answers, no key of a random name', async () => {
    const koffi = require('koffi');
    const rt = new WinRt({ koffi, api: loadApi(koffi), timing: { pollMs: 20 } });
    assert.equal(rt.probe(), true, 'CryptographicBuffer CreateFromByteArray / CopyToByteArray');
    const big = crypto.randomBytes(512);
    const buf = rt.bufferFrom(Buffer.from(big));
    assert.ok(rt.bytesOf(buf).equals(big));
    rt.release(buf);
    assert.equal(typeof rt.remoteSession(), 'boolean');
    assert.ok(rt.manager(), 'KeyCredentialManager activation factory');
    assert.equal(typeof (await rt.isSupported()), 'boolean');
    const status = await rt.exists(`GateControl CI ${crypto.randomBytes(8).toString('hex')}`);
    assert.ok(['not_found', 'failed', 'locked'].includes(status), status);
  });

  it('remove() of a key that does not exist: no prompt, no crash', async () => {
    const hello = createWindowsHello();
    const r = await hello.remove(`GateControl CI ${crypto.randomBytes(8).toString('hex')}`);
    assert.ok(['not_found', 'failed', 'unavailable'].includes(r.status), JSON.stringify(r));
  });

  it('UserConsentVerifier (Drive vaults): availability with a known answer, the interop for a window, our IIDs', async () => {
    const consent = createConsentVerifier();
    const a = await consent.available();
    assert.equal(typeof a.available, 'boolean');
    assert.ok(a.available ? a.reason === null : ['not_set_up', 'device_not_present', 'disabled_by_policy', 'device_busy', 'unsupported_os', 'error'].includes(a.reason), JSON.stringify(a));
    console.log(`UserConsentVerifier here: ${JSON.stringify(a)}`);
    const koffi = require('koffi');
    const rt = new WinRt({ koffi, api: loadApi(koffi), timing: { pollMs: 20 } });
    assert.ok(rt.consentStatics(), 'UserConsentVerifier activation factory (IUserConsentVerifierStatics)');
    assert.ok(rt.consentInterop(), 'IUserConsentVerifierInterop on the factory');
    // the parameterized IID computed here is the one Windows answers to (QueryInterface on the real operation)
    const op = [null];
    rt.check(rt.invoke(rt.consentStatics(), SLOT.consentAvailability, rt.P.outPtr, op), 'CheckAvailabilityAsync');
    const same = rt.queryInterface(op[0], IID.IAsyncAvailability);
    rt.release(same);
    const v = await rt.finish(op[0], (o) => rt._i32Result(o));
    assert.ok(Number.isInteger(v) && v >= 0 && v <= 4, String(v));
  });
});
