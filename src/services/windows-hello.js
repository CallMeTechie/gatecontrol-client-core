'use strict';

/**
 * GateControl – Windows Hello (Core service, Windows)
 *
 * The key behind "Mit Windows Hello entsperren" of Vault: a Windows Hello key
 * credential (Windows.Security.Credentials.KeyCredentialManager, RSA 2048 in
 * the Microsoft Passport key storage provider — in the TPM when there is one)
 * that signs a fixed random challenge only after face, fingerprint or PIN.
 * RSA PKCS#1 v1.5 signatures are deterministic, so the signature is stable
 * key material (utils/vault-hello.js derives the wrapping key from it); the
 * private key never leaves Windows.
 *
 * WinRT is called directly through koffi (no PowerShell, no native addon):
 *
 *   combase  RoGetActivationFactory(class, IID) → statics; WindowsCreateString / WindowsDeleteString
 *   ole32    CoGetApartmentType (COM on this thread? Electron's main thread is an STA already;
 *            plain Node gets RoInitialize(MTA)), CoTaskMemFree
 *   user32   GetSystemMetrics(SM_REMOTESESSION) (Hello does not work in a remote desktop session),
 *            FindWindowW / SetForegroundWindow (the Hello dialog in front of the app)
 *
 *   KeyCredentialManager  IsSupportedAsync · RequestCreateAsync(name, ReplaceExisting) · OpenAsync(name) · DeleteAsync(name)
 *   KeyCredential         RetrievePublicKey() (X.509 SubjectPublicKeyInfo) · RequestSignAsync(IBuffer)
 *   CryptographicBuffer   CreateFromByteArray / CopyToByteArray (IBuffer ⇄ bytes)
 *
 * Async operations are polled through IAsyncInfo.Status (setTimeout, so the
 * Electron main thread keeps pumping messages while the dialog is open); no
 * COM callback object is needed. koffi and the DLLs load on the first call
 * on Windows only, so requiring this module is safe anywhere. The COM layer
 * takes { koffi, api } so test/windows-hello.test.js runs it against fake
 * COM objects (koffi callbacks) on any platform; test/windows-hello.win.test.js
 * runs the real one on Windows (no prompt: availability, buffers, OpenAsync
 * of a name that does not exist).
 *
 * createWindowsHello() → provider:
 *   available()             → { available, reason: null | 'unsupported_os' | 'remote_session' | 'not_set_up' | 'error' }
 *   create(name, challenge) → { status, publicKey?, signature? }   (prompt; replaces a key of that name)
 *   sign(name, challenge)   → { status, signature? }               (prompt)
 *   remove(name)            → { status }                           (no prompt)
 * status: 'ok' | 'cancelled' | 'prefers_password' | 'not_found' | 'locked' | 'exists' | 'unavailable' | 'failed'
 * Signatures and keys are never logged (only statuses and HRESULTs).
 */

// ── Windows constants ──────────────────────────────────────

const CO_E_NOTINITIALIZED = 0x800401F0 | 0;
const RPC_E_CHANGED_MODE = 0x80010106 | 0;
const RO_INIT_MULTITHREADED = 1;
const SM_REMOTESESSION = 0x1000;
const HELLO_DIALOG_CLASS = 'Credential Dialog Xaml Host';

const CLASS = {
  manager: 'Windows.Security.Credentials.KeyCredentialManager',
  buffer: 'Windows.Security.Cryptography.CryptographicBuffer',
};

const IID = {
  IKeyCredentialManagerStatics: '6AAC468B-0EF1-4CE0-8290-4106DA6A63B5',
  ICryptographicBufferStatics: '320B7E22-3CB0-4CDF-8663-1D28910065EB',
  IAsyncInfo: '00000036-0000-0000-C000-000000000046',
};

// vtable slots. IUnknown: 0 QueryInterface, 1 AddRef, 2 Release; IInspectable adds 3 GetIids,
// 4 GetRuntimeClassName, 5 GetTrustLevel — every WinRT interface's own methods start at 6 (metadata order).
const SLOT = {
  queryInterface: 0,
  release: 2,
  // IKeyCredentialManagerStatics
  isSupportedAsync: 6, renewAttestationAsync: 7, requestCreateAsync: 8, openAsync: 9, deleteAsync: 10,
  // IAsyncInfo
  asyncId: 6, asyncStatus: 7, asyncErrorCode: 8, asyncCancel: 9, asyncClose: 10,
  // IAsyncOperation<T> / IAsyncAction: 6 put_Completed, 7 get_Completed, 8 GetResults
  getResults: 8,
  // IKeyCredentialRetrievalResult: 6 get_Credential, 7 get_Status
  retrievalCredential: 6, retrievalStatus: 7,
  // IKeyCredentialOperationResult: 6 get_Result, 7 get_Status
  operationResult: 6, operationStatus: 7,
  // IKeyCredential: 6 get_Name, 7 RetrievePublicKeyWithDefaultBlobType, 8 RetrievePublicKeyWithBlobType,
  // 9 RequestSignAsync, 10 GetAttestationAsync
  credentialPublicKey: 7, credentialSign: 9,
  // ICryptographicBufferStatics: 6 Compare, 7 GenerateRandom, 8 GenerateRandomNumber, 9 CreateFromByteArray,
  // 10 CopyToByteArray, …
  bufferFromBytes: 9, bufferToBytes: 10,
};

// AsyncStatus
const ASYNC = { started: 0, completed: 1, canceled: 2, error: 3 };
// KeyCredentialStatus 0…6
const KEY_STATUS = ['ok', 'failed', 'not_found', 'cancelled', 'prefers_password', 'exists', 'locked'];
// KeyCredentialCreationOption
const REPLACE_EXISTING = 0;

const DEFAULT_TIMING = {
  pollMs: 50,                 // IAsyncInfo.Status
  promptMs: 3 * 60 * 1000,    // a dialog the person answers
  quickMs: 20 * 1000,         // IsSupportedAsync, OpenAsync, DeleteAsync
  focusMs: 4000,              // look for the Hello dialog this long
};

const MAX_BLOB = 16384;       // sanity bound for buffers read back (an RSA public key / signature is far smaller)

class WinRtError extends Error {
  constructor(what, hr = null) {
    super(`${what}${hr != null ? ` (HRESULT 0x${(hr >>> 0).toString(16).padStart(8, '0')})` : ''}`);
    this.name = 'WinRtError';
    this.hr = hr;
  }
}

/** '6AAC468B-0EF1-…' → the 16 bytes of a GUID in memory (Data1–3 little endian). */
function guidBytes(text) {
  const h = String(text).replace(/[{}-]/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new Error(`bad GUID ${text}`);
  const b = Buffer.alloc(16);
  b.writeUInt32LE(parseInt(h.slice(0, 8), 16), 0);
  b.writeUInt16LE(parseInt(h.slice(8, 12), 16), 4);
  b.writeUInt16LE(parseInt(h.slice(12, 16), 16), 6);
  Buffer.from(h.slice(16), 'hex').copy(b, 8);
  return b;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const PROTOS = new WeakMap();
/** Function types of the vtable slots (anonymous: the module may load more than once). */
function protos(koffi) {
  let p = PROTOS.get(koffi);
  if (!p) {
    p = {
      queryInterface: koffi.proto('int32_t __stdcall (void *self, const uint8_t *riid, _Out_ void **out)'),
      release: koffi.proto('uint32_t __stdcall (void *self)'),
      call: koffi.proto('int32_t __stdcall (void *self)'),
      outPtr: koffi.proto('int32_t __stdcall (void *self, _Out_ void **out)'),
      outU8: koffi.proto('int32_t __stdcall (void *self, _Out_ uint8_t *out)'),
      outI32: koffi.proto('int32_t __stdcall (void *self, _Out_ int32_t *out)'),
      strOut: koffi.proto('int32_t __stdcall (void *self, void *name, _Out_ void **out)'),
      strI32Out: koffi.proto('int32_t __stdcall (void *self, void *name, int32_t option, _Out_ void **out)'),
      ptrOut: koffi.proto('int32_t __stdcall (void *self, void *arg, _Out_ void **out)'),
      fromBytes: koffi.proto('int32_t __stdcall (void *self, uint32_t size, const uint8_t *data, _Out_ void **out)'),
      toBytes: koffi.proto('int32_t __stdcall (void *self, void *buffer, _Out_ uint32_t *size, _Out_ void **data)'),
    };
    PROTOS.set(koffi, p);
  }
  return p;
}

/** The Win32 functions (koffi bindings of combase / ole32 / user32). */
function loadApi(koffi) {
  const combase = koffi.load('combase.dll');
  const ole32 = koffi.load('ole32.dll');
  const user32 = koffi.load('user32.dll');
  return {
    RoInitialize: combase.func('int32_t __stdcall RoInitialize(int32_t initType)'),
    RoGetActivationFactory: combase.func('int32_t __stdcall RoGetActivationFactory(void *activatableClassId, const uint8_t *iid, _Out_ void **factory)'),
    WindowsCreateString: combase.func('int32_t __stdcall WindowsCreateString(const char16_t *sourceString, uint32_t length, _Out_ void **string)'),
    WindowsDeleteString: combase.func('int32_t __stdcall WindowsDeleteString(void *string)'),
    CoGetApartmentType: ole32.func('int32_t __stdcall CoGetApartmentType(_Out_ int32_t *aptType, _Out_ int32_t *aptQualifier)'),
    CoTaskMemFree: ole32.func('void __stdcall CoTaskMemFree(void *pv)'),
    GetSystemMetrics: user32.func('int32_t __stdcall GetSystemMetrics(int32_t nIndex)'),
    FindWindowW: user32.func('void *__stdcall FindWindowW(const char16_t *lpClassName, const char16_t *lpWindowName)'),
    SetForegroundWindow: user32.func('int32_t __stdcall SetForegroundWindow(void *hWnd)'),
  };
}

/**
 * The COM / WinRT calls. `api`: loadApi(koffi) or a fake (tests). Every object it gets is released again,
 * every HSTRING deleted, every CoTaskMem block wiped and freed.
 */
class WinRt {
  constructor({ koffi, api, timing = {}, log = null }) {
    this.koffi = koffi;
    this.api = api;
    this.P = protos(koffi);
    this.ptr = koffi.sizeof('void *');
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.log = log;
    this._ready = false;
    this._statics = new Map();
  }

  check(hr, what) {
    if (hr < 0) throw new WinRtError(what, hr);
    return hr;
  }

  _fn(obj, slot) {
    if (obj == null) throw new WinRtError('null object');
    const vtbl = this.koffi.decode(obj, 'void *');
    return this.koffi.decode(vtbl, slot * this.ptr, 'void *');
  }

  invoke(obj, slot, proto, ...args) {
    return this.koffi.call(this._fn(obj, slot), proto, obj, ...args);
  }

  release(obj) {
    if (obj == null) return;
    try { this.invoke(obj, SLOT.release, this.P.release); } catch { /* gone */ }
  }

  /** COM on this thread: Electron's main thread already is an STA (kept); plain Node: the MTA. */
  apartment() {
    if (this._ready) return;
    const type = [0];
    const qualifier = [0];
    const hr = this.api.CoGetApartmentType(type, qualifier);
    if (hr === CO_E_NOTINITIALIZED) {
      const r = this.api.RoInitialize(RO_INIT_MULTITHREADED);
      if (r < 0 && r !== RPC_E_CHANGED_MODE) throw new WinRtError('RoInitialize', r);
    } else {
      this.check(hr, 'CoGetApartmentType');
    }
    this._ready = true;
  }

  /** An HSTRING for the call `fn(h)`, deleted afterwards. */
  withString(text, fn) {
    const out = [null];
    this.check(this.api.WindowsCreateString(text, text.length, out), 'WindowsCreateString');
    try {
      return fn(out[0]);
    } finally {
      if (out[0] != null) this.api.WindowsDeleteString(out[0]);
    }
  }

  /** The activation factory's statics interface (kept for the process' lifetime). */
  statics(className, iid) {
    this.apartment();
    if (this._statics.has(className)) return this._statics.get(className);
    const out = [null];
    this.withString(className, (h) => this.check(this.api.RoGetActivationFactory(h, guidBytes(iid), out), `RoGetActivationFactory(${className})`));
    if (out[0] == null) throw new WinRtError(`no factory for ${className}`);
    this._statics.set(className, out[0]);
    return out[0];
  }

  queryInterface(obj, iid) {
    const out = [null];
    this.check(this.invoke(obj, SLOT.queryInterface, this.P.queryInterface, guidBytes(iid), out), 'QueryInterface');
    if (out[0] == null) throw new WinRtError('QueryInterface: null');
    return out[0];
  }

  /**
   * Waits for an IAsyncOperation / IAsyncAction (polling IAsyncInfo.Status), then `results(op)` and Close.
   * `tick` runs on every poll (the Hello dialog to the front). Releases `op`.
   */
  async finish(op, results, { timeoutMs = this.timing.quickMs, tick = null } = {}) {
    let info = null;
    try {
      info = this.queryInterface(op, IID.IAsyncInfo);
      const status = [ASYNC.started];
      const start = Date.now();
      for (;;) {
        this.check(this.invoke(info, SLOT.asyncStatus, this.P.outI32, status), 'IAsyncInfo.Status');
        if (status[0] !== ASYNC.started) break;
        if (Date.now() - start > timeoutMs) {
          try { this.invoke(info, SLOT.asyncCancel, this.P.call); } catch { /* finished meanwhile */ }
          throw new WinRtError('timeout');
        }
        if (tick) { try { tick(); } catch { /* best effort */ } }
        await sleep(this.timing.pollMs);
      }
      if (status[0] === ASYNC.error) {
        const code = [0];
        this.invoke(info, SLOT.asyncErrorCode, this.P.outI32, code);
        throw new WinRtError('async operation failed', code[0]);
      }
      if (status[0] === ASYNC.canceled) throw new WinRtError('canceled');
      return results(op);
    } finally {
      if (info != null) {
        try { this.invoke(info, SLOT.asyncClose, this.P.call); } catch { /* closed */ }
        this.release(info);
      }
      this.release(op);
    }
  }

  /** GetResults of an IAsyncOperation<Interface> → the object (the caller releases it). */
  resultObject(op) {
    const out = [null];
    this.check(this.invoke(op, SLOT.getResults, this.P.outPtr, out), 'GetResults');
    if (out[0] == null) throw new WinRtError('GetResults: null');
    return out[0];
  }

  getI32(obj, slot, what) {
    const out = [0];
    this.check(this.invoke(obj, slot, this.P.outI32, out), what);
    return out[0];
  }

  getObject(obj, slot, what) {
    const out = [null];
    this.check(this.invoke(obj, slot, this.P.outPtr, out), what);
    if (out[0] == null) throw new WinRtError(`${what}: null`);
    return out[0];
  }

  // ── CryptographicBuffer ──

  bufferFrom(bytes) {
    const b = Buffer.from(bytes);
    const out = [null];
    try {
      this.check(this.invoke(this.statics(CLASS.buffer, IID.ICryptographicBufferStatics), SLOT.bufferFromBytes, this.P.fromBytes, b.length, b, out), 'CreateFromByteArray');
    } finally {
      b.fill(0);
    }
    if (out[0] == null) throw new WinRtError('CreateFromByteArray: null');
    return out[0];
  }

  /** IBuffer → a Buffer copy; the CoTaskMem copy is wiped and freed. */
  bytesOf(ibuffer) {
    const size = [0];
    const data = [null];
    this.check(this.invoke(this.statics(CLASS.buffer, IID.ICryptographicBufferStatics), SLOT.bufferToBytes, this.P.toBytes, ibuffer, size, data), 'CopyToByteArray');
    if (data[0] == null) return Buffer.alloc(0);
    try {
      if (size[0] > MAX_BLOB) throw new WinRtError('buffer too large');
      const view = new Uint8Array(this.koffi.view(data[0], size[0]));
      const copy = Buffer.from(view);
      view.fill(0);
      return copy;
    } finally {
      this.api.CoTaskMemFree(data[0]);
    }
  }

  // ── KeyCredentialManager ──

  manager() {
    return this.statics(CLASS.manager, IID.IKeyCredentialManagerStatics);
  }

  remoteSession() {
    return this.api.GetSystemMetrics(SM_REMOTESESSION) !== 0;
  }

  /** The Hello dialog in front of the app (it can open behind a desktop app's window). */
  focuser() {
    const until = Date.now() + this.timing.focusMs;
    let done = false;
    return () => {
      if (done || Date.now() > until) return;
      const hwnd = this.api.FindWindowW(HELLO_DIALOG_CLASS, null);
      if (hwnd == null || hwnd === 0n) return;
      done = true;
      this.api.SetForegroundWindow(hwnd);
    };
  }

  async isSupported() {
    const op = [null];
    this.check(this.invoke(this.manager(), SLOT.isSupportedAsync, this.P.outPtr, op), 'IsSupportedAsync');
    return this.finish(op[0], (o) => {
      const v = [0];
      this.check(this.invoke(o, SLOT.getResults, this.P.outU8, v), 'GetResults');
      return v[0] !== 0;
    });
  }

  /** CryptographicBuffer round trip: the vtable layout is what this code expects. */
  probe() {
    const pattern = Buffer.from([0x47, 0x43, 0x00, 0xff, 0x10, 0x80, 0x7f, 0x01]);
    const buf = this.bufferFrom(Buffer.from(pattern));
    try {
      return this.bytesOf(buf).equals(pattern);
    } finally {
      this.release(buf);
    }
  }

  /** A retrieval result → { status, credential } (credential only for 'ok'; the caller releases it). */
  _retrieval(result) {
    try {
      const st = KEY_STATUS[this.getI32(result, SLOT.retrievalStatus, 'RetrievalResult.Status')] || 'failed';
      if (st !== 'ok') return { status: st, credential: null };
      return { status: 'ok', credential: this.getObject(result, SLOT.retrievalCredential, 'RetrievalResult.Credential') };
    } finally {
      this.release(result);
    }
  }

  async _sign(credential, data, tick) {
    const buf = this.bufferFrom(data);
    let result;
    try {
      const op = [null];
      this.check(this.invoke(credential, SLOT.credentialSign, this.P.ptrOut, buf, op), 'RequestSignAsync');
      result = await this.finish(op[0], (o) => this.resultObject(o), { timeoutMs: this.timing.promptMs, tick });
    } finally {
      this.release(buf);
    }
    try {
      const st = KEY_STATUS[this.getI32(result, SLOT.operationStatus, 'OperationResult.Status')] || 'failed';
      if (st !== 'ok') return { status: st };
      const ib = this.getObject(result, SLOT.operationResult, 'OperationResult.Result');
      try {
        return { status: 'ok', signature: this.bytesOf(ib) };
      } finally {
        this.release(ib);
      }
    } finally {
      this.release(result);
    }
  }

  async create(name, challenge) {
    const tick = this.focuser();
    const op = [null];
    this.withString(name, (h) => this.check(this.invoke(this.manager(), SLOT.requestCreateAsync, this.P.strI32Out, h, REPLACE_EXISTING, op), 'RequestCreateAsync'));
    const r = this._retrieval(await this.finish(op[0], (o) => this.resultObject(o), { timeoutMs: this.timing.promptMs, tick }));
    if (r.status !== 'ok') return { status: r.status };
    try {
      const pk = this.getObject(r.credential, SLOT.credentialPublicKey, 'RetrievePublicKey');
      let publicKey;
      try { publicKey = this.bytesOf(pk); } finally { this.release(pk); }
      const s = await this._sign(r.credential, challenge, this.focuser());
      return s.status === 'ok' ? { status: 'ok', publicKey, signature: s.signature } : { status: s.status };
    } finally {
      this.release(r.credential);
    }
  }

  async sign(name, challenge) {
    const op = [null];
    this.withString(name, (h) => this.check(this.invoke(this.manager(), SLOT.openAsync, this.P.strOut, h, op), 'OpenAsync'));
    const r = this._retrieval(await this.finish(op[0], (o) => this.resultObject(o)));
    if (r.status !== 'ok') return { status: r.status };
    try {
      return await this._sign(r.credential, challenge, this.focuser());
    } finally {
      this.release(r.credential);
    }
  }

  /** Is there a key of this name (no prompt)? → 'ok' | 'not_found' | … */
  async exists(name) {
    const op = [null];
    this.withString(name, (h) => this.check(this.invoke(this.manager(), SLOT.openAsync, this.P.strOut, h, op), 'OpenAsync'));
    const r = this._retrieval(await this.finish(op[0], (o) => this.resultObject(o)));
    this.release(r.credential);
    return r.status;
  }

  async remove(name) {
    const op = [null];
    this.withString(name, (h) => this.check(this.invoke(this.manager(), SLOT.deleteAsync, this.P.strOut, h, op), 'DeleteAsync'));
    await this.finish(op[0], (o) => { this.check(this.invoke(o, SLOT.getResults, this.P.call), 'GetResults'); });
  }
}

const validName = (n) => typeof n === 'string' && n.length > 0 && n.length <= 200;
const validData = (d) => (Buffer.isBuffer(d) || d instanceof Uint8Array) && d.length > 0 && d.length <= 1024;

/**
 * @param {object} [opts]
 * @param {string} [opts.platform] - process.platform (tests)
 * @param {object} [opts.koffi] - koffi (tests; default require('koffi') on the first call)
 * @param {object} [opts.api] - the Win32 functions (tests; default loadApi(koffi))
 * @param {object} [opts.timing] - { pollMs, promptMs, quickMs, focusMs }
 * @param {object} [opts.log]
 */
function createWindowsHello({ platform = process.platform, koffi = null, api = null, timing = {}, log = null } = {}) {
  let rt = null;
  let loadError = null;
  let queue = Promise.resolve();

  function runtime() {
    if (rt) return rt;
    if (loadError) throw loadError;
    try {
      const k = koffi || require('koffi');
      rt = new WinRt({ koffi: k, api: api || loadApi(k), timing, log });
      return rt;
    } catch (err) {
      loadError = err;
      throw err;
    }
  }

  /** One Windows Hello call at a time (never two dialogs). */
  function serial(fn) {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  const warn = (what, err) => { if (log) log.warn(`Windows Hello: ${what}: ${err && err.message}`); };

  async function available() {
    if (platform !== 'win32') return { available: false, reason: 'unsupported_os' };
    let r;
    try {
      r = runtime();
    } catch (err) {
      warn('not loadable', err);
      return { available: false, reason: 'unsupported_os' };
    }
    try {
      if (r.remoteSession()) return { available: false, reason: 'remote_session' };
      r.manager();
    } catch (err) {
      warn('KeyCredentialManager not available', err);
      return { available: false, reason: 'unsupported_os' };
    }
    try {
      if (!r.probe()) {
        warn('buffer check', new Error('unexpected bytes'));
        return { available: false, reason: 'error' };
      }
      return (await r.isSupported()) ? { available: true, reason: null } : { available: false, reason: 'not_set_up' };
    } catch (err) {
      warn('IsSupportedAsync', err);
      return { available: false, reason: 'error' };
    }
  }

  /** Runs a prompt operation; WinRT / load failures become { status: 'failed' | 'unavailable' }. */
  const guarded = (what, fn) => serial(async () => {
    if (platform !== 'win32') return { status: 'unavailable' };
    let r;
    try {
      r = runtime();
      if (r.remoteSession()) return { status: 'unavailable' };
    } catch (err) {
      warn(`${what}: not loadable`, err);
      return { status: 'unavailable' };
    }
    try {
      return await fn(r);
    } catch (err) {
      warn(what, err);
      return { status: 'failed' };
    }
  });

  return {
    kind: 'windows-hello',
    available,
    create(name, challenge) {
      if (!validName(name) || !validData(challenge)) return Promise.resolve({ status: 'failed' });
      return guarded('create', (r) => r.create(name, challenge));
    },
    sign(name, challenge) {
      if (!validName(name) || !validData(challenge)) return Promise.resolve({ status: 'failed' });
      return guarded('sign', (r) => r.sign(name, challenge));
    },
    remove(name) {
      if (!validName(name)) return Promise.resolve({ status: 'failed' });
      return guarded('remove', async (r) => {
        if ((await r.exists(name)) === 'not_found') return { status: 'not_found' };
        await r.remove(name);
        return { status: 'ok' };
      });
    },
    /** Diagnostics without a prompt (Windows CI): does a key of this name exist? */
    exists(name) {
      if (!validName(name)) return Promise.resolve('failed');
      return guarded('exists', (r) => r.exists(name).then((status) => ({ status }))).then((x) => x.status);
    },
  };
}

module.exports = {
  createWindowsHello,
  WinRt,
  WinRtError,
  loadApi,
  guidBytes,
  protos,
  // constants (tests)
  CLASS,
  IID,
  SLOT,
  ASYNC,
  KEY_STATUS,
  HELLO_DIALOG_CLASS,
  SM_REMOTESESSION,
  CO_E_NOTINITIALIZED,
  RPC_E_CHANGED_MODE,
};
