'use strict';

/**
 * A fake Windows Runtime for services/windows-hello.js: real COM objects in memory (vtables of koffi callbacks,
 * called through koffi.call exactly like the real ones) for KeyCredentialManager, KeyCredential,
 * CryptographicBuffer, IAsyncOperation / IAsyncInfo, plus fake combase / ole32 / user32 functions. Hello keys are
 * node RSA 2048 keys that sign with PKCS#1 v1.5 / SHA-256 (as Windows does).
 *
 *   const rt = fakeWinRt(koffi, { supported: true });
 *   const hello = createWindowsHello({ platform: 'win32', koffi, api: rt.api, timing: { pollMs: 1 } });
 *   rt.next = 'cancel';              // the person's answer to the next prompt: 'ok' | 'cancel' | 'password' | 'locked'
 *                                    // (or a list for the next prompts)
 *   rt.live()                        // objects not released yet (must be 0 after every call)
 *   rt.dispose()                     // unregisters the callbacks
 */

const crypto = require('node:crypto');
const { protos, guidBytes, IID, CO_E_NOTINITIALIZED } = require('../../src/services/windows-hello');

const E_NOINTERFACE = 0x80004002 | 0;
const E_NOTIMPL = 0x80004001 | 0;
const E_FAIL = 0x80004005 | 0;
const STATUS = { ok: 0, failed: 1, not_found: 2, cancel: 3, password: 4, exists: 5, locked: 6 };

function fakeWinRt(koffi, opts = {}) {
  const P = protos(koffi);
  const PTR = koffi.sizeof('void *');
  const cbs = [];
  const objects = new Map();   // address (bigint) → { cls, refs, state }
  const memory = new Map();    // CoTaskMem address → bytes handed out (to check the wipe)
  const strings = new Map();   // HSTRING → text
  let nextString = 0x1000n;

  const rt = {
    supported: opts.supported !== false,
    remote: false,
    apartment: CO_E_NOTINITIALIZED,
    keys: new Map(),         // name → { privateKey, spki }
    next: 'ok',              // answer to the next prompt
    polls: opts.polls == null ? 2 : opts.polls,
    asyncError: null,        // HRESULT for the next async operation
    badBuffer: false,        // CopyToByteArray returns other bytes
    dialog: null,            // hwnd FindWindowW finds
    focused: [],
    prompts: [],             // { kind: 'create' | 'sign', name }
    signFlip: false,         // signatures change every time (not deterministic)
    freed: [],               // wiped? per CoTaskMemFree
    roInit: 0,
    created: 0,
  };

  const reg = (proto, fn) => {
    const p = koffi.register(fn, koffi.pointer(proto));
    cbs.push(p);
    return p;
  };

  const sameIid = (riid, iid) => Buffer.from(koffi.view(riid, 16)).equals(guidBytes(iid));

  // one vtable per class; slot functions get (state, ...args) of the object
  const classes = new Map();
  function defineClass(name, slots, { qi = null } = {}) {
    const max = Math.max(10, ...Object.keys(slots).map(Number));
    const vt = koffi.alloc('void *', max + 1);
    const notImpl = reg(P.call, () => E_NOTIMPL);
    for (let i = 0; i <= max; i++) koffi.encode(vt, i * PTR, 'void *', notImpl);
    const obj = (self) => {
      const o = objects.get(self);
      if (!o) throw new Error(`${name}: unknown object`);
      return o;
    };
    koffi.encode(vt, 0, 'void *', reg(P.queryInterface, (self, riid, out) => {
      const o = obj(self);
      const other = qi ? qi(o, riid) : null;
      if (!other) { koffi.encode(out, 'void *', null); return E_NOINTERFACE; }
      koffi.encode(out, 'void *', other);
      return 0;
    }));
    koffi.encode(vt, 1 * PTR, 'void *', reg(P.release, (self) => ++obj(self).refs));
    koffi.encode(vt, 2 * PTR, 'void *', reg(P.release, (self) => {
      const o = obj(self);
      o.refs--;
      if (o.refs < 0) throw new Error(`${name}: released too often`);
      return o.refs;
    }));
    for (const [slot, [proto, fn]] of Object.entries(slots)) {
      koffi.encode(vt, Number(slot) * PTR, 'void *', reg(proto, (self, ...args) => fn(obj(self), ...args)));
    }
    classes.set(name, vt);
    return vt;
  }

  function make(cls, state = {}) {
    const mem = koffi.alloc('void *', 1);
    koffi.encode(mem, 'void *', classes.get(cls));
    objects.set(mem, { cls, refs: 1, state, mem });
    return mem;
  }

  const put = (out, v) => { koffi.encode(out, 'void *', v); return 0; };
  const putI32 = (out, v) => { koffi.encode(out, 'int32_t', v); return 0; };

  // ── async: the operation finishes after `polls` Status reads ──
  function asyncOp(cls, result) {
    const state = { polls: rt.polls, error: rt.asyncError, result, closed: false, status: 0, info: null };
    rt.asyncError = null;
    return make(cls, state);
  }
  const qiAsync = (o, riid) => {
    if (!sameIid(riid, IID.IAsyncInfo)) return null;
    return make('AsyncInfo', o.state);
  };
  const getResultsPtr = [P.outPtr, (o, out) => {
    if (o.state.status !== 1 || o.state.closed) return E_FAIL;
    const r = o.state.result();
    return put(out, r);
  }];
  defineClass('AsyncOpPtr', { 8: getResultsPtr }, { qi: qiAsync });
  defineClass('AsyncOpBool', { 8: [P.outU8, (o, out) => { koffi.encode(out, 'uint8_t', o.state.result() ? 1 : 0); return 0; }] }, { qi: qiAsync });
  defineClass('AsyncAction', { 8: [P.call, (o) => { o.state.result(); return 0; }] }, { qi: qiAsync });
  defineClass('AsyncInfo', {
    7: [P.outI32, (o, out) => {
      const s = o.state;
      if (s.status === 0) {
        if (s.polls > 0) s.polls--;
        else s.status = s.error != null ? 3 : 1;
      }
      return putI32(out, s.status);
    }],
    8: [P.outI32, (o, out) => putI32(out, o.state.error || 0)],
    9: [P.call, (o) => { o.state.status = 2; return 0; }],
    10: [P.call, (o) => { o.state.closed = true; return 0; }],
  });

  // ── buffers ──
  defineClass('Buffer', {});
  const bufferOf = (bytes) => make('Buffer', { bytes: Buffer.from(bytes) });
  defineClass('BufferStatics', {
    9: [P.fromBytes, (_o, size, data, out) => put(out, bufferOf(size ? Buffer.from(koffi.view(data, size)) : Buffer.alloc(0)))],
    10: [P.toBytes, (_o, buf, size, data) => {
      const b = objects.get(buf);
      let bytes = b.state.bytes;
      if (rt.badBuffer) bytes = Buffer.from(bytes).reverse();
      const mem = koffi.alloc('uint8_t', Math.max(1, bytes.length));
      if (bytes.length) koffi.encode(mem, 'uint8_t', [...bytes], bytes.length);
      memory.set(mem, bytes.length);
      koffi.encode(size, 'uint32_t', bytes.length);
      return put(data, mem);
    }],
  });

  // ── key credentials ──
  const answer = () => {
    if (Array.isArray(rt.next)) return rt.next.length ? rt.next.shift() : 'ok';
    const a = rt.next;
    rt.next = 'ok';
    return a;
  };
  defineClass('OperationResult', {
    6: [P.outPtr, (o, out) => (o.state.bytes ? put(out, bufferOf(o.state.bytes)) : E_FAIL)],
    7: [P.outI32, (o, out) => putI32(out, o.state.status)],
  });
  defineClass('Credential', {
    7: [P.outPtr, (o, out) => put(out, bufferOf(rt.keys.get(o.state.name).spki))],
    9: [P.ptrOut, (o, buf, out) => {
      const data = Buffer.from(objects.get(buf).state.bytes);
      rt.prompts.push({ kind: 'sign', name: o.state.name });
      return put(out, asyncOp('AsyncOpPtr', () => {
        const a = answer();
        const key = rt.keys.get(o.state.name);
        if (a !== 'ok' || !key) return make('OperationResult', { status: key ? STATUS[a] : STATUS.not_found, bytes: null });
        let sig = crypto.sign('sha256', data, { key: key.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
        if (rt.signFlip) sig = crypto.randomBytes(sig.length);
        return make('OperationResult', { status: 0, bytes: sig });
      }));
    }],
  });
  defineClass('RetrievalResult', {
    6: [P.outPtr, (o, out) => (o.state.name ? put(out, make('Credential', { name: o.state.name })) : E_FAIL)],
    7: [P.outI32, (o, out) => putI32(out, o.state.status)],
  });
  const textOf = (h) => {
    if (!strings.has(h)) throw new Error('unknown HSTRING');
    return strings.get(h);
  };
  defineClass('ManagerStatics', {
    6: [P.outPtr, (_o, out) => put(out, asyncOp('AsyncOpBool', () => rt.supported))],
    8: [P.strI32Out, (_o, h, option, out) => {
      const name = textOf(h);
      rt.prompts.push({ kind: 'create', name, option });
      return put(out, asyncOp('AsyncOpPtr', () => {
        const a = answer();
        if (a !== 'ok') return make('RetrievalResult', { status: STATUS[a], name: null });
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        rt.keys.set(name, { privateKey, spki: publicKey.export({ type: 'spki', format: 'der' }) });
        rt.created++;
        return make('RetrievalResult', { status: 0, name });
      }));
    }],
    9: [P.strOut, (_o, h, out) => {
      const name = textOf(h);
      return put(out, asyncOp('AsyncOpPtr', () => make('RetrievalResult', rt.keys.has(name) ? { status: 0, name } : { status: STATUS.not_found, name: null })));
    }],
    10: [P.strOut, (_o, h, out) => {
      const name = textOf(h);
      return put(out, asyncOp('AsyncAction', () => { rt.keys.delete(name); }));
    }],
  });

  const statics = { 'Windows.Security.Credentials.KeyCredentialManager': ['ManagerStatics', IID.IKeyCredentialManagerStatics], 'Windows.Security.Cryptography.CryptographicBuffer': ['BufferStatics', IID.ICryptographicBufferStatics] };
  const factories = new Map();

  rt.api = {
    RoInitialize: () => { rt.roInit++; rt.apartment = 0; return 0; },
    CoGetApartmentType: (type, qualifier) => { type[0] = 1; qualifier[0] = 0; return rt.apartment; },
    WindowsCreateString: (text, len, out) => {
      const h = nextString++;
      strings.set(h, String(text).slice(0, len));
      out[0] = h;
      return 0;
    },
    WindowsDeleteString: (h) => { strings.delete(h); return 0; },
    RoGetActivationFactory: (h, iid, out) => {
      const s = statics[textOf(h)];
      if (!s) return 0x80040154 | 0; // REGDB_E_CLASSNOTREG
      if (!Buffer.from(iid).equals(guidBytes(s[1]))) return E_NOINTERFACE;
      if (!factories.has(s[0])) factories.set(s[0], make(s[0]));
      out[0] = factories.get(s[0]);
      return 0;
    },
    CoTaskMemFree: (p) => {
      const n = memory.get(p);
      memory.delete(p);
      rt.freed.push(n ? Buffer.from(koffi.view(p, n)).every((x) => x === 0) : true);
      koffi.free(p);
    },
    GetSystemMetrics: (i) => (i === 0x1000 && rt.remote ? 1 : 0),
    FindWindowW: (cls) => (cls === 'Credential Dialog Xaml Host' ? rt.dialog : null),
    SetForegroundWindow: (h) => { rt.focused.push(h); return 1; },
  };

  /** Objects still referenced (factories excluded: kept for the process' lifetime). */
  rt.live = () => [...objects.values()].filter((o) => o.refs > 0 && !['ManagerStatics', 'BufferStatics'].includes(o.cls)).map((o) => o.cls);
  rt.strings = () => strings.size;
  rt.leakedMemory = () => memory.size;
  rt.dispose = () => { for (const c of cbs.splice(0)) koffi.unregister(c); };
  return rt;
}

module.exports = { fakeWinRt, STATUS };
