'use strict';

// Fernzugriff stage 7 ("Bildschirm teilen"): H.264 helpers, SendInput mapping and its locks, the capture window
// (fake Electron), the sender of gc-screen.v1 (fake WebSocket) and RemoteHost with the second switch.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const H = require('../src/screen-share/h264');
const ScreenInput = require('../src/services/screen-input');
const ScreenShare = require('../src/services/screen-share');
const ScreenCapture = require('../src/services/screen-capture');
const RemoteHost = require('../src/services/remote-host');
const RemoteHostApi = require('../src/services/remote-host-api');

const REF = 'A'.repeat(43);
const RQ = 'rq_abcdefghijklmnop';
const tick = () => new Promise((r) => setImmediate(r));

// ─── H.264 ───

test('h264: NAL units, codec string, SPS/PPS in front of every key frame, the frame head, sizes', () => {
  const sps = [0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0xaa];
  const pps = [0, 0, 1, 0x68, 0xce];
  const idr = [0, 0, 0, 1, 0x65, 1, 2, 3];
  const slice = [0, 0, 0, 1, 0x41, 9];
  assert.deepEqual(H.nalUnits(new Uint8Array([...sps, ...pps, ...idr])).map((u) => u.type), [7, 8, 5]);
  assert.equal(H.codecOf(new Uint8Array([0x67, 0x4d, 0x40, 0x28])), 'avc1.4D4028');
  assert.equal(H.codecOf(new Uint8Array([0x68, 1, 2, 3])), null);
  const cache = {};
  const first = H.withParamSets(new Uint8Array([...sps, ...pps, ...idr]), cache);
  assert.deepEqual([first.codec, first.key, first.data.length], ['avc1.42E01F', true, sps.length + pps.length + idr.length]);
  const delta = H.withParamSets(new Uint8Array(slice), cache);
  assert.deepEqual([delta.key, delta.data.length], [false, slice.length]);
  const bare = H.withParamSets(new Uint8Array(idr), cache);
  assert.equal(bare.key, true);
  assert.deepEqual(H.nalUnits(bare.data).map((u) => u.type), [7, 8, 5], 'the cached SPS/PPS went in front');
  const head = H.frameHeader(true, 5000000000);
  assert.deepEqual([head.length, head[0], head[1]], [12, 1, 1]);
  assert.equal(Buffer.from(head).readBigUInt64BE(4), 5000000000n);
  assert.deepEqual(H.fitSize(3840, 2160), { width: 1920, height: 1080 });
  assert.deepEqual(H.fitSize(2560, 1600), { width: 1728, height: 1080 });
  assert.deepEqual(H.fitSize(1366, 768), { width: 1366, height: 768 });
  assert.deepEqual(H.fitSize(1080, 1920), { width: 1080, height: 1920 });
  const cfgs = H.encoderConfigs(1920, 1080, { fps: 15, bitrate: 2000000 });
  assert.deepEqual(cfgs.slice(0, 3).map((c) => c.hardwareAcceleration), ['prefer-hardware', 'prefer-software', 'no-preference']);
  assert.equal(cfgs[0].codec, 'avc1.42E028');
  assert.equal(H.encoderConfigs(1280, 720)[0].codec, 'avc1.42E01F');
  assert.ok(cfgs.every((c) => c.avc.format === 'annexb' && c.latencyMode === 'realtime'));
});

// ─── SendInput ───

function fakeBackend(o = {}) {
  const b = { sent: [], desk: 'default', vs: { x: 0, y: 0, w: 3840, h: 1080 }, ...o };
  b.send = (ev) => { b.sent.push(...ev); return ev.length; };
  b.inputDesktop = () => b.desk;
  b.virtualScreen = () => b.vs;
  return b;
}

function makeInput(o = {}) {
  let t = 1000;
  const timers = [];
  const backend = fakeBackend(o.backend);
  const input = new ScreenInput({ backend, isLocked: o.isLocked || (() => false), now: () => t,
    setTimer: (fn, ms) => { const x = { fn, ms }; timers.push(x); return x; }, clearTimer: (x) => { if (x) x.cleared = true; } });
  return { input, backend, timers, advance: (ms) => { t += ms; } };
}

test('input: nothing before enable; mouse, wheel and physical keys after; a release always', () => {
  const { input, backend } = makeInput();
  assert.deepEqual(input.handle({ k: 'move', x: 0.5, y: 0.5 }), { ok: false, reason: 'blocked', k: 'move' });
  assert.equal(backend.sent.length, 0);
  input.enable({ x: 1920, y: 0, w: 1920, h: 1080 });
  assert.equal(input.handle({ k: 'move', x: 0, y: 0 }).ok, true);
  const mv = backend.sent.pop();
  const M = ScreenInput.MOUSE;
  assert.equal(mv.flags, M.MOVE | M.ABSOLUTE | M.VIRTUALDESK);
  assert.equal(mv.dx, Math.round(1920 * 65535 / 3839), 'on the second display of the virtual desktop');
  assert.equal(input.handle({ k: 'button', b: 'right', down: true, x: 1, y: 1 }).ok, true);
  assert.equal(backend.sent.pop().flags, M.RIGHTDOWN);
  assert.equal(input.handle({ k: 'button', b: 'right', down: false, x: 1, y: 1 }).ok, true);
  assert.equal(backend.sent.pop().flags, M.RIGHTUP);
  input.handle({ k: 'wheel', x: 0.5, y: 0.5, dx: 0, dy: -240 });
  const w = backend.sent.pop();
  assert.deepEqual([w.flags, w.data], [M.WHEEL, -240]);
  backend.sent.length = 0;
  input.handle({ k: 'kbd', code: 'ControlLeft', down: true });
  input.handle({ k: 'kbd', code: 'ArrowUp', down: true });
  input.handle({ k: 'kbd', code: 'KeyC', down: true });
  const K = ScreenInput.KEY;
  assert.deepEqual(backend.sent.map((e) => [e.scan, e.flags]), [[0x1d, K.SCANCODE], [0x48, K.SCANCODE | K.EXTENDED], [0x2e, K.SCANCODE]]);
  assert.deepEqual(input.handle({ k: 'kbd', code: 'Power', down: true }), { ok: false, reason: 'blocked', k: 'kbd' });
  // stop: everything held is let go (reverse order), nothing more runs
  backend.sent.length = 0;
  input.stop();
  assert.deepEqual(backend.sent.map((e) => [e.scan, e.flags & K.UP]), [[0x2e, K.UP], [0x48, K.UP], [0x1d, K.UP]]);
  assert.equal(input.handle({ k: 'kbd', code: 'KeyA', down: true }).ok, false);
});

test('input: text as Unicode, touch kinds of a phone viewer, limits, a held key let go after 15 s', () => {
  const { input, backend, timers, advance } = makeInput();
  input.enable({ x: 0, y: 0, w: 1920, h: 1080 });
  input.handle({ k: 'text', text: 'Hé😀' });
  const K = ScreenInput.KEY;
  assert.equal(backend.sent.length, 8, 'four UTF-16 units, down and up');
  assert.ok(backend.sent.every((e) => e.flags & K.UNICODE));
  backend.sent.length = 0;
  input.handle({ k: 'tap', x: 0.5, y: 0.5 });
  const M = ScreenInput.MOUSE;
  assert.deepEqual(backend.sent.map((e) => e.flags & ~(M.ABSOLUTE | M.VIRTUALDESK)), [M.MOVE, M.LEFTDOWN, M.LEFTUP]);
  backend.sent.length = 0;
  input.handle({ k: 'key', key: 'back' });
  assert.deepEqual(backend.sent.map((e) => [e.scan, !!(e.flags & K.UP)]), [[0x38, false], [0x4b, false], [0x4b, true], [0x38, true]], 'Alt+Left');
  backend.sent.length = 0;
  input.handle({ k: 'scroll', x: 0.5, y: 0.5, dx: 0, dy: 0.1 });
  assert.equal(backend.sent[1].data, -1200 < -130 ? Math.round(-0.1 * 1080 / 100 * 120) : 0);
  // 5 texts a second
  advance(2000);
  const r = [];
  for (let i = 0; i < 7; i++) r.push(input.handle({ k: 'text', text: 'ab' }).ok);
  assert.deepEqual(r, [true, true, true, true, true, false, false]);
  // a held key: let go after 15 s without input
  backend.sent.length = 0;
  input.handle({ k: 'kbd', code: 'ShiftLeft', down: true });
  const stuck = timers.filter((t) => !t.cleared && t.ms === ScreenInput.STUCK_MS).pop();
  assert.ok(stuck);
  stuck.fn();
  assert.equal(backend.sent.pop().flags & K.UP, K.UP);
  // 16 keys held at most
  advance(2000);
  const codes = 'ABCDEFGHIJKLMNOPQ'.split('').map((c) => 'Key' + c);
  const res = codes.map((code) => input.handle({ k: 'kbd', code, down: true }).ok);
  assert.deepEqual(res.slice(-2), [true, false]);
});

test('input: the secure desktop (UAC prompt, lock screen) refuses input and lets go of everything', () => {
  let locked = false;
  const { input, backend, advance } = makeInput({ isLocked: () => locked });
  input.enable({ x: 0, y: 0, w: 1920, h: 1080 });
  input.handle({ k: 'kbd', code: 'AltLeft', down: true });
  backend.desk = 'secure';
  advance(300);
  backend.sent.length = 0;
  assert.deepEqual(input.handle({ k: 'kbd', code: 'Tab', down: true }), { ok: false, reason: 'secure', k: 'kbd' });
  assert.deepEqual(backend.sent.map((e) => [e.scan, !!(e.flags & ScreenInput.KEY.UP)]), [[0x38, true]], 'Alt let go, Tab not pressed');
  locked = true;
  advance(300);
  assert.equal(input.handle({ k: 'move', x: 0, y: 0 }).reason, 'locked');
  assert.equal(input.desktop(), 'locked');
});

test('input: the koffi backend describes INPUT for SendInput (structure only, no call)', () => {
  const calls = [];
  const fakeKoffi = {
    load: () => ({ func: (sig) => { calls.push(sig); return () => 1; } }),
    struct: (name, def) => ({ name, def }),
    union: (name, def) => ({ name, def }),
    sizeof: () => 40,
  };
  const b = ScreenInput.createWin32Backend(fakeKoffi);
  assert.equal(b.send([{ type: 0, dx: 1, dy: 2, data: -120, flags: 0x0800 }, { type: 1, scan: 0x1e, flags: 8 }]), 2);
  assert.ok(calls.some((s) => /SendInput\(uint32_t cInputs, GC_INPUT \*pInputs, int cbSize\)/.test(s)));
  assert.ok(calls.some((s) => /OpenInputDesktop/.test(s)));
});

// ─── The capture window (fake Electron) ───

function fakeElectron() {
  const sent = [];
  let ipcHandler = null;
  const wc = new EventEmitter();
  wc.ipc = { on: (ch, fn) => { if (ch === 'gc-capture:event') ipcHandler = fn; } };
  wc.send = (ch, m) => { sent.push(m); };
  wc.setWindowOpenHandler = () => {};
  const perms = {};
  class BrowserWindow {
    constructor(o) { this.opts = o; this.webContents = wc; this.destroyed = false; }
    loadFile() { setImmediate(() => ipcHandler(null, { t: 'ready' })); return Promise.resolve(); }
    isDestroyed() { return this.destroyed; }
    destroy() { this.destroyed = true; }
  }
  const electron = {
    BrowserWindow,
    session: { fromPartition: (p) => ({ p, setPermissionRequestHandler: (fn) => { perms.req = fn; }, setPermissionCheckHandler: (fn) => { perms.check = fn; } }) },
    screen: {
      getPrimaryDisplay: () => ({ id: 2 }),
      getAllDisplays: () => [{ id: 1, bounds: { x: -1920, y: 0, width: 1920, height: 1080 }, scaleFactor: 1 }, { id: 2, bounds: { x: 0, y: 0, width: 1280, height: 800 }, scaleFactor: 2 }],
    },
    desktopCapturer: { getSources: async () => [{ id: 'screen:1:0', display_id: '1' }, { id: 'screen:2:0', display_id: '2' }] },
  };
  return { electron, sent, emit: (m) => ipcHandler(null, m), perms };
}

test('capture: displays in physical pixels, the main one first to share, start waits for the encoder; output as events', async () => {
  const f = fakeElectron();
  const cap = new ScreenCapture({ electron: f.electron });
  const list = cap.displays();
  assert.deepEqual(list.map((d) => [d.i, d.primary, d.w, d.h]), [[0, false, 1920, 1080], [1, true, 2560, 1600]]);
  assert.equal(cap.primaryIndex(), 1);
  const p = cap.start(1, { fps: 15, bitrate: 2000000 });
  for (let i = 0; i < 5 && !f.sent.length; i++) await tick();
  assert.deepEqual(f.sent[0], { t: 'start', sourceId: 'screen:2:0', width: 1728, height: 1080, fps: 15, bitrate: 2000000 });
  // the page may only capture
  assert.equal(await new Promise((r) => f.perms.req(null, 'media', r)), true);
  assert.equal(await new Promise((r) => f.perms.req(null, 'notifications', r)), false);
  f.emit({ t: 'started', width: 1728, height: 1080, codec: 'avc1.42E028', hardware: 'prefer-hardware' });
  const s = await p;
  assert.deepEqual([s.display.i, s.width, s.hardware], [1, 1728, 'prefer-hardware']);
  const got = [];
  cap.on('config', (c) => got.push(['config', c.codec]));
  cap.on('chunk', (c) => got.push(['chunk', c.key, c.data.length]));
  cap.on('error', (e) => got.push(['error', e.code]));
  f.emit({ t: 'config', codec: 'avc1.42E028', width: 1728, height: 1080 });
  f.emit({ t: 'config', codec: '<script>', width: 1, height: 1 });
  f.emit({ t: 'chunk', key: true, ts: 1, data: new Uint8Array([1, 2, 3]) });
  f.emit({ t: 'error', code: 'whatever' });
  assert.deepEqual(got, [['config', 'avc1.42E028'], ['chunk', true, 3], ['error', 'capture_failed']]);
  // no encoder on this PC: the start fails with its code
  const p2 = cap.start(0);
  for (let i = 0; i < 5 && f.sent.length < 2; i++) await tick();
  f.emit({ t: 'error', code: 'encoder_unavailable' });
  await assert.rejects(p2, (e) => e.code === 'encoder_unavailable');
});

// ─── The sender of gc-screen.v1 (fake WebSocket) ───

class FakeWS {
  constructor(url, protocols) {
    FakeWS.all.push(this);
    this.url = url;
    this.protocols = protocols;
    this.readyState = 0;
    this.sent = [];
    this.bufferedAmount = 0;
  }
  send(d) { this.sent.push(d); }
  close() { this.readyState = 3; if (this.onclose) this.onclose({}); }
  open() { this.readyState = 1; this.onopen(); }
  recv(o) { this.onmessage({ data: JSON.stringify(o) }); }
  texts(t) { return this.sent.filter((x) => typeof x === 'string').map((x) => JSON.parse(x)).filter((m) => !t || m.t === t); }
  binaries() { return this.sent.filter((x) => typeof x !== 'string'); }
}
FakeWS.all = [];

function fakeCapture() {
  const c = new EventEmitter();
  c.calls = [];
  const list = [{ i: 0, id: '1', primary: true, w: 1920, h: 1080, rect: { x: 0, y: 0, w: 1920, h: 1080 } }, { i: 1, id: '2', primary: false, w: 1280, h: 1024, rect: { x: 1920, y: 0, w: 1280, h: 1024 } }];
  c.displays = () => list;
  c.primaryIndex = () => 0;
  c.start = async (i) => { c.calls.push(['start', i]); const d = list[i]; return { display: d, width: d.w, height: d.h }; };
  c.keyframe = () => c.calls.push(['keyframe']);
  c.setBitrate = (b) => c.calls.push(['bitrate', b]);
  c.stop = () => c.calls.push(['stop']);
  return c;
}

function fakeInput() {
  const i = { active: false, handled: [], released: 0, desk: 'default', rect: null };
  i.enable = (r) => { i.active = true; i.rect = r; };
  i.stop = () => { i.active = false; i.released++; };
  i.releaseAll = () => { i.released++; };
  i.setDisplay = (r) => { i.rect = r; };
  i.desktop = () => i.desk;
  i.handle = (m) => { if (!i.active) return { ok: false, reason: 'blocked' }; i.handled.push(m); return m.k === 'kbd' && m.code === 'F13' ? { ok: false, reason: 'secure' } : { ok: true }; };
  return i;
}

function makeShare(o = {}) {
  FakeWS.all = [];
  const timers = [];
  const repeats = [];
  const capture = fakeCapture();
  const input = fakeInput();
  const api = { tokens: 0, screenToken: async (ref) => { api.tokens++; assert.equal(ref, REF); if (o.tokenError) throw o.tokenError; return { ok: true, token: 'T'.repeat(43), wsPath: '/api/v1/remote/screen-relay', ttl: 60, role: 'sender' }; } };
  const share = new ScreenShare({ api, capture, input, serverUrl: () => 'https://gate.example.org/', WebSocketImpl: FakeWS, appVersion: '1.97.0',
    setTimer: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; }, clearTimer: (t) => { if (t) t.cleared = true; },
    setRepeat: (fn, ms) => { const t = { fn, ms }; repeats.push(t); return t; }, clearRepeat: (t) => { if (t) t.cleared = true; } });
  const events = [];
  share.on('session', (s) => events.push(s));
  return { share, capture, input, api, timers, repeats, events, ws: () => FakeWS.all[FakeWS.all.length - 1] };
}

test('share: token in the protocol (never the URL), hello as a desktop sender, the picture after ready', async () => {
  const x = makeShare();
  await x.share.start({ requestId: RQ, ref: REF, mode: 'control', viewerName: 'Tom' });
  const ws = x.ws();
  assert.equal(ws.url, 'wss://gate.example.org/api/v1/remote/screen-relay');
  assert.deepEqual(ws.protocols, ['gc-screen.v1', 'token.' + 'T'.repeat(43)]);
  ws.open();
  const hello = ws.texts('hello')[0];
  assert.deepEqual([hello.role, hello.input, hello.control, hello.scope, hello.width, hello.height, hello.app.platform, hello.display], ['sender', 'desktop', true, 'display', 1920, 1080, 'windows', 0]);
  assert.deepEqual(hello.displays, [{ i: 0, primary: true, w: 1920, h: 1080 }, { i: 1, primary: false, w: 1280, h: 1024 }]);
  // nothing before ready and config
  x.capture.emit('config', { codec: 'avc1.42E028', width: 1920, height: 1080 });
  x.capture.emit('chunk', { key: true, ts: 10, data: new Uint8Array([0, 0, 0, 1, 0x65]) });
  assert.equal(ws.binaries().length, 0);
  ws.recv({ t: 'ready', role: 'sender', mode: 'control', peer: { name: 'Tom' } });
  assert.deepEqual(ws.texts('config')[0], { t: 'config', codec: 'avc1.42E028', width: 1920, height: 1080 });
  x.capture.emit('chunk', { key: true, ts: 20, data: new Uint8Array([0, 0, 0, 1, 0x65, 7]) });
  const bin = ws.binaries()[0];
  assert.deepEqual([bin.length, bin[0], bin[1]], [18, 1, 1]);
  assert.equal(x.input.active, true, 'control: input on');
  ws.recv({ t: 'viewer', state: 'joined', name: 'Tom Berger' });
  assert.deepEqual([x.share.status().state, x.share.status().viewer, x.share.status().mode], ['live', 'Tom Berger', 'control']);
  // input passes; a failure goes back (at most 2 a second)
  ws.recv({ t: 'input', k: 'kbd', code: 'KeyA', down: true });
  for (let i = 0; i < 4; i++) ws.recv({ t: 'input', k: 'kbd', code: 'F13', down: true });
  assert.equal(x.input.handled.length, 5);
  assert.deepEqual(ws.texts('input_fail'), [{ t: 'input_fail', k: 'kbd', reason: 'secure' }, { t: 'input_fail', k: 'kbd', reason: 'secure' }]);
  // rate and key frame
  ws.recv({ t: 'rate', bitrate: 900000 });
  ws.recv({ t: 'keyframe' });
  assert.ok(x.capture.calls.some((c) => c[0] === 'bitrate' && c[1] === 900000));
});

test('share: "Nur ansehen" stops input at once and for good; "Beenden" stops input before bye', async () => {
  const x = makeShare();
  await x.share.start({ requestId: RQ, ref: REF, mode: 'control' });
  const ws = x.ws();
  ws.open();
  ws.recv({ t: 'ready', mode: 'control' });
  assert.equal(x.input.active, true);
  x.share.downgrade();
  assert.equal(x.input.active, false);
  assert.deepEqual(ws.texts('mode'), [{ t: 'mode', mode: 'view', reason: 'sender' }]);
  ws.recv({ t: 'input', k: 'move', x: 0.5, y: 0.5 });
  assert.equal(x.input.handled.length, 0);
  // a reconnect cannot bring control back
  ws.recv({ t: 'ready', mode: 'control' });
  assert.equal(x.input.active, false);
  const before = x.input.released;
  x.share.stop();
  assert.ok(x.input.released > before);
  assert.equal(ws.texts('bye').length, 1);
  assert.deepEqual([x.share.status().state, x.share.status().reason], ['ended', 'sender']);
  assert.ok(x.capture.calls.some((c) => c[0] === 'stop'));
});

test('share: a view-only grant never turns on input, even when the relay says control', async () => {
  const x = makeShare();
  await x.share.start({ requestId: RQ, ref: REF, mode: 'view' });
  const ws = x.ws();
  ws.open();
  assert.equal(ws.texts('hello')[0].control, false);
  ws.recv({ t: 'ready', mode: 'control' });
  assert.equal(x.input.active, false);
  ws.recv({ t: 'input', k: 'kbd', code: 'KeyA', down: true });
  assert.equal(x.input.handled.length, 0);
});

test('share: the secure desktop pauses the picture for the viewer; a display switch; the end and reconnects', async () => {
  const x = makeShare();
  await x.share.start({ requestId: RQ, ref: REF, mode: 'control' });
  let ws = x.ws();
  ws.open();
  ws.recv({ t: 'ready', mode: 'control' });
  const desk = x.repeats.find((r) => r.ms === 1000);
  x.input.desk = 'secure';
  desk.fn();
  assert.deepEqual(ws.texts('state').pop(), { t: 'state', paused: true, reason: 'secure' });
  ws.recv({ t: 'input', k: 'move', x: 0, y: 0 });
  assert.equal(x.input.handled.length, 0, 'no input while paused');
  x.input.desk = 'default';
  desk.fn();
  assert.deepEqual(ws.texts('state').pop(), { t: 'state', paused: false });
  // the viewer picks the second display
  ws.recv({ t: 'display', i: 1 });
  await tick(); await tick();
  assert.deepEqual(x.capture.calls.filter((c) => c[0] === 'start').map((c) => c[1]), [0, 1]);
  assert.deepEqual(x.input.rect, { x: 1920, y: 0, w: 1280, h: 1024 });
  assert.equal(ws.texts('displays').pop().display, 1);
  // the line breaks: a new token after 1 s, the same ref
  ws.close();
  assert.equal(x.share.status().state, 'connecting');
  const t1 = x.timers.find((t) => t.ms === 1000 && !t.cleared);
  t1.fn();
  await tick(); await tick();
  assert.equal(x.api.tokens, 2);
  ws = x.ws();
  ws.open();
  ws.recv({ t: 'end', reason: 'viewer' });
  assert.deepEqual([x.share.status().state, x.share.status().reason, x.share.status().started], ['ended', 'viewer', false]);
});

test('share: a ticket that is gone ends at once; nothing of a ref or token in the log', async () => {
  const logs = [];
  const x = makeShare({ tokenError: Object.assign(new Error('x'), { status: 404, code: 'not_found' }) });
  x.share.log = { info: (...a) => logs.push(a.join(' ')), warn: (...a) => logs.push(a.join(' ')), debug() {}, error() {} };
  await x.share.start({ requestId: RQ, ref: REF, mode: 'view' });
  assert.deepEqual([x.share.status().state, x.share.status().reason], ['ended', 'failed']);
  assert.ok(!logs.join('\n').includes(REF));
});

// ─── RemoteHost with "Bildschirm teilen" ───

function fakeApi(over = {}) {
  const calls = [];
  let n = 0;
  const api = {
    calls,
    register: async (b) => { calls.push(['register', b]); return { host: { deviceId: 100001, shareMode: 'code', allowOpen: true, state: 'ready', ...(b.screen ? { screen: { view: true, control: true } } : {}) } }; },
    state: async (b) => { calls.push(['state', b]); return { shareMode: 'code', allowOpen: true, pending: [] }; },
    unregister: async () => { calls.push(['unregister']); return { removed: true }; },
    code: async () => { n++; calls.push(['code']); return { code: `482-913-07${n}`, expiresAt: new Date(Date.now() + 600000).toISOString() }; },
    decide: async (id, d, m) => { calls.push(['decide', id, d, m]); return { request: { id, state: d === 'allow' ? 'allowed' : 'denied', mode: m || 'view' }, ...(d === 'allow' ? { screen: { ref: REF, wsPath: '/api/v1/remote/screen-relay' } } : {}) }; },
    screenEnd: async (id, r) => { calls.push(['screenEnd', id, r]); return { ended: true }; },
    firewallList: async () => ({ open: [] }),
    firewallReport: async () => ({ ok: true }),
    ...over,
  };
  return api;
}

function fakeFirewall() {
  return { open: async () => {}, close: async () => {}, closeAll: async () => 0, builtInOpen: async () => false };
}

function fakeShare() {
  const s = new EventEmitter();
  s.busy = false;
  s.calls = [];
  s.status = () => s.st || null;
  s.start = async (o) => { s.calls.push(['start', o]); s.busy = true; s.st = { state: 'connecting', requestId: o.requestId, mode: o.mode, started: false }; s.emit('session', s.st); return s.st; };
  s.stop = (r) => { s.calls.push(['stop', r]); s.busy = false; s.st = { ...s.st, state: 'ended', reason: r }; s.emit('session', s.st); };
  s.downgrade = () => { s.calls.push(['downgrade']); };
  s.end = (r) => { s.calls.push(['end', r]); s.busy = false; s.st = { ...s.st, state: 'ended', reason: r }; s.emit('session', s.st); };
  return s;
}

function makeHost(o = {}) {
  let handler = null;
  const api = o.api || fakeApi();
  const share = 'share' in o ? o.share : fakeShare();
  const host = new RemoteHost({
    api, firewall: fakeFirewall(), info: { detect: async () => ({ edition: 'pro', rdpAvailable: true, rdpEnabled: true, osUser: 'marc', ...(o.det || {}) }), enable: async () => {} },
    screenShare: share, name: 'PC-MARC', appVersion: '1.97.0',
    notificationCenter: { addPushHandler: (h) => { handler = h; return () => {}; } },
    setTimer: () => ({}), clearTimer: () => {},
  });
  const push = (data) => handler.notification({ kind: 'data', topic: RemoteHost.SIGNAL_TOPIC, data });
  return { host, api, share, push };
}

test('host: Windows Home with "Bildschirm teilen" registers for the screen; only RDP stays "home"', async () => {
  const { host, api } = makeHost({ det: { edition: 'home', rdpAvailable: false, rdpEnabled: false } });
  let s = await host.enable();
  assert.equal(s.status, 'home');
  assert.equal(api.calls.filter((c) => c[0] === 'register').length, 0);
  s = await host.setScreen(true);
  const reg = api.calls.find((c) => c[0] === 'register')[1];
  assert.deepEqual([reg.edition, reg.rdp.offered, reg.rdp.available, reg.screen], ['home', false, false, { view: true, control: true }]);
  assert.deepEqual([s.status, s.screen.enabled, s.screen.status, s.rdpAvailable], ['ready', true, 'ready', false]);
  assert.ok(s.code);
  // the screen off: Home has nothing left → signed off
  s = await host.setScreen(false);
  assert.ok(api.calls.some((c) => c[0] === 'unregister'));
});

test('host: a plugin before 1.5 does not know the screen of a PC → screen "unavailable", Remote Desktop as before', async () => {
  const api = fakeApi({ register: async (b) => { api.calls.push(['register', b]); return { host: { deviceId: 100001, shareMode: 'code', allowOpen: true, state: 'ready' } }; } });
  const { host } = makeHost({ api });
  await host.enable();
  const s = await host.setScreen(true);
  assert.deepEqual([s.status, s.screen.status], ['ready', 'unavailable']);
  // RDP off, the screen stays: registered with rdp.offered false
  await host.disable();
  const last = api.calls.filter((c) => c[0] === 'register').pop()[1];
  assert.equal(last.rdp.offered, false);
});

test('host: a screen request — control only when asked and chosen now; the picture starts; a new code after the end', async () => {
  const { host, api, share, push } = makeHost();
  await host.start(false, true);
  const asked = [];
  host.on('request', (r) => asked.push(r));
  push({ type: 'remote.request', requestId: RQ, from: { userId: 2, name: 'Tom Berger' }, mode: 'control', via: 'browser', kind: 'screen', expiresAt: new Date(Date.now() + 30000).toISOString() });
  await tick();
  assert.equal(asked[0].kind, 'screen');
  // "Nur ansehen": view goes to the plugin and to the session
  await host.decide(RQ, 'allow', 'view');
  assert.deepEqual(api.calls.find((c) => c[0] === 'decide').slice(1), [RQ, 'allow', 'view']);
  assert.deepEqual([share.calls[0][1].mode, share.calls[0][1].ref, share.calls[0][1].viewerName], ['view', REF, 'Tom Berger']);
  // the helper ended it after it ran: the plugin knows, a new code
  share.st.started = true;
  const codes = api.calls.filter((c) => c[0] === 'code').length;
  push({ type: 'remote.screen.end', requestId: RQ, reason: 'viewer' });
  await tick(); await tick();
  assert.deepEqual(share.calls.pop(), ['end', 'viewer']);
  assert.ok(api.calls.filter((c) => c[0] === 'code').length > codes, 'a new code');
  assert.equal(api.calls.filter((c) => c[0] === 'screenEnd').length, 0);
  // the next request: "Ansehen und steuern"
  const rq2 = 'rq_zyxwvutsrqponmlk';
  push({ type: 'remote.request', requestId: rq2, from: { userId: 2, name: 'Tom' }, mode: 'control', kind: 'screen' });
  await tick();
  await host.decide(rq2, 'allow', 'control');
  assert.equal(api.calls.filter((c) => c[0] === 'decide').pop()[3], 'control');
  assert.equal(share.calls.pop()[1].mode, 'control');
  // "Beenden" before the picture ran: the plugin hears "stopped"
  host.screenStop();
  await tick();
  assert.deepEqual(api.calls.filter((c) => c[0] === 'screenEnd').pop(), ['screenEnd', rq2, 'stopped']);
});

test('host: a view request is never answered with control; a screen request without the switch is not asked', async () => {
  const { host, api, push } = makeHost();
  await host.start(true, true);
  push({ type: 'remote.request', requestId: RQ, from: { name: 'Tom' }, mode: 'view', kind: 'screen' });
  await tick();
  await host.decide(RQ, 'allow', 'control');
  assert.equal(api.calls.find((c) => c[0] === 'decide')[3], 'view');
  await host.setScreen(false);
  const asked = [];
  host.on('request', (r) => asked.push(r));
  push({ type: 'remote.request', requestId: 'rq_qqqqqqqqqqqqqqqq', from: { name: 'Tom' }, mode: 'view', kind: 'screen' });
  await tick();
  assert.equal(asked.filter(Boolean).length, 0);
});

test('host api: the screen token goes to GateControl\'s own route; the end of a request to the plugin', async () => {
  const calls = [];
  const http = { _call: async (m, p, o) => { calls.push([m, p, o && o.body]); return { ok: true }; } };
  const api = new RemoteHostApi({ http });
  await api.screenToken(REF);
  await api.screenEnd(RQ, 'stopped');
  await assert.rejects(api.screenToken('short'), (e) => e.code === 'invalid');
  assert.deepEqual(calls, [['POST', '/api/v1/client/remote/screen-token', { ref: REF }],
    ['POST', '/api/v1/client/plugins/gatecontrol-remote/api/host/screen/' + RQ + '/end', { reason: 'stopped' }]]);
});
