'use strict';

/**
 * GateControl – Fernzugriff stage 7: the helper's mouse and keyboard on this PC ("Bildschirm teilen", Core service)
 *
 * The input frames of gc-screen.v1 (the relay already cleaned and limited them) become SendInput calls of user32 —
 * through koffi, no native addon, no helper process. Only while the session is in mode control and the person here
 * allowed it for this very request; `stop()` locks at once (the bar's "Beenden" / "Nur ansehen") and lets go of
 * every key and button held.
 *
 *   desktop  move {x,y} · button {x,y,b,down} · wheel {x,y,dx,dy} · kbd {code,down} · text {text}
 *   touch    tap = left click · long = right click · swipe = drag with the left button · scroll = wheel ·
 *            key back = Alt+Left, home = Win, recents = Win+Tab, enter, backspace
 *
 * Coordinates are 0…1 of the shared display; the display's rectangle (physical pixels, virtual desktop) comes from
 * the capture. Keys are physical (KeyboardEvent.code → scan code), so the PC's layout decides the character;
 * text is typed as Unicode.
 *
 * Nothing runs when: the session is not control (inactive), the input desktop is not the normal one (UAC prompt,
 * lock or sign-in screen, Ctrl+Alt+Del — Windows' secure desktop, which no app can operate), or a limit is over
 * (90 events a second, text 5 a second and 4000 characters in 10 s, 16 keys held). A release always runs. A key or
 * button held 15 s without any input is let go. No input, no text and no coordinate is ever logged.
 */

const INPUT_MOUSE = 0;
const INPUT_KEYBOARD = 1;

const MOUSE = Object.freeze({ MOVE: 0x0001, LEFTDOWN: 0x0002, LEFTUP: 0x0004, RIGHTDOWN: 0x0008, RIGHTUP: 0x0010, MIDDLEDOWN: 0x0020, MIDDLEUP: 0x0040,
  WHEEL: 0x0800, HWHEEL: 0x1000, VIRTUALDESK: 0x4000, ABSOLUTE: 0x8000 });
const KEY = Object.freeze({ EXTENDED: 0x0001, UP: 0x0002, UNICODE: 0x0004, SCANCODE: 0x0008 });
const BUTTONS = Object.freeze({ left: [MOUSE.LEFTDOWN, MOUSE.LEFTUP], right: [MOUSE.RIGHTDOWN, MOUSE.RIGHTUP], middle: [MOUSE.MIDDLEDOWN, MOUSE.MIDDLEUP] });

const EVENTS_PER_S = 90;
const TEXT_PER_S = 5;
const TEXT_CHARS_WINDOW_MS = 10000;
const TEXT_CHARS = 4000;
const MAX_HELD = 16;
const STUCK_MS = 15000;
const DESKTOP_CHECK_MS = 250;

// KeyboardEvent.code → [scan code (set 1), extended] | { vk } — the same list as the relay (services/remote/screen.js)
const SCAN = (() => {
  const m = new Map();
  'QWERTYUIOP'.split('').forEach((c, i) => m.set('Key' + c, [0x10 + i, false]));
  'ASDFGHJKL'.split('').forEach((c, i) => m.set('Key' + c, [0x1e + i, false]));
  'ZXCVBNM'.split('').forEach((c, i) => m.set('Key' + c, [0x2c + i, false]));
  '1234567890'.split('').forEach((c, i) => m.set('Digit' + c, [0x02 + i, false]));
  for (let i = 1; i <= 10; i++) m.set('F' + i, [0x3a + i, false]);
  m.set('F11', [0x57, false]);
  m.set('F12', [0x58, false]);
  for (let i = 13; i <= 23; i++) m.set('F' + i, [0x64 + (i - 13), false]);
  m.set('F24', [0x76, false]);
  const plain = { Escape: 0x01, Minus: 0x0c, Equal: 0x0d, Backspace: 0x0e, Tab: 0x0f, BracketLeft: 0x1a, BracketRight: 0x1b, Enter: 0x1c, ControlLeft: 0x1d,
    Semicolon: 0x27, Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2a, Backslash: 0x2b, Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
    NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3a, ScrollLock: 0x46, Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49,
    NumpadSubtract: 0x4a, Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, NumpadAdd: 0x4e, Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52,
    NumpadDecimal: 0x53, IntlBackslash: 0x56 };
  for (const [k, v] of Object.entries(plain)) m.set(k, [v, false]);
  const ext = { NumpadEnter: 0x1c, ControlRight: 0x1d, NumpadDivide: 0x35, AltRight: 0x38, NumLock: 0x45, Home: 0x47, ArrowUp: 0x48, PageUp: 0x49,
    ArrowLeft: 0x4b, ArrowRight: 0x4d, End: 0x4f, ArrowDown: 0x50, PageDown: 0x51, Insert: 0x52, Delete: 0x53, MetaLeft: 0x5b, MetaRight: 0x5c, ContextMenu: 0x5d };
  for (const [k, v] of Object.entries(ext)) m.set(k, [v, true]);
  // keys without a plain scan code: the virtual key
  m.set('PrintScreen', { vk: 0x2c });
  m.set('Pause', { vk: 0x13 });
  return m;
})();

const unit = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class ScreenInput {
  /**
   * @param {object} o
   * @param {object} o.backend - { send(events) → number, inputDesktop() → 'default'|'secure', virtualScreen() → { x, y, w, h } } (createWin32Backend)
   * @param {() => boolean} [o.isLocked] - the workstation is locked (Electron powerMonitor)
   * @param {object} [o.log]
   * @param {() => number} [o.now]
   * @param {Function} [o.setTimer] / [o.clearTimer]
   */
  constructor({ backend, isLocked = () => false, log, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    this.backend = backend;
    this.isLocked = isLocked;
    this.log = log || noopLog();
    this.now = now;
    this._set = setTimer;
    this._clear = clearTimer;
    this.active = false;
    this.rect = null; // the shared display, physical pixels on the virtual desktop
    this.keys = new Map(); // code → the key event that pressed it
    this.buttons = new Set();
    this._bucket = EVENTS_PER_S;
    this._bucketAt = now();
    this._texts = [];
    this._textSecond = { at: 0, n: 0 };
    this._desk = { at: 0, state: 'default' };
    this._stuck = null;
  }

  /** Control starts (the person here chose "Ansehen und steuern" and the relay says control). */
  enable(rect) {
    if (rect) this.setDisplay(rect);
    this.active = true;
  }

  /** The display being shared changed (its rectangle in physical pixels). */
  setDisplay(rect) {
    if (!rect || !(rect.w > 0 && rect.h > 0)) return;
    this.releaseAll();
    this.rect = { x: Math.round(rect.x) || 0, y: Math.round(rect.y) || 0, w: Math.round(rect.w), h: Math.round(rect.h) };
  }

  /** No more input, at once (Beenden, Nur ansehen, the end, the secure desktop): everything held is let go. */
  stop() {
    this.active = false;
    this.releaseAll();
  }

  /** Let go of every key and button pressed by the helper. */
  releaseAll() {
    const ev = [];
    for (const b of this.buttons) ev.push(this._mouse(BUTTONS[b][1]));
    for (const k of [...this.keys.values()].reverse()) ev.push({ ...k, flags: k.flags | KEY.UP });
    this.buttons.clear();
    this.keys.clear();
    this._clearStuck();
    if (ev.length) this._send(ev);
  }

  _clearStuck() { if (this._stuck) { this._clear(this._stuck); this._stuck = null; } }

  /** A key or button held 15 s without any further input: let go (a lost key up, a helper gone). */
  _armStuck() {
    this._clearStuck();
    if (!this.keys.size && !this.buttons.size) return;
    this._stuck = this._set(() => { this._stuck = null; this.releaseAll(); }, STUCK_MS);
    if (this._stuck && this._stuck.unref) this._stuck.unref();
  }

  /** 'default' | 'secure' | 'locked' — checked at most every 250 ms. */
  desktop() {
    const now = this.now();
    if (now - this._desk.at >= DESKTOP_CHECK_MS) {
      let st = 'default';
      try { st = this.backend.inputDesktop() === 'default' ? 'default' : 'secure'; } catch { st = 'secure'; }
      this._desk = { at: now, state: st };
    }
    if (this._desk.state === 'default') return 'default';
    return this.isLocked() ? 'locked' : 'secure';
  }

  _take(now) {
    this._bucket = Math.min(EVENTS_PER_S, this._bucket + ((now - this._bucketAt) / 1000) * EVENTS_PER_S);
    this._bucketAt = now;
    if (this._bucket < 1) return false;
    this._bucket -= 1;
    return true;
  }

  _textAllowed(n, now) {
    if (now - this._textSecond.at >= 1000) this._textSecond = { at: now, n: 0 };
    if (this._textSecond.n >= TEXT_PER_S) return false;
    this._texts = this._texts.filter((e) => now - e.at < TEXT_CHARS_WINDOW_MS);
    if (this._texts.reduce((a, e) => a + e.n, 0) + n > TEXT_CHARS) return false;
    this._textSecond.n++;
    this._texts.push({ at: now, n });
    return true;
  }

  _point(x, y) {
    const r = this.rect;
    const vs = this.backend.virtualScreen();
    if (!r || !vs || !(vs.w > 1 && vs.h > 1)) return null;
    const px = r.x + Math.min(r.w - 1, Math.round(x * (r.w - 1)));
    const py = r.y + Math.min(r.h - 1, Math.round(y * (r.h - 1)));
    return { dx: Math.round(((px - vs.x) * 65535) / (vs.w - 1)), dy: Math.round(((py - vs.y) * 65535) / (vs.h - 1)) };
  }

  _mouse(flags, extra = {}) { return { type: INPUT_MOUSE, dx: 0, dy: 0, data: 0, flags, ...extra }; }

  _move(x, y) {
    const p = this._point(x, y);
    return p ? this._mouse(MOUSE.MOVE | MOUSE.ABSOLUTE | MOUSE.VIRTUALDESK, p) : null;
  }

  _keyEvent(code, up) {
    const s = SCAN.get(code);
    if (!s) return null;
    if (!Array.isArray(s)) return { type: INPUT_KEYBOARD, vk: s.vk, scan: 0, flags: up ? KEY.UP : 0 };
    return { type: INPUT_KEYBOARD, vk: 0, scan: s[0], flags: KEY.SCANCODE | (s[1] ? KEY.EXTENDED : 0) | (up ? KEY.UP : 0) };
  }

  _tapKeys(codes) {
    const down = codes.map((c) => this._keyEvent(c, false));
    const up = codes.slice().reverse().map((c) => this._keyEvent(c, true));
    return down.concat(up);
  }

  _send(events) {
    const list = events.filter(Boolean);
    if (!list.length) return true;
    try {
      const n = this.backend.send(list);
      return n === list.length;
    } catch (err) {
      this.log.warn('Screen input: SendInput failed:', err && err.code ? err.code : 'error');
      return false;
    }
  }

  /** A release (key up, button up): always carried out, even when inactive (nothing stays pressed). */
  _release(m) {
    if (m.k === 'kbd') {
      const k = this.keys.get(m.code);
      if (!k) return { ok: true };
      this.keys.delete(m.code);
      this._send([{ ...k, flags: k.flags | KEY.UP }]);
    } else {
      if (!this.buttons.has(m.b)) return { ok: true };
      this.buttons.delete(m.b);
      const mv = unit(m.x) && unit(m.y) && this.active ? this._move(m.x, m.y) : null;
      this._send([mv, this._mouse(BUTTONS[m.b][1])]);
    }
    this._armStuck();
    return { ok: true };
  }

  /**
   * One input frame of the relay → { ok: true } | { ok: false, reason: 'secure'|'locked'|'blocked'|'rate', k }.
   * Never throws; nothing of it is logged.
   */
  handle(m) {
    if (!m || typeof m !== 'object' || typeof m.k !== 'string') return { ok: false, reason: 'blocked' };
    const k = m.k;
    if ((k === 'kbd' || k === 'button') && m.down === false) return this._release(m);
    if (!this.active) return { ok: false, reason: 'blocked', k };
    const now = this.now();
    const desk = this.desktop();
    if (desk !== 'default') { this.releaseAll(); return { ok: false, reason: desk, k }; }
    if (!this._take(now)) return { ok: false, reason: 'rate', k };
    let ev = null;
    switch (k) {
      case 'move':
        if (!unit(m.x) || !unit(m.y)) return { ok: false, reason: 'blocked', k };
        ev = [this._move(m.x, m.y)];
        break;
      case 'button': {
        if (!BUTTONS[m.b] || !unit(m.x) || !unit(m.y)) return { ok: false, reason: 'blocked', k };
        if (this.buttons.has(m.b)) return { ok: true };
        this.buttons.add(m.b);
        ev = [this._move(m.x, m.y), this._mouse(BUTTONS[m.b][0])];
        break;
      }
      case 'wheel': {
        if (!unit(m.x) || !unit(m.y) || !Number.isInteger(m.dx) || !Number.isInteger(m.dy)) return { ok: false, reason: 'blocked', k };
        const clamp = (v) => Math.max(-1200, Math.min(1200, v));
        ev = [this._move(m.x, m.y)];
        if (m.dy) ev.push(this._mouse(MOUSE.WHEEL, { data: clamp(m.dy) }));
        if (m.dx) ev.push(this._mouse(MOUSE.HWHEEL, { data: clamp(m.dx) }));
        break;
      }
      case 'kbd': {
        const e = this._keyEvent(m.code, false);
        if (!e) return { ok: false, reason: 'blocked', k };
        if (!this.keys.has(m.code) && this.keys.size >= MAX_HELD) return { ok: false, reason: 'rate', k };
        this.keys.set(m.code, e);
        ev = [e];
        break;
      }
      case 'text': {
        if (typeof m.text !== 'string' || !m.text) return { ok: false, reason: 'blocked', k };
        const chars = [...m.text];
        if (chars.length > 500 || !this._textAllowed(chars.length, now)) return { ok: false, reason: 'rate', k };
        ev = [];
        for (let i = 0; i < m.text.length; i++) {
          const c = m.text.charCodeAt(i);
          if (c < 0x20 || (c >= 0x7f && c < 0xa0)) continue; // no control characters
          ev.push({ type: INPUT_KEYBOARD, vk: 0, scan: c, flags: KEY.UNICODE }, { type: INPUT_KEYBOARD, vk: 0, scan: c, flags: KEY.UNICODE | KEY.UP });
        }
        break;
      }
      // a phone viewer (touch kinds) on a PC
      case 'tap':
      case 'long': {
        if (!unit(m.x) || !unit(m.y)) return { ok: false, reason: 'blocked', k };
        const b = BUTTONS[k === 'tap' ? 'left' : 'right'];
        ev = [this._move(m.x, m.y), this._mouse(b[0]), this._mouse(b[1])];
        break;
      }
      case 'swipe': {
        if (!Array.isArray(m.pts) || m.pts.length < 2 || !m.pts.every((p) => Array.isArray(p) && unit(p[0]) && unit(p[1]))) return { ok: false, reason: 'blocked', k };
        ev = [this._move(m.pts[0][0], m.pts[0][1]), this._mouse(MOUSE.LEFTDOWN)];
        for (const p of m.pts.slice(1)) ev.push(this._move(p[0], p[1]));
        ev.push(this._mouse(MOUSE.LEFTUP));
        break;
      }
      case 'scroll': {
        if (!unit(m.x) || !unit(m.y) || typeof m.dy !== 'number' || typeof m.dx !== 'number') return { ok: false, reason: 'blocked', k };
        const h = this.rect ? this.rect.h : 1080;
        const w = this.rect ? this.rect.w : 1920;
        // dy > 0: the content goes down like a mouse wheel turned towards the person; about 100 px a notch
        const dy = Math.max(-1200, Math.min(1200, Math.round((-m.dy * h / 100) * 120)));
        const dx = Math.max(-1200, Math.min(1200, Math.round((m.dx * w / 100) * 120)));
        ev = [this._move(m.x, m.y)];
        if (dy) ev.push(this._mouse(MOUSE.WHEEL, { data: dy }));
        if (dx) ev.push(this._mouse(MOUSE.HWHEEL, { data: dx }));
        break;
      }
      case 'key': {
        const combos = { back: ['AltLeft', 'ArrowLeft'], home: ['MetaLeft'], recents: ['MetaLeft', 'Tab'], enter: ['Enter'], backspace: ['Backspace'] };
        if (!combos[m.key]) return { ok: false, reason: 'blocked', k };
        ev = this._tapKeys(combos[m.key]);
        break;
      }
      default:
        return { ok: false, reason: 'blocked', k };
    }
    const ok = this._send(ev);
    this._armStuck();
    return ok ? { ok: true } : { ok: false, reason: 'blocked', k };
  }
}

/**
 * The real backend: user32 through koffi (Windows only; loaded on first use). SendInput one event at a time (a JS
 * object for an INPUT pointer is copied into native memory by koffi), OpenInputDesktop for the secure desktop,
 * GetSystemMetrics for the virtual desktop.
 */
const APIS = new WeakMap(); // koffi → the types and functions (koffi refuses a type name twice)

function createWin32Backend(koffiIn = null) {
  let api = null;
  function load() {
    if (api) return api;
    const koffi = koffiIn || require('koffi');
    api = APIS.get(koffi) || null;
    if (api) return api;
    const user32 = koffi.load('user32.dll');
    const MOUSEINPUT = koffi.struct('GC_MOUSEINPUT', { dx: 'int32_t', dy: 'int32_t', mouseData: 'uint32_t', dwFlags: 'uint32_t', time: 'uint32_t', dwExtraInfo: 'uintptr_t' });
    const KEYBDINPUT = koffi.struct('GC_KEYBDINPUT', { wVk: 'uint16_t', wScan: 'uint16_t', dwFlags: 'uint32_t', time: 'uint32_t', dwExtraInfo: 'uintptr_t' });
    const HARDWAREINPUT = koffi.struct('GC_HARDWAREINPUT', { uMsg: 'uint32_t', wParamL: 'uint16_t', wParamH: 'uint16_t' });
    const UNION = koffi.union('GC_INPUT_UNION', { mi: MOUSEINPUT, ki: KEYBDINPUT, hi: HARDWAREINPUT });
    const INPUT = koffi.struct('GC_INPUT', { type: 'uint32_t', u: UNION });
    api = {
      size: koffi.sizeof(INPUT),
      sendInput: user32.func('uint32_t __stdcall SendInput(uint32_t cInputs, GC_INPUT *pInputs, int cbSize)'),
      metrics: user32.func('int __stdcall GetSystemMetrics(int nIndex)'),
      openInputDesktop: user32.func('void * __stdcall OpenInputDesktop(uint32_t dwFlags, bool fInherit, uint32_t dwDesiredAccess)'),
      closeDesktop: user32.func('bool __stdcall CloseDesktop(void *hDesktop)'),
      objectInfo: user32.func('bool __stdcall GetUserObjectInformationW(void *hObj, int nIndex, _Out_ uint8_t *pvInfo, uint32_t nLength, _Out_ uint32_t *lpnLengthNeeded)'),
    };
    APIS.set(koffi, api);
    return api;
  }
  return {
    /** sizeof(INPUT) as koffi lays it out (40 on x64 — what SendInput's cbSize must say). */
    inputSize() { return load().size; },
    send(events) {
      const a = load();
      let n = 0;
      for (const e of events) {
        const input = e.type === INPUT_MOUSE
          ? { type: INPUT_MOUSE, u: { mi: { dx: e.dx | 0, dy: e.dy | 0, mouseData: (e.data | 0) >>> 0, dwFlags: e.flags >>> 0, time: 0, dwExtraInfo: 0 } } }
          : { type: INPUT_KEYBOARD, u: { ki: { wVk: e.vk || 0, wScan: e.scan || 0, dwFlags: e.flags >>> 0, time: 0, dwExtraInfo: 0 } } };
        n += a.sendInput(1, input, a.size);
      }
      return n;
    },
    /** 'default' while the normal desktop takes input; 'secure' for the UAC prompt, lock and sign-in screen. */
    inputDesktop() {
      const a = load();
      const DESKTOP_READOBJECTS = 0x0001;
      const h = a.openInputDesktop(0, false, DESKTOP_READOBJECTS);
      if (!h) return 'secure';
      try {
        const buf = Buffer.alloc(128);
        const need = [0];
        if (!a.objectInfo(h, 2 /* UOI_NAME */, buf, buf.length, need)) return 'secure';
        const name = buf.toString('utf16le').replace(/\0.*$/s, '');
        return name.toLowerCase() === 'default' ? 'default' : 'secure';
      } finally {
        a.closeDesktop(h);
      }
    },
    virtualScreen() {
      const a = load();
      return { x: a.metrics(76), y: a.metrics(77), w: a.metrics(78), h: a.metrics(79) };
    },
  };
}

ScreenInput.SCAN = SCAN;
ScreenInput.MOUSE = MOUSE;
ScreenInput.KEY = KEY;
ScreenInput.STUCK_MS = STUCK_MS;
ScreenInput.createWin32Backend = createWin32Backend;

module.exports = ScreenInput;
