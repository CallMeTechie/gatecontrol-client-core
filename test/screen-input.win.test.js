'use strict';

// "Bildschirm teilen" (Fernzugriff stage 7) against the real user32 (Windows only; skipped elsewhere): the koffi layout
// of INPUT for SendInput (40 bytes on x64), the virtual desktop, the input desktop (a runner may have none: 'secure'),
// and one SendInput call with a relative mouse move of 0 — it moves nothing; 0 or 1 events taken, never a throw.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const ScreenInput = require('../src/services/screen-input');

const win = process.platform === 'win32';

describe('screen-input on Windows', { skip: win ? false : 'Windows only' }, () => {
  it('INPUT, the virtual desktop, the input desktop, SendInput', () => {
    const b = ScreenInput.createWin32Backend(require('koffi'));
    assert.equal(b.inputSize(), process.arch === 'x64' || process.arch === 'arm64' ? 40 : 28);
    const vs = b.virtualScreen();
    assert.ok(Number.isInteger(vs.x) && Number.isInteger(vs.w) && vs.w >= 0 && vs.h >= 0, JSON.stringify(vs));
    const desk = b.inputDesktop();
    assert.ok(desk === 'default' || desk === 'secure', desk);
    const n = b.send([{ type: 0, dx: 0, dy: 0, data: 0, flags: ScreenInput.MOUSE.MOVE }]);
    assert.ok(n === 0 || n === 1, String(n));
    console.log(`screen-input here: virtual desktop ${vs.w}×${vs.h}, input desktop ${desk}, SendInput took ${n}`);
  });
});
