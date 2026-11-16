'use strict';

/**
 * GateControl – Fernzugriff stage 7: the picture of "Bildschirm teilen" (Core service, Electron main process)
 *
 * A hidden window (src/screen-share/capture.html: no UI, sandboxed, no Node, an in-memory session of its own that
 * may only capture) turns one display into H.264: desktopCapturer here picks the source, the window captures and
 * encodes it with WebCodecs (hardware first, software as the fallback). Its output comes back over the window's own
 * IPC (webContents.ipc), never a global channel.
 *
 *   displays()                     [{ i, primary, w, h, rect: { x, y, w, h } (physical pixels), id }] — i: order of Electron
 *   start(i, { fps, bitrate })     → { display, width, height, codec, hardware } once the encoder runs
 *   keyframe() / setBitrate(b) / stop() / destroy()
 * Events: 'config' { codec, width, height }, 'chunk' { key, ts (µs), data: Uint8Array }, 'error' { code }
 *
 * Electron is passed in (BrowserWindow, desktopCapturer, screen, session), so tests drive it with fakes.
 * Nothing of a picture is logged.
 */

const path = require('path');
const { EventEmitter } = require('events');
const { fitSize } = require('../screen-share/h264');

const PAGE = path.join(__dirname, '..', 'screen-share', 'capture.html');
const PRELOAD = path.join(__dirname, '..', 'screen-share', 'capture-preload.js');
const PARTITION = 'gc-screen-capture';
const START_MS = 15000;
const CODES = new Set(['encoder_unavailable', 'encoder_failed', 'capture_failed']);

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class ScreenCapture extends EventEmitter {
  /**
   * @param {object} o
   * @param {object} o.electron - { BrowserWindow, desktopCapturer, screen, session }
   * @param {object} [o.log]
   */
  constructor({ electron, log } = {}) {
    super();
    this.electron = electron;
    this.log = log || noopLog();
    this.win = null;
    this._ready = null;
    this._pending = null; // the start that waits for 'started'
    this.current = null; // { display, width, height }
  }

  /** The displays, in Electron's order; the rectangle in physical pixels of the virtual desktop. */
  displays() {
    const { screen } = this.electron;
    const primary = screen.getPrimaryDisplay();
    return screen.getAllDisplays().slice(0, 8).map((d, i) => {
      let rect;
      try { rect = typeof screen.dipToScreenRect === 'function' ? screen.dipToScreenRect(null, d.bounds) : null; } catch { rect = null; }
      if (!rect) {
        const f = d.scaleFactor || 1;
        rect = { x: Math.round(d.bounds.x * f), y: Math.round(d.bounds.y * f), width: Math.round(d.bounds.width * f), height: Math.round(d.bounds.height * f) };
      }
      return { i, id: String(d.id), primary: d.id === primary.id, w: rect.width, h: rect.height, rect: { x: rect.x, y: rect.y, w: rect.width, h: rect.height } };
    });
  }

  /** The index of the main display. */
  primaryIndex() {
    const list = this.displays();
    const p = list.find((d) => d.primary);
    return p ? p.i : 0;
  }

  _window() {
    if (this.win && !this.win.isDestroyed()) return this._ready;
    const { BrowserWindow, session } = this.electron;
    const ses = session.fromPartition(PARTITION, { cache: false });
    // this page may capture the screen and nothing else
    ses.setPermissionRequestHandler((wc, permission, cb) => cb(permission === 'media'));
    if (typeof ses.setPermissionCheckHandler === 'function') ses.setPermissionCheckHandler((wc, permission) => permission === 'media');
    this.win = new BrowserWindow({
      show: false, width: 320, height: 200, skipTaskbar: true, focusable: false,
      webPreferences: { preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false, session: ses, backgroundThrottling: false, spellcheck: false },
    });
    const wc = this.win.webContents;
    // never navigate, never open a window
    wc.setWindowOpenHandler(() => ({ action: 'deny' }));
    wc.on('will-navigate', (e) => e.preventDefault());
    this._ready = new Promise((resolve) => {
      wc.ipc.on('gc-capture:event', (_e, m) => {
        if (m && m.t === 'ready') { resolve(true); return; }
        this._event(m);
      });
    });
    wc.on('render-process-gone', () => { this._event({ t: 'error', code: 'capture_failed' }); this.win = null; });
    this.win.loadFile(PAGE).catch((err) => this.log.warn('Screen capture: page not loaded:', err && err.message));
    return this._ready;
  }

  _send(m) {
    if (this.win && !this.win.isDestroyed()) this.win.webContents.send('gc-capture:cmd', m);
  }

  _event(m) {
    if (!m || typeof m !== 'object') return;
    switch (m.t) {
      case 'started':
        if (this._pending) { const p = this._pending; this._pending = null; p.resolve(m); }
        return;
      case 'config':
        if (typeof m.codec === 'string' && /^avc1\.[0-9A-F]{6}$/i.test(m.codec)) this.emit('config', { codec: m.codec, width: m.width | 0, height: m.height | 0 });
        return;
      case 'chunk':
        if (m.data instanceof Uint8Array && m.data.length) this.emit('chunk', { key: m.key === true, ts: Number(m.ts) || 0, data: m.data });
        return;
      case 'error': {
        const code = CODES.has(m.code) ? m.code : 'capture_failed';
        this.log.warn('Screen capture:', code);
        if (this._pending) { const p = this._pending; this._pending = null; p.reject(Object.assign(new Error(code), { code })); return; }
        this.emit('error', { code });
        return;
      }
      default:
    }
  }

  /** Capture display `i` (another one replaces the running capture). */
  async start(i, { fps = 15, bitrate = 2000000 } = {}) {
    const list = this.displays();
    const display = list.find((d) => d.i === i) || list.find((d) => d.primary) || list[0];
    if (!display) throw Object.assign(new Error('no display'), { code: 'capture_failed' });
    await this._window();
    const sources = await this.electron.desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 0, height: 0 } });
    const src = sources.find((s) => String(s.display_id) === display.id) || sources[display.i] || null;
    if (!src) throw Object.assign(new Error('no source'), { code: 'capture_failed' });
    const size = fitSize(display.w, display.h);
    if (this._pending) this._pending.reject(Object.assign(new Error('replaced'), { code: 'capture_failed' }));
    const started = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (this._pending && this._pending.resolve === done) { this._pending = null; reject(Object.assign(new Error('timeout'), { code: 'capture_failed' })); } }, START_MS);
      const done = (m) => { clearTimeout(timer); resolve(m); };
      this._pending = { resolve: done, reject: (e) => { clearTimeout(timer); reject(e); } };
    });
    this._send({ t: 'start', sourceId: src.id, width: size.width, height: size.height, fps, bitrate });
    const m = await started;
    this.current = { display, width: m.width | 0, height: m.height | 0 };
    return { display, width: m.width | 0, height: m.height | 0, codec: m.codec || null, hardware: m.hardware || null };
  }

  keyframe() { this._send({ t: 'keyframe' }); }

  setBitrate(bitrate) { this._send({ t: 'bitrate', bitrate }); }

  stop() {
    this.current = null;
    if (this._pending) { const p = this._pending; this._pending = null; p.reject(Object.assign(new Error('stopped'), { code: 'capture_failed' })); }
    this._send({ t: 'stop' });
  }

  /** The window goes (app quit, the switch off). */
  destroy() {
    this.stop();
    if (this.win && !this.win.isDestroyed()) this.win.destroy();
    this.win = null;
    this._ready = null;
  }
}

ScreenCapture.PAGE = PAGE;
ScreenCapture.PRELOAD = PRELOAD;

module.exports = ScreenCapture;
