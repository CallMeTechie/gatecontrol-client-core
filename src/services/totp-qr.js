'use strict';

/**
 * GateControl – 2FA from a QR code (Vault entry editor, IPC vault:totp-qr)
 *
 * Reads an image in the main process and returns the otpauth://totp URIs of
 * the QR codes in it (utils/totp-qr.js). Sources:
 *
 *   'screen'    every display, captured with desktopCapturer at its native
 *               resolution (display size × scale factor). When nothing is
 *               found and the GateControl window is visible, it is made fully
 *               transparent for one more capture (it may cover the website's
 *               QR code) and restored right after; Windows / macOS only
 *               (setOpacity), elsewhere the second capture is skipped.
 *   'clipboard' the clipboard's image: clipboard.read() → ClipboardItem 'image/png'
 *               (Electron 44's asynchronous clipboard API), clipboard.readImage()
 *               in older Electron versions
 *   'file'      an image picked with dialog.showOpenDialog (PNG, JPG, GIF,
 *               BMP, WebP). PNG / JPG through nativeImage; the others through
 *               the Windows shell's thumbnail (nativeImage.createThumbnailFromPath,
 *               Windows / macOS), up to 2048 px.
 *
 * The bitmaps stay in the main process: they are decoded in a worker thread
 * (services/totp-qr-worker.js), in the main process when the worker cannot
 * start. Neither images nor URIs are logged.
 *
 * Errors carry `code`: `none_found` (no QR code with a 2FA key), `hotp` (only
 * otpauth://hotp codes), `invalid_code` (otpauth code without a usable key),
 * `no_image` (clipboard without an image), `unsupported` (image format /
 * screen capture not available), `cancelled` (file dialog closed), `failed`.
 */

const path = require('path');
const fs = require('fs');
const qr = require('../utils/totp-qr');
const { t } = require('../i18n');

const SOURCES = ['screen', 'clipboard', 'file'];
const CODES = ['none_found', 'hotp', 'invalid_code', 'no_image', 'unsupported', 'cancelled', 'failed'];
const MAX_FILE_BYTES = 30 * 1024 * 1024;
const THUMB_PX = 2048;
const HIDE_SETTLE_MS = 250;   // the compositor shows the window transparent before the capture
const FILE_TYPES = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'];
const WORKER_TIMEOUT_MS = 60 * 1000;

function err(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/** The clipboard's image as a nativeImage, or null (Electron ≥ 44: async read(); older: readImage()). */
async function clipboardImage(cb, nativeImage) {
  if (!cb) return null;
  if (typeof cb.readImage === 'function') return cb.readImage();
  if (typeof cb.read !== 'function' || !nativeImage) return null;
  const items = await cb.read();
  for (const item of Array.isArray(items) ? items : []) {
    const types = (Array.isArray(item && item.types) ? item.types : [])
      .filter((tp) => /^image\/(png|jpeg)$/i.test(tp))
      .sort((a, b) => (/png/i.test(b) ? 1 : 0) - (/png/i.test(a) ? 1 : 0));
    for (const tp of types) {
      try {
        const blob = await item.getType(tp);
        if (!blob || typeof blob.arrayBuffer !== 'function' || blob.size > MAX_FILE_BYTES) continue;
        const img = nativeImage.createFromBuffer(Buffer.from(await blob.arrayBuffer()));
        if (img && !img.isEmpty()) return img;
      } catch { /* next type */ }
    }
  }
  return null;
}

/** nativeImage → { data, width, height, bgra } (scaled down to ≤ MAX_PIXELS), or null when empty. */
function bitmapOf(image, platform = process.platform) {
  if (!image || (typeof image.isEmpty === 'function' && image.isEmpty())) return null;
  let img = image;
  let { width, height } = img.getSize();
  if (!(width > 0 && height > 0)) return null;
  if (width * height > qr.MAX_PIXELS) {
    const f = Math.sqrt(qr.MAX_PIXELS / (width * height)) * 0.99;
    img = img.resize({ width: Math.floor(width * f), height: Math.floor(height * f), quality: 'good' });
    ({ width, height } = img.getSize());
  }
  const data = img.toBitmap();
  if (!data || data.length < width * height * 4) return null;
  // Skia's N32 byte order: BGRA on Windows, macOS and Linux (little endian), RGBA on Android only
  return { data, width, height, bgra: platform !== 'android' };
}

/**
 * Decodes one bitmap in a worker thread (it gets a copy of the pixels) → Promise<string[]>. Rejects with
 * code `worker` when the worker cannot run (the caller decodes in the main process then), `failed` otherwise.
 */
function decodeInWorker(bmp, { Worker = null } = {}) {
  let W = Worker;
  if (!W) {
    try { W = require('worker_threads').Worker; } catch { return Promise.reject(err('worker')); }
  }
  return new Promise((resolve, reject) => {
    let w;
    try {
      w = new W(path.join(__dirname, 'totp-qr-worker.js'), {
        workerData: { data: bmp.data, width: bmp.width, height: bmp.height, bgra: bmp.bgra },
      });
    } catch {
      reject(err('worker'));
      return;
    }
    let done = false;
    const finish = (fn) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      Promise.resolve(w.terminate()).catch(() => {});
      fn();
    };
    const timer = setTimeout(() => finish(() => reject(err('failed'))), WORKER_TIMEOUT_MS);
    w.once('message', (m) => finish(() => (m && Array.isArray(m.texts) ? resolve(m.texts) : reject(err('failed')))));
    w.once('error', () => finish(() => reject(err('worker'))));
    w.once('exit', () => finish(() => reject(err('worker'))));
  });
}

/**
 * @param {object} opts
 * @param {'screen'|'clipboard'|'file'} opts.source
 * @param {() => object|null} [opts.getWindow] - the main window (dialog parent; made transparent for the 2nd screen capture)
 * @param {object} [opts.electron] - { desktopCapturer, screen, clipboard, dialog, nativeImage } (tests)
 * @param {Function} [opts.decode] - bitmap → Promise<string[]> (tests; default: worker thread)
 * @param {object} [opts.log]
 * @param {string} [opts.platform]
 * @returns {Promise<string[]>} otpauth://totp URIs (at least one)
 */
async function scanTotpQr({ source, getWindow = null, electron = null, decode = null, log = null, platform = process.platform } = {}) {
  if (!SOURCES.includes(source)) throw err('failed');
  const el = electron || require('electron');
  const win = () => {
    const w = typeof getWindow === 'function' ? getWindow() : null;
    return w && !(typeof w.isDestroyed === 'function' && w.isDestroyed()) ? w : null;
  };
  const run = decode || (async (bmp) => {
    try {
      return await decodeInWorker(bmp);
    } catch (e) {
      if (!e || e.code !== 'worker') throw e;
      // e.g. a packaged app whose worker cannot load its file: decode here (blocks the main process ~1–3 s)
      if (log) log.debug('QR scan: no worker thread, decoding in the main process');
      return qr.decodeQrImage(bmp);
    }
  });
  const decodeAll = async (bitmaps) => {
    const texts = [];
    for (const list of await Promise.all(bitmaps.map((b) => run(b)))) texts.push(...list);
    return qr.totpUris(texts);
  };
  const result = (res) => {
    const code = qr.totpQrError(res);
    if (code) throw err(code);
    return res.uris;
  };

  if (source === 'clipboard') {
    let image = null;
    try { image = await clipboardImage(el.clipboard, el.nativeImage); } catch { image = null; }
    const bmp = bitmapOf(image, platform);
    if (!bmp) throw err('no_image');
    return result(await decodeAll([bmp]));
  }

  if (source === 'file') {
    const parent = win();
    const opts = {
      title: t('vault.qrFileTitle'),
      properties: ['openFile'],
      filters: [{ name: t('vault.qrFileFilter'), extensions: FILE_TYPES }],
    };
    const pick = parent ? await el.dialog.showOpenDialog(parent, opts) : await el.dialog.showOpenDialog(opts);
    if (!pick || pick.canceled || !Array.isArray(pick.filePaths) || !pick.filePaths[0]) throw err('cancelled');
    const file = pick.filePaths[0];
    let st;
    try { st = await fs.promises.stat(file); } catch { throw err('failed'); }
    if (!st.isFile() || st.size > MAX_FILE_BYTES) throw err('unsupported');
    let image = null;
    if (/\.(png|jpe?g)$/i.test(file)) {
      image = el.nativeImage.createFromBuffer(await fs.promises.readFile(file));
    }
    if ((!image || image.isEmpty()) && (platform === 'win32' || platform === 'darwin') && typeof el.nativeImage.createThumbnailFromPath === 'function') {
      try { image = await el.nativeImage.createThumbnailFromPath(file, { width: THUMB_PX, height: THUMB_PX }); } catch { image = null; }
    }
    const bmp = bitmapOf(image, platform);
    if (!bmp) throw err('unsupported');
    return result(await decodeAll([bmp]));
  }

  // screen: every display at its native resolution
  const displays = (el.screen && typeof el.screen.getAllDisplays === 'function' ? el.screen.getAllDisplays() : []) || [];
  let width = 0;
  let height = 0;
  for (const d of displays) {
    const f = Number(d.scaleFactor) || 1;
    width = Math.max(width, Math.round(((d.size && d.size.width) || 0) * f));
    height = Math.max(height, Math.round(((d.size && d.size.height) || 0) * f));
  }
  if (!width || !height) { width = 1920; height = 1080; }
  const capture = async () => {
    let sources;
    try {
      sources = await el.desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width, height } });
    } catch (e) {
      if (log) log.info(`QR scan: screen capture failed (${e && e.name ? e.name : 'error'})`);
      throw err('unsupported');
    }
    const bitmaps = (sources || []).map((s) => bitmapOf(s.thumbnail, platform)).filter(Boolean);
    if (!bitmaps.length) throw err('unsupported');
    return decodeAll(bitmaps);
  };

  let res = await capture();
  const w = win();
  if (!res.uris.length && w && (platform === 'win32' || platform === 'darwin') && typeof w.setOpacity === 'function'
    && (typeof w.isVisible !== 'function' || w.isVisible()) && !(typeof w.isMinimized === 'function' && w.isMinimized())) {
    // The window may cover the website's QR code: one more capture with the window transparent.
    const before = typeof w.getOpacity === 'function' ? w.getOpacity() : 1;
    let again;
    try {
      w.setOpacity(0);
      await delay(HIDE_SETTLE_MS);
      again = await capture();
    } finally {
      const back = win();
      if (back) back.setOpacity(before);
    }
    res = {
      uris: again.uris,
      hotp: res.hotp + again.hotp,
      invalid: res.invalid + again.invalid,
      other: res.other + again.other,
    };
  }
  return result(res);
}

module.exports = { scanTotpQr, decodeInWorker, bitmapOf, clipboardImage, SOURCES, CODES, FILE_TYPES };
