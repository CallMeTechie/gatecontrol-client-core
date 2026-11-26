'use strict';

/**
 * GateControl – text recognition of Windows (Core service, Windows)
 *
 * Drive 1.14 'scanDocs': a scan of printed text becomes a searchable PDF on this PC — without AI, nothing leaves the
 * PC for it. The words and their places come from Windows.Media.Ocr (the OCR of Windows 10 / 11, the languages of
 * the user's profile), called through koffi like Windows Hello (services/windows-hello.js: its WinRt layer, the same
 * polling of IAsyncInfo, no PowerShell, no native addon):
 *
 *   OcrEngine           MaxImageDimension · TryCreateFromUserProfileLanguages() (null: no OCR language installed)
 *   SoftwareBitmap      CreateCopyFromBuffer(IBuffer, Bgra8, width, height)
 *   IOcrEngine          RecognizeAsync(SoftwareBitmap) → OcrResult
 *   OcrResult / Line    Lines / Words (IVectorView: GetAt, Size), Text (HSTRING)
 *   OcrWord             BoundingRect (Rect: x, y, width, height as floats) · Text
 *
 * The picture is decoded by Electron (nativeImage: JPEG / PNG → BGRA) and made smaller to MaxImageDimension first;
 * the places of the words are given in pixels of the original picture.
 *
 * createWindowsOcr() → provider:
 *   available()          → { available, reason: null | 'unsupported_os' | 'no_language' | 'error' }   (no prompt, cached)
 *   recognize(bytes)     → { width, height, lines: [{ text, words: [{ text, x, y, w, h }] }], text }
 *   recognizePixels({ width, height, bgra }) → { lines, text }   (the pixels already ≤ MaxImageDimension)
 *   image(bytes)         → { width, height, jpeg }   the picture for a PDF page (a JPEG stays as it is)
 *   jpeg(bytes, { maxSide, quality }) → Buffer          a smaller JPEG (for Drive's scans/convert `images`; needs no OCR)
 * Failures throw (WinRtError, or an Error with `code` 'unsupported_os' | 'no_language' | 'bad_image').
 */

const { WinRt, WinRtError, loadApi } = require('./windows-hello');

const CLASS = {
  engine: 'Windows.Media.Ocr.OcrEngine',
  bitmap: 'Windows.Graphics.Imaging.SoftwareBitmap',
};

const IID = {
  IOcrEngineStatics: '5BFFA85A-3384-3540-9940-699120D428A8',
  ISoftwareBitmapStatics: 'DF0385DB-672F-4A9D-806E-C2442F343E86',
};

// vtable slots (IInspectable: 0 … 5; the interface's own methods from 6 in metadata order)
const SLOT = {
  // IOcrEngineStatics: 6 get_MaxImageDimension, 7 get_AvailableRecognizerLanguages, 8 IsLanguageSupported,
  // 9 TryCreateFromLanguage, 10 TryCreateFromUserProfileLanguages
  maxDimension: 6, userProfileEngine: 10,
  // IOcrEngine: 6 RecognizeAsync, 7 get_RecognizerLanguage
  recognize: 6,
  // IOcrResult: 6 get_Lines, 7 get_TextAngle, 8 get_Text
  resultLines: 6,
  // IVectorView<T>: 6 GetAt, 7 get_Size
  vectorAt: 6, vectorSize: 7,
  // IOcrLine: 6 get_Words, 7 get_Text
  lineWords: 6, lineText: 7,
  // IOcrWord: 6 get_BoundingRect, 7 get_Text
  wordRect: 6, wordText: 7,
  // ISoftwareBitmapStatics: 6 Copy, 7 Convert, 8 ConvertWithAlpha, 9 CreateCopyFromBuffer
  bitmapFromBuffer: 9,
};

const BGRA8 = 87;                 // BitmapPixelFormat.Bgra8
const MAX_LINES = 2000;           // sanity bounds of what is read back
const MAX_WORDS = 200;
const DEFAULT_MAX_DIMENSION = 2600;
const DEFAULT_TIMING = { recognizeMs: 60 * 1000 };

const PROTOS = new WeakMap();
function ocrProtos(koffi) {
  let p = PROTOS.get(koffi);
  if (!p) {
    p = {
      getAt: koffi.proto('int32_t __stdcall (void *self, uint32_t index, _Out_ void **out)'),
      outU32: koffi.proto('int32_t __stdcall (void *self, _Out_ uint32_t *out)'),
      // the Rect (4 floats) into memory of koffi.alloc (decoded, never viewed: Electron's V8 sandbox)
      rect: koffi.proto('int32_t __stdcall (void *self, void *out)'),
      fromBuffer: koffi.proto('int32_t __stdcall (void *self, void *buffer, int32_t format, int32_t width, int32_t height, _Out_ void **out)'),
    };
    PROTOS.set(koffi, p);
  }
  return p;
}

/** Windows Hello's Win32 functions plus WindowsGetStringRawBuffer (HSTRINGs the OCR returns). */
function loadOcrApi(koffi) {
  const combase = koffi.load('combase.dll');
  return {
    ...loadApi(koffi),
    WindowsGetStringRawBuffer: combase.func('const char16_t *__stdcall WindowsGetStringRawBuffer(void *string, _Out_ uint32_t *length)'),
  };
}

function codeError(message, code) {
  const e = new Error(message);
  e.code = code;
  return e;
}

/** The WinRT calls of the OCR (on top of Windows Hello's WinRt: apartment, statics, async, buffers, release). */
class OcrRt extends WinRt {
  constructor(o) {
    super(o);
    this.Q = ocrProtos(this.koffi);
  }

  engineStatics() {
    return this.statics(CLASS.engine, IID.IOcrEngineStatics);
  }

  maxDimension() {
    const out = [0];
    this.check(this.invoke(this.engineStatics(), SLOT.maxDimension, this.Q.outU32, out), 'MaxImageDimension');
    return out[0] >>> 0;
  }

  /** TryCreateFromUserProfileLanguages → the engine (kept by the caller) or null when no OCR language is there. */
  createEngine() {
    const out = [null];
    this.check(this.invoke(this.engineStatics(), SLOT.userProfileEngine, this.P.outPtr, out), 'TryCreateFromUserProfileLanguages');
    return out[0] == null || out[0] === 0n ? null : out[0];
  }

  /** An HSTRING handed to us → its text; the string is deleted. */
  text(h) {
    if (h == null || h === 0n) return '';
    try {
      const len = [0];
      const s = this.api.WindowsGetStringRawBuffer(h, len);
      return typeof s === 'string' ? s.slice(0, Math.min(len[0] >>> 0 || s.length, 100000)) : '';
    } finally {
      this.api.WindowsDeleteString(h);
    }
  }

  stringOf(obj, slot, what) {
    const out = [null];
    this.check(this.invoke(obj, slot, this.P.outPtr, out), what);
    return this.text(out[0]);
  }

  /** The items of an IVectorView (each released after `fn`) → fn's results. */
  items(vector, max, fn) {
    const size = [0];
    this.check(this.invoke(vector, SLOT.vectorSize, this.Q.outU32, size), 'IVectorView.Size');
    const n = Math.min(size[0] >>> 0, max);
    const out = [];
    for (let i = 0; i < n; i++) {
      const item = [null];
      this.check(this.invoke(vector, SLOT.vectorAt, this.Q.getAt, i, item), 'IVectorView.GetAt');
      if (item[0] == null) continue;
      try { out.push(fn(item[0])); } finally { this.release(item[0]); }
    }
    return out;
  }

  rectOf(word) {
    const mem = this.koffi.alloc('float', 4);
    try {
      this.check(this.invoke(word, SLOT.wordRect, this.Q.rect, mem), 'OcrWord.BoundingRect');
      const a = this.koffi.decode(mem, 'float', 4);
      return { x: a[0], y: a[1], w: a[2], h: a[3] };
    } finally {
      this.koffi.free(mem);
    }
  }

  /** SoftwareBitmap (Bgra8) of the pixels (the caller releases it). */
  bitmap(bgra, width, height) {
    const statics = this.statics(CLASS.bitmap, IID.ISoftwareBitmapStatics);
    const buf = this.bufferFrom(bgra);
    try {
      const out = [null];
      this.check(this.invoke(statics, SLOT.bitmapFromBuffer, this.Q.fromBuffer, buf, BGRA8, width, height, out), 'SoftwareBitmap.CreateCopyFromBuffer');
      if (out[0] == null) throw new WinRtError('CreateCopyFromBuffer: null');
      return out[0];
    } finally {
      this.release(buf);
    }
  }

  /** RecognizeAsync → { lines: [{ text, words: [{ text, x, y, w, h }] }] } */
  async recognize(engine, bitmap) {
    const op = [null];
    this.check(this.invoke(engine, SLOT.recognize, this.P.ptrOut, bitmap, op), 'RecognizeAsync');
    const result = await this.finish(op[0], (o) => this.resultObject(o), { timeoutMs: this.timing.recognizeMs });
    try {
      const vec = this.getObject(result, SLOT.resultLines, 'OcrResult.Lines');
      try {
        const lines = this.items(vec, MAX_LINES, (line) => {
          const words = this.getObject(line, SLOT.lineWords, 'OcrLine.Words');
          try {
            return {
              text: this.stringOf(line, SLOT.lineText, 'OcrLine.Text'),
              words: this.items(words, MAX_WORDS, (w) => ({ text: this.stringOf(w, SLOT.wordText, 'OcrWord.Text'), ...this.rectOf(w) })),
            };
          } finally {
            this.release(words);
          }
        });
        return { lines };
      } finally {
        this.release(vec);
      }
    } finally {
      this.release(result);
    }
  }
}

const isJpeg = (b) => b && b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
const finite = (v) => (Number.isFinite(v) ? v : 0);

/** Lines of the OCR → clean lines (words with text and a size), the places scaled by `k`. */
function cleanLines(lines, k = 1) {
  const out = [];
  for (const l of lines || []) {
    const words = [];
    for (const w of (l && l.words) || []) {
      const text = typeof w.text === 'string' ? w.text.replace(/[\u0000-\u001F\u007F]/g, '').trim() : '';
      if (!text || !(w.w > 0) || !(w.h > 0)) continue;
      words.push({ text, x: finite(w.x) * k, y: finite(w.y) * k, w: w.w * k, h: w.h * k });
    }
    if (!words.length) continue;
    const text = typeof l.text === 'string' && l.text.trim() ? l.text.replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : words.map((w) => w.text).join(' ');
    out.push({ text, words });
  }
  return out;
}

/**
 * @param {object} [o]
 * @param {string} [o.platform]
 * @param {object} [o.koffi]
 * @param {object} [o.api] - the Win32 functions (tests: a fake)
 * @param {object} [o.nativeImage] - Electron's nativeImage (default: require('electron').nativeImage on first use)
 * @param {object} [o.timing] - { recognizeMs, pollMs }
 * @param {object} [o.log]
 */
function createWindowsOcr({ platform = process.platform, koffi = null, api = null, nativeImage = null, timing = {}, log = null } = {}) {
  let rt = null;
  let engine;            // undefined: not asked yet; null: no OCR language
  let maxDim = null;
  let chain = Promise.resolve();
  let state = null;      // the cached answer of available()

  const load = () => {
    if (rt) return rt;
    if (platform !== 'win32') throw codeError('Windows OCR needs Windows', 'unsupported_os');
    const k = koffi || require('koffi');
    rt = new OcrRt({ koffi: k, api: api || loadOcrApi(k), timing: { ...DEFAULT_TIMING, ...timing }, log });
    return rt;
  };
  const engineNow = () => {
    const r = load();
    if (engine === undefined) {
      engine = r.createEngine();
      try { maxDim = r.maxDimension() || DEFAULT_MAX_DIMENSION; } catch { maxDim = DEFAULT_MAX_DIMENSION; }
    }
    if (!engine) throw codeError('no OCR language installed', 'no_language');
    return engine;
  };
  const images = () => {
    if (nativeImage) return nativeImage;
    try { nativeImage = require('electron').nativeImage; } catch { nativeImage = null; }
    if (!nativeImage) throw codeError('no image decoder', 'unsupported_os');
    return nativeImage;
  };
  const decode = (bytes) => {
    const img = images().createFromBuffer(Buffer.from(bytes));
    if (!img || (typeof img.isEmpty === 'function' && img.isEmpty())) throw codeError('not a picture', 'bad_image');
    const { width, height } = img.getSize();
    if (!(width > 0 && height > 0)) throw codeError('not a picture', 'bad_image');
    return { img, width, height };
  };
  // one recognition at a time (the engine is not shared between calls)
  const serial = (fn) => {
    const run = chain.then(fn, fn);
    chain = run.catch(() => {});
    return run;
  };

  async function available() {
    if (state) return state;
    if (platform !== 'win32') return { available: false, reason: 'unsupported_os' };
    try {
      engineNow();
      state = { available: true, reason: null };
    } catch (err) {
      state = { available: false, reason: err && err.code === 'no_language' ? 'no_language' : 'error' };
      if (log && state.reason === 'error') log.warn(`Windows OCR not available: ${err && err.message}`);
    }
    return state;
  }

  function recognizePixels({ width, height, bgra }) {
    return serial(async () => {
      const e = engineNow();
      if (!(Number.isSafeInteger(width) && Number.isSafeInteger(height) && width > 0 && height > 0) || !bgra || bgra.length !== width * height * 4) {
        throw codeError('bad pixels', 'bad_image');
      }
      const r = load();
      const bmp = r.bitmap(bgra, width, height);
      try {
        const res = await r.recognize(e, bmp);
        const lines = cleanLines(res.lines);
        return { lines, text: lines.map((l) => l.text).join('\n') };
      } finally {
        r.release(bmp);
      }
    });
  }

  async function recognize(bytes) {
    engineNow();
    const { img, width, height } = decode(bytes);
    const max = maxDim || DEFAULT_MAX_DIMENSION;
    const k = Math.max(width, height) > max ? max / Math.max(width, height) : 1;
    const small = k < 1 ? img.resize({ width: Math.max(1, Math.round(width * k)), height: Math.max(1, Math.round(height * k)), quality: 'best' }) : img;
    const size = small.getSize();
    const bgra = small.toBitmap();
    const res = await recognizePixels({ width: size.width, height: size.height, bgra });
    // the places in pixels of the original picture
    const back = width / size.width;
    const lines = back === 1 ? res.lines : cleanLines(res.lines, back);
    return { width, height, lines, text: res.text };
  }

  /** The picture of a PDF page: a JPEG as it is, anything else as JPEG (quality 90). */
  function image(bytes) {
    const { img, width, height } = decode(bytes);
    return { width, height, jpeg: isJpeg(bytes) ? Buffer.from(bytes) : img.toJPEG(90) };
  }

  /** A JPEG of the picture whose longer side is at most `maxSide` (never enlarged). */
  function jpeg(bytes, { maxSide = 1600, quality = 70 } = {}) {
    const { img, width, height } = decode(bytes);
    const k = Math.max(width, height) > maxSide ? maxSide / Math.max(width, height) : 1;
    const small = k < 1 ? img.resize({ width: Math.max(1, Math.round(width * k)), height: Math.max(1, Math.round(height * k)), quality: 'best' }) : img;
    return small.toJPEG(quality);
  }

  return { available, recognize, recognizePixels, image, jpeg };
}

module.exports = {
  createWindowsOcr,
  cleanLines,
  loadOcrApi,
  ocrProtos,
  OcrRt,
  CLASS,
  IID,
  SLOT,
  BGRA8,
};
