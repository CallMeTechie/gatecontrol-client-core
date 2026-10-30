'use strict';

// The text recognition of Windows (services/windows-ocr.js, Drive 1.14 searchable PDFs): the WinRT calls through
// koffi against fake COM objects (fixtures/fake-winrt.js): an OCR language there or not, the picture made smaller to
// MaxImageDimension (Electron's nativeImage: a fake here), the SoftwareBitmap (Bgra8), the lines and words with their
// places in pixels of the original picture, every object released and every HSTRING deleted. The real Windows OCR
// runs in windows-ocr.win.test.js (Windows only).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const koffi = require('koffi');

const { createWindowsOcr, cleanLines, SLOT, IID, BGRA8 } = require('../src/services/windows-ocr');
const { fakeWinRt } = require('./fixtures/fake-winrt');

const runtimes = [];
after(() => { for (const rt of runtimes) rt.dispose(); });

/** Electron's nativeImage as far as the OCR uses it: a picture of `size`, resize, BGRA pixels, JPEG. */
function fakeImages(size = { width: 5200, height: 1000 }) {
  const calls = { resize: [], jpeg: 0 };
  const picture = (sz) => ({
    isEmpty: () => false,
    getSize: () => ({ ...sz }),
    resize: (o) => { calls.resize.push(o); return picture({ width: o.width, height: o.height }); },
    toBitmap: () => Buffer.alloc(sz.width * sz.height * 4, 0xff),
    toJPEG: (q) => { calls.jpeg = q; return Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1]); },
  });
  return {
    calls,
    createFromBuffer: (b) => (b.length ? picture(size) : { isEmpty: () => true, getSize: () => ({ width: 0, height: 0 }) }),
  };
}

function setup({ size, languages = true, maxDim = 2600 } = {}) {
  const rt = fakeWinRt(koffi);
  runtimes.push(rt);
  rt.ocr.languages = languages;
  rt.ocr.maxDim = maxDim;
  const images = fakeImages(size);
  const ocr = createWindowsOcr({ platform: 'win32', koffi, api: rt.api, nativeImage: images, timing: { pollMs: 1, recognizeMs: 2000 } });
  return { rt, ocr, images };
}

const LINES = [
  { text: 'Stadtwerke Rechnung', words: [{ text: 'Stadtwerke', x: 10, y: 20, w: 30, h: 40 }, { text: 'Rechnung', x: 50, y: 20, w: 25, h: 40 }] },
  { text: '', words: [{ text: 'Größe', x: 10, y: 80, w: 20, h: 10 }, { text: ' ', x: 40, y: 80, w: 5, h: 10 }] },
];

describe('windows-ocr: layout', () => {
  it('IIDs and vtable slots as in the Windows SDK metadata', () => {
    assert.equal(IID.IOcrEngineStatics, '5BFFA85A-3384-3540-9940-699120D428A8');
    assert.equal(IID.ISoftwareBitmapStatics, 'DF0385DB-672F-4A9D-806E-C2442F343E86');
    assert.deepEqual([SLOT.maxDimension, SLOT.userProfileEngine, SLOT.recognize, SLOT.resultLines], [6, 10, 6, 6]);
    assert.deepEqual([SLOT.vectorAt, SLOT.vectorSize, SLOT.lineWords, SLOT.lineText, SLOT.wordRect, SLOT.wordText, SLOT.bitmapFromBuffer], [6, 7, 6, 7, 6, 7, 9]);
    assert.equal(BGRA8, 87);
  });

  it('cleanLines: empty words go, a line without text gets its words, places scaled', () => {
    assert.deepEqual(cleanLines(LINES, 2), [
      { text: 'Stadtwerke Rechnung', words: [{ text: 'Stadtwerke', x: 20, y: 40, w: 60, h: 80 }, { text: 'Rechnung', x: 100, y: 40, w: 50, h: 80 }] },
      { text: 'Größe', words: [{ text: 'Größe', x: 20, y: 160, w: 40, h: 20 }] },
    ]);
  });
});

describe('windows-ocr: recognition', () => {
  it('available: an OCR language there or not; other systems: unsupported_os', async () => {
    assert.deepEqual(await setup().ocr.available(), { available: true, reason: null });
    assert.deepEqual(await setup({ languages: false }).ocr.available(), { available: false, reason: 'no_language' });
    assert.deepEqual(await createWindowsOcr({ platform: 'linux' }).available(), { available: false, reason: 'unsupported_os' });
    await assert.rejects(createWindowsOcr({ platform: 'linux' }).recognize(Buffer.from('x')), (e) => e.code === 'unsupported_os');
  });

  it('a large picture is made smaller to MaxImageDimension; the places come back in its own pixels', async () => {
    const { rt, ocr, images } = setup();
    rt.ocr.lines = LINES;
    const r = await ocr.recognize(Buffer.from('jpeg'));
    assert.deepEqual(images.calls.resize, [{ width: 2600, height: 500, quality: 'best' }]);
    assert.deepEqual(rt.ocr.bitmaps, [{ format: 87, width: 2600, height: 500, bytes: 2600 * 500 * 4 }]);
    assert.equal(r.width, 5200);
    assert.equal(r.height, 1000);
    assert.equal(r.text, 'Stadtwerke Rechnung\nGröße');
    assert.deepEqual(r.lines[0].words[0], { text: 'Stadtwerke', x: 20, y: 40, w: 60, h: 80 });
    // the engine is kept for the next picture; everything else is released, every HSTRING deleted
    assert.deepEqual(rt.live(), ['OcrEngine']);
    assert.equal(rt.strings(), 0);
    const again = await ocr.recognize(Buffer.from('jpeg'));
    assert.equal(again.lines.length, 2);
    assert.deepEqual(rt.live(), ['OcrEngine']);
  });

  it('a small picture as it is; a picture without text; errors', async () => {
    const { rt, ocr, images } = setup({ size: { width: 800, height: 600 } });
    const r = await ocr.recognize(Buffer.from('png'));
    assert.deepEqual(images.calls.resize, []);
    assert.deepEqual(r, { width: 800, height: 600, lines: [], text: '' });
    await assert.rejects(ocr.recognize(Buffer.alloc(0)), (e) => e.code === 'bad_image');
    await assert.rejects(ocr.recognizePixels({ width: 2, height: 2, bgra: Buffer.alloc(3) }), (e) => e.code === 'bad_image');
    rt.asyncError = 0x80004005 | 0;
    await assert.rejects(ocr.recognize(Buffer.from('png')), (e) => e.name === 'WinRtError');
    assert.deepEqual(rt.live(), ['OcrEngine']);
    assert.equal(rt.strings(), 0);
    const none = setup({ languages: false });
    await assert.rejects(none.ocr.recognize(Buffer.from('png')), (e) => e.code === 'no_language');
  });

  it('image(): a JPEG stays as it is, anything else becomes one', () => {
    const { ocr, images } = setup({ size: { width: 40, height: 30 } });
    const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xdb, 9, 9]);
    assert.deepEqual(ocr.image(jpeg), { width: 40, height: 30, jpeg });
    const png = ocr.image(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    assert.equal(images.calls.jpeg, 90);
    assert.equal(png.jpeg[0], 0xff);
  });
});
