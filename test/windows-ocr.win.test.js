'use strict';

// The text recognition of Windows against the real Windows Runtime (Windows only; skipped elsewhere): the WinRT layout
// of services/windows-ocr.js (OcrEngine statics, MaxImageDimension, SoftwareBitmap.CreateCopyFromBuffer) and — when
// the runner has an OCR language — the words of a printed test picture (fixtures/ocr-scan.bgra.gz: 480 × 120 BGRA,
// "GateControl Rechnung" / "Betrag 84,20 Euro"). Without an OCR language the line "OCR-SKIPPED" is logged.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const { createWindowsOcr, OcrRt, loadOcrApi } = require('../src/services/windows-ocr');

const win = process.platform === 'win32';
const pixels = () => zlib.gunzipSync(fs.readFileSync(path.join(__dirname, 'fixtures', 'ocr-scan.bgra.gz')));

describe('windows-ocr on Windows', { skip: win ? false : 'Windows only' }, () => {
  it('the WinRT layout: OcrEngine statics, MaxImageDimension, a SoftwareBitmap from BGRA pixels', () => {
    const koffi = require('koffi');
    const rt = new OcrRt({ koffi, api: loadOcrApi(koffi), timing: { pollMs: 20 } });
    const max = rt.maxDimension();
    assert.ok(max >= 1000 && max <= 100000, `MaxImageDimension ${max}`);
    const bmp = rt.bitmap(pixels(), 480, 120);
    assert.ok(bmp, 'SoftwareBitmap.CreateCopyFromBuffer');
    rt.release(bmp);
    const engine = rt.createEngine();
    console.log(`Windows OCR here: MaxImageDimension ${max}, engine ${engine ? 'yes' : 'no (no OCR language)'}`);
    if (engine) rt.release(engine);
  });

  it('recognises the printed words of the test picture (or says why not)', async () => {
    const ocr = createWindowsOcr({ timing: { pollMs: 20 } });
    const a = await ocr.available();
    assert.ok(a.available ? a.reason === null : ['no_language', 'error'].includes(a.reason), JSON.stringify(a));
    if (!a.available) {
      console.log(`OCR-SKIPPED: ${a.reason}`);
      return;
    }
    const r = await ocr.recognizePixels({ width: 480, height: 120, bgra: pixels() });
    console.log(`Windows OCR read: ${JSON.stringify(r.text)}`);
    assert.match(r.text, /Rechnung/);
    assert.match(r.text, /84[,.]20/);
    const w = r.lines.flatMap((l) => l.words).find((x) => x.text === 'Rechnung');
    assert.ok(w && w.x > 100 && w.y < 60 && w.w > 40 && w.h > 10, JSON.stringify(w));
  });
});
