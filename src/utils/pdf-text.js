'use strict';

/**
 * The text layer of a PDF for Drive's search (`uploads/commit { text }`, like
 * the Android app): read with unpdf (pdf.js, MIT / Apache-2.0) in a worker
 * thread of the main process, so a large or broken PDF never blocks the app
 * and is stopped after the time limit (the worker is terminated).
 *
 * Only PDFs up to 50 MB, at most 10 s, at most 100 000 characters (Drive's
 * TEXT_MAX). Scans without a text layer give no text (the server recognises
 * them itself). Every failure ends in `null`: the upload goes on without text.
 */

const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const { TEXT_MAX } = require('./drive');

const PDF_MAX_BYTES = 50 * 1024 * 1024;
const PDF_TIMEOUT_MS = 10000;
const PDF_MAX_PAGES = 2000;

// Runs in the worker: { file, unpdf, max, pages } → { text } | { error }
const WORKER_CODE = `
const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');
(async () => {
  const { getDocumentProxy, extractText } = require(workerData.unpdf);
  const data = new Uint8Array(fs.readFileSync(workerData.file));
  const pdf = await getDocumentProxy(data, { isEvalSupported: false, disableFontFace: true, useSystemFonts: false, verbosity: 0 });
  if (pdf.numPages > workerData.pages) { parentPort.postMessage({ text: '' }); return; }
  const r = await extractText(pdf, { mergePages: true });
  const text = Array.isArray(r.text) ? r.text.join('\\n') : String(r.text || '');
  parentPort.postMessage({ text: text.slice(0, workerData.max) });
})().catch((e) => parentPort.postMessage({ error: String((e && e.message) || e).slice(0, 200) }));
`;

let unpdfPath;
/**
 * The path of unpdf for the worker. In the packed app it lies unpacked next to app.asar
 * (Pro: build.asarUnpack), so the worker loads it from a plain folder.
 */
function resolveUnpdf() {
  if (unpdfPath === undefined) {
    try { unpdfPath = require.resolve('unpdf'); } catch { unpdfPath = null; }
    const asar = `app.asar${path.sep}`;
    if (unpdfPath && unpdfPath.includes(asar)) {
      const unpacked = unpdfPath.replace(asar, `app.asar.unpacked${path.sep}`);
      try { if (fs.existsSync(unpacked)) unpdfPath = unpacked; } catch { /* keep the asar path */ }
    }
  }
  return unpdfPath;
}

/** Is this a file whose text layer is read (by name or type)? */
function isPdf(name, mime = null) {
  return /\.pdf$/i.test(String(name || '')) || String(mime || '').toLowerCase() === 'application/pdf';
}

/** Cleans the text: control characters out, spaces folded, ≤ TEXT_MAX; null when nothing is left. */
function cleanText(raw, max = TEXT_MAX) {
  if (typeof raw !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = raw.slice(0, max * 2).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .split('\n').map((l) => l.replace(/[ \t\r]+/g, ' ').trim()).filter(Boolean).join('\n');
  return s ? s.slice(0, max) : null;
}

/**
 * The text of the PDF at `file` → string | null.
 * @param {string} file
 * @param {object} [o]
 * @param {number} [o.size] - known size (else stat)
 * @param {number} [o.timeoutMs=10000]
 * @param {number} [o.maxBytes=50 MB]
 * @param {object} [o.log]
 */
async function pdfText(file, { size = null, timeoutMs = PDF_TIMEOUT_MS, maxBytes = PDF_MAX_BYTES, log = null } = {}) {
  try {
    if (typeof file !== 'string' || !path.isAbsolute(file)) return null;
    let bytes = size;
    if (!Number.isFinite(bytes)) bytes = (await fs.promises.stat(file)).size;
    if (!bytes || bytes > maxBytes) return null;
    const unpdf = resolveUnpdf();
    if (!unpdf) return null;
    const text = await new Promise((resolve) => {
      let done = false;
      let worker;
      const finish = (v) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (worker) worker.terminate().catch(() => {});
        resolve(v);
      };
      const timer = setTimeout(() => finish(null), timeoutMs);
      if (timer.unref) timer.unref();
      try {
        worker = new Worker(WORKER_CODE, { eval: true, workerData: { file, unpdf, max: TEXT_MAX * 2, pages: PDF_MAX_PAGES }, resourceLimits: { maxOldGenerationSizeMb: 512 } });
      } catch (err) {
        if (log) log.debug(`PDF text: no worker (${err.message})`);
        finish(null);
        return;
      }
      worker.on('message', (m) => finish(m && typeof m.text === 'string' ? m.text : null));
      worker.on('error', () => finish(null));
      worker.on('exit', () => finish(null));
    });
    return cleanText(text);
  } catch (err) {
    if (log) log.debug(`PDF text not read: ${err && err.message}`);
    return null;
  }
}

module.exports = { pdfText, isPdf, cleanText, PDF_MAX_BYTES, PDF_TIMEOUT_MS };
