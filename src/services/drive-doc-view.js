'use strict';

/**
 * The viewer of PDFs, texts and Markdown of the normal files of Drive (not of a vault) — the rules, without Electron.
 *
 * The page shows them with the vault viewer's pages (pdf.js on <canvas>, text as text nodes — Pro
 * drive-vault-viewer.js), but the content is the file as "Öffnen" loads it anyway: the copy of this revision in
 * %TEMP%\gatecontrol-drive\<id>-<rev>\, else a download (a row of the transfer list) — DriveService.docView(). So
 * "Mit anderem Programm öffnen" afterwards opens that same copy without loading it again. A PDF goes to the page as
 * bytes, a text already decoded. Office files and everything else keep opening in another program; a file the virus
 * scan holds back is refused (423) as by open().
 */

const DriveVaultViews = require('./drive-vault-view');

const MB = 1048576;

/** What the page gets at most: a PDF (pdf.js draws a page at a time), a text (shown as a whole). */
const LIMITS = Object.freeze({ pdf: 100 * MB, text: 2 * MB, markdown: 2 * MB });

const TEXT_MIME = new Set(['application/json', 'application/xml']);

/** 'pdf' | 'text' | 'markdown' | null: by the name (as in the vault), else by the type the server stored. */
function kindOf(name, mime) {
  const k = DriveVaultViews.kindOf(name);
  if (k === 'pdf' || k === 'text' || k === 'markdown') return k;
  // a picture, a video, sound, an Office file by its name: not here, whatever the type says
  if (k !== 'other') return null;
  const m = typeof mime === 'string' ? mime.split(';')[0].trim().toLowerCase() : '';
  if (m === 'application/pdf') return 'pdf';
  if (m === 'text/markdown' || m === 'text/x-markdown') return 'markdown';
  if ((m.startsWith('text/') && m !== 'text/html') || TEXT_MIME.has(m)) return 'text';
  return null;
}

/** Too large for the viewer of `kind` (it says so; the way out is another program). */
function tooLarge(kind, size) {
  return Number.isSafeInteger(size) && size > (LIMITS[kind] || 0);
}

function limitMb(kind) {
  return Math.round((LIMITS[kind] || 0) / MB);
}

// Windows-1252 at 0x80–0x9F (undefined ones stay as they are); everything else is Latin-1. Written out: the
// TextDecoder of some Node versions reads "windows-1252" as plain Latin-1 (0x80 → U+0080 instead of €).
const CP1252_HIGH = [
  0x20ac, 0x81, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8d, 0x017d, 0x8f,
  0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x9d, 0x017e, 0x0178,
];

function windows1252(b) {
  let out = '';
  for (let i = 0; i < b.length; i += 8192) {
    const part = b.subarray(i, i + 8192);
    const codes = new Array(part.length);
    for (let j = 0; j < part.length; j++) {
      const c = part[j];
      codes[j] = c >= 0x80 && c <= 0x9f ? CP1252_HIGH[c - 0x80] : c;
    }
    out += String.fromCharCode.apply(null, codes);
  }
  return out;
}

/**
 * The bytes of a text file as text: UTF-8 (a BOM dropped), UTF-16 with its BOM; what is not valid UTF-8 is read as
 * Windows-1252 (old German texts from Windows: ä, ö, ü, ß, €), never with replacement marks all over it.
 */
function decodeText(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf || []);
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8').decode(b.subarray(3));
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.subarray(2));
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.subarray(2));
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(b);
  } catch {
    return windows1252(b);
  }
}

module.exports = { LIMITS, kindOf, tooLarge, limitMb, decodeText };
