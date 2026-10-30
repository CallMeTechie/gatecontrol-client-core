'use strict';

/**
 * GateControl – a searchable PDF of scanned pages (Drive 1.14 'scanDocs', printed text)
 *
 * Each page is the scan as it is (a JPEG, DCTDecode) over the whole page; the words the OCR recognised lie on top as
 * invisible text (text render mode 3) at their places — the PDF looks like the scan, its text can be searched, marked
 * and copied. No font is embedded: Courier of the PDF standard fonts (every glyph 600 / 1000 wide, so a word is
 * stretched to its box with Tz), WinAnsiEncoding (German umlauts, ß, €, „ “ …; anything else becomes "?").
 *
 *   buildSearchablePdf(pages, { title }) → Buffer
 *     pages: [{ jpeg: Buffer, width, height (pixels), lines: [{ words: [{ text, x, y, w, h }] }] }]
 *
 * The page is A4 wide (portrait) or A4 high (landscape); the places are scaled from pixels to points.
 */

const zlib = require('zlib');

const A4_SHORT = 595.28;
const COURIER_ADVANCE = 0.6;   // em
const MAX_PAGES = 100;

// Windows-1252 0x80…0x9F (WinAnsiEncoding); 0xA0…0xFF are the Latin-1 code points themselves
const CP1252_HIGH = {
  0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87, 0x02C6: 0x88,
  0x2030: 0x89, 0x0160: 0x8A, 0x2039: 0x8B, 0x0152: 0x8C, 0x017D: 0x8E, 0x2018: 0x91, 0x2019: 0x92, 0x201C: 0x93,
  0x201D: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97, 0x02DC: 0x98, 0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B,
  0x0153: 0x9C, 0x017E: 0x9E, 0x0178: 0x9F,
};

/** Text → WinAnsi bytes (unknown characters: '?'). */
function winAnsi(text) {
  const out = [];
  for (const ch of String(text).normalize('NFC')) {
    const c = ch.codePointAt(0);
    if (c >= 0x20 && c < 0x7F) out.push(c);
    else if (c >= 0xA0 && c <= 0xFF) out.push(c);
    else if (CP1252_HIGH[c]) out.push(CP1252_HIGH[c]);
    else if (c === 0x09) out.push(0x20);
    else out.push(0x3F);
  }
  return Buffer.from(out);
}

const num = (v) => {
  const n = Math.round(v * 100) / 100;
  return Object.is(n, -0) ? '0' : String(n);
};

/** A PDF string of a text: its WinAnsi bytes as a hex string <…> (nothing to escape). */
function pdfText(text) {
  return `<${winAnsi(text).toString('hex')}>`;
}

/** PDF date of `ms`: D:YYYYMMDDHHmmSSZ */
function pdfDate(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `D:${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

/** Page size in points and the scale pixels → points. */
function pageGeometry(width, height) {
  const k = width <= height ? A4_SHORT / width : A4_SHORT / height;
  return { k, w: width * k, h: height * k };
}

/** The content stream of a page: the picture, then the words invisible at their places. */
function pageContent(page, geo) {
  const ops = [`q ${num(geo.w)} 0 0 ${num(geo.h)} 0 0 cm /Im0 Do Q`];
  const lines = Array.isArray(page.lines) ? page.lines : [];
  if (lines.some((l) => l && Array.isArray(l.words) && l.words.length)) {
    ops.push('BT 3 Tr');
    for (const l of lines) {
      const words = (l && Array.isArray(l.words) ? l.words : []).filter((w) => w && typeof w.text === 'string' && w.text && w.w > 0 && w.h > 0);
      words.forEach((wd, i) => {
        // a space after every word but the line's last: copied text keeps its words apart
        const text = i < words.length - 1 ? `${wd.text} ` : wd.text;
        const size = Math.max(1, wd.h * geo.k);
        const chars = [...wd.text].length;
        const tz = Math.min(1000, Math.max(1, (wd.w * geo.k) / (COURIER_ADVANCE * size * chars) * 100));
        const x = wd.x * geo.k;
        // the baseline a little above the box's bottom (the box holds the descenders)
        const y = geo.h - (wd.y + wd.h) * geo.k + size * 0.2;
        ops.push(`/F0 ${num(size)} Tf ${num(tz)} Tz 1 0 0 1 ${num(x)} ${num(y)} Tm ${pdfText(text)} Tj`);
      });
    }
    ops.push('ET');
  }
  return Buffer.from(ops.join('\n'), 'latin1');
}

/**
 * @param {Array<{ jpeg: Buffer, width: number, height: number, lines?: Array }>} pages
 * @param {object} [o]
 * @param {string} [o.title]
 * @param {number} [o.now]
 * @returns {Buffer}
 */
function buildSearchablePdf(pages, { title = null, now = Date.now() } = {}) {
  const list = Array.isArray(pages) ? pages : [];
  if (!list.length || list.length > MAX_PAGES) throw new Error('no pages');
  for (const p of list) {
    if (!p || !Buffer.isBuffer(p.jpeg) || p.jpeg.length < 4 || p.jpeg[0] !== 0xff || p.jpeg[1] !== 0xd8) throw new Error('page without a JPEG');
    if (!(Number.isSafeInteger(p.width) && Number.isSafeInteger(p.height) && p.width > 0 && p.height > 0)) throw new Error('page without a size');
  }

  const objects = [];   // index + 1 = object number; each a Buffer of the object's body
  const reserve = () => { objects.push(null); return objects.length; };
  const set = (n, body) => { objects[n - 1] = Buffer.isBuffer(body) ? body : Buffer.from(body, 'latin1'); };
  const stream = (dict, data) => Buffer.concat([Buffer.from(`<< ${dict} /Length ${data.length} >>\nstream\n`, 'latin1'), data, Buffer.from('\nendstream', 'latin1')]);

  const catalog = reserve();
  const pagesObj = reserve();
  const font = reserve();
  const info = reserve();
  set(font, '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
  const kids = [];
  for (const p of list) {
    const geo = pageGeometry(p.width, p.height);
    const page = reserve();
    const img = reserve();
    const content = reserve();
    kids.push(`${page} 0 R`);
    set(img, stream(`/Type /XObject /Subtype /Image /Width ${p.width} /Height ${p.height} ${colorSpace(p.jpeg)} /BitsPerComponent 8 /Filter /DCTDecode`, p.jpeg));
    set(content, stream('/Filter /FlateDecode', zlib.deflateSync(pageContent(p, geo))));
    set(page, `<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${num(geo.w)} ${num(geo.h)}] /Resources << /XObject << /Im0 ${img} 0 R >> /Font << /F0 ${font} 0 R >> >> /Contents ${content} 0 R >>`);
  }
  set(pagesObj, `<< /Type /Pages /Kids [${kids.join(' ')}] /Count ${kids.length} >>`);
  set(catalog, `<< /Type /Catalog /Pages ${pagesObj} 0 R >>`);
  const t = typeof title === 'string' && title.trim() ? ` /Title ${pdfText(title.trim().slice(0, 200))}` : '';
  set(info, `<< /Producer (GateControl)${t} /CreationDate (${pdfDate(now)}) >>`);

  const parts = [Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'latin1')];
  let offset = parts[0].length;
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(offset);
    const b = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), body, Buffer.from('\nendobj\n', 'latin1')]);
    parts.push(b);
    offset += b.length;
  });
  const xref = [`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`, ...offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`)].join('');
  parts.push(Buffer.from(`${xref}trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${offset}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(parts);
}

/** The colour space of a JPEG by its components: grey, RGB or (Adobe) CMYK. */
function colorSpace(jpeg) {
  const n = jpegComponents(jpeg);
  if (n === 1) return '/ColorSpace /DeviceGray';
  if (n === 4) return '/ColorSpace /DeviceCMYK /Decode [1 0 1 0 1 0 1 0]';
  return '/ColorSpace /DeviceRGB';
}

/** The number of colour components of a JPEG (its SOF marker), or 3 when not found. */
function jpegComponents(jpeg) {
  let i = 2;
  while (i + 9 < jpeg.length) {
    if (jpeg[i] !== 0xff) { i++; continue; }
    const m = jpeg[i + 1];
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
    const len = jpeg.readUInt16BE(i + 2);
    // SOF0 … SOF15 without DHT (C4), JPG (C8), DAC (CC)
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return jpeg[i + 9];
    if (m === 0xda) break;
    i += 2 + len;
  }
  return 3;
}

/** The text of the pages for the search (Drive's doc_text): the lines, a blank line between pages. */
function pagesText(pages) {
  return (Array.isArray(pages) ? pages : []).map((p) => (Array.isArray(p.lines) ? p.lines : []).map((l) => (l && typeof l.text === 'string' ? l.text : ((l && l.words) || []).map((w) => w.text).join(' '))).filter(Boolean).join('\n')).filter(Boolean).join('\n\n');
}

module.exports = { buildSearchablePdf, pagesText, winAnsi, pageGeometry, jpegComponents };
