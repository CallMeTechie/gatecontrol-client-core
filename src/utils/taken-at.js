'use strict';

/**
 * When a photo or video was taken (Drive 1.7 'takenAt'): read from the file
 * itself, without dependencies, and sent with `uploads/commit` (the page
 * "Drive" and "Ordner sichern").
 *
 * - JPEG (APP1 "Exif"), TIFF and the raw formats built on it (DNG, CR2, NEF,
 *   ARW, ORF, RW2), HEIC / HEIF / AVIF (the item "Exif" of the box `meta`),
 *   WebP (chunk "EXIF") and PNG (chunk "eXIf"): EXIF DateTimeOriginal with
 *   OffsetTimeOriginal, else DateTime with OffsetTime. Without an offset the
 *   time counts as local time of this PC (the plugin's README).
 * - MP4 / MOV / 3GP (videos): `mvhd` creation_time of the box `moov`
 *   (UTC, seconds since 1904); 0 is "unknown".
 *
 * Only a few small reads per file (at most ~1 MB is looked at); anything
 * unexpected gives null, then the server takes the file's mtime itself.
 * A time before 1900 or more than a day ahead is dropped as well.
 */

const fs = require('fs');

const MAX_SCAN = 1024 * 1024;        // JPEG markers / boxes / chunks looked at, from the start
const MAX_IFD_ENTRIES = 1000;
const MAX_BOXES = 4096;
const DAY = 24 * 60 * 60 * 1000;
const MAC_EPOCH = Date.UTC(1904, 0, 1);

const EXT_RE = /\.(jpe?g|jpe|jfif|tiff?|dng|cr2|nef|nrw|arw|orf|rw2|pef|srw|heic|heif|hif|avif|webp|png|mp4|m4v|mov|qt|3gp|3g2)$/i;

/** Is `name` a picture / video whose date we look for? */
function isMediaName(name) {
  return typeof name === 'string' && EXT_RE.test(name);
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

/** A local time → "2026-07-14T18:03:22+02:00" (the offset of this PC at that time). */
function isoLocal(d) {
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const a = Math.abs(off);
  return `${pad(d.getFullYear(), 4)}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}

/** Is `ms` a plausible time of a photo (1900 … now + 1 day)? */
function plausible(ms, now = Date.now()) {
  return Number.isFinite(ms) && ms >= Date.UTC(1900, 0, 1) && ms <= now + DAY;
}

/**
 * EXIF "2026:07:14 18:03:22" (+ "+02:00") → { iso, ms } or null.
 * Without an offset the time is local time of this PC.
 */
function parseExifDate(raw, offset = null, { now = Date.now() } = {}) {
  if (typeof raw !== 'string') return null;
  const m = /^\s*(\d{4})[:\-](\d{2})[:\-](\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(raw);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] || '0'].map(Number);
  if (y < 1900 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return null;
  const off = typeof offset === 'string' ? /^\s*([+-])(\d{2}):?(\d{2})\s*$/.exec(offset) : null;
  let ms;
  let iso;
  if (off && Number(off[2]) <= 14 && Number(off[3]) < 60) {
    const mins = (Number(off[2]) * 60 + Number(off[3])) * (off[1] === '-' ? -1 : 1);
    ms = Date.UTC(y, mo - 1, d, h, mi, Math.min(s, 59)) - mins * 60000;
    iso = `${pad(y, 4)}-${pad(mo)}-${pad(d)}T${pad(h)}:${pad(mi)}:${pad(Math.min(s, 59))}${off[1]}${off[2]}:${off[3]}`;
  } else {
    const local = new Date(y, mo - 1, d, h, mi, Math.min(s, 59));
    if (local.getMonth() !== mo - 1) return null; // 31.02. and the like
    ms = local.getTime();
    iso = isoLocal(local);
  }
  return plausible(ms, now) ? { iso, ms } : null;
}

// ── Random access ─────────────────────────────────────────

/** A source to read from: { size, read(pos, len) → Buffer (shorter at the end) }. */
async function fileSource(file) {
  const fh = await fs.promises.open(file, 'r');
  const st = await fh.stat();
  return {
    size: st.size,
    async read(pos, len) {
      if (pos < 0 || pos >= st.size || len <= 0) return Buffer.alloc(0);
      const n = Math.min(len, st.size - pos);
      const buf = Buffer.alloc(n);
      const { bytesRead } = await fh.read(buf, 0, n, pos);
      return buf.subarray(0, bytesRead);
    },
    close: () => fh.close(),
  };
}

/** A Buffer as a source (tests). */
function bufferSource(buf) {
  return { size: buf.length, async read(pos, len) { return pos < 0 ? Buffer.alloc(0) : buf.subarray(pos, Math.min(buf.length, pos + len)); }, close: async () => {} };
}

// ── TIFF / EXIF ───────────────────────────────────────────

const TAG = { exifIfd: 0x8769, dateTime: 0x0132, original: 0x9003, offsetTime: 0x9010, offsetOriginal: 0x9011 };

/** The tags of one IFD at `base + off` → Map tag → string (ASCII tags) / number (LONG pointers). */
async function readIfd(src, base, off, le) {
  const head = await src.read(base + off, 2);
  if (head.length < 2) return null;
  const n = le ? head.readUInt16LE(0) : head.readUInt16BE(0);
  if (!n || n > MAX_IFD_ENTRIES) return null;
  const buf = await src.read(base + off + 2, n * 12);
  if (buf.length < n * 12) return null;
  const u16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const out = new Map();
  for (let i = 0; i < n; i++) {
    const e = i * 12;
    const tag = u16(e);
    if (![TAG.exifIfd, TAG.dateTime, TAG.original, TAG.offsetTime, TAG.offsetOriginal].includes(tag)) continue;
    const type = u16(e + 2);
    const count = u32(e + 4);
    if (tag === TAG.exifIfd && (type === 4 || type === 13)) { out.set(tag, u32(e + 8)); continue; }
    if (type !== 2 || !count || count > 64) continue;
    const raw = count <= 4 ? buf.subarray(e + 8, e + 8 + count) : await src.read(base + u32(e + 8), count);
    out.set(tag, raw.toString('latin1').replace(/\0.*$/s, ''));
  }
  return out;
}

/** The date of a TIFF structure starting at `base` → { iso, ms } or null. */
async function tiffDate(src, base, opts = {}) {
  const h = await src.read(base, 8);
  if (h.length < 8) return null;
  const order = h.toString('latin1', 0, 2);
  if (order !== 'II' && order !== 'MM') return null;
  const le = order === 'II';
  const magic = le ? h.readUInt16LE(2) : h.readUInt16BE(2);
  // 42: TIFF; 0x4F52 / 0x5352: Olympus ORF; 0x55: Panasonic RW2; 43: BigTIFF is not read
  if (![42, 0x4f52, 0x5352, 0x55].includes(magic)) return null;
  const ifd0 = le ? h.readUInt32LE(4) : h.readUInt32BE(4);
  const t0 = await readIfd(src, base, ifd0, le);
  if (!t0) return null;
  let tx = null;
  if (t0.has(TAG.exifIfd)) tx = await readIfd(src, base, t0.get(TAG.exifIfd), le).catch(() => null);
  if (tx && tx.has(TAG.original)) {
    const r = parseExifDate(tx.get(TAG.original), tx.get(TAG.offsetOriginal) || null, opts);
    if (r) return r;
  }
  const dt = (tx && tx.get(TAG.dateTime)) || t0.get(TAG.dateTime);
  return dt ? parseExifDate(dt, (tx && tx.get(TAG.offsetTime)) || null, opts) : null;
}

/** EXIF data that may start with "Exif\0\0" → the TIFF's start. */
async function exifBase(src, pos) {
  const h = await src.read(pos, 6);
  return h.length === 6 && h.toString('latin1', 0, 4) === 'Exif' ? pos + 6 : pos;
}

// ── JPEG ──────────────────────────────────────────────────

async function jpegDate(src, opts) {
  let pos = 2;
  while (pos + 4 <= Math.min(src.size, MAX_SCAN)) {
    const m = await src.read(pos, 4);
    if (m.length < 4 || m[0] !== 0xff) return null;
    const marker = m[1];
    if (marker === 0xff) { pos++; continue; }
    if (marker === 0xda || marker === 0xd9) return null; // image data: no EXIF before it
    const len = m.readUInt16BE(2);
    if (len < 2) return null;
    if (marker === 0xe1) {
      const id = await src.read(pos + 4, 6);
      if (id.toString('latin1', 0, 4) === 'Exif') {
        const r = await tiffDate(src, pos + 10, opts);
        if (r) return r;
      }
    }
    pos += 2 + len;
  }
  return null;
}

// ── ISO-BMFF (HEIC / AVIF / MP4 / MOV) ────────────────────

/** The boxes in [start, end) → [{ type, start (of the content), end }] */
async function boxes(src, start, end) {
  const out = [];
  let pos = start;
  while (pos + 8 <= end && out.length < MAX_BOXES) {
    const h = await src.read(pos, 16);
    if (h.length < 8) break;
    let size = h.readUInt32BE(0);
    const type = h.toString('latin1', 4, 8);
    let head = 8;
    if (size === 1) {
      if (h.length < 16) break;
      size = Number(h.readBigUInt64BE(8));
      head = 16;
    } else if (size === 0) {
      size = end - pos;
    }
    if (size < head) break;
    // a box running past its parent: take what is there (the last box of a file cut short)
    if (size > end - pos) size = end - pos;
    out.push({ type, start: pos + head, end: pos + size });
    pos += size;
  }
  return out;
}

const uintN = (buf, o, n) => (n === 0 ? 0 : n === 2 ? buf.readUInt16BE(o) : n === 4 ? buf.readUInt32BE(o) : n === 8 ? Number(buf.readBigUInt64BE(o)) : NaN);

/** HEIF: the item "Exif" (iinf) and where it is (iloc) → { iso, ms } or null. */
async function heifDate(src, top, opts) {
  const meta = top.find((b) => b.type === 'meta');
  if (!meta || meta.end - meta.start > MAX_SCAN) return null;
  const kids = await boxes(src, meta.start + 4, meta.end); // `meta` is a full box
  const iinf = kids.find((b) => b.type === 'iinf');
  const iloc = kids.find((b) => b.type === 'iloc');
  if (!iinf || !iloc) return null;
  // iinf: the id of the item of type "Exif"
  const ib = await src.read(iinf.start, iinf.end - iinf.start);
  const iv = ib[0];
  const infes = await boxes(src, iinf.start + 4 + (iv === 0 ? 2 : 4), iinf.end);
  let exifId = null;
  for (const b of infes) {
    if (b.type !== 'infe') continue;
    const e = await src.read(b.start, 16);
    const v = e[0];
    if (v < 2) continue;
    const id = v === 2 ? e.readUInt16BE(4) : e.readUInt32BE(4);
    const typeAt = v === 2 ? 8 : 10;
    if (e.toString('latin1', typeAt, typeAt + 4) === 'Exif') { exifId = id; break; }
  }
  if (exifId === null) return null;
  // iloc: where the item lies
  const lb = await src.read(iloc.start, iloc.end - iloc.start);
  const v = lb[0];
  let o = 4;
  const offSize = lb[o] >> 4;
  const lenSize = lb[o] & 15;
  const baseSize = lb[o + 1] >> 4;
  const idxSize = v === 1 || v === 2 ? lb[o + 1] & 15 : 0;
  o += 2;
  const count = v < 2 ? lb.readUInt16BE(o) : lb.readUInt32BE(o);
  o += v < 2 ? 2 : 4;
  for (let i = 0; i < count && o < lb.length; i++) {
    const id = v < 2 ? lb.readUInt16BE(o) : lb.readUInt32BE(o);
    o += v < 2 ? 2 : 4;
    let method = 0;
    if (v === 1 || v === 2) { method = lb.readUInt16BE(o) & 15; o += 2; }
    o += 2; // data_reference_index
    const baseOff = uintN(lb, o, baseSize);
    o += baseSize;
    const extents = lb.readUInt16BE(o);
    o += 2;
    let first = null;
    for (let x = 0; x < extents; x++) {
      o += idxSize;
      const eo = uintN(lb, o, offSize);
      o += offSize;
      const el = uintN(lb, o, lenSize);
      o += lenSize;
      if (first === null) first = { off: eo, len: el };
    }
    if (id !== exifId) continue;
    if (method !== 0 || !first) return null; // in `idat` or elsewhere: not read
    const at = baseOff + first.off;
    // the item: a 4-byte offset to the TIFF header, then (often) "Exif\0\0", then the TIFF
    const h = await src.read(at, 4);
    if (h.length < 4) return null;
    const skip = h.readUInt32BE(0);
    if (skip > 64) return null;
    return tiffDate(src, await exifBase(src, at + 4 + skip), opts);
  }
  return null;
}

/** MP4 / MOV: moov › mvhd creation_time (UTC since 1904) → { iso, ms } or null. */
async function movieDate(src, top, opts) {
  const moov = top.find((b) => b.type === 'moov');
  if (!moov) return null;
  const kids = await boxes(src, moov.start, Math.min(moov.end, moov.start + MAX_SCAN));
  const mvhd = kids.find((b) => b.type === 'mvhd');
  if (!mvhd) return null;
  const h = await src.read(mvhd.start, 12);
  if (h.length < 8) return null;
  const secs = h[0] === 1 ? (h.length >= 12 ? Number(h.readBigUInt64BE(4)) : 0) : h.readUInt32BE(4);
  if (!secs) return null;
  const ms = MAC_EPOCH + secs * 1000;
  if (!plausible(ms, opts.now) || ms < Date.UTC(1971, 0, 1)) return null;
  return { iso: new Date(ms).toISOString(), ms };
}

async function bmffDate(src, opts) {
  // the top-level boxes may lie anywhere (moov after a large mdat): only their heads are read
  const top = await boxes(src, 0, src.size);
  const ftyp = top.find((b) => b.type === 'ftyp');
  if (!ftyp) return null;
  if (top.some((b) => b.type === 'meta')) {
    const r = await heifDate(src, top, opts).catch(() => null);
    if (r) return r;
  }
  return movieDate(src, top, opts);
}

// ── RIFF (WebP) / PNG ─────────────────────────────────────

async function webpDate(src, opts) {
  let pos = 12;
  for (let i = 0; i < 64 && pos + 8 <= Math.min(src.size, MAX_SCAN * 16); i++) {
    const h = await src.read(pos, 8);
    if (h.length < 8) return null;
    const type = h.toString('latin1', 0, 4);
    const len = h.readUInt32LE(4);
    if (type === 'EXIF') return tiffDate(src, await exifBase(src, pos + 8), opts);
    pos += 8 + len + (len & 1);
  }
  return null;
}

async function pngDate(src, opts) {
  let pos = 8;
  for (let i = 0; i < 256 && pos + 8 <= src.size; i++) {
    const h = await src.read(pos, 8);
    if (h.length < 8) return null;
    const len = h.readUInt32BE(0);
    const type = h.toString('latin1', 4, 8);
    if (type === 'eXIf') return tiffDate(src, await exifBase(src, pos + 8), opts);
    if (type === 'IDAT' || type === 'IEND') return null;
    pos += 12 + len;
  }
  return null;
}

/** The date of a source (format by its first bytes) → { iso, ms } or null. */
async function takenAtOf(src, opts = {}) {
  const o = { now: Number.isFinite(opts.now) ? opts.now : Date.now() };
  const h = await src.read(0, 16);
  if (h.length < 12) return null;
  if (h[0] === 0xff && h[1] === 0xd8) return jpegDate(src, o);
  const two = h.toString('latin1', 0, 2);
  if (two === 'II' || two === 'MM') return tiffDate(src, 0, o);
  if (h.toString('latin1', 4, 8) === 'ftyp') return bmffDate(src, o);
  if (h.toString('latin1', 0, 4) === 'RIFF' && h.toString('latin1', 8, 12) === 'WEBP') return webpDate(src, o);
  if (h.readUInt32BE(0) === 0x89504e47) return pngDate(src, o);
  return null;
}

/**
 * When the photo / video `file` was taken → ISO string (with the offset) or null.
 * Never throws; only files named like pictures / videos are opened.
 */
async function takenAt(file, { name = null, now } = {}) {
  if (!isMediaName(name || file)) return null;
  let src = null;
  try {
    src = await fileSource(file);
    const r = await takenAtOf(src, { now });
    return r ? r.iso : null;
  } catch {
    return null;
  } finally {
    if (src) await src.close().catch(() => {});
  }
}

module.exports = { takenAt, takenAtOf, isMediaName, parseExifDate, bufferSource, plausible };
