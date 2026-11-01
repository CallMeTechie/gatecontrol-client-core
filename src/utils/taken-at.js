'use strict';

/**
 * When a photo or video was taken (Drive 1.7 'takenAt') and where (Drive 1.16
 * 'photoPlaces': the GPS position): read from the file itself, without
 * dependencies, and sent with `uploads/commit` (the page "Drive" and "Ordner
 * sichern").
 *
 * - JPEG (APP1 "Exif"), TIFF and the raw formats built on it (DNG, CR2, NEF,
 *   ARW, ORF, RW2), HEIC / HEIF / AVIF (the item "Exif" of the box `meta`),
 *   WebP (chunk "EXIF") and PNG (chunk "eXIf"): EXIF DateTimeOriginal with
 *   OffsetTimeOriginal, else DateTime with OffsetTime. Without an offset the
 *   time counts as local time of this PC (the plugin's README).
 * - MP4 / MOV / 3GP (videos): `mvhd` creation_time of the box `moov`
 *   (UTC, seconds since 1904); 0 is "unknown".
 * - Where: the GPS IFD of the same EXIF (GPSLatitude / GPSLongitude with
 *   their refs, WGS84), for videos `moov › udta › ©xyz` (ISO 6709, what
 *   phones write). 0/0 and anything out of range count as "no position".
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

const TAG = { exifIfd: 0x8769, gpsIfd: 0x8825, dateTime: 0x0132, original: 0x9003, offsetTime: 0x9010, offsetOriginal: 0x9011 };
const MAIN_TAGS = [TAG.exifIfd, TAG.gpsIfd, TAG.dateTime, TAG.original, TAG.offsetTime, TAG.offsetOriginal];
// GPS IFD: GPSLatitudeRef (N/S), GPSLatitude (3 RATIONAL), GPSLongitudeRef (E/W), GPSLongitude
const GPS = { latRef: 0x0001, lat: 0x0002, lonRef: 0x0003, lon: 0x0004 };
const GPS_TAGS = [GPS.latRef, GPS.lat, GPS.lonRef, GPS.lon];

/** A position → { lat, lon } (6 decimals) or null: out of range, not a number, or 0/0 (no fix). */
function geoOf(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  if (lat === 0 && lon === 0) return null;
  const r = (v) => Math.round(v * 1e6) / 1e6;
  return { lat: r(lat), lon: r(lon) };
}

/** Degrees, minutes, seconds (EXIF RATIONALs) and a ref ('S' / 'W': negative) → degrees or NaN. */
function dms(parts, ref) {
  if (!Array.isArray(parts) || parts.length < 1 || parts.some((v) => !Number.isFinite(v) || v < 0)) return NaN;
  const [d, m = 0, s = 0] = parts;
  if (m >= 60 || s >= 60) return NaN;
  const v = d + m / 60 + s / 3600;
  return ref === 'S' || ref === 'W' ? -v : v;
}

/**
 * The tags of one IFD at `base + off` (only those in `want`) → Map tag → string (ASCII tags) / number (LONG pointers)
 * / [numbers] (RATIONALs).
 */
async function readIfd(src, base, off, le, want = MAIN_TAGS) {
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
    if (!want.includes(tag)) continue;
    const type = u16(e + 2);
    const count = u32(e + 4);
    if ((tag === TAG.exifIfd || tag === TAG.gpsIfd) && (type === 4 || type === 13)) { out.set(tag, u32(e + 8)); continue; }
    if (type === 5 && count >= 1 && count <= 4) {
      // RATIONAL: numerator / denominator (2 × LONG), always at an offset
      const raw = await src.read(base + u32(e + 8), count * 8);
      if (raw.length < count * 8) continue;
      const vals = [];
      for (let k = 0; k < count; k++) {
        const num = le ? raw.readUInt32LE(k * 8) : raw.readUInt32BE(k * 8);
        const den = le ? raw.readUInt32LE(k * 8 + 4) : raw.readUInt32BE(k * 8 + 4);
        vals.push(den ? num / den : NaN);
      }
      out.set(tag, vals);
      continue;
    }
    if (type !== 2 || !count || count > 64) continue;
    const raw = count <= 4 ? buf.subarray(e + 8, e + 8 + count) : await src.read(base + u32(e + 8), count);
    out.set(tag, raw.toString('latin1').replace(/\0.*$/s, ''));
  }
  return out;
}

/** The GPS IFD at `off` → { lat, lon } or null. */
async function gpsOf(src, base, off, le) {
  const g = await readIfd(src, base, off, le, GPS_TAGS);
  if (!g || !g.has(GPS.lat) || !g.has(GPS.lon)) return null;
  const ref = (t) => String(g.get(t) || '').trim().toUpperCase().slice(0, 1);
  return geoOf(dms(g.get(GPS.lat), ref(GPS.latRef)), dms(g.get(GPS.lon), ref(GPS.lonRef)));
}

/** Date and position of a TIFF structure starting at `base` → { date: { iso, ms } | null, geo: { lat, lon } | null } or null. */
async function tiffMeta(src, base, opts = {}) {
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
  const geo = opts.geo !== false && t0.has(TAG.gpsIfd) ? await gpsOf(src, base, t0.get(TAG.gpsIfd), le).catch(() => null) : null;
  let date = null;
  if (tx && tx.has(TAG.original)) date = parseExifDate(tx.get(TAG.original), tx.get(TAG.offsetOriginal) || null, opts);
  if (!date) {
    const dt = (tx && tx.get(TAG.dateTime)) || t0.get(TAG.dateTime);
    date = dt ? parseExifDate(dt, (tx && tx.get(TAG.offsetTime)) || null, opts) : null;
  }
  return { date, geo };
}

/** EXIF data that may start with "Exif\0\0" → the TIFF's start. */
async function exifBase(src, pos) {
  const h = await src.read(pos, 6);
  return h.length === 6 && h.toString('latin1', 0, 4) === 'Exif' ? pos + 6 : pos;
}

// ── JPEG ──────────────────────────────────────────────────

async function jpegMeta(src, opts) {
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
        const r = await tiffMeta(src, pos + 10, opts);
        if (r && (r.date || r.geo)) return r;
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

/** HEIF: the item "Exif" (iinf) and where it is (iloc) → { date, geo } or null. */
async function heifMeta(src, top, opts) {
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
    return tiffMeta(src, await exifBase(src, at + 4 + skip), opts);
  }
  return null;
}

/** ISO 6709 "+52.5200+013.4050+034.000/" (©xyz of a video) → { lat, lon } or null. */
function iso6709(s) {
  const m = /^\s*([+-]\d{1,2}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)/.exec(String(s || ''));
  return m ? geoOf(Number(m[1]), Number(m[2])) : null;
}

/** MP4 / MOV: moov › mvhd creation_time (UTC since 1904), moov › udta › ©xyz (the position) → { date, geo } or null. */
async function movieMeta(src, top, opts) {
  const moov = top.find((b) => b.type === 'moov');
  if (!moov) return null;
  const kids = await boxes(src, moov.start, Math.min(moov.end, moov.start + MAX_SCAN));
  let geo = null;
  const udta = kids.find((b) => b.type === 'udta');
  if (opts.geo !== false && udta) {
    const xyz = (await boxes(src, udta.start, Math.min(udta.end, udta.start + 64 * 1024))).find((b) => b.type === '\u00a9xyz');
    if (xyz && xyz.end - xyz.start <= 256) {
      const b = await src.read(xyz.start, xyz.end - xyz.start);
      // a 16-bit length and a 16-bit language, then the text
      const len = b.length >= 4 ? b.readUInt16BE(0) : 0;
      geo = iso6709(b.toString('latin1', 4, 4 + Math.min(len, b.length - 4)));
    }
  }
  let date = null;
  const mvhd = kids.find((b) => b.type === 'mvhd');
  const h = mvhd ? await src.read(mvhd.start, 12) : Buffer.alloc(0);
  if (h.length >= 8) {
    const secs = h[0] === 1 ? (h.length >= 12 ? Number(h.readBigUInt64BE(4)) : 0) : h.readUInt32BE(4);
    const ms = MAC_EPOCH + secs * 1000;
    if (secs && plausible(ms, opts.now) && ms >= Date.UTC(1971, 0, 1)) date = { iso: new Date(ms).toISOString(), ms };
  }
  return date || geo ? { date, geo } : null;
}

async function bmffMeta(src, opts) {
  // the top-level boxes may lie anywhere (moov after a large mdat): only their heads are read
  const top = await boxes(src, 0, src.size);
  const ftyp = top.find((b) => b.type === 'ftyp');
  if (!ftyp) return null;
  if (top.some((b) => b.type === 'meta')) {
    const r = await heifMeta(src, top, opts).catch(() => null);
    if (r && (r.date || r.geo)) return r;
  }
  return movieMeta(src, top, opts);
}

// ── RIFF (WebP) / PNG ─────────────────────────────────────

async function webpMeta(src, opts) {
  let pos = 12;
  for (let i = 0; i < 64 && pos + 8 <= Math.min(src.size, MAX_SCAN * 16); i++) {
    const h = await src.read(pos, 8);
    if (h.length < 8) return null;
    const type = h.toString('latin1', 0, 4);
    const len = h.readUInt32LE(4);
    if (type === 'EXIF') return tiffMeta(src, await exifBase(src, pos + 8), opts);
    pos += 8 + len + (len & 1);
  }
  return null;
}

async function pngMeta(src, opts) {
  let pos = 8;
  for (let i = 0; i < 256 && pos + 8 <= src.size; i++) {
    const h = await src.read(pos, 8);
    if (h.length < 8) return null;
    const len = h.readUInt32BE(0);
    const type = h.toString('latin1', 4, 8);
    if (type === 'eXIf') return tiffMeta(src, await exifBase(src, pos + 8), opts);
    if (type === 'IDAT' || type === 'IEND') return null;
    pos += 12 + len;
  }
  return null;
}

/** Date and position of a source (format by its first bytes) → { date: { iso, ms } | null, geo: { lat, lon } | null }. */
async function shotOf(src, opts = {}) {
  const o = { now: Number.isFinite(opts.now) ? opts.now : Date.now(), geo: opts.geo !== false };
  const h = await src.read(0, 16);
  let r = null;
  if (h.length < 12) r = null;
  else if (h[0] === 0xff && h[1] === 0xd8) r = await jpegMeta(src, o);
  else if (h.toString('latin1', 0, 2) === 'II' || h.toString('latin1', 0, 2) === 'MM') r = await tiffMeta(src, 0, o);
  else if (h.toString('latin1', 4, 8) === 'ftyp') r = await bmffMeta(src, o);
  else if (h.toString('latin1', 0, 4) === 'RIFF' && h.toString('latin1', 8, 12) === 'WEBP') r = await webpMeta(src, o);
  else if (h.readUInt32BE(0) === 0x89504e47) r = await pngMeta(src, o);
  return { date: (r && r.date) || null, geo: (r && r.geo) || null };
}

/** The date of a source (format by its first bytes) → { iso, ms } or null. */
async function takenAtOf(src, opts = {}) {
  return (await shotOf(src, { ...opts, geo: false })).date;
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

/**
 * When and where the photo / video `file` was taken (one read for both) → { takenAt: ISO string | null,
 * geo: { lat, lon } | null }. `geo: false` leaves the position out. Never throws; only pictures / videos are opened.
 */
async function shot(file, { name = null, now, geo = true } = {}) {
  const none = { takenAt: null, geo: null };
  if (!isMediaName(name || file)) return none;
  let src = null;
  try {
    src = await fileSource(file);
    const r = await shotOf(src, { now, geo });
    return { takenAt: r.date ? r.date.iso : null, geo: geo ? r.geo : null };
  } catch {
    return none;
  } finally {
    if (src) await src.close().catch(() => {});
  }
}

module.exports = { takenAt, takenAtOf, shot, shotOf, geoOf, iso6709, isMediaName, parseExifDate, bufferSource, plausible };
