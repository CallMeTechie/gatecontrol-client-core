'use strict';

// Pictures and videos built byte by byte for utils/taken-at.js (Drive 1.7 'takenAt'):
// a TIFF with EXIF dates, and that TIFF inside a JPEG, a HEIC, a WebP and a PNG; an MP4.

/** A TIFF (little / big endian): IFD0 { DateTime?, ExifIFD } → Exif IFD { DateTimeOriginal?, OffsetTimeOriginal? } */
function tiff({ le = true, original = '2026:07:14 18:03:22', offset = '+02:00', dateTime = '2026:07:20 09:00:00' } = {}) {
  const parts = [];
  const u16 = (v) => { const b = Buffer.alloc(2); if (le) b.writeUInt16LE(v); else b.writeUInt16BE(v); return b; };
  const u32 = (v) => { const b = Buffer.alloc(4); if (le) b.writeUInt32LE(v); else b.writeUInt32BE(v); return b; };
  const ascii = (s) => Buffer.from(`${s}\0`, 'latin1');
  // layout: header 8 | IFD0 at 8 | its strings | Exif IFD | its strings
  const ifd0Tags = [];
  const exifTags = [];
  if (dateTime) ifd0Tags.push({ tag: 0x0132, data: ascii(dateTime) });
  if (original) exifTags.push({ tag: 0x9003, data: ascii(original) });
  if (offset) exifTags.push({ tag: 0x9011, data: ascii(offset) });
  const ifdSize = (n) => 2 + n * 12 + 4;
  const ifd0At = 8;
  const ifd0Len = ifdSize(ifd0Tags.length + 1);
  let dataAt = ifd0At + ifd0Len;
  const ifd0Data = [];
  for (const t of ifd0Tags) { t.at = dataAt; dataAt += t.data.length; ifd0Data.push(t.data); }
  const exifAt = dataAt;
  let exifDataAt = exifAt + ifdSize(exifTags.length);
  const exifData = [];
  for (const t of exifTags) { t.at = exifDataAt; exifDataAt += t.data.length; exifData.push(t.data); }
  const entry = (tag, type, count, value) => Buffer.concat([u16(tag), u16(type), u32(count), value]);
  const strEntry = (t) => entry(t.tag, 2, t.data.length, t.data.length <= 4 ? Buffer.concat([t.data, Buffer.alloc(4 - t.data.length)]) : u32(t.at));
  parts.push(Buffer.from(le ? 'II' : 'MM', 'latin1'), u16(42), u32(ifd0At));
  parts.push(u16(ifd0Tags.length + 1), ...ifd0Tags.map(strEntry), entry(0x8769, 4, 1, u32(exifAt)), u32(0), ...ifd0Data);
  parts.push(u16(exifTags.length), ...exifTags.map(strEntry), u32(0), ...exifData);
  return Buffer.concat(parts);
}

function jpeg(t) {
  const app1 = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), t]);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(app1.length + 2);
  // SOI, APP0 (JFIF) first like most cameras, then APP1, then SOS
  const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0, 0, 1, 0, 1, 0, 0]);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app0, Buffer.from([0xff, 0xe1]), len, app1, Buffer.from([0xff, 0xda, 0x00, 0x02, 0x11, 0x22, 0xff, 0xd9])]);
}

const box = (type, ...content) => {
  const body = Buffer.concat(content);
  const h = Buffer.alloc(8);
  h.writeUInt32BE(body.length + 8);
  h.write(type, 4, 'latin1');
  return Buffer.concat([h, body]);
};
const full = (v, flags = 0) => { const b = Buffer.alloc(4); b.writeUInt32BE((v << 24) | flags); return b; };
const be16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
const be32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };

/** A HEIC: ftyp, meta { hdlr, iinf { infe hvc1 #1, infe Exif #2 }, iloc (v1) }, mdat with the Exif item. */
function heic(t) {
  const item = Buffer.concat([be32(6), Buffer.from('Exif\0\0', 'latin1'), t]);
  const infe = (id, type) => box('infe', full(2), be16(id), be16(0), Buffer.from(type, 'latin1'), Buffer.from('\0'));
  const iinf = box('iinf', full(0), be16(2), infe(1, 'hvc1'), infe(2, 'Exif'));
  const ftyp = box('ftyp', Buffer.from('heic', 'latin1'), be32(0), Buffer.from('mif1heic', 'latin1'));
  const build = (exifAt) => {
    // iloc v1: offset_size 4, length_size 4, base_offset_size 0, index_size 0
    const iloc = box('iloc', full(1), Buffer.from([0x44, 0x00]), be16(2),
      be16(1), be16(0), be16(0), be16(1), be32(0), be32(10),
      be16(2), be16(0), be16(0), be16(1), be32(exifAt), be32(item.length));
    const meta = box('meta', full(0), box('hdlr', full(0), be32(0), Buffer.from('pict', 'latin1'), Buffer.alloc(13)), iinf, iloc);
    return Buffer.concat([ftyp, meta]);
  };
  const head = build(0);
  const mdatAt = head.length;
  const file = Buffer.concat([build(mdatAt + 8 + 10), box('mdat', Buffer.alloc(10), item)]);
  return file;
}

/** An MP4 with `moov` after a large `mdat` (not "fast start"). */
function mp4(secsSince1904, version = 0) {
  const ftyp = box('ftyp', Buffer.from('isom', 'latin1'), be32(512), Buffer.from('isomiso2mp41', 'latin1'));
  const mdat = box('mdat', Buffer.alloc(200000));
  let times;
  if (version === 1) {
    const b = Buffer.alloc(16);
    b.writeBigUInt64BE(BigInt(secsSince1904), 0);
    b.writeBigUInt64BE(BigInt(secsSince1904), 8);
    times = b;
  } else times = Buffer.concat([be32(secsSince1904), be32(secsSince1904)]);
  const mvhd = box('mvhd', full(version), times, Buffer.alloc(80));
  return Buffer.concat([ftyp, mdat, box('moov', mvhd, box('trak', Buffer.alloc(16)))]);
}

function webp(t) {
  const chunk = (type, data) => { const h = Buffer.alloc(8); h.write(type, 0, 'latin1'); h.writeUInt32LE(data.length, 4); return Buffer.concat([h, data, data.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0)]); };
  const body = Buffer.concat([Buffer.from('WEBP', 'latin1'), chunk('VP8X', Buffer.alloc(10)), chunk('VP8 ', Buffer.alloc(31)), chunk('EXIF', t)]);
  const h = Buffer.alloc(8);
  h.write('RIFF', 0, 'latin1');
  h.writeUInt32LE(body.length, 4);
  return Buffer.concat([h, body]);
}

function png(t) {
  const chunk = (type, data) => Buffer.concat([be32(data.length), Buffer.from(type, 'latin1'), data, be32(0)]);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', Buffer.alloc(13)), chunk('eXIf', t), chunk('IDAT', Buffer.alloc(5)), chunk('IEND', Buffer.alloc(0))]);
}

module.exports = { tiff, jpeg, heic, mp4, webp, png };
