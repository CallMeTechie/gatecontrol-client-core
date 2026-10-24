'use strict';

/**
 * Pure helpers of "2FA from a QR code" (Vault entry editor, IPC vault:totp-qr):
 *
 *   - images (RGBA or BGRA bitmaps: Electron's nativeImage.toBitmap() is BGRA
 *     on Windows) → the texts of the QR codes in them (jsQR, Apache-2.0, pure
 *     JS). jsQR finds one code per pass; a found code is painted white and the
 *     image searched again, so a screen with several codes yields all of them.
 *     A large image (a 4K screen, ≥ 2000 px wide) is searched at half size
 *     first (~0.4 s instead of ~1.8 s for a 4K screen; also light-on-dark
 *     codes), then at full size (small codes); a smaller one at full size
 *     (normal and inverted). When nothing is found, four overlapping tiles
 *     (60 % × 60 %) are searched: jsQR combines the finder patterns of two
 *     codes of the same size into one and then reads neither;
 *   - texts → `otpauth://totp/…` URIs the vault's own parser (utils/vault.js
 *     parseTotp) accepts. `otpauth://hotp/…` is counted, not returned (Vault
 *     makes time-based codes only). `otpauth-migration://offline?data=…`
 *     (Google Authenticator's export: a protobuf MigrationPayload) becomes one
 *     otpauth://totp URI per TOTP account in it.
 *
 * Nothing here logs; the URIs carry secrets.
 */

const vault = require('./vault');

const MAX_CODES_PER_IMAGE = 4;
const HALF_FIRST_MIN_WIDTH = 2000;     // from here the half size image is searched first
const TILE = 0.6;                      // tiles: 60 % of width and height, at 0 and 40 %
const MAX_PIXELS = 50 * 1000 * 1000;   // larger bitmaps are refused (callers scale them first)
const MAX_TEXT = 8192;                 // a QR code holds at most ~3 KB; anything longer is not ours
const MAX_MIGRATION_ACCOUNTS = 100;

let jsQRImpl = null;
function jsQR() {
  if (!jsQRImpl) jsQRImpl = require('jsqr');
  return jsQRImpl;
}

// ── Bitmaps ──────────────────────────────────────────────────────

/** BGRA → RGBA in place (swaps bytes 0 and 2 of every pixel). */
function bgraToRgba(px) {
  for (let i = 0; i + 3 < px.length; i += 4) {
    const b = px[i];
    px[i] = px[i + 2];
    px[i + 2] = b;
  }
  return px;
}

/** RGBA → half size (2×2 box filter) → { data, width, height }. */
function halfSize(data, width, height) {
  const w = width >> 1;
  const h = height >> 1;
  const out = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) {
    const r0 = (2 * y) * width * 4;
    const r1 = r0 + width * 4;
    for (let x = 0; x < w; x++) {
      const a = r0 + 8 * x;
      const b = r1 + 8 * x;
      const o = (y * w + x) * 4;
      for (let c = 0; c < 4; c++) out[o + c] = (data[a + c] + data[a + 4 + c] + data[b + c] + data[b + 4 + c] + 2) >> 2;
    }
  }
  return { data: out, width: w, height: h };
}

/** Paints the bounding box of a found code (plus a margin) white, so the next pass finds the next code. */
function blank(data, width, height, loc) {
  const pts = [loc.topLeftCorner, loc.topRightCorner, loc.bottomLeftCorner, loc.bottomRightCorner];
  let x0 = Math.min(...pts.map((p) => p.x));
  let x1 = Math.max(...pts.map((p) => p.x));
  let y0 = Math.min(...pts.map((p) => p.y));
  let y1 = Math.max(...pts.map((p) => p.y));
  const m = Math.max(4, Math.round(Math.max(x1 - x0, y1 - y0) * 0.1));
  x0 = Math.max(0, Math.floor(x0 - m)); x1 = Math.min(width - 1, Math.ceil(x1 + m));
  y0 = Math.max(0, Math.floor(y0 - m)); y1 = Math.min(height - 1, Math.ceil(y1 + m));
  for (let y = y0; y <= y1; y++) data.fill(255, (y * width + x0) * 4, (y * width + x1 + 1) * 4);
}

/** Every code jsQR finds in one RGBA image (each found one painted white before the next pass). */
function scanPasses(data, width, height, inversionAttempts, decode) {
  const found = [];
  for (let i = 0; i < MAX_CODES_PER_IMAGE; i++) {
    const code = decode(data, width, height, { inversionAttempts });
    if (!code) break;
    if (typeof code.data === 'string' && code.data) found.push(code.data);
    if (!code.location) break;
    blank(data, width, height, code.location);
  }
  return found;
}

/**
 * The texts of the QR codes in an image.
 * @param {object} img
 * @param {Uint8Array|Uint8ClampedArray|Buffer} img.data - width × height × 4 bytes (modified: converted, painted)
 * @param {number} img.width
 * @param {number} img.height
 * @param {boolean} [img.bgra] - byte order B, G, R, A (Electron's toBitmap() on Windows)
 * @param {Function} [decode] - jsQR (tests)
 * @returns {string[]}
 */
function decodeQrImage({ data, width, height, bgra = false }, decode = null) {
  const w = Math.floor(Number(width));
  const h = Math.floor(Number(height));
  if (!(w > 0 && h > 0) || w * h > MAX_PIXELS || !data || data.length < w * h * 4) return [];
  const px = data instanceof Uint8ClampedArray ? data : new Uint8ClampedArray(data.buffer, data.byteOffset, w * h * 4);
  if (bgra) bgraToRgba(px);
  const fn = decode || jsQR();
  let base = { data: px, width: w, height: h };
  let out;
  if (w >= HALF_FIRST_MIN_WIDTH && h >= 2) {
    const half = halfSize(px, w, h);
    out = scanPasses(half.data, half.width, half.height, 'attemptBoth', fn);
    if (out.length) return out;
    out = scanPasses(px, w, h, 'dontInvert', fn);   // nothing found above: px is unchanged
    if (out.length) return out;
    base = half;
  } else {
    out = scanPasses(px, w, h, 'attemptBoth', fn);
    if (out.length) return out;
  }
  return [...new Set(scanTiles(base, fn))];
}

/** Four overlapping tiles (60 % × 60 %, at 0 % and 40 %) of an image, each searched on its own. */
function scanTiles({ data, width, height }, fn) {
  const tw = Math.ceil(width * TILE);
  const th = Math.ceil(height * TILE);
  if (tw < 64 || th < 64) return [];
  const out = [];
  for (const y0 of [0, height - th]) {
    for (const x0 of [0, width - tw]) {
      const tile = new Uint8ClampedArray(tw * th * 4);
      for (let y = 0; y < th; y++) tile.set(data.subarray(((y0 + y) * width + x0) * 4, ((y0 + y) * width + x0 + tw) * 4), y * tw * 4);
      out.push(...scanPasses(tile, tw, th, 'dontInvert', fn));
    }
  }
  return out;
}

// ── Texts → otpauth://totp URIs ──────────────────────────────────

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Bytes → RFC 4648 base32 without '='. */
function base32Encode(bytes) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

/** Minimal protobuf reader: fields of one message → [{ no, wire, value }] (value: Buffer for length-delimited, Number for varints). */
function protoFields(buf) {
  const out = [];
  let i = 0;
  const varint = () => {
    let v = 0;
    let mul = 1;
    for (let n = 0; n < 10; n++) {
      if (i >= buf.length) throw new Error('truncated');
      const b = buf[i++];
      v += (b & 0x7f) * mul;
      mul *= 128;
      if (!(b & 0x80)) return v;
    }
    throw new Error('varint');
  };
  while (i < buf.length) {
    const key = varint();
    const no = Math.floor(key / 8);
    const wire = key % 8;
    if (no < 1) throw new Error('field');
    if (wire === 0) out.push({ no, wire, value: varint() });
    else if (wire === 2) {
      const len = varint();
      if (i + len > buf.length) throw new Error('truncated');
      out.push({ no, wire, value: buf.subarray(i, i + len) });
      i += len;
    } else if (wire === 1) { if (i + 8 > buf.length) throw new Error('truncated'); i += 8; }
    else if (wire === 5) { if (i + 4 > buf.length) throw new Error('truncated'); i += 4; }
    else throw new Error('wire');
  }
  return out;
}

const MIGRATION_ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };   // 4 = MD5: not supported
const MIGRATION_DIGITS = { 0: 6, 1: 6, 2: 8 };

/** One OtpParameters { secret 1, name 2, issuer 3, algorithm 4, digits 5, type 6 } → { uri } | { hotp } | null. */
function migrationAccount(msg) {
  let secret = null;
  let name = '';
  let issuer = '';
  let algorithm = 0;
  let digits = 0;
  let type = 0;
  for (const f of protoFields(msg)) {
    if (f.wire === 2 && f.no === 1) secret = f.value;
    else if (f.wire === 2 && f.no === 2) name = f.value.toString('utf8');
    else if (f.wire === 2 && f.no === 3) issuer = f.value.toString('utf8');
    else if (f.wire === 0 && f.no === 4) algorithm = f.value;
    else if (f.wire === 0 && f.no === 5) digits = f.value;
    else if (f.wire === 0 && f.no === 6) type = f.value;
  }
  if (type === 1) return { hotp: true };                       // HOTP
  if (type !== 0 && type !== 2) return null;                   // unknown (0: unspecified, treated as TOTP)
  if (!secret || !secret.length || !(algorithm in MIGRATION_ALGORITHMS) || !(digits in MIGRATION_DIGITS)) return null;
  issuer = issuer.trim();
  let account = name.trim();
  if (issuer && account.startsWith(`${issuer}:`)) account = account.slice(issuer.length + 1).trim();
  const enc = encodeURIComponent;
  const label = issuer && account ? `${enc(issuer)}:${enc(account)}` : enc(account || issuer);
  const q = [`secret=${base32Encode(secret)}`];
  if (issuer) q.push(`issuer=${enc(issuer)}`);
  if (MIGRATION_ALGORITHMS[algorithm] !== 'SHA1') q.push(`algorithm=${MIGRATION_ALGORITHMS[algorithm]}`);
  if (MIGRATION_DIGITS[digits] !== 6) q.push(`digits=${MIGRATION_DIGITS[digits]}`);
  return { uri: `otpauth://totp/${label}?${q.join('&')}` };
}

/**
 * `otpauth-migration://offline?data=<base64 MigrationPayload>` → { uris, hotp, invalid }
 * (MigrationPayload: repeated OtpParameters otp_parameters = 1; version, batch fields ignored).
 */
function migrationUris(text) {
  const res = { uris: [], hotp: 0, invalid: 0 };
  const m = /[?&]data=([^&#]*)/i.exec(String(text));
  if (!m) { res.invalid++; return res; }
  let b64;
  try { b64 = decodeURIComponent(m[1]); } catch { res.invalid++; return res; }
  b64 = b64.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) { res.invalid++; return res; }
  try {
    const params = protoFields(Buffer.from(b64, 'base64')).filter((f) => f.no === 1 && f.wire === 2);
    if (!params.length) { res.invalid++; return res; }
    for (const p of params.slice(0, MAX_MIGRATION_ACCOUNTS)) {
      let a = null;
      try { a = migrationAccount(p.value); } catch { a = null; }
      if (a && a.uri) res.uris.push(a.uri);
      else if (a && a.hotp) res.hotp++;
      else res.invalid++;
    }
  } catch {
    res.invalid++;
  }
  return res;
}

/**
 * Texts of QR codes → { uris, hotp, invalid, other }: the otpauth://totp URIs vault.parseTotp accepts
 * (deduplicated, in order), HOTP codes, otpauth codes that do not parse, and QR codes that are no 2FA code.
 */
function totpUris(texts) {
  const res = { uris: [], hotp: 0, invalid: 0, other: 0 };
  const seen = new Set();
  const add = (uri) => {
    if (!vault.parseTotp(uri)) { res.invalid++; return; }
    if (!seen.has(uri)) { seen.add(uri); res.uris.push(uri); }
  };
  for (const raw of texts || []) {
    const s = typeof raw === 'string' ? raw.trim() : '';
    if (!s || s.length > MAX_TEXT) { res.other++; continue; }
    if (/^otpauth:\/\/totp\//i.test(s) || /^otpauth:\/\/totp\?/i.test(s)) add(s);
    else if (/^otpauth:\/\/hotp[/?]/i.test(s)) res.hotp++;
    else if (/^otpauth:\/\//i.test(s)) res.invalid++;
    else if (/^otpauth-migration:\/\//i.test(s)) {
      const m = migrationUris(s);
      res.hotp += m.hotp;
      res.invalid += m.invalid;
      for (const u of m.uris) add(u);
    } else res.other++;
  }
  return res;
}

/** totpUris() result → error code when nothing usable was found (`hotp`, `invalid_code`, `none_found`), else null. */
function totpQrError(res) {
  if (res && res.uris && res.uris.length) return null;
  if (res && res.hotp) return 'hotp';
  if (res && res.invalid) return 'invalid_code';
  return 'none_found';
}

module.exports = {
  MAX_PIXELS,
  bgraToRgba, halfSize, decodeQrImage,
  base32Encode, protoFields, migrationUris, totpUris, totpQrError,
};
