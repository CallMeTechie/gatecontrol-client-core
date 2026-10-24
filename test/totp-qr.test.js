'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qrcode = require('qrcode-generator');

const qr = require('../src/utils/totp-qr');
const { scanTotpQr, decodeInWorker, bitmapOf } = require('../src/services/totp-qr');
const vault = require('../src/utils/vault');

// ── Fixtures: QR codes drawn into RGBA "screens" ─────────────────

const URI_A = 'otpauth://totp/Example:anna@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
const URI_B = 'otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA256&digits=8&period=60';

/** A screen-like RGBA canvas: light background with lines of small "glyphs" (seeded, so every run is the same). */
function canvas(width, height, { bg = [236, 238, 242], text = true } = {}) {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < data.length; i += 4) { data[i] = bg[0]; data[i + 1] = bg[1]; data[i + 2] = bg[2]; data[i + 3] = 255; }
  if (!text) return { data, width, height };
  let seed = 42;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const dot = (x, y) => { if (x >= 0 && y >= 0 && x < width && y < height) { const i = (y * width + x) * 4; data[i] = data[i + 1] = data[i + 2] = 50; } };
  for (let y = 30; y < height - 30; y += 22) {
    let x = 20;
    while (x < width - 40) {
      const letters = 3 + Math.floor(rnd() * 8);
      for (let c = 0; c < letters; c++) {
        const gw = 5 + Math.floor(rnd() * 3);
        for (let k = 0; k < 4; k++) {       // a glyph: four short strokes
          const vertical = rnd() < 0.5;
          const sx = x + Math.floor(rnd() * gw);
          const sy = y + Math.floor(rnd() * 9);
          const len = 2 + Math.floor(rnd() * 9);
          for (let i = 0; i < len; i++) dot(vertical ? sx : sx + i - 3, vertical ? sy + i - 2 : sy);
        }
        x += gw + 1;
      }
      x += 6 + Math.floor(rnd() * 6) + (rnd() < 0.05 ? 200 : 0);
    }
  }
  return { data, width, height };
}

/** Draws `text` as a QR code (module size `scale`, quiet zone 4) at x, y; `invert`: light modules on dark. */
function drawQr(img, text, x0, y0, scale, { invert = false } = {}) {
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  const n = q.getModuleCount();
  for (let y = -4; y < n + 4; y++) {
    for (let x = -4; x < n + 4; x++) {
      const dark = x >= 0 && y >= 0 && x < n && y < n && q.isDark(y, x);
      const v = dark !== invert ? 0 : 255;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = x0 + (x + 4) * scale + dx;
          const py = y0 + (y + 4) * scale + dy;
          const i = (py * img.width + px) * 4;
          img.data[i] = img.data[i + 1] = img.data[i + 2] = v;
        }
      }
    }
  }
  return (n + 8) * scale;
}

const toBgra = (img) => ({ ...img, data: Buffer.from(qr.bgraToRgba(Uint8ClampedArray.from(img.data))), bgra: true });

/** A fake nativeImage of a bitmap (BGRA like Electron on Windows). */
function fakeImage(img) {
  const bgra = img ? Buffer.from(qr.bgraToRgba(Uint8ClampedArray.from(img.data))) : null;
  return {
    isEmpty: () => !img,
    getSize: () => (img ? { width: img.width, height: img.height } : { width: 0, height: 0 }),
    toBitmap: () => Buffer.from(bgra),
    resize: () => { throw new Error('not expected'); },
  };
}

// Protobuf encoder for MigrationPayload fixtures (Google Authenticator export)
const varint = (n) => { const out = []; let v = n; do { let b = v % 128; v = Math.floor(v / 128); if (v) b |= 0x80; out.push(b); } while (v); return Buffer.from(out); };
const fieldV = (no, v) => Buffer.concat([varint(no * 8), varint(v)]);
const fieldB = (no, buf) => Buffer.concat([varint(no * 8 + 2), varint(buf.length), Buffer.from(buf)]);
function otpParams({ secret, name, issuer, algorithm = 1, digits = 1, type = 2, counter = null }) {
  const parts = [fieldB(1, secret), fieldB(2, Buffer.from(name, 'utf8'))];
  if (issuer != null) parts.push(fieldB(3, Buffer.from(issuer, 'utf8')));
  parts.push(fieldV(4, algorithm), fieldV(5, digits), fieldV(6, type));
  if (counter != null) parts.push(fieldV(7, counter));
  return Buffer.concat(parts);
}
function migration(accounts, { urlEncode = true } = {}) {
  const payload = Buffer.concat([...accounts.map((a) => fieldB(1, otpParams(a))), fieldV(2, 1), fieldV(3, 1), fieldV(4, 0), fieldV(5, 123456)]);
  const b64 = payload.toString('base64');
  return `otpauth-migration://offline?data=${urlEncode ? encodeURIComponent(b64) : b64}`;
}

// ── Bitmaps ──────────────────────────────────────────────────────

describe('totp-qr: bitmaps', () => {
  it('bgraToRgba swaps blue and red in place', () => {
    const px = Uint8ClampedArray.from([1, 2, 3, 4, 10, 20, 30, 40]);
    assert.equal(qr.bgraToRgba(px), px);
    assert.deepEqual([...px], [3, 2, 1, 4, 30, 20, 10, 40]);
  });

  it('halfSize averages 2×2 blocks', () => {
    const px = new Uint8ClampedArray(4 * 2 * 4);
    // left block: 0, 100, 200, 100 → 100; right block: all 255
    const set = (x, y, v) => { const i = (y * 4 + x) * 4; px[i] = px[i + 1] = px[i + 2] = v; px[i + 3] = 255; };
    set(0, 0, 0); set(1, 0, 100); set(0, 1, 200); set(1, 1, 100);
    set(2, 0, 255); set(3, 0, 255); set(2, 1, 255); set(3, 1, 255);
    const h = qr.halfSize(px, 4, 2);
    assert.deepEqual([h.width, h.height], [2, 1]);
    assert.deepEqual([...h.data], [100, 100, 100, 255, 255, 255, 255, 255]);
  });

  it('finds an otpauth code on a Full HD screen (RGBA and BGRA)', () => {
    const img = canvas(1920, 1080);
    drawQr(img, URI_A, 1200, 300, 5);
    assert.deepEqual(qr.decodeQrImage(toBgra(img)), [URI_A]);
    assert.deepEqual(qr.decodeQrImage(img), [URI_A]);
  });

  it('finds a normal-sized code on a 4K screen (and a small one)', () => {
    const img = canvas(3840, 2160);
    drawQr(img, URI_A, 2600, 900, 8);    // ~ 200 px CSS at 200 % scaling
    assert.deepEqual(qr.decodeQrImage(toBgra(img)), [URI_A]);
    const small = canvas(3840, 2160);
    drawQr(small, URI_B, 300, 1500, 3);
    assert.deepEqual(qr.decodeQrImage(small), [URI_B]);
  });

  it('finds several codes in one image', () => {
    const img = canvas(1920, 1080);
    drawQr(img, URI_A, 100, 200, 5);
    drawQr(img, URI_B, 1100, 300, 5);
    assert.deepEqual(qr.decodeQrImage(img).sort(), [URI_A, URI_B].sort());
  });

  it('finds an inverted code (light on dark, e.g. a dark theme) through the half size pass', () => {
    const img = canvas(2560, 1440, { bg: [24, 26, 30], text: false });
    drawQr(img, URI_A, 900, 300, 6, { invert: true });
    assert.deepEqual(qr.decodeQrImage(img), [URI_A]);
    const small = canvas(600, 600, { bg: [24, 26, 30], text: false });
    drawQr(small, URI_A, 40, 40, 4, { invert: true });
    assert.deepEqual(qr.decodeQrImage(small), [URI_A]);
  });

  it('no code, broken input → []', () => {
    assert.deepEqual(qr.decodeQrImage(canvas(800, 600)), []);
    assert.deepEqual(qr.decodeQrImage({ data: new Uint8Array(10), width: 100, height: 100 }), []);
    assert.deepEqual(qr.decodeQrImage({ data: new Uint8Array(4), width: 0, height: 1 }), []);
    assert.deepEqual(qr.decodeQrImage({ data: null, width: 10, height: 10 }), []);
    assert.deepEqual(qr.decodeQrImage({ data: new Uint8Array(4), width: 20000, height: 20000 }), []);
  });
});

// ── Texts → URIs ─────────────────────────────────────────────────

describe('totp-qr: texts → otpauth://totp URIs', () => {
  it('base32Encode is the inverse of the vault parser (RFC 4648 vectors)', () => {
    const vectors = { '': '', f: 'MY', fo: 'MZXQ', foo: 'MZXW6', foob: 'MZXW6YQ', fooba: 'MZXW6YTB', foobar: 'MZXW6YTBOI' };
    for (const [plain, enc] of Object.entries(vectors)) assert.equal(qr.base32Encode(Buffer.from(plain)), enc, plain);
    const raw = Buffer.from('00ff10e0c3a5b6c7d8e9fa0b1c2d3e4f5061', 'hex');
    assert.deepEqual(vault.base32Decode(qr.base32Encode(raw)), raw);
  });

  it('keeps valid TOTP URIs (deduplicated), counts HOTP, broken otpauth and other codes', () => {
    const r = qr.totpUris([
      URI_A, URI_A, ` ${URI_B} `, 'OTPAUTH://TOTP/X?secret=JBSWY3DPEHPK3PXP',
      'otpauth://hotp/Example:anna?secret=JBSWY3DPEHPK3PXP&counter=1',
      'otpauth://totp/Bad?secret=not*base32', 'otpauth://totp/Bad?issuer=x', 'otpauth://totp/Algo?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
      'otpauth://steam/x?secret=JBSWY3DPEHPK3PXP',
      'https://example.com/', 'WIFI:S:Heim;T:WPA;P:x;;', '', null, 'x'.repeat(9000),
    ]);
    assert.deepEqual(r.uris, [URI_A, URI_B, 'OTPAUTH://TOTP/X?secret=JBSWY3DPEHPK3PXP']);
    assert.equal(r.hotp, 1);
    assert.equal(r.invalid, 4);
    assert.equal(r.other, 5);
    const p = vault.parseTotp(r.uris[1]);
    assert.deepEqual([p.algorithm, p.digits, p.period], ['SHA256', 8, 60]);
  });

  it('error codes: hotp only, broken only, nothing', () => {
    assert.equal(qr.totpQrError(qr.totpUris([URI_A])), null);
    assert.equal(qr.totpQrError(qr.totpUris(['otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP'])), 'hotp');
    assert.equal(qr.totpQrError(qr.totpUris(['otpauth://totp/x?secret=1', 'otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP'])), 'hotp');
    assert.equal(qr.totpQrError(qr.totpUris(['otpauth://totp/x?secret=1'])), 'invalid_code');
    assert.equal(qr.totpQrError(qr.totpUris(['https://example.com'])), 'none_found');
    assert.equal(qr.totpQrError(qr.totpUris([])), 'none_found');
  });

  it('otpauth-migration (Google Authenticator export) → one otpauth://totp URI per TOTP account', () => {
    const s1 = Buffer.from('Hello!\xde\xad\xbe\xef', 'latin1');
    const s2 = crypto32();
    const text = migration([
      { secret: s1, name: 'anna@example.com', issuer: 'Example' },
      { secret: s2, name: 'ACME Co:john.doe', issuer: 'ACME Co', algorithm: 2, digits: 2 },
      { secret: s1, name: 'no-issuer', issuer: null, algorithm: 3, type: 0 },
      { secret: s1, name: 'counter', issuer: 'H', type: 1, counter: 5 },     // HOTP
      { secret: s1, name: 'md5', issuer: 'M', algorithm: 4 },                // MD5: not supported
      { secret: Buffer.alloc(0), name: 'empty', issuer: 'E' },              // no secret
    ]);
    const m = qr.migrationUris(text);
    assert.equal(m.hotp, 1);
    assert.equal(m.invalid, 2);
    assert.deepEqual(m.uris, [
      `otpauth://totp/Example:anna%40example.com?secret=${qr.base32Encode(s1)}&issuer=Example`,
      `otpauth://totp/ACME%20Co:john.doe?secret=${qr.base32Encode(s2)}&issuer=ACME%20Co&algorithm=SHA256&digits=8`,
      `otpauth://totp/no-issuer?secret=${qr.base32Encode(s1)}&algorithm=SHA512`,
    ]);
    const p0 = vault.parseTotp(m.uris[0]);
    assert.deepEqual(p0.secret, s1);
    assert.deepEqual([p0.algorithm, p0.digits, p0.period], ['SHA1', 6, 30]);
    const p1 = vault.parseTotp(m.uris[1]);
    assert.deepEqual(p1.secret, s2);
    assert.deepEqual([p1.algorithm, p1.digits], ['SHA256', 8]);
    assert.equal(vault.totpLabel(m.uris[1]), 'ACME Co');
    assert.equal(vault.totpLabel(m.uris[2]), 'no-issuer');
    // through totpUris (+ a plain base64 data parameter with '+' / '/')
    const r = qr.totpUris([migration([{ secret: Buffer.from([0xfb, 0xff, 0xfe, 0xfd, 0xfc]), name: 'x', issuer: 'Y' }], { urlEncode: false })]);
    assert.equal(r.uris.length, 1);
    assert.deepEqual(vault.parseTotp(r.uris[0]).secret, Buffer.from([0xfb, 0xff, 0xfe, 0xfd, 0xfc]));
    assert.equal(qr.totpQrError(qr.totpUris([migration([{ secret: s1, name: 'c', issuer: 'H', type: 1 }])])), 'hotp');
  });

  it('otpauth-migration: broken payloads are invalid, never a crash', () => {
    for (const bad of [
      'otpauth-migration://offline?data=', 'otpauth-migration://offline', 'otpauth-migration://offline?data=%%%',
      'otpauth-migration://offline?data=!!!!', `otpauth-migration://offline?data=${Buffer.from([0x0a, 0x50, 0x01]).toString('base64')}`,
      `otpauth-migration://offline?data=${Buffer.from([0x0f, 0x01]).toString('base64')}`,
      `otpauth-migration://offline?data=${Buffer.from([0x10, 0x01]).toString('base64')}`,
      `otpauth-migration://offline?data=${Buffer.from([0x0a, 0x02, 0x0a, 0x7f]).toString('base64')}`,
    ]) {
      const r = qr.totpUris([bad]);
      assert.deepEqual(r.uris, [], bad);
      assert.equal(qr.totpQrError(r), 'invalid_code', bad);
    }
    assert.throws(() => qr.protoFields(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])));
  });
});

function crypto32() {
  return require('crypto').createHash('sha256').update('vault-qr').digest().subarray(0, 20);
}

// ── scanTotpQr (fake Electron) ───────────────────────────────────

describe('scanTotpQr', () => {
  const screenWith = (text, scale = 4) => { const img = canvas(1000, 700); if (text) drawQr(img, text, 480, 120, scale); return img; };
  const code = (c) => (e) => e && e.code === c;

  it('clipboard: image with a code → URIs (decoded in a worker thread); no image → no_image', async () => {
    let img = screenWith(URI_A);
    const electron = { clipboard: { readImage: () => fakeImage(img) } };
    assert.deepEqual(await scanTotpQr({ source: 'clipboard', electron }), [URI_A]);
    img = null;
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('no_image'));
    img = screenWith('https://example.com/not-2fa');
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('none_found'));
    img = screenWith('otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=0');
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('hotp'));
    img = screenWith(migration([{ secret: crypto32(), name: 'a@b.c', issuer: 'Z' }, { secret: crypto32(), name: 'd@e.f', issuer: 'Z' }]), 4);
    const uris = await scanTotpQr({ source: 'clipboard', electron });
    assert.equal(uris.length, 2);
    assert.match(uris[1], /^otpauth:\/\/totp\/Z:d%40e\.f\?secret=/);
  });

  it('clipboard of Electron 44 (async read() → ClipboardItem image/png → nativeImage)', async () => {
    let items = [];
    const seen = [];
    const electron = {
      clipboard: { read: async () => items },
      nativeImage: { createFromBuffer: (buf) => { seen.push(String(buf)); return String(buf) === 'PNG' ? fakeImage(screenWith(URI_A)) : fakeImage(null); } },
    };
    const item = (types, data) => ({ types, getType: async (tp) => { if (!types.includes(tp)) throw new Error('no'); return new Blob([data[tp]]); } });
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('no_image'));
    items = [item(['text/plain'], { 'text/plain': 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' })];
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('no_image'), 'text is no image');
    items = [item(['text/html', 'image/jpeg', 'image/png'], { 'image/png': 'PNG', 'image/jpeg': 'JPEG' })];
    assert.deepEqual(await scanTotpQr({ source: 'clipboard', electron }), [URI_A]);
    assert.deepEqual(seen, ['PNG'], 'PNG first');
    items = [item(['image/jpeg'], { 'image/jpeg': 'broken' })];
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('no_image'));
    electron.clipboard.read = async () => { throw new Error('busy'); };
    await assert.rejects(scanTotpQr({ source: 'clipboard', electron }), code('no_image'));
  });

  it('decodeInWorker: worker answer, worker that cannot start → code worker', async () => {
    const img = screenWith(URI_B);
    assert.deepEqual(await decodeInWorker({ ...toBgra(img) }), [URI_B]);
    class Broken { constructor() { throw new Error('no'); } }
    await assert.rejects(decodeInWorker(toBgra(img), { Worker: Broken }), code('worker'));
    const { EventEmitter } = require('events');
    class Dies extends EventEmitter { constructor() { super(); setImmediate(() => this.emit('error', new Error('MODULE_NOT_FOUND'))); } terminate() {} }
    await assert.rejects(decodeInWorker(toBgra(img), { Worker: Dies }), code('worker'));
  });

  it('bitmapOf: empty images → null, BGRA flag', () => {
    assert.equal(bitmapOf(null), null);
    assert.equal(bitmapOf(fakeImage(null)), null);
    const b = bitmapOf(fakeImage(canvas(10, 10)));
    assert.deepEqual([b.width, b.height, b.bgra, b.data.length], [10, 10, true, 400]);
    let resized = null;
    const huge = {
      isEmpty: () => false, getSize: () => ({ width: 10000, height: 8000 }), toBitmap: () => { throw new Error('too big'); },
      resize: (o) => { resized = o; return fakeImage(canvas(16, 12, { text: false })); },
    };
    const h = bitmapOf(huge);
    assert.ok(resized && resized.width * resized.height <= qr.MAX_PIXELS && Math.abs(resized.width / resized.height - 1.25) < 0.01);
    assert.deepEqual([h.width, h.height], [16, 12]);
  });

  it('screen: every display at native resolution; window made transparent for a 2nd capture, then restored', async () => {
    const calls = [];
    let opacity = 1;
    const shots = [];
    const win = {
      isDestroyed: () => false, isVisible: () => true, isMinimized: () => false,
      getOpacity: () => opacity, setOpacity: (v) => { opacity = v; calls.push(['opacity', v]); },
    };
    const electron = {
      screen: { getAllDisplays: () => [{ size: { width: 1920, height: 1080 }, scaleFactor: 1 }, { size: { width: 1280, height: 720 }, scaleFactor: 2 }] },
      desktopCapturer: {
        getSources: async (o) => {
          calls.push(['capture', o]);
          // the website's QR code is "under" the window: visible only while the window is transparent
          return [{ thumbnail: fakeImage(screenWith(opacity === 0 ? URI_A : null)) }, { thumbnail: fakeImage(screenWith(null)) }];
        },
      },
    };
    const uris = await scanTotpQr({ source: 'screen', electron, getWindow: () => win, platform: 'win32', decode: async (b) => { shots.push(b); return qr.decodeQrImage(b); } });
    assert.deepEqual(uris, [URI_A]);
    assert.deepEqual(calls[0], ['capture', { types: ['screen'], thumbnailSize: { width: 2560, height: 1440 } }]);
    assert.deepEqual(calls.slice(1).map((c) => c[0] === 'capture' ? 'capture' : `opacity ${c[1]}`), ['opacity 0', 'capture', 'opacity 1']);
    assert.equal(opacity, 1);
    assert.equal(shots.length, 4, 'two displays, two captures');
  });

  it('screen: a visible code needs no 2nd capture; no window / Linux → no hiding; nothing → none_found', async () => {
    let captures = 0;
    let img = screenWith(URI_B);
    const electron = {
      screen: { getAllDisplays: () => [{ size: { width: 1920, height: 1080 }, scaleFactor: 1 }] },
      desktopCapturer: { getSources: async () => { captures++; return [{ thumbnail: fakeImage(img) }]; } },
    };
    const win = { isVisible: () => true, isMinimized: () => false, getOpacity: () => 1, setOpacity: () => { throw new Error('not expected'); } };
    assert.deepEqual(await scanTotpQr({ source: 'screen', electron, getWindow: () => win, platform: 'win32' }), [URI_B]);
    assert.equal(captures, 1);
    img = screenWith(null);
    captures = 0;
    await assert.rejects(scanTotpQr({ source: 'screen', electron, getWindow: () => win, platform: 'linux' }), code('none_found'));
    assert.equal(captures, 1);
    // the window was hidden and is restored even when the 2nd capture fails
    let opacity = 0.9;
    const w2 = { isVisible: () => true, isMinimized: () => false, getOpacity: () => opacity, setOpacity: (v) => { opacity = v; } };
    let n = 0;
    const failing = { ...electron, desktopCapturer: { getSources: async () => { if (n++) throw new Error('denied'); return [{ thumbnail: fakeImage(img) }]; } } };
    await assert.rejects(scanTotpQr({ source: 'screen', electron: failing, getWindow: () => w2, platform: 'win32' }), code('unsupported'));
    assert.equal(opacity, 0.9);
    // minimized window: no 2nd capture
    captures = 0;
    await assert.rejects(scanTotpQr({ source: 'screen', electron, getWindow: () => ({ ...win, isMinimized: () => true }), platform: 'win32' }), code('none_found'));
    assert.equal(captures, 1);
    // no sources (capture not allowed) → unsupported
    await assert.rejects(scanTotpQr({ source: 'screen', electron: { ...electron, desktopCapturer: { getSources: async () => [] } }, platform: 'linux' }), code('unsupported'));
  });

  it('file: dialog cancelled, PNG / JPG via nativeImage, other formats via the shell thumbnail (Windows), too large', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-qr-'));
    const png = path.join(dir, 'qr.png');
    const webp = path.join(dir, 'qr.webp');
    fs.writeFileSync(png, 'PNG bytes');
    fs.writeFileSync(webp, 'WEBP bytes');
    let pick = { canceled: true, filePaths: [] };
    const seen = [];
    const parent = { isDestroyed: () => false };
    const electron = {
      dialog: { showOpenDialog: async (w, o) => { seen.push([w, o]); return pick; } },
      nativeImage: {
        createFromBuffer: (buf) => (String(buf) === 'PNG bytes' ? fakeImage(screenWith(URI_A)) : fakeImage(null)),
        createThumbnailFromPath: async (p, size) => { seen.push(['thumb', path.basename(p), size]); return fakeImage(screenWith(URI_B)); },
      },
    };
    await assert.rejects(scanTotpQr({ source: 'file', electron, getWindow: () => parent }), code('cancelled'));
    assert.equal(seen[0][0], parent);
    assert.deepEqual(seen[0][1].filters[0].extensions, ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']);
    assert.deepEqual(seen[0][1].properties, ['openFile']);
    pick = { canceled: false, filePaths: [png] };
    assert.deepEqual(await scanTotpQr({ source: 'file', electron, getWindow: () => parent, platform: 'linux' }), [URI_A]);
    pick = { canceled: false, filePaths: [webp] };
    await assert.rejects(scanTotpQr({ source: 'file', electron, platform: 'linux' }), code('unsupported'));
    assert.deepEqual(await scanTotpQr({ source: 'file', electron, platform: 'win32' }), [URI_B]);
    assert.deepEqual(seen.at(-1), ['thumb', 'qr.webp', { width: 2048, height: 2048 }]);
    pick = { canceled: false, filePaths: [path.join(dir, 'missing.png')] };
    await assert.rejects(scanTotpQr({ source: 'file', electron, platform: 'win32' }), code('failed'));
    fs.writeFileSync(png, Buffer.alloc(31 * 1024 * 1024));
    pick = { canceled: false, filePaths: [png] };
    await assert.rejects(scanTotpQr({ source: 'file', electron, platform: 'win32' }), code('unsupported'));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('unknown source → failed', async () => {
    await assert.rejects(scanTotpQr({ source: 'camera', electron: {} }), code('failed'));
  });
});
