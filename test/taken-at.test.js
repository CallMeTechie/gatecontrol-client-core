'use strict';

// utils/taken-at.js (Drive 1.7 'takenAt'): the date a photo / video was taken,
// read without dependencies from JPEG, TIFF, HEIC, WebP, PNG and MP4 / MOV
// files built here byte by byte.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { takenAt, takenAtOf, isMediaName, parseExifDate, bufferSource } = require('../src/utils/taken-at');

const cleanup = [];
afterEach(() => { for (const fn of cleanup.splice(0)) fn(); });

const { tiff, jpeg, heic, mp4, webp, png } = require('./fixtures/exif-files');

const at = (buf, opts) => takenAtOf(bufferSource(buf), opts);
const MAC = Date.UTC(1904, 0, 1);

describe('utils/taken-at', () => {
  it('parses EXIF dates with and without an offset', () => {
    assert.deepEqual(parseExifDate('2026:07:14 18:03:22', '+02:00'), { iso: '2026-07-14T18:03:22+02:00', ms: Date.UTC(2026, 6, 14, 16, 3, 22) });
    assert.equal(parseExifDate('2026:07:14 18:03:22', '-05:30').ms, Date.UTC(2026, 6, 14, 23, 33, 22));
    // local time of this PC
    const local = parseExifDate('2020:01:02 03:04:05');
    assert.equal(local.ms, new Date(2020, 0, 2, 3, 4, 5).getTime());
    assert.match(local.iso, /^2020-01-02T03:04:05[+-]\d{2}:\d{2}$/);
    for (const bad of ['0000:00:00 00:00:00', '    :  :     :  :  ', '1899:12:31 10:00:00', '2026:13:01 10:00:00', '2026:02:31 10:00:00', '', null, 12]) assert.equal(parseExifDate(bad), null, String(bad));
    // more than a day ahead
    assert.equal(parseExifDate('2026:07:20 12:00:00', '+00:00', { now: Date.UTC(2026, 6, 18) }), null);
    assert.ok(parseExifDate('2026:07:18 12:00:00', '+00:00', { now: Date.UTC(2026, 6, 18) }));
    assert.equal(isMediaName('IMG_0001.HEIC'), true);
    assert.equal(isMediaName('clip.mov'), true);
    assert.equal(isMediaName('Brief.pdf'), false);
  });

  it('reads JPEG, TIFF (both byte orders), HEIC, WebP and PNG', async () => {
    const want = '2026-07-14T18:03:22+02:00';
    assert.equal((await at(jpeg(tiff()))).iso, want);
    assert.equal((await at(tiff())).iso, want);
    assert.equal((await at(tiff({ le: false }))).iso, want);
    assert.equal((await at(heic(tiff()))).iso, want);
    assert.equal((await at(webp(tiff()))).iso, want);
    assert.equal((await at(png(tiff()))).iso, want);
    // no DateTimeOriginal: DateTime (local time)
    const r = await at(jpeg(tiff({ original: null, offset: null })));
    assert.equal(r.ms, new Date(2026, 6, 20, 9, 0, 0).getTime());
    // nothing at all
    assert.equal(await at(jpeg(tiff({ original: null, offset: null, dateTime: null }))), null);
    assert.equal(await at(Buffer.from('not a picture at all')), null);
    // broken: cut short, nonsense offsets
    const j = jpeg(tiff());
    assert.equal(await at(j.subarray(0, 40)), null);
    const bad = Buffer.from(j);
    bad.writeUInt32LE(0xfffffff0, 4 + 18 + 4 + 6 + 4);
    assert.equal(await at(bad), null);
  });

  it('reads the creation time of MP4 / MOV (moov after mdat, mvhd v0 and v1)', async () => {
    const secs = Math.round((Date.UTC(2025, 11, 24, 17, 30, 0) - MAC) / 1000);
    assert.equal((await at(mp4(secs))).iso, '2025-12-24T17:30:00.000Z');
    assert.equal((await at(mp4(secs, 1))).iso, '2025-12-24T17:30:00.000Z');
    assert.equal(await at(mp4(0)), null);
  });

  it('takenAt(file): only pictures and videos, never throws', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'taken-at-'));
    cleanup.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const p = path.join(dir, 'IMG_1.jpg');
    fs.writeFileSync(p, jpeg(tiff()));
    assert.equal(await takenAt(p), '2026-07-14T18:03:22+02:00');
    const q = path.join(dir, 'kopie.bin');
    fs.writeFileSync(q, jpeg(tiff()));
    assert.equal(await takenAt(q), null);
    assert.equal(await takenAt(q, { name: 'Foto.JPG' }), '2026-07-14T18:03:22+02:00');
    assert.equal(await takenAt(path.join(dir, 'fehlt.jpg')), null);
  });
});
