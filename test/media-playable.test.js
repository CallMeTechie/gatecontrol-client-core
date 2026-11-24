'use strict';

// Medien (Stufe 4e): can the app's Chromium play a NAS file as it is? (for "In VLC öffnen", 4h) — what a file's start
// says (Matroska / MP4) and the verdict, pure.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const MP = require('../src/utils/media-playable');
const J = require('../src/utils/media-jellyfin');

// ── EBML ─────────────────────────────────────────────────────
function idBytes(id) {
  const out = [];
  for (let v = id; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return Buffer.from(out);
}
function size(n) {
  if (n < 0x7f) return Buffer.from([0x80 | n]);
  return Buffer.from([0x40 | (n >> 8), n & 0xff]);
}
const el = (id, ...content) => {
  const body = Buffer.concat(content.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c, 'ascii'))));
  return Buffer.concat([idBytes(id), size(body.length), body]);
};
const uint = (n) => Buffer.from([n]);
function mkv(tracks, docType = 'matroska') {
  const header = el(0x1a45dfa3, el(0x4286, uint(1)), el(0x4282, docType));
  const entries = tracks.map(([type, codec]) => el(0xae, el(0xd7, uint(1)), el(0x83, uint(type)), el(0x86, codec)));
  const segBody = Buffer.concat([el(0x1549a966, el(0x2ad7b1, Buffer.from([0x0f, 0x42, 0x40]))), el(0x1654ae6b, ...entries), el(0x1f43b675, Buffer.alloc(10))]);
  // a Segment of unknown size, as muxers write while recording
  return Buffer.concat([header, idBytes(0x18538067), Buffer.from([0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), segBody]);
}

// ── MP4 ──────────────────────────────────────────────────────
const box = (type, ...content) => {
  const body = Buffer.concat(content);
  const h = Buffer.alloc(8);
  h.writeUInt32BE(8 + body.length, 0);
  h.write(type, 4, 'latin1');
  return Buffer.concat([h, body]);
};
const full = (type, ...content) => box(type, Buffer.alloc(4), ...content);
function trak(handler, entry) {
  const hdlr = full('hdlr', Buffer.alloc(4), Buffer.from(handler, 'latin1'), Buffer.alloc(12), Buffer.from([0]));
  const stsd = full('stsd', Buffer.from([0, 0, 0, 1]), box(entry, Buffer.alloc(16)));
  return box('trak', box('mdia', hdlr, box('minf', box('stbl', stsd))));
}
const ftyp = (brand = 'isom') => box('ftyp', Buffer.from(brand, 'latin1'), Buffer.alloc(4), Buffer.from('isomavc1', 'latin1'));

describe('media-playable: what a file says', () => {
  it('Matroska: the codecs of its tracks; WebM by its DocType', () => {
    const info = MP.sniff(mkv([[1, 'V_MPEGH/ISO/HEVC'], [2, 'A_DTS'], [2, 'A_AAC'], [17, 'S_HDMV/PGS']]), 'Kobaltnacht (2025).mkv');
    assert.deepEqual(info, { container: 'mkv', video: ['hevc'], audio: ['dts', 'aac'], subtitles: ['pgssub'], complete: true });
    assert.equal(MP.sniff(mkv([[1, 'V_VP9'], [2, 'A_OPUS']], 'webm')).container, 'webm');
  });

  it('MP4: moov in front, or behind the media data (read again from moovAt)', () => {
    const fast = Buffer.concat([ftyp(), box('moov', trak('vide', 'avc1'), trak('soun', 'mp4a')), box('mdat', Buffer.alloc(32))]);
    assert.deepEqual(MP.sniff(fast, 'a.mp4'), { container: 'mp4', video: ['h264'], audio: ['aac'], subtitles: [], complete: true });
    // mdat first, and only its beginning read: its end is where the moov starts
    const mdatHeader = Buffer.alloc(8);
    mdatHeader.writeUInt32BE(5000000, 0);
    mdatHeader.write('mdat', 4, 'latin1');
    const head = Buffer.concat([ftyp(), mdatHeader, Buffer.alloc(100)]);
    const first = MP.sniff(head, 'b.mp4');
    assert.equal(first.moovAt, ftyp().length + 5000000);
    const tail = box('moov', trak('vide', 'hvc1'), trak('soun', 'ac-3'), trak('sbtl', 'tx3g'));
    assert.deepEqual(MP.sniffMp4(tail, first.moovAt), { container: 'mp4', video: ['hevc'], audio: ['ac3'], subtitles: ['mov_text'], complete: true });
    assert.equal(MP.sniff(Buffer.concat([ftyp('qt  '), box('moov', trak('vide', 'avc1'))])).container, 'mov');
  });

  it('anything else: by its name only, or nothing', () => {
    assert.deepEqual(MP.sniff(Buffer.from('RIFF....AVI LIST'), 'alt.avi'), { container: 'avi', video: [], audio: [], subtitles: [], complete: false });
    assert.equal(MP.sniff(Buffer.alloc(4), 'x.mkv'), null);
    assert.equal(MP.sniff(Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0xff, 0xff, 0xff, 0xff, 0xff])).container, 'mkv', 'a cut header does not throw');
  });
});

describe('media-playable: the verdict for Chromium', () => {
  const caps = J.capsOf({});
  it('H.264 + AAC in mp4 or mkv: yes', () => {
    assert.equal(MP.verdict({ container: 'mp4', video: ['h264'], audio: ['aac'] }, caps).verdict, 'yes');
    assert.equal(MP.verdict({ container: 'mkv', video: ['h264'], audio: ['aac'] }, caps).verdict, 'yes');
    assert.equal(MP.verdict({ container: 'webm', video: ['vp9'], audio: ['opus'] }, caps).external, false);
  });

  it('DTS only: the picture plays, no sound — "In VLC öffnen"', () => {
    const v = MP.verdict({ container: 'mkv', video: ['h264'], audio: ['dts'] }, caps);
    assert.equal(v.verdict, 'partial');
    assert.equal(v.audio, 'no');
    assert.deepEqual(v.reasons, ['audio_codec']);
    assert.ok(v.external);
  });

  it('DTS first, AAC second: plays with the second track', () => {
    const v = MP.verdict({ container: 'mkv', video: ['hevc'], audio: ['dts', 'aac'], subtitles: ['pgssub'] }, J.capsOf({ hevc: true }));
    assert.equal(v.verdict, 'yes');
    assert.deepEqual(v.playableAudio, [1]);
    assert.deepEqual(v.reasons, ['some_audio', 'picture_subtitles']);
  });

  it('HEVC without the hardware decoder: sound only (Risiko 4)', () => {
    const v = MP.verdict({ container: 'mp4', video: ['hevc'], audio: ['aac'] }, caps);
    assert.equal(v.verdict, 'partial');
    assert.equal(v.video, 'hw');
    assert.deepEqual(v.reasons, ['hevc_no_hw']);
    assert.equal(MP.verdict({ container: 'mp4', video: ['hevc'], audio: ['aac'] }, J.capsOf({ hevc: true })).verdict, 'yes');
  });

  it('AC3 only when Chromium says so; avi / wmv: no; nothing known: unknown', () => {
    assert.equal(MP.verdict({ container: 'mp4', video: ['h264'], audio: ['ac3'] }, caps).verdict, 'partial');
    assert.equal(MP.verdict({ container: 'mp4', video: ['h264'], audio: ['ac3'] }, J.capsOf({ ac3: true })).verdict, 'yes');
    assert.deepEqual(MP.verdict({ name: 'alt.avi' }, caps).reasons, ['container']);
    assert.equal(MP.verdict({ name: 'alt.wmv' }, caps).verdict, 'no');
    assert.equal(MP.verdict({ container: 'mp4', video: ['mpeg4'], audio: ['dts'] }, caps).verdict, 'no');
    assert.equal(MP.verdict({ name: 'x.mp4' }, caps).verdict, 'unknown');
    assert.equal(MP.verdict({ container: 'mp3', audio: ['mp3'] }, caps).verdict, 'yes');
  });
});
