'use strict';

/**
 * Medien (Stufe 4e): can the app's Chromium play a file of a NAS share as it is? A share is never converted (only
 * Jellyfin converts), so before the start the page says what will not work — "Ton DTS: am PC kein Ton", "HEVC ohne
 * Hardware-Decoder: kein Bild" — and offers "In VLC öffnen" (4h). Pure, unit-tested:
 *
 *   sniff(buf, name) → { container, video: [codec], audio: [codec], subtitles: [codec], moovAt? }   what a file's start
 *     says: Matroska/WebM (EBML, the Tracks' CodecIDs) or MP4/MOV (the sample entries of moov). `moovAt`: an MP4 whose
 *     moov lies behind the media data — read again from there (the bytes from moovAt, then sniff once more).
 *   verdict(info, caps) → { verdict: 'yes' | 'no' | 'partial' | 'unknown', video, audio, reasons, external }
 *     yes: picture and sound play; partial: the picture plays, the sound does not (or the other way round);
 *     no: neither / the container cannot be read; unknown: not enough known (play and watch: videoWidth 0 → no picture).
 */

const J = require('./media-jellyfin');
const S = require('./media-share');

const MKV_CODECS = [
  ['V_MPEG4/ISO/AVC', 'h264'], ['V_MPEGH/ISO/HEVC', 'hevc'], ['V_VP9', 'vp9'], ['V_VP8', 'vp8'], ['V_AV1', 'av1'],
  ['V_MPEG2', 'mpeg2video'], ['V_MPEG4/ISO/', 'mpeg4'], ['V_MS/VFW/FOURCC', 'vfw'], ['V_THEORA', 'theora'],
  ['A_AAC', 'aac'], ['A_EAC3', 'eac3'], ['A_AC3', 'ac3'], ['A_DTS', 'dts'], ['A_TRUEHD', 'truehd'], ['A_MLP', 'truehd'],
  ['A_OPUS', 'opus'], ['A_VORBIS', 'vorbis'], ['A_FLAC', 'flac'], ['A_MPEG/L3', 'mp3'], ['A_MPEG/L2', 'mp2'],
  ['A_PCM', 'pcm'], ['A_ALAC', 'alac'],
  ['S_TEXT/UTF8', 'subrip'], ['S_TEXT/ASS', 'ass'], ['S_TEXT/SSA', 'ass'], ['S_TEXT/WEBVTT', 'webvtt'],
  ['S_HDMV/PGS', 'pgssub'], ['S_VOBSUB', 'dvdsub'], ['S_DVBSUB', 'dvbsub'],
];

const MP4_CODECS = {
  avc1: 'h264', avc3: 'h264', hvc1: 'hevc', hev1: 'hevc', dvh1: 'hevc', dvhe: 'hevc', av01: 'av1', vp09: 'vp9', vp08: 'vp8',
  mp4v: 'mpeg4', mp4a: 'aac', 'ac-3': 'ac3', 'ec-3': 'eac3', dtsc: 'dts', dtsh: 'dts', dtsl: 'dts', dtse: 'dts', 'dts+': 'dts',
  mlpa: 'truehd', Opus: 'opus', fLaC: 'flac', '.mp3': 'mp3', alac: 'alac', lpcm: 'pcm', sowt: 'pcm', twos: 'pcm',
  tx3g: 'mov_text', wvtt: 'webvtt', stpp: 'ttml',
};

// ── Matroska / WebM ──────────────────────────────────────────

function vint(buf, pos, keepMarker) {
  if (pos >= buf.length) return null;
  const first = buf[pos];
  let len = 1;
  let mask = 0x80;
  while (len <= 8 && !(first & mask)) { len++; mask >>= 1; }
  if (len > 8 || pos + len > buf.length) return null;
  let value = keepMarker ? first : first & (mask - 1);
  let allOnes = (first & (mask - 1)) === mask - 1;
  for (let k = 1; k < len; k++) {
    value = value * 256 + buf[pos + k];
    if (buf[pos + k] !== 0xff) allOnes = false;
  }
  return { value, len, unknown: !keepMarker && allOnes };
}

const EBML = 0x1a45dfa3;
const SEGMENT = 0x18538067;
const TRACKS = 0x1654ae6b;
const TRACK_ENTRY = 0xae;
const TRACK_TYPE = 0x83;
const CODEC_ID = 0x86;
const DOC_TYPE = 0x4282;
const CLUSTER = 0x1f43b675;

/** The elements of buf[start..end): [{ id, start (of the data), size }]; stops at what is cut off. */
function elements(buf, start, end, max = 4096) {
  const out = [];
  let p = start;
  while (p < end && out.length < max) {
    const id = vint(buf, p, true);
    if (!id) break;
    const size = vint(buf, p + id.len, false);
    if (!size) break;
    const data = p + id.len + size.len;
    const sz = size.unknown ? end - data : size.value;
    out.push({ id: id.value, start: data, size: sz, cut: data + sz > end });
    if (size.unknown || data + sz > end) break;
    p = data + sz;
  }
  return out;
}

function mkvCodec(id) {
  const hit = MKV_CODECS.find(([prefix]) => id === prefix || id.startsWith(prefix));
  return hit ? hit[1] : id.toLowerCase();
}

function sniffMatroska(buf) {
  const top = elements(buf, 0, buf.length, 8);
  if (!top.length || top[0].id !== EBML) return null;
  let container = 'mkv';
  for (const e of elements(buf, top[0].start, Math.min(buf.length, top[0].start + top[0].size), 32)) {
    if (e.id === DOC_TYPE && !e.cut) container = buf.toString('ascii', e.start, e.start + e.size).replace(/\0+$/, '') === 'webm' ? 'webm' : 'mkv';
  }
  const seg = top.find((e) => e.id === SEGMENT);
  const out = { container, video: [], audio: [], subtitles: [], complete: false };
  if (!seg) return out;
  const segEnd = Math.min(buf.length, seg.start + seg.size);
  for (const e of elements(buf, seg.start, segEnd)) {
    if (e.id === CLUSTER) break;
    if (e.id !== TRACKS) continue;
    for (const t of elements(buf, e.start, Math.min(segEnd, e.start + e.size), 256)) {
      if (t.id !== TRACK_ENTRY || t.cut) continue;
      let type = null;
      let codec = null;
      for (const f of elements(buf, t.start, t.start + t.size, 128)) {
        if (f.cut) continue;
        if (f.id === TRACK_TYPE && f.size >= 1 && f.size <= 8) type = buf.readUIntBE(f.start, Math.min(6, f.size));
        if (f.id === CODEC_ID && f.size <= 64) codec = mkvCodec(buf.toString('ascii', f.start, f.start + f.size).replace(/\0+$/, ''));
      }
      if (!codec) continue;
      if (type === 1) out.video.push(codec);
      else if (type === 2) out.audio.push(codec);
      else if (type === 17) out.subtitles.push(codec);
    }
    out.complete = !e.cut;
    break;
  }
  return out;
}

// ── MP4 / MOV ────────────────────────────────────────────────

function boxes(buf, start, end, max = 1024) {
  const out = [];
  let p = start;
  while (p + 8 <= end && out.length < max) {
    let size = buf.readUInt32BE(p);
    const type = buf.toString('latin1', p + 4, p + 8);
    let header = 8;
    if (size === 1) {
      if (p + 16 > end) break;
      const hi = buf.readUInt32BE(p + 8);
      size = hi * 2 ** 32 + buf.readUInt32BE(p + 12);
      header = 16;
    } else if (size === 0) {
      size = end - p;
    }
    if (size < header) break;
    out.push({ type, at: p, start: p + header, end: p + size, cut: p + size > end });
    p += size;
  }
  return { list: out, next: p };
}

function handlerOf(buf, mdia) {
  const hdlr = boxes(buf, mdia.start, Math.min(mdia.end, buf.length)).list.find((b) => b.type === 'hdlr' && !b.cut);
  return hdlr && hdlr.start + 12 <= buf.length ? buf.toString('latin1', hdlr.start + 8, hdlr.start + 12) : null;
}

function sampleEntry(buf, mdia) {
  const find = (b, t) => (b ? boxes(buf, b.start, Math.min(b.end, buf.length)).list.find((x) => x.type === t && !x.cut) : null);
  const stsd = find(find(find(mdia, 'minf'), 'stbl'), 'stsd');
  if (!stsd || stsd.start + 16 > buf.length) return null;
  return buf.toString('latin1', stsd.start + 12, stsd.start + 16);
}

/** `offset`: where `buf` lies in the file (a second read from moovAt). */
function sniffMp4(buf, offset = 0) {
  const top = boxes(buf, 0, buf.length, 64);
  if (offset === 0 && (!top.list.length || !['ftyp', 'moov', 'mdat', 'free', 'skip', 'wide', 'pdin'].includes(top.list[0].type))) return null;
  const ftyp = top.list.find((b) => b.type === 'ftyp' && !b.cut);
  const brand = ftyp ? buf.toString('latin1', ftyp.start, ftyp.start + 4) : '';
  const out = { container: brand === 'qt  ' ? 'mov' : 'mp4', video: [], audio: [], subtitles: [], complete: false };
  const moov = top.list.find((b) => b.type === 'moov');
  if (!moov) {
    // the media data first, the moov behind it (no "fast start")
    const last = top.list[top.list.length - 1];
    if (last && last.cut) out.moovAt = offset + last.end;
    else if (top.next >= buf.length) out.moovAt = offset + top.next;
    return out;
  }
  if (moov.cut) { out.moovAt = offset + moov.at; out.moovCut = true; }
  for (const trak of boxes(buf, moov.start, Math.min(moov.end, buf.length)).list.filter((b) => b.type === 'trak' && !b.cut)) {
    const mdia = boxes(buf, trak.start, trak.end).list.find((b) => b.type === 'mdia' && !b.cut);
    if (!mdia) continue;
    const handler = handlerOf(buf, mdia);
    const entry = sampleEntry(buf, mdia);
    if (!entry) continue;
    const codec = Object.prototype.hasOwnProperty.call(MP4_CODECS, entry) ? MP4_CODECS[entry] : entry.trim().toLowerCase();
    if (handler === 'vide') out.video.push(codec);
    else if (handler === 'soun') out.audio.push(codec);
    else if (handler === 'sbtl' || handler === 'text' || handler === 'subt') out.subtitles.push(codec);
  }
  out.complete = !moov.cut;
  return out;
}

/** What a file's first bytes say (Matroska/WebM or MP4/MOV); null for anything else (avi, ts, …: unknown). */
function sniff(buf, name = '') {
  if (!Buffer.isBuffer(buf) || buf.length < 8) return null;
  const mkv = sniffMatroska(buf);
  if (mkv) return mkv;
  const mp4 = sniffMp4(buf);
  if (mp4) return mp4;
  const e = S.extension(name);
  return e ? { container: e, video: [], audio: [], subtitles: [], complete: false } : null;
}

// ── the verdict ──────────────────────────────────────────────

// Matroska too: a share's file goes to <video> as video/webm (Chromium's demuxer reads Matroska, as the Drive viewer
// plays it); what decides is the codecs inside. Jellyfin's own profile stays careful (caps.mkv) — remuxing is cheap there.
const CONTAINERS_OK = ['mp4', 'm4v', 'mov', 'webm', 'mkv', 'mp3', 'm4a', 'flac', 'ogg', 'oga', 'opus', 'wav'];

function videoOk(codec, container, caps) {
  if (codec === 'h264') return container !== 'webm';
  if (codec === 'hevc') return caps.hevc ? container !== 'webm' : false;
  if (codec === 'vp9') return caps.vp9;
  if (codec === 'vp8') return container === 'webm' || container === 'mkv';
  if (codec === 'av1') return caps.av1;
  return false;
}

function audioOk(codec, container, caps) {
  if (codec === 'vorbis') return container === 'webm' || container === 'mkv' || container === 'ogg';
  if (codec === 'pcm') return container === 'wav' || container === 'mov';
  return J.directAudio(caps).includes(codec);
}

/**
 * info: { container | name, video: [codec], audio: [codec], subtitles?: [codec] } (sniff(), or Jellyfin's streams of
 * the file when it is in a library); caps: J.capsOf() of the page.
 * → { verdict, container, video: 'ok' | 'no' | 'hw' | 'none' | 'unknown', audio: 'ok' | 'no' | 'none' | 'unknown',
 *     playableAudio: [index into info.audio], reasons: [code], external: bool }
 *   reasons: 'container' (mkv without Matroska in Chromium, avi, wmv, …), 'video_codec', 'hevc_no_hw',
 *   'audio_codec' (DTS, TrueHD, AC3 …: no sound), 'some_audio' (another sound track plays), 'picture_subtitles'
 *   (PGS/DVD: not shown), 'unknown'. external: "In VLC öffnen" is the better way.
 */
function verdict(info, caps = J.DEFAULT_CAPS) {
  const i = info && typeof info === 'object' ? info : {};
  const container = String(i.container || S.extension(i.name || '') || '').toLowerCase();
  const video = Array.isArray(i.video) ? i.video.map((c) => String(c).toLowerCase()) : [];
  const audio = Array.isArray(i.audio) ? i.audio.map((c) => String(c).toLowerCase()) : [];
  const subs = Array.isArray(i.subtitles) ? i.subtitles.map((c) => String(c).toLowerCase()) : [];
  const reasons = [];
  const containerOk = CONTAINERS_OK.includes(container);
  if (!containerOk) {
    reasons.push('container');
    return { verdict: 'no', container, video: video.length ? 'unknown' : 'none', audio: audio.length ? 'unknown' : 'none', playableAudio: [], reasons, external: true };
  }
  const known = video.length > 0 || audio.length > 0;
  let v = 'none';
  if (video.length) {
    const ok = videoOk(video[0], container, caps);
    v = ok ? 'ok' : video[0] === 'hevc' ? 'hw' : 'no';
    if (!ok) reasons.push(video[0] === 'hevc' ? 'hevc_no_hw' : 'video_codec');
  }
  const playableAudio = audio.map((c, k) => (audioOk(c, container, caps) ? k : -1)).filter((k) => k >= 0);
  let a = 'none';
  if (audio.length) {
    a = playableAudio.length ? 'ok' : 'no';
    if (!playableAudio.length) reasons.push('audio_codec');
    else if (playableAudio[0] !== 0) reasons.push('some_audio');
  }
  if (subs.some((c) => ['pgssub', 'pgs', 'dvdsub', 'dvbsub'].includes(c))) reasons.push('picture_subtitles');
  if (!known) {
    reasons.push('unknown');
    return { verdict: 'unknown', container, video: 'unknown', audio: 'unknown', playableAudio, reasons, external: false };
  }
  const pictureOk = v === 'ok' || v === 'none';
  const soundOk = a === 'ok' || a === 'none';
  let out;
  if (pictureOk && soundOk) out = 'yes';
  else if ((v === 'ok' && !soundOk) || (a === 'ok' && !pictureOk)) out = 'partial';
  else out = 'no';
  return { verdict: out, container, video: v, audio: a, playableAudio, reasons, external: out !== 'yes' };
}

module.exports = { sniff, sniffMatroska, sniffMp4, verdict, MKV_CODECS, MP4_CODECS };
