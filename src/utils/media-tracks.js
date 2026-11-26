'use strict';

/**
 * Medien (Stufe 4e): the sound tracks and subtitles of a title — choosing, remembering per series ("merkt sich
 * GateControl je Serie"), the labels, what happens with a sound on this PC. Pure, unit-tested with the cases of
 * Android's MediaTracks. On the PC nothing goes to an AV receiver: a sound Chromium does not decode is converted by
 * Jellyfin (DTS / TrueHD → AAC 5.1).
 */

const J = require('./media-jellyfin');

/** ISO 639-2/B codes (as ffprobe and Jellyfin write them) → the two-letter tag. */
const BIBLIOGRAPHIC = {
  ger: 'de', fre: 'fr', dut: 'nl', chi: 'zh', cze: 'cs', gre: 'el', per: 'fa', rum: 'ro', slo: 'sk', alb: 'sq',
  arm: 'hy', baq: 'eu', bur: 'my', geo: 'ka', ice: 'is', mac: 'mk', mao: 'mi', may: 'ms', tib: 'bo', wel: 'cy',
};

/** ISO 639-2/T codes of the languages films come in → the two-letter tag (Intl knows the two-letter ones). */
const THREE_LETTER = {
  deu: 'de', eng: 'en', fra: 'fr', spa: 'es', ita: 'it', por: 'pt', nld: 'nl', pol: 'pl', rus: 'ru', ukr: 'uk',
  tur: 'tr', ara: 'ar', heb: 'he', hin: 'hi', jpn: 'ja', kor: 'ko', zho: 'zh', ces: 'cs', slk: 'sk', hun: 'hu',
  ron: 'ro', bul: 'bg', hrv: 'hr', srp: 'sr', slv: 'sl', ell: 'el', swe: 'sv', nor: 'no', nob: 'nb', nno: 'nn',
  dan: 'da', fin: 'fi', isl: 'is', est: 'et', lav: 'lv', lit: 'lt', cat: 'ca', eus: 'eu', glg: 'gl', fas: 'fa',
  tha: 'th', vie: 'vi', ind: 'id', msa: 'ms', tgl: 'tl', fil: 'fil', sqi: 'sq', hye: 'hy', kat: 'ka', mkd: 'mk',
  bos: 'bs', gle: 'ga', cym: 'cy', lat: 'la', ben: 'bn', tam: 'ta', tel: 'te', urd: 'ur', afr: 'af', swa: 'sw',
};

/** "ger" / "deu" / "de" → "Deutsch" in `lang`; null when it is not a language ("und", unknown). */
function languageName(code, lang = 'de') {
  const c = String(code == null ? '' : code).trim().toLowerCase();
  if (!c || c === 'und' || c === 'mis' || c === 'zxx' || !/^[a-z]{2,3}(-[a-z0-9]{2,8})?$/.test(c)) return null;
  const tag = BIBLIOGRAPHIC[c] || THREE_LETTER[c] || c;
  if (tag.length === 3 && !THREE_LETTER[c] && !BIBLIOGRAPHIC[c]) return null;
  let name = null;
  try {
    name = new Intl.DisplayNames([lang], { type: 'language', fallback: 'none' }).of(tag) || null;
  } catch { name = null; }
  if (!name || name.toLowerCase() === tag) return null;
  return name.charAt(0).toLocaleUpperCase(lang) + name.slice(1);
}

const CODEC_LABELS = {
  dts: 'DTS', dca: 'DTS', truehd: 'TrueHD', mlp: 'TrueHD', ac3: 'Dolby Digital', eac3: 'Dolby Digital Plus', aac: 'AAC',
  mp3: 'MP3', flac: 'FLAC', opus: 'Opus', vorbis: 'Vorbis', subrip: 'SRT', srt: 'SRT', ass: 'ASS', ssa: 'ASS',
  webvtt: 'VTT', vtt: 'VTT', pgssub: 'PGS', pgs: 'PGS', dvdsub: 'DVD', dvbsub: 'DVD', mov_text: 'Text',
};

/** "DTS", "TrueHD", "Dolby Digital", "AAC" … */
function codecLabel(codec) {
  const c = codec ? String(codec).toLowerCase() : '';
  if (!c) return null;
  return Object.prototype.hasOwnProperty.call(CODEC_LABELS, c) ? CODEC_LABELS[c] : c.toUpperCase();
}

function channelsLabel(channels) {
  if (channels === 1) return 'Mono';
  if (channels === 2) return 'Stereo';
  if (channels === 6) return '5.1';
  if (channels === 8) return '7.1';
  if (!channels) return null;
  return `${channels} ch`;
}

/** "DTS 5.1", "AAC Stereo". */
function audioLabel(s) {
  return [codecLabel(s.codec), channelsLabel(s.channels)].filter(Boolean).join(' ') || 'Audio';
}

/** 'decoded' (Chromium plays it itself) | 'converted' (Jellyfin converts it, e.g. DTS → AAC 5.1). */
function fate(s, caps = J.DEFAULT_CAPS) {
  const c = s && s.codec ? String(s.codec).toLowerCase() : '';
  return J.directAudio(caps).includes(c) ? 'decoded' : 'converted';
}

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

/** The audio stream for a series' choice (its language), else the server's default, else the first. */
function pickAudio(version, choice) {
  const audio = J.audioOf(version);
  const lang = choice && choice.audioLanguage;
  if (lang) {
    const match = audio.filter((a) => same(a.language, lang));
    const hit = match.find((a) => a.isDefault) || match[0];
    if (hit) return hit.index;
  }
  if (version.defaultAudio !== null && version.defaultAudio !== undefined && audio.some((a) => a.index === version.defaultAudio)) return version.defaultAudio;
  return audio.length ? audio[0].index : null;
}

/** The subtitle for `choice`: off, the one of its language (not forced first), else the server's default (null). */
function pickSubtitle(version, choice) {
  if (!choice) return null;
  if (choice.subtitlesOff) return J.SUBTITLES_OFF;
  const lang = choice.subtitleLanguage;
  if (!lang) return null;
  const match = J.subtitlesOf(version).filter((s) => same(s.language, lang));
  const hit = match.find((s) => !s.forced) || match[0];
  return hit ? hit.index : null;
}

/** What to remember for the series from what was chosen: { audioLanguage, subtitleLanguage, subtitlesOff }. */
function choiceOf(version, audioIndex, subtitleIndex) {
  const a = J.audioOf(version).find((s) => s.index === audioIndex);
  const s = J.subtitlesOf(version).find((x) => x.index === subtitleIndex);
  return { audioLanguage: (a && a.language) || null, subtitleLanguage: (s && s.language) || null, subtitlesOff: subtitleIndex === J.SUBTITLES_OFF };
}

/**
 * The place of stream `index` among the streams of its kind inside the file (0, 1, …), as a player numbers the
 * file's own tracks (HTMLMediaElement.audioTracks); null for a stream beside the file (external) or one not there.
 */
function ordinal(version, index) {
  const s = version.streams.find((x) => x.index === index);
  if (!s || s.external) return null;
  const list = version.streams.filter((x) => x.type === s.type && !x.external).sort((a, b) => a.index - b.index);
  const i = list.findIndex((x) => x.index === index);
  return i >= 0 ? i : null;
}

module.exports = { languageName, codecLabel, channelsLabel, audioLabel, fate, pickAudio, pickSubtitle, choiceOf, ordinal };
