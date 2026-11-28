'use strict';

/**
 * Medien (Stufe 4h): what a share's file names say (no Jellyfin, no server reads the files) — film or episode, the
 * title, the year, season and episode: `Kobaltnacht (2025).mkv`, `Graufeld.S02E04.Die.Fähre.1080p.mkv`,
 * `Graufeld/Staffel 1/03 - Nebel.mkv`. The same rules and test cases as Android's `ShareNames` (:core:media), plus the
 * keys two titles of different sources are compared and sorted by (Jellyfin wins a pair, decision of Stufe 4). Pure.
 */

const S = require('./media-share');

const VIDEO = S.VIDEO;
const IMAGE = S.IMAGE;

/** Folders that are not the film itself. */
const SKIP_DIRS = new Set(['sample', 'samples', 'extras', 'featurettes', 'trailers', 'behind the scenes', 'deleted scenes', 'system volume information']);

const SEP = '[ ._\\-\\[\\]()]';
const EPISODE = new RegExp(`(?:^|${SEP})s(\\d{1,2})${SEP}?e(\\d{1,3})(?:${SEP}?-?e\\d{1,3})*(?=$|${SEP})`, 'i');
const EPISODE_X = new RegExp(`(?:^|${SEP})(\\d{1,2})x(\\d{2,3})(?=$|${SEP})`, 'i');
const YEAR = new RegExp(`(?:^|${SEP})((?:19|20)\\d{2})(?=$|${SEP})`, 'g');
const JUNK = new RegExp(`(?:^|${SEP})(2160p|1080p|1080i|720p|576p|480p|4k|uhd|hdr10\\+?|hdr|dv|dovi|x26[45]|h\\.?26[45]|hevc|avc|xvid|divx|bluray|blu-ray|bdrip|brrip|`
  + `web-?dl|webrip|web|hdtv|dvdrip|remux|proper|repack|german|deutsch|english|multi|dl|ac3|dts|truehd|atmos|aac|ddp?5\\.1|10bit|extended|unrated)(?=$|${SEP})`, 'i');
const SEASON_DIR = /^(?:staffel|season|s)[ ._-]*(\d{1,2})$/i;
const LEADING_NUMBER = new RegExp(`^(\\d{1,3})(?:${SEP}+([\\s\\S]*))?$`);
const SAMPLE = new RegExp(`(?:^|${SEP})sample$`, 'i');
const TRIM_CHARS = new Set(['-', '–', ' ', '(', '[', '{', ')', ']', '}']);

const extension = (name) => S.extension(name);
const baseOf = (name) => {
  const n = String(name || '');
  const i = n.lastIndexOf('.');
  return i > 0 ? n.slice(0, i) : n;
};

const hidden = (name) => S.hidden(name);

function isSample(name) { return SAMPLE.test(baseOf(name)); }

function isVideo(name) { return !hidden(name) && VIDEO.includes(extension(name)) && !isSample(name); }

function isImage(name) { return !hidden(name) && IMAGE.includes(extension(name)); }

function skipDir(name) { return hidden(name) || SKIP_DIRS.has(String(name || '').toLowerCase()); }

/** "Staffel 2" / "Season 02" / "S2" → 2; null for any other folder. */
function seasonOfDir(name) {
  const m = SEASON_DIR.exec(String(name || '').trim());
  return m ? Number(m[1]) : null;
}

function trimEnds(s) {
  let a = 0;
  let b = s.length;
  while (a < b && TRIM_CHARS.has(s[a])) a += 1;
  while (b > a && TRIM_CHARS.has(s[b - 1])) b -= 1;
  return s.slice(a, b);
}

/** Dots and underscores to spaces, brackets and dashes off the ends. */
function clean(s) {
  return trimEnds(String(s || '').replace(/[._]/g, ' ').replace(/\s+/g, ' ').trim()).trim();
}

function beforeJunk(s) {
  const m = JUNK.exec(s);
  return m ? s.slice(0, m.index) : s;
}

/** The text before the year and the year ("Kobaltnacht (2025) 1080p" → ["Kobaltnacht ", 2025]); a title of only a year stays. */
function stripYear(s) {
  let last = null;
  for (const m of String(s).matchAll(YEAR)) if (m.index > 0) last = m;
  if (!last) return [s, null];
  const before = s.slice(0, last.index);
  if (!clean(before)) return [s, null];
  return [before, Number(last[1])];
}

/**
 * `fileName` in its folders (`dirs`: from the root down to its own folder) → { title, year, season, episode,
 * episodeName }. An episode needs `S01E02`, `1x02` or a number at the start inside a season folder; its series is the
 * text before, else the series' folder.
 */
function parse(fileName, dirs = []) {
  const name = String(fileName || '');
  const base = baseOf(name) || name;
  const parent = dirs.length ? dirs[dirs.length - 1] : null;
  const parentSeason = parent !== null ? seasonOfDir(parent) : null;
  const folder = parentSeason !== null ? (dirs.length > 1 ? dirs[dirs.length - 2] : null) : parent;
  const seriesFolder = folder !== null && folder !== undefined ? clean(stripYear(folder)[0]) : null;

  const ep = EPISODE.exec(base) || EPISODE_X.exec(base);
  if (ep) {
    const season = Number(ep[1]);
    const episode = Number(ep[2]);
    const before = clean(stripYear(base.slice(0, ep.index))[0]);
    const after = clean(beforeJunk(base.slice(ep.index + ep[0].length)));
    const series = before || seriesFolder || clean(base);
    return parsed(series, null, season, episode, after || null);
  }
  if (parentSeason !== null && seriesFolder) {
    const m = LEADING_NUMBER.exec(base.trim());
    if (m) {
      const epName = clean(beforeJunk(m[2] || ''));
      return parsed(seriesFolder, null, parentSeason, Number(m[1]), epName || null);
    }
  }
  const [title, year] = stripYear(base);
  const cleaned = clean(beforeJunk(title));
  return parsed(cleaned || clean(base), year, null, null, null);
}

function parsed(title, year, season, episode, episodeName) {
  return { title, year, season, episode, episodeName, isEpisode: season !== null && episode !== null };
}

/** The key two titles are the same by ("Die letzte Fähre nach Mirow" = "die.letzte.fähre.nach.mirow"). */
function key(name) {
  return String(name || '').toLowerCase().replace(/[^\p{L}\p{Nd}]/gu, '');
}

/** A–Z as Jellyfin sorts by default (an English article in front does not count). */
function sortKey(name) {
  const n = String(name || '').toLowerCase().trim();
  const article = ['the ', 'a ', 'an '].find((a) => n.startsWith(a) && n.length > a.length);
  const stripped = article ? n.slice(article.length) : n;
  const plain = stripped.replace(/ß/g, 'ss').normalize('NFD').replace(/\p{M}+/gu, '');
  return plain.replace(/[^\p{L}\p{Nd} ]/gu, '').replace(/ +/g, ' ').trim();
}

/**
 * „Im Ordner suchen“ (as Android's `ShareFolders.matches`): a file name (without its extension) or a folder's name
 * (`folder`) holds every word of `text`, in any case and spelling of accents ("fussball" finds "Fußball", "oma" finds
 * "Geburtstag.Oma.mkv").
 */
function matches(name, text, folder = false) {
  const words = sortKey(text).split(' ').filter(Boolean);
  if (!words.length) return false;
  const n = String(name || '');
  const dot = folder ? -1 : n.lastIndexOf('.');
  const base = dot > 0 ? n.slice(0, dot) : n;
  const hay = sortKey(base.replace(/[._]/g, ' '));
  return words.every((w) => hay.includes(w));
}

module.exports = { VIDEO, IMAGE, extension, hidden, isVideo, isImage, skipDir, seasonOfDir, clean, parse, key, sortKey, matches };
