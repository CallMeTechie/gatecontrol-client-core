'use strict';

/**
 * Medien (Stufe 4h): the films and series of a share as the rows want them — made from its folders (the file names,
 * the pictures beside them: Kodi's and Jellyfin's names), as Android's `ShareIndex` (:core:media). Titles have the
 * shape of Jellyfin's (utils/media-jellyfin.js title()) with `fromShare: true`; their ids:
 *
 *   f:<path>        a film or episode (the file below the share's root)
 *   s:<key>         a series (ShareNames.key of its name)
 *   s:<key>:<n>     its season n
 *
 * posterId / backdropId are paths of pictures in the share (posterTag 'share'). The progress is not here: the service
 * adds the one of this PC. `scan()` reads the folders from the root down (at most MAX_DEPTH deep, MAX_DIRS folders,
 * MAX_FILES videos, PARALLEL folders at once); the rest is pure.
 */

const crypto = require('crypto');
const N = require('./media-share-names');
const S = require('./media-share');

const MAX_DEPTH = 6;
const MAX_DIRS = 600;
const MAX_FILES = 8000;
const PARALLEL = 4;
const SHARE_TAG = 'share';
// a share item's id as the IPC takes it: a file path (no control characters) or a series / season key
// eslint-disable-next-line no-control-regex
const ITEM_ID_RE = /^(?:f:[^\u0000-\u001f\u007f]{1,1024}|s:[\p{L}\p{Nd}]{1,200}(?::\d{1,3})?|s:#[0-9a-f]{16}(?::\d{1,3})?)$/u;

const fileId = (path) => `f:${path}`;
const pathOf = (id) => (typeof id === 'string' && id.startsWith('f:') ? S.clean(id.slice(2)) || null : null);
/** "s:" + the series' key (a name without letters or digits: a hash of it). */
function seriesId(name) {
  const k = N.key(name);
  return k ? `s:${k.slice(0, 200)}` : `s:#${crypto.createHash('sha256').update(String(name || '')).digest('hex').slice(0, 16)}`;
}
const isItemId = (id) => typeof id === 'string' && ITEM_ID_RE.test(id);
const lowerBase = (name) => {
  const i = name.lastIndexOf('.');
  return (i > 0 ? name.slice(0, i) : name).toLowerCase();
};

/** The pictures of one folder by their name without extension (`poster` → `Filme/poster.jpg`). */
function imagesOf(entries) {
  const out = new Map();
  for (const e of entries) if (!e.directory && N.isImage(e.name)) out.set(lowerBase(e.name), e.path);
  return out;
}

const firstOf = (images, names) => {
  for (const n of names) if (images.has(n)) return images.get(n);
  return null;
};

/**
 * The videos of one folder (`names`: the folder names from the root down) with the pictures beside them;
 * `parentImages`: the pictures of the folder above when this is a season folder (the series' poster is there).
 */
function videosOf(names, entries, parentImages = null) {
  const images = imagesOf(entries);
  const files = entries.filter((e) => !e.directory && N.isVideo(e.name));
  const alone = files.length === 1;
  return files.map((f) => {
    const base = lowerBase(f.name);
    const parsed = N.parse(f.name, names);
    const folderPoster = firstOf(images, ['poster', 'folder', 'cover']);
    const poster = firstOf(images, [`${base}-poster`, base, `${base}-thumb`, `${base}-cover`])
      || (alone && !parsed.isEpisode ? folderPoster : null);
    const backdrop = firstOf(images, [`${base}-fanart`, `${base}-backdrop`])
      || ((alone || parsed.isEpisode) ? firstOf(images, ['fanart', 'backdrop']) : null);
    let seriesPoster = null;
    if (parsed.isEpisode) seriesPoster = (parentImages && firstOf(parentImages, ['poster', 'folder', 'cover'])) || folderPoster;
    return { path: f.path, parsed, size: f.size || 0, modifiedAt: Number.isFinite(f.modifiedAt) ? f.modifiedAt : null, poster, backdrop, seriesPoster };
  });
}

/** An episode in a season folder takes the picture of its series' folder above, when its own folder has none. */
function attachSeriesPosters(videos) {
  const posterOf = new Map();
  for (const v of videos) {
    if (!v.parsed.isEpisode) continue;
    const id = seriesId(v.parsed.title);
    if (!posterOf.get(id) && v.seriesPoster) posterOf.set(id, v.seriesPoster);
  }
  return videos.map((v) => (v.parsed.isEpisode && !v.seriesPoster ? { ...v, seriesPoster: posterOf.get(seriesId(v.parsed.title)) || null } : v));
}

function base(sourceId, kind, name) {
  return {
    id: null, sourceId, kind, name: String(name || '').slice(0, 200), year: null, runtimeMs: null, positionMs: 0, played: false,
    seriesId: null, seriesName: null, seasonId: null, season: null, episode: null, overview: null, genres: [], rating: null,
    childCount: null, unplayed: null, posterId: null, posterTag: SHARE_TAG, backdropId: null, backdropTag: SHARE_TAG,
    addedAt: null, playedAt: null, fromShare: true,
  };
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

class ShareIndex {
  /**
   * @param {string} sourceId
   * @param {object[]} videos - videosOf() of the folders
   * @param {(n: number) => string} [seasonName]
   */
  constructor(sourceId, videos, seasonName = (n) => `Staffel ${n}`) {
    this.sourceId = sourceId;
    this.videos = videos;
    this.seasonName = seasonName;
    this.byPath = new Map(videos.map((v) => [v.path, v]));
    this.movies = videos.filter((v) => !v.parsed.isEpisode).map((v) => this._movie(v))
      .sort((a, b) => cmp(N.sortKey(a.name), N.sortKey(b.name)) || (a.year || 0) - (b.year || 0) || cmp(a.id, b.id));
    this.episodes = new Map();
    for (const v of videos) {
      if (!v.parsed.isEpisode) continue;
      const id = seriesId(v.parsed.title);
      if (!this.episodes.has(id)) this.episodes.set(id, []);
      this.episodes.get(id).push(this._episode(v));
    }
    for (const list of this.episodes.values()) list.sort((a, b) => (a.season || 0) - (b.season || 0) || (a.episode || 0) - (b.episode || 0) || cmp(a.id, b.id));
    this.series = [...this.episodes.entries()].map(([id, list]) => {
      const first = list[0];
      const pic = (pick) => { for (const e of list) { const p = pick(this.byPath.get(pathOf(e.id))); if (p) return p; } return null; };
      const added = list.map((e) => e.addedAt).filter((x) => Number.isFinite(x));
      return {
        ...base(this.sourceId, 'series', first.seriesName || first.name),
        id,
        childCount: new Set(list.map((e) => e.season)).size,
        posterId: pic((v) => v && v.seriesPoster) || pic((v) => v && v.poster),
        backdropId: pic((v) => v && v.backdrop),
        addedAt: added.length ? Math.max(...added) : null,
      };
    }).sort((a, b) => cmp(N.sortKey(a.name), N.sortKey(b.name)) || cmp(a.id, b.id));
    this._seriesById = new Map(this.series.map((s) => [s.id, s]));
  }

  _movie(v) {
    return {
      ...base(this.sourceId, 'movie', v.parsed.title),
      id: fileId(v.path), year: v.parsed.year, posterId: v.poster, backdropId: v.backdrop, addedAt: v.modifiedAt,
    };
  }

  _episode(v) {
    const sid = seriesId(v.parsed.title);
    return {
      ...base(this.sourceId, 'episode', v.parsed.episodeName || v.parsed.title),
      id: fileId(v.path),
      seriesId: sid,
      seriesName: v.parsed.title.slice(0, 200),
      seasonId: `${sid}:${v.parsed.season || 0}`,
      season: v.parsed.season,
      episode: v.parsed.episode,
      // an episode without its own picture shows its series' (as in Jellyfin)
      posterId: v.poster || v.seriesPoster,
      backdropId: v.backdrop,
      addedAt: v.modifiedAt,
    };
  }

  video(path) { return this.byPath.get(path) || null; }

  /** A film or episode by its id (f:…). */
  file(id) {
    const v = this.byPath.get(pathOf(id));
    if (!v) return null;
    return v.parsed.isEpisode ? this._episode(v) : this._movie(v);
  }

  seriesTitle(id) { return this._seriesById.get(id) || null; }

  /** The seasons of a series as titles (`episode` carries the number, as Jellyfin's IndexNumber of a season). */
  seasons(sid) {
    const list = this.episodes.get(sid) || [];
    const series = this.seriesTitle(sid);
    const nums = [...new Set(list.map((e) => e.season || 0))].sort((a, b) => a - b);
    return nums.map((n) => ({
      ...base(this.sourceId, 'season', this.seasonName(n)),
      id: `${sid}:${n}`, seriesId: sid, seriesName: series ? series.name : null, season: n, episode: n,
      posterId: series ? series.posterId : null,
    }));
  }
}

/**
 * The share's videos from its root (`fsx.list(dir)` → { ok, value: [{ name, path, directory, size, modifiedAt }] }).
 * The root not reachable (or refused) is the answer; a folder below that fails is left out.
 */
async function scan(fsx, sourceId, { seasonName, maxDepth = MAX_DEPTH, maxDirs = MAX_DIRS, maxFiles = MAX_FILES, parallel = PARALLEL } = {}) {
  const root = await fsx.list('');
  if (!root.ok) return root;
  let videos = [];
  let dirs = 1;
  let depth = 0;
  let level = [{ dir: '', names: [], entries: root.value }];
  const imagesByDir = new Map();
  while (level.length && videos.length < maxFiles) {
    const next = [];
    for (const { dir, names, entries } of level) {
      imagesByDir.set(dir, imagesOf(entries));
      // a season folder: the series' picture is in the folder above
      const above = names.length && N.seasonOfDir(names[names.length - 1]) !== null ? imagesByDir.get(S.parent(dir)) || null : null;
      videos = videos.concat(videosOf(names, entries, above));
      if (depth < maxDepth) {
        for (const e of entries) {
          if (e.directory && !N.skipDir(e.name) && dirs < maxDirs) {
            dirs += 1;
            next.push({ dir: e.path, names: names.concat(e.name) });
          }
        }
      }
    }
    depth += 1;
    const found = new Array(next.length).fill(null);
    let at = 0;
    const worker = async () => {
      while (at < next.length) {
        const i = at++;
        const r = await fsx.list(next[i].dir).catch(() => null);
        if (r && r.ok) found[i] = { ...next[i], entries: r.value };
      }
    };
    await Promise.all(Array.from({ length: Math.min(parallel, next.length) }, worker));
    level = found.filter(Boolean);
  }
  return { ok: true, value: new ShareIndex(sourceId, attachSeriesPosters(videos).slice(0, maxFiles), seasonName) };
}

module.exports = {
  MAX_DEPTH, MAX_DIRS, MAX_FILES, SHARE_TAG, ITEM_ID_RE, ShareIndex, scan, videosOf, imagesOf, fileId, pathOf, seriesId, isItemId,
};
