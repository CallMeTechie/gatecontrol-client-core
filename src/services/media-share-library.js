'use strict';

/**
 * Medien (Stufe 4h): an SMB or WebDAV share as a library — its films and series from the folders (utils/
 * media-share-index.js: the file names and the pictures beside them), always played as the original (no converting),
 * the progress kept on this PC (MediaStore; Jellyfin keeps its own). As Android's `ShareLibrary` (:core:media).
 *
 * `fs()` gives the share to read now: of a pair SMB + WebDAV the one of the network now (MediaService._shareFor); the
 * titles stay under the share's id either way, so does the progress. Every method resolves { ok, value } or
 * { ok: false, code }.
 */

const SI = require('../utils/media-share-index');
const N = require('../utils/media-share-names');

const INDEX_MS = 10 * 60 * 1000;   // the folders are read again after this long (a new film on the NAS shows up)
const PLAYED_SHARE = 0.9;          // watched to here (90 %, as Jellyfin): "gesehen"
const MIN_RESUME_MS = 30 * 1000;   // less than this from the start is no place to go on from
const SORTS = ['name', 'added', 'year'];

const ok = (value) => ({ ok: true, value });
const no = (code) => ({ ok: false, code });

/** The order of a grid: A–Z (as Jellyfin sorts), newest first, or the latest year first; then A–Z. */
function comparator(sort) {
  const byName = (a, b) => {
    const x = N.sortKey(a.name);
    const y = N.sortKey(b.name);
    return x < y ? -1 : x > y ? 1 : 0;
  };
  if (sort === 'added') return (a, b) => (b.addedAt || 0) - (a.addedAt || 0) || byName(a, b);
  if (sort === 'year') return (a, b) => (b.year || 0) - (a.year || 0) || byName(a, b);
  return byName;
}

/** Not watched yet: a film or episode not played, a series with episodes left. */
function unwatched(t) {
  if (t.kind === 'series' || t.kind === 'season') return Number.isInteger(t.unplayed) ? t.unplayed > 0 : !t.played;
  return !t.played;
}

/** The titles whose name (or series' name) holds `text` (letters and digits, no case); those starting with it first. */
function search(items, text) {
  const q = N.key(text);
  if (!q) return [];
  return items.filter((t) => N.key(t.name).includes(q) || N.key(t.seriesName).includes(q))
    .map((t, i) => ({ t, i, starts: N.key(t.name).startsWith(q) ? 0 : 1, sk: N.sortKey(t.name) }))
    .sort((a, b) => a.starts - b.starts || (a.sk < b.sk ? -1 : a.sk > b.sk ? 1 : 0) || a.i - b.i)
    .map((x) => x.t);
}

class ShareLibrary {
  /**
   * @param {object} o
   * @param {string} o.sourceId - the share (of a pair: the one the titles carry)
   * @param {() => object|null} o.fs - SmbShare / WebDavShare to read now
   * @param {object} o.store - MediaStore (progress)
   * @param {() => number} [o.now]
   * @param {(n: number) => string} [o.seasonName]
   */
  constructor({ sourceId, fs, store, now = Date.now, seasonName }) {
    this.sourceId = sourceId;
    this.fs = fs;
    this.store = store;
    this.now = now;
    this.seasonName = seasonName;
    this._index = null;
    this._indexedAt = 0;
    this._scanning = null;
  }

  /** The share's index, read again after INDEX_MS (`force`: now); offline, what was found before is still right. */
  async index(force = false) {
    if (this._index && !force && this.now() - this._indexedAt < INDEX_MS) return ok(this._index);
    if (this._scanning) return this._scanning;
    this._scanning = (async () => {
      const fsx = this.fs();
      if (!fsx) return no('not_found');
      const r = await SI.scan(fsx, this.sourceId, { seasonName: this.seasonName });
      if (r.ok) {
        this._index = r.value;
        this._indexedAt = this.now();
        return r;
      }
      return this._index && (r.code === 'offline' || r.code === 'timeout') ? ok(this._index) : r;
    })().finally(() => { this._scanning = null; });
    return this._scanning;
  }

  key(path) { return `${this.sourceId}|${path}`; }

  _all() { return this.store.all(`${this.sourceId}|`); }

  /** `t` with where it was left (a film or episode) or its unwatched episodes (a series, a season). */
  withProgress(t, all, idx) {
    const path = SI.pathOf(t.id);
    if (path) {
      const p = all[this.key(path)];
      if (!p) return t;
      return { ...t, positionMs: p.played ? 0 : p.positionMs, runtimeMs: p.durationMs > 0 ? p.durationMs : t.runtimeMs, played: p.played, playedAt: p.at > 0 ? p.at : null };
    }
    if (t.kind === 'series' || t.kind === 'season') {
      const eps = (idx.episodes.get(t.seriesId || t.id) || []).filter((e) => t.kind === 'series' || e.season === t.season);
      const unplayed = eps.filter((e) => { const p = all[this.key(SI.pathOf(e.id))]; return !(p && p.played); }).length;
      return { ...t, unplayed, played: eps.length > 0 && unplayed === 0 };
    }
    return t;
  }

  async _with(fn) {
    const r = await this.index();
    if (!r.ok) return r;
    const all = this._all();
    return ok(fn(r.value, all, (t) => this.withProgress(t, all, r.value)));
  }

  resume(limit) {
    return this._with((i, _all, wp) => [...i.movies, ...[...i.episodes.values()].flat()].map(wp)
      .filter((t) => t.positionMs > 0 && !t.played)
      .sort((a, b) => (b.playedAt || 0) - (a.playedAt || 0))
      .slice(0, limit));
  }

  latest(limit) {
    return this._with((i, _all, wp) => [...i.movies, ...i.series].map(wp).sort((a, b) => (b.addedAt || 0) - (a.addedAt || 0)).slice(0, limit));
  }

  _page(list, start, limit, o) {
    const sorted = list.filter((t) => (!o.unplayed || unwatched(t)) && (!o.genre)).sort(comparator(SORTS.includes(o.sort) ? o.sort : 'name'));
    const items = sorted.slice(start, start + limit);
    return { items, total: sorted.length, start, next: start + items.length < sorted.length ? start + items.length : null };
  }

  movies(start, limit, o = {}) { return this._with((i, _a, wp) => this._page(i.movies.map(wp), start, limit, o)); }

  series(start, limit, o = {}) { return this._with((i, _a, wp) => this._page(i.series.map(wp), start, limit, o)); }

  seasons(sid) { return this._with((i, _a, wp) => i.seasons(sid).map(wp)); }

  episodes(sid, seasonId = null) {
    return this._with((i, _a, wp) => (i.episodes.get(sid) || []).filter((e) => !seasonId || e.seasonId === seasonId).map(wp));
  }

  search(q) { return this._with((i, _a, wp) => search([...i.movies, ...i.series], q).slice(0, 60).map(wp)); }

  /**
   * „Im Ordner suchen“ (as Android's `ShareLibrary.searchBelow`): the videos of the index below folder `dir` ("" the
   * root) whose file name holds every word of `text`, A–Z, at most `limit` → the index's records ({ path, parsed, … }).
   */
  searchBelow(dir, text, limit = 60) {
    const prefix = dir ? `${dir}/` : '';
    return this._with((i) => i.videos
      .filter((v) => v.path.startsWith(prefix) && N.matches(v.path.slice(v.path.lastIndexOf('/') + 1), text))
      .map((v) => ({ v, sk: N.sortKey(v.path.slice(v.path.lastIndexOf('/') + 1)) }))
      .sort((a, b) => (a.sk < b.sk ? -1 : a.sk > b.sk ? 1 : 0) || (a.v.path < b.v.path ? -1 : a.v.path > b.v.path ? 1 : 0))
      .slice(0, limit)
      .map((x) => x.v));
  }

  /** A film or episode with its one version (the file as it is), or a series without one. */
  async detail(itemId) {
    const r = await this.index();
    if (!r.ok) return r;
    const i = r.value;
    const all = this._all();
    const file = i.file(itemId);
    if (file) {
      const path = SI.pathOf(itemId);
      const v = i.video(path);
      const t = this.withProgress(file, all, i);
      return ok({ title: t, path, size: v ? v.size : 0, container: N.extension(path) || null });
    }
    const series = i.seriesTitle(itemId);
    return series ? ok({ title: this.withProgress(series, all, i), path: null }) : no('not_found');
  }

  /**
   * Where the player is (start, progress, stop): watched to 90 % is "gesehen"; less than 30 s from the start is no
   * place to go on from; a short look into a file already watched does not take "gesehen" away.
   */
  keep(path, positionMs, durationMs) {
    const k = this.key(path);
    const old = this.store.progress(k);
    const duration = durationMs > 0 ? durationMs : (old ? old.durationMs : 0);
    const played = duration > 0 && positionMs >= duration * PLAYED_SHARE;
    const position = played || positionMs < MIN_RESUME_MS ? 0 : positionMs;
    this.store.setProgress(k, { positionMs: position, durationMs: duration, played: played || (!!(old && old.played) && position === 0), at: this.now() });
  }

  setPlayed(path, played) {
    const k = this.key(path);
    const old = this.store.progress(k);
    this.store.setProgress(k, { positionMs: 0, durationMs: old ? old.durationMs : 0, played: played === true, at: this.now() });
    return ok(true);
  }

  /** The cached index (the folder view takes the titles of its files from it), or null. */
  cached() { return this._index; }

  drop() { this._index = null; this._indexedAt = 0; }
}

ShareLibrary.INDEX_MS = INDEX_MS;
ShareLibrary.MIN_RESUME_MS = MIN_RESUME_MS;
ShareLibrary.PLAYED_SHARE = PLAYED_SHARE;
ShareLibrary.comparator = comparator;
ShareLibrary.search = search;
ShareLibrary.unwatched = unwatched;

module.exports = ShareLibrary;
