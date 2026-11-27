'use strict';

/**
 * Medien (Stufe 4e): the REST API of one Jellyfin server (10.9+) — its own small client over https/axios as Drive, no
 * SDK. As Android's JellyfinClient / JellyfinLibrary / JellyfinSignIn (:core:media), the pure parts in
 * utils/media-jellyfin.js.
 *
 * The token goes in the `Authorization: MediaBrowser …` header, never in a logged URL; errors are logged by class
 * only. Every call answers { ok: true, value } or { ok: false, code } — code 'offline' (not reachable, timeout),
 * 'unauthorized' (401/403: sign in again), 'not_found', 'failed' (status), 'cert_untrusted' / 'cert_changed'.
 *
 *   JellyfinClient({ base, info, token?, net, way? })   way(): { localAddress, pin } of the connection now
 *   JellyfinLibrary({ source, client, caps? })          resume, latest, movies, series, seasons, episodes, views,
 *                                                       children ("Ordner"), latestMovies, latestEpisodes, nextUp,
 *                                                       favorites, collections, collection, genres, setFavorite, search,
 *                                                       detail, play, started/progress/stopped, setPlayed, measure,
 *                                                       authorize (Quick Connect code of another device)
 *   JellyfinSignIn({ client })                          server, quickConnectEnabled, quickConnect, confirmed,
 *                                                       signInQuick, signIn (name, password: sent once, never kept)
 */

const J = require('../utils/media-jellyfin');
const MediaNet = require('./media-net');

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const ok = (value) => ({ ok: true, value });
const no = (code, status = null) => ({ ok: false, code, status });
const map = (r, f) => (r.ok ? ok(f(r.value)) : r);
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** An id of Jellyfin (32 hex, some servers with dashes) — never a path. */
function idOk(id) { return typeof id === 'string' && J.ID_RE.test(id); }

class JellyfinClient {
  /**
   * @param {object} opts
   * @param {string} opts.base - the server's base URL (utils/media-address normalize)
   * @param {object} opts.info - { client, device, deviceId, version }
   * @param {string} [opts.token]
   * @param {object} opts.net - MediaNet
   * @param {() => { localAddress?: string|null, pin?: string|null }} [opts.way]
   * @param {object} [opts.log]
   */
  constructor({ base, info, token = null, net, way = null, log = null }) {
    this.base = String(base).replace(/\/+$/, '');
    this.info = info;
    this.token = token;
    this.net = net;
    this.way = typeof way === 'function' ? way : () => ({});
    this.log = log || noopLog();
  }

  authorization() { return J.authorization(this.info, this.token); }

  url(path, query) { return J.url(this.base, path, query); }

  absolute(relative) { return J.absolute(this.base, relative); }

  _way() {
    const w = this.way() || {};
    return { localAddress: w.localAddress || null, pin: w.pin || null, blocked: w.blocked === true };
  }

  async call(method, path, query = {}, body = undefined, { timeout = 15000 } = {}) {
    const u = this.url(path, query);
    let res;
    try {
      res = await this.net.request({
        method,
        url: u,
        headers: {
          Authorization: this.authorization(),
          Accept: 'application/json',
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        data: body !== undefined ? JSON.stringify(body) : (method === 'POST' ? '' : undefined),
        responseType: 'text',
        timeout,
        maxBytes: 32 * 1024 * 1024,
        ...this._way(),
      });
    } catch (err) {
      const e = MediaNet.toError(err);
      this.log.debug(`Jellyfin: ${String(path).split('/')[0]} not reached (${e.code})`);
      return no(e.code === 'timeout' || e.code === 'failed' ? 'offline' : e.code);
    }
    const s = res.status;
    if (s === 401 || s === 403) return no('unauthorized', s);
    if (s === 404) return no('not_found', s);
    if (s < 200 || s >= 300) return no('failed', s);
    const text = typeof res.data === 'string' ? res.data : res.data == null ? '' : JSON.stringify(res.data);
    if (!text.trim()) return ok(null);
    try { return ok(JSON.parse(text)); } catch { return no('failed', s); }
  }

  get(path, query) { return this.call('GET', path, query); }

  post(path, query, body) { return this.call('POST', path, query, body); }

  delete(path, query) { return this.call('DELETE', path, query); }

  /** `GET` of `path` read to its end: the bit/s, or null when it did not work. */
  async measure(path, query, { now = () => process.hrtime.bigint(), timeout = 20000 } = {}) {
    let res;
    try {
      res = await this.net.request({ method: 'GET', url: this.url(path, query), headers: { Authorization: this.authorization() }, responseType: 'stream', timeout, ...this._way() });
    } catch (err) {
      this.log.debug(`Jellyfin: bandwidth not measured (${MediaNet.toError(err).code})`);
      return null;
    }
    if (res.status < 200 || res.status >= 300) { try { res.data.destroy(); } catch { /* ignore */ } return null; }
    return new Promise((resolve) => {
      let total = 0;
      let start = null;
      const timer = setTimeout(() => { try { res.data.destroy(); } catch { /* ignore */ } finish(); }, timeout);
      const finish = () => {
        clearTimeout(timer);
        if (start === null || total <= 0) { resolve(null); return; }
        const nanos = Number(now() - start) || 1;
        resolve(Math.floor((total * 8 * 1e9) / Math.max(1, nanos)));
      };
      res.data.on('data', (c) => { if (start === null) start = now(); total += c.length; });
      res.data.once('end', finish);
      res.data.once('error', () => { clearTimeout(timer); resolve(null); });
    });
  }

  /** A stream of the server for the player (gcmedia:, services/media-stream.js): the access in the header. */
  stream(absUrl, { headers = {}, signal, timeout = 30000 } = {}) {
    return this.net.request({ method: 'GET', url: absUrl, headers: { ...headers, Authorization: this.authorization() }, responseType: 'stream', signal, timeout, ...this._way() });
  }
}

class JellyfinLibrary {
  /**
   * @param {object} opts
   * @param {object} opts.source - the stored source (userId, token)
   * @param {JellyfinClient} opts.client
   * @param {() => object} [opts.caps] - J.capsOf() of the page
   * @param {object} [opts.log]
   */
  constructor({ source, client, caps = null, log = null }) {
    this.source = source;
    this.client = client;
    this.caps = typeof caps === 'function' ? caps : () => J.DEFAULT_CAPS;
    this.log = log || noopLog();
  }

  get user() { return this.source.userId || ''; }

  _items(r) { return map(r, (e) => J.items(e, this.source.id)); }

  async resume(limit = 12) {
    return this._items(await this.client.get('UserItems/Resume', {
      userId: this.user, limit, mediaTypes: 'Video', fields: J.FIELDS, enableUserData: true, enableImageTypes: J.IMAGES,
    }));
  }

  async latest(limit = 16) {
    return this._items(await this.client.get('Items/Latest', {
      userId: this.user, limit, includeItemTypes: 'Movie,Series', fields: J.FIELDS, enableUserData: true, enableImageTypes: J.IMAGES,
    }));
  }

  /** "Neue Filme": only films (before, films and series came mixed in one row). */
  async latestMovies(limit = 16) {
    return this._items(await this.client.get('Items/Latest', {
      userId: this.user, limit, includeItemTypes: 'Movie', fields: J.FIELDS, enableUserData: true, enableImageTypes: J.IMAGES,
    }));
  }

  /** "Neue Folgen": new episodes grouped per series (groupItems: "3 neu" on the series). */
  async latestEpisodes(limit = 16) {
    return map(await this.client.get('Items/Latest', {
      userId: this.user, limit, includeItemTypes: 'Episode', groupItems: true, fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableImageTypes: J.IMAGES,
    }), (e) => J.latestEpisodes(e, this.source.id));
  }

  /**
   * "Als Nächstes" (Shows/NextUp): the next unseen episode of each series begun → { items, total }; half-watched ones
   * stay in "Weiterschauen" (enableResumable=false), series seen through are not started again.
   */
  async nextUp(limit = 16) {
    return map(await this.client.get('Shows/NextUp', {
      userId: this.user, limit, fields: `${J.FIELDS},Overview`, enableUserData: true, enableImageTypes: J.IMAGES,
      enableTotalRecordCount: true, enableResumable: false, enableRewatching: false,
    }), (e) => { const list = J.items(e, this.source.id); return { items: list, total: J.total(e) ?? list.length }; });
  }

  /** The person's favourites (filters=IsFavorite): films, series and episodes, A–Z → { items, total }. */
  async favorites(limit = 20) {
    return map(await this.client.get('Items', {
      userId: this.user, filters: 'IsFavorite', includeItemTypes: 'Movie,Series,Episode', recursive: true, sortBy: 'SortName', sortOrder: 'Ascending',
      limit, fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableTotalRecordCount: true, enableImageTypes: J.IMAGES,
    }), (e) => { const list = J.items(e, this.source.id, { seriesPoster: true }); return { items: list, total: J.total(e) ?? list.length }; });
  }

  /** "Sammlungen": the box sets (film series), A–Z, with how many titles each holds → { items, total }. */
  async collections(limit = 20) {
    return map(await this.client.get('Items', {
      userId: this.user, includeItemTypes: 'BoxSet', recursive: true, sortBy: 'SortName', sortOrder: 'Ascending', limit,
      fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableTotalRecordCount: true, enableImageTypes: J.IMAGES,
    }), (e) => { const list = J.items(e, this.source.id).filter((t) => t.kind === 'collection'); return { items: list, total: J.total(e) ?? list.length }; });
  }

  /** A collection's titles, oldest first (a film series in its order). */
  async collection(id) {
    if (!idOk(id)) return no('not_found');
    return map(await this.client.get('Items', {
      userId: this.user, parentId: id, sortBy: 'ProductionYear,SortName', sortOrder: 'Ascending', limit: 500,
      fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableImageTypes: J.IMAGES,
    }), (e) => J.items(e, this.source.id).filter((t) => t.kind !== 'collection'));
  }

  /** The genres of the films (or series), A–Z: the tiles of "Genres". */
  async genres(movies = true) {
    return map(await this.client.get('Genres', { userId: this.user, includeItemTypes: movies ? 'Movie' : 'Series', recursive: true, sortBy: 'SortName' }), (e) => J.genreNames(e));
  }

  /** The heart: kept in Jellyfin for this person (the same on all devices). */
  async setFavorite(itemId, favorite) {
    if (!idOk(itemId)) return no('not_found');
    const path = `UserFavoriteItems/${itemId}`;
    const q = { userId: this.user };
    return map(await (favorite ? this.client.post(path, q) : this.client.delete(path, q)), () => true);
  }

  movies(start, limit, sort) { return this._page('Movie', start, limit, sort); }

  series(start, limit, sort) { return this._page('Series', start, limit, sort); }

  /** sort: 'name' (A–Z), 'added' (zuletzt hinzugefügt), 'year'; filter unplayed / genre as the chips of the page. */
  async _page(type, start, limit, { sort = 'name', unplayed = false, genre = null, favorite = false } = {}) {
    // a series counts as added when its last episode came ("Neue Folgen ›")
    const added = type === 'Series' ? 'DateLastContentAdded,SortName' : 'DateCreated,SortName';
    const by = sort === 'added' ? [added, 'Descending'] : sort === 'year' ? ['ProductionYear,SortName', 'Descending'] : ['SortName', 'Ascending'];
    const filters = [unplayed ? 'IsUnplayed' : null, favorite ? 'IsFavorite' : null].filter(Boolean).join(',') || null;
    const r = await this.client.get('Items', {
      userId: this.user, includeItemTypes: type, recursive: true, sortBy: by[0], sortOrder: by[1], startIndex: start, limit,
      fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableTotalRecordCount: true, enableImageTypes: J.IMAGES,
      filters, genres: typeof genre === 'string' && genre ? genre.slice(0, 64) : null,
    });
    return map(r, (e) => {
      const list = J.items(e, this.source.id);
      const page = { items: list, total: J.total(e) ?? start + list.length, start };
      return { ...page, next: J.nextOf(page) };
    });
  }

  async seasons(seriesId) {
    if (!idOk(seriesId)) return no('not_found');
    return this._items(await this.client.get(`Shows/${seriesId}/Seasons`, { userId: this.user, fields: J.FIELDS, enableUserData: true }));
  }

  async episodes(seriesId, seasonId = null) {
    if (!idOk(seriesId) || (seasonId !== null && !idOk(seasonId))) return no('not_found');
    return this._items(await this.client.get(`Shows/${seriesId}/Episodes`, { userId: this.user, seasonId, fields: `${J.FIELDS},Overview`, enableUserData: true }));
  }

  /** "Ordner": the person's libraries (`/UserViews`), those with video → { folders, items: [] }. */
  async views() {
    return map(await this.client.get('UserViews', { userId: this.user }), (e) => ({ folders: J.views(e), items: [] }));
  }

  /** "Ordner": what a library or folder holds, A–Z (at most `limit`) → { folders, items, total }. */
  async children(parentId, limit = 500) {
    if (!idOk(parentId)) return no('not_found');
    return map(await this.client.get('Items', {
      userId: this.user, parentId, sortBy: 'SortName', sortOrder: 'Ascending', limit,
      fields: `${J.FIELDS},ChildCount`, enableUserData: true, enableTotalRecordCount: true, enableImageTypes: J.IMAGES,
    }), (e) => J.folderPage(e, this.source.id));
  }

  /** "In allen Quellen suchen": films, series and episodes whose name has `q`. */
  async search(q, limit = 40) {
    const term = typeof q === 'string' ? q.trim().slice(0, 100) : '';
    if (!term) return ok([]);
    return this._items(await this.client.get('Items', {
      userId: this.user, searchTerm: term, includeItemTypes: 'Movie,Series,Episode', recursive: true, limit,
      fields: J.FIELDS, enableUserData: true, enableImageTypes: J.IMAGES,
    }));
  }

  async detail(itemId) {
    if (!idOk(itemId)) return no('not_found');
    const r = await this.client.get(`Items/${itemId}`, { userId: this.user });
    if (!r.ok) return r;
    if (!isObj(r.value)) return no('failed', 200);
    const t = J.title(r.value, this.source.id);
    if (!t) return no('not_found');
    return ok({ title: t, versions: J.versions(r.value) });
  }

  /** How `play` is sent (the server decides with the device profile and the bit rate) → the plan. */
  async play(play) {
    if (!play || !idOk(play.itemId) || (play.versionId && !idOk(play.versionId))) return no('not_found');
    const body = J.playbackBody(play, this.caps(), this.user);
    const r = await this.client.post(`Items/${play.itemId}/PlaybackInfo`, { userId: this.user }, body);
    if (!r.ok) return r;
    const o = r.value;
    if (!isObj(o)) return no('failed', 200);
    if (J.str(o, 'ErrorCode')) {
      this.log.debug(`Jellyfin: playback refused (${J.str(o, 'ErrorCode')})`);
      return no('failed', 200);
    }
    const vs = J.versions(o);
    const v = vs.find((x) => x.id === play.versionId) || vs[0];
    if (!v) return no('not_found');
    const p = J.plan(this.client.base, play, v, J.str(o, 'PlaySessionId'), this.client.info.deviceId);
    return p ? ok(p) : no('failed', 200);
  }

  async _report(path, body) {
    const r = await this.client.post(path, {}, body);
    if (!r.ok) this.log.debug(`Jellyfin: ${path} not taken (${r.code})`);
    return r.ok ? ok(true) : r;
  }

  started(p) { return this._report('Sessions/Playing', J.progressBody(p)); }

  progress(p) { return this._report('Sessions/Playing/Progress', J.progressBody(p)); }

  stopped(p) { return this._report('Sessions/Playing/Stopped', J.progressBody(p, true)); }

  async setPlayed(itemId, played) {
    if (!idOk(itemId)) return no('not_found');
    const path = `UserPlayedItems/${itemId}`;
    const q = { userId: this.user };
    return map(await (played ? this.client.post(path, q) : this.client.delete(path, q)), () => true);
  }

  /** The bit/s from the server to this PC just now; null when it could not be measured. */
  measure(bytes = J.MEASURE_BYTES) { return this.client.measure('Playback/BitrateTest', { size: bytes }); }

  /**
   * "Gerät anmelden": the Quick Connect code shown on another device (TV, PC) confirmed with this PC's access
   * (Jellyfin 10.8+). → { ok: true } | { ok: false, code: 'invalid' | 'not_found' (no such code) | … }.
   */
  async authorize(code) {
    const c = J.quickConnectCode(code);
    if (!c) return no('invalid');
    const r = await this.client.post('QuickConnect/Authorize', { code: c, userId: this.user || null });
    if (!r.ok) return r;
    return r.value === false ? no('not_found') : ok(true);
  }
}

class JellyfinSignIn {
  constructor({ client }) { this.client = client; }

  async server() {
    const r = await this.client.get('System/Info/Public');
    if (!r.ok) return r;
    const s = isObj(r.value) ? J.serverInfo(r.value) : null;
    return s ? ok(s) : no('failed', 200);
  }

  async quickConnectEnabled() {
    const r = await this.client.get('QuickConnect/Enabled');
    return r.ok && r.value === true;
  }

  async quickConnect() {
    const r = await this.client.post('QuickConnect/Initiate');
    if (!r.ok) return r;
    const q = isObj(r.value) ? J.quickConnect(r.value) : null;
    return q ? ok(q) : no('failed', 200);
  }

  /** Whether the code was confirmed in Jellyfin (or on another GateControl device). */
  async confirmed(q) {
    return map(await this.client.get('QuickConnect/Connect', { secret: q.secret }), (e) => isObj(e) && e.Authenticated === true);
  }

  async signInQuick(q) { return this._auth(await this.client.post('Users/AuthenticateWithQuickConnect', {}, { Secret: q.secret })); }

  async signIn(name, password) { return this._auth(await this.client.post('Users/AuthenticateByName', {}, { Username: String(name || ''), Pw: String(password || '') })); }

  _auth(r) {
    if (!r.ok) return r;
    const a = isObj(r.value) ? J.auth(r.value) : null;
    return a ? ok(a) : no('failed', 200);
  }
}

module.exports = { JellyfinClient, JellyfinLibrary, JellyfinSignIn, idOk };
