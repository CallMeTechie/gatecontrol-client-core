'use strict';

/**
 * IPC of "Medien" (Stufe 4e; opt-in: registerBaseHandlers(…, { media }) — the Pro client, decision 26 a).
 * Arguments from the renderer are checked here and again in MediaService. Every handler resolves; failures come back
 * as { ok: false, code, error? }. No token, no password, no api_key ever goes to the page: pictures and video are
 * gcmedia:// addresses (MediaService.stream.handleProtocol), not IPC.
 *
 *   media:status          () → { ok, supported, deviceName, quality, caps, sources: [{ id, kind, name, address, unc,
 *                         userName, serverId, alwaysOriginal, pairWith, signedIn, hasPassword, pinned, useExisting,
 *                         ready, link: { atHome, via: 'lan' | 'tunnel', bps, measuredAt, route } }] }
 *   media:caps:set        ({ hevc, av1, vp9, mkv, hdr, ac3, eac3, maxAudioChannels }) → { ok, caps }   what the page's
 *                         Chromium plays (canPlayType / MediaCapabilities, matchMedia('(dynamic-range: high)'))
 *   media:quality:set     ({ quality: 'auto' | 'original' | '20' | '12' | '8' | '4' | '2' }) → { ok, quality }
 *   media:check           ({ id, force? }) → { ok, link }   home or away now, away the bandwidth
 *   media:network         () → { ok }   the network changed (Wi-Fi, tunnel up/down): home/away found again
 *   media:sources:status  () → { ok, server: { state, reason, visible, tab, media, rev, fetchedAt, lastContactAt,
 *                         offline: { days, hint, expired }, unavailableSince, network, cast, notice } | null }
 *   media:sources:refresh () → the same, the plugin asked now (opening Medien)
 *                         Medien-Plugin (W1): the sources come from the server only — reading here, no channel sets one
 *                         up, signs in, removes one or confirms a code (the core's setup methods stay for the tests).
 *   media:source:original ({ id, on }) → { ok }   "Immer Original"
 *   media:resume | media:latest ({ id, limit? }) → { ok, items }   titles with poster/backdrop gcmedia:// URLs,
 *                         resumable, leftMs, progress
 *   media:movies | media:series ({ id, start?, limit?, sort?: 'name' | 'added' | 'year', unplayed?, genre? })
 *                         → { ok, items, total, start, next }
 *   media:seasons         ({ id, seriesId }) → { ok, items }
 *   media:episodes        ({ id, seriesId, seasonId? }) → { ok, items }
 *   media:search          ({ id, q }) → { ok, items }
 *   media:detail          ({ id, itemId }) → { ok, title, versions: [{ …, videoLabel, hdr, audio: [{ …, label, fate:
 *                         'decoded' | 'converted' }], subtitles: [{ …, burnIn }], pick: { audioIndex, subtitleIndex },
 *                         quality: { originalBps, originalFits, adaptedBps, suggestAdapted } }], link }
 *   media:play            ({ id, itemId, versionId?, startMs?, audioIndex?, subtitleIndex?, quality?, originalBps?,
 *                         seriesId? }) → { ok, playId, url, hls, method, converted, bitrate, audioIndex, subtitleIndex,
 *                         subtitles: [{ index, url, mime, language, label }], transcodeReasons, link }
 *   media:report          ({ playId, event: 'start' | 'progress' | 'stop', positionMs, paused?, durationMs? }) → { ok }
 *   media:played          ({ id, itemId, played }) → { ok }
 *   media:stream:end      ({ url | playId }) → { ok }   the addresses stop working
 *   media:share:list      ({ id, dir? }) → { ok, dir, via: 'smb' | 'webdav', items: [{ name, path, directory, size,
 *                         modifiedAt, kind, progress }], link }
 *   media:share:open      ({ id, path }) → { ok, playId, url, mime, size, via, check: { verdict: 'yes' | 'partial' |
 *                         'no' | 'unknown', video, audio, reasons, external, streams }, progress }
 *   media:share:check     ({ id, path | itemId }) → { ok, check, size, via }   the format check before the start (4h)
 *   media:share:external  ({ id, path | itemId, app: 'vlc' | 'default', title? }) → { ok, app } | { ok: false, code:
 *                         'no_vlc' | 'unsupported' (WebDAV has no path for Windows' app) | … }   "In VLC öffnen" /
 *                         "In anderer App öffnen" (4h)
 *   media:external:info   () → { ok, vlc, openPath }
 *   media:tracks          ({ seriesId }) → { ok, choice }
 *   media:tracks:set      ({ seriesId, choice: { audioLanguage, subtitleLanguage, subtitlesOff } }) → { ok }
 *
 * Shares (4h): resume, latest, movies, series, seasons, episodes, search, detail, play and played take a share's id as
 * well; its item ids are `f:<path>` (a file), `s:<key>` (a series) and `s:<key>:<n>` (a season).
 *
 * Events to the main window: media:state (status()), media:link ({ sourceId, link }), media:vpn ({ state: 'connecting' |
 * 'up' | 'failed' }: the tunnel started for Medien, the network rule), media:sources:state (the server's list).
 */

const J = require('../utils/media-jellyfin');
const MS = require('../utils/media-sources');
const SI = require('../utils/media-share-index');

const MEDIA_EVENTS = { state: 'media:state', link: 'media:link', vpn: 'media:vpn' };

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const isId = (v) => typeof v === 'string' && MS.ID_RE.test(v);
const isItem = (v) => typeof v === 'string' && (J.ID_RE.test(v) || SI.isItemId(v));
const isStr = (v, max) => typeof v === 'string' && v.length <= max;
const optInt = (v) => (Number.isInteger(v) ? v : undefined);

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed' };
}

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.media - MediaService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerMediaHandlers(handle, { media: m, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument' });

  handle('media:status', wrap(async () => m.status()));
  handle('media:caps:set', wrap(async (a) => m.setCaps(a)));
  handle('media:quality:set', wrap(async (a) => m.setQuality(a.quality)));
  handle('media:check', wrap(async (a) => (isId(a.id) ? m.check(a.id, { force: a.force === true }) : invalid())));
  handle('media:network', wrap(async () => m.networkChanged()));
  handle('media:sources:status', wrap(async () => m.serverStatus()));
  handle('media:sources:refresh', wrap(async () => m.serverRefresh()));
  handle('media:source:original', wrap(async (a) => (isId(a.id) && typeof a.on === 'boolean' ? m.setAlwaysOriginal(a.id, a.on) : invalid())));
  handle('media:resume', wrap(async (a) => (isId(a.id) ? m.resume(a.id, a.limit) : invalid())));
  handle('media:latest', wrap(async (a) => (isId(a.id) ? m.latest(a.id, a.limit) : invalid())));
  const pageArgs = (a) => ({ start: a.start, limit: a.limit, sort: a.sort, unplayed: a.unplayed === true, genre: isStr(a.genre, 64) ? a.genre : null });
  handle('media:movies', wrap(async (a) => (isId(a.id) ? m.movies(a.id, pageArgs(a)) : invalid())));
  handle('media:series', wrap(async (a) => (isId(a.id) ? m.series(a.id, pageArgs(a)) : invalid())));
  handle('media:seasons', wrap(async (a) => (isId(a.id) && isItem(a.seriesId) ? m.seasons(a.id, a.seriesId) : invalid())));
  handle('media:episodes', wrap(async (a) => {
    if (!isId(a.id) || !isItem(a.seriesId) || (a.seasonId != null && !isItem(a.seasonId))) return invalid();
    return m.episodes(a.id, a.seriesId, a.seasonId || null);
  }));
  handle('media:search', wrap(async (a) => (isId(a.id) && isStr(a.q, 200) ? m.search(a.id, a.q) : invalid())));
  handle('media:detail', wrap(async (a) => (isId(a.id) && isItem(a.itemId) ? m.detail(a.id, a.itemId) : invalid())));
  handle('media:play', wrap(async (a) => {
    if (!isId(a.id) || !isItem(a.itemId) || (a.versionId != null && !isItem(a.versionId)) || (a.seriesId != null && !isItem(a.seriesId))) return invalid();
    return m.play({
      sourceId: a.id, itemId: a.itemId, versionId: a.versionId || null, startMs: a.startMs, audioIndex: optInt(a.audioIndex),
      subtitleIndex: optInt(a.subtitleIndex), quality: isStr(a.quality, 16) ? a.quality : undefined,
      originalBps: Number.isFinite(a.originalBps) ? a.originalBps : undefined, seriesId: a.seriesId || null,
    });
  }));
  handle('media:report', wrap(async (a) => {
    if (!isStr(a.playId, 64) || !['start', 'progress', 'stop'].includes(a.event)) return invalid();
    return m.report({ playId: a.playId, event: a.event, positionMs: a.positionMs, paused: a.paused === true, durationMs: a.durationMs });
  }));
  handle('media:played', wrap(async (a) => (isId(a.id) && isItem(a.itemId) && typeof a.played === 'boolean' ? m.setPlayed(a.id, a.itemId, a.played) : invalid())));
  handle('media:stream:end', wrap(async (a) => {
    const v = isStr(a.url, 4096) ? a.url : isStr(a.playId, 64) ? a.playId : null;
    return v ? m.stream.revoke(v) : invalid();
  }));
  handle('media:share:list', wrap(async (a) => (isId(a.id) && (a.dir == null || isStr(a.dir, 1024)) ? m.shareList({ sourceId: a.id, dir: a.dir || '' }) : invalid())));
  handle('media:share:open', wrap(async (a) => (isId(a.id) && isStr(a.path, 1024) && a.path ? m.shareOpen({ sourceId: a.id, path: a.path }) : invalid())));
  const sharePath = (a) => (isStr(a.path, 1024) && a.path ? { path: a.path } : isItem(a.itemId) && a.itemId.startsWith('f:') ? { itemId: a.itemId } : null);
  handle('media:share:check', wrap(async (a) => {
    const p = isId(a.id) ? sharePath(a) : null;
    return p ? m.shareInspect({ sourceId: a.id, ...p }) : invalid();
  }));
  handle('media:share:external', wrap(async (a) => {
    const p = isId(a.id) ? sharePath(a) : null;
    if (!p || (a.app !== 'vlc' && a.app !== 'default') || (a.title != null && !isStr(a.title, 200))) return invalid();
    return m.shareExternal({ sourceId: a.id, ...p, app: a.app, title: a.title || null });
  }));
  handle('media:external:info', wrap(async () => m.externalInfo()));
  handle('media:tracks', wrap(async (a) => (isStr(a.seriesId, 80) && a.seriesId ? m.trackChoice(a.seriesId) : invalid())));
  handle('media:tracks:set', wrap(async (a) => (isStr(a.seriesId, 80) && a.seriesId ? m.setTrackChoice(a.seriesId, obj(a.choice)) : invalid())));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(MEDIA_EVENTS)) m.on(event, (payload) => send(channel, payload));
  m.on('server', (payload) => send('media:sources:state', payload));
}

module.exports = { registerMediaHandlers, MEDIA_EVENTS };
