'use strict';

/**
 * IPC of „Meine Orte“ (opt-in: registerBaseHandlers(…, { places })). Arguments from the renderer are checked here and
 * again in PlacesService (utils/places.js). Every handler resolves; failures come back as
 * { ok: false, code, error, status, field?, usedBy?, retryAfter? }.
 *
 *   places:status   () → { state: unknown|available|unsupported|error, search, family, count }
 *   places:list     ({ refresh?, shared? }) → { ok, places, family, limits, icons, visibility, search, fetchedAt, stale }
 *                   (code 'unsupported': GateControl before 1.299.0)
 *   places:get      ({ id }) → { ok, place }
 *   places:create   ({ place: { name, lat, lon, icon?, radiusM?, address?, visibility? } }) → { ok, place }
 *                   (codes invalid + field, duplicate, limit)
 *   places:update   ({ id, patch }) → { ok, place }   only the fields given; lat and lon together; address null clears
 *   places:delete   ({ id, force? }) → { ok, deleted, id }   (code in_use + usedBy without force)
 *   places:used     ({ id }) → { ok, place }   „zuletzt genutzt“ — a form took the place
 *   places:search   ({ q, near?, lang? }) → { ok, results, attribution, via: 'server' | 'device' }
 *                   (only on „Suchen“ / Enter; codes invalid, search_off, rate_limited + retryAfter, search_unavailable)
 *   places:map:tile ({ z, x, y }) → { ok, mime, data: Uint8Array }   an OpenStreetMap tile of the map (services/map-service.js)
 *   places:map:reverse ({ lat, lon, lang? }) → { ok, label | null }  the address of a point clicked on the map
 *
 * Events to the main window: places:changed ({ ids, deleted, origin }), places:state (status()).
 */

const P = require('../utils/places');

const PLACES_EVENTS = {
  changed: 'places:changed',
  state: 'places:state',
};

const FIELD_RE = /^[A-Za-z0-9_.]{1,40}$/;

function fail(err) {
  const out = { ok: false, code: (err && typeof err.code === 'string' && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
  const field = (err && err.field) || (err && err.body && err.body.field);
  if (typeof field === 'string' && FIELD_RE.test(field)) out.field = field;
  if (err && Array.isArray(err.usedBy)) out.usedBy = err.usedBy;
  if (err && Number.isSafeInteger(err.retryAfter) && err.retryAfter > 0) out.retryAfter = err.retryAfter;
  return out;
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.places - PlacesService
 * @param {object} [deps.maps] - MapService (tiles and the address of a point)
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerPlacesHandlers(handle, { places: s, maps = null, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = (field = null) => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null, ...(field ? { field } : {}) });
  const id = (v) => Number.isSafeInteger(v) && v > 0;
  const lang = (v) => (v === 'en' ? 'en' : (v === 'de' ? 'de' : undefined));

  handle('places:status', () => s.status());
  handle('places:list', wrap(async (a) => s.list({ refresh: a.refresh === true, shared: a.shared === true })));
  handle('places:get', wrap(async (a) => (id(a.id) ? s.get(a.id) : invalid('id'))));
  handle('places:create', wrap(async (a) => {
    try { P.createBody(a.place); } catch (err) { return invalid(err.field); }
    return s.create(a.place);
  }));
  handle('places:update', wrap(async (a) => {
    if (!id(a.id)) return invalid('id');
    try { P.patchBody(a.patch); } catch (err) { return invalid(err.field); }
    return s.update(a.id, a.patch);
  }));
  handle('places:delete', wrap(async (a) => (id(a.id) ? s.remove(a.id, { force: a.force === true }) : invalid('id'))));
  handle('places:used', wrap(async (a) => (id(a.id) ? s.markUsed(a.id) : invalid('id'))));
  handle('places:search', wrap(async (a) => {
    try { P.searchArg({ q: a.q, near: a.near }); } catch (err) { return invalid(err.field); }
    return s.search({ q: a.q, near: a.near }, { lang: lang(a.lang) });
  }));

  const noMaps = () => ({ ok: false, code: 'unavailable', error: 'no map service', status: null });
  handle('places:map:tile', wrap(async (a) => {
    if (!maps) return noMaps();
    if (![a.z, a.x, a.y].every((v) => Number.isSafeInteger(v) && v >= 0)) return invalid();
    const r = await maps.tile(a.z, a.x, a.y);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));
  handle('places:map:reverse', wrap(async (a) => {
    if (!maps) return noMaps();
    if (!Number.isFinite(a.lat) || !Number.isFinite(a.lon) || !P.hasPoint(a.lat, a.lon)) return invalid('lat');
    return { ok: true, ...(await maps.reverse(a.lat, a.lon, { lang: lang(a.lang) })) };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(PLACES_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerPlacesHandlers, PLACES_EVENTS };
