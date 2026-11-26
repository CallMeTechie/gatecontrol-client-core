'use strict';

/**
 * IPC of "Familie" (opt-in: registerBaseHandlers(…, { familie })).
 * Arguments from the renderer are checked here and again in FamilieService.
 * Every handler resolves; failures come back as { ok: false, code, error, status, field }.
 *
 *   familie:status            () → FamilieService.status()
 *   familie:check             () → status after asking the server again
 *   familie:internet          ({ refresh? }) → { ok, internet: { available, supported, manage, serverTime, timezone, children }, fetchedAt, stale }
 *   familie:internet:pause    ({ childId, minutes | until | add }) → { ok, child }
 *   familie:internet:resume   ({ childId }) → { ok, child }
 *   familie:internet:extend   ({ childId, minutes, fromNow? }) → { ok, child }
 *                             (codes: invalid, parents_only, not_found, unavailable, not_person, …)
 *   familie:rules             ({ refresh? }) → { ok, rules, can, … } | code 'module_off'
 *   familie:rules:options     ({ refresh? }) → { ok, internet: { available, reason, children }, people, … }
 *   familie:rules:active      ({ id, active }) → { ok, rule }
 *   familie:rules:actions     ({ id, actions }) → { ok, rule }   (all actions of the rule; `field` names a refused one)
 *   familie:presence          ({ refresh? }) → { ok, me: { share, wifi }, self, … } | code 'module_off'
 *   familie:presence:share    ({ share }) → { ok, share, self }
 *   familie:wifi              ({ refresh? }) → { ok, wifi: { available, consent, since, devices }, … }
 *   familie:wifi:set          ({ enabled }) → { ok, wifi }
 *   familie:wifi:device       ({ id, counts }) → { ok, wifi }
 *   familie:avatar            ({ url }) → { ok, mime, data: Uint8Array }
 *
 * Events to the main window: familie:state (status()), familie:push (context
 * of an "Internet zu Hause" push: { type, kind, userId, until, ruleId, notificationId }).
 */

const { isAvatarPath } = require('../utils/messenger');

const FAMILIE_EVENTS = {
  state: 'familie:state',
  push: 'familie:push',
};

const FIELD_RE = /^[A-Za-z0-9_.]{1,60}$/;

function fail(err) {
  const field = err && err.body && typeof err.body.field === 'string' && FIELD_RE.test(err.body.field) ? err.body.field : null;
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null, field };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.familie - FamilieService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerFamilieHandlers(handle, { familie: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null, field: null });
  const refresh = (a) => ({ refresh: a.refresh === true });
  const id = (v) => Number.isSafeInteger(v) && v > 0;

  handle('familie:status', () => s.status());
  handle('familie:check', wrap(async () => s.check()));

  handle('familie:internet', wrap(async (a) => s.internet(refresh(a))));
  handle('familie:internet:pause', wrap(async (a) => {
    if (!id(a.childId)) return invalid();
    return s.pause(a.childId, { minutes: a.minutes, until: a.until, add: a.add });
  }));
  handle('familie:internet:resume', wrap(async (a) => (id(a.childId) ? s.resume(a.childId) : invalid())));
  handle('familie:internet:extend', wrap(async (a) => {
    if (!id(a.childId)) return invalid();
    return s.extend(a.childId, { minutes: a.minutes, fromNow: a.fromNow === true });
  }));

  handle('familie:rules', wrap(async (a) => s.rules(refresh(a))));
  handle('familie:rules:options', wrap(async (a) => s.ruleOptions(refresh(a))));
  handle('familie:rules:active', wrap(async (a) => (id(a.id) && typeof a.active === 'boolean' ? s.setRuleActive(a.id, a.active) : invalid())));
  handle('familie:rules:actions', wrap(async (a) => (id(a.id) && Array.isArray(a.actions) ? s.setRuleActions(a.id, a.actions) : invalid())));

  handle('familie:presence', wrap(async (a) => s.presence(refresh(a))));
  handle('familie:presence:share', wrap(async (a) => (typeof a.share === 'boolean' ? s.setShare(a.share) : invalid())));
  handle('familie:wifi', wrap(async (a) => s.wifi(refresh(a))));
  handle('familie:wifi:set', wrap(async (a) => (typeof a.enabled === 'boolean' ? s.setWifi(a.enabled) : invalid())));
  handle('familie:wifi:device', wrap(async (a) => (id(a.id) && typeof a.counts === 'boolean' ? s.setWifiDevice(a.id, a.counts) : invalid())));

  handle('familie:avatar', wrap(async (a) => {
    if (!isAvatarPath(a.url)) return invalid();
    const r = await s.avatar(a.url);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(FAMILIE_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerFamilieHandlers, FAMILIE_EVENTS };
