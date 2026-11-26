'use strict';

/**
 * IPC of "DNS-Schutz" (opt-in: registerBaseHandlers(…, { dnsProtect })).
 * Arguments from the renderer are checked here and again in DnsProtectService.
 * Every handler resolves; failures come back as { ok: false, code, error, status, reason }
 * (`error` is the plugin's sentence in the app's language, `reason` the one of `not_allowed`).
 *
 *   dnsprotect:status    () → DnsProtectService.snapshot()
 *   dnsprotect:check     () → snapshot after asking GET permissions again
 *   dnsprotect:refresh   () → snapshot after asking the plugin's status again
 *   dnsprotect:pause     ({ minutes } | { forever: true } | { extend }) → { ok, snapshot }
 *                        (codes: invalid, not_allowed, forever_not_allowed, too_long, off, not_filtering, no_device, unavailable, …)
 *   dnsprotect:resume    () → { ok, resumed, snapshot }
 *   dnsprotect:watch     ({ on }) → { ok }   (the card is on screen: status is asked more often)
 *
 * Event to the main window: dnsprotect:change (snapshot()).
 */

const { REASONS } = require('../utils/dns-protect');

const DNS_PROTECT_EVENTS = {
  change: 'dnsprotect:change',
};

const REFUSALS = [...REASONS, 'admin_target', 'not_yours'];

function fail(err) {
  const reason = err && err.body && REFUSALS.includes(err.body.reason) ? err.body.reason : null;
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null, reason };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.dnsProtect - DnsProtectService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerDnsProtectHandlers(handle, { dnsProtect: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };

  handle('dnsprotect:status', () => s.snapshot());
  handle('dnsprotect:check', wrap(async () => s.check()));
  handle('dnsprotect:refresh', wrap(async () => s.refresh()));
  handle('dnsprotect:pause', wrap(async (a) => s.pause({ minutes: a.minutes, forever: a.forever, extend: a.extend })));
  handle('dnsprotect:resume', wrap(async () => s.resume()));
  handle('dnsprotect:watch', wrap(async (a) => { s.watch(a.on === true); return { ok: true }; }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(DNS_PROTECT_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerDnsProtectHandlers, DNS_PROTECT_EVENTS };
