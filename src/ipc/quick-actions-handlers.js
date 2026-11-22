'use strict';

/**
 * IPC of the plugin quick actions (opt-in: registerBaseHandlers(…, { quickActions })).
 * Arguments from the renderer are checked here and again in QuickActionsService.
 * Every handler resolves.
 *
 *   quickactions:list  () → QuickActionsService.list()
 *                      { ok: true, supported, actions, fetchedAt, offline, reason? } | { ok: false, reason }
 *   quickactions:run   ({ plugin, id, control?, value?, state? })
 *                      → { ok, message, state, widget, unchanged } | { ok: false, reason, status, message }
 */

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.quickActions - QuickActionsService
 * @param {object} deps.log
 */
function registerQuickActionsHandlers(handle, { quickActions: s, log }) {
  handle('quickactions:list', async () => {
    try {
      return await s.list();
    } catch (err) {
      log.warn(`Quick actions: list failed: ${err.message}`);
      return { ok: false, reason: 'failed' };
    }
  });

  handle('quickactions:run', async (_e, arg) => {
    const a = obj(arg);
    const opts = {};
    if (a.control != null) { opts.control = a.control; opts.value = a.value; }
    if (a.state != null) opts.state = a.state;
    try {
      return await s.run(a.plugin, a.id, opts);
    } catch (err) {
      log.warn(`Quick actions: run failed: ${err.message}`);
      return { ok: false, reason: 'failed', status: null, message: null };
    }
  });
}

module.exports = { registerQuickActionsHandlers };
