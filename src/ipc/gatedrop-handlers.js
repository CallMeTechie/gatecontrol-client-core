'use strict';

/**
 * IPC of "GateDrop" (opt-in: registerBaseHandlers(…, { gatedrop })).
 * Arguments from the renderer are checked here and again in GateDropService.
 * Every handler resolves; failures come back as { ok: false, code, error, status }.
 *
 *   gatedrop:status        () → GateDropService.status()
 *   gatedrop:check         () → status after asking the server again
 *   gatedrop:targets       ({ refresh? }) → { ok, me, people, devices, nas, links }
 *   gatedrop:pick          () → file dialog → { ok, files, rejected } | { ok: false, code: 'cancelled' }
 *   gatedrop:prepare       ({ paths }) → { ok, files: [{ id, name, size, mime }], rejected }
 *   gatedrop:compose:take  () → files of a "Senden an" start the window has not seen yet
 *   gatedrop:send          ({ files: [ids], text?, link?, note?, to }) → { ok, id, deliveries, link, direct }
 *   gatedrop:inbox         ({ kind, refresh? }) → { ok, kind, items, stale }
 *   gatedrop:send:get      ({ id }) → { ok, send }
 *   gatedrop:send:save     ({ id }) → download a received send again
 *   gatedrop:link:end      ({ token }) → { ok }
 *   gatedrop:folder        () → opens Downloads\GateControl
 *   gatedrop:show          ({ path }) → shows a saved file in the Explorer (saved files only)
 *   gatedrop:open          ({ path }) → opens a saved file (saved files only)
 *   gatedrop:copy          ({ text }) → clipboard
 *   gatedrop:open-link     ({ url }) → browser (http/https only)
 *   gatedrop:explorer      ({ enabled? }) → { ok, enabled } "Senden an" shortcut (when the app has it)
 *
 * Events to the main window: gatedrop:state, gatedrop:compose, gatedrop:progress,
 * gatedrop:received, gatedrop:changed, gatedrop:navigate.
 */

const GATEDROP_EVENTS = {
  state: 'gatedrop:state',
  compose: 'gatedrop:compose',
  progress: 'gatedrop:progress',
  received: 'gatedrop:received',
  changed: 'gatedrop:changed',
  navigate: 'gatedrop:navigate',
};

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
const optStr = (v, max) => v === undefined || v === null || (typeof v === 'string' && v.length <= max);

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.gatedrop - GateDropService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 * @param {object} [deps.dialog] - Electron dialog (gatedrop:pick)
 * @param {object} [deps.explorer] - { get(): boolean, set(enabled): Promise<boolean>|boolean } ("Senden an")
 */
function registerGateDropHandlers(handle, { gatedrop: s, getMainWindow, log, dialog = null, explorer = null }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };

  handle('gatedrop:status', () => s.status());
  handle('gatedrop:check', wrap(async () => s.check()));
  handle('gatedrop:targets', wrap(async (a) => s.targets({ refresh: a.refresh === true })));
  handle('gatedrop:pick', wrap(async () => {
    if (!dialog || typeof dialog.showOpenDialog !== 'function') return { ok: false, code: 'unsupported', error: 'no dialog', status: null };
    const win = getMainWindow && getMainWindow();
    const opts = { properties: ['openFile', 'multiSelections'] };
    const r = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled', status: null };
    return s.prepareFiles(r.filePaths);
  }));
  handle('gatedrop:prepare', wrap(async (a) => {
    if (!Array.isArray(a.paths) || a.paths.length > 100 || !a.paths.every((p) => typeof p === 'string' && p.length <= 4096)) return invalid();
    return s.prepareFiles(a.paths);
  }));
  handle('gatedrop:compose:take', wrap(async () => ({ ok: true, ...s.takeCompose() })));
  handle('gatedrop:send', wrap(async (a) => {
    if (!Array.isArray(a.files || []) || !optStr(a.text, 20000) || !optStr(a.link, 2048) || !optStr(a.note, 500) || !a.to || typeof a.to !== 'object') return invalid();
    return s.send({ files: a.files || [], text: a.text || null, link: a.link || null, note: a.note || null, to: a.to });
  }));
  handle('gatedrop:inbox', wrap(async (a) => s.inbox({ kind: a.kind, refresh: a.refresh === true })));
  handle('gatedrop:send:get', wrap(async (a) => {
    if (typeof a.id !== 'string' && typeof a.id !== 'number') return invalid();
    return s.sendDetails(a.id);
  }));
  handle('gatedrop:send:save', wrap(async (a) => {
    if (typeof a.id !== 'string' && typeof a.id !== 'number') return invalid();
    return s.saveSend(a.id);
  }));
  handle('gatedrop:link:end', wrap(async (a) => {
    if (typeof a.token !== 'string') return invalid();
    return s.endLink(a.token);
  }));
  handle('gatedrop:folder', wrap(async () => s.openFolder()));
  handle('gatedrop:show', wrap(async (a) => (typeof a.path === 'string' ? s.showItem(a.path) : invalid())));
  handle('gatedrop:open', wrap(async (a) => (typeof a.path === 'string' ? s.openItem(a.path) : invalid())));
  handle('gatedrop:copy', wrap(async (a) => (typeof a.text === 'string' ? s.copyText(a.text) : invalid())));
  handle('gatedrop:open-link', wrap(async (a) => (typeof a.url === 'string' ? s.openLink(a.url) : invalid())));
  handle('gatedrop:explorer', wrap(async (a) => {
    if (!explorer) return { ok: true, enabled: false, supported: false };
    if (typeof a.enabled === 'boolean') await explorer.set(a.enabled);
    return { ok: true, enabled: !!explorer.get(), supported: true };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(GATEDROP_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerGateDropHandlers, GATEDROP_EVENTS };
