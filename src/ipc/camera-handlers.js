'use strict';

/**
 * IPC of "Kameras im Heimnetz" (opt-in: registerBaseHandlers(…, { cameras })).
 * Arguments from the renderer are checked here and again in CamerasService.
 * Every handler resolves; failures come back as { ok: false, code, error, status }.
 *
 *   cameras:status      () → CamerasService.status()
 *   cameras:check       () → status after asking the server again
 *   cameras:list        ({ refresh? }) → { ok, supported, every, cameras, fetchedAt, stale }
 *   cameras:live        ({ id }) → { ok, live: { mode: 'live', mp4, hls, snapshot, audio, … } | { mode: 'snapshot', snapshot, every, reason } }
 *   cameras:clips       ({ id, day?, refresh? }) → { ok, day, clips, fetchedAt, stale }
 *   cameras:still:save  ({ id }) → "Standbild speichern": a fresh still into a file the person picks
 *                       (Pictures of the person signed in) → { ok, path } | { ok: false, cancelled }
 *
 * Media go through the scheme gccam: (CamerasService.handleProtocol), not over IPC.
 * Errors of the plugin keep their codes (not_found — no right on that camera —, cam_offline,
 * cam_unreachable, cam_not_ready, cam_needs_gc, rate_limited, …).
 *
 * Events to the main window: cameras:state (status()), cameras:push ({ cameraId, eventId, notificationId }).
 */

const cam = require('../utils/cameras');

const CAMERA_EVENTS = {
  state: 'cameras:state',
  push: 'cameras:push',
};

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.cameras - CamerasService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 * @param {object} [deps.dialog] - Electron dialog (Standbild speichern)
 * @param {Function} [deps.dialogPath] - utils/user-folders dialogPath
 * @param {object} [deps.fsp] - fs.promises (tests)
 */
function registerCameraHandlers(handle, { cameras: c, getMainWindow, log, dialog = null, dialogPath = null, fsp = null }) {
  const files = fsp || require('fs').promises;
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });

  handle('cameras:status', () => c.status());
  handle('cameras:check', wrap(async () => c.check()));
  handle('cameras:list', wrap(async (a) => c.list({ refresh: a.refresh === true })));
  handle('cameras:live', wrap(async (a) => (cam.isCameraId(a.id) ? c.live(a.id) : invalid())));
  handle('cameras:clips', wrap(async (a) => {
    if (!cam.isCameraId(a.id) || cam.dayArg(a.day) === null) return invalid();
    return c.clips(a.id, { day: cam.dayArg(a.day), refresh: a.refresh === true });
  }));
  handle('cameras:still:save', wrap(async (a) => {
    if (!cam.isCameraId(a.id)) return invalid();
    if (!dialog || typeof dialog.showSaveDialog !== 'function') return { ok: false, code: 'unsupported', error: 'no dialog', status: null };
    const still = await c.still(a.id);
    const name = cam.stillFileName(c.nameOf(a.id), still.at || Date.now());
    const win = getMainWindow && getMainWindow();
    const opts = {
      defaultPath: typeof dialogPath === 'function' ? (dialogPath('pictures', name) || name) : name,
      filters: [{ name: 'JPEG', extensions: ['jpg', 'jpeg'] }],
    };
    const res = win ? await dialog.showSaveDialog(win, opts) : await dialog.showSaveDialog(opts);
    if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true };
    await files.writeFile(res.filePath, still.data);
    return { ok: true, path: res.filePath };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(CAMERA_EVENTS)) c.on(event, (payload) => send(channel, payload));
}

module.exports = { registerCameraHandlers, CAMERA_EVENTS };
