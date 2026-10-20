'use strict';

/**
 * IPC of "Schule" (opt-in: registerBaseHandlers(…, { school })).
 * Arguments from the renderer are checked here and again in SchoolService.
 * Every handler resolves; failures come back as { ok: false, code, error, status }.
 *
 *   school:status     () → SchoolService.status()
 *   school:check      () → status after asking the server again
 *   school:timetable  ({ from, to, refresh? }) → { ok, updatedAt, students, fetchedAt, stale }
 *   school:changes    ({ days?, refresh? }) → { ok, changes, fetchedAt, stale }
 *   school:messages   ({ days?, refresh? }) → { ok, messages, … } | code 'unsupported' (plugin < 1.4.0)
 *   school:absences   ({ days?, refresh? }) → { ok, absences, … } | code 'unsupported' (plugin < 1.4.0)
 *   school:avatar     ({ url }) → { ok, mime, data: Uint8Array }
 *
 * Events to the main window: school:state (status()), school:push (context
 * of a Schule push message: { kind, studentId, date, messageId, notificationId }).
 */

const { isAvatarPath } = require('../utils/messenger');

const SCHOOL_EVENTS = {
  state: 'school:state',
  push: 'school:push',
};

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.school - SchoolService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerSchoolHandlers(handle, { school: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
  const refresh = (a) => a.refresh === true;

  handle('school:status', () => s.status());
  handle('school:check', wrap(async () => s.check()));
  handle('school:timetable', wrap(async (a) => {
    if (typeof a.from !== 'string' || typeof a.to !== 'string') return invalid();
    return s.timetable({ from: a.from, to: a.to, refresh: refresh(a) });
  }));
  handle('school:changes', wrap(async (a) => s.changes({ days: a.days, refresh: refresh(a) })));
  handle('school:messages', wrap(async (a) => s.messages({ days: a.days, refresh: refresh(a) })));
  handle('school:absences', wrap(async (a) => s.absences({ days: a.days, refresh: refresh(a) })));
  handle('school:avatar', wrap(async (a) => {
    if (!isAvatarPath(a.url)) return invalid();
    const r = await s.avatar(a.url);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(SCHOOL_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerSchoolHandlers, SCHOOL_EVENTS };
