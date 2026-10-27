'use strict';

/**
 * IPC of "Drive" (opt-in: registerBaseHandlers(…, { drive })).
 * Arguments from the renderer are checked here and again in DriveService.
 * Every handler resolves; failures come back as { ok: false, code, error, status }.
 *
 *   drive:status          () → DriveService.status()
 *   drive:check           () → status after asking the server again
 *   drive:me              () → { ok, me, licence, areas, settings, limits, people, usable }
 *   drive:areas           () → { ok, areas }
 *   drive:folder          ({ id, sort?, order?, offset?, limit? }) → { ok, node, crumbs, role, writable, items, total, next }
 *   drive:search          ({ q, area? }) → { ok, items }
 *   drive:mkdir           ({ parentId, name }) → { ok, node }
 *   drive:rename          ({ id, name }) → { ok, node }
 *   drive:move            ({ id, parentId }) → { ok, node }
 *   drive:remove          ({ id }) → { ok, id, trashed }       into the trash
 *   drive:trash           ({ area? }) → { ok, items }
 *   drive:restore         ({ id }) → { ok, node }              out of the trash
 *   drive:purge           ({ id }) → { ok, id }                gone for good
 *   drive:versions        ({ id }) → { ok, current, versions }
 *   drive:version:restore ({ id, versionId }) → { ok, node }
 *   drive:links           ({ nodeId? }) → { ok, links, enabled }
 *   drive:link:create     ({ nodeId, mode, expires, pin? }) → { ok, link }
 *   drive:link:end        ({ token }) → { ok, ended }
 *   drive:preview         ({ mediaId, large? }) → { ok, mime, data: Uint8Array }
 *   drive:pick            () → file dialog → { ok, paths } | { ok: false, code: 'cancelled' }
 *   drive:upload          ({ parentId, paths }) → { ok, queued, rejected }
 *   drive:upload:resolve  ({ id, choice: 'version' | 'rename' | null }) → { ok }
 *   drive:transfers       () → { ok, transfers }
 *   drive:transfers:clear () → { ok, transfers }
 *   drive:open            ({ id, versionId? }) → { ok, path } | { ok: false, code: 'unsafe' }
 *   drive:save-as         ({ id, versionId? }) → { ok, path } | { ok: false, cancelled }
 *   drive:show            ({ path }) → shows a loaded file in the Explorer
 *   drive:last-folder     () → { ok, folderId }
 *   drive:last-folder:set ({ folderId }) → { ok, folderId }
 *
 * Events to the main window: drive:state, drive:transfers, drive:changed.
 */

const DRIVE_EVENTS = {
  state: 'drive:state',
  transfers: 'drive:transfers',
  changed: 'drive:changed',
};

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
const isId = (v) => Number.isSafeInteger(v) && v > 0;
const optId = (v) => v === undefined || v === null || isId(v);
const isStr = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.drive - DriveService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerDriveHandlers(handle, { drive: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const byId = (fn) => wrap(async (a) => (isId(a.id) ? fn(a) : invalid()));

  handle('drive:status', () => s.status());
  handle('drive:check', wrap(async () => s.check()));
  handle('drive:me', wrap(async () => s.me()));
  handle('drive:areas', wrap(async () => s.areas()));
  handle('drive:folder', byId(async (a) => s.folder(a.id, { sort: a.sort, order: a.order, offset: a.offset, limit: a.limit })));
  handle('drive:search', wrap(async (a) => {
    if (!isStr(a.q, 100) || !(a.area === undefined || a.area === null || isStr(a.area, 80))) return invalid();
    return s.search(a.q, a.area || null);
  }));
  handle('drive:mkdir', wrap(async (a) => (isId(a.parentId) && isStr(a.name, 255) ? s.mkdir(a.parentId, a.name) : invalid())));
  handle('drive:rename', byId(async (a) => (isStr(a.name, 255) ? s.rename(a.id, a.name) : invalid())));
  handle('drive:move', byId(async (a) => (isId(a.parentId) ? s.move(a.id, a.parentId) : invalid())));
  handle('drive:remove', byId(async (a) => s.remove(a.id)));
  handle('drive:trash', wrap(async (a) => ((a.area === undefined || a.area === null || isStr(a.area, 80)) ? s.trashList(a.area || null) : invalid())));
  handle('drive:restore', byId(async (a) => s.restore(a.id)));
  handle('drive:purge', byId(async (a) => s.purge(a.id)));
  handle('drive:versions', byId(async (a) => s.versions(a.id)));
  handle('drive:version:restore', byId(async (a) => (isId(a.versionId) ? s.restoreVersion(a.id, a.versionId) : invalid())));
  handle('drive:links', wrap(async (a) => (optId(a.nodeId) ? s.links(a.nodeId || null) : invalid())));
  handle('drive:link:create', wrap(async (a) => {
    if (!isId(a.nodeId) || !isStr(a.mode, 20) || !isStr(a.expires, 10) || !(a.pin === undefined || a.pin === null || a.pin === '' || isStr(a.pin, 12))) return invalid();
    return s.createLink({ nodeId: a.nodeId, mode: a.mode, expires: a.expires, pin: a.pin || null });
  }));
  handle('drive:link:end', wrap(async (a) => (isStr(a.token, 200) ? s.endLink(a.token) : invalid())));
  handle('drive:preview', wrap(async (a) => {
    if (!isStr(a.mediaId, 128)) return invalid();
    const r = await s.preview(a.mediaId, { large: a.large === true });
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));
  handle('drive:pick', wrap(async () => s.pickFiles()));
  handle('drive:upload', wrap(async (a) => {
    if (!isId(a.parentId) || !Array.isArray(a.paths) || a.paths.length > 200 || !a.paths.every((p) => isStr(p, 4096))) return invalid();
    return s.upload(a.parentId, a.paths);
  }));
  handle('drive:upload:resolve', wrap(async (a) => {
    if (!isStr(a.id, 40) || !(a.choice === null || a.choice === undefined || a.choice === 'version' || a.choice === 'rename')) return invalid();
    return s.resolve(a.id, a.choice || null);
  }));
  handle('drive:transfers', wrap(async () => ({ ok: true, transfers: s.transfers() })));
  handle('drive:transfers:clear', wrap(async () => s.clearTransfers()));
  handle('drive:open', byId(async (a) => (optId(a.versionId) ? s.open(a.id, { versionId: a.versionId || null }) : invalid())));
  handle('drive:save-as', byId(async (a) => (optId(a.versionId) ? s.saveAs(a.id, { versionId: a.versionId || null }) : invalid())));
  handle('drive:show', wrap(async (a) => (isStr(a.path, 4096) ? s.showItem(a.path) : invalid())));
  handle('drive:last-folder', wrap(async () => s.lastFolder()));
  handle('drive:last-folder:set', wrap(async (a) => (isId(a.folderId) ? s.rememberFolder(a.folderId) : invalid())));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(DRIVE_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerDriveHandlers, DRIVE_EVENTS };
