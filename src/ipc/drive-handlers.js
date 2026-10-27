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
 *
 * "Ordner sichern" (deps.sync: DriveSync, services/drive-sync.js):
 *   drive:sync:status     () → { ok, settings, device, network, state, folders, known, … }
 *   drive:sync:pick       () → folder dialog → { ok, path } | { ok: false, code: 'cancelled' }
 *   drive:sync:add        ({ path, mode: 'backup' | 'sync', targetId? }) → { ok, folder }
 *   drive:sync:remove     ({ id }) → { ok }                    stops; deletes nothing
 *   drive:sync:pause      ({ id?, paused }) → status            id null: all folders
 *   drive:sync:settings   ({ skipDev?, maxFileBytes?, upKBs?, downKBs?, homeOnly?, vpnOnly?, paused? }) → status
 *   drive:sync:home       ({ on }) → status                     this network is a home network / forget them
 *   drive:sync:run        ({ id? }) → { ok }                    a run now (all folders without id)
 *   drive:sync:deletes    ({ id, decision: 'apply' | 'restore' }) → status
 *   drive:sync:open       ({ id }) → { ok }                     the folder in the Explorer
 *
 * Events to the main window: drive:state, drive:transfers, drive:changed, drive:sync.
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
const isFolderId = (v) => typeof v === 'string' && /^[a-f0-9]{8,32}$/.test(v);
const SYNC_SETTINGS = {
  skipDev: (v) => typeof v === 'boolean',
  homeOnly: (v) => typeof v === 'boolean',
  vpnOnly: (v) => typeof v === 'boolean',
  paused: (v) => typeof v === 'boolean',
  maxFileBytes: (v) => Number.isSafeInteger(v) && v >= 0,
  upKBs: (v) => Number.isSafeInteger(v) && v >= 0,
  downKBs: (v) => Number.isSafeInteger(v) && v >= 0,
};

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.drive - DriveService
 * @param {object} [deps.sync] - DriveSync ("Ordner sichern")
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerDriveHandlers(handle, { drive: s, sync = null, getMainWindow, log }) {
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

  if (sync) {
    handle('drive:sync:status', () => sync.status());
    handle('drive:sync:pick', wrap(async () => sync.pickFolder()));
    handle('drive:sync:add', wrap(async (a) => {
      if (!isStr(a.path, 4096) || (a.mode !== 'backup' && a.mode !== 'sync')) return invalid();
      if (a.mode === 'sync' && !isId(a.targetId)) return invalid();
      return sync.addFolder({ path: a.path, mode: a.mode, ...(a.mode === 'sync' ? { targetId: a.targetId } : {}) });
    }));
    handle('drive:sync:remove', wrap(async (a) => (isFolderId(a.id) ? sync.removeFolder(a.id) : invalid())));
    handle('drive:sync:pause', wrap(async (a) => {
      if (!(a.id === undefined || a.id === null || isFolderId(a.id)) || typeof a.paused !== 'boolean') return invalid();
      return sync.setPaused(a.id || null, a.paused);
    }));
    handle('drive:sync:settings', wrap(async (a) => {
      const patch = {};
      for (const [k, ok] of Object.entries(SYNC_SETTINGS)) {
        if (a[k] === undefined) continue;
        if (!ok(a[k])) return invalid();
        patch[k] = a[k];
      }
      return sync.setSettings(patch);
    }));
    handle('drive:sync:home', wrap(async (a) => (typeof a.on === 'boolean' ? sync.setHome(a.on) : invalid())));
    handle('drive:sync:run', wrap(async (a) => {
      if (a.id === undefined || a.id === null) return sync.syncAll({ full: true });
      return isFolderId(a.id) ? sync.sync(a.id, { full: true }) : invalid();
    }));
    handle('drive:sync:deletes', wrap(async (a) => (isFolderId(a.id) && (a.decision === 'apply' || a.decision === 'restore') ? sync.confirmDeletes(a.id, a.decision) : invalid())));
    handle('drive:sync:open', wrap(async (a) => (isFolderId(a.id) ? sync.openFolder(a.id) : invalid())));
  }

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(DRIVE_EVENTS)) s.on(event, (payload) => send(channel, payload));
  if (sync) sync.on('change', (payload) => send('drive:sync', payload));
}

module.exports = { registerDriveHandlers, DRIVE_EVENTS };
