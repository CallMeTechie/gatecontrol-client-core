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
 *   drive:pick-folders    () → folder dialog ("Ordner hochladen") → { ok, paths } | { ok: false, code: 'cancelled' }
 *   drive:upload          ({ parentId, paths }) → { ok, queued, rejected, folders, skipped }  (files and whole folders)
 *   drive:upload:resolve  ({ id, choice: 'version' | 'rename' | null }) → { ok }
 *   drive:transfers       () → { ok, transfers }
 *   drive:transfers:clear () → { ok, transfers }
 *   drive:open            ({ id, versionId? }) → { ok, path } | { ok: false, code: 'unsafe' }
 *   drive:save-as         ({ id, versionId? }) → { ok, path } | { ok: false, cancelled }
 *   drive:show            ({ path }) → shows a loaded file in the Explorer
 *   drive:last-folder     () → { ok, folderId }
 *   drive:last-folder:set ({ folderId }) → { ok, folderId }
 *   drive:portal          ({ id? }) → { ok } | { ok: false, code: 'unsupported' }   "Im Portal öffnen" (Drive 1.6 'links')
 *   drive:guard           ({ fresh? }) → { ok, supported, locked, incident, incidents, portal }   (Drive 1.6 'guard')
 *   drive:guard:decide    ({ id, decision: 'undo' | 'release' }) → { ok, decision, incident, restored, trashed, guard }
 *   drive:timetravel:preview ({ id, at }) → { ok, at, historySince, restore, revert, trash, move, total, sample, limited,
 *                         linked: [{ id, path, name, mode, relation }] }   (Drive 1.7 'timeTravel'; linked: folders of this PC)
 *   drive:timetravel      ({ id, at }) → { ok, at, before, restored, reverted, trashed, moved, failed }
 *   drive:photos          ({ area?, before?, limit? }) → { ok, items, next }        (Drive 1.7 'photos')
 *   drive:photos:months   ({ area? }) → { ok, months }
 *   drive:photos:memories ({ date? }) → { ok, groups }
 *   drive:preview:node    ({ id, large? }) → { ok, mime, data }   a photo's preview by its node
 *   drive:albums          () → { ok, albums }                                       (Drive 1.7 'albums')
 *   drive:album           ({ id, before?, limit? }) → { ok, album, items, next }
 *   drive:album:create    ({ name, areaId? }) → { ok, album }
 *   drive:album:update    ({ id, name?, coverId?, frame? }) → { ok, album }         (frame: Drive 1.7 'frame')
 *   drive:album:delete    ({ id }) → { ok }
 *   drive:album:items     ({ id, ids, remove? }) → { ok, album }
 *   drive:storage         ({ all? }) → { ok, total, limit, areas, people, largest, duplicates }   (Drive 1.7 'storage')
 *   drive:storage:prune   ({ areaId, keep }) → { ok, removed, freedBytes }
 *   drive:insight         ({ id }) → { ok, insight }                               (Drive 1.8 'docAi')
 *   drive:insight:run     ({ id }) → { ok, insight }                               "Erneut erkennen"
 *   drive:insight:apply   ({ id, name?, folder? }) → { ok, node, insight }         the suggestion taken
 *   drive:deadlines       ({ from?, to? }) → { ok, deadlines }
 *   drive:deadline:remind ({ id, daysBefore: 0…90 | null }) → { ok, deadline }     null: no reminder
 *   drive:area:docai      ({ areaId, on }) → { ok, area }
 *   drive:import          () → { ok }   the portal's import page in the browser   (Drive 1.8 'cloudImport')
 *   drive:office          ({ id }) → { ok, mode, expiresAt }   "Im Browser bearbeiten" (Drive 1.9 'office')
 *   drive:vault:status    () → { ok, supported, protect, device }                  (Drive 1.9 'vault')
 *   drive:vaults          () → { ok, vaults }
 *   drive:vault:create    ({ areaId? | parentId?, name }) → { ok, vault, node, recoveryKey }   recoveryKey: shown once;
 *                         Drive 1.11: always in the top folder of the area (areaId, else the area of parentId)
 *   drive:vault:open      ({ vaultId }) → { ok, state }
 *   drive:vault:request   ({ vaultId }) → { ok, state, safetyNumber, deviceId }
 *   drive:vault:devices   ({ vaultId }) → { ok, devices, vault }
 *   drive:vault:approve   ({ vaultId, deviceId, safetyNumber }) → { ok, device }
 *   drive:vault:decline   ({ vaultId, deviceId }) → { ok, device }
 *   drive:vault:recover   ({ vaultId, recoveryKey }) → { ok, state }
 *   drive:vault:rotate    ({ vaultId }) → { ok, vault, recoveryKey }
 *   drive:tree            ({ id }) → { ok, items: [{ id, name, hasDirs }], more }    Drive 1.11: the menu's folder tree
 *   drive:vault:lock-status () → { ok, enforced, unlocked, settings, hello: { available, reason }, choices, lastLock }
 *   drive:vault:unlock    ({ vaultId? }) → { ok, unlocked, state? } | { ok: false, code: 'hello_cancelled' | 'hello_not_set_up' | … }
 *   drive:vault:lock      () → { ok, unlocked: false }                              "Jetzt sperren"
 *   drive:vault:lock-settings ({ hello?, autoLockMinutes?: 0|1|3|5|15, lockOnLeave? }) → like lock-status
 *   drive:vault:touch     () → { ok }                                               activity while a vault is open
 *   drive:hello-settings  () → { ok }                                               Windows' sign-in options
 *   drive:cache           () → { ok, bytes, files, previews }                       the cache on this PC
 *   drive:cache:clear     () → { ok, removed, kept }
 *   drive:ops:check       ({ op: 'move'|'copy'|'trash', ids, target? }) → { ok, bulk, local, files, folders, bytes,
 *                         conflicts, blocked }                                          Drive 1.12 'bulk'
 *   drive:ops:start       ({ op, ids, target?, onConflict?: 'version'|'rename'|'skip', meta?: { name, count, target,
 *                         parents } }) → { ok, op }   (a row of the transfer list; event drive:op when it ends)
 *   drive:ops:cancel      ({ id }) → { ok, op }
 *   drive:ops:undo        ({ id }) → { ok, op }                                     until op.undoUntil
 *   drive:zip             ({ ids, name? }) → { ok, path } | { ok: false, cancelled }  Drive 1.12 'zip' ("Speichern unter …")
 *   drive:link:create     ({ ids, mode: 'view'|'download', expires, pin? }) → { ok, link }   one link for several ('multiLink')
 *   drive:deadline:calendar ({ id }) → { ok, deadline }                            Drive 1.14 'deadlineCalendar'
 *   drive:area:calendar   ({ areaId, on }) → { ok, area: { id, docAi, deadlinesToCalendar } }   Drive 1.14 'deadlineCalendar'
 *   drive:deadline:calendar ({ id, target? }) → { ok, deadline }   Drive 1.17 'deadlineMailCalendar': target { kind: 'mail',
 *                         calendarId, label? } into a mail calendar (409 mail_unavailable); none / { kind: 'family' } as before
 *   drive:deadline:calendars () → { ok, family, mail: [{ id, name, account: { id, label, kind }, color }] }   Drive 1.17
 *   drive:deadline:targets () → { ok, targets: [{ areaId, label, target }] }                                Drive 1.17
 *   drive:deadline:target ({ areaId, target: null | { kind: 'family' } | { kind: 'mail', calendarId, label? } }) → { ok, targets }
 *   drive:ask             ({ q: 3…300, area? }) → { ok, status, answer, sources, terms, areas, deadline }   Drive 1.14 'docAsk'
 *   drive:photos          ({ …, q }) → { ok, items, next, terms, total }            Drive 1.14 'photoSearch'
 *   drive:scan:status     () → { ok, supported, local, reason }                      Drive 1.14 'scanDocs'
 *   drive:scan:prepare    ({ ids }) → { ok, scanId, pages, kind, confidence, summary, local, words, folderId, name, suggestion }
 *   drive:scan:save       ({ scanId, target: 'pdf'|'docx'|'xlsx'|'image', folderId?, name?, keepOriginal }) → { ok, node, target, local }
 *   drive:scan:discard    ({ scanId }) → { ok }
 *
 * Drive 1.16 'photoPlaces' / 'photoPeople' (only with the features `me` reports):
 *   drive:photos          ({ …, place?, bbox?: [w,s,e,n], person?: id | [id], districts?, withPeople? })
 *                         → { ok, items, next, marks?, districts? }
 *   drive:photos:months   ({ area?, q?, place?, person? }) → { ok, months }
 *   drive:photos:places   ({ area?, q?, person? }) → { ok, places }
 *   drive:photos:map      ({ bbox, zoom, area?, q?, person? }) → { ok, clusters }
 *   drive:photos:suggest  ({ q }) → { ok, people, places, labels }
 *   drive:photos:settings () → { ok, keepGeo, stripGeoOnShare, people, peopleKids }
 *   drive:photos:settings:set ({ keepGeo?, stripGeoOnShare?, people?, peopleKids? }) → { ok, …, deleted }
 *   drive:photos:geo:delete () → { ok, deleted }
 *   drive:people          () → { ok, people, progress }
 *   drive:person          ({ id }) → { ok, person, together, places, uncertain, years }
 *   drive:person:update   ({ id, name?, hidden?, contact?: { kind, id, name } | null }) → { ok, person, mergedInto }
 *   drive:person:merge    ({ id, into }) → { ok, person }
 *   drive:person:similar  ({ id }) → { ok, people }
 *   drive:person:uncertain ({ id, limit? }) → { ok, faces }
 *   drive:person:confirm  ({ id, faceIds, yes }) → { ok, person }
 *   drive:face:move       ({ id, person: id | null }) → { ok }
 *   drive:map:tile        ({ z, x, y }) → { ok, mime, data }   an OpenStreetMap tile (services/map-service.js, as for the chats)
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
 *   drive:sync:suspect    ({ id, decision: 'upload' | 'keep' }) → status   the answer to "ungewöhnliche Änderungen"
 *   drive:sync:open       ({ id }) → { ok }                     the folder in the Explorer
 *
 * Events to the main window: drive:state, drive:transfers, drive:changed, drive:remote
 * ({ areas, seq }: Drive changed elsewhere), drive:guard (guard state), drive:vault ({ vault, event, device,
 * keyVersion }: a vault request / approval / new key), drive:vault-lock ({ locked, reason }: Drive 1.11), drive:op
 * (the row of a job that ended: Drive 1.12), drive:sync.
 */

const DRIVE_EVENTS = {
  state: 'drive:state',
  transfers: 'drive:transfers',
  changed: 'drive:changed',
  remote: 'drive:remote',
  guard: 'drive:guard',
  vault: 'drive:vault',
  vaultLock: 'drive:vault-lock',
  op: 'drive:op',
};

function fail(err) {
  const out = { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
  // the plugin's detail of a refusal (Drive 1.8: 422 unsupported { reason: no_text | media_disabled }; 1.9: stale_key …)
  const b = err && err.body;
  if (b && typeof b.reason === 'string' && /^[a-z_]{1,40}$/.test(b.reason)) out.reason = b.reason;
  if (b && typeof b.field === 'string' && /^[A-Za-z_.]{1,40}$/.test(b.field)) out.field = b.field;
  return out;
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
const isId = (v) => Number.isSafeInteger(v) && v > 0;
const optId = (v) => v === undefined || v === null || isId(v);
const isStr = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;
const isFolderId = (v) => typeof v === 'string' && /^[a-f0-9]{8,32}$/.test(v);
const isIds = (v, max = 10000) => Array.isArray(v) && v.length > 0 && v.length <= max && v.every(isId);
const isOpId = (v) => isId(v) || (typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v));
const optStr = (v, max) => v === undefined || v === null || (typeof v === 'string' && v.length <= max);
const isAt = (v) => (Number.isSafeInteger(v) && v > 0) || (typeof v === 'string' && v.length <= 40 && Number.isFinite(Date.parse(v)));
const isAlbumId = (v) => isId(v) || (typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v));
const optArea = (v) => v === undefined || v === null || v === '' || (typeof v === 'string' && /^[A-Za-z0-9:_-]{1,80}$/.test(v));
const optCursor = (v) => v === undefined || v === null || v === '' || (typeof v === 'string' && /^[A-Za-z0-9:._+|,-]{1,100}$/.test(v));
const isVaultId = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{22}$/.test(v);
const isDay = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
const optDay = (v) => v === undefined || v === null || v === '' || isDay(v);
const optLimit = (v) => v === undefined || v === null || (Number.isSafeInteger(v) && v > 0 && v <= 200);
const isPersonId = (v) => isId(v) || (typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v));
const optPerson = (v) => v === undefined || v === null || v === '' || isPersonId(v) || (Array.isArray(v) && v.length > 0 && v.length <= 10 && v.every(isPersonId));
const optPlace = (v) => v === undefined || v === null || v === '' || (typeof v === 'string' && /^[A-Za-z0-9:_.-]{1,100}$/.test(v));
const isBbox = (v) => Array.isArray(v) && v.length === 4 && v.every((x) => typeof x === 'number' && Number.isFinite(x));
const optBbox = (v) => v === undefined || v === null || isBbox(v);
const optBool = (v) => v === undefined || typeof v === 'boolean';
const isContact = (v) => v === null || (!!v && typeof v === 'object' && (v.kind === 'family' || v.kind === 'contact')
  && (isId(v.id) || (typeof v.id === 'string' && /^[A-Za-z0-9:_.@-]{1,120}$/.test(v.id))) && isStr(v.name, 200));
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
 * @param {object} [deps.maps] - MapService (drive:map:tile, the same one as the chats'); without it 'unsupported'
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerDriveHandlers(handle, { drive: s, sync = null, maps = null, getMainWindow, log }) {
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
    if (Array.isArray(a.ids)) {
      if (!isIds(a.ids, 5000) || (a.mode !== 'view' && a.mode !== 'download') || !isStr(a.expires, 10) || !(a.pin === undefined || a.pin === null || a.pin === '' || isStr(a.pin, 12))) return invalid();
      return s.createLink({ ids: a.ids, mode: a.mode, expires: a.expires, pin: a.pin || null });
    }
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
  handle('drive:pick-folders', wrap(async () => s.pickFolders()));
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
  handle('drive:portal', wrap(async (a) => (optId(a.id) ? s.openInPortal(a.id || null) : invalid())));
  handle('drive:guard', wrap(async (a) => s.guard({ fresh: a.fresh === true })));
  handle('drive:guard:decide', wrap(async (a) => {
    const idOk = isId(a.id) || (typeof a.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(a.id));
    return idOk && (a.decision === 'undo' || a.decision === 'release') ? s.guardDecide(a.id, a.decision) : invalid();
  }));

  // ── Drive 1.7 ──────────────────────────────────────────
  handle('drive:timetravel:preview', byId(async (a) => {
    if (!isAt(a.at)) return invalid();
    const r = await s.timeTravelPreview(a.id, a.at);
    let linked = [];
    if (sync && typeof sync.linkedFolders === 'function') linked = await sync.linkedFolders(a.id).catch(() => []);
    return { ...r, linked };
  }));
  handle('drive:timetravel', byId(async (a) => (isAt(a.at) ? s.timeTravel(a.id, a.at) : invalid())));
  handle('drive:photos', wrap(async (a) => {
    if (!(optArea(a.area) && optCursor(a.before) && optLimit(a.limit) && optStr(a.q, 100) && optPlace(a.place) && optBbox(a.bbox) && optPerson(a.person) && optBool(a.districts) && optBool(a.withPeople))) return invalid();
    const more = {};
    if (a.q) more.q = a.q;
    if (a.place) more.place = a.place;
    if (a.bbox) more.bbox = a.bbox;
    if (a.person) more.person = a.person;
    if (a.districts === true) more.districts = true;
    if (a.withPeople === true) more.withPeople = true;
    return s.photos({ area: a.area || null, before: a.before || null, limit: a.limit || 100, ...more });
  }));
  handle('drive:photos:months', wrap(async (a) => {
    if (!(optArea(a.area) && optStr(a.q, 100) && optPlace(a.place) && optPerson(a.person))) return invalid();
    if (!a.q && !a.place && !a.person) return s.photoMonths(a.area || null);
    return s.photoMonths(a.area || null, { q: a.q || null, place: a.place || null, person: a.person || null });
  }));
  handle('drive:photos:memories', wrap(async (a) => {
    if (!(a.date === undefined || a.date === null || (typeof a.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(a.date)))) return invalid();
    return s.memories(a.date || null);
  }));
  handle('drive:preview:node', byId(async (a) => {
    const r = await s.previewOf(a.id, { large: a.large === true });
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));
  handle('drive:albums', wrap(async () => s.albums()));
  handle('drive:album', wrap(async (a) => (isAlbumId(a.id) && optCursor(a.before) && optLimit(a.limit) ? s.album(a.id, { before: a.before || null, limit: a.limit || 100 }) : invalid())));
  handle('drive:album:create', wrap(async (a) => (isStr(a.name, 200) && optArea(a.areaId) ? s.createAlbum({ name: a.name, areaId: a.areaId || null }) : invalid())));
  handle('drive:album:update', wrap(async (a) => {
    if (!isAlbumId(a.id)) return invalid();
    const patch = {};
    if (a.name !== undefined) { if (!isStr(a.name, 200)) return invalid(); patch.name = a.name; }
    if (a.coverId !== undefined) { if (!(a.coverId === null || isId(a.coverId))) return invalid(); patch.coverId = a.coverId; }
    if (a.frame !== undefined) { if (typeof a.frame !== 'boolean') return invalid(); patch.frame = a.frame; }
    return Object.keys(patch).length ? s.updateAlbum(a.id, patch) : invalid();
  }));
  handle('drive:album:delete', wrap(async (a) => (isAlbumId(a.id) ? s.deleteAlbum(a.id) : invalid())));
  handle('drive:album:items', wrap(async (a) => {
    if (!isAlbumId(a.id) || !Array.isArray(a.ids) || !a.ids.length || a.ids.length > 500 || !a.ids.every(isId)) return invalid();
    return s.albumItems(a.id, a.ids, { remove: a.remove === true });
  }));
  handle('drive:storage', wrap(async (a) => s.storage({ all: a.all === true })));
  handle('drive:storage:prune', wrap(async (a) => (optArea(a.areaId) && a.areaId && Number.isSafeInteger(a.keep) && a.keep >= 0 && a.keep <= 1000 ? s.pruneVersions({ areaId: a.areaId, keep: a.keep }) : invalid())));

  // ── Drive 1.16: places and people ──────────────────────
  const filterOk = (a) => optArea(a.area) && optStr(a.q, 100) && optPerson(a.person);
  const filterOf = (a) => ({ area: a.area || null, q: a.q || null, person: a.person || null });
  handle('drive:photos:places', wrap(async (a) => (filterOk(a) ? s.photoPlaces(filterOf(a)) : invalid())));
  handle('drive:photos:map', wrap(async (a) => (filterOk(a) && isBbox(a.bbox) && Number.isSafeInteger(a.zoom) && a.zoom >= 0 && a.zoom <= 19 ? s.photoMap({ bbox: a.bbox, zoom: a.zoom, ...filterOf(a) }) : invalid())));
  handle('drive:photos:suggest', wrap(async (a) => (isStr(a.q, 100) ? s.photoSuggest(a.q) : invalid())));
  handle('drive:photos:settings', wrap(async () => s.photoSettings()));
  handle('drive:photos:settings:set', wrap(async (a) => {
    const patch = {};
    for (const k of ['keepGeo', 'stripGeoOnShare', 'people', 'peopleKids']) {
      if (a[k] === undefined) continue;
      if (typeof a[k] !== 'boolean') return invalid();
      patch[k] = a[k];
    }
    return Object.keys(patch).length ? s.setPhotoSettings(patch) : invalid();
  }));
  handle('drive:photos:geo:delete', wrap(async () => s.deletePhotoGeo()));
  handle('drive:people', wrap(async () => s.people()));
  const byPerson = (fn) => wrap(async (a) => (isPersonId(a.id) ? fn(a) : invalid()));
  handle('drive:person', byPerson(async (a) => s.person(a.id)));
  handle('drive:person:update', byPerson(async (a) => {
    const patch = {};
    if (a.name !== undefined) { if (typeof a.name !== 'string' || a.name.length > 200) return invalid(); patch.name = a.name; }
    if (a.hidden !== undefined) { if (typeof a.hidden !== 'boolean') return invalid(); patch.hidden = a.hidden; }
    if (a.contact !== undefined) { if (!isContact(a.contact)) return invalid(); patch.contact = a.contact; }
    return Object.keys(patch).length ? s.updatePerson(a.id, patch) : invalid();
  }));
  handle('drive:person:merge', byPerson(async (a) => (isPersonId(a.into) && String(a.into) !== String(a.id) ? s.mergePerson(a.id, a.into) : invalid())));
  handle('drive:person:similar', byPerson(async (a) => s.similarPeople(a.id)));
  handle('drive:person:uncertain', byPerson(async (a) => (optLimit(a.limit) ? s.uncertainFaces(a.id, a.limit || 50) : invalid())));
  handle('drive:person:confirm', byPerson(async (a) => {
    if (!Array.isArray(a.faceIds) || !a.faceIds.length || a.faceIds.length > 500 || !a.faceIds.every(isPersonId) || typeof a.yes !== 'boolean') return invalid();
    return s.confirmFaces(a.id, a.faceIds, a.yes);
  }));
  handle('drive:face:move', byPerson(async (a) => (a.person === null || isPersonId(a.person) ? s.moveFace(a.id, a.person) : invalid())));
  handle('drive:map:tile', wrap(async (a) => {
    if (!maps) return { ok: false, code: 'unsupported', error: 'no map service', status: null };
    if (![a.z, a.x, a.y].every((v) => Number.isSafeInteger(v) && v >= 0)) return invalid();
    const r = await maps.tile(a.z, a.x, a.y);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));

  // ── Drive 1.8 / 1.9 ────────────────────────────────────
  handle('drive:insight', byId(async (a) => s.insight(a.id)));
  handle('drive:insight:run', byId(async (a) => s.recognize(a.id)));
  handle('drive:insight:apply', byId(async (a) => (a.name === true || a.folder === true ? s.applyInsight(a.id, { name: a.name === true, folder: a.folder === true }) : invalid())));
  handle('drive:deadlines', wrap(async (a) => (optDay(a.from) && optDay(a.to) ? s.deadlines({ from: a.from || null, to: a.to || null }) : invalid())));
  handle('drive:deadline:remind', byId(async (a) => {
    if (!(a.daysBefore === null || (Number.isSafeInteger(a.daysBefore) && a.daysBefore >= 0 && a.daysBefore <= 90))) return invalid();
    return s.remind(a.id, a.daysBefore);
  }));
  handle('drive:area:docai', wrap(async (a) => (optArea(a.areaId) && a.areaId && typeof a.on === 'boolean' ? s.setDocAi(a.areaId, a.on) : invalid())));
  handle('drive:import', wrap(async () => s.openImport()));
  handle('drive:office', byId(async (a) => s.office(a.id)));
  handle('drive:vault:status', wrap(async () => s.vaultStatus()));
  handle('drive:vaults', wrap(async () => s.vaults()));
  handle('drive:vault:create', wrap(async (a) => {
    if (!isStr(a.name, 255) || !(optArea(a.areaId) && optId(a.parentId)) || (!a.areaId && !isId(a.parentId))) return invalid();
    return s.vaultCreate(a.parentId || null, a.name, { areaId: a.areaId || null });
  }));
  const byVault = (fn) => wrap(async (a) => (isVaultId(a.vaultId) ? fn(a) : invalid()));
  handle('drive:vault:open', byVault(async (a) => s.vaultOpen(a.vaultId)));
  handle('drive:vault:request', byVault(async (a) => s.vaultRequest(a.vaultId)));
  handle('drive:vault:devices', byVault(async (a) => s.vaultDevices(a.vaultId)));
  handle('drive:vault:approve', byVault(async (a) => (isVaultId(a.deviceId) && isStr(a.safetyNumber, 30) ? s.vaultApprove(a.vaultId, a.deviceId, a.safetyNumber) : invalid())));
  handle('drive:vault:decline', byVault(async (a) => (isVaultId(a.deviceId) ? s.vaultDecline(a.vaultId, a.deviceId) : invalid())));
  handle('drive:vault:recover', byVault(async (a) => (isStr(a.recoveryKey, 200) ? s.vaultRecover(a.vaultId, a.recoveryKey) : invalid())));
  handle('drive:vault:rotate', byVault(async (a) => s.vaultRotate(a.vaultId)));
  // ── Drive 1.11 ─────────────────────────────────────────
  handle('drive:tree', byId(async (a) => s.tree(a.id)));
  handle('drive:vault:lock-status', wrap(async () => s.vaultLockStatus()));
  handle('drive:vault:unlock', wrap(async (a) => ((a.vaultId === undefined || a.vaultId === null || isVaultId(a.vaultId)) ? s.vaultUnlock(a.vaultId || null) : invalid())));
  handle('drive:vault:lock', wrap(async () => s.vaultLockNow()));
  handle('drive:vault:lock-settings', wrap(async (a) => {
    const patch = {};
    if (a.hello !== undefined) { if (typeof a.hello !== 'boolean') return invalid(); patch.hello = a.hello; }
    if (a.lockOnLeave !== undefined) { if (typeof a.lockOnLeave !== 'boolean') return invalid(); patch.lockOnLeave = a.lockOnLeave; }
    if (a.autoLockMinutes !== undefined) { if (![0, 1, 3, 5, 15].includes(a.autoLockMinutes)) return invalid(); patch.autoLockMinutes = a.autoLockMinutes; }
    return Object.keys(patch).length ? s.vaultLockSettings(patch) : invalid();
  }));
  handle('drive:vault:touch', wrap(async () => s.vaultTouch()));
  handle('drive:hello-settings', wrap(async () => s.openHelloSettings()));
  handle('drive:cache', wrap(async () => s.cacheInfo()));
  handle('drive:cache:clear', wrap(async () => s.clearCache()));
  // ── Drive 1.12 ─────────────────────────────────────────
  handle('drive:ops:check', wrap(async (a) => {
    if (!['move', 'copy', 'trash'].includes(a.op) || !isIds(a.ids) || (a.op !== 'trash' && !isId(a.target))) return invalid();
    return s.opsCheck({ op: a.op, ids: a.ids, target: a.op === 'trash' ? null : a.target });
  }));
  handle('drive:ops:start', wrap(async (a) => {
    if (!['move', 'copy', 'trash', 'restore', 'purge'].includes(a.op) || !isIds(a.ids)) return invalid();
    if ((a.op === 'move' || a.op === 'copy') && !isId(a.target)) return invalid();
    if (!(a.onConflict === undefined || a.onConflict === null || ['version', 'rename', 'skip'].includes(a.onConflict))) return invalid();
    const m = obj(a.meta);
    if (!optStr(m.name, 255) || !optStr(m.target, 2000) || !(m.count === undefined || m.count === null || (Number.isSafeInteger(m.count) && m.count >= 0)) || !(m.parents === undefined || m.parents === null || (Array.isArray(m.parents) && m.parents.length <= 100 && m.parents.every(isId)))) return invalid();
    return s.opsStart({ op: a.op, ids: a.ids, target: a.target || null, onConflict: a.onConflict || null, meta: { name: m.name || null, count: m.count || null, target: m.target || null, parents: m.parents || [] } });
  }));
  handle('drive:ops:cancel', wrap(async (a) => (isOpId(a.id) ? s.opCancel(String(a.id)) : invalid())));
  handle('drive:ops:undo', wrap(async (a) => (isOpId(a.id) ? s.opUndo(String(a.id)) : invalid())));
  handle('drive:zip', wrap(async (a) => (isIds(a.ids) && optStr(a.name, 255) ? s.zip(a.ids, { name: a.name || null }) : invalid())));
  // ── Drive 1.14 ─────────────────────────────────────────
  // Drive 1.17: a target is null / { kind: 'family' } / { kind: 'mail', calendarId (≤ 200), label? (≤ 200) }
  const isTarget = (t) => t === null || (t !== undefined && typeof t === 'object' && !Array.isArray(t) && (
    (t.kind === 'family') || (t.kind === 'mail' && isStr(t.calendarId, 200) && optStr(t.label, 200))));
  handle('drive:deadline:calendar', byId(async (a) => {
    if (a.target !== undefined && a.target !== null && !isTarget(a.target)) return invalid();
    return s.calendar(a.id, a.target || null);
  }));
  handle('drive:deadline:calendars', wrap(async () => s.deadlineCalendars()));
  handle('drive:deadline:targets', wrap(async () => s.deadlineTargets()));
  handle('drive:deadline:target', wrap(async (a) => (optArea(a.areaId) && a.areaId && isTarget(a.target) ? s.setDeadlineTarget(a.areaId, a.target) : invalid())));
  handle('drive:ask', wrap(async (a) => (isStr(a.q, 300) && a.q.trim().length >= 3 && optArea(a.area) ? s.ask(a.q, a.area || null) : invalid())));
  handle('drive:scan:status', wrap(async () => s.scanStatus()));
  handle('drive:scan:prepare', wrap(async (a) => (isIds(a.ids, 8) ? s.scanPrepare(a.ids) : invalid())));
  handle('drive:area:calendar', wrap(async (a) => (optArea(a.areaId) && a.areaId && typeof a.on === 'boolean' ? s.setDeadlinesToCalendar(a.areaId, a.on) : invalid())));
  const isScanId = (v) => typeof v === 'string' && /^[0-9a-f]{24}$/.test(v);
  handle('drive:scan:save', wrap(async (a) => {
    if (!isScanId(a.scanId) || !['pdf', 'docx', 'xlsx', 'image'].includes(a.target) || !optId(a.folderId) || !optStr(a.name, 255) || typeof a.keepOriginal !== 'boolean') return invalid();
    return s.scanSave(a.scanId, { target: a.target, folderId: a.folderId || null, name: a.name || null, keepOriginal: a.keepOriginal });
  }));
  handle('drive:scan:discard', wrap(async (a) => (isScanId(a.scanId) ? s.scanDiscard(a.scanId) : invalid())));

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
    handle('drive:sync:suspect', wrap(async (a) => (isFolderId(a.id) && (a.decision === 'upload' || a.decision === 'keep') ? sync.confirmSuspect(a.id, a.decision) : invalid())));
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
