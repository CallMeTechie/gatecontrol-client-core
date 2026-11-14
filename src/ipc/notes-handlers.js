'use strict';

/**
 * IPC of "Notizen & Aufgaben" (opt-in: registerBaseHandlers(…, { notes })). Arguments from the renderer are checked
 * here (utils/notes.js) and again by the plugin. Every handler resolves; failures come back as
 * { ok: false, code, error, status, field? }.
 *
 *   notes:status · notes:check · notes:me ({ refresh? })
 *   notes:nav ({ area }) · notes:view ({ name, area }) · notes:parse ({ text, area }) · notes:people
 *   notes:search ({ q, area }) · notes:prefs · notes:prefs:set ({ patch }) · notes:sources · notes:sources:sync ({ plugin })
 *   notes:lists ({ area }) · notes:list:create ({ name, area, color?, groupId? }) · notes:list:update ({ id, patch })
 *   notes:list:delete ({ id }) · notes:list:members ({ id, members }) · notes:group:create ({ name, area })
 *   notes:group:update ({ id, name?, position? }) · notes:group:delete ({ id })
 *   notes:task:create ({ task }) · notes:task ({ id }) · notes:task:update ({ id, patch }) · notes:task:complete ({ id, done })
 *   notes:task:move ({ id, to }) · notes:yesterday ({ area? }) · notes:yesterday:decide ({ action, to?, ids?, area? })
 *   notes:task:delete ({ id }) · notes:item ({ id }) · notes:item:complete ({ id, done }) · notes:item:carry ({ id })
 *   notes:notebooks ({ area }) · notes:notebook:create ({ name, area, color?, vault? }) → recoveryKey for a Tresor
 *   notes:notebook:update ({ id, patch }) · notes:notebook:delete ({ id }) · notes:notebook:members ({ id, members })
 *   notes:notes ({ query }) · notes:note ({ id }) · notes:note:create ({ note }) · notes:note:update ({ id, patch })
 *   notes:note:delete ({ id }) · notes:note:check ({ id, line, done }) · notes:note:task ({ id, line, listId?, myDay? })
 *   notes:attach ({ kind, refId, images? }) (the file dialog) · notes:attachment:image ({ id, vaultId? }) → { mime, data }
 *   notes:attachment:open ({ id, vaultId? }) · notes:attachment:save ({ id, vaultId? }) · notes:attachment:delete ({ id })
 *   notes:vault:status · notes:vault:unlock ({ vaultId? }) · notes:vault:lock · notes:vault:settings ({ patch })
 *   notes:vault:info · notes:vault:open · notes:vault:request · notes:vault:devices ({ vaultId })
 *   notes:vault:approve ({ vaultId, deviceId, safetyNumber }) · notes:vault:decline ({ vaultId, deviceId })
 *   notes:vault:recover ({ vaultId, text }) · notes:vault:rotate ({ vaultId })
 *   notes:mstodo:accounts · notes:mstodo:consent ({ accountId }) · notes:mstodo:poll ({ accountId, deviceId })
 *   notes:mstodo:open ({ uri }) · notes:mstodo:preview ({ accountId }) · notes:mstodo:start ({ accountId, lists, doneDays, twoWay })
 *   notes:job ({ id }) · notes:mstodo:links · notes:mstodo:unlink ({ id })
 *   notes:dsnote:pick · notes:dsnote:import ({ password?, area }) · notes:dsnote:cancel
 *
 * Events to the main window: notes:state, notes:changed, notes:vault, notes:vault-lock, notes:import.
 */

const N = require('../utils/notes');

const NOTES_EVENTS = {
  state: 'notes:state',
  changed: 'notes:changed',
  vault: 'notes:vault',
  vaultLock: 'notes:vault-lock',
  import: 'notes:import',
};

function fail(err) {
  const out = { ok: false, code: N.errorCode(err), error: (err && err.message) || 'failed', status: (err && err.status) || null };
  const b = err && err.body;
  if (b && typeof b === 'object') {
    if (typeof b.field === 'string') out.field = b.field.slice(0, 60);
    if (typeof b.reason === 'string') out.reason = b.reason.slice(0, 60);
  }
  return out;
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const invalid = (field = null) => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null, field });
const area = (v) => N.areaOf(v) || 'private';
const VID = (v) => N.vaultIdOf(v);

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.notes - NotesService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerNotesHandlers(handle, { notes: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const id = (v) => N.posId(v);
  const on = (ch, fn) => handle(ch, wrap(fn));

  handle('notes:status', () => s.status());
  on('notes:check', async () => s.check());
  on('notes:me', async (a) => s.me({ refresh: a.refresh === true }));
  on('notes:nav', async (a) => s.nav({ area: area(a.area) }));
  on('notes:view', async (a) => (N.viewName(a.name) ? s.view({ name: a.name, area: area(a.area) }) : invalid('name')));
  on('notes:parse', async (a) => (typeof a.text === 'string' && a.text.length <= 1000 ? s.parse({ text: a.text, area: area(a.area) }) : invalid('text')));
  on('notes:people', async () => s.people());
  on('notes:search', async (a) => {
    const q = typeof a.q === 'string' ? a.q.trim() : '';
    return q.length >= 2 && q.length <= N.QUERY_MAX ? s.search({ q, area: area(a.area) }) : invalid('q');
  });
  on('notes:prefs', async () => s.prefs());
  on('notes:prefs:set', async (a) => {
    const p = obj(a.patch);
    const body = {};
    if (p.area !== undefined) { if (!N.areaOf(p.area)) return invalid('area'); body.area = p.area; }
    if (p.evening !== undefined) { if (!N.timeOf(p.evening)) return invalid('evening'); body.evening = p.evening; }
    if (p.sources !== undefined) {
      const clean = N.normalizePrefs({ sources: p.sources }).sources;
      if (!Object.keys(clean).length) return invalid('sources');
      body.sources = clean;
    }
    if (p.groups !== undefined) {
      const clean = N.normalizePrefs({ groups: p.groups }).groups;
      if (!Object.keys(clean).length) return invalid('groups');
      body.groups = clean;
    }
    if (p.times !== undefined) body.times = N.normalizePrefs({ times: p.times }).times;
    return Object.keys(body).length ? s.setPrefs(body) : invalid('patch');
  });
  on('notes:sources', async () => s.sources());
  on('notes:sources:sync', async (a) => (N.SOURCES.includes(a.plugin) ? s.syncSource(a.plugin) : invalid('plugin')));

  // lists and groups
  on('notes:lists', async (a) => s.lists({ area: area(a.area) }));
  on('notes:list:create', async (a) => {
    const name = N.nameArg(a.name);
    if (!name) return invalid('name');
    const body = { name, area: area(a.area) };
    if (a.color) { if (!N.colorOf(a.color)) return invalid('color'); body.color = a.color; }
    if (a.groupId) { if (!id(a.groupId)) return invalid('groupId'); body.groupId = a.groupId; }
    return s.createList(body);
  });
  on('notes:list:update', async (a) => {
    const p = obj(a.patch);
    const body = {};
    if (p.name !== undefined) { const n = N.nameArg(p.name); if (!n) return invalid('name'); body.name = n; }
    if (p.color !== undefined) { if (p.color !== null && !N.colorOf(p.color)) return invalid('color'); body.color = p.color || 'none'; }
    if (p.area !== undefined) { if (!N.areaOf(p.area)) return invalid('area'); body.area = p.area; }
    if (p.groupId !== undefined) { if (p.groupId !== null && !id(p.groupId)) return invalid('groupId'); body.groupId = p.groupId; }
    if (p.position !== undefined) { if (!Number.isFinite(p.position)) return invalid('position'); body.position = p.position; }
    return id(a.id) ? s.updateList(a.id, body) : invalid('id');
  });
  on('notes:list:delete', async (a) => (id(a.id) ? s.deleteList(a.id) : invalid('id')));
  on('notes:list:members', async (a) => {
    const m = N.membersArg(a.members);
    return id(a.id) && m ? s.setListMembers(a.id, m) : invalid('members');
  });
  on('notes:group:create', async (a) => { const name = N.nameArg(a.name); return name ? s.createGroup({ name, area: area(a.area) }) : invalid('name'); });
  on('notes:group:update', async (a) => {
    const body = {};
    if (a.name !== undefined) { const n = N.nameArg(a.name); if (!n) return invalid('name'); body.name = n; }
    if (a.position !== undefined) { if (!Number.isFinite(a.position)) return invalid('position'); body.position = a.position; }
    return id(a.id) ? s.updateGroup(a.id, body) : invalid('id');
  });
  on('notes:group:delete', async (a) => (id(a.id) ? s.deleteGroup(a.id) : invalid('id')));

  // tasks and items
  on('notes:task:create', async (a) => { const b = N.taskCreate(a.task); return b ? s.createTask(b) : invalid('task'); });
  on('notes:task', async (a) => (id(a.id) ? s.task(a.id) : invalid('id')));
  on('notes:task:update', async (a) => {
    const b = N.taskPatch(a.patch);
    return id(a.id) && b && Object.keys(b).length ? s.updateTask(a.id, b) : invalid('patch');
  });
  on('notes:task:complete', async (a) => (id(a.id) && typeof a.done === 'boolean' ? s.completeTask(a.id, a.done) : invalid('id')));
  on('notes:task:delete', async (a) => (id(a.id) ? s.deleteTask(a.id) : invalid('id')));
  on('notes:task:move', async (a) => {
    if (!id(a.id)) return invalid('id');
    const to = N.moveArg(a.to);
    return to ? s.moveTask(a.id, to) : invalid('to');
  });
  on('notes:yesterday', async (a) => (a.area == null || N.areaOf(a.area) ? s.yesterday({ area: a.area || undefined }) : invalid('area')));
  on('notes:yesterday:decide', async (a) => { const b = N.yesterdayArg(a); return b ? s.decideYesterday(b) : invalid('action'); });
  on('notes:item', async (a) => (id(a.id) ? s.item(a.id) : invalid('id')));
  on('notes:item:complete', async (a) => (id(a.id) && typeof a.done === 'boolean' ? s.completeItem(a.id, a.done) : invalid('id')));
  on('notes:item:carry', async (a) => (id(a.id) ? s.carryItem(a.id) : invalid('id')));

  // notebooks and notes
  on('notes:notebooks', async (a) => s.notebooks({ area: area(a.area) }));
  on('notes:notebook:create', async (a) => {
    const name = N.nameArg(a.name);
    if (!name) return invalid('name');
    if (a.color && !N.colorOf(a.color)) return invalid('color');
    return s.createNotebook({ name, area: area(a.area), color: a.color || null, vault: a.vault === true });
  });
  on('notes:notebook:update', async (a) => {
    const p = obj(a.patch);
    const body = {};
    if (p.name !== undefined) { const n = N.nameArg(p.name); if (!n) return invalid('name'); body.name = n; }
    if (p.color !== undefined) { if (p.color !== null && !N.colorOf(p.color)) return invalid('color'); body.color = p.color || 'none'; }
    if (p.area !== undefined) { if (!N.areaOf(p.area)) return invalid('area'); body.area = p.area; }
    if (p.position !== undefined) { if (!Number.isFinite(p.position)) return invalid('position'); body.position = p.position; }
    return id(a.id) && Object.keys(body).length ? s.updateNotebook(a.id, body) : invalid('patch');
  });
  on('notes:notebook:delete', async (a) => (id(a.id) ? s.deleteNotebook(a.id) : invalid('id')));
  on('notes:notebook:members', async (a) => {
    const m = N.membersArg(a.members);
    return id(a.id) && m ? s.setNotebookMembers(a.id, m) : invalid('members');
  });
  on('notes:notes', async (a) => { const q = N.notesQuery(a.query); return q ? s.notes(q) : invalid('query'); });
  on('notes:note', async (a) => (id(a.id) ? s.note(a.id) : invalid('id')));
  on('notes:note:create', async (a) => {
    const n = obj(a.note);
    const b = N.notePatch({ title: n.title === undefined ? '' : n.title, body: n.body === undefined ? '' : n.body, pinned: n.pinned, color: n.color });
    if (!b) return invalid('note');
    if (n.notebookId !== undefined && n.notebookId !== null && !id(n.notebookId)) return invalid('notebookId');
    return s.createNote({ ...b, notebookId: n.notebookId || null, area: area(n.area) });
  });
  on('notes:note:update', async (a) => {
    const b = N.notePatch(a.patch);
    return id(a.id) && b && Object.keys(b).length ? s.updateNote(a.id, b) : invalid('patch');
  });
  on('notes:note:delete', async (a) => (id(a.id) ? s.deleteNote(a.id) : invalid('id')));
  on('notes:note:check', async (a) => (id(a.id) && Number.isSafeInteger(a.line) && a.line >= 0 && typeof a.done === 'boolean' ? s.checkNote(a.id, a.line, a.done) : invalid('line')));
  on('notes:note:task', async (a) => {
    if (!id(a.id) || !Number.isSafeInteger(a.line) || a.line < 0) return invalid('line');
    const body = { line: a.line };
    if (a.listId !== undefined && a.listId !== null) { if (!id(a.listId)) return invalid('listId'); body.listId = a.listId; }
    if (a.myDay !== undefined) body.myDay = a.myDay === true;
    return s.noteToTask(a.id, body);
  });

  // attachments
  on('notes:attach', async (a) => (['note', 'task'].includes(a.kind) && id(a.refId) ? s.addAttachments({ kind: a.kind, refId: a.refId, images: a.images === true }) : invalid('refId')));
  const vopt = (a) => (a.vaultId === undefined || a.vaultId === null ? {} : { vaultId: VID(a.vaultId) });
  on('notes:attachment:image', async (a) => {
    if (!id(a.id) || (a.vaultId != null && !VID(a.vaultId))) return invalid('id');
    const r = await s.attachmentImage(a.id, vopt(a));
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  });
  on('notes:attachment:open', async (a) => (id(a.id) && (a.vaultId == null || VID(a.vaultId)) ? s.openAttachment(a.id, vopt(a)) : invalid('id')));
  on('notes:attachment:save', async (a) => (id(a.id) && (a.vaultId == null || VID(a.vaultId)) ? s.saveAttachment(a.id, vopt(a)) : invalid('id')));
  on('notes:attachment:delete', async (a) => (id(a.id) ? s.deleteAttachment(a.id) : invalid('id')));

  // Tresor notebooks
  on('notes:vault:status', async () => s.vaultStatus());
  on('notes:vault:unlock', async (a) => (a.vaultId == null || VID(a.vaultId) ? s.vaultUnlock(VID(a.vaultId)) : invalid('vaultId')));
  on('notes:vault:lock', async () => s.vaultLockNow());
  on('notes:vault:settings', async (a) => s.vaultLockSettings(obj(a.patch)));
  on('notes:vault:info', async (a) => (VID(a.vaultId) ? s.vaultInfo(a.vaultId) : invalid('vaultId')));
  on('notes:vault:open', async (a) => (VID(a.vaultId) ? s.vaultOpen(a.vaultId) : invalid('vaultId')));
  on('notes:vault:request', async (a) => (VID(a.vaultId) ? s.vaultRequest(a.vaultId) : invalid('vaultId')));
  on('notes:vault:devices', async (a) => (VID(a.vaultId) ? s.vaultDevices(a.vaultId) : invalid('vaultId')));
  on('notes:vault:approve', async (a) => (VID(a.vaultId) && VID(a.deviceId) && typeof a.safetyNumber === 'string' && /^\d{5}( \d{5}){3}$/.test(a.safetyNumber)
    ? s.vaultApprove(a.vaultId, a.deviceId, a.safetyNumber) : invalid('safetyNumber')));
  on('notes:vault:decline', async (a) => (VID(a.vaultId) && VID(a.deviceId) ? s.vaultDecline(a.vaultId, a.deviceId) : invalid('deviceId')));
  on('notes:vault:recover', async (a) => (VID(a.vaultId) && typeof a.text === 'string' && a.text.length <= 200 ? s.vaultRecover(a.vaultId, a.text) : invalid('text')));
  on('notes:vault:rotate', async (a) => (VID(a.vaultId) ? s.vaultRotate(a.vaultId) : invalid('vaultId')));

  // moving over
  on('notes:mstodo:accounts', async () => s.msAccounts());
  on('notes:mstodo:consent', async (a) => (id(a.accountId) ? s.msConsent(a.accountId) : invalid('accountId')));
  on('notes:mstodo:poll', async (a) => (id(a.accountId) && typeof a.deviceId === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(a.deviceId) ? s.msConsentPoll(a.accountId, a.deviceId) : invalid('deviceId')));
  on('notes:mstodo:open', async (a) => (typeof a.uri === 'string' && a.uri.length <= 300 ? s.openVerification(a.uri) : invalid('uri')));
  on('notes:mstodo:preview', async (a) => (id(a.accountId) ? s.msPreview(a.accountId) : invalid('accountId')));
  on('notes:mstodo:start', async (a) => {
    if (!id(a.accountId) || !Array.isArray(a.lists) || a.lists.length > 500 || !N.DONE_DAYS.includes(a.doneDays)) return invalid('lists');
    const lists = [];
    for (const l of a.lists) {
      const x = obj(l);
      if (typeof x.id !== 'string' || x.id.length > 400 || !N.areaOf(x.area)) return invalid('lists');
      lists.push({ id: x.id, name: N.line(x.name, 200) || '', area: x.area, include: x.include !== false });
    }
    return s.msStart({ accountId: a.accountId, lists, doneDays: a.doneDays, twoWay: a.twoWay === true });
  });
  on('notes:job', async (a) => (id(a.id) ? s.job(a.id) : invalid('id')));
  on('notes:mstodo:links', async () => s.msLinks());
  on('notes:mstodo:unlink', async (a) => (id(a.id) ? s.msUnlink(a.id) : invalid('id')));
  on('notes:dsnote:pick', async () => s.dsPick());
  on('notes:dsnote:import', async (a) => (typeof (a.password ?? '') === 'string' && String(a.password ?? '').length <= 500 ? s.dsImport({ password: a.password || '', area: area(a.area) }) : invalid('password')));
  on('notes:dsnote:cancel', async () => s.dsCancel());

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(NOTES_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerNotesHandlers, NOTES_EVENTS };
