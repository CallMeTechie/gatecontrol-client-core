'use strict';

/**
 * IPC of "Mail" (opt-in: registerBaseHandlers(…, { mail })).
 * Arguments from the renderer are checked here and again in MailService / utils/mail.js.
 * Every handler resolves; failures come back as { ok: false, code, error, status, detail? }.
 *
 *   mail:status            () → MailService.status()
 *   mail:check             () → status after asking the server again
 *   mail:me                () → { ok, features, limits, microsoft, accounts, unread, settings, offline? }
 *   mail:settings          ({ threads?, swipeLeft?, swipeRight? }) → { ok, settings }
 *   mail:providers         () → { ok, providers }
 *   mail:discover          ({ email }) → { ok, provider, auth, imap, smtp, hint }
 *   mail:account:add       ({ provider, email, password, username?, name?, color?, kind?, imap?, smtp? }) → { ok, account }
 *   mail:account:microsoft ({ accountId?, name?, color?, kind? }) → { ok, account }   browser sign-in (PKCE, loopback)
 *   mail:signin:cancel     () → { ok }
 *   mail:account:update    ({ id, name?, color?, kind?, push?, ai?, attachments?, signature?, password? }) → { ok, account }
 *   mail:account:delete    ({ id }) → { ok }
 *   mail:folders           () → { ok, accounts: [{ accountId, folders }], offline? }
 *   mail:list              ({ box?, folder?, tab?, unread?, flagged?, attachments?, before?, limit? }) → { ok, items, next, counts, offline? }
 *   mail:search            ({ q, box?, from?, after?, before?, attachments?, unread?, cursor? }) → { ok, items, next, remote }
 *   mail:thread            ({ id }) → { ok, items: [Message + doc] }
 *   mail:message           ({ id, markRead? }) → { ok, message, doc, offline? }
 *   mail:images            ({ id, allow: 'once' | 'sender' }) → { ok, message, doc }
 *   mail:flags             ({ ids, unread?, flagged? }) → { ok, items? }
 *   mail:act               ({ action: 'archive'|'delete'|'junk'|'move'|'tab', ids, folderId?, tab? }) → { ok, items? }
 *   mail:attachment:open   ({ id, attachmentId, name?, mime? }) → { ok, path } | { ok: false, code: 'unsafe' }
 *   mail:attachment:save   ({ id, attachmentId, name? }) → { ok, path } | { ok: false, code: 'cancelled' }
 *   mail:pick              () → file dialog → { ok, paths } | { ok: false, code: 'cancelled' }
 *   mail:upload            ({ paths }) → { ok, items: [{ mediaId, name, size, mime }], rejected }
 *   mail:editor            ({ html }) → { ok, doc }   the editor frame's document
 *   mail:draft:create      ({ accountId?, to?, cc?, bcc?, subject?, html?, replyTo?, mode?, attachments? }) → { ok, draft }
 *   mail:draft:update      ({ id, …same }) → { ok, draft }
 *   mail:draft:get         ({ id }) → { ok, draft }
 *   mail:draft:delete      ({ id }) → { ok }
 *   mail:send              ({ id, sendAt? }) → { ok, outboxId, undoUntil, sendAt }
 *   mail:send:cancel       ({ outboxId }) → { ok, draftId, draft }
 *   mail:outbox            () → { ok, items }
 *   mail:contacts          ({ q }) → { ok, items }
 *   mail:ai                ({ id }) → { ok, ai }  ·  mail:ai:run ({ id, again? }) → { ok, ai }   again: "Neu erstellen"
 *   mail:ai:todo           ({ id, index }) → { ok, where }   into the family calendar
 *   mail:drive:suggest     ({ id, attachmentId }) → { ok, suggestion, duplicate }
 *   mail:drive:save        ({ id, attachmentId, folderId?, name?, remember? }) → { ok, savedTo }
 *   mail:drive:save-all    ({ id }) → { ok, saved, failed }
 *   mail:filing            () → { ok, items }
 *   mail:filing:confirm    ({ id, folderId?, name? }) → { ok, savedTo }
 *   mail:filing:dismiss    ({ id }) → { ok }
 *
 * Events to the main window: mail:state, mail:changed ({ accountId, folderId }), mail:outbox.
 */

const MAIL_EVENTS = {
  state: 'mail:state',
  changed: 'mail:changed',
  outbox: 'mail:outbox',
};

function fail(err) {
  const out = { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
  const d = err && err.detail;
  if (d && typeof d === 'object') out.detail = d;
  return out;
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
const isId = (v) => Number.isSafeInteger(v) && v > 0;
const isIds = (v) => Array.isArray(v) && v.length > 0 && v.length <= 500 && v.every(isId);
const isStr = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;
const optStr = (v, max) => v === undefined || v === null || (typeof v === 'string' && v.length <= max);

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.mail - MailService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerMailHandlers(handle, { mail: s, getMainWindow, log }) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const byId = (fn) => wrap(async (a) => (isId(a.id) ? fn(a) : invalid()));
  const draftInput = (a) => {
    const out = {};
    for (const k of ['accountId', 'to', 'cc', 'bcc', 'subject', 'html', 'replyTo', 'mode', 'attachments']) if (a[k] !== undefined) out[k] = a[k];
    return out;
  };

  handle('mail:status', () => s.status());
  handle('mail:check', wrap(async () => s.check()));
  handle('mail:me', wrap(async () => s.me()));
  handle('mail:settings', wrap(async (a) => s.settings({ threads: a.threads, swipeLeft: a.swipeLeft, swipeRight: a.swipeRight })));
  handle('mail:providers', wrap(async () => s.providers()));
  handle('mail:discover', wrap(async (a) => (isStr(a.email, 320) ? s.discover(a.email) : invalid())));
  handle('mail:account:add', wrap(async (a) => {
    if (!isStr(a.provider, 20) || !isStr(a.email, 320) || !isStr(a.password, 1024)) return invalid();
    return s.addAccount({ provider: a.provider, email: a.email, password: a.password, username: a.username, name: a.name, color: a.color, kind: a.kind, imap: a.imap, smtp: a.smtp });
  }));
  handle('mail:account:microsoft', wrap(async (a) => {
    if (!(a.accountId === undefined || a.accountId === null || isId(a.accountId)) || !optStr(a.name, 120) || !optStr(a.color, 7) || !optStr(a.kind, 20)) return invalid();
    return s.signInMicrosoft({ accountId: a.accountId || null, name: a.name || undefined, color: a.color || undefined, kind: a.kind || undefined });
  }));
  handle('mail:signin:cancel', wrap(async () => s.cancelSignIn()));
  handle('mail:account:update', byId(async (a) => {
    const patch = {};
    for (const k of ['name', 'color', 'kind', 'push', 'ai', 'attachments', 'signature', 'password']) if (a[k] !== undefined) patch[k] = a[k];
    return s.updateAccount(a.id, patch);
  }));
  handle('mail:account:delete', byId(async (a) => s.deleteAccount(a.id)));
  handle('mail:folders', wrap(async () => s.folders()));
  handle('mail:list', wrap(async (a) => s.list({
    box: a.box, folder: a.folder, tab: a.tab, unread: a.unread === true, flagged: a.flagged === true,
    attachments: a.attachments === true, before: a.before, limit: a.limit,
  })));
  handle('mail:search', wrap(async (a) => (isStr(a.q, 200) ? s.search({
    q: a.q, box: a.box, from: a.from, after: a.after, before: a.before, attachments: a.attachments === true, unread: a.unread === true, cursor: a.cursor,
  }) : invalid())));
  handle('mail:thread', byId(async (a) => s.thread(a.id)));
  handle('mail:message', byId(async (a) => s.message(a.id, { markRead: a.markRead !== false })));
  handle('mail:images', byId(async (a) => (a.allow === 'once' || a.allow === 'sender' ? s.allowImages(a.id, a.allow) : invalid())));
  handle('mail:flags', wrap(async (a) => {
    if (!isIds(a.ids) || (typeof a.unread !== 'boolean' && typeof a.flagged !== 'boolean')) return invalid();
    return s.flags(a.ids, { unread: a.unread, flagged: a.flagged });
  }));
  handle('mail:act', wrap(async (a) => {
    if (!isIds(a.ids) || !['archive', 'delete', 'junk', 'move', 'tab'].includes(a.action)) return invalid();
    if (a.action === 'move' && !isId(a.folderId)) return invalid();
    if (a.action === 'tab' && a.tab !== 'relevant' && a.tab !== 'other') return invalid();
    return s.act(a.action, a.ids, { folderId: a.folderId || null, tab: a.tab || null });
  }));
  handle('mail:attachment:open', byId(async (a) => (isId(a.attachmentId) && optStr(a.name, 255) && optStr(a.mime, 120)
    ? s.openAttachment(a.id, a.attachmentId, { name: a.name || null, mime: a.mime || null }) : invalid())));
  handle('mail:attachment:save', byId(async (a) => (isId(a.attachmentId) && optStr(a.name, 255) ? s.saveAttachment(a.id, a.attachmentId, { name: a.name || null }) : invalid())));
  handle('mail:pick', wrap(async () => s.pickFiles()));
  handle('mail:upload', wrap(async (a) => {
    if (!Array.isArray(a.paths) || !a.paths.length || a.paths.length > 20 || !a.paths.every((p) => isStr(p, 4096))) return invalid();
    return s.uploadFiles(a.paths);
  }));
  handle('mail:editor', wrap(async (a) => (optStr(a.html, 2 * 1024 * 1024) ? s.editorDoc(a.html || '') : invalid())));
  handle('mail:draft:create', wrap(async (a) => s.createDraft(draftInput(a))));
  handle('mail:draft:update', byId(async (a) => s.updateDraft(a.id, draftInput(a))));
  handle('mail:draft:get', byId(async (a) => s.draft(a.id)));
  handle('mail:draft:delete', byId(async (a) => s.deleteDraft(a.id)));
  handle('mail:send', byId(async (a) => {
    if (!(a.sendAt === undefined || a.sendAt === null || (Number.isSafeInteger(a.sendAt) && a.sendAt > 0))) return invalid();
    return s.send(a.id, a.sendAt || null);
  }));
  handle('mail:send:cancel', wrap(async (a) => (isId(a.outboxId) ? s.cancelSend(a.outboxId) : invalid())));
  handle('mail:outbox', wrap(async () => s.outbox()));
  handle('mail:contacts', wrap(async (a) => (optStr(a.q, 100) ? s.contacts(a.q || '') : invalid())));
  handle('mail:ai', byId(async (a) => s.ai(a.id)));
  handle('mail:ai:run', byId(async (a) => s.runAi(a.id, { again: a.again === true })));
  handle('mail:ai:todo', byId(async (a) => (Number.isSafeInteger(a.index) && a.index >= 0 && a.index <= 50 ? s.todo(a.id, a.index) : invalid())));
  handle('mail:drive:suggest', byId(async (a) => (isId(a.attachmentId) ? s.suggest(a.id, a.attachmentId) : invalid())));
  handle('mail:drive:save', byId(async (a) => {
    if (!isId(a.attachmentId) || !(a.folderId === undefined || a.folderId === null || isId(a.folderId)) || !optStr(a.name, 255)) return invalid();
    return s.saveToDrive(a.id, a.attachmentId, { folderId: a.folderId || null, name: a.name || null, remember: typeof a.remember === 'boolean' ? a.remember : undefined });
  }));
  handle('mail:drive:save-all', byId(async (a) => s.saveAll(a.id)));
  handle('mail:filing', wrap(async () => s.filing()));
  handle('mail:filing:confirm', byId(async (a) => {
    if (!(a.folderId === undefined || a.folderId === null || isId(a.folderId)) || !optStr(a.name, 255)) return invalid();
    return s.confirmFiling(a.id, { folderId: a.folderId || null, name: a.name || null });
  }));
  handle('mail:filing:dismiss', byId(async (a) => s.dismissFiling(a.id)));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(MAIL_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerMailHandlers, MAIL_EVENTS };
