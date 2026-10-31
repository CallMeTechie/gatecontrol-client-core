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
 *   mail:avatar            ({ mediaId }) → { ok, mime, url }   an account's picture as a data: URL
 *   mail:folders           () → { ok, accounts: [{ accountId, folders }], offline? }
 *   mail:list              ({ box?, folder?, tab?, unread?, flagged?, attachments?, before?, limit? }) → { ok, items, next, counts, offline? }
 *   mail:search            ({ q?, box?, from?, after?, before?, attachments?, unread?, cursor? }) → { ok, items, next, remote } (q or from)
 *   mail:thread            ({ id }) → { ok, items: [Message + doc + docDark] }
 *   mail:message           ({ id, markRead? }) → { ok, message, doc, docDark, offline? }
 *   mail:images            ({ id, allow: 'once' | 'sender' }) → { ok, message, doc }
 *   mail:flags             ({ ids, unread?, flagged? }) → { ok, items? }
 *   mail:act               ({ action: 'archive'|'delete'|'junk'|'move'|'tab', ids, folderId?, tab? }) → { ok, items? }
 *   mail:attachment:open   ({ id, attachmentId, name?, mime? }) → { ok, path } | { ok: false, code: 'unsafe' }
 *                          (still on its way from the provider: { ok: false, code: 'busy', detail: { reason: 'loading', retryAfter } })
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
 *   mail:ai:todo           ({ id, index, action?: 'family_calendar' | 'calendar', calendarId? }) → { ok, where, eventId? }
 *   mail:drive:suggest     ({ id, attachmentId }) → { ok, suggestion, duplicate }
 *   mail:drive:save        ({ id, attachmentId, folderId?, name?, remember? }) → { ok, savedTo }
 *   mail:drive:save-all    ({ id }) → { ok, saved, failed }
 *   mail:filing            () → { ok, items }
 *   mail:filing:confirm    ({ id, folderId?, name? }) → { ok, savedTo }
 *   mail:filing:dismiss    ({ id }) → { ok }
 *
 * Phase 2 — calendar:
 *   mail:cal:list          () → { ok, calendars, overlays, prefs, consent, offline? }
 *   mail:cal:create        ({ name, color? }) → { ok, calendar }
 *   mail:cal:update        ({ id, name?, color?, visible?, notify? }) → { ok, calendar }
 *   mail:cal:delete        ({ id }) → { ok }
 *   mail:cal:subscribe     ({ url, name?, color?, accountId? }) → { ok, calendar }   iCal subscription
 *   mail:cal:settings      ({ defaultCalendarId?, view?, weekStart?, workWeek?, timeZone?, reminders?, defaultReminder?, allDayReminder? }) → { ok, prefs }
 *   mail:overlay:update    ({ id: 'familie' | 'alltag:<n>' | 'birthdays', visible?, color? }) → { ok, overlay }
 *   mail:events            ({ from, to, calendars? }) → { ok, items, overlays, pending, offline? }   ≤ 62 days
 *   mail:event:get         ({ id, occurrence? }) → { ok, event, doc, docDark, offline? }
 *   mail:event:create      ({ calendarId, title, allDay, start?, end?, startDate?, endDate?, … }) → { ok, event, sent }
 *   mail:event:update      ({ id, …fields, scope?, occurrence?, etag? }) → { ok, event, sent } | { ok: false, code: 'conflict', current }
 *   mail:event:delete      ({ id, scope?, occurrence?, notify?, comment? }) → { ok, sent }
 *   mail:event:respond     ({ id, response, comment?, occurrence?, proposeStart?, proposeEnd? }) → { ok, event }
 *   mail:invitations       ({ state? }) → { ok, items }
 *   mail:invitation:get    ({ id }) → { ok, invitation }
 *   mail:invitation:respond ({ id, response, comment?, calendarId?, proposeStart?, proposeEnd? }) → { ok, invitation, event }
 *   mail:invitation:apply  ({ id }) → { ok, invitation, event }
 *   mail:invitation:dismiss ({ id, decline? }) → { ok }
 * Phase 2 — contacts:
 *   mail:books             () → { ok, items, groups, prefs, offline? }
 *   mail:book:update       ({ id, visible?, name? }) → { ok, addressbook }
 *   mail:card:settings     ({ sort?, show?, defaultAddressbookId?, birthdays? }) → { ok, prefs }
 *   mail:cards             ({ q?, book?, group? }) → { ok, items, version, offline? }   searched on this PC
 *   mail:card:get          ({ id }) → { ok, card, offline? }
 *   mail:card:create       ({ addressbookId?, name, emails, … }) → { ok, card }
 *   mail:card:update       ({ id, …fields, etag }) → { ok, card, writeBack } | { ok: false, code: 'conflict', current }
 *   mail:card:delete       ({ id, linked? 'keep' | 'delete' }) → { ok }
 *   mail:card:photo        ({ id, etag? }) → { ok, mime, url }
 *   mail:card:photo:set    ({ id }) → file dialog → { ok, card } | { ok: false, code: 'cancelled' }
 *   mail:card:photo:delete ({ id }) → { ok, card }
 *   mail:card:lookup       ({ email }) → { ok, card, person, recent }
 *   mail:card:activity     ({ id }) → { ok, mails, events }
 *   mail:card:draft        ({ email, messageId? }) → { ok, draft, existing }
 *   mail:card:duplicates   ({ details? }) → { ok, items }
 *   mail:card:merge        ({ ids, primaryId?, pick? }) → { ok, card, mergeId }
 *   mail:card:ignore       ({ ids }) → { ok }
 * Mail 1.4.0 — the GC contact as the master, favourites, the calendar widget ({ ok, unsupported } from servers before):
 *   mail:card:preview      ({ ids }) → { ok, preview }
 *   mail:card:merge:auto   () → { ok, merged, open, items }
 *   mail:card:merges       ({ limit? }) → { ok, items }
 *   mail:card:merge:undo   ({ id, keepMaster? }) → { ok, card, unlinked, restored }
 *   mail:card:unmerge      ({ id, ids?, keepMaster? }) → { ok, card, unlinked, restored }
 *   mail:card:conflicts    () → { ok, items }
 *   mail:card:conflict:accept  ({ id, conflictId, mode? }) → { ok, card }
 *   mail:card:conflict:dismiss ({ id, conflictId }) → { ok, card }
 *   mail:card:favorite     ({ id, on }) → { ok, card }
 *   mail:card:main-phone   ({ id, value | null }) → { ok, card }
 *   mail:favorites         () → { ok, items, offline? }
 *   mail:favorites:set     ({ ids }) → { ok, items }
 *   mail:upcoming          ({ days?, limit? }) → { ok, timeZone, today, items, more, offline? }
 *   mail:card:import       ({ addressbookId? }) → file dialog → { ok, imported, updated, skipped } | { ok: false, code: 'cancelled' }
 *   mail:card:export       ({ book?, group? }) → save dialog → { ok, path } | { ok: false, code: 'cancelled' }
 *   mail:group:create      ({ name, color? }) → { ok, group }
 *   mail:group:update      ({ id, name?, color? }) → { ok, group }
 *   mail:group:delete      ({ id }) → { ok }
 *   mail:group:get         ({ id }) → { ok, group, members }
 *   mail:group:members     ({ id, add?, remove? }) → { ok, group, members }
 *   mail:call              ({ number }) → { ok }   tel: to the system
 *
 * Events to the main window: mail:state, mail:changed ({ accountId, folderId, messageId, threadId, attachmentId }),
 * mail:outbox, mail:loading ({ messageId, attachmentId, retryAfter }) an embedded picture still on its way,
 * mail:calendar ({ kind, … }) and mail:contacts ({ kind, … }) of the live events.
 */

const MAIL_EVENTS = {
  state: 'mail:state',
  changed: 'mail:changed',
  outbox: 'mail:outbox',
  loading: 'mail:loading',
  calendar: 'mail:calendar',
  contacts: 'mail:contacts',
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
  handle('mail:avatar', wrap(async (a) => (isStr(a.mediaId, 128) ? s.avatar(a.mediaId) : invalid())));
  handle('mail:folders', wrap(async () => s.folders()));
  handle('mail:list', wrap(async (a) => s.list({
    box: a.box, folder: a.folder, tab: a.tab, unread: a.unread === true, flagged: a.flagged === true,
    attachments: a.attachments === true, before: a.before, limit: a.limit,
  })));
  // words, or a sender alone (the sender's mails)
  handle('mail:search', wrap(async (a) => ((isStr(a.q, 200) && optStr(a.from, 200)) || (optStr(a.q, 200) && isStr(a.from, 200)) ? s.search({
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
  handle('mail:ai:todo', byId(async (a) => {
    if (!Number.isSafeInteger(a.index) || a.index < 0 || a.index > 50) return invalid();
    if (!(a.action === undefined || a.action === 'family_calendar' || a.action === 'calendar') || !(a.calendarId === undefined || a.calendarId === null || isId(a.calendarId))) return invalid();
    return s.todo(a.id, a.index, { action: a.action || 'family_calendar', calendarId: a.calendarId || null });
  }));
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

  // ── Calendar (Phase 2) ──
  const pick = (a, keys) => { const out = {}; for (const k of keys) if (a[k] !== undefined) out[k] = a[k]; return out; };
  const EVENT_KEYS = ['calendarId', 'title', 'allDay', 'start', 'end', 'startDate', 'endDate', 'timeZone', 'location', 'description', 'online', 'reminders',
    'recurrence', 'attendees', 'busy', 'private', 'sendInvites', 'fromAccountId', 'scope', 'occurrence', 'etag'];
  const CARD_KEYS = ['addressbookId', 'name', 'emails', 'phones', 'company', 'department', 'title', 'addresses', 'birthday', 'note', 'urls', 'groups', 'etag'];
  const isOcc = (v) => v === undefined || v === null || (typeof v === 'string' && /^(?:\d{10,16}|\d{4}-\d{2}-\d{2})$/.test(v));
  handle('mail:cal:list', wrap(async () => s.calendars()));
  handle('mail:cal:create', wrap(async (a) => (isStr(a.name, 80) && optStr(a.color, 7) ? s.createCalendar(pick(a, ['name', 'color'])) : invalid())));
  handle('mail:cal:update', byId(async (a) => s.updateCalendar(a.id, pick(a, ['name', 'color', 'visible', 'notify']))));
  handle('mail:cal:delete', byId(async (a) => s.deleteCalendar(a.id)));
  handle('mail:cal:subscribe', wrap(async (a) => (isStr(a.url, 2048) && optStr(a.name, 80) ? s.subscribe(pick(a, ['url', 'name', 'color', 'accountId'])) : invalid())));
  handle('mail:cal:settings', wrap(async (a) => s.calSettings(pick(a, ['defaultCalendarId', 'view', 'weekStart', 'workWeek', 'timeZone', 'reminders', 'defaultReminder', 'allDayReminder']))));
  handle('mail:overlay:update', wrap(async (a) => (isStr(a.id, 40) ? s.updateOverlay(a.id, pick(a, ['visible', 'color'])) : invalid())));
  handle('mail:events', wrap(async (a) => (Number.isSafeInteger(a.from) && Number.isSafeInteger(a.to) ? s.events(pick(a, ['from', 'to', 'calendars'])) : invalid())));
  handle('mail:event:get', byId(async (a) => (isOcc(a.occurrence) ? s.event(a.id, a.occurrence || null) : invalid())));
  handle('mail:event:create', wrap(async (a) => s.createEvent(pick(a, EVENT_KEYS))));
  handle('mail:event:update', byId(async (a) => s.updateEvent(a.id, pick(a, EVENT_KEYS))));
  handle('mail:event:delete', byId(async (a) => (isOcc(a.occurrence) && optStr(a.comment, 1000)
    ? s.deleteEvent(a.id, { scope: a.scope === 'occurrence' ? 'occurrence' : 'series', occurrence: a.occurrence || null, notify: a.notify === true, comment: a.comment || null }) : invalid())));
  handle('mail:event:respond', byId(async (a) => s.respondEvent(a.id, pick(a, ['response', 'comment', 'occurrence', 'proposeStart', 'proposeEnd', 'send']))));
  handle('mail:invitations', wrap(async (a) => s.invitations(a.state === 'all' ? 'all' : 'open')));
  handle('mail:invitation:get', byId(async (a) => s.invitation(a.id)));
  handle('mail:invitation:respond', byId(async (a) => s.respondInvitation(a.id, pick(a, ['response', 'comment', 'calendarId', 'proposeStart', 'proposeEnd']))));
  handle('mail:invitation:apply', byId(async (a) => s.applyInvitation(a.id)));
  handle('mail:invitation:dismiss', byId(async (a) => s.dismissInvitation(a.id, { decline: a.decline === true })));

  // ── Contacts (Phase 2) ──
  handle('mail:books', wrap(async () => s.addressbooks()));
  handle('mail:book:update', byId(async (a) => s.updateAddressbook(a.id, pick(a, ['visible', 'name']))));
  handle('mail:card:settings', wrap(async (a) => s.cardSettings(pick(a, ['sort', 'show', 'defaultAddressbookId', 'birthdays']))));
  handle('mail:cards', wrap(async (a) => {
    if (!optStr(a.q, 100) || !(a.book === undefined || a.book === null || a.book === 'all' || isId(a.book)) || !(a.group === undefined || a.group === null || isId(a.group))) return invalid();
    return s.cards({ q: a.q || '', book: a.book || 'all', group: a.group || null });
  }));
  handle('mail:card:get', byId(async (a) => s.card(a.id)));
  handle('mail:card:create', wrap(async (a) => s.createCard(pick(a, CARD_KEYS))));
  handle('mail:card:update', byId(async (a) => s.updateCard(a.id, pick(a, CARD_KEYS))));
  handle('mail:card:delete', byId(async (a) => (a.linked === undefined || a.linked === null || a.linked === 'keep' || a.linked === 'delete' ? s.deleteCard(a.id, { linked: a.linked || null }) : invalid())));
  handle('mail:card:photo', byId(async (a) => (optStr(a.etag, 120) ? s.cardPhoto(a.id, a.etag || null) : invalid())));
  handle('mail:card:photo:set', byId(async (a) => s.setCardPhoto(a.id)));
  handle('mail:card:photo:delete', byId(async (a) => s.deleteCardPhoto(a.id)));
  handle('mail:card:lookup', wrap(async (a) => (isStr(a.email, 320) ? s.lookup(a.email) : invalid())));
  handle('mail:card:activity', byId(async (a) => s.activity(a.id)));
  handle('mail:card:draft', wrap(async (a) => (isStr(a.email, 320) && (a.messageId === undefined || a.messageId === null || isId(a.messageId)) ? s.cardDraft({ email: a.email, messageId: a.messageId || null }) : invalid())));
  handle('mail:card:duplicates', wrap(async (a) => s.duplicates({ details: a.details === true })));
  handle('mail:card:merge', wrap(async (a) => (isIds(a.ids) && (a.primaryId === undefined || a.primaryId === null || isId(a.primaryId)) ? s.merge(pick(a, ['ids', 'primaryId', 'pick'])) : invalid())));
  handle('mail:card:preview', wrap(async (a) => (isIds(a.ids) && a.ids.length <= 10 ? s.mergePreview(a.ids) : invalid())));
  handle('mail:card:merge:auto', wrap(async () => s.autoMerge()));
  handle('mail:card:merges', wrap(async (a) => (a.limit === undefined || a.limit === null || (isId(a.limit) && a.limit <= 200) ? s.merges(a.limit || 50) : invalid())));
  handle('mail:card:merge:undo', byId(async (a) => (a.keepMaster === undefined || typeof a.keepMaster === 'boolean' ? s.undoMerge(a.id, pick(a, ['keepMaster'])) : invalid())));
  handle('mail:card:unmerge', byId(async (a) => ((a.ids === undefined || a.ids === null || (isIds(a.ids) && a.ids.length <= 20)) && (a.keepMaster === undefined || typeof a.keepMaster === 'boolean')
    ? s.unmerge(a.id, pick(a, ['ids', 'keepMaster'])) : invalid())));
  handle('mail:card:conflicts', wrap(async () => s.conflicts()));
  handle('mail:card:conflict:accept', byId(async (a) => (isId(a.conflictId) && (a.mode === undefined || a.mode === null || a.mode === 'replace' || a.mode === 'add') ? s.acceptConflict(a.id, a.conflictId, a.mode || null) : invalid())));
  handle('mail:card:conflict:dismiss', byId(async (a) => (isId(a.conflictId) ? s.dismissConflict(a.id, a.conflictId) : invalid())));
  handle('mail:card:favorite', byId(async (a) => (typeof a.on === 'boolean' ? s.setFavorite(a.id, a.on) : invalid())));
  handle('mail:card:main-phone', byId(async (a) => (a.value === null || isStr(a.value, 60) ? s.setMainPhone(a.id, a.value) : invalid())));
  handle('mail:favorites', wrap(async () => s.favorites()));
  handle('mail:favorites:set', wrap(async (a) => (Array.isArray(a.ids) && a.ids.length <= 50 && a.ids.every(isId) ? s.setFavorites(a.ids) : invalid())));
  handle('mail:upcoming', wrap(async (a) => ((a.days === undefined || (Number.isSafeInteger(a.days) && a.days >= 1 && a.days <= 7)) && (a.limit === undefined || (Number.isSafeInteger(a.limit) && a.limit >= 1 && a.limit <= 20))
    ? s.upcoming(pick(a, ['days', 'limit'])) : invalid())));
  handle('mail:card:ignore', wrap(async (a) => (isIds(a.ids) ? s.ignoreDuplicates(a.ids) : invalid())));
  handle('mail:card:import', wrap(async (a) => (a.addressbookId === undefined || a.addressbookId === null || isId(a.addressbookId) ? s.importVcf({ addressbookId: a.addressbookId || null }) : invalid())));
  handle('mail:card:export', wrap(async (a) => ((a.book === undefined || a.book === null || a.book === 'all' || isId(a.book)) && (a.group === undefined || a.group === null || isId(a.group))
    ? s.exportVcf({ book: a.book || 'all', group: a.group || null }) : invalid())));
  handle('mail:group:create', wrap(async (a) => (isStr(a.name, 80) ? s.createGroup(pick(a, ['name', 'color'])) : invalid())));
  handle('mail:group:update', byId(async (a) => s.updateGroup(a.id, pick(a, ['name', 'color']))));
  handle('mail:group:delete', byId(async (a) => s.deleteGroup(a.id)));
  handle('mail:group:get', byId(async (a) => s.group(a.id)));
  handle('mail:group:members', byId(async (a) => s.groupMembers(a.id, pick(a, ['add', 'remove']))));
  handle('mail:call', wrap(async (a) => (isStr(a.number, 40) ? s.call(a.number) : invalid())));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(MAIL_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerMailHandlers, MAIL_EVENTS };
