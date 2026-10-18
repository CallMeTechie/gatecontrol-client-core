'use strict';

/**
 * IPC of the Messenger ("Chats", opt-in: registerBaseHandlers(…, { messenger })).
 * Arguments from the renderer are checked here and again in the service.
 * Every handler resolves; failures come back as { ok: false, code, error }.
 *
 *   chat:status          () → MessengerService.status()
 *   chat:check           () → status after asking the server again
 *   chat:conversations   ({ refresh? }) → { ok, conversations, unread }
 *   chat:conversation    ({ id, refresh? }) → { ok, conversation }
 *   chat:messages        ({ id, before?, after?, around?, cached? }) → { ok, conversationId, messages, pending, hasMore, hasMoreAfter, detached, offline }
 *                        around: the page around a message (Messenger ≥ 1.1.0, else code 'unsupported'); after: newer page of that window
 *   chat:send            ({ conversationId, clientId?, kind, text?, replyTo?, meta?, location?, video?: { durationMs, width, height }, file?: { name, mime, data }, thumb?: { mime, data },
 *                          poll?, event?, action?, replyStory?: { storyId } }) → { ok, message }
 *                        video / file thumb: only sent when the server lists `video_meta` / `file_thumbs`;
 *                        kinds poll / event / action (1.4.0): code 'unsupported' without features polls / events / actions
 *   chat:outbox:retry    ({ clientId }) → { ok }
 *   chat:outbox:discard  ({ clientId }) → { ok }
 *   chat:edit            ({ id, text }) → { ok, message }
 *   chat:delete          ({ id, scope: 'me'|'all' }) → { ok, forAll, message }
 *   chat:react           ({ id, emoji|null }) → { ok, reactions }
 *   chat:read            ({ id, upTo? }) → { ok, lastReadId, unread }
 *   chat:typing          ({ id, stop? }) → { ok }
 *   chat:open            ({ id|null, visible }) → { ok }  open + visible conversation ("active", read)
 *   chat:view            ({ open }) → { ok }               chat page shown (polling cadence)
 *   chat:people          ({ refresh? }) → { ok, people }
 *   chat:create          ({ kind, userIds, title?, avatar?: { mime, data } }) → { ok, conversation, created }
 *   chat:update          ({ id, patch, avatar? }) → { ok, conversation, left }
 *   chat:prefs           ({ readReceipts?, typing?, preview? }) → { ok, prefs }
 *   chat:search          ({ id, q }) → { ok, results, truncated }
 *   chat:media:list      ({ id, kind?: 'image'|'voice'|'file'|'video'|'all', before?, limit? }) → { ok, items, counts, hasMore }
 *   chat:media           ({ mediaId }) → { ok, mime, data: Uint8Array }
 *   chat:avatar          ({ url }) → { ok, mime, data }
 *   chat:media:save      ({ mediaId, fileName? }) → { ok, path } | { ok: false, cancelled }
 *   chat:media:open      ({ mediaId, fileName? }) → { ok } | { ok: false, code: 'unsafe' }
 *   chat:map:tile        ({ z, x, y }) → { ok, mime, data: Uint8Array }   OpenStreetMap tile (services/map-service.js)
 *   chat:map:search      ({ q, lang? }) → { ok, results: [{ lat, lon, label }] }   address search (Nominatim)
 *   chat:map:reverse     ({ lat, lon, lang? }) → { ok, label|null }       address of a point
 *   chat:update-hint:dismiss () → { ok }   close the "newer version" banner (status().updateHint) for this set of features
 *
 * Messenger 1.4.0 (each answers code 'unsupported' when `GET me` lacks the feature):
 *   chat:status:feed     ({ refresh? }) → { ok, items, me, serverTime }        status strip / stories
 *   chat:status:set      ({ preset, text?, until?, visibility?, userIds?, eta?, destLabel? }) → { ok, status }
 *   chat:status:clear    () → { ok }
 *   chat:story:create    ({ kind, text?, bg?, font?, visibility?, userIds?, eventMessageId?, place?, video?, file?, thumb?, durationH? }) → { ok, story }
 *                          durationH (1/3/6/12/24) only with `story_duration` (Messenger 1.4.1)
 *   chat:story:delete    ({ id }) → { ok }
 *   chat:story:seen      ({ id }) → { ok }
 *   chat:story:viewers   ({ id }) → { ok, viewers }
 *   chat:story:react     ({ id, emoji }) → { ok, message }
 *   chat:blocks          () → { ok, blocks }
 *   chat:block           ({ userId, blocked }) → { ok, blocks }
 *   chat:archive         ({ id, archived }) → { ok, conversation }
 *   chat:pin             ({ id, messageId, pinned }) → { ok, conversation }
 *   chat:lists           ({ refresh? }) → { ok, lists }
 *   chat:lists:save      ({ lists }) → { ok, lists }
 *   chat:export          ({ id }) → { ok, path, count, truncated } | { ok: false, cancelled }   whole chat as .txt (save dialog)
 *   chat:remind          ({ id, at }) → { ok, reminder }
 *   chat:reminders       () → { ok, reminders }
 *   chat:reminder:delete ({ id }) → { ok }
 *   chat:suggest         ({ id }) → { ok, items, dates }
 *   chat:to-list         ({ id, items, list? }) → { ok, listId, listName, added, skipped }
 *   chat:to-calendar     ({ id, title, startsAt, endsAt?, allDay?, place? }) → { ok, eventId }
 *   chat:places          () → { ok, places }                                     Familie places
 *   chat:poll            ({ id, op: 'vote'|'option'|'close'|'nudge', optionIds?, text? }) → { ok, message, nudged? }
 *   chat:event           ({ id, op: 'rsvp'|'check'|'edit', answer?, guests?, itemId?, done?, patch? }) → { ok, message }
 *   chat:arrival:stop    ({ id }) → { ok, message }
 *   chat:actions         ({ refresh? }) → { ok, actions }                        attach menu "Aus deinem Zuhause"
 *   chat:action          ({ id, op: 'run'|'approve'|'deny', actionId?, plugin? }) → { ok, message, result }
 *   chat:card:image      ({ id }) → { ok, mime, data: Uint8Array }                picture of a plugin card
 *   chat:storage         () → { ok, mediaCacheBytes, avatarCacheBytes, cachedChats, cachedMessages, outbox, server }
 *   chat:cache:clear     () → { ok, … storage }
 *
 * Events to the main window: chat:state, chat:conversations, chat:messages,
 * chat:typing, chat:unread, chat:outbox, chat:navigate, chat:feed, chat:lists,
 * chat:reminders.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  posInt, isClientId, isMediaId, isAvatarPath, safeFileName, unsafeToOpen, extForMime, extOf, prefsBody,
} = require('../utils/messenger');

const CHAT_EVENTS = {
  state: 'chat:state',
  conversations: 'chat:conversations',
  messages: 'chat:messages',
  typing: 'chat:typing',
  unread: 'chat:unread',
  outbox: 'chat:outbox',
  feed: 'chat:feed',
  lists: 'chat:lists',
  reminders: 'chat:reminders',
};
const MAX_IPC_FILE = 64 * 1024 * 1024;

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/** File from the renderer: { name?, mime, data: Uint8Array|ArrayBuffer } → plain object, or null. */
function fileArg(f) {
  if (!f || typeof f !== 'object') return null;
  const data = f.data;
  const ok = data && (ArrayBuffer.isView(data) || data instanceof ArrayBuffer);
  if (!ok || data.byteLength === 0 || data.byteLength > MAX_IPC_FILE) return null;
  return {
    data,
    mime: typeof f.mime === 'string' ? f.mime.slice(0, 100) : '',
    name: typeof f.name === 'string' ? f.name.slice(0, 200) : null,
  };
}

/** Windows "Mark of the Web": files from a chat count as from the internet. */
async function markOfTheWeb(file, platform, fsp) {
  if (platform !== 'win32') return;
  try { await fsp.writeFile(`${file}:Zone.Identifier`, '[ZoneTransfer]\r\nZoneId=3\r\n'); } catch { /* not NTFS */ }
}

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.messenger - MessengerService
 * @param {object} [deps.chatNotifier] - ChatNotifier (its 'navigate' becomes chat:navigate)
 * @param {object} [deps.maps] - MapService (chat:map:*); without it those channels answer 'unsupported'
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 * @param {object} [deps.dialog] - Electron dialog (save as)
 * @param {object} [deps.shell] - Electron shell (open)
 * @param {Function} [deps.getTempDir] - () => folder for opened files
 * @param {string} [deps.platform]
 * @param {object} [deps.fsp]
 */
function registerMessengerHandlers(handle, {
  messenger: m, chatNotifier = null, maps = null, getMainWindow, log, dialog = null, shell = null,
  getTempDir = () => path.join(os.tmpdir(), 'gatecontrol-chat'), platform = process.platform, fsp = fs.promises,
}) {
  const wrap = (fn) => async (_e, arg) => {
    try {
      return await fn(obj(arg));
    } catch (err) {
      return fail(err);
    }
  };
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument' });

  handle('chat:status', () => m.status());
  handle('chat:check', wrap(async () => m.check({ force: true })));
  handle('chat:update-hint:dismiss', wrap(async () => ({ ok: m.dismissUpdateHint() })));
  handle('chat:conversations', wrap(async (a) => {
    if (a.refresh === true && m.available()) await m.refreshConversations({ full: false }).catch(() => null);
    return { ok: true, conversations: m.listConversations(), unread: m.unreadTotal() };
  }));
  handle('chat:conversation', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    return { ok: true, conversation: await m.getConversation(id, { refresh: a.refresh !== false }) };
  }));
  handle('chat:messages', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    if (a.cached === true) return { ok: true, ...m.messagesView(id) };
    const opts = {};
    for (const k of ['before', 'after', 'around']) if (posInt(a[k])) opts[k] = posInt(a[k]);
    if (!Object.keys(opts).length) opts.before = null;
    return { ok: true, ...(await m.getMessages(id, opts)) };
  }));
  handle('chat:send', wrap(async (a) => {
    const conversationId = posInt(a.conversationId);
    if (!conversationId) return invalid();
    const req = {
      conversationId,
      clientId: isClientId(a.clientId) ? a.clientId : undefined,
      kind: typeof a.kind === 'string' ? a.kind : 'text',
      text: typeof a.text === 'string' ? a.text : undefined,
      replyTo: posInt(a.replyTo) || undefined,
      meta: a.meta && typeof a.meta === 'object' ? a.meta : undefined,
      location: a.location && typeof a.location === 'object' ? a.location : undefined,
      video: a.video && typeof a.video === 'object' && !Array.isArray(a.video) ? a.video : undefined,
      file: a.file ? fileArg(a.file) : undefined,
      thumb: a.thumb ? fileArg(a.thumb) : undefined,
      // Messenger 1.4.0 (checked again in the core: utils/messenger buildSendBody)
      poll: a.poll && typeof a.poll === 'object' ? a.poll : undefined,
      event: a.event && typeof a.event === 'object' ? a.event : undefined,
      action: a.action && typeof a.action === 'object' ? a.action : undefined,
      replyStory: a.replyStory && typeof a.replyStory === 'object' ? a.replyStory : undefined,
    };
    if (a.file && !req.file) return { ok: false, code: 'invalid', error: 'invalid file' };
    return { ok: true, message: await m.send(req) };
  }));
  handle('chat:outbox:retry', wrap(async (a) => (isClientId(a.clientId) ? { ok: m.retrySend(a.clientId) } : invalid())));
  handle('chat:outbox:discard', wrap(async (a) => (isClientId(a.clientId) ? { ok: await m.discardSend(a.clientId) } : invalid())));
  handle('chat:edit', wrap(async (a) => {
    if (!posInt(a.id) || typeof a.text !== 'string') return invalid();
    return { ok: true, message: await m.edit(posInt(a.id), a.text) };
  }));
  handle('chat:delete', wrap(async (a) => {
    if (!posInt(a.id) || !['me', 'all'].includes(a.scope || 'me')) return invalid();
    return { ok: true, ...(await m.remove(posInt(a.id), a.scope || 'me')) };
  }));
  handle('chat:react', wrap(async (a) => {
    if (!posInt(a.id) || (a.emoji != null && (typeof a.emoji !== 'string' || a.emoji.length > 16))) return invalid();
    return { ok: true, reactions: await m.react(posInt(a.id), a.emoji == null ? null : a.emoji) };
  }));
  handle('chat:read', wrap(async (a) => {
    if (!posInt(a.id)) return invalid();
    const r = await m.markRead(posInt(a.id), posInt(a.upTo));
    return { ok: !!r, ...(r || {}) };
  }));
  handle('chat:typing', wrap(async (a) => {
    if (!posInt(a.id)) return invalid();
    return { ok: await m.typing(posInt(a.id), { stop: a.stop === true }) };
  }));
  handle('chat:open', wrap(async (a) => ({ ok: true, open: m.setOpen({ id: posInt(a.id), visible: a.visible === true }) })));
  handle('chat:view', wrap(async (a) => { m.setViewOpen(a.open === true); return { ok: true }; }));
  handle('chat:people', wrap(async (a) => ({ ok: true, people: await m.people({ refresh: a.refresh === true }) })));
  handle('chat:create', wrap(async (a) => {
    const avatar = a.avatar ? fileArg(a.avatar) : null;
    const r = await m.createConversation({ kind: a.kind, userIds: Array.isArray(a.userIds) ? a.userIds.slice(0, 300) : [], title: a.title, avatar });
    return { ok: true, ...r };
  }));
  handle('chat:update', wrap(async (a) => {
    if (!posInt(a.id)) return invalid();
    const avatar = a.avatar ? fileArg(a.avatar) : null;
    return { ok: true, ...(await m.updateConversation(posInt(a.id), obj(a.patch), { avatar })) };
  }));
  handle('chat:prefs', wrap(async (a) => {
    // the 1.0 booleans and (1.4.0) partial privacy / notify / chats
    const patch = prefsBody(a);
    if (!Object.keys(patch).length) return invalid();
    return { ok: true, prefs: await m.setPrefs(patch) };
  }));
  handle('chat:search', wrap(async (a) => {
    if (!posInt(a.id) || typeof a.q !== 'string') return invalid();
    return { ok: true, ...(await m.search(posInt(a.id), a.q)) };
  }));
  handle('chat:media:list', wrap(async (a) => {
    if (!posInt(a.id)) return invalid();
    return { ok: true, ...(await m.mediaList(posInt(a.id), { kind: a.kind, before: posInt(a.before), limit: posInt(a.limit) })) };
  }));
  handle('chat:media', wrap(async (a) => {
    if (!isMediaId(a.mediaId)) return invalid();
    const r = await m.media(a.mediaId);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));
  handle('chat:avatar', wrap(async (a) => {
    if (!isAvatarPath(a.url)) return invalid();
    const r = await m.avatar(a.url);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));

  const nameFor = (a, mime) => {
    const fallback = `gatecontrol-${String(a.mediaId).slice(0, 8)}.${extForMime(mime)}`;
    const n = safeFileName(typeof a.fileName === 'string' ? a.fileName : '', fallback);
    return extOf(n) ? n : `${n}.${extForMime(mime)}`;
  };

  handle('chat:media:save', wrap(async (a) => {
    if (!isMediaId(a.mediaId)) return invalid();
    if (!dialog) return { ok: false, code: 'unsupported', error: 'no dialog' };
    const r = await m.media(a.mediaId);
    const name = nameFor(a, r.mime);
    const win = getMainWindow && getMainWindow();
    const res = await dialog.showSaveDialog(win || undefined, { defaultPath: name });
    if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true };
    await fsp.writeFile(res.filePath, r.data);
    await markOfTheWeb(res.filePath, platform, fsp);
    return { ok: true, path: res.filePath };
  }));

  handle('chat:media:open', wrap(async (a) => {
    if (!isMediaId(a.mediaId)) return invalid();
    if (!shell) return { ok: false, code: 'unsupported', error: 'no shell' };
    const r = await m.media(a.mediaId);
    const name = nameFor(a, r.mime);
    if (unsafeToOpen(name, r.mime)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
    const dir = path.join(getTempDir(), String(a.mediaId).slice(0, 16));
    await fsp.mkdir(dir, { recursive: true });
    const file = path.join(dir, name);
    await fsp.writeFile(file, r.data);
    await markOfTheWeb(file, platform, fsp);
    const err = await shell.openPath(file);
    if (err) {
      log.warn(`Opening a chat file failed: ${err}`);
      return { ok: false, code: 'open_failed', error: String(err) };
    }
    return { ok: true };
  }));

  // ── Messenger 1.4.0 ──────────────────────────────────────
  const bytesOut = (r) => ({ ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) });
  const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : undefined);
  const ids = (v) => (Array.isArray(v) ? v.slice(0, 500) : undefined);

  handle('chat:status:feed', wrap(async (a) => ({ ok: true, ...(await m.statusFeed({ refresh: a.refresh === true })) })));
  handle('chat:status:set', wrap(async (a) => ({
    ok: true,
    status: await m.setStatus({
      preset: str(a.preset, 20), text: str(a.text, 200), until: str(a.until, 40), visibility: str(a.visibility, 20), userIds: ids(a.userIds), eta: str(a.eta, 40), destLabel: str(a.destLabel, 200),
    }),
  })));
  handle('chat:status:clear', wrap(async () => { await m.clearStatus(); return { ok: true }; }));
  handle('chat:story:create', wrap(async (a) => {
    const file = a.file ? fileArg(a.file) : null;
    if (a.file && !file) return { ok: false, code: 'invalid', error: 'invalid file' };
    const story = await m.createStory({
      kind: str(a.kind, 10), text: str(a.text, 2000), bg: str(a.bg, 10), font: str(a.font, 10), visibility: str(a.visibility, 20), userIds: ids(a.userIds),
      eventMessageId: posInt(a.eventMessageId) || undefined, place: str(a.place, 200), video: obj(a.video), file, thumb: a.thumb ? fileArg(a.thumb) : null,
      durationH: posInt(a.durationH) || undefined,
    });
    return { ok: true, story };
  }));
  handle('chat:story:delete', wrap(async (a) => (posInt(a.id) ? { ok: await m.deleteStory(posInt(a.id)) } : invalid())));
  handle('chat:story:seen', wrap(async (a) => (posInt(a.id) ? { ok: await m.storySeen(posInt(a.id)) } : invalid())));
  handle('chat:story:viewers', wrap(async (a) => (posInt(a.id) ? { ok: true, viewers: await m.storyViewers(posInt(a.id)) } : invalid())));
  handle('chat:story:react', wrap(async (a) => {
    if (!posInt(a.id) || typeof a.emoji !== 'string' || !a.emoji || a.emoji.length > 16) return invalid();
    return { ok: true, message: await m.storyReact(posInt(a.id), a.emoji) };
  }));

  handle('chat:blocks', wrap(async () => ({ ok: true, blocks: await m.blocks() })));
  handle('chat:block', wrap(async (a) => (posInt(a.userId) ? { ok: true, blocks: await m.setBlocked(posInt(a.userId), a.blocked !== false) } : invalid())));
  handle('chat:archive', wrap(async (a) => (posInt(a.id) ? { ok: true, conversation: await m.archive(posInt(a.id), a.archived === true) } : invalid())));
  handle('chat:pin', wrap(async (a) => {
    if (!posInt(a.id) || !posInt(a.messageId)) return invalid();
    return { ok: true, conversation: await m.pin(posInt(a.id), posInt(a.messageId), a.pinned !== false) };
  }));
  handle('chat:lists', wrap(async (a) => ({ ok: true, lists: await m.lists({ refresh: a.refresh === true }) })));
  handle('chat:lists:save', wrap(async (a) => (Array.isArray(a.lists) ? { ok: true, lists: await m.saveLists(a.lists.slice(0, 40)) } : invalid())));
  handle('chat:export', wrap(async (a) => {
    if (!posInt(a.id)) return invalid();
    if (!dialog) return { ok: false, code: 'unsupported', error: 'no dialog' };
    const r = await m.exportChat(posInt(a.id));
    const name = safeFileName(r.fileName, 'Chat.txt');
    const win = getMainWindow && getMainWindow();
    const res = await dialog.showSaveDialog(win || undefined, { defaultPath: extOf(name) === 'txt' ? name : `${name}.txt`, filters: [{ name: 'Text', extensions: ['txt'] }] });
    if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true };
    // UTF-8 with BOM: umlauts read right in every Windows editor.
    await fsp.writeFile(res.filePath, `\ufeff${r.text.replace(/\r?\n/g, '\r\n')}`, 'utf8');
    return { ok: true, path: res.filePath, count: r.count, truncated: r.truncated };
  }));
  handle('chat:remind', wrap(async (a) => {
    if (!posInt(a.id) || typeof a.at !== 'string') return invalid();
    return { ok: true, reminder: await m.remind(posInt(a.id), a.at.slice(0, 40)) };
  }));
  handle('chat:reminders', wrap(async () => ({ ok: true, reminders: await m.reminders() })));
  handle('chat:reminder:delete', wrap(async (a) => (posInt(a.id) ? { ok: await m.deleteReminder(posInt(a.id)) } : invalid())));
  handle('chat:suggest', wrap(async (a) => (posInt(a.id) ? { ok: true, ...(await m.suggest(posInt(a.id))) } : invalid())));
  handle('chat:to-list', wrap(async (a) => {
    if (!posInt(a.id) || !Array.isArray(a.items)) return invalid();
    return { ok: true, ...(await m.toList(posInt(a.id), { items: a.items.slice(0, 60), list: str(a.list, 64) })) };
  }));
  handle('chat:to-calendar', wrap(async (a) => {
    if (!posInt(a.id) || typeof a.title !== 'string' || typeof a.startsAt !== 'string') return invalid();
    return { ok: true, ...(await m.toCalendar(posInt(a.id), { title: a.title.slice(0, 200), startsAt: a.startsAt.slice(0, 40), endsAt: str(a.endsAt, 40), allDay: a.allDay === true, place: str(a.place, 200) })) };
  }));
  handle('chat:places', wrap(async () => ({ ok: true, places: await m.places() })));
  handle('chat:poll', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    if (a.op === 'vote' && Array.isArray(a.optionIds)) return { ok: true, message: await m.vote(id, a.optionIds.slice(0, 20)) };
    if (a.op === 'option' && typeof a.text === 'string') return { ok: true, message: await m.addPollOption(id, a.text.slice(0, 200)) };
    if (a.op === 'close') return { ok: true, message: await m.closePoll(id) };
    if (a.op === 'nudge') return { ok: true, ...(await m.nudgePoll(id)) };
    return invalid();
  }));
  handle('chat:event', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    if (a.op === 'rsvp') return { ok: true, message: await m.rsvp(id, a.answer === undefined ? null : a.answer, Number.isSafeInteger(a.guests) ? a.guests : undefined) };
    if (a.op === 'check' && typeof a.itemId === 'string') return { ok: true, message: await m.checkItem(id, a.itemId.slice(0, 40), a.done === true) };
    if (a.op === 'edit' && a.patch && typeof a.patch === 'object') return { ok: true, message: await m.editEvent(id, obj(a.patch)) };
    return invalid();
  }));
  handle('chat:arrival:stop', wrap(async (a) => (posInt(a.id) ? { ok: true, message: await m.stopArrival(posInt(a.id)) } : invalid())));
  handle('chat:actions', wrap(async (a) => ({ ok: true, actions: await m.actions({ refresh: a.refresh === true }) })));
  handle('chat:action', wrap(async (a) => {
    if (!posInt(a.id) || !['run', 'approve', 'deny'].includes(a.op)) return invalid();
    return { ok: true, ...(await m.actionOp(posInt(a.id), a.op, { actionId: str(a.actionId, 200), plugin: str(a.plugin, 100) })) };
  }));
  handle('chat:card:image', wrap(async (a) => (posInt(a.id) ? bytesOut(await m.cardImage(posInt(a.id))) : invalid())));
  handle('chat:storage', wrap(async () => ({ ok: true, ...m.storage() })));
  handle('chat:cache:clear', wrap(async () => ({ ok: true, ...m.clearMediaCache() })));

  // ── Map (location dialog, location previews) ─────────────
  const noMaps = () => ({ ok: false, code: 'unsupported', error: 'no map service' });
  const lang = (v) => (v === 'en' || v === 'de' ? v : undefined);
  handle('chat:map:tile', wrap(async (a) => {
    if (!maps) return noMaps();
    if (![a.z, a.x, a.y].every((v) => Number.isSafeInteger(v) && v >= 0)) return invalid();
    const r = await maps.tile(a.z, a.x, a.y);
    return { ok: true, mime: r.mime, data: new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength) };
  }));
  handle('chat:map:search', wrap(async (a) => {
    if (!maps) return noMaps();
    if (typeof a.q !== 'string' || a.q.length > 500) return invalid();
    return { ok: true, results: await maps.search(a.q, { lang: lang(a.lang) }) };
  }));
  handle('chat:map:reverse', wrap(async (a) => {
    if (!maps) return noMaps();
    if (!Number.isFinite(a.lat) || !Number.isFinite(a.lon)) return invalid();
    return { ok: true, ...(await maps.reverse(a.lat, a.lon, { lang: lang(a.lang) })) };
  }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(CHAT_EVENTS)) m.on(event, (payload) => send(channel, payload));
  if (chatNotifier && typeof chatNotifier.on === 'function') chatNotifier.on('navigate', (payload) => send('chat:navigate', payload));
}

module.exports = { registerMessengerHandlers, CHAT_EVENTS };
