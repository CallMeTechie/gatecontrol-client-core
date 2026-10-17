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
 *   chat:messages        ({ id, before?, cached? }) → { ok, conversationId, messages, pending, hasMore, offline }
 *   chat:send            ({ conversationId, clientId?, kind, text?, replyTo?, meta?, location?, file?: { name, mime, data }, thumb?: { mime, data } }) → { ok, message }
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
 *   chat:media:list      ({ id, kind?, before?, limit? }) → { ok, items, counts, hasMore }
 *   chat:media           ({ mediaId }) → { ok, mime, data: Uint8Array }
 *   chat:avatar          ({ url }) → { ok, mime, data }
 *   chat:media:save      ({ mediaId, fileName? }) → { ok, path } | { ok: false, cancelled }
 *   chat:media:open      ({ mediaId, fileName? }) → { ok } | { ok: false, code: 'unsafe' }
 *
 * Events to the main window: chat:state, chat:conversations, chat:messages,
 * chat:typing, chat:unread, chat:outbox, chat:navigate.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  posInt, isClientId, isMediaId, isAvatarPath, safeFileName, unsafeToOpen, extForMime, extOf,
} = require('../utils/messenger');

const CHAT_EVENTS = {
  state: 'chat:state',
  conversations: 'chat:conversations',
  messages: 'chat:messages',
  typing: 'chat:typing',
  unread: 'chat:unread',
  outbox: 'chat:outbox',
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
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 * @param {object} [deps.dialog] - Electron dialog (save as)
 * @param {object} [deps.shell] - Electron shell (open)
 * @param {Function} [deps.getTempDir] - () => folder for opened files
 * @param {string} [deps.platform]
 * @param {object} [deps.fsp]
 */
function registerMessengerHandlers(handle, {
  messenger: m, chatNotifier = null, getMainWindow, log, dialog = null, shell = null,
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
    return { ok: true, ...(await m.getMessages(id, { before: posInt(a.before) })) };
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
      file: a.file ? fileArg(a.file) : undefined,
      thumb: a.thumb ? fileArg(a.thumb) : undefined,
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
    const patch = {};
    for (const k of ['readReceipts', 'typing', 'preview']) if (typeof a[k] === 'boolean') patch[k] = a[k];
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

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(CHAT_EVENTS)) m.on(event, (payload) => send(channel, payload));
  if (chatNotifier && typeof chatNotifier.on === 'function') chatNotifier.on('navigate', (payload) => send('chat:navigate', payload));
}

module.exports = { registerMessengerHandlers, CHAT_EVENTS };
