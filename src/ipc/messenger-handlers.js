'use strict';

/**
 * IPC of the Messenger ("Chats", opt-in: registerBaseHandlers(…, { messenger })).
 * Arguments from the renderer are checked here and again in the service.
 * Every handler resolves; failures come back as { ok: false, code, error }.
 *
 *   chat:status          () → MessengerService.status()
 *   chat:check           () → status after asking the server again
 *   chat:conversations   ({ refresh? }) → { ok, conversations, unread, channels: { count, unread } | null }
 *   chat:channels        ({ refresh? }) → { ok, channels, summary: { count, unread } | null }   Messenger 1.20 (bridge_channels):
 *                        the page „Kanäle“ — channels are not in chat:conversations then, nor in its unread
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
 *   chat:status:feed     ({ refresh? }) → { ok, items, me, bridged, serverTime } status strip / stories (1.25: bridged —
 *                        the contacts' WhatsApp status updates)
 *   chat:story:bridged:seen  ({ id }) → { ok }                                 1.25: a contact's WhatsApp status was shown
 *   chat:story:bridged:reply ({ id, text? | emoji? }) → { ok, message }        1.25: answer / reaction as a WhatsApp message
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
 *   chat:to-drive        ({ id, folderId? }) → { ok, saved: { nodeId, name, where } } (Messenger 1.10, Drive)
 *   chat:to-calendar     ({ id, title, startsAt, endsAt?, allDay?, place? }) → { ok, eventId }
 *   chat:places          () → { ok, places }                                     Familie places
 *                        ({ all: true }) → { ok, places, sources, profile }      the place choice: Messenger 1.28
 *                        (`profilePlaces`) GET places — own profile places + Familie's, with `ref`; older: Familie's
 *   chat:poll            ({ id, op: 'vote'|'option'|'close'|'nudge', optionIds?, text? }) → { ok, message, nudged? }
 *   chat:event           ({ id, op: 'rsvp'|'check'|'edit', answer?, guests?, itemId?, done?, patch? }) → { ok, message }
 *   chat:arrival:stop    ({ id }) → { ok, message }
 *   chat:actions         ({ refresh? }) → { ok, actions }                        attach menu "Aus deinem Zuhause"
 *   chat:action          ({ id, op: 'run'|'approve'|'deny', actionId?, plugin? }) → { ok, message, result }
 *   chat:card:image      ({ id }) → { ok, mime, data: Uint8Array }                picture of a plugin card
 *   chat:notice:image    ({ path }) → { ok, mime, data: Uint8Array }              picture of a notice card (/notify-media/…)
 *   chat:storage         () → { ok, mediaCacheBytes, avatarCacheBytes, cachedChats, cachedMessages, outbox, server }
 *   chat:cache:clear     () → { ok, … storage }
 *
 * Messenger 1.13 („Verknüpfte Dienste“, code 'unsupported' without feature `linked_services`) and 1.14 (chats over a
 * bridge). The number and the pairing code pass through and are never logged or stored:
 *   chat:bridges         () → { ok, bridges: { available, location, networks: [{ id, state, allowed, lock, consent, outdated, logins }] } }
 *   chat:bridge:consent  ({ network }) → { ok, consent }
 *   chat:bridge:login    ({ network, flow: 'phone'|'qr' }) → { ok, login }
 *   chat:bridge:step     ({ network, processId, stepId, phone?, secret?, fieldId? }) → { ok, login }   without phone or secret: waits for the
 *                        phone (≤ 15 s); secret (1.24): Telegram's code or password, passed through once
 *                        login: { processId, waiting } | { processId, step: { id, type: 'complete'|'phone'|'secret'|'code'|'qr'|'unsupported', fieldId?, kind?, retry?, code?, matrix? } }
 *   chat:bridge:cancel   ({ network, processId }) → { ok }
 *   chat:bridge:unlink   ({ network, loginId }) → { ok }
 *   chat:resend          ({ id }) → { ok, message }   an own message with bridge.state 'failed', once more
 *
 * Messenger 1.15 (feature `bridge_new_chat`; code 'unsupported' without it). `number` as typed, `cc` the country
 * code for a number without one (default +49); normalized in main, sent once, never logged or stored:
 *   chat:bridge:resolve  ({ network, number, cc? }) → { ok, found, name, avatarMediaId, existing: { conversationId } | null }
 *   chat:bridge:chat     ({ network, number, cc? }) → { ok, conversation, created }   kept in the list until it is listed
 * Refusals: invalid_number, rate_limited (+ retryAfterS, perHour), bridge_unlinked (reason), bridge_logged_out (1.16),
 * bridge_locked, child_new_chat_off,
 * bridge_unreachable, bridge_off, feature_off, not_found (reason not_on_network).
 * Messenger 1.18 (feature `bridge_contacts`; code 'unsupported' without it) — „Neuer Chat“ with contacts:
 *   chat:bridge:contacts     ({ network, q? }) → { ok, network, query, gatecontrol, whatsapp, addressBook, addressBookReason,
 *                            number, numberEntry, limit }   (utils normalizeNewChatContacts; q never logged)
 *   chat:bridge:contact-chat ({ network, contact: { ref } | { contactId, phoneKind } }) → { ok, conversation, created }
 * Refusals as above, and: contact_expired (load the list again), not_found (reason not_on_network, remembered |
 * contact_gone), mail_missing.
 * chat:send in a chat over a bridge also takes image / voice / file of a kind and type in `bridge.supports` /
 * `bridge.mediaTypes` (else bridge_text_only / bridge_media_type with reason image | voice | video); 423 scan_pending
 * is sent again by the queue.
 *
 * Messenger 1.17 (feature `bridge_history`; code 'unsupported' without it):
 *   chat:bridge:history  ({ days: 0 | 30 | -1 }) → { ok, history: { available, days, default, options, pending } }
 *   chat:fetch           ({ id }) → { ok, message }   a file of the older history (placeholder on_request), now
 * Refusals: invalid (nothing to fetch / days), feature_off, not_found.
 *
 * Messenger 1.21 (feature `chat_people`; code 'unsupported' without it) — persons, one entry per human over several
 * ways (`person` on the entry; chat:messages / chat:send / chat:read / chat:search / chat:update / chat:archive of
 * that entry go through persons/:id/…):
 *   chat:person:way        ({ id, way: 'gatecontrol'|'whatsapp'|…|null }) → { ok, …chat:messages }   the source chips
 *   chat:suggestions       ({ refresh? }) → { ok, suggestions }        „… ist vielleicht …“ (asked ≤ every 15 min)
 *   chat:suggestion:answer ({ id, action: 'later'|'never' }) → { ok, suggestion }
 *   chat:person:merge      ({ conversationIds, userId?, name?: 'account'|conversationId }) → { ok, conversation }
 *   chat:person:split      ({ id, conversationId? }) → { ok, person, conversationIds }   „Trennen“, nothing is lost
 *   chat:person:name       ({ id, name: 'account'|conversationId }) → { ok, conversation }
 *   chat:person:candidates ({ id }) → { ok, accounts, chats }          „Mit Person zusammenführen …“
 *   chat:bridge:recognition ({ allowed }) → { ok, recognition }        asked once after WhatsApp was linked
 *                        Messenger 1.23: ({ allowed, network? }) — one consent per service (network missing: whatsapp)
 *   chat:bridge:handoff     ({ network, target: 'portal'|'windows' }) → { ok, handoff: { network, target, expiresAt, portalPath } }
 *   chat:bridge:handoff:end ({ network }) → { ok }                     the second screen is not needed any more
 *   event chat:handoff      { network, target: 'portal'|'windows'|null, expiresAt, portalPath } (bridge.handoff; null: over)
 * Refusals: cannot_merge (reason group | channel | not_direct | two_accounts | one_way), not_found, feature_off.
 *
 * Events to the main window: chat:state, chat:conversations, chat:messages,
 * chat:typing, chat:unread, chat:outbox, chat:navigate, chat:feed, chat:lists,
 * chat:reminders, chat:suggestions (1.21).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  posInt, isClientId, isMediaId, isAvatarPath, isNotifyMediaPath, safeFileName, unsafeToOpen, extForMime, extOf, prefsBody,
} = require('../utils/messenger');
const SC = require('../utils/scan');
const { dialogPath: defaultDialogPath } = require('../utils/user-folders');

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
  suggestions: 'chat:suggestions',
  // Messenger 1.23: „Im Windows-Client fortsetzen“ of another device (bridge.handoff)
  handoff: 'chat:handoff',
};
const MAX_IPC_FILE = 64 * 1024 * 1024;

function fail(err) {
  // Messenger 1.11: the virus scan's refusal (423 quarantined | scan_pending | scan_blocked, 422 infected) → scan,
  // finding, retryAfter
  // Messenger 1.13 / 1.14: a bridge's refusal names why (`reason`: timeout, not_running, logged_out, …)
  const reason = err && err.body && typeof err.body.reason === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(err.body.reason) ? err.body.reason : null;
  // Messenger 1.15: 429 rate_limited of a new chat by number says when the next try goes (`retryAfterS`)
  const ra = err && err.body ? err.body.retryAfterS : null;
  const retryAfterS = Number.isSafeInteger(ra) && ra > 0 && ra <= 86400 ? ra : null;
  // Messenger 1.16: … and the brake per hour (`perHour`)
  const ph = err && err.body ? err.body.perHour : null;
  const perHour = retryAfterS && Number.isSafeInteger(ph) && ph > 0 && ph <= 1000 ? ph : null;
  // Messenger 1.18: a „nicht bei WhatsApp“ of an address book number came from the server's 30-day memory
  const remembered = !!(err && err.body && err.body.remembered === true);
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null, ...(reason ? { reason } : {}), ...(retryAfterS ? { retryAfterS } : {}), ...(perHour ? { perHour } : {}), ...(remembered ? { remembered } : {}), ...SC.refusalFields(err) };
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
 * @param {Function} [deps.dialogPath] - utils/user-folders dialogPath (save dialogs: the Downloads of the person signed in)
 * @param {string} [deps.platform]
 * @param {object} [deps.fsp]
 */
function registerMessengerHandlers(handle, {
  messenger: m, chatNotifier = null, maps = null, getMainWindow, log, dialog = null, shell = null,
  getTempDir = () => path.join(os.tmpdir(), 'gatecontrol-chat'), platform = process.platform, fsp = fs.promises,
  dialogPath = defaultDialogPath,
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
    return { ok: true, conversations: m.listConversations(), unread: m.unreadTotal(), channels: m.channelSummary() };
  }));
  // Messenger 1.20 (feature `bridge_channels`): the page „Kanäle“ — [] / summary null without it
  handle('chat:channels', wrap(async (a) => {
    if (a.refresh === true && m.available() && m.channelSummary()) await m.refreshChannels().catch(() => null);
    return { ok: true, channels: m.listChannels(), summary: m.channelSummary() };
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
  // Messenger 1.13 / 1.14: linked services, chats over a bridge
  const text = (v, max) => (typeof v === 'string' && v.length <= max ? v : '');
  handle('chat:bridges', wrap(async () => ({ ok: true, bridges: await m.bridges() })));
  handle('chat:bridge:consent', wrap(async (a) => ({ ok: true, ...(await m.bridgeConsent(text(a.network, 32))) })));
  handle('chat:bridge:login', wrap(async (a) => ({ ok: true, login: await m.bridgeLogin(text(a.network, 32), text(a.flow, 8)) })));
  handle('chat:bridge:step', wrap(async (a) => ({
    ok: true,
    // Messenger 1.24: `secret` — Telegram's code or password, passed through once (never logged)
    login: await m.bridgeStep(text(a.network, 32), text(a.processId, 128), text(a.stepId, 128),
      typeof a.secret === 'string' ? { secret: a.secret.slice(0, 256), fieldId: text(a.fieldId, 128) }
        : (typeof a.phone === 'string' ? { phone: a.phone.slice(0, 40), fieldId: text(a.fieldId, 128) } : {})),
  })));
  handle('chat:bridge:cancel', wrap(async (a) => ({ ok: await m.bridgeCancel(text(a.network, 32), text(a.processId, 128)) })));
  handle('chat:bridge:unlink', wrap(async (a) => ({ ok: await m.bridgeUnlink(text(a.network, 32), text(a.loginId, 128)) })));
  // Messenger 1.15: a new chat by number — the number passes through once and is never logged or stored
  const num = (v) => (typeof v === 'string' ? v.slice(0, 40) : '');
  handle('chat:bridge:resolve', wrap(async (a) => ({ ok: true, ...(await m.bridgeResolve(text(a.network, 32), num(a.number), text(a.cc, 5))) })));
  handle('chat:bridge:chat', wrap(async (a) => ({ ok: true, ...(await m.bridgeStartChat(text(a.network, 32), num(a.number), text(a.cc, 5))) })));
  // Messenger 1.17 (feature `bridge_history`; code 'unsupported' without it): older history at a new link, its files
  handle('chat:bridge:history', wrap(async (a) => ({ ok: true, history: await m.setBridgeHistory(a.days) })));
  // Messenger 1.21: persons (feature `chat_people`)
  handle('chat:person:way', wrap(async (a) => {
    const id = posInt(a.id);
    const way = a.way == null ? null : text(a.way, 20);
    if (!id || (way != null && !/^[a-z]{2,20}$/.test(way))) return invalid();
    return { ok: true, ...(await m.setWay(id, way)) };
  }));
  handle('chat:suggestions', wrap(async (a) => ({ ok: true, suggestions: await m.suggestions({ refresh: a.refresh === true }) })));
  handle('chat:suggestion:answer', wrap(async (a) => ({ ok: true, suggestion: await m.answerSuggestion(text(a.id, 40), text(a.action, 10)) })));
  handle('chat:person:merge', wrap(async (a) => ({ ok: true, conversation: await m.mergePersons({ conversationIds: a.conversationIds, userId: a.userId, name: a.name }) })));
  handle('chat:person:split', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id || (a.conversationId != null && !posInt(a.conversationId))) return invalid();
    return { ok: true, ...(await m.splitPerson(id, a.conversationId == null ? null : posInt(a.conversationId))) };
  }));
  handle('chat:person:name', wrap(async (a) => {
    const id = posInt(a.id);
    const name = a.name === 'account' ? 'account' : posInt(a.name);
    if (!id || !name) return invalid();
    return { ok: true, conversation: await m.renamePerson(id, name) };
  }));
  // Messenger 1.27: „Nachrichten senden über“ — 'auto' (null), 'gatecontrol' or a network of the person (checked in the core)
  handle('chat:person:reply-pref', wrap(async (a) => {
    const id = posInt(a.id);
    const pref = a.pref == null ? 'auto' : text(a.pref, 20);
    if (!id || !/^[a-z]{2,20}$/.test(pref)) return invalid();
    return { ok: true, conversation: await m.setReplyPref(id, pref) };
  }));
  handle('chat:person:candidates', wrap(async (a) => (posInt(a.id) ? { ok: true, ...(await m.personCandidates(posInt(a.id))) } : invalid())));
  handle('chat:bridge:recognition', wrap(async (a) => {
    if (typeof a.allowed !== 'boolean') return invalid();
    // Messenger 1.23: one consent per service (network missing: WhatsApp, as before)
    return { ok: true, recognition: await m.setRecognition(a.allowed, a.network == null ? 'whatsapp' : text(a.network, 32)) };
  }));
  // Messenger 1.23: „Im Portal / Windows-Client fortsetzen“ (a service with the QR code only) and its end
  handle('chat:bridge:handoff', wrap(async (a) => ({ ok: true, handoff: await m.bridgeHandoff(text(a.network, 32), text(a.target, 16)) })));
  handle('chat:bridge:handoff:end', wrap(async (a) => ({ ok: await m.bridgeHandoffEnd(text(a.network, 32)) })));
  handle('chat:fetch', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    return { ok: true, message: await m.fetchBridgeFile(id) };
  }));
  // Messenger 1.18: „Neuer Chat“ with contacts — the search passes through once and is never logged or stored
  handle('chat:bridge:contacts', wrap(async (a) => ({ ok: true, ...(await m.newChatContacts(text(a.network, 32), typeof a.q === 'string' ? a.q.slice(0, 200) : '')) })));
  handle('chat:bridge:contact-chat', wrap(async (a) => {
    const c = obj(a.contact);
    const contact = typeof c.ref === 'string' ? { ref: c.ref.slice(0, 1500) } : { contactId: c.contactId, phoneKind: text(c.phoneKind, 16) };
    return { ok: true, ...(await m.bridgeContactChat(text(a.network, 32), contact)) };
  }));
  handle('chat:resend', wrap(async (a) => {
    const id = posInt(a.id);
    if (!id) return invalid();
    return { ok: true, message: await m.resend(id) };
  }));
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
    const res = await dialog.showSaveDialog(win || undefined, { defaultPath: dialogPath('downloads', name) });
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
  // Messenger 1.25: a contact's WhatsApp status — watched; an answer or a reaction goes as a message into the WhatsApp chat
  handle('chat:story:bridged:seen', wrap(async (a) => (posInt(a.id) ? { ok: await m.bridgedStorySeen(posInt(a.id)) } : invalid())));
  handle('chat:story:bridged:reply', wrap(async (a) => {
    const emoji = typeof a.emoji === 'string' && a.emoji && a.emoji.length <= 16 ? a.emoji : null;
    const text = typeof a.text === 'string' && a.text.trim() && a.text.length <= 4000 ? a.text : null;
    if (!posInt(a.id) || (emoji == null) === (text == null)) return invalid();
    return { ok: true, message: await m.bridgedStoryReply(posInt(a.id), emoji ? { emoji } : { text }) };
  }));
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
    const res = await dialog.showSaveDialog(win || undefined, { defaultPath: dialogPath('downloads', extOf(name) === 'txt' ? name : `${name}.txt`), filters: [{ name: 'Text', extensions: ['txt'] }] });
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
  handle('chat:to-drive', wrap(async (a) => {
    if (!posInt(a.id) || !(a.folderId === undefined || a.folderId === null || posInt(a.folderId))) return invalid();
    return { ok: true, saved: await m.toDrive(posInt(a.id), posInt(a.folderId) || null) };
  }));
  handle('chat:places', wrap(async (a) => (a.all === true ? { ok: true, ...(await m.pickPlaces()) } : { ok: true, places: await m.places() })));
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
  handle('chat:notice:image', wrap(async (a) => (isNotifyMediaPath(a.path) ? bytesOut(await m.noticeImage(a.path)) : invalid())));
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
