'use strict';

/**
 * Notizen & Aufgaben (plugin gatecontrol-notizen 1.0.0) — the pure helpers of the Windows apps: the plugin's paths,
 * the answers of its API cleaned (README "API": Task, Item, List, Notebook, NoteSummary, Attachment, the views, the
 * menu), the arguments the renderer may send, the targets of a push click and of an item's `open` (the contract
 * docs/notes-sources-contract.md § 5) and the check boxes of a note's Markdown (the plugin's ui/notemd.js `toggle`,
 * for the Tresor notebooks the device changes itself). Plugin 1.3.0 (what `me.features` names — never a version):
 * `reminderActions` (a task's pending `reminder`, `snoozed`, `missedReminder`), `yesterdayOpen` (the card „Gestern offen
 * geblieben“: `yesterday` of GET views/myday, POST tasks/<id>/move, POST yesterday) and `taskCalendar` (a task's
 * `calendar`, `me.calendar`). Plugin 1.4.0: `shoppingLists` (GET shopping, POST shopping/ops — the lists and their items
 * with ids the device makes, `nav.shopping`, `me.shopping`, the event `shopping`), `taskList` (a task's `attachedList`,
 * `attachedListId` / `attachedListUid` when writing, `attach` of POST parse and POST tasks, the button „Liste öffnen“ of
 * a reminder) and `familyShopping` (family lists: PUT shopping/lists/<id>/family, POST …/going, …/assign).
 *
 * Every text from the server stays text: the renderer puts it into textContent only.
 */

const PLUGIN_ID = 'gatecontrol-notizen';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const PLUGINS_PATH = '/api/v1/client/plugins';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_PATH = `/api/v1/client/plugins/${PLUGIN_ID}/media`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const VAULT_PREFIX = 'gcnotes-v1';

const AREAS = Object.freeze(['private', 'work']);
const SMART_VIEWS = Object.freeze(['myday', 'important', 'planned', 'assigned']);
const SOURCES = Object.freeze(['gatecontrol-familie', 'gatecontrol-mail', 'gatecontrol-drive', 'gatecontrol-schule', 'gatecontrol-alltag']);
const COLORS = Object.freeze(['none', 'yellow', 'green', 'blue', 'pink', 'grey', 'orange', 'purple']);
const ITEM_KINDS = Object.freeze(['task', 'event', 'deadline', 'homework', 'exam', 'list', 'note']);
const REPEAT_TYPES = Object.freeze(['daily', 'weekly', 'monthly', 'yearly', 'after']);
const DONE_DAYS = Object.freeze([0, 30, 90, 365, -1]);
const JOB_STATES = Object.freeze(['running', 'done', 'failed', 'canceled']);
const TITLE_MAX = 300;
const BODY_MAX = 1000000;
const NOTE_MAX = 20000;
const NAME_MAX = 80;
const QUERY_MAX = 200;
const MOVE_WORDS = Object.freeze(['today', 'tomorrow', 'weekend']);
const YESTERDAY_ACTIONS = Object.freeze(['done', 'today', 'move']);
const YESTERDAY_MAX = 200;
// plugin 1.4.0: shopping lists
const SHOP_NAME_MAX = 40;
const SHOP_TEXT_MAX = 120;
const SHOP_QTY_MAX = 40;
const SHOP_OPS_MAX = 200;
const SHOP_OPS = Object.freeze(['list_add', 'list_rename', 'list_delete', 'item_add', 'item_edit', 'item_check', 'item_delete', 'clear_checked']);
const SHOP_REJECTS = Object.freeze(['invalid', 'not_found', 'forbidden', 'too_many']);
const ATTACH_VIA = Object.freeze(['tag', 'name', 'word']);
const ASSIGN_NOTIFY = Object.freeze(['direct', 'family', 'push']);

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const PLUGIN_RE = /^gatecontrol-[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ROUTE_RE = /^[A-Za-z0-9/._:=-]{0,200}$/;
const GROUP_ID_RE = /^[A-Za-z0-9:._-]{1,80}$/;
const MEDIA_ID_RE = /^[A-Za-z0-9_-]{6,128}$/;
const VAULT_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const CODE_RE = /^[A-Za-z0-9_.-]{1,60}$/;
const SHOP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const ICON_RE = /^[a-z][a-z0-9-]{0,39}$/;
const REMINDER_TAG_RE = /^task:[1-9]\d{0,14}:[1-9]\d{0,15}$/;
const CTRL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const CTRL_LINE_RE = /[\u0000-\u001F\u007F]/g;

// ── small cleaners ──────────────────────────────────────────

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);
const bool = (v) => v === true;

/** One line of text (control characters out), at most `max` characters, or null. */
function line(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(CTRL_LINE_RE, ' ').trim();
  return s ? s.slice(0, max) : null;
}

/** Text with line breaks (control characters but \t \n \r out), at most `max` characters ('' allowed). */
function text(v, max) {
  if (typeof v !== 'string') return null;
  return v.replace(CTRL_RE, '').slice(0, max);
}

function posId(v) {
  return Number.isSafeInteger(v) && v > 0 ? v : null;
}

function count(v) {
  return Number.isSafeInteger(v) && v >= 0 ? v : null;
}

const msOf = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
const dateOf = (v) => (typeof v === 'string' && DATE_RE.test(v) ? v : null);
const timeOf = (v) => (typeof v === 'string' && TIME_RE.test(v) ? v : null);
const areaOf = (v) => (AREAS.includes(v) ? v : null);
const colorOf = (v) => (COLORS.includes(v) ? v : null);
const pluginOf = (v) => (typeof v === 'string' && PLUGIN_RE.test(v) && v.length <= 60 ? v : null);
const vaultIdOf = (v) => (typeof v === 'string' && VAULT_ID_RE.test(v) ? v : null);
const b64uOf = (v, max) => (typeof v === 'string' && v.length <= max && B64U_RE.test(v) ? v : null);
const isMediaId = (v) => typeof v === 'string' && MEDIA_ID_RE.test(v);
const shopIdOf = (v) => (typeof v === 'string' && SHOP_ID_RE.test(v) ? v : null);
const iconOf = (v) => (typeof v === 'string' && ICON_RE.test(v) ? v : null);
const isoOf = (v) => (typeof v === 'string' && v.length <= 40 && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/.test(v) ? v : null);

function whenOf(v) {
  const o = obj(v);
  const date = o && dateOf(o.date);
  return date ? { date, time: timeOf(o.time) } : null;
}

function progressOf(v) {
  const o = obj(v);
  const total = o && count(o.total);
  return total ? { done: Math.min(count(o.done) || 0, total), total } : null;
}

function personOf(v) {
  const o = obj(v);
  if (!o) return null;
  const id = posId(o.id);
  const name = line(o.name, 120);
  return id || name ? { id, name } : null;
}

function personList(v, max = 50) {
  return arr(v).slice(0, max).map(personOf).filter((p) => p && p.id);
}

/** A repeat rule (the plugin's ui/repeat.js) → the rule or null. */
function repeatOf(v) {
  const o = obj(v);
  if (!o || !REPEAT_TYPES.includes(o.type)) return null;
  const interval = Number.isSafeInteger(o.interval) && o.interval >= 1 && o.interval <= 999 ? o.interval : 1;
  const r = { type: o.type, interval };
  if (o.type === 'weekly') {
    const days = [...new Set(arr(o.days).filter((d) => Number.isSafeInteger(d) && d >= 1 && d <= 7))].sort();
    if (!days.length) return null;
    r.days = days;
  }
  if ((o.type === 'monthly' || o.type === 'yearly') && Number.isSafeInteger(o.day) && o.day >= 1 && o.day <= 31) r.day = o.day;
  if (o.type === 'yearly' && Number.isSafeInteger(o.month) && o.month >= 1 && o.month <= 12) r.month = o.month;
  return r;
}

/** A task's pending reminder (plugin 1.3.0) → { tag, at, atMs, mine, snoozed } or null. */
function reminderOf(v) {
  const o = obj(v);
  const tag = o && typeof o.tag === 'string' && REMINDER_TAG_RE.test(o.tag) ? o.tag : null;
  const atMs = o && msOf(o.atMs);
  return tag && atMs ? { tag, at: isoOf(o.at), atMs, mine: bool(o.mine), snoozed: bool(o.snoozed) } : null;
}

/** A task's event in the calendar „Aufgaben“ of Mail (plugin 1.3.0) → { state, eventId, calendarId, mine } or null. */
function calendarOf(v) {
  const o = obj(v);
  if (!o || (o.state !== 'synced' && o.state !== 'pending')) return null;
  return { state: o.state, eventId: posId(o.eventId), calendarId: posId(o.calendarId), mine: bool(o.mine) };
}

/**
 * The shopping list a task carries, a list of the suggestion (plugin 1.4.0) → { id (the list's number), uid (its text
 * id), name, icon, open, total, done, family } or null.
 */
function attachedListOf(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const uid = o && shopIdOf(o.uid);
  if (!id || !uid) return null;
  const total = count(o.total) || 0;
  const open = Math.min(count(o.open) || 0, total);
  return { id, uid, name: line(o.name, SHOP_NAME_MAX) || '', icon: iconOf(o.icon), open, total, done: total - open, family: bool(o.family) };
}

/** `meta` of an item: flat, strings ≤ 120 / numbers / booleans (contract § 2). */
function metaOf(v) {
  const o = obj(v);
  const out = {};
  if (!o) return out;
  for (const [k, x] of Object.entries(o).slice(0, 30)) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(k)) continue;
    if (typeof x === 'string') out[k] = x.replace(CTRL_LINE_RE, ' ').slice(0, 120);
    else if (typeof x === 'number' && Number.isFinite(x)) out[k] = x;
    else if (typeof x === 'boolean') out[k] = x;
  }
  return out;
}

/** An item's `open` → { plugin, route } or null. */
function openOf(v) {
  const o = obj(v);
  const plugin = o && pluginOf(o.plugin);
  if (!plugin) return null;
  return { plugin, route: typeof o.route === 'string' && ROUTE_RE.test(o.route) ? o.route : '' };
}

// ── the answers ─────────────────────────────────────────────

/** Task (README "API") → cleaned, or null. */
function normalizeTask(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const src = obj(o.source);
  const t = {
    uid: `t:${id}`, type: 'task', id, listId: posId(o.listId), parentId: posId(o.parentId), title: line(o.title, TITLE_MAX) || '',
    hasNote: bool(o.hasNote), important: bool(o.important), done: bool(o.done), doneAt: isoOf(o.doneAt) || msOf(o.doneAt),
    due: whenOf(o.due), overdue: bool(o.overdue), remindAt: isoOf(o.remindAt), repeat: repeatOf(o.repeat), repeatText: line(o.repeatText, 120),
    assignee: personOf(o.assignee), myDay: bool(o.myDay), progress: progressOf(o.progress), attachments: count(o.attachments) || 0,
    source: src && pluginOf(src.plugin) && typeof src.id === 'string' ? { plugin: src.plugin, id: src.id.slice(0, 120) } : null,
    noteId: posId(o.noteId), position: Number.isFinite(o.position) ? o.position : 0, canComplete: o.canComplete !== false,
    canEdit: o.canEdit !== false, updatedAt: msOf(o.updatedAt),
    // plugin 1.3.0 — an older plugin sends none of these
    reminder: reminderOf(o.reminder), snoozed: bool(o.snoozed), missedReminder: bool(o.missedReminder), calendar: calendarOf(o.calendar),
    // plugin 1.4.0 — null without a list, and when the person does not see the list
    attachedList: attachedListOf(o.attachedList),
  };
  // GET tasks/<id>: the details
  if (typeof o.note === 'string') t.note = text(o.note, NOTE_MAX);
  if (Array.isArray(o.subtasks)) {
    t.subtasks = o.subtasks.slice(0, 200).map((s) => {
      const x = obj(s);
      const sid = x && posId(x.id);
      return sid ? { id: sid, title: line(x.title, TITLE_MAX) || '', done: bool(x.done) } : null;
    }).filter(Boolean);
  }
  if (o.list !== undefined) t.list = normalizeList(o.list);
  if (Array.isArray(o.attachmentList)) t.attachmentList = o.attachmentList.slice(0, 100).map(normalizeAttachment).filter(Boolean);
  if (o.sourceItem !== undefined) t.sourceItem = normalizeItem(o.sourceItem);
  return t;
}

/** Item (an item of another plugin) → cleaned, or null. */
function normalizeItem(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const s = o && obj(o.source);
  const plugin = s && pluginOf(s.plugin);
  if (!id || !plugin) return null;
  const group = obj(o.group);
  return {
    uid: `s:${id}`, type: 'source', id, kind: ITEM_KINDS.includes(o.kind) ? o.kind : 'task', title: line(o.title, 200) || '',
    subtitle: line(o.subtitle, 200),
    source: { plugin, label: line(s.label, 60) || plugin.replace(/^gatecontrol-/, ''), open: openOf(s.open) || { plugin, route: '' } },
    due: whenOf(o.due), show: whenOf(o.show), allDay: bool(o.allDay), lead: o.lead === 'evening' ? 'evening' : null,
    overdue: bool(o.overdue), area: areaOf(o.area) || 'private', important: bool(o.important), done: bool(o.done),
    doneAt: msOf(o.doneAt), canComplete: bool(o.canComplete), assignee: personOf(o.assignee), progress: progressOf(o.progress),
    group: group && typeof group.id === 'string' && GROUP_ID_RE.test(group.id) ? { id: group.id, label: line(group.label, 80) || group.id } : null,
    meta: metaOf(o.meta), updatedAt: msOf(o.updatedAt),
  };
}

/** A row of a view: a task or an item. */
function normalizeEntry(v) {
  const o = obj(v);
  if (!o) return null;
  return o.type === 'source' ? normalizeItem(o) : normalizeTask(o);
}

/** List → cleaned, or null. */
function normalizeList(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id, name: line(o.name, NAME_MAX) || '', area: areaOf(o.area) || 'private', color: colorOf(o.color), icon: line(o.icon, 40),
    isDefault: bool(o.isDefault), owner: personOf(o.owner), role: o.role === 'owner' || o.role === 'member' ? o.role : null,
    groupId: posId(o.groupId), position: Number.isFinite(o.position) ? o.position : 0, shared: bool(o.shared),
    members: personList(o.members), open: count(o.open), ext: obj(o.ext) && typeof o.ext.kind === 'string' ? { kind: o.ext.kind.slice(0, 20) } : null,
  };
}

function normalizeGroup(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  return id ? { id, name: line(o.name, NAME_MAX) || '', area: areaOf(o.area) || 'private', position: Number.isFinite(o.position) ? o.position : 0 } : null;
}

/** The vault of a notebook ({ id, nameCipher, keyVersion, needsRotation }) or null. */
function notebookVaultOf(v) {
  const o = obj(v);
  const id = o && vaultIdOf(o.id);
  if (!id) return null;
  return { id, nameCipher: b64uOf(o.nameCipher, 2000), keyVersion: posId(o.keyVersion) || 1, needsRotation: bool(o.needsRotation) };
}

/** Notebook → cleaned, or null (a Tresor's name is null: the device decrypts nameCipher). */
function normalizeNotebook(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const vault = notebookVaultOf(o.vault);
  const b = obj(o.bound);
  return {
    id, name: vault ? null : line(o.name, NAME_MAX) || '', area: areaOf(o.area) || 'private', color: colorOf(o.color),
    isDefault: bool(o.isDefault), role: o.role === 'owner' || o.role === 'member' ? o.role : null, owner: personOf(o.owner),
    members: personList(o.members), shared: bool(o.shared), vault,
    bound: b && pluginOf(b.plugin) ? { plugin: b.plugin, key: line(b.key, 32), kind: b.kind === 'checklists' ? 'checklists' : 'notes', label: line(b.label, 60) || b.plugin } : null,
    count: count(o.count), position: Number.isFinite(o.position) ? o.position : 0,
  };
}

/** NoteSummary → cleaned, or null (a Tresor note: title and snippet null, titleCipher set). */
function normalizeNoteSummary(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const encrypted = bool(o.encrypted) || !!o.titleCipher;
  const check = obj(o.check);
  const n = {
    id, notebookId: posId(o.notebookId), title: encrypted ? null : (line(o.title, TITLE_MAX) || ''), snippet: encrypted ? null : line(o.snippet, 400),
    titleCipher: encrypted ? b64uOf(o.titleCipher, 2000) : null, keyVersion: posId(o.keyVersion), encrypted,
    pinned: bool(o.pinned), color: colorOf(o.color), due: dateOf(o.due), expiresAt: msOf(o.expiresAt),
    check: check && count(check.total) ? { done: count(check.done) || 0, total: check.total } : null,
    images: count(o.images) || 0, files: count(o.files) || 0,
    tags: arr(o.tags).slice(0, 50).map((x) => line(x, 40)).filter(Boolean), ext: line(o.ext, 20),
    createdAt: msOf(o.createdAt), updatedAt: msOf(o.updatedAt), updatedBy: posId(o.updatedBy), rev: count(o.rev) || 0,
  };
  if (typeof o.hit === 'string') n.hit = o.hit.replace(/[\u0000\u0001\u0004-\u001F\u007F]/g, ' ').slice(0, 600);
  return n;
}

/** A note of GET notes/<id> (summary + body | cipher, notebook, attachments, tasks) → cleaned, or null. */
function normalizeNote(v) {
  const n = normalizeNoteSummary(v);
  if (!n) return null;
  const o = v;
  n.body = n.encrypted ? null : (text(o.body, BODY_MAX) || '');
  n.cipher = n.encrypted ? b64uOf(o.cipher, BODY_MAX * 2) : null;
  const nb = obj(o.notebook);
  n.notebook = nb && posId(nb.id) ? { id: nb.id, name: line(nb.name, NAME_MAX), area: areaOf(nb.area) || 'private', vault: bool(nb.vault), bound: typeof nb.bound === 'string' ? nb.bound.slice(0, 60) : null } : null;
  n.attachments = arr(o.attachments).slice(0, 200).map(normalizeAttachment).filter(Boolean);
  n.tasks = arr(o.tasks).slice(0, 200).map((t) => {
    const x = obj(t);
    const id = x && posId(x.id);
    return id ? { id, title: line(x.title, TITLE_MAX) || '', due: whenOf(x.due), done: bool(x.done) } : null;
  }).filter(Boolean);
  return n;
}

/** Attachment → cleaned, or null (`url`: a signed URL of the own server, 1 h — fetched by the main process only). */
function normalizeAttachment(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const encrypted = bool(o.encrypted);
  return {
    id, kind: o.kind === 'task' ? 'task' : 'note', refId: posId(o.refId), name: encrypted ? null : line(o.name, 255),
    nameCipher: encrypted ? b64uOf(o.nameCipher, 2000) : null, mime: typeof o.mime === 'string' && /^[a-z]+\/[A-Za-z0-9.+-]{1,100}$/.test(o.mime) ? o.mime : 'application/octet-stream',
    bytes: count(o.bytes) || 0, encrypted, hasText: bool(o.hasText), url: typeof o.url === 'string' && o.url.length <= 2000 ? o.url : null,
    createdAt: msOf(o.createdAt),
  };
}

/**
 * „Gestern offen geblieben“ (GET yesterday, `yesterday` of GET views/myday, the answer of POST yesterday) →
 * { day, title, count, items: [Task], moveOptions: [{ to, date, label }] } or null (an older plugin has none).
 */
function normalizeYesterday(v) {
  const o = obj(v);
  if (!o) return null;
  const items = arr(o.items).slice(0, YESTERDAY_MAX).map(normalizeTask).filter(Boolean);
  return {
    day: dateOf(o.day), title: line(o.title, 120) || '', count: count(o.count) ?? items.length, items,
    moveOptions: arr(o.moveOptions).slice(0, 10).map((m) => {
      const x = obj(m);
      const to = x && (MOVE_WORDS.includes(x.to) ? x.to : dateOf(x.to));
      return to && to !== 'today' ? { to, date: dateOf(x.date), label: line(x.label, 60) || '' } : null;
    }).filter(Boolean),
  };
}

// ── shopping lists (plugin 1.4.0) ───────────────────────────

/**
 * A shopping list of GET shopping → cleaned, or null. `id` is the text id the device made (the id of the ops, the same
 * in Familie), `listId` the list's number (lists/<listId>, a task's attachedListId). A tombstone: `deleted: true`.
 */
function normalizeShopList(v) {
  const o = obj(v);
  const id = o && shopIdOf(o.id);
  if (!id) return null;
  const total = count(o.total) || 0;
  const as = obj(o.assignee);
  return {
    id, listId: posId(o.listId), name: line(o.name, SHOP_NAME_MAX) || '', icon: iconOf(o.icon), area: areaOf(o.area) || 'private',
    sort: Number.isFinite(o.sort) ? o.sort : 0, updatedAt: isoOf(o.updatedAt), deleted: bool(o.deleted),
    role: ['owner', 'write', 'read'].includes(o.role) ? o.role : null, canEdit: bool(o.canEdit), canManage: bool(o.canManage),
    owner: personOf(o.owner), shared: bool(o.shared),
    members: arr(o.members).slice(0, 200).map((m) => { const p = personOf(m); return p && p.id ? { ...p, role: obj(m).role === 'read' ? 'read' : 'write' } : null; }).filter(Boolean),
    family: bool(o.family), open: Math.min(count(o.open) || 0, total), total,
    assignee: as && posId(as.userId) ? { userId: as.userId, by: posId(as.by), at: isoOf(as.at), state: ['open', 'taken', 'declined'].includes(as.state) ? as.state : 'open' } : null,
    dueAt: isoOf(o.dueAt),
    going: arr(o.going).slice(0, 50).map((g) => { const x = obj(g); return x && posId(x.userId) ? { userId: x.userId, at: isoOf(x.at) } : null; }).filter(Boolean),
    tasks: arr(o.tasks).slice(0, 5).map((x) => { const y = obj(x); return y && posId(y.id) ? { id: y.id, title: line(y.title, TITLE_MAX) || '' } : null; }).filter(Boolean),
  };
}

/** An item of a shopping list → cleaned, or null (`listId`: the list's text id). */
function normalizeShopItem(v) {
  const o = obj(v);
  const id = o && shopIdOf(o.id);
  const listId = o && shopIdOf(o.listId);
  if (!id || !listId) return null;
  return {
    id, listId, text: line(o.text, SHOP_TEXT_MAX) || '', qty: line(o.qty, SHOP_QTY_MAX), checked: bool(o.checked), checkedBy: posId(o.checkedBy),
    updatedAt: isoOf(o.updatedAt), deleted: bool(o.deleted),
  };
}

/** GET shopping[?since] → { lists, items, serverTime } */
function normalizeShopping(v) {
  const o = obj(v) || {};
  return {
    lists: arr(o.lists).slice(0, 700).map(normalizeShopList).filter(Boolean),
    items: arr(o.items).slice(0, 20000).map(normalizeShopItem).filter(Boolean),
    serverTime: isoOf(o.serverTime),
  };
}

/** The answer of POST shopping/ops → { applied, rejected: [{ index, code }], serverTime, completed: [{ taskId, title, listId }] } */
function normalizeOpsAnswer(v) {
  const o = obj(v) || {};
  return {
    applied: count(o.applied) || 0,
    rejected: arr(o.rejected).slice(0, SHOP_OPS_MAX).map((r) => {
      const x = obj(r);
      return x && count(x.index) !== null ? { index: x.index, code: SHOP_REJECTS.includes(x.code) ? x.code : 'invalid' } : null;
    }).filter(Boolean),
    serverTime: isoOf(o.serverTime),
    completed: arr(o.completed).slice(0, 50).map((c) => {
      const x = obj(c);
      const taskId = x && posId(x.taskId);
      return taskId ? { taskId, title: line(x.title, TITLE_MAX) || '', listId: shopIdOf(x.listId) } : null;
    }).filter(Boolean),
  };
}

/** `attach` of POST parse / POST tasks → { via, word, list, lists } or null (no suggestion, an older plugin). */
function normalizeAttach(v) {
  const o = obj(v);
  if (!o || !ATTACH_VIA.includes(o.via)) return null;
  const lists = arr(o.lists).slice(0, 20).map(attachedListOf).filter(Boolean);
  const list = attachedListOf(o.list);
  if (!list && !lists.length) return null;
  return { via: o.via, word: o.via === 'word' ? line(o.word, 40) : null, list, lists: lists.length ? lists : [list] };
}

/** GET views/<name> → { view, title, date?, list?, plugin?, sections: [{ id, title, count, items, collapsed }] } */
function normalizeView(v) {
  const o = obj(v) || {};
  return {
    view: line(o.view, 40) || 'myday', title: line(o.title, 120) || '', date: dateOf(o.date),
    list: o.list ? normalizeList(o.list) : null, plugin: pluginOf(o.plugin), yesterday: normalizeYesterday(o.yesterday),
    sections: arr(o.sections).slice(0, 40).map((s) => {
      const x = obj(s);
      if (!x || typeof x.id !== 'string') return null;
      const items = arr(x.items).slice(0, 2000).map(normalizeEntry).filter(Boolean);
      return { id: x.id.slice(0, 120), title: line(x.title, 120) || '', count: count(x.count) ?? items.length, items, collapsed: bool(x.collapsed) };
    }).filter(Boolean),
  };
}

/** GET nav → the menu. */
function normalizeNav(v) {
  const o = obj(v) || {};
  const sm = obj(o.smart) || {};
  const notes = obj(o.notes) || {};
  return {
    area: areaOf(o.area) || 'private',
    smart: { myday: count(sm.myday) || 0, important: count(sm.important) || 0, planned: count(sm.planned) || 0, assigned: count(sm.assigned) || 0 },
    sources: arr(o.sources).slice(0, 20).map((s) => {
      const x = obj(s);
      const plugin = x && pluginOf(x.plugin);
      return plugin ? { plugin, label: line(x.label, 60) || plugin, hint: line(x.hint, 200), open: count(x.open) || 0 } : null;
    }).filter(Boolean),
    lists: arr(o.lists).slice(0, 500).map(normalizeList).filter(Boolean),
    // plugin 1.4.0: the shopping lists of the area (not part of `lists`: they hold items, no tasks)
    shopping: arr(o.shopping).slice(0, 500).map((s) => {
      const x = obj(s);
      const id = x && shopIdOf(x.id);
      if (!id) return null;
      const total = count(x.total) || 0;
      return { id, listId: posId(x.listId), name: line(x.name, SHOP_NAME_MAX) || '', icon: iconOf(x.icon), open: Math.min(count(x.open) || 0, total), total, family: bool(x.family), shared: bool(x.shared), role: ['owner', 'write', 'read'].includes(x.role) ? x.role : null };
    }).filter(Boolean),
    groups: arr(o.groups).slice(0, 200).map(normalizeGroup).filter(Boolean),
    notes: {
      total: count(notes.total) || 0,
      notebooks: arr(notes.notebooks).slice(0, 500).map(normalizeNotebook).filter(Boolean),
      tags: arr(notes.tags).slice(0, 200).map((t) => {
        const x = obj(t);
        const tag = x && line(x.tag, 40);
        return tag ? { tag, count: count(x.count) || 0 } : null;
      }).filter(Boolean),
    },
  };
}

/** The person's choices (`prefs`) as the plugin keeps them — copied as plain JSON. */
function normalizePrefs(v) {
  const o = obj(v) || {};
  const times = obj(o.times) || {};
  const t = {};
  for (const k of ['morning', 'noon', 'afternoon', 'evening', 'night']) if (timeOf(times[k])) t[k] = times[k];
  const sources = {};
  for (const [k, x] of Object.entries(obj(o.sources) || {})) {
    if (!pluginOf(k)) continue;
    const s = obj(x) || {};
    const out = {};
    if (typeof s.on === 'boolean') out.on = s.on;
    if (['all', 'mine', 'none'].includes(s.kids)) out.kids = s.kids;
    for (const f of ['shoppingInMyDay', 'flagged']) if (typeof s[f] === 'boolean') out[f] = s[f];
    if (timeOf(s.evening)) out.evening = s.evening;
    sources[k] = out;
  }
  const groups = {};
  for (const [k, x] of Object.entries(obj(o.groups) || {}).slice(0, 500)) {
    if (/^[a-z0-9-]{1,60}\|[A-Za-z0-9:._-]{1,80}$/.test(k) && ['private', 'work', 'hide'].includes(x)) groups[k] = x;
  }
  return { area: areaOf(o.area) || 'private', evening: timeOf(o.evening) || '18:00', sources, groups, times: t };
}

/** GET me */
function normalizeMe(v) {
  const o = obj(v) || {};
  const u = obj(o.user) || {};
  const im = obj(o.imports) || {};
  const cal = obj(o.calendar);
  const yd = obj(o.yesterday);
  const fam = obj(o.shopping) && obj(o.shopping.family);
  return {
    user: { id: posId(u.id), name: line(u.name, 120) || '' }, lang: o.lang === 'en' ? 'en' : 'de', today: dateOf(o.today),
    time: timeOf(o.time), timezone: line(o.timezone, 60), features: arr(o.features).filter((f) => typeof f === 'string' && /^[A-Za-z]{1,30}$/.test(f)).slice(0, 50),
    prefs: normalizePrefs(o.prefs), sharing: ['all', 'groups', 'off'].includes(o.sharing) ? o.sharing : 'all', vaults: o.vaults !== false,
    imports: { mstodo: bool(im.mstodo), mstodoSync: bool(im.mstodoSync), dsnote: bool(im.dsnote) },
    attachMB: Number.isSafeInteger(o.attachMB) && o.attachMB > 0 ? Math.min(o.attachMB, 100) : 25, readOnly: bool(o.readOnly),
    // plugin 1.3.0: the calendar „Aufgaben“ of Mail (shown only when all three are true), the morning hint
    calendar: cal ? { available: bool(cal.available), enabled: bool(cal.enabled), mine: bool(cal.mine), name: line(cal.name, NAME_MAX) || '' } : null,
    yesterday: yd ? { push: bool(yd.push), at: timeOf(yd.at) } : null,
    // plugin 1.4.0: the symbols a list may carry, what Familie adds to the shopping lists
    listIcons: arr(o.listIcons).map(iconOf).filter(Boolean).slice(0, 40),
    shopping: obj(o.shopping) ? { family: { available: bool(fam && fam.available), bound: bool(fam && fam.bound), parent: bool(fam && fam.parent) } } : null,
  };
}

/** GET people */
function normalizePeople(v) {
  return arr(obj(v) ? v.people : v).slice(0, 2000).map((p) => {
    const o = obj(p);
    const id = o && posId(o.id);
    if (!id) return null;
    return {
      id, name: line(o.name, 120) || '', initials: line(o.initials, 4) || '', me: bool(o.me),
      colorHex: typeof o.colorHex === 'string' && /^#[0-9A-Fa-f]{6}$/.test(o.colorHex) ? o.colorHex : null,
    };
  }).filter(Boolean);
}

/** GET sources */
function normalizeSources(v) {
  return arr(obj(v) ? v.sources : v).slice(0, 20).map((s) => {
    const o = obj(s);
    const plugin = o && pluginOf(o.plugin);
    if (!plugin) return null;
    return {
      plugin, label: line(o.label, 60) || plugin, hint: line(o.hint, 200), enabled: bool(o.enabled), available: bool(o.available),
      open: count(o.open) || 0, lastSync: msOf(o.lastSync), error: line(o.error, 60),
      groups: arr(o.groups).slice(0, 100).map((g) => {
        const x = obj(g);
        return x && typeof x.id === 'string' && GROUP_ID_RE.test(x.id) ? { id: x.id, label: line(x.label, 80) || x.id, count: count(x.count) || 0 } : null;
      }).filter(Boolean),
    };
  }).filter(Boolean);
}

/** GET search → { tasks, notes, items } */
function normalizeSearch(v) {
  const o = obj(v) || {};
  return {
    tasks: arr(o.tasks).slice(0, 400).map(normalizeTask).filter(Boolean),
    notes: arr(o.notes).slice(0, 400).map(normalizeNoteSummary).filter(Boolean),
    items: arr(o.items).slice(0, 400).map(normalizeItem).filter(Boolean),
  };
}

/** POST parse → the quick entry as the server reads it (ui/quickparse.js). */
function normalizeParsed(v) {
  const o = obj(v) || {};
  const list = obj(o.list);
  const as = obj(o.assignee);
  const rem = obj(o.remind);
  return {
    title: line(o.title, TITLE_MAX) || '', date: dateOf(o.date), time: timeOf(o.time),
    remind: rem && dateOf(rem.date) && timeOf(rem.time) ? { date: rem.date, time: rem.time } : null, important: bool(o.important),
    list: list && posId(list.id) ? { id: list.id, name: line(list.name, NAME_MAX) || '' } : null, listName: line(o.listName, NAME_MAX),
    assignee: as && posId(as.id) ? { id: as.id, name: line(as.name, 120) || '' } : null, assigneeName: line(o.assigneeName, 120),
    repeat: repeatOf(o.repeat),
  };
}

/** An import job → { id, kind, state, stats, error } or null. */
function normalizeJob(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const stats = {};
  for (const [k, x] of Object.entries(obj(o.stats) || {}).slice(0, 20)) if (/^[A-Za-z]{1,30}$/.test(k) && count(x) !== null) stats[k] = x;
  return { id, kind: o.kind === 'dsnote' ? 'dsnote' : 'mstodo', state: JOB_STATES.includes(o.state) ? o.state : 'running', stats, error: line(o.error, 60) };
}

function normalizeMsAccounts(v) {
  const o = obj(v) || {};
  return {
    available: bool(o.available), reason: line(o.reason, 40),
    accounts: arr(o.accounts).slice(0, 50).map((a) => {
      const x = obj(a);
      const id = x && posId(x.id);
      return id ? { id, email: line(x.email, 200) || '', label: line(x.label, 120), kind: line(x.kind, 20), tasks: bool(x.tasks) } : null;
    }).filter(Boolean),
  };
}

function normalizeMsPreview(v) {
  const o = obj(v) || {};
  const t = obj(o.totals) || {};
  return {
    lists: arr(o.lists).slice(0, 500).map((l) => {
      const x = obj(l);
      if (!x || typeof x.id !== 'string' || x.id.length > 400) return null;
      return {
        id: x.id, name: line(x.name, 200) || '', open: count(x.open) || 0, done: count(x.done) || 0, attachments: count(x.attachments) || 0,
        area: areaOf(x.area) || 'private', wellknown: line(x.wellknown, 40), shared: bool(x.shared), include: x.include !== false,
      };
    }).filter(Boolean),
    totals: { lists: count(t.lists) || 0, open: count(t.open) || 0, done: count(t.done) || 0, attachments: count(t.attachments) || 0 },
  };
}

/** POST import/mstodo/consent → the device code { deviceId, userCode, verificationUri, expiresIn, interval } | { status } */
function normalizeConsent(v) {
  const o = obj(v) || {};
  if (typeof o.status === 'string') return { status: ['done', 'pending', 'expired', 'denied', 'failed'].includes(o.status) ? o.status : 'failed' };
  const uri = typeof o.verificationUri === 'string' && /^https:\/\/[A-Za-z0-9.-]+(\/[A-Za-z0-9._~/?=&%-]*)?$/.test(o.verificationUri) && o.verificationUri.length <= 300 ? o.verificationUri : null;
  const userCode = typeof o.userCode === 'string' && /^[A-Za-z0-9-]{4,20}$/.test(o.userCode) ? o.userCode : null;
  const deviceId = typeof o.deviceId === 'string' && /^[A-Za-z0-9_-]{4,100}$/.test(o.deviceId) ? o.deviceId : (posId(o.deviceId) ? String(o.deviceId) : null);
  if (!uri || !userCode || !deviceId) return null;
  return { deviceId, userCode, verificationUri: uri, expiresIn: count(o.expiresIn) || 900, interval: Math.max(1, Math.min(60, count(o.interval) || 5)) };
}

function normalizeMsLinks(v) {
  return arr(obj(v) ? v.links : v).slice(0, 200).map((l) => {
    const x = obj(l);
    const id = x && posId(x.id);
    return id ? { id, listId: posId(x.listId), listName: line(x.listName, 200) || '', twoWay: bool(x.twoWay), error: line(x.error, 60), lastSync: msOf(x.lastSync) } : null;
  }).filter(Boolean);
}

/** A vault of GET vaults[/<id>] → { id, notebookId, area, nameCipher, keyVersion, recoveryPub, … } or null. */
function normalizeVault(v) {
  const o = obj(v);
  const id = o && vaultIdOf(o.id);
  const notebookId = o && posId(o.notebookId);
  if (!id || !notebookId) return null;
  return {
    id, notebookId, area: areaOf(o.area) || 'private', nameCipher: b64uOf(o.nameCipher, 2000), keyVersion: posId(o.keyVersion) || 1,
    recoveryPub: b64uOf(o.recoveryPub, 43), recoveryHolder: posId(o.recoveryHolder), needsRotation: bool(o.needsRotation),
    rotatedAt: msOf(o.rotatedAt), createdAt: msOf(o.createdAt),
    myDevices: arr(o.myDevices).slice(0, 200).map((d) => {
      const x = obj(d);
      const did = x && typeof x.deviceId === 'string' && VAULT_ID_RE.test(x.deviceId) ? x.deviceId : null;
      return did && ['approved', 'pending', 'revoked'].includes(x.state) ? { deviceId: did, state: x.state, name: line(x.name, 80) } : null;
    }).filter(Boolean),
    pending: count(o.pending) || 0,
  };
}

// ── arguments from the renderer ─────────────────────────────

/** 'myday' | 'important' | 'planned' | 'assigned' | 'list:<id>' | 'source:<plugin>' → the view name or null. */
function viewName(v) {
  if (SMART_VIEWS.includes(v)) return v;
  if (typeof v !== 'string') return null;
  const l = /^list:([1-9]\d{0,14})$/.exec(v);
  if (l) return v;
  const s = /^source:(.+)$/.exec(v);
  return s && pluginOf(s[1]) ? v : null;
}

/** { date, time? } | null → the body value, undefined when not one. */
function dueArg(v) {
  if (v === null) return null;
  const o = obj(v);
  const date = o && dateOf(o.date);
  if (!date) return undefined;
  const time = o.time == null || o.time === '' ? null : timeOf(o.time);
  if (o.time != null && o.time !== '' && !time) return undefined;
  return { date, time };
}

/** remindAt: null | ISO | { date, time } */
function remindArg(v) {
  if (v === null) return null;
  if (typeof v === 'string') return isoOf(v) || undefined;
  const o = obj(v);
  return o && dateOf(o.date) && timeOf(o.time) ? { date: o.date, time: o.time } : undefined;
}

const TASK_FIELDS = ['title', 'note', 'important', 'due', 'remindAt', 'repeat', 'assigneeId', 'listId', 'position', 'myDay'];

/** The fields of PATCH tasks/<id> the renderer may send → the body, or null when one is wrong. */
function taskPatch(p) {
  const o = obj(p);
  if (!o) return null;
  const b = {};
  for (const k of TASK_FIELDS) {
    if (o[k] === undefined) continue;
    const x = o[k];
    if (k === 'title') { const s = line(x, TITLE_MAX); if (!s) return null; b.title = s; } else if (k === 'note') { if (typeof x !== 'string') return null; b.note = text(x, NOTE_MAX); } else if (k === 'important' || k === 'myDay') { if (typeof x !== 'boolean') return null; b[k] = x; } else if (k === 'due') { const d = dueArg(x); if (d === undefined) return null; b.due = d; } else if (k === 'remindAt') { const r = remindArg(x); if (r === undefined) return null; b.remindAt = r; } else if (k === 'repeat') { if (x === null) b.repeat = null; else { const r = repeatOf(x); if (!r) return null; b.repeat = r; } } else if (k === 'assigneeId') { if (x !== null && !posId(x)) return null; b.assigneeId = x; } else if (k === 'listId') { if (!posId(x)) return null; b.listId = x; } else if (k === 'position') { if (!Number.isFinite(x)) return null; b.position = x; }
  }
  // plugin 1.4.0 (`taskList`): the shopping list a task carries — its number (null takes it off) or its text id
  if (o.attachedListId !== undefined) { if (o.attachedListId !== null && !posId(o.attachedListId)) return null; b.attachedListId = o.attachedListId; }
  else if (o.attachedListUid !== undefined) { if (o.attachedListUid === null) b.attachedListId = null; else if (!shopIdOf(o.attachedListUid)) return null; else b.attachedListUid = o.attachedListUid; }
  return b;
}

/** POST tasks: { title | text, listId?, area?, note?, important?, due?, remindAt?, repeat?, assigneeId?, myDay?, parentId?, createList? } */
function taskCreate(p) {
  const o = obj(p);
  if (!o) return null;
  const b = {};
  if (typeof o.text === 'string') { const s = text(o.text, 1000).trim(); if (!s) return null; b.text = s; } else { const s = line(o.title, TITLE_MAX); if (!s) return null; b.title = s; }
  if (o.listId !== undefined && o.listId !== null) { if (!posId(o.listId)) return null; b.listId = o.listId; }
  if (o.parentId !== undefined && o.parentId !== null) { if (!posId(o.parentId)) return null; b.parentId = o.parentId; }
  if (o.area !== undefined) { if (!areaOf(o.area)) return null; b.area = o.area; }
  if (o.createList !== undefined) b.createList = o.createList === true;
  const rest = taskPatch({ note: o.note, important: o.important, due: o.due, remindAt: o.remindAt, repeat: o.repeat, assigneeId: o.assigneeId, myDay: o.myDay });
  if (!rest) return null;
  // plugin 1.4.0: a list to carry, or `attach: 'auto'` — the server attaches the list the line names when exactly one fits
  if (o.attachedListId !== undefined && o.attachedListId !== null) { if (!posId(o.attachedListId)) return null; b.attachedListId = o.attachedListId; }
  else if (o.attachedListUid !== undefined && o.attachedListUid !== null) { if (!shopIdOf(o.attachedListUid)) return null; b.attachedListUid = o.attachedListUid; }
  else if (o.attach !== undefined && o.attach !== null) { if (o.attach !== 'auto') return null; b.attach = 'auto'; }
  return { ...b, ...rest };
}

/** The target of POST tasks/<id>/move: 'today' | 'tomorrow' | 'weekend' | 'YYYY-MM-DD' → the value or null. */
function moveArg(v) {
  return MOVE_WORDS.includes(v) ? v : dateOf(v);
}

/** POST yesterday { action, to?, ids?, area? } → the body, or null when a part is wrong. */
function yesterdayArg(p) {
  const o = obj(p);
  if (!o || !YESTERDAY_ACTIONS.includes(o.action)) return null;
  const b = { action: o.action };
  if (o.action === 'move') { const to = moveArg(o.to); if (!to || to === 'today') return null; b.to = to; }
  if (o.ids !== undefined && o.ids !== null) {
    if (!Array.isArray(o.ids) || !o.ids.length || o.ids.length > YESTERDAY_MAX || !o.ids.every((x) => posId(x))) return null;
    b.ids = [...new Set(o.ids)];
  }
  if (o.area !== undefined && o.area !== null) { if (!areaOf(o.area)) return null; b.area = o.area; }
  return b;
}

/**
 * One operation of POST shopping/ops as the renderer may send it → the op, or null when a part is wrong. The ids are
 * made by the device (8–64 of [A-Za-z0-9_-]); `list_add` / `item_add` without one get it from `makeId`.
 */
function shopOp(v, makeId = null) {
  const o = obj(v);
  if (!o || !SHOP_OPS.includes(o.op)) return null;
  const adds = o.op === 'list_add' || o.op === 'item_add';
  const op = { op: o.op };
  if (o.op === 'clear_checked') {
    if (!shopIdOf(o.listId)) return null;
    op.listId = o.listId;
    return op;
  }
  const id = o.id === undefined && adds && typeof makeId === 'function' ? shopIdOf(makeId()) : shopIdOf(o.id);
  if (!id) return null;
  op.id = id;
  if (o.op === 'list_add' || o.op === 'list_rename') {
    const name = typeof o.name === 'string' && o.name.trim().length <= SHOP_NAME_MAX ? line(o.name, SHOP_NAME_MAX) : null;
    if (!name) return null;
    op.name = name;
    if (o.icon !== undefined && o.icon !== null) { if (!iconOf(o.icon)) return null; op.icon = o.icon; }
    if (o.op === 'list_add') {
      if (o.area !== undefined && o.area !== null) { if (!areaOf(o.area)) return null; op.area = o.area; }
      if (o.family !== undefined && o.family !== null) { if (typeof o.family !== 'boolean') return null; if (o.family) op.family = true; }
    }
  } else if (o.op === 'item_add' || o.op === 'item_edit') {
    if (o.op === 'item_add') { if (!shopIdOf(o.listId)) return null; op.listId = o.listId; }
    if (o.text !== undefined || o.op === 'item_add') {
      const s = typeof o.text === 'string' && o.text.trim().length <= SHOP_TEXT_MAX ? line(o.text, SHOP_TEXT_MAX) : null;
      if (!s) return null;
      op.text = s;
    }
    if (o.qty !== undefined) {
      if (o.qty === null || o.qty === '') { if (o.op === 'item_edit') op.qty = null; } else {
        const q = typeof o.qty === 'string' && o.qty.trim().length <= SHOP_QTY_MAX ? line(o.qty, SHOP_QTY_MAX) : null;
        if (!q) { if (typeof o.qty !== 'string' || o.qty.trim()) return null; if (o.op === 'item_edit') op.qty = null; } else op.qty = q;
      }
    }
    if (o.op === 'item_edit' && op.text === undefined && op.qty === undefined) return null;
  } else if (o.op === 'item_check') {
    if (typeof o.checked !== 'boolean') return null;
    op.checked = o.checked;
  }
  return op;
}

/** The ops of a call (1…200) → the cleaned ops, or null. */
function shopOps(v, makeId = null) {
  if (!Array.isArray(v) || !v.length || v.length > SHOP_OPS_MAX) return null;
  const out = v.map((x) => shopOp(x, makeId));
  return out.every(Boolean) ? out : null;
}

/** POST shopping/lists/<id>/assign { userId | null, dueAt?, notify? } → the body, or null. */
function assignArg(p) {
  const o = obj(p);
  if (!o || (o.userId !== null && !posId(o.userId))) return null;
  const b = { userId: o.userId };
  if (o.dueAt !== undefined) { if (o.dueAt !== null && !isoOf(o.dueAt)) return null; b.dueAt = o.dueAt; }
  if (o.notify !== undefined && o.notify !== null) { if (!ASSIGN_NOTIFY.includes(o.notify)) return null; b.notify = o.notify; }
  return b;
}

function nameArg(v) {
  return line(v, NAME_MAX);
}

/** The ids of a member list (PUT …/members) → ids or null. */
function membersArg(v) {
  if (!Array.isArray(v) || v.length > 200 || !v.every((x) => posId(x))) return null;
  return [...new Set(v)];
}

/** GET notes query → the params, or null. */
function notesQuery(q) {
  const o = obj(q) || {};
  const p = {};
  if (o.area !== undefined && o.area !== null) { if (!areaOf(o.area)) return null; p.area = o.area; }
  if (o.notebook !== undefined && o.notebook !== null) { if (!posId(o.notebook)) return null; p.notebook = o.notebook; }
  if (o.tag !== undefined && o.tag !== null) { const t = line(o.tag, 40); if (!t) return null; p.tag = t; }
  if (o.pinned === true) p.pinned = '1';
  if (o.before !== undefined && o.before !== null) { if (typeof o.before !== 'string' || !/^\d{1,15}:\d{1,15}$/.test(o.before)) return null; p.before = o.before; }
  if (o.limit !== undefined && o.limit !== null) { if (!Number.isSafeInteger(o.limit) || o.limit < 1 || o.limit > 200) return null; p.limit = o.limit; }
  return p;
}

/** PATCH notes/<id> of a plain note → the body or null. */
function notePatch(p) {
  const o = obj(p);
  if (!o) return null;
  const b = {};
  if (o.title !== undefined) { if (typeof o.title !== 'string') return null; b.title = (line(o.title, TITLE_MAX) || ''); }
  if (o.body !== undefined) { if (typeof o.body !== 'string' || o.body.length > BODY_MAX) return null; b.body = text(o.body, BODY_MAX); }
  if (o.pinned !== undefined) { if (typeof o.pinned !== 'boolean') return null; b.pinned = o.pinned; }
  if (o.color !== undefined) { if (o.color !== null && !colorOf(o.color)) return null; b.color = o.color || 'none'; }
  if (o.due !== undefined) { if (o.due !== null && !dateOf(o.due)) return null; b.due = o.due; }
  if (o.expiresAt !== undefined) { if (o.expiresAt !== null && !msOf(o.expiresAt)) return null; b.expiresAt = o.expiresAt; }
  if (o.notebookId !== undefined) { if (!posId(o.notebookId)) return null; b.notebookId = o.notebookId; }
  if (o.rev !== undefined) { if (count(o.rev) === null) return null; b.rev = o.rev; }
  return b;
}

// ── a note's check boxes (ui/notemd.js) ─────────────────────

const CHECK_RE = /^(\s*)([-*+])\s+\[([ xX])\]\s+(.*)$/;

/** The Markdown with the check box of line `line` set (notemd.toggle), or null when that line has none. */
function toggleCheck(md, lineNo, done) {
  const ls = String(md == null ? '' : md).replace(/\r\n?/g, '\n').split('\n');
  const m = Number.isSafeInteger(lineNo) && ls[lineNo] != null ? CHECK_RE.exec(ls[lineNo]) : null;
  if (!m) return null;
  ls[lineNo] = `${m[1]}${m[2]} [${done ? 'x' : ' '}] ${m[4]}`;
  return ls.join('\n');
}

// ── where a click leads ─────────────────────────────────────

/**
 * A click on a push of the hub → { kind: 'task', taskId } | { kind: 'list', listId } | { kind: 'notebook', notebookId }
 * | { kind: 'vault', vaultId, event } | { kind: 'yesterday', day, taskIds, action } | { kind: 'home' } (topic of the
 * plugin without data) | null (not ours).
 * The plugin's pushes carry data.notizen = { task | list | notebook | vault } (README "Live updates"). The morning hint
 * (plugin 1.3.0, data.notizen.kind 'yesterday') opens „Mein Tag“ with the card; `actionId` is the button that was
 * pressed: 'done_ask' and 'move' — which GateControl sends as a portal link, the plugin has no app tab — are answered
 * by the page (`action`), every other button stays what it is (`action: null`). A reminder of a task with a shopping
 * list (plugin 1.4.0, data.notizen.attachedList): its button „Liste öffnen“ ('open_list') → { kind: 'shopping', uid,
 * listId, taskId } — the list to tick off; a click on the message itself stays the task.
 */
function pushTarget(topic, data, actionId = null) {
  if (typeof topic !== 'string' || !topic.startsWith(TOPIC_PREFIX)) return null;
  const d = obj(data);
  const n = d && obj(d.notizen);
  if (n && n.kind === 'yesterday') {
    return {
      kind: 'yesterday', day: dateOf(n.day), taskIds: [...new Set(arr(n.taskIds).filter((x) => posId(x)))].slice(0, YESTERDAY_MAX),
      action: actionId === 'done_ask' || actionId === 'move' ? actionId : null,
    };
  }
  if (n) {
    const al = obj(n.attachedList);
    if (actionId === 'open_list' && al && shopIdOf(al.uid)) return { kind: 'shopping', uid: al.uid, listId: posId(al.id), taskId: posId(n.task) || posId(n.taskId) };
    if (posId(n.task)) return { kind: 'task', taskId: n.task };
    if (posId(n.list)) return { kind: 'list', listId: n.list };
    if (posId(n.notebook)) return { kind: 'notebook', notebookId: n.notebook };
    if (vaultIdOf(n.vault)) return { kind: 'vault', vaultId: n.vault, event: n.event === 'request' || n.event === 'approved' ? n.event : null };
  }
  return { kind: 'home' };
}

/** The live event `changed` { what } → the kinds that changed. */
function changedOf(data) {
  const d = obj(data) || {};
  const all = ['tasks', 'notes', 'items', 'lists', 'notebooks', 'shopping'];
  const what = arr(d.what).filter((w) => all.includes(w));
  return { what: what.length ? [...new Set(what)] : all };
}

/** An error → a code for the renderer. */
function errorCode(err) {
  return (err && typeof err.code === 'string' && CODE_RE.test(err.code) && err.code) || 'failed';
}

module.exports = {
  PLUGIN_ID, APP_ROUTE, PLUGINS_PATH, API_BASE, MEDIA_PATH, TOPIC_PREFIX, VAULT_PREFIX,
  AREAS, SMART_VIEWS, SOURCES, COLORS, ITEM_KINDS, REPEAT_TYPES, DONE_DAYS, TITLE_MAX, BODY_MAX, NOTE_MAX, NAME_MAX, QUERY_MAX,
  SHOP_OPS, SHOP_OPS_MAX, SHOP_NAME_MAX, SHOP_TEXT_MAX, SHOP_QTY_MAX,
  line, text, posId, count, dateOf, timeOf, areaOf, colorOf, pluginOf, vaultIdOf, isMediaId, repeatOf, openOf, shopIdOf, isoOf,
  normalizeShopList, normalizeShopItem, normalizeShopping, normalizeOpsAnswer, normalizeAttach, shopOp, shopOps, assignArg,
  normalizeTask, normalizeItem, normalizeEntry, normalizeList, normalizeGroup, normalizeNotebook, normalizeNoteSummary, normalizeNote,
  normalizeAttachment, normalizeYesterday, normalizeView, normalizeNav, normalizePrefs, normalizeMe, normalizePeople, normalizeSources, normalizeSearch,
  normalizeParsed, normalizeJob, normalizeMsAccounts, normalizeMsPreview, normalizeConsent, normalizeMsLinks, normalizeVault,
  viewName, dueArg, remindArg, taskPatch, taskCreate, moveArg, yesterdayArg, nameArg, membersArg, notesQuery, notePatch, toggleCheck,
  pushTarget, changedOf, errorCode,
};
