'use strict';

/**
 * Pure helpers of Mail (plugin `gatecontrol-mail`, Phase 1: the person's mail
 * accounts — IMAP / SMTP, Microsoft, Gmail — on the own server; contract:
 * the plugin's client API, "C2"): constants, argument checks, cleaned answers
 * of the app API, request bodies, the HTML document of a mail for the
 * sandboxed reading frame and the Microsoft sign-in (PKCE).
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * enums checked, ids positive integers, times as milliseconds. Every parser
 * accepts more than it needs and drops what it does not understand, so later
 * additions on the plugin side do not break older Windows apps. Electron-free
 * and side-effect free (unit-tested directly).
 */

const crypto = require('crypto');

const PLUGIN_ID = 'gatecontrol-mail';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const PLUGINS_PATH = '/api/v1/client/plugins';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const MEDIA_PATH = `/api/v1/client/plugins/${PLUGIN_ID}/media`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const MAIL_TOPIC = `${TOPIC_PREFIX}mail`;
const FAILED_TOPIC = `${TOPIC_PREFIX}mail_failed`;
/** The scheme the reading frame loads pictures with (img/<token>, cid/<message>/<attachment>), see MailService.handleProtocol. */
const SCHEME = 'gcmail';

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;   // gc.mail.smtp.send: a mail ≤ 50 MB in all
const IMAGE_MAX_BYTES = 5 * 1024 * 1024;     // gc.http.fetchImage ≤ 5 MB
const HTML_MAX = 2 * 1024 * 1024;
const TEXT_MAX = 1024 * 1024;
const SUBJECT_MAX = 998;
const NAME_MAX = 255;
const IDS_MAX = 500;

const PROVIDERS = Object.freeze(['gmx', 'webde', 'tonline', 'gmail', 'outlook', 'm365', 'imap']);
const AUTHS = Object.freeze(['password', 'app_password', 'microsoft', 'imap']);
const KINDS = Object.freeze(['personal', 'business']);
const ACCOUNT_STATES = Object.freeze(['ok', 'syncing', 'auth_failed', 'unreachable']);
const PUSH_MODES = Object.freeze(['off', 'relevant', 'all']);
const ATTACH_MODES = Object.freeze(['off', 'suggest', 'auto']);
const SWIPES = Object.freeze(['archive', 'delete', 'read', 'none']);
const ROLES = Object.freeze(['inbox', 'sent', 'drafts', 'archive', 'junk', 'trash']);
const TABS = Object.freeze(['relevant', 'other']);
const SECURITY = Object.freeze(['tls', 'starttls']);
const MODES = Object.freeze(['reply', 'replyAll', 'forward']);
const TODO_KINDS = Object.freeze(['question', 'deadline', 'event', 'amount', 'task']);
const REASONS = Object.freeze(['rule', 'learned', 'ai', 'kind']);
const OUTBOX_STATES = Object.freeze(['waiting', 'sending', 'failed']);
const WARNINGS = Object.freeze(['password', 'too_large', 'no_subject']);
const CONTACT_SOURCES = Object.freeze(['person', 'recent']);
const FEATURES = Object.freeze(['mail', 'ai', 'microsoft', 'drive', 'familyCalendar', 'images']);
const MS_SCOPES = Object.freeze(['openid', 'profile', 'email', 'offline_access', 'User.Read', 'Mail.ReadWrite', 'Mail.Send']);
const MS_AUTHORITY = 'https://login.microsoftonline.com/common';
const MS_HOSTS = Object.freeze(['login.microsoftonline.com', 'login.microsoft.com']);

const CTRL_LINE_RE = /[\u0000-\u001F\u007F]/g;
const CTRL_TEXT_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const MEDIA_ID_RE = /^[A-Za-z0-9_-]{6,128}$/;
const CODE_RE = /^[A-Za-z0-9_.-]{1,60}$/;
const CURSOR_RE = /^[A-Za-z0-9:._+|,=~-]{1,200}$/;
const TOKEN_RE = /^[A-Za-z0-9_.~-]{1,200}$/;
const COLOR_RE = /^#[0-9A-Fa-f]{6}$/;
const EMAIL_RE = /^[^\s@<>()",;:\\[\]]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z0-9-]{2,63}$/;
const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);
const bool = (v) => v === true;
const oneOf = (list, v, fallback = null) => (list.includes(v) ? v : fallback);

/** Trimmed single-line string ≤ max, or null. */
function line(v, max) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const s = String(v).replace(CTRL_LINE_RE, ' ').trim().slice(0, max);
  return s || null;
}

/** Multi-line text ≤ max (line breaks and tabs kept), or null. */
function text(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/\r\n?/g, '\n').replace(CTRL_TEXT_RE, '').slice(0, max);
  return s.trim() ? s : null;
}

/** Positive safe integer (number or numeric string), else null. */
function posId(v) {
  const n = typeof v === 'string' && /^\d{1,16}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** Non-negative safe integer, else null. */
function count(v) {
  const n = typeof v === 'string' && /^\d{1,16}$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

/** Epoch ms (or an ISO string) → ms, else null. */
function msOf(v) {
  if (Number.isFinite(v) && v > 0) return Math.round(v);
  if (typeof v !== 'string' || v.length > 40) return null;
  if (/^\d{10,16}$/.test(v)) return Number(v);
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

const isMediaId = (v) => typeof v === 'string' && MEDIA_ID_RE.test(v);
const codeOf = (v) => (typeof v === 'string' && CODE_RE.test(v) ? v : null);
const cursorOf = (v) => (typeof v === 'string' && CURSOR_RE.test(v) ? v : null);
const colorOf = (v) => (typeof v === 'string' && COLOR_RE.test(v) ? v.toUpperCase() : null);
const isEmail = (v) => typeof v === 'string' && v.length <= 320 && EMAIL_RE.test(v.trim());
const emailOf = (v) => (isEmail(v) ? v.trim() : null);
const isHost = (v) => typeof v === 'string' && HOST_RE.test(v);
const isToken = (v) => typeof v === 'string' && TOKEN_RE.test(v);

/** { de, en } of the plugin (hints) → both strings, or null. */
function i18nText(v, max = 500) {
  if (typeof v === 'string') { const s = line(v, max); return s ? { de: s, en: s } : null; }
  const o = obj(v);
  if (!o) return null;
  const de = line(o.de, max);
  const en = line(o.en, max);
  return de || en ? { de: de || en, en: en || de } : null;
}

/** An https URL (help pages, list-unsubscribe, Drive links), else null. */
function httpsUrl(v) {
  if (typeof v !== 'string' || v.length > 2048) return null;
  try {
    const u = new URL(v.trim());
    return u.protocol === 'https:' && u.hostname ? u.toString() : null;
  } catch {
    return null;
  }
}

/** http(s) URL (List-Unsubscribe may be http), else null. */
function webUrl(v) {
  if (typeof v !== 'string' || v.length > 2048) return null;
  try {
    const u = new URL(v.trim());
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.hostname ? u.toString() : null;
  } catch {
    return null;
  }
}

// ── Answers ────────────────────────────────────────────────

/** { name, email } (the plugin also sends `address`), or null without a usable address. */
function normalizeAddress(v) {
  const o = obj(v);
  if (!o) return null;
  const email = emailOf(o.email) || emailOf(o.address);
  const name = line(o.name, 200);
  if (!email && !name) return null;
  return { name, email };
}

const addresses = (v, max = 100) => arr(v).map(normalizeAddress).filter(Boolean).slice(0, max);

function normalizeSettings(v) {
  const o = obj(v) || {};
  return {
    threads: o.threads !== false,
    swipeLeft: oneOf(SWIPES, o.swipeLeft, 'archive'),
    swipeRight: oneOf(SWIPES, o.swipeRight, 'read'),
  };
}

/** An `Account` of the contract, or null. */
function normalizeAccount(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const email = o && emailOf(o.email);
  if (!id || !email) return null;
  const err = obj(o.error);
  return {
    id,
    provider: oneOf(PROVIDERS, o.provider, 'imap'),
    email,
    name: line(o.name, 120) || email,
    color: colorOf(o.color) || '#79B8FF',
    kind: oneOf(KINDS, o.kind, 'personal'),
    state: oneOf(ACCOUNT_STATES, o.state, 'ok'),
    error: err && codeOf(err.code) ? { code: err.code, at: msOf(err.at) } : null,
    push: oneOf(PUSH_MODES, o.push, 'relevant'),
    ai: bool(o.ai),
    attachments: oneOf(ATTACH_MODES, o.attachments, 'off'),
    signature: text(o.signature, 10000) || '',
    avatar: normalizeAvatar(o.avatar),
  };
}

/** Raster pictures only (never SVG). */
const PICTURE_MIME_RE = /^image\/(png|jpe?g|gif|webp|bmp|avif)$/;

/** `Account.avatar` (Mail 1.1.2, Microsoft only) → { mediaId, mime }, else null. */
function normalizeAvatar(v) {
  const o = obj(v);
  if (!o || !isMediaId(o.mediaId)) return null;
  const mime = typeof o.mime === 'string' ? o.mime.split(';')[0].trim().toLowerCase() : '';
  return PICTURE_MIME_RE.test(mime) ? { mediaId: o.mediaId, mime } : null;
}

/**
 * The live event `mail` `{ kind: 'changed', accountId, folderId }` — since Mail 1.1.2 also with `messageId` (a body
 * the answer did not wait for is there; with `attachmentId`: that attachment) or `threadId` — → the 'changed' payload.
 */
function normalizeChanged(v) {
  const o = obj(v) || {};
  return {
    accountId: posId(o.accountId),
    folderId: posId(o.folderId),
    messageId: posId(o.messageId),
    threadId: posId(o.threadId),
    attachmentId: posId(o.attachmentId),
  };
}

/**
 * `409 busy { reason?, retryAfter? }` (an error of MailApi, or the IPC failure { code, detail }) → { loading,
 * retryAfter (s, 1…60, 5 without one) }; null when it is no `busy`. `loading`: an attachment or embedded picture the
 * provider is still sending.
 */
function busyOf(err) {
  if (!err || err.code !== 'busy') return null;
  const d = obj(err.detail) || {};
  const n = Number.isFinite(d.retryAfter) ? Math.round(d.retryAfter) : 5;
  return { loading: d.reason === 'loading', retryAfter: Math.min(60, Math.max(1, n)) };
}

/** GET me → { features, limits, microsoft, accounts, unread, settings }. */
function normalizeMe(v) {
  const o = obj(v) || {};
  const features = arr(o.features).filter((f) => typeof f === 'string' && FEATURES.includes(f));
  if (!features.includes('mail')) features.unshift('mail');
  const l = obj(o.limits) || {};
  const ms = obj(o.microsoft) || {};
  const clientId = typeof ms.clientId === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(ms.clientId) ? ms.clientId : null;
  const scopes = arr(ms.scopes).filter((s) => typeof s === 'string' && /^[A-Za-z0-9_.:/-]{1,100}$/.test(s)).slice(0, 30);
  const u = obj(o.unread) || {};
  const byAccount = {};
  for (const [k, n] of Object.entries(obj(u.byAccount) || {})) {
    if (posId(k) && count(n) !== null) byAccount[String(posId(k))] = count(n);
  }
  return {
    features: [...new Set(features)],
    limits: {
      accountsMax: count(l.accountsMax),
      quotaBytes: count(l.quotaBytes),
      usedBytes: count(l.usedBytes),
      retentionMonths: count(l.retentionMonths),
    },
    microsoft: {
      clientId,
      authority: msAuthority(ms.authority) || MS_AUTHORITY,
      scopes: scopes.length ? scopes : MS_SCOPES.slice(),
    },
    accounts: arr(o.accounts).map(normalizeAccount).filter(Boolean).slice(0, 50),
    unread: { all: count(u.all) || 0, byAccount },
    settings: normalizeSettings(o.settings),
  };
}

/** GET providers → [{ id, label, auth, hint, help }]. */
function normalizeProviders(v) {
  const list = Array.isArray(v) ? v : arr(obj(v) && (v.items || v.providers));
  return list.map((p) => {
    const o = obj(p);
    const id = o && oneOf(PROVIDERS, o.id);
    if (!id) return null;
    return { id, label: line(o.label, 80) || id, auth: oneOf(AUTHS, o.auth, 'password'), hint: i18nText(o.hint), help: httpsUrl(o.help) };
  }).filter(Boolean).slice(0, 30);
}

function server(v) {
  const o = obj(v);
  if (!o || !isHost(o.host)) return null;
  const port = posId(o.port);
  return { host: o.host.toLowerCase(), port: port && port <= 65535 ? port : null, security: oneOf(SECURITY, o.security, 'tls') };
}

/** POST accounts/discover → { provider, auth, imap, smtp, hint }. */
function normalizeDiscover(v) {
  const o = obj(v) || {};
  return {
    provider: oneOf(PROVIDERS, o.provider, 'imap'),
    auth: oneOf(AUTHS, o.auth, 'password'),
    imap: server(o.imap),
    smtp: server(o.smtp),
    hint: i18nText(o.hint),
  };
}

function normalizeFolder(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const name = o && (line(o.name, 200) || line(o.path, 200));
  if (!id || !name) return null;
  return { id, name, path: line(o.path, 500) || name, role: oneOf(ROLES, o.role), parentId: posId(o.parentId), unread: count(o.unread) || 0, total: count(o.total) || 0 };
}

/** GET folders → { accounts: [{ accountId, folders }] }. */
function normalizeFolders(v) {
  const o = obj(v) || {};
  return {
    accounts: arr(o.accounts).map((a) => {
      const x = obj(a);
      const accountId = x && posId(x.accountId);
      if (!accountId) return null;
      return { accountId, folders: arr(x.folders).map(normalizeFolder).filter(Boolean).slice(0, 2000) };
    }).filter(Boolean).slice(0, 50),
  };
}

/** A `Summary` of a list, or null. */
function normalizeSummary(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const accountId = o && posId(o.accountId);
  if (!id || !accountId) return null;
  const ai = obj(o.ai);
  return {
    id,
    accountId,
    folderId: posId(o.folderId),
    threadId: posId(o.threadId),
    threadCount: count(o.threadCount) || 1,
    from: normalizeAddress(o.from) || { name: null, email: null },
    to: addresses(o.to, 3),
    subject: line(o.subject, SUBJECT_MAX),
    snippet: line(o.snippet, 160),
    date: msOf(o.date),
    unread: bool(o.unread),
    flagged: bool(o.flagged),
    answered: bool(o.answered),
    hasAttachments: bool(o.hasAttachments),
    tab: oneOf(TABS, o.tab, 'relevant'),
    savedToDrive: bool(o.savedToDrive),
    ai: ai && line(ai.summary, 500) ? { summary: line(ai.summary, 500) } : null,
  };
}

/** GET messages / search → { items, next, counts, remote }. */
function normalizeList(v) {
  const o = obj(v) || {};
  const c = obj(o.counts);
  return {
    items: arr(o.items).map(normalizeSummary).filter(Boolean).slice(0, 500),
    next: cursorOf(o.next),
    counts: c ? { relevant: count(c.relevant) || 0, other: count(c.other) || 0 } : null,
    remote: bool(o.remote),
  };
}

/** A Drive `Suggestion`, or null. */
function normalizeSuggestion(v) {
  const o = obj(v);
  const folderId = o && posId(o.folderId);
  if (!folderId) return null;
  const c = Number(o.confidence);
  return {
    folderId,
    areaId: line(o.areaId, 80),
    path: line(o.path, 1000),
    where: line(o.where, 500),
    name: line(o.name, NAME_MAX),
    confidence: Number.isFinite(c) ? Math.min(1, Math.max(0, c)) : null,
    reason: oneOf(REASONS, o.reason),
  };
}

function savedTo(v) {
  const o = obj(v);
  const nodeId = o && posId(o.nodeId);
  return nodeId ? { nodeId, where: line(o.where, 500) } : null;
}

function normalizeAttachment(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id,
    name: line(o.name, NAME_MAX) || 'Anhang',
    mime: line(o.mime, 120),
    size: count(o.size) || 0,
    inline: bool(o.inline),
    cid: line(o.cid, 300),
    savedTo: savedTo(o.savedTo),
    suggestion: normalizeSuggestion(o.suggestion),
  };
}

/** GET messages/<id> → `Message` (Summary + body, attachments, images), or null. */
function normalizeMessage(v) {
  const s = normalizeSummary(v);
  if (!s) return null;
  const o = v;
  const lu = obj(o.listUnsubscribe);
  const unsub = lu ? { url: webUrl(lu.url), mail: emailOf(typeof lu.mail === 'string' ? lu.mail.replace(/^mailto:/i, '').split('?')[0] : null) } : null;
  return {
    ...s,
    to: addresses(o.to),
    cc: addresses(o.cc),
    bcc: addresses(o.bcc),
    replyTo: addresses(o.replyTo, 10),
    html: typeof o.html === 'string' && o.html.trim() ? o.html.slice(0, HTML_MAX) : null,
    text: text(o.text, TEXT_MAX),
    imagesBlocked: bool(o.imagesBlocked),
    trackers: count(o.trackers) || 0,
    attachments: arr(o.attachments).map(normalizeAttachment).filter(Boolean).slice(0, 200),
    listUnsubscribe: unsub && (unsub.url || unsub.mail) ? unsub : null,
    // the body is not in the server's copy (and the provider did not give it now): "wird geladen" / try again
    bodyMissing: bool(o.bodyMissing),
  };
}

/** GET threads/<id> → { items } (oldest first). */
function normalizeThread(v) {
  return { items: arr(obj(v) && v.items).map(normalizeMessage).filter(Boolean).slice(0, 200) };
}

function draftAttachment(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return { id, name: line(o.name, NAME_MAX) || 'Anhang', size: count(o.size) || 0, mime: line(o.mime, 120), as: o.as === 'link' ? 'link' : 'copy', url: httpsUrl(o.url) };
}

/** A `draft` ({ draft } or the draft itself), or null. */
function normalizeDraft(v) {
  const o = obj(v) && obj(v.draft) ? v.draft : obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id,
    accountId: posId(o.accountId),
    to: addresses(o.to),
    cc: addresses(o.cc),
    bcc: addresses(o.bcc),
    subject: line(o.subject, SUBJECT_MAX) || '',
    html: typeof o.html === 'string' ? o.html.slice(0, HTML_MAX) : '',
    attachments: arr(o.attachments).map(draftAttachment).filter(Boolean).slice(0, 100),
    warnings: arr(o.warnings).map((w) => {
      const x = obj(w);
      const kind = x && oneOf(WARNINGS, x.kind);
      return kind ? { kind, text: line(x.text, 500) } : null;
    }).filter(Boolean).slice(0, 10),
  };
}

/** POST drafts/<id>/send → { outboxId, undoUntil, sendAt }. */
function normalizeSend(v) {
  const o = obj(v) || {};
  const outboxId = posId(o.outboxId);
  if (!outboxId) return null;
  return { outboxId, undoUntil: msOf(o.undoUntil), sendAt: msOf(o.sendAt) };
}

function normalizeOutbox(v) {
  return {
    items: arr(obj(v) && v.items).map((x) => {
      const o = obj(x);
      const id = o && posId(o.id);
      if (!id) return null;
      const e = o.error;
      return {
        id,
        draftId: posId(o.draftId),
        accountId: posId(o.accountId),
        subject: line(o.subject, SUBJECT_MAX),
        sendAt: msOf(o.sendAt),
        state: oneOf(OUTBOX_STATES, o.state, 'waiting'),
        error: typeof e === 'string' ? line(e, 300) : (obj(e) ? (codeOf(e.code) || line(e.text, 300)) : null),
      };
    }).filter(Boolean).slice(0, 200),
  };
}

function normalizeContacts(v) {
  return {
    items: arr(obj(v) && v.items).map((x) => {
      const o = obj(x);
      const email = o && emailOf(o.email);
      return email ? { name: line(o.name, 200), email, source: oneOf(CONTACT_SOURCES, o.source, 'recent') } : null;
    }).filter(Boolean).slice(0, 10),
  };
}

/** GET / POST ai/<id> → { status: 'done', summary, todos, replies } | { status: 'none' }. */
function normalizeAi(v) {
  const o = obj(v) || {};
  if (o.status !== 'done') return { status: 'none' };
  return {
    status: 'done',
    summary: line(o.summary, 2000),
    todos: arr(o.todos).map((x) => {
      const t = obj(x);
      const kind = t && oneOf(TODO_KINDS, t.kind);
      const txt = t && line(t.text, 300);
      if (!kind || !txt) return null;
      const amount = Number(t.amount);
      return {
        kind,
        text: txt,
        date: typeof t.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(t.date) ? t.date : null,
        time: typeof t.time === 'string' && /^\d{2}:\d{2}$/.test(t.time) ? t.time : null,
        amount: Number.isFinite(amount) ? amount : null,
        currency: typeof t.currency === 'string' && /^[A-Z]{3}$/.test(t.currency) ? t.currency : null,
      };
    }).filter(Boolean).slice(0, 20),
    replies: arr(o.replies).map((x) => {
      const r = obj(x);
      const label = r && line(r.label, 80);
      const body = r && text(r.text, 5000);
      return label && body ? { label, text: body } : null;
    }).filter(Boolean).slice(0, 5),
  };
}

/** GET filing → { items: [{ id, messageId, attachmentId, name, from, date, suggestion, accountId? }] }. */
function normalizeFiling(v) {
  return {
    items: arr(obj(v) && v.items).map((x) => {
      const o = obj(x);
      const id = o && posId(o.id);
      if (!id) return null;
      return {
        id,
        messageId: posId(o.messageId),
        attachmentId: posId(o.attachmentId),
        accountId: posId(o.accountId),
        name: line(o.name, NAME_MAX) || 'Anhang',
        from: typeof o.from === 'string' ? { name: line(o.from, 200), email: null } : (normalizeAddress(o.from) || { name: null, email: null }),
        date: msOf(o.date),
        suggestion: normalizeSuggestion(o.suggestion),
      };
    }).filter(Boolean).slice(0, 500),
  };
}

/** GET messages/<id>/attachments/<aid> → { mediaId, name, mime, size }, or null. */
function normalizeMedia(v) {
  const o = obj(v);
  if (!o || !isMediaId(o.mediaId)) return null;
  return { mediaId: o.mediaId, name: line(o.name, NAME_MAX) || 'Anhang', mime: line(o.mime, 120), size: count(o.size) || 0 };
}

// ── Request bodies ─────────────────────────────────────────

const BOX_RE = /^(all|\d{1,16})$/;

/** Ids of a list action (1 … 500 positive ints), or null. */
function idList(v) {
  if (!Array.isArray(v) || !v.length || v.length > IDS_MAX) return null;
  const out = [];
  for (const x of v) {
    const id = posId(x);
    if (!id) return null;
    if (!out.includes(id)) out.push(id);
  }
  return out;
}

/**
 * Query of GET messages ({ box, folder, tab, unread, flagged, attachments, before, limit }) → params, or null when
 * an argument is invalid. `box`: 'all' or an account id; `folder` only with an account.
 */
function listQuery(q = {}) {
  const o = obj(q) || {};
  const box = o.box === undefined || o.box === null ? 'all' : String(o.box);
  if (!BOX_RE.test(box) || (box !== 'all' && !posId(box))) return null;
  const p = { box };
  if (o.folder !== undefined && o.folder !== null) {
    if (box === 'all' || !posId(o.folder)) return null;
    p.folder = posId(o.folder);
  }
  if (o.tab !== undefined && o.tab !== null) {
    if (!['relevant', 'other', 'all'].includes(o.tab)) return null;
    p.tab = o.tab;
  }
  for (const k of ['unread', 'flagged', 'attachments']) if (o[k] === true) p[k] = 1;
  if (o.before !== undefined && o.before !== null) {
    if (!cursorOf(o.before)) return null;
    p.before = o.before;
  }
  const limit = o.limit === undefined || o.limit === null ? 50 : posId(o.limit);
  if (!limit || limit > 200) return null;
  p.limit = limit;
  return p;
}

/**
 * Query of GET search ({ q, box, from, after, before, attachments, unread, cursor }) → params, or null. Words or a
 * sender (`from` alone: the sender's mails) are needed.
 */
function searchQuery(q = {}) {
  const o = obj(q) || {};
  const s = typeof o.q === 'string' ? o.q.replace(CTRL_LINE_RE, ' ').trim() : '';
  const hasFrom = o.from !== undefined && o.from !== null && o.from !== '';
  if ((!s && !hasFrom) || s.length > 200) return null;
  const p = s ? { q: s } : {};
  if (o.box !== undefined && o.box !== null) {
    const box = String(o.box);
    if (!BOX_RE.test(box)) return null;
    p.box = box;
  }
  if (hasFrom) {
    const f = line(o.from, 200);
    if (!f) return null;
    p.from = f;
  }
  for (const k of ['after', 'before']) {
    if (o[k] === undefined || o[k] === null || o[k] === '') continue;
    const ms = msOf(o[k]);
    if (!ms) return null;
    p[k] = ms;
  }
  for (const k of ['attachments', 'unread']) if (o[k] === true) p[k] = 1;
  if (o.cursor !== undefined && o.cursor !== null) {
    if (!cursorOf(o.cursor)) return null;
    p.cursor = o.cursor;
  }
  return p;
}

/** Recipients as typed ([{ name?, email }] or "a@b, Name <c@d>") → [{ name, email }] | null when one is invalid. */
function recipients(v) {
  if (v === undefined || v === null || v === '') return [];
  let list = v;
  if (typeof v === 'string') list = splitAddresses(v);
  if (!Array.isArray(list) || list.length > 100) return null;
  const out = [];
  for (const x of list) {
    const o = typeof x === 'string' ? parseAddress(x) : obj(x);
    const email = o && emailOf(o.email || o.address);
    if (!email) return null;
    if (out.some((r) => r.email.toLowerCase() === email.toLowerCase())) continue;
    out.push({ name: line(o.name, 200), email });
  }
  return out;
}

/** "Name <a@b>" | "a@b" → { name, email } | null. */
function parseAddress(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  const m = /^(?:"?([^"<]*?)"?\s*)?<([^<>\s]+)>$/.exec(s);
  if (m) return isEmail(m[2]) ? { name: line(m[1], 200), email: m[2] } : null;
  return isEmail(s) ? { name: null, email: s } : null;
}

/** Splits "a@b, Name <c@d>; e@f" at commas / semicolons outside quotes. */
function splitAddresses(raw) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (const ch of String(raw)) {
    if (ch === '"') quoted = !quoted;
    if (!quoted && (ch === ',' || ch === ';' || ch === '\n')) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/**
 * An attachment of a draft request (PUT drafts: always the whole list): { mediaId, name? } | { messageId, attachmentId } | { driveNodeId, as, expiresDays?,
 * password? } | { id } (one the draft has already: kept), or null.
 */
function draftAtt(v) {
  const o = obj(v);
  if (!o) return null;
  if (posId(o.id) && Object.keys(o).every((k) => k === 'id' || k === 'name' || k === 'size')) return { id: posId(o.id) };
  if (isMediaId(o.mediaId)) {
    const name = line(o.name, NAME_MAX);
    return name ? { mediaId: o.mediaId, name } : { mediaId: o.mediaId };
  }
  if (posId(o.messageId) && posId(o.attachmentId)) return { messageId: posId(o.messageId), attachmentId: posId(o.attachmentId) };
  if (posId(o.driveNodeId)) {
    const as = o.as === 'link' ? 'link' : (o.as === 'copy' || o.as === undefined ? 'copy' : null);
    if (!as) return null;
    const out = { driveNodeId: posId(o.driveNodeId), as };
    if (as === 'link') {
      if (o.expiresDays !== undefined && o.expiresDays !== null) {
        const d = posId(o.expiresDays);
        if (!d || d > 90) return null;
        out.expiresDays = d;
      }
      if (typeof o.password === 'string' && o.password) {
        if (o.password.length > 200) return null;
        out.password = o.password;
      }
    }
    return out;
  }
  return null;
}

/**
 * Body of POST drafts / PUT drafts/<id> → the body, or null when invalid. Fields left out stay out (the server fills
 * a reply / forward when `to` / `subject` / `html` are missing).
 */
function draftBody(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.accountId !== undefined && o.accountId !== null) {
    if (!posId(o.accountId)) return null;
    b.accountId = posId(o.accountId);
  }
  for (const k of ['to', 'cc', 'bcc']) {
    if (o[k] === undefined) continue;
    const r = recipients(o[k]);
    if (!r) return null;
    b[k] = r;
  }
  if (o.subject !== undefined) {
    if (typeof o.subject !== 'string' || o.subject.length > SUBJECT_MAX) return null;
    b.subject = o.subject.replace(CTRL_LINE_RE, ' ');
  }
  if (o.html !== undefined) {
    if (typeof o.html !== 'string' || o.html.length > HTML_MAX) return null;
    b.html = serverHtml(o.html);
  }
  if (o.replyTo !== undefined && o.replyTo !== null) {
    if (!posId(o.replyTo)) return null;
    b.replyTo = posId(o.replyTo);
  }
  if (o.mode !== undefined && o.mode !== null) {
    if (!MODES.includes(o.mode)) return null;
    b.mode = o.mode;
  }
  if (b.mode && !b.replyTo) return null;
  if (o.attachments !== undefined) {
    if (!Array.isArray(o.attachments) || o.attachments.length > 100) return null;
    const list = o.attachments.map(draftAtt);
    if (list.some((x) => !x)) return null;
    b.attachments = list;
  } else if (!b.attachments) {
    b.attachments = [];
  }
  return b;
}

/** POST accounts → the body, or null. */
function accountBody(v) {
  const o = obj(v);
  if (!o || !oneOf(PROVIDERS, o.provider) || !isEmail(o.email) || typeof o.password !== 'string' || !o.password || o.password.length > 1024) return null;
  const b = { provider: o.provider, email: o.email.trim(), password: o.password };
  if (typeof o.username === 'string' && o.username.trim()) {
    if (o.username.length > 320) return null;
    b.username = o.username.trim();
  }
  const extra = accountPatch({ name: o.name, color: o.color, kind: o.kind }, { partial: true });
  if (!extra) return null;
  Object.assign(b, extra);
  for (const k of ['imap', 'smtp']) {
    if (o[k] === undefined || o[k] === null) continue;
    const s = obj(o[k]);
    const port = s && posId(s.port);
    if (!s || !isHost(s.host) || !port || port > 65535 || !SECURITY.includes(s.security)) return null;
    b[k] = { host: s.host.toLowerCase(), port, security: s.security };
  }
  return b;
}

/** PATCH accounts/<id> → the patch (only fields given), or null when one is invalid. */
function accountPatch(v, { partial = false } = {}) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  const set = (k, val) => { if (val !== undefined) b[k] = val; };
  if (o.name !== undefined && o.name !== null && o.name !== '') {
    const n = line(o.name, 120);
    if (!n) return null;
    set('name', n);
  }
  if (o.color !== undefined && o.color !== null && o.color !== '') {
    if (!colorOf(o.color)) return null;
    set('color', colorOf(o.color));
  }
  if (o.kind !== undefined && o.kind !== null) { if (!KINDS.includes(o.kind)) return null; set('kind', o.kind); }
  if (partial) return b;
  if (o.push !== undefined) { if (!PUSH_MODES.includes(o.push)) return null; set('push', o.push); }
  if (o.ai !== undefined) { if (typeof o.ai !== 'boolean') return null; set('ai', o.ai); }
  if (o.attachments !== undefined) { if (!ATTACH_MODES.includes(o.attachments)) return null; set('attachments', o.attachments); }
  if (o.signature !== undefined) {
    if (typeof o.signature !== 'string' || o.signature.length > 10000) return null;
    set('signature', o.signature.replace(/\r\n?/g, '\n').replace(CTRL_TEXT_RE, ''));
  }
  if (o.password !== undefined) {
    if (typeof o.password !== 'string' || !o.password || o.password.length > 1024) return null;
    set('password', o.password);
  }
  return Object.keys(b).length ? b : null;
}

/** PUT settings → the patch, or null. */
function settingsPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.threads !== undefined) { if (typeof o.threads !== 'boolean') return null; b.threads = o.threads; }
  for (const k of ['swipeLeft', 'swipeRight']) {
    if (o[k] === undefined) continue;
    if (!SWIPES.includes(o[k])) return null;
    b[k] = o[k];
  }
  return Object.keys(b).length ? b : null;
}

// ── HTML of a mail (the sandboxed reading frame) ──────────

const IMG_PATH_RE = new RegExp(`^(?:${API_BASE.replace(/[/.-]/g, (c) => `\\${c}`)})?img/(${TOKEN_RE.source.slice(1, -1)})$`);
const SAFE_DATA_IMG_RE = /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=\s]{1,2000000}$/i;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function decodeAttr(s) {
  return String(s).replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/gi, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
}

/**
 * The picture sources of a mail's (already sanitized) HTML for the frame:
 * `img/<token>` (the plugin's image proxy) → gcmail://img/<token> (none while `imagesBlocked`), `cid:<id>` → the
 * attachment with that Content-ID → gcmail://cid/<message>/<attachment>, safe data: pictures kept; every other
 * source (http, file, …), srcset and background attributes are removed — the frame's CSP would refuse them anyway.
 */
function rewriteSources(html, message) {
  const m = message || {};
  const byCid = new Map();
  for (const a of arr(m.attachments)) if (a && a.cid) byCid.set(String(a.cid).replace(/^<|>$/g, '').toLowerCase(), a.id);
  const blocked = m.imagesBlocked === true;
  // only inside tags (text that reads " src=" stays as it is)
  return String(html || '').replace(/<[A-Za-z](?:[^>"']|"[^"]*"|'[^']*')*>/g, (tag) => rewriteTag(tag, m, byCid, blocked));
}

const ATTR_RE = /\s+([^\s"'=<>/`]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?/g;
const DROP_ATTRS = new Set(['srcset', 'background', 'lowsrc', 'dynsrc', 'poster']);

/** One start tag with its picture attributes rewritten (attributes parsed one by one: values never count as names). */
function rewriteTag(tag, m, byCid, blocked) {
  const head = /^<[A-Za-z][A-Za-z0-9-]*/.exec(tag);
  if (!head) return tag;
  const close = /\/?>$/.exec(tag);
  const inner = tag.slice(head[0].length, close ? tag.length - close[0].length : tag.length);
  let changed = false;
  const attrs = [];
  ATTR_RE.lastIndex = 0;
  let a;
  while ((a = ATTR_RE.exec(inner)) !== null) {
    const name = a[1].toLowerCase();
    if (DROP_ATTRS.has(name)) { changed = true; continue; }
    if (name !== 'src' || a[2] === undefined) { attrs.push(a[0]); continue; }
    changed = true;
    const rawQ = a[2];
    const raw = decodeAttr(rawQ[0] === '"' || rawQ[0] === "'" ? rawQ.slice(1, -1) : rawQ);
    attrs.push(` ${sourceOf(raw, m, byCid, blocked)}`);
  }
  return changed ? `${head[0]}${attrs.join('')}${close ? close[0] : ''}` : tag;
}

function sourceOf(raw, m, byCid, blocked) {
  const img = IMG_PATH_RE.exec(raw);
  if (img) return blocked ? 'data-gc-blocked=""' : `src="${SCHEME}://img/${img[1]}"`;
  if (/^cid:/i.test(raw)) {
    const id = byCid.get(raw.slice(4).replace(/^<|>$/g, '').toLowerCase());
    return id && posId(m.id) ? `src="${SCHEME}://cid/${m.id}/${id}"` : 'data-gc-blocked=""';
  }
  if (SAFE_DATA_IMG_RE.test(raw)) return `src="${escapeHtml(raw.replace(/\s+/g, ''))}"`;
  return 'data-gc-blocked=""';
}

/** Plain text → HTML with http(s) links (escaped). */
function textToHtml(t) {
  const esc = escapeHtml(String(t || ''));
  return esc.replace(/\bhttps?:\/\/[^\s<>"']{1,2000}/g, (u) => {
    const clean = u.replace(/[.,;:!?)]+$/, '');
    return `<a href="${clean}">${clean}</a>${u.slice(clean.length)}`;
  });
}

const FRAME_CSP = `default-src 'none'; img-src ${SCHEME}: data:; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'`;

/** The element of the frame document that holds the mail (the window makes it smaller when it is too wide). */
const FIT_ID = 'gc-fit';

/**
 * The whole document of the reading frame (iframe srcdoc, sandboxed without scripts): its own CSP (pictures only
 * through gcmail: and data:), links open in a new window (the window guard hands them to the browser), a white
 * page like mail programs show it. Pictures, tables, long links and preformatted text stay inside the width; the
 * mail sits in #gc-fit, which the window sets smaller (CSS zoom) when it is still wider (a newsletter's table of a
 * fixed 600 px) — measured from outside, the frame runs no script.
 */
function mailDocument(message, { lang = 'de' } = {}) {
  const m = message || {};
  const body = m.html ? rewriteSources(m.html, m) : `<div class="gc-text">${textToHtml(m.text || '')}</div>`;
  return '<!doctype html><html lang="' + (lang === 'en' ? 'en' : 'de') + '"><head><meta charset="utf-8">'
    + `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}">`
    + '<meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width, initial-scale=1"><base target="_blank">'
    + '<style>html,body{margin:0;padding:0;background:#fff;color:#1A1D22}body{padding:16px;font:14px/1.5 "Segoe UI",system-ui,sans-serif;overflow-wrap:anywhere}'
    + 'img{max-width:100%;height:auto}img[data-gc-blocked]{display:inline-block;min-width:16px;min-height:16px;background:#EEF1F5;border-radius:3px}'
    + '.gc-text{white-space:pre-wrap}blockquote{margin:0 0 0 8px;padding-left:10px;border-left:3px solid #D5DBE3;color:#4A5563}'
    + 'table{max-width:100%}td,th{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#1A56C4;overflow-wrap:anywhere;word-break:break-word}</style>'
    + `</head><body><div id="${FIT_ID}">${body}</div></body></html>`;
}

/** Draft HTML for the editor frame: the plugin's img/<token> pictures through gcmail: (serverHtml() turns them back). */
function editorHtml(html) {
  return String(html || '').replace(/(\ssrc\s*=\s*")(?:[^"]*?\/)?img\/([A-Za-z0-9_.~-]{1,200})"/gi, (_a, pre, tok) => `${pre}${SCHEME}://img/${tok}"`);
}

/** HTML of the editor back for the plugin: gcmail://img/<token> → img/<token>; gcmail://cid/… stays out. */
function serverHtml(html) {
  return String(html || '')
    .replace(new RegExp(`${SCHEME}://img/([A-Za-z0-9_.~-]{1,200})`, 'g'), 'img/$1')
    .replace(new RegExp(`\\ssrc\\s*=\\s*"${SCHEME}://[^"]*"`, 'g'), '');
}

/** The editor frame's document (contenteditable body; the frame is sandboxed without scripts). */
function editorDocument(html, { lang = 'de', placeholder = '' } = {}) {
  return '<!doctype html><html lang="' + (lang === 'en' ? 'en' : 'de') + '"><head><meta charset="utf-8">'
    + `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}">`
    + '<style>html,body{margin:0;background:#fff;color:#1A1D22;height:100%}body{padding:12px 14px;font:14px/1.55 "Segoe UI",system-ui,sans-serif;outline:none;overflow-wrap:anywhere;box-sizing:border-box;min-height:100%}'
    + 'body:empty::before{content:attr(data-placeholder);color:#8C96A5}img{max-width:100%}blockquote{margin:0 0 0 8px;padding-left:10px;border-left:3px solid #D5DBE3;color:#4A5563}</style>'
    + `</head><body contenteditable="true" spellcheck="true" data-placeholder="${escapeHtml(placeholder)}">${editorHtml(html)}</body></html>`;
}

/** gcmail:// URL → { kind: 'img', token } | { kind: 'cid', messageId, attachmentId } | null. */
function parseSchemeUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 400) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== `${SCHEME}:` || u.search || u.hash) return null;
  const parts = `${u.hostname}${u.pathname}`.split('/').filter(Boolean);
  if (parts[0] === 'img' && parts.length === 2 && isToken(parts[1])) return { kind: 'img', token: parts[1] };
  if (parts[0] === 'cid' && parts.length === 3 && posId(parts[1]) && posId(parts[2])) return { kind: 'cid', messageId: posId(parts[1]), attachmentId: posId(parts[2]) };
  return null;
}

// ── Microsoft sign-in (authorization code with PKCE, public client) ───

/** The authority of GET me (https on Microsoft's sign-in host), else null. */
function msAuthority(v) {
  if (typeof v !== 'string' || v.length > 300) return null;
  try {
    const u = new URL(v);
    if (u.protocol !== 'https:' || !MS_HOSTS.includes(u.hostname.toLowerCase()) || u.search || u.hash || u.username || u.password || u.port) return null;
    const p = u.pathname.replace(/\/+$/, '');
    return /^\/[A-Za-z0-9.-]{1,100}$/.test(p) ? `https://${u.hostname.toLowerCase()}${p}` : null;
  } catch {
    return null;
  }
}

const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** PKCE: verifier (43 characters of 32 random bytes) and its S256 challenge. */
function pkcePair(random = crypto.randomBytes) {
  const verifier = b64u(random(32));
  const challenge = b64u(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

/** The authorize URL of the Microsoft sign-in in the browser. */
function msAuthorizeUrl({ authority, clientId, redirectUri, scopes, state, challenge, loginHint = null }) {
  const base = msAuthority(authority);
  if (!base || typeof clientId !== 'string' || !clientId) return null;
  const u = new URL(`${base}/oauth2/v2.0/authorize`);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('response_mode', 'query');
  u.searchParams.set('scope', (Array.isArray(scopes) && scopes.length ? scopes : MS_SCOPES).join(' '));
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('prompt', 'select_account');
  if (isEmail(loginHint)) u.searchParams.set('login_hint', loginHint);
  return u.toString();
}

// ── Misc ───────────────────────────────────────────────────

/** A stable key of a list query (offline cache). */
function listKey(p) {
  const o = obj(p) || {};
  return ['box', 'folder', 'tab', 'unread', 'flagged', 'attachments'].map((k) => (o[k] === undefined ? '' : String(o[k]))).join('|');
}

/** Is this list a plain inbox (kept for at least 30 days offline)? */
function isInboxKey(p) {
  const o = obj(p) || {};
  return !o.folder && !o.unread && !o.flagged && !o.attachments && !o.before;
}

/** The click on a Mail push → { kind: 'message', messageId, accountId } | { kind: 'outbox', outboxId } | null. */
function pushTarget(topic, data) {
  const d = obj(data);
  const m = d && obj(d.mail);
  if (!m) return null;
  if (topic === MAIL_TOPIC && posId(m.messageId)) return { kind: 'message', messageId: posId(m.messageId), accountId: posId(m.accountId) };
  if (topic === FAILED_TOPIC && posId(m.outboxId)) return { kind: 'outbox', outboxId: posId(m.outboxId) };
  return null;
}

/** A failure → a code for the renderer. */
function errorCode(err) {
  return (err && typeof err.code === 'string' && /^[A-Za-z0-9_.-]{1,60}$/.test(err.code) && err.code) || 'failed';
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  PLUGINS_PATH,
  API_BASE,
  MEDIA_PATH,
  MAIL_TOPIC,
  FAILED_TOPIC,
  SCHEME,
  FRAME_CSP,
  FIT_ID,
  MAX_UPLOAD_BYTES,
  IMAGE_MAX_BYTES,
  PROVIDERS,
  AUTHS,
  KINDS,
  PUSH_MODES,
  ATTACH_MODES,
  SWIPES,
  ROLES,
  TABS,
  MODES,
  FEATURES,
  MS_SCOPES,
  MS_AUTHORITY,
  line,
  posId,
  count,
  msOf,
  isEmail,
  isMediaId,
  isToken,
  codeOf,
  cursorOf,
  colorOf,
  normalizeAddress,
  normalizeSettings,
  normalizeAccount,
  normalizeAvatar,
  normalizeChanged,
  busyOf,
  normalizeMe,
  normalizeProviders,
  normalizeDiscover,
  normalizeFolders,
  normalizeSummary,
  normalizeList,
  normalizeSuggestion,
  normalizeAttachment,
  normalizeMessage,
  normalizeThread,
  normalizeDraft,
  normalizeSend,
  normalizeOutbox,
  normalizeContacts,
  normalizeAi,
  normalizeFiling,
  normalizeMedia,
  idList,
  listQuery,
  searchQuery,
  recipients,
  parseAddress,
  splitAddresses,
  draftAtt,
  draftBody,
  accountBody,
  accountPatch,
  settingsPatch,
  escapeHtml,
  rewriteSources,
  textToHtml,
  mailDocument,
  editorHtml,
  serverHtml,
  editorDocument,
  parseSchemeUrl,
  msAuthority,
  pkcePair,
  msAuthorizeUrl,
  listKey,
  isInboxKey,
  pushTarget,
  errorCode,
};
