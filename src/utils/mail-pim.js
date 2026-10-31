'use strict';

/**
 * Pure helpers of Mail Phase 2 — calendar and contacts in the plugin
 * `gatecontrol-mail` (contract: the plugin's client API "C3"): cleaned answers
 * (calendars, overlays, occurrences, an event, invitations, address books,
 * contacts, groups, duplicates), query parameters and request bodies, the
 * live events `calendar` / `contacts` and the offline filter of contacts.
 *
 * Same rules as utils/mail.js (exported from there as well): known fields
 * only, strings capped and without control characters, enums checked, ids
 * positive integers, times in ms; what is not understood is dropped, so later
 * additions of the plugin do not break older apps. Electron-free, no side
 * effects (unit-tested directly).
 */

const m = require('./mail');

const { line, text, obj, arr, bool, oneOf, posId, count, msOf, emailOf, colorOf, codeOf, cursorOf, webUrl, i18nText } = m;

const CAL_SOURCES = Object.freeze(['local', 'graph', 'caldav', 'ics']);
const CAL_KINDS = Object.freeze(['private', 'business', 'other']);
const SYNC_STATES = Object.freeze(['ok', 'syncing', 'auth_failed', 'unreachable', 'consent_required']);
const VIEWS = Object.freeze(['day', '3day', 'week', 'month', 'list']);
const EVENT_STATUS = Object.freeze(['confirmed', 'tentative', 'cancelled']);
const BUSY = Object.freeze(['busy', 'free', 'tentative', 'oof']);
const MY_RESPONSES = Object.freeze(['organizer', 'accepted', 'tentative', 'declined', 'needs_action']);
const RESPONSES = Object.freeze(['accepted', 'tentative', 'declined', 'needs_action']);
const ANSWERS = Object.freeze(['accepted', 'tentative', 'declined']);
const ATTENDEE_ROLES = Object.freeze(['required', 'optional', 'resource']);
const FREQS = Object.freeze(['daily', 'weekly', 'monthly', 'yearly']);
const WEEKDAYS = Object.freeze(['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU']);
const ONLINE = Object.freeze(['teams', 'zoom', 'meet', 'webex', 'other']);
const INVITE_KINDS = Object.freeze(['mail', 'internal']);
const INVITE_STATES = Object.freeze(['open', 'answered', 'applied', 'cancelled', 'outdated']);
const BOOK_SOURCES = Object.freeze(['local', 'graph', 'carddav']);
const EMAIL_TYPES = Object.freeze(['home', 'work', 'other']);
const PHONE_TYPES = Object.freeze(['mobile', 'home', 'work', 'fax', 'other']);
const ADDRESS_TYPES = Object.freeze(['home', 'work', 'other']);
const DUP_REASONS = Object.freeze(['email', 'phone', 'name']);
const CARD_SORTS = Object.freeze(['family', 'given']);
const CARD_SHOWS = Object.freeze(['given_family', 'family_given']);
const PHOTO_MIMES = Object.freeze(['image/jpeg', 'image/png']);

const DAY = 24 * 60 * 60 * 1000;
const RANGE_MAX_MS = 62 * DAY;
const TITLE_MAX = 255;
const DESCRIPTION_MAX = 32 * 1024;
const NOTE_MAX = 8 * 1024;
const ATTENDEES_MAX = 100;
const PHOTO_MAX_BYTES = 256 * 1024;
const VCF_MAX_BYTES = 5 * 1024 * 1024;

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const OCC_RE = /^(?:\d{10,16}|\d{4}-\d{2}-\d{2})$/;
const BIRTHDAY_RE = /^(?:\d{4}|-)-\d{2}-\d{2}$/;
const TZ_RE = /^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/;
const OVERLAY_RE = /^(?:familie|birthdays|alltag:\d{1,16})$/;
const KEY_RE = /^[A-Za-z0-9:_.|@-]{1,200}$/;
const ETAG_RE = /^[\x21-\x7E]{1,200}$/;
const RRULE_RE = /^[A-Z0-9=;,:+-]{1,500}$/;

const isDate = (v) => typeof v === 'string' && DATE_RE.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`));
const dateOf = (v) => (isDate(v) ? v : null);
const occOf = (v) => (typeof v === 'string' && OCC_RE.test(v) ? v : null);
const tzOf = (v) => (typeof v === 'string' && TZ_RE.test(v) ? v : null);
const ids = (v, max) => [...new Set(arr(v).map(posId).filter(Boolean))].slice(0, max);
const intIn = (v, lo, hi) => (Number.isSafeInteger(v) && v >= lo && v <= hi ? v : null);

/** An { code, at } error of a calendar / address book, or null. */
function syncError(v) {
  const e = obj(v);
  return e && codeOf(e.code) ? { code: e.code, at: msOf(e.at) } : null;
}

// ── Calendars ──────────────────────────────────────────────

/** A `Calendar`, or null. */
function normalizeCalendar(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id,
    source: oneOf(CAL_SOURCES, o.source, 'local'),
    accountId: posId(o.accountId),
    name: line(o.name, 120) || 'Kalender',
    color: colorOf(o.color) || '#46E0A0',
    kind: oneOf(CAL_KINDS, o.kind, 'other'),
    writable: bool(o.writable),
    visible: o.visible !== false,
    notify: o.notify !== false,
    isDefault: bool(o.isDefault),
    canInvite: bool(o.canInvite),
    canOnline: bool(o.canOnline),
    maxReminders: intIn(o.maxReminders, 0, 3) ?? 3,
    state: oneOf(SYNC_STATES, o.state, 'ok'),
    error: syncError(o.error),
    syncedAt: msOf(o.syncedAt),
    version: count(o.version) || 0,
  };
}

/** An `Overlay` (Familie, an Alltag subscription, birthdays), or null. */
function normalizeOverlay(v) {
  const o = obj(v);
  if (!o || typeof o.id !== 'string' || !OVERLAY_RE.test(o.id)) return null;
  return {
    id: o.id,
    source: o.id === 'familie' ? 'familie' : (o.id === 'birthdays' ? 'birthdays' : 'alltag'),
    name: line(o.name, 120) || o.id,
    color: colorOf(o.color) || '#8C96A5',
    visible: bool(o.visible),
  };
}

/** `CalPrefs`. */
function normalizeCalPrefs(v) {
  const o = obj(v) || {};
  const rem = o.defaultReminder === null ? null : intIn(o.defaultReminder, 0, 40320);
  return {
    defaultCalendarId: posId(o.defaultCalendarId),
    view: oneOf(VIEWS, o.view, 'week'),
    weekStart: o.weekStart === 0 ? 0 : 1,
    workWeek: bool(o.workWeek),
    timeZone: tzOf(o.timeZone),
    reminders: o.reminders !== false,
    defaultReminder: o.defaultReminder === undefined ? 15 : rem,
    allDayReminder: intIn(o.allDayReminder, 0, 10080) ?? 1080,
  };
}

/** GET calendars → { calendars, overlays, prefs, consent: [{ accountId, missing }] }. */
function normalizeCalendars(v) {
  const o = obj(v) || {};
  return {
    calendars: arr(o.calendars).map(normalizeCalendar).filter(Boolean).slice(0, 200),
    overlays: arr(o.overlays).map(normalizeOverlay).filter(Boolean).slice(0, 50),
    prefs: normalizeCalPrefs(o.prefs),
    consent: arr(o.consent).map((x) => {
      const c = obj(x);
      const accountId = c && posId(c.accountId);
      return accountId ? { accountId, missing: arr(c.missing).map((s) => line(s, 100)).filter(Boolean).slice(0, 5) } : null;
    }).filter(Boolean).slice(0, 50),
  };
}

/** `online` of an event → { url, provider } (http(s) only), or null. */
function normalizeOnline(v) {
  const o = obj(v);
  const url = o && webUrl(o.url);
  return url ? { url, provider: oneOf(ONLINE, o.provider, 'other') } : null;
}

/** The dates of an all-day item ({ startDate, endDate } inclusive), {} for one with a time. */
function allDayDates(o, allDay) {
  if (!allDay) return {};
  const startDate = dateOf(o.startDate);
  const endDate = dateOf(o.endDate);
  return startDate ? { startDate, endDate: endDate && endDate >= startDate ? endDate : startDate } : {};
}

/** An `Occurrence` of GET events, or null. */
function normalizeOccurrence(v) {
  const o = obj(v);
  const eventId = o && posId(o.eventId);
  const start = o && msOf(o.start);
  if (!eventId || !start) return null;
  const end = msOf(o.end);
  const occurrence = occOf(o.occurrence);
  const allDay = bool(o.allDay);
  return {
    key: occurrence ? `${eventId}:${occurrence}` : String(eventId),
    eventId,
    calendarId: posId(o.calendarId),
    occurrence,
    title: line(o.title, TITLE_MAX) || '',
    start,
    end: end && end >= start ? end : start,
    allDay,
    ...allDayDates(o, allDay),
    timeZone: tzOf(o.timeZone),
    location: line(o.location, 500),
    online: normalizeOnline(o.online),
    status: oneOf(EVENT_STATUS, o.status, 'confirmed'),
    busy: oneOf(BUSY, o.busy, 'busy'),
    myResponse: oneOf(MY_RESPONSES, o.myResponse),
    recurring: bool(o.recurring),
    attendees: count(o.attendees) || 0,
    private: bool(o.private),
    reminder: o.reminder === null || o.reminder === undefined ? null : intIn(o.reminder, 0, 40320),
  };
}

/** An `OverlayItem` (read only), or null. */
function normalizeOverlayItem(v) {
  const o = obj(v);
  const start = o && msOf(o.start);
  if (!o || typeof o.key !== 'string' || !KEY_RE.test(o.key) || typeof o.overlayId !== 'string' || !OVERLAY_RE.test(o.overlayId) || !start) return null;
  const end = msOf(o.end);
  const allDay = bool(o.allDay);
  return {
    key: o.key,
    overlayId: o.overlayId,
    title: line(o.title, TITLE_MAX) || '',
    start,
    end: end && end >= start ? end : start,
    allDay,
    ...allDayDates(o, allDay),
    location: line(o.location, 500),
    readOnly: true,
  };
}

/** GET events → { items, overlays, pending }. */
function normalizeEvents(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map(normalizeOccurrence).filter(Boolean).slice(0, 5000),
    overlays: arr(o.overlays).map(normalizeOverlayItem).filter(Boolean).slice(0, 5000),
    pending: ids(o.pending, 200),
  };
}

/** An attendee of an event or an invitation, or null without an address. */
function normalizeAttendee(v) {
  const o = obj(v);
  const email = o && emailOf(o.email);
  if (!email) return null;
  return {
    name: line(o.name, 200) || '',
    email,
    role: oneOf(ATTENDEE_ROLES, o.role, 'required'),
    response: oneOf(RESPONSES, o.response, 'needs_action'),
    self: bool(o.self),
    contactId: posId(o.contactId),
  };
}

/** `Recurrence` of an event, or null. */
function normalizeRecurrence(v) {
  const o = obj(v);
  if (!o) return null;
  const rrule = typeof o.rrule === 'string' && RRULE_RE.test(o.rrule) ? o.rrule : null;
  const freq = oneOf(FREQS, o.freq);
  if (!rrule && !freq) return null;
  const byDay = arr(o.byDay).filter((d) => typeof d === 'string' && /^(?:[+-]?\d)?(MO|TU|WE|TH|FR|SA|SU)$/.test(d)).slice(0, 7);
  const byMonthDay = arr(o.byMonthDay).filter((d) => Number.isSafeInteger(d) && d !== 0 && d >= -31 && d <= 31).slice(0, 31);
  return {
    rrule,
    editable: o.editable !== false && !!freq,
    freq,
    interval: intIn(o.interval, 1, 999) || 1,
    byDay: byDay.length ? byDay : null,
    byMonthDay: byMonthDay.length ? byMonthDay : null,
    bySetPos: Number.isSafeInteger(o.bySetPos) && o.bySetPos !== 0 && o.bySetPos >= -5 && o.bySetPos <= 5 ? o.bySetPos : null,
    until: dateOf(o.until),
    count: intIn(o.count, 1, 9999),
    exceptions: arr(o.exceptions).map(occOf).filter(Boolean).slice(0, 1000),
    deleted: arr(o.deleted).map(occOf).filter(Boolean).slice(0, 1000),
  };
}

/** `series` of an event of a series (Mail 1.3.0: DTSTART / DTEND of the master) → { start, end, allDay, startDate?, endDate? }, or null. */
function seriesOf(v) {
  const o = obj(v);
  const start = o && msOf(o.start);
  if (!start) return null;
  const end = msOf(o.end);
  const allDay = bool(o.allDay);
  // all-day series: their dates as well (endDate inclusive)
  return { start, end: end && end >= start ? end : start, allDay, ...allDayDates(o, allDay) };
}

/** GET events/<id> → `Event` (Occurrence + description, organizer, attendees, rights, etag), or null. */
function normalizeEvent(v) {
  const base = normalizeOccurrence(v);
  if (!base) return null;
  const o = v;
  const org = obj(o.organizer);
  const orgMail = org && emailOf(org.email);
  return {
    ...base,
    description: text(o.description, DESCRIPTION_MAX) || '',
    descriptionHtml: typeof o.descriptionHtml === 'string' && o.descriptionHtml.trim() ? o.descriptionHtml.slice(0, 256 * 1024) : null,
    organizer: orgMail ? { name: line(org.name, 200) || '', email: orgMail, self: bool(org.self) } : null,
    attendees: arr(o.attendees).map(normalizeAttendee).filter(Boolean).slice(0, ATTENDEES_MAX),
    reminders: arr(o.reminders).filter((x) => intIn(x, 0, 40320) !== null).slice(0, 3),
    recurrence: normalizeRecurrence(o.recurrence),
    seriesId: posId(o.seriesId),
    // Mail 1.3.0: DTSTART / DTEND of the series' master (a change of "Alle Termine der Serie" is made against it); null before
    series: seriesOf(o.series),
    readOnly: bool(o.readOnly),
    canRespond: bool(o.canRespond),
    canEdit: bool(o.canEdit),
    canDelete: bool(o.canDelete),
    categories: arr(o.categories).map((c) => line(c, 80)).filter(Boolean).slice(0, 20),
    invitationId: posId(o.invitationId),
    url: webUrl(o.url),
    createdAt: msOf(o.createdAt),
    updatedAt: msOf(o.updatedAt),
    etag: typeof o.etag === 'string' && ETAG_RE.test(o.etag) ? o.etag : null,
  };
}

/** POST/PATCH events → { event, sent: { mail, internal } }. */
function normalizeSaved(v) {
  const o = obj(v) || {};
  const s = obj(o.sent) || {};
  return { event: normalizeEvent(o.event), sent: { mail: count(s.mail) || 0, internal: count(s.internal) || 0 } };
}

// ── Invitations ────────────────────────────────────────────

/** An `Invitation` (the card in a mail, an internal invitation), or null. */
function normalizeInvitation(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const start = o && msOf(o.start);
  if (!id || !start) return null;
  const allDay = bool(o.allDay);
  const end = msOf(o.end);
  const org = obj(o.organizer) || {};
  const from = obj(o.from) || {};
  const c = obj(o.counts) || {};
  const proposed = obj(o.proposed);
  const rec = obj(o.recurrence);
  return {
    id,
    kind: oneOf(INVITE_KINDS, o.kind, 'mail'),
    messageId: posId(o.messageId),
    accountId: posId(o.accountId),
    method: oneOf(m.INVITES, o.method, 'request'),
    state: oneOf(INVITE_STATES, o.state, 'open'),
    title: line(o.title, TITLE_MAX) || '',
    start,
    end: end && end >= start ? end : start,
    allDay,
    ...allDayDates(o, allDay),
    timeZone: tzOf(o.timeZone),
    location: line(o.location, 500),
    online: normalizeOnline(o.online),
    recurrence: rec ? { summary: i18nText(rec.summary, 300) } : null,
    organizer: { name: line(org.name, 200) || '', email: emailOf(org.email), contactId: posId(org.contactId) },
    from: { name: line(from.name, 200) || '', email: emailOf(from.email) },
    attendees: arr(o.attendees).map(normalizeAttendee).filter(Boolean).slice(0, ATTENDEES_MAX),
    counts: { accepted: count(c.accepted) || 0, tentative: count(c.tentative) || 0, declined: count(c.declined) || 0, needs_action: count(c.needs_action) || 0 },
    myResponse: oneOf(MY_RESPONSES, o.myResponse),
    comment: text(o.comment, 2000),
    proposed: proposed && msOf(proposed.start) && msOf(proposed.end) ? { start: msOf(proposed.start), end: msOf(proposed.end) } : null,
    eventId: posId(o.eventId),
    calendarId: posId(o.calendarId),
    calendarChoices: ids(o.calendarChoices, 200),
    day: arr(o.day).map(normalizeOccurrence).filter(Boolean).slice(0, 50),
    conflicts: arr(o.conflicts).map((x) => {
      const k = obj(x);
      const s = k && msOf(k.start);
      return s ? { title: line(k.title, TITLE_MAX) || '', start: s, end: msOf(k.end) || s, calendarId: posId(k.calendarId) } : null;
    }).filter(Boolean).slice(0, 20),
  };
}

/** GET invitations → { items }. */
function normalizeInvitations(v) {
  return { items: arr(obj(v) && v.items).map(normalizeInvitation).filter(Boolean).slice(0, 500) };
}

/** POST invitations/<id>/respond | apply → { invitation, event }. */
function normalizeInviteResult(v) {
  const o = obj(v) || {};
  return { invitation: normalizeInvitation(o.invitation), event: o.event ? normalizeEvent(o.event) : null };
}

// ── Calendar requests ──────────────────────────────────────

/** GET events → params { from, to, calendars? } (≤ 62 days), or null. */
function eventsQuery(q) {
  const o = obj(q) || {};
  const from = Number.isSafeInteger(o.from) && o.from > 0 ? o.from : null;
  const to = Number.isSafeInteger(o.to) && o.to > 0 ? o.to : null;
  if (!from || !to || to <= from || to - from > RANGE_MAX_MS) return null;
  const p = { from, to };
  if (o.calendars !== undefined && o.calendars !== null) {
    // a list, or the joined form of an earlier eventsQuery
    const cals = typeof o.calendars === 'string' ? o.calendars.split(',') : o.calendars;
    if (!Array.isArray(cals) || cals.length > 200) return null;
    const list = [];
    for (const c of cals) {
      const v = posId(c) ? String(posId(c)) : (typeof c === 'string' && OVERLAY_RE.test(c) ? c : null);
      if (!v) return null;
      if (!list.includes(v)) list.push(v);
    }
    p.calendars = list.join(',');
  }
  return p;
}

/** A stable key of an events query (offline cache). */
function eventsKey(p) {
  const o = obj(p) || {};
  return `${o.from}|${o.to}|${o.calendars || ''}`;
}

function recurrenceBody(v) {
  if (v === null) return null;
  const o = obj(v);
  if (!o) return undefined;
  if (o.rrule !== undefined) return typeof o.rrule === 'string' && RRULE_RE.test(o.rrule) ? { rrule: o.rrule } : undefined;
  if (!FREQS.includes(o.freq)) return undefined;
  const b = { freq: o.freq, interval: 1 };
  if (o.interval !== undefined && o.interval !== null) { if (!intIn(o.interval, 1, 999)) return undefined; b.interval = o.interval; }
  if (o.byDay !== undefined && o.byDay !== null) {
    if (!Array.isArray(o.byDay) || !o.byDay.length || o.byDay.length > 7 || !o.byDay.every((d) => typeof d === 'string' && /^(?:[+-]?\d)?(MO|TU|WE|TH|FR|SA|SU)$/.test(d))) return undefined;
    b.byDay = [...new Set(o.byDay)];
  }
  if (o.byMonthDay !== undefined && o.byMonthDay !== null) {
    if (!Array.isArray(o.byMonthDay) || !o.byMonthDay.length || o.byMonthDay.length > 31 || !o.byMonthDay.every((d) => Number.isSafeInteger(d) && d !== 0 && d >= -31 && d <= 31)) return undefined;
    b.byMonthDay = o.byMonthDay;
  }
  if (o.bySetPos !== undefined && o.bySetPos !== null) {
    if (!Number.isSafeInteger(o.bySetPos) || o.bySetPos === 0 || o.bySetPos < -5 || o.bySetPos > 5) return undefined;
    b.bySetPos = o.bySetPos;
  }
  if (o.until !== undefined && o.until !== null) { if (!isDate(o.until)) return undefined; b.until = o.until; }
  if (o.count !== undefined && o.count !== null) { if (!intIn(o.count, 1, 9999)) return undefined; b.count = o.count; }
  if (b.until && b.count) return undefined;
  return b;
}

/**
 * Body of POST events / PATCH events/<id> → the body, or null when a field is invalid. A new event needs a calendar,
 * a title and its times; a change sends only what is given (with `scope`, `occurrence`, `etag`).
 */
function eventBody(v, { patch = false } = {}) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.calendarId !== undefined && o.calendarId !== null) { if (!posId(o.calendarId)) return null; b.calendarId = posId(o.calendarId); }
  if (o.title !== undefined) {
    const t = typeof o.title === 'string' ? o.title.replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : '';
    if (!t || t.length > TITLE_MAX) return null;
    b.title = t;
  }
  if (o.allDay !== undefined) { if (typeof o.allDay !== 'boolean') return null; b.allDay = o.allDay; }
  for (const k of ['start', 'end']) {
    if (o[k] === undefined || o[k] === null) continue;
    if (!Number.isSafeInteger(o[k]) || o[k] <= 0) return null;
    b[k] = o[k];
  }
  for (const k of ['startDate', 'endDate']) {
    if (o[k] === undefined || o[k] === null) continue;
    if (!isDate(o[k])) return null;
    b[k] = o[k];
  }
  if (b.start && b.end && b.end < b.start) return null;
  if (b.startDate && b.endDate && b.endDate < b.startDate) return null;
  if (o.timeZone !== undefined && o.timeZone !== null) { if (!tzOf(o.timeZone)) return null; b.timeZone = o.timeZone; }
  if (o.location !== undefined) {
    if (o.location !== null && (typeof o.location !== 'string' || o.location.length > 500)) return null;
    b.location = o.location === null ? null : o.location.replace(/[\u0000-\u001F\u007F]/g, ' ').trim();
  }
  if (o.description !== undefined) {
    if (typeof o.description !== 'string' || o.description.length > DESCRIPTION_MAX) return null;
    b.description = o.description.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  }
  if (o.online !== undefined) {
    if (o.online === null) b.online = null;
    else if (obj(o.online) && o.online.create === 'teams') b.online = { create: 'teams' };
    else if (obj(o.online) && webUrl(o.online.url)) b.online = { url: webUrl(o.online.url) };
    else return null;
  }
  if (o.reminders !== undefined) {
    if (!Array.isArray(o.reminders) || o.reminders.length > 3 || !o.reminders.every((x) => intIn(x, 0, 40320) !== null)) return null;
    b.reminders = [...new Set(o.reminders)];
  }
  if (o.recurrence !== undefined) {
    const r = recurrenceBody(o.recurrence);
    if (r === undefined) return null;
    b.recurrence = r;
  }
  if (o.attendees !== undefined) {
    if (!Array.isArray(o.attendees) || o.attendees.length > ATTENDEES_MAX) return null;
    const list = [];
    for (const a of o.attendees) {
      const x = obj(a);
      const email = x && emailOf(x.email);
      if (!email) return null;
      if (x.role !== undefined && x.role !== null && !ATTENDEE_ROLES.includes(x.role)) return null;
      if (list.some((y) => y.email.toLowerCase() === email.toLowerCase())) continue;
      const out = { email };
      if (line(x.name, 200)) out.name = line(x.name, 200);
      if (x.role) out.role = x.role;
      list.push(out);
    }
    b.attendees = list;
  }
  if (o.busy !== undefined) { if (!BUSY.includes(o.busy)) return null; b.busy = o.busy; }
  for (const k of ['private', 'sendInvites']) {
    if (o[k] === undefined) continue;
    if (typeof o[k] !== 'boolean') return null;
    b[k] = o[k];
  }
  if (o.fromAccountId !== undefined && o.fromAccountId !== null) { if (!posId(o.fromAccountId)) return null; b.fromAccountId = posId(o.fromAccountId); }
  if (patch) {
    if (o.scope !== undefined) { if (o.scope !== 'occurrence' && o.scope !== 'series') return null; b.scope = o.scope; }
    if (o.occurrence !== undefined && o.occurrence !== null) { if (!occOf(o.occurrence)) return null; b.occurrence = o.occurrence; }
    if (b.scope === 'occurrence' && !b.occurrence) return null;
    if (o.etag !== undefined && o.etag !== null) { if (typeof o.etag !== 'string' || !ETAG_RE.test(o.etag)) return null; b.etag = o.etag; }
    const fields = Object.keys(b).filter((k) => !['scope', 'occurrence', 'etag', 'sendInvites'].includes(k));
    return fields.length ? b : null;
  }
  if (!b.calendarId || !b.title || typeof b.allDay !== 'boolean') return null;
  if (b.allDay ? !b.startDate : !(b.start && b.end)) return null;
  return b;
}

/** Query of DELETE events/<id> → params, or null. */
function deleteEventQuery(v) {
  const o = obj(v) || {};
  const p = { scope: o.scope === 'occurrence' ? 'occurrence' : 'series' };
  if (p.scope === 'occurrence') {
    if (!occOf(o.occurrence)) return null;
    p.occurrence = o.occurrence;
  }
  if (o.notify === true) p.notify = 1;
  if (o.comment !== undefined && o.comment !== null && o.comment !== '') {
    const c = line(o.comment, 1000);
    if (!c) return null;
    p.comment = c;
  }
  return p;
}

/** Body of POST events/<id>/respond and invitations/<id>/respond → the body, or null. */
function respondBody(v, { invitation = false } = {}) {
  const o = obj(v);
  if (!o || !ANSWERS.includes(o.response)) return null;
  const b = { response: o.response };
  if (o.comment !== undefined && o.comment !== null && o.comment !== '') {
    if (typeof o.comment !== 'string' || o.comment.length > 2000) return null;
    b.comment = o.comment.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
  }
  if (o.proposeStart !== undefined || o.proposeEnd !== undefined) {
    if (!Number.isSafeInteger(o.proposeStart) || !Number.isSafeInteger(o.proposeEnd) || o.proposeStart <= 0 || o.proposeEnd <= o.proposeStart) return null;
    b.proposeStart = o.proposeStart;
    b.proposeEnd = o.proposeEnd;
  }
  if (invitation) {
    if (o.calendarId !== undefined && o.calendarId !== null) { if (!posId(o.calendarId)) return null; b.calendarId = posId(o.calendarId); }
  } else {
    if (o.occurrence !== undefined && o.occurrence !== null) { if (!occOf(o.occurrence)) return null; b.occurrence = o.occurrence; }
    if (o.send !== undefined) { if (typeof o.send !== 'boolean') return null; b.send = o.send; }
  }
  return b;
}

/** PATCH calendars/<id> → the patch, or null. */
function calendarPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.name !== undefined) { const n = line(o.name, 80); if (!n) return null; b.name = n; }
  if (o.color !== undefined) { if (!colorOf(o.color)) return null; b.color = colorOf(o.color); }
  for (const k of ['visible', 'notify']) {
    if (o[k] === undefined) continue;
    if (typeof o[k] !== 'boolean') return null;
    b[k] = o[k];
  }
  return Object.keys(b).length ? b : null;
}

/** PATCH overlays/<id> → the patch, or null. */
function overlayPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.visible !== undefined) { if (typeof o.visible !== 'boolean') return null; b.visible = o.visible; }
  if (o.color !== undefined) { if (!colorOf(o.color)) return null; b.color = colorOf(o.color); }
  return Object.keys(b).length ? b : null;
}

/** PUT calendar/settings → the patch, or null. */
function calSettingsPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.defaultCalendarId !== undefined) { if (!posId(o.defaultCalendarId)) return null; b.defaultCalendarId = posId(o.defaultCalendarId); }
  if (o.view !== undefined) { if (!VIEWS.includes(o.view)) return null; b.view = o.view; }
  if (o.weekStart !== undefined) { if (o.weekStart !== 0 && o.weekStart !== 1) return null; b.weekStart = o.weekStart; }
  for (const k of ['workWeek', 'reminders']) {
    if (o[k] === undefined) continue;
    if (typeof o[k] !== 'boolean') return null;
    b[k] = o[k];
  }
  if (o.timeZone !== undefined) { if (!tzOf(o.timeZone)) return null; b.timeZone = o.timeZone; }
  if (o.defaultReminder !== undefined) { if (o.defaultReminder !== null && intIn(o.defaultReminder, 0, 40320) === null) return null; b.defaultReminder = o.defaultReminder; }
  if (o.allDayReminder !== undefined) { if (intIn(o.allDayReminder, 0, 10080) === null) return null; b.allDayReminder = o.allDayReminder; }
  return Object.keys(b).length ? b : null;
}

/** POST calendars/subscribe → the body (webcal: → https:), or null. */
function subscribeBody(v) {
  const o = obj(v);
  if (!o || typeof o.url !== 'string') return null;
  const raw = o.url.trim().replace(/^webcal:\/\//i, 'https://');
  const url = m.httpsUrl(raw);
  if (!url) return null;
  const b = { url };
  if (o.name !== undefined && o.name !== null && o.name !== '') { const n = line(o.name, 80); if (!n) return null; b.name = n; }
  if (o.color !== undefined && o.color !== null) { if (!colorOf(o.color)) return null; b.color = colorOf(o.color); }
  if (o.accountId !== undefined && o.accountId !== null) { if (!posId(o.accountId)) return null; b.accountId = posId(o.accountId); }
  return b;
}

// ── Contacts ───────────────────────────────────────────────

function normalizeAddressbook(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id,
    source: oneOf(BOOK_SOURCES, o.source, 'local'),
    accountId: posId(o.accountId),
    name: line(o.name, 120) || 'Kontakte',
    writable: bool(o.writable),
    visible: o.visible !== false,
    isDefault: bool(o.isDefault),
    count: count(o.count) || 0,
    state: oneOf(SYNC_STATES, o.state, 'ok'),
    error: syncError(o.error),
    syncedAt: msOf(o.syncedAt),
  };
}

function normalizeGroup(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return { id, name: line(o.name, 120) || '', color: colorOf(o.color), count: count(o.count) || 0 };
}

function normalizeCardPrefs(v) {
  const o = obj(v) || {};
  return {
    sort: oneOf(CARD_SORTS, o.sort, 'family'),
    show: oneOf(CARD_SHOWS, o.show, 'given_family'),
    defaultAddressbookId: posId(o.defaultAddressbookId),
    birthdays: o.birthdays !== false,
  };
}

/** GET addressbooks → { items, groups, prefs }. */
function normalizeAddressbooks(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map(normalizeAddressbook).filter(Boolean).slice(0, 100),
    groups: arr(o.groups).map(normalizeGroup).filter(Boolean).slice(0, 200),
    prefs: normalizeCardPrefs(o.prefs),
  };
}

const letterOf = (v) => (typeof v === 'string' && /^[A-Z#]$/.test(v) ? v : '#');

/** A `CardSummary` of a list, or null. */
function normalizeCardSummary(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const name = line(o.name, 200);
  const emails = arr(o.emails).map(emailOf).filter(Boolean).slice(0, 3);
  return {
    id,
    addressbookId: posId(o.addressbookId),
    name: name || emails[0] || '',
    sortKey: line(o.sortKey, 200) || '',
    letter: letterOf(o.letter),
    company: line(o.company, 200),
    title: line(o.title, 200),
    emails,
    phone: line(o.phone, 60),
    photo: bool(o.photo),
    photoEtag: line(o.photoEtag, 120),
    groups: ids(o.groups, 200),
    linked: ids(o.linked, 20),
    gcUserId: posId(o.gcUserId),
    updatedAt: msOf(o.updatedAt),
  };
}

/** GET cards → { items, next, version, deleted }. */
function normalizeCardList(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map(normalizeCardSummary).filter(Boolean).slice(0, 1000),
    next: cursorOf(o.next),
    version: count(o.version) || 0,
    deleted: ids(o.deleted, 5000),
  };
}

function nameOf(v) {
  const o = obj(v) || {};
  const out = { display: line(o.display, 200) || '', given: line(o.given, 120) || '', family: line(o.family, 120) || '' };
  for (const k of ['middle', 'prefix', 'suffix', 'nickname']) out[k] = line(o[k], 120);
  return out;
}

function addressOf(v) {
  const o = obj(v);
  if (!o) return null;
  const a = { type: oneOf(ADDRESS_TYPES, o.type, 'home') };
  for (const k of ['street', 'postalCode', 'city', 'region', 'country']) a[k] = line(o[k], k === 'street' ? 300 : 120) || '';
  return a.street || a.postalCode || a.city || a.region || a.country ? a : null;
}

/** The editable fields of a contact (Card without id / etag; also a draft of "Als Kontakt speichern"). */
function cardFields(o) {
  const photo = obj(o.photo);
  return {
    name: nameOf(o.name),
    emails: arr(o.emails).map((x) => {
      const e = obj(x);
      const value = e && emailOf(e.value);
      return value ? { value, type: oneOf(EMAIL_TYPES, e.type, 'other'), primary: bool(e.primary) } : null;
    }).filter(Boolean).slice(0, 20),
    phones: arr(o.phones).map((x) => {
      const p = obj(x);
      const value = p && line(p.value, 60);
      return value ? { value, type: oneOf(PHONE_TYPES, p.type, 'other') } : null;
    }).filter(Boolean).slice(0, 20),
    company: line(o.company, 200),
    department: line(o.department, 200),
    title: line(o.title, 200),
    addresses: arr(o.addresses).map(addressOf).filter(Boolean).slice(0, 10),
    birthday: typeof o.birthday === 'string' && BIRTHDAY_RE.test(o.birthday) ? o.birthday : null,
    note: text(o.note, NOTE_MAX) || '',
    urls: arr(o.urls).map(webUrl).filter(Boolean).slice(0, 10),
    photo: photo && line(photo.etag, 120) ? { etag: line(photo.etag, 120), mime: oneOf(PHOTO_MIMES, photo.mime, 'image/jpeg') } : null,
    groups: ids(o.groups, 200),
  };
}

/** GET cards/<id> → `Card`, or null. */
function normalizeCard(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  return {
    id,
    addressbookId: posId(o.addressbookId),
    source: oneOf(BOOK_SOURCES, o.source, 'local'),
    readOnly: bool(o.readOnly),
    etag: typeof o.etag === 'string' && ETAG_RE.test(o.etag) ? o.etag : null,
    ...cardFields(o),
    linked: arr(o.linked).map((x) => {
      const l = obj(x);
      const lid = l && posId(l.id);
      return lid ? { id: lid, addressbookId: posId(l.addressbookId), source: oneOf(BOOK_SOURCES, l.source, 'local') } : null;
    }).filter(Boolean).slice(0, 20),
    gcUserId: posId(o.gcUserId),
    updatedAt: msOf(o.updatedAt),
  };
}

/** { card } of POST / PATCH cards (or the card itself) → Card, or null. */
const cardOf = (v) => normalizeCard(obj(v) && obj(v.card) ? v.card : v);

/** GET cards/lookup → { card, person, recent }. */
function normalizeLookup(v) {
  const o = obj(v) || {};
  const p = obj(o.person);
  const r = obj(o.recent);
  return {
    card: o.card ? normalizeCard(o.card) : null,
    person: p && posId(p.userId) ? { userId: posId(p.userId), name: line(p.name, 200) || '' } : null,
    recent: r ? { name: line(r.name, 200) || '', sent: count(r.sent) || 0, received: count(r.received) || 0, lastAt: msOf(r.lastAt) } : null,
  };
}

/** GET cards/<id>/activity → { mails: [Summary], events: [Occurrence] }. */
function normalizeActivity(v) {
  const o = obj(v) || {};
  return {
    mails: arr(o.mails).map(m.normalizeSummary).filter(Boolean).slice(0, 5),
    events: arr(o.events).map(normalizeOccurrence).filter(Boolean).slice(0, 10),
  };
}

/** GET cards/draft → { draft: Card fields, existing: Card | null }. */
function normalizeCardDraft(v) {
  const o = obj(v) || {};
  return { draft: cardFields(obj(o.draft) || {}), existing: o.existing ? normalizeCard(o.existing) : null };
}

/** GET cards/duplicates → { items: [{ key, reason, cards }] }. */
function normalizeDuplicates(v) {
  return {
    items: arr(obj(v) && v.items).map((x) => {
      const o = obj(x);
      const cards = o ? arr(o.cards).map(normalizeCardSummary).filter(Boolean).slice(0, 10) : [];
      if (cards.length < 2) return null;
      return { key: typeof o.key === 'string' && KEY_RE.test(o.key) ? o.key : cards.map((c) => c.id).join('-'), reason: oneOf(DUP_REASONS, o.reason, 'name'), cards };
    }).filter(Boolean).slice(0, 500),
  };
}

/** GET groups/<id> (and POST groups/<id>/members) → { group, members: [{ id, contactId, name, email }] }. */
function normalizeGroupDetail(v) {
  const o = obj(v) || {};
  return {
    group: normalizeGroup(o.group),
    members: arr(o.members).map((x) => {
      const g = obj(x);
      const id = g && posId(g.id);
      if (!id) return null;
      return { id, contactId: posId(g.contactId), name: line(g.name, 200) || '', email: emailOf(g.email) };
    }).filter(Boolean).slice(0, 500),
  };
}

/** GET cards/<id>/photo → { mime, data (base64) } of a JPEG / PNG ≤ 256 KB, or null. */
function normalizeCardPhoto(v) {
  const o = obj(v);
  const mime = o && typeof o.mime === 'string' ? o.mime.split(';')[0].trim().toLowerCase() : '';
  if (!PHOTO_MIMES.includes(mime) || typeof o.data !== 'string' || !o.data || o.data.length > Math.ceil(PHOTO_MAX_BYTES / 3) * 4 + 8 || !/^[A-Za-z0-9+/=\s]+$/.test(o.data)) return null;
  return { mime, data: o.data.replace(/\s+/g, '') };
}

/** GET cards/export → { name, mime, data (base64 of the vCard file) }, or null. */
function normalizeExport(v) {
  const o = obj(v);
  if (!o || typeof o.data !== 'string' || !/^[A-Za-z0-9+/=\s]*$/.test(o.data)) return null;
  const n = line(o.name, 120);
  return { name: n && /\.vcf$/i.test(n) ? n.replace(/[\\/:*?"<>|]/g, '_') : 'kontakte.vcf', mime: 'text/vcard', data: o.data.replace(/\s+/g, '') };
}

// ── Contact requests ───────────────────────────────────────

/** GET cards → params, or null. */
function cardsQuery(q) {
  const o = obj(q) || {};
  const p = {};
  if (o.q !== undefined && o.q !== null && o.q !== '') {
    const s = line(o.q, 100);
    if (!s) return null;
    p.q = s;
  }
  if (o.book !== undefined && o.book !== null) {
    if (o.book !== 'all' && !posId(o.book)) return null;
    p.book = o.book === 'all' ? 'all' : posId(o.book);
  }
  if (o.group !== undefined && o.group !== null) { if (!posId(o.group)) return null; p.group = posId(o.group); }
  if (o.cursor !== undefined && o.cursor !== null) { if (!cursorOf(o.cursor)) return null; p.cursor = o.cursor; }
  if (o.since !== undefined && o.since !== null) { if (count(o.since) === null) return null; p.since = count(o.since); }
  const limit = o.limit === undefined || o.limit === null ? 200 : posId(o.limit);
  if (!limit || limit > 1000) return null;
  p.limit = limit;
  return p;
}

/** The fields of a contact for POST cards / PATCH cards/<id> → the body, or null when one is invalid. */
function cardBody(v, { patch = false } = {}) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.addressbookId !== undefined && o.addressbookId !== null && !patch) { if (!posId(o.addressbookId)) return null; b.addressbookId = posId(o.addressbookId); }
  if (o.name !== undefined) {
    const n = obj(o.name);
    if (!n) return null;
    const out = {};
    for (const k of ['display', 'given', 'family', 'middle', 'prefix', 'suffix', 'nickname']) {
      if (n[k] === undefined || n[k] === null || n[k] === '') continue;
      if (typeof n[k] !== 'string' || n[k].length > 200) return null;
      out[k] = n[k].replace(/[\u0000-\u001F\u007F]/g, ' ').trim();
    }
    b.name = out;
  }
  if (o.emails !== undefined) {
    if (!Array.isArray(o.emails) || o.emails.length > 20) return null;
    const list = [];
    for (const x of o.emails) {
      const e = obj(x);
      const value = e && emailOf(e.value);
      if (!value || (e.type !== undefined && !EMAIL_TYPES.includes(e.type))) return null;
      if (!list.some((y) => y.value.toLowerCase() === value.toLowerCase())) list.push({ value, type: e.type || 'other', primary: e.primary === true });
    }
    b.emails = list;
  }
  if (o.phones !== undefined) {
    if (!Array.isArray(o.phones) || o.phones.length > 20) return null;
    const list = [];
    for (const x of o.phones) {
      const p = obj(x);
      const value = p && typeof p.value === 'string' ? p.value.replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : '';
      if (!value || value.length > 60 || !/\d/.test(value) || (p.type !== undefined && !PHONE_TYPES.includes(p.type))) return null;
      list.push({ value, type: p.type || 'other' });
    }
    b.phones = list;
  }
  for (const k of ['company', 'department', 'title']) {
    if (o[k] === undefined) continue;
    if (o[k] !== null && (typeof o[k] !== 'string' || o[k].length > 200)) return null;
    b[k] = o[k] === null ? null : (o[k].replace(/[\u0000-\u001F\u007F]/g, ' ').trim() || null);
  }
  if (o.addresses !== undefined) {
    if (!Array.isArray(o.addresses) || o.addresses.length > 10) return null;
    const list = [];
    for (const x of o.addresses) {
      const a = obj(x);
      if (!a || (a.type !== undefined && !ADDRESS_TYPES.includes(a.type))) return null;
      const out = { type: a.type || 'home' };
      for (const k of ['street', 'postalCode', 'city', 'region', 'country']) {
        if (a[k] !== undefined && a[k] !== null && (typeof a[k] !== 'string' || a[k].length > 300)) return null;
        out[k] = typeof a[k] === 'string' ? a[k].replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : '';
      }
      if (out.street || out.postalCode || out.city || out.region || out.country) list.push(out);
    }
    b.addresses = list;
  }
  if (o.birthday !== undefined) {
    if (o.birthday !== null && (typeof o.birthday !== 'string' || !BIRTHDAY_RE.test(o.birthday))) return null;
    b.birthday = o.birthday;
  }
  if (o.note !== undefined) {
    if (typeof o.note !== 'string' || o.note.length > NOTE_MAX) return null;
    b.note = o.note.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  }
  if (o.urls !== undefined) {
    if (!Array.isArray(o.urls) || o.urls.length > 10 || !o.urls.every((u) => webUrl(u))) return null;
    b.urls = o.urls.map(webUrl);
  }
  if (o.groups !== undefined) {
    if (!Array.isArray(o.groups) || o.groups.length > 200 || !o.groups.every((g) => posId(g))) return null;
    b.groups = [...new Set(o.groups.map(posId))];
  }
  if (patch && o.etag !== undefined && o.etag !== null) { if (typeof o.etag !== 'string' || !ETAG_RE.test(o.etag)) return null; b.etag = o.etag; }
  const fields = Object.keys(b).filter((k) => k !== 'etag' && k !== 'addressbookId');
  if (!fields.length) return null;
  if (!patch) {
    const n = b.name || {};
    if (!n.display && !n.given && !n.family && !b.company && !(b.emails && b.emails.length) && !(b.phones && b.phones.length)) return null;
  }
  return b;
}

/** PUT cards/settings → the patch, or null. */
function cardPrefsPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.sort !== undefined) { if (!CARD_SORTS.includes(o.sort)) return null; b.sort = o.sort; }
  if (o.show !== undefined) { if (!CARD_SHOWS.includes(o.show)) return null; b.show = o.show; }
  if (o.defaultAddressbookId !== undefined) { if (!posId(o.defaultAddressbookId)) return null; b.defaultAddressbookId = posId(o.defaultAddressbookId); }
  if (o.birthdays !== undefined) { if (typeof o.birthdays !== 'boolean') return null; b.birthdays = o.birthdays; }
  return Object.keys(b).length ? b : null;
}

/** POST cards/merge → the body, or null. */
function mergeBody(v) {
  const o = obj(v);
  const list = o && Array.isArray(o.ids) ? ids(o.ids, 10) : [];
  if (list.length < 2 || list.length !== o.ids.length || !list.includes(posId(o.primaryId))) return null;
  const b = { ids: list, primaryId: posId(o.primaryId) };
  if (o.pick !== undefined && o.pick !== null) {
    const p = obj(o.pick);
    if (!p) return null;
    const pick = {};
    for (const k of ['name', 'company', 'title', 'birthday', 'photo']) {
      if (p[k] === undefined || p[k] === null) continue;
      if (!list.includes(posId(p[k]))) return null;
      pick[k] = posId(p[k]);
    }
    if (p.note === 'join') pick.note = 'join';
    else if (p.note !== undefined && p.note !== null) return null;
    if (Object.keys(pick).length) b.pick = pick;
  }
  return b;
}

/** POST groups / PATCH groups/<id> → the body, or null. */
function groupBody(v, { patch = false } = {}) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.name !== undefined) { const n = line(o.name, 80); if (!n) return null; b.name = n; }
  if (o.color !== undefined && o.color !== null) { if (!colorOf(o.color)) return null; b.color = colorOf(o.color); }
  if (!patch && !b.name) return null;
  return Object.keys(b).length ? b : null;
}

/** POST groups/<id>/members → { add, remove }, or null. */
function membersBody(v) {
  const o = obj(v);
  if (!o) return null;
  const add = [];
  for (const x of arr(o.add).slice(0, 500)) {
    const a = obj(x);
    if (a && posId(a.contactId)) add.push({ contactId: posId(a.contactId) });
    else if (a && emailOf(a.email)) add.push(line(a.name, 200) ? { email: emailOf(a.email), name: line(a.name, 200) } : { email: emailOf(a.email) });
    else return null;
  }
  const remove = ids(o.remove, 500);
  if ((o.remove !== undefined && remove.length !== arr(o.remove).length) || (!add.length && !remove.length)) return null;
  return { add, remove };
}

// ── Live events ────────────────────────────────────────────

/** The live event `calendar` → { kind: 'changed', calendarId, accountId, from, to } | { kind: 'calendars' } | { kind: 'invitation', invitationId, messageId } | { kind: 'conflict', eventId } | null. */
function normalizeCalendarLive(v) {
  const o = obj(v) || {};
  if (o.kind === 'changed') return { kind: 'changed', calendarId: posId(o.calendarId), accountId: posId(o.accountId), from: msOf(o.from), to: msOf(o.to) };
  if (o.kind === 'calendars') return { kind: 'calendars' };
  if (o.kind === 'invitation') return { kind: 'invitation', invitationId: posId(o.invitationId), messageId: posId(o.messageId) };
  if (o.kind === 'conflict') return { kind: 'conflict', eventId: posId(o.eventId) };
  return null;
}

/** The live event `contacts` → { kind: 'changed', addressbookId, contactIds } | { kind: 'addressbooks' } | { kind: 'groups' } | null. */
function normalizeContactsLive(v) {
  const o = obj(v) || {};
  if (o.kind === 'changed') return { kind: 'changed', addressbookId: posId(o.addressbookId), contactIds: ids(o.contactIds, 50) };
  if (o.kind === 'addressbooks') return { kind: 'addressbooks' };
  if (o.kind === 'groups') return { kind: 'groups' };
  return null;
}

// ── Offline (contacts searched on this PC) ─────────────────

/** Folded for searching: lower case, umlauts as their base letters (Ä → a, ß → ss). */
function fold(s) {
  return String(s || '').toLowerCase().replace(/ß/g, 'ss').normalize('NFD').replace(/[̀-ͯ]/g, '');
}

/**
 * The cached CardSummaries filtered like GET cards: `q` in name, company, addresses, the number (digits), `book` an
 * address book (or 'all': linked ones only under their primary), `group` a group; sorted by sortKey.
 */
function filterCards(items, { q = '', book = 'all', group = null } = {}) {
  const words = fold(q).trim();
  const digits = String(q || '').replace(/\D/g, '');
  const bookId = book && book !== 'all' ? posId(book) : null;
  const groupId = posId(group);
  const linkedAway = new Set();
  if (!bookId) for (const c of items) for (const l of c.linked || []) linkedAway.add(l);
  return items.filter((c) => {
    if (bookId && c.addressbookId !== bookId) return false;
    if (!bookId && linkedAway.has(c.id)) return false;
    if (groupId && !(c.groups || []).includes(groupId)) return false;
    if (!words) return true;
    const hay = fold([c.name, c.company, c.title, ...(c.emails || [])].filter(Boolean).join(' '));
    if (hay.includes(words)) return true;
    return digits.length >= 3 && String(c.phone || '').replace(/\D/g, '').includes(digits);
  }).sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : a.id - b.id));
}

module.exports = {
  CAL_SOURCES,
  CAL_KINDS,
  VIEWS,
  EVENT_STATUS,
  BUSY,
  RESPONSES,
  ANSWERS,
  FREQS,
  WEEKDAYS,
  BOOK_SOURCES,
  EMAIL_TYPES,
  PHONE_TYPES,
  ADDRESS_TYPES,
  PHOTO_MIMES,
  RANGE_MAX_MS,
  PHOTO_MAX_BYTES,
  VCF_MAX_BYTES,
  isDate,
  occOf,
  normalizeCalendar,
  normalizeOverlay,
  normalizeCalPrefs,
  normalizeCalendars,
  normalizeOccurrence,
  normalizeOverlayItem,
  normalizeEvents,
  normalizeAttendee,
  normalizeRecurrence,
  normalizeEvent,
  normalizeSaved,
  normalizeInvitation,
  normalizeInvitations,
  normalizeInviteResult,
  eventsQuery,
  eventsKey,
  eventBody,
  deleteEventQuery,
  respondBody,
  calendarPatch,
  overlayPatch,
  calSettingsPatch,
  subscribeBody,
  normalizeAddressbook,
  normalizeGroup,
  normalizeCardPrefs,
  normalizeAddressbooks,
  normalizeCardSummary,
  normalizeCardList,
  normalizeCard,
  cardOf,
  normalizeLookup,
  normalizeActivity,
  normalizeCardDraft,
  normalizeDuplicates,
  normalizeGroupDetail,
  normalizeCardPhoto,
  normalizeExport,
  cardsQuery,
  cardBody,
  cardPrefsPatch,
  mergeBody,
  groupBody,
  membersBody,
  normalizeCalendarLive,
  normalizeContactsLive,
  fold,
  filterCards,
};

// mail.js exports these as well (whichever of the two is loaded first)
Object.assign(m, module.exports);
