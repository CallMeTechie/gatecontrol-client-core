'use strict';

/**
 * Notizen & Aufgaben — „Termin“ in the quick entry (plugin gatecontrol-notizen 1.9.0, feature `calendarEvents`). Pure:
 * no network, no clock. The event is stored in a calendar of Mail only; the hub hands it over and keeps no copy.
 *
 * - The calendars of the person (GET events/calendars) cleaned, why no event can be made (`reason`), which reason
 *   passes by itself (`unreachable`) and which does not (Mail missing, the calendar off, nothing to write into).
 * - What the renderer may send for POST events / PATCH events/<id> (`eventCreate`, `eventPatch`) and the answer.
 * - The queue (contract § 7): a waiting POST events carries its finished body and a `clientId` made on this PC. The
 *   server makes exactly one event per clientId, but the key lives as long as the event — so an entry leaves the queue
 *   after the first 200 (also `replayed`) and is never sent again „to be sure“; a changed body gets a new clientId.
 *   `refused()` says what becomes of a waiting event the server refused (the same rules as the Android app): it stays
 *   while Mail does not answer, it goes once more without its calendar when that is gone, it becomes a task with its
 *   day and time when no event can be made for good, it is dropped on anything else (400).
 * - A waiting event as a row of „Mein Tag“ („wartet auf Verbindung“): `pendingItem`, `overlay`.
 */

const N = require('./notes');

const QUEUE_MAX = 200;
const TITLE_MAX = 255;
const LOCATION_MAX = 255;
const REMINDER_MAX = 40320;
const SPAN_DAYS = 7;
const SOON_DAYS = 14;
const CLIENT_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const COLOR_RE = /^#[0-9A-Fa-f]{6}$/;
const KEY_RE = /^[A-Za-z0-9:._-]{1,80}$/;
const CODE_RE = /^[A-Za-z0-9_.-]{1,60}$/;
const MAIL = 'gatecontrol-mail';

/** Reasons that do not pass by themselves: no event is queued, „Als Aufgabe mit Datum speichern“ is offered. */
const PERMANENT = Object.freeze(['no_mail', 'mail_old', 'feature_off', 'not_allowed', 'not_licensed', 'no_seat', 'no_calendar']);

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const arr = (v) => (Array.isArray(v) ? v : []);
const bool = (v) => v === true;
const mins = (v) => (Number.isSafeInteger(v) && v >= 0 && v <= REMINDER_MAX ? v : null);

function permanent(reason) {
  return PERMANENT.includes(reason);
}

/**
 * The text of the card „Kein Kalender“ (Bild 9) for a reason: 'mail' (Mail missing or too old), 'off' (the calendar is
 * off for the person), 'none' (no calendar to write into), 'unreachable' (Mail does not answer; also every other reason).
 */
function why(reason) {
  if (reason === 'no_mail' || reason === 'mail_old') return 'mail';
  if (['feature_off', 'not_allowed', 'not_licensed', 'no_seat'].includes(reason)) return 'off';
  if (reason === 'no_calendar') return 'none';
  return 'unreachable';
}

/** A calendar of GET events/calendars → cleaned, or null. */
function calendarOf(v) {
  const o = obj(v);
  const key = o && typeof o.key === 'string' && KEY_RE.test(o.key) ? o.key : null;
  if (!key) return null;
  const id = N.posId(o.id);
  const writable = bool(o.writable);
  return {
    id, key, name: N.line(o.name, 80) || '', color: typeof o.color === 'string' && COLOR_RE.test(o.color) ? o.color : null,
    kind: N.CALENDAR_KINDS.includes(o.kind) ? o.kind : 'own', writable,
    // „Aufgaben“ is never a target, nor a calendar without a number
    target: bool(o.target) && writable && !!id && o.kind !== 'tasks', isDefault: bool(o.isDefault), area: o.area === 'work' ? 'work' : 'private',
    shown: bool(o.shown),
  };
}

/**
 * GET events/calendars → { state: 'ok' | 'none', reason, calendars, targets (the ids a new event may go into), defaultId,
 * reminders: { timed, allDay }, timeZone }. `reminders.allDay`: minutes before the midnight of the day (360: the day
 * before at 18:00). A state 'ok' without a target reads as 'none' / no_calendar.
 */
function normalizeCalendars(v) {
  const o = obj(v) || {};
  const calendars = arr(o.calendars).slice(0, 100).map(calendarOf).filter(Boolean);
  const targets = calendars.filter((c) => c.target).map((c) => c.id);
  let state = o.state === 'ok' ? 'ok' : 'none';
  let reason = state === 'ok' ? null : (typeof o.reason === 'string' && CODE_RE.test(o.reason) ? o.reason : 'no_calendar');
  if (state === 'ok' && !targets.length) { state = 'none'; reason = 'no_calendar'; }
  const def = N.posId(o.defaultId);
  const defaultId = def && targets.includes(def) ? def : (calendars.find((c) => c.target && c.isDefault) || {}).id || targets[0] || null;
  for (const c of calendars) c.isDefault = c.id !== null && c.id === defaultId;
  const rem = obj(o.reminders) || {};
  return {
    state, reason, calendars, targets, defaultId, reminders: { timed: mins(rem.timed), allDay: mins(rem.allDay) },
    timeZone: N.line(o.timeZone, 60),
  };
}

/** Why the person cannot make an event right now — `calendars` is the newer word when it is there, else `me.events`. */
function reasonOf(me, calendars) {
  if (calendars) return calendars.state === 'ok' ? null : calendars.reason || 'no_calendar';
  const ev = me && me.events;
  if (ev && ev.available === false) return ev.reason || 'no_calendar';
  return null;
}

/** A reason that does not pass (null: an event can be made, or it will wait in the queue). */
function blocked(me, calendars) {
  const r = reasonOf(me, calendars);
  return r && permanent(r) ? r : null;
}

/** The reminder a chip shows without a choice: the calendar's for a timed or an all-day event (null: none). */
function defaultReminder(calendars, allDay) {
  const r = calendars && calendars.reminders;
  return r ? (allDay ? r.allDay : r.timed) : null;
}

/** An hour after 'HH:MM' (past midnight it wraps — the next day). */
function plusHour(time) {
  const h = (Number(time.slice(0, 2)) + 1) % 24;
  return `${String(h).padStart(2, '0')}:${time.slice(3, 5)}`;
}

function repeatArg(v) {
  const r = N.repeatOf(v);
  return r && r.type !== 'after' ? r : null;
}

/**
 * The fields of POST events / PATCH events/<id> the renderer may send → the body, or null when one is wrong.
 * `creating`: title and date are needed, calendarId may come; for a change `location: null` takes the place off and
 * `repeat: null` ends the series. `reminder`: minutes before (all day: before the midnight of the day) or false —
 * left out (the person chose nothing) the calendar's default applies at the time of sending.
 */
function eventFields(p, creating) {
  const o = obj(p);
  if (!o) return null;
  const b = {};
  const has = (k) => o[k] !== undefined;
  if (creating || has('title')) {
    const t = N.line(o.title, TITLE_MAX + 1);
    if (!t || t.length > TITLE_MAX) return null;
    b.title = t;
  }
  const timeGiven = creating || ['date', 'time', 'endTime', 'endDate', 'allDay'].some(has);
  if (timeGiven) {
    const date = N.dateOf(o.date);
    if (!date) return null;
    b.date = date;
    if (o.allDay != null && typeof o.allDay !== 'boolean') return null;
    const time = o.time == null || o.time === '' ? null : N.timeOf(o.time);
    if (o.time != null && o.time !== '' && !time) return null;
    const endTime = o.endTime == null || o.endTime === '' ? null : N.timeOf(o.endTime);
    if (o.endTime != null && o.endTime !== '' && !endTime) return null;
    if (o.allDay === true && (time || endTime)) return null;
    if (o.allDay === false && !time) return null;
    if (!time && endTime) return null;
    if (time) { b.time = time; if (endTime) b.endTime = endTime; }
    if (o.allDay === true) b.allDay = true;
    if (o.endDate != null) {
      const end = N.dateOf(o.endDate);
      if (!end || end < date || (Date.parse(`${end}T00:00:00Z`) - Date.parse(`${date}T00:00:00Z`)) / 86400000 > SPAN_DAYS) return null;
      if (end !== date) b.endDate = end;
    }
  }
  if (has('location')) {
    if (o.location === null || o.location === '') { if (!creating) b.location = null; } else {
      const loc = N.line(o.location, LOCATION_MAX + 1);
      if (!loc || loc.length > LOCATION_MAX) return null;
      b.location = loc;
    }
  }
  if (creating && o.calendarId != null) {
    if (!N.posId(o.calendarId)) return null;
    b.calendarId = o.calendarId;
  }
  if (has('reminder') && o.reminder !== null) {
    if (o.reminder !== false && mins(o.reminder) === null) return null;
    b.reminder = o.reminder;
  }
  if (has('repeat')) {
    if (o.repeat === null) { if (!creating) b.repeat = null; } else {
      const r = repeatArg(o.repeat);
      if (!r) return null;
      b.repeat = r;
    }
  }
  return b;
}

const eventCreate = (p) => eventFields(p, true);
const eventPatch = (p) => eventFields(p, false);

/** The answer of POST / PATCH events → { event: { id, calendarId }, items, clientId, replayed }. */
function normalizeCreated(v) {
  const o = obj(v) || {};
  const ev = obj(o.event) || {};
  return {
    event: { id: N.posId(ev.id), calendarId: N.posId(ev.calendarId) },
    items: arr(o.items).slice(0, 100).map(N.normalizeItem).filter(Boolean),
    clientId: typeof o.clientId === 'string' && CLIENT_ID_RE.test(o.clientId) ? o.clientId : null,
    replayed: bool(o.replayed),
  };
}

const clientIdOf = (v) => (typeof v === 'string' && CLIENT_ID_RE.test(v) ? v : null);

/**
 * A waiting event that can never be made (Mail gone, the calendar off) → POST tasks with its title, day, time and a
 * reminder at the start; the place goes into the note. Nothing the person typed is lost.
 */
function asTask(body, clientId = null) {
  const b = obj(body) || {};
  const out = { title: N.line(b.title, N.TITLE_MAX) || '…' };
  const date = N.dateOf(b.date);
  const time = N.timeOf(b.time);
  if (date) {
    out.due = { date, time: time || null };
    if (time) out.remindAt = { date, time };
  }
  const loc = N.line(b.location, LOCATION_MAX);
  if (loc) out.note = loc;
  const r = repeatArg(b.repeat);
  if (r) out.repeat = r;
  if (clientId) out.clientId = clientId;
  return out;
}

/**
 * A waiting entry the server refused (contract § 6) → what becomes of it: 'keep' (Mail does not answer: it stays and
 * goes later), { op } (the entry to put in its place: the same without `calendarId` and with a new clientId when the
 * calendar is gone; a task with its day and time when no event can be made for good) or 'drop' (400 and anything else).
 * `status` null: no answer at all (no network, a time-out) — 'keep'.
 */
function refused(op, err, newClientId) {
  const status = err && err.status;
  const body = (err && err.body) || {};
  const reason = typeof body.reason === 'string' ? body.reason : null;
  if (!status || status === 401 || status === 408 || status === 429 || (status >= 500 && status !== 503)) return 'keep';
  if (op.what !== 'event') return status === 503 ? 'keep' : 'drop';
  if (status === 503 && !permanent(reason)) return 'keep';
  if (status === 404 && body.field === 'calendarId' && op.body.calendarId != null) {
    const cid = newClientId();
    const b = { ...op.body, clientId: cid };
    delete b.calendarId;
    return { op: { ...op, clientId: cid, body: b } };
  }
  if (status === 503) {
    const cid = newClientId();
    return { op: { ...op, what: 'task', clientId: cid, body: asTask(op.body, cid), reason } };
  }
  return 'drop';
}

/** An entry of the queue as stored → { what: 'event' | 'task', clientId, body, at } or null. */
function queueOp(v) {
  const o = obj(v);
  if (!o || (o.what !== 'event' && o.what !== 'task')) return null;
  const clientId = clientIdOf(o.clientId);
  const b = obj(o.body);
  if (!clientId || !b) return null;
  let body;
  if (o.what === 'event') {
    body = eventCreate(b);
    if (!body) return null;
    body.clientId = clientId;
  } else {
    body = asTask(b, clientId);
  }
  return { what: o.what, clientId, body, at: Number.isSafeInteger(o.at) && o.at > 0 ? o.at : null, ...(typeof o.reason === 'string' && CODE_RE.test(o.reason) ? { reason: o.reason } : {}) };
}

/** The queue as stored → the entries of this server and person (another's are not sent). */
function storedQueue(v, scope) {
  if (!v || typeof v !== 'object' || v.scope !== scope || !Array.isArray(v.ops)) return [];
  return v.ops.slice(0, QUEUE_MAX).map(queueOp).filter(Boolean);
}

/**
 * A waiting POST events as a row of the overview: title, time and place from its body, `pending: true` („wartet auf
 * Verbindung“), no tick box. Its uid is `q:<clientId>`; the answer's `items` take its place once it is sent.
 */
function pendingItem(op) {
  if (!op || op.what !== 'event') return null;
  const b = op.body;
  const due = { date: b.date, time: b.time || null };
  return {
    uid: `q:${op.clientId}`, type: 'source', id: null, kind: 'event', title: b.title, subtitle: b.location || null,
    source: { plugin: MAIL, label: '', open: null }, due, show: due, allDay: !b.time, lead: null, overdue: false, area: 'private',
    important: false, done: false, doneAt: null, canComplete: false, assignee: null, progress: null, group: null, meta: {},
    updatedAt: op.at || null, pending: true, clientId: op.clientId,
    event: {
      end: b.time ? { date: b.date, time: b.endTime || plusHour(b.time) } : (b.endDate ? { date: b.endDate, time: null } : null),
      location: b.location || null, calendar: null, eventId: null, recurring: !!b.repeat, writable: false,
    },
  };
}

/** 'YYYY-MM-DD' + n days (calendar days, no clock). */
function addDays(date, n) {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

const sortKey = (x) => {
  const d = x.show || x.due;
  return `${d && d.date ? d.date : '9999'} ${d && d.time ? d.time : '99:99'}`;
};

/**
 * The waiting events in „Mein Tag“: today's under „Termine heute“ (`events`), those of the next 14 days under
 * „Demnächst“ (`upcoming`), each sorted by time with what is there. Another view, or no `date`: unchanged.
 */
function overlay(view, ops) {
  if (!view || view.view !== 'myday' || !view.date) return view;
  const waiting = arr(ops).map(pendingItem).filter(Boolean);
  if (!waiting.length) return view;
  const today = view.date;
  const last = addDays(today, SOON_DAYS);
  let sections = view.sections.slice();
  const into = (id, items) => {
    if (!items.length) return;
    const i = sections.findIndex((s) => s.id === id);
    if (i >= 0) {
      const s = sections[i];
      const all = [...s.items, ...items].sort((a, b) => (sortKey(a) < sortKey(b) ? -1 : sortKey(a) > sortKey(b) ? 1 : 0));
      sections[i] = { ...s, items: all, count: s.count + items.length };
    } else {
      const s = { id, title: '', count: items.length, items, collapsed: false };
      // „Termine heute“ on top, „Demnächst“ before „Erledigt“
      if (id === 'events') sections = [s, ...sections];
      else {
        const done = sections.findIndex((x) => x.id === 'done');
        if (done >= 0) sections.splice(done, 0, s); else sections.push(s);
      }
    }
  };
  into('events', waiting.filter((x) => x.due.date === today));
  into('upcoming', waiting.filter((x) => x.due.date > today && x.due.date <= last));
  return { ...view, sections };
}

/**
 * „Mehr Angaben …“: what the Mail calendar's form is filled in with — { title, date, time, endTime, allDay, location,
 * calendarId, reminder, repeat }. `reminder`: what the chip shows (the person's choice, else the calendar's default;
 * null: none), so the form shows the same. Saved there through Mail's own API, not through the hub.
 */
function formPrefill(draft, calendars) {
  const d = obj(draft) || {};
  const time = N.timeOf(d.time);
  const allDay = !time;
  const calendarId = N.posId(d.calendarId) || (calendars && calendars.defaultId) || null;
  const chosen = d.reminder !== undefined;
  const reminder = chosen ? (d.reminder === false || d.reminder === null ? null : mins(d.reminder)) : defaultReminder(calendars, allDay);
  return {
    title: N.line(d.title, TITLE_MAX) || '', date: N.dateOf(d.date), time: time || null, endTime: time ? (N.timeOf(d.endTime) || plusHour(time)) : null,
    allDay, location: N.line(d.location, LOCATION_MAX), calendarId, reminder, repeat: repeatArg(d.repeat),
  };
}

module.exports = {
  QUEUE_MAX, PERMANENT, permanent, why, normalizeCalendars, blocked, reasonOf, defaultReminder, plusHour,
  eventCreate, eventPatch, normalizeCreated, clientIdOf, asTask, refused, queueOp, storedQueue, pendingItem, overlay, formPrefill, addDays,
};
