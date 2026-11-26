'use strict';

/**
 * Pure helpers of Mail Phase 3 — free/busy, shared calendars and resources in the plugin `gatecontrol-mail` (since
 * 1.9.0, the plugin's README "Free/busy, shared calendars and resources"): the rows of `POST freebusy` and the
 * suggestions, the shares of an own GateControl calendar, the calendars shared with the person, the people and groups
 * to share with, the bookable resources with their day, bookings and the requests to decide on, the live event
 * `resources`, request bodies and the details of the new refusals (violations, conflicts, who decided).
 *
 * Same rules as utils/mail.js and utils/mail-pim.js (exported from utils/mail.js as well): known fields only, strings
 * capped and without control characters, enums checked, ids positive integers, times in ms; what is not understood is
 * dropped. Electron-free, no side effects (unit-tested directly). Only self-service: resources are kept on the
 * plugin's page in GateControl, never here.
 */

const m = require('./mail');

const { line, text, obj, arr, bool, oneOf, posId, count, msOf, emailOf, colorOf } = m;

const LEVELS = Object.freeze(['freebusy', 'read', 'write']);
const ROW_KINDS = Object.freeze(['self', 'person', 'microsoft', 'resource', 'external']);
const BLOCK_STATUS = Object.freeze(['busy', 'tentative']);
const SHARE_STATES = Object.freeze(['accepted', 'pending', 'group']);
const RES_KINDS = Object.freeze(['room', 'vehicle', 'device', 'other']);
const BOOKING_STATES = Object.freeze(['pending', 'confirmed', 'declined', 'cancelled']);
const BOOKING_LISTS = Object.freeze(['open', 'done', 'mine']);
const RULES = Object.freeze(['max_duration', 'horizon', 'hours']);
const DEFAULT_WORK_HOURS = Object.freeze({ days: Object.freeze([1, 2, 3, 4, 5]), from: '08:00', to: '18:00' });

const DAY = 24 * 60 * 60 * 1000;
const FREEBUSY_MAX_MS = 31 * DAY;
const SUGGEST_MAX_MS = 14 * DAY;
const RESOURCES_MAX_MS = 31 * DAY;
const ATTENDEES_MAX = 50;
const RESOURCES_MAX = 20;

const HM_RE = /^(?:(?:[01]\d|2[0-3]):[0-5]\d|24:00)$/;
const TZ_RE = /^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
/** The address of a resource as an attendee (never shown). */
const RESOURCE_ADDRESS_RE = /^resource-\d{1,16}@resources\.gatecontrol\.invalid$/;

const isDate = (v) => typeof v === 'string' && DATE_RE.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`));
const intIn = (v, lo, hi) => (Number.isSafeInteger(v) && v >= lo && v <= hi ? v : null);
const ms = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
const minutesOf = (hm) => Number(hm.slice(0, 2)) * 60 + Number(hm.slice(3));
const isResourceAddress = (v) => typeof v === 'string' && RESOURCE_ADDRESS_RE.test(v.trim().toLowerCase());

/** `{ days: [1…7], from: 'HH:MM', to: 'HH:MM' }` (1 = Monday, from < to, to may be 24:00), or null. */
function workHoursOf(v) {
  const o = obj(v);
  if (!o || typeof o.from !== 'string' || typeof o.to !== 'string' || !HM_RE.test(o.from) || !HM_RE.test(o.to)) return null;
  if (o.from === '24:00' || minutesOf(o.from) >= minutesOf(o.to)) return null;
  const days = [...new Set(arr(o.days).filter((d) => intIn(d, 1, 7) !== null))].sort((a, b) => a - b);
  if (!days.length) return null;
  return { days, from: o.from, to: o.to };
}

/** The working hours of the settings for PUT calendar/settings, or null (every day once, from < to). */
function workHoursBody(v) {
  const o = obj(v);
  if (!o || !Array.isArray(o.days) || !o.days.length || o.days.length > 7 || !o.days.every((d) => intIn(d, 1, 7) !== null)) return null;
  if (new Set(o.days).size !== o.days.length) return null;
  return workHoursOf(o);
}

// ── Free/busy (mockup Planer) ──────────────────────────────

function blockOf(v, statuses = BLOCK_STATUS) {
  const o = obj(v);
  const start = o && msOf(o.start);
  const end = o && msOf(o.end);
  if (!start || !end || end <= start) return null;
  return { start, end, status: oneOf(statuses, o.status, statuses[0]) };
}

/** A `Row` of POST freebusy (never titles), or null. */
function normalizeRow(v) {
  const o = obj(v);
  const key = o && line(o.key, 200);
  if (!key) return null;
  const kind = oneOf(ROW_KINDS, o.kind, 'external');
  const state = oneOf(['ok', 'unknown'], o.state, 'unknown');
  return {
    key,
    kind,
    email: emailOf(o.email),
    resourceId: posId(o.resourceId),
    userId: posId(o.userId),
    name: line(o.name, 200) || '',
    state,
    blocks: state === 'ok' ? arr(o.blocks).map((b) => blockOf(b)).filter(Boolean).sort((a, b) => a.start - b.start).slice(0, 500) : [],
  };
}

/** POST freebusy → { from, to, items: [Row] } — the asker first. */
function normalizeFreeBusy(v) {
  const o = obj(v) || {};
  const items = arr(o.items).map(normalizeRow).filter(Boolean).slice(0, 80);
  const self = items.findIndex((r) => r.kind === 'self');
  if (self > 0) items.unshift(...items.splice(self, 1));
  return { from: msOf(o.from), to: msOf(o.to), items };
}

/** Addresses of attendees (≤ 50, each once, lower case kept as given) → list, or null for a bad one. */
function attendeeList(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const a of v) {
    const e = emailOf(typeof a === 'string' ? a : (obj(a) && a.email));
    if (!e) return null;
    if (!out.some((x) => x.toLowerCase() === e.toLowerCase())) out.push(e);
  }
  return out.length > ATTENDEES_MAX ? null : out;
}

function resourceIds(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || !v.every((x) => posId(x))) return null;
  const out = [...new Set(v.map(posId))];
  return out.length > RESOURCES_MAX ? null : out;
}

/** POST freebusy { from, to (≤ 31 days), attendees, resources? } → the body, or null. */
function freeBusyBody(v) {
  const o = obj(v);
  if (!o || !ms(o.from) || !ms(o.to) || o.to <= o.from || o.to - o.from > FREEBUSY_MAX_MS) return null;
  const attendees = attendeeList(o.attendees);
  const resources = resourceIds(o.resources);
  if (!attendees || !resources) return null;
  const b = { from: o.from, to: o.to, attendees };
  if (resources.length) b.resources = resources;
  return b;
}

/** POST freebusy/suggest { duration (5…1440), from?, to? (≤ 14 days), attendees, resources?, limit? } → the body, or null. */
function suggestBody(v) {
  const o = obj(v);
  if (!o || intIn(o.duration, 5, 1440) === null) return null;
  const attendees = attendeeList(o.attendees);
  const resources = resourceIds(o.resources);
  if (!attendees || !resources) return null;
  const b = { duration: o.duration, attendees };
  for (const k of ['from', 'to']) {
    if (o[k] === undefined || o[k] === null) continue;
    if (!ms(o[k])) return null;
    b[k] = o[k];
  }
  if (b.from && b.to && (b.to <= b.from || b.to - b.from > SUGGEST_MAX_MS)) return null;
  if (resources.length) b.resources = resources;
  if (o.limit !== undefined && o.limit !== null) { if (intIn(o.limit, 1, 10) === null) return null; b.limit = o.limit; }
  return b;
}

/** POST freebusy/suggest → { items: [{ start, end }], unknown: [key], workHours, timeZone }. */
function normalizeSuggest(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map((x) => { const b = blockOf(x); return b ? { start: b.start, end: b.end } : null; }).filter(Boolean).slice(0, 10),
    unknown: arr(o.unknown).map((k) => line(k, 200)).filter(Boolean).slice(0, 60),
    workHours: workHoursOf(o.workHours) || { ...DEFAULT_WORK_HOURS, days: DEFAULT_WORK_HOURS.days.slice() },
    timeZone: typeof o.timeZone === 'string' && TZ_RE.test(o.timeZone) ? o.timeZone : null,
  };
}

// ── Shared calendars (mockup Teilen) ───────────────────────

/** A `Share` of an own GateControl calendar, or null. */
function normalizeShare(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const type = o && oneOf(['user', 'group'], o.type);
  if (!id || !type) return null;
  return {
    id,
    type,
    principalId: posId(o.principalId),
    name: line(o.name, 200) || '',
    level: oneOf(LEVELS, o.level, 'read'),
    state: oneOf(SHARE_STATES, o.state, type === 'group' ? 'group' : 'pending'),
    members: type === 'group' ? count(o.members) : null,
    createdAt: msOf(o.createdAt),
  };
}

/** GET calendars/<id>/shares → { items: [Share], freeBusy }. */
function normalizeShares(v) {
  const o = obj(v) || {};
  return { items: arr(o.items).map(normalizeShare).filter(Boolean).slice(0, 50), freeBusy: o.freeBusy !== false };
}

/** POST calendars/<id>/shares { type, id, level } → the body, or null. */
function shareBody(v) {
  const o = obj(v);
  if (!o || !['user', 'group'].includes(o.type) || !posId(o.id) || !LEVELS.includes(o.level)) return null;
  return { type: o.type, id: posId(o.id), level: o.level };
}

/** A `SharedCalendar` (a GateControl calendar someone shares with the person), or null. */
function normalizeSharedCalendar(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  if (!id) return null;
  const owner = obj(o.owner) || {};
  const level = oneOf(LEVELS, o.level, 'freebusy');
  const via = oneOf(['user', 'group'], o.via, 'user');
  return {
    id,
    name: line(o.name, 120) || 'Kalender',
    color: colorOf(o.color) || '#8C96A5',
    owner: { userId: posId(owner.userId), name: line(owner.name, 200) || '' },
    level,
    via,
    group: via === 'group' ? line(o.group, 200) : null,
    visible: bool(o.visible),
    accepted: bool(o.accepted),
    writable: level === 'write',
  };
}

/** GET shared → { items: [SharedCalendar], accounts: [{ calendarId, accountId, name, color, owner: { email }, writable, visible }] }. */
function normalizeShared(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map(normalizeSharedCalendar).filter(Boolean).slice(0, 200),
    accounts: arr(o.accounts).map((x) => {
      const a = obj(x);
      const calendarId = a && posId(a.calendarId);
      const email = a && obj(a.owner) && emailOf(a.owner.email);
      if (!calendarId || !email) return null;
      return {
        calendarId,
        accountId: posId(a.accountId),
        name: line(a.name, 120) || 'Kalender',
        color: colorOf(a.color) || '#8C96A5',
        owner: { email },
        writable: bool(a.writable),
        visible: bool(a.visible),
      };
    }).filter(Boolean).slice(0, 200),
  };
}

/** PATCH shared/<calendarId> { visible?, color? ('#RRGGBB' | null) } → the patch, or null. */
function sharedPatch(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.visible !== undefined) { if (typeof o.visible !== 'boolean') return null; b.visible = o.visible; }
  if (o.color !== undefined) {
    if (o.color === null) b.color = null;
    else { if (!colorOf(o.color)) return null; b.color = colorOf(o.color); }
  }
  return Object.keys(b).length ? b : null;
}

/** GET principals?q= → { items: [{ type: 'user', id, name, initials, color } | { type: 'group', id, name, sub, members }] } (never addresses). */
function normalizePrincipals(v) {
  const o = obj(v) || {};
  return {
    items: arr(o.items).map((x) => {
      const p = obj(x);
      const id = p && posId(p.id);
      const name = p && line(p.name, 200);
      if (!id || !name) return null;
      if (p.type === 'group') return { type: 'group', id, name, sub: line(p.sub, 300), members: count(p.members) };
      if (p.type !== 'user') return null;
      const initials = line(p.initials, 4);
      return { type: 'user', id, name, initials: initials ? initials.toUpperCase() : null, color: colorOf(p.color) };
    }).filter(Boolean).slice(0, 20),
  };
}

/** The search of GET principals → the query (2…60 characters), or null. */
function principalsQuery(q) {
  const s = typeof q === 'string' ? q.replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : '';
  return s.length >= 2 && s.length <= 60 ? { q: s } : null;
}

// ── Resources and bookings (mockups Ressource, Anfragen) ───

/** `rules` of a resource → { maxMinutes, horizonDays, hours: { days, from, to } | null }. */
function rulesOf(v) {
  const o = obj(v) || {};
  return {
    maxMinutes: intIn(o.maxMinutes, 1, 527040),
    horizonDays: intIn(o.horizonDays, 1, 3660),
    hours: workHoursOf(o.hours),
  };
}

/** A `Resource` (+ `busy` of GET resources?from&to), or null. */
function normalizeResource(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const name = o && line(o.name, 120);
  if (!id || !name) return null;
  const address = typeof o.address === 'string' && isResourceAddress(o.address) ? o.address.trim().toLowerCase() : null;
  return {
    id,
    name,
    kind: oneOf(RES_KINDS, o.kind, 'other'),
    location: line(o.location, 200),
    seats: intIn(o.seats, 1, 100000),
    equipment: line(o.equipment, 300),
    color: colorOf(o.color) || '#8C96A5',
    approval: o.approval === 'approval' ? 'approval' : 'auto',
    approvers: arr(o.approvers).map((x) => line(x, 120)).filter(Boolean).slice(0, 10),
    rules: rulesOf(o.rules),
    timeZone: typeof o.timeZone === 'string' && TZ_RE.test(o.timeZone) ? o.timeZone : null,
    address,
    busy: arr(o.busy).map((x) => {
      const b = blockOf(x, ['busy', 'pending']);
      return b ? { ...b, mine: bool(x.mine) } : null;
    }).filter(Boolean).sort((a, b) => a.start - b.start).slice(0, 500),
  };
}

/** GET resources → { items: [Resource], kinds }. */
function normalizeResources(v) {
  const o = obj(v) || {};
  const kinds = arr(o.kinds).filter((k) => RES_KINDS.includes(k));
  return { items: arr(o.items).map(normalizeResource).filter(Boolean).slice(0, 500), kinds: kinds.length ? [...new Set(kinds)] : RES_KINDS.slice() };
}

/** The query of GET resources { from?, to? (both, ≤ 31 days), kind? } → params, or null. */
function resourcesQuery(v) {
  const o = obj(v) || {};
  const p = {};
  if (o.from !== undefined || o.to !== undefined) {
    if (!ms(o.from) || !ms(o.to) || o.to <= o.from || o.to - o.from > RESOURCES_MAX_MS) return null;
    p.from = o.from;
    p.to = o.to;
  }
  if (o.kind !== undefined && o.kind !== null && o.kind !== 'all') { if (!RES_KINDS.includes(o.kind)) return null; p.kind = o.kind; }
  return p;
}

/** POST resources/<id>/book { title?, allDay?, start?, end?, startDate?, endDate?, timeZone?, calendarId?, note? } → the body, or null. */
function bookBody(v) {
  const o = obj(v);
  if (!o) return null;
  const b = {};
  if (o.title !== undefined && o.title !== null && o.title !== '') {
    const t = typeof o.title === 'string' ? o.title.replace(/[\u0000-\u001F\u007F]/g, ' ').trim() : '';
    if (!t || t.length > 255) return null;
    b.title = t;
  }
  const allDay = o.allDay === true;
  if (o.allDay !== undefined && typeof o.allDay !== 'boolean') return null;
  if (allDay) {
    if (!isDate(o.startDate)) return null;
    const end = o.endDate === undefined || o.endDate === null ? o.startDate : o.endDate;
    if (!isDate(end) || end < o.startDate) return null;
    Object.assign(b, { allDay: true, startDate: o.startDate, endDate: end });
  } else {
    if (!ms(o.start) || !ms(o.end) || o.end <= o.start) return null;
    Object.assign(b, { start: o.start, end: o.end });
  }
  if (o.timeZone !== undefined && o.timeZone !== null) { if (typeof o.timeZone !== 'string' || !TZ_RE.test(o.timeZone)) return null; b.timeZone = o.timeZone; }
  if (o.calendarId !== undefined && o.calendarId !== null) { if (!posId(o.calendarId)) return null; b.calendarId = posId(o.calendarId); }
  if (o.note !== undefined && o.note !== null && o.note !== '') {
    const n = text(o.note, 2000);
    if (!n) return null;
    b.note = n;
  }
  return b;
}

/** A `Violation`, or null. */
function normalizeViolation(v) {
  const o = obj(v);
  const rule = o && oneOf(RULES, o.rule);
  if (!rule) return null;
  if (rule === 'hours') {
    const h = workHoursOf({ days: o.days, from: o.from, to: o.to }) || { days: [], from: typeof o.from === 'string' && HM_RE.test(o.from) ? o.from : null, to: typeof o.to === 'string' && HM_RE.test(o.to) ? o.to : null };
    return { rule, days: h.days, from: h.from, to: h.to };
  }
  return { rule, limit: intIn(o.limit, 0, 527040) };
}

const spans = (v, max = 50) => arr(v).map((x) => { const b = blockOf(x); return b ? { start: b.start, end: b.end } : null; }).filter(Boolean).slice(0, max);
const personOf = (v) => { const p = obj(v); return p && (posId(p.userId) || line(p.name, 200)) ? { userId: posId(p.userId), name: line(p.name, 200) || '' } : null; };

/** A `Booking`, or null. */
function normalizeBooking(v) {
  const o = obj(v);
  const id = o && posId(o.id);
  const start = o && msOf(o.start);
  if (!id || !start) return null;
  const end = msOf(o.end);
  const allDay = bool(o.allDay);
  const r = obj(o.resource) || {};
  const state = oneOf(BOOKING_STATES, o.state, 'pending');
  return {
    id,
    resourceId: posId(o.resourceId) || posId(r.id),
    resource: { id: posId(r.id) || posId(o.resourceId), name: line(r.name, 120) || '', kind: oneOf(RES_KINDS, r.kind, 'other'), color: colorOf(r.color) || '#8C96A5', location: line(r.location, 200) },
    title: line(o.title, 255) || '',
    start,
    end: end && end >= start ? end : start,
    allDay,
    ...(allDay && isDate(o.startDate) ? { startDate: o.startDate, endDate: isDate(o.endDate) && o.endDate >= o.startDate ? o.endDate : o.startDate } : {}),
    state,
    booker: personOf(o.booker) || { userId: null, name: '' },
    eventId: posId(o.eventId),
    note: text(o.note, 2000) || '',
    violations: arr(o.violations).map(normalizeViolation).filter(Boolean).slice(0, 10),
    conflicts: state === 'pending' ? spans(o.conflicts) : [],
    decidedBy: personOf(o.decidedBy),
    decidedAt: msOf(o.decidedAt),
    override: bool(o.override),
    comment: text(o.comment, 2000) || '',
    createdAt: msOf(o.createdAt),
    updatedAt: msOf(o.updatedAt),
    canDecide: bool(o.canDecide),
    day: arr(o.day).map((x) => blockOf(x, ['busy', 'pending'])).filter(Boolean).slice(0, 100),
  };
}

/** GET bookings?state= → { items: [Booking], counts: { open } }. */
function normalizeBookings(v) {
  const o = obj(v) || {};
  const c = obj(o.counts) || {};
  return { items: arr(o.items).map(normalizeBooking).filter(Boolean).slice(0, 500), counts: { open: count(c.open) || 0 } };
}

/** POST bookings/<id>/decide { decision, comment?, override? } → the body, or null. */
function decideBody(v) {
  const o = obj(v);
  if (!o || (o.decision !== 'approve' && o.decision !== 'decline')) return null;
  const b = { decision: o.decision };
  if (o.comment !== undefined && o.comment !== null && o.comment !== '') {
    const c = text(o.comment, 2000);
    if (!c) return null;
    b.comment = c;
  }
  if (o.override !== undefined) { if (typeof o.override !== 'boolean') return null; if (o.override) b.override = true; }
  return b;
}

/**
 * The structured fields of the refusals of 1.9.0 (`resource_busy { conflicts }`, `rule_violation { violations }`,
 * `already_decided { state, decidedBy, decidedAt }`) → cleaned, for the error's `detail` (the strings and numbers come
 * along anyway).
 */
function refusalDetail(v) {
  const o = obj(v);
  if (!o) return {};
  const out = {};
  if (Array.isArray(o.violations)) out.violations = o.violations.map(normalizeViolation).filter(Boolean).slice(0, 10);
  if (Array.isArray(o.conflicts)) out.conflicts = spans(o.conflicts);
  if (obj(o.decidedBy)) { const p = personOf(o.decidedBy); if (p) out.decidedBy = p; }
  return out;
}

/** The live event `resources` → { kind: 'request' | 'booking', bookingId, resourceId, state } | { kind: 'resources' } | null. */
function normalizeResourcesLive(v) {
  const o = obj(v) || {};
  if (o.kind === 'request' || o.kind === 'booking') {
    return { kind: o.kind, bookingId: posId(o.bookingId), resourceId: posId(o.resourceId), state: oneOf(BOOKING_STATES, o.state) };
  }
  if (o.kind === 'resources') return { kind: 'resources' };
  return null;
}

module.exports = {
  LEVELS,
  RES_KINDS,
  BOOKING_STATES,
  BOOKING_LISTS,
  DEFAULT_WORK_HOURS,
  RESOURCE_ADDRESS_RE,
  isResourceAddress,
  workHoursOf,
  workHoursBody,
  normalizeRow,
  normalizeFreeBusy,
  freeBusyBody,
  suggestBody,
  normalizeSuggest,
  normalizeShare,
  normalizeShares,
  shareBody,
  normalizeSharedCalendar,
  normalizeShared,
  sharedPatch,
  normalizePrincipals,
  principalsQuery,
  normalizeResource,
  normalizeResources,
  resourcesQuery,
  bookBody,
  normalizeViolation,
  normalizeBooking,
  normalizeBookings,
  decideBody,
  refusalDetail,
  normalizeResourcesLive,
};
