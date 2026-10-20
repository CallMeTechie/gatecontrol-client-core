'use strict';

/**
 * Pure helpers of "Schule" (plugin `gatecontrol-schule`, WebUntis timetable;
 * contract: the plugin's README "API"): paths, argument checks, cleaned
 * answers of app/timetable, app/changes, app/messages and app/absences
 * (1.4.0), and the Schule context of a push message.
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * enums checked, colours `#RRGGBB`, avatar paths `/avatars/<file>`. The
 * apps show the text with textContent only.
 */

const { isAvatarPath, posInt } = require('./messenger');

const PLUGIN_ID = 'gatecontrol-schule';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;

const MAX_RANGE_DAYS = 14;            // app/timetable: from … to, both included
const CHANGES_DAYS = { min: 1, max: 30, def: 7 };
const MESSAGES_DAYS = { min: 1, max: 365, def: 30 };
const ABSENCES_DAYS = { min: 1, max: 365, def: 60 };
// Plugin version that brought app/messages and app/absences.
const MESSAGES_VERSION = '1.4.0';

const LESSON_STATES = ['normal', 'cancelled', 'changed', 'extra'];
const CHANGE_KINDS = ['cancelled', 'changed', 'extra', 'restored'];
const PUSH_KINDS = ['changes', 'exams', 'homework', 'messages', 'absences'];

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
// C0 controls and DEL (tab and line feed stay in multi-line texts)
const CTRL_RE = /[\u0000-\u0008\u000B-\u001F\u007F]/g;
const CTRL_LINE_RE = /[\u0000-\u001F\u007F]/g;

/** Trimmed single-line string ≤ max, or null when empty / not a string. */
function line(v, max) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const s = String(v).replace(CTRL_LINE_RE, ' ').trim().slice(0, max);
  return s || null;
}

/** Multi-line text ≤ max (CR LF → LF), or null. */
function text(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/\r\n?/g, '\n').replace(CTRL_RE, '').trim().slice(0, max);
  return s || null;
}

/** 'YYYY-MM-DD' of a real calendar day? */
function isDate(v) {
  if (typeof v !== 'string') return false;
  const m = DATE_RE.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
}

const dateOr = (v) => (isDate(v) ? v : null);
const timeOr = (v) => (typeof v === 'string' && TIME_RE.test(v) ? v : null);
const bool = (v) => v === true;

/** Days from `from` to `to` (calendar days, to - from). */
function diffDays(from, to) {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86400000);
}

/** 'YYYY-MM-DD' + n days. */
function addDays(date, n) {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

/**
 * Range of app/timetable: { from, to } (at most 14 days, both included) or
 * null when invalid.
 */
function rangeArgs(from, to) {
  if (!isDate(from) || !isDate(to)) return null;
  const d = diffDays(from, to);
  if (d < 0 || d >= MAX_RANGE_DAYS) return null;
  return { from, to };
}

/** days argument within limits ({ min, max, def }); null when invalid. */
function daysArg(v, limits) {
  if (v === undefined || v === null || v === '') return limits.def;
  const n = posInt(v);
  if (!n || n < limits.min || n > limits.max) return null;
  return n;
}

/** Id of a record: positive integer or a short token string. */
function idOf(v) {
  const n = posInt(v);
  if (n) return n;
  return typeof v === 'string' && ID_RE.test(v) ? v : null;
}

/** ms timestamp from a number or an ISO string, or null. */
function msOf(v) {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return Math.round(v);
  if (typeof v === 'string' && v) {
    const t = Date.parse(v);
    if (Number.isFinite(t)) return t;
  }
  return null;
}

/** Semver compare (major.minor.patch, rest ignored): a < b → -1. */
function cmpVersion(a, b) {
  const pa = String(a || '').split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  const pb = String(b || '').split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1;
  return 0;
}

/**
 * Do app/messages and app/absences exist? true (plugin ≥ 1.4.0), false
 * (older plugin), null (version unknown: ask and see).
 */
function messagesSupported(version) {
  if (typeof version !== 'string' || !/^\d+\.\d+/.test(version)) return null;
  return cmpVersion(version, MESSAGES_VERSION) >= 0;
}

// ── Answers ──────────────────────────────────────────────

function normalizeLesson(l) {
  if (!l || typeof l !== 'object') return null;
  const start = timeOr(l.start);
  const end = timeOr(l.end);
  if (!start || !end) return null;
  const period = posInt(l.period);
  const periodEnd = posInt(l.periodEnd);
  return {
    start,
    end,
    period: period && period <= 30 ? period : null,
    periodEnd: periodEnd && period && periodEnd > period && periodEnd <= 30 ? periodEnd : null,
    subject: line(l.subject, 40) || '',
    subjectLong: line(l.subjectLong, 120),
    subjectOld: line(l.subjectOld, 40),
    teacher: line(l.teacher, 80),
    teacherOld: line(l.teacherOld, 80),
    room: line(l.room, 60),
    roomOld: line(l.roomOld, 60),
    state: LESSON_STATES.includes(l.state) ? l.state : 'normal',
    info: text(l.info, 500),
    substText: text(l.substText, 500),
    text: text(l.text, 1000),
  };
}

function normalizeHomework(h) {
  if (!h || typeof h !== 'object') return null;
  const body = text(h.text, 2000);
  const subject = line(h.subject, 60);
  if (!body && !subject) return null;
  return {
    subject: subject || '',
    subjectLong: line(h.subjectLong, 120),
    text: body || '',
    givenDate: dateOr(h.givenDate),
    completed: bool(h.completed),
  };
}

function normalizeExam(x) {
  if (!x || typeof x !== 'object') return null;
  const name = line(x.name, 200);
  const subject = line(x.subject, 60);
  if (!name && !subject) return null;
  return {
    subject: subject || '',
    subjectLong: line(x.subjectLong, 120),
    name: name || '',
    start: timeOr(x.start),
    end: timeOr(x.end),
    type: line(x.type, 80),
    text: text(x.text, 1000),
  };
}

const byStart = (a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
const list = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);

function normalizeDay(d) {
  if (!d || typeof d !== 'object' || !isDate(d.date)) return null;
  return {
    date: d.date,
    holiday: line(d.holiday, 120),
    lessons: list(d.lessons, 40).map(normalizeLesson).filter(Boolean).sort(byStart),
    homework: list(d.homework, 40).map(normalizeHomework).filter(Boolean),
    exams: list(d.exams, 20).map(normalizeExam).filter(Boolean).sort((a, b) => byStart({ start: a.start || '' }, { start: b.start || '' })),
  };
}

function normalizeStudent(s) {
  if (!s || typeof s !== 'object') return null;
  const id = posInt(s.id);
  if (!id) return null;
  const days = list(s.days, 31).map(normalizeDay).filter(Boolean).sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  return {
    id,
    name: line(s.name, 80) || `#${id}`,
    userId: posInt(s.userId) || null,
    klasse: line(s.klasse, 40),
    color: typeof s.color === 'string' && COLOR_RE.test(s.color) ? s.color.toUpperCase() : null,
    avatarUrl: isAvatarPath(s.avatarUrl) ? s.avatarUrl : null,
    days,
  };
}

/** app/timetable → { updatedAt, students } */
function normalizeTimetable(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  return {
    updatedAt: msOf(r.updatedAt),
    students: list(r.students, 20).map(normalizeStudent).filter(Boolean),
  };
}

function normalizeChange(c) {
  if (!c || typeof c !== 'object') return null;
  if (!CHANGE_KINDS.includes(c.kind) || !isDate(c.date)) return null;
  const period = posInt(c.period);
  return {
    id: idOf(c.id),
    studentId: posInt(c.studentId) || null,
    student: line(c.student, 80),
    date: c.date,
    start: timeOr(c.start),
    end: timeOr(c.end),
    period: period && period <= 30 ? period : null,
    kind: c.kind,
    subject: line(c.subject, 40) || '',
    subjectLong: line(c.subjectLong, 120),
    subjectOld: line(c.subjectOld, 40),
    teacher: line(c.teacher, 80),
    teacherOld: line(c.teacherOld, 80),
    room: line(c.room, 60),
    roomOld: line(c.roomOld, 60),
    substText: text(c.substText, 500),
    info: text(c.info, 500),
    detectedAt: msOf(c.detectedAt),
    pushed: bool(c.pushed),
  };
}

/** app/changes → { changes } (newest first) */
function normalizeChanges(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const changes = list(r.changes, 200).map(normalizeChange).filter(Boolean);
  changes.sort((a, b) => (b.detectedAt || 0) - (a.detectedAt || 0));
  return { changes };
}

function normalizeMessage(m) {
  if (!m || typeof m !== 'object') return null;
  const id = idOf(m.id);
  if (id === null) return null;
  return {
    id,
    accountId: posInt(m.accountId) || null,
    studentIds: list(m.studentIds, 20).map((x) => posInt(x)).filter(Boolean),
    subject: line(m.subject, 300) || '',
    preview: line(m.preview, 500),
    body: text(m.body, 20000),
    sender: line(m.sender, 120),
    sentAt: msOf(m.sentAt),
    hasAttachments: bool(m.hasAttachments),
    isNew: bool(m.isNew),
  };
}

/** app/messages (1.4.0) → { messages } (newest first) */
function normalizeMessages(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const messages = list(r.messages, 300).map(normalizeMessage).filter(Boolean);
  messages.sort((a, b) => (b.sentAt || 0) - (a.sentAt || 0));
  return { messages };
}

function normalizeAbsence(a) {
  if (!a || typeof a !== 'object' || !isDate(a.date)) return null;
  const endDate = dateOr(a.endDate);
  return {
    id: idOf(a.id),
    studentId: posInt(a.studentId) || null,
    date: a.date,
    start: timeOr(a.start),
    end: timeOr(a.end),
    endDate: endDate && endDate > a.date ? endDate : null,
    reason: line(a.reason, 200),
    excused: a.excused === true ? true : a.excused === false ? false : null,
    text: text(a.text, 1000),
  };
}

/** app/absences (1.4.0) → { absences } (newest first) */
function normalizeAbsences(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const absences = list(r.absences, 500).map(normalizeAbsence).filter(Boolean);
  absences.sort((a, b) => (a.date === b.date ? ((b.start || '') < (a.start || '') ? -1 : 1) : (a.date < b.date ? 1 : -1)));
  return { absences };
}

// ── Push messages ────────────────────────────────────────

/**
 * Schule context of a push / inbox entry ({ topic, data }), or null when it
 * is no Schule message: { kind, studentId, date, messageId } — kind from
 * the topic (`plugin:gatecontrol-schule:<kind>`) or `data.schule.kind`.
 * The plugin sends data { route: 'plg-gatecontrol-schule', schule: {
 * studentId, date, kind? } } (messages: messageId).
 */
function pushContext(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const topic = typeof entry.topic === 'string' ? entry.topic : '';
  const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {};
  const ours = topic.startsWith(TOPIC_PREFIX) || data.route === APP_ROUTE;
  if (!ours) return null;
  const s = data.schule && typeof data.schule === 'object' && !Array.isArray(data.schule) ? data.schule : {};
  const fromTopic = topic.startsWith(TOPIC_PREFIX) ? topic.slice(TOPIC_PREFIX.length) : '';
  const kind = PUSH_KINDS.includes(fromTopic) ? fromTopic : PUSH_KINDS.includes(s.kind) ? s.kind : null;
  return {
    kind,
    studentId: posInt(s.studentId) || null,
    date: dateOr(s.date),
    messageId: idOf(s.messageId),
  };
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  TOPIC_PREFIX,
  API_BASE,
  MAX_RANGE_DAYS,
  CHANGES_DAYS,
  MESSAGES_DAYS,
  ABSENCES_DAYS,
  MESSAGES_VERSION,
  LESSON_STATES,
  CHANGE_KINDS,
  PUSH_KINDS,
  isDate,
  diffDays,
  addDays,
  rangeArgs,
  daysArg,
  cmpVersion,
  messagesSupported,
  normalizeTimetable,
  normalizeChanges,
  normalizeMessages,
  normalizeAbsences,
  pushContext,
};
