'use strict';

/**
 * Pure helpers of "Familie" (plugin `gatecontrol-familie`; contract: the
 * plugin's app API "Internet zu Hause", plugin 1.20.0): paths, argument
 * checks, cleaned answers of `me`, `internet`, `rules`, `rules/options`,
 * `presence` and `presence/wifi`, the body a rule's actions are written
 * back with, and the Familie context of a push message.
 *
 * Everything that reaches the renderer goes through the normalizers below:
 * known fields only, strings capped and stripped of control characters,
 * enums checked, colours `#RRGGBB`, avatar paths `/avatars/<file>`, times
 * as ms timestamps. A field an older plugin does not send counts as "not
 * there" (no presence, no rule behind a pause, no rule action). The apps
 * show the text with textContent only.
 */

const { isAvatarPath, posInt } = require('./messenger');

const PLUGIN_ID = 'gatecontrol-familie';
const APP_ROUTE = `plg-${PLUGIN_ID}`;
const TOPIC_PREFIX = `plugin:${PLUGIN_ID}:`;
const INTERNET_TOPIC = `${TOPIC_PREFIX}internet`;
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;

const ROLES = ['parent', 'child', 'wall'];
const PRESENCE_STATES = ['home', 'away', 'unknown', 'not_shared'];
const SOURCES = ['app', 'wifi'];
const BLOCKS = ['all', 'categories'];
const CATEGORIES = ['social', 'games', 'video'];
const CHILD_ERRORS = ['invalid', 'unavailable', 'error'];
const INTERNET_OPS = ['pause', 'resume', 'extend'];
// What a push of the topic "Internet zu Hause" tells (pause_over / extend_over: plugin 1.20.0).
const PUSH_KINDS = ['pause', 'resume', 'extend', 'extend_end', 'pause_over', 'extend_over'];
const RULE_OPS = ['pause', 'resume'];
const RULE_PROBLEMS = ['unavailable', 'not_allowed', 'not_found'];
const OPTION_REASONS = ['parents_only', 'unavailable'];
const SCOPES = ['house', 'personal'];
const SCHOOL_KINDS = ['cancelled', 'changed', 'extra', 'restored'];
const SCHOOL_DAYS = ['today', 'tomorrow', 'any'];

const MAX_PAUSE_MIN = 7 * 24 * 60;   // pause { minutes }
const MAX_ADD_MIN = 24 * 60;         // pause { add }
const MAX_EXTEND_MIN = 24 * 60;      // extend { minutes }
const MAX_RULE_MIN = 24 * 60;        // rule action { minutes }
const MAX_ACTIONS = 10;              // actions of a rule
const MAX_ACTION_BYTES = 4096;       // one action written back

const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const TZ_RE = /^[A-Za-z][A-Za-z0-9_+-]{0,30}(?:\/[A-Za-z0-9_+-]{1,30}){0,2}$/;
const CODE_RE = /^[a-z][a-z0-9_]{0,39}$/;
const CTRL_LINE_RE = /[\u0000-\u001F\u007F]/g;

/** Trimmed single-line string ≤ max, or null when empty / not a string. */
function line(v, max) {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const s = String(v).replace(CTRL_LINE_RE, ' ').trim().slice(0, max);
  return s || null;
}

/** ms timestamp from an ISO string (or a number), or null. */
function msOf(v) {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return Math.round(v);
  if (typeof v === 'string' && v && v.length <= 40) {
    const t = Date.parse(v);
    if (Number.isFinite(t) && t > 0) return t;
  }
  return null;
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const list = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);
const oneOf = (v, all) => (typeof v === 'string' && all.includes(v) ? v : null);
const timeOr = (v) => (typeof v === 'string' && TIME_RE.test(v) ? v : null);
const count = (v, max) => (Number.isSafeInteger(v) && v >= 0 ? Math.min(v, max) : 0);

/** A whole number within min … max, or null. */
function intIn(v, min, max) {
  return Number.isSafeInteger(v) && v >= min && v <= max ? v : null;
}

/** The face of a member: { userId, name, avatarUrl, color, initials } or null without an id. */
function face(m) {
  const o = obj(m);
  const userId = o ? posInt(o.userId) : null;
  if (!userId) return null;
  return {
    userId,
    name: line(o.name, 80) || '',
    avatarUrl: isAvatarPath(o.avatarUrl) ? o.avatarUrl : null,
    color: typeof o.colorHex === 'string' && COLOR_RE.test(o.colorHex) ? o.colorHex.toUpperCase() : null,
    initials: line(o.initials, 4),
  };
}

// ── me ───────────────────────────────────────────────────

/**
 * GET me → { me: { userId, name, role }, modules: { rules, presence } } or
 * null when it is not one (no member object).
 */
function normalizeMe(raw) {
  const r = obj(raw) || {};
  const m = obj(r.me);
  const userId = m ? posInt(m.userId) : null;
  const role = m ? oneOf(m.role, ROLES) : null;
  if (!userId || !role) return null;
  const mod = obj(r.modules) || {};
  return {
    me: { userId, name: line(m.name, 80) || '', role },
    modules: { rules: mod.rules === true, presence: mod.presence === true },
  };
}

// ── Internet zu Hause ────────────────────────────────────

/** `presence` of a child: { state, since, source } or null (function off / older plugin). */
function normalizePresenceOf(p) {
  const o = obj(p);
  const state = o ? oneOf(o.state, PRESENCE_STATES) : null;
  if (!state) return null;
  return { state, since: msOf(o.since), source: oneOf(o.source, SOURCES) };
}

/** `pausedBy` / `extendedBy`: { userId, name, at, rule: { id, title } | null } or null. */
function normalizeBy(b) {
  const o = obj(b);
  if (!o) return null;
  const rule = obj(o.rule);
  const ruleId = rule ? posInt(rule.id) : null;
  return {
    userId: posInt(o.userId),
    name: line(o.name, 80),
    at: msOf(o.at),
    rule: ruleId ? { id: ruleId, title: line(rule.title, 80) || '' } : null,
  };
}

function normalizeSchedule(s) {
  const o = obj(s);
  const from = o ? msOf(o.from) : null;
  if (!from) return null;
  const block = oneOf(o.block, BLOCKS) || 'all';
  return {
    from,
    to: msOf(o.to),
    block,
    categories: block === 'categories' ? CATEGORIES.filter((c) => Array.isArray(o.categories) && o.categories.includes(c)) : [],
    active: o.active === true,
  };
}

/** A child of GET internet / the answer of a change, or null without an id. */
function normalizeChild(c) {
  const f = face(c);
  if (!f) return null;
  const error = typeof c.error === 'string' && c.error ? (oneOf(c.error, CHILD_ERRORS) || 'error') : null;
  return {
    ...f,
    presence: normalizePresenceOf(c.presence),
    paused: msOf(c.paused),
    pausedBy: normalizeBy(c.pausedBy),
    extended: msOf(c.extended),
    extendedBy: normalizeBy(c.extendedBy),
    nextSchedule: normalizeSchedule(c.nextSchedule),
    profile: line(c.profile, 60),
    devices: count(c.devices, 999),
    filtered: c.filtered === true,
    error,
  };
}

/**
 * GET internet → { available, supported, manage, serverTime, timezone, children }.
 * `supported: false` is what the service answers for a plugin without the
 * route (< 1.18.0).
 */
function normalizeInternet(raw) {
  const i = obj(obj(raw) && raw.internet) || {};
  const seen = new Set();
  const children = [];
  for (const c of list(i.children, 50)) {
    const k = normalizeChild(c);
    if (!k || seen.has(k.userId)) continue;
    seen.add(k.userId);
    children.push(k);
  }
  return {
    available: i.available === true,
    supported: true,
    manage: i.manage === true,
    serverTime: msOf(i.serverTime),
    timezone: typeof i.timezone === 'string' && TZ_RE.test(i.timezone) ? i.timezone : null,
    children: i.available === true ? children : [],
  };
}

const NO_INTERNET = Object.freeze({ available: false, supported: false, manage: false, serverTime: null, timezone: null, children: [] });

/** Body of `POST internet/<id>/pause`: exactly one of minutes / until / add, or null. */
function pauseBody(a) {
  const o = obj(a) || {};
  const given = ['minutes', 'until', 'add'].filter((k) => o[k] !== undefined && o[k] !== null);
  if (given.length !== 1) return null;
  if (given[0] === 'minutes') {
    const n = intIn(o.minutes, 1, MAX_PAUSE_MIN);
    return n ? { minutes: n } : null;
  }
  if (given[0] === 'add') {
    const n = intIn(o.add, 1, MAX_ADD_MIN);
    return n ? { add: n } : null;
  }
  // 'HH:MM' (the next such time in the family's time zone) or a moment
  if (timeOr(o.until)) return { until: o.until };
  const t = msOf(o.until);
  return t ? { until: new Date(t).toISOString() } : null;
}

/** Body of `POST internet/<id>/extend`: { minutes: 0…1440, fromNow? }, or null. */
function extendBody(a) {
  const o = obj(a) || {};
  const n = intIn(o.minutes, 0, MAX_EXTEND_MIN);
  if (n === null) return null;
  return o.fromNow === true ? { minutes: n, fromNow: true } : { minutes: n };
}

/** `internet/<childId>/<op>` or null. */
function internetPath(childId, op) {
  const id = posInt(childId);
  return id && INTERNET_OPS.includes(op) ? `internet/${id}/${op}` : null;
}

// ── Rules ────────────────────────────────────────────────

function normalizeTrigger(t) {
  const o = obj(t) || {};
  const type = line(o.type, 40) || '';
  const out = { type };
  if (type === 'schedule') {
    out.weekdays = [...new Set(list(o.weekdays, 7).filter((d) => Number.isSafeInteger(d) && d >= 1 && d <= 7))].sort((a, b) => a - b);
    out.time = timeOr(o.time);
  } else if (type === 'person_home' || type === 'person_away') {
    out.userId = posInt(o.userId);
  } else if (type === 'place_enter' || type === 'place_exit') {
    out.placeName = line(o.placeName, 60);
    out.userId = posInt(o.userId);
  } else if (type === 'all_away') {
    out.graceMinutes = count(o.graceMinutes, 1440);
  } else if (type === 'school_change') {
    out.userId = posInt(o.userId);
    out.kinds = SCHOOL_KINDS.filter((k) => Array.isArray(o.kinds) && o.kinds.includes(k));
    out.days = oneOf(o.days, SCHOOL_DAYS) || 'any';
  }
  return out;
}

/** `to` of a notify / messenger action: a word or user ids. */
function toOf(v, words) {
  if (typeof v === 'string') return words.includes(v) ? v : null;
  const ids = list(v, 50).map(posInt).filter(Boolean);
  return ids.length ? ids : null;
}

/**
 * What goes back to the server for an action the app does not change
 * (`PATCH rules/<id> { actions }` replaces all of them): the fields the
 * rule API reads, nothing of the view. An action of a kind this app does
 * not know goes back as it came.
 */
function actionInput(a) {
  const o = obj(a);
  if (!o || typeof o.type !== 'string') return null;
  if (o.type === 'internet') {
    const userId = posInt(o.userId);
    const op = oneOf(o.op, RULE_OPS);
    // Without its fields the plugin puts the stored step back in this place.
    if (!userId || !op) return { type: 'internet' };
    if (op === 'resume') return { type: 'internet', op, userId };
    const until = timeOr(o.until);
    if (until) return { type: 'internet', op, userId, until };
    const minutes = intIn(o.minutes, 1, MAX_RULE_MIN);
    return minutes ? { type: 'internet', op, userId, minutes } : { type: 'internet' };
  }
  if (o.type === 'quick_action') {
    const out = { type: 'quick_action' };
    if (typeof o.actionId === 'string') out.actionId = o.actionId;
    else { out.plugin = o.plugin; out.id = o.id; }
    if (typeof o.title === 'string' && o.title) out.title = o.title;
    if (typeof o.state === 'string' && o.state) out.state = o.state;
    return out;
  }
  if (o.type === 'notify') {
    const out = { type: 'notify', to: o.to };
    if (typeof o.text === 'string' && o.text) out.text = o.text;
    if (o.facts === true) out.facts = true;
    if (Array.isArray(o.buttons) && o.buttons.length) out.buttons = o.buttons.slice(0, 10);
    return out;
  }
  if (o.type === 'messenger') {
    const out = { type: 'messenger', to: o.to };
    if (typeof o.text === 'string' && o.text) out.text = o.text;
    return out;
  }
  let copy;
  try { copy = JSON.parse(JSON.stringify(o)); } catch { return null; }
  return copy;
}

/**
 * An action of a rule as the list shows it — { type, …, input } where
 * `input` is what is written back for it (actionInput).
 */
function normalizeAction(a) {
  const input = actionInput(a);
  if (!input) return null;
  const type = line(a.type, 40) || '';
  const out = { type, input };
  if (type === 'internet') {
    const problem = oneOf(a.problem, RULE_PROBLEMS);
    out.op = oneOf(a.op, RULE_OPS);
    out.userId = posInt(a.userId);
    out.name = line(a.name, 80);
    out.minutes = intIn(a.minutes, 1, MAX_RULE_MIN);
    out.until = timeOr(a.until);
    out.available = a.available !== false && !problem;
    out.problem = problem || (a.available === false ? 'unavailable' : null);
  } else if (type === 'quick_action') {
    out.title = line(a.title, 60);
    out.verb = line(a.verb, 40);
    out.available = a.available === false ? false : null;
  } else if (type === 'notify') {
    out.to = toOf(a.to, ['parents', 'all']);
  } else if (type === 'messenger') {
    out.to = toOf(a.to, ['family']);
  }
  return out;
}

function normalizeRule(r) {
  const o = obj(r);
  const id = o ? posInt(o.id) : null;
  if (!id) return null;
  return {
    id,
    title: line(o.title, 60) || '',
    scope: oneOf(o.scope, SCOPES) || 'house',
    active: o.active === true,
    trigger: normalizeTrigger(o.trigger),
    actions: list(o.actions, MAX_ACTIONS).map(normalizeAction).filter(Boolean),
    ownerId: posInt(o.ownerId),
    ownerName: line(o.ownerName, 80),
    editable: o.editable === true,
    pausable: o.pausable === true || o.editable === true,
  };
}

/** GET rules → { rules, can: { house, personal } } (log and open reminders are not used here). */
function normalizeRules(raw) {
  const r = obj(raw) || {};
  const can = obj(r.can) || {};
  return {
    rules: list(r.rules, 200).map(normalizeRule).filter(Boolean),
    can: { house: can.house === true, personal: can.personal === true },
  };
}

/**
 * GET rules/options → { internet: { available, reason, children }, people }.
 * Without `internet` (plugin < 1.20.0, or GateControl without the rule
 * action) the action is "unavailable".
 */
function normalizeOptions(raw) {
  const r = obj(raw) || {};
  const i = obj(r.internet);
  const available = !!i && i.available === true;
  return {
    internet: {
      available,
      reason: available ? null : ((i && oneOf(i.reason, OPTION_REASONS)) || 'unavailable'),
      children: available ? list(i.children, 50).map(face).filter(Boolean) : [],
    },
    people: list(r.people, 100).map((p) => {
      const f = face(p);
      return f ? { userId: f.userId, name: f.name, role: oneOf(p.role, ROLES) } : null;
    }).filter(Boolean),
  };
}

/** The actions of `PATCH rules/<id>`: 1 … 10 plain objects with a type, each small; or null. */
function actionsBody(v) {
  if (!Array.isArray(v) || !v.length || v.length > MAX_ACTIONS) return null;
  const out = [];
  for (const a of v) {
    if (!obj(a) || typeof a.type !== 'string' || !a.type || a.type.length > 40) return null;
    let json;
    try { json = JSON.stringify(a); } catch { return null; }
    if (json.length > MAX_ACTION_BYTES) return null;
    out.push(JSON.parse(json));
  }
  return out;
}

// ── Presence ─────────────────────────────────────────────

/**
 * GET presence → { me: { share, wifi }, self: { state, since, source } | null }.
 * `me.wifi`: true / false, null = the server has no Wi-Fi detection (the
 * switch is hidden). `self`: the caller's own row of `members`.
 */
function normalizePresence(raw, userId) {
  const r = obj(raw) || {};
  const me = obj(r.me) || {};
  const own = list(r.members, 200).find((m) => obj(m) && posInt(m.userId) === userId) || null;
  const state = own ? oneOf(own.state, PRESENCE_STATES) : null;
  return {
    me: { share: me.share === true, wifi: typeof me.wifi === 'boolean' ? me.wifi : null },
    self: state ? { state, since: msOf(own.since), source: oneOf(own.source, SOURCES) } : null,
  };
}

/** `state` of PUT presence/consent → { state, since, source } or null. */
function normalizeOwnState(s) {
  const o = obj(s);
  const state = o ? oneOf(o.state, PRESENCE_STATES) : null;
  return state ? { state, since: msOf(o.since), source: oneOf(o.source, SOURCES) } : null;
}

/** GET / PUT presence/wifi → { available, consent, since, devices: [{ id, name, lastSeen, counts, gateway }] }. */
function normalizeWifi(raw) {
  const w = obj(obj(raw) && raw.wifi) || {};
  const available = w.available === true;
  const seen = new Set();
  const devices = [];
  for (const d of available ? list(w.devices, 100) : []) {
    const id = obj(d) ? posInt(d.id) : null;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    devices.push({ id, name: line(d.name, 80) || '', lastSeen: msOf(d.lastSeen), counts: d.counts === true, gateway: line(d.gateway, 60) });
  }
  return { available, consent: available && w.consent === true, since: available ? msOf(w.since) : null, devices };
}

const NO_WIFI = Object.freeze({ available: false, consent: false, since: null, devices: [] });

// ── Push messages ────────────────────────────────────────

/**
 * "Internet zu Hause" context of a push / inbox entry ({ topic, data }), or
 * null when it is none: { type: 'internet', kind, userId, until, ruleId }.
 * The plugin sends the topic `plugin:gatecontrol-familie:internet` with data
 * { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind,
 * userId, until, by, ruleId } }. A kind this app does not know is null (the
 * page just reloads). The other topics of Familie have no page here.
 */
function pushContext(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const topic = typeof entry.topic === 'string' ? entry.topic : '';
  const data = obj(entry.data) || {};
  const f = obj(data.familie) || {};
  const ours = topic === INTERNET_TOPIC || ((topic.startsWith(TOPIC_PREFIX) || data.route === APP_ROUTE) && f.type === 'internet');
  if (!ours) return null;
  return {
    type: 'internet',
    kind: oneOf(f.kind, PUSH_KINDS),
    userId: posInt(f.userId),
    until: msOf(f.until),
    ruleId: posInt(f.ruleId),
  };
}

/** A refusal's code as the pages know it (lower case word) or 'failed'. */
function codeOf(v) {
  return typeof v === 'string' && CODE_RE.test(v) ? v : 'failed';
}

module.exports = {
  PLUGIN_ID,
  APP_ROUTE,
  TOPIC_PREFIX,
  INTERNET_TOPIC,
  API_BASE,
  ROLES,
  PRESENCE_STATES,
  CATEGORIES,
  INTERNET_OPS,
  PUSH_KINDS,
  RULE_OPS,
  MAX_PAUSE_MIN,
  MAX_ADD_MIN,
  MAX_EXTEND_MIN,
  MAX_RULE_MIN,
  MAX_ACTIONS,
  NO_INTERNET,
  NO_WIFI,
  msOf,
  normalizeMe,
  normalizeChild,
  normalizeInternet,
  pauseBody,
  extendBody,
  internetPath,
  actionInput,
  normalizeRule,
  normalizeRules,
  normalizeOptions,
  actionsBody,
  normalizePresence,
  normalizeOwnState,
  normalizeWifi,
  pushContext,
  codeOf,
};
