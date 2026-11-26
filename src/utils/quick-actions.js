'use strict';

/**
 * GateControl – plugin quick actions (pure helpers of services/quick-actions.js)
 *
 * The apps' quick actions of the plugins (server docs/plugins.md "Quick
 * actions", src/services/plugins/quickActions.js of the server; the fields of
 * 1.317.1: choice value null, control.disabled, widget.timeline):
 *
 *   GET  /api/v1/client/actions[?lang=de|en]  → { ok, actions: [action] }
 *   POST /api/v1/client/actions/<plugin>/<id> { source?, control?, value?, state? }
 *        → 200 { ok, message, state, widget, unchanged } · 400 invalid_* · 403 no_user ·
 *          404 not_found · 409 state_unknown | control_disabled · 429 · 502 · 504
 *
 * Everything the server answers is checked here again as strictly as the host
 * does (an app must not draw what a newer or broken server sends): an invalid
 * action is dropped, an invalid widget becomes null (the action stays), an
 * invalid reading is dropped, an invalid badge or timeline becomes null (the
 * widget stays). The apps draw the result declaratively (text only, icons as
 * SVG path data checked against ICON_RE).
 */

const MAX_ACTIONS = 16 * 64;           // every plugin's 16, a generous cap of the whole list
const ACTION_ID_RE = /^[A-Za-z0-9:._-]{1,64}$/;
const PLUGIN_ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ICON_RE = /^[MmLlHhVvCcSsQqTtAaZz0-9 .,-]{1,2000}$/;
const KINDS = new Set(['button', 'toggle']);
const TOGGLE_STATES = new Set(['on', 'off']);
const WIDGET_STATES = new Set(['on', 'off', 'good', 'warn', 'crit']);
const CONTROL_KINDS = new Set(['stepper', 'slider', 'choice']);
const CONTROL_ID_RE = /^[A-Za-z0-9_-]{1,24}$/;
const MAX_CONTROLS = 4;
const MIN_OPTIONS = 2;
const MAX_OPTIONS = 8;
const DEVICE_ID_RE = /^[A-Za-z0-9:._-]{1,64}$/;
const TONES = new Set(['good', 'warn', 'crit', 'neutral']);
const MAX_READINGS = 4;
const MAX_VERB = 20;
const BADGE_STATES = new Set(['good', 'warn', 'crit']);
const CTRL_RE = /[\0-\x1f\x7f]/;
const SCREEN_RE = /^[a-z][a-z0-9_-]{0,39}$/;
const MAX_REF = 80;
const MAX_SEGMENTS = 12;
const COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
const SOURCES = new Set(['app', 'notification']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const icon = (v) => (typeof v === 'string' && ICON_RE.test(v) ? v : null);
const toggleState = (v) => (typeof v === 'string' && TOGGLE_STATES.has(v) ? v : null);

/** A text of the server like the host's text(): a number as text, control characters → space, trimmed, cut to max; else null. */
function text(v, max) {
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\0-\x1f\x7f]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
}

/** A short text: a string, trimmed 1–max characters without control characters, else null (never cut). */
function shortText(v, max) {
  if (typeof v !== 'string' || CTRL_RE.test(v)) return null;
  const s = v.trim();
  return s.length >= 1 && s.length <= max ? s : null;
}

/** badge: { icon (required), value ≤ 8 | number, unit ≤ 4 (with a value), state, label ≤ 20 } or null. */
function sanitizeBadge(b) {
  if (!isObj(b)) return null;
  const i = icon(b.icon);
  if (!i) return null;
  const value = typeof b.value === 'number' ? num(b.value) : shortText(b.value, 8);
  return {
    icon: i,
    value,
    unit: value === null ? null : shortText(b.unit, 4),
    state: typeof b.state === 'string' && BADGE_STATES.has(b.state) ? b.state : null,
    label: shortText(b.label, 20),
  };
}

/** verbs of a toggle: { on, off } (both 1–20) or null. */
function sanitizeVerbs(v) {
  if (!isObj(v)) return null;
  const on = shortText(v.on, MAX_VERB);
  const off = shortText(v.off, MAX_VERB);
  return on && off ? { on, off } : null;
}

/** device: { id, title, subtitle?, icon? } or null. */
function sanitizeDevice(d) {
  if (!isObj(d) || typeof d.id !== 'string' || !DEVICE_ID_RE.test(d.id)) return null;
  const title = text(d.title, 40);
  if (!title) return null;
  return { id: d.id, title, subtitle: text(d.subtitle, 60), icon: icon(d.icon) };
}

function lookPart(p) {
  if (!isObj(p)) return null;
  const i = icon(p.icon);
  const tone = typeof p.tone === 'string' && TONES.has(p.tone) ? p.tone : null;
  return i || tone ? { icon: i, tone } : null;
}

/** look of a toggle: { on, off } (each { icon, tone } or null) or null. */
function sanitizeLook(l) {
  if (!isObj(l)) return null;
  const on = lookPart(l.on);
  const off = lookPart(l.off);
  return on || off ? { on, off } : null;
}

/** One reading: { id, label ≤ 20, value (≤ 16 | number), unit ≤ 8, icon, state } — a value or an icon is required. */
function sanitizeReading(r) {
  if (!isObj(r) || typeof r.id !== 'string' || !CONTROL_ID_RE.test(r.id)) return null;
  const label = text(r.label, 20);
  if (!label) return null;
  const value = typeof r.value === 'string' ? text(r.value, 16) : num(r.value);
  const i = icon(r.icon);
  if (value === null && i === null) return null;
  return {
    id: r.id, label, value, unit: text(r.unit, 8), icon: i,
    state: typeof r.state === 'string' && WIDGET_STATES.has(r.state) ? r.state : null,
  };
}

/** readings: at most 4 valid ones with unique ids (invalid ones dropped). */
function sanitizeReadings(list) {
  if (!Array.isArray(list)) return [];
  const res = [];
  const seen = new Set();
  for (const raw of list.slice(0, MAX_READINGS * 4)) {
    const r = sanitizeReading(raw);
    if (!r || seen.has(r.id)) continue;
    seen.add(r.id);
    res.push(r);
    if (res.length >= MAX_READINGS) break;
  }
  return res;
}

/**
 * One control → the checked control or null: stepper / slider { value, min < max, step > 0 } (value into the
 * range), choice { options 2–8 with unique ids, value an option id, null (no option active) or — anything else —
 * the first }; disabled only for a JSON true.
 */
function sanitizeControl(c) {
  if (!isObj(c) || typeof c.id !== 'string' || !CONTROL_ID_RE.test(c.id)) return null;
  if (typeof c.kind !== 'string' || !CONTROL_KINDS.has(c.kind)) return null;
  const label = text(c.label, 20);
  const disabled = c.disabled === true;
  if (c.kind === 'choice') {
    if (!Array.isArray(c.options) || c.options.length < MIN_OPTIONS || c.options.length > MAX_OPTIONS) return null;
    const options = [];
    const seen = new Set();
    for (const o of c.options) {
      if (!isObj(o) || typeof o.id !== 'string' || !CONTROL_ID_RE.test(o.id) || seen.has(o.id)) return null;
      const l = text(o.label, 20);
      if (!l) return null;
      seen.add(o.id);
      options.push({ id: o.id, label: l, icon: icon(o.icon) });
    }
    let value;
    if (c.value === null) value = null;
    else value = typeof c.value === 'string' && seen.has(c.value) ? c.value : options[0].id;
    return { id: c.id, kind: 'choice', label, value, options, disabled };
  }
  const min = num(c.min);
  const max = num(c.max);
  const step = num(c.step);
  const value = num(c.value);
  if (min === null || max === null || step === null || value === null || !(min < max) || !(step > 0)) return null;
  return { id: c.id, kind: c.kind, label, value: Math.min(max, Math.max(min, value)), min, max, step, unit: text(c.unit, 8), disabled };
}

/** One segment of a timeline within [lo, hi] → { from, to, tone, color, label } or null (a present field invalid → null). */
function sanitizeSegment(s, lo, hi) {
  if (!isObj(s)) return null;
  const from = num(s.from);
  const to = num(s.to);
  if (from === null || to === null || !(from < to) || from < lo || to > hi) return null;
  let tone = null;
  if (s.tone != null) {
    if (typeof s.tone !== 'string' || !TONES.has(s.tone)) return null;
    tone = s.tone;
  }
  let color = null;
  if (s.color != null) {
    if (typeof s.color !== 'string' || !COLOR_RE.test(s.color)) return null;
    color = s.color.toLowerCase();
  }
  let label = null;
  if (s.label != null) {
    label = shortText(s.label, 20);
    if (label === null) return null;
  }
  return { from, to, tone, color, label };
}

/**
 * timeline (a day bar, display only) → { from, to, now, segments } or null: from < to (default 0 / 24), now within
 * them or null, 1–12 valid segments in order without overlaps (gaps are fine). Anything invalid → null.
 */
function sanitizeTimeline(t) {
  if (!isObj(t)) return null;
  const from = t.from == null ? 0 : num(t.from);
  const to = t.to == null ? 24 : num(t.to);
  if (from === null || to === null || !(from < to)) return null;
  let now = null;
  if (t.now != null) {
    now = num(t.now);
    if (now === null || now < from || now > to) return null;
  }
  if (!Array.isArray(t.segments) || t.segments.length < 1 || t.segments.length > MAX_SEGMENTS) return null;
  const segments = [];
  let end = from;
  for (const raw of t.segments) {
    const s = sanitizeSegment(raw, from, to);
    if (!s || s.from < end) return null;
    end = s.to;
    segments.push(s);
  }
  return { from, to, now, segments };
}

/**
 * The widget of an action (listed or a run's answer) → the checked widget, or null when there is none or anything
 * in it (but a reading, the badge or the timeline) is invalid.
 */
function sanitizeWidget(w) {
  if (!isObj(w)) return null;
  let value = null;
  if (typeof w.value === 'string') value = text(w.value, 24);
  else if (typeof w.value === 'number' && Number.isFinite(w.value)) value = w.value;
  const controls = [];
  if (w.controls != null) {
    if (!Array.isArray(w.controls) || w.controls.length > MAX_CONTROLS) return null;
    const seen = new Set();
    for (const raw of w.controls) {
      const c = sanitizeControl(raw);
      if (!c || seen.has(c.id)) return null;
      seen.add(c.id);
      controls.push(c);
    }
  }
  return {
    label: text(w.label, 24),
    value,
    unit: text(w.unit, 8),
    icon: icon(w.icon),
    status: text(w.status, 60),
    state: typeof w.state === 'string' && WIDGET_STATES.has(w.state) ? w.state : null,
    readings: sanitizeReadings(w.readings),
    controls,
    power: w.power !== false,
    badge: sanitizeBadge(w.badge),
    timeline: sanitizeTimeline(w.timeline),
  };
}

/** opens: { screen, ref } or null. */
function sanitizeOpens(o) {
  if (!isObj(o) || typeof o.screen !== 'string' || !SCREEN_RE.test(o.screen)) return null;
  let ref = null;
  if (o.ref != null) {
    if (typeof o.ref !== 'string' || !o.ref.length || o.ref.length > MAX_REF || CTRL_RE.test(o.ref)) return null;
    ref = o.ref;
  }
  return { screen: o.screen, ref };
}

/** One listed action (with `plugin` and `pluginName`) → the checked action, or null (dropped). */
function sanitizeAction(a) {
  if (!isObj(a)) return null;
  if (typeof a.plugin !== 'string' || a.plugin.length < 2 || a.plugin.length > 64 || !PLUGIN_ID_RE.test(a.plugin)) return null;
  if (typeof a.id !== 'string' || !ACTION_ID_RE.test(a.id)) return null;
  const title = text(a.title, 40);
  if (!title) return null;
  const kind = a.kind == null ? 'button' : a.kind;
  if (!KINDS.has(kind)) return null;
  const toggle = kind === 'toggle';
  return {
    plugin: a.plugin,
    pluginName: text(a.pluginName, 60) || a.plugin,
    id: a.id,
    title,
    subtitle: text(a.subtitle, 60),
    icon: icon(a.icon),
    kind,
    state: toggle ? toggleState(a.state) : null,
    confirm: a.confirm === true,
    confirmWhen: toggle ? toggleState(a.confirmWhen) : null,
    look: toggle ? sanitizeLook(a.look) : null,
    verbs: toggle ? sanitizeVerbs(a.verbs) : null,
    targets: toggle && a.targets === true,
    device: sanitizeDevice(a.device),
    widget: sanitizeWidget(a.widget),
    opens: sanitizeOpens(a.opens),
  };
}

/** The list of GET /actions → the checked actions, unique per plugin and id, in the server's order. */
function sanitizeActions(list) {
  if (!Array.isArray(list)) return [];
  const res = [];
  const seen = new Set();
  for (const raw of list.slice(0, MAX_ACTIONS)) {
    const a = sanitizeAction(raw);
    if (!a) continue;
    const key = `${a.plugin}/${a.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    res.push(a);
  }
  return res;
}

/**
 * The body of a run: { source } plus either { control, value } (a control of the action's widget moved: a finite
 * number or an option id) or { state: 'on'|'off' } — null when the request is not acceptable.
 */
function runBody(opts = {}) {
  const o = isObj(opts) ? opts : {};
  const source = o.source == null ? 'app' : o.source;
  if (!SOURCES.has(source)) return null;
  const body = { source };
  const hasControl = o.control != null;
  const hasState = o.state != null;
  if (hasControl && hasState) return null;
  if (hasControl) {
    if (typeof o.control !== 'string' || !CONTROL_ID_RE.test(o.control)) return null;
    const v = o.value;
    const ok = (typeof v === 'number' && Number.isFinite(v)) || (typeof v === 'string' && CONTROL_ID_RE.test(v));
    if (!ok) return null;
    body.control = o.control;
    body.value = v;
  }
  if (hasState) {
    if (!TOGGLE_STATES.has(o.state)) return null;
    body.state = o.state;
  }
  return body;
}

/** A run's 200 answer → { ok, message, state, widget, unchanged } (checked). */
function sanitizeRunAnswer(data) {
  const d = isObj(data) ? data : {};
  return {
    ok: d.ok !== false,
    message: text(d.message, 120),
    state: toggleState(d.state),
    widget: sanitizeWidget(d.widget),
    unchanged: d.unchanged === true,
  };
}

/**
 * Why a run failed, from the HTTP status and the server's `error` code — what the apps say:
 *   control_disabled (409 control_disabled) · state_unknown (409) · gone (404) · no_user (403) · busy (429) ·
 *   timeout (504, no answer in time) · invalid (400) · network (no answer) · failed (anything else).
 */
function failureReason(status, code) {
  if (status === 409 && code === 'control_disabled') return 'control_disabled';
  if (status === 409 && code === 'state_unknown') return 'state_unknown';
  if (status === 404) return 'gone';
  if (status === 403) return 'no_user';
  if (status === 429) return 'busy';
  if (status === 504 || code === 'timeout') return 'timeout';
  if (status === 400) return 'invalid';
  if (code === 'network') return 'network';
  return 'failed';
}

const isPluginId = (v) => typeof v === 'string' && v.length >= 2 && v.length <= 64 && PLUGIN_ID_RE.test(v);
const isActionId = (v) => typeof v === 'string' && ACTION_ID_RE.test(v);

module.exports = {
  ACTION_ID_RE, CONTROL_ID_RE, DEVICE_ID_RE, PLUGIN_ID_RE, ICON_RE, TONES, MAX_CONTROLS, MAX_READINGS, MAX_SEGMENTS,
  text, sanitizeAction, sanitizeActions, sanitizeWidget, sanitizeControl, sanitizeReading, sanitizeReadings,
  sanitizeBadge, sanitizeTimeline, sanitizeDevice, sanitizeLook, sanitizeVerbs, sanitizeOpens,
  runBody, sanitizeRunAnswer, failureReason, isPluginId, isActionId,
};
