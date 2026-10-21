'use strict';

/**
 * Where a kind of notification (a push topic) appears (core 1.191,
 * `GET/PUT /api/v1/client/push/routes`, device token):
 *
 *   inbox   the pinned chat "GateControl" (the core inbox, default)
 *   family  the family chat (Familie plugin's group, for the whole household;
 *           only admins and parents may set it: `canFamily`)
 *   own     an own notice chat of the topic's source ("Schule"), only for the person
 *
 * GET → { ok, sink, canFamily, groups: [ { source, label, topics: [
 *         { id, label, dest, locked, familySetBy } ] } ] }
 * PUT { topic, dest } → the same answer. Refusals: 400 invalid_dest /
 * invalid_topic, 404 unknown_topic, 409 locked / no_sink, 403
 * family_not_allowed / no_user, 503 push_disabled. Older servers answer
 * 404 to GET → the feature is hidden.
 *
 * Pure and Electron-free; the answer is untrusted: ids checked, labels plain
 * and capped, malformed topics / groups dropped, a malformed answer → null.
 */

const DESTS = Object.freeze(['inbox', 'own', 'family']);
// Topics that always stay in GateControl, whatever the server says.
const ALWAYS_INBOX = Object.freeze(['security', 'admin_notice']);
// Core topics (`security`, `devices`, …) and `plugin:<id>:<topic>` as the push topics.
const TOPIC_RE = /^(?:[a-z][a-z0-9_]{0,31}|plugin:[a-z0-9]+(?:-[a-z0-9]+)*:[a-z][a-z0-9_-]{0,31})$/;
const SOURCE_RE = /^(?:core|plugin:[a-z0-9]+(?:-[a-z0-9]+)*)$/;
const ERROR_RE = /^[a-z][a-z0-9_]{0,39}$/;
// The refusals the routes API knows (anything else is shown as a general failure).
const ERRORS = Object.freeze([
  'invalid_dest', 'invalid_topic', 'unknown_topic', 'locked', 'no_sink', 'family_not_allowed', 'no_user', 'push_disabled',
]);
const MAX_GROUPS = 64;
const MAX_TOPICS = 64;

const isTopic = (v) => typeof v === 'string' && v.length <= 120 && TOPIC_RE.test(v);
const isDest = (v) => typeof v === 'string' && DESTS.includes(v);

/** A plain one-line label: no control characters, trimmed, ≤ max; null when empty. */
function line(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
  return s || null;
}

const flag = (v) => v === true || v === 1;

/** The routes answer → { sink, canFamily, groups } or null when it is not one. */
function normalizeRoutes(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.groups)) return null;
  const seen = new Set();
  const groups = [];
  for (const g of data.groups) {
    if (groups.length >= MAX_GROUPS) break;
    if (!g || typeof g !== 'object' || typeof g.source !== 'string' || !SOURCE_RE.test(g.source) || g.source.length > 100) continue;
    const source = g.source;
    const label = line(g.label, 60) || (source === 'core' ? 'GateControl' : source.slice('plugin:'.length));
    const topics = [];
    for (const tp of Array.isArray(g.topics) ? g.topics : []) {
      if (topics.length >= MAX_TOPICS) break;
      if (!tp || typeof tp !== 'object' || !isTopic(tp.id) || seen.has(tp.id)) continue;
      seen.add(tp.id);
      const locked = flag(tp.locked) || ALWAYS_INBOX.includes(tp.id);
      topics.push({
        id: tp.id,
        label: line(tp.label, 80) || tp.id.slice(tp.id.lastIndexOf(':') + 1),
        dest: locked ? 'inbox' : (isDest(tp.dest) ? tp.dest : 'inbox'),
        locked,
        familySetBy: line(tp.familySetBy, 80),
      });
    }
    if (topics.length) groups.push({ source, label, topics });
  }
  return { sink: flag(data.sink), canFamily: flag(data.canFamily), groups };
}

/** `{ error }` (or `code`) of a refusal body, lower case, or null. */
function errorCode(data) {
  if (!data || typeof data !== 'object') return null;
  const v = typeof data.error === 'string' ? data.error : (typeof data.code === 'string' ? data.code : null);
  const s = v ? v.trim().toLowerCase() : '';
  return ERROR_RE.test(s) ? s : null;
}

module.exports = {
  DESTS,
  ALWAYS_INBOX,
  ERRORS,
  TOPIC_RE,
  SOURCE_RE,
  isTopic,
  isDest,
  normalizeRoutes,
  errorCode,
};
