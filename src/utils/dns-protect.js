'use strict';

/**
 * Pure helpers of "DNS-Schutz" (the server-side DNS filter of the VPN
 * devices, plugin gatecontrol-dns from 1.0.0, server from 1.264.0): what
 * GET /api/v1/client/permissions says about it, the cleaned answer of the
 * plugin's `status`, the body of `pause`, and the entries of the tray menu.
 * No Electron, no network.
 */

const { posInt } = require('./messenger');

const PERMISSIONS_PATH = '/api/v1/client/permissions';
const PLUGIN_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const FILTER_STATES = ['starting', 'filtering', 'fallback'];
const STATES = ['active', 'paused', 'fallback', 'unfiltered', 'starting', 'off'];
const DEVICE_STATES = ['filtered', 'ownDns', 'excluded', 'disabled'];
const COUNTER_SCOPES = ['device', 'person', 'server'];
const PAUSE_SCOPES = ['peer', 'user', 'all'];
const REASONS = ['admins_only', 'profile', 'not_filtered', 'no_device', 'fallback', 'off', 'paused_for_all'];
// The minutes the plugin offers; the chips of the card and the tray entries.
const DURATIONS = [5, 30, 60, 240];
const EXTEND_MINUTES = 30;
const MAX_MINUTES = 7 * 24 * 60;
const DOMAIN_RE = /^[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?)*$/i;
const DNS_RE = /^[0-9a-fA-F:.]{2,45}$/;

// Server text is shown as text only; control characters never.
const clean = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, ' ').trim().slice(0, max) : '');
const count = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
const msOf = (v) => {
  if (typeof v !== 'string' || v.length > 40) return null;
  const n = Date.parse(v);
  return Number.isFinite(n) && n > 0 ? n : null;
};

/** `…/plugins/<plugin>/api/` of the plugin the server names, or null. */
function apiBase(plugin) {
  return typeof plugin === 'string' && PLUGIN_ID_RE.test(plugin) ? `/api/v1/client/plugins/${plugin}/api/` : null;
}

/**
 * The `vpnDns` field of GET permissions:
 *   { supported: false }                      the field is missing (server < 1.264.0)
 *   { supported: true, plugin: null }         null: no DNS protection (no plugin / off / no licence)
 *   { supported: true, plugin, filter }       it runs: filter = starting | filtering | fallback
 */
function vpnDnsOf(answer) {
  const a = answer && typeof answer === 'object' ? answer : {};
  if (!Object.prototype.hasOwnProperty.call(a, 'vpnDns')) return { supported: false, plugin: null, filter: null };
  const v = a.vpnDns;
  if (!v || typeof v !== 'object' || !apiBase(v.plugin)) return { supported: true, plugin: null, filter: null };
  return { supported: true, plugin: v.plugin, filter: FILTER_STATES.includes(v.state) ? v.state : 'starting' };
}

function normalizeMay(raw) {
  const m = raw && typeof raw === 'object' ? raw : {};
  const durations = [...new Set((Array.isArray(m.durations) ? m.durations : []).filter((n) => DURATIONS.includes(n)))].sort((a, b) => a - b);
  const max = posInt(m.maxMinutes);
  return {
    pause: m.pause === true,
    resume: m.resume === true,
    extend: m.extend === true,
    reason: REASONS.includes(m.reason) ? m.reason : null,
    durations,
    maxMinutes: max ? Math.min(max, MAX_MINUTES) : null,
    forever: m.forever === true,
  };
}

function normalizePause(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const openEnd = raw.openEnd === true;
  const until = openEnd ? null : msOf(raw.until);
  // Neither an end nor "until switched on again": nothing to show.
  if (!openEnd && !until) return null;
  const by = raw.by && typeof raw.by === 'object' && clean(raw.by.name, 80) ? { userId: posInt(raw.by.userId), name: clean(raw.by.name, 80) } : null;
  return {
    scope: PAUSE_SCOPES.includes(raw.scope) ? raw.scope : 'peer',
    until,
    openEnd,
    since: msOf(raw.since),
    by,
    byMe: raw.byMe === true,
  };
}

function normalizeDevice(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const ownDns = typeof raw.ownDns === 'string' && DNS_RE.test(raw.ownDns) ? raw.ownDns : null;
  return {
    peerId: posInt(raw.peerId),
    name: clean(raw.name, 80),
    state: DEVICE_STATES.includes(raw.state) ? raw.state : 'filtered',
    ownDns,
  };
}

function normalizeTop(raw) {
  if (!Array.isArray(raw)) return null;
  const out = [];
  for (const x of raw) {
    if (out.length >= 5) break;
    if (!x || typeof x !== 'object' || typeof x.domain !== 'string' || x.domain.length > 253 || !DOMAIN_RE.test(x.domain)) continue;
    out.push({ domain: x.domain.toLowerCase(), count: count(x.count) });
  }
  return out;
}

/**
 * The plugin's `status` (GET status, and `status` inside the answers of
 * pause / resume) → what the apps show; times as ms. An answer without a
 * known `state` is null.
 */
function normalizeStatus(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  if (!STATES.includes(r.state)) return null;
  const c = r.counters && typeof r.counters === 'object' ? r.counters : {};
  const queries = count(c.queries);
  const blocked = Math.min(count(c.blocked), queries);
  const pct = typeof c.percent === 'number' && Number.isFinite(c.percent) ? Math.min(100, Math.max(0, c.percent)) : 0;
  const pause = r.state === 'paused' ? normalizePause(r.pause) : null;
  const profile = r.profile && typeof r.profile === 'object' && clean(r.profile.name, 80) ? { name: clean(r.profile.name, 80), safeSearch: r.profile.safeSearch === true } : null;
  return {
    state: r.state,
    device: normalizeDevice(r.device),
    profile,
    pause,
    outage: r.state === 'fallback' ? { since: msOf(r.outage && r.outage.since) } : null,
    counters: { scope: COUNTER_SCOPES.includes(c.scope) ? c.scope : 'server', queries, blocked, percent: pct },
    top: normalizeTop(r.top),
    may: normalizeMay(r.may),
    manage: r.manage === true,
    serverTime: msOf(r.serverTime),
  };
}

/**
 * Body of POST pause — exactly one of { minutes: 1…7 days } | { forever:
 * true } | { extend: 1…7 days } ("+30 Min."), else null.
 */
function pauseBody(args) {
  const a = args && typeof args === 'object' ? args : {};
  const given = ['minutes', 'forever', 'extend'].filter((k) => a[k] !== undefined && a[k] !== null && a[k] !== false);
  if (given.length !== 1) return null;
  if (given[0] === 'forever') return a.forever === true ? { forever: true } : null;
  const n = posInt(a[given[0]]);
  if (!n || n > MAX_MINUTES || typeof a[given[0]] !== 'number') return null;
  return { [given[0]]: n };
}

/** The server's clock now: its time plus what passed here since the answer. */
function serverNow(snapshot, now) {
  const s = snapshot && snapshot.data;
  if (!s || !s.serverTime || !snapshot.fetchedAt) return now;
  return s.serverTime + Math.max(0, now - snapshot.fetchedAt);
}

/**
 * A server time on this PC's clock. Only a clock that is off by a minute or
 * more is corrected — below that the server's instant is shown as it is.
 */
function onLocalClock(ms, snapshot) {
  const s = snapshot && snapshot.data;
  if (!ms || !s || !s.serverTime || !snapshot.fetchedAt) return ms;
  const skew = snapshot.fetchedAt - s.serverTime;
  return Math.abs(skew) >= 60000 ? ms + skew : ms;
}

function clockText(ms, locale) {
  try {
    return new Intl.DateTimeFormat(locale === 'en' ? 'en-GB' : 'de-DE', { hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(ms));
  } catch {
    return '';
  }
}

/**
 * Tray entries of "DNS-Schutz" (mockup E), Electron-free (menu template
 * items): a line with the state and, when the server allows it, "DNS-Schutz
 * unterbrechen" with the allowed durations or "DNS-Schutz wieder
 * einschalten". Nothing while the server reports no DNS protection; in the
 * fallback only the line. Not allowed (`may.pause` false): no entry.
 *
 * @param {object} opts
 * @param {object} opts.snapshot - DnsProtectService.snapshot()
 * @param {Function} opts.t - i18n t()
 * @param {string} [opts.locale]
 * @param {(how: object) => void} opts.pause - { minutes } | { forever: true }
 * @param {() => void} opts.resume
 * @returns {object[]}
 */
function dnsProtectMenuItems({ snapshot, t, locale = 'de', pause, resume }) {
  const s = snapshot && snapshot.state === 'available' ? snapshot.data : null;
  if (!s || s.state === 'off' || s.state === 'starting') return [];
  const line = (label) => ({ label, enabled: false });
  if (s.state === 'fallback') return [line(t('dnsProtect.tray.fallback'))];
  if (s.state === 'unfiltered') return [line(t('dnsProtect.tray.unfiltered'))];
  if (s.state === 'paused') {
    const p = s.pause;
    const until = p && p.until ? clockText(onLocalClock(p.until, snapshot), locale) : '';
    return [
      line(until ? t('dnsProtect.tray.pausedUntil', { time: until }) : t('dnsProtect.tray.paused')),
      ...(s.may.resume ? [{ label: t('dnsProtect.tray.resume'), click: () => resume() }] : []),
    ];
  }
  const items = [line(t('dnsProtect.tray.active'))];
  if (!s.may.pause) return items;
  const submenu = s.may.durations.map((m) => ({ label: t(`dnsProtect.tray.minutes.${m}`), click: () => pause({ minutes: m }) }));
  if (submenu.length) submenu.push({ type: 'separator' });
  submenu.push({ label: t('dnsProtect.forever'), enabled: s.may.forever, click: () => pause({ forever: true }) });
  items.push({ label: t('dnsProtect.tray.pause'), submenu });
  return items;
}

module.exports = {
  PERMISSIONS_PATH,
  FILTER_STATES,
  STATES,
  REASONS,
  DURATIONS,
  EXTEND_MINUTES,
  MAX_MINUTES,
  apiBase,
  vpnDnsOf,
  normalizeMay,
  normalizePause,
  normalizeStatus,
  pauseBody,
  serverNow,
  onLocalClock,
  clockText,
  dnsProtectMenuItems,
};
