/*
 * Repeat rules of tasks — shared by the server, the portal and (ported 1:1) the apps. Pure, no clock: every function
 * gets the dates it works on. Dates are 'YYYY-MM-DD' (the wall-clock date in the hub's time zone), weekdays ISO
 * (1 = Monday … 7 = Sunday). Vectors: test/vectors/repeat.json.
 *
 *   { type: 'daily',   interval: n }                       every n days
 *   { type: 'weekly',  interval: n, days: [1…7] }          every n weeks on these weekdays (the weeks count from the
 *                                                          week of the date the rule starts from, Monday-based)
 *   { type: 'monthly', interval: n, day?: 1…31 }           every n months on that day (clamped to the month's end)
 *   { type: 'yearly',  interval: n, month?: 1…12, day? }   every n years
 *   { type: 'after',   interval: n }                       n days after the task was completed
 *
 * next(rule, { due, done }) → the next due date: from `due` (or `done` without a due date, always `done` for 'after'),
 * moved forward until it is after `done` (a task completed late does not get a due date in the past).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GCRepeat = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var TYPES = ['daily', 'weekly', 'monthly', 'yearly', 'after'];
  var DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

  function toDays(date) {
    var m = DATE_RE.exec(String(date || ''));
    if (!m) return null;
    var t = Date.UTC(+m[1], +m[2] - 1, +m[3]);
    var d = new Date(t);
    if (d.getUTCFullYear() !== +m[1] || d.getUTCMonth() !== +m[2] - 1 || d.getUTCDate() !== +m[3]) return null;
    return Math.round(t / 86400000);
  }
  function fromDays(n) {
    var d = new Date(n * 86400000);
    var p = function (v) { return (v < 10 ? '0' : '') + v; };
    return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate());
  }
  function addDays(date, n) { var d = toDays(date); return d == null ? null : fromDays(d + n); }
  /** ISO weekday of a date: 1 = Monday … 7 = Sunday. */
  function weekday(date) { var d = toDays(date); return d == null ? null : ((d + 3) % 7 + 7) % 7 + 1; }
  function daysIn(y, m) { return new Date(Date.UTC(y, m, 0)).getUTCDate(); }
  function ymd(date) { var m = DATE_RE.exec(date); return { y: +m[1], m: +m[2], d: +m[3] }; }
  function make(y, m, d) {
    var p = function (v) { return (v < 10 ? '0' : '') + v; };
    return y + '-' + p(m) + '-' + p(Math.min(d, daysIn(y, m)));
  }

  /** A rule as given → the canonical rule, or null when it is not one. */
  function normalize(r) {
    if (!r || typeof r !== 'object' || TYPES.indexOf(r.type) < 0) return null;
    var interval = r.interval == null ? 1 : r.interval;
    if (typeof interval !== 'number' || interval % 1 !== 0 || interval < 1 || interval > 999) return null;
    var out = { type: r.type, interval: interval };
    if (r.type === 'weekly') {
      if (!Array.isArray(r.days) || !r.days.length) return null;
      var days = [];
      for (var i = 0; i < r.days.length; i++) {
        var x = r.days[i];
        if (typeof x !== 'number' || x % 1 !== 0 || x < 1 || x > 7) return null;
        if (days.indexOf(x) < 0) days.push(x);
      }
      out.days = days.sort(function (a, b) { return a - b; });
    }
    if (r.type === 'monthly' || r.type === 'yearly') {
      if (r.day != null) { if (typeof r.day !== 'number' || r.day % 1 !== 0 || r.day < 1 || r.day > 31) return null; out.day = r.day; }
    }
    if (r.type === 'yearly' && r.month != null) {
      if (typeof r.month !== 'number' || r.month % 1 !== 0 || r.month < 1 || r.month > 12) return null;
      out.month = r.month;
    }
    return out;
  }

  /** Monday-based week number of a date (for "every n weeks"). */
  function weekIndex(n) { return Math.floor((n + 3) / 7); }

  /** One step of a rule from `date` → the next date after it. */
  function step(rule, date, anchor) {
    var n = toDays(date);
    if (rule.type === 'daily' || rule.type === 'after') return fromDays(n + rule.interval);
    if (rule.type === 'weekly') {
      var a = weekIndex(toDays(anchor || date));
      for (var i = 1; i <= 7 * rule.interval + 7; i++) {
        var c = n + i;
        var wd = ((c + 3) % 7 + 7) % 7 + 1;
        if (rule.days.indexOf(wd) >= 0 && (weekIndex(c) - a) % rule.interval === 0) return fromDays(c);
      }
      return fromDays(n + 7 * rule.interval);
    }
    var p = ymd(date);
    var base = ymd(anchor || date);
    if (rule.type === 'monthly') {
      var mm = p.m - 1 + rule.interval;
      return make(p.y + Math.floor(mm / 12), mm % 12 + 1, rule.day || base.d);
    }
    // yearly
    return make(p.y + rule.interval, rule.month || base.m, rule.day || base.d);
  }

  /**
   * The next due date after a completion. ctx: { due: 'YYYY-MM-DD' | null, done: 'YYYY-MM-DD' (the day it was
   * completed) } → 'YYYY-MM-DD', or null for no rule / bad dates.
   */
  function next(rule, ctx) {
    var r = normalize(rule);
    var c = ctx || {};
    if (!r || toDays(c.done) == null) return null;
    if (r.type === 'after') return addDays(c.done, r.interval);
    var from = c.due && toDays(c.due) != null ? c.due : c.done;
    var anchor = from;
    var d = step(r, from, anchor);
    var guard = 0;
    while (toDays(d) <= toDays(c.done) && guard++ < 5000) d = step(r, d, anchor);
    return d;
  }

  /** The first due date of a new rule from `today` (today counts): weekly → the first of its days. */
  function first(rule, today) {
    var r = normalize(rule);
    if (!r || toDays(today) == null) return null;
    if (r.type === 'weekly') {
      for (var i = 0; i < 7; i++) { var d = addDays(today, i); if (r.days.indexOf(weekday(d)) >= 0) return d; }
    }
    if (r.type === 'monthly' && r.day) {
      var p = ymd(today);
      var m = make(p.y, p.m, r.day);
      return toDays(m) >= toDays(today) ? m : make(p.m === 12 ? p.y + 1 : p.y, p.m === 12 ? 1 : p.m + 1, r.day);
    }
    return today;
  }

  var WD = {
    de: ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'],
    en: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
  };

  function list(words, lang) {
    if (words.length < 2) return words.join('');
    return words.slice(0, -1).join(', ') + (lang === 'en' ? ' and ' : ' und ') + words[words.length - 1];
  }

  /** A short text of the rule: „jeden Montag“, „alle 2 Wochen am Montag und Donnerstag“, „3 Tage nach Erledigung“. */
  function describe(rule, lang) {
    var r = normalize(rule);
    var en = lang === 'en';
    if (!r) return en ? 'Never' : 'Nie';
    var n = r.interval;
    if (r.type === 'after') return en ? n + (n === 1 ? ' day' : ' days') + ' after completion' : n + (n === 1 ? ' Tag' : ' Tage') + ' nach Erledigung';
    if (r.type === 'daily') return n === 1 ? (en ? 'Daily' : 'Täglich') : (en ? 'Every ' + n + ' days' : 'Alle ' + n + ' Tage');
    if (r.type === 'weekly') {
      var names = r.days.map(function (d) { return WD[en ? 'en' : 'de'][d - 1]; });
      var work = r.days.join(',') === '1,2,3,4,5';
      if (n === 1) {
        if (work) return en ? 'Every weekday' : 'Werktags';
        return en ? 'Every ' + list(names, 'en') : 'Jeden ' + list(names, 'de');
      }
      return en ? 'Every ' + n + ' weeks on ' + list(names, 'en') : 'Alle ' + n + ' Wochen am ' + list(names, 'de');
    }
    if (r.type === 'monthly') return n === 1 ? (en ? 'Monthly' : 'Monatlich') : (en ? 'Every ' + n + ' months' : 'Alle ' + n + ' Monate');
    return n === 1 ? (en ? 'Yearly' : 'Jährlich') : (en ? 'Every ' + n + ' years' : 'Alle ' + n + ' Jahre');
  }

  return { normalize: normalize, next: next, first: first, describe: describe, addDays: addDays, weekday: weekday, toDays: toDays, fromDays: fromDays, TYPES: TYPES };
}));
