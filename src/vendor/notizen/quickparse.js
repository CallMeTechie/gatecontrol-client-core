/*
 * Schnell-Eingabe: a line in plain language → a task (title, date, time, repeat, list, person, important).
 * Deterministic, no AI, no clock of its own — the same in the server, the portal and (ported 1:1) the apps:
 * test/vectors/quickparse.json holds the cases every port must pass.
 *
 *   parse(text, ctx) → { title, date, time, remind, important, list, listName, assignee, assigneeName, repeat, marks }
 *     ctx: { today: 'YYYY-MM-DD' (the wall-clock date in the hub's time zone),
 *            lists?: [{ id, name }], people?: [{ id, name }],
 *            times?: { morning: '09:00', noon: '12:00', afternoon: '15:00', evening: '19:00', night: '21:00' } }
 *     date 'YYYY-MM-DD' | null, time 'HH:MM' | null, remind { date, time } | null (= date and time when a time is given),
 *     list { id, name } | null with listName the written name when no list matched (the client may offer to create
 *     it), assignee { id, name } | null with assigneeName likewise, repeat a rule of repeat.js | null,
 *     marks [{ start, end, kind: 'date'|'time'|'repeat'|'list'|'person'|'important' }] (offsets in `text`, sorted).
 *
 * German and English work in every language. What it understands (each word on its own, case does not matter):
 *   heute, morgen, übermorgen, today, tomorrow, (the) day after tomorrow
 *   Montag … Sonntag, Mo. … So. (two letters with a dot, or right before a time: „Fr 10 Uhr“), monday … sunday,
 *     mon. … sun.; a weekday is the next such day after today („Freitag“ on a Friday = in a week);
 *     „nächsten Montag“, „next monday“ the same; „nächste Woche“ / „next week“ = next Monday;
 *     „am Wochenende“ / „weekend“ = Saturday (today when it is Saturday or Sunday)
 *   in 3 Tagen / in einer Woche / in 2 Wochen / in einem Monat / in 1 Jahr, in 3 days / in a week / in 2 months
 *   13.11. / 13.11.2026 / 13.11.26 / 13. November / 13. Nov / November 13 / 13 november / 2026-11-13 (without a
 *     year the next such day from today on)
 *   9 Uhr, 9:30, 9.30 Uhr, um 9, um 9:30, halb 10 (9:30), 14h, 9 am, 9:30 pm, at 9
 *   früh, morgens, vormittags, mittags, nachmittags, abends, heute Abend, morgen früh, nachts, morning, noon,
 *     afternoon, evening, tonight (ctx.times, defaults above)
 *   jeden Tag, täglich, werktags, jeden Werktag, jede Woche, wöchentlich, jeden Monat, monatlich, jedes Jahr,
 *     jährlich, jeden Montag (und Donnerstag …), jeden Mo, Mi und Fr, alle 2 Tage/Wochen/Monate/Jahre,
 *     3 Tage nach Erledigung; daily, every day, weekdays, every weekday, weekly, every week, monthly, yearly,
 *     every monday (and thursday), every 2 weeks, 3 days after completion — the first date is today or the first
 *     of the weekdays (today counts) unless a date is given
 *   @Name (a person: the first of ctx.people whose name or first name starts with it), #liste (a list: the same
 *     name without case, spaces and dashes, else the only one starting with it)
 *   wichtig, dringend, important, urgent, ! and !! on their own
 * What it took is removed from the title (with „am“, „um“, „bis“, „on“, „at“, „by“ before it and commas around it).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(root.GCRepeat || (typeof require === 'function' ? require('./repeat') : null));
  else root.GCQuickParse = factory(root.GCRepeat);
}(typeof self !== 'undefined' ? self : this, function (R) {
  'use strict';

  var L = '[\\p{L}\\p{N}]';
  var B = '(?<!' + L + ')'; // start of a word
  var E = '(?!' + L + ')';  // end of a word

  var WEEKDAYS = [
    ['montag', 'monday', 'mo', 'mon'],
    ['dienstag', 'tuesday', 'di', 'tue', 'tues'],
    ['mittwoch', 'wednesday', 'mi', 'wed'],
    ['donnerstag', 'thursday', 'do', 'thu', 'thur', 'thurs'],
    ['freitag', 'friday', 'fr', 'fri'],
    ['samstag', 'sonnabend', 'saturday', 'sa', 'sat'],
    ['sonntag', 'sunday', 'so', 'sun'],
  ];
  var MONTHS = [
    ['januar', 'jänner', 'january', 'jan'], ['februar', 'february', 'feb'], ['märz', 'maerz', 'march', 'mär', 'mar'],
    ['april', 'apr'], ['mai', 'may'], ['juni', 'june', 'jun'], ['juli', 'july', 'jul'], ['august', 'aug'],
    ['september', 'sept', 'sep'], ['oktober', 'october', 'okt', 'oct'], ['november', 'nov'], ['dezember', 'december', 'dez', 'dec'],
  ];
  var NUMBERS = { ein: 1, eins: 1, eine: 1, einem: 1, einen: 1, einer: 1, a: 1, an: 1, one: 1, zwei: 2, two: 2, drei: 3, three: 3,
    vier: 4, four: 4, 'fünf': 5, fuenf: 5, five: 5, sechs: 6, six: 6, sieben: 7, seven: 7, acht: 8, eight: 8, neun: 9, nine: 9, zehn: 10, ten: 10 };
  var DEFAULT_TIMES = { morning: '09:00', noon: '12:00', afternoon: '15:00', evening: '19:00', night: '21:00' };

  function alt(groups, short) {
    var words = [];
    groups.forEach(function (g) { g.forEach(function (w) { if (!short || w.length <= 4) words.push(w); }); });
    return words.sort(function (a, b) { return b.length - a.length; }).join('|');
  }
  function full(groups) {
    var words = [];
    groups.forEach(function (g) { g.forEach(function (w) { if (w.length > 4) words.push(w); }); });
    return words.sort(function (a, b) { return b.length - a.length; }).join('|');
  }
  var WD_FULL = full(WEEKDAYS);
  var WD_SHORT = alt(WEEKDAYS, true);
  var MON = alt(MONTHS);
  var NUM = '\\d{1,3}|' + Object.keys(NUMBERS).sort(function (a, b) { return b.length - a.length; }).join('|');
  var TIME_AHEAD = '(?=\\s*(?:um\\s+|at\\s+)?\\d{1,2}(?:[:.]\\d{2})?\\s*(?:uhr|h|am|pm)?' + E + ')';
  // a weekday word: written out, or two/three letters with a dot or right before a time
  var WD_WORD = '(?:' + WD_FULL + '|(?:' + WD_SHORT + ')(?:\\.|' + TIME_AHEAD + '))';
  var PRE = '(?:(?:am|bis|ab|on|by|due|until|für|for)\\s+)?';

  function weekdayOf(word) {
    var w = String(word).toLowerCase().replace(/\.$/, '');
    for (var i = 0; i < WEEKDAYS.length; i++) if (WEEKDAYS[i].indexOf(w) >= 0) return i + 1;
    return null;
  }
  function monthOf(word) {
    var w = String(word).toLowerCase().replace(/\.$/, '');
    for (var i = 0; i < MONTHS.length; i++) if (MONTHS[i].indexOf(w) >= 0) return i + 1;
    return null;
  }
  function numberOf(word) {
    var w = String(word).toLowerCase();
    return /^\d+$/.test(w) ? parseInt(w, 10) : (NUMBERS[w] || null);
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function hhmm(h, m) { return pad(h) + ':' + pad(m || 0); }
  function validDate(y, m, d) {
    if (m < 1 || m > 12 || d < 1) return false;
    return d <= new Date(Date.UTC(y, m, 0)).getUTCDate();
  }
  function ymd(date) { var p = date.split('-'); return { y: +p[0], m: +p[1], d: +p[2] }; }
  function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

  /** The next date with ISO weekday `wd` strictly after `today`. */
  function nextWeekday(today, wd) {
    var cur = R.weekday(today);
    var diff = (wd - cur + 7) % 7;
    return R.addDays(today, diff === 0 ? 7 : diff);
  }
  /** A day and month without a year → the next such date from today on. */
  function upcoming(today, m, d) {
    var t = ymd(today);
    for (var y = t.y; y <= t.y + 8; y++) {
      if (!validDate(y, m, d)) continue;
      var s = y + '-' + pad(m) + '-' + pad(d);
      if (cmp(s, today) >= 0) return s;
    }
    return null;
  }
  function addMonths(date, n) {
    var p = ymd(date);
    var mm = p.m - 1 + n;
    var y = p.y + Math.floor(mm / 12);
    var m = mm % 12 + 1;
    var last = new Date(Date.UTC(y, m, 0)).getUTCDate();
    return y + '-' + pad(m) + '-' + pad(Math.min(p.d, last));
  }

  function norm(s) { return String(s || '').toLowerCase().normalize('NFC').replace(/[\s_\-–—.]+/g, ''); }

  /**
   * The patterns, tried in this order on what is left of the text. Each returns what it found or null (then the
   * match is left in the title).
   */
  function rules(ctx) {
    var today = ctx.today;
    var times = ctx.times;
    var dayPart = {
      'früh': times.morning, frueh: times.morning, morgens: times.morning, vormittags: times.morning, morning: times.morning, 'in the morning': times.morning,
      mittags: times.noon, noon: times.noon, 'at noon': times.noon, nachmittags: times.afternoon, afternoon: times.afternoon, 'in the afternoon': times.afternoon,
      abends: times.evening, abend: times.evening, evening: times.evening, 'in the evening': times.evening, tonight: times.evening, nachts: times.night, 'at night': times.night,
    };
    var DP = Object.keys(dayPart).sort(function (a, b) { return b.length - a.length; }).map(function (k) { return k.replace(/ /g, '\\s+'); }).join('|');
    var UNIT = '(tag|tage|tagen|woche|wochen|monat|monate|monaten|jahr|jahre|jahren|day|days|week|weeks|month|months|year|years)';
    function unitOf(u) {
      u = u.toLowerCase();
      if (/^(tag|day)/.test(u)) return 'daily';
      if (/^(woche|week)/.test(u)) return 'weekly';
      if (/^(monat|month)/.test(u)) return 'monthly';
      return 'yearly';
    }
    function weekdayList(s) {
      var out = [];
      s.split(/\s*(?:,|\bund\b|\band\b|&|\/)\s*/i).forEach(function (w) { var d = weekdayOf(w.trim()); if (d && out.indexOf(d) < 0) out.push(d); });
      return out.sort();
    }
    var WD_ANY = '(?:' + WD_FULL + '|' + WD_SHORT + ')\\.?';
    var WD_SEQ = WD_ANY + '(?:\\s*(?:,|und|and|&|/)\\s*' + WD_ANY + ')*';
    return [
      // ── repeat ──
      { kind: 'repeat', re: '(\\d{1,3})\\s+(tage?|tagen|days?)\\s+nach\\s+(?:der\\s+)?erledigung|(\\d{1,3})\\s+days?\\s+after\\s+(?:completion|done|completing)',
        take: function (m) { return { repeat: { type: 'after', interval: parseInt(m[1] || m[3], 10) } }; } },
      { kind: 'repeat', re: '(?:jeden|jede|every)\\s+(' + WD_SEQ + ')',
        take: function (m) { var d = weekdayList(m[1]); return d.length ? { repeat: { type: 'weekly', interval: 1, days: d } } : null; } },
      { kind: 'repeat', re: '(?:alle|every)\\s+(' + NUM + ')\\s+' + UNIT + '(?:\\s+(?:am|on)\\s+(' + WD_SEQ + '))?',
        take: function (m) {
          var n = numberOf(m[1]);
          if (!n) return null;
          var type = unitOf(m[2]);
          var days = m[3] ? weekdayList(m[3]) : null;
          var r = { type: type, interval: n };
          if (type === 'weekly') r.days = days && days.length ? days : null;
          return { repeat: r };
        } },
      { kind: 'repeat', re: 'werktags|(?:jeden|every)\\s+(?:werktag|weekday)|weekdays|(?:montags?|monday)\\s*(?:bis|-|–|to)\\s*(?:freitags?|friday)',
        take: function () { return { repeat: { type: 'weekly', interval: 1, days: [1, 2, 3, 4, 5] } }; } },
      { kind: 'repeat', re: 'täglich|taeglich|jeden\\s+tag|daily|every\\s+day', take: function () { return { repeat: { type: 'daily', interval: 1 } }; } },
      { kind: 'repeat', re: 'wöchentlich|woechentlich|jede\\s+woche|weekly|every\\s+week', take: function () { return { repeat: { type: 'weekly', interval: 1, days: null } }; } },
      { kind: 'repeat', re: 'monatlich|jeden\\s+monat|monthly|every\\s+month', take: function () { return { repeat: { type: 'monthly', interval: 1 } }; } },
      { kind: 'repeat', re: 'jährlich|jaehrlich|jedes\\s+jahr|yearly|annually|every\\s+year', take: function () { return { repeat: { type: 'yearly', interval: 1 } }; } },
      // ── a date ──
      { kind: 'date', re: PRE + '(\\d{4})-(\\d{2})-(\\d{2})',
        take: function (m) { var y = +m[1], mo = +m[2], d = +m[3]; return validDate(y, mo, d) ? { date: m[1] + '-' + m[2] + '-' + m[3] } : null; } },
      { kind: 'date', re: PRE + '(\\d{1,2})\\.(\\d{1,2})\\.(\\d{4}|\\d{2})?',
        take: function (m) {
          var d = +m[1], mo = +m[2];
          if (m[3]) { var y = +m[3] < 100 ? 2000 + +m[3] : +m[3]; return validDate(y, mo, d) ? { date: y + '-' + pad(mo) + '-' + pad(d) } : null; }
          var u = upcoming(today, mo, d);
          return u ? { date: u } : null;
        } },
      { kind: 'date', re: PRE + '(\\d{1,2})(?:\\.|st|nd|rd|th)?\\s+(?:of\\s+)?(' + MON + ')\\.?(?:\\s+(\\d{4}))?',
        take: function (m) {
          var d = +m[1], mo = monthOf(m[2]);
          if (m[3]) return validDate(+m[3], mo, d) ? { date: m[3] + '-' + pad(mo) + '-' + pad(d) } : null;
          var u = upcoming(today, mo, d);
          return u ? { date: u } : null;
        } },
      { kind: 'date', re: PRE + '(' + MON + ')\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(\\d{4}))?',
        take: function (m) {
          var mo = monthOf(m[1]), d = +m[2];
          if (m[3]) return validDate(+m[3], mo, d) ? { date: m[3] + '-' + pad(mo) + '-' + pad(d) } : null;
          var u = upcoming(today, mo, d);
          return u ? { date: u } : null;
        } },
      { kind: 'date', re: PRE + 'in\\s+(' + NUM + ')\\s+' + UNIT,
        take: function (m) {
          var n = numberOf(m[1]);
          if (!n) return null;
          var u = unitOf(m[2]);
          if (u === 'daily') return { date: R.addDays(today, n) };
          if (u === 'weekly') return { date: R.addDays(today, 7 * n) };
          if (u === 'monthly') return { date: addMonths(today, n) };
          return { date: addMonths(today, 12 * n) };
        } },
      { kind: 'date', re: '(?:nächste|naechste|nächsten|naechsten)\\s+woche|next\\s+week', take: function () { return { date: nextWeekday(today, 1) }; } },
      { kind: 'date', re: '(?:am\\s+|this\\s+|on\\s+the\\s+)?(?:wochenende|weekend)',
        take: function () { var w = R.weekday(today); return { date: w >= 6 ? today : R.addDays(today, 6 - w) }; } },
      { kind: 'date', re: PRE + '(?:(?:heute|today)\\s+(?:abend|nacht)|tonight)',
        take: function (m) { return { date: today, time: /nacht/i.test(m[0]) ? times.night : times.evening }; } },
      { kind: 'date', re: PRE + '(?:übermorgen|uebermorgen|(?:the\\s+)?day\\s+after\\s+tomorrow)', take: function () { return { date: R.addDays(today, 2) }; } },
      { kind: 'date', re: PRE + '(?:morgen|tomorrow)(?:\\s+(früh|frueh|vormittag|mittag|nachmittag|abend|morning|afternoon|evening|night))?',
        take: function (m) {
          var out = { date: R.addDays(today, 1) };
          var p = (m[1] || '').toLowerCase();
          if (p) out.time = /früh|frueh|vormittag|morning/.test(p) ? times.morning : /^mittag/.test(p) ? times.noon : /nachmittag|afternoon/.test(p) ? times.afternoon : /night/.test(p) ? times.night : times.evening;
          return out;
        } },
      { kind: 'date', re: PRE + '(?:heute|today)', take: function () { return { date: today }; } },
      { kind: 'date', re: PRE + '(?:(?:nächsten|naechsten|nächster|kommenden|diesen|next|this)\\s+)?(' + WD_WORD + ')',
        take: function (m) { var wd = weekdayOf(m[1]); return wd ? { date: nextWeekday(today, wd) } : null; } },
      // ── a time ──
      { kind: 'time', re: '(?:um\\s+|gegen\\s+|ab\\s+)?halb\\s+(\\d{1,2})(?:\\s*uhr)?',
        take: function (m) { var h = +m[1] - 1; return h >= 0 && h <= 23 ? { time: hhmm(h, 30) } : null; } },
      { kind: 'time', re: '(?:um\\s+|at\\s+|gegen\\s+|ab\\s+)?(\\d{1,2})(?::(\\d{2}))?\\s*(am|pm|a\\.m\\.|p\\.m\\.)',
        take: function (m) {
          var h = +m[1], mi = m[2] ? +m[2] : 0, pm = /^p/i.test(m[3]);
          if (h < 1 || h > 12 || mi > 59) return null;
          if (h === 12) h = 0;
          return { time: hhmm(pm ? h + 12 : h, mi) };
        } },
      { kind: 'time', re: '(?:um\\s+|at\\s+|gegen\\s+|ab\\s+)?(\\d{1,2})(?:[:.](\\d{2}))?\\s*(?:uhr|h|o\'clock)',
        take: function (m) { var h = +m[1], mi = m[2] ? +m[2] : 0; return h <= 23 && mi <= 59 ? { time: hhmm(h, mi) } : null; } },
      { kind: 'time', re: '(?:um\\s+|at\\s+|gegen\\s+|ab\\s+)?(\\d{1,2}):(\\d{2})',
        take: function (m) { var h = +m[1], mi = +m[2]; return h <= 23 && mi <= 59 ? { time: hhmm(h, mi) } : null; } },
      { kind: 'time', re: '(?:um|at|gegen)\\s+(\\d{1,2})',
        take: function (m) { var h = +m[1]; return h <= 23 ? { time: hhmm(h, 0) } : null; } },
      { kind: 'time', re: '(' + DP + ')', take: function (m) { return { time: dayPart[m[1].toLowerCase().replace(/\s+/g, ' ')] || null, soft: true }; } },
      // ── important ──
      { kind: 'important', re: 'wichtig|dringend|important|urgent', take: function () { return { important: true }; } },
      { kind: 'important', re: '!{1,3}', bare: true, take: function () { return { important: true }; } },
    ];
  }

  function blank(s, start, end) { return s.slice(0, start) + new Array(end - start + 1).join(' ') + s.slice(end); }

  function matchList(name, lists) {
    var n = norm(name);
    var exact = lists.filter(function (l) { return norm(l.name) === n; });
    if (exact.length) return exact[0];
    var pre = lists.filter(function (l) { return norm(l.name).indexOf(n) === 0; });
    return pre.length === 1 ? pre[0] : null;
  }
  function matchPerson(name, people) {
    var n = norm(name);
    for (var i = 0; i < people.length; i++) {
      var p = people[i];
      var words = String(p.name || '').split(/\s+/);
      if (norm(p.name) === n) return p;
      for (var j = 0; j < words.length; j++) if (norm(words[j]) === n) return p;
    }
    var pre = people.filter(function (p) { return norm(p.name).indexOf(n) === 0 || String(p.name || '').split(/\s+/).some(function (w) { return norm(w).indexOf(n) === 0; }); });
    return pre.length === 1 ? pre[0] : null;
  }

  function parse(text, ctxIn) {
    var ctx = ctxIn || {};
    if (!R || R.toDays(ctx.today) == null) throw new Error('quickparse: ctx.today (YYYY-MM-DD) is required');
    var src = String(text == null ? '' : text).normalize('NFC').replace(/[\u0000-\u001f\u007f]/g, ' ');
    var times = {};
    Object.keys(DEFAULT_TIMES).forEach(function (k) { times[k] = (ctx.times && /^\d{2}:\d{2}$/.test(ctx.times[k] || '')) ? ctx.times[k] : DEFAULT_TIMES[k]; });
    var c = { today: ctx.today, times: times };
    var work = src;
    var out = { title: '', date: null, time: null, remind: null, important: false, list: null, listName: null, assignee: null, assigneeName: null, repeat: null, marks: [] };
    var softTime = false;

    // #list and @person first (their words are never dates)
    var tagRe = new RegExp('(?:^|(?<=[\\s,;(]))([#@])(' + L + '[\\p{L}\\p{N}_\\-&+.]*' + L + '|' + L + ')', 'gu');
    var m;
    var found = [];
    while ((m = tagRe.exec(work))) found.push({ start: m.index, end: m.index + m[0].length, sign: m[1], name: m[2] });
    found.forEach(function (f) {
      if (f.sign === '#' && out.listName == null) {
        out.listName = f.name;
        out.list = matchList(f.name, ctx.lists || []);
        if (out.list) out.listName = null;
        out.marks.push({ start: f.start, end: f.end, kind: 'list' });
        work = blank(work, f.start, f.end);
      } else if (f.sign === '@' && out.assigneeName == null && !out.assignee) {
        out.assignee = matchPerson(f.name, ctx.people || []);
        out.assigneeName = out.assignee ? null : f.name;
        out.marks.push({ start: f.start, end: f.end, kind: 'person' });
        work = blank(work, f.start, f.end);
      }
    });
    if (out.list) out.list = { id: out.list.id, name: out.list.name };
    if (out.assignee) out.assignee = { id: out.assignee.id, name: out.assignee.name };

    rules(c).forEach(function (r) {
      var re = new RegExp((r.bare ? '(?<![\\p{L}\\p{N}!])' : B) + '(?:' + r.re + ')' + (r.bare ? '(?![\\p{L}\\p{N}!])' : E), 'giu');
      var mm;
      re.lastIndex = 0;
      while ((mm = re.exec(work))) {
        if (!mm[0].trim()) { re.lastIndex++; continue; }
        if (r.kind === 'date' && out.date) break;
        if (r.kind === 'time' && out.time && !softTime) break;
        if (r.kind === 'repeat' && out.repeat) break;
        if (r.kind === 'important' && out.important) { work = blank(work, mm.index, mm.index + mm[0].length); out.marks.push({ start: mm.index, end: mm.index + mm[0].length, kind: 'important' }); continue; }
        var got = r.take(mm);
        if (!got) continue;
        if (got.time && r.kind === 'time' && out.time && softTime && got.soft) continue;
        if (got.repeat) out.repeat = got.repeat;
        if (got.date) out.date = got.date;
        // a time of a word („morgen früh“, „abends“) gives way to a written one („morgen früh 7 Uhr“)
        if (got.time && (!out.time || softTime)) { out.time = got.time; softTime = !!got.soft || r.kind === 'date'; }
        if (got.important) out.important = true;
        out.marks.push({ start: mm.index, end: mm.index + mm[0].length, kind: r.kind });
        work = blank(work, mm.index, mm.index + mm[0].length);
        if (r.kind !== 'important') break;
      }
    });

    if (out.repeat) {
      if (out.repeat.type === 'weekly' && !out.repeat.days) out.repeat.days = [R.weekday(out.date || ctx.today)];
      out.repeat = R.normalize(out.repeat);
      if (out.repeat && !out.date) out.date = out.repeat.type === 'after' ? ctx.today : R.first(out.repeat, ctx.today);
    }
    if (out.time && !out.date) {
      // a time alone: today, or tomorrow when that time is over (ctx.now 'HH:MM', optional)
      out.date = ctx.now && /^\d{2}:\d{2}$/.test(ctx.now) && out.time <= ctx.now ? R.addDays(ctx.today, 1) : ctx.today;
    }
    if (out.date && out.time) out.remind = { date: out.date, time: out.time };

    out.title = work.replace(/\s+/g, ' ')
      .replace(/\s+([,;:.!?])/g, '$1')
      .replace(/([,;:])(?=[,;:])/g, '')
      .replace(/^[\s,;:\-–—]+|[\s,;:\-–—]+$/g, '')
      .replace(/\s*,\s*,+/g, ',')
      .trim();
    out.marks.sort(function (a, b) { return a.start - b.start; });
    return out;
  }

  return { parse: parse, DEFAULT_TIMES: DEFAULT_TIMES };
}));
