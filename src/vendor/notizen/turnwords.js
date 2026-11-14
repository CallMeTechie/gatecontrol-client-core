/*
 * 1.6.0 — whose turn: what a line of the quick entry says about several people and stars. Applied AFTER
 * ui/quickparse.js (which stays as it is and takes the first „@Name“): deterministic, no AI — the same in the server
 * (POST parse, POST tasks { text }), the portal and (ported 1:1) the apps; test/vectors/turnwords.json holds the cases
 * every port must pass.
 *
 *   apply(parsed, ctx) → { title, people, turn, stars }
 *     parsed: the result of quickparse.parse (title, assignee, assigneeName); ctx: { people?: [{ id, name }], stars?: bool }
 *     people  [{ id, name }] — the person quickparse took and every further „@Name“ of the title that names one of
 *             ctx.people (in the order written, nobody twice); a further „@Name“ nobody matches stays in the title
 *     turn    'rotate' („reihum“, „abwechselnd“, „in turns“, „taking turns“) | 'first' („wer zuerst“, „whoever is
 *             first“, „whoever first“) | null — only with at least two people; with fewer the word stays in the title
 *     stars   1 … 10 („2 Sterne“, „1 Stern“, „3 stars“, „1 star“) | null — only with ctx.stars (the person may give
 *             stars: a parent of the family, GET me familyTasks.parent and .stars); a number outside stays in the title
 *     title   what is left (white space folded, commas tidied as quickparse does)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GCTurnWords = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var L = '[\\p{L}\\p{N}]';
  var B = '(?<!' + L + ')';
  var E = '(?!' + L + ')';
  var ROTATE = 'reihum|abwechselnd|in turns|taking turns';
  var FIRST = 'wer zuerst|whoever is first|whoever first';

  function norm(s) { return String(s || '').toLowerCase().normalize('NFC').replace(/[\s_\-–—.]+/g, ''); }
  function blank(s, start, end) { return s.slice(0, start) + new Array(end - start + 1).join(' ') + s.slice(end); }

  // the same person quickparse would find
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

  function apply(parsed, ctxIn) {
    var ctx = ctxIn || {};
    var all = ctx.people || [];
    var work = String((parsed && parsed.title) || '');
    var people = [];
    if (parsed && parsed.assignee) people.push({ id: parsed.assignee.id, name: parsed.assignee.name });
    var took = false;
    var has = function (id) { return people.some(function (p) { return p.id === id; }); };

    var tagRe = new RegExp('(?:^|(?<=[\\s,;(]))@(' + L + '[\\p{L}\\p{N}_\\-&+.]*' + L + '|' + L + ')', 'gu');
    var m;
    var found = [];
    while ((m = tagRe.exec(work))) found.push({ start: m.index, end: m.index + m[0].length, name: m[1] });
    found.forEach(function (f) {
      var p = matchPerson(f.name, all);
      if (!p) return;
      if (!has(p.id)) people.push({ id: p.id, name: p.name });
      work = blank(work, f.start, f.end);
      took = true;
    });

    var stars = null;
    var sm = ctx.stars !== true ? null : new RegExp(B + '(\\d{1,2})\\s*(?:sterne|stern|stars|star)' + E, 'iu').exec(work);
    if (sm && Number(sm[1]) >= 1 && Number(sm[1]) <= 10) { stars = Number(sm[1]); work = blank(work, sm.index, sm.index + sm[0].length); took = true; }

    var turn = null;
    if (people.length > 1) {
      var fm = new RegExp(B + '(?:' + FIRST + ')' + E, 'iu').exec(work);
      var rm = new RegExp(B + '(?:' + ROTATE + ')' + E, 'iu').exec(work);
      if (fm && (!rm || fm.index < rm.index)) { turn = 'first'; work = blank(work, fm.index, fm.index + fm[0].length); took = true; }
      else if (rm) { turn = 'rotate'; work = blank(work, rm.index, rm.index + rm[0].length); took = true; }
    }

    // nothing taken: the title is quickparse's, untouched
    if (!took) return { title: String((parsed && parsed.title) || ''), people: people, turn: null, stars: null };
    var title = work.replace(/\s+/g, ' ')
      .replace(/\s+([,;:.!?])/g, '$1')
      .replace(/([,;:])(?=[,;:])/g, '')
      .replace(/^[\s,;:\-–—]+|[\s,;:\-–—]+$/g, '')
      .replace(/\s*,\s*,+/g, ',')
      .trim();
    return { title: title, people: people, turn: turn, stars: stars };
  }

  return { apply: apply, ROTATE: ROTATE.split('|'), FIRST: FIRST.split('|') };
}));
