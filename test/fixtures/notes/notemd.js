/*
 * The text of a note: Markdown (CommonMark with GitHub's tables and task lists) — what every client can render with
 * its own Markdown library (Android: Markwon, Windows: markdown-it) and what stays readable as plain text. Shared by
 * the server (plain text for the search, the snippet, the counts of check boxes, the tags) and the portal (rendering,
 * ticking a box). Pure, no DOM.
 *
 * What is used of Markdown:
 *   # / ## / ### headings, paragraphs, **bold**, *italic* / _italic_, ~~strike~~, `code`, ``` code blocks ```,
 *   > quotes, - / * / + lists, 1. lists, - [ ] / - [x] check boxes, | tables | with a | --- | line, ---,
 *   [text](https://…) links (http, https, mailto only), ![name](att:<attachment id>) pictures of the note,
 *   [name](att:<id>) files of the note, [Aufgabe](task:<task id>) the task a line became, #tags in the text
 * Raw HTML is never rendered (it shows as text). Links to anything else render as text.
 *
 *   render(md, { att(id) → { url, name, mime } | null, task(id) → { label, done } | null, checkable }) → HTML
 *   plain(md) → text without marks (search, snippet)
 *   checks(md) → [{ line, text, done, task }]   line: index of the source line (0-based)
 *   toggle(md, line, done) → md with that check box set
 *   linkTask(md, line, taskId, label) → md with „[label](task:<id>)“ at the end of that line
 *   tags(md) → ['auto', 'werkstatt'] (lower case, unique, without the #)
 *   attachments(md) → [id, …] the att: ids it names
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GCNoteMd = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var CHECK_RE = /^(\s*)([-*+])\s+\[([ xX])\]\s+(.*)$/;
  var BULLET_RE = /^(\s*)([-*+])\s+(.*)$/;
  var ORDERED_RE = /^(\s*)(\d{1,9})[.)]\s+(.*)$/;
  var HEAD_RE = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
  var HR_RE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
  var FENCE_RE = /^\s{0,3}(```|~~~)/;
  var TABLE_SEP_RE = /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/;
  var TAG_RE = /(^|[\s(,;])#([\p{L}\p{N}][\p{L}\p{N}_\-]{0,40})/gu;
  var TASK_LINK_RE = /\s*\[[^\]]*\]\(task:(\d{1,12})\)/;
  var ATT_RE = /\]\(att:(\d{1,12})\)/g;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }
  function lines(md) { return String(md == null ? '' : md).replace(/\r\n?/g, '\n').split('\n'); }

  function safeUrl(u) {
    var s = String(u || '').trim();
    return /^(https?:\/\/|mailto:)[^\s<>"']+$/i.test(s) ? s : null;
  }

  /** Inline marks of one line → HTML. */
  function inline(text, o) {
    var codes = [];
    var s = String(text).replace(/`([^`\n]+)`/g, function (_, c) { codes.push(c); return '\u0000' + (codes.length - 1) + '\u0000'; });
    var parts = [];
    // links and pictures first (their text is escaped on its own)
    s = s.replace(/(!?)\[([^\]\n]{0,300})\]\(([^)\s]{1,2000})\)/g, function (all, bang, label, url) {
      var m = /^(att|task):(\d{1,12})$/.exec(url);
      var html;
      if (m && m[1] === 'att') {
        var a = o.att ? o.att(Number(m[2])) : null;
        if (!a) html = '<span class="nm-missing">' + esc(label || '') + '</span>';
        else if (bang && a.url && /^image\//.test(a.mime || '')) html = '<img class="nm-img" src="' + esc(a.url) + '" alt="' + esc(label || a.name || '') + '" loading="lazy" data-att="' + m[2] + '">';
        else html = '<a class="nm-file" href="#" data-att="' + m[2] + '">' + esc(label || a.name || '') + '</a>';
      } else if (m && m[1] === 'task') {
        var t = o.task ? o.task(Number(m[2])) : null;
        html = '<a class="nm-task' + (t && t.done ? ' is-done' : '') + '" href="#" data-task="' + m[2] + '">' + esc((t && t.label) || label || '') + '</a>';
      } else {
        var u = safeUrl(url);
        html = u && !bang ? '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(label) + '</a>' : esc(all);
      }
      parts.push(html);
      return '\u0001' + (parts.length - 1) + '\u0001';
    });
    s = esc(s);
    s = s.replace(/(^|[\s(])(https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)])/g, function (_, pre, u) {
      parts.push('<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(u) + '</a>');
      return pre + '\u0001' + (parts.length - 1) + '\u0001';
    });
    s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
      .replace(/__([^_\n]+)__/g, '<strong>$1</strong>')
      .replace(/(^|[^*\w])\*([^*\n]+)\*(?![*\w])/g, '$1<em>$2</em>')
      .replace(/(^|[^_\p{L}\p{N}])_([^_\n]+)_(?![_\p{L}\p{N}])/gu, '$1<em>$2</em>')
      .replace(/~~([^~\n]+)~~/g, '<del>$1</del>');
    s = s.replace(TAG_RE, function (_, pre, tag) { return pre + '<span class="nm-tag">#' + tag + '</span>'; });
    s = s.replace(/\u0001(\d+)\u0001/g, function (_, i) { return parts[+i]; });
    return s.replace(/\u0000(\d+)\u0000/g, function (_, i) { return '<code>' + esc(codes[+i]) + '</code>'; });
  }

  function cells(row) {
    var r = row.trim().replace(/^\|/, '').replace(/\|$/, '');
    var out = [];
    var cur = '';
    for (var i = 0; i < r.length; i++) {
      if (r[i] === '\\' && r[i + 1] === '|') { cur += '|'; i++; } else if (r[i] === '|') { out.push(cur.trim()); cur = ''; } else cur += r[i];
    }
    out.push(cur.trim());
    return out;
  }

  /** Markdown → HTML (safe: every text escaped, no raw HTML, only the links above). */
  function render(md, opts) {
    var o = opts || {};
    var ls = lines(md);
    var out = [];
    var para = [];
    var list = null; // { tag, items }
    function flushPara() { if (para.length) { out.push('<p>' + para.map(function (p) { return inline(p, o); }).join('<br>') + '</p>'); para = []; } }
    function flushList() { if (list) { out.push('<' + list.tag + (list.check ? ' class="nm-checks"' : '') + '>' + list.items.join('') + '</' + list.tag + '>'); list = null; } }
    function flush() { flushPara(); flushList(); }
    for (var i = 0; i < ls.length; i++) {
      var l = ls[i];
      var m;
      if (FENCE_RE.test(l)) {
        flush();
        var fence = FENCE_RE.exec(l)[1];
        var code = [];
        i++;
        while (i < ls.length && ls[i].trim().indexOf(fence) !== 0) code.push(ls[i++]);
        out.push('<pre><code>' + esc(code.join('\n')) + '</code></pre>');
        continue;
      }
      if (!l.trim()) { flush(); continue; }
      if ((m = HEAD_RE.exec(l))) { flush(); var lv = Math.min(m[1].length + 1, 4); out.push('<h' + lv + '>' + inline(m[2], o) + '</h' + lv + '>'); continue; }
      if (HR_RE.test(l)) { flush(); out.push('<hr>'); continue; }
      if (/^\s*>/.test(l)) {
        flush();
        var q = [];
        while (i < ls.length && /^\s*>/.test(ls[i])) q.push(ls[i++].replace(/^\s*>\s?/, ''));
        i--;
        out.push('<blockquote>' + q.map(function (x) { return inline(x, o); }).join('<br>') + '</blockquote>');
        continue;
      }
      if (l.indexOf('|') >= 0 && i + 1 < ls.length && TABLE_SEP_RE.test(ls[i + 1]) && ls[i + 1].indexOf('-') >= 0) {
        flush();
        var head = cells(l);
        i += 2;
        var rows = [];
        while (i < ls.length && ls[i].indexOf('|') >= 0 && ls[i].trim()) rows.push(cells(ls[i++]));
        i--;
        out.push('<div class="nm-table"><table><thead><tr>' + head.map(function (c) { return '<th>' + inline(c, o) + '</th>'; }).join('') + '</tr></thead><tbody>'
          + rows.map(function (r) { return '<tr>' + head.map(function (_, k) { return '<td>' + inline(r[k] || '', o) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>');
        continue;
      }
      if ((m = CHECK_RE.exec(l))) {
        flushPara();
        if (!list || !list.check) { flushList(); list = { tag: 'ul', items: [], check: true }; }
        var done = m[3] !== ' ';
        var depth = Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2));
        list.items.push('<li class="nm-check' + (done ? ' is-done' : '') + (depth ? ' nm-d' + depth : '') + '" data-line="' + i + '">'
          + '<input type="checkbox" class="nm-box" data-line="' + i + '"' + (done ? ' checked' : '') + (o.checkable ? '' : ' disabled') + ' aria-label="' + esc(m[4].replace(TASK_LINK_RE, '')) + '">'
          + '<span class="nm-ct">' + inline(m[4], o) + '</span></li>');
        continue;
      }
      if ((m = BULLET_RE.exec(l)) || (m = ORDERED_RE.exec(l))) {
        flushPara();
        var tag = /^\d/.test(m[2]) ? 'ol' : 'ul';
        if (!list || list.tag !== tag || list.check) { flushList(); list = { tag: tag, items: [] }; }
        var d2 = Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2));
        list.items.push('<li' + (d2 ? ' class="nm-d' + d2 + '"' : '') + '>' + inline(m[3], o) + '</li>');
        continue;
      }
      flushList();
      para.push(l.trim());
    }
    flush();
    return out.join('');
  }

  /** Markdown → plain text (marks removed, one line per block). */
  function plain(md) {
    var out = [];
    lines(md).forEach(function (l) {
      if (FENCE_RE.test(l) || HR_RE.test(l) || TABLE_SEP_RE.test(l) && l.indexOf('-') >= 0) return;
      var s = l.replace(HEAD_RE, '$2').replace(/^\s*>\s?/, '').replace(CHECK_RE, '$4').replace(BULLET_RE, '$3').replace(ORDERED_RE, '$3')
        .replace(/!?\[([^\]]*)\]\((?:task|att):\d+\)/g, function (all, label) { return /\]\(task:/.test(all) ? '' : label; })
        .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
        .replace(/\*\*|__|~~|`/g, '').replace(/(^|\s)[*_]([^*_]+)[*_](?=\s|$)/g, '$1$2')
        .replace(/\|/g, ' ').replace(/\s+/g, ' ').trim();
      if (s) out.push(s);
    });
    return out.join('\n');
  }

  function checks(md) {
    var out = [];
    var fenced = false;
    lines(md).forEach(function (l, i) {
      if (FENCE_RE.test(l)) { fenced = !fenced; return; }
      if (fenced) return;
      var m = CHECK_RE.exec(l);
      if (!m) return;
      var t = TASK_LINK_RE.exec(m[4]);
      out.push({ line: i, text: m[4].replace(TASK_LINK_RE, '').trim(), done: m[3] !== ' ', task: t ? Number(t[1]) : null });
    });
    return out;
  }

  function toggle(md, line, done) {
    var ls = lines(md);
    var m = ls[line] != null ? CHECK_RE.exec(ls[line]) : null;
    if (!m) return null;
    ls[line] = m[1] + m[2] + ' [' + (done ? 'x' : ' ') + '] ' + m[4];
    return ls.join('\n');
  }

  /** The text of a line without its list or check mark (a line → a task). */
  function lineText(md, line) {
    var l = lines(md)[line];
    if (l == null) return null;
    return plain(l.replace(TASK_LINK_RE, '')).replace(/\n/g, ' ').trim() || null;
  }

  function linkTask(md, line, taskId, label) {
    var ls = lines(md);
    if (ls[line] == null || !/^\d+$/.test(String(taskId))) return null;
    var lab = String(label || 'Aufgabe').replace(/[[\]()]/g, '');
    ls[line] = ls[line].replace(TASK_LINK_RE, '').replace(/\s+$/, '') + ' [' + lab + '](task:' + taskId + ')';
    return ls.join('\n');
  }

  function tags(md) {
    var out = [];
    var fenced = false;
    lines(md).forEach(function (l) {
      if (FENCE_RE.test(l)) { fenced = !fenced; return; }
      if (fenced) return;
      var s = l.replace(/^#{1,6}\s+/, ' ').replace(/`[^`]*`/g, ' ').replace(/\]\([^)]*\)/g, ']');
      var m;
      TAG_RE.lastIndex = 0;
      while ((m = TAG_RE.exec(s))) {
        var t = m[2].toLowerCase().normalize('NFC');
        if (!/^\d+$/.test(t) && out.indexOf(t) < 0) out.push(t);
      }
    });
    return out.slice(0, 50);
  }

  function attachments(md) {
    var out = [];
    var m;
    ATT_RE.lastIndex = 0;
    var s = String(md || '');
    while ((m = ATT_RE.exec(s))) { var id = Number(m[1]); if (out.indexOf(id) < 0) out.push(id); }
    return out;
  }

  return { render: render, plain: plain, checks: checks, toggle: toggle, lineText: lineText, linkTask: linkTask, tags: tags, attachments: attachments, esc: esc };
}));
