/*
 * Synology DS Note / Note Station export (.nsx) — read on the device, never uploaded as a whole: window.NotesNsx.
 * Shared by the portal and (ported) the apps; test/nsx.test.js reads test/fixtures/sample.nsx with it.
 *
 * An .nsx file is a ZIP (stored or deflated entries, ZIP64 for large exports):
 *   config.json            { "note": [noteId…], "notebook": [notebookId…], … }
 *   <notebookId>           JSON { "title", "ctime", "mtime", … }
 *   <noteId>               JSON { "title", "parent_id" (its notebook), "content" (HTML), "ctime", "mtime" (seconds),
 *                                 "tag": [..], "attachment": { <key>: { "md5", "name", "type"?, "size", "ref"? } },
 *                                 "encrypt": true|false, … }
 *   file_<md5>             the bytes of an attachment; a picture in the text is
 *                          <img class="syno-notestation-image-object" … ref="<attachment ref>">
 *
 *   open(read, size, { inflateRaw }) → Archive { entries, has(name), json(name), bytes(name), size(name) }
 *     read(start, endExclusive) → Promise<Uint8Array>  (a File: file.slice(a, b).arrayBuffer())
 *     inflateRaw(bytes) → Promise<Uint8Array>          (browser: DecompressionStream('deflate-raw'); Node: zlib)
 *   summary(archive) → { notebooks: [{ id, title, notes, protected }], notes, protectedNotes, attachments, bytes }
 *   note(archive, id) → { id, notebookId, title, created, updated, tags, encrypted, html, attachments: [{ key, md5, name,
 *                         mime, size, ref, entry }] }
 *   toMarkdown(html, { image(ref) → 'att:<id>' | null }) → Markdown of the note (notemd.js)
 *   decrypt(cipherText, password) → Promise<string>  — a protected note's content, if it is in the CryptoJS / OpenSSL
 *     passphrase form ("U2FsdGVkX1…": "Salted__" ‖ salt (8) ‖ AES-256-CBC, key and IV by EVP_BytesToKey with MD5, one
 *     round). DS Note does not document its format; anything else (or a wrong password) → Error code 'decrypt' — the
 *     import then skips that note with a hint (README "Umzug aus DS Note").
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NotesNsx = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function err(code, msg) { var e = new Error(msg || code); e.code = code; return e; }
  var utf8 = new TextDecoder('utf-8');

  // ── ZIP ─────────────────────────────────────────────

  function dv(b) { return new DataView(b.buffer, b.byteOffset, b.byteLength); }
  function u64(v, o) { return v.getUint32(o, true) + v.getUint32(o + 4, true) * 4294967296; }

  /** The central directory → [{ name, method, csize, size, offset }]. */
  function open(read, size, opts) {
    var o = opts || {};
    if (typeof read !== 'function' || !(size > 22)) return Promise.reject(err('invalid', 'not a zip file'));
    var tail = Math.min(size, 65557 + 20);
    return read(size - tail, size).then(function (t) {
      var v = dv(t);
      var at = -1;
      for (var i = t.length - 22; i >= 0; i--) if (v.getUint32(i, true) === 0x06054b50) { at = i; break; }
      if (at < 0) throw err('invalid', 'not a zip file');
      var count = v.getUint16(at + 10, true);
      var cdSize = v.getUint32(at + 12, true);
      var cdOff = v.getUint32(at + 16, true);
      // ZIP64: the locator right before the end record
      if ((cdOff === 0xffffffff || count === 0xffff) && at >= 20 && v.getUint32(at - 20, true) === 0x07064b50) {
        var eocd64 = u64(v, at - 12);
        return read(eocd64, eocd64 + 56).then(function (z) {
          var zv = dv(z);
          if (zv.getUint32(0, true) !== 0x06064b50) throw err('invalid', 'bad zip64 record');
          return dir(read, u64(zv, 48), u64(zv, 40), u64(zv, 32), o);
        });
      }
      return dir(read, cdOff, cdSize, count, o);
    });
  }

  function dir(read, off, len, count, o) {
    if (len > 64 * 1024 * 1024) throw err('invalid', 'zip directory too large');
    return read(off, off + len).then(function (d) {
      var v = dv(d);
      var entries = Object.create(null);
      var list = [];
      var p = 0;
      for (var n = 0; n < count && p + 46 <= d.length; n++) {
        if (v.getUint32(p, true) !== 0x02014b50) throw err('invalid', 'bad zip directory');
        var method = v.getUint16(p + 10, true);
        var csize = v.getUint32(p + 20, true);
        var size = v.getUint32(p + 24, true);
        var nl = v.getUint16(p + 28, true), xl = v.getUint16(p + 30, true), cl = v.getUint16(p + 32, true);
        var lho = v.getUint32(p + 42, true);
        var name = utf8.decode(d.subarray(p + 46, p + 46 + nl));
        // ZIP64 extra field (0x0001): the fields that are 0xffffffff, in this order
        var x = p + 46 + nl, xe = x + xl;
        while (x + 4 <= xe) {
          var id = v.getUint16(x, true), l = v.getUint16(x + 2, true), q = x + 4;
          if (id === 1) {
            if (size === 0xffffffff) { size = u64(v, q); q += 8; }
            if (csize === 0xffffffff) { csize = u64(v, q); q += 8; }
            if (lho === 0xffffffff) { lho = u64(v, q); q += 8; }
          }
          x += 4 + l;
        }
        var e = { name: name, method: method, csize: csize, size: size, offset: lho };
        entries[name] = e;
        list.push(e);
        p += 46 + nl + xl + cl;
      }
      return archive(read, entries, list, o);
    });
  }

  function archive(read, entries, list, o) {
    function bytes(name) {
      var e = entries[name];
      if (!e) return Promise.reject(err('not_found', 'no entry ' + name));
      return read(e.offset, e.offset + 30).then(function (h) {
        var v = dv(h);
        if (v.getUint32(0, true) !== 0x04034b50) throw err('invalid', 'bad local header');
        var start = e.offset + 30 + v.getUint16(26, true) + v.getUint16(28, true);
        return read(start, start + e.csize);
      }).then(function (raw) {
        if (e.method === 0) return raw;
        if (e.method !== 8) throw err('unsupported', 'zip method ' + e.method);
        if (typeof o.inflateRaw !== 'function') throw err('unsupported', 'no inflate');
        return o.inflateRaw(raw);
      });
    }
    return {
      entries: list,
      has: function (n) { return !!entries[n]; },
      size: function (n) { return entries[n] ? entries[n].size : 0; },
      bytes: bytes,
      json: function (n) {
        if (entries[n] && entries[n].size > 32 * 1024 * 1024) return Promise.reject(err('too_large', n));
        return bytes(n).then(function (b) { try { return JSON.parse(utf8.decode(b)); } catch (e) { throw err('invalid', 'bad JSON in ' + n); } });
      },
    };
  }

  // ── the export ──────────────────────────────────────

  var ids = function (v) { return Array.isArray(v) ? v.filter(function (x) { return typeof x === 'string' && x; }) : []; };
  var secs = function (v) { var n = Number(v); return Number.isFinite(n) && n > 0 ? Math.round(n < 1e11 ? n * 1000 : n) : null; };
  var MIME = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', heic: 'image/heic', pdf: 'application/pdf', txt: 'text/plain' };

  function mimeOf(a) {
    if (a && typeof a.type === 'string' && /^[a-z]+\/[A-Za-z0-9.+-]+$/.test(a.type)) return a.type;
    var m = /\.([a-z0-9]{1,5})$/i.exec(String((a && a.name) || ''));
    return (m && MIME[m[1].toLowerCase()]) || 'application/octet-stream';
  }

  function note(arc, id) {
    return arc.json(id).then(function (n) {
      var atts = [];
      var raw = n && n.attachment && typeof n.attachment === 'object' ? n.attachment : {};
      Object.keys(raw).forEach(function (k) {
        var a = raw[k] || {};
        var md5 = typeof a.md5 === 'string' ? a.md5 : '';
        atts.push({ key: k, md5: md5, name: String(a.name || 'Anhang').slice(0, 200), mime: mimeOf(a), size: Number(a.size) || arc.size('file_' + md5),
          ref: typeof a.ref === 'string' ? a.ref : null, entry: arc.has('file_' + md5) ? 'file_' + md5 : null });
      });
      return {
        id: id, notebookId: typeof n.parent_id === 'string' ? n.parent_id : null, title: String(n.title || '').slice(0, 300),
        created: secs(n.ctime), updated: secs(n.mtime) || secs(n.ctime), tags: ids(n.tag).map(function (t) { return t.slice(0, 40); }),
        encrypted: n.encrypt === true || n.encrypt === 1, html: typeof n.content === 'string' ? n.content : '', attachments: atts,
      };
    });
  }

  function summary(arc) {
    return arc.json('config.json').then(function (cfg) {
      var nbIds = ids(cfg && cfg.notebook);
      var noteIds = ids(cfg && cfg.note);
      var books = {};
      return Promise.all(nbIds.map(function (id) {
        return arc.has(id) ? arc.json(id).then(function (b) { books[id] = { id: id, title: String((b && b.title) || '').slice(0, 120) || 'Notizbuch', notes: 0, protected: 0 }; }) : null;
      })).then(function () {
        var out = { notebooks: [], notes: 0, protectedNotes: 0, attachments: 0, bytes: 0, noteIds: [] };
        var i = 0;
        function next() {
          if (i >= noteIds.length) {
            out.notebooks = nbIds.map(function (id) { return books[id]; }).filter(Boolean);
            return out;
          }
          var id = noteIds[i++];
          if (!arc.has(id)) return next();
          return note(arc, id).then(function (n) {
            out.notes++;
            out.noteIds.push(id);
            var b = books[n.notebookId] || (books[n.notebookId || '_'] = books[n.notebookId || '_'] || { id: n.notebookId || '_', title: 'DS Note', notes: 0, protected: 0 });
            if (nbIds.indexOf(b.id) < 0) nbIds.push(b.id);
            b.notes++;
            if (n.encrypted) { out.protectedNotes++; b.protected++; }
            n.attachments.forEach(function (a) { if (a.entry) { out.attachments++; out.bytes += a.size || 0; } });
            return next();
          });
        }
        return next();
      });
    });
  }

  // ── HTML → Markdown ─────────────────────────────────

  var ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', auml: 'ä', ouml: 'ö', uuml: 'ü', Auml: 'Ä', Ouml: 'Ö', Uuml: 'Ü', szlig: 'ß', euro: '€', ndash: '–', mdash: '—', hellip: '…', laquo: '«', raquo: '»', bdquo: '„', ldquo: '“', rdquo: '”' };
  function decode(s) {
    return String(s).replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, function (all, e) {
      if (e[0] === '#') { var c = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return c > 0 && c < 0x110000 ? String.fromCodePoint(c) : ''; }
      return Object.prototype.hasOwnProperty.call(ENT, e) ? ENT[e] : all;
    });
  }
  function attr(tag, name) {
    var m = new RegExp('\\s' + name + '\\s*=\\s*("([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(tag);
    return m ? decode(m[2] != null ? m[2] : m[3] != null ? m[3] : m[4]) : null;
  }
  function mdEscape(s) { return s.replace(/([\\`*_[\]|])/g, '\\$1').replace(/^(#{1,6}\s|>|[-+*]\s|\d+[.)]\s)/, '\\$1'); }

  /** The text of a DS Note (HTML) → Markdown. Tolerant: unknown tags are dropped, their text kept. */
  function toMarkdown(html, opts) {
    var o = opts || {};
    var tokens = String(html || '').replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style)[\s\S]*?<\/\1\s*>/gi, '').split(/(<[^>]{0,4000}>)/);
    var out = [];
    var line = '';
    var lists = [];
    var href = null;
    var linkText = '';
    var table = null;
    var cell = null;
    var checked = null;
    function push(s) { if (cell) cell.push(s); else if (href != null) linkText += s; else line += s; }
    function endLine() {
      var l = line.replace(/[ \t]+$/, '');
      if (l.trim()) out.push(l);
      line = '';
    }
    function block() { endLine(); if (out.length && out[out.length - 1] !== '') out.push(''); }
    tokens.forEach(function (tk) {
      if (!tk) return;
      if (tk[0] !== '<') { var t = decode(tk).replace(/\s+/g, ' '); if (t) push(line || cell ? mdEscape(t) : mdEscape(t.replace(/^\s+/, ''))); return; }
      var m = /^<\s*(\/?)\s*([a-z0-9]+)/i.exec(tk);
      if (!m) return;
      var close = !!m[1];
      var tag = m[2].toLowerCase();
      if (/^h[1-6]$/.test(tag)) { if (close) { block(); } else { block(); line = new Array(Math.min(3, +tag[1]) + 1).join('#') + ' '; } return; }
      switch (tag) {
        case 'br': if (cell) cell.push(' '); else { endLine(); } return;
        case 'p': case 'div': if (!cell) { if (close) endLine(); else if (line.trim()) endLine(); } return;
        case 'b': case 'strong': push('**'); return;
        case 'i': case 'em': push('*'); return;
        case 's': case 'strike': case 'del': push('~~'); return;
        case 'code': push('`'); return;
        case 'hr': block(); out.push('---'); out.push(''); return;
        case 'ul': case 'ol':
          if (close) { lists.pop(); if (!lists.length) block(); } else { if (!lists.length) block(); else endLine(); lists.push({ tag: tag, n: 0, check: /checklist|todo/i.test(attr(tk, 'class') || '') }); }
          return;
        case 'li':
          if (close) { endLine(); return; }
          endLine();
          var cur = lists[lists.length - 1] || { tag: 'ul', n: 0 };
          cur.n++;
          var pad = new Array(Math.max(0, lists.length - 1) * 2 + 1).join(' ');
          var cls = attr(tk, 'class') || '';
          checked = cur.check || /check/i.test(cls) ? /checked|done/i.test(cls) : null;
          line = pad + (cur.tag === 'ol' ? cur.n + '. ' : '- ') + (checked != null ? '[' + (checked ? 'x' : ' ') + '] ' : '');
          return;
        case 'input':
          if (/type\s*=\s*["']?checkbox/i.test(tk)) {
            var on = /\schecked/i.test(tk);
            if (/^(\s*)[-\d.]+\s(\[[ x]\]\s)?$/.test(line)) line = line.replace(/\[[ x]\]\s$/, '').replace(/\s*$/, ' ') + '[' + (on ? 'x' : ' ') + '] ';
            else { endLine(); line = '- [' + (on ? 'x' : ' ') + '] '; }
          }
          return;
        case 'a':
          if (close) { if (href != null) { var u = href; href = null; var txt = linkText.trim(); linkText = ''; push(/^(https?:|mailto:)/i.test(u) ? '[' + (txt || u) + '](' + u.replace(/[()\s]/g, encodeURIComponent) + ')' : txt); } }
          else { href = attr(tk, 'href') || ''; linkText = ''; }
          return;
        case 'img':
          var ref = attr(tk, 'ref');
          var target = ref && o.image ? o.image(ref) : null;
          var alt = attr(tk, 'alt') || 'Bild';
          if (target) push('![' + mdEscape(alt) + '](' + target + ')');
          return;
        case 'table': if (close) { if (table) { flushTable(); } table = null; } else { block(); table = []; } return;
        case 'tr': if (table && !close) table.push([]); return;
        case 'td': case 'th':
          if (!table) return;
          if (close) { if (cell) { table[table.length - 1].push(cell.join('').replace(/\s+/g, ' ').trim()); cell = null; } }
          else { if (!table.length) table.push([]); cell = []; }
          return;
        default: return;
      }
    });
    function flushTable() {
      var rows = table.filter(function (r) { return r.length; });
      if (!rows.length) return;
      var w = rows.reduce(function (n, r) { return Math.max(n, r.length); }, 0);
      var fmt = function (r) { var c = []; for (var i = 0; i < w; i++) c.push(r[i] || ''); return '| ' + c.join(' | ') + ' |'; };
      out.push(fmt(rows[0]));
      out.push('|' + new Array(w + 1).join(' --- |'));
      rows.slice(1).forEach(function (r) { out.push(fmt(r)); });
      out.push('');
    }
    endLine();
    while (out.length && out[out.length - 1] === '') out.pop();
    var md = out.join('\n').replace(/\*\*\s*\*\*/g, '').replace(/\n{3,}/g, '\n\n');
    return md;
  }

  // ── protected notes ─────────────────────────────────

  // MD5 (RFC 1321) — only for OpenSSL's EVP_BytesToKey of a protected note (WebCrypto has no MD5)
  function md5(bytes) {
    var K = new Int32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    for (var i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
    var n = bytes.length;
    var words = ((n + 8) >>> 6) + 1;
    var X = new Int32Array(words * 16);
    for (i = 0; i < n; i++) X[i >> 2] |= bytes[i] << ((i % 4) * 8);
    X[n >> 2] |= 0x80 << ((n % 4) * 8);
    X[words * 16 - 2] = (n * 8) | 0;
    X[words * 16 - 1] = Math.floor(n / 536870912) | 0;
    var a = 0x67452301, b = 0xefcdab89 | 0, c = 0x98badcfe | 0, d = 0x10325476;
    for (var j = 0; j < X.length; j += 16) {
      var A = a, Bb = b, Cc = c, D = d;
      for (i = 0; i < 64; i++) {
        var f, g;
        if (i < 16) { f = (Bb & Cc) | (~Bb & D); g = i; }
        else if (i < 32) { f = (D & Bb) | (~D & Cc); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = Bb ^ Cc ^ D; g = (3 * i + 5) % 16; }
        else { f = Cc ^ (Bb | ~D); g = (7 * i) % 16; }
        var s = S[(i >> 4) * 4 + (i % 4)];
        var t = (A + f + K[i] + X[j + g]) | 0;
        A = D; D = Cc; Cc = Bb;
        Bb = (Bb + ((t << s) | (t >>> (32 - s)))) | 0;
      }
      a = (a + A) | 0; b = (b + Bb) | 0; c = (c + Cc) | 0; d = (d + D) | 0;
    }
    var out = new Uint8Array(16);
    [a, b, c, d].forEach(function (w, k) { for (var q = 0; q < 4; q++) out[k * 4 + q] = (w >>> (q * 8)) & 255; });
    return out;
  }

  function b64dec(s) {
    var bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }

  function decrypt(cipherText, password) {
    var s = String(cipherText || '').replace(/\s+/g, '');
    var subtle = (typeof crypto !== 'undefined' && crypto.subtle) || null;
    if (!subtle) return Promise.reject(err('unsupported', 'no WebCrypto'));
    if (!/^U2FsdGVkX1[A-Za-z0-9+/=]+$/.test(s)) return Promise.reject(err('decrypt', 'unknown format'));
    var raw;
    try { raw = b64dec(s); } catch (e) { return Promise.reject(err('decrypt', 'bad base64')); }
    if (raw.length < 32 || (raw.length - 16) % 16) return Promise.reject(err('decrypt', 'bad length'));
    var salt = raw.subarray(8, 16);
    var pw = new TextEncoder().encode(String(password || ''));
    var dk = new Uint8Array(0), prev = new Uint8Array(0);
    while (dk.length < 48) { prev = md5(concat(concat(prev, pw), salt)); dk = concat(dk, prev); }
    return subtle.importKey('raw', dk.subarray(0, 32), { name: 'AES-CBC' }, false, ['decrypt'])
      .then(function (k) { return subtle.decrypt({ name: 'AES-CBC', iv: dk.subarray(32, 48) }, k, raw.subarray(16)); })
      .then(function (pt) { return new TextDecoder('utf-8', { fatal: true }).decode(pt); }, function () { throw err('decrypt', 'wrong password'); })
      .catch(function (e) { throw e && e.code === 'decrypt' ? e : err('decrypt', 'wrong password'); });
  }

  return { open: open, summary: summary, note: note, toMarkdown: toMarkdown, decrypt: decrypt, md5: md5 };
}));
