'use strict';

// A fake GateControl server with the plugin gatecontrol-mail (client API "C2" of the Mail contract) for the
// MailService tests: the plugin list, me / settings / providers / discover, accounts (password, Microsoft code
// with PKCE checked against the verifier, change, remove), folders, lists with a cursor (Relevant / Sonstige,
// Alle Posteingänge), search, threads, a mail (HTML with img/<token> and cid:, imagesBlocked), the image proxy
// img/<token> and cid/<m>/<a> (PNG, client sign-in required), flags / move / archive / delete / junk / tab,
// attachments as media, drafts (reply filled by the server), send with undo / sendAt, outbox, contacts, AI,
// Drive suggest / save / save-all, filing, and the core media routes (PUT, GET).
//
//   const srv = await mailServer({ plugin, allowed, features });
//   srv.url, srv.state (requests, accounts, messages, drafts, outbox, media, uploads, …),
//   srv.state.fail = { '<METHOD> <route>': { status, code, … } } — refuse a route with { error: { code, … } },
//   srv.down = true — every request fails (connection closed), srv.close()

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = 'gatecontrol-mail';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
const DAY = 24 * 60 * 60 * 1000;

async function mailServer({ plugin = true, allowed = true, features = ['mail', 'ai', 'microsoft', 'drive', 'familyCalendar', 'images'], clientId = 'abcd-1234-efgh-5678', token = 'gc_token', now = Date.now() } = {}) {
  let nextId = 1000;
  const state = {
    plugin,
    allowed,
    features,
    requests: [],
    fail: {},
    media: new Map(),       // mediaId → { bytes, mime }
    uploads: [],
    settings: { threads: true, swipeLeft: 'archive', swipeRight: 'read' },
    accounts: [
      { id: 1, provider: 'gmx', email: 'max@gmx.de', name: 'Privat · GMX', color: '#F5B544', kind: 'personal', state: 'ok', error: null, push: 'relevant', ai: true, attachments: 'suggest', signature: 'Max' },
      { id: 2, provider: 'm365', email: 'max@firma.de', name: 'Firma · M365', color: '#79B8FF', kind: 'business', state: 'ok', error: null, push: 'all', ai: true, attachments: 'auto', signature: '' },
    ],
    passwords: new Map([[1, 'geheim']]),
    folders: [
      { id: 11, accountId: 1, name: 'Posteingang', path: 'INBOX', role: 'inbox', parentId: null },
      { id: 12, accountId: 1, name: 'Gesendet', path: 'Sent', role: 'sent', parentId: null },
      { id: 13, accountId: 1, name: 'Papierkorb', path: 'Trash', role: 'trash', parentId: null },
      { id: 14, accountId: 1, name: 'Archiv', path: 'Archive', role: 'archive', parentId: null },
      { id: 15, accountId: 1, name: 'Rechnungen', path: 'Archive/Rechnungen', role: null, parentId: 14 },
      { id: 21, accountId: 2, name: 'Inbox', path: 'INBOX', role: 'inbox', parentId: null },
      { id: 23, accountId: 2, name: 'Deleted', path: 'Deleted', role: 'trash', parentId: null },
      { id: 24, accountId: 2, name: 'Archive', path: 'Archive', role: 'archive', parentId: null },
    ],
    messages: new Map(),
    drafts: new Map(),
    outbox: new Map(),
    ai: new Map(),
    filing: [
      { id: 501, messageId: 101, attachmentId: 1, accountId: 1, name: 'Beitragsrechnung_2027.pdf', from: { name: 'Sportverein', address: 'kasse@verein.de' }, date: now - DAY, suggestion: { folderId: 77, areaId: 'mine', path: 'Finanzen › Mitgliedschaften', where: 'Meine Dateien › Finanzen › Mitgliedschaften', name: 'Beitragsrechnung_2027.pdf', confidence: 0.72, reason: 'ai' } },
    ],
    microsoft: [],          // { code, codeVerifier, redirectUri }
    msCodes: new Map(),     // code → challenge
    todos: [],
  };
  const addMsg = (m) => state.messages.set(m.id, {
    threadId: m.id, threadCount: 1, to: [{ name: 'Max', address: 'max@gmx.de' }], cc: [], bcc: [], replyTo: [], answered: false,
    flagged: false, hasAttachments: false, savedToDrive: false, ai: null, tab: 'relevant', unread: false, attachments: [],
    html: null, text: 'Hallo', imagesBlocked: false, trackers: 0, listUnsubscribe: null, imagesAllowed: false, ...m,
  });
  addMsg({
    id: 101, accountId: 1, folderId: 11, from: { name: 'Stadtwerke', address: 'rechnung@stadtwerke.de' }, subject: 'Ihre Rechnung November',
    snippet: 'Im Anhang finden Sie Ihre Rechnung.', date: now - 60 * 60 * 1000, unread: true, hasAttachments: true,
    html: '<p>Sehr geehrte Kundin,</p><p><img src="img/tok_logo" alt="Logo"><img src="cid:sig@stadtwerke"></p><a href="https://stadtwerke.de/portal" target="_blank" rel="noopener noreferrer">Portal</a>',
    text: 'Sehr geehrte Kundin, im Anhang finden Sie Ihre Rechnung.', imagesBlocked: true, trackers: 2,
    attachments: [
      { id: 1, name: 'Rechnung_2026_11.pdf', mime: 'application/pdf', size: 212000, inline: false, cid: null, savedTo: null, suggestion: { folderId: 77, areaId: 'mine', path: 'Finanzen › Strom', where: 'Meine Dateien › Finanzen › Strom', name: '2026-11-03 Stadtwerke Rechnung.pdf', confidence: 0.95, reason: 'learned' } },
      { id: 2, name: 'sig.png', mime: 'image/png', size: 900, inline: true, cid: '<sig@stadtwerke>', savedTo: null, suggestion: null },
    ],
    listUnsubscribe: { url: 'https://stadtwerke.de/abmelden', mail: 'mailto:abmelden@stadtwerke.de?subject=stop' },
  });
  addMsg({ id: 102, accountId: 2, folderId: 21, from: { name: 'Sabine Keller', address: 'sabine@firma.de' }, subject: 'Projektbesprechung Dienstag', snippet: 'Passt dir Dienstag 10 Uhr?', date: now - 2 * 60 * 60 * 1000, unread: true, threadId: 900, threadCount: 2 });
  addMsg({ id: 103, accountId: 2, folderId: 21, from: { name: 'Sabine Keller', address: 'sabine@firma.de' }, subject: 'Projektbesprechung', snippet: 'Erste Mail', date: now - 3 * DAY, threadId: 900, threadCount: 2 });
  addMsg({ id: 104, accountId: 1, folderId: 11, from: { name: 'Elektromarkt', address: 'news@elektromarkt.de' }, subject: 'Nur heute: 20 %', snippet: 'Newsletter', date: now - 5 * 60 * 60 * 1000, tab: 'other', unread: true });
  // a mail whose body is not in the server's copy (bodyMissing)
  addMsg({ id: 105, accountId: 2, folderId: 21, from: { name: 'Tim Brandt', address: 'tim@firma.de' }, subject: 'Alte Unterlagen', snippet: 'Inhalt fehlt', date: now - 6 * 60 * 60 * 1000, bodyMissing: true });
  // older inbox mails of account 1 (pages, the offline cache fills 30 days back)
  for (let i = 0; i < 60; i += 1) {
    addMsg({ id: 200 + i, accountId: 1, folderId: 11, from: { name: `Absender ${i}`, address: `a${i}@example.com` }, subject: `Alte Mail ${i}`, snippet: 'alt', date: now - (i + 1) * DAY });
  }
  state.ai.set(101, { status: 'done', summary: 'Rechnung über 84,20 € für Strom im Oktober, wird am 28.11. abgebucht.', todos: [{ kind: 'deadline', text: 'Abbuchung am 28.11.', date: '2026-11-28' }, { kind: 'amount', text: '84,20 €', amount: 84.2, currency: 'EUR' }], replies: [{ label: 'Danke', text: 'Danke, ist angekommen.' }] });

  const sum = (m) => ({
    id: m.id, accountId: m.accountId, folderId: m.folderId, threadId: m.threadId, threadCount: m.threadCount, from: m.from,
    to: m.to.slice(0, 3), subject: m.subject, snippet: m.snippet, date: m.date, unread: m.unread, flagged: m.flagged, answered: m.answered,
    hasAttachments: m.hasAttachments, tab: m.tab, savedToDrive: m.savedToDrive, ai: m.ai,
  });
  const full = (m) => ({
    ...sum(m), cc: m.cc, bcc: m.bcc, replyTo: m.replyTo, text: m.bodyMissing ? null : m.text, trackers: m.trackers,
    imagesBlocked: m.imagesBlocked && !m.imagesAllowed,
    html: m.bodyMissing ? null : m.html, attachments: m.attachments, listUnsubscribe: m.listUnsubscribe, bodyMissing: !!m.bodyMissing,
  });
  const inbox = (accountId) => state.folders.find((f) => f.accountId === accountId && f.role === 'inbox');
  const trash = (accountId) => state.folders.find((f) => f.accountId === accountId && f.role === 'trash');
  const archive = (accountId) => state.folders.find((f) => f.accountId === accountId && f.role === 'archive');

  function json(res, status, body) {
    const buf = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': buf.length });
    res.end(buf);
  }
  const err = (res, status, code, extra = {}) => json(res, status, { error: { code, ...extra } });

  function readBody(req) {
    return new Promise((resolve) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  function draftOut(d) {
    return { id: d.id, accountId: d.accountId, to: d.to, cc: d.cc, bcc: d.bcc, subject: d.subject, html: d.html, attachments: d.attachments.map(({ device, ...a }) => a), warnings: d.warnings };
  }

  function applyAtts(d, list) {
    const out = [];
    for (const a of list || []) {
      if (a.id) { const keep = d.attachments.find((x) => x.id === a.id); if (keep) out.push(keep); continue; }
      if (a.mediaId) {
        const m = state.media.get(a.mediaId);
        if (!m) return 'invalid';
        out.push({ id: ++nextId, name: a.name || m.name || 'datei', size: m.bytes.length, mime: m.mime, as: 'copy', device: true });
      } else if (a.messageId) {
        const msg = state.messages.get(a.messageId);
        const att = msg && msg.attachments.find((x) => x.id === a.attachmentId);
        if (!att) return 'invalid';
        out.push({ id: ++nextId, name: att.name, size: att.size, mime: att.mime, as: 'copy' });
      } else if (a.driveNodeId) {
        const big = a.driveNodeId === 9999;
        out.push({ id: ++nextId, name: big ? 'Preisliste 2027.xlsx' : `Datei ${a.driveNodeId}.pdf`, size: big ? 46e6 : 340000, mime: 'application/pdf', as: big ? 'link' : a.as, url: a.as === 'link' || big ? `https://drive.example.com/s/${a.driveNodeId}` : undefined });
        if (big && a.as === 'copy') d.warnings.push({ kind: 'too_large', text: 'Preisliste 2027.xlsx ist zu groß und wird als Link geschickt.' });
      }
    }
    d.attachments = out;
    return null;
  }

  const server = http.createServer(async (req, res) => {
    if (srv.down) { req.socket.destroy(); return; }
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const raw = await readBody(req);
    state.requests.push({ method: req.method, path: p, query: Object.fromEntries(url.searchParams), auth: req.headers['x-api-token'] || req.headers.authorization || null });
    const authed = (req.headers['x-api-token'] || '') === token || (req.headers.authorization || '') === `Bearer ${token}`;
    if (!authed) return json(res, 401, { error: 'unauthorized' });

    if (req.method === 'GET' && p === '/api/v1/client/plugins') {
      return json(res, 200, { plugins: state.plugin ? [{ id: PLUGIN, version: '1.0.0', tab: { label: 'Mail' } }] : [] });
    }
    if (!state.plugin) return json(res, 404, { error: 'not found' });

    // ── core media routes ──
    if (req.method === 'PUT' && p === MEDIA) {
      const mediaId = `m${crypto.randomBytes(8).toString('hex')}`;
      state.media.set(mediaId, { bytes: raw, mime: req.headers['content-type'] || 'application/octet-stream', device: true });
      state.uploads.push({ mediaId, bytes: raw.length });
      return json(res, 200, { mediaId, mime: req.headers['content-type'], bytes: raw.length });
    }
    if (req.method === 'GET' && p.startsWith(`${MEDIA}/`)) {
      const m = state.media.get(p.slice(MEDIA.length + 1));
      if (!m) return json(res, 404, { error: 'not found' });
      res.writeHead(200, { 'Content-Type': m.mime, 'Content-Length': m.bytes.length });
      return res.end(m.bytes);
    }

    if (!p.startsWith(API)) return json(res, 404, { error: 'not found' });
    const route = p.slice(API.length);
    const seg = route.split('/');
    let body = {};
    if (raw.length) { try { body = JSON.parse(raw.toString('utf8')); } catch { return err(res, 400, 'invalid'); } }
    const failKey = `${req.method} ${seg.map((s) => (/^\d+$/.test(s) ? ':id' : s)).join('/')}`;
    if (state.fail[failKey]) {
      const f = state.fail[failKey];
      return err(res, f.status || 409, f.code || 'failed', f.extra || {});
    }
    if (!state.allowed) return err(res, 403, 'not_allowed');

    // ── account ──
    if (req.method === 'GET' && route === 'me') {
      const byAccount = {};
      for (const a of state.accounts) byAccount[a.id] = [...state.messages.values()].filter((m) => m.accountId === a.id && m.folderId === inbox(a.id).id && m.unread).length;
      return json(res, 200, {
        features: state.features,
        limits: { accountsMax: 5, quotaBytes: 5 * 1024 ** 3, usedBytes: 123456789, retentionMonths: 12 },
        microsoft: { clientId: state.features.includes('microsoft') ? clientId : null, authority: 'https://login.microsoftonline.com/common', scopes: ['openid', 'profile', 'email', 'offline_access', 'User.Read', 'Mail.ReadWrite', 'Mail.Send'] },
        accounts: state.accounts,
        unread: { all: Object.values(byAccount).reduce((a, b) => a + b, 0), byAccount },
        settings: state.settings,
        extra: 'ignored',
      });
    }
    if (req.method === 'PUT' && route === 'settings') {
      for (const k of ['threads', 'swipeLeft', 'swipeRight']) if (body[k] !== undefined) state.settings[k] = body[k];
      return json(res, 200, { settings: state.settings });
    }
    if (req.method === 'GET' && route === 'providers') {
      return json(res, 200, [
        { id: 'm365', label: 'Microsoft 365 · outlook.com', auth: 'microsoft', hint: null, help: null },
        { id: 'gmx', label: 'GMX', auth: 'password', hint: { de: 'Bei GMX zuerst im Webmail IMAP erlauben.', en: 'Allow IMAP in GMX webmail first.' }, help: 'https://hilfe.gmx.net/pop-imap/imap/imap-serverdaten.html' },
        { id: 'gmail', label: 'Gmail', auth: 'app_password', hint: { de: 'App-Passwort (2FA nötig).', en: 'App password (needs 2FA).' }, help: 'javascript:alert(1)' },
        { id: 'imap', label: 'Andere / eigene Domain', auth: 'imap', hint: null, help: null },
        { id: 'bogus', label: 'X', auth: 'password' },
      ]);
    }
    if (req.method === 'POST' && route === 'accounts/discover') {
      return json(res, 200, { provider: 'imap', auth: 'imap', imap: { host: 'imap.example.org', port: 993, security: 'tls' }, smtp: { host: 'smtp.example.org', port: 587, security: 'starttls' }, hint: null });
    }
    if (req.method === 'POST' && route === 'accounts') {
      if (!body.email || !body.password) return err(res, 400, 'invalid');
      if (body.password === 'falsch') return err(res, 409, 'auth_failed', { hint: { de: 'Passwort prüfen.', en: 'Check the password.' } });
      if (state.accounts.length >= 5) return err(res, 403, 'limit');
      const a = { id: ++nextId, provider: body.provider, email: body.email, name: body.name || body.email, color: body.color || '#B79CFF', kind: body.kind || 'personal', state: 'syncing', error: null, push: 'relevant', ai: true, attachments: 'suggest', signature: '' };
      state.accounts.push(a);
      state.passwords.set(a.id, body.password);
      state.lastAccountBody = body;
      return json(res, 200, { account: a });
    }
    if (req.method === 'POST' && (route === 'accounts/microsoft' || /^accounts\/\d+\/microsoft$/.test(route))) {
      state.microsoft.push(body);
      const challenge = state.msCodes.get(body.code);
      const ok = challenge && crypto.createHash('sha256').update(body.codeVerifier).digest('base64url') === challenge;
      if (!ok) return err(res, 409, 'auth_failed');
      if (seg.length === 3) {
        const a = state.accounts.find((x) => x.id === Number(seg[1]));
        if (!a) return err(res, 404, 'not_found');
        a.state = 'ok';
        return json(res, 200, { account: a });
      }
      const a = { id: ++nextId, provider: 'm365', email: 'neu@firma.de', name: body.name || 'Firma', color: body.color || '#79B8FF', kind: body.kind || 'business', state: 'syncing', error: null, push: 'all', ai: true, attachments: 'suggest', signature: '' };
      state.accounts.push(a);
      return json(res, 200, { account: a });
    }
    if (seg[0] === 'accounts' && /^\d+$/.test(seg[1] || '') && seg.length === 2) {
      const a = state.accounts.find((x) => x.id === Number(seg[1]));
      if (!a) return err(res, 404, 'not_found');
      if (req.method === 'PATCH') {
        for (const k of ['name', 'color', 'kind', 'push', 'ai', 'attachments', 'signature']) if (body[k] !== undefined) a[k] = body[k];
        if (body.password) state.passwords.set(a.id, body.password);
        return json(res, 200, { account: a });
      }
      if (req.method === 'DELETE') {
        state.accounts = state.accounts.filter((x) => x !== a);
        return json(res, 200, { ok: true });
      }
    }

    // ── folders, lists ──
    if (req.method === 'GET' && route === 'folders') {
      return json(res, 200, {
        accounts: state.accounts.map((a) => ({
          accountId: a.id,
          folders: state.folders.filter((f) => f.accountId === a.id).map((f) => {
            const ms = [...state.messages.values()].filter((m) => m.folderId === f.id);
            return { id: f.id, name: f.name, path: f.path, role: f.role, parentId: f.parentId, unread: ms.filter((m) => m.unread).length, total: ms.length };
          }),
        })),
      });
    }
    if (req.method === 'GET' && route === 'messages') {
      const q = Object.fromEntries(url.searchParams);
      const box = q.box || 'all';
      let list = [...state.messages.values()];
      if (box === 'all') list = list.filter((m) => inbox(m.accountId) && m.folderId === inbox(m.accountId).id);
      else if (q.folder) list = list.filter((m) => m.accountId === Number(box) && m.folderId === Number(q.folder));
      else list = list.filter((m) => m.accountId === Number(box) && m.folderId === inbox(Number(box)).id);
      const isInbox = !q.folder || state.folders.find((f) => f.id === Number(q.folder) && f.role === 'inbox');
      const counts = { relevant: list.filter((m) => m.tab === 'relevant' && m.unread).length, other: list.filter((m) => m.tab === 'other' && m.unread).length };
      if (isInbox && (q.tab === 'relevant' || q.tab === 'other')) list = list.filter((m) => m.tab === q.tab);
      if (q.unread) list = list.filter((m) => m.unread);
      if (q.flagged) list = list.filter((m) => m.flagged);
      if (q.attachments) list = list.filter((m) => m.hasAttachments);
      list.sort((a, b) => b.date - a.date || b.id - a.id);
      if (q.before) { const [d, id] = q.before.split('.').map(Number); list = list.filter((m) => m.date < d || (m.date === d && m.id < id)); }
      const limit = Number(q.limit) || 50;
      const page = list.slice(0, limit);
      const last = page[page.length - 1];
      return json(res, 200, { items: page.map(sum), next: list.length > limit ? `${last.date}.${last.id}` : null, counts });
    }
    if (req.method === 'GET' && route === 'search') {
      const q = String(url.searchParams.get('q') || '').toLowerCase();
      const items = [...state.messages.values()].filter((m) => `${m.subject} ${m.snippet} ${m.from.name}`.toLowerCase().includes(q)).sort((a, b) => b.date - a.date);
      return json(res, 200, { items: items.slice(0, 50).map(sum), next: null, remote: items.length === 0 });
    }
    if (req.method === 'GET' && seg[0] === 'threads' && seg.length === 2) {
      const items = [...state.messages.values()].filter((m) => m.threadId === Number(seg[1])).sort((a, b) => a.date - b.date);
      return items.length ? json(res, 200, { items: items.map(full) }) : err(res, 404, 'not_found');
    }
    if (seg[0] === 'messages' && /^\d+$/.test(seg[1] || '')) {
      const m = state.messages.get(Number(seg[1]));
      if (!m) return err(res, 404, 'not_found');
      if (req.method === 'GET' && seg.length === 2) return json(res, 200, full(m));
      if (req.method === 'POST' && seg[2] === 'images') {
        if (body.allow !== 'once' && body.allow !== 'sender') return err(res, 400, 'invalid');
        m.imagesAllowed = true;
        return json(res, 200, full(m));
      }
      if (seg[2] === 'attachments' && /^\d+$/.test(seg[3] || '')) {
        const a = m.attachments.find((x) => x.id === Number(seg[3]));
        if (!a) return err(res, 404, 'not_found');
        if (req.method === 'GET' && seg.length === 4) {
          const mediaId = `att${m.id}x${a.id}`;
          state.media.set(mediaId, { bytes: Buffer.from(`%PDF-1.4 ${a.name}`), mime: a.mime });
          return json(res, 200, { mediaId, name: a.name, mime: a.mime, size: a.size });
        }
        if (req.method === 'POST' && seg[4] === 'drive' && seg[5] === 'suggest') return json(res, 200, { suggestion: a.suggestion, duplicate: false });
        if (req.method === 'POST' && seg[4] === 'drive' && seg[5] === 'save') {
          if (!state.features.includes('drive')) return err(res, 409, 'drive_unavailable');
          const where = body.folderId && body.folderId !== 77 ? 'Meine Dateien › Anderer Ordner' : (a.suggestion && a.suggestion.where) || 'Meine Dateien › Mail';
          a.savedTo = { nodeId: 4000 + a.id, where };
          m.savedToDrive = true;
          state.lastSave = body;
          return json(res, 200, { savedTo: a.savedTo });
        }
      }
      if (req.method === 'POST' && seg[2] === 'drive' && seg[3] === 'save-all') {
        const saved = [];
        const failed = [];
        for (const a of m.attachments) {
          if (a.inline) continue;
          a.savedTo = { nodeId: 4000 + a.id, where: 'Meine Dateien › Mail' };
          saved.push({ attachmentId: a.id, savedTo: a.savedTo });
        }
        failed.push({ attachmentId: 99, code: 'too_large' });
        return json(res, 200, { saved, failed });
      }
    }
    if (req.method === 'POST' && seg[0] === 'messages' && seg.length === 2) {
      const ids = Array.isArray(body.ids) ? body.ids : [];
      const ms = ids.map((id) => state.messages.get(id)).filter(Boolean);
      if (!ms.length) return err(res, 400, 'invalid');
      if (seg[1] === 'flags') {
        for (const m of ms) { if (typeof body.unread === 'boolean') m.unread = body.unread; if (typeof body.flagged === 'boolean') m.flagged = body.flagged; }
        return json(res, 200, { ok: true, items: ms.map(sum) });
      }
      if (seg[1] === 'move') { for (const m of ms) m.folderId = body.folderId; return json(res, 200, { ok: true }); }
      if (seg[1] === 'archive') { for (const m of ms) m.folderId = archive(m.accountId).id; return json(res, 200, { ok: true }); }
      if (seg[1] === 'delete') {
        for (const m of ms) { if (m.folderId === trash(m.accountId).id) state.messages.delete(m.id); else m.folderId = trash(m.accountId).id; }
        return json(res, 200, { ok: true });
      }
      if (seg[1] === 'junk') { for (const m of ms) state.messages.delete(m.id); return json(res, 200, { ok: true }); }
      if (seg[1] === 'tab') { for (const m of ms) m.tab = body.tab; return json(res, 200, { ok: true, items: ms.map(sum) }); }
    }

    // ── pictures ──
    // GET img/<token> → { mime, size, data (base64) }; ≤ 700 KB, else 413 too_large
    if (req.method === 'GET' && seg[0] === 'img' && seg.length === 2) {
      if (seg[1] === 'tok_svg') return json(res, 200, { mime: 'image/svg+xml', size: 20, data: Buffer.from('<svg onload="x()"/>').toString('base64') });
      if (seg[1] === 'tok_big') return err(res, 413, 'too_large', { max: 716800 });
      return json(res, 200, { mime: 'image/png', size: PNG.length, data: PNG.toString('base64') });
    }
    // GET cid/<m>/<a> → { mediaId, mime, size, url }; the apps load media/<mediaId>
    if (req.method === 'GET' && seg[0] === 'cid' && seg.length === 3) {
      const m = state.messages.get(Number(seg[1]));
      const a = m && m.attachments.find((x) => x.id === Number(seg[2]));
      if (!a) return err(res, 404, 'not_found');
      const mediaId = `cid${m.id}x${a.id}`;
      state.media.set(mediaId, { bytes: PNG, mime: 'image/png' });
      return json(res, 200, { mediaId, mime: 'image/png', size: PNG.length, url: `https://portal.example/signed/${mediaId}` });
    }

    // ── writing ──
    if (req.method === 'POST' && route === 'drafts') {
      const d = { id: ++nextId, accountId: body.accountId || 1, to: body.to || [], cc: body.cc || [], bcc: body.bcc || [], subject: body.subject || '', html: body.html || '', attachments: [], warnings: [] };
      if (body.mode && body.replyTo) {
        const src = state.messages.get(body.replyTo);
        if (!src) return err(res, 404, 'not_found');
        d.accountId = src.accountId;
        if (!body.to && body.mode !== 'forward') d.to = [src.from];
        if (!body.subject) d.subject = `${body.mode === 'forward' ? 'WG' : 'AW'}: ${src.subject}`;
        if (!body.html) d.html = `<p></p><blockquote>${src.text}</blockquote>`;
      }
      const bad = applyAtts(d, body.attachments || []);
      if (bad && body.attachments && body.attachments.length) return err(res, 400, bad);
      if (!d.subject) d.warnings.push({ kind: 'no_subject', text: 'Kein Betreff' });
      state.drafts.set(d.id, d);
      state.lastDraftBody = body;
      return json(res, 200, { draft: draftOut(d) });
    }
    if (seg[0] === 'drafts' && /^\d+$/.test(seg[1] || '')) {
      const d = state.drafts.get(Number(seg[1]));
      if (!d) return err(res, 404, 'not_found');
      if (req.method === 'GET' && seg.length === 2) return json(res, 200, { draft: draftOut(d) });
      if (req.method === 'DELETE' && seg.length === 2) { state.drafts.delete(d.id); return json(res, 200, { ok: true }); }
      if (req.method === 'PUT' && seg.length === 2) {
        for (const k of ['accountId', 'to', 'cc', 'bcc', 'subject', 'html']) if (body[k] !== undefined) d[k] = body[k];
        d.warnings = [];
        if (body.attachments !== undefined) {
          const bad = applyAtts(d, body.attachments);
          if (bad) return err(res, 400, bad);
        }
        const acc = state.accounts.find((x) => x.id === d.accountId);
        if (acc && (acc.provider === 'm365' || acc.provider === 'outlook') && d.attachments.some((a) => a.device)) {
          d.warnings.push({ kind: 'too_large', text: 'Microsoft-Konten können Dateien vom Gerät nicht mitsenden.' });
        }
        if (d.attachments.reduce((s, a) => s + (a.as === 'copy' ? a.size : 0), 0) > 20e6) return err(res, 413, 'too_large');
        state.lastDraftBody = body;
        return json(res, 200, { draft: draftOut(d) });
      }
      if (req.method === 'POST' && seg[2] === 'send') {
        const acc = state.accounts.find((x) => x.id === d.accountId);
        if (acc && (acc.provider === 'm365' || acc.provider === 'outlook') && d.attachments.some((a) => a.device)) return err(res, 409, 'attachments_unsupported');
        const id = ++nextId;
        const at = Date.now();
        state.outbox.set(id, { id, draftId: d.id, accountId: d.accountId, subject: d.subject, sendAt: body.sendAt || at + 10000, state: 'waiting' });
        return json(res, 200, { outboxId: id, undoUntil: at + 10000, sendAt: body.sendAt || at + 10000 });
      }
    }
    if (req.method === 'POST' && seg[0] === 'outbox' && seg[2] === 'cancel') {
      const o = state.outbox.get(Number(seg[1]));
      if (!o) return err(res, 404, 'not_found');
      state.outbox.delete(o.id);
      return json(res, 200, { draftId: o.draftId });
    }
    if (req.method === 'GET' && route === 'outbox') return json(res, 200, { items: [...state.outbox.values()] });
    if (req.method === 'GET' && route === 'contacts') {
      const q = String(url.searchParams.get('q') || '').toLowerCase();
      const all = [{ name: 'Tim Brandt', email: 'tim@firma.de', source: 'person' }, { name: 'Sabine Keller', email: 'sabine@firma.de', source: 'recent' }, { name: 'Kaputt', email: 'no-at-sign', source: 'recent' }];
      return json(res, 200, { items: all.filter((c) => `${c.name} ${c.email}`.toLowerCase().includes(q)) });
    }

    // ── AI ──
    if (seg[0] === 'ai' && /^\d+$/.test(seg[1] || '')) {
      const id = Number(seg[1]);
      if (!state.features.includes('ai')) return err(res, 409, 'ai_off');
      if (req.method === 'GET' && seg.length === 2) return json(res, 200, state.ai.get(id) || { status: 'none' });
      if (req.method === 'POST' && seg.length === 2) {
        if (state.ai.has(id) && body.again !== true) return json(res, 200, state.ai.get(id));
        state.aiRuns = (state.aiRuns || 0) + 1;
        const r = { status: 'done', summary: null, todos: [], replies: [{ label: 'OK', text: 'Passt, danke!' }] };
        state.ai.set(id, r);
        return json(res, 200, r);
      }
      if (req.method === 'POST' && seg[2] === 'todo') {
        if (!state.features.includes('familyCalendar')) return err(res, 409, 'familie_unavailable');
        state.todos.push({ id, index: Number(seg[3]), body });
        return json(res, 200, { where: 'Familienkalender · 28.11.' });
      }
    }

    // ── filing ──
    if (req.method === 'GET' && route === 'filing') return json(res, 200, { items: state.filing });
    if (req.method === 'POST' && seg[0] === 'filing' && /^\d+$/.test(seg[1] || '')) {
      const f = state.filing.find((x) => x.id === Number(seg[1]));
      if (!f) return err(res, 404, 'not_found');
      state.filing = state.filing.filter((x) => x !== f);
      if (seg[2] === 'confirm') return json(res, 200, { savedTo: { nodeId: 7001, where: body.folderId ? 'Meine Dateien › Gewählt' : f.suggestion.where } });
      return json(res, 200, { ok: true });
    }

    return err(res, 404, 'not_found');
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const srv = {
    url: `http://127.0.0.1:${server.address().port}`,
    state,
    down: false,
    /** Microsoft would answer this code for this PKCE challenge. */
    issueCode(challenge) {
      const code = `M.C${crypto.randomBytes(12).toString('hex')}`;
      state.msCodes.set(code, challenge);
      return code;
    },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
  return srv;
}

module.exports = { mailServer, PLUGIN, API, MEDIA, PNG };
