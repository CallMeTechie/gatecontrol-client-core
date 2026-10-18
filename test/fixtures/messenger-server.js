'use strict';

// A small in-memory GateControl server with the Messenger plugin
// (gatecontrol-plugins/plugins/gatecontrol-messenger README "App-API") and
// the push stream: enough of the contract for the messenger client tests.
//
//   const srv = await messengerServer({ me: 7 });   // Messenger 1.1 API (around, serverTime)
//   messengerServer({ legacy: true })               // 1.0.x: no around, no serverTime in messages
//   messengerServer({ features: ['video_meta', 'file_thumbs'] })  // 1.3.0 `GET me` features
//   srv.url, srv.state (conversations, messages, media, requests),
//   srv.event(type, data) → `event: plugin` on every open push stream,
//   srv.notify(payload) → `event: notification`, srv.fail(path, status, code),
//   srv.close()

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = 'gatecontrol-messenger';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;

const iso = (ms) => new Date(ms).toISOString();

async function messengerServer({ me = 7, plugin = true, tab = true, people = null, now = () => Date.now(), legacy = false, features = null } = {}) {
  const users = people || [
    { id: 7, name: 'Marc', initials: 'MA', colorHex: '#2FBF71', avatarUrl: null },
    { id: 8, name: 'Anna', initials: 'AN', colorHex: '#F97316', avatarUrl: '/avatars/annaAvatarFile0001.webp' },
    { id: 9, name: 'Lena', initials: 'LE', colorHex: '#F2B91B', avatarUrl: null },
  ];
  const state = {
    me,
    plugin,
    tab,
    convs: new Map(),
    msgs: new Map(),
    media: new Map(),
    nextConv: 12,
    nextMsg: 4700,
    requests: [],
    failures: new Map(),
    acks: [],
    reads: [],
    actives: [],
    typings: [],
    prefs: { readReceipts: true, typing: true, preview: true },
    delay: 0,
  };
  const streams = new Set();
  const person = (id) => {
    const u = users.find((x) => x.id === id);
    return u ? { userId: u.id, name: u.name, avatarUrl: u.avatarUrl, initials: u.initials, colorHex: u.colorHex, color: 'green', gone: false }
      : { userId: id, name: null, avatarUrl: null, initials: null, colorHex: null, color: null, gone: true };
  };

  function addConv({ kind = 'direct', members = [me, 8], title = null } = {}) {
    const id = state.nextConv++;
    const c = { id, kind, title, members: members.map((u) => ({ id: u, role: u === me ? 'admin' : 'member', lastRead: 0, lastDelivered: 0 })), createdAt: now(), updatedAt: now() };
    state.convs.set(id, c);
    state.msgs.set(id, []);
    return id;
  }

  function addMsg(convId, { senderId = 8, text = 'Hallo', kind = 'text', clientId = null, mediaId = null, meta = null, thumbMediaId = null, video = null } = {}) {
    const m = { id: state.nextMsg++, conversationId: convId, senderId, clientId, kind, text, mediaId, meta, thumbMediaId, video, createdAt: now(), changedAt: now(), editedAt: null, deleted: false, reactions: [] };
    state.msgs.get(convId).push(m);
    const c = state.convs.get(convId);
    c.updatedAt = now();
    if (senderId === me) { const mb = c.members.find((x) => x.id === me); mb.lastRead = m.id; mb.lastDelivered = m.id; }
    return m;
  }

  function msgView(m, viewer = me) {
    const c = state.convs.get(m.conversationId);
    const others = c.members.filter((x) => x.id !== viewer);
    const readUpTo = others.length ? Math.min(...others.map((x) => x.lastRead)) : null;
    const deliveredUpTo = others.length ? Math.min(...others.map((x) => x.lastDelivered)) : null;
    return {
      id: m.id, conversationId: m.conversationId, senderId: m.senderId, clientId: m.clientId, kind: m.kind, via: null, mine: m.senderId === viewer,
      createdAt: iso(m.createdAt), editedAt: m.editedAt ? iso(m.editedAt) : null, deletedAt: null, expiresAt: null, deleted: m.deleted, undecryptable: false,
      text: m.deleted ? null : m.text, replyTo: null,
      media: m.mediaId && !m.deleted ? { id: m.mediaId, mime: (state.media.get(m.mediaId) || {}).mime || null, bytes: (state.media.get(m.mediaId) || {}).data?.length || 0, url: null, thumbId: m.thumbMediaId || null, thumbUrl: null } : null,
      ...(m.video && !m.deleted ? { video: m.video } : {}),
      meta: m.deleted ? null : m.meta, location: null, system: null, reactions: m.deleted ? [] : m.reactions,
      status: m.senderId === viewer ? (m.id <= readUpTo ? 'read' : m.id <= deliveredUpTo ? 'delivered' : 'sent') : null,
    };
  }

  function convView(c, viewer = me) {
    const list = state.msgs.get(c.id).filter((m) => !m.hidden);
    const mine = c.members.find((x) => x.id === viewer);
    const others = c.members.filter((x) => x.id !== viewer);
    const last = list[list.length - 1] || null;
    const peer = c.kind === 'direct' ? person(others[0] && others[0].id) : null;
    return {
      id: c.id, kind: c.kind, title: c.kind === 'direct' ? (peer && peer.name) : c.title, peer, avatarUrl: peer ? peer.avatarUrl : null, avatarMediaId: null,
      managedBy: null, readonly: false, disappearingS: 0, createdBy: me, createdAt: iso(c.createdAt), updatedAt: iso(c.updatedAt),
      lastMessageId: last ? last.id : null,
      members: c.members.map((x) => ({ ...person(x.id), role: x.role, joinedAt: iso(c.createdAt) })),
      me: { role: mine.role, mutedUntil: null, notify: 'all', lastReadId: mine.lastRead, lastDeliveredId: mine.lastDelivered },
      muted: false,
      unread: list.filter((m) => m.senderId !== viewer && m.id > mine.lastRead && !m.deleted).length,
      lastMessage: last ? msgView(last, viewer) : null,
      typing: [],
      readUpTo: others.length ? Math.min(...others.map((x) => x.lastRead)) : null,
      deliveredUpTo: others.length ? Math.min(...others.map((x) => x.lastDelivered)) : null,
      receipts: others.map((x) => ({ userId: x.id, lastReadId: x.lastRead, lastDeliveredId: x.lastDelivered })),
      can: { send: true, editInfo: c.kind === 'group', manageMembers: c.kind === 'group', leave: c.kind === 'group', setDisappearing: true },
    };
  }

  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const err = (res, status, code) => json(res, status, { ok: false, code, error: code });

  async function readBody(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    return Buffer.concat(chunks);
  }

  async function handle(req, res) {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const q = Object.fromEntries(u.searchParams);
    const raw = await readBody(req);
    let body = null;
    if (raw.length && String(req.headers['content-type'] || '').includes('json')) { try { body = JSON.parse(raw.toString('utf8')); } catch { body = null; } }
    state.requests.push({ method: req.method, path: p, query: q, body, headers: req.headers, bytes: raw.length });
    if (state.delay) await new Promise((r) => setTimeout(r, state.delay));
    for (const [prefix, f] of state.failures) {
      if (`${req.method} ${p}`.startsWith(prefix) || p.startsWith(prefix)) {
        if (f.times != null) { f.times -= 1; if (f.times <= 0) state.failures.delete(prefix); }
        if (f.status === 0) { req.socket.destroy(); return; }
        return err(res, f.status, f.code);
      }
    }

    if (p === '/api/v1/client/push') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(`event: hello\ndata: ${JSON.stringify({ keepalive_s: 25, via: 'direct', unread: 0, topics: [], server_time: iso(now()) })}\n\n`);
      streams.add(res);
      res.on('close', () => streams.delete(res));
      return undefined;
    }
    if (p === '/api/v1/client/push/ack') { state.acks.push(body); return json(res, 200, { ok: true }); }
    if (p === '/api/v1/client/push/prefs') return json(res, 200, { ok: true });
    if (p === '/api/v1/client/push/inbox') return json(res, 200, { items: [], unread: 0 });
    if (p === '/api/v1/client/plugins') {
      return json(res, 200, { ok: true, plugins: state.plugin ? [{ id: PLUGIN, name: 'Messenger', version: '1.0.0', tab: state.tab ? { label: 'Chats', icon: 'M0 0' } : null }] : [] });
    }
    if (p.startsWith('/avatars/')) {
      res.writeHead(200, { 'Content-Type': 'image/webp' });
      return res.end(Buffer.from('RIFFxxxxWEBP'));
    }
    if (!state.plugin && (p.startsWith(API) || p.startsWith(MEDIA))) return err(res, 404, 'not_found');
    if (p === MEDIA && req.method === 'PUT') {
      if (!req.headers['content-length']) return err(res, 411, 'length_required');
      const mime = String(req.headers['content-type'] || '');
      if (!/^(image|audio|video)\/|^application\/pdf$/.test(mime)) return err(res, 415, 'unsupported_type');
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { mime, data: raw });
      return json(res, 200, { ok: true, mediaId, mime, bytes: raw.length });
    }
    if (p.startsWith(`${MEDIA}/`) && req.method === 'GET') {
      const f = state.media.get(p.slice(MEDIA.length + 1));
      if (!f) return err(res, 404, 'not_found');
      res.writeHead(200, { 'Content-Type': f.mime, 'Content-Length': f.data.length });
      return res.end(f.data);
    }
    if (!p.startsWith(API)) return err(res, 404, 'not_found');
    const seg = p.slice(API.length).split('/').filter(Boolean);
    const [a, b, c] = seg;
    const m = req.method;

    if (a === 'me' && m === 'GET') {
      return json(res, 200, { ok: true, user: { id: me, name: 'Marc', avatarUrl: null, initials: 'MA', colorHex: '#2FBF71' }, prefs: state.prefs,
        license: { licensed: true, state: 'active', expiresAt: null },
        features: features || { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false },
        limits: { maxBytes: 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400], retentionDays: 0 },
        serverTime: iso(now()) });
    }
    if (a === 'prefs' && m === 'PUT') { Object.assign(state.prefs, body || {}); return json(res, 200, { ok: true, prefs: state.prefs }); }
    if (a === 'people') return json(res, 200, { ok: true, people: users.filter((x) => x.id !== me).map((x) => ({ id: x.id, name: x.name, avatarUrl: x.avatarUrl, initials: x.initials, colorHex: x.colorHex, color: 'green' })) });
    if (a === 'conversations' && !b && m === 'GET') {
      const since = q.since ? Date.parse(q.since) : null;
      const list = [...state.convs.values()].filter((x) => !since || x.updatedAt > since).map((x) => convView(x));
      return json(res, 200, { ok: true, conversations: list, removed: [], serverTime: iso(now()) });
    }
    if (a === 'conversations' && !b && m === 'POST') {
      if (body.kind === 'direct') {
        const ex = [...state.convs.values()].find((x) => x.kind === 'direct' && x.members.some((y) => y.id === body.userIds[0]));
        if (ex) return json(res, 200, { ok: true, conversation: convView(ex), created: false });
      }
      const id = addConv({ kind: body.kind, members: [me, ...body.userIds], title: body.title || null });
      return json(res, 200, { ok: true, conversation: convView(state.convs.get(id)), created: true });
    }
    if (a === 'conversations' && b) {
      const conv = state.convs.get(Number(b));
      if (!conv) return err(res, 404, 'not_found');
      const list = state.msgs.get(conv.id);
      if (!c && m === 'GET') return json(res, 200, { ok: true, conversation: convView(conv) });
      if (!c && m === 'PATCH') {
        if (body.title) conv.title = body.title;
        if (Array.isArray(body.remove) && body.remove.includes(me)) { state.convs.delete(conv.id); return json(res, 200, { ok: true, conversation: null, left: true }); }
        conv.updatedAt = now();
        return json(res, 200, { ok: true, conversation: convView(conv), left: false });
      }
      if (c === 'messages' && m === 'GET') {
        const limit = Number(q.limit) || 50;
        let out;
        let hasMore = false;
        const vis = list.filter((x) => !x.hidden);
        const extra = {};
        if (q.before) { const older = vis.filter((x) => x.id < Number(q.before)); out = older.slice(-limit); hasMore = older.length > limit; } else if (q.after) { const newer = vis.filter((x) => x.id > Number(q.after)); out = newer.slice(0, limit); hasMore = newer.length > limit; } else if (q.around && !legacy) {
          const at = Number(q.around);
          const older = vis.filter((x) => x.id < at);
          const half = Math.floor(limit / 2);
          const before = older.slice(-half);
          const rest = vis.filter((x) => x.id >= at);
          const after = rest.slice(0, limit - before.length);
          out = before.concat(after);
          extra.hasMoreBefore = older.length > before.length;
          extra.hasMoreAfter = rest.length > after.length;
          hasMore = extra.hasMoreBefore || extra.hasMoreAfter;
        } else if (q.changedSince) { out = vis.filter((x) => x.changedAt > Date.parse(q.changedSince)); } else { out = vis.slice(-limit); hasMore = vis.length > limit; }
        const v = convView(conv);
        if (!legacy) extra.serverTime = iso(now());
        return json(res, 200, { ok: true, messages: out.map((x) => msgView(x)), hasMore, readUpTo: v.readUpTo, deliveredUpTo: v.deliveredUpTo, receipts: v.receipts, ...extra });
      }
      if (c === 'messages' && m === 'POST') {
        const dup = list.find((x) => x.clientId === body.clientId && x.senderId === me);
        if (dup) return json(res, 200, { ok: true, message: msgView(dup), duplicate: true });
        if (body.mediaId && !state.media.has(body.mediaId)) return err(res, 409, 'media_invalid');
        if (body.thumbMediaId && !state.media.has(body.thumbMediaId)) return err(res, 409, 'media_invalid');
        const msg = addMsg(conv.id, { senderId: me, text: body.text || null, kind: body.kind || 'text', clientId: body.clientId, mediaId: body.mediaId || null, meta: body.meta || null, thumbMediaId: body.thumbMediaId || null, video: body.video || null });
        return json(res, 200, { ok: true, message: msgView(msg), duplicate: false });
      }
      if (c === 'read' && m === 'POST') {
        state.reads.push({ conversationId: conv.id, upTo: body.upTo });
        const mb = conv.members.find((x) => x.id === me);
        mb.lastRead = Math.max(mb.lastRead, body.upTo);
        return json(res, 200, { ok: true, lastReadId: mb.lastRead, unread: convView(conv).unread });
      }
      if (c === 'typing') { state.typings.push({ conversationId: conv.id, body }); return json(res, 200, { ok: true, until: body && body.stop ? null : iso(now() + 6000) }); }
      if (c === 'active') { state.actives.push({ conversationId: conv.id, body }); return json(res, 200, { ok: true, until: iso(now() + 30000) }); }
      if (c === 'search') {
        if (!q.q || q.q.length < 2) return err(res, 400, 'invalid');
        return json(res, 200, { ok: true, results: list.filter((x) => (x.text || '').includes(q.q)).reverse().map((x) => msgView(x)), scanned: list.length, truncated: false });
      }
      if (c === 'media') {
        const isVideo = (x) => /^video\//.test((state.media.get(x.mediaId) || {}).mime || '');
        const withMedia = list.filter((x) => x.mediaId && !x.deleted);
        const kinds = { image: (x) => x.kind === 'image', voice: (x) => x.kind === 'voice', file: (x) => x.kind === 'file' && !isVideo(x), video: (x) => x.kind === 'file' && isVideo(x), all: () => true };
        const pick = kinds[q.kind] || kinds.all;
        const counts = { image: 0, voice: 0, file: 0 };
        for (const k of ['image', 'voice', 'file']) counts[k] = withMedia.filter(kinds[k]).length;
        if (!legacy) counts.video = withMedia.filter(kinds.video).length;
        return json(res, 200, { ok: true, items: withMedia.filter(pick).reverse().map((x) => msgView(x)), counts, hasMore: false });
      }
    }
    if (a === 'messages' && b) {
      let msg = null;
      for (const l of state.msgs.values()) { msg = l.find((x) => x.id === Number(b)) || msg; }
      if (!msg) return err(res, 404, 'not_found');
      if (!c && m === 'PATCH') {
        if (msg.senderId !== me) return err(res, 403, 'not_sender');
        msg.text = body.text; msg.editedAt = now(); msg.changedAt = now();
        return json(res, 200, { ok: true, message: msgView(msg) });
      }
      if (!c && m === 'DELETE') {
        if (q.for === 'all') { msg.deleted = true; msg.changedAt = now(); return json(res, 200, { ok: true, forAll: true, message: msgView(msg) }); }
        msg.hidden = true;
        return json(res, 200, { ok: true, forAll: false, message: null });
      }
      if (c === 'reaction') {
        msg.reactions = body.emoji ? [{ emoji: body.emoji, count: 1, userIds: [me] }] : [];
        msg.changedAt = now();
        return json(res, 200, { ok: true, reactions: msg.reactions });
      }
    }
    return err(res, 404, 'not_found');
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => { try { err(res, 500, `internal: ${e.message}`); } catch { /* closed */ } });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;

  return {
    url,
    state,
    users,
    addConv,
    addMsg,
    convView,
    msgView,
    streams,
    /** `event: plugin` to every open stream. */
    event(type, data) {
      for (const s of streams) s.write(`event: plugin\ndata: ${JSON.stringify({ plugin: PLUGIN, type, data })}\n\n`);
    },
    /** `event: notification` (e.g. a chat push). */
    notify(payload) {
      for (const s of streams) s.write(`id: ${payload.seq}\nevent: notification\ndata: ${JSON.stringify(payload)}\n\n`);
    },
    /** Answer `prefix` (path or "METHOD path") with an error; status 0 = drop the connection. */
    fail(prefix, status, code = 'failed', times = null) { state.failures.set(prefix, { status, code, times }); },
    heal() { state.failures.clear(); },
    dropStreams() { for (const s of streams) s.destroy(); },
    close() {
      for (const s of streams) s.destroy();
      return new Promise((r) => server.close(() => r()));
    },
  };
}

module.exports = { messengerServer, PLUGIN, API, MEDIA };
