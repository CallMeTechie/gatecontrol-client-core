'use strict';

// A small in-memory GateControl server with the Messenger plugin
// (gatecontrol-plugins/plugins/gatecontrol-messenger README "App-API") and
// the push stream: enough of the contract for the messenger client tests.
//
//   const srv = await messengerServer({ me: 7 });   // Messenger 1.1 API (around, serverTime)
//   messengerServer({ legacy: true })               // 1.0.x: no around, no serverTime in messages
//   messengerServer({ features: ['video_meta', 'file_thumbs'] })  // 1.3.0 `GET me` features
//   messengerServer({ features: FEATURES_14, familie: true })     // 1.4.0: status, stories, polls, events,
//                                                                 // arrival, actions, msg_tools, privacy2 (+ Familie)
//   messengerServer({ features: { ...FEATURES_14, story_duration: true } })  // 1.4.1: story durationH
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
const STORY_DURATIONS_H = [1, 3, 6, 12, 24];

const FEATURES_14 = Object.freeze({
  direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false,
  video_meta: true, file_thumbs: true, status: true, stories: true, polls: true, events: true, arrival: true, actions: true, msg_tools: true, privacy2: true,
});

async function messengerServer({ me = 7, plugin = true, tab = true, people = null, now = () => Date.now(), legacy = false, features = null, familie = false } = {}) {
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
    // 1.4.0
    statuses: new Map(),      // userId → status
    stories: [],              // { id, userId, kind, text, mediaId, thumbMediaId, createdAt, seen:Set, reactions }
    nextStory: 300,
    blocks: [],
    lists: [],
    reminders: [],
    nextReminder: 1,
    suggest: { items: [], dates: [] },
    toList: [],
    toCalendar: [],
    places: [{ id: 'home', name: 'Zuhause', lat: 50.1, lon: 7.1, radiusM: 150 }],
    actions: [
      { id: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', icon: 'M0 0h24v24H0z', kind: 'button', needsConfirm: false, state: null, subtitle: null, pluginName: 'Garage' },
      { id: 'door.open', plugin: 'gatecontrol-door', label: 'Haustür öffnen', icon: null, kind: 'button', needsConfirm: true, state: null, subtitle: null, pluginName: 'Tür' },
    ],
    actionRuns: [],
    cardImages: new Map(),     // messageId → { mime, data: Buffer }
    exportCalls: [],
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

  function addMsg(convId, { senderId = 8, text = 'Hallo', kind = 'text', clientId = null, mediaId = null, meta = null, thumbMediaId = null, video = null, poll = null, event = null, action = null, arrival = null, card = null, replyStory = null } = {}) {
    const m = { id: state.nextMsg++, conversationId: convId, senderId, clientId, kind, text, mediaId, meta, thumbMediaId, video, poll, event, action, arrival, card, replyStory, createdAt: now(), changedAt: now(), editedAt: null, deleted: false, reactions: [] };
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
      ...(m.poll ? { poll: m.poll } : {}), ...(m.event ? { event: m.event } : {}), ...(m.action ? { action: m.action } : {}),
      ...(m.arrival ? { arrival: m.arrival } : {}), ...(m.card ? { card: m.card } : {}), ...(m.replyStory ? { replyStory: m.replyStory } : {}),
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
      can: { send: !(c.kind === 'direct' && peer && state.blocks.some((b) => b.userId === peer.userId)), editInfo: c.kind === 'group', manageMembers: c.kind === 'group', leave: c.kind === 'group', setDisappearing: true, pin: true },
      archived: !!c.archived,
      pinned: c.pinned || [],
      nextEvent: null,
    };
  }

  const userOut = (id) => { const u = users.find((x) => x.id === id) || {}; return { id, name: u.name || null, avatarUrl: u.avatarUrl || null, initials: u.initials || null, colorHex: u.colorHex || null }; };
  const storyOut = (st, own) => ({
    id: st.id, kind: st.kind, text: st.text || null, bg: st.bg || null, font: st.font || null, mediaId: st.mediaId || null, thumbMediaId: st.thumbMediaId || null,
    video: st.video || null, url: null, thumbUrl: null, createdAt: iso(st.createdAt), expiresAt: iso(st.createdAt + (st.durationH || 24) * 3600000), seen: own ? true : st.seen.has(me),
    place: st.place || null, eventMessageId: st.eventMessageId || null, ...(own ? { viewerCount: st.seen.size, reactionCount: st.reactions.size, visibility: st.visibility || 'all' } : {}),
  });
  function feed() {
    const ids = new Set([...state.statuses.keys(), ...state.stories.map((x) => x.userId)]);
    ids.delete(me);
    const items = [...ids].filter((id) => !state.blocks.some((b) => b.userId === id)).map((id) => {
      const stories = state.stories.filter((x) => x.userId === id).map((x) => storyOut(x, false));
      return { user: userOut(id), status: state.statuses.get(id) || null, stories, unseen: stories.some((x) => !x.seen) };
    }).sort((x, y) => Number(y.unseen) - Number(x.unseen));
    const mine = state.stories.filter((x) => x.userId === me).map((x) => storyOut(x, true));
    return { items, me: { user: userOut(me), status: state.statuses.get(me) || null, stories: mine, unseen: false }, serverTime: iso(now()) };
  }
  const findMsg = (id) => { let msg = null; for (const l of state.msgs.values()) msg = l.find((x) => x.id === Number(id)) || msg; return msg; };
  const changed = (msg, type) => { msg.changedAt = now(); return type; };

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

  /** Messenger 1.4.0 routes → a response, or undefined when not one of them. */
  async function route14(req, res, seg, q, body) {
    const m = req.method;
    const [a, b, c, d] = seg;
    const bd = body || {};
    const ev = (type, data) => { for (const st of streams) st.write(`event: plugin\ndata: ${JSON.stringify({ plugin: PLUGIN, type, data })}\n\n`); };
    if (a === 'status' && !b) {
      if (m === 'GET') return json(res, 200, { ok: true, status: state.statuses.get(me) || null });
      if (m === 'PUT') {
        if (bd.preset === 'none' && !bd.text) return err(res, 400, 'invalid');
        const st = { preset: bd.preset, text: bd.text || null, place: null, until: bd.until || null, eta: bd.eta || null, destLabel: bd.destLabel || null, updatedAt: iso(now()), ownText: bd.text || null, visibility: bd.visibility || 'all', userIds: bd.userIds || [] };
        state.statuses.set(me, st);
        ev('status.update', { userId: me });
        return json(res, 200, { ok: true, status: st });
      }
      if (m === 'DELETE') { state.statuses.delete(me); return json(res, 200, { ok: true, status: null }); }
    }
    if (a === 'status' && b === 'feed') return json(res, 200, { ok: true, ...feed() });
    if (a === 'status' && b === 'stories') {
      if (!c && m === 'POST') {
        if (bd.kind === 'text' && !bd.text) return err(res, 400, 'invalid');
        if (bd.mediaId && !state.media.has(bd.mediaId)) return err(res, 409, 'media_invalid');
        // 1.4.1: durationH only with the feature `story_duration`, one of limits.storyDurationsH
        if (bd.durationH !== undefined && !(features && features.story_duration === true && STORY_DURATIONS_H.includes(bd.durationH))) return err(res, 400, 'invalid');
        // known fields only (no request keys written into the stored story)
        const st = {
          id: state.nextStory++, userId: me, kind: bd.kind, text: bd.text, bg: bd.bg, font: bd.font, mediaId: bd.mediaId, thumbMediaId: bd.thumbMediaId,
          video: bd.video, visibility: bd.visibility, userIds: bd.userIds, eventMessageId: bd.eventMessageId, place: bd.place,
          durationH: bd.durationH || 24, createdAt: now(), seen: new Set(), reactions: new Map(),
        };
        state.stories.push(st);
        return json(res, 200, { ok: true, story: storyOut(st, true) });
      }
      const st = state.stories.find((x) => x.id === Number(c));
      if (!st) return err(res, 404, 'not_found');
      if (!d && m === 'DELETE') { state.stories = state.stories.filter((x) => x !== st); return json(res, 200, { ok: true, deleted: true }); }
      if (d === 'seen') { st.seen.add(me); return json(res, 200, { ok: true, seen: true }); }
      if (d === 'viewers') return json(res, 200, { ok: true, viewers: [...st.seen].map((u) => ({ user: userOut(u), seenAt: iso(now()), reaction: st.reactions.get(u) || null })) });
      if (d === 'react') {
        st.reactions.set(me, bd.emoji);
        const conv = [...state.convs.values()].find((x) => x.kind === 'direct' && x.members.some((y) => y.id === st.userId)) || state.convs.get(addConv({ members: [me, st.userId] }));
        const msg = addMsg(conv.id, { senderId: me, text: bd.emoji, replyStory: { storyId: st.id, ownerId: st.userId, preview: { kind: st.kind, text: st.text || null, thumbMediaId: null } } });
        return json(res, 200, { ok: true, message: msgView(msg) });
      }
    }
    if (a === 'blocks') {
      if (!b && m === 'GET') return json(res, 200, { ok: true, blocks: state.blocks });
      if (!b && m === 'POST') { if (!state.blocks.some((x) => x.userId === bd.userId)) state.blocks.push({ userId: bd.userId, ...userOut(bd.userId), at: iso(now()), gone: false }); return json(res, 200, { ok: true, blocks: state.blocks }); }
      if (b && m === 'DELETE') { state.blocks = state.blocks.filter((x) => x.userId !== Number(b)); return json(res, 200, { ok: true, blocks: state.blocks }); }
    }
    if (a === 'lists') {
      if (m === 'GET') return json(res, 200, { ok: true, lists: state.lists });
      if (m === 'PUT') { state.lists = Array.isArray(bd) ? bd : bd.lists; return json(res, 200, { ok: true, lists: state.lists }); }
    }
    if (a === 'reminders') {
      if (!b && m === 'GET') return json(res, 200, { ok: true, reminders: state.reminders });
      if (b && m === 'DELETE') { state.reminders = state.reminders.filter((x) => x.id !== Number(b)); return json(res, 200, { ok: true, deleted: true }); }
    }
    if (a === 'actions' && !b) return json(res, 200, { ok: true, actions: state.actions });
    if (a === 'familie' && b === 'places') return familie ? json(res, 200, { ok: true, places: state.places }) : err(res, 409, 'unavailable');
    if (a === 'conversations' && b && ['archive', 'pins', 'export'].includes(c)) {
      const conv = state.convs.get(Number(b));
      if (!conv) return err(res, 404, 'not_found');
      if (c === 'archive') { conv.archived = bd.archived === true; return json(res, 200, { ok: true, conversation: convView(conv) }); }
      if (c === 'pins' && m === 'POST') {
        conv.pinned = conv.pinned || [];
        if (conv.pinned.length >= 3) return err(res, 409, 'too_many');
        if (!conv.pinned.includes(bd.messageId)) conv.pinned.push(bd.messageId);
        return json(res, 200, { ok: true, conversation: convView(conv) });
      }
      if (c === 'pins' && m === 'DELETE') { conv.pinned = (conv.pinned || []).filter((x) => x !== Number(d)); return json(res, 200, { ok: true, conversation: convView(conv) }); }
      if (c === 'export') {
        state.exportCalls.push(q);
        // two parts: the newest message, then everything older
        const list = state.msgs.get(conv.id).filter((x) => !x.hidden);
        const line = (x) => `01.01.26, 10:00 - ${(users.find((u) => u.id === x.senderId) || {}).name || 'GateControl'}: ${x.text || '<Medien>'}`;
        if (!q.before) {
          const last = list.slice(-1);
          return json(res, 200, { ok: true, format: 'txt', mime: 'text/plain', fileName: 'WhatsApp Chat Anna.txt', text: last.map(line).join('\n') + '\n', count: last.length, truncated: list.length > 1, before: list.length > 1 ? last[0].id : null });
        }
        const older = list.filter((x) => x.id < Number(q.before));
        return json(res, 200, { ok: true, format: 'txt', mime: 'text/plain', fileName: 'x.txt', text: older.map(line).join('\n') + '\n', count: older.length, truncated: false, before: null });
      }
    }
    if (a === 'messages' && b && c) {
      const msg = findMsg(b);
      if (!msg) return err(res, 404, 'not_found');
      const conv = state.convs.get(msg.conversationId);
      const out = (extra = {}) => json(res, 200, { ok: true, ...extra, message: msgView(msg) });
      if (c === 'remind' && m === 'POST') {
        const r = { id: state.nextReminder++, messageId: msg.id, conversationId: msg.conversationId, at: bd.at, createdAt: iso(now()), preview: msg.text };
        state.reminders.push(r);
        return json(res, 200, { ok: true, reminder: r });
      }
      if (c === 'suggest') return json(res, 200, { ok: true, ...state.suggest });
      if (c === 'to-list') { if (!familie) return err(res, 409, 'unavailable'); state.toList.push({ messageId: msg.id, ...bd }); return json(res, 200, { ok: true, listId: 'shopping', listName: 'Einkaufsliste', added: bd.items.length, skipped: 0 }); }
      if (c === 'to-calendar') { if (!familie) return err(res, 409, 'unavailable'); state.toCalendar.push({ messageId: msg.id, ...bd }); return json(res, 200, { ok: true, eventId: 77 }); }
      if (c === 'vote') {
        const p = msg.poll;
        if (p.closed) return err(res, 409, 'closed');
        for (const o of p.options) { o.voters = (o.voters || []).filter((u) => u !== me); if ((bd.optionIds || []).includes(o.id)) o.voters.push(me); o.count = o.voters.length; }
        p.myVotes = bd.optionIds || [];
        p.voterCount = new Set(p.options.flatMap((o) => o.voters)).size;
        changed(msg);
        return out();
      }
      if (c === 'options') { msg.poll.options.push({ id: `o${msg.poll.options.length + 1}`, text: bd.text, count: 0, voters: [], addedBy: me }); changed(msg); return out(); }
      if (c === 'close') { msg.poll.closed = true; msg.poll.closedAt = iso(now()); changed(msg); return out(); }
      if (c === 'nudge') return out({ nudged: 2 });
      if (c === 'rsvp') {
        const r = msg.event.rsvp;
        for (const k of ['yes', 'maybe', 'no']) r[k] = r[k].filter((x) => x.userId !== me);
        if (bd.answer) r[bd.answer].push({ userId: me, guests: bd.guests || 0 });
        r.mine = bd.answer || null;
        r.myGuests = bd.guests || 0;
        changed(msg);
        return out();
      }
      if (c === 'checklist') {
        const it = msg.event.checklist.find((x) => x.id === d);
        if (!it) return err(res, 404, 'not_found');
        it.doneBy = bd.done ? me : null;
        changed(msg);
        return out();
      }
      if (c === 'event' && m === 'PATCH') {
        if (msg.senderId !== me) return err(res, 403, 'not_allowed');
        const { checklist, rsvp, ...rest } = bd;
        Object.assign(msg.event, rest);
        if (rsvp !== undefined) msg.event.rsvpEnabled = rsvp;
        changed(msg);
        return out();
      }
      if (c === 'arrival' && d === 'stop') { msg.arrival.state = 'stopped'; changed(msg); return out(); }
      if (c === 'action') {
        state.actionRuns.push({ messageId: msg.id, op: d, body: bd });
        if (msg.kind === 'card') { msg.card.lastRun = { by: me, at: iso(now()), ok: true }; changed(msg); return out({ result: { ok: true, message: 'Geöffnet', state: null, error: null } }); }
        const ac = msg.action;
        if (ac.state !== 'open' && ac.mode === 'request') return err(res, 409, 'closed');
        if (d === 'deny') { ac.state = 'denied'; ac.can = { run: false, approve: false, deny: false }; changed(msg); return out({ result: null }); }
        if (d === 'approve') { ac.state = 'done'; ac.can = { run: false, approve: false, deny: false }; }
        ac.result = { ok: true, message: 'OK' };
        changed(msg);
        return out({ result: { ok: true, message: 'OK', state: null, error: null } });
      }
      if (c === 'card' && d === 'image') {
        const img = state.cardImages.get(msg.id);
        if (!img) return err(res, 404, 'not_found');
        return json(res, 200, { ok: true, mime: img.mime, bytes: img.data.length, data: img.data.toString('base64') });
      }
    }
    if (a === 'conversations' && b && c === 'messages' && m === 'POST' && features && features.polls !== true && ['poll', 'event', 'action'].includes(bd.kind)) {
      return err(res, 400, 'invalid');
    }
    return undefined;
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
        integrations: { familie: { lists: !!familie, calendar: !!familie, places: !!familie } },
        limits: { maxBytes: 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400], retentionDays: 0, statusTextMax: 60, storyTextMax: 700, ...(features && features.story_duration === true ? { storyDurationsH: STORY_DURATIONS_H } : {}), pollOptionsMax: 12, pinsMax: 3, listsMax: 20 },
        serverTime: iso(now()) });
    }
    if (a === 'prefs' && m === 'PUT') {
      for (const [k, v] of Object.entries(body || {})) state.prefs[k] = v && typeof v === 'object' ? { ...(state.prefs[k] || {}), ...v } : v;
      return json(res, 200, { ok: true, prefs: state.prefs });
    }
    const r14 = await route14(req, res, seg, q, body);
    if (r14 !== undefined) return r14;
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
        const rich = {};
        if (body.kind === 'poll') rich.poll = { ...body.poll, options: body.poll.options.map((t, i) => ({ id: `o${i + 1}`, text: t, count: 0, voters: [], addedBy: null })), closed: false, closedAt: null, voterCount: 0, memberCount: conv.members.length, creatorId: me, myVotes: [] };
        if (body.kind === 'event') {
          const { rsvp, checklist, ...ev } = body.event;
          rich.event = { ...ev, checklist: (checklist || []).map((t, i) => ({ id: `c${i + 1}`, text: t, doneBy: null, doneAt: null })), rsvpEnabled: rsvp !== false, rsvp: { yes: [], maybe: [], no: [], mine: null, myGuests: 0 }, cancelled: false, creatorId: me };
        }
        if (body.kind === 'action') rich.action = { ...body.action, plugin: body.action.plugin || null, icon: null, needsConfirm: false, state: 'open', result: null, by: null, at: null, can: { run: body.action.mode === 'run', approve: false, deny: false } };
        if (body.replyStory) rich.replyStory = { storyId: body.replyStory.storyId, ownerId: 8, preview: { kind: 'text', text: 'Story', thumbMediaId: null } };
        const msg = addMsg(conv.id, { senderId: me, text: body.text || null, kind: body.kind || 'text', clientId: body.clientId, mediaId: body.mediaId || null, meta: body.meta || null, thumbMediaId: body.thumbMediaId || null, video: body.video || null, ...rich });
        state.lastSendBody = body;
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

module.exports = { messengerServer, PLUGIN, API, MEDIA, FEATURES_14 };
