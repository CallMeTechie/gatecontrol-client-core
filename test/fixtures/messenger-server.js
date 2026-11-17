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
//   features.chat_people (1.21): persons — srv.addPerson({ convIds, userId, nameFrom }), ?people=1 folds the ways
//   (`person`, `folded`), persons/… routes, state.suggestions, state.recognition (GET bridges › recognition)
//   features.placeMessages (1.27): person.replyPref (PUT persons/:id { replyPref } → state.replyPrefs), reply.fallback,
//   state.bridge.location (`supports` names location, kind location over the bridge), message.placeMessage
//   srv.url, srv.state (conversations, messages, media, requests),
//   srv.event(type, data) → `event: plugin` on every open push stream,
//   srv.notify(payload) → `event: notification`, srv.fail(path, status, code, times?, extra?) (extra: more fields of the refusal, e.g. { finding }),
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
    // Messenger 1.25: the contacts' WhatsApp status updates (`bridged` of the feed, only with features.bridge_status)
    bridged: [],              // { network, contact: { id, name }, chatId, canReply, stories: [{ id, kind, text, createdAt, seen }] }
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
    // 1.13 / 1.14: linked services and chats over a bridge (routes only with features.linked_services)
    bridge: {
      available: true,
      location: 'server',
      networks: [{ id: 'whatsapp', state: 'running', allowed: true, lock: null, consent: null, outdated: false, version: '0.12.1', wantVersion: '0.12.1', logins: [] }],
      process: null,            // { id, flow, step, polls } of the login in progress
      confirmAfter: 2,          // so many waiting calls before the phone "confirmed"
      qrRenewAt: null,          // a waiting call number at which the QR code is renewed (a new step)
      loginFails: null,         // { status, code, reason } for the next waiting call
      phoneRefused: false,
      tgPassword: null,         // 1.24: Telegram asks for this password after the code (null: no two-step verification)
      sendFails: null,          // a reason: the bridge does not take the next message (stored as failed)
      calls: [],                // what was asked of the bridge (never a number: only that one came)
      // 1.15: files over the bridge (supports + mediaTypes), the new chat by number (features.bridge_new_chat)
      media: false,
      // 1.27 (gc.bridges version 14): the bridge sends a location (`supports` names `location`)
      location: false,
      scanPending: 0,           // so many sends of a file are refused with 423 scan_pending first
      numbers: new Map(),       // '+49…' → name of the numbers "at WhatsApp"
      lookups: 0,
      lookupMax: 10,
      // 1.18: „Neuer Chat“ with contacts (features.bridge_contacts): the WhatsApp contacts of the bridge (ref → name,
      // conversationId) and the address book of Mail (contactId → name, phones); listState 'ok' | 'unreachable' |
      // 'logged_out'; book null = no Mail; refs that ran out; numbers remembered as „nicht bei WhatsApp“
      contacts: [],
      book: null,
      listState: 'ok',
      expired: new Set(),
      notOn: new Set(),
      // 1.17: older history at a new link (features.bridge_history; null = the server has none)
      history: { available: true, days: 30, default: 30, options: [0, 30, -1], pending: 0 },
      fetches: [],              // ids of messages whose file of the history was asked for
    },
    // 1.21 (features.chat_people): persons of the viewer (id → { id, ways: [convId], userId, nameFrom }), the open
    // suggestions (GET persons/suggestions), their answers, the consent „an meinem WhatsApp erkennen“ (null: no call)
    persons: new Map(),
    nextPerson: 1,
    suggestions: [],
    answers: [],
    recognition: null,
    // 1.23: the consent per further service (network → { asked, allowed }, e.g. signal), an open „am PC fortsetzen“
    recognitions: {},
    handoff: null,
    personReads: [],
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

  /** A chat over a bridge: one member (the linked person), no peer; `state` as GET conversations says it. */
  function addBridgeConv({ kind = 'direct', title = 'Kim Muster', network = 'whatsapp', bridgeState = 'ok', closed = false, channel = false, readOnly = false } = {}) {
    const id = addConv({ kind: channel ? 'group' : kind, members: [me], title });
    // 1.20: a channel (muted from the start, read only), a group where only admins write
    Object.assign(state.convs.get(id), { bridge: { network, state: bridgeState, closed, channel, readOnly: readOnly || channel, reactions: 'own' }, notify: channel ? 'none' : 'all' });
    return id;
  }

  /** A message of a contact (`contact`: { contactId, name }) or of the person's phone (`remote`), a placeholder, a notice. */
  function addBridgeMsg(convId, { contact = { contactId: 12, name: 'Kim Muster' }, text = 'Hallo', remote = false, placeholder = null, notice = false, state: st = null, reason = null, post = false, marks = null, preview = null } = {}) {
    const mine = remote || st != null;
    const m = addMsg(convId, { senderId: mine ? me : null, text, kind: notice ? 'system' : 'text' });
    // 1.20: a post of a channel (`post`: no contact wrote it), the format of the text, a link preview
    m.bridge = { sender: mine || notice || post ? null : contact, remote, state: mine ? (st || 'sent') : null, reason, placeholder, ...(post ? { channel: true } : {}) };
    m.marks = marks;
    m.preview = preview;
    if (notice) m.system = { event: 'bridge_notice', network: state.convs.get(convId).bridge.network };
    return m;
  }

  /** GET contacts/new-chat (contactchat.js of the plugin, 1.18) → the three sections, filtered by q. */
  function contactsRoute(res, q) {
    if (!(features && features.bridge_contacts === true)) return err(res, 404, 'not_found');
    const B = state.bridge;
    const net = B.networks[0];
    const query = String(q.q || '').trim().slice(0, 100);
    const has = (n) => !query || String(n || '').toLowerCase().includes(query.toLowerCase());
    const gatecontrol = users.filter((x) => x.id !== me && has(x.name)).map((x) => {
      const c = [...state.convs.values()].find((y) => y.kind === 'direct' && !y.bridge && y.members.some((mb) => mb.id === x.id));
      return { userId: x.id, name: x.name, avatarUrl: x.avatarUrl, initials: x.initials, colorHex: x.colorHex, conversationId: c ? c.id : null };
    });
    const linked = net.logins.length > 0 && net.allowed;
    const st = !linked ? null : (net.logins.every((l) => l.state === 'logged_out') ? 'logged_out' : (net.state !== 'running' || B.listState === 'unreachable' ? 'unreachable' : B.listState));
    const items = B.contacts.filter((c) => has(c.name)).sort((a, b) => a.name.localeCompare(b.name, 'de'));
    const whatsapp = st ? { state: st, total: B.contacts.length, items: st === 'ok' ? items.map((c) => ({ ref: c.ref, name: c.name, avatarMediaId: c.avatarMediaId || null, avatarUrl: null, conversationId: c.conversationId || null, alsoInAddressBook: !!c.alsoInAddressBook, addressBookId: c.addressBookId || null })) : [] } : null;
    const bookItems = whatsapp && B.book ? B.book.filter((x) => has(x.name)).map((x) => ({ contactId: x.contactId, name: x.name, conversationId: null,
      phones: x.phones.map((p) => ({ ...p, notOnNetwork: B.notOn.has(`${x.contactId}|${p.key}`) })) })) : [];
    const addressBook = whatsapp && B.book && B.book.length ? { state: st, total: B.book.length, items: bookItems } : null;
    const digits = /^[+0-9\s\-./()]{6,40}$/.test(query) ? query.replace(/[\s\-./()]/g, '').replace(/^0(?=[1-9])/, '+49') : '';
    const number = whatsapp && /^\+[1-9][0-9]{6,14}$/.test(digits) ? { e164: digits, show: digits, conversationId: null } : null;
    B.calls.push({ op: 'contacts' });
    return json(res, 200, { ok: true, network: 'whatsapp', query, gatecontrol, whatsapp, addressBook, addressBookReason: whatsapp && !B.book ? 'no_mail' : null,
      number, numberEntry: !!whatsapp, limit: { perHour: B.lookupMax, left: Math.max(0, B.lookupMax - B.lookups), retryAfterS: 0 } });
  }

  const QR_ROWS = (seed) => Array.from({ length: 25 }, (_, y) => Array.from({ length: 25 }, (_, x) => (((x * 7 + y * 13 + seed) % 3 === 0 || x === 0 || y === 0) ? '1' : '0')).join(''));
  const waitStep = (pr) => (pr.flow === 'qr'
    ? { id: `qr${pr.n}`, type: 'display_and_wait', display: { type: 'qr', data: `2@fixture${pr.n}`, matrix: { size: 25, rows: QR_ROWS(pr.n) } } }
    : { id: 'code1', type: 'display_and_wait', display: { type: 'code', data: 'K7P2-M4X9' } });

  /** bridges/* (bridges.js of the plugin) → the answer, or undefined when the path is not ours. */
  function bridgeRoute(res, seg, m, body) {
    const B = state.bridge;
    if (seg[0] !== 'bridges') return undefined;
    if (!(features && features.linked_services === true)) return err(res, 404, 'not_found');
    const hist = features && features.bridge_history === true;
    // 1.23: networks[].recognition of the further services, the open handoff
    const recOf = (id) => (state.recognitions[id] ? { available: true, ...state.recognitions[id] } : null);
    const nets = () => B.networks.map((n) => (state.recognitions[n.id] ? { ...n, recognition: recOf(n.id) } : n));
    if (seg.length === 1 && m === 'GET') return json(res, 200, { ok: true, bridges: B.available ? { available: true, location: B.location, networks: nets(), ...(hist ? { history: B.history } : {}), ...(state.recognition ? { recognition: { available: true, network: 'whatsapp', ...state.recognition } } : {}), ...(state.handoff ? { handoff: state.handoff } : {}) } : { available: false, networks: [] } });
    // 1.21 (gc.bridges version 9): „Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?“ (1.23: `network`)
    if (seg.length === 2 && seg[1] === 'recognition' && m === 'PUT') {
      if (!state.recognition) return err(res, 403, 'feature_off');
      if (typeof (body && body.allowed) !== 'boolean') return err(res, 400, 'invalid');
      const net = body.network == null ? 'whatsapp' : body.network;
      if (net !== 'whatsapp' && !state.recognitions[net]) return err(res, 400, 'invalid');
      if (net === 'whatsapp') state.recognition = { asked: true, allowed: body.allowed };
      else state.recognitions[net] = { asked: true, allowed: body.allowed };
      const recognitions = { whatsapp: { available: true, ...state.recognition } };
      for (const k of Object.keys(state.recognitions)) recognitions[k] = recOf(k);
      return json(res, 200, { ok: true, recognition: { available: true, network: 'whatsapp', ...state.recognition }, ...(body.network != null ? { recognitions } : {}) });
    }
    // 1.23: „Im Portal / Windows-Client fortsetzen“
    if (seg.length === 3 && seg[2] === 'handoff' && (m === 'POST' || m === 'DELETE')) {
      if (m === 'DELETE') { state.handoff = null; return json(res, 200, { ok: true, handoff: null }); }
      if (!['portal', 'windows'].includes(body && body.target)) return err(res, 400, 'invalid');
      state.handoff = { network: seg[1], target: body.target, expiresAt: new Date(now() + 600000).toISOString() };
      return json(res, 200, { ok: true, handoff: { ...state.handoff, portalPath: '/portal#plg-gatecontrol-messenger' } });
    }
    // 1.17: what of the older messages comes over
    if (seg.length === 2 && seg[1] === 'history' && m === 'PUT') {
      if (!hist || !B.history) return err(res, 403, 'feature_off');
      if (![0, 30, -1].includes(body && body.days)) return err(res, 400, 'invalid');
      B.history = { ...B.history, days: body.days, pending: body.days === 0 ? 0 : B.history.pending };
      return json(res, 200, { ok: true, history: B.history });
    }
    const net = B.networks.find((n) => n.id === seg[1]);
    if (!net || seg.length < 3) return err(res, 404, 'not_found');
    if (!B.available) return err(res, 409, 'bridge_off', { reason: 'no_host' });
    const gate = (consent = true) => (!net.allowed ? [403, 'bridge_locked'] : (consent && !net.consent ? [409, 'consent_required'] : null));
    if (seg.length === 3 && seg[2] === 'consent' && m === 'POST') {
      if (!body || body.accept !== true) return err(res, 400, 'invalid');
      const g = gate(false);
      if (g) return err(res, g[0], g[1]);
      net.consent = net.consent || iso(now());
      return json(res, 200, { ok: true, consent: net.consent });
    }
    if (seg.length === 3 && seg[2] === 'login' && m === 'POST') {
      const g = gate();
      if (g) return err(res, g[0], g[1]);
      if (net.state !== 'running') return err(res, 503, 'bridge_unreachable', { reason: 'not_running' });
      if (!['phone', 'qr'].includes(body && body.flow)) return err(res, 400, 'invalid');
      const pr = { id: `proc${(B.calls.length + 1)}`, flow: body.flow, n: 1, polls: 0, asked: body.flow === 'phone' };
      B.process = pr;
      B.calls.push({ op: 'start', flow: pr.flow });
      return json(res, 200, { ok: true, login: { processId: pr.id, step: pr.flow === 'phone' ? { id: 'phone1', type: 'user_input', fields: [{ id: 'phone_number', type: 'phone_number', optional: false }] } : waitStep(pr) } });
    }
    if (seg.length === 5 && seg[2] === 'login' && m === 'POST') {
      const g = gate();
      if (g) return err(res, g[0], g[1]);
      const pr = B.process;
      if (!pr || pr.id !== seg[3]) return err(res, 404, 'not_found');
      // 1.24: Telegram — number, the code from the Telegram app, the password of the two-step verification (B.tgPassword);
      // a wrong one is asked again (`retry`); what was typed is never kept, only whether it fitted
      if (body && body.input && net.id === 'telegram') {
        const tg = (sid, type, retry) => json(res, 200, { ok: true, login: { processId: pr.id, step: { id: sid, type: 'user_input', fields: [{ id: type === 'password' ? 'pass' : 'code', type, optional: false }], ...(retry ? { retry: true } : {}) } } });
        const v = String(Object.values(body.input)[0] || '');
        B.calls.push({ op: 'input', step: seg[4], field: Object.keys(body.input)[0] });
        if (seg[4] === 'phone1') return tg('code1', '2fa_code', false);
        if (seg[4].startsWith('code')) {
          if (v !== '47000') return tg('code1.incorrect', '2fa_code', true);
          if (B.tgPassword) return tg('pass1', 'password', false);
        } else if (seg[4].startsWith('pass') && v !== B.tgPassword) {
          return tg('pass1.incorrect', 'password', true);
        }
        B.process = null;
        net.logins = [{ id: 'login1', name: 'Kim Muster', state: 'connected', since: iso(now()) }];
        return json(res, 200, { ok: true, login: { processId: pr.id, step: { id: 'done', type: 'complete', loginId: 'login1' } } });
      }
      if (body && body.input) {
        const v = body.input.phone_number;
        B.calls.push({ op: 'input', step: seg[4], ok: /^\+[0-9]{6,15}$/.test(String(v || '')) });
        if (B.phoneRefused) return err(res, 502, 'bridge_failed', { reason: 'bad_number' });
        pr.asked = false;
        return json(res, 200, { ok: true, login: { processId: pr.id, step: waitStep(pr) } });
      }
      pr.polls += 1;
      B.calls.push({ op: 'wait', step: seg[4] });
      if (B.loginFails) { const f = B.loginFails; B.loginFails = null; if (f.status === 0) { res.socket.destroy(); return true; } B.process = null; return err(res, f.status, f.code, f.reason ? { reason: f.reason } : null); }
      if (pr.flow === 'qr' && B.qrRenewAt === pr.polls) { pr.n += 1; return json(res, 200, { ok: true, login: { processId: pr.id, step: waitStep(pr) } }); }
      if (pr.polls < B.confirmAfter) return json(res, 200, { ok: true, login: { processId: pr.id, waiting: true } });
      B.process = null;
      net.logins = [{ id: 'login1', name: '+49 1512 0000000', state: 'connected', since: iso(now()) }];
      for (const c of state.convs.values()) if (c.bridge && c.bridge.network === net.id) c.bridge.state = 'ok';
      return json(res, 200, { ok: true, login: { processId: pr.id, step: { id: 'done', type: 'complete', loginId: 'login1' } } });
    }
    if (seg.length === 4 && seg[2] === 'login' && m === 'DELETE') {
      B.calls.push({ op: 'cancel', process: seg[3] });
      if (B.process && B.process.id === seg[3]) B.process = null;
      return json(res, 200, { ok: true, cancelled: true });
    }
    if (seg.length === 3 && seg[2] === 'chats' && m === 'POST' && body && (body.ref != null || body.contactId != null)) {
      // 1.18: a WhatsApp contact ({ ref }: nothing checked or counted) or an address book number ({ contactId, phoneKind })
      if (!(features && features.bridge_contacts === true)) return err(res, 400, 'invalid_number');
      if (!net.allowed) return err(res, 403, 'bridge_locked');
      if (net.logins.every((l) => l.state === 'logged_out')) return err(res, 409, 'bridge_logged_out', { reason: 'logged_out' });
      if (net.state !== 'running') return err(res, 503, 'bridge_unreachable', { reason: 'not_running' });
      if (body.ref != null) {
        if (B.expired.has(body.ref)) return err(res, 409, 'contact_expired');
        const c = B.contacts.find((x) => x.ref === body.ref);
        if (!c) return err(res, 400, 'invalid');
        B.calls.push({ op: 'chat_ref' });
        const existing = c.conversationId && state.convs.get(c.conversationId);
        const id = existing ? existing.id : addBridgeConv({ title: c.name });
        c.conversationId = id;
        return json(res, 200, { ok: true, conversation: convView(state.convs.get(id)), created: !existing });
      }
      if (!B.book) return err(res, 409, 'mail_missing');
      const x = B.book.find((y) => y.contactId === body.contactId);
      const ph = x && x.phones.find((p) => p.key === body.phoneKind);
      if (!ph) return err(res, 404, 'not_found', { reason: 'contact_gone' });
      if (B.notOn.has(`${x.contactId}|${ph.key}`)) return err(res, 404, 'not_found', { reason: 'not_on_network', remembered: true });
      if (B.lookups >= B.lookupMax) return err(res, 429, 'rate_limited', { retryAfterS: 840, perHour: B.lookupMax });
      B.lookups += 1;
      B.calls.push({ op: 'chat_book' });
      if (!B.numbers.has(ph.e164)) { B.notOn.add(`${x.contactId}|${ph.key}`); return err(res, 404, 'not_found', { reason: 'not_on_network' }); }
      const existing = [...state.convs.values()].find((c) => c.bridge && c.bridge.number === ph.e164);
      const id = existing ? existing.id : addBridgeConv({ title: x.name });
      state.convs.get(id).bridge.number = ph.e164;
      return json(res, 200, { ok: true, conversation: convView(state.convs.get(id)), created: !existing });
    }
    if (seg.length === 3 && (seg[2] === 'resolve' || seg[2] === 'chats') && m === 'POST') {
      if (!(features && features.bridge_new_chat === true)) return err(res, 404, 'not_found');
      if (!net.allowed) return err(res, 403, 'bridge_locked');
      if (!net.logins.length) return err(res, 409, 'bridge_unlinked', { reason: 'unlinked' });
      if (net.logins.every((l) => l.state === 'logged_out')) return err(res, 409, 'bridge_logged_out', { reason: 'logged_out' });
      if (net.state !== 'running') return err(res, 503, 'bridge_unreachable', { reason: 'not_running' });
      const num = String((body && body.number) || '').replace(/[\s()-]/g, '');
      if (!/^\+[1-9][0-9]{6,14}$/.test(num)) return err(res, 400, 'invalid_number');
      if (B.lookups >= B.lookupMax) return err(res, 429, 'rate_limited', { retryAfterS: 840, perHour: B.lookupMax });
      B.lookups += 1;
      B.calls.push({ op: seg[2] });
      const name = B.numbers.get(num);
      const existing = [...state.convs.values()].find((c) => c.bridge && c.bridge.number === num);
      if (seg[2] === 'resolve') return json(res, 200, { ok: true, found: name != null, name: name || null, avatarUrl: null, existing: existing ? { conversationId: existing.id } : null });
      if (name == null) return err(res, 404, 'not_found', { reason: 'not_on_network' });
      const id = existing ? existing.id : addBridgeConv({ title: name });
      state.convs.get(id).bridge.number = num;
      return json(res, 200, { ok: true, conversation: convView(state.convs.get(id)), created: !existing });
    }
    if (seg.length === 4 && seg[2] === 'logins' && m === 'DELETE') {
      if (!net.logins.some((l) => l.id === seg[3])) return err(res, 404, 'not_found');
      B.calls.push({ op: 'unlink', login: seg[3] });
      net.logins = net.logins.filter((l) => l.id !== seg[3]);
      for (const c of state.convs.values()) if (c.bridge && c.bridge.network === net.id) c.bridge.state = 'unlinked';
      return json(res, 200, { ok: true, unlinked: true });
    }
    return err(res, 404, 'not_found');
  }

  // ── 1.21: persons ──
  /** A person of the viewer over the given chats (`nameFrom`: 'account' or a conversation id). → its id */
  function addPerson({ convIds, userId = null, nameFrom = null }) {
    const id = state.nextPerson++;
    state.persons.set(id, { id, ways: convIds.slice(), userId, nameFrom: nameFrom || (userId ? 'account' : Math.min(...convIds)), createdAt: now() });
    return id;
  }
  const personOf = (cid) => [...state.persons.values()].find((p) => p.ways.includes(cid)) || null;
  const wayName = (c) => (c.bridge ? c.bridge.network : 'gatecontrol');
  const keyLess = (x, y) => x.createdAt < y.createdAt || (x.createdAt === y.createdAt && x.id < y.id);
  const byKey = (x, y) => (keyLess(x, y) ? -1 : keyLess(y, x) ? 1 : 0);
  function personEntry(p) {
    const convs = p.ways.map((id) => state.convs.get(id)).filter(Boolean);
    const views = convs.map((c) => convView(c));
    const gc = convs.find((c) => !c.bridge);
    const lead = gc || convs.slice().sort((x, y) => x.id - y.id)[0];
    const leadView = views.find((v) => v.id === lead.id);
    const acc = p.userId ? users.find((u) => u.id === p.userId) : null;
    const src = p.nameFrom !== 'account' ? views.find((v) => v.id === p.nameFrom) : null;
    const name = src ? src.title : (acc ? acc.name : leadView.title);
    // the way of the newest incoming message (a tie, none: GateControl); a bridged way that cannot send gives way
    let best = null;
    for (const c of convs) {
      const inc = state.msgs.get(c.id).filter((m) => !m.hidden && m.senderId !== me);
      const li = inc[inc.length - 1];
      if (li && (!best || li.createdAt > best.li.createdAt || (li.createdAt === best.li.createdAt && !c.bridge))) best = { c, li };
    }
    let pick = best ? best.c : lead;
    if (pick.bridge && gc && !(pick.bridge.state === 'ok' && !pick.bridge.closed)) pick = gc;
    // 1.27: „Nachrichten senden über“ — a fixed way while it can send, else GateControl with `fallback`
    let fallback = false;
    const pref = p.replyPref || 'auto';
    const want = pref !== 'auto' ? convs.find((c) => wayName(c) === pref) : null;
    if (want) {
      const sends = !want.bridge || (want.bridge.state === 'ok' && !want.bridge.closed);
      if (sends) pick = want;
      else if (gc && gc !== want) { pick = gc; fallback = true; }
    }
    const ways = views.slice().sort((x, y) => (x.bridge ? 1 : 0) - (y.bridge ? 1 : 0) || x.id - y.id).map((v) => ({
      way: v.bridge ? v.bridge.network : 'gatecontrol', label: v.bridge ? v.bridge.label : 'GateControl', conversationId: v.id, title: v.title,
      avatarUrl: v.avatarUrl || null, avatarMediaId: v.avatarMediaId || null, unread: v.unread, muted: v.muted, archived: v.archived,
      lastMessageAt: v.lastMessage ? v.lastMessage.createdAt : null, bridge: v.bridge || null,
      can: { send: !!v.can.send, sendReason: v.can.sendReason || null, react: v.can.react !== false },
    }));
    let last = null;
    for (const v of views) if (v.lastMessage && (!last || v.lastMessage.createdAt > last.createdAt || (v.lastMessage.createdAt === last.createdAt && v.lastMessage.id > last.id))) last = v.lastMessage;
    const names = [];
    for (const n of [name, acc && acc.name, ...views.map((v) => v.title)]) if (n && !names.includes(n)) names.push(n);
    return {
      ...leadView,
      title: name,
      unread: views.reduce((s, v) => s + v.unread, 0),
      lastMessage: last,
      archived: views.every((v) => v.archived),
      person: {
        id: p.id, name, nameFrom: src ? src.id : (acc ? 'account' : null), userId: p.userId, conversationId: lead.id, names, ways,
        reply: { way: wayName(pick), label: pick.bridge ? 'WhatsApp' : 'GateControl', conversationId: pick.id, ...(fallback ? { fallback: true } : {}) },
        ...(features && features.placeMessages === true ? { replyPref: pref } : {}),
        createdAt: iso(p.createdAt),
      },
    };
  }
  /** persons/* (persons.js of the plugin) → the answer, a rewrite of POST …/messages, or undefined when not ours. */
  function personRoute(res, seg, m, q, body) {
    if (seg[0] !== 'persons') return undefined;
    const [, b, c, d] = seg;
    if (seg.length === 2 && b === 'suggestions' && m === 'GET') return json(res, 200, { ok: true, suggestions: state.suggestions });
    if (seg.length === 3 && b === 'suggestions' && m === 'POST') {
      const s = state.suggestions.find((x) => x.id === c);
      if (!s) return err(res, 404, 'not_found');
      if (!['later', 'never'].includes(body && body.action)) return err(res, 400, 'invalid');
      state.answers.push({ id: c, action: body.action });
      state.suggestions = state.suggestions.filter((x) => x.id !== c);
      return json(res, 200, { ok: true, suggestion: { id: c, state: body.action, until: null } });
    }
    if (seg.length === 2 && b === 'candidates' && m === 'GET') {
      const cid = Number(q.conversationId);
      const own = personOf(cid);
      const conv = state.convs.get(cid);
      if (!conv) return err(res, 404, 'not_found');
      const hasAccount = (!conv.bridge && conv.kind === 'direct') || !!(own && own.userId);
      const accounts = hasAccount ? [] : users.filter((u) => u.id !== me).map((u) => ({ userId: u.id, name: u.name, avatarUrl: u.avatarUrl, initials: u.initials, colorHex: u.colorHex, personId: null }));
      const chats = [...state.convs.values()].filter((x) => x.bridge && x.kind === 'direct' && !x.bridge.channel && x.id !== cid && !(own && own.ways.includes(x.id)))
        .map((x) => ({ conversationId: x.id, title: x.title, network: x.bridge.network, label: 'WhatsApp', avatarUrl: null, avatarMediaId: null, personId: (personOf(x.id) || {}).id || null }));
      return json(res, 200, { ok: true, accounts, chats });
    }
    if (seg.length === 1 && m === 'POST') {
      const ids = (body && body.conversationIds) || [];
      for (const id of ids) {
        const x = state.convs.get(id);
        if (!x) return err(res, 404, 'not_found');
        if (x.kind !== 'direct' || (x.bridge && x.bridge.channel)) return err(res, 409, 'cannot_merge', { reason: x.bridge && x.bridge.channel ? 'channel' : 'group' });
      }
      let userId = body.userId || null;
      const all = new Set(ids);
      for (const id of ids) { const x = state.convs.get(id); if (!x.bridge) userId = x.members.find((y) => y.id !== me).id; const pp = personOf(id); if (pp) { pp.ways.forEach((w) => all.add(w)); if (pp.userId) userId = pp.userId; state.persons.delete(pp.id); } }
      if (userId && ![...all].some((id) => !state.convs.get(id).bridge)) {
        const ex = [...state.convs.values()].find((x) => x.kind === 'direct' && !x.bridge && x.members.some((y) => y.id === userId));
        all.add(ex ? ex.id : addConv({ kind: 'direct', members: [me, userId] }));
      }
      if (all.size < 2) return err(res, 409, 'cannot_merge', { reason: 'one_way' });
      const pid = addPerson({ convIds: [...all], userId, nameFrom: body.name || (userId ? 'account' : null) });
      state.suggestions = state.suggestions.filter((s) => !all.has(s.conversationId));
      const e = personEntry(state.persons.get(pid));
      return json(res, 200, { ok: true, conversation: e, person: e.person });
    }
    const p = state.persons.get(Number(b));
    if (!p) return err(res, 404, 'not_found');
    if (seg.length === 2 && m === 'GET') { const e = personEntry(p); return json(res, 200, { ok: true, conversation: e, person: e.person }); }
    if (seg.length === 2 && (m === 'PATCH' || m === 'PUT')) {
      // 1.27: replyPref — auto | gatecontrol | a network the person has (else bad_request); not a word → invalid
      if (body.replyPref !== undefined) {
        const v = body.replyPref === null ? 'auto' : body.replyPref;
        if (typeof v !== 'string' || !/^[a-z]{2,20}$/.test(v)) return err(res, 400, 'invalid');
        if (v !== 'auto' && !p.ways.some((id) => wayName(state.convs.get(id)) === v)) return err(res, 400, 'bad_request');
        p.replyPref = v;
        state.replyPrefs = (state.replyPrefs || []).concat([{ personId: p.id, method: m, replyPref: v }]);
      }
      if (body.name !== undefined) p.nameFrom = body.name;
      for (const id of p.ways) { const x = state.convs.get(id); if (body.notify) x.notify = body.notify; x.updatedAt = now(); }
      const e = personEntry(p);
      return json(res, 200, { ok: true, conversation: e, person: e.person });
    }
    if (seg.length === 3 && c === 'archive' && m === 'POST') {
      for (const id of p.ways) state.convs.get(id).archived = body.archived === true;
      const e = personEntry(p);
      return json(res, 200, { ok: true, conversation: e, person: e.person });
    }
    if ((seg.length === 4 && c === 'ways' && m === 'DELETE') || (seg.length === 2 && m === 'DELETE')) {
      const leave = d ? [Number(d)] : p.ways.slice();
      if (d && !p.ways.includes(Number(d))) return err(res, 404, 'not_found');
      p.ways = p.ways.filter((id) => !leave.includes(id));
      let person = null;
      const out = [];
      if (p.ways.length < 2) { leave.push(...p.ways); state.persons.delete(p.id); } else { if (leave.includes(p.nameFrom)) p.nameFrom = p.userId ? 'account' : Math.min(...p.ways); const e = personEntry(p); person = e.person; out.push(e); }
      for (const id of new Set(leave)) out.push(convView(state.convs.get(id)));
      return json(res, 200, { ok: true, person, conversations: out });
    }
    const all = p.ways.map((id) => state.convs.get(id));
    const ways = q.way ? all.filter((x) => wayName(x) === q.way) : all;
    const rows = () => ways.flatMap((x) => state.msgs.get(x.id).filter((mm) => !mm.hidden)).sort(byKey);
    if (seg.length === 3 && c === 'messages' && m === 'GET') {
      const limit = Number(q.limit) || 50;
      const list = rows();
      const cur = (id) => { for (const x of all) { const f = state.msgs.get(x.id).find((mm) => mm.id === Number(id)); if (f) return f; } return null; };
      let out;
      let hasMore = false;
      const extra = {};
      if (q.before) { const k = cur(q.before); const older = list.filter((x) => keyLess(x, k)); out = older.slice(-limit); hasMore = older.length > limit; } else if (q.after) { const k = cur(q.after); const newer = list.filter((x) => keyLess(k, x)); out = newer.slice(0, limit); hasMore = newer.length > limit; } else if (q.around) {
        const k = cur(q.around);
        const half = Math.floor(limit / 2);
        const older = list.filter((x) => keyLess(x, k));
        const rest = list.filter((x) => !keyLess(x, k));
        out = older.slice(-half).concat(rest.slice(0, limit - Math.min(half, older.length)));
        extra.hasMoreBefore = older.length > half;
        extra.hasMoreAfter = rest.length > limit - Math.min(half, older.length);
        hasMore = extra.hasMoreBefore || extra.hasMoreAfter;
      } else if (q.changedSince) { out = list.filter((x) => x.changedAt > Date.parse(q.changedSince)); } else { out = list.slice(-limit); hasMore = list.length > limit; }
      const marks = all.map((x) => { const v = convView(x); return { conversationId: x.id, way: wayName(x), lastReadId: v.me.lastReadId, readUpTo: v.readUpTo, deliveredUpTo: v.deliveredUpTo }; });
      return json(res, 200, { ok: true, messages: out.map((x) => msgView(x)), hasMore, ...extra, ways: marks, serverTime: iso(now()) });
    }
    if (seg.length === 3 && c === 'read' && m === 'POST') {
      state.personReads.push({ personId: p.id, upTo: body && body.upTo != null ? body.upTo : null });
      const k = body && body.upTo != null ? all.flatMap((x) => state.msgs.get(x.id)).find((mm) => mm.id === body.upTo) : null;
      const out = all.map((x) => {
        const mb = x.members.find((y) => y.id === me);
        const msgs = state.msgs.get(x.id).filter((mm) => !k || !keyLess(k, mm));
        const top = msgs.length ? msgs[msgs.length - 1].id : 0;
        mb.lastRead = Math.max(mb.lastRead, top);
        return { conversationId: x.id, way: wayName(x), lastReadId: mb.lastRead, unread: convView(x).unread };
      });
      return json(res, 200, { ok: true, unread: out.reduce((s, x) => s + x.unread, 0), ways: out });
    }
    if (seg.length === 3 && c === 'search' && m === 'GET') {
      return json(res, 200, { ok: true, results: rows().filter((x) => (x.text || '').includes(q.q)).reverse().map((x) => msgView(x)), scanned: rows().length, truncated: false });
    }
    if (seg.length === 3 && c === 'messages' && m === 'POST') {
      const e = personEntry(p);
      let w = e.person.reply;
      const rq = body && body.replyTo ? all.find((x) => state.msgs.get(x.id).some((mm) => mm.id === body.replyTo)) : null;
      const rw = rq && e.person.ways.find((x) => x.conversationId === rq.id && x.can.send);
      if (rw) w = rw;
      return { rewrite: ['conversations', String(w.conversationId), 'messages'], extra: { way: w.way, conversationId: w.conversationId } };
    }
    return err(res, 404, 'not_found');
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
      media: m.mediaId && !m.deleted ? { id: m.mediaId, mime: (state.media.get(m.mediaId) || {}).mime || null, bytes: (state.media.get(m.mediaId) || {}).data?.length || 0, url: null, thumbId: m.thumbMediaId || null, thumbUrl: null, ...(m.scan ? { scan: m.scan } : {}) } : null,
      ...(m.video && !m.deleted ? { video: m.video } : {}),
      meta: m.deleted ? null : m.meta, location: m.deleted ? null : m.location || null, system: null, reactions: m.deleted ? [] : m.reactions,
      // 1.27: sent by a place message — only the sender sees it
      ...(features && features.placeMessages === true ? { placeMessage: m.placeMessage && m.senderId === viewer ? m.placeMessage : null } : {}),
      ...(m.poll ? { poll: m.poll } : {}), ...(m.event ? { event: m.event } : {}), ...(m.action ? { action: m.action } : {}),
      ...(m.arrival ? { arrival: m.arrival } : {}), ...(m.card ? { card: m.card } : {}), ...(m.replyStory ? { replyStory: m.replyStory } : {}),
      status: m.senderId === viewer ? (m.id <= readUpTo ? 'read' : m.id <= deliveredUpTo ? 'delivered' : 'sent') : null,
      // 1.21: the way of every message (a client with ?people=1)
      ...(features && features.chat_people === true ? { way: c.bridge ? c.bridge.network : 'gatecontrol' } : {}),
      ...(c.bridge ? {
        via: `bridge:${c.bridge.network}`,
        system: m.system || null,
        bridge: m.bridge || { sender: null, remote: false, state: m.senderId === viewer ? 'sent' : null, reason: null, placeholder: null },
        marks: m.marks || null,
        preview: m.preview || null,
        ...(m.senderId === viewer && m.bridge && m.bridge.state ? { status: { pending: 'sending' }[m.bridge.state] || m.bridge.state } : {}),
      } : {}),
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
      me: { role: mine.role, mutedUntil: null, notify: c.notify || 'all', lastReadId: mine.lastRead, lastDeliveredId: mine.lastDelivered },
      muted: c.notify === 'none',
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
      // 1.14: `bridge` on every conversation (null inside GateControl); a chat over a bridge has no peer
      ...(features && (features.linked_services === true || features.bridge_chats === true) ? { bridge: null } : {}),
      ...(c.bridge ? {
        title: c.title, peer: null, avatarUrl: null,
        bridge: {
          network: c.bridge.network, label: 'WhatsApp', state: c.bridge.state, closed: !!c.bridge.closed,
          ...(features && features.bridge_channels === true ? { channel: !!c.bridge.channel, readOnly: !!c.bridge.readOnly, ...(c.bridge.channel ? { reactions: c.bridge.reactions } : {}) } : {}),
          supports: ['text', 'reply', 'reaction', 'edit', 'delete', 'read', 'typing', ...(state.bridge.media ? ['image', 'video', 'voice', 'file'] : []), ...(state.bridge.location ? ['location'] : [])],
          ...(state.bridge.media ? { mediaTypes: { image: ['image/jpeg', 'image/png', 'image/webp'], video: ['video/mp4'], voice: ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg'], file: null } } : {}),
        },
        avatarMediaId: c.avatarMediaId || null,
        readUpTo: c.bridge.readUpTo || null, deliveredUpTo: c.bridge.deliveredUpTo || null, receipts: [],
        can: {
          send: c.bridge.state === 'ok' && !c.bridge.closed && !c.bridge.readOnly, pin: true, editInfo: false, manageMembers: false, leave: false, setDisappearing: false,
          ...(features && features.bridge_channels === true ? { sendReason: c.bridge.channel ? 'channel' : (c.bridge.readOnly ? 'admins_only' : null), react: c.bridge.state === 'ok' && (!c.bridge.channel || c.bridge.reactions === 'own') } : {}),
        },
      } : {}),
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
    const bridged = features && features.bridge_status === true
      ? { bridged: state.bridged.map((x) => ({ ...x, stories: x.stories.map((s) => ({ ...s })), unseen: x.stories.some((s) => !s.seen) })) } : {};
    return { items, me: { user: userOut(me), status: state.statuses.get(me) || null, stories: mine, unseen: false }, ...bridged, serverTime: iso(now()) };
  }
  const findMsg = (id) => { let msg = null; for (const l of state.msgs.values()) msg = l.find((x) => x.id === Number(id)) || msg; return msg; };
  const changed = (msg, type) => { msg.changedAt = now(); return type; };

  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    // 1.21: POST persons/:id/messages answers like the way's POST, plus its way
    res.end(JSON.stringify(res.extra && status === 200 ? { ...body, ...res.extra } : body));
  };
  const err = (res, status, code, extra = null) => json(res, status, { ok: false, code, error: code, ...(extra || {}) });

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
    // Messenger 1.25: a contact's WhatsApp status — watched; an answer or a reaction as a message in the direct chat
    if (a === 'status' && b === 'bridged' && m === 'POST') {
      const it = state.bridged.find((x) => x.stories.some((s) => s.id === Number(c)));
      const st = it && it.stories.find((s) => s.id === Number(c));
      if (!st) return err(res, 404, 'not_found');
      if (d === 'seen') { st.seen = true; return json(res, 200, { ok: true, seen: true, reported: false }); }
      if (d === 'reply') {
        if (!it.chatId || !state.convs.has(it.chatId)) return err(res, 404, 'not_found', { reason: 'no_chat' });
        if ((bd.emoji == null) === (bd.text == null)) return err(res, 400, 'invalid');
        st.seen = true;
        const msg = addMsg(it.chatId, { senderId: me, text: bd.emoji ? `${bd.emoji} auf deinen Status` : bd.text });
        return json(res, 200, { ok: true, message: msgView(msg), conversationId: it.chatId, ...(bd.emoji ? { emoji: bd.emoji } : {}) });
      }
    }
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
        return err(res, f.status, f.code, f.extra);
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
    let seg = p.slice(API.length).split('/').filter(Boolean);
    const m = req.method;
    // 1.21: persons — only for a client that knows them (?people=1 with ?bridged=1)
    const peopleOn = !!(features && features.chat_people === true) && (q.people === '1' || !!(body && body.people === true)) && (q.bridged === '1' || !!(body && body.bridged === true));
    if (seg[0] === 'persons') {
      if (!peopleOn) return err(res, 404, 'not_found');
      const pr = personRoute(res, seg, m, q, body);
      if (pr && pr.rewrite) { seg = pr.rewrite; res.extra = pr.extra; } else return pr;
    }
    const [a, b, c] = seg;

    if (a === 'me' && m === 'GET') {
      return json(res, 200, { ok: true, user: { id: me, name: 'Marc', avatarUrl: null, initials: 'MA', colorHex: '#2FBF71' }, prefs: state.prefs,
        license: { licensed: true, state: 'active', expiresAt: null },
        features: features || { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false },
        integrations: { familie: { lists: !!familie, calendar: !!familie, places: !!familie } },
        limits: { maxBytes: 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400], retentionDays: 0, statusTextMax: 60, storyTextMax: 700, ...(features && features.story_duration === true ? { storyDurationsH: STORY_DURATIONS_H } : {}), pollOptionsMax: 12, pinsMax: 3, listsMax: 20 },
        // Messenger 1.22: „Wer sieht dein Bild?“ from the profile (state.avatarInProfile, a test switch)
        ...(state.avatarInProfile ? { avatarInProfile: true } : {}),
        serverTime: iso(now()) });
    }
    if (a === 'prefs' && m === 'PUT') {
      for (const [k, v] of Object.entries(body || {})) state.prefs[k] = v && typeof v === 'object' ? { ...(state.prefs[k] || {}), ...v } : v;
      return json(res, 200, { ok: true, prefs: state.prefs });
    }
    if (a === 'contacts' && b === 'new-chat' && !c && m === 'GET') return contactsRoute(res, q);
    const rb = bridgeRoute(res, seg, m, body);
    if (rb !== undefined) return rb;
    // 1.14: a chat over a bridge exists only for a client that says it knows them
    const bridged = q.bridged === '1' || !!(body && typeof body === 'object' && body.bridged === true);
    const r14 = await route14(req, res, seg, q, body);
    if (r14 !== undefined) return r14;
    if (a === 'people') return json(res, 200, { ok: true, people: users.filter((x) => x.id !== me).map((x) => ({ id: x.id, name: x.name, avatarUrl: x.avatarUrl, initials: x.initials, colorHex: x.colorHex, color: 'green' })) });
    // 1.20: channels on their own page for a client that knows them (?channels=1)
    const chans = !!(features && features.bridge_channels === true) && (q.channels === '1' || !!(body && typeof body === 'object' && body.channels === true));
    const isChan = (x) => !!(x.bridge && x.bridge.channel);
    if (a === 'conversations' && !b && m === 'GET') {
      const since = q.since ? Date.parse(q.since) : null;
      let list = [...state.convs.values()].filter((x) => (!since || x.updatedAt > since) && (!x.bridge || (bridged && state.msgs.get(x.id).length)) && !(chans && isChan(x))).map((x) => convView(x));
      const cl = chans && bridged ? [...state.convs.values()].filter((x) => isChan(x) && state.msgs.get(x.id).length).map((x) => convView(x)) : null;
      // 1.21: one entry per person (the lead's id), the other ways `folded`
      let folded = null;
      if (peopleOn) {
        folded = [];
        const seen = new Set();
        list = list.flatMap((v) => {
          const pp = personOf(v.id);
          if (!pp) return [v];
          if (seen.has(pp.id)) { folded.push(v.id); return []; }
          seen.add(pp.id);
          const e = personEntry(pp);
          if (e.id !== v.id) folded.push(v.id);
          return [e];
        });
        for (const pp of state.persons.values()) for (const id of pp.ways) if (id !== personEntry(pp).id && !folded.includes(id)) folded.push(id);
      }
      return json(res, 200, { ok: true, conversations: list, removed: [], ...(folded ? { folded } : {}), ...(cl ? { channels: { count: cl.length, unread: cl.reduce((n, x) => n + x.unread, 0) } } : {}), serverTime: iso(now()) });
    }
    if (a === 'channels' && !b && m === 'GET') {
      if (!bridged || !(features && features.bridge_channels === true)) return err(res, 404, 'not_found');
      const cl = [...state.convs.values()].filter((x) => isChan(x) && state.msgs.get(x.id).length).map((x) => convView(x));
      return json(res, 200, { ok: true, channels: cl, removed: [], unread: cl.reduce((n, x) => n + x.unread, 0), serverTime: iso(now()) });
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
      if (!conv || (conv.bridge && !bridged)) return err(res, 404, 'not_found');
      const list = state.msgs.get(conv.id);
      // 1.21: a way of a person names it (the app opens the person)
      if (!c && m === 'GET') return json(res, 200, { ok: true, conversation: { ...convView(conv), ...(peopleOn && personOf(conv.id) ? { person: personEntry(personOf(conv.id)).person } : {}) } });
      if (!c && m === 'PATCH') {
        if (body.title) conv.title = body.title;
        if (body.notify === 'all' || body.notify === 'none') conv.notify = body.notify;
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
        if (conv.bridge && conv.bridge.readOnly && features && features.bridge_channels === true) return err(res, 409, 'bridge_read_only', { reason: conv.bridge.channel ? 'channel' : 'admins_only' });
        if (conv.bridge) {
          const fileKind = state.bridge.media && ['image', 'voice', 'file'].includes(body.kind) && body.mediaId;
          // 1.27: a location where the bridge sends one — lat, lon, label only
          const locKind = state.bridge.location && body.kind === 'location' && body.location && !body.text;
          if (locKind && Object.keys(body.location).some((k) => !['lat', 'lon', 'label'].includes(k))) return err(res, 400, 'invalid');
          if (!fileKind && !locKind && ((body.kind != null && body.kind !== 'text') || ['mediaId', 'thumbMediaId', 'video', 'meta'].some((k) => body[k] != null))) return err(res, 409, 'bridge_text_only', { reason: 'kind' });
          if ([locKind ? null : 'location', 'poll', 'event', 'arrival', 'action', 'replyStory'].some((k) => k && body[k] != null)) return err(res, 409, 'bridge_text_only', { reason: 'kind' });
          if (fileKind) {
            const fm = state.media.get(body.mediaId);
            if (!fm) return err(res, 409, 'media_invalid');
            if (state.bridge.scanPending > 0) { state.bridge.scanPending -= 1; res.setHeader('Retry-After', '1'); return err(res, 423, 'scan_pending'); }
            const k = body.kind === 'file' ? (/^video\//.test(fm.mime) ? 'video' : 'file') : body.kind;
            const types = { image: ['image/jpeg', 'image/png', 'image/webp'], video: ['video/mp4'], voice: ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg'] }[k];
            if (types && !types.includes(fm.mime)) return err(res, 409, 'bridge_media_type', { reason: k });
          }
          const st = conv.bridge.state;
          if (st === 'locked') return err(res, 403, 'bridge_locked');
          if (st === 'off') return err(res, 409, 'bridge_off', { reason: 'off' });
          if (st === 'unreachable') return err(res, 503, 'bridge_unreachable', { reason: 'not_running' });
          if (st === 'logged_out' || st === 'unlinked') return err(res, 409, 'bridge_unlinked', { reason: st });
          if (conv.bridge.closed) return err(res, 502, 'bridge_failed', { reason: 'chat_closed' });
          const bm = addMsg(conv.id, { senderId: me, text: body.text || null, clientId: body.clientId, kind: fileKind || locKind ? body.kind : 'text', mediaId: fileKind ? body.mediaId : null, meta: fileKind ? body.meta || null : null });
          if (locKind) bm.location = { ...body.location };
          bm.bridge = { sender: null, remote: false, state: state.bridge.sendFails ? 'failed' : 'sent', reason: state.bridge.sendFails || null, placeholder: null };
          state.lastSendBody = body;
          return json(res, 200, { ok: true, message: msgView(bm), duplicate: false });
        }
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
        if (body.location) msg.location = { ...body.location };
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
      if (!msg || (state.convs.get(msg.conversationId).bridge && !bridged)) return err(res, 404, 'not_found');
      // 1.17: a file of the older history, fetched now
      if (c === 'fetch' && m === 'POST') {
        if (!state.convs.get(msg.conversationId).bridge) return err(res, 404, 'not_found');
        const ph = msg.bridge && msg.bridge.placeholder;
        // 1.17: on request (bridge_history); 1.19: once more after it failed (`retry: true`)
        const again = ph && ph.state === 'failed' && ph.retry === true;
        if (!again && !(features && features.bridge_history === true)) return err(res, 404, 'not_found');
        if (!ph || (ph.state !== 'on_request' && !again)) return err(res, 400, 'invalid');
        state.bridge.fetches.push(msg.id);
        msg.bridge = { ...msg.bridge, placeholder: { ...ph, state: 'loading' } };
        msg.changedAt = now();
        return json(res, 200, { ok: true, message: msgView(msg) });
      }
      if (c === 'resend' && m === 'POST') {
        if (!state.convs.get(msg.conversationId).bridge) return err(res, 404, 'not_found');
        if (!msg.bridge || msg.bridge.state !== 'failed') return err(res, 400, 'invalid');
        msg.bridge = { ...msg.bridge, state: state.bridge.sendFails ? 'failed' : 'sent', reason: state.bridge.sendFails || null };
        msg.changedAt = now();
        return json(res, 200, { ok: true, message: msgView(msg) });
      }
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
    addBridgeConv,
    addBridgeMsg,
    addPerson,
    personEntry,
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
    fail(prefix, status, code = 'failed', times = null, extra = null) { state.failures.set(prefix, { status, code, times, extra }); },
    heal() { state.failures.clear(); },
    dropStreams() { for (const s of streams) s.destroy(); },
    close() {
      for (const s of streams) s.destroy();
      return new Promise((r) => server.close(() => r()));
    },
  };
}

module.exports = { messengerServer, PLUGIN, API, MEDIA, FEATURES_14 };
