'use strict';

// A small in-memory GateControl server with the GateDrop plugin (contract
// "GateDrop – Schnittstelle" B + core A1 media upload): enough for the
// Windows client tests.
//
// Answers in the exact shapes of the plugin (gatecontrol-plugins
// plugins/gatecontrol-gatedrop README "App-API"): send ids of 24 hex,
// items { index, mediaId|null, name, mime, bytes, local, available },
// GET items/<id> → { item, url }, GET transfers/<id> → { transfer },
// POST transfers/<id>/result → { transfer, delivery, fallback, missing? },
// POST sends/<id>/items { items: [{ index, mediaId }] },
// GET pending (GateDrop 1.1.0, plugins PR #79) → { ok, items: [send view,
// role "sent"] } oldest first: the sends with a `waiting` / `delivered`
// delivery to this device (me.deviceId); the call flips `waiting` to
// `delivered`, POST sends/<id>/opened from this device marks it `opened`
// (out of the list). Deliveries to an own device that is offline get `waiting`.
//
//   const srv = await gatedropServer({ targets, direct: (body, sendId) => [...] });
//   (direct entries the test returns are registered as transfers of that send)
//   srv.url, srv.state (requests, presence, sends, media, results, addItems, uploads),
//   srv.addSend(send) → stored send (GET sends/<id>, items downloadable),
//   srv.cutUploadAfter = n  → the next resumable part breaks off after n bytes (whole 64 KiB kept),
//   srv.state.failCreate = { status, code } → POST sends answers with that error,
//   srv.addSend(send, { pending: true }) → a `waiting` delivery to this device (GET pending lists it until POST opened),
//   srv.state.pendingMode = 'ok' | 404 (older plugin) | 'no_device' (409),
//   srv.state.mediaFail = Set of mediaIds whose download answers 500,
//   GET / PUT device (GateDrop 1.2.0): srv.state.device = { receiveFrom }, srv.state.deviceMode =
//     'ok' | 404 (older plugin) | 'no_device' (409); srv.state.deviceCalls = [{ method, body }],
//   targets.peopleDevices: others' devices open for everyone (sendable like own devices; a send's
//     `from.own` is false for another person), srv.state.closed = Set of their ids closed meanwhile
//     (POST sends → 409 unavailable),
//   srv.failTransfer(id, error) → the other end reported a failure (GET transfers/<id>: status failed, no key /
//     ticket, peer { ok: false, error } as GateDrop 1.2.1 answers),
//   srv.close()

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = 'gatecontrol-gatedrop';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;

async function gatedropServer({ plugin = true, version = '1.0.0', targets = null, direct = null, inbox = null } = {}) {
  const state = {
    plugin,
    requests: [],
    presence: [],
    sends: new Map(),
    media: new Map(),       // mediaId → { data, mime }
    results: [],            // transfer results
    addItems: [],
    opened: [],
    endedLinks: [],
    uploads: new Map(),     // uploadId → { data, total, mime } (resumable, partial)
    uploadCalls: [],
    transfers: new Map(),   // transferId → transfer (GET transfers/<id>: { id, sendId, side, mode, status, … })
    pendingMode: 'ok',
    device: { receiveFrom: 'self' },
    deviceMode: 'ok',
    deviceCalls: [],
    closed: new Set(),
    pendingCalls: 0,
    mediaFail: new Set(),
    targets: targets || {
      ok: true,
      me: { id: 2, name: 'Marc', canLink: true, canNas: true, deviceId: '42', receiveFrom: 'self' },
      people: [{ id: 'family', name: 'Familie', avatar: null, initials: null, colorHex: null, kind: 'family' }, { id: 8, name: 'Anna', avatar: null, initials: 'AN', colorHex: '#84CC16', kind: 'user' }],
      devices: [{ id: '43', name: 'Pixel', platform: 'android', online: true, direct: false, mode: null }],
      peopleDevices: [],
      nas: [{ id: 1, label: 'Fotos', path: '/Familie/Fotos' }],
      links: { enabled: true },
      messenger: true,
      limits: { maxItems: 20, maxBytes: 2147483648, types: ['image/*', 'video/*', 'audio/*', 'application/*', 'text/plain'], textMax: 20000, noteMax: 500, retentionDays: 7, linkExpires: ['1h', '1d', '7d', 'once'], directPort: 47731, presenceEveryS: 300, ticketS: 600 },
      storage: { bytes: 0, quota: 10737418240 },
      serverTime: new Date().toISOString(),
    },
    inbox: inbox || { received: [], sent: [], links: [] },
    direct,
  };
  const srv = { state, cutUploadAfter: null };

  const json = (res, status, body, headers = {}) => {
    const data = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': data.length, ...headers });
    res.end(data);
  };
  const readBody = (req) => new Promise((resolve) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', () => resolve(Buffer.concat(parts)));
  });

  const hex24 = () => crypto.randomBytes(12).toString('hex');
  const iso = (ms) => (ms ? new Date(ms).toISOString() : null);

  /** A send as the plugin answers it (GET sends/<id>, inbox entries). */
  const view = (st, role = 'received') => ({
    id: st.id, role, createdAt: iso(st.createdAt), expiresAt: iso(st.createdAt + 7 * 86400000), expired: false,
    from: {
      userId: st.from && st.from.userId != null ? st.from.userId : 3, name: (st.from && st.from.name) || 'Anna', avatarUrl: null, deviceId: (st.from && st.from.deviceId) || '41', deviceName: (st.from && st.from.deviceName) || null,
      ...(st.from && typeof st.from.own === 'boolean' ? { own: st.from.own } : {}),
    },
    text: st.text || null, link: st.link || null, note: st.note || null,
    items: st.items.map((i) => ({ index: i.idx, mediaId: i.mediaId || null, name: i.name, mime: i.mime || null, bytes: i.bytes, local: !!i.local && !i.mediaId, available: !!i.mediaId })),
    deliveries: st.deliveries || [],
  });
  srv.view = view;

  srv.failTransfer = (id, error = 'failed') => {
    const tr = state.transfers.get(id);
    if (!tr) throw new Error(`no transfer ${id}`);
    Object.assign(tr, { status: 'failed', key: null, ticket: null, peer: { ok: false, error } });
  };

  /** A received send with files on the server: items { name, data, mime }. */
  srv.addSend = (send, { pending = false } = {}) => {
    const st = { id: send.id || hex24(), createdAt: send.createdAt || Date.now(), from: send.from || null, text: send.text, link: send.link, note: send.note, deliveries: [] };
    if (pending) st.deliveries.push({ id: 1, kind: 'device', target: String(state.targets.me.deviceId), label: 'Laptop', status: 'waiting', via: null, at: iso(st.createdAt), error: null, openedAt: null });
    st.items = (send.items || []).map((it, idx) => {
      const mediaId = it.local ? null : (it.mediaId || crypto.randomBytes(16).toString('hex'));
      if (it.data && mediaId) state.media.set(mediaId, { data: it.data, mime: it.mime || 'application/octet-stream' });
      return { idx, mediaId, name: it.name, mime: it.mime || 'application/octet-stream', bytes: it.data ? it.data.length : it.bytes, local: !!it.local };
    });
    state.sends.set(st.id, st);
    return view(st);
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    state.requests.push({ method: req.method, path: p, query: Object.fromEntries(url.searchParams) });
    if (req.headers['x-api-token'] !== 'gc_token') return json(res, 401, { error: 'unauthorized' });

    if (req.method === 'GET' && p === '/api/v1/client/plugins') {
      return json(res, 200, { plugins: state.plugin ? [{ id: PLUGIN, version, tab: null }] : [{ id: 'gatecontrol-messenger', version: '1.8.0' }] });
    }

    // ── Media (core A1, resumable parts of core 1.193) ──
    if (req.method === 'GET' && p.startsWith(`${MEDIA}/uploads/`)) {
      const up = state.uploads.get(decodeURIComponent(p.slice(MEDIA.length + 9)));
      return up ? json(res, 200, { offset: up.data.length, total: up.total, mime: up.mime }) : json(res, 404, { error: 'not_found' });
    }
    if (req.method === 'PUT' && p === MEDIA) {
      const uploadId = url.searchParams.get('uploadId');
      const offset = Number(url.searchParams.get('offset') || 0);
      const range = req.headers['content-range'] || null;
      state.uploadCalls.push({ uploadId, offset, range, length: Number(req.headers['content-length']) });
      if (uploadId) {
        const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(range || '');
        if (!m || Number(m[1]) !== offset) return json(res, 400, { error: 'bad range', code: 'bad_range' });
        const total = Number(m[3]);
        const up = state.uploads.get(uploadId) || { data: Buffer.alloc(0), total, mime: req.headers['content-type'] };
        state.uploads.set(uploadId, up);
        if (offset !== up.data.length) { req.resume(); return json(res, 409, { error: 'offset', code: 'offset_mismatch', offset: up.data.length }); }
        if (srv.cutUploadAfter !== null) {
          const cut = srv.cutUploadAfter;
          srv.cutUploadAfter = null;
          let got = Buffer.alloc(0);
          req.on('data', (c) => {
            got = Buffer.concat([got, c]);
            if (got.length >= cut) {
              const keep = Math.floor(cut / 65536) * 65536; // the server keeps whole 64 KiB blocks
              up.data = Buffer.concat([up.data, got.subarray(0, keep)]);
              req.socket.destroy();
            }
          });
          return undefined;
        }
        const body = await readBody(req);
        up.data = Buffer.concat([up.data, body]);
        if (up.data.length < up.total) return json(res, 200, { ok: true, complete: false, uploadId, offset: up.data.length, total: up.total });
        state.uploads.delete(uploadId);
        const mediaId = crypto.randomBytes(16).toString('hex');
        state.media.set(mediaId, { data: up.data, mime: up.mime });
        return json(res, 200, { ok: true, complete: true, mediaId, mime: up.mime, bytes: up.data.length });
      }
      const body = await readBody(req);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data: body, mime: req.headers['content-type'] });
      return json(res, 200, { mediaId, mime: req.headers['content-type'], bytes: body.length });
    }

    if (req.method === 'GET' && p.startsWith(`${MEDIA}/`)) {
      const md = state.media.get(p.slice(MEDIA.length + 1));
      if (state.mediaFail.has(p.slice(MEDIA.length + 1))) return json(res, 500, { ok: false, code: 'internal', error: 'broken' });
      if (!md) return json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
      res.writeHead(200, { 'Content-Type': md.mime, 'Content-Length': md.data.length });
      return res.end(md.data);
    }

    if (!p.startsWith(API)) return json(res, 404, { error: 'not_found' });
    const route = p.slice(API.length);
    const body = req.method === 'GET' || req.method === 'HEAD' ? null : JSON.parse((await readBody(req)).toString('utf8') || '{}');
    if (!state.plugin) return json(res, 404, { error: 'not_found' });
    let m;

    if (req.method === 'GET' && route === 'targets') return json(res, 200, { ...state.targets, me: { ...state.targets.me, receiveFrom: state.device.receiveFrom } });
    if (route === 'device' && (req.method === 'GET' || req.method === 'PUT')) {
      state.deviceCalls.push({ method: req.method, body });
      if (state.deviceMode === 404) return json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
      if (state.deviceMode === 'no_device') return json(res, 409, { ok: false, code: 'no_device', error: 'no device' });
      if (req.method === 'PUT') {
        if (!body || !['self', 'everyone'].includes(body.receiveFrom)) return json(res, 400, { ok: false, code: 'invalid', error: 'invalid' });
        state.device = { receiveFrom: body.receiveFrom };
      }
      return json(res, 200, { ok: true, device: { id: String(state.targets.me.deviceId), receiveFrom: state.device.receiveFrom } });
    }
    if (req.method === 'PUT' && route === 'presence') {
      state.presence.push(body);
      return json(res, 200, { ok: true, presence: { lan: body.lan, port: body.port, listening: body.listening, everyS: 300, freshS: 900 } });
    }
    if (req.method === 'POST' && route === 'sends') {
      if (state.failCreate) return json(res, state.failCreate.status, { error: state.failCreate.code, code: state.failCreate.code });
      if ((body.to.devices || []).some((d) => state.closed.has(String(d)))) return json(res, 409, { ok: false, code: 'unavailable', error: 'Das Gerät nimmt nichts mehr an.' });
      const id = hex24();
      const st = { id, createdAt: Date.now(), from: { userId: 2, name: 'Marc', deviceId: '42', deviceName: 'Laptop' }, text: body.text, link: body.link, note: body.note, to: body.to, deliveries: [] };
      st.items = (body.items || []).map((it, idx) => {
        const md = it.mediaId ? state.media.get(it.mediaId) : null;
        return { idx, mediaId: it.local ? null : it.mediaId, name: it.name, mime: it.mime || (md && md.mime) || null, bytes: it.local ? it.bytes : (md ? md.data.length : null), local: !!it.local };
      });
      state.sends.set(id, st);
      const direct = state.direct ? state.direct(body, id) : [];
      for (const d of direct) {
        if (!state.transfers.has(d.transferId)) {
          state.transfers.set(d.transferId, { id: d.transferId, sendId: id, side: 'receiver', mode: d.mode, status: 'open', fromDevice: '42', toDevice: d.deviceId, from: { userId: 2, deviceId: '42', deviceName: 'Laptop' }, candidates: d.candidates, key: d.key, ticket: d.ticket, expiresAt: d.expiresAt, items: st.items.map((i) => ({ index: i.idx, name: i.name, bytes: i.bytes, mime: i.mime })) });
        } else {
          state.transfers.get(d.transferId).sendId = id;
        }
      }
      let n = 1;
      for (const d of body.to.devices || []) {
        const own = (state.targets.devices || []).find((x) => String(x.id) === String(d));
        const other = own ? null : (state.targets.peopleDevices || []).find((x) => String(x.id) === String(d));
        const dev = own || (other ? { ...other, name: `${other.name} (${other.owner.name})` } : null);
        const isDirect = direct.some((x) => x.deviceId === d);
        // An own device that is offline: the send waits in its `pending` list.
        const status = isDirect ? 'direct' : dev && dev.online === false ? 'waiting' : 'delivered';
        st.deliveries.push({ id: n++, kind: 'device', target: d, label: dev ? dev.name : d, status, via: isDirect ? 'direct' : status === 'waiting' ? null : 'server', at: iso(Date.now()), error: null, openedAt: null });
      }
      for (const u of body.to.people || []) st.deliveries.push({ id: n++, kind: 'person', target: String(u), label: String(u), status: 'delivered', via: 'server', at: iso(Date.now()), error: null, openedAt: null });
      let link = null;
      if (body.to.link) {
        const token = crypto.randomBytes(16).toString('base64url');
        link = { token, url: `https://gc.example/s/${token}`, pin: body.to.link.pin ? '4711' : null, expiresAt: iso(Date.now() + 86400000), maxDownloads: body.to.link.expires === 'once' ? 1 : null };
        st.deliveries.push({ id: n++, kind: 'link', target: token, label: st.items[0] ? st.items[0].name : 'Link', status: 'delivered', via: 'server', at: iso(Date.now()), error: null, openedAt: null });
      }
      return json(res, 200, { ok: true, id, send: view(st, 'sent'), deliveries: st.deliveries, link, direct });
    }
    if (req.method === 'POST' && (m = /^sends\/([^/]+)\/items$/.exec(route))) {
      const st = state.sends.get(m[1]);
      if (!st) return json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
      for (const it of body.items) {
        const item = st.items.find((x) => x.idx === it.index);
        if (!item || !state.media.has(it.mediaId) || item.mediaId) return json(res, 409, { ok: false, code: 'media_invalid', error: 'media' });
      }
      for (const it of body.items) {
        const item = st.items.find((x) => x.idx === it.index);
        item.mediaId = it.mediaId;
        item.local = false;
      }
      state.addItems.push({ sendId: m[1], items: body.items });
      return json(res, 200, { ok: true, send: view(st, 'sent') });
    }
    if (req.method === 'POST' && (m = /^sends\/([^/]+)\/opened$/.exec(route))) {
      state.opened.push(m[1]);
      const st = state.sends.get(m[1]);
      const own = st && st.deliveries.find((d) => d.kind === 'device' && d.target === String(state.targets.me.deviceId));
      if (own) { own.status = 'opened'; own.openedAt = iso(Date.now()); }
      return st ? json(res, 200, { ok: true, send: view(st) }) : json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
    }
    if (req.method === 'GET' && (m = /^sends\/([^/]+)$/.exec(route))) {
      const st = state.sends.get(m[1]);
      return st ? json(res, 200, { ok: true, send: view(st) }) : json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
    }
    if (req.method === 'POST' && (m = /^transfers\/([^/]+)\/result$/.exec(route))) {
      state.results.push({ transferId: m[1], ...body });
      const tr = state.transfers.get(m[1]);
      const st = tr && state.sends.get(tr.sendId);
      if (!tr || !st) return json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
      const delivery = { id: 1, kind: 'device', target: tr.toDevice, status: body.ok ? 'delivered' : 'pending', via: body.ok ? 'direct' : null, error: body.ok ? null : 'direct_failed', at: iso(Date.now()) };
      if (body.ok) { tr.status = 'done'; return json(res, 200, { ok: true, transfer: { id: tr.id, status: 'done', side: 'sender' }, delivery, fallback: null }); }
      tr.status = 'failed';
      const missing = st.items.filter((i) => !i.mediaId).map((i) => i.idx);
      return json(res, 200, { ok: true, transfer: { id: tr.id, status: 'failed', side: 'sender' }, delivery, fallback: missing.length ? 'upload' : 'server', ...(missing.length ? { missing } : {}) });
    }
    if (req.method === 'GET' && (m = /^transfers\/([^/]+)$/.exec(route))) {
      const tr = state.transfers.get(m[1]);
      return tr ? json(res, 200, { ok: true, transfer: tr }) : json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
    }
    if (req.method === 'GET' && route === 'pending') {
      state.pendingCalls++;
      if (state.pendingMode === 404) return json(res, 404, { error: 'not_found' });
      if (state.pendingMode === 'no_device') return json(res, 409, { ok: false, code: 'no_device', error: 'no device' });
      const me = String(state.targets.me.deviceId);
      const mine = (st) => st.deliveries.find((d) => d.kind === 'device' && d.target === me && (d.status === 'waiting' || d.status === 'delivered'));
      const list = [...state.sends.values()].filter(mine).sort((a, b) => a.createdAt - b.createdAt);
      const items = list.map((st) => view(st, 'sent'));
      for (const st of list) { const d = mine(st); if (d.status === 'waiting') { d.status = 'delivered'; d.via = 'server'; } }
      return json(res, 200, { ok: true, items });
    }
    if (req.method === 'GET' && route === 'inbox') {
      const kind = url.searchParams.get('kind');
      return json(res, 200, { ok: true, kind, items: state.inbox[kind] || [], hasMore: false });
    }
    if (req.method === 'DELETE' && (m = /^links\/([^/]+)$/.exec(route))) { state.endedLinks.push(m[1]); return json(res, 200, { ok: true, revoked: true }); }
    if (req.method === 'GET' && (m = /^items\/([^/]+)$/.exec(route))) {
      for (const st of state.sends.values()) {
        const item = st.items.find((i) => i.mediaId === m[1]);
        if (item) {
          return json(res, 200, { ok: true, item: { sendId: st.id, index: item.idx, mediaId: item.mediaId, name: item.name, mime: item.mime, bytes: item.bytes, local: false, available: true }, url: `${MEDIA}/${item.mediaId}` });
        }
      }
      return json(res, 404, { ok: false, code: 'not_found', error: 'not found' });
    }
    return json(res, 404, { error: 'not_found' });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  srv.url = `http://127.0.0.1:${server.address().port}`;
  srv.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  return srv;
}

module.exports = { gatedropServer, PLUGIN, API, MEDIA };
