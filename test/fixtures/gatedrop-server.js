'use strict';

// A small in-memory GateControl server with the GateDrop plugin (contract
// "GateDrop – Schnittstelle" B + core A1 media upload): enough for the
// Windows client tests.
//
//   const srv = await gatedropServer({ targets, direct: (body, sendId) => [...] });
//   srv.url, srv.state (requests, presence, sends, media, results, addItems, uploads),
//   srv.addSend(send) → stored send (GET sends/<id>, items downloadable),
//   srv.cutUploadAfter = n  → the next resumable upload breaks off after n bytes,
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
    uploads: new Map(),     // uploadId → Buffer (partial)
    uploadCalls: [],
    transfers: new Map(),   // transferId → transfer description (GET transfers/<id>)
    nextSend: 100,
    targets: targets || {
      me: { canLink: true, canNas: true },
      people: [{ id: 8, name: 'Anna', kind: 'user' }, { id: 'family', name: 'Familie', kind: 'family' }],
      devices: [{ id: 'tok_pixel', name: 'Pixel', platform: 'android', online: true, direct: false }],
      nas: [{ id: 'n1', label: 'Fotos', path: '/Familie/Fotos' }],
      links: { enabled: true },
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

  srv.addSend = (send) => {
    const s = { id: String(send.id || state.nextSend++), createdAt: Date.now(), ...send };
    s.items = (send.items || []).map((it) => {
      const mediaId = it.mediaId || crypto.randomBytes(16).toString('hex');
      if (it.data) state.media.set(mediaId, { data: it.data, mime: it.mime || 'application/octet-stream' });
      return { mediaId, name: it.name, mime: it.mime || 'application/octet-stream', bytes: it.data ? it.data.length : it.bytes };
    });
    state.sends.set(s.id, s);
    return s;
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    state.requests.push({ method: req.method, path: p, query: Object.fromEntries(url.searchParams) });
    if (req.headers['x-api-token'] !== 'gc_token') return json(res, 401, { error: 'unauthorized' });

    if (req.method === 'GET' && p === '/api/v1/client/plugins') {
      return json(res, 200, { plugins: state.plugin ? [{ id: PLUGIN, version, tab: null }] : [{ id: 'gatecontrol-messenger', version: '1.8.0' }] });
    }

    // ── Media (core A1) ─────────────────────────────
    if (req.method === 'PUT' && p === MEDIA) {
      const uploadId = url.searchParams.get('uploadId');
      const offset = Number(url.searchParams.get('offset') || 0);
      state.uploadCalls.push({ uploadId, offset, range: req.headers['content-range'] || null, length: Number(req.headers['content-length']) });
      if (uploadId && srv.cutUploadAfter !== null) {
        const cut = srv.cutUploadAfter;
        srv.cutUploadAfter = null;
        let got = Buffer.alloc(0);
        req.on('data', (c) => {
          got = Buffer.concat([got, c]);
          if (got.length >= cut) {
            state.uploads.set(uploadId, got.subarray(0, cut));
            req.socket.destroy();
          }
        });
        return undefined;
      }
      const body = await readBody(req);
      let data = body;
      if (uploadId) {
        const before = state.uploads.get(uploadId) || Buffer.alloc(0);
        if (offset !== before.length) return json(res, 409, { error: 'offset mismatch', code: 'upload_offset' });
        data = Buffer.concat([before, body]);
        state.uploads.delete(uploadId);
      }
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data, mime: req.headers['content-type'] });
      return json(res, 200, { mediaId, mime: req.headers['content-type'], bytes: data.length });
    }
    if (req.method === 'HEAD' && p.startsWith(`${MEDIA}/uploads/`)) {
      const id = p.slice(`${MEDIA}/uploads/`.length);
      const have = state.uploads.get(id);
      res.writeHead(have ? 200 : 404, { 'Upload-Offset': String(have ? have.length : 0) });
      return res.end();
    }

    if (!p.startsWith(API)) return json(res, 404, { error: 'not_found' });
    const route = p.slice(API.length);
    const body = req.method === 'GET' || req.method === 'HEAD' ? null : JSON.parse((await readBody(req)).toString('utf8') || '{}');
    if (!state.plugin) return json(res, 404, { error: 'not_found' });
    let m;

    if (req.method === 'GET' && route === 'targets') return json(res, 200, state.targets);
    if (req.method === 'PUT' && route === 'presence') { state.presence.push(body); return json(res, 200, { ok: true }); }
    if (req.method === 'POST' && route === 'sends') {
      const id = String(state.nextSend++);
      state.sends.set(id, { id, ...body, createdAt: Date.now() });
      const deliveries = [];
      for (const d of body.to.devices || []) deliveries.push({ kind: 'device', target: d, status: 'pending' });
      for (const u of body.to.people || []) deliveries.push({ kind: 'person', target: String(u), status: 'pending' });
      const answer = { id, deliveries, direct: state.direct ? state.direct(body, id) : [] };
      if (body.to.link) answer.link = { url: `https://gc.example/s/${crypto.randomBytes(16).toString('base64url')}`, pin: body.to.link.pin ? '4711' : null };
      return json(res, 200, answer);
    }
    if (req.method === 'POST' && (m = /^sends\/([^/]+)\/items$/.exec(route))) { state.addItems.push({ sendId: m[1], items: body.items }); return json(res, 200, { ok: true }); }
    if (req.method === 'POST' && (m = /^sends\/([^/]+)\/opened$/.exec(route))) { state.opened.push(m[1]); return json(res, 200, { ok: true }); }
    if (req.method === 'GET' && (m = /^sends\/([^/]+)$/.exec(route))) {
      const s = state.sends.get(m[1]);
      return s ? json(res, 200, { send: s }) : json(res, 404, { error: 'not_found' });
    }
    if (req.method === 'POST' && (m = /^transfers\/([^/]+)\/result$/.exec(route))) {
      state.results.push({ transferId: m[1], ...body });
      return json(res, 200, body.ok ? { ok: true } : { ok: true, fallback: 'upload' });
    }
    if (req.method === 'GET' && (m = /^transfers\/([^/]+)$/.exec(route))) {
      const t = state.transfers.get(m[1]);
      return t ? json(res, 200, t) : json(res, 404, { error: 'not_found' });
    }
    if (req.method === 'GET' && route === 'inbox') return json(res, 200, { items: state.inbox[url.searchParams.get('kind')] || [] });
    if (req.method === 'DELETE' && (m = /^links\/([^/]+)$/.exec(route))) { state.endedLinks.push(m[1]); return json(res, 200, { ok: true }); }
    if (req.method === 'GET' && (m = /^items\/([^/]+)$/.exec(route))) {
      const md = state.media.get(m[1]);
      if (!md) return json(res, 404, { error: 'not_found' });
      res.writeHead(200, { 'Content-Type': md.mime, 'Content-Length': md.data.length });
      return res.end(md.data);
    }
    return json(res, 404, { error: 'not_found' });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  srv.url = `http://127.0.0.1:${server.address().port}`;
  srv.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  return srv;
}

module.exports = { gatedropServer, PLUGIN, API, MEDIA };
