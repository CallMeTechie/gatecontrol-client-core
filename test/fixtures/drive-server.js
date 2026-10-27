'use strict';

// A fake GateControl server with the plugin gatecontrol-drive (README "API")
// for the DriveService tests: the plugin list, me / areas, a small tree
// (nodes, children, mkdir, rename / move, trash, restore, purge), versions,
// uploads/check + commit, content, search, links, and the core media routes
// (raw / resumable PUT, GET of a file, its preview).
//
//   const srv = await driveServer({ plugin, seat, licence });
//   srv.url, srv.state (requests, nodes, media, uploadCalls, links),
//   srv.state.fail = { '<METHOD> <route>': { status, code } } — refuse a route,
//   srv.close()

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = 'gatecontrol-drive';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;
const PREVIEW_JPEG = Buffer.from('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AN//Z', 'base64');

async function driveServer({ plugin = true, version = '1.4.0', seat = 'family', licence = true } = {}) {
  let nextId = 100;
  const iso = (ms) => new Date(ms).toISOString();
  const state = {
    plugin,
    requests: [],
    uploadCalls: [],
    uploads: new Map(),
    media: new Map(),
    links: [],
    fail: {},
    nodes: new Map(),
    versions: new Map(), // nodeId → [{ id, rev, size, at, by, mediaId }]
    pending: new Set(),  // mediaIds whose preview is still being made
  };
  const areas = [
    { id: 'mine:2', kind: 'mine', label: 'Meine Dateien', role: 'manage', via: 'owner', rootId: 1, owner: 2, archived: false, storage: { bytes: 1024, quota: 0, form: 'readable', target: { kind: 'local', label: 'Dieser Server' }, state: 'ok' } },
    { id: 'family:1', kind: 'family', label: 'Familie Muster', role: 'write', via: 'member', rootId: 2, owner: null, archived: false },
    { id: 'child:7', kind: 'child', label: 'Lena', role: 'read', via: 'parent', rootId: 3, owner: 7, archived: false },
    { id: 'team:1', kind: 'team', label: 'Büro', role: 'read', via: 'member', rootId: 4, owner: null, archived: true },
  ];
  const node = (o) => {
    const n = { parentId: null, isDir: false, size: 0, mime: null, sha256: null, mediaId: null, rev: 1, createdAt: iso(1760000000000), createdBy: 2, updatedAt: iso(1760000000000), updatedBy: 2, deleted: false, mtime: iso(1760000000000), ...o };
    state.nodes.set(n.id, n);
    return n;
  };
  node({ id: 1, areaId: 'mine:2', name: 'Meine Dateien', isDir: true });
  node({ id: 2, areaId: 'family:1', name: 'Familie Muster', isDir: true });
  node({ id: 3, areaId: 'child:7', name: 'Lena', isDir: true });
  node({ id: 4, areaId: 'team:1', name: 'Büro', isDir: true });
  node({ id: 10, areaId: 'mine:2', parentId: 1, name: 'Dokumente', isDir: true });
  const photoMedia = 'photoMedia000001';
  state.media.set(photoMedia, { data: Buffer.from('jpeg-bytes'), mime: 'image/jpeg' });
  node({ id: 11, areaId: 'mine:2', parentId: 1, name: 'Foto.jpg', size: 10, mime: 'image/jpeg', mediaId: photoMedia, sha256: 'a'.repeat(64), rev: 2 });
  const docMedia = 'docMedia00000001';
  state.media.set(docMedia, { data: Buffer.from('%PDF-1.4 brief'), mime: 'application/pdf' });
  node({ id: 12, areaId: 'mine:2', parentId: 10, name: 'Brief.pdf', size: 14, mime: 'application/pdf', mediaId: docMedia, sha256: crypto.createHash('sha256').update('%PDF-1.4 brief').digest('hex') });
  const oldMedia = 'oldMedia00000001';
  state.media.set(oldMedia, { data: Buffer.from('old'), mime: 'image/jpeg' });
  state.versions.set(11, [{ id: 501, rev: 1, size: 3, at: iso(1759000000000), by: 2, mediaId: oldMedia }]);
  const toolMedia = 'toolMedia0000001';
  state.media.set(toolMedia, { data: Buffer.from('MZ'), mime: 'application/x-msdownload' });
  node({ id: 13, areaId: 'mine:2', parentId: 1, name: 'setup.exe', size: 2, mime: 'application/x-msdownload', mediaId: toolMedia });

  const srv = { state, cutUploadAfter: null };

  const json = (res, status, body) => {
    const data = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': data.length });
    res.end(data);
  };
  const refuse = (res, status, code) => json(res, status, { ok: false, code, error: code });
  const readBody = (req) => new Promise((resolve) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', () => resolve(Buffer.concat(parts)));
  });
  const view = (n) => ({
    ...n,
    preview: !n.isDir && n.mediaId && /^image\//.test(n.mime || '') ? { url: `${MEDIA}/${n.mediaId}/preview`, largeUrl: `${MEDIA}/${n.mediaId}/preview?size=large` } : (n.isDir ? undefined : null),
  });
  const areaOf = (n) => areas.find((a) => a.id === n.areaId);
  const writable = (n) => { const a = areaOf(n); return a && !a.archived && (a.role === 'write' || a.role === 'manage'); };
  const crumbs = (n) => {
    const out = [];
    for (let c = n; c; c = c.parentId ? state.nodes.get(c.parentId) : null) out.unshift({ id: c.id, name: c.name });
    return out;
  };
  const children = (id) => [...state.nodes.values()].filter((n) => n.parentId === id && !n.deleted)
    .sort((a, b) => (Number(b.isDir) - Number(a.isDir)) || a.name.localeCompare(b.name));
  const taken = (parentId, name) => children(parentId).find((n) => n.name.toLowerCase() === name.toLowerCase());
  const freeName = (parentId, name) => {
    if (!taken(parentId, name)) return name;
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';
    for (let i = 2; ; i++) if (!taken(parentId, `${base} (${i})${ext}`)) return `${base} (${i})${ext}`;
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    state.requests.push({ method: req.method, path: p, query: Object.fromEntries(url.searchParams) });
    if (req.headers['x-api-token'] !== 'gc_token') return json(res, 401, { error: 'unauthorized' });

    if (p === '/api/v1/client/plugins') {
      return json(res, 200, { ok: true, plugins: state.plugin ? [{ id: PLUGIN, name: 'Drive', version, tab: null }] : [] });
    }

    // ── Media (core: raw / resumable upload, file, preview) ──
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
        if (!m || Number(m[1]) !== offset) return refuse(res, 400, 'bad_range');
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
              const keep = Math.floor(cut / 65536) * 65536;
              up.data = Buffer.concat([up.data, got.subarray(0, keep)]);
              req.socket.destroy();
            }
          });
          return undefined;
        }
        up.data = Buffer.concat([up.data, await readBody(req)]);
        if (up.data.length < up.total) return json(res, 200, { ok: true, complete: false, uploadId, offset: up.data.length, total: up.total });
        state.uploads.delete(uploadId);
        const mediaId = crypto.randomBytes(16).toString('hex');
        state.media.set(mediaId, { data: up.data, mime: up.mime });
        return json(res, 200, { ok: true, complete: true, mediaId, mime: up.mime, bytes: up.data.length });
      }
      const body = await readBody(req);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data: body, mime: req.headers['content-type'] });
      return json(res, 200, { ok: true, mediaId, mime: req.headers['content-type'], bytes: body.length });
    }
    if (req.method === 'GET' && p.startsWith(`${MEDIA}/`)) {
      const rest = p.slice(MEDIA.length + 1).split('/');
      const md = state.media.get(rest[0]);
      if (!md) return refuse(res, 404, 'not_found');
      if (rest[1] === 'preview') {
        if (state.pending.has(rest[0])) return refuse(res, 503, 'preview_pending');
        if (!/^image\//.test(md.mime)) return refuse(res, 404, 'not_found');
        res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': PREVIEW_JPEG.length });
        return res.end(PREVIEW_JPEG);
      }
      res.writeHead(200, { 'Content-Type': md.mime, 'Content-Length': md.data.length });
      return res.end(md.data);
    }

    if (!p.startsWith(API)) return json(res, 404, { error: 'not_found' });
    if (!state.plugin) return json(res, 404, { error: 'not_found' });
    const route = p.slice(API.length);
    const body = req.method === 'GET' ? null : JSON.parse((await readBody(req)).toString('utf8') || '{}');
    state.requests[state.requests.length - 1].body = body;
    const f = state.fail[`${req.method} ${route}`];
    if (f) return refuse(res, f.status, f.code);
    if (route !== 'me' && !licence) return refuse(res, 403, 'not_licensed');
    if (route !== 'me' && !seat) return refuse(res, 403, 'no_seat');
    const seg = route.split('/');
    const get = (id) => { const n = state.nodes.get(Number(id)); return n && !n.deleted ? n : null; };

    if (req.method === 'GET' && route === 'me') {
      return json(res, 200, {
        ok: true, me: { id: 2, name: 'Marc', seat: seat || null, deviceId: '42' }, licence: { valid: licence, tier: 'combo' },
        areas: seat ? areas : [], latest: 9, settings: { trashDays: 30, versionsDays: 30 }, limits: { maxBytes: 107374182400 },
        people: [{ id: 2, name: 'Marc' }, { id: 7, name: 'Lena' }], wipes: 0, devices: 1,
      });
    }
    if (req.method === 'GET' && route === 'areas') return json(res, 200, { ok: true, areas });
    if (req.method === 'GET' && route === 'search') {
      const q = String(url.searchParams.get('q') || '').toLowerCase();
      const items = [...state.nodes.values()].filter((n) => !n.deleted && n.parentId && n.name.toLowerCase().includes(q)).map((n) => ({ ...view(n), path: crumbs(n).slice(1, -1).map((c) => c.name).join('/'), match: 'name' }));
      if (q === 'miete') items.push({ ...view(state.nodes.get(12)), path: 'Dokumente', match: 'text', snippet: '… die Miete für Oktober …' });
      return json(res, 200, { ok: true, items });
    }
    if (seg[0] === 'nodes') {
      if (seg.length === 1 && req.method === 'POST') {
        const parent = get(body.parentId);
        if (!parent || !parent.isDir) return refuse(res, 404, 'not_found');
        if (!writable(parent)) return refuse(res, 403, 'forbidden');
        if (taken(parent.id, body.name) && !body.rename) return refuse(res, 409, 'exists');
        return json(res, 200, { ok: true, node: view(node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: freeName(parent.id, body.name), isDir: true })) });
      }
      const n = get(seg[1]);
      if (!n) return refuse(res, 404, 'not_found');
      if (seg.length === 2 && req.method === 'GET') return json(res, 200, { ok: true, node: { ...view(n), crumbs: crumbs(n), role: areaOf(n).role, path: '' } });
      if (seg.length === 2 && req.method === 'PATCH') {
        if (!writable(n)) return refuse(res, 403, 'forbidden');
        if (body.parentId) {
          const target = get(body.parentId);
          if (!target || !target.isDir) return refuse(res, 404, 'not_found');
          if (!writable(target)) return refuse(res, 403, 'forbidden');
          n.parentId = target.id;
          n.areaId = target.areaId;
        }
        if (body.name) {
          if (taken(n.parentId, body.name) && taken(n.parentId, body.name) !== n) return refuse(res, 409, 'exists');
          n.name = body.name;
        }
        return json(res, 200, { ok: true, node: view(n) });
      }
      if (seg.length === 2 && req.method === 'DELETE') {
        if (!writable(n)) return refuse(res, 403, 'forbidden');
        n.deleted = true;
        n.deletedAt = iso(Date.now());
        return json(res, 200, { ok: true, id: n.id, trashed: true });
      }
      if (seg[2] === 'children' && req.method === 'GET') {
        const items = children(n.id).map(view);
        return json(res, 200, { ok: true, items, total: items.length, next: null, role: areaOf(n).role });
      }
      if (seg[2] === 'content' && req.method === 'GET') return json(res, 200, { ok: true, url: '/plugin-media/x', name: n.name, mime: n.mime, size: n.size, mediaId: n.mediaId });
      if (seg[2] === 'versions') {
        const list = state.versions.get(n.id) || [];
        if (seg.length === 3) return json(res, 200, { ok: true, current: view(n), versions: list.map(({ mediaId, ...v }) => v) });
        const v = list.find((x) => x.id === Number(seg[3]));
        if (!v) return refuse(res, 404, 'not_found');
        if (seg[4] === 'content') return json(res, 200, { ok: true, url: '/plugin-media/y', name: n.name, mime: n.mime, size: v.size, mediaId: v.mediaId });
        if (seg[4] === 'restore' && req.method === 'POST') {
          n.mediaId = v.mediaId;
          n.size = v.size;
          n.rev += 1;
          return json(res, 200, { ok: true, node: view(n) });
        }
      }
    }
    if (seg[0] === 'uploads' && seg[1] === 'check') {
      const t = taken(body.parentId, body.name);
      return json(res, 200, { ok: true, exists: !!t, same: !!t && !!body.sha256 && t.sha256 === body.sha256, node: t ? view(t) : null });
    }
    if (seg[0] === 'uploads' && seg[1] === 'commit') {
      const parent = get(body.parentId);
      if (!parent) return refuse(res, 404, 'not_found');
      if (!writable(parent)) return refuse(res, 403, 'forbidden');
      const md = state.media.get(body.mediaId);
      if (!md) return refuse(res, 409, 'upload_invalid');
      const t = taken(parent.id, body.name);
      if (t && body.onConflict === 'version') {
        t.mediaId = body.mediaId;
        t.size = md.data.length;
        t.rev += 1;
        return json(res, 200, { ok: true, node: view(t), created: false });
      }
      if (t && body.onConflict !== 'rename') return json(res, 409, { ok: false, code: 'conflict', error: 'conflict', current: view(t) });
      const n = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: freeName(parent.id, body.name), size: md.data.length, mime: md.mime, mediaId: body.mediaId, sha256: crypto.createHash('sha256').update(md.data).digest('hex') });
      return json(res, 200, { ok: true, node: view(n), created: true });
    }
    if (seg[0] === 'trash') {
      if (seg.length === 1 && req.method === 'GET') {
        return json(res, 200, { ok: true, items: [...state.nodes.values()].filter((n) => n.deleted).map((n) => ({ ...n, preview: null, from: crumbs(state.nodes.get(n.parentId)).map((c) => c.name).join('/') })) });
      }
      const n = state.nodes.get(Number(seg[1]));
      if (!n || !n.deleted) return refuse(res, 404, 'not_found');
      if (seg[2] === 'restore' && req.method === 'POST') {
        n.deleted = false;
        n.name = freeName(n.parentId, n.name);
        return json(res, 200, { ok: true, node: view(n) });
      }
      if (seg.length === 2 && req.method === 'DELETE') {
        state.nodes.delete(n.id);
        return json(res, 200, { ok: true, id: n.id, files: 1 });
      }
    }
    if (seg[0] === 'links') {
      if (seg.length === 1 && req.method === 'POST') {
        const n = get(body.nodeId);
        if (!n) return refuse(res, 404, 'not_found');
        if (!writable(n)) return refuse(res, 403, 'forbidden');
        const token = crypto.randomBytes(12).toString('base64url');
        const link = {
          token, url: `https://gc.example.com/s/${token}`, nodeId: n.id, areaId: n.areaId, kind: n.isDir ? 'folder' : 'files', mode: body.mode,
          title: n.name, name: n.name, path: '', state: 'active', active: true, endedWhy: null,
          expiresAt: body.expires === 'never' ? null : iso(Date.now() + 86400000), pin: !!body.pin, opens: 0, downloads: 0, createdAt: iso(Date.now()), createdBy: 2,
        };
        state.links.push(link);
        return json(res, 200, { ok: true, link });
      }
      if (seg.length === 1 && req.method === 'GET') return json(res, 200, { ok: true, links: state.links, enabled: true });
      if (seg.length === 2 && req.method === 'DELETE') {
        const l = state.links.find((x) => x.token === seg[1]);
        if (!l) return refuse(res, 404, 'not_found');
        l.active = false;
        l.state = 'ended';
        return json(res, 200, { ok: true, ended: true });
      }
    }
    return refuse(res, 404, 'not_found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  srv.url = `http://127.0.0.1:${server.address().port}`;
  srv.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  return srv;
}

module.exports = { driveServer, PLUGIN, API, MEDIA };
