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
//   srv.state.log — the change log (GET changes?since=): every create / update / move / delete / restore / purge,
//   srv.mutate.* — changes made "by another device" (create a file or folder, change, rename / move, delete),
//   srv.close()
//
// Drive 1.5 (`driveServer({ features: ['devices', 'emptyFiles'] })`): `me.features`,
// PUT devices/<id> (folder Meine Dateien › Geräte › <name>, names unique), PUT devices/<id>/folders
// (srv.state.devices), empty files (uploads/commit { size: 0 } without media, content { empty: true }).

const http = require('node:http');
const crypto = require('node:crypto');

const PLUGIN = 'gatecontrol-drive';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;
const PREVIEW_JPEG = Buffer.from('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AN//Z', 'base64');

async function driveServer({ plugin = true, version = '1.4.0', seat = 'family', licence = true, features = null } = {}) {
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
    log: [],             // { seq, op, areaId, nodeId, device }
    seq: 9,
    devices: new Map(),  // Drive 1.5: id → { id, name, platform, version, folderId, folders }
  };
  const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const logChange = (op, n, device = '42', areaId = n.areaId) => { state.log.push({ seq: ++state.seq, op, areaId, nodeId: n.id, at: Date.now(), device }); };
  const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
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

  const srv = { state, cutUploadAfter: null, pageMax: 1000 };
  // nodes below `id` (all, also deleted ones)
  srv.below = (id) => {
    const out = [];
    const stack = [id];
    while (stack.length) {
      const x = stack.pop();
      for (const n of state.nodes.values()) if (n.parentId === x) { out.push(n); stack.push(n.id); }
    }
    return out;
  };
  // Changes "by another device" (they land in the change log with device '77').
  srv.mutate = {
    file(parentId, name, content, { mtime = Date.now() } = {}) {
      const data = Buffer.from(content);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data, mime: 'application/octet-stream' });
      const n = node({ id: ++nextId, areaId: state.nodes.get(parentId).areaId, parentId, name, size: data.length, mediaId, sha256: sha(data), mtime: iso(mtime) });
      logChange('create', n, '77');
      return n;
    },
    dir(parentId, name) {
      const n = node({ id: ++nextId, areaId: state.nodes.get(parentId).areaId, parentId, name, isDir: true });
      logChange('create', n, '77');
      return n;
    },
    change(id, content, { mtime = Date.now() } = {}) {
      const n = state.nodes.get(id);
      const data = Buffer.from(content);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data, mime: 'application/octet-stream' });
      Object.assign(n, { mediaId, size: data.length, sha256: sha(data), rev: n.rev + 1, mtime: iso(mtime) });
      logChange('update', n, '77');
      return n;
    },
    place(id, { name, parentId } = {}) {
      const n = state.nodes.get(id);
      if (name) n.name = name;
      if (parentId) n.parentId = parentId;
      logChange('move', n, '77');
      return n;
    },
    remove(id) {
      const n = state.nodes.get(id);
      n.deleted = true;
      for (const d of srv.below(id)) d.deleted = true;
      logChange('delete', n, '77');
      return n;
    },
  };

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
        areas: seat ? areas : [], latest: state.seq, settings: { trashDays: 30, versionsDays: 30 }, limits: { maxBytes: 107374182400 },
        people: [{ id: 2, name: 'Marc' }, { id: 7, name: 'Lena' }], wipes: 0, devices: 1,
        ...(features ? { features } : {}),
      });
    }
    if (features && features.includes('devices') && seg[0] === 'devices' && seg[1] && req.method === 'PUT') {
      const id = decodeURIComponent(seg[1]);
      if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(id)) return refuse(res, 400, 'invalid');
      const devView = (d) => {
        const fo = state.nodes.get(d.folderId);
        return { id: d.id, name: d.name, platform: d.platform, version: d.version, folder: fo ? { id: fo.id, name: fo.name, areaId: fo.areaId, path: `Geräte/${fo.name}`, where: `Meine Dateien › Geräte › ${fo.name}` } : null, folders: d.folders };
      };
      let d = state.devices.get(id);
      if (seg[2] === 'folders') {
        if (!d) return refuse(res, 404, 'not_found');
        d.folders = Array.isArray(body) ? body : body.folders;
        return json(res, 200, { ok: true, device: devView(d) });
      }
      if (!d) {
        // names unique per person: a second "PC" becomes "PC (2)"
        const taken = new Set([...state.devices.values()].map((x) => x.name.toLowerCase()));
        let name = String(body.name || 'PC');
        for (let i = 2; taken.has(name.toLowerCase()); i++) name = `${body.name} (${i})`;
        let geraete = [...state.nodes.values()].find((n) => n.parentId === 1 && !n.deleted && n.name === 'Geräte');
        if (!geraete) { geraete = node({ id: ++nextId, areaId: 'mine:2', parentId: 1, name: 'Geräte', isDir: true }); logChange('create', geraete); }
        let fo = [...state.nodes.values()].find((n) => n.parentId === geraete.id && !n.deleted && n.name === name);
        if (!fo) { fo = node({ id: ++nextId, areaId: 'mine:2', parentId: geraete.id, name, isDir: true }); logChange('create', fo); }
        d = { id, name, platform: body.platform, version: body.version, folderId: fo.id, folders: [] };
        state.devices.set(id, d);
      }
      return json(res, 200, { ok: true, device: devView(d) });
    }
    if (req.method === 'GET' && route === 'areas') return json(res, 200, { ok: true, areas });
    if (req.method === 'GET' && route === 'search') {
      const q = String(url.searchParams.get('q') || '').toLowerCase();
      const items = [...state.nodes.values()].filter((n) => !n.deleted && n.parentId && n.name.toLowerCase().includes(q)).map((n) => ({ ...view(n), path: crumbs(n).slice(1, -1).map((c) => c.name).join('/'), match: 'name' }));
      if (q === 'miete') items.push({ ...view(state.nodes.get(12)), path: 'Dokumente', match: 'text', snippet: '… die Miete für Oktober …' });
      return json(res, 200, { ok: true, items });
    }
    if (req.method === 'GET' && route === 'changes') {
      const since = Number(url.searchParams.get('since') || 0);
      const limit = Math.min(1000, Number(url.searchParams.get('limit') || 500));
      const rows = state.log.filter((c) => c.seq > since);
      const page = rows.slice(0, limit);
      const changes = page.map((c) => {
        const n = state.nodes.get(c.nodeId);
        return { seq: c.seq, op: c.op, areaId: c.areaId, nodeId: c.nodeId, at: iso(c.at), by: 2, device: c.device, node: n && n.areaId === c.areaId ? view(n) : null };
      });
      return json(res, 200, { ok: true, changes, next: page.length ? page[page.length - 1].seq : Math.max(since, state.seq), more: rows.length > limit });
    }
    if (req.method === 'GET' && route === 'nodes/by-path') {
      const area = areas.find((a) => a.id === url.searchParams.get('area'));
      if (!area) return refuse(res, 404, 'not_found');
      let cur = state.nodes.get(area.rootId);
      for (const s of String(url.searchParams.get('path') || '').split('/').filter(Boolean)) {
        cur = taken(cur.id, s);
        if (!cur) return refuse(res, 404, 'not_found');
      }
      return json(res, 200, { ok: true, node: { ...view(cur), crumbs: crumbs(cur).slice(0, -1), role: area.role } });
    }
    if (seg[0] === 'nodes') {
      if (seg.length === 1 && req.method === 'POST') {
        const parent = get(body.parentId);
        if (!parent || !parent.isDir) return refuse(res, 404, 'not_found');
        if (!writable(parent)) return refuse(res, 403, 'forbidden');
        if (taken(parent.id, body.name) && !body.rename) return refuse(res, 409, 'exists');
        const made = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: freeName(parent.id, body.name), isDir: true });
        logChange('create', made);
        return json(res, 200, { ok: true, node: view(made) });
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
        logChange('move', n);
        return json(res, 200, { ok: true, node: view(n) });
      }
      if (seg.length === 2 && req.method === 'DELETE') {
        if (!writable(n)) return refuse(res, 403, 'forbidden');
        n.deleted = true;
        n.deletedAt = iso(Date.now());
        for (const d of srv.below(n.id)) { d.deleted = true; d.deletedAt = n.deletedAt; }
        logChange('delete', n);
        return json(res, 200, { ok: true, id: n.id, trashed: true });
      }
      if (seg[2] === 'children' && req.method === 'GET') {
        const all = children(n.id).map(view);
        const offset = Number(url.searchParams.get('offset') || 0);
        const limit = Math.min(srv.pageMax, Number(url.searchParams.get('limit') || 200));
        const items = all.slice(offset, offset + limit);
        return json(res, 200, { ok: true, items, total: all.length, next: offset + limit < all.length ? offset + limit : null, role: areaOf(n).role });
      }
      if (seg[2] === 'content' && req.method === 'GET') {
        if (!n.isDir && !n.mediaId && n.size === 0) return json(res, 200, { ok: true, url: 'data:,', name: n.name, mime: n.mime, size: 0, mediaId: null, empty: true });
        return json(res, 200, { ok: true, url: '/plugin-media/x', name: n.name, mime: n.mime, size: n.size, mediaId: n.mediaId });
      }
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
      const empty = !!(features && features.includes('emptyFiles') && !body.mediaId && body.size === 0);
      const md = empty ? { data: Buffer.alloc(0), mime: 'application/octet-stream' } : state.media.get(body.mediaId);
      if (!md) return refuse(res, empty || body.size === 0 ? 400 : 409, body.size === 0 ? 'invalid' : 'upload_invalid');
      if (state.claimed && state.claimed.has(body.mediaId)) return refuse(res, 409, 'upload_invalid');
      const t = taken(parent.id, body.name);
      const mtime = body.mtime ? iso(Number(body.mtime)) : null;
      if (t && !t.isDir && ((body.baseRev != null && body.baseRev === t.rev) || body.onConflict === 'version')) {
        (state.versions.get(t.id) || state.versions.set(t.id, []).get(t.id)).push({ id: ++nextId, rev: t.rev, size: t.size, at: iso(Date.now()), by: 2, mediaId: t.mediaId });
        t.mediaId = empty ? null : body.mediaId;
        t.size = md.data.length;
        t.sha256 = empty ? EMPTY_SHA : sha(md.data);
        t.mtime = mtime;
        t.rev += 1;
        if (!empty) (state.claimed || (state.claimed = new Set())).add(body.mediaId);
        logChange('update', t);
        return json(res, 200, { ok: true, node: view(t), created: false });
      }
      if (t && body.onConflict !== 'rename') return json(res, 409, { ok: false, code: t.isDir ? 'exists' : 'conflict', error: 'conflict', current: view(t) });
      const n = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: freeName(parent.id, body.name), size: md.data.length, mime: md.mime, mediaId: empty ? null : body.mediaId, sha256: empty ? EMPTY_SHA : sha(md.data), mtime });
      if (!empty) (state.claimed || (state.claimed = new Set())).add(body.mediaId);
      logChange('create', n);
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
        logChange('restore', n);
        return json(res, 200, { ok: true, node: view(n) });
      }
      if (seg.length === 2 && req.method === 'DELETE') {
        logChange('purge', n);
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
