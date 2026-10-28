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
// (srv.state.devices), empty files (uploads/commit { size: 0 } without media, content { empty: true }),
// 'deleteAfter': DELETE nodes/<id>?after=<s>&device=<id> marks the node (deleteAt, change `mark`),
// PATCH { deleteAt: null } / a new version calls it off (`unmark`), srv.expireMarks() trashes what is due.
// Drive 1.6: 'links' (me.links), 'guard' (me.guard / incidents; srv.lock({ snapshot: srv.snapshot() }) → every
// write 423 device_locked; POST guard/incidents/<id>/release | undo – undo gives the files changed since the
// snapshot their old bytes as a new version and trashes the files this device made since then).
// Drive 1.7: 'takenAt' (uploads/commit { takenAt } kept on the node), 'timeTravel' (GET / POST nodes/<id>/timetravel
// against the history of every change: srv.state.history), 'photos' (photos, photos/months, photos/memories – items
// with mediaId / previewUrl / largeUrl; srv.photoMediaIds = false: without), 'albums' / 'frame' (srv.state.albums), 'storage' (GET storage,
// storage/versions/prune).
// Drive 1.8: 'docAi' (node.insight { status, kind }, GET / POST nodes/<id>/insight, …/insight/apply, GET deadlines,
// POST / DELETE deadlines/<id>/remind, PATCH areas/<id> { docAi }, areas[].docAi; srv.setInsight(id, insight),
// srv.state.deadlines), 'cloudImport' (only the feature: the import runs in the portal).
// Drive 1.9: 'office' (POST nodes/<id>/office → an https URL; 409 encrypted / office_unavailable), 'vault' (vaults,
// keys, recovery, devices, approve, revoke, rotate; nodes, uploads/commit and PATCH with encrypted / nameCipher /
// keyVersion; 409 stale_key; no links, search or office in a vault; srv.state.vaults).
// Drive 1.11: 'vaultsApart' (children leave out vault folders — `vaults=1` keeps them —, `children?dirs=1` lists
// folders only with `hasDirs`, POST vaults puts the vault into the top folder of the parent's area, a vault folder
// cannot be moved: 400 invalid parentId).

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
    guard: { locked: false, incident: null, since: 0 },
    incidents: [],
  };
  const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  // Drive 1.7 'timeTravel': how every node was after each change
  state.history = [];
  state.albums = new Map();
  // Drive 1.8 'docAi': nodeId → the full insight; deadlines; areas switched off
  state.insights = new Map();
  state.deadlines = [];
  state.docAiOff = new Set();
  // Drive 1.9 'vault': id → { id, nodeId, areaId, keyVersion, recoveryPub, recoveryAuth (sha256 hex), recoveryBy, needsRotation, devices, wraps }
  state.vaults = new Map();
  state.officeCalls = [];
  const snap = () => new Map([...state.nodes.values()].map((n) => [n.id, { name: n.name, parentId: n.parentId, isDir: n.isDir, deleted: !!n.deleted, mediaId: n.mediaId, size: n.size, sha256: n.sha256, mime: n.mime }]));
  const logChange = (op, n, device = '42', areaId = n.areaId) => {
    state.log.push({ seq: ++state.seq, op, areaId, nodeId: n.id, at: Date.now(), device });
    if (features && features.includes('timeTravel')) state.history.push({ at: Date.now(), nodes: snap() });
  };
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

  // linksBase: the origin of me.links (an e2e test points it at its mock server)
  const srv = { state, nextId: () => ++nextId, linksBase: 'https://gc.example.com', cutUploadAfter: null, pageMax: 1000, photoMediaIds: true, startedAt: Date.now(), timeTravelMax: 2000 };
  state.history.push({ at: 0, nodes: snap() });
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
  // Drive 1.7 'timeTravel': what going back to `at` changes below `folderId` → [{ op, id, then }]
  srv.timeTravelPlan = (folderId, at) => {
    const then = (state.history.filter((h) => h.at <= at).pop() || state.history[0]).nodes;
    const isBelow = (map, id) => { for (let c = map.get(id); c; c = c.parentId ? map.get(c.parentId) : null) { if (c.deleted) return false; if (c.parentId === folderId) return true; } return false; };
    const nowMap = new Map([...state.nodes.values()].map((n) => [n.id, n]));
    const depth = (map, id) => { let d = 0; for (let c = map.get(id); c && c.parentId; c = map.get(c.parentId)) d++; return d; };
    const out = [];
    for (const [id, t] of then) {
      if (t.deleted || !isBelow(then, id)) continue;
      const n = state.nodes.get(id);
      if (!n) continue; // purged: gone for good
      if (n.deleted) out.push({ op: 'restore', id, then: t, d: depth(then, id) });
      else if (!t.isDir && t.mediaId !== n.mediaId) out.push({ op: 'revert', id, then: t, d: depth(then, id) });
      else if (t.name !== n.name || t.parentId !== n.parentId) out.push({ op: 'move', id, then: t, d: depth(then, id) });
    }
    for (const n of state.nodes.values()) {
      if (n.deleted || !isBelow(nowMap, n.id)) continue;
      const t = then.get(n.id);
      if (!t || t.deleted) out.push({ op: 'trash', id: n.id, then: null, d: -depth(nowMap, n.id) });
    }
    // folders first when they come back, deepest first when they go
    return out.sort((a, b) => (a.op === 'trash') - (b.op === 'trash') || a.d - b.d);
  };
  // Changes "by another device" (they land in the change log with device '77').
  // Drive 1.5 'deleteAfter': marked nodes whose time has come go into the trash
  srv.expireMarks = (now = Date.now()) => {
    for (const n of [...state.nodes.values()]) {
      if (!n.deleted && n.deleteAt && Date.parse(n.deleteAt) <= now) {
        n.deleted = true;
        n.deletedAt = iso(now);
        n.deleteAt = null;
        for (const d of srv.below(n.id)) { d.deleted = true; d.deletedAt = n.deletedAt; }
        logChange('delete', n, 'nas');
      }
    }
  };
  // Drive 1.6 'guard': stops this device (writes → 423) with an incident
  // the files as they are now (srv.lock({ snapshot }) – "Rückgängig machen" goes back to it)
  srv.snapshot = () => ({ seq: state.seq, nodes: new Map([...state.nodes.values()].filter((n) => !n.isDir && !n.deleted).map((n) => [n.id, { mediaId: n.mediaId, size: n.size, sha256: n.sha256 }])) });
  srv.lock = ({ snapshot = srv.snapshot(), files = 60, sample = ['Brief.docx', 'Steuer.xlsx'] } = {}) => {
    const incident = { id: 7001 + state.incidents.length, at: iso(Date.now()), device: '42', deviceName: 'Desktop-PC', files, sample, state: 'open' };
    state.incidents.push(incident);
    state.guard = { locked: true, incident, since: snapshot.seq, snapshot: snapshot.nodes };
    return incident;
  };
  srv.mutate = {
    file(parentId, name, content, { mtime = Date.now() } = {}) {
      const data = Buffer.from(content);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data, mime: 'application/octet-stream' });
      const n = node({ id: ++nextId, areaId: state.nodes.get(parentId).areaId, parentId, name, size: data.length, mediaId, sha256: sha(data), mtime: iso(mtime) });
      logChange('create', n, '77');
      return n;
    },
    // Drive 1.7: a picture (image/jpeg with a preview) taken at `takenAt`
    photo(parentId, name, { takenAt = Date.now(), content = name, mime = 'image/jpeg' } = {}) {
      const data = Buffer.from(content);
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.media.set(mediaId, { data, mime });
      const n = node({ id: ++nextId, areaId: state.nodes.get(parentId).areaId, parentId, name, size: data.length, mime, mediaId, sha256: sha(data), takenAt: iso(takenAt), mtime: iso(takenAt) });
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

  // Drive 1.8: an insight for node `id` (status ready …), its deadlines with ids
  srv.setInsight = (id, ins) => {
    const deadlines = (ins.deadlines || []).map((d) => {
      const row = { id: ++nextId, nodeId: id, kind: d.kind, date: d.date, label: d.label || null, reminder: null };
      state.deadlines.push(row);
      return row;
    });
    state.insights.set(id, { status: 'ready', kind: 'other', title: null, date: null, sender: null, amount: null, currency: null, error: null, at: iso(Date.now()), suggestion: null, ...ins, deadlines });
  };
  // Drive 1.9: another device of the person asks for vault `vaultId` (pending)
  srv.vaultAsk = (vaultId, publicKey, name = 'Pixel') => {
    const v = state.vaults.get(vaultId);
    const deviceId = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('gcdrive-v1:device:'), Buffer.from(publicKey, 'base64url')])).digest().subarray(0, 16).toString('base64url');
    v.devices.set(deviceId, { deviceId, userId: 2, name, platform: 'android', publicKey, state: 'pending', via: null, createdAt: iso(Date.now()), approvedAt: null, approvedBy: null, revokedAt: null });
    return deviceId;
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
  const insightOf = (n) => {
    if (n.isDir) return undefined;
    if (n.encrypted || state.docAiOff.has(n.areaId)) return { status: 'off', kind: null };
    const i = state.insights.get(n.id);
    return i ? { status: i.status, kind: i.status === 'ready' ? i.kind : null } : { status: 'none', kind: null };
  };
  const view = (n) => ({
    ...n,
    preview: !n.isDir && n.mediaId && !n.encrypted && /^image\//.test(n.mime || '') ? { url: `${MEDIA}/${n.mediaId}/preview`, largeUrl: `${MEDIA}/${n.mediaId}/preview?size=large` } : (n.isDir ? undefined : null),
    ...(features && features.includes('docAi') && !n.isDir ? { insight: insightOf(n) } : {}),
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

    const areasNowMe = () => (features && features.includes('docAi') ? areas.map((a) => ({ ...a, docAi: !state.docAiOff.has(a.id) })) : areas);
    if (req.method === 'GET' && route === 'me') {
      return json(res, 200, {
        ok: true, me: { id: 2, name: 'Marc', seat: seat || null, deviceId: '42' }, licence: { valid: licence, tier: 'combo' },
        areas: seat ? areasNowMe() : [], latest: state.seq, settings: { trashDays: 30, versionsDays: 30 }, limits: { maxBytes: 107374182400 },
        people: [{ id: 2, name: 'Marc' }, { id: 7, name: 'Lena' }], wipes: 0, devices: 1,
        ...(features ? { features } : {}),
        ...(features && features.includes('links') ? { links: { node: `${srv.linksBase}/portal#plg-gatecontrol-drive/node/{id}`, drive: `${srv.linksBase}/portal#plg-gatecontrol-drive` } } : {}),
        ...(features && features.includes('guard') ? { guard: { locked: state.guard.locked, incident: state.guard.locked ? state.guard.incident : null }, incidents: state.incidents } : {}),
      });
    }
    // Drive 1.6 'guard': decide an incident
    if (features && features.includes('guard') && seg[0] === 'guard' && seg[1] === 'incidents' && req.method === 'POST') {
      const inc = state.incidents.find((i) => String(i.id) === seg[2]);
      if (!inc) return refuse(res, 404, 'not_found');
      let restored = 0;
      let trashed = 0;
      if (seg[3] === 'undo') {
        // back to the snapshot taken when the incident began: changed files get their old bytes
        // as a new version, files this device made since then go into the trash
        const snap = state.guard.snapshot || new Map();
        for (const n of state.nodes.values()) {
          if (n.deleted || n.isDir) continue;
          const was = snap.get(n.id);
          if (was) {
            if (was.mediaId === n.mediaId) continue;
            Object.assign(n, { mediaId: was.mediaId, size: was.size, sha256: was.sha256, rev: n.rev + 1 });
            logChange('update', n, 'nas');
            restored++;
          } else if (state.log.some((c) => c.nodeId === n.id && c.seq > state.guard.since && c.op === 'create' && c.device === '42')) {
            n.deleted = true;
            n.deletedAt = iso(Date.now());
            logChange('delete', n, 'nas');
            trashed++;
          }
        }
      } else if (seg[3] !== 'release') return refuse(res, 404, 'not_found');
      inc.state = seg[3] === 'undo' ? 'undone' : 'released';
      state.guard = { locked: false, incident: null, since: 0, snapshot: null };
      return json(res, 200, { ok: true, incident: inc, restored, trashed });
    }
    // Drive 1.6 'guard': a stopped device writes nothing
    if (state.guard.locked && req.method !== 'GET' && !(seg[0] === 'uploads' && seg[1] === 'check')) {
      return json(res, 423, { ok: false, code: 'device_locked', error: 'device locked', incident: state.guard.incident });
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
    const has = (f) => !!(features && features.includes(f));
    const areasNow = () => (has('docAi') ? areas.map((a) => ({ ...a, docAi: !state.docAiOff.has(a.id) })) : areas);
    if (req.method === 'GET' && route === 'areas') return json(res, 200, { ok: true, areas: areasNow() });
    // ── Drive 1.8 'docAi' ──
    if (has('docAi') && seg[0] === 'areas' && seg[1] && req.method === 'PATCH') {
      const a = areas.find((x) => x.id === decodeURIComponent(seg[1]));
      if (!a) return refuse(res, 404, 'not_found');
      if (!(a.role === 'write' || a.role === 'manage')) return refuse(res, 403, 'forbidden');
      if (body.docAi) state.docAiOff.delete(a.id); else state.docAiOff.add(a.id);
      return json(res, 200, { ok: true, area: { id: a.id, docAi: !!body.docAi } });
    }
    if (seg[0] === 'nodes' && seg[2] === 'insight') {
      if (!has('docAi')) return refuse(res, 404, 'not_found');
      const n = get(seg[1]);
      if (!n || n.isDir) return refuse(res, 404, 'not_found');
      const dl = (id) => state.deadlines.filter((d) => d.nodeId === id).map(({ nodeId, ...d }) => d);
      const full = () => {
        if (n.encrypted || state.docAiOff.has(n.areaId)) return { status: 'off', kind: null, title: null, date: null, sender: null, amount: null, currency: null, error: null, at: null, suggestion: null, deadlines: n.encrypted ? [] : dl(n.id) };
        const i = state.insights.get(n.id);
        return i ? { ...i, deadlines: dl(n.id) } : { status: 'none', kind: null, title: null, date: null, sender: null, amount: null, currency: null, error: null, at: null, suggestion: null, deadlines: dl(n.id) };
      };
      if (seg.length === 3 && req.method === 'GET') return json(res, 200, { ok: true, ...full() });
      if (n.encrypted) return refuse(res, 409, 'encrypted');
      if (!writable(n)) return refuse(res, 403, 'forbidden');
      if (seg.length === 3 && req.method === 'POST') {
        if (n.mime !== 'application/pdf') return json(res, 422, { ok: false, code: 'unsupported', error: 'unsupported', reason: 'no_text' });
        state.insights.set(n.id, { ...(state.insights.get(n.id) || {}), status: 'pending', kind: null, suggestion: null, at: iso(Date.now()) });
        return json(res, 200, { ok: true, ...full() });
      }
      if (seg[3] === 'apply' && req.method === 'POST') {
        const i = state.insights.get(n.id);
        if (!i || i.status !== 'ready' || !i.suggestion) return json(res, 400, { ok: false, code: 'invalid', field: 'insight', error: 'invalid' });
        if (body.name && i.suggestion.name) n.name = freeName(n.parentId, i.suggestion.name);
        if (body.folder && i.suggestion.folderId) n.parentId = i.suggestion.folderId;
        i.suggestion = { folderId: body.folder ? null : i.suggestion.folderId, folderPath: body.folder ? null : i.suggestion.folderPath, name: body.name ? null : i.suggestion.name };
        if (!i.suggestion.folderId && !i.suggestion.name) i.suggestion = null;
        logChange('move', n);
        return json(res, 200, { ok: true, node: view(n), insight: full() });
      }
    }
    if (has('docAi') && seg[0] === 'deadlines') {
      if (seg.length === 1 && req.method === 'GET') {
        const from = url.searchParams.get('from') || new Date().toISOString().slice(0, 10);
        const to = url.searchParams.get('to') || '9999-12-31';
        const list = state.deadlines.filter((d) => d.date >= from && d.date <= to && get(d.nodeId) && !get(d.nodeId).encrypted)
          .sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.id - b.id))
          .map(({ nodeId, ...d }) => ({ ...d, node: { ...view(get(nodeId)), path: '' } }));
        return json(res, 200, { ok: true, deadlines: list });
      }
      const d = state.deadlines.find((x) => x.id === Number(seg[1]));
      if (!d || seg[2] !== 'remind') return refuse(res, 404, 'not_found');
      const plain = () => { const { nodeId, ...x } = d; return x; };
      if (req.method === 'POST') {
        const days = Number(body.daysBefore);
        if (!Number.isInteger(days) || days < 0 || days > 90) return json(res, 400, { ok: false, code: 'invalid', field: 'daysBefore', error: 'invalid' });
        d.reminder = { at: iso(Date.parse(`${d.date}T07:00:00Z`) - days * 86400000), daysBefore: days, sent: false };
        return json(res, 200, { ok: true, deadline: plain() });
      }
      if (req.method === 'DELETE') { d.reminder = null; return json(res, 200, { ok: true, deadline: plain() }); }
    }
    // ── Drive 1.9 'office' ──
    if (seg[0] === 'nodes' && seg[2] === 'office' && req.method === 'POST') {
      if (!has('office')) return refuse(res, 404, 'not_found');
      const n = get(seg[1]);
      if (!n || n.isDir) return refuse(res, 404, 'not_found');
      if (n.encrypted) return refuse(res, 409, 'encrypted');
      if (!/\.(docx|xlsx|pptx|odt|ods|odp|csv)$/i.test(n.name)) return json(res, 409, { ok: false, code: 'office_unavailable', reason: 'type', error: 'office_unavailable' });
      state.officeCalls.push(n.id);
      return json(res, 200, { ok: true, url: `https://gc.example.com/plugin-public/gatecontrol-drive/office/open/${n.id}?access_token=tok`, mode: writable(n) ? 'edit' : 'view', expiresAt: iso(Date.now() + 120000) });
    }
    // ── Drive 1.9 'vault' ──
    const vaultOfNode = (n) => (n && n.vaultId ? state.vaults.get(n.vaultId) : null);
    const kvOf = (c) => Buffer.from(c, 'base64url').readUInt32BE(1);
    if (has('vault') && seg[0] === 'vaults') {
      const vaultView = (v) => {
        const n = state.nodes.get(v.nodeId);
        const devs = [...v.devices.values()];
        const mine = devs.filter((d) => d.userId === 2);
        return {
          id: v.id, nodeId: v.nodeId, areaId: v.areaId, parentId: n.parentId, nameCipher: n.nameCipher, keyVersion: v.keyVersion, recoveryPub: v.recoveryPub,
          recoveryHolder: v.recoveryBy, needsRotation: v.needsRotation, createdAt: iso(Date.now()), createdBy: 2, rotatedAt: null,
          myDevices: mine.map((d) => ({ deviceId: d.deviceId, state: d.state, name: d.name })),
          pending: mine.some((d) => d.state === 'approved') ? devs.filter((d) => d.state === 'pending').length : 0,
        };
      };
      const devId = (pub) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from('gcdrive-v1:device:'), Buffer.from(pub, 'base64url')])).digest().subarray(0, 16).toString('base64url');
      const authHash = (a) => crypto.createHash('sha256').update(Buffer.from(String(a || ''), 'base64url')).digest('hex');
      const wrapOk = (w) => typeof w === 'string' && Buffer.from(w, 'base64url').length === 81 && Buffer.from(w, 'base64url')[0] === 1;
      if (seg.length === 1 && req.method === 'POST') {
        let parent = get(body.parentId);
        if (!parent || !parent.isDir) return refuse(res, 404, 'not_found');
        if (!writable(parent)) return refuse(res, 403, 'forbidden');
        if (parent.vaultId) return json(res, 400, { ok: false, code: 'invalid', field: 'parentId', error: 'invalid' });
        // Drive 1.11: parentId only names the area; the vault goes into its top folder
        if (has('vaultsApart')) parent = state.nodes.get(areaOf(parent).rootId);
        if (!/^[A-Za-z0-9_-]{22}$/.test(String(body.id)) || !wrapOk(body.wrap) || !wrapOk(body.recoveryWrap) || !body.device || !body.nameCipher || kvOf(body.nameCipher) !== 1) return refuse(res, 400, 'invalid');
        const made = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: crypto.randomBytes(16).toString('hex'), isDir: true, encrypted: true, vaultId: body.id, nameCipher: body.nameCipher, keyVersion: 1 });
        logChange('create', made);
        const did = devId(body.device.publicKey);
        const v = { id: body.id, nodeId: made.id, areaId: parent.areaId, keyVersion: 1, recoveryPub: body.recoveryPub, recoveryAuth: authHash(body.recoveryAuth), recoveryBy: 2, needsRotation: false, devices: new Map(), wraps: new Map() };
        v.devices.set(did, { deviceId: did, userId: 2, name: body.device.name || null, platform: body.device.platform || null, publicKey: body.device.publicKey, state: 'approved', via: 'create', createdAt: iso(Date.now()), approvedAt: iso(Date.now()), approvedBy: 2, revokedAt: null });
        v.wraps.set(`${did}|1`, body.wrap);
        v.wraps.set('recovery|1', body.recoveryWrap);
        state.vaults.set(v.id, v);
        return json(res, 200, { ok: true, vault: vaultView(v), node: view(made) });
      }
      if (seg.length === 1 && req.method === 'GET') return json(res, 200, { ok: true, vaults: [...state.vaults.values()].filter((v) => get(v.nodeId)).map(vaultView) });
      const v = state.vaults.get(seg[1]);
      if (!v || !get(v.nodeId)) return refuse(res, 404, 'not_found');
      const wrapsFor = (did) => [...v.wraps.entries()].filter(([k]) => k.split('|')[0] === did).map(([k, wrap]) => ({ keyVersion: Number(k.split('|')[1]), wrap })).sort((a, b) => a.keyVersion - b.keyVersion);
      if (seg.length === 2 && req.method === 'GET') return json(res, 200, { ok: true, vault: vaultView(v) });
      if (seg[2] === 'keys' && req.method === 'GET') {
        const d = v.devices.get(url.searchParams.get('deviceId'));
        if (!d || d.userId !== 2) return refuse(res, 404, 'not_found');
        return json(res, 200, { ok: true, deviceId: d.deviceId, state: d.state, keyVersion: v.keyVersion, keys: d.state === 'approved' ? wrapsFor(d.deviceId) : [] });
      }
      if (seg[2] === 'recovery' && req.method === 'GET') return json(res, 200, { ok: true, recoveryPub: v.recoveryPub, keyVersion: v.keyVersion, keys: wrapsFor('recovery') });
      if (seg[2] === 'devices' && seg.length === 3 && req.method === 'GET') return json(res, 200, { ok: true, devices: [...v.devices.values()] });
      if (seg[2] === 'devices' && seg.length === 3 && req.method === 'POST') {
        const did = devId(body.publicKey);
        const have = v.devices.get(did);
        if (have && have.state !== 'revoked') return json(res, 200, { ok: true, device: have });
        const d = { deviceId: did, userId: 2, name: body.name || null, platform: body.platform || null, publicKey: body.publicKey, state: 'pending', via: null, createdAt: iso(Date.now()), approvedAt: null, approvedBy: null, revokedAt: null };
        v.devices.set(did, d);
        return json(res, 200, { ok: true, device: d });
      }
      if (seg[2] === 'devices' && seg.length === 5 && seg[4] === 'approve' && req.method === 'POST') {
        const d = v.devices.get(seg[3]);
        if (!d || d.state === 'revoked') return refuse(res, 404, 'not_found');
        const mine = [...v.devices.values()].some((x) => x.userId === 2 && x.state === 'approved');
        const recovered = body.via === 'recovery' && authHash(body.recoveryAuth) === v.recoveryAuth;
        if (body.via === 'recovery' && !recovered) return json(res, 403, { ok: false, code: 'forbidden', reason: 'recovery_auth', error: 'forbidden' });
        if (!mine && !recovered) return refuse(res, 403, 'forbidden');
        const list = Array.isArray(body.wraps) ? body.wraps : [{ keyVersion: v.keyVersion, wrap: body.wrap }];
        if (!list.some((w) => w.keyVersion === v.keyVersion) || !list.every((w) => wrapOk(w.wrap) && w.keyVersion <= v.keyVersion)) return json(res, 400, { ok: false, code: 'invalid', field: 'wraps', error: 'invalid' });
        for (const w of list) v.wraps.set(`${d.deviceId}|${w.keyVersion}`, w.wrap);
        Object.assign(d, { state: 'approved', approvedAt: iso(Date.now()), approvedBy: 2, via: recovered ? 'recovery' : 'device' });
        return json(res, 200, { ok: true, device: d });
      }
      if (seg[2] === 'devices' && seg.length === 4 && req.method === 'DELETE') {
        const d = v.devices.get(seg[3]);
        if (!d) return refuse(res, 404, 'not_found');
        if (d.state === 'approved') v.needsRotation = true;
        Object.assign(d, { state: 'revoked', revokedAt: iso(Date.now()) });
        for (const k of [...v.wraps.keys()]) if (k.startsWith(`${d.deviceId}|`)) v.wraps.delete(k);
        return json(res, 200, { ok: true, device: d });
      }
      if (seg[2] === 'rotate' && req.method === 'POST') {
        if (body.keyVersion !== v.keyVersion + 1) return json(res, 409, { ok: false, code: 'conflict', keyVersion: v.keyVersion, error: 'conflict' });
        const want = [...v.devices.values()].filter((d) => d.state === 'approved').map((d) => d.deviceId).sort();
        const got = (body.wraps || []).map((w) => w.deviceId).sort();
        if (JSON.stringify(want) !== JSON.stringify(got)) return json(res, 409, { ok: false, code: 'conflict', devices: want, error: 'conflict' });
        if (srv.recoveryRequired && !body.recovery) return json(res, 409, { ok: false, code: 'conflict', reason: 'recovery_required', error: 'conflict' });
        for (const w of body.wraps) v.wraps.set(`${w.deviceId}|${body.keyVersion}`, w.wrap);
        if (body.recovery) {
          for (const k of [...v.wraps.keys()]) if (k.startsWith('recovery|')) v.wraps.delete(k);
          for (const w of body.recovery.wraps) v.wraps.set(`recovery|${w.keyVersion}`, w.wrap);
          Object.assign(v, { recoveryPub: body.recovery.pub, recoveryAuth: authHash(body.recovery.auth), recoveryBy: 2 });
        } else v.wraps.set(`recovery|${body.keyVersion}`, body.recoveryWrap);
        Object.assign(v, { keyVersion: body.keyVersion, needsRotation: false });
        return json(res, 200, { ok: true, vault: vaultView(v) });
      }
      return refuse(res, 404, 'not_found');
    }
    // ── Drive 1.7 ──
    if (has('timeTravel') && seg[0] === 'nodes' && seg[2] === 'timetravel') {
      const folder = get(seg[1]);
      if (!folder || !folder.isDir) return refuse(res, 404, 'not_found');
      const atRaw = req.method === 'GET' ? url.searchParams.get('at') : body.at;
      const at = Date.parse(atRaw);
      if (!Number.isFinite(at)) return refuse(res, 400, 'invalid');
      if (req.method === 'POST' && !writable(folder)) return refuse(res, 403, 'forbidden');
      const plan = srv.timeTravelPlan(folder.id, at);
      const sample = plan.slice(0, 10).map((x) => ({ op: x.op, name: x.then ? x.then.name : state.nodes.get(x.id).name, path: '' }));
      const count = (op) => plan.filter((x) => x.op === op).length;
      if (req.method === 'GET') {
        return json(res, 200, { ok: true, at: iso(at), historySince: iso(srv.startedAt), restore: count('restore'), revert: count('revert'), trash: count('trash'), move: count('move'), sample, limited: at < srv.startedAt, lost: 0, ops: plan.length, max: srv.timeTravelMax });
      }
      if (at >= Date.now()) return json(res, 400, { ok: false, code: 'invalid', field: 'at', error: 'invalid' });
      if (plan.length > srv.timeTravelMax) return json(res, 400, { ok: false, code: 'invalid', field: 'at', ops: plan.length, max: srv.timeTravelMax, error: 'invalid' });
      const before = Date.now() - 1;
      for (const x of plan) {
        const n = state.nodes.get(x.id);
        if (x.op === 'trash') { n.deleted = true; n.deletedAt = iso(Date.now()); logChange('delete', n); continue; }
        if (x.op === 'restore') n.deleted = false;
        if (x.op === 'revert' || (x.op === 'restore' && x.then.mediaId !== n.mediaId)) {
          (state.versions.get(n.id) || state.versions.set(n.id, []).get(n.id)).push({ id: ++nextId, rev: n.rev, size: n.size, at: iso(Date.now()), by: 2, mediaId: n.mediaId });
          Object.assign(n, { mediaId: x.then.mediaId, size: x.then.size, sha256: x.then.sha256, rev: n.rev + 1 });
        }
        if (x.then && (x.then.name !== n.name || x.then.parentId !== n.parentId)) { n.name = x.then.name; n.parentId = x.then.parentId; }
        logChange(x.op === 'restore' ? 'restore' : x.op === 'move' ? 'move' : 'update', n);
      }
      return json(res, 200, { ok: true, at: iso(at), before: iso(before), restored: count('restore'), reverted: count('revert'), trashed: count('trash'), moved: count('move'), failed: 0, lost: 0 });
    }
    const isMedia = (n) => !n.isDir && !n.deleted && /^(image|video)\//.test(n.mime || '');
    const when = (n) => Date.parse(n.takenAt || n.mtime || n.createdAt);
    const photo = (n) => ({ id: n.id, name: n.name, mime: n.mime, size: n.size, takenAt: new Date(when(n)).toISOString(), areaId: n.areaId, parentId: n.parentId, preview: /^image\//.test(n.mime || ''), ...(srv.photoMediaIds ? { mediaId: n.mediaId, previewUrl: `${MEDIA}/${n.mediaId}/preview`, largeUrl: `${MEDIA}/${n.mediaId}/preview?size=large` } : {}) });
    const photoList = (area) => [...state.nodes.values()].filter((n) => isMedia(n) && (!area || n.areaId === area)).sort((a, b) => when(b) - when(a) || b.id - a.id);
    const pageOf = (list) => {
      const before = url.searchParams.get('before');
      const limit = Math.min(200, Number(url.searchParams.get('limit') || 100));
      const rest = before ? list.filter((n) => when(n) < Date.parse(before)) : list;
      const items = rest.slice(0, limit);
      return { items: items.map(photo), next: rest.length > limit ? new Date(when(items[items.length - 1])).toISOString() : null };
    };
    if (has('photos') && req.method === 'GET' && route === 'photos') return json(res, 200, { ok: true, ...pageOf(photoList(url.searchParams.get('area'))) });
    if (has('photos') && req.method === 'GET' && route === 'photos/months') {
      const m = new Map();
      for (const n of photoList(url.searchParams.get('area'))) { const k = new Date(when(n)).toISOString().slice(0, 7); m.set(k, (m.get(k) || 0) + 1); }
      return json(res, 200, { ok: true, months: [...m].map(([month, count]) => ({ month, count })) });
    }
    if (has('photos') && req.method === 'GET' && route === 'photos/memories') {
      const d = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      const [y, mo, da] = d.split('-').map(Number);
      const groups = new Map();
      for (const n of photoList(null)) {
        const t = new Date(when(n));
        const ago = y - t.getUTCFullYear();
        if (ago < 1) continue;
        const same = Math.abs(Date.UTC(y, t.getUTCMonth(), t.getUTCDate()) - Date.UTC(y, mo - 1, da)) <= 86400000;
        if (!same) continue;
        if (!groups.has(ago)) groups.set(ago, { yearsAgo: ago, date: t.toISOString().slice(0, 10), items: [] });
        groups.get(ago).items.push(photo(n));
      }
      return json(res, 200, { ok: true, date: d, groups: [...groups.values()] });
    }
    if (has('albums') && seg[0] === 'albums') {
      const albumView = (a) => {
        const ar = areas.find((x) => x.id === a.areaId);
        const items = a.items.map((id) => state.nodes.get(id)).filter((n) => n && !n.deleted);
        const canEdit = !!ar && !ar.archived && (ar.role === 'write' || ar.role === 'manage');
        return { id: a.id, name: a.name, areaId: a.areaId, count: items.length, coverId: a.coverId || (items[0] ? items[0].id : null), coverUrl: null, frame: !!a.frame, updatedAt: iso(a.updatedAt), createdBy: 2, canEdit, canFrame: canEdit && has('frame') && !srv.noFrame };
      };
      if (seg.length === 1 && req.method === 'GET') return json(res, 200, { ok: true, albums: [...state.albums.values()].map(albumView) });
      if (seg.length === 1 && req.method === 'POST') {
        const areaId = body.areaId || 'mine:2';
        const ar = areas.find((x) => x.id === areaId);
        if (!ar || !(ar.role === 'write' || ar.role === 'manage')) return refuse(res, 403, 'forbidden');
        if (!String(body.name || '').trim()) return refuse(res, 400, 'invalid');
        const a = { id: ++nextId, name: String(body.name).trim(), areaId, items: [], coverId: null, frame: false, updatedAt: Date.now() };
        state.albums.set(a.id, a);
        return json(res, 200, { ok: true, album: albumView(a) });
      }
      const a = state.albums.get(Number(seg[1]));
      if (!a) return refuse(res, 404, 'not_found');
      const canEdit = albumView(a).canEdit;
      if (seg.length === 2 && req.method === 'GET') {
        const list = a.items.map((id) => state.nodes.get(id)).filter((n) => n && isMedia(n)).sort((x, y) => when(y) - when(x));
        return json(res, 200, { ok: true, album: albumView(a), ...pageOf(list) });
      }
      if (req.method !== 'GET' && !canEdit) return refuse(res, 403, 'forbidden');
      if (seg.length === 2 && req.method === 'PATCH') {
        if (body.name !== undefined) a.name = String(body.name).trim();
        if (body.coverId !== undefined) a.coverId = body.coverId;
        if (body.frame !== undefined) { if (!albumView(a).canFrame) return json(res, 403, { ok: false, code: 'forbidden', field: 'frame', error: 'forbidden' }); a.frame = body.frame === true; }
        a.updatedAt = Date.now();
        return json(res, 200, { ok: true, album: albumView(a) });
      }
      if (seg.length === 2 && req.method === 'DELETE') { state.albums.delete(a.id); return json(res, 200, { ok: true, id: a.id }); }
      if (seg[2] === 'items' && (req.method === 'POST' || req.method === 'DELETE')) {
        const q = url.searchParams.get('ids');
        const ids = Array.isArray(body.ids) ? body.ids : q ? q.split(',').map(Number) : [];
        if (!ids.length || ids.length > 500) return refuse(res, 400, 'invalid');
        if (req.method === 'POST') { for (const id of ids) { const n = state.nodes.get(id); if (n && isMedia(n) && !a.items.includes(id)) a.items.push(id); } } else a.items = a.items.filter((id) => !ids.includes(id));
        a.updatedAt = Date.now();
        return json(res, 200, { ok: true, album: albumView(a) });
      }
    }
    if (has('storage') && req.method === 'GET' && route === 'storage') {
      const all = url.searchParams.get('all') === '1';
      const files = [...state.nodes.values()].filter((n) => !n.isDir);
      const live = files.filter((n) => !n.deleted);
      const pathOf = (n) => crumbs(n).map((c) => c.name).join('/');
      const sum = (list) => list.reduce((x, n) => x + (n.size || 0), 0);
      const versionsOf = (list) => list.reduce((x, n) => x + (state.versions.get(n.id) || []).reduce((y, v) => y + v.size, 0), 0);
      const byArea = areas.map((a) => {
        const l = live.filter((n) => n.areaId === a.id);
        const d = files.filter((n) => n.deleted && n.areaId === a.id);
        return { id: a.id, label: a.label, kind: a.kind, bytes: sum(l), files: l.length, versionsBytes: versionsOf(l), trashBytes: sum(d), quota: null, canPrune: a.role === 'manage' };
      });
      const groups = new Map();
      for (const n of live) if (n.size > 0 && n.sha256) { const k = `${n.sha256}|${n.size}`; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n); }
      const item = (n) => ({ id: n.id, name: n.name, size: n.size, areaId: n.areaId, parentId: n.parentId, path: pathOf(n), updatedAt: n.updatedAt, canDelete: writable(n) });
      const duplicates = [...groups.values()].filter((g) => g.length > 1).map((g) => ({ sha256: g[0].sha256, size: g[0].size, count: g.length, wasted: g[0].size * (g.length - 1), items: g.map(item) }))
        .sort((x, y) => y.wasted - x.wasted).slice(0, 20);
      return json(res, 200, {
        ok: true,
        all,
        total: { bytes: sum(live), files: live.length, versionsBytes: versionsOf(live), trashBytes: sum(files.filter((n) => n.deleted)) },
        limit: { maxBytes: 107374182400 },
        areas: byArea,
        people: all ? [{ user: 2, name: 'Marc', bytes: sum(live), files: live.length }] : [],
        largest: live.slice().sort((x, y) => y.size - x.size).slice(0, 20).map(item),
        duplicates,
      });
    }
    if (has('storage') && req.method === 'POST' && route === 'storage/versions/prune') {
      let removed = 0;
      let freedBytes = 0;
      for (const [id, list] of state.versions) {
        const n = state.nodes.get(id);
        if (!n || n.areaId !== body.areaId) continue;
        list.sort((x, y) => y.rev - x.rev);
        for (const v of list.splice(Number(body.keep) || 0)) { removed++; freedBytes += v.size; }
      }
      return json(res, 200, { ok: true, removed, freedBytes, more: false });
    }
    if (req.method === 'GET' && route === 'search') {
      const q = String(url.searchParams.get('q') || '').toLowerCase();
      const items = [...state.nodes.values()].filter((n) => !n.deleted && !n.encrypted && n.parentId && n.name.toLowerCase().includes(q)).map((n) => ({ ...view(n), path: crumbs(n).slice(1, -1).map((c) => c.name).join('/'), match: 'name' }));
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
        if (parent.vaultId || body.encrypted) {
          const v = state.vaults.get(parent.vaultId);
          if (!v || body.encrypted !== true || !body.nameCipher) return json(res, 400, { ok: false, code: 'invalid', field: 'encrypted', error: 'invalid' });
          if (body.keyVersion !== v.keyVersion || kvOf(body.nameCipher) !== v.keyVersion) return json(res, 409, { ok: false, code: 'conflict', reason: 'stale_key', keyVersion: v.keyVersion, error: 'conflict' });
          const made = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: crypto.randomBytes(16).toString('hex'), isDir: true, encrypted: true, vaultId: v.id, nameCipher: body.nameCipher, keyVersion: body.keyVersion });
          logChange('create', made);
          return json(res, 200, { ok: true, node: view(made) });
        }
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
        if (features && features.includes('deleteAfter') && Object.prototype.hasOwnProperty.call(body, 'deleteAt') && body.deleteAt === null) {
          n.deleteAt = null;
          n.deletedOnDevice = null;
          logChange('unmark', n);
          return json(res, 200, { ok: true, node: view(n) });
        }
        if (body.nameCipher !== undefined || n.encrypted) {
          const v = vaultOfNode(n);
          if (has('vaultsApart') && v && v.nodeId === n.id && body.parentId && body.parentId !== n.parentId) return json(res, 400, { ok: false, code: 'invalid', field: 'parentId', error: 'invalid' });
          if (!v || (body.name && body.name !== n.name) || (body.parentId && (get(body.parentId) || {}).vaultId !== n.vaultId)) return json(res, 400, { ok: false, code: 'invalid', field: 'nameCipher', error: 'invalid' });
          if (body.nameCipher) {
            if (kvOf(body.nameCipher) !== v.keyVersion) return json(res, 409, { ok: false, code: 'conflict', reason: 'stale_key', keyVersion: v.keyVersion, error: 'conflict' });
            n.nameCipher = body.nameCipher;
          }
          if (body.parentId) n.parentId = body.parentId;
          logChange('move', n);
          return json(res, 200, { ok: true, node: view(n) });
        }
        if (body.parentId) {
          const target = get(body.parentId);
          if (!target || !target.isDir) return refuse(res, 404, 'not_found');
          if (!writable(target)) return refuse(res, 403, 'forbidden');
          if (target.vaultId) return json(res, 400, { ok: false, code: 'invalid', field: 'parentId', error: 'invalid' });
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
        const after = Number(url.searchParams.get('after') || 0);
        if (after > 0 && features && features.includes('deleteAfter')) {
          n.deleteAt = iso(Date.now() + after * 1000);
          n.deletedOnDevice = url.searchParams.get('device') || null;
          logChange('mark', n);
          return json(res, 200, { ok: true, id: n.id, deleteAt: n.deleteAt });
        }
        n.deleted = true;
        n.deletedAt = iso(Date.now());
        for (const d of srv.below(n.id)) { d.deleted = true; d.deletedAt = n.deletedAt; }
        logChange('delete', n);
        return json(res, 200, { ok: true, id: n.id, trashed: true });
      }
      if (seg[2] === 'children' && req.method === 'GET') {
        let kids = children(n.id);
        // Drive 1.11 'vaultsApart': no vault folders outside a vault (vaults=1: as before); dirs=1: folders with hasDirs
        if (has('vaultsApart') && !n.encrypted && url.searchParams.get('vaults') !== '1') kids = kids.filter((k) => !k.encrypted);
        const dirs = has('vaultsApart') && url.searchParams.get('dirs') === '1';
        if (dirs) kids = kids.filter((k) => k.isDir && !k.encrypted).sort((a, b) => a.name.localeCompare(b.name));
        state.dirCalls = (state.dirCalls || 0) + (dirs ? 1 : 0);
        const all = kids.map((k) => (dirs ? { ...view(k), hasDirs: children(k.id).some((c) => c.isDir && !c.encrypted) } : view(k)));
        const offset = Number(url.searchParams.get('offset') || 0);
        const limit = Math.min(srv.pageMax, Number(url.searchParams.get('limit') || 200));
        const items = all.slice(offset, offset + limit);
        return json(res, 200, { ok: true, items, total: all.length, next: offset + limit < all.length ? offset + limit : null, role: areaOf(n).role });
      }
      if (seg[2] === 'content' && req.method === 'GET') {
        if (!n.isDir && !n.mediaId && n.size === 0) return json(res, 200, { ok: true, url: 'data:,', name: n.name, mime: n.mime, size: 0, mediaId: null, empty: true });
        return json(res, 200, { ok: true, url: '/plugin-media/x', name: n.name, mime: n.mime, size: n.size, mediaId: n.mediaId, ...(n.encrypted ? { encrypted: true, vaultId: n.vaultId, nameCipher: n.nameCipher } : {}) });
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
      if (parent.vaultId || body.encrypted) {
        const v = state.vaults.get(parent.vaultId);
        if (!v || body.encrypted !== true || (body.name && !/^[0-9a-f]{32}$/.test(body.name))) return json(res, 400, { ok: false, code: 'invalid', field: 'encrypted', error: 'invalid' });
        if (body.keyVersion !== v.keyVersion || (body.nameCipher && kvOf(body.nameCipher) !== v.keyVersion)) return json(res, 409, { ok: false, code: 'conflict', reason: 'stale_key', keyVersion: v.keyVersion, error: 'conflict' });
        (state.claimed || (state.claimed = new Set())).add(body.mediaId);
        const old = body.name ? taken(parent.id, body.name) : null;
        if (old && body.onConflict === 'version') {
          (state.versions.get(old.id) || state.versions.set(old.id, []).get(old.id)).push({ id: ++nextId, rev: old.rev, size: old.size, at: iso(Date.now()), by: 2, mediaId: old.mediaId });
          Object.assign(old, { mediaId: body.mediaId, size: md.data.length, sha256: sha(md.data), rev: old.rev + 1, keyVersion: body.keyVersion, ...(body.nameCipher ? { nameCipher: body.nameCipher } : {}) });
          logChange('update', old);
          return json(res, 200, { ok: true, node: view(old), created: false });
        }
        if (!body.nameCipher) return json(res, 400, { ok: false, code: 'invalid', field: 'nameCipher', error: 'invalid' });
        const n = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: crypto.randomBytes(16).toString('hex'), size: md.data.length, mime: 'application/octet-stream', mediaId: body.mediaId, sha256: sha(md.data), mtime: body.mtime ? iso(Number(body.mtime)) : null, encrypted: true, vaultId: v.id, nameCipher: body.nameCipher, keyVersion: body.keyVersion });
        logChange('create', n);
        return json(res, 200, { ok: true, node: view(n), created: true });
      }
      const t = taken(parent.id, body.name);
      const mtime = body.mtime ? iso(Number(body.mtime)) : null;
      if (body.takenAt !== undefined && !Number.isFinite(Date.parse(body.takenAt))) return json(res, 400, { ok: false, code: 'invalid', field: 'takenAt', error: 'invalid' });
      const takenAt = body.takenAt !== undefined && features && features.includes('takenAt') ? iso(Date.parse(body.takenAt)) : null;
      if (t && !t.isDir && ((body.baseRev != null && body.baseRev === t.rev) || body.onConflict === 'version')) {
        (state.versions.get(t.id) || state.versions.set(t.id, []).get(t.id)).push({ id: ++nextId, rev: t.rev, size: t.size, at: iso(Date.now()), by: 2, mediaId: t.mediaId });
        t.mediaId = empty ? null : body.mediaId;
        t.size = md.data.length;
        t.sha256 = empty ? EMPTY_SHA : sha(md.data);
        t.mtime = mtime;
        t.takenAt = takenAt;
        t.rev += 1;
        if (t.deleteAt) { t.deleteAt = null; t.deletedOnDevice = null; }
        if (!empty) (state.claimed || (state.claimed = new Set())).add(body.mediaId);
        logChange('update', t);
        return json(res, 200, { ok: true, node: view(t), created: false });
      }
      if (t && body.onConflict !== 'rename') return json(res, 409, { ok: false, code: t.isDir ? 'exists' : 'conflict', error: 'conflict', current: view(t) });
      const n = node({ id: ++nextId, areaId: parent.areaId, parentId: parent.id, name: freeName(parent.id, body.name), size: md.data.length, mime: md.mime, mediaId: empty ? null : body.mediaId, sha256: empty ? EMPTY_SHA : sha(md.data), mtime, takenAt });
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
        if (n.encrypted) return refuse(res, 409, 'encrypted');
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
