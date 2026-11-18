'use strict';

// A small GateControl server for „Mein Profil › Meine Orte“ (GateControl 1.299.0, docs/feature-user-profile.md):
// GET / POST …/me/profile/places, GET / PATCH / DELETE …/profile/places/:id (409 IN_USE without ?force=1, DUPLICATE,
// LIMIT, INVALID with field), POST …/:id/used and GET …/me/places/search (8 hits at most, SEARCH_OFF while the
// administrator switched the search off, the attribution). Names and addresses are made up.
//
//   const srv = await placesServer({ search: 'osm' | 'own' | 'off', family: false, places: [...] | null });
//   srv.url, srv.state.places (Map id → place), srv.state.search, srv.state.family, srv.state.hits (the search's answer),
//   srv.calls ([{ method, path, query, body }]), srv.fail(path, status, code, times?, extra?), srv.unsupported = true
//   (an older GateControl: 404 without a code), srv.handle(req, res, raw) → true when it was a places route (to mount
//   it in another fake), srv.close()

const http = require('node:http');

const BASE = '/api/v1/client/me/';
const ICONS = ['home', 'work', 'school', 'gym', 'shop', 'family', 'pin'];
const VISIBILITY = ['self', 'family', 'all'];
const KEYS = ['name', 'lat', 'lon', 'icon', 'radiusM', 'address', 'visibility'];

/** The places of the mockup (made-up addresses). */
function seedPlaces() {
  return [
    { id: 11, name: 'Zuhause', icon: 'home', lat: 50.05, lon: 8.6, radiusM: 150, address: 'Lindenweg 12, Musterstadt', visibility: 'family', source: 'manual',
      usedBy: [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }, { plugin: 'gatecontrol-notizen', pluginName: 'Notizen', kind: 'task', count: 2 }],
      lastUsedAt: '2026-11-18 07:31:00' },
    { id: 12, name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, address: 'Hafenstraße 4, Musterstadt', visibility: 'self', source: 'manual',
      usedBy: [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }], lastUsedAt: '2026-11-17 18:02:00' },
    { id: 13, name: 'Fitnessstudio', icon: 'gym', lat: 50.07, lon: 8.63, radiusM: 100, address: 'Am Markt 7, Musterstadt', visibility: 'self', source: 'manual', usedBy: [], lastUsedAt: null },
    { id: 14, name: 'Baumarkt', icon: 'shop', lat: 50.09, lon: 8.7, radiusM: 120, address: 'Industriestraße 20, Musterstadt', visibility: 'self', source: 'notizen',
      usedBy: [{ plugin: 'gatecontrol-notizen', pluginName: 'Notizen', kind: 'task', count: 2 }], lastUsedAt: null },
  ];
}

const HITS = [
  { name: 'Bauhaus', address: 'Industriestraße 20, Musterstadt', lat: 50.0901, lon: 8.7002, source: 'osm' },
  { name: 'Baustoffhandel Nord', address: 'Kanalweg 3, Musterstadt', lat: 50.12, lon: 8.71, source: 'osm' },
];

async function placesServer({ search = 'osm', family = false, places = null, now = () => Date.now() } = {}) {
  const stamp = () => new Date(now()).toISOString().slice(0, 19).replace('T', ' ');
  const state = {
    places: new Map((places || seedPlaces()).map((p) => [p.id, { createdAt: '2026-11-18 09:12:44', updatedAt: '2026-11-18 09:12:44', ...p }])),
    nextId: 100,
    search,
    family,
    hits: HITS.map((h) => ({ ...h })),
    failures: new Map(),
  };
  const calls = [];
  const srv = { state, calls, unsupported: false };

  const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const err = (res, status, code, extra = {}) => json(res, status, { ok: false, code, error: code, ...extra });
  const out = (p) => ({ ...p, ref: `profile:${p.id}`, usedBy: p.usedBy || [] });

  function check(body, create) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return 'body';
    for (const k of Object.keys(body)) if (!KEYS.includes(k)) return k;
    if (create || body.name !== undefined) { if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 60) return 'name'; }
    if (create || body.lat !== undefined || body.lon !== undefined) {
      if (typeof body.lat !== 'number' || Math.abs(body.lat) > 90) return 'lat';
      if (typeof body.lon !== 'number' || Math.abs(body.lon) > 180) return 'lon';
      if (body.lat === 0 && body.lon === 0) return 'lat';
    }
    if (body.icon !== undefined && !ICONS.includes(body.icon)) return 'icon';
    if (body.visibility !== undefined && !VISIBILITY.includes(body.visibility)) return 'visibility';
    if (body.radiusM !== undefined && !(Number.isInteger(body.radiusM) && body.radiusM >= 50 && body.radiusM <= 2000)) return 'radiusM';
    if (body.address !== undefined && body.address !== null && (typeof body.address !== 'string' || body.address.length > 200)) return 'address';
    return null;
  }
  const taken = (name, except) => [...state.places.values()].some((p) => p.id !== except && p.name.toLowerCase() === String(name).trim().toLowerCase());

  srv.fail = (path, status, code, times = 1, extra = {}) => { state.failures.set(path, { status, code, times, extra }); };

  /** → true when the request was a places route (answered). */
  srv.handle = (req, res, raw) => {
    const url = new URL(req.url, 'http://x');
    if (!url.pathname.startsWith(BASE)) return false;
    const rest = url.pathname.slice(BASE.length);
    const parts = rest.split('/');
    if (!((parts[0] === 'profile' && parts[1] === 'places') || (parts[0] === 'places' && parts[1] === 'search'))) return false;
    let body = null;
    try { body = raw && raw.length ? JSON.parse(String(raw)) : null; } catch { body = '!'; }
    const m = req.method;
    calls.push({ method: m, path: url.pathname, query: Object.fromEntries(url.searchParams), body });
    if (srv.unsupported) { json(res, 404, { ok: false, error: 'Not found' }); return true; }
    const f = state.failures.get(url.pathname);
    if (f && f.times > 0) { f.times -= 1; err(res, f.status, f.code, f.extra); return true; }

    if (parts[0] === 'places') {
      if (state.search === 'off') { err(res, 403, 'SEARCH_OFF'); return true; }
      const q = (url.searchParams.get('q') || '').trim();
      if (q.length < 3 || q.length > 120) { err(res, 400, 'INVALID', { field: 'q' }); return true; }
      const near = url.searchParams.get('near');
      if (near && !/^-?\d{1,2}\.\d{2},-?\d{1,3}\.\d{2}$/.test(near)) { err(res, 400, 'INVALID', { field: 'near' }); return true; }
      const lc = q.toLowerCase();
      const results = state.hits.filter((h) => h.name.toLowerCase().includes(lc) || h.address.toLowerCase().includes(lc)).slice(0, 8)
        .map((h) => (near ? { ...h, distanceM: 6000 } : h));
      json(res, 200, { ok: true, results, attribution: { text: '© OpenStreetMap', url: 'https://www.openstreetmap.org/copyright' } });
      return true;
    }

    const id = parts[2] ? Number(parts[2]) : null;
    if (!parts[2]) {
      if (m === 'GET') {
        json(res, 200, {
          ok: true, places: [...state.places.values()].map(out), family: state.family,
          limits: { places: 100, name: 60, address: 200, radius: { min: 50, max: 2000, default: 150 } },
          options: { icons: ICONS, visibility: VISIBILITY }, search: state.search,
        });
        return true;
      }
      if (m === 'POST') {
        const bad = check(body, true);
        if (bad) { err(res, 400, 'INVALID', { field: bad }); return true; }
        if (taken(body.name)) { err(res, 409, 'DUPLICATE', { field: 'name' }); return true; }
        if (state.places.size >= 100) { err(res, 409, 'LIMIT'); return true; }
        const p = {
          id: state.nextId++, name: body.name.trim(), icon: body.icon || 'pin', lat: body.lat, lon: body.lon, radiusM: body.radiusM || 150,
          address: body.address || null, visibility: body.visibility || 'self', source: 'manual', usedBy: [], createdAt: stamp(), updatedAt: stamp(), lastUsedAt: null,
        };
        state.places.set(p.id, p);
        json(res, 201, { ok: true, place: out(p) });
        return true;
      }
    }
    const p = Number.isSafeInteger(id) ? state.places.get(id) : null;
    if (!p) { err(res, 404, 'NOT_FOUND'); return true; }
    if (parts[3] === 'used' && m === 'POST') { p.lastUsedAt = stamp(); json(res, 200, { ok: true, place: out(p) }); return true; }
    if (parts[3]) { err(res, 404, 'NOT_FOUND'); return true; }
    if (m === 'GET') { json(res, 200, { ok: true, place: out(p) }); return true; }
    if (m === 'PATCH') {
      const bad = check(body, false);
      if (bad) { err(res, 400, 'INVALID', { field: bad }); return true; }
      if ((body.lat === undefined) !== (body.lon === undefined)) { err(res, 400, 'INVALID', { field: body.lat === undefined ? 'lat' : 'lon' }); return true; }
      if (body.name !== undefined && taken(body.name, p.id)) { err(res, 409, 'DUPLICATE', { field: 'name' }); return true; }
      for (const k of KEYS) if (body[k] !== undefined) p[k] = k === 'name' ? body[k].trim() : body[k];
      p.updatedAt = stamp();
      json(res, 200, { ok: true, place: out(p) });
      return true;
    }
    if (m === 'DELETE') {
      if ((p.usedBy || []).length && url.searchParams.get('force') !== '1') { err(res, 409, 'IN_USE', { usedBy: p.usedBy }); return true; }
      state.places.delete(p.id);
      json(res, 200, { ok: true, deleted: true, id: p.id });
      return true;
    }
    err(res, 405, 'METHOD');
    return true;
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (!srv.handle(req, res, Buffer.concat(chunks))) json(res, 404, { ok: false, error: 'Not found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  srv.url = `http://127.0.0.1:${server.address().port}`;
  srv.close = () => new Promise((r) => server.close(r));
  return srv;
}

module.exports = { placesServer, seedPlaces, HITS };
