'use strict';

// A small in-memory server with the Vault plugin (gatecontrol-plugins/plugins/gatecontrol-vault README "App-API",
// semantics of its server/*.js): enough of the contract for the VaultService tests. It never decrypts anything — it
// checks shapes, compare-and-swap revisions and key generations like the real one.
//
//   const srv = vaultServer();                 // people 2 Anna, 3 Marc, 4 Lena
//   srv.transport(2, 'pc')                     // MessengerApi-compatible { _call, scope } of Anna's device "pc"
//   srv.offline = true                         // every call fails with code 'network'
//   srv.calls                                  // [{ uid, method, path, body, params }]
//   srv.pushes                                 // [{ to, topic, event, data }]

const crypto = require('node:crypto');
const { MessengerError } = require('../../src/services/messenger-api');

const API = '/api/v1/client/plugins/gatecontrol-vault/api/';
const PLUGINS = '/api/v1/client/plugins';
const STATUS = { invalid: 400, forbidden: 403, no_account: 404, not_found: 404, exists: 409, conflict: 409, stale_key: 409, rekeying: 409, last_manager: 409, limit: 409, no_wall: 409 };
const ID_RE = /^[A-Za-z0-9_-]{16,40}$/;
const B64 = /^[A-Za-z0-9_-]+$/;

function vaultServer({ people = [{ id: 2, name: 'Anna' }, { id: 3, name: 'Marc' }, { id: 4, name: 'Lena' }], plugin = true } = {}) {
  const srv = {
    users: new Map(people.map((u) => [u.id, u])),
    accounts: new Map(),     // uid → account
    vaults: new Map(),       // id → { id, kind, ownerId, nameEnc, keyRev, pendingKeyRev, needsRekey, members: Map(uid → { role, sealedKey, pendingKey }), updatedAt }
    items: new Map(),        // id → item
    history: new Map(),      // item id → [{ rev, keyRev, blob, updatedAt, updatedBy, device }]
    emergency: new Map(),    // id → { id, grantor, grantee, waitHours, status, sealedKey, requestedAt, releaseAt, grantedAt }
    shares: new Map(),       // id → Wi-Fi share (plugin 1.4.0): { id, itemId, vaultId, target, ssid, security, password, hidden, expiresAt, createdBy }
    wall: true,              // the Familie plugin with a wall tablet is there (targets.wall)
    seq: 0,
    offline: false,
    plugin,
    calls: [],
    pushes: [],
  };

  const fail = (code, extra) => new MessengerError(code, { status: STATUS[code] || 400, code, body: { ok: false, code, error: code, ...(extra || {}) } });
  const now = () => new Date().toISOString();
  const next = () => ++srv.seq;
  const id = (v) => { if (typeof v !== 'string' || !ID_RE.test(v)) throw fail('invalid'); return v; };
  const b64 = (v) => { if (typeof v !== 'string' || !B64.test(v)) throw fail('invalid'); return v; };
  const posInt = (v) => (Number.isSafeInteger(Number(v)) && Number(v) > 0 ? Number(v) : null);
  const canWrite = (r) => r === 'write' || r === 'manage';

  const accountView = (a) => ({ kdf: a.kdf, userKeyPw: a.userKeyPw, userKeyRk: a.userKeyRk, publicKey: a.publicKey, privateKeyEnc: a.privateKeyEnc, rev: a.rev, createdAt: a.createdAt, updatedAt: a.updatedAt });
  const need = (uid) => { const a = srv.accounts.get(uid); if (!a) throw fail('no_account'); return a; };
  const vaultView = (v, uid) => {
    const m = v.members.get(uid);
    return {
      id: v.id, kind: v.kind, ownerId: v.ownerId, nameEnc: v.nameEnc, role: m.role, keyRev: v.keyRev, sealedKey: m.sealedKey,
      pending: v.pendingKeyRev ? { keyRev: v.pendingKeyRev, sealedKey: m.pendingKey || null } : null,
      needsRekey: !!v.needsRekey,
      members: [...v.members].map(([u, x]) => ({ userId: u, name: srv.users.get(u).name, role: x.role })),
      updatedAt: v.updatedAt,
    };
  };
  const member = (vid, uid) => { const v = srv.vaults.get(vid); if (!v || !v.members.has(uid)) throw fail('not_found'); return { v, role: v.members.get(uid).role }; };
  const needRole = (vid, uid, want) => {
    const m = member(vid, uid);
    if (want === 'write' && !canWrite(m.role)) throw fail('forbidden');
    if (want === 'manage' && m.role !== 'manage') throw fail('forbidden');
    return m.v;
  };
  const listFor = (uid) => [...srv.vaults.values()].filter((v) => v.members.has(uid)).sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'personal' ? -1 : 1));
  const itemView = (it) => ({ ...it, blob: it.state === 'purged' ? null : it.blob });
  const dropVault = (vid) => {
    for (const [iid, it] of srv.items) if (it.vaultId === vid) { srv.items.delete(iid); srv.history.delete(iid); }
    srv.vaults.delete(vid);
  };
  const managers = (v) => [...v.members].filter(([, m]) => m.role === 'manage').map(([u]) => u);
  const emView = (e) => ({
    id: e.id, grantor: { id: e.grantor, name: srv.users.get(e.grantor).name }, grantee: { id: e.grantee, name: srv.users.get(e.grantee).name },
    waitHours: e.waitHours, status: e.status, requestedAt: e.requestedAt, releaseAt: e.releaseAt, grantedAt: e.grantedAt,
  });

  function saveOne(uid, it, device) {
    const iid = id(it.id);
    const vid = id(it.vaultId);
    const blob = b64(it.blob);
    const keyRev = posInt(it.keyRev);
    const baseRev = it.baseRev == null ? 0 : Number(it.baseRev);
    if (!keyRev || !Number.isSafeInteger(baseRev) || baseRev < 0) throw fail('invalid');
    const v = srv.vaults.get(vid);
    if (!v || !v.members.has(uid)) return { id: iid, ok: false, code: 'not_found' };
    if (!canWrite(v.members.get(uid).role)) return { id: iid, ok: false, code: 'forbidden' };
    if (keyRev !== (v.pendingKeyRev || v.keyRev)) return { id: iid, ok: false, code: 'stale_key' };
    const cur = srv.items.get(iid);
    const seq = next();
    if (!cur) {
      if (baseRev !== 0) return { id: iid, ok: false, code: 'not_found' };
      srv.items.set(iid, { id: iid, vaultId: vid, rev: 1, keyRev, blob, state: 'live', trashedAt: null, updatedAt: now(), updatedBy: uid, device, seq });
      return { id: iid, ok: true, rev: 1, seq };
    }
    const from = srv.vaults.get(cur.vaultId);
    if (!from || !from.members.has(uid) || cur.state === 'purged') return { id: iid, ok: false, code: 'not_found' };
    if (!canWrite(from.members.get(uid).role)) return { id: iid, ok: false, code: 'forbidden' };
    if (cur.rev !== baseRev) return { id: iid, ok: false, code: 'conflict', current: itemView(cur) };
    if (cur.vaultId === vid) {
      const h = srv.history.get(iid) || [];
      h.unshift({ rev: cur.rev, keyRev: cur.keyRev, blob: cur.blob, updatedAt: cur.updatedAt, updatedBy: cur.updatedBy, device: cur.device });
      srv.history.set(iid, h.slice(0, 10));
    } else {
      srv.history.delete(iid);
    }
    Object.assign(cur, { vaultId: vid, rev: cur.rev + 1, keyRev, blob, seq, updatedAt: now(), updatedBy: uid, device });
    return { id: iid, ok: true, rev: cur.rev, seq };
  }

  function handle(uid, method, p, body, q) {
    const seg = p.split('/').filter(Boolean).map(decodeURIComponent);
    const [a, b, c, d] = seg;
    const n = seg.length;
    const B = body || {};
    if (a === 'account') {
      if (n === 1 && method === 'GET') { const acc = srv.accounts.get(uid); return { account: acc ? accountView(acc) : null }; }
      if (n === 1 && method === 'POST') {
        if (srv.accounts.has(uid)) throw fail('exists');
        const per = B.personal || {};
        const pid = id(per.id);
        if (srv.vaults.has(pid)) throw fail('exists');
        const seq = next();
        const acc = { kdf: B.kdf, userKeyPw: b64(B.userKeyPw), userKeyRk: b64(B.userKeyRk), publicKey: b64(B.publicKey), privateKeyEnc: b64(B.privateKeyEnc), rev: 1, seq, createdAt: now(), updatedAt: now() };
        srv.accounts.set(uid, acc);
        srv.vaults.set(pid, { id: pid, kind: 'personal', ownerId: uid, nameEnc: b64(per.nameEnc), keyRev: 1, pendingKeyRev: null, needsRekey: false, members: new Map([[uid, { role: 'manage', sealedKey: b64(per.sealedKey), pendingKey: null }]]), updatedAt: now() });
        return { account: accountView(acc) };
      }
      if (n === 1 && method === 'PUT') {
        const acc = need(uid);
        if (B.rev !== acc.rev) throw fail('conflict', { account: accountView(acc) });
        Object.assign(acc, { kdf: B.kdf, userKeyPw: b64(B.userKeyPw), rev: acc.rev + 1, seq: next(), updatedAt: now() });
        if (B.userKeyRk) acc.userKeyRk = b64(B.userKeyRk);
        return { account: accountView(acc) };
      }
      if (n === 2 && b === 'delete' && method === 'POST') {
        if (B.confirm !== 'DELETE') throw fail('invalid');
        need(uid);
        srv.accounts.delete(uid);
        next();
        for (const v of listFor(uid)) {
          if (v.kind === 'personal' || v.members.size === 1) { dropVault(v.id); continue; }
          const wasManager = v.members.get(uid).role === 'manage';
          v.members.delete(uid);
          if (wasManager && !managers(v).length) v.members.values().next().value.role = 'manage';
          v.needsRekey = true;
        }
        for (const [eid, e] of srv.emergency) if (e.grantor === uid || e.grantee === uid) srv.emergency.delete(eid);
        return { account: null };
      }
    }
    if (a === 'people' && n === 1 && method === 'GET') {
      need(uid);
      return { people: [...srv.users.values()].filter((u) => u.id !== uid).map((u) => ({ id: u.id, name: u.name, publicKey: srv.accounts.has(u.id) ? srv.accounts.get(u.id).publicKey : null })) };
    }
    if (a === 'sync' && n === 1 && method === 'GET') {
      const acc = need(uid);
      const since = Number(q.since || 0);
      const limit = Math.min(Number(q.limit) || 200, 500);
      const list = listFor(uid);
      let ids = list.map((v) => v.id);
      if (q.vault) {
        if (!ids.includes(q.vault)) throw fail('not_found');
        ids = [q.vault];
      }
      const seq = srv.seq;
      let rows = [...srv.items.values()].filter((it) => ids.includes(it.vaultId) && it.seq > since && it.seq <= seq).sort((x, y) => x.seq - y.seq);
      const more = rows.length > limit;
      rows = rows.slice(0, limit);
      return {
        seq,
        account: since === 0 || acc.seq > since ? accountView(acc) : null,
        vaults: list.map((v) => vaultView(v, uid)),
        items: rows.map(itemView),
        more,
        next: more ? rows[rows.length - 1].seq : seq,
      };
    }
    if (a === 'vaults') {
      if (n === 1 && method === 'POST') {
        need(uid);
        const vid = id(B.id);
        if (srv.vaults.has(vid)) throw fail('exists');
        next();
        srv.vaults.set(vid, { id: vid, kind: 'shared', ownerId: uid, nameEnc: b64(B.nameEnc), keyRev: 1, pendingKeyRev: null, needsRekey: false, members: new Map([[uid, { role: 'manage', sealedKey: b64(B.sealedKey), pendingKey: null }]]), updatedAt: now() });
        return { vault: vaultView(srv.vaults.get(vid), uid) };
      }
      if (n === 2 && method === 'PUT') {
        const v = needRole(b, uid, 'manage');
        if (v.pendingKeyRev) throw fail('rekeying');
        v.nameEnc = b64(B.nameEnc);
        next();
        return { vault: vaultView(v, uid) };
      }
      if (n === 2 && method === 'DELETE') {
        const v = needRole(b, uid, 'manage');
        if (v.kind !== 'shared') throw fail('forbidden');
        next();
        dropVault(v.id);
        return { removed: v.id };
      }
      if (n === 3 && c === 'members' && method === 'POST') {
        const v = needRole(b, uid, 'manage');
        if (v.kind !== 'shared') throw fail('forbidden');
        if (v.pendingKeyRev) throw fail('rekeying');
        const target = posInt(B.userId);
        if (!target || !srv.users.has(target)) throw fail('not_found');
        if (!srv.accounts.has(target)) throw fail('no_account');
        if (v.members.has(target)) throw fail('exists');
        v.members.set(target, { role: B.role, sealedKey: b64(B.sealedKey), pendingKey: null });
        next();
        srv.pushes.push({ to: target, topic: 'share', event: 'shared', data: { vault: v.id } });
        return { vault: vaultView(v, uid) };
      }
      if (n === 4 && c === 'members' && method === 'PUT') {
        const v = needRole(b, uid, 'manage');
        const target = posInt(d);
        const m = v.members.get(target);
        if (!m) throw fail('not_found');
        if (m.role === 'manage' && B.role !== 'manage' && managers(v).length <= 1) throw fail('last_manager');
        m.role = B.role;
        next();
        return { vault: vaultView(v, uid) };
      }
      if (n === 4 && c === 'members' && method === 'DELETE') {
        const { v, role } = member(b, uid);
        if (v.kind !== 'shared') throw fail('forbidden');
        const target = posInt(d);
        if (target !== uid && role !== 'manage') throw fail('forbidden');
        const m = v.members.get(target);
        if (!m) throw fail('not_found');
        if (v.pendingKeyRev) throw fail('rekeying');
        next();
        if (v.members.size === 1) { dropVault(v.id); return { vault: null }; }
        if (m.role === 'manage' && managers(v).length <= 1) throw fail('last_manager');
        v.members.delete(target);
        v.needsRekey = true;
        return { vault: target === uid ? null : vaultView(v, uid) };
      }
      if (n === 4 && c === 'rekey' && d === 'start' && method === 'POST') {
        const v = needRole(b, uid, 'manage');
        if (B.keyRev !== v.keyRev + 1) throw fail('stale_key');
        if (v.pendingKeyRev && [...srv.items.values()].some((it) => it.vaultId === v.id && it.keyRev === v.pendingKeyRev)) throw fail('rekeying');
        const keys = new Map((B.keys || []).map((k) => [k.userId, b64(k.sealedKey)]));
        if (keys.size !== v.members.size || ![...v.members.keys()].every((u) => keys.has(u))) throw fail('invalid');
        for (const [u, m] of v.members) m.pendingKey = keys.get(u);
        v.pendingKeyRev = B.keyRev;
        next();
        return { vault: vaultView(v, uid) };
      }
      if (n === 4 && c === 'rekey' && d === 'finish' && method === 'POST') {
        const v = needRole(b, uid, 'manage');
        if (!v.pendingKeyRev) throw fail('invalid');
        const left = [...srv.items.values()].filter((it) => it.vaultId === v.id && it.state !== 'purged' && it.keyRev !== v.pendingKeyRev).length;
        if (left) throw fail('rekeying', { left });
        for (const m of v.members.values()) { m.sealedKey = m.pendingKey; m.pendingKey = null; }
        v.keyRev = v.pendingKeyRev;
        v.pendingKeyRev = null;
        v.needsRekey = false;
        v.nameEnc = b64(B.nameEnc);
        for (const [iid, h] of srv.history) if (srv.items.get(iid) && srv.items.get(iid).vaultId === v.id) srv.history.set(iid, h.filter((x) => x.keyRev === v.keyRev));
        next();
        return { vault: vaultView(v, uid) };
      }
    }
    if (a === 'items') {
      if (n === 1 && method === 'POST') {
        need(uid);
        if (!Array.isArray(B.items) || !B.items.length || B.items.length > 100) throw fail('invalid');
        if (JSON.stringify(B).length > 64 * 1024) throw fail('invalid');
        return { results: B.items.map((it) => saveOne(uid, it, B.device || null)) };
      }
      const it = srv.items.get(b);
      if (!it) throw fail('not_found');
      const { role } = member(it.vaultId, uid);
      if (n === 3 && c === 'history' && method === 'GET') return { history: srv.history.get(b) || [] };
      if (!canWrite(role)) throw fail('forbidden');
      if (it.state === 'purged') throw fail('not_found');
      if (n === 3 && (c === 'trash' || c === 'restore') && method === 'POST') {
        Object.assign(it, { state: c === 'trash' ? 'trash' : 'live', trashedAt: c === 'trash' ? now() : null, seq: next() });
        return { item: itemView(it) };
      }
      if (n === 2 && method === 'DELETE') {
        srv.history.delete(b);
        Object.assign(it, { state: 'purged', blob: null, seq: next() });
        return { item: itemView(it) };
      }
    }
    if (a === 'emergency') {
      need(uid);
      if (n === 1 && method === 'GET') {
        const all = [...srv.emergency.values()];
        return { granted: all.filter((e) => e.grantor === uid).map(emView), received: all.filter((e) => e.grantee === uid).map(emView) };
      }
      if (n === 1 && method === 'POST') {
        const g = posInt(B.granteeId);
        if (!g || !srv.accounts.has(g) || g === uid) throw fail('no_account');
        let e = [...srv.emergency.values()].find((x) => x.grantor === uid && x.grantee === g);
        if (e && e.status !== 'ready') throw fail('conflict');
        if (!e) {
          e = { id: crypto.randomBytes(12).toString('hex'), grantor: uid, grantee: g, status: 'ready', requestedAt: null, releaseAt: null, grantedAt: null };
          srv.emergency.set(e.id, e);
        }
        Object.assign(e, { waitHours: B.waitHours, sealedKey: b64(B.sealedKey) });
        return { emergency: emView(e) };
      }
      const e = srv.emergency.get(b);
      if (!e || (e.grantor !== uid && e.grantee !== uid)) throw fail('not_found');
      if (n === 2 && method === 'DELETE') { srv.emergency.delete(b); return { removed: b }; }
      if (n === 3 && method === 'POST') {
        if (c === 'request' && e.grantee === uid && e.status === 'ready') Object.assign(e, { status: 'requested', requestedAt: now(), releaseAt: now() });
        else if (c === 'deny' && e.grantor === uid) Object.assign(e, { status: 'ready', requestedAt: null, releaseAt: null, grantedAt: null });
        else if (c === 'approve' && e.grantor === uid && e.status === 'requested') Object.assign(e, { status: 'granted', grantedAt: now() });
        else throw fail('conflict');
        srv.pushes.push({ to: c === 'request' ? e.grantor : e.grantee, topic: 'emergency', event: c, data: { emergency: e.id } });
        return { emergency: emView(e) };
      }
      if (n === 3 && method === 'GET') {
        if (e.grantee !== uid || e.status !== 'granted') throw fail('forbidden');
        const gv = listFor(e.grantor);
        if (c === 'access') {
          const ga = srv.accounts.get(e.grantor);
          return { sealedKey: e.sealedKey, grantor: { id: e.grantor, name: srv.users.get(e.grantor).name, publicKey: ga.publicKey, privateKeyEnc: ga.privateKeyEnc }, vaults: gv.map((v) => vaultView(v, e.grantor)) };
        }
        if (c === 'items') {
          const ids = gv.map((v) => v.id);
          const since = Number(q.since || 0);
          const rows = [...srv.items.values()].filter((it) => ids.includes(it.vaultId) && it.state !== 'purged' && it.seq > since).sort((x, y) => x.seq - y.seq);
          return { seq: srv.seq, items: rows.map(itemView), more: false, next: srv.seq };
        }
      }
    }
    if (a === 'wifi-shares') {
      need(uid);
      const DUR = { '5m': 5 * 60000, '1h': 3600000, '24h': 86400000, forever: null };
      const view = (x) => ({ ...x, createdBy: { id: x.createdBy, name: srv.users.get(x.createdBy).name }, canEnd: canWrite(member(x.vaultId, uid).role) });
      if (n === 1 && method === 'GET') {
        const mine = [...srv.shares.values()].filter((x) => { const v = srv.vaults.get(x.vaultId); return v && v.members.has(uid) && (!q.item || x.itemId === q.item); });
        return { shares: mine.map(view), targets: { wall: srv.wall, portal: true } };
      }
      if (n === 1 && method === 'POST') {
        const it = srv.items.get(id(B.itemId));
        if (!it || it.state === 'purged') throw fail('not_found');
        needRole(it.vaultId, uid, 'write');
        if (!['wall', 'portal'].includes(B.target) || !(B.duration in DUR || B.duration === 'keep')) throw fail('invalid');
        if (B.target === 'wall' && !srv.wall) throw fail('no_wall');
        let x = [...srv.shares.values()].find((y) => y.itemId === it.id && y.target === B.target);
        if (B.duration === 'keep' && !x) throw fail('not_found');
        const expiresAt = B.duration === 'keep' ? x.expiresAt : (DUR[B.duration] == null ? null : new Date(Date.now() + DUR[B.duration]).toISOString());
        if (!x) { x = { id: crypto.randomBytes(12).toString('hex'), itemId: it.id, vaultId: it.vaultId, target: B.target, createdBy: uid }; srv.shares.set(x.id, x); }
        Object.assign(x, { ssid: B.ssid, security: B.security, password: B.password, hidden: B.hidden === true, expiresAt });
        return { share: view(x) };
      }
      if (n === 2 && method === 'DELETE') {
        const x = srv.shares.get(b);
        if (!x) throw fail('not_found');
        needRole(x.vaultId, uid, 'write');
        srv.shares.delete(b);
        return { removed: b };
      }
    }
    throw fail('not_found');
  }

  srv.transport = (uid, device = 'pc') => ({
    scope: () => `https://gc.example\nkey-${uid}-${device}`,
    async _call(method, path, opts = {}) {
      const body = opts.body === undefined ? undefined : JSON.parse(JSON.stringify(opts.body));
      srv.calls.push({ uid, device, method, path, body, params: opts.params || null });
      await new Promise((r) => setImmediate(r));
      if (srv.offline) throw new MessengerError('network error', { code: 'network' });
      if (path === PLUGINS) return { ok: true, plugins: srv.plugin ? [{ id: 'gatecontrol-vault', name: 'Vault', version: '1.0.0', tab: null }] : [] };
      if (!path.startsWith(API)) throw new MessengerError('HTTP 404', { status: 404, code: 'http_404' });
      const r = handle(uid, method, path.slice(API.length), body, opts.params || {});
      return JSON.parse(JSON.stringify({ ok: true, ...r }));
    },
  });

  return srv;
}

module.exports = { vaultServer, API };
