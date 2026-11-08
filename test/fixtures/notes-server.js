'use strict';

// A fake GateControl server with the plugin gatecontrol-notizen 1.0.0 (README "API") for the NotesService tests and
// the Pro app's e2e runs (support/notes-mock.js forwards there): the plugin list, me, nav, the views (Mein Tag with
// Termine / Überfällig / Heute / Demnächst / Erledigt heute, Wichtig, Geplant, Mir zugewiesen, a list, a source), the
// quick entry (the plugin's own ui/quickparse.js: src/vendor/notizen), people, search, prefs, sources, lists, groups,
// tasks (sub tasks, repeat → the next one with ui/repeat.js), items of the other plugins (Mail, Drive, Schule, Alltag,
// Familie as in the mockups), notebooks, notes (Markdown: check boxes, tags, rev), attachments with the core media
// routes (PUT …/media, GET /plugin-media/<token>), the Tresor routes (Drive's vault routes: keys, devices, recovery,
// rotate — only public keys and wraps are kept) and the moves from Microsoft To Do (device code, preview, a job) and
// DS Note (start, notebook, notes, finish).
//
//   const srv = await notesServer({ plugin, allowed, features, today, time, vaults, imports });
//   srv.url, srv.state (lists, tasks, items, notebooks, notes, attachments, media, vaults, devices, keys, ms, jobs,
//   requests …), srv.state.fail = { '<METHOD> <route>': { status, code, extra } }, srv.down = true, srv.close()

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

/**
 * The plugin's own modules (src/vendor/notizen) as CommonJS with `this` = module.exports, as Node loads them — also
 * when a test runner that rewrites modules (Playwright's) loads this fixture.
 */
function vendor(file, deps) {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'vendor', 'notizen', file), 'utf8');
  const mod = { exports: {} };
  const fn = new vm.Script(`(function (module, exports, require) {${src}\n})`, { filename: file }).runInThisContext();
  fn.call(mod.exports, mod, mod.exports, (name) => deps[name]);
  return mod.exports;
}
const R = vendor('repeat.js', {});
const Q = vendor('quickparse.js', { './repeat': R });

const PLUGIN = 'gatecontrol-notizen';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;
const FEATURES = ['tasks', 'notes', 'sources', 'vault', 'mstodo', 'dsnote', 'search', 'quickparse', 'attachments', 'ocrText'];
const TEXTS = {
  'v.myday': 'Mein Tag', 'v.important': 'Wichtig', 'v.planned': 'Geplant', 'v.assigned': 'Mir zugewiesen', 'v.events': 'Termine heute',
  'v.overdue': 'Überfällig', 'v.today': 'Heute', 'v.upcoming': 'Demnächst', 'v.done': 'Erledigt', 'v.tomorrow': 'Morgen', 'v.week': 'Nächste 7 Tage',
  'v.later': 'Später', 'v.open': 'Offen',
  'src.gatecontrol-familie': 'Familie', 'src.gatecontrol-mail': 'Mail', 'src.gatecontrol-drive': 'Drive', 'src.gatecontrol-schule': 'Schule', 'src.gatecontrol-alltag': 'Alltag',
  'srch.gatecontrol-familie': 'Aufgaben, Packlisten, Einkauf', 'srch.gatecontrol-mail': 'Zu tun, markierte Mails', 'srch.gatecontrol-drive': 'Fristen aus Dokumenten',
  'srch.gatecontrol-schule': 'Hausaufgaben, Arbeiten', 'srch.gatecontrol-alltag': 'Müllabfuhr',
};
const SOURCES = ['gatecontrol-familie', 'gatecontrol-mail', 'gatecontrol-drive', 'gatecontrol-schule', 'gatecontrol-alltag'];
const t = (k) => TEXTS[k] || k;
const VID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const TAG_RE = /(^|[\s(,;])#([\p{L}\p{N}][\p{L}\p{N}_-]{0,40})/gu;
const CHECK_RE = /^(\s*)([-*+])\s+\[([ xX])\]\s+(.*)$/;

function addDays(date, n) { return R.addDays(date, n); }

function noteMeta(body) {
  const lines = String(body || '').split('\n');
  let done = 0;
  let total = 0;
  const tags = [];
  for (const l of lines) {
    const m = CHECK_RE.exec(l);
    if (m) { total++; if (m[3] !== ' ') done++; }
    if (/^#{1,6}\s/.test(l)) continue;
    let x;
    TAG_RE.lastIndex = 0;
    while ((x = TAG_RE.exec(l))) { const tag = x[2].toLowerCase(); if (!/^\d+$/.test(tag) && !tags.includes(tag)) tags.push(tag); }
  }
  const plain = lines.map((l) => l.replace(/^#{1,6}\s+/, '').replace(CHECK_RE, '$4').replace(/^\s*[-*+]\s+/, '').replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/\*\*|__|~~|`/g, '').trim()).filter(Boolean);
  return { check: total ? { done, total } : null, tags, snippet: plain.join(' · ').slice(0, 160) || null };
}

async function notesServer({
  plugin = true, allowed = true, features = FEATURES, today = '2026-11-08', time = '08:00', vaults = true, imports = { mstodo: true, mstodoSync: true, dsnote: true },
  now = Date.UTC(2026, 10, 8, 7, 0, 0),
} = {}) {
  let nextId = 100;
  const id = () => ++nextId;
  const state = {
    plugin, allowed, features, today, time, vaultsOn: vaults, imports, now,
    fail: {}, requests: [], down: false,
    user: { id: 1, name: 'Max Muster' },
    people: [{ id: 1, name: 'Max Muster', initials: 'MM', colorHex: '#1B7A4E' }, { id: 12, name: 'Jenny Muster', initials: 'JM', colorHex: '#7C3AED' }, { id: 15, name: 'Noah Muster', initials: 'NM', colorHex: '#EA580C' }],
    prefs: { area: 'private', evening: '18:00', sources: {}, groups: {}, times: {} },
    lists: new Map(), groups: new Map(), tasks: new Map(), myDay: new Set(), items: new Map(),
    notebooks: new Map(), notes: new Map(), attachments: new Map(), media: new Map(), tokens: new Map(),
    vaults: new Map(),        // vaultId → { notebookId, recoveryPub, recoveryAuthHash, recoveryHolder }
    devices: new Map(),       // vaultId → Map deviceId → device
    keys: new Map(),          // `${vaultId}|${deviceId}|${kv}` → wrap
    ms: { accounts: [{ id: 3, email: 'max@outlook.com', label: 'Privat · Outlook', kind: 'personal', tasks: false }], consents: new Map(), links: [], interval: 5 },
    jobs: new Map(),
    sync: [],
  };
  // lists, tasks
  const list = (o) => { const l = { color: null, icon: null, isDefault: false, ownerId: 1, members: [1], groupId: null, position: 0, ext: null, ...o }; state.lists.set(l.id, l); return l; };
  list({ id: 1, name: 'Aufgaben', area: 'private', isDefault: true });
  list({ id: 2, name: 'Haus & Garten', area: 'private', color: 'green', members: [1, 12] });
  list({ id: 3, name: 'Gesundheit', area: 'private' });
  list({ id: 4, name: 'Aufgaben', area: 'work', isDefault: true });
  list({ id: 5, name: 'Büro', area: 'work' });
  const task = (o) => { const x = { parentId: null, note: '', important: false, doneAt: null, due: null, remindAt: null, repeat: null, assigneeId: null, source: null, noteId: null, position: 0, updatedAt: now, deleted: false, ...o }; state.tasks.set(x.id, x); return x; };
  task({ id: 11, listId: 3, title: 'Zahnarzt anrufen', important: true, due: { date: today, time: '09:00' } });
  task({ id: 12, listId: 1, title: 'Winterreifen-Termin ausmachen', due: { date: today, time: null }, note: 'Rabatt ab 50 Stück nachfragen' });
  task({ id: 13, listId: 1, parentId: 12, title: 'Werkstatt anrufen' });
  task({ id: 14, listId: 1, parentId: 12, title: 'Reifen aus dem Keller', doneAt: now - 3600000 });
  task({ id: 15, listId: 1, parentId: 12, title: 'Felgen putzen' });
  task({ id: 16, listId: 2, title: 'Rasen mähen', due: { date: addDays(today, 3), time: null }, repeat: { type: 'weekly', interval: 1, days: [R.weekday(addDays(today, 3))] } });
  task({ id: 17, listId: 5, title: 'Angebot nachfassen', due: { date: addDays(today, 5), time: '10:00' } });
  // items of the other plugins (contract § 2, as the hub shows them)
  const item = (o) => { const x = { subtitle: null, allDay: false, lead: null, area: 'private', important: false, done: false, doneAt: null, canComplete: true, assignee: null, progress: null, group: null, meta: {}, updatedAt: now, due: null, ...o }; state.items.set(x.id, x); return x; };
  item({ id: 201, plugin: 'gatecontrol-alltag', kind: 'event', title: 'Gelbe Tonne rausstellen', subtitle: 'Abholung morgen früh', due: { date: addDays(today, 1), time: null }, allDay: true, lead: 'evening', route: `waste/${addDays(today, 1)}` });
  item({ id: 202, plugin: 'gatecontrol-schule', kind: 'event', title: 'Elternabend Klasse 6b', due: { date: today, time: '19:30' }, canComplete: false, route: 'event/77', group: { id: 'child:8', label: 'Ben' } });
  item({ id: 203, plugin: 'gatecontrol-drive', kind: 'deadline', title: 'Rechnung Stadtwerke bezahlen', due: { date: addDays(today, -1), time: null }, allDay: true, meta: { amount: '84,20 €' }, route: 'node/501' });
  item({ id: 204, plugin: 'gatecontrol-mail', kind: 'task', title: 'Angebot von ACME beantworten', subtitle: 'Zu tun aus „Ihr Angebot 2026-114“', due: { date: today, time: null }, route: 'message/4711', group: { id: 'account:2', label: 'Firma · M365' } });
  item({ id: 205, plugin: 'gatecontrol-familie', kind: 'task', title: 'Rasen mähen – Noah', due: { date: today, time: null }, assignee: { id: 15, name: 'Noah' }, meta: { stars: 2 }, route: 'task/31' });
  item({ id: 206, plugin: 'gatecontrol-schule', kind: 'homework', title: 'Mathe: Buch S. 42, Nr. 3–6 – Ben', due: { date: addDays(today, 1), time: null }, allDay: true, route: 'homework/90', group: { id: 'child:8', label: 'Ben' } });
  // notebooks, notes
  const book = (o) => { const b = { color: null, isDefault: false, ownerId: 1, members: [1], vault: null, bound: null, position: 0, deleted: false, ...o }; state.notebooks.set(b.id, b); return b; };
  book({ id: 31, name: 'Notizen', area: 'private', isDefault: true });
  book({ id: 32, name: 'Haushalt', area: 'private' });
  book({ id: 33, name: 'Notizen', area: 'work', isDefault: true });
  const note = (o) => { const n = { title: '', body: '', titleCipher: null, cipher: null, keyVersion: null, pinned: false, color: null, due: null, expiresAt: null, createdAt: now - 86400000, updatedAt: now - 3600000, updatedBy: 1, rev: 1, ext: null, deleted: false, ...o }; state.notes.set(n.id, n); return n; };
  note({ id: 41, notebookId: 32, title: 'Werkstatt Montag', pinned: true, color: 'yellow', body: 'Winterreifen auf die Alufelgen, danach **Luftdruck 2,5 bar** prüfen. Mitnehmen:\n\n- [ ] Drehmomentschlüssel\n- [x] Reifen-Check\n- [ ] Ölfilter bestellen\n\n## Notizen vom letzten Mal\n\n- Profil vorne links 4 mm\n\n#auto #werkstatt' });
  note({ id: 42, notebookId: 31, title: 'Lasagne (Oma)', body: '500 g Hack, 2 Dosen Tomaten\n\n| Zutat | Menge |\n| --- | --- |\n| Hack | 500 g |\n\n#rezept', updatedAt: now - 7200000 });

  const fail = (status, code, extra = {}) => { const e = new Error(code); e.status = status; e.code = code; e.extra = extra; return e; };
  const posInt = (v) => { const n = Number(v); return Number.isSafeInteger(n) && n > 0 ? n : null; };
  const area = (v) => (v === 'work' ? 'work' : 'private');
  const me = () => state.user.id;
  const nameOf = (uid) => (state.people.find((p) => p.id === uid) || {}).name || null;
  const listView = (l) => ({
    id: l.id, name: l.name, area: l.area, color: l.color, icon: l.icon, isDefault: l.isDefault, owner: { id: l.ownerId, name: nameOf(l.ownerId) },
    role: l.ownerId === me() ? 'owner' : 'member', groupId: l.groupId, position: l.position, shared: l.members.length > 1,
    members: l.members.filter((m) => m !== l.ownerId).map((m) => ({ id: m, name: nameOf(m) })),
    open: [...state.tasks.values()].filter((x) => x.listId === l.id && !x.doneAt && !x.deleted && !x.parentId).length, ext: l.ext,
  });
  const myLists = (a) => [...state.lists.values()].filter((l) => l.members.includes(me()) && (!a || l.area === a));
  const overdueOf = (due, done) => !done && !!due && (due.time ? `${due.date} ${due.time}` < `${state.today} ${state.time}` : due.date < state.today);
  const taskView = (x, full = false) => {
    const subs = [...state.tasks.values()].filter((s) => s.parentId === x.id && !s.deleted);
    const v = {
      uid: `t:${x.id}`, type: 'task', id: x.id, listId: x.listId, parentId: x.parentId, title: x.title, hasNote: !!(x.note && x.note.trim()),
      important: x.important, done: !!x.doneAt, doneAt: x.doneAt ? new Date(x.doneAt).toISOString() : null, due: x.due, overdue: overdueOf(x.due, !!x.doneAt),
      remindAt: x.remindAt, repeat: x.repeat, repeatText: x.repeat ? R.describe(x.repeat, 'de') : null,
      assignee: x.assigneeId ? { id: x.assigneeId, name: nameOf(x.assigneeId) } : null, myDay: state.myDay.has(x.id),
      progress: subs.length ? { done: subs.filter((s) => s.doneAt).length, total: subs.length } : null,
      attachments: [...state.attachments.values()].filter((a) => a.kind === 'task' && a.refId === x.id).length,
      source: x.source, noteId: x.noteId, position: x.position, canComplete: true, updatedAt: x.updatedAt,
    };
    if (full) {
      v.note = x.note;
      v.subtasks = subs.map((s) => ({ id: s.id, title: s.title, done: !!s.doneAt }));
      v.list = listView(state.lists.get(x.listId));
      v.attachmentList = [...state.attachments.values()].filter((a) => a.kind === 'task' && a.refId === x.id).map(attView);
      const si = x.source ? [...state.items.values()].find((i) => i.plugin === x.source.plugin && String(i.id) === String(x.source.id)) : null;
      v.sourceItem = si ? itemView(si) : null;
    }
    return v;
  };
  const showOf = (i) => (i.lead === 'evening' && i.due ? { date: addDays(i.due.date, -1), time: state.prefs.evening } : i.due);
  const itemView = (i) => {
    const show = showOf(i);
    return {
      uid: `s:${i.id}`, type: 'source', id: i.id, kind: i.kind, title: i.title, subtitle: i.subtitle,
      source: { plugin: i.plugin, label: t(`src.${i.plugin}`), open: { plugin: i.plugin, route: i.route || '' } },
      due: i.due, show, allDay: i.allDay, lead: i.lead, overdue: i.kind !== 'event' && overdueOf(show, i.done), area: i.area, important: i.important,
      done: i.done, doneAt: i.doneAt, canComplete: i.canComplete, assignee: i.assignee, progress: i.progress, group: i.group, meta: i.meta, updatedAt: i.updatedAt,
    };
  };
  const sourceOn = (p) => !(state.prefs.sources[p] && state.prefs.sources[p].on === false);
  const visibleItems = (a) => [...state.items.values()].filter((i) => i.area === a && sourceOn(i.plugin)).map(itemView);
  const openTasks = (a) => [...state.tasks.values()].filter((x) => !x.deleted && !x.parentId && myLists(a).some((l) => l.id === x.listId));
  const sortKey = (x) => { const d = x.show || x.due; return `${d ? `${d.date} ${d.time || '99:99'}` : '9999'} ${String(x.title).toLowerCase()}`; };
  const byTime = (a, b) => (sortKey(a) < sortKey(b) ? -1 : sortKey(a) > sortKey(b) ? 1 : 0);
  const section = (sid, items, extra) => ({ id: sid, title: t(`v.${sid}`), count: items.length, items, ...(extra || {}) });
  const dayStart = now - ((Number(state.time.slice(0, 2)) * 60 + Number(state.time.slice(3))) * 60000);

  function myDayView(a) {
    const soon = addDays(state.today, 14);
    const out = { events: [], overdue: [], today: [], upcoming: [], done: [] };
    for (const x of openTasks(a).map((r) => taskView(r))) {
      if (x.done) { if (Date.parse(x.doneAt) >= dayStart) out.done.push(x); continue; }
      if (x.overdue) out.overdue.push(x);
      else if ((x.due && x.due.date <= state.today) || x.myDay) out.today.push(x);
      else if (x.due && x.due.date <= soon) out.upcoming.push(x);
    }
    for (const x of visibleItems(a)) {
      if (x.done) { if ((x.doneAt || 0) >= dayStart) out.done.push(x); continue; }
      if (!x.show) continue;
      if (x.kind === 'event' && x.show.date === state.today) out.events.push(x);
      else if (x.overdue) out.overdue.push(x);
      else if (x.show.date === state.today) out.today.push(x);
      else if (x.show.date <= soon && x.kind !== 'event') out.upcoming.push(x);
    }
    for (const k of Object.keys(out)) out[k].sort(byTime);
    return { view: 'myday', title: t('v.myday'), date: state.today, sections: [section('events', out.events), section('overdue', out.overdue), section('today', out.today), section('upcoming', out.upcoming), section('done', out.done, { collapsed: true })] };
  }

  function view(name, a) {
    if (name === 'myday') return myDayView(a);
    const open = openTasks(a).filter((x) => !x.doneAt).map((r) => taskView(r));
    const items = visibleItems(a).filter((x) => !x.done);
    if (name === 'important') return { view: 'important', title: t('v.important'), sections: [section('important', [...open.filter((x) => x.important), ...items.filter((x) => x.important)])] };
    if (name === 'assigned') return { view: 'assigned', title: t('v.assigned'), sections: [section('assigned', [...open, ...items].filter((x) => x.assignee && x.assignee.id === me()).sort(byTime))] };
    if (name === 'planned') {
      const g = { overdue: [], today: [], tomorrow: [], week: [], later: [] };
      for (const x of [...open.filter((y) => y.due), ...items.filter((y) => y.show)]) {
        const d = (x.show || x.due).date;
        if (x.overdue) g.overdue.push(x);
        else if (d <= state.today) g.today.push(x);
        else if (d === addDays(state.today, 1)) g.tomorrow.push(x);
        else if (d <= addDays(state.today, 7)) g.week.push(x);
        else g.later.push(x);
      }
      return { view: 'planned', title: t('v.planned'), sections: Object.keys(g).map((k) => section(k, g[k].sort(byTime))) };
    }
    let m = /^list:(\d+)$/.exec(name);
    if (m) {
      const l = state.lists.get(Number(m[1]));
      if (!l || !l.members.includes(me())) throw fail(404, 'not_found');
      const rows = [...state.tasks.values()].filter((x) => x.listId === l.id && !x.deleted && !x.parentId);
      return { view: 'list', title: l.name, list: listView(l), sections: [section('open', rows.filter((x) => !x.doneAt).map((r) => taskView(r))), section('done', rows.filter((x) => x.doneAt).map((r) => taskView(r)), { collapsed: true })] };
    }
    m = /^source:(gatecontrol-[a-z]+)$/.exec(name);
    if (m && SOURCES.includes(m[1])) {
      const groups = new Map();
      for (const x of items.filter((y) => y.source.plugin === m[1]).sort(byTime)) {
        const k = x.group ? x.group.id : '';
        if (!groups.has(k)) groups.set(k, { id: k ? `g:${k}` : 'all', title: x.group ? x.group.label : t(`src.${m[1]}`), count: 0, items: [] });
        groups.get(k).items.push(x);
        groups.get(k).count++;
      }
      return { view: 'source', title: t(`src.${m[1]}`), plugin: m[1], sections: [...groups.values()] };
    }
    throw fail(404, 'not_found');
  }

  const bookView = (b) => {
    const v = b.vault ? state.vaults.get(b.vault) : null;
    return {
      id: b.id, name: v ? null : b.name, area: b.area, color: b.color, isDefault: b.isDefault, role: b.ownerId === me() ? 'owner' : 'member',
      owner: { id: b.ownerId, name: nameOf(b.ownerId) }, members: b.members.filter((m) => m !== b.ownerId).map((m) => ({ id: m, name: nameOf(m) })),
      shared: b.members.length > 1, vault: v ? { id: b.vault, nameCipher: v.nameCipher, keyVersion: v.keyVersion, needsRotation: v.needsRotation } : null,
      bound: b.bound, count: [...state.notes.values()].filter((n) => n.notebookId === b.id && !n.deleted).length, position: b.position,
    };
  };
  const myBooks = (a) => [...state.notebooks.values()].filter((b) => !b.deleted && b.members.includes(me()) && (!a || b.area === a));
  const summary = (n) => {
    const enc = !!n.titleCipher;
    const meta = enc ? { check: null, tags: [], snippet: null } : noteMeta(n.body);
    const atts = [...state.attachments.values()].filter((a) => a.kind === 'note' && a.refId === n.id);
    return {
      id: n.id, notebookId: n.notebookId, title: enc ? null : n.title, snippet: meta.snippet, titleCipher: n.titleCipher, keyVersion: n.keyVersion, encrypted: enc,
      pinned: n.pinned, color: n.color, due: n.due, expiresAt: n.expiresAt, check: meta.check, images: atts.filter((a) => /^image\//.test(a.mime)).length,
      files: atts.filter((a) => !/^image\//.test(a.mime)).length, tags: meta.tags, ext: n.ext, createdAt: n.createdAt, updatedAt: n.updatedAt, updatedBy: n.updatedBy, rev: n.rev,
    };
  };
  const noteFull = (n) => {
    const b = state.notebooks.get(n.notebookId);
    const s = summary(n);
    const ids = [];
    for (const l of String(n.body || '').split('\n')) { const m = /\]\(task:(\d+)\)/.exec(l); if (m) ids.push(Number(m[1])); }
    return {
      ...s, body: n.titleCipher ? null : n.body, cipher: n.cipher, notebook: { id: b.id, name: b.vault ? null : b.name, area: b.area, vault: !!b.vault, bound: b.bound ? b.bound.plugin : null },
      attachments: [...state.attachments.values()].filter((a) => a.kind === 'note' && a.refId === n.id).map(attView),
      tasks: ids.map((x) => state.tasks.get(x)).filter(Boolean).map((x) => ({ id: x.id, title: x.title, due: x.due, done: !!x.doneAt })),
    };
  };
  const notesNav = (a) => {
    const books = myBooks(a);
    const tags = new Map();
    for (const n of state.notes.values()) if (!n.deleted && books.some((b) => b.id === n.notebookId)) for (const g of noteMeta(n.body).tags) tags.set(g, (tags.get(g) || 0) + 1);
    return { total: [...state.notes.values()].filter((n) => !n.deleted && books.some((b) => b.id === n.notebookId)).length, notebooks: books.map(bookView), tags: [...tags].map(([tag, c]) => ({ tag, count: c })) };
  };
  function attView(a) {
    let token = null;
    for (const [k, v] of state.tokens) if (v === a.mediaId) token = k;
    if (!token) { token = `${a.mediaId}.${crypto.randomBytes(8).toString('hex')}`; state.tokens.set(token, a.mediaId); }
    return { id: a.id, kind: a.kind, refId: a.refId, name: a.encrypted ? null : a.name, nameCipher: a.nameCipher, mime: a.mime, bytes: a.bytes, encrypted: a.encrypted, hasText: !!a.ocr, url: `/plugin-media/${token}`, createdAt: a.createdAt };
  }
  const accessNote = (nid) => {
    const n = state.notes.get(posInt(nid));
    if (!n || n.deleted) throw fail(404, 'not_found');
    const b = state.notebooks.get(n.notebookId);
    if (!b || !b.members.includes(me())) throw fail(404, 'not_found');
    return { n, b };
  };
  const accessTask = (tid) => {
    const x = state.tasks.get(posInt(tid));
    if (!x || x.deleted) throw fail(404, 'not_found');
    return x;
  };
  const vaultView = (vid) => {
    const v = state.vaults.get(vid);
    const b = state.notebooks.get(v.notebookId);
    const devs = [...(state.devices.get(vid) || new Map()).values()];
    const mine = devs.filter((d) => d.userId === me());
    return {
      id: vid, notebookId: b.id, area: b.area, nameCipher: v.nameCipher, keyVersion: v.keyVersion, recoveryPub: v.recoveryPub, recoveryHolder: v.recoveryHolder,
      needsRotation: v.needsRotation, rotatedAt: null, createdAt: v.createdAt, myDevices: mine.map((d) => ({ deviceId: d.deviceId, state: d.state, name: d.name })),
      pending: mine.some((d) => d.state === 'approved') ? devs.filter((d) => d.state === 'pending').length : 0,
    };
  };
  const deviceIdOf = (pub) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from('gcnotes-v1:device:'), Buffer.from(pub, 'base64url')])).digest().subarray(0, 16).toString('base64url');
  const deviceView = (d) => ({ deviceId: d.deviceId, userId: d.userId, name: d.name, platform: d.platform, publicKey: d.publicKey, state: d.state, via: d.via, createdAt: d.createdAt, approvedAt: d.approvedAt || null, approvedBy: null, revokedAt: null });
  const wrapOk = (w) => typeof w === 'string' && w.length === 108 && B64U_RE.test(w);
  const reachVault = (vid) => { if (!VID_RE.test(String(vid)) || !state.vaults.has(vid)) throw fail(404, 'not_found'); return state.vaults.get(vid); };
  const wrapsOf = (vid, did) => [...state.keys].filter(([k]) => k.startsWith(`${vid}|${did}|`)).map(([k, w]) => ({ keyVersion: Number(k.split('|')[2]), wrap: w })).sort((a, b) => a.keyVersion - b.keyVersion);

  function createTask(b) {
    let title = b.title;
    let parsed = null;
    let listId = posInt(b.listId);
    const a = area(b.area);
    const fields = { important: !!b.important, due: b.due || null, remindAt: null, repeat: b.repeat || null, assigneeId: b.assigneeId || null };
    if (typeof b.text === 'string') {
      parsed = Q.parse(b.text, { today: state.today, now: state.time, lists: myLists(a).map((l) => ({ id: l.id, name: l.name })), people: state.people.map((p) => ({ id: p.id, name: p.name })) });
      title = parsed.title || b.text.trim();
      if (parsed.date) fields.due = { date: parsed.date, time: parsed.time };
      if (parsed.remind) fields.remindAt = `${parsed.remind.date}T${parsed.remind.time}:00+01:00`;
      if (parsed.important) fields.important = true;
      if (parsed.repeat) fields.repeat = parsed.repeat;
      if (parsed.assignee) fields.assigneeId = parsed.assignee.id;
      if (parsed.list) listId = parsed.list.id;
      else if (parsed.listName && b.createList) { const l = list({ id: id(), name: parsed.listName, area: a }); listId = l.id; }
    }
    if (!title || typeof title !== 'string') throw fail(400, 'invalid', { field: 'title' });
    if (b.parentId) { const p = accessTask(b.parentId); listId = p.listId; }
    if (!listId) listId = myLists(a).find((l) => l.isDefault).id;
    if (!state.lists.has(listId)) throw fail(404, 'not_found');
    const x = task({ id: id(), listId, parentId: posInt(b.parentId), title: title.slice(0, 300), note: b.note || '', ...fields, updatedAt: state.now });
    if (b.myDay) state.myDay.add(x.id);
    return { task: taskView(x, true), ...(parsed ? { parsed } : {}) };
  }

  function route(method, p, q, b) {
    const parts = p.split('/').map(decodeURIComponent);
    const [a, x, y, z, w] = parts;
    const n = parts.length;
    const is = (m, len, first) => method === m && n === len && a === first;
    if (!state.allowed) throw fail(403, 'forbidden');
    if (is('GET', 1, 'me')) {
      return { user: state.user, lang: 'de', today: state.today, time: state.time, timezone: 'Europe/Berlin', features: state.features, prefs: state.prefs, sharing: 'all', vaults: state.vaultsOn, imports: state.imports, attachMB: 25, readOnly: false };
    }
    if (is('GET', 1, 'nav')) {
      const ar = area(q.area);
      const md = myDayView(ar);
      const open = visibleItems(ar).filter((i) => !i.done);
      const by = {};
      for (const s of SOURCES) by[s] = 0;
      for (const i of open) by[i.source.plugin]++;
      const tasksOpen = openTasks(ar).filter((r) => !r.doneAt);
      return {
        area: ar,
        smart: {
          myday: md.sections.filter((s) => ['events', 'overdue', 'today'].includes(s.id)).reduce((c, s) => c + s.items.filter((i) => !i.done).length, 0),
          important: tasksOpen.filter((r) => r.important).length + open.filter((i) => i.important).length,
          planned: tasksOpen.filter((r) => r.due).length + open.filter((i) => i.show).length,
          assigned: tasksOpen.filter((r) => r.assigneeId === me()).length + open.filter((i) => i.assignee && i.assignee.id === me()).length,
        },
        sources: SOURCES.filter(sourceOn).map((s) => ({ plugin: s, label: t(`src.${s}`), hint: t(`srch.${s}`), open: by[s] })),
        lists: myLists(ar).map(listView), groups: [...state.groups.values()].filter((g) => g.area === ar),
        notes: notesNav(ar),
      };
    }
    if (method === 'GET' && n === 2 && a === 'views') return view(x, area(q.area));
    if (is('POST', 1, 'parse')) return { parsed: Q.parse(String(b.text || ''), { today: state.today, now: state.time, lists: myLists(area(b.area)).map((l) => ({ id: l.id, name: l.name })), people: state.people }) };
    if (is('GET', 1, 'people')) return { people: state.people.map((pp) => ({ ...pp, avatarUrl: null, me: pp.id === me() })) };
    if (is('GET', 1, 'search')) {
      const s = String(q.q || '').toLowerCase();
      if (s.length < 2) throw fail(400, 'invalid', { field: 'q' });
      const ar = area(q.area);
      return {
        tasks: openTasks(ar).filter((r) => `${r.title} ${r.note}`.toLowerCase().includes(s)).map((r) => taskView(r)),
        notes: [...state.notes.values()].filter((nn) => !nn.deleted && !nn.titleCipher && myBooks(ar).some((bb) => bb.id === nn.notebookId) && `${nn.title} ${nn.body}`.toLowerCase().includes(s)).map((nn) => ({ ...summary(nn), hit: `\u0002${nn.title}\u0003` })),
        items: visibleItems(ar).filter((i) => i.title.toLowerCase().includes(s)),
      };
    }
    if (is('GET', 1, 'prefs')) return { prefs: state.prefs };
    if (is('PUT', 1, 'prefs')) {
      if (b.area) state.prefs.area = area(b.area);
      if (b.evening) state.prefs.evening = b.evening;
      if (b.sources) for (const [k, v] of Object.entries(b.sources)) state.prefs.sources[k] = { ...(state.prefs.sources[k] || {}), ...v };
      if (b.groups) Object.assign(state.prefs.groups, b.groups);
      if (b.times) Object.assign(state.prefs.times, b.times);
      return { prefs: state.prefs };
    }
    if (is('GET', 1, 'sources')) {
      return {
        sources: SOURCES.map((s) => ({
          plugin: s, label: t(`src.${s}`), hint: t(`srch.${s}`), enabled: true, available: true, open: [...state.items.values()].filter((i) => i.plugin === s && !i.done).length,
          lastSync: state.now - 3600000, error: null, groups: [...new Map([...state.items.values()].filter((i) => i.plugin === s && i.group).map((i) => [i.group.id, { id: i.group.id, label: i.group.label, count: 1 }])).values()],
        })),
      };
    }
    if (method === 'POST' && n === 3 && a === 'sources' && y === 'sync') { if (!SOURCES.includes(x)) throw fail(404, 'not_found'); state.sync.push(x); return { scheduled: true }; }

    // lists and groups
    if (is('GET', 1, 'lists')) return { lists: myLists(q.area ? area(q.area) : null).map(listView), groups: [...state.groups.values()] };
    if (is('POST', 1, 'lists')) {
      if (!b.name) throw fail(400, 'invalid', { field: 'name' });
      return { list: listView(list({ id: id(), name: String(b.name).slice(0, 80), area: area(b.area), color: b.color || null, groupId: b.groupId || null })) };
    }
    if (method === 'PATCH' && n === 2 && a === 'lists') {
      const l = state.lists.get(posInt(x));
      if (!l) throw fail(404, 'not_found');
      for (const k of ['name', 'color', 'area', 'groupId', 'position']) if (b[k] !== undefined) l[k] = b[k] === 'none' ? null : b[k];
      return { list: listView(l) };
    }
    if (method === 'DELETE' && n === 2 && a === 'lists') {
      const l = state.lists.get(posInt(x));
      if (!l) throw fail(404, 'not_found');
      if (l.isDefault) throw fail(409, 'conflict', { reason: 'default' });
      state.lists.delete(l.id);
      return {};
    }
    if (method === 'PUT' && n === 3 && a === 'lists' && y === 'members') {
      const l = state.lists.get(posInt(x));
      if (!l) throw fail(404, 'not_found');
      l.members = [l.ownerId, ...(b.members || []).filter((m) => m !== l.ownerId)];
      return { list: listView(l) };
    }
    if (is('POST', 1, 'groups')) { const g = { id: id(), name: b.name, area: area(b.area), position: 0 }; state.groups.set(g.id, g); return { group: g }; }
    if (method === 'PATCH' && n === 2 && a === 'groups') { const g = state.groups.get(posInt(x)); if (!g) throw fail(404, 'not_found'); Object.assign(g, b); return {}; }
    if (method === 'DELETE' && n === 2 && a === 'groups') { state.groups.delete(posInt(x)); return {}; }

    // tasks
    if (is('POST', 1, 'tasks')) return createTask(b);
    if (method === 'GET' && n === 2 && a === 'tasks') return { task: taskView(accessTask(x), true) };
    if (method === 'PATCH' && n === 2 && a === 'tasks') {
      const r = accessTask(x);
      for (const k of ['title', 'note', 'important', 'due', 'remindAt', 'repeat', 'assigneeId', 'listId', 'position']) {
        if (b[k] === undefined) continue;
        if (k === 'remindAt' && b[k] && typeof b[k] === 'object') r.remindAt = `${b[k].date}T${b[k].time}:00+01:00`;
        else r[k] = b[k];
      }
      if (b.myDay === true) state.myDay.add(r.id);
      if (b.myDay === false) state.myDay.delete(r.id);
      r.updatedAt = state.now;
      return { task: taskView(r, true) };
    }
    if (method === 'DELETE' && n === 2 && a === 'tasks') { accessTask(x).deleted = true; return {}; }
    if (method === 'POST' && n === 3 && a === 'tasks' && y === 'complete') {
      const r = accessTask(x);
      const done = b.done !== false;
      r.doneAt = done ? state.now : null;
      r.updatedAt = state.now;
      let next = null;
      if (done && r.repeat) {
        const nd = R.next(r.repeat, { due: r.due ? r.due.date : null, done: state.today });
        next = task({ ...r, id: id(), doneAt: null, due: { date: nd, time: r.due ? r.due.time : null } });
        r.repeat = null;
      }
      return { task: taskView(r), ...(next ? { next: taskView(next) } : {}) };
    }

    // items
    const accessItem = (iid) => { const i = state.items.get(posInt(iid)); if (!i) throw fail(404, 'not_found'); return i; };
    const carried = (i) => [...state.tasks.values()].find((r) => r.source && r.source.plugin === i.plugin && r.source.id === String(i.id) && !r.deleted);
    if (method === 'GET' && n === 2 && a === 'items') { const i = accessItem(x); const c = carried(i); return { item: itemView(i), taskId: c ? c.id : null }; }
    if (method === 'POST' && n === 3 && a === 'items' && y === 'complete') {
      const i = accessItem(x);
      if (!i.canComplete) throw fail(403, 'forbidden', { reason: 'read_only' });
      i.done = b.done !== false;
      i.doneAt = i.done ? state.now : null;
      return { item: itemView(i), taskId: null };
    }
    if (method === 'POST' && n === 3 && a === 'items' && y === 'carry') {
      const i = accessItem(x);
      const c = carried(i) || task({ id: id(), listId: myLists(i.area).find((l) => l.isDefault).id, title: i.title, due: i.due, source: { plugin: i.plugin, id: String(i.id) } });
      return { task: taskView(c, true) };
    }

    // notebooks and notes
    if (is('GET', 1, 'notebooks')) { const nv = notesNav(area(q.area)); return { notebooks: nv.notebooks, tags: nv.tags, total: nv.total }; }
    if (is('POST', 1, 'notebooks')) { if (!b.name) throw fail(400, 'invalid', { field: 'name' }); return { notebook: bookView(book({ id: id(), name: b.name, area: area(b.area), color: b.color || null })) }; }
    if (method === 'PATCH' && n === 2 && a === 'notebooks') {
      const nb = state.notebooks.get(posInt(x));
      if (!nb || nb.deleted) throw fail(404, 'not_found');
      if (b.nameCipher) { if (!nb.vault) throw fail(400, 'invalid', { field: 'nameCipher' }); state.vaults.get(nb.vault).nameCipher = b.nameCipher; }
      for (const k of ['name', 'color', 'area', 'position']) if (b[k] !== undefined) nb[k] = b[k] === 'none' ? null : b[k];
      return { notebook: bookView(nb) };
    }
    if (method === 'DELETE' && n === 2 && a === 'notebooks') { const nb = state.notebooks.get(posInt(x)); if (!nb) throw fail(404, 'not_found'); nb.deleted = true; return {}; }
    if (method === 'PUT' && n === 3 && a === 'notebooks' && y === 'members') { const nb = state.notebooks.get(posInt(x)); nb.members = [nb.ownerId, ...(b.members || [])]; return { notebook: bookView(nb) }; }
    if (is('GET', 1, 'notes')) {
      let rows = [...state.notes.values()].filter((nn) => !nn.deleted);
      if (q.notebook) { const nb = state.notebooks.get(posInt(q.notebook)); if (!nb || nb.deleted) throw fail(404, 'not_found'); rows = rows.filter((nn) => nn.notebookId === nb.id); } else rows = rows.filter((nn) => myBooks(area(q.area)).some((bb) => bb.id === nn.notebookId));
      if (q.tag) rows = rows.filter((nn) => noteMeta(nn.body).tags.includes(String(q.tag)));
      if (q.pinned === '1') rows = rows.filter((nn) => nn.pinned);
      rows.sort((l, r) => r.updatedAt - l.updatedAt || r.id - l.id);
      if (q.before) { const [u, i] = String(q.before).split(':').map(Number); rows = rows.filter((nn) => nn.updatedAt < u || (nn.updatedAt === u && nn.id < i)); }
      const limit = Math.min(200, posInt(q.limit) || 60);
      const page = rows.slice(0, limit);
      const last = page[page.length - 1];
      return { notes: page.map(summary), next: rows.length > limit && last ? `${last.updatedAt}:${last.id}` : null };
    }
    if (is('POST', 1, 'notes')) {
      const nbId = posInt(b.notebookId) || myBooks(area(b.area)).find((bb) => bb.isDefault).id;
      const nb = state.notebooks.get(nbId);
      if (!nb || nb.deleted) throw fail(404, 'not_found');
      if (nb.vault) {
        if (!B64U_RE.test(String(b.titleCipher || '')) || !B64U_RE.test(String(b.cipher || '')) || typeof b.title === 'string' || typeof b.body === 'string') throw fail(400, 'invalid', { field: 'cipher' });
        if (b.keyVersion !== state.vaults.get(nb.vault).keyVersion) throw fail(409, 'stale_key', { reason: 'stale_key', keyVersion: state.vaults.get(nb.vault).keyVersion });
      } else if (b.titleCipher || b.cipher) throw fail(400, 'invalid', { field: 'cipher' });
      const nn = note({ id: id(), notebookId: nb.id, title: nb.vault ? '' : String(b.title || ''), body: nb.vault ? '' : String(b.body || ''), titleCipher: nb.vault ? b.titleCipher : null, cipher: nb.vault ? b.cipher : null, keyVersion: nb.vault ? b.keyVersion : null, pinned: !!b.pinned, color: b.color && b.color !== 'none' ? b.color : null, createdAt: state.now, updatedAt: state.now });
      return { note: noteFull(nn) };
    }
    if (method === 'GET' && n === 2 && a === 'notes') return { note: noteFull(accessNote(x).n) };
    if (method === 'PATCH' && n === 2 && a === 'notes') {
      const { n: nn, b: nb } = accessNote(x);
      if (b.rev !== undefined && b.rev !== nn.rev) throw fail(409, 'conflict', { rev: nn.rev });
      if (nb.vault) {
        if (typeof b.title === 'string' || typeof b.body === 'string') throw fail(409, 'encrypted');
        if (b.titleCipher) { if (b.keyVersion !== state.vaults.get(nb.vault).keyVersion) throw fail(409, 'stale_key', { reason: 'stale_key', keyVersion: state.vaults.get(nb.vault).keyVersion }); nn.titleCipher = b.titleCipher; nn.keyVersion = b.keyVersion; }
        if (b.cipher) nn.cipher = b.cipher;
      } else {
        if (b.title !== undefined) nn.title = String(b.title);
        if (b.body !== undefined) nn.body = String(b.body);
      }
      if (b.pinned !== undefined) nn.pinned = !!b.pinned;
      if (b.color !== undefined) nn.color = b.color === 'none' ? null : b.color;
      if (b.notebookId !== undefined) nn.notebookId = posInt(b.notebookId);
      nn.rev++;
      nn.updatedAt = state.now + nn.rev;
      return { note: noteFull(nn) };
    }
    if (method === 'DELETE' && n === 2 && a === 'notes') { accessNote(x).n.deleted = true; return {}; }
    if (method === 'POST' && n === 3 && a === 'notes' && y === 'check') {
      const { n: nn, b: nb } = accessNote(x);
      if (nb.vault) throw fail(409, 'encrypted');
      const ls = nn.body.split('\n');
      const m = CHECK_RE.exec(ls[b.line] || '');
      if (!m) throw fail(400, 'invalid', { field: 'line' });
      ls[b.line] = `${m[1]}${m[2]} [${b.done ? 'x' : ' '}] ${m[4]}`;
      nn.body = ls.join('\n');
      nn.rev++;
      return { note: noteFull(nn) };
    }
    if (method === 'POST' && n === 3 && a === 'notes' && y === 'task') {
      const { n: nn, b: nb } = accessNote(x);
      if (nb.vault) throw fail(409, 'encrypted');
      const ls = nn.body.split('\n');
      const m = CHECK_RE.exec(ls[b.line] || '');
      if (!m) throw fail(400, 'invalid', { field: 'line' });
      const made = createTask({ title: m[4].replace(/\s*\[[^\]]*\]\(task:\d+\)/, ''), listId: b.listId, myDay: b.myDay, area: nb.area });
      ls[b.line] = `${ls[b.line]} [Aufgabe](task:${made.task.id})`;
      nn.body = ls.join('\n');
      nn.rev++;
      return { task: made.task, note: noteFull(nn) };
    }

    // attachments
    if (is('POST', 1, 'attachments')) {
      const md = state.media.get(b.mediaId);
      if (!md) throw fail(400, 'invalid', { field: 'mediaId' });
      let enc = false;
      if (b.kind === 'note') { const { b: nb } = accessNote(b.refId); enc = !!nb.vault; } else if (b.kind === 'task') accessTask(b.refId); else throw fail(400, 'invalid', { field: 'kind' });
      if (enc ? !b.nameCipher || typeof b.name === 'string' : !b.name) throw fail(400, 'invalid', { field: enc ? 'nameCipher' : 'name' });
      if (md.bytes.length > 25 * 1048576) throw fail(413, 'too_large', { maxMB: 25 });
      const att = { id: id(), kind: b.kind, refId: posInt(b.refId), mediaId: b.mediaId, name: enc ? null : b.name, nameCipher: enc ? b.nameCipher : null, mime: enc ? 'application/octet-stream' : md.mime, bytes: md.bytes.length, encrypted: enc, ocr: null, createdAt: state.now };
      state.attachments.set(att.id, att);
      return { attachment: attView(att) };
    }
    const accessAtt = (aid) => { const at = state.attachments.get(posInt(aid)); if (!at) throw fail(404, 'not_found'); return at; };
    if (method === 'GET' && n === 2 && a === 'attachments') return { attachment: attView(accessAtt(x)) };
    if (method === 'DELETE' && n === 2 && a === 'attachments') { state.attachments.delete(accessAtt(x).id); return {}; }
    if (method === 'PUT' && n === 3 && a === 'attachments' && y === 'text') { const at = accessAtt(x); if (at.encrypted) throw fail(409, 'encrypted'); at.ocr = b.text; return {}; }

    // Tresor notebooks
    if (a === 'vaults') {
      if (method === 'POST' && n === 1) {
        if (!state.vaultsOn) throw fail(403, 'forbidden', { reason: 'vaults_off' });
        if (!VID_RE.test(String(b.id)) || state.vaults.has(b.id)) throw fail(400, 'invalid', { field: 'id' });
        if (!B64U_RE.test(String(b.nameCipher || '')) || !wrapOk(b.wrap) || !wrapOk(b.recoveryWrap) || !b.device || !/^[A-Za-z0-9_-]{43}$/.test(String(b.device.publicKey)) || !/^[A-Za-z0-9_-]{43}$/.test(String(b.recoveryPub)) || typeof b.recoveryAuth !== 'string') throw fail(400, 'invalid', { field: 'body' });
        const nb = book({ id: id(), name: '', area: area(b.area), vault: b.id });
        state.vaults.set(b.id, { notebookId: nb.id, nameCipher: b.nameCipher, keyVersion: 1, recoveryPub: b.recoveryPub, recoveryAuthHash: crypto.createHash('sha256').update(b.recoveryAuth).digest('hex'), recoveryHolder: me(), needsRotation: false, createdAt: state.now });
        const did = deviceIdOf(b.device.publicKey);
        state.devices.set(b.id, new Map([[did, { deviceId: did, userId: me(), publicKey: b.device.publicKey, name: b.device.name || null, platform: b.device.platform || null, state: 'approved', via: 'create', createdAt: state.now, approvedAt: state.now }]]));
        state.keys.set(`${b.id}|${did}|1`, b.wrap);
        state.keys.set(`${b.id}|recovery|1`, b.recoveryWrap);
        return { vault: vaultView(b.id), notebook: bookView(nb) };
      }
      if (method === 'GET' && n === 1) return { vaults: [...state.vaults.keys()].map(vaultView) };
      const v = reachVault(x);
      const devs = state.devices.get(x);
      if (method === 'GET' && n === 2) return { vault: vaultView(x) };
      if (method === 'GET' && n === 3 && y === 'keys') {
        const d = devs.get(String(q.deviceId));
        if (!d) throw fail(404, 'not_found');
        return { deviceId: d.deviceId, state: d.state, keyVersion: v.keyVersion, keys: d.state === 'approved' ? wrapsOf(x, d.deviceId) : [] };
      }
      if (method === 'GET' && n === 3 && y === 'recovery') return { recoveryPub: v.recoveryPub, keyVersion: v.keyVersion, keys: wrapsOf(x, 'recovery') };
      if (method === 'GET' && n === 3 && y === 'devices') return { devices: [...devs.values()].map(deviceView) };
      if (method === 'POST' && n === 3 && y === 'devices') {
        const did = deviceIdOf(b.publicKey);
        const have = devs.get(did);
        if (have && have.state !== 'revoked') return { device: deviceView(have) };
        const d = { deviceId: did, userId: me(), publicKey: b.publicKey, name: b.name || null, platform: b.platform || null, state: 'pending', via: null, createdAt: state.now };
        devs.set(did, d);
        return { device: deviceView(d) };
      }
      if (method === 'POST' && n === 5 && y === 'devices' && w === 'approve') {
        const d = devs.get(z);
        if (!d) throw fail(404, 'not_found');
        if (b.via === 'recovery' && crypto.createHash('sha256').update(String(b.recoveryAuth)).digest('hex') !== v.recoveryAuthHash) throw fail(403, 'forbidden', { reason: 'recovery' });
        const wraps = Array.isArray(b.wraps) ? b.wraps : [];
        if (!wraps.every((x2) => wrapOk(x2.wrap)) || wraps.length !== v.keyVersion) throw fail(400, 'invalid', { field: 'wraps' });
        for (const x2 of wraps) state.keys.set(`${x}|${z}|${x2.keyVersion}`, x2.wrap);
        d.state = 'approved';
        d.via = b.via === 'recovery' ? 'recovery' : 'device';
        d.approvedAt = state.now;
        return { device: deviceView(d) };
      }
      if (method === 'DELETE' && n === 4 && y === 'devices') {
        const d = devs.get(z);
        if (!d) throw fail(404, 'not_found');
        d.state = 'revoked';
        for (const k of [...state.keys.keys()]) if (k.startsWith(`${x}|${z}|`)) state.keys.delete(k);
        return { device: deviceView(d) };
      }
      if (method === 'POST' && n === 3 && y === 'rotate') {
        if (b.keyVersion !== v.keyVersion + 1) throw fail(409, 'conflict', { keyVersion: v.keyVersion });
        const want = [...devs.values()].filter((d) => d.state === 'approved').map((d) => d.deviceId).sort();
        const got = (b.wraps || []).map((x2) => x2.deviceId).sort();
        if (JSON.stringify(want) !== JSON.stringify(got)) throw fail(409, 'conflict', { devices: want });
        for (const x2 of b.wraps) state.keys.set(`${x}|${x2.deviceId}|${b.keyVersion}`, x2.wrap);
        if (b.recovery) for (const x2 of b.recovery.wraps) state.keys.set(`${x}|recovery|${x2.keyVersion}`, x2.wrap);
        else state.keys.set(`${x}|recovery|${b.keyVersion}`, b.recoveryWrap);
        v.keyVersion = b.keyVersion;
        v.needsRotation = false;
        return { vault: vaultView(x) };
      }
    }

    // moving over
    if (a === 'import') {
      if (method === 'GET' && n === 3 && x === 'mstodo' && y === 'accounts') return state.imports.mstodo ? { available: true, accounts: state.ms.accounts } : { available: false, reason: 'off', accounts: [] };
      if (method === 'POST' && n === 3 && x === 'mstodo' && y === 'consent') {
        const acc = state.ms.accounts.find((ac) => ac.id === b.accountId);
        if (!acc) throw fail(404, 'not_found');
        if (!b.deviceId) {
          const did = `dev${id()}`;
          state.ms.consents.set(did, { accountId: acc.id, polls: 0 });
          return { deviceId: did, userCode: 'ABCD-EFGH', verificationUri: 'https://microsoft.com/devicelogin', expiresIn: 900, interval: state.ms.interval };
        }
        const c = state.ms.consents.get(b.deviceId);
        if (!c) return { status: 'expired' };
        c.polls++;
        if (c.polls < 2) return { status: 'pending' };
        acc.tasks = true;
        return { status: 'done', tasks: true };
      }
      if (method === 'GET' && n === 3 && x === 'mstodo' && y === 'preview') {
        const acc = state.ms.accounts.find((ac) => ac.id === posInt(q.accountId));
        if (!acc) throw fail(404, 'not_found');
        if (!acc.tasks) throw fail(409, 'consent_required');
        const lists = [{ id: 'AAMk-1', name: 'Aufgaben', open: 12, done: 40, attachments: 2, area: 'private', wellknown: 'defaultList', shared: false, include: true },
          { id: 'AAMk-2', name: 'Projekt X', open: 7, done: 3, attachments: 1, area: 'work', wellknown: null, shared: false, include: true },
          { id: 'AAMk-3', name: 'Markierte E-Mails', open: 4, done: 0, attachments: 0, area: 'private', wellknown: 'flaggedEmails', shared: false, include: false }];
        return { lists, totals: { lists: 3, open: 23, done: 43, attachments: 3 } };
      }
      if (method === 'POST' && n === 3 && x === 'mstodo' && y === 'start') {
        const j = { id: id(), kind: 'mstodo', state: 'running', stats: { lists: 0, tasks: 0, attachments: 0 }, error: null, polls: 0, body: b };
        state.jobs.set(j.id, j);
        if (b.twoWay) for (const l of b.lists.filter((l2) => l2.include)) state.ms.links.push({ id: id(), listId: 1, listName: l.name, accountId: b.accountId, twoWay: true, lastSync: null, error: null });
        return { job: { id: j.id, kind: j.kind, state: j.state, stats: j.stats, error: null } };
      }
      if (method === 'GET' && n === 3 && x === 'jobs') {
        const j = state.jobs.get(posInt(y));
        if (!j) throw fail(404, 'not_found');
        if (j.kind === 'mstodo' && j.state === 'running' && ++j.polls >= 2) { j.state = 'done'; j.stats = { lists: 2, tasks: 19, attachments: 3 }; }
        return { job: { id: j.id, kind: j.kind, state: j.state, stats: j.stats, error: j.error } };
      }
      if (method === 'GET' && n === 3 && x === 'mstodo' && y === 'links') return { links: state.ms.links };
      if (method === 'DELETE' && n === 4 && x === 'mstodo' && y === 'links') { state.ms.links = state.ms.links.filter((l) => l.id !== posInt(z)); return {}; }
      if (method === 'POST' && n === 3 && x === 'dsnote' && y === 'start') {
        const j = { id: id(), kind: 'dsnote', state: 'running', stats: { notebooks: 0, notes: 0, attachments: 0, skipped: 0, protectedSkipped: 0 }, error: null, options: b, refs: new Map() };
        state.jobs.set(j.id, j);
        return { job: { id: j.id, kind: j.kind, state: j.state, stats: j.stats, error: null } };
      }
      const job = state.jobs.get(posInt(y));
      if (x === 'dsnote' && (!job || job.kind !== 'dsnote')) throw fail(404, 'not_found');
      if (method === 'POST' && n === 4 && x === 'dsnote' && z === 'notebook') {
        if (job.state !== 'running') throw fail(409, 'conflict');
        const have = [...state.notebooks.values()].find((nb) => nb.ext === `dsnote:${b.ref}`);
        if (have) return { notebookId: have.id, existed: true };
        const nb = book({ id: id(), name: b.name, area: area(b.area), ext: `dsnote:${b.ref}` });
        job.stats.notebooks++;
        return { notebookId: nb.id };
      }
      if (method === 'POST' && n === 4 && x === 'dsnote' && z === 'notes') {
        const nb = state.notebooks.get(posInt(b.notebookId));
        if (!nb || !Array.isArray(b.notes) || !b.notes.length || b.notes.length > 20) throw fail(400, 'invalid', { field: 'notes' });
        let imported = 0;
        let skipped = 0;
        const ids = {};
        for (const nn of b.notes) {
          const have = [...state.notes.values()].find((x2) => x2.notebookId === nb.id && x2.ext === `dsnote:${nn.ref}`);
          if (have) { ids[nn.ref] = have.id; skipped++; continue; }
          const made = note({ id: id(), notebookId: nb.id, title: nb.vault ? '' : nn.title, body: '', titleCipher: nb.vault ? nn.titleCipher : null, cipher: nb.vault ? nn.cipher : null, keyVersion: nb.vault ? nn.keyVersion : null, ext: `dsnote:${nn.ref}`, createdAt: nn.created || state.now, updatedAt: nn.updated || state.now });
          const map = new Map();
          for (const at of nn.attachments || []) {
            const md = state.media.get(at.mediaId);
            if (!md) { skipped++; continue; }
            const att = { id: id(), kind: 'note', refId: made.id, mediaId: at.mediaId, name: nb.vault ? null : at.name, nameCipher: nb.vault ? at.nameCipher : null, mime: nb.vault ? 'application/octet-stream' : md.mime, bytes: md.bytes.length, encrypted: !!nb.vault, createdAt: state.now };
            state.attachments.set(att.id, att);
            map.set(at.n, att.id);
            job.stats.attachments++;
          }
          if (!nb.vault) {
            let body = String(nn.body || '').replace(/\]\(attnew:(\d{1,4})\)/g, (all, k) => (map.has(Number(k)) ? `](att:${map.get(Number(k))})` : ']()'));
            if (Array.isArray(nn.tags) && nn.tags.length) body += `${body ? '\n\n' : ''}${nn.tags.map((g) => `#${g}`).join(' ')}`;
            made.body = body;
          }
          ids[nn.ref] = made.id;
          imported++;
        }
        job.stats.notes += imported;
        job.stats.skipped += skipped;
        return { imported, skipped, ids };
      }
      if (method === 'POST' && n === 4 && x === 'dsnote' && z === 'finish') {
        job.stats.skipped += b.skipped || 0;
        job.stats.protectedSkipped += b.protectedSkipped || 0;
        job.state = 'done';
        return { job: { id: job.id, kind: job.kind, state: job.state, stats: job.stats, error: null } };
      }
    }
    throw fail(404, 'not_found');
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (state.down) { req.socket.destroy(); return; }
      const url = new URL(req.url, 'http://x');
      const raw = Buffer.concat(chunks);
      const send = (status, json) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(json)); };
      state.requests.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body: raw.length && /json/.test(req.headers['content-type'] || '') ? (() => { try { return JSON.parse(raw.toString()); } catch { return null; } })() : null });
      // the signed media URLs (gc.media.url): no token needed
      if (req.method === 'GET' && url.pathname.startsWith('/plugin-media/')) {
        const mid = state.tokens.get(url.pathname.slice('/plugin-media/'.length));
        const m = mid && state.media.get(mid);
        if (!m) return send(404, { ok: false, code: 'not_found' });
        res.writeHead(200, { 'content-type': m.mime, 'content-length': String(m.bytes.length) });
        return res.end(m.bytes);
      }
      if (req.headers['x-api-token'] !== 'gc_token' && req.headers.authorization !== 'Bearer gc_token') return send(401, { ok: false, error: 'unauthorized' });
      if (url.pathname === '/api/v1/client/plugins') return send(200, { ok: true, plugins: state.plugin ? [{ id: PLUGIN, name: 'Notizen & Aufgaben', version: '1.0.0', tab: null }] : [] });
      if (!state.plugin) return send(404, { ok: false, code: 'not_found' });
      if (req.method === 'PUT' && url.pathname === MEDIA) {
        if (!raw.length) return send(411, { ok: false, code: 'length_required' });
        const mediaId = crypto.randomBytes(16).toString('hex');
        state.media.set(mediaId, { bytes: raw, mime: String(req.headers['content-type'] || 'application/octet-stream').split(';')[0] });
        return send(200, { ok: true, mediaId, mime: state.media.get(mediaId).mime, bytes: raw.length });
      }
      if (!url.pathname.startsWith(API)) return send(404, { ok: false, code: 'not_found' });
      const p = url.pathname.slice(API.length);
      const routeKey = `${req.method} ${p.replace(/\/\d+/g, '/:id')}`;
      const f = state.fail[routeKey];
      if (f) return send(f.status || 500, { ok: false, code: f.code || 'failed', ...(f.extra || {}) });
      let body = {};
      if (raw.length) { try { body = JSON.parse(raw.toString()); } catch { return send(400, { ok: false, code: 'invalid' }); } }
      try {
        return send(200, { ok: true, ...route(req.method, p, Object.fromEntries(url.searchParams), body) });
      } catch (err) {
        if (err.status) return send(err.status, { ok: false, code: err.code, ...(err.extra || {}) });
        return send(500, { ok: false, code: 'failed', error: err.message });
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    state,
    get down() { return state.down; },
    set down(v) { state.down = !!v; },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

module.exports = { notesServer, PLUGIN, FEATURES, noteMeta };
