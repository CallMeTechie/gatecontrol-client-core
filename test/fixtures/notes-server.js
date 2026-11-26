'use strict';

// A fake GateControl server with the plugin gatecontrol-notizen 1.0.0 (README "API") for the NotesService tests and
// the Pro app's e2e runs (support/notes-mock.js forwards there): the plugin list, me, nav, the views (Mein Tag with
// Termine / Überfällig / Heute / Demnächst / Erledigt heute, Wichtig, Geplant, Mir zugewiesen, a list, a source), the
// quick entry (the plugin's own ui/quickparse.js: src/vendor/notizen), people, search, prefs, sources, lists, groups,
// tasks (sub tasks, repeat → the next one with ui/repeat.js), items of the other plugins (Mail, Drive, Schule, Alltag,
// Familie as in the mockups), notebooks, notes (Markdown: check boxes, tags, rev), attachments with the core media
// routes (PUT …/media, GET /plugin-media/<token>), the Tresor routes (Drive's vault routes: keys, devices, recovery,
// rotate — only public keys and wraps are kept) and the moves from Microsoft To Do (device code, preview, a job) and
// DS Note (start, notebook, notes, finish). With the plugin's 1.3.0 words in `features` (STAGE1: reminderActions,
// yesterdayOpen, taskCalendar — not in the default, which stays an older plugin): a task's `reminder` / `snoozed` /
// `missedReminder` / `calendar`, `me.calendar` / `me.yesterday`, „Gestern offen geblieben“ (`yesterday` of
// views/myday, GET yesterday, POST yesterday, POST tasks/<id>/move); without them those routes answer 404. With the
// 1.4.0 words (STAGE2: shoppingLists, taskList, familyShopping — not in the default either): the shopping lists of the
// hub (GET shopping[?since] with tombstones, POST shopping/ops — in order, safe to repeat, `completed` when the last
// open item of a list is ticked —, nav.shopping, me.shopping, PUT shopping/lists/<uid>/family, POST …/going, …/assign;
// PATCH / DELETE lists/<n> and PUT lists/<n>/members with a shopping list's number), a task's `attachedList`
// (attachedListId / attachedListUid, `attach: 'auto'`) and `attach` of POST parse; without them: 404, fields passed over.
// With the 1.5.0 words (STAGE3: places, placeSearch — not in the default either): a task's `place` (one place or
// „Jeder Lidl“, on arriving / leaving, consent), `place` of POST / PATCH tasks and of POST parse (a small table of the
// plugin's words: Baumarkt, Bäcker, Apotheke, Tankstelle, Supermarkt; „bei <Name>“; „zu Hause“; an own place by its
// name; an address), GET / POST / PATCH / DELETE places, PUT places/favs, POST places/search (a fixed catalogue; 403
// module_off while state.placeCfg.mode is 'off' or the person switched it off, 503 while state.placeCfg.down),
// POST tasks/<id>/place/consent, me.places, prefs.places. POST places/watch and POST places/fired are the phone's:
// the fake has neither, and state.requests shows that a Windows app never asks for them.
//
// With the 1.6.0 words (STAGE4: taskTurns, taskStars, familyTasks, doneFeedback, placeMine — not in the default either):
// whose turn (`turn`, `people` of a task, when writing and from the typed line — the plugin's own ui/turnwords.js after
// the parser), stars, the family's list (srv.addFamily(): `List.family`, `Task.family`, `Task.doneBy`, `me.familyTasks`,
// what a child may, POST tasks/<id>/complete { userId }, POST family/seen), `prefs.feedback` and a place's `mine` /
// `canConsent`. state.user decides who asks (a parent or a child of the family).
//
// With the 1.7.0 word (STAGE5: driveDeadlines — not in the default either): a task's `deadline` (srv.addDeadline():
// the task the hub made for a reminder of one of Drive's deadlines), `me.driveDeadlines`, and srv.reminderPush(taskId):
// the push of that task's reminder as the plugin sends it („Frist in 3 Tagen: …“, four buttons, the fourth a link to
// the file in the portal). With the 1.8.0 word (STAGE6: profilePlaces — not in the default either): the named places
// are the profile's (`ref` profile:<id>, `icon`, `visibility`, `usedBy` from state.placeUses), GET places `profile` and
// `notMoved` (state.notMoved), POST / PATCH places take `icon` / `visibility`, DELETE places/<id> answers 409 in_use
// { usedBy, ref } while another plugin uses the place (state.placeUses) unless ?force=1, `me.places.profile`. A list's own role is 'owner' | 'write' | 'read' with `canEdit` as the plugin says them;
// `readers` of a list (user ids) only read: their tasks are `canEdit: false`, writing answers 403 read_only.
//   const srv = await notesServer({ plugin, allowed, features, today, time, vaults, imports });
//   srv.url, srv.state (lists, tasks, items, notebooks, notes, attachments, media, vaults, devices, keys, ms, jobs,
//   requests …), srv.addTask({ id, listId, title, due, … }), srv.addShopList({ id, name, icon?, area?, family?, role?,
//   members?, items: [{ id?, text, qty?, checked? }] }), srv.addPlace({ name, address?, lat, lon, radius?, named?, ref?, fav? }),
//   srv.setTaskPlace(taskId, { placeId | any, key?, label?, trigger?, by?, who?, consent? }), srv.state.fail = { '<METHOD> <route>': { status, code, extra } }, srv.down = true, srv.close()

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
const TW = vendor('turnwords.js', {});

const PLUGIN = 'gatecontrol-notizen';
const API = `/api/v1/client/plugins/${PLUGIN}/api/`;
const MEDIA = `/api/v1/client/plugins/${PLUGIN}/media`;
const FEATURES = ['tasks', 'notes', 'sources', 'vault', 'mstodo', 'dsnote', 'search', 'quickparse', 'attachments', 'ocrText'];
const STAGE1 = ['reminderActions', 'yesterdayOpen', 'taskCalendar'];
const STAGE2 = ['shoppingLists', 'taskList', 'familyShopping'];
const STAGE3 = ['places', 'placeSearch'];
const STAGE4 = ['taskTurns', 'taskStars', 'familyTasks', 'doneFeedback', 'placeMine'];
const STAGE5 = ['driveDeadlines'];
const STAGE6 = ['profilePlaces'];
const LIST_ICONS = ['list', 'cart', 'home', 'tool', 'gift', 'plane', 'heart', 'work'];
const SHOP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHOP_WORDS = ['einkaufen', 'einkauf', 'einkäufe', 'besorgen', 'besorgung', 'besorgungen', 'shopping', 'groceries', 'grocery'];
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
const STAGE4_TURNS = ['rotate', 'first'];
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
    // plugin 1.3.0
    snoozed: new Set(), missed: new Set(), yesterdayDay: new Set(),   // task ids: put off with „Später“, reminder lost, in „Mein Tag“ yesterday
    calendar: { available: true, enabled: true, mine: true, name: 'Aufgaben' }, yesterdayPrefs: { push: true, at: '07:30' },
    // plugin 1.4.0
    shopLists: new Map(),     // uid → { uid, num, name, icon, area, ownerId, members: [{ id, role }], family, deletedAt, updatedAt, was }
    shopItems: new Map(),     // id → { id, list (uid), text, qty, checked, checkedBy, updatedAt, deleted, seq }
    attached: new Map(),      // task id → the number of the shopping list it carries
    shopFamily: { available: true, bound: true, parent: true }, shopSeq: 0, going: [], assigned: [],
    // plugin 1.5.0
    places: new Map(),        // id → { id, userId, name, address, lat, lon, radius, named, ref, deleted, updatedAt }
    picks: new Map(),         // `${key}|${placeId}` → { key, placeId, uses, fav }
    taskPlace: new Map(),     // task id → { placeId, key, label, any, trigger, by, who, consent }
    familyPlaces: [{ id: 'home', name: 'Zuhause', lat: 52.5203, lon: 13.4051, radius: 150 }, { id: 'place:3', name: 'Schule', lat: 52.5301, lon: 13.4101, radius: 300 }],
    // 1.8.0 (profilePlaces): „Genutzt von“ of another plugin per place id, what the move could not take
    placeUses: new Map(),
    notMoved: [],
    placeCfg: { mode: 'osm', down: false },   // the administrator's choice (off | osm | own); down: the map service does not answer
    placeSearches: [],        // the bodies of POST places/search
    // plugin 1.6.0
    family: { available: true, listId: null, parents: [], kids: [], stars: true, starsMax: 10, moved: null },   // srv.addFamily()
    feedback: [],             // what the parents were told: { taskId, userId, stars } (the push kind done_feedback)
  };
  if (features.includes('doneFeedback')) state.prefs.feedback = 'all';
  if (features.includes('places')) state.prefs.places = { search: true, nearby: true, quiet: { from: '21:00', to: '07:00' } };
  const has = (f) => state.features.includes(f);
  // lists, tasks
  const list = (o) => { const l = { color: null, icon: null, isDefault: false, ownerId: 1, members: [1], readers: [], groupId: null, position: 0, ext: null, ...o }; state.lists.set(l.id, l); return l; };
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
  // the own role in a list as the plugin names it (1.2.0: 'read' only looks)
  const roleIn = (l) => (l.ownerId === me() ? 'owner' : l.readers.includes(me()) ? 'read' : 'write');
  const readOnly = (listId) => { const l = state.lists.get(listId); return !!l && roleIn(l) === 'read'; };
  const listView = (l) => ({
    id: l.id, name: l.name, area: l.area, color: l.color, icon: l.icon, isDefault: l.isDefault, owner: { id: l.ownerId, name: nameOf(l.ownerId) },
    role: roleIn(l), canEdit: roleIn(l) !== 'read', groupId: l.groupId, position: l.position, shared: l.members.length > 1,
    members: l.members.filter((m) => m !== l.ownerId).map((m) => ({ id: m, name: nameOf(m), role: l.readers.includes(m) ? 'read' : 'write' })),
    open: [...state.tasks.values()].filter((x) => x.listId === l.id && !x.doneAt && !x.deleted && !x.parentId).length, ext: l.ext,
    ...(has('familyTasks') ? { family: isFamilyList(l.id) } : {}),
  });
  // ── plugin 1.6.0: whose turn, stars, the family's list ──
  const isFamilyList = (lid) => has('familyTasks') && !!state.family.listId && state.family.listId === lid;
  const famMember = (uid) => state.family.parents.includes(uid) || state.family.kids.includes(uid);
  const isParent = (uid = me()) => state.family.parents.includes(uid);
  const isKid = (uid = me()) => state.family.kids.includes(uid);
  const person = (uid) => ({ id: uid, name: nameOf(uid) });
  /** Who takes part in a task: only who is (still) a member of its list; fewer than two → an ordinary task. */
  const turnOf = (x) => {
    const l = state.lists.get(x.listId);
    const people = x.turn && l ? (x.people || []).filter((u) => l.members.includes(u)) : [];
    return people.length >= 2 ? { turn: x.turn, people } : { turn: null, people: [] };
  };
  /** What a child may in the family's list (the contract § 5): change what no parent made, tick off what is theirs. */
  const mayEdit = (x) => !(isFamilyList(x.listId) && isKid() && isParent(x.by || 1));
  const mayComplete = (x) => {
    if (!isFamilyList(x.listId) || !isKid()) return true;
    const tn = turnOf(x);
    if (tn.turn === 'first') return tn.people.includes(me());
    return !x.assigneeId || x.assigneeId === me();
  };
  /** turn / people / stars of POST / PATCH tasks for task `x` (an older plugin passes them over in silence). */
  function setTurnAndStars(x, b, soft = false) {
    const l = state.lists.get(x.listId);
    if (has('taskTurns') && (b.turn !== undefined || b.people !== undefined)) {
      const turn = b.turn !== undefined ? b.turn : x.turn || null;
      const people = b.people !== undefined ? b.people : x.people || [];
      if (turn !== null && !STAGE4_TURNS.includes(turn)) throw fail(400, 'invalid', { field: 'turn' });
      if (turn) {
        if (!Array.isArray(people) || new Set(people).size < 2) { if (!soft) throw fail(400, 'invalid', { field: 'people' }); } else if (!people.every((u) => l.members.includes(u))) { if (!soft) throw fail(409, 'not_member', { field: 'people' }); } else {
          x.turn = turn;
          x.people = [...new Set(people)];
          if (turn === 'first') x.assigneeId = null;
          else x.assigneeId = x.people.includes(b.assigneeId) ? b.assigneeId : x.people.includes(x.assigneeId) ? x.assigneeId : x.people[0];
        }
      } else { x.turn = null; x.people = []; }
    }
    if (has('taskStars') && b.stars !== undefined) {
      if (!Number.isSafeInteger(b.stars) || b.stars < 0 || b.stars > 10) throw fail(400, 'invalid', { field: 'stars' });
      if (b.stars > 0 && !isFamilyList(x.listId)) { if (!soft) throw fail(400, 'invalid', { field: 'stars', reason: 'family' }); } else if (b.stars > 0 && !isParent()) { if (!soft) throw fail(403, 'forbidden', { reason: 'parents_only' }); } else x.stars = b.stars;
    }
  }
  /** `me.familyTasks` for who asks. */
  const familyTasksView = () => {
    const f = state.family;
    const bound = !!f.listId && famMember(me());
    return { available: f.available, bound, listId: bound ? f.listId : null, parent: isParent(), stars: f.stars, starsMax: f.starsMax, moved: bound && f.moved ? { ...f.moved, seen: !!(f.moved.seenBy || []).includes(me()) } : null };
  };
  const myLists = (a) => [...state.lists.values()].filter((l) => l.members.includes(me()) && (!a || l.area === a));
  // ── plugin 1.4.0: shopping lists ──
  const isoAt = (ms) => `${new Date(Math.floor(ms / 1000) * 1000 + 3600000).toISOString().slice(0, 19)}+01:00`;
  const shopRole = (l) => { const m = l.members.find((x) => x.id === me()); return l.ownerId === me() ? 'owner' : m ? m.role : null; };
  const myShop = () => [...state.shopLists.values()].filter((l) => !l.deletedAt && shopRole(l));
  const shopByNum = (num) => [...state.shopLists.values()].find((l) => l.num === num) || null;
  const shopCounts = (l) => { const its = [...state.shopItems.values()].filter((i) => i.list === l.uid && !i.deleted); return { total: its.length, open: its.filter((i) => !i.checked).length }; };
  const attachView = (l) => { const c = shopCounts(l); return { id: l.num, uid: l.uid, name: l.name, icon: l.icon, open: c.open, total: c.total, done: c.total - c.open, family: l.family }; };
  const attachedOf = (x) => { const l = state.attached.has(x.id) ? shopByNum(state.attached.get(x.id)) : null; return l && !l.deletedAt && shopRole(l) ? attachView(l) : null; };
  const shopListView = (l) => {
    const role = shopRole(l);
    const c = shopCounts(l);
    return {
      id: l.uid, listId: l.num, name: l.name, icon: l.icon, area: l.area, sort: 0, updatedAt: isoAt(l.updatedAt), deleted: false, role,
      canEdit: role !== 'read', canManage: role === 'owner' || (l.family && state.shopFamily.parent), owner: { id: l.ownerId, name: nameOf(l.ownerId) },
      shared: l.members.length > 0 || l.family, members: l.members.map((m) => ({ id: m.id, name: nameOf(m.id), role: m.role })), family: l.family, open: c.open, total: c.total,
      assignee: l.assignee || null, dueAt: null, going: [],
      tasks: [...state.tasks.values()].filter((x) => state.attached.get(x.id) === l.num && !x.doneAt && !x.deleted && !x.parentId).slice(0, 5).map((x) => ({ id: x.id, title: x.title })),
      days: [], remind: null, mydayOff: false, dayToday: false,
    };
  };
  const shopItemView = (i) => ({ id: i.id, listId: i.list, text: i.text, qty: i.qty, checked: i.checked, checkedBy: i.checkedBy, updatedAt: isoAt(i.updatedAt), deleted: i.deleted });
  function shopGet(q) {
    let from = null;
    if (q.since != null && q.since !== '') {
      from = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(String(q.since)) ? Math.floor(Date.parse(q.since) / 1000) * 1000 : NaN;
      if (!Number.isFinite(from)) throw fail(400, 'invalid', { field: 'since' });
    }
    const mine = myShop();
    const lists = mine.map(shopListView);
    const seen = new Set(mine.map((l) => l.uid));
    let items = [...state.shopItems.values()].filter((i) => seen.has(i.list));
    if (from == null) items = items.filter((i) => !i.deleted);
    else {
      items = items.filter((i) => i.updatedAt >= from);
      for (const l of state.shopLists.values()) if (l.deletedAt && l.deletedAt >= from && l.was.includes(me())) lists.push({ id: l.uid, listId: l.num, name: l.name, icon: l.icon, area: l.area, updatedAt: isoAt(l.deletedAt), deleted: true });
    }
    return { lists, items: items.sort((a, b) => a.seq - b.seq).map(shopItemView), serverTime: isoAt(state.now) };
  }
  function shopOp(op, ticked) {
    const rej = (code) => { const e = new Error(code); e.rej = code; return e; };
    const sid = (v) => { if (typeof v !== 'string' || !SHOP_ID_RE.test(v)) throw rej('invalid'); return v; };
    const str = (v, max, required) => { if (v == null || v === '') { if (required) throw rej('invalid'); return null; } if (typeof v !== 'string' || v.trim().length > max || (required && !v.trim())) throw rej('invalid'); return v.trim() || null; };
    const editable = (l) => { if (!l || l.deletedAt || !shopRole(l)) throw rej('not_found'); if (shopRole(l) === 'read') throw rej('forbidden'); return l; };
    const manageable = (l) => { if (!l || l.deletedAt || !shopRole(l)) throw rej('not_found'); if (!(shopRole(l) === 'owner' || (l.family && state.shopFamily.parent))) throw rej('forbidden'); return l; };
    const itemOf = (v) => { const i = state.shopItems.get(sid(v)); if (!i) throw rej('not_found'); editable(state.shopLists.get(i.list)); return i; };
    const o = op && typeof op === 'object' ? op : {};
    if (o.op === 'list_add') {
      const uid = sid(o.id);
      const name = str(o.name, 40, true);
      if (o.icon != null && !LIST_ICONS.includes(o.icon)) throw rej('invalid');
      if (o.family && !state.shopFamily.parent) throw rej('forbidden');
      const have = state.shopLists.get(uid);
      if (have) { if (have.ownerId !== me()) throw rej('forbidden'); return; }
      state.shopLists.set(uid, { uid, num: id(), name, icon: o.icon || 'cart', area: area(o.area), ownerId: me(), members: [], family: !!o.family, deletedAt: null, updatedAt: state.now, was: [me()] });
    } else if (o.op === 'list_rename') {
      const l = manageable(state.shopLists.get(sid(o.id)));
      l.name = str(o.name, 40, true);
      if (o.icon != null) { if (!LIST_ICONS.includes(o.icon)) throw rej('invalid'); l.icon = o.icon; }
      l.updatedAt = state.now;
    } else if (o.op === 'list_delete') {
      const l = state.shopLists.get(sid(o.id));
      if (l && l.deletedAt) return;
      manageable(l);
      l.deletedAt = state.now;
      l.was = [l.ownerId, ...l.members.map((m) => m.id)];
    } else if (o.op === 'item_add') {
      const iid = sid(o.id);
      const l = state.shopLists.get(sid(o.listId));
      const text = str(o.text, 120, true);
      const qty = str(o.qty, 40, false);
      if (state.shopItems.has(iid)) { if (state.shopItems.get(iid).list !== (l && l.uid)) throw rej('forbidden'); return; }
      editable(l);
      state.shopItems.set(iid, { id: iid, list: l.uid, text, qty, checked: false, checkedBy: null, updatedAt: state.now, deleted: false, seq: ++state.shopSeq });
    } else if (o.op === 'item_edit') {
      const i = itemOf(o.id);
      if (i.deleted) throw rej('not_found');
      if (o.text !== undefined) i.text = str(o.text, 120, true);
      if (o.qty !== undefined) i.qty = str(o.qty, 40, false);
      i.updatedAt = state.now;
    } else if (o.op === 'item_check') {
      const i = itemOf(o.id);
      if (i.deleted) throw rej('not_found');
      if (typeof o.checked !== 'boolean') throw rej('invalid');
      if (i.checked === o.checked) return;
      i.checked = o.checked;
      i.checkedBy = o.checked ? me() : null;
      i.updatedAt = state.now;
      if (o.checked) ticked.add(i.list);
    } else if (o.op === 'item_delete') {
      const i = itemOf(o.id);
      if (i.deleted) return;
      i.deleted = true;
      i.updatedAt = state.now;
    } else if (o.op === 'clear_checked') {
      const l = editable(state.shopLists.get(sid(o.listId)));
      for (const i of state.shopItems.values()) if (i.list === l.uid && i.checked && !i.deleted) { i.deleted = true; i.updatedAt = state.now; }
    } else throw rej('invalid');
  }
  function shopOps(b) {
    if (!Array.isArray(b.ops) || b.ops.length > 200) throw fail(400, 'invalid', { field: 'ops' });
    const ticked = new Set();
    const rejected = [];
    let applied = 0;
    b.ops.forEach((op, index) => {
      try { shopOp(op, ticked); applied++; } catch (e) { if (!e.rej) throw e; rejected.push({ index, code: e.rej }); }
    });
    // „alles abgehakt“: a tick happened and the list is ticked off completely at the end of the batch
    const completed = [];
    for (const uid of ticked) {
      const l = state.shopLists.get(uid);
      const c = shopCounts(l);
      if (!c.total || c.open || !has('taskList')) continue;
      for (const x of state.tasks.values()) {
        if (state.attached.get(x.id) !== l.num || x.doneAt || x.deleted || x.parentId) continue;
        x.doneAt = state.now;
        x.updatedAt = state.now;
        completed.push({ taskId: x.id, title: x.title, listId: l.uid });
      }
    }
    return { applied, rejected, serverTime: isoAt(state.now), completed };
  }
  /** attachedListId / attachedListUid of a task's body → the list's number, null (taken off) or undefined (not named). */
  function attachArg(b) {
    if (!has('taskList') || (b.attachedListId === undefined && b.attachedListUid === undefined)) return undefined;
    if (b.attachedListId === null || (b.attachedListId === undefined && b.attachedListUid === null)) return null;
    const l = b.attachedListId !== undefined ? shopByNum(posInt(b.attachedListId)) : state.shopLists.get(b.attachedListUid);
    if (!l || l.deletedAt || !shopRole(l)) {
      if (b.attachedListId !== undefined && state.lists.has(posInt(b.attachedListId))) throw fail(400, 'invalid', { field: 'attachedListId', reason: 'kind' });
      throw fail(404, 'not_found', { field: 'attachedListId' });
    }
    return l.num;
  }
  /** The shopping list a line of the quick entry names → { via, word?, list, lists } | null (the plugin's fixed table). */
  function suggest(text, parsed, a) {
    const rows = myShop().filter((l) => l.area === a);
    if (!rows.length || typeof text !== 'string') return null;
    const lower = (s) => String(s || '').normalize('NFKC').toLowerCase();
    const tokens = (s) => lower(s).split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    let via = null;
    let word = null;
    let cands = [];
    const tag = parsed && !parsed.list && parsed.listName ? lower(parsed.listName) : null;
    if (tag) { cands = rows.filter((l) => lower(l.name).startsWith(tag)); if (cands.length) via = 'tag'; }
    const toks = tokens(text);
    if (!via) {
      const hay = ` ${toks.join(' ')} `;
      cands = rows.filter((l) => { const nm = tokens(l.name).join(' '); return nm.length >= 3 && hay.includes(` ${nm} `); });
      if (cands.length) via = 'name';
    }
    if (!via) {
      word = SHOP_WORDS.find((w) => toks.includes(w)) || null;
      if (word) {
        cands = rows.filter((l) => /^(?:einkauf|lebensmittel|shopping|grocer)/.test(lower(l.name)) || l.icon === 'cart');
        if (!cands.length) cands = rows;
        via = 'word';
      }
    }
    if (!via || !cands.length) return null;
    const out = cands.map(attachView);
    return { via, ...(via === 'word' ? { word } : {}), list: out.length === 1 ? out[0] : null, lists: out };
  }

  // ── 1.5.0: places ──────────────────────────────────────────
  const KIND_LABEL = { 'kind:diy': 'Baumarkt', 'kind:bakery': 'Bäcker', 'kind:pharmacy': 'Apotheke', 'kind:fuel': 'Tankstelle', 'kind:supermarket': 'Supermarkt' };
  const KIND_WORDS = { baumarkt: 'kind:diy', 'bäcker': 'kind:bakery', 'bäckerei': 'kind:bakery', apotheke: 'kind:pharmacy', tankstelle: 'kind:fuel', supermarkt: 'kind:supermarket' };
  const POI = {
    'kind:diy': [{ ref: 'osm:W101', name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424 }, { ref: 'osm:W102', name: 'Baumarkt am Ring', address: 'Ringstraße 21, Berlin', lat: 52.501, lon: 13.362 },
      { ref: 'osm:W103', name: 'Baumarkt Süd', address: 'Am Hafen 2, Berlin', lat: 52.455, lon: 13.47 }],
    'name:lidl': [{ ref: 'osm:N201', name: 'Lidl Marktstraße', address: 'Marktstraße 3, Berlin', lat: 52.526, lon: 13.401 }, { ref: 'osm:N202', name: 'Lidl Bahnhofsplatz', address: 'Bahnhofsplatz 1, Berlin', lat: 52.511, lon: 13.435 }],
    'kind:bakery': [{ ref: 'osm:N301', name: 'Bäckerei am Markt', address: 'Marktplatz 1, Berlin', lat: 52.522, lon: 13.412 }],
  };
  const ADDRESSES = [{ ref: 'osm:W900', name: 'Ringstraße 21', address: 'Ringstraße 21, 10115 Berlin', lat: 52.5012, lon: 13.3621 }, { ref: 'osm:W901', name: 'Gartenweg 5', address: 'Gartenweg 5, 12345 Musterstadt', lat: 52.4, lon: 13.2 }];
  const ATTRIBUTION = { text: '© OpenStreetMap', url: 'https://www.openstreetmap.org/copyright' };
  const KEY_RE = /^(?:kind:[a-z]{2,20}|name:[^\u0000-\u001f\u007f]{2,40})$/;
  const OSM_RE = /^osm:[NWR]\d{1,18}$/;
  const ADDRESS_RE = /(?:^|\s)(\p{Lu}[\p{L}.-]*(?:straße|str\.|weg|platz|allee|gasse)\s+\d+[a-z]?)(?=$|[\s,.])/u;
  const validKey = (k) => typeof k === 'string' && KEY_RE.test(k) && (!k.startsWith('kind:') || !!KIND_LABEL[k]);
  const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);
  const labelOf = (key, as) => (key.startsWith('kind:') ? KIND_LABEL[key] : as || cap(key.slice(5)));
  const famPlaces = () => (has('places') ? state.familyPlaces : []);
  const myPlaces = () => [...state.places.values()].filter((r) => r.userId === me() && !r.deleted);
  const favsOf = () => [...state.picks.values()].filter((k) => k.fav && myPlaces().some((r) => r.id === k.placeId));
  // 1.8.0 (profilePlaces): a named place is one of the profile — its ref, symbol, who sees it and „Genutzt von“
  const profiled = (r) => has('profilePlaces') && r.named && !(r.ref && r.ref.startsWith('familie:'));
  const placeView = (r, extra = {}) => ({ id: r.id, name: r.name, address: r.address || '', lat: r.lat, lon: r.lon, radius: r.radius, named: !!r.named,
    ref: profiled(r) ? `profile:${r.id}` : (r.ref || null), family: !!(r.ref && r.ref.startsWith('familie:')),
    ...(profiled(r) ? { icon: r.icon || 'pin', visibility: r.visibility || 'self', usedBy: state.placeUses.get(r.id) || [] } : {}),
    ...(extra.favFor ? { favFor: extra.favFor } : {}), ...(extra.uses != null ? { uses: extra.uses } : {}), updatedAt: r.updatedAt });
  const minePlace = (pid) => { const r = state.places.get(posInt(pid)); if (!r || r.deleted || r.userId !== me()) throw fail(404, 'not_found', { field: 'place' }); return r; };
  const clampRadius = (v) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(50, Math.min(2000, n)) : 150; };
  const coord = (v, max, field) => { if (typeof v !== 'number' || !Number.isFinite(v) || Math.abs(v) > max) throw fail(400, 'invalid', { field }); return Math.round(v * 1e6) / 1e6; };
  const searchState = () => (state.placeCfg.mode === 'off' || (state.prefs.places && state.prefs.places.search === false) ? 'off' : state.placeCfg.mode === 'own' && state.placeCfg.down ? 'unavailable' : 'on');
  const placesAll = () => {
    const favs = favsOf();
    const favFor = (pid) => favs.filter((k) => k.placeId === pid).map((k) => ({ key: k.key, label: labelOf(k.key) }));
    return {
      places: myPlaces().filter((r) => r.named || favFor(r.id).length).sort((x, y) => (y.named - x.named) || x.name.localeCompare(y.name)).map((r) => placeView(r, { favFor: favFor(r.id) })),
      family: famPlaces().map((f) => ({ familyId: f.id, name: f.name, lat: f.lat, lon: f.lon, radius: f.radius })),
      favs: favs.map((k) => ({ key: k.key, label: labelOf(k.key), placeId: k.placeId, uses: k.uses })),
      ...(has('profilePlaces') ? { profile: true, notMoved: state.notMoved } : {}),
    };
  };
  /** The person's row for a place taken once (a search hit, a point, a place of the family) — found again by its ref. */
  function upsertPlace(f) {
    const have = f.ref ? myPlaces().find((r) => r.ref === f.ref) : null;
    if (have) return have.id;
    const r = { id: id(), userId: me(), name: f.name, address: f.address || '', lat: f.lat, lon: f.lon, radius: f.radius, named: !!f.named, ref: f.ref || null, deleted: false, updatedAt: state.now };
    state.places.set(r.id, r);
    return r.id;
  }
  const chosenFor = (key) => [...state.picks.values()].filter((k) => k.key === key && myPlaces().some((r) => r.id === k.placeId)).sort((x, y) => (y.fav - x.fav) || (y.uses - x.uses));
  /** Task.place of a task → the object or null. */
  function taskPlaceView(x) {
    const j = state.taskPlace.get(x.id);
    if (!j || x.parentId) return null;
    const r = j.placeId ? state.places.get(j.placeId) : null;
    if (!j.any && !r) return null;
    const label = j.key ? labelOf(j.key, j.label) : null;
    return {
      mode: j.any ? 'any' : 'place', id: r ? r.id : null, name: r ? r.name : `Jeder ${label}`, address: r ? r.address || '' : '', lat: r ? r.lat : null, lon: r ? r.lon : null, radius: r ? r.radius : null,
      ref: r ? r.ref || null : null, own: !!(r && r.named && r.userId === me()), trigger: j.trigger === 'exit' ? 'exit' : 'enter', key: j.key || null, label, by: j.by || null,
      consent: j.consent || 'accepted', watch: j.who === me() && (j.consent || 'accepted') === 'accepted', nearby: !!j.key && j.trigger !== 'exit' && !j.any, skipped: 0, later: null,
      // 1.6.0: whose phone is to watch the place, and who may accept or decline it (everybody else gets 403)
      ...(has('placeMine') ? { mine: j.who === me(), canConsent: j.who === me() } : {}),
    };
  }
  /** `place` of POST / PATCH tasks for task `x` (the plugin's places.argFor): written into state.taskPlace. */
  function setTaskPlace(x, v) {
    const was = state.taskPlace.get(x.id) || null;
    if (v === null) { state.taskPlace.delete(x.id); return; }
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw fail(400, 'invalid', { field: 'place' });
    const trigger = v.trigger !== undefined ? v.trigger : (was ? was.trigger : 'enter');
    if (!['enter', 'exit'].includes(trigger)) throw fail(400, 'invalid', { field: 'place.trigger' });
    let key = was ? was.key || null : null;
    if (v.key !== undefined) { if (v.key !== null && !validKey(v.key)) throw fail(400, 'invalid', { field: 'place.key' }); key = v.key; }
    let placeId = was ? was.placeId || null : null;
    let any = !!(was && was.any);
    if (v.any === true) {
      if (!key) throw fail(400, 'invalid', { field: 'place.key' });
      placeId = null; any = true;
    } else if (v.placeId != null) { placeId = minePlace(v.placeId).id; any = false; } else if (v.familyId != null) {
      const f = famPlaces().find((q) => q.id === v.familyId);
      if (!f) throw fail(404, 'not_found', { field: 'place' });
      placeId = upsertPlace({ ref: `familie:${f.id}`, name: f.name, address: '', lat: f.lat, lon: f.lon, radius: f.radius });
      any = false;
    } else if (v.lat !== undefined || v.lon !== undefined) {
      if (typeof v.name !== 'string' || !v.name.trim()) throw fail(400, 'invalid', { field: 'place.name' });
      if (v.ref != null && (typeof v.ref !== 'string' || !OSM_RE.test(v.ref))) throw fail(400, 'invalid', { field: 'place.ref' });
      placeId = upsertPlace({ ref: v.ref || null, name: v.name.trim().slice(0, 80), address: v.address || '', lat: coord(v.lat, 90, 'place.lat'), lon: coord(v.lon, 180, 'place.lon'), radius: v.radius === undefined ? 150 : clampRadius(v.radius) });
      any = false;
    } else if (!was) throw fail(400, 'invalid', { field: 'place' });
    if (v.remember === true && (!key || !placeId)) throw fail(400, 'invalid', { field: 'place.remember' });
    const fresh = !was || (was.placeId || null) !== placeId || !!was.any !== any;
    const who = x.assigneeId || x.by || 1;
    // another place asks anew; only the trigger changes nothing
    const consent = fresh ? (who === me() ? 'accepted' : 'pending') : was.consent;
    state.taskPlace.set(x.id, { placeId, key, label: key ? labelOf(key, typeof v.label === 'string' ? v.label.slice(0, 40) : was && was.key === key ? was.label : null) : null, any, trigger, by: fresh ? me() : was.by, who, consent });
    if (key && placeId) {
      const pk = `${key}|${placeId}`;
      const k = state.picks.get(pk) || { key, placeId, uses: 0, fav: false };
      if (fresh) k.uses++;
      if (v.remember === true) { for (const o of state.picks.values()) if (o.key === key) o.fav = false; k.fav = true; }
      state.picks.set(pk, k);
    }
  }
  /** The place a line names (the plugin's placewords.detect, a small part of it) → the suggestion or null. */
  function placeSuggest(title) {
    const s2 = String(title || '');
    if (!has('places') || !s2.trim()) return null;
    const PREP = '(?:beim|bei|im|in der|an der|am|zum|zur|zu)';
    const escRe = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const find = (re) => { const m = re.exec(s2); if (!m) return null; const from = m.index + m[0].indexOf(m[1]); return { m, from, to: from + m[1].length, word: m[1] }; };
    const without = (h) => { const rest = `${s2.slice(0, h.from)} ${s2.slice(h.to)}`.replace(/\s+/g, ' ').trim(); return rest.split(' ').length >= 2 ? rest : s2.trim(); };
    const out = (h, o) => ({ via: o.via, word: h.word, query: o.query, key: o.key || null, label: o.label, title: without(h), certain: o.certain, trigger: 'enter', place: o.place || null, uses: o.uses || 0, options: o.options || [], search: searchState() });
    for (const r of myPlaces().filter((q) => q.named)) {
      const h = find(new RegExp(`(?:^|\\s)(${PREP}\\s+${escRe(r.name)})(?=$|[\\s,.])`, 'iu'));
      if (h) return out(h, { via: 'own', query: r.name, label: r.name, certain: true, place: placeView(r) });
    }
    const home = famPlaces().find((f) => f.id === 'home');
    const hh = home ? find(/(?:^|\s)(zu hause|zuhause|daheim|at home)(?=$|[\s,.])/iu) : null;
    if (hh) return out(hh, { via: 'family', query: home.name, label: home.name, certain: true, place: { familyId: home.id, name: home.name, address: '', lat: home.lat, lon: home.lon, radius: home.radius, family: true } });
    const ha = find(ADDRESS_RE);
    if (ha) return out(ha, { via: 'address', query: ha.word, label: ha.word, certain: true });
    const decided = (key) => { const list = chosenFor(key); const options = list.map((k) => placeView(state.places.get(k.placeId), { uses: k.uses })); return list.length && list[0].fav ? { options, place: options[0], uses: list[0].uses } : { options }; };
    const hk = find(new RegExp(`(?:^|\\s)((?:(${PREP}|an der|in der)\\s+)?(${Object.keys(KIND_WORDS).join('|')}))(?=$|[\\s,.])`, 'iu'));
    if (hk) { const key = KIND_WORDS[hk.m[3].toLowerCase()]; return out(hk, { via: 'kind', query: KIND_LABEL[key], key, label: KIND_LABEL[key], certain: !!hk.m[2], ...decided(key) }); }
    const hn = find(new RegExp(`(?:^|\\s)((${PREP})\\s+(\\p{Lu}[\\p{L}\\d-]+))(?=$|[\\s,.])`, 'u'));
    if (hn) { const key = `name:${hn.m[3].toLowerCase()}`; return out(hn, { via: 'name', query: cap(hn.m[3]), key, label: cap(hn.m[3]), certain: /^bei/i.test(hn.m[2]), ...decided(key) }); }
    return null;
  }
  const metres = (a, b) => { const rad = Math.PI / 180; const x = (b.lon - a.lon) * rad * Math.cos(((a.lat + b.lat) / 2) * rad); const y = (b.lat - a.lat) * rad; return Math.round(Math.sqrt(x * x + y * y) * 6371000); };
  /** POST places/search (the plugin's places.find over a fixed catalogue). */
  function placeSearch(b) {
    state.placeSearches.push(b);
    const st = searchState();
    if (st === 'off') throw fail(403, 'module_off', { reason: state.placeCfg.mode === 'off' ? 'admin' : 'self' });
    if (st !== 'on' || state.placeCfg.down) throw fail(503, 'unavailable', { reason: 'service' });
    let key = null;
    let address = null;
    if (b.key != null) { if (!validKey(b.key)) throw fail(400, 'invalid', { field: 'key' }); key = b.key; } else {
      const q = typeof b.q === 'string' ? b.q.trim().slice(0, 80) : '';
      if (q.length < 2) throw fail(400, 'invalid', { field: 'q' });
      if (b.address === true || ADDRESS_RE.test(q)) address = q;
      else key = KIND_WORDS[q.toLowerCase()] || `name:${q.toLowerCase()}`;
    }
    let near = b.near;
    if (b.nearPlaceId != null) { const pl = minePlace(b.nearPlaceId); near = { lat: pl.lat, lon: pl.lon }; } else if (b.nearFamilyId != null) {
      const f = famPlaces().find((q) => q.id === b.nearFamilyId);
      if (!f) throw fail(404, 'not_found', { field: 'near' });
      near = { lat: f.lat, lon: f.lon };
    }
    const cell = near && typeof near.lat === 'number' && typeof near.lon === 'number' ? { lat: Math.round(near.lat * 100) / 100, lon: Math.round(near.lon * 100) / 100 } : null;
    if (!cell && !(address && near == null)) throw fail(400, 'invalid', { field: 'near' });
    const hits = address ? ADDRESSES.filter((x) => x.address.toLowerCase().includes(address.toLowerCase().split(',')[0])) : POI[key] || [];
    const before = key ? chosenFor(key) : [];
    const results = hits.map((h) => {
      const c = before.find((k) => state.places.get(k.placeId).ref === h.ref) || null;
      const dist = cell ? metres(cell, h) : null;
      return { ref: h.ref, name: h.name, address: h.address, lat: h.lat, lon: h.lon, distanceM: dist, minutes: dist == null ? null : Math.max(1, Math.round((dist * 1.3) / 500)), placeId: c ? c.placeId : null, fav: !!(c && c.fav), uses: c ? c.uses : 0 };
    });
    results.sort((x, y) => (y.fav - x.fav) || ((y.uses > 0) - (x.uses > 0)) || (x.distanceM - y.distanceM));
    return { key, label: key ? labelOf(key, typeof b.label === 'string' ? b.label : typeof b.q === 'string' ? b.q.trim() : null) : address, kind: address ? 'address' : key.startsWith('kind:') ? 'kind' : 'name', radiusKm: 15, cell,
      results: results.slice(0, 10), any: !!key && results.length > 0, approx: true, attribution: ATTRIBUTION };
  }

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
      source: x.source, noteId: x.noteId, position: x.position, canComplete: true, canEdit: true, updatedAt: x.updatedAt,
    };
    if (has('reminderActions')) {
      const atMs = x.remindAt ? Date.parse(x.remindAt) : NaN;
      v.reminder = !x.doneAt && atMs > state.now ? { tag: `task:${x.id}:${atMs}`, at: x.remindAt, atMs, mine: true, snoozed: state.snoozed.has(x.id) } : null;
      v.snoozed = !!v.reminder && state.snoozed.has(x.id);
      v.missedReminder = state.missed.has(x.id);
    }
    if (has('taskList')) v.attachedList = x.parentId ? null : attachedOf(x);
    if (has('places')) v.place = taskPlaceView(x);
    if (has('taskTurns')) {
      const tn = turnOf(x);
      v.turn = tn.turn;
      v.people = tn.people.map(person);
      if (tn.turn === 'first') v.assignee = null;
    }
    if (has('taskStars')) v.stars = isFamilyList(x.listId) && state.family.stars ? x.stars || 0 : 0;
    if (has('familyTasks')) {
      v.family = isFamilyList(x.listId);
      v.doneBy = x.doneAt && x.doneBy ? person(x.doneBy) : null;
      v.canEdit = mayEdit(x);
      v.canComplete = mayComplete(x);
    }
    // 1.2.0: a member who only reads changes nothing and ticks off only what is assigned to them
    if (readOnly(x.listId)) { v.canEdit = false; v.canComplete = x.assigneeId === me(); }
    // 1.7.0: the deadline of a file in Drive this task reminds of
    if (has('driveDeadlines')) v.deadline = x.deadline || null;
    if (has('taskCalendar')) {
      const c = state.calendar;
      v.calendar = c.available && c.enabled && c.mine && x.due && x.due.time && !x.doneAt ? { state: 'synced', eventId: 900 + x.id, calendarId: 7, mine: true } : null;
    }
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

  // „Gestern offen geblieben“: open tasks due yesterday, in „Mein Tag“ yesterday, or whose reminder was lost
  const weekend = () => { let d = addDays(state.today, 1); while (R.weekday(d) !== (R.weekday(state.today) === 6 ? 7 : 6)) d = addDays(d, 1); return d; };
  const yesterdayTasks = (a) => openTasks(a).filter((x) => !x.doneAt && ((x.due && x.due.date === addDays(state.today, -1)) || state.yesterdayDay.has(x.id) || state.missed.has(x.id)));
  function yesterdayView(a) {
    const items = yesterdayTasks(a).map((r) => taskView(r)).sort(byTime);
    return {
      day: addDays(state.today, -1), title: 'Gestern offen geblieben', count: items.length, items,
      moveOptions: [{ to: 'tomorrow', date: addDays(state.today, 1), label: 'Morgen' }, { to: 'weekend', date: weekend(), label: 'Am Wochenende' }],
    };
  }
  function moveTask(r, to) {
    const date = to === 'today' ? state.today : to === 'tomorrow' ? addDays(state.today, 1) : to === 'weekend' ? weekend() : to;
    if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) || date < state.today) throw fail(400, 'invalid', { field: 'to' });
    if (r.due && r.due.date <= state.today) r.due = { date, time: r.due.time };
    else if (to === 'today') state.myDay.add(r.id);
    else r.due = { date, time: r.due ? r.due.time : null };
    state.yesterdayDay.delete(r.id);
    state.missed.delete(r.id);
    r.updatedAt = state.now;
    return r;
  }

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
    return { view: 'myday', title: t('v.myday'), date: state.today, ...(has('yesterdayOpen') ? { yesterday: yesterdayView(a) } : {}), sections: [section('events', out.events), section('overdue', out.overdue), section('today', out.today), section('upcoming', out.upcoming), section('done', out.done, { collapsed: true })] };
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
      id: b.id, name: v ? null : b.name, area: b.area, color: b.color, isDefault: b.isDefault, role: b.ownerId === me() ? 'owner' : 'write', canEdit: true,
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

  /** ui/turnwords.js on what the parser read, for a line typed in list `listId` (stars only in the family's list, by a parent). */
  function turnWords(parsed, listId) {
    const w = TW.apply(parsed, { people: state.people.map((q) => ({ id: q.id, name: q.name })), stars: has('taskStars') && isFamilyList(listId) && isParent() && state.family.stars });
    return { title: w.title, people: has('taskTurns') ? w.people : [], turn: has('taskTurns') ? w.turn : null, stars: w.stars };
  }

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
    // 1.6.0: several people, „reihum“ / „wer zuerst“ and stars of the typed line (ui/turnwords.js, after the parser)
    let words = null;
    if (parsed && (has('taskTurns') || has('taskStars'))) {
      words = turnWords(parsed, listId || (myLists(a).find((l) => l.isDefault) || {}).id);
      title = words.title || title;
      parsed = { ...parsed, title: words.title, people: words.people, turn: words.turn, stars: words.stars };
    }
    if (!title || typeof title !== 'string') throw fail(400, 'invalid', { field: 'title' });
    if (b.parentId) { const p = accessTask(b.parentId); listId = p.listId; }
    if (!listId) listId = myLists(a).find((l) => l.isDefault).id;
    if (readOnly(listId)) throw fail(403, 'forbidden', { reason: 'read_only' });
    if (!state.lists.has(listId)) throw fail(404, 'not_found');
    // 1.4.0: a list to carry — named, or (attach: 'auto') the one the line names when exactly one fits; never by itself
    let attach = null;
    let carry = b.parentId ? undefined : attachArg(b);
    if (carry === undefined && has('taskList') && b.attach === 'auto' && typeof b.text === 'string' && !b.parentId) {
      attach = suggest(b.text, parsed, a);
      if (attach && attach.list) carry = attach.list.id;
    }
    // 1.5.0: the place — named, or (place: 'auto') the one the line names when it is decided and surely meant; never by
    // itself. With a place the words of the place leave the title. An older plugin passes the field over in silence
    let place = null;
    let placeArg;
    if (has('places') && b.place !== undefined && !b.parentId) {
      place = typeof b.text === 'string' ? placeSuggest(title) : null;
      if (b.place === 'auto') placeArg = place && place.place && place.certain ? (place.place.familyId ? { familyId: place.place.familyId, trigger: place.trigger } : { placeId: place.place.id, key: place.key || undefined, trigger: place.trigger }) : undefined;
      else placeArg = b.place;
      if (placeArg !== undefined && placeArg !== null && place) title = place.title;
    }
    if (b.parentId && !mayEdit(accessTask(b.parentId))) throw fail(403, 'forbidden', { reason: 'parents_only' });
    const x = task({ id: id(), listId, parentId: posInt(b.parentId), title: title.slice(0, 300), note: b.note || '', ...fields, by: me(), updatedAt: state.now });
    try {
      // what the line says and does not fit (somebody is no member of the list, stars without the right) is dropped in
      // silence; what the body names itself is refused
      if (words && !b.parentId) setTurnAndStars(x, { ...(words.turn ? { turn: words.turn, people: words.people.map((q) => q.id) } : {}), ...(words.stars ? { stars: words.stars } : {}) }, true);
      if (!b.parentId) setTurnAndStars(x, { turn: b.turn, people: b.people, stars: b.stars, assigneeId: b.assigneeId });
    } catch (err) { state.tasks.delete(x.id); throw err; }
    if (placeArg !== undefined && placeArg !== null) { try { setTaskPlace(x, placeArg); } catch (err) { state.tasks.delete(x.id); throw err; } }
    if (b.myDay) state.myDay.add(x.id);
    if (carry) state.attached.set(x.id, carry);
    return { task: taskView(x, true), ...(parsed ? { parsed } : {}), ...(attach ? { attach } : {}), ...(place ? { place } : {}) };
  }

  function route(method, p, q, b) {
    const parts = p.split('/').map(decodeURIComponent);
    const [a, x, y, z, w] = parts;
    const n = parts.length;
    const is = (m, len, first) => method === m && n === len && a === first;
    if (!state.allowed) throw fail(403, 'forbidden');
    if (is('GET', 1, 'me')) {
      return { user: state.user, lang: 'de', today: state.today, time: state.time, timezone: 'Europe/Berlin', features: state.features, prefs: state.prefs, sharing: 'all', vaults: state.vaultsOn, imports: state.imports, attachMB: 25, readOnly: false,
        ...(has('taskCalendar') ? { calendar: state.calendar } : {}), ...(has('yesterdayOpen') ? { yesterday: state.yesterdayPrefs } : {}),
        ...(has('shoppingLists') ? { listIcons: LIST_ICONS, shopping: { family: has('familyShopping') ? state.shopFamily : { available: false, bound: false, parent: false } } } : {}),
        ...(has('places') ? { places: {
          search: { state: searchState(), enabled: state.placeCfg.mode !== 'off', mine: state.prefs.places.search !== false, service: state.placeCfg.mode, radiusKm: 15, decimals: 2, attribution: ATTRIBUTION },
          nearby: state.prefs.places.nearby !== false, quiet: state.prefs.places.quiet || null, perTask: 5, radius: { min: 50, max: 2000, default: 150 }, family: state.familyPlaces.length > 0,
          ...(has('profilePlaces') ? { profile: { places: true, edit: 'plugin' } } : {}),
        } } : {}),
        ...(has('familyTasks') ? { familyTasks: familyTasksView() } : {}),
        ...(has('driveDeadlines') ? { driveDeadlines: { available: true, active: [...state.tasks.values()].some((r) => r.deadline && !r.deleted) } } : {}),
      };
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
        ...(has('shoppingLists') ? { shopping: myShop().filter((l) => l.area === ar).map((l) => { const c = shopCounts(l); return { id: l.uid, listId: l.num, name: l.name, icon: l.icon, open: c.open, total: c.total, family: l.family, shared: l.members.length > 0 || l.family, role: shopRole(l) }; }) } : {}),
        notes: notesNav(ar),
      };
    }
    if (method === 'GET' && n === 2 && a === 'views') return view(x, area(q.area));
    if (is('POST', 1, 'parse')) {
      let parsed = Q.parse(String(b.text || ''), { today: state.today, now: state.time, lists: myLists(area(b.area)).map((l) => ({ id: l.id, name: l.name })), people: state.people });
      // 1.6.0: `listId` — the list the line is typed in (or the one it names with #): only there stars are read
      if (has('taskTurns') || has('taskStars')) { const w = turnWords(parsed, parsed.list ? parsed.list.id : posInt(b.listId)); parsed = { ...parsed, title: w.title, people: w.people, turn: w.turn, stars: w.stars }; }
      return { parsed, ...(has('taskList') ? { attach: suggest(b.text, parsed, area(b.area)) } : {}), ...(has('places') ? { place: placeSuggest(parsed.title) } : {}) };
    }
    // 1.5.0: places (an older plugin has none of these routes). What a phone watches and what fired is not here
    if (has('places')) {
      if (is('GET', 1, 'places')) return placesAll();
      if (is('POST', 1, 'places')) {
        if (typeof b.name !== 'string' || !b.name.trim()) throw fail(400, 'invalid', { field: 'name' });
        if (b.ref != null && (typeof b.ref !== 'string' || !OSM_RE.test(b.ref))) throw fail(400, 'invalid', { field: 'ref' });
        if (myPlaces().length >= 100) throw fail(409, 'too_many');
        const f = { name: b.name.trim().slice(0, 80), address: b.address || '', lat: coord(b.lat, 90, 'lat'), lon: coord(b.lon, 180, 'lon'), radius: b.radius === undefined ? 150 : clampRadius(b.radius), ref: b.ref || null, named: true };
        const r = state.places.get(upsertPlace(f));
        Object.assign(r, { name: f.name, named: true, updatedAt: state.now });
        if (has('profilePlaces')) Object.assign(r, { icon: b.icon || 'pin', visibility: b.visibility || 'self' });
        return { place: placeView(r, { favFor: [] }) };
      }
      if (method === 'PUT' && n === 2 && a === 'places' && x === 'favs') {
        if (!validKey(b.key)) throw fail(400, 'invalid', { field: 'key' });
        const pl = b.placeId == null ? null : minePlace(b.placeId);
        for (const k of state.picks.values()) if (k.key === b.key) k.fav = false;
        if (pl) { const pk = `${b.key}|${pl.id}`; state.picks.set(pk, { ...(state.picks.get(pk) || { key: b.key, placeId: pl.id, uses: 0 }), fav: true }); }
        return { favs: placesAll().favs };
      }
      if (method === 'POST' && n === 2 && a === 'places' && x === 'search' && has('placeSearch')) return placeSearch(b);
      if (method === 'PATCH' && n === 2 && a === 'places') {
        const r = minePlace(x);
        if (b.name !== undefined) { if (typeof b.name !== 'string' || !b.name.trim()) throw fail(400, 'invalid', { field: 'name' }); r.name = b.name.trim().slice(0, 80); }
        if (b.address !== undefined) r.address = String(b.address || '');
        if (b.lat !== undefined) r.lat = coord(b.lat, 90, 'lat');
        if (b.lon !== undefined) r.lon = coord(b.lon, 180, 'lon');
        if (b.radius !== undefined) r.radius = clampRadius(b.radius);
        if (b.named !== undefined) r.named = !!b.named;
        if (has('profilePlaces') && b.icon !== undefined) r.icon = b.icon;
        if (has('profilePlaces') && b.visibility !== undefined) r.visibility = b.visibility;
        r.updatedAt = state.now;
        return { place: placeView(r, { favFor: placesAll().favs.filter((k) => k.placeId === r.id).map((k) => ({ key: k.key, label: k.label })) }) };
      }
      if (method === 'DELETE' && n === 2 && a === 'places') {
        const r = state.places.get(posInt(x));
        if (r && r.userId === me() && r.deleted) return { gone: true };
        const mine = minePlace(x);
        // 1.8.0: another plugin still uses the place of the profile → 409 in_use, ?force=1 deletes it all the same
        if (has('profilePlaces') && (state.placeUses.get(mine.id) || []).length && q.force !== '1') throw fail(409, 'in_use', { usedBy: state.placeUses.get(mine.id), ref: `profile:${mine.id}` });
        mine.deleted = true;
        return {};
      }
      if (method === 'POST' && n === 4 && a === 'tasks' && y === 'place' && z === 'consent') {
        const r = accessTask(x);
        const j = state.taskPlace.get(r.id);
        if (!j) throw fail(400, 'invalid', { field: 'place' });
        if (j.who !== me()) throw fail(403, 'forbidden');
        j.consent = b.accept === false ? 'declined' : 'accepted';
        return { consent: j.consent };
      }
    }
    // 1.4.0: the shopping lists (an older plugin has none of these routes)
    if (has('shoppingLists')) {
      if (is('GET', 1, 'shopping')) return shopGet(q);
      if (method === 'POST' && n === 2 && a === 'shopping' && x === 'ops') return shopOps(b);
      if (n === 4 && a === 'shopping' && x === 'lists' && ['family', 'going', 'assign'].includes(z)) {
        const l = state.shopLists.get(y);
        if (!has('familyShopping') || !state.shopFamily.available) throw fail(409, 'unavailable');
        if (!l || l.deletedAt || !shopRole(l)) throw fail(404, 'not_found');
        if (method === 'PUT' && z === 'family') {
          if (b.on && !state.shopFamily.parent) throw fail(403, 'forbidden');
          l.family = !!b.on;
          l.updatedAt = state.now;
          return { list: shopListView(l) };
        }
        if (!l.family) throw fail(400, 'invalid', { field: 'family' });
        if (method === 'POST' && z === 'going') { state.going.push(l.uid); return { notified: 2, chat: true }; }
        if (method === 'POST' && z === 'assign') {
          if (b.userId !== null && !state.people.some((pp) => pp.id === b.userId)) throw fail(400, 'invalid', { field: 'userId' });
          l.assignee = b.userId ? { userId: b.userId, by: me(), at: isoAt(state.now), state: 'open', notify: b.notify || 'direct' } : null;
          state.assigned.push({ list: l.uid, userId: b.userId });
          return { list: shopListView(l), notified: b.userId ? 1 : 0 };
        }
      }
      // a shopping list through the list routes (its number): rename, share, delete (the owner) or leave (a member)
      const sl = a === 'lists' && n >= 2 ? shopByNum(posInt(x)) : null;
      if (sl && method === 'POST' && n === 3 && y === 'restore') {
        if (!sl.deletedAt || sl.ownerId !== me()) throw fail(404, 'not_found');
        sl.deletedAt = null;
        sl.updatedAt = state.now;
        return { list: { id: sl.num, name: sl.name, area: sl.area, icon: sl.icon } };
      }
      if (sl && !sl.deletedAt && shopRole(sl)) {
        if (method === 'PATCH' && n === 2) { if (b.name !== undefined) sl.name = String(b.name).slice(0, 40); if (b.icon !== undefined) sl.icon = b.icon; sl.updatedAt = state.now; return { list: { id: sl.num, name: sl.name, area: sl.area, icon: sl.icon } }; }
        if (method === 'PUT' && n === 3 && y === 'members') {
          sl.members = (b.members || []).map((m) => (m && typeof m === 'object' ? { id: m.id, role: m.role === 'read' ? 'read' : 'write' } : { id: m, role: 'write' })).filter((m) => m.id !== sl.ownerId);
          sl.updatedAt = state.now;
          return { list: { id: sl.num, name: sl.name, area: sl.area, icon: sl.icon } };
        }
        if (method === 'DELETE' && n === 2) {
          if (shopRole(sl) === 'owner') { sl.deletedAt = state.now; sl.was = [sl.ownerId, ...sl.members.map((m) => m.id)]; return {}; }
          sl.members = sl.members.filter((m) => m.id !== me());
          return { left: true };
        }
      }
    }
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
      if (b.places && has('places')) {
        const pl = state.prefs.places;
        for (const k of ['search', 'nearby']) if (typeof b.places[k] === 'boolean') pl[k] = b.places[k];
        if (b.places.quiet !== undefined) { const q = b.places.quiet; pl.quiet = q && /^\d\d:\d\d$/.test(q.from) && /^\d\d:\d\d$/.test(q.to) && q.from !== q.to ? { from: q.from, to: q.to } : null; }
      }
      if (b.feedback !== undefined && has('doneFeedback')) { if (!['all', 'stars', 'off'].includes(b.feedback)) throw fail(400, 'invalid', { field: 'feedback' }); state.prefs.feedback = b.feedback; }
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
      if (isFamilyList(l.id)) throw fail(403, 'forbidden', { reason: 'family' });
      state.lists.delete(l.id);
      return {};
    }
    if (method === 'PUT' && n === 3 && a === 'lists' && y === 'members') {
      const l = state.lists.get(posInt(x));
      if (!l) throw fail(404, 'not_found');
      if (isFamilyList(l.id)) throw fail(403, 'forbidden', { reason: 'family' });
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
      const carry = attachArg(b);
      if (carry !== undefined) { if (carry) state.attached.set(r.id, carry); else state.attached.delete(r.id); }
      if (b.listId !== undefined && shopByNum(posInt(b.listId))) throw fail(400, 'invalid', { field: 'listId', reason: 'shopping' });
      if (readOnly(r.listId) && Object.keys(b).some((k) => k !== 'myDay' && k !== 'base')) throw fail(403, 'forbidden', { reason: 'read_only' });
      // 1.6.0: a child changes only „Mein Tag“ at a task a parent made
      if (!mayEdit(r) && Object.keys(b).some((k) => k !== 'myDay' && k !== 'base')) throw fail(403, 'forbidden', { reason: 'parents_only' });
      if (b.place !== undefined && has('places') && !r.parentId) setTaskPlace(r, b.place);
      if (!r.parentId) setTurnAndStars(r, b);
      // „wer zuerst“ has nobody assigned; „reihum“ only somebody who takes part
      const tn0 = turnOf(r);
      if (b.assigneeId !== undefined && tn0.turn && (tn0.turn === 'first' || !tn0.people.includes(b.assigneeId))) delete b.assigneeId;
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
    if (method === 'DELETE' && n === 2 && a === 'tasks') {
      const r = accessTask(x);
      if (readOnly(r.listId)) throw fail(403, 'forbidden', { reason: 'read_only' });
      if (!mayEdit(r)) throw fail(403, 'forbidden', { reason: 'parents_only' });
      r.deleted = true;
      return {};
    }
    // 1.6.0: the note „Umzug abgeschlossen“ was read (an older plugin has no such route)
    if (method === 'POST' && n === 2 && a === 'family' && x === 'seen' && has('familyTasks')) {
      const f = state.family;
      if (f.moved) f.moved.seenBy = [...new Set([...(f.moved.seenBy || []), me()])];
      return {};
    }
    if (method === 'POST' && n === 3 && a === 'tasks' && y === 'complete') {
      const r = accessTask(x);
      const done = b.done !== false;
      // 1.6.0: who it is ticked off for — a parent for a member of the family (`userId`, or the child it is assigned to)
      const fam = isFamilyList(r.listId);
      if (fam && !mayComplete(r)) throw fail(403, 'forbidden');
      let doneBy = me();
      if (has('familyTasks') && b.userId !== undefined && b.userId !== null) {
        if (!fam) throw fail(400, 'invalid', { field: 'userId' });
        if (!isParent() && b.userId !== me()) throw fail(403, 'forbidden', { reason: 'parents_only' });
        if (!famMember(b.userId)) throw fail(400, 'invalid', { field: 'userId' });
        doneBy = b.userId;
      } else if (fam && isParent() && r.assigneeId && isKid(r.assigneeId)) doneBy = r.assigneeId;
      r.doneAt = done ? state.now : null;
      r.doneBy = done ? doneBy : null;
      r.updatedAt = state.now;
      if (fam && done && isKid(doneBy) && has('doneFeedback')) state.feedback.push({ taskId: r.id, userId: doneBy, stars: r.stars || 0 });
      let next = null;
      const tn = turnOf(r);
      if (done && r.repeat) {
        const nd = R.next(r.repeat, { due: r.due ? r.due.date : null, done: state.today });
        next = task({ ...r, id: id(), doneAt: null, doneBy: null, due: { date: nd, time: r.due ? r.due.time : null } });
        // „reihum“: the next one of `people` is on
        if (tn.turn === 'rotate') next.assigneeId = tn.people[(tn.people.indexOf(r.assigneeId) + 1) % tn.people.length];
        if (state.attached.has(r.id)) state.attached.set(next.id, state.attached.get(r.id));
        if (state.taskPlace.has(r.id)) state.taskPlace.set(next.id, { ...state.taskPlace.get(r.id) });
        r.repeat = null;
      }
      return { task: taskView(r), ...(next ? { next: taskView(next) } : {}) };
    }

    // „Gestern offen geblieben“ (plugin 1.3.0) — an older plugin has none of these routes
    if (method === 'POST' && n === 3 && a === 'tasks' && y === 'move') {
      if (!has('yesterdayOpen')) throw fail(404, 'not_found');
      return { task: taskView(moveTask(accessTask(x), b.to), true) };
    }
    if (is('GET', 1, 'yesterday')) {
      if (!has('yesterdayOpen')) throw fail(404, 'not_found');
      return yesterdayView(q.area ? area(q.area) : null);
    }
    if (is('POST', 1, 'yesterday')) {
      if (!has('yesterdayOpen')) throw fail(404, 'not_found');
      if (!['done', 'today', 'move'].includes(b.action)) throw fail(400, 'invalid', { field: 'action' });
      const ar = b.area ? area(b.area) : null;
      const rows = yesterdayTasks(ar).filter((r) => !Array.isArray(b.ids) || b.ids.includes(r.id));
      for (const r of rows) {
        if (b.action === 'done') { r.doneAt = state.now; r.updatedAt = state.now; } else moveTask(r, b.action === 'today' ? 'today' : b.to);
      }
      return { changed: rows.length, failed: [], yesterday: yesterdayView(ar) };
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
    addTask: (o) => task({ id: id(), listId: 1, ...o }),
    /**
     * The family's list of the hub (plugin 1.6.0, after the move): parents and children are its members → the list.
     * `moved`: { tasks, places } — the note „Umzug abgeschlossen“ is still to be shown to everybody.
     */
    addFamily: ({ parents = [1, 12], kids = [15, 16], name = 'Familie', moved = null, stars = true } = {}) => {
      const names = { 16: ['Mia Muster', 'MM', '#DB2777'], 17: ['Jonas Muster', 'JM', '#0891B2'] };
      for (const u of [...parents, ...kids]) if (!state.people.some((q) => q.id === u)) { const nm = names[u] || [`Person ${u}`, 'P', '#64748B']; state.people.push({ id: u, name: nm[0], initials: nm[1], colorHex: nm[2] }); }
      const l = list({ id: id(), name, area: 'private', icon: 'home', ownerId: parents[0], members: [...parents, ...kids] });
      Object.assign(state.family, { listId: l.id, parents: [...parents], kids: [...kids], stars, moved: moved ? { at: '2026-11-08T07:00:00Z', tasks: moved.tasks || 0, places: moved.places || 0, seenBy: [] } : null });
      return l;
    },
    /**
     * The task the hub made for a reminder of one of Drive's deadlines (plugin 1.7.0) → the task. `nodeId`: the file in
     * Drive, `deadlineId`: Drive's deadline, `daysBefore`: what the person chose there.
     */
    addDeadline: ({ title, date, kind = null, file = null, daysBefore = 3, nodeId = 41, deadlineId = 12, listId = 1, remindAt }) => task({
      id: id(), listId, title, due: { date, time: null }, source: { plugin: 'gatecontrol-drive', id: `deadline:${deadlineId}` },
      remindAt: remindAt || `${new Date(Date.parse(`${date}T00:00:00Z`) - daysBefore * 86400000).toISOString().slice(0, 10)}T08:00:00+01:00`,
      deadline: { date, kind, file, daysBefore, open: { plugin: 'gatecontrol-drive', route: `node/${nodeId}` } },
    }),
    /** The push of a task's reminder as the plugin sends it (topic, title, body, collapseKey, data) — a deadline's with four buttons. */
    reminderPush: (taskId) => {
      const x = state.tasks.get(taskId);
      const l = state.lists.get(x.listId);
      const atMs = Date.parse(x.remindAt);
      const dl = has('driveDeadlines') ? x.deadline || null : null;
      const node = dl ? /^node\/(\d+)$/.exec(dl.open.route) : null;
      const kinds = { payment: 'Zahlung', cancellation: 'Kündigung', objection: 'Widerspruch', warranty: 'Garantie', renewal: 'Kündigung vor Verlängerung' };
      const days = dl ? Math.round((Date.parse(`${dl.date}T00:00:00Z`) - Date.parse(`${x.remindAt.slice(0, 10)}T00:00:00Z`)) / 86400000) : 0;
      return {
        topic: `plugin:${PLUGIN}:reminders`,
        title: dl ? `${days > 1 ? `Frist in ${days} Tagen` : days === 1 ? 'Frist morgen' : days === 0 ? 'Frist heute' : 'Frist abgelaufen'}: ${x.title}` : x.title,
        body: dl ? `${kinds[dl.kind] || 'Frist'} bis ${dl.date.slice(8)}.${dl.date.slice(5, 7)}.${dl.date.slice(0, 4)}${dl.file ? ` · ${dl.file}` : ''}` : 'Erinnerung',
        collapseKey: `task:${x.id}`,
        data: {
          notizen: { kind: 'reminder', taskId: x.id, task: x.id, listId: x.listId, area: l.area, tag: `task:${x.id}:${atMs}`, remindAtMs: atMs, dueAt: null, late: false, snoozed: false, ...(dl ? { deadline: dl } : {}) },
          actions: [
            { type: 'callback', id: 'done', label: 'Erledigt' }, { type: 'callback', id: 'snooze_1h', label: 'In 1 Std.' }, { type: 'callback', id: 'snooze_eve', label: 'Heute Abend' },
            ...(node ? [{ type: 'open_portal', id: 'open_file', label: 'Datei öffnen', target: `/portal?drive=${node[1]}#plg-gatecontrol-drive` }] : []),
          ],
        },
      };
    },
    /** A shopping list of the hub with its items → { uid, num, items: [ids] } (num: Task.attachedList.id). */
    addShopList: ({ id: uid, name, icon = 'cart', area: ar = 'private', family = false, role = 'owner', members = [], items = [] }) => {
      const l = { uid, num: id(), name, icon, area: ar, ownerId: role === 'owner' ? 1 : 12, members: role === 'owner' ? members : [{ id: 1, role }, ...members], family, deletedAt: null, updatedAt: state.now, was: [1] };
      state.shopLists.set(uid, l);
      const ids = items.map((it, k) => {
        const iid = it.id || `i${String(k + 1).padStart(3, '0')}-${uid}`.slice(0, 64);
        state.shopItems.set(iid, { id: iid, list: uid, text: it.text, qty: it.qty || null, checked: !!it.checked, checkedBy: it.checked ? 1 : null, updatedAt: state.now, deleted: false, seq: ++state.shopSeq });
        return iid;
      });
      return { uid, num: l.num, items: ids };
    },
    /** One of „Meine Orte“ → its row (`fav`: remembered for that key, `uses` times chosen). */
    addPlace: ({ name, address = '', lat, lon, radius = 150, named = true, ref = null, fav = null, uses = 1 }) => {
      const r = { id: id(), userId: 1, name, address, lat, lon, radius, named, ref, deleted: false, updatedAt: state.now };
      state.places.set(r.id, r);
      if (fav) state.picks.set(`${fav}|${r.id}`, { key: fav, placeId: r.id, uses, fav: true });
      return r;
    },
    /** A task's place as someone set it: { placeId | any, key?, label?, trigger?, by?, who?, consent? }. */
    setTaskPlace: (taskId, { placeId = null, any = false, key = null, label = null, trigger = 'enter', by = 1, who = 1, consent = null }) => {
      state.taskPlace.set(taskId, { placeId, key, label, any, trigger, by, who, consent: consent || (by === who ? 'accepted' : 'pending') });
    },
    get down() { return state.down; },
    set down(v) { state.down = !!v; },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

module.exports = { notesServer, PLUGIN, FEATURES, STAGE1, STAGE2, STAGE3, STAGE4, STAGE5, STAGE6, noteMeta };
