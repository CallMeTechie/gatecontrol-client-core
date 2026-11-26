'use strict';

// Phase 2 of the fake Mail server (test/fixtures/mail-server.js): calendar and contacts of the client API "C3" —
// calendars with overlays and settings, occurrences of a range (a weekly series expanded), an event with etag and
// conflict, create / change / delete / respond, invitations (one in mail 106), address books, contacts with summaries,
// `since` and tombstones, photos, lookup, activity, "Als Kontakt speichern", duplicates and merge, vCard import / export,
// groups and their members; GET contacts?q= with contacts and groups.
// Mail 1.4.0 (`pimState(now, { master: true })`, mailServer({ contactsMaster: true })): the GC contact as the master —
// a linked Outlook card with a conflict and the protocol of its automatic merge, an uncertain duplicate ("Schatzimausi 💞"
// and "Sabrina Martin", one number), favourites with a main number, writeBack, unmerge / undo, the calendar widget
// (events/upcoming). Without it the new paths answer 404 not_found like a server before 1.4.0.
//
//   pimState(now, { master }) → the state (state.calendars, events, invitations, books, cards, groups, …)
//   pimRoute({ req, route, seg, url, body, state, json, err, sum }) → true when answered

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

const midnight = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
const ymd = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const fold = (s) => String(s || '').toLowerCase().replace(/ß/g, 'ss').normalize('NFD').replace(/[̀-ͯ]/g, '');

function pimState(now, { master = false } = {}) {
  const day0 = midnight(now);
  const at = (days, h, mi = 0) => { const d = new Date(day0); d.setDate(d.getDate() + days); d.setHours(h, mi, 0, 0); return d.getTime(); };
  const sabine = { name: 'Sabine Keller', email: 'sabine@firma.de' };
  const state = {
    calendars: [
      { id: 1, source: 'local', accountId: null, name: 'Privat', color: '#46E0A0', kind: 'private', writable: true, visible: true, notify: true, isDefault: true, canInvite: true, canOnline: false, maxReminders: 3, state: 'ok', error: null, syncedAt: now, version: 1 },
      { id: 2, source: 'local', accountId: null, name: 'Firma', color: '#79B8FF', kind: 'business', writable: true, visible: true, notify: true, isDefault: false, canInvite: true, canOnline: false, maxReminders: 3, state: 'ok', error: null, syncedAt: now, version: 1 },
      { id: 3, source: 'graph', accountId: 2, name: 'Kalender', color: '#B79CFF', kind: 'business', writable: true, visible: true, notify: true, isDefault: false, canInvite: true, canOnline: true, maxReminders: 1, state: 'ok', error: null, syncedAt: now, version: 1 },
      { id: 4, source: 'ics', accountId: null, name: 'Feiertage', color: '#F28CC2', kind: 'other', writable: false, visible: false, notify: false, isDefault: false, canInvite: false, canOnline: false, maxReminders: 3, state: 'ok', error: null, syncedAt: now, version: 1 },
    ],
    overlays: [
      { id: 'familie', source: 'familie', name: 'Familie', color: '#F5B544', visible: true },
      { id: 'birthdays', source: 'birthdays', name: 'Geburtstage', color: '#FF8080', visible: true },
    ],
    calPrefs: { defaultCalendarId: 1, view: 'week', weekStart: 1, workWeek: false, timeZone: 'Europe/Berlin', reminders: true, defaultReminder: 15, allDayReminder: 360 },
    consent: [],
    events: new Map(),
    overlayItems: [
      { key: `familie:9:${ymd(at(0, 0))}`, overlayId: 'familie', title: 'Tim abholen', start: at(0, 15), end: at(0, 16), allDay: false, location: 'Schule', readOnly: true },
      { key: `bday:403:${new Date(day0).getFullYear()}`, overlayId: 'birthdays', title: 'Anna Lang (40)', start: at(1, 0), end: at(2, 0), allDay: true, startDate: ymd(at(1, 0)), endDate: ymd(at(1, 0)), location: null, readOnly: true },
    ],
    invitations: new Map(),
    books: [
      { id: 1, source: 'local', accountId: null, name: 'Meine Kontakte', writable: true, visible: true, isDefault: true, state: 'ok', error: null, syncedAt: now },
      { id: 2, source: 'graph', accountId: 2, name: 'Firma · M365', writable: true, visible: true, isDefault: false, state: 'ok', error: null, syncedAt: now },
      { id: 3, source: 'carddav', accountId: 1, name: 'Privat · GMX', writable: false, visible: true, isDefault: false, state: 'ok', error: null, syncedAt: now },
    ],
    cardPrefs: { sort: 'family', show: 'given_family', defaultAddressbookId: 1, birthdays: true },
    cards: new Map(),
    photos: new Map(),
    groups: new Map(),
    tombstones: [],
    ignored: [],
    imports: [],
    version: 10,
    nextId: 9000,
    sent: [],
    // Mail 1.4.0
    master,
    conflicts: [],
    merges: [],
    origins: [],
    dismissed: [],
  };
  const ev = (e) => state.events.set(e.id, {
    location: null, online: null, status: 'confirmed', busy: 'busy', myResponse: null, attendees: [], organizer: null, description: '', descriptionHtml: null,
    reminders: [], recurrence: null, private: false, allDay: false, deleted: [], updatedAt: now, sequence: 0, createdAt: now, ...e,
  });
  ev({
    id: 301, calendarId: 3, title: 'Projektbesprechung', start: at(0, 10), end: at(0, 11), location: 'Raum 1', online: { url: 'https://teams.microsoft.com/l/meetup-join/abc', provider: 'teams' },
    myResponse: 'organizer', organizer: { name: 'Max', email: 'max@firma.de', self: true },
    attendees: [{ ...sabine, role: 'required', response: 'accepted' }, { name: 'Tim Brandt', email: 'tim@firma.de', role: 'required', response: 'tentative' }, { name: 'Anna Lang', email: 'anna.lang@example.com', role: 'optional', response: 'needs_action' }],
    description: 'Agenda: Stand, Risiken', descriptionHtml: '<p><b>Agenda</b>: Stand, Risiken</p><script>alert(1)</script>', reminders: [15],
  });
  ev({ id: 302, calendarId: 1, title: 'Zahnarzt', start: at(1, 14), end: at(1, 14, 45), reminders: [60] });
  ev({
    id: 303, calendarId: 3, title: 'Sprint-Review', start: at(2, 13), end: at(2, 14), location: 'Besprechungsraum 1', myResponse: 'needs_action', status: 'tentative',
    organizer: { ...sabine, self: false }, attendees: [{ name: 'Max', email: 'max@firma.de', role: 'required', response: 'needs_action' }, { name: 'Tim Brandt', email: 'tim@firma.de', role: 'required', response: 'accepted' }],
  });
  ev({ id: 304, calendarId: 1, title: 'Training', start: at(0, 18), end: at(0, 19, 30), recurrence: { rrule: 'FREQ=WEEKLY', editable: true, freq: 'weekly', interval: 1, byDay: null, byMonthDay: null, bySetPos: null, until: null, count: null, exceptions: [], deleted: [] } });
  ev({ id: 305, calendarId: 2, title: 'Messe', start: at(3, 0), end: at(5, 0), allDay: true, startDate: ymd(at(3, 0)), endDate: ymd(at(4, 0)) });

  state.invitations.set(701, {
    id: 701, kind: 'mail', messageId: 106, accountId: 2, method: 'request', state: 'open', uid: 'sprint-review@firma.de', eventId: 303,
    organizer: { ...sabine, contactId: 401 }, from: { ...sabine }, comment: 'Bitte die Zahlen mitbringen.', proposed: null, calendarId: 3, calendarChoices: [1, 2, 3],
  });

  const card = (c) => state.cards.set(c.id, {
    emails: [], phones: [], company: null, department: null, title: null, addresses: [], birthday: null, note: '', urls: [], groups: [], linkId: null,
    favorite: 0, mainPhone: null, version: (state.version += 1), updatedAt: now, ...c, name: { display: '', given: '', family: '', middle: null, prefix: null, suffix: null, nickname: null, ...c.name },
  });
  card({
    id: 401, addressbookId: 2, name: { display: 'Sabine Keller', given: 'Sabine', family: 'Keller' }, emails: [{ value: 'sabine@firma.de', type: 'work', primary: true }, { value: 'sabine.k@gmx.de', type: 'home', primary: false }],
    phones: [{ value: '0171 2345678', type: 'mobile' }, { value: '0221 3004012', type: 'work' }], company: 'Keller GmbH', title: 'Projektleitung',
    addresses: [{ type: 'work', street: 'Hansaring 12', postalCode: '50670', city: 'Köln', region: '', country: '' }], birthday: '1981-03-14', note: 'Mittwochs im Homeoffice.', groups: [501],
  });
  card({ id: 402, addressbookId: 1, name: { display: 'Tim Brandt', given: 'Tim', family: 'Brandt' }, emails: [{ value: 'tim@firma.de', type: 'work', primary: true }], phones: [{ value: '0170 1112223', type: 'mobile' }], company: 'Firma GmbH', groups: [501, 502] });
  card({ id: 403, addressbookId: 1, name: { display: 'Anna Lang', given: 'Anna', family: 'Lang' }, emails: [{ value: 'anna.lang@example.com', type: 'home', primary: true }], birthday: '1986-11-05' });
  card({ id: 404, addressbookId: 3, name: { display: 'Bernd Albers', given: 'Bernd', family: 'Albers' }, emails: [{ value: 'bernd@gmx.de', type: 'home', primary: true }] });
  card({ id: 405, addressbookId: 1, name: { display: 'Sabine Keller', given: 'Sabine', family: 'Keller' }, emails: [{ value: 'sabine@firma.de', type: 'work', primary: true }] });
  card({ id: 406, addressbookId: 1, name: { display: 'Älbert Ötzi', given: 'Älbert', family: 'Ötzi' }, emails: [{ value: 'oetzi@example.com', type: 'other', primary: true }] });
  state.photos.set(401, { mime: 'image/png', data: PNG.toString('base64'), etag: 'ph401' });
  state.groups.set(501, { id: 501, name: 'Team Vertrieb', color: '#79B8FF', members: [{ id: 801, contactId: 401, name: 'Sabine Keller', email: 'sabine@firma.de' }, { id: 802, contactId: 402, name: 'Tim Brandt', email: 'tim@firma.de' }] });
  state.groups.set(502, { id: 502, name: 'Familie', color: null, members: [{ id: 803, contactId: 402, name: 'Tim Brandt', email: 'tim@firma.de' }, { id: 804, contactId: null, name: 'Oma', email: 'oma@example.com' }] });
  if (master) {
    // after the run of 1.4.0: "Sabine Keller" of Meine Kontakte is the GC contact, the Outlook card is linked to it; the
    // Outlook card has another mobile number (a conflict); her second address came from Outlook (writeBack goes there)
    const m = state.cards.get(405);
    Object.assign(m, {
      emails: [{ value: 'sabine@firma.de', type: 'work', primary: true }, { value: 'sabine.k@gmx.de', type: 'home', primary: false }],
      phones: [{ value: '0170 1234567', type: 'mobile' }, { value: '0221 3004012', type: 'work' }], company: 'Keller GmbH', title: 'Projektleitung',
      addresses: [{ type: 'work', street: 'Hansaring 12', postalCode: '50670', city: 'Köln', region: '', country: '' }], birthday: '1981-03-14', note: 'Mittwochs im Homeoffice.',
    });
    state.cards.get(401).linkId = 405;
    for (const g of state.groups.values()) for (const x of g.members) if (x.contactId === 401) x.contactId = 405;
    state.photos.set(405, { mime: 'image/png', data: PNG.toString('base64'), etag: 'ph405' });
    state.origins.push({ cardId: 405, field: 'emails', key: 'sabine.k@gmx.de', sourceId: 401 }, { cardId: 405, field: 'phones', key: '2213004012', sourceId: 401 });
    state.conflicts.push({ id: 951, cardId: 405, sourceId: 401, field: 'phones', type: 'mobile', value: { value: '0171 2345678', type: 'mobile' }, replaces: { value: '0170 1234567', type: 'mobile' }, at: now - DAY });
    state.merges.push({ id: 901, masterId: 405, mode: 'auto', created: false, reason: 'email', at: now - DAY, undoneAt: null, removed: [],
      cards: [{ id: 405, name: 'Sabine Keller', addressbookId: 1, addressbook: 'Meine Kontakte', source: 'local', removed: false }, { id: 401, name: 'Sabine Keller', addressbookId: 2, addressbook: 'Firma · M365', source: 'graph', removed: false }] });
    // an uncertain duplicate: one number, names that do not match
    card({ id: 407, addressbookId: 2, name: { display: 'Schatzimausi 💞', given: '', family: '' }, phones: [{ value: '+49 172 3334444', type: 'mobile' }], birthday: '--07-21' });
    card({ id: 408, addressbookId: 1, name: { display: 'Sabrina Martin', given: 'Sabrina', family: 'Martin' }, emails: [{ value: 'sabrina@example.com', type: 'home', primary: true }], phones: [{ value: '0172 3334444', type: 'mobile' }, { value: '0221 777888', type: 'home' }],
      addresses: [{ type: 'home', street: 'Ringstraße 3', postalCode: '50667', city: 'Köln', region: '', country: '' }] });
    state.photos.set(407, { mime: 'image/png', data: PNG.toString('base64'), etag: 'ph407' });
    // favourites: Tim (his mobile number), Anna (no number: the tile opens her)
    state.cards.get(402).favorite = 1;
    state.cards.get(403).favorite = 2;
  }
  return state;
}

// ── Mail 1.4.0: the GC contact as the master ───────────────

const digitsOf = (v) => String(v || '').replace(/\D/g, '').replace(/^(?:00?49)/, '').slice(-9);
const valueKey = (field, v) => {
  if (field === 'phones') return digitsOf(v && v.value);
  if (field === 'emails') return String((v && v.value) || '').toLowerCase();
  if (field === 'addresses') return fold([v && v.street, v && v.postalCode, v && v.city].join('|'));
  return fold(typeof v === 'string' ? v : JSON.stringify(v));
};
const hasEmoji = (s) => /\p{Extended_Pictographic}/u.test(String(s || ''));

/** The main number of card `c`: the chosen one, else the first mobile number, else the first. */
function mainPhoneOf(c) {
  const chosen = c.mainPhone ? c.phones.find((p) => digitsOf(p.value) === c.mainPhone) : null;
  return chosen || c.phones.find((p) => p.type === 'mobile') || c.phones[0] || null;
}

function sourceOf(state, c) {
  const b = state.books.find((x) => x.id === c.addressbookId) || {};
  return { id: c.id, addressbookId: c.addressbookId, addressbook: b.name || '', source: b.source || 'local', accountId: b.accountId || null, account: b.accountId === 2 ? 'max@firma.de' : (b.accountId === 1 ? 'max@gmx.de' : null) };
}

function conflictView(state, x) {
  return { id: x.id, field: x.field, type: x.type, value: x.value, replaces: x.replaces, source: sourceOf(state, state.cards.get(x.sourceId)), at: x.at };
}

/** Names alike (1.4.0 rule 2.2, simplified): the same folded, the words of one in the other's, or one without a name. */
function similar(a, b) {
  const words = (c) => fold(display(c)).split(/\s+/).filter((w) => w && !/\p{Extended_Pictographic}/u.test(w));
  const x = words(a);
  const y = words(b);
  if (!a.name.display && !a.name.given && !a.name.family) return true;
  if (!b.name.display && !b.name.given && !b.name.family) return true;
  if (x.join(' ') === y.join(' ')) return true;
  return x.length > 0 && y.length > 0 && (x.every((w) => y.includes(w)) || y.every((w) => x.includes(w)));
}

function union(state, cards) {
  const local = cards.filter((c) => state.books.find((b) => b.id === c.addressbookId).source === 'local');
  const keep = local.sort((a, b) => a.id - b.id)[0] || null;
  const list = (field) => {
    const out = [];
    for (const c of cards) for (const v of c[field]) if (!out.some((o) => valueKey(field, o) === valueKey(field, v))) out.push(v);
    return out;
  };
  const named = cards.find((c) => hasEmoji(c.name.display)) || [...cards].sort((a, b) => display(b).length - display(a).length)[0];
  const first = (k) => (keep && keep[k]) || (cards.find((c) => c[k]) || {})[k] || null;
  const photoFrom = (keep && state.photos.has(keep.id) ? keep : cards.find((c) => state.photos.has(c.id))) || null;
  const conflicts = [];
  for (const k of ['company', 'title']) {
    const v = first(k);
    for (const c of cards) if (c[k] && v && c[k] !== v) conflicts.push({ field: k, value: c[k], source: sourceOf(state, c) });
  }
  return {
    keep, conflicts,
    fields: {
      name: { ...named.name, display: display(named) }, emails: list('emails'), phones: list('phones'), addresses: list('addresses'), urls: list('urls'),
      company: first('company'), department: first('department'), title: first('title'), birthday: cards.map((c) => c.birthday).find((x) => x && !x.startsWith('--')) || first('birthday'),
      note: [...new Set(cards.map((c) => c.note).filter(Boolean))].join('\n\n'),
    },
    photoFrom: photoFrom ? photoFrom.id : null,
  };
}

function previewOf(state, cards) {
  const u = union(state, cards);
  const main = mainPhoneOf({ phones: u.fields.phones, mainPhone: null });
  return { id: u.keep ? u.keep.id : null, ...u.fields, birthday: u.fields.birthday, mainPhone: main, photoFrom: u.photoFrom, sources: cards.map((c) => sourceOf(state, c)), conflicts: u.conflicts };
}

/** The duplicate groups over the shown entries (a master stands for its links) → [{ key, reason, ids, certain }]. */
function dupGroups(state) {
  const visible = state.books.filter((b) => b.visible).map((b) => b.id);
  const entries = [...state.cards.values()].filter((c) => visible.includes(c.addressbookId) && !c.linkId);
  const ignored = (a, b) => state.ignored.some((ig) => ig.includes(a.id) && ig.includes(b.id));
  const out = [];
  const seen = new Set();
  for (let i = 0; i < entries.length; i += 1) {
    for (let j = i + 1; j < entries.length; j += 1) {
      const a = entries[i];
      const b = entries[j];
      if (ignored(a, b)) continue;
      const mail = a.emails.some((e) => b.emails.some((f) => e.value.toLowerCase() === f.value.toLowerCase()));
      const phone = !mail && a.phones.some((p) => b.phones.some((q) => digitsOf(p.value) && digitsOf(p.value) === digitsOf(q.value)));
      const name = !mail && !phone && !a.emails.length && !b.emails.length && fold(display(a)) === fold(display(b)) && !!display(a);
      if (!mail && !phone && !name) continue;
      const key = [a.id, b.id].sort((x, y) => x - y).join('-');
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ key, reason: mail ? 'email' : (phone ? 'phone' : 'name'), ids: [a.id, b.id], certain: (mail || phone) && similar(a, b) });
    }
  }
  return [...out.filter((g) => !g.certain), ...out.filter((g) => g.certain)];
}

function mergeCards(state, ids, mode, reason) {
  const cards = ids.map((x) => state.cards.get(x)).filter(Boolean);
  const u = union(state, cards);
  let m = u.keep;
  const created = !m;
  if (!m) {
    m = { id: (state.nextId += 1), addressbookId: 1, emails: [], phones: [], company: null, department: null, title: null, addresses: [], birthday: null, note: '', urls: [], linkId: null, favorite: 0, mainPhone: null, name: {} };
    state.cards.set(m.id, m);
  }
  Object.assign(m, u.fields, { name: { display: '', given: '', family: '', middle: null, prefix: null, suffix: null, nickname: null, ...u.fields.name } });
  if (u.photoFrom && u.photoFrom !== m.id && !state.photos.has(m.id)) state.photos.set(m.id, { ...state.photos.get(u.photoFrom), etag: `ph${m.id}` });
  const fav = cards.map((c) => c.favorite).filter((x) => x > 0);
  m.favorite = fav.length ? Math.min(...fav) : 0;
  const removed = [];
  for (const c of cards) {
    if (c.id === m.id) continue;
    if (state.books.find((b) => b.id === c.addressbookId).source === 'local') {
      removed.push(JSON.parse(JSON.stringify(c)));
      state.cards.delete(c.id);
      state.tombstones.push({ id: c.id, version: (state.version += 1) });
    } else {
      c.linkId = m.id;
      c.version = (state.version += 1);
    }
  }
  m.version = (state.version += 1);
  const books = (c) => state.books.find((b) => b.id === c.addressbookId);
  const mg = { id: (state.nextId += 1), masterId: m.id, mode, created, reason, at: Date.now(), undoneAt: null, removed,
    cards: cards.map((c) => ({ id: c.id, name: display(c), addressbookId: c.addressbookId, addressbook: books(c).name, source: books(c).source, removed: removed.some((r) => r.id === c.id) })) };
  state.merges.push(mg);
  return { m, mg };
}

/** Loosen links `ids` of master `m` (all without); the merges' GC cards back, a created master gone when no link is left. */
function loosen(state, m, ids, keepMaster) {
  const links = [...state.cards.values()].filter((c) => c.linkId === m.id);
  const targets = ids ? links.filter((l) => ids.includes(l.id)) : links;
  for (const t of targets) {
    t.linkId = null;
    t.version = (state.version += 1);
    state.ignored.push([m.id, t.id]);
    state.conflicts = state.conflicts.filter((x) => !(x.cardId === m.id && x.sourceId === t.id));
  }
  const restored = [];
  let card = m;
  if (links.length === targets.length) {
    for (const mg of state.merges.filter((x) => x.masterId === m.id && !x.undoneAt)) {
      for (const r of mg.removed) { state.cards.set(r.id, { ...r, version: (state.version += 1) }); restored.push(r.id); state.ignored.push([r.id, m.id]); }
      mg.undoneAt = Date.now();
      if (mg.created && !keepMaster) { state.cards.delete(m.id); state.tombstones.push({ id: m.id, version: (state.version += 1) }); card = null; }
    }
  }
  if (card) card.version = (state.version += 1);
  return { card: card ? fullCard(state, card) : null, unlinked: targets.map((x) => x.id), restored };
}

/** GET events/upcoming: from now to the end of today + days − 1, all-day ones of a day first. */
function upcoming(state, q) {
  const days = Math.min(Math.max(Number(q.days) || 2, 1), 7);
  const limit = Math.min(Math.max(Number(q.limit) || 8, 1), 20);
  const now = Date.now();
  const to = (() => { const d = new Date(midnight(now)); d.setDate(d.getDate() + days); return d.getTime(); })();
  const color = new Map(state.calendars.map((c) => [c.id, c.color]));
  const list = [];
  for (const e of state.events.values()) {
    const cal = state.calendars.find((c) => c.id === e.calendarId);
    if (!cal || !cal.visible) continue;
    for (const o of occurrences(state, e, now, to)) {
      if (o.status === 'cancelled' || o.myResponse === 'declined') continue;
      list.push({ key: o.key, eventId: o.eventId, calendarId: o.calendarId, overlayId: null, color: color.get(o.calendarId), title: o.title, start: o.start, end: o.end, allDay: o.allDay,
        ...(o.allDay ? { startDate: o.startDate, endDate: o.endDate } : {}), location: o.location, online: o.online ? o.online.url : null, myResponse: o.myResponse, tentative: o.myResponse === 'needs_action' || o.status === 'tentative' });
    }
  }
  for (const o of state.overlayItems) {
    const ov = state.overlays.find((x) => x.id === o.overlayId);
    if (!ov || !ov.visible || o.end <= now || o.start >= to) continue;
    list.push({ key: o.key, eventId: null, calendarId: null, overlayId: o.overlayId, color: ov.color, title: o.title, start: o.start, end: o.end, allDay: !!o.allDay,
      ...(o.allDay ? { startDate: o.startDate, endDate: o.endDate } : {}), location: o.location || null, online: null, myResponse: null, tentative: false });
  }
  const today = ymd(now);
  for (const x of list) x.day = x.allDay ? (x.startDate < today ? today : x.startDate) : ymd(Math.max(x.start, now));
  list.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0) || (b.allDay ? 1 : 0) - (a.allDay ? 1 : 0) || a.start - b.start);
  return { timeZone: 'Europe/Berlin', today, items: list.slice(0, limit), more: Math.max(0, list.length - limit) };
}

// ── views ──────────────────────────────────────────────────

function occurrences(state, e, from, to) {
  const one = (start, end, occ) => ({
    key: occ ? `${e.id}:${occ}` : String(e.id), eventId: e.id, calendarId: e.calendarId, occurrence: occ, title: e.title, start, end, allDay: e.allDay,
    ...(e.allDay ? { startDate: ymd(start), endDate: ymd(end - 1) } : {}), timeZone: 'Europe/Berlin', location: e.location, online: e.online, status: e.status,
    busy: e.busy, myResponse: e.myResponse, recurring: !!e.recurrence, attendees: e.attendees.length, private: e.private, reminder: e.reminders[0] ?? null,
  });
  if (!e.recurrence) return e.start < to && e.end > from ? [one(e.start, e.end, null)] : [];
  const out = [];
  for (let k = -12; k <= 30; k += 1) {
    const start = e.start + k * 7 * DAY;
    const end = e.end + k * 7 * DAY;
    const occ = String(start);
    if (e.deleted.includes(occ) || start >= to || end <= from) continue;
    out.push(one(start, end, occ));
  }
  return out;
}

function fullEvent(state, e, occ = null) {
  const list = occurrences(state, e, -Infinity, Infinity);
  const base = (occ ? list.find((o) => o.occurrence === occ) : null) || list[0] || occurrences(state, { ...e, recurrence: null }, -Infinity, Infinity)[0];
  const cal = state.calendars.find((c) => c.id === e.calendarId);
  const attendeeOf = e.myResponse && e.myResponse !== 'organizer';
  return {
    ...base, key: occ ? base.key : String(e.id), occurrence: occ || null,
    description: e.description, descriptionHtml: e.descriptionHtml, organizer: e.organizer,
    attendees: e.attendees.map((a) => ({ name: a.name, email: a.email, role: a.role || 'required', response: a.response || 'needs_action', self: a.email === 'max@firma.de', contactId: [...state.cards.values()].find((c) => c.emails.some((x) => x.value === a.email))?.id || null })),
    reminders: e.reminders, recurrence: e.recurrence, seriesId: occ ? e.id : null,
    // Mail 1.3.0: DTSTART / DTEND of the series' master (null for a single event)
    series: e.recurrence ? { start: e.start, end: e.end, allDay: e.allDay, ...(e.allDay ? { startDate: e.startDate, endDate: e.endDate } : {}) } : null, readOnly: !cal.writable, canRespond: cal.writable && attendeeOf, canEdit: cal.writable && !attendeeOf, canDelete: cal.writable,
    categories: [], invitationId: [...state.invitations.values()].find((i) => i.eventId === e.id && (i.state === 'open' || i.state === 'answered'))?.id || null,
    url: null, createdAt: e.createdAt, updatedAt: e.updatedAt, etag: `"${e.updatedAt}-${e.sequence}"`,
  };
}

function invitationView(state, inv) {
  const e = state.events.get(inv.eventId);
  const counts = { accepted: 0, tentative: 0, declined: 0, needs_action: 0 };
  const attendees = (e ? e.attendees : []).map((a) => ({ name: a.name, email: a.email, role: a.role || 'required', response: a.response, self: a.email === 'max@firma.de', contactId: null }));
  for (const a of attendees) counts[a.response] += 1;
  const start = e ? e.start : Date.now();
  const end = e ? e.end : start + HOUR;
  const day = [...state.events.values()].filter((x) => x !== e && state.calendars.find((c) => c.id === x.calendarId).visible).flatMap((x) => occurrences(state, x, start - 2 * HOUR, end + 2 * HOUR));
  return {
    id: inv.id, kind: inv.kind, messageId: inv.messageId, accountId: inv.accountId, method: inv.method, state: inv.state, uid: inv.uid,
    title: e ? e.title : 'Termin', start, end, allDay: false, timeZone: 'Europe/Berlin', location: e ? e.location : null, online: null, recurrence: null,
    organizer: inv.organizer, from: inv.from, attendees, counts, myResponse: e ? e.myResponse : 'needs_action', comment: inv.comment, proposed: inv.proposed,
    eventId: inv.eventId, calendarId: inv.calendarId, calendarChoices: inv.calendarChoices, day,
    conflicts: day.filter((o) => o.start < end && o.end > start).map((o) => ({ title: o.title, start: o.start, end: o.end, calendarId: o.calendarId })),
  };
}

const display = (c) => c.name.display || [c.name.given, c.name.family].filter(Boolean).join(' ') || c.company || (c.emails[0] && c.emails[0].value) || '';
const sortKey = (c) => fold([c.name.family, c.name.given].filter(Boolean).join(' ') || display(c)).toUpperCase();
const letterOf = (k) => (/^[A-Z]/.test(k) ? k[0] : '#');

function summary(state, c) {
  const key = sortKey(c);
  const ph = state.photos.get(c.id);
  return {
    id: c.id, addressbookId: c.addressbookId, name: display(c), sortKey: key, letter: letterOf(key), company: c.company, title: c.title,
    emails: c.emails.map((e) => e.value).slice(0, 3), phone: c.phones[0] ? c.phones[0].value : null, photo: !!ph, photoEtag: ph ? ph.etag : null,
    groups: [...state.groups.values()].filter((g) => g.members.some((m) => m.contactId === c.id)).map((g) => g.id),
    linked: [...state.cards.values()].filter((x) => x.linkId === c.id).map((x) => x.id), gcUserId: null, updatedAt: c.updatedAt,
    ...(state.master ? masterSummary(state, c) : {}),
  };
}

function masterSummary(state, c) {
  const main = mainPhoneOf(c);
  const links = [...state.cards.values()].filter((x) => x.linkId === c.id);
  const src = (x) => { const b = state.books.find((y) => y.id === x.addressbookId); return { addressbookId: b.id, source: b.source, accountId: b.accountId }; };
  return {
    phone: main ? main.value : null, favorite: c.favorite > 0, mainPhone: main ? main.value : null, conflicts: state.conflicts.filter((x) => x.cardId === c.id).length,
    masterId: c.linkId || null, sources: [c, ...links].map(src).filter((x, i, a) => a.findIndex((y) => y.addressbookId === x.addressbookId) === i),
  };
}

function fullCard(state, c) {
  const book = state.books.find((b) => b.id === c.addressbookId);
  const ph = state.photos.get(c.id);
  return {
    id: c.id, addressbookId: c.addressbookId, source: book.source, readOnly: !book.writable, etag: `"v${c.version}"`, name: { ...c.name, display: display(c) },
    emails: c.emails, phones: c.phones, company: c.company, department: c.department, title: c.title, addresses: c.addresses, birthday: c.birthday, note: c.note, urls: c.urls,
    photo: ph ? { etag: ph.etag, mime: ph.mime } : null, groups: summary(state, c).groups,
    linked: [...state.cards.values()].filter((x) => x.linkId === c.id).map((x) => ({ id: x.id, addressbookId: x.addressbookId, source: state.books.find((b) => b.id === x.addressbookId).source })),
    gcUserId: null, updatedAt: c.updatedAt,
    ...(state.master ? {
      favorite: c.favorite > 0, mainPhone: mainPhoneOf(c), mainPhoneChosen: !!c.mainPhone, masterId: c.linkId || null,
      conflicts: state.conflicts.filter((x) => x.cardId === c.id).map((x) => conflictView(state, x)),
      sources: [c, ...[...state.cards.values()].filter((x) => x.linkId === c.id)].map((x) => sourceOf(state, x)),
    } : {}),
  };
}

function applyCard(state, c, b) {
  for (const k of ['emails', 'phones', 'company', 'department', 'title', 'addresses', 'birthday', 'note', 'urls']) if (b[k] !== undefined) c[k] = b[k];
  if (b.name) c.name = { display: '', given: '', family: '', middle: null, prefix: null, suffix: null, nickname: null, ...b.name };
  if (b.groups) {
    for (const g of state.groups.values()) {
      const has = g.members.some((m) => m.contactId === c.id);
      if (b.groups.includes(g.id) && !has) g.members.push({ id: (state.nextId += 1), contactId: c.id, name: display(c), email: c.emails[0] ? c.emails[0].value : null });
      if (!b.groups.includes(g.id) && has) g.members = g.members.filter((m) => m.contactId !== c.id);
    }
  }
  c.version = (state.version += 1);
  c.updatedAt = Date.now();
}

// ── routes ─────────────────────────────────────────────────

function pimRoute({ req, route, seg, url, body, state: all, json, err, sum }) {
  const state = all.pim;
  const m = req.method;
  const q = Object.fromEntries(url.searchParams);
  const n = seg.length;
  const id = Number(seg[1]);
  const need = (feature) => { if (!all.features.includes(feature)) { err(403, 'feature_off', { feature }); return false; } return true; };

  // ── calendar ──
  if (seg[0] === 'calendars' || seg[0] === 'overlays' || seg[0] === 'calendar' || seg[0] === 'events' || seg[0] === 'invitations') {
    if (!need('calendar')) return true;
  }
  if (seg[0] === 'calendars') {
    if (n === 1 && m === 'GET') return json(200, { calendars: state.calendars, overlays: state.overlays, prefs: state.calPrefs, consent: state.consent }), true;
    if (n === 1 && m === 'POST') {
      if (!body.name) return err(400, 'invalid', { field: 'name' }), true;
      const c = { ...state.calendars[0], id: (state.nextId += 1), name: body.name, color: body.color || '#5FD3E0', kind: 'other', isDefault: false };
      state.calendars.push(c);
      return json(200, { calendar: c }), true;
    }
    if (n === 2 && seg[1] === 'subscribe' && m === 'POST') {
      if (!/^https:\/\//.test(body.url || '')) return err(400, 'invalid', { field: 'url' }), true;
      const c = { ...state.calendars[3], id: (state.nextId += 1), name: body.name || 'Abo', color: body.color || '#C7CDD6', visible: true };
      state.calendars.push(c);
      state.lastSubscribe = body;
      return json(200, { calendar: c }), true;
    }
    const c = state.calendars.find((x) => x.id === id);
    if (!c) return err(404, 'not_found'), true;
    if (n === 2 && m === 'PATCH') { for (const k of ['name', 'color', 'visible', 'notify']) if (body[k] !== undefined) c[k] = body[k]; return json(200, { calendar: c }), true; }
    if (n === 2 && m === 'DELETE') {
      if (c.source !== 'local' && c.source !== 'ics') return err(409, 'not_supported', { what: 'delete' }), true;
      state.calendars = state.calendars.filter((x) => x !== c);
      return json(200, { ok: true }), true;
    }
  }
  if (seg[0] === 'overlays' && n === 2 && m === 'PATCH') {
    const o = state.overlays.find((x) => x.id === decodeURIComponent(seg[1]));
    if (!o) return err(404, 'not_found'), true;
    for (const k of ['visible', 'color']) if (body[k] !== undefined) o[k] = body[k];
    return json(200, { overlay: o }), true;
  }
  if (seg[0] === 'calendar' && seg[1] === 'settings' && m === 'PUT') {
    Object.assign(state.calPrefs, body);
    state.lastCalSettings = body;
    return json(200, { prefs: state.calPrefs }), true;
  }
  if (seg[0] === 'events') {
    if (n === 2 && seg[1] === 'upcoming' && m === 'GET' && state.master) return json(200, upcoming(state, q)), true;
    if (n === 1 && m === 'GET') {
      const from = Number(q.from);
      const to = Number(q.to);
      if (!(to > from) || to - from > 62 * DAY) return err(400, 'invalid', { field: 'to' }), true;
      const want = q.calendars ? q.calendars.split(',') : null;
      const cals = state.calendars.filter((c) => (want ? want.includes(String(c.id)) : c.visible)).map((c) => c.id);
      const ovs = state.overlays.filter((o) => (want ? want.includes(o.id) : o.visible)).map((o) => o.id);
      const items = [...state.events.values()].filter((e) => cals.includes(e.calendarId)).flatMap((e) => occurrences(state, e, from, to)).sort((a, b) => a.start - b.start);
      const overlays = state.overlayItems.filter((o) => ovs.includes(o.overlayId) && o.start < to && o.end > from);
      return json(200, { items, overlays, pending: [] }), true;
    }
    if (n === 1 && m === 'POST') {
      const cal = state.calendars.find((c) => c.id === body.calendarId);
      if (!cal) return err(404, 'not_found'), true;
      if (!cal.writable) return err(409, 'read_only'), true;
      if (!body.title) return err(400, 'invalid', { field: 'title' }), true;
      if (body.online && body.online.create === 'teams' && !cal.canOnline) return err(409, 'not_supported', { what: 'teams' }), true;
      const e = {
        id: (state.nextId += 1), calendarId: cal.id, title: body.title, allDay: !!body.allDay, start: body.start, end: body.end, location: body.location || null,
        online: body.online && body.online.url ? { url: body.online.url, provider: 'other' } : (body.online && body.online.create ? { url: 'https://teams.microsoft.com/l/meetup-join/new', provider: 'teams' } : null),
        status: 'confirmed', busy: body.busy || 'busy', myResponse: body.attendees && body.attendees.length ? 'organizer' : null,
        attendees: (body.attendees || []).map((a) => ({ name: a.name || '', email: a.email, role: a.role || 'required', response: 'needs_action' })),
        organizer: body.attendees && body.attendees.length ? { name: 'Max', email: 'max@gmx.de', self: true } : null, description: body.description || '', descriptionHtml: null,
        reminders: body.reminders || [], recurrence: body.recurrence ? { rrule: `FREQ=${String(body.recurrence.freq || 'weekly').toUpperCase()}`, editable: true, interval: 1, byDay: null, byMonthDay: null, bySetPos: null, until: null, count: null, exceptions: [], deleted: [], ...body.recurrence } : null,
        private: !!body.private, deleted: [], updatedAt: Date.now(), sequence: 0, createdAt: Date.now(),
      };
      if (e.allDay) { e.startDate = body.startDate; e.endDate = body.endDate || body.startDate; e.start = midnight(Date.parse(`${body.startDate}T12:00:00`)); e.end = midnight(Date.parse(`${e.endDate}T12:00:00`)) + DAY; }
      state.events.set(e.id, e);
      state.lastEventBody = body;
      const sent = { mail: body.sendInvites === false ? 0 : e.attendees.length, internal: 0 };
      return json(200, { event: fullEvent(state, e), sent }), true;
    }
    const e = state.events.get(id);
    if (!e) return err(404, 'not_found'), true;
    if (n === 2 && m === 'GET') {
      if (q.occurrence && e.recurrence && !occurrences(state, e, -Infinity, Infinity).some((o) => o.occurrence === q.occurrence)) return err(404, 'not_found'), true;
      return json(200, fullEvent(state, e, q.occurrence || null)), true;
    }
    if (n === 2 && m === 'PATCH') {
      if (body.etag && body.etag !== `"${e.updatedAt}-${e.sequence}"`) return err(409, 'conflict', { current: fullEvent(state, e) }), true;
      for (const k of ['title', 'allDay', 'start', 'end', 'location', 'description', 'reminders', 'busy', 'private', 'calendarId']) if (body[k] !== undefined) e[k] = body[k];
      if (body.attendees) e.attendees = body.attendees.map((a) => ({ name: a.name || '', email: a.email, role: a.role || 'required', response: 'needs_action' }));
      if (body.recurrence !== undefined) e.recurrence = body.recurrence ? { rrule: `FREQ=${String(body.recurrence.freq).toUpperCase()}`, editable: true, interval: 1, byDay: null, byMonthDay: null, bySetPos: null, until: null, count: null, exceptions: [], deleted: [], ...body.recurrence } : null;
      e.updatedAt += 1;
      e.sequence += 1;
      state.lastEventBody = body;
      return json(200, { event: fullEvent(state, e, body.scope === 'occurrence' ? body.occurrence : null), sent: { mail: 0, internal: 0 } }), true;
    }
    if (n === 2 && m === 'DELETE') {
      if (q.scope === 'occurrence' && q.occurrence) e.deleted.push(q.occurrence);
      else state.events.delete(e.id);
      state.lastDelete = q;
      return json(200, { ok: true, sent: { mail: q.notify ? e.attendees.length : 0, internal: 0 } }), true;
    }
    if (n === 3 && seg[2] === 'respond' && m === 'POST') {
      e.myResponse = body.response;
      state.lastRespond = body;
      return json(200, { event: fullEvent(state, e, body.occurrence || null) }), true;
    }
  }
  if (seg[0] === 'invitations') {
    if (n === 1 && m === 'GET') return json(200, { items: [...state.invitations.values()].filter((i) => q.state !== 'open' || i.state === 'open').map((i) => invitationView(state, i)) }), true;
    const inv = state.invitations.get(id);
    if (!inv) return err(404, 'not_found'), true;
    if (n === 2 && m === 'GET') return json(200, invitationView(state, inv)), true;
    if (n === 3 && seg[2] === 'respond' && m === 'POST') {
      if (inv.state === 'outdated') return err(409, 'invitation_outdated'), true;
      const e = state.events.get(inv.eventId);
      if (e) {
        e.myResponse = body.response;
        const me = e.attendees.find((a) => a.email === 'max@firma.de');
        if (me) me.response = body.response;
        if (body.calendarId) e.calendarId = body.calendarId;
      }
      inv.state = 'answered';
      state.lastInviteRespond = body;
      return json(200, { invitation: invitationView(state, inv), event: e ? fullEvent(state, e) : null }), true;
    }
    if (n === 3 && seg[2] === 'apply' && m === 'POST') { inv.state = 'applied'; return json(200, { invitation: invitationView(state, inv), event: null }), true; }
    if (n === 3 && seg[2] === 'dismiss' && m === 'POST') { inv.state = 'answered'; state.lastDismiss = body; return json(200, { ok: true }), true; }
  }

  // ── contacts ──
  if (seg[0] === 'addressbooks' || seg[0] === 'cards' || seg[0] === 'groups') {
    if (!need('contacts')) return true;
  }
  const visibleBooks = () => state.books.filter((b) => b.visible).map((b) => b.id);
  if (seg[0] === 'addressbooks') {
    if (n === 1 && m === 'GET') {
      return json(200, {
        items: state.books.map((b) => ({ ...b, count: [...state.cards.values()].filter((c) => c.addressbookId === b.id).length })),
        groups: [...state.groups.values()].map((g) => ({ id: g.id, name: g.name, color: g.color, count: g.members.length })),
        prefs: state.cardPrefs,
      }), true;
    }
    const b = state.books.find((x) => x.id === id);
    if (!b) return err(404, 'not_found'), true;
    if (n === 2 && m === 'PATCH') { for (const k of ['visible', 'name']) if (body[k] !== undefined) b[k] = body[k]; return json(200, { addressbook: b }), true; }
  }
  if (seg[0] === 'cards') {
    if (n === 1 && m === 'GET') {
      let list = [...state.cards.values()];
      const book = q.book && q.book !== 'all' ? Number(q.book) : null;
      list = list.filter((c) => (book ? c.addressbookId === book : visibleBooks().includes(c.addressbookId) && !c.linkId));
      if (q.group) { const g = state.groups.get(Number(q.group)); list = list.filter((c) => g && g.members.some((x) => x.contactId === c.id)); }
      if (q.q) { const f = fold(q.q); list = list.filter((c) => fold(`${display(c)} ${c.company || ''} ${c.emails.map((e) => e.value).join(' ')}`).includes(f)); }
      let deleted;
      if (q.since !== undefined) {
        const since = Number(q.since);
        list = list.filter((c) => c.version > since);
        deleted = state.tombstones.filter((t) => t.version > since).map((t) => t.id);
      }
      list.sort((a, b) => (sortKey(a) < sortKey(b) ? -1 : sortKey(a) > sortKey(b) ? 1 : a.id - b.id));
      const off = q.cursor ? Number(Buffer.from(q.cursor, 'base64url').toString()) : 0;
      const limit = Number(q.limit) || 200;
      const page = list.slice(off, off + limit);
      state.cardsAsked = (state.cardsAsked || 0) + 1;
      state.lastCardsQuery = q;
      return json(200, { items: page.map((c) => summary(state, c)), next: off + limit < list.length ? Buffer.from(String(off + limit)).toString('base64url') : null, version: state.version, ...(deleted ? { deleted } : {}) }), true;
    }
    if (n === 1 && m === 'POST') {
      const bookId = body.addressbookId || state.cardPrefs.defaultAddressbookId;
      const b = state.books.find((x) => x.id === bookId);
      if (!b) return err(404, 'not_found'), true;
      if (!b.writable) return err(409, 'read_only'), true;
      const c = { id: (state.nextId += 1), addressbookId: b.id, emails: [], phones: [], company: null, department: null, title: null, addresses: [], birthday: null, note: '', urls: [], linkId: null, name: {} };
      applyCard(state, c, body);
      state.cards.set(c.id, c);
      state.lastCardBody = body;
      return json(200, { card: fullCard(state, c) }), true;
    }
    if (n === 2 && seg[1] === 'settings' && m === 'PUT') { Object.assign(state.cardPrefs, body); return json(200, { prefs: state.cardPrefs }), true; }
    if (n === 2 && seg[1] === 'lookup' && m === 'GET') {
      const e = String(q.email || '').toLowerCase();
      const c = [...state.cards.values()].find((x) => x.emails.some((y) => y.value.toLowerCase() === e));
      return json(200, { card: c ? fullCard(state, c) : null, person: e === 'tim@firma.de' ? { userId: 7, name: 'Tim Brandt' } : null, recent: { name: '', sent: 2, received: 5, lastAt: Date.now() - DAY } }), true;
    }
    if (n === 2 && seg[1] === 'draft' && m === 'GET') {
      const e = String(q.email || '');
      const existing = [...state.cards.values()].find((x) => x.emails.some((y) => y.value.toLowerCase() === e.toLowerCase()));
      const msg = all.messages.get(Number(q.messageId));
      const nm = msg && msg.from && msg.from.name ? msg.from.name : '';
      const [given, ...rest] = nm.split(' ');
      return json(200, { draft: { name: { display: nm, given: given || '', family: rest.join(' ') }, emails: [{ value: e, type: 'work', primary: true }], phones: [{ value: '0221 555 12 34', type: 'work' }], company: 'Stadtwerke', title: null, addresses: [], birthday: null, note: '', urls: [], groups: [] }, existing: existing ? fullCard(state, existing) : null }), true;
    }
    if (state.master) {
      const r = masterRoute({ state, m, n, seg, q, body, json, err });
      if (r) return true;
    }
    if (n === 2 && seg[1] === 'duplicates' && m === 'GET') {
      const byMail = new Map();
      for (const c of state.cards.values()) {
        if (!visibleBooks().includes(c.addressbookId) || c.linkId) continue;
        for (const e of c.emails) { const k = e.value.toLowerCase(); if (!byMail.has(k)) byMail.set(k, []); byMail.get(k).push(c); }
      }
      const items = [...byMail.entries()].filter(([, cs]) => cs.length > 1)
        .filter(([, cs]) => !state.ignored.some((ig) => cs.every((c) => ig.includes(c.id))))
        .map(([k, cs]) => ({ key: `email:${k}`, reason: 'email', cards: cs.map((c) => summary(state, c)) }));
      return json(200, { items }), true;
    }
    if (n === 3 && seg[1] === 'duplicates' && seg[2] === 'ignore' && m === 'POST') { state.ignored.push(body.ids); return json(200, { ok: true }), true; }
    if (n === 2 && seg[1] === 'merge' && m === 'POST') {
      const primary = state.cards.get(body.primaryId);
      if (!primary) return err(404, 'not_found'), true;
      for (const oid of body.ids.filter((x) => x !== body.primaryId)) {
        const o = state.cards.get(oid);
        if (!o) continue;
        if (o.addressbookId === primary.addressbookId) {
          state.cards.delete(oid);
          state.tombstones.push({ id: oid, version: (state.version += 1) });
        } else {
          o.linkId = primary.id;
          o.version = (state.version += 1);
        }
      }
      primary.version = (state.version += 1);
      state.lastMerge = body;
      return json(200, { card: fullCard(state, primary) }), true;
    }
    if (n === 2 && seg[1] === 'import' && m === 'POST') {
      const count = (String(body.vcf || '').match(/BEGIN:VCARD/gi) || []).length;
      if (!count) return err(400, 'invalid_vcard'), true;
      state.imports.push(body);
      return json(200, { imported: count, updated: 0, skipped: 0 }), true;
    }
    if (n === 2 && seg[1] === 'export' && m === 'GET') {
      const vcf = [...state.cards.values()].map((c) => `BEGIN:VCARD\r\nVERSION:4.0\r\nFN:${display(c)}\r\nEND:VCARD\r\n`).join('');
      return json(200, { name: 'kontakte.vcf', mime: 'text/vcard', data: Buffer.from(vcf).toString('base64') }), true;
    }
    const c = state.cards.get(id);
    if (!c) return err(404, 'not_found'), true;
    const book = state.books.find((b) => b.id === c.addressbookId);
    if (n === 2 && m === 'GET') return json(200, fullCard(state, c)), true;
    if (n === 2 && m === 'PATCH') {
      const ownOnly = state.master && Object.keys(body).every((k) => ['favorite', 'mainPhone', 'etag'].includes(k));
      if (!book.writable && !ownOnly) return err(409, 'read_only'), true;
      if (body.etag && body.etag !== `"v${c.version}"`) return err(409, 'conflict', { current: fullCard(state, c) }), true;
      state.lastCardBody = body;
      if (!state.master) {
        applyCard(state, c, body);
        return json(200, { card: fullCard(state, c) }), true;
      }
      if (body.mainPhone !== undefined && body.mainPhone !== null && !(body.phones || c.phones).some((p) => digitsOf(p.value) === digitsOf(body.mainPhone))) return err(400, 'invalid', { field: 'mainPhone' }), true;
      if (body.favorite === true && !(c.favorite > 0)) {
        const favs = [...state.cards.values()].filter((x) => x.favorite > 0);
        if (favs.length >= 50) return err(409, 'limit', { max: 50 }), true;
        c.favorite = Math.max(0, ...favs.map((x) => x.favorite)) + 1;
      } else if (body.favorite === false) c.favorite = 0;
      if (body.mainPhone !== undefined) c.mainPhone = body.mainPhone === null ? null : digitsOf(body.mainPhone);
      // a value taken over from a linked card that the change removes goes back to that card (writeBack)
      const writeBack = [];
      for (const field of ['emails', 'phones', 'addresses']) {
        if (!body[field]) continue;
        const now = new Set(body[field].map((v) => valueKey(field, v)));
        for (const o of state.origins.filter((x) => x.cardId === c.id && x.field === field && !now.has(x.key))) {
          const src = state.cards.get(o.sourceId);
          if (!src || writeBack.some((w) => w.id === src.id)) continue;
          const sb = state.books.find((b) => b.id === src.addressbookId);
          writeBack.push(sb.writable ? { id: src.id, addressbookId: sb.id, ok: true } : { id: src.id, addressbookId: sb.id, ok: false, code: 'read_only' });
        }
      }
      const fields = Object.fromEntries(Object.entries(body).filter(([k]) => !['favorite', 'mainPhone', 'etag'].includes(k)));
      if (Object.keys(fields).length) applyCard(state, c, fields);
      else c.version = (state.version += 1);
      return json(200, { card: fullCard(state, c), writeBack }), true;
    }
    if (n === 2 && m === 'DELETE') {
      if (state.master && q.linked !== undefined && q.linked !== 'keep' && q.linked !== 'delete') return err(400, 'invalid', { field: 'linked' }), true;
      if (!book.writable) return err(409, 'read_only'), true;
      if (state.master) {
        state.lastDelete = { id: c.id, linked: q.linked || null };
        for (const l of [...state.cards.values()].filter((x) => x.linkId === c.id)) {
          const lb = state.books.find((b) => b.id === l.addressbookId);
          if (q.linked === 'delete' && lb.writable) { state.cards.delete(l.id); state.tombstones.push({ id: l.id, version: (state.version += 1) }); } else { l.linkId = null; l.version = (state.version += 1); }
        }
      }
      state.cards.delete(c.id);
      state.tombstones.push({ id: c.id, version: (state.version += 1) });
      for (const g of state.groups.values()) g.members = g.members.filter((x) => x.contactId !== c.id);
      return json(200, { ok: true }), true;
    }
    if (n === 3 && seg[2] === 'photo') {
      if (m === 'GET') { const ph = state.photos.get(c.id); return ph ? (json(200, { mime: ph.mime, size: Buffer.from(ph.data, 'base64').length, data: ph.data }), true) : (err(404, 'not_found'), true); }
      if (m === 'PUT') {
        if (!['image/jpeg', 'image/png'].includes(body.mime) || Buffer.from(body.data || '', 'base64').length > 256 * 1024) return err(413, 'too_large'), true;
        state.photos.set(c.id, { mime: body.mime, data: body.data, etag: `ph${Date.now()}` });
        c.version = (state.version += 1);
        return json(200, { card: fullCard(state, c) }), true;
      }
      if (m === 'DELETE') { state.photos.delete(c.id); c.version = (state.version += 1); return json(200, { card: fullCard(state, c) }), true; }
    }
    if (n === 3 && seg[2] === 'activity' && m === 'GET') {
      const mails = c.emails.map((e) => e.value.toLowerCase());
      const ms = [...all.messages.values()].filter((x) => mails.includes(String(x.from.address || '').toLowerCase())).sort((a, b) => b.date - a.date).slice(0, 5);
      const evs = [...state.events.values()].filter((e) => e.attendees.some((a) => mails.includes(a.email.toLowerCase())) || (e.organizer && mails.includes(e.organizer.email.toLowerCase())))
        .flatMap((e) => occurrences(state, e, Date.now() - 30 * DAY, Date.now() + 60 * DAY)).slice(0, 5);
      return json(200, { mails: ms.map(sum), events: evs }), true;
    }
  }
  if (seg[0] === 'groups') {
    const out = (g) => ({ id: g.id, name: g.name, color: g.color, count: g.members.length });
    if (n === 1 && m === 'POST') {
      if (!body.name) return err(400, 'invalid'), true;
      const g = { id: (state.nextId += 1), name: body.name, color: body.color || null, members: [] };
      state.groups.set(g.id, g);
      return json(200, { group: out(g) }), true;
    }
    const g = state.groups.get(id);
    if (!g) return err(404, 'not_found'), true;
    if (n === 2 && m === 'GET') return json(200, { group: out(g), members: g.members }), true;
    if (n === 2 && m === 'PATCH') { for (const k of ['name', 'color']) if (body[k] !== undefined) g[k] = body[k]; return json(200, { group: out(g) }), true; }
    if (n === 2 && m === 'DELETE') { state.groups.delete(g.id); return json(200, { ok: true }), true; }
    if (n === 3 && seg[2] === 'members' && m === 'POST') {
      for (const a of body.add || []) {
        const c = a.contactId ? state.cards.get(a.contactId) : null;
        g.members.push({ id: (state.nextId += 1), contactId: c ? c.id : null, name: c ? display(c) : (a.name || ''), email: c ? (c.emails[0] && c.emails[0].value) || null : a.email });
      }
      g.members = g.members.filter((x) => !(body.remove || []).includes(x.id));
      return json(200, { group: out(g), members: g.members }), true;
    }
  }
  return false;
}

/** The paths of Mail 1.4.0 below cards/ (only with `state.master`) → true when answered. */
function masterRoute({ state, m, n, seg, q, body, json, err }) {
  const reply = (st, b) => { json(st, b); return true; };
  if (n === 2 && seg[1] === 'duplicates' && m === 'GET') {
    const details = q.details === '1' || q.details === 'true';
    return reply(200, {
      items: dupGroups(state).map((g) => {
        const cards = g.ids.map((x) => state.cards.get(x));
        const item = { key: g.key, reason: g.reason, certain: g.certain, cards: cards.map((c) => summary(state, c)) };
        if (details) { item.details = cards.map((c) => ({ card: fullCard(state, c), source: sourceOf(state, c) })); item.preview = previewOf(state, cards); }
        return item;
      }),
    });
  }
  if (n === 3 && seg[1] === 'merge' && seg[2] === 'preview' && m === 'POST') {
    const cards = (body.ids || []).map((x) => state.cards.get(x)).filter(Boolean);
    if (cards.length < 2) return reply(400, { error: { code: 'invalid', field: 'ids' } });
    return reply(200, { preview: previewOf(state, cards) });
  }
  if (n === 2 && seg[1] === 'merge' && m === 'POST') {
    const ids = body.ids || [];
    if (ids.length < 2 || ids.some((x) => !state.cards.has(x))) return reply(404, { error: { code: 'not_found' } });
    state.lastMerge = body;
    const { m: master, mg } = mergeCards(state, ids, 'manual', null);
    return reply(200, { card: fullCard(state, master), mergeId: mg.id });
  }
  if (n === 3 && seg[1] === 'merge' && seg[2] === 'auto' && m === 'POST') {
    const done = [];
    for (const g of dupGroups(state).filter((x) => x.certain)) done.push(mergeCards(state, g.ids, 'auto', g.reason).mg);
    return reply(200, { merged: done.length, open: dupGroups(state).length, items: done.map(({ removed, ...x }) => x) });
  }
  if (n === 2 && seg[1] === 'merges' && m === 'GET') return reply(200, { items: [...state.merges].reverse().slice(0, Number(q.limit) || 50).map(({ removed, ...x }) => x) });
  if (n === 4 && seg[1] === 'merges' && seg[3] === 'undo' && m === 'POST') {
    const mg = state.merges.find((x) => x.id === Number(seg[2]));
    if (!mg || mg.undoneAt) return reply(404, { error: { code: 'not_found' } });
    const master = state.cards.get(mg.masterId);
    if (!master) return reply(404, { error: { code: 'not_found' } });
    const r = loosen(state, master, null, body.keepMaster === true);
    mg.undoneAt = mg.undoneAt || Date.now();
    state.lastUndo = { id: mg.id, ...body };
    return reply(200, r);
  }
  if (n === 2 && seg[1] === 'conflicts' && m === 'GET') {
    const ids = [...new Set(state.conflicts.map((x) => x.cardId))];
    return reply(200, { items: ids.map((x) => ({ card: summary(state, state.cards.get(x)), conflicts: state.conflicts.filter((y) => y.cardId === x).map((y) => conflictView(state, y)) })) });
  }
  if (n === 2 && seg[1] === 'favorites') {
    const out = () => ({ items: [...state.cards.values()].filter((c) => c.favorite > 0 && !c.linkId).sort((a, b) => a.favorite - b.favorite).map((c) => {
      const p = mainPhoneOf(c);
      const ph = state.photos.get(c.id);
      return { id: c.id, name: display(c), photo: !!ph, photoEtag: ph ? ph.etag : null, phone: p ? { value: p.value, type: p.type } : null, email: c.emails[0] ? c.emails[0].value : null };
    }) });
    if (m === 'GET') return reply(200, out());
    if (m === 'PUT') {
      if (!Array.isArray(body.ids) || body.ids.length > 50 || body.ids.some((x) => !state.cards.has(x))) return reply(400, { error: { code: 'invalid', field: 'ids' } });
      for (const c of state.cards.values()) c.favorite = 0;
      body.ids.forEach((x, i) => { state.cards.get(x).favorite = i + 1; });
      return reply(200, out());
    }
  }
  const c = state.cards.get(Number(seg[1]));
  if (!c) return false;
  if (n === 3 && seg[2] === 'unmerge' && m === 'POST') {
    const links = [...state.cards.values()].filter((x) => x.linkId === c.id).map((x) => x.id);
    if (body.ids && body.ids.some((x) => !links.includes(x))) return reply(404, { error: { code: 'not_found' } });
    state.lastUnmerge = { id: c.id, ...body };
    return reply(200, loosen(state, c, body.ids || null, body.keepMaster === true));
  }
  if (n === 5 && seg[2] === 'conflicts' && (seg[4] === 'accept' || seg[4] === 'dismiss') && m === 'POST') {
    const x = state.conflicts.find((y) => y.id === Number(seg[3]) && y.cardId === c.id);
    if (!x) return reply(404, { error: { code: 'not_found' } });
    state.conflicts = state.conflicts.filter((y) => y !== x);
    if (seg[4] === 'dismiss') { state.dismissed.push({ cardId: c.id, sourceId: x.sourceId, field: x.field, key: valueKey(x.field, x.value) }); c.version = (state.version += 1); return reply(200, { card: fullCard(state, c) }); }
    const mode = body.mode || (x.replaces ? 'replace' : 'add');
    state.lastAccept = { id: x.id, mode };
    if (Array.isArray(c[x.field])) {
      const i = mode === 'replace' && x.replaces ? c[x.field].findIndex((v) => valueKey(x.field, v) === valueKey(x.field, x.replaces)) : -1;
      if (i >= 0) c[x.field][i] = x.value; else c[x.field].push(x.value);
    } else c[x.field] = x.value;
    c.version = (state.version += 1);
    return reply(200, { card: fullCard(state, c) });
  }
  return false;
}

/** GET contacts?q= of Phase 2: contacts (one entry per address), groups, people, recent addresses. */
function contactSuggestions(all, q) {
  const s = fold(q);
  const out = [];
  if (all.features.includes('contacts')) {
    const state = all.pim;
    for (const c of state.cards.values()) {
      if (c.linkId) continue;
      for (const e of c.emails) if (fold(`${display(c)} ${e.value}`).includes(s)) out.push({ name: display(c), email: e.value, source: 'contact', contactId: c.id, photo: state.photos.has(c.id) });
    }
    for (const g of state.groups.values()) {
      if (fold(g.name).includes(s)) out.push({ name: g.name, email: null, source: 'group', groupId: g.id, members: g.members.filter((x) => x.email).map((x) => ({ name: x.name, email: x.email })) });
    }
  }
  return out;
}

module.exports = { pimState, pimRoute, contactSuggestions, fullEvent, invitationView };
