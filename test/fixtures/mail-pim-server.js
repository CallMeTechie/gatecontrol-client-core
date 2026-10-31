'use strict';

// Phase 2 of the fake Mail server (test/fixtures/mail-server.js): calendar and contacts of the client API "C3" —
// calendars with overlays and settings, occurrences of a range (a weekly series expanded), an event with etag and
// conflict, create / change / delete / respond, invitations (one in mail 106), address books, contacts with summaries,
// `since` and tombstones, photos, lookup, activity, "Als Kontakt speichern", duplicates and merge, vCard import / export,
// groups and their members; GET contacts?q= with contacts and groups.
//
//   pimState(now) → the state (state.calendars, events, invitations, books, cards, groups, …)
//   pimRoute({ req, route, seg, url, body, state, json, err, sum }) → true when answered

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

const midnight = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
const ymd = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const fold = (s) => String(s || '').toLowerCase().replace(/ß/g, 'ss').normalize('NFD').replace(/[̀-ͯ]/g, '');

function pimState(now) {
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
    calPrefs: { defaultCalendarId: 1, view: 'week', weekStart: 1, workWeek: false, timeZone: 'Europe/Berlin', reminders: true, defaultReminder: 15, allDayReminder: 1080 },
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
    version: (state.version += 1), updatedAt: now, ...c, name: { display: '', given: '', family: '', middle: null, prefix: null, suffix: null, nickname: null, ...c.name },
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
  return state;
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
    reminders: e.reminders, recurrence: e.recurrence, seriesId: occ ? e.id : null, readOnly: !cal.writable, canRespond: cal.writable && attendeeOf, canEdit: cal.writable && !attendeeOf, canDelete: cal.writable,
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
      if (!book.writable) return err(409, 'read_only'), true;
      if (body.etag && body.etag !== `"v${c.version}"`) return err(409, 'conflict', { current: fullCard(state, c) }), true;
      applyCard(state, c, body);
      state.lastCardBody = body;
      return json(200, { card: fullCard(state, c) }), true;
    }
    if (n === 2 && m === 'DELETE') {
      if (!book.writable) return err(409, 'read_only'), true;
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
