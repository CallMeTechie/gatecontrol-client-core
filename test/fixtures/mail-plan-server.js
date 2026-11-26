'use strict';

// Phase 3 of the fake Mail server (test/fixtures/mail-server.js, `mailServer({ plan: true })`): Mail 1.9.0 — free/busy
// with suggestions, sharing own GateControl calendars (people, groups, three levels), „Mit mir geteilt“ (a calendar of
// Sabine at „Lesen“, one of Tom's group at „Frei/Gebucht“, a Microsoft 365 calendar of another mailbox), the people and
// groups to share with, three resources (a car with approval, a room and a projector that confirm at once), bookings
// (two open requests — one free, one breaking a rule and in conflict —, a decided one, an own one) and resources as
// attendees of POST events. Without `plan` the features are missing and these paths answer 403 feature_off.
//
//   planState(now) → the state (state.plan.shares, shared, resources, bookings, …)
//   planRoute({ req, seg, url, body, state, json, err, sum, pimRoute }) → true when answered

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const FEATURES = ['freeBusy', 'calendarSharing', 'resources', 'bookingRequests'];

const midnight = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
const ymd = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const address = (id) => `resource-${id}@resources.gatecontrol.invalid`;

function planState(now) {
  const day0 = midnight(now);
  const at = (days, h, mi = 0) => { const d = new Date(day0); d.setDate(d.getDate() + days); d.setHours(h, mi, 0, 0); return d.getTime(); };
  const markus = { userId: 20, name: 'Markus B.' };
  const lisa = { userId: 21, name: 'Lisa M.' };
  const max = { userId: 1, name: 'Max' };
  const state = {
    at,
    nextId: 6000,
    people: [
      { id: 7, name: 'Sabine Keller', initials: 'SK', colorHex: '#F28CC2', email: 'sabine@firma.de' },
      { id: 8, name: 'Tom Brandt', initials: 'TB', colorHex: '#79B8FF', email: 'tim@firma.de' },
      { id: 9, name: 'Lisa Maier', initials: 'LM', colorHex: '#F5B544', email: 'lisa@firma.de' },
    ],
    groups: [
      { id: 3, name: 'Familie', path: 'Familie', members: 4 },
      { id: 4, name: 'Vertrieb', path: 'Firma › Vertrieb', members: 6 },
    ],
    // shares of the own calendar 1 (Privat)
    shares: [
      { id: 71, calendarId: 1, type: 'user', principalId: 7, level: 'write', accepted: true, createdAt: now - 5 * DAY },
      { id: 72, calendarId: 1, type: 'group', principalId: 3, level: 'read', accepted: false, createdAt: now - 4 * DAY },
      { id: 73, calendarId: 1, type: 'user', principalId: 8, level: 'freebusy', accepted: false, createdAt: now - DAY },
    ],
    shared: [
      { id: 50, name: 'Urlaube', color: '#F28CC2', owner: { userId: 7, name: 'Sabine Keller' }, level: 'read', via: 'user', group: null, visible: false, accepted: false, writable: false },
      { id: 51, name: 'Team', color: '#5FD3E0', owner: { userId: 8, name: 'Tom Brandt' }, level: 'freebusy', via: 'group', group: 'Vertrieb', visible: true, accepted: true, writable: false },
    ],
    sharedItems: [
      { key: '950', eventId: 950, calendarId: 50, occurrence: null, title: 'Sabine: Urlaub', start: at(2, 0), end: at(3, 0), allDay: true, startDate: ymd(at(2, 0)), endDate: ymd(at(2, 0)), timeZone: 'Europe/Berlin', location: null, online: null, status: 'confirmed', busy: 'oof', myResponse: null, recurring: false, attendees: 0, private: false, reminder: null, shared: 'read' },
      { key: 's:51:1:x', eventId: null, calendarId: 51, occurrence: null, title: 'Gebucht', start: at(0, 13), end: at(0, 14, 30), allDay: false, timeZone: 'Europe/Berlin', location: null, online: null, status: 'confirmed', busy: 'busy', myResponse: null, recurring: false, attendees: 0, private: true, reminder: null, shared: 'freebusy' },
      { key: 's:51:2:x', eventId: null, calendarId: 51, occurrence: null, title: 'Vorläufig', start: at(1, 9), end: at(1, 10), allDay: false, timeZone: 'Europe/Berlin', location: null, online: null, status: 'confirmed', busy: 'tentative', myResponse: null, recurring: false, attendees: 0, private: true, reminder: null, shared: 'freebusy' },
    ],
    // a calendar of the Microsoft 365 account that belongs to another mailbox
    accountCalendar: { id: 5, source: 'graph', accountId: 2, name: 'Team', color: '#B79CFF', kind: 'business', writable: true, visible: false, notify: true, isDefault: false, canInvite: true, canOnline: true, maxReminders: 1, state: 'ok', error: null, syncedAt: now, version: 1, sharedBy: { email: 'team@firma.de' } },
    resources: [
      { id: 11, name: 'Firmenwagen Kombi', kind: 'vehicle', location: 'Tiefgarage', seats: 5, equipment: null, color: '#79B8FF', approval: 'approval', approvers: ['Fuhrpark'], rules: { maxMinutes: 1440, horizonDays: 60, hours: null }, timeZone: 'Europe/Berlin', address: address(11) },
      { id: 12, name: 'Besprechungsraum 1', kind: 'room', location: '2. OG', seats: 8, equipment: 'Bildschirm', color: '#46E0A0', approval: 'auto', approvers: [], rules: { maxMinutes: 480, horizonDays: null, hours: { days: [1, 2, 3, 4, 5], from: '07:00', to: '20:00' } }, timeZone: 'Europe/Berlin', address: address(12) },
      { id: 13, name: 'Beamer', kind: 'device', location: 'Lager EG', seats: null, equipment: null, color: '#F5B544', approval: 'auto', approvers: [], rules: { maxMinutes: null, horizonDays: null, hours: null }, timeZone: 'Europe/Berlin', address: address(13) },
    ],
    bookings: [],
    decided: [],
    lastBook: null,
    lastDecide: null,
    lastFreeBusy: null,
    lastSuggest: null,
  };
  const res = (id) => { const r = state.resources.find((x) => x.id === id); return { id: r.id, name: r.name, kind: r.kind, color: r.color, location: r.location }; };
  const b = ({ res: rid, ...x }) => state.bookings.push({
    resourceId: rid, resource: res(rid), allDay: false, note: '', violations: [], conflicts: [], decidedBy: null, decidedAt: null, override: false, comment: '',
    createdAt: now - HOUR, updatedAt: now - HOUR, canDecide: false, day: [], eventId: null, ...x,
  });
  b({ id: 801, res: 11, title: 'Kunde Müller', start: at(1, 12), end: at(1, 15), state: 'pending', booker: markus, canDecide: true, day: [{ start: at(1, 8), end: at(1, 10), status: 'busy' }] });
  b({ id: 802, res: 11, title: 'Messe Köln', start: at(2, 0), end: at(4, 0), allDay: true, startDate: ymd(at(2, 0)), endDate: ymd(at(3, 0)), state: 'pending', booker: lisa, canDecide: true,
    violations: [{ rule: 'max_duration', limit: 1440 }], conflicts: [{ start: at(2, 8), end: at(2, 10) }] });
  b({ id: 803, res: 12, title: 'Kundentermin', start: at(-1, 10), end: at(-1, 11), state: 'confirmed', booker: lisa, decidedBy: max, decidedAt: now - 2 * DAY, override: true, comment: 'Ausnahmsweise' });
  b({ id: 804, res: 12, title: 'Sprint-Review', start: at(1, 14), end: at(1, 15), state: 'confirmed', booker: max, eventId: 302 });
  return state;
}

/** The blocks of a booking list for a resource: confirmed busy, requested pending. */
function resourceBusy(p, r, from, to, me = 1) {
  return p.bookings.filter((x) => x.resourceId === r.id && (x.state === 'pending' || x.state === 'confirmed') && x.start < to && x.end > from)
    .map((x) => ({ start: x.start, end: x.end, status: x.state === 'confirmed' ? 'busy' : 'pending', mine: x.booker.userId === me }));
}

function bookingView(p, x, tab) {
  return { ...x, canDecide: tab !== 'mine' && x.canDecide && x.state === 'pending', conflicts: x.state === 'pending' ? x.conflicts : [] };
}

function planRoute({ req, seg, url, body, state: all, json, err, sum, pimRoute }) {
  const p = all.plan;
  const pim = all.pim;
  const m = req.method;
  const q = Object.fromEntries(url.searchParams);
  const n = seg.length;
  const has = (f) => all.features.includes(f);
  const off = (feature) => (err(403, 'feature_off', { feature }), true);

  // GET calendars: the shared calendars too, the account calendar of another mailbox
  if (seg[0] === 'calendars' && n === 1 && m === 'GET' && has('calendar')) {
    return pimRoute({ req, route: seg.join('/'), seg, url, body, state: all, err, sum, json: (st, b) => json(st, st === 200 ? { ...b, shared: has('calendarSharing') ? p.shared : [] } : b) });
  }
  // GET events: the items of the shown shared calendars (or those asked for)
  if (seg[0] === 'events' && n === 1 && m === 'GET' && has('calendar')) {
    const from = Number(q.from);
    const to = Number(q.to);
    const want = q.calendars ? q.calendars.split(',') : null;
    return pimRoute({ req, route: seg.join('/'), seg, url, body, state: all, err, sum, json: (st, b) => {
      if (st !== 200 || !has('calendarSharing')) return json(st, b);
      const show = p.shared.filter((c) => (want ? want.includes(String(c.id)) : c.visible)).map((c) => c.id);
      const extra = p.sharedItems.filter((x) => show.includes(x.calendarId) && x.start < to && x.end > from);
      return json(st, { ...b, items: [...b.items, ...extra].sort((a, c) => a.start - c.start) });
    } });
  }
  // a read-only event of a shared calendar
  if (seg[0] === 'events' && n === 2 && seg[1] === '950' && m === 'GET') {
    const x = p.sharedItems[0];
    return json(200, { ...x, description: '', descriptionHtml: null, organizer: null, attendees: [], reminders: [], recurrence: null, seriesId: null, series: null, readOnly: true, canRespond: false, canEdit: false, canDelete: false, categories: [], invitationId: null, url: null, createdAt: 1, updatedAt: 1, etag: '"1-0"' }), true;
  }
  // resources as attendees: a GateControl calendar only, no series; the answer has `bookings`
  if (seg[0] === 'events' && (m === 'POST' || m === 'PATCH') && Array.isArray(body.attendees) && body.attendees.some((a) => a && a.role === 'resource')) {
    if (!has('resources')) return off('resources');
    const calId = m === 'POST' ? body.calendarId : (pim.events.get(Number(seg[1])) || {}).calendarId;
    const cal = pim.calendars.find((c) => c.id === calId);
    if (cal && cal.source !== 'local') return err(409, 'not_supported', { what: 'resource' }), true;
    if (body.recurrence) return err(409, 'not_supported', { what: 'resource_series' }), true;
    const wanted = body.attendees.filter((a) => a.role === 'resource').map((a) => p.resources.find((r) => r.address === a.email)).filter(Boolean);
    return pimRoute({ req, route: seg.join('/'), seg, url, body, state: all, err, sum, json: (st, b) => {
      if (st !== 200) return json(st, b);
      const bookings = wanted.map((r) => {
        const x = { id: (p.nextId += 1), resourceId: r.id, resource: { id: r.id, name: r.name, kind: r.kind, color: r.color, location: r.location }, title: body.title || b.event.title, start: b.event.start, end: b.event.end, allDay: false,
          state: r.approval === 'approval' ? 'pending' : 'confirmed', booker: { userId: 1, name: 'Max' }, eventId: b.event.eventId, note: '', violations: [], conflicts: [], decidedBy: null, decidedAt: null, override: false, comment: '', createdAt: Date.now(), updatedAt: Date.now(), canDecide: false, day: [] };
        p.bookings.push(x);
        return x;
      });
      return json(st, { ...b, bookings });
    } });
  }

  // ── free/busy ──
  if (seg[0] === 'freebusy') {
    if (!has('freeBusy')) return off('freeBusy');
    if (m !== 'POST') return false;
    if (n === 1) {
      p.lastFreeBusy = body;
      if (!(body.to > body.from) || body.to - body.from > 31 * DAY) return err(400, 'invalid', { field: 'to' }), true;
      const own = [...pim.events.values()].filter((e) => pim.calendars.find((c) => c.id === e.calendarId && c.visible) && !e.allDay && e.start < body.to && e.end > body.from);
      const items = [{ key: 'self', kind: 'self', email: 'max@firma.de', resourceId: null, userId: 1, name: 'Max', state: 'ok', blocks: own.map((e) => ({ start: e.start, end: e.end, status: e.busy === 'tentative' ? 'tentative' : 'busy' })) }];
      for (const email of body.attendees || []) {
        const who = p.people.find((x) => x.email === email);
        const r = p.resources.find((x) => x.address === email);
        if (r) continue;
        if (who && who.id === 7) items.push({ key: email, kind: 'person', email, resourceId: null, userId: 7, name: 'Sabine', state: 'ok', blocks: [{ start: p.at(0, 9), end: p.at(0, 10), status: 'tentative' }] });
        else if (who) items.push({ key: email, kind: 'person', email, resourceId: null, userId: who.id, name: who.name.split(' ')[0], state: 'ok', blocks: [{ start: p.at(0, 14), end: p.at(0, 15), status: 'busy' }, { start: p.at(1, 14), end: p.at(1, 15), status: 'busy' }] });
        else items.push({ key: email, kind: 'external', email, resourceId: null, userId: null, name: email.split('@')[0], state: 'unknown', blocks: [] });
      }
      const resIds = [...(body.resources || []), ...(body.attendees || []).map((e) => (p.resources.find((x) => x.address === e) || {}).id).filter(Boolean)];
      for (const id of [...new Set(resIds)]) {
        const r = p.resources.find((x) => x.id === id);
        if (!r) { items.push({ key: `resource:${id}`, kind: 'resource', email: null, resourceId: id, userId: null, name: '', state: 'unknown', blocks: [] }); continue; }
        items.push({ key: `resource:${id}`, kind: 'resource', email: null, resourceId: id, userId: null, name: r.name, state: 'ok',
          blocks: resourceBusy(p, r, body.from, body.to).map((x) => ({ start: x.start, end: x.end, status: x.status === 'busy' ? 'busy' : 'tentative' })) });
      }
      return json(200, { from: body.from, to: body.to, items }), true;
    }
    if (n === 2 && seg[1] === 'suggest') {
      p.lastSuggest = body;
      if (!(body.duration >= 5 && body.duration <= 1440)) return err(400, 'invalid', { field: 'duration' }), true;
      const unknown = (body.attendees || []).filter((e) => !p.people.some((x) => x.email === e) && !p.resources.some((x) => x.address === e));
      const starts = [p.at(1, 15), p.at(1, 16), p.at(2, 9), p.at(2, 10, 30)].slice(0, body.limit || 4);
      return json(200, { items: starts.map((s) => ({ start: s, end: s + body.duration * 60000 })), unknown, workHours: pim.calPrefs.workHours || { days: [1, 2, 3, 4, 5], from: '08:00', to: '18:00' }, timeZone: 'Europe/Berlin' }), true;
    }
    return false;
  }

  // ── sharing ──
  if (seg[0] === 'calendars' && n >= 3 && seg[2] === 'shares') {
    if (!has('calendarSharing')) return off('sharing');
    const cal = pim.calendars.find((c) => c.id === Number(seg[1]));
    if (!cal) return err(404, 'not_found'), true;
    if (cal.source !== 'local') return err(409, 'not_supported', { what: 'share' }), true;
    const view = (s) => {
      if (s.type === 'user') { const u = p.people.find((x) => x.id === s.principalId); return { id: s.id, type: 'user', principalId: s.principalId, name: u ? u.name : '', level: s.level, state: s.accepted ? 'accepted' : 'pending', members: null, createdAt: s.createdAt }; }
      const g = p.groups.find((x) => x.id === s.principalId);
      return { id: s.id, type: 'group', principalId: s.principalId, name: g ? g.path : '', level: s.level, state: 'group', members: g ? g.members : 0, createdAt: s.createdAt };
    };
    if (n === 3 && m === 'GET') return json(200, { items: p.shares.filter((s) => s.calendarId === cal.id).map(view), freeBusy: pim.calPrefs.freeBusy !== false }), true;
    if (n === 3 && m === 'POST') {
      if (!['user', 'group'].includes(body.type) || !['freebusy', 'read', 'write'].includes(body.level)) return err(400, 'invalid', { field: 'level' }), true;
      if (body.type === 'user' && body.id === 1) return err(400, 'invalid', { field: 'id' }), true;
      const known = body.type === 'user' ? p.people.some((x) => x.id === body.id) : p.groups.some((x) => x.id === body.id);
      if (!known) return err(404, 'not_found'), true;
      let s = p.shares.find((x) => x.calendarId === cal.id && x.type === body.type && x.principalId === body.id);
      if (s) s.level = body.level;
      else {
        if (p.shares.filter((x) => x.calendarId === cal.id).length >= 50) return err(403, 'limit', { max: 50 }), true;
        s = { id: (p.nextId += 1), calendarId: cal.id, type: body.type, principalId: body.id, level: body.level, accepted: false, createdAt: Date.now() };
        p.shares.push(s);
      }
      return json(200, { share: view(s) }), true;
    }
    const s = p.shares.find((x) => x.id === Number(seg[3]) && x.calendarId === cal.id);
    if (!s) return err(404, 'not_found'), true;
    if (n === 4 && m === 'PATCH') { if (!['freebusy', 'read', 'write'].includes(body.level)) return err(400, 'invalid', { field: 'level' }), true; s.level = body.level; return json(200, { share: view(s) }), true; }
    if (n === 4 && m === 'DELETE') { p.shares = p.shares.filter((x) => x !== s); return json(200, { ok: true }), true; }
    return false;
  }
  if (seg[0] === 'shared') {
    if (!has('calendarSharing')) return off('sharing');
    if (n === 1 && m === 'GET') {
      const c = p.accountCalendar;
      return json(200, { items: p.shared, accounts: [{ calendarId: c.id, accountId: c.accountId, name: c.name, color: c.color, owner: { email: c.sharedBy.email }, writable: c.writable, visible: c.visible }] }), true;
    }
    if (n === 2 && m === 'PATCH') {
      const x = p.shared.find((c) => c.id === Number(seg[1]));
      if (!x) return err(404, 'not_found'), true;
      if (body.visible !== undefined) { x.visible = body.visible; if (body.visible) x.accepted = true; }
      if (body.color !== undefined) x.color = body.color || '#5FD3E0';
      return json(200, { item: x }), true;
    }
    return false;
  }
  if (seg[0] === 'principals' && n === 1 && m === 'GET') {
    if (!has('calendarSharing')) return off('sharing');
    const text = String(q.q || '').trim().toLowerCase();
    if (text.length < 2) return json(200, { items: [] }), true;
    const users = p.people.filter((u) => u.name.toLowerCase().includes(text)).map((u) => ({ type: 'user', id: u.id, name: u.name, initials: u.initials, color: u.colorHex, email: u.email }));
    const groups = p.groups.filter((g) => `${g.name} ${g.path}`.toLowerCase().includes(text)).map((g) => ({ type: 'group', id: g.id, name: g.name, sub: g.path !== g.name ? g.path : null, members: g.members }));
    return json(200, { items: [...users, ...groups] }), true;
  }

  // ── resources and bookings ──
  if (seg[0] === 'resources') {
    if (!has('resources')) return off('resources');
    if (n === 1 && m === 'GET') {
      const from = q.from ? Number(q.from) : null;
      const to = q.to ? Number(q.to) : null;
      if (from !== null && (!(to > from) || to - from > 31 * DAY)) return err(400, 'invalid', { field: 'to' }), true;
      const list = p.resources.filter((r) => !q.kind || r.kind === q.kind).map((r) => (from !== null ? { ...r, busy: resourceBusy(p, r, from, to) } : r));
      return json(200, { items: list, kinds: ['room', 'vehicle', 'device', 'other'] }), true;
    }
    const r = p.resources.find((x) => x.id === Number(seg[1]));
    if (!r) return err(404, 'not_found'), true;
    if (n === 3 && seg[2] === 'book' && m === 'POST') {
      p.lastBook = { resourceId: r.id, ...body };
      const start = body.allDay ? midnight(Date.parse(`${body.startDate}T12:00:00`)) : body.start;
      const end = body.allDay ? midnight(Date.parse(`${body.endDate || body.startDate}T12:00:00`)) + DAY : body.end;
      if (start < Date.now() - HOUR && !body.allDay) return err(400, 'invalid', { field: 'start', reason: 'past' }), true;
      const clash = resourceBusy(p, r, start, end).filter((x) => x.status === 'busy');
      if (clash.length) return err(409, 'resource_busy', { resourceId: r.id, name: r.name, conflicts: clash.map((x) => ({ start: x.start, end: x.end })) }), true;
      const violations = r.rules.maxMinutes && (end - start) / 60000 > r.rules.maxMinutes ? [{ rule: 'max_duration', limit: r.rules.maxMinutes }] : [];
      if (violations.length && r.approval === 'auto') return err(409, 'rule_violation', { resourceId: r.id, name: r.name, violations }), true;
      const calId = body.calendarId || pim.calPrefs.defaultCalendarId || 1;
      const ev = { id: (pim.nextId += 1), calendarId: calId, title: body.title || r.name, allDay: !!body.allDay, start, end, location: [r.name, r.location].filter(Boolean).join(', '), online: null, status: 'confirmed', busy: 'busy',
        myResponse: 'organizer', attendees: [{ name: r.name, email: r.address, role: 'resource', response: r.approval === 'approval' ? 'needs_action' : 'accepted' }], organizer: { name: 'Max', email: 'max@gmx.de', self: true },
        description: body.note || '', descriptionHtml: null, reminders: [], recurrence: null, private: false, deleted: [], updatedAt: Date.now(), sequence: 0, createdAt: Date.now(),
        ...(body.allDay ? { startDate: body.startDate, endDate: body.endDate || body.startDate } : {}) };
      pim.events.set(ev.id, ev);
      const x = { id: (p.nextId += 1), resourceId: r.id, resource: { id: r.id, name: r.name, kind: r.kind, color: r.color, location: r.location }, title: ev.title, start, end, allDay: !!body.allDay,
        ...(body.allDay ? { startDate: body.startDate, endDate: body.endDate || body.startDate } : {}), state: r.approval === 'approval' ? 'pending' : 'confirmed', booker: { userId: 1, name: 'Max' }, eventId: ev.id,
        note: body.note || '', violations, conflicts: [], decidedBy: null, decidedAt: null, override: false, comment: '', createdAt: Date.now(), updatedAt: Date.now(), canDecide: false, day: [] };
      p.bookings.push(x);
      const { fullEvent } = require('./mail-pim-server');
      return json(200, { event: fullEvent(pim, ev), sent: { mail: 0, internal: 0 }, bookings: [x] }), true;
    }
    return false;
  }
  if (seg[0] === 'bookings') {
    if (!has('resources')) return off('resources');
    if (n === 1 && m === 'GET') {
      const st = q.state || 'mine';
      const open = has('bookingRequests') ? p.bookings.filter((x) => x.state === 'pending' && x.canDecide) : [];
      let items;
      if (st === 'open') items = open;
      else if (st === 'done') items = has('bookingRequests') ? p.bookings.filter((x) => x.state !== 'pending' && x.booker.userId !== 1) : [];
      else items = p.bookings.filter((x) => x.booker.userId === 1);
      return json(200, { items: items.map((x) => bookingView(p, x, st)), counts: { open: open.length } }), true;
    }
    const x = p.bookings.find((b) => b.id === Number(seg[1]));
    if (!x) return err(404, 'not_found'), true;
    if (n === 2 && m === 'GET') return json(200, bookingView(p, x, x.booker.userId === 1 ? 'mine' : 'open')), true;
    if (n === 2 && m === 'DELETE') {
      if (x.booker.userId !== 1) return err(403, 'forbidden'), true;
      x.state = 'cancelled';
      return json(200, { ok: true }), true;
    }
    if (n === 3 && seg[2] === 'decide' && m === 'POST') {
      p.lastDecide = { id: x.id, ...body };
      if (!x.canDecide) return err(403, 'forbidden'), true;
      if (x.state !== 'pending') return err(409, 'already_decided', { state: x.state, decidedBy: x.decidedBy, decidedAt: x.decidedAt }), true;
      if (body.decision === 'approve' && x.conflicts.length) return err(409, 'resource_busy', { resourceId: x.resourceId, name: x.resource.name, conflicts: x.conflicts }), true;
      if (body.decision === 'approve' && x.violations.length && !body.override) return err(409, 'rule_violation', { resourceId: x.resourceId, name: x.resource.name, violations: x.violations }), true;
      Object.assign(x, { state: body.decision === 'approve' ? 'confirmed' : 'declined', decidedBy: { userId: 1, name: 'Max' }, decidedAt: Date.now(), override: !!body.override, comment: body.comment || '' });
      return json(200, { booking: bookingView(p, x, 'done') }), true;
    }
    return false;
  }
  return false;
}

module.exports = { planState, planRoute, PLAN_FEATURES: FEATURES };
