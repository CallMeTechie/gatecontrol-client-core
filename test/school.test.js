'use strict';

// "Schule" (plugin gatecontrol-schule): the pure helpers (utils/school.js —
// argument checks, cleaned answers, push context), the service
// (services/school.js — availability from the plugin list, messages /
// absences only with plugin 1.4.0, cache and offline copy, Schule pushes,
// toast click → page), its IPC (school:*) and the school.* texts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const school = require('../src/utils/school');
const SchoolService = require('../src/services/school');
const MessengerApi = require('../src/services/messenger-api');
const NotificationCenter = require('../src/services/notification-center');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const { MessengerError } = MessengerApi;
const tick = () => new Promise((r) => setImmediate(r));

const TIMETABLE = {
  ok: true,
  updatedAt: 1760940000000,
  students: [{
    id: 3, name: 'Lena', userId: 9, klasse: '5b', color: '#2fbf71', avatarUrl: '/avatars/lenaAvatarFile00001.webp',
    days: [
      {
        date: '2026-10-20',
        lessons: [
          { start: '09:50', end: '10:35', period: 3, subject: 'E', subjectLong: 'Englisch', teacher: 'SCH', room: '104', state: 'cancelled', info: 'Lehrkraft krank' },
          { start: '08:00', end: '08:45', period: 1, periodEnd: 2, subject: 'M', subjectLong: 'Mathematik', subjectOld: 'D', teacher: 'MUE', teacherOld: 'SCH', room: '201', roomOld: '104', state: 'changed', substText: 'Vertretung\u0007' },
          { start: '25:00', end: '26:00', subject: 'X', state: 'normal' },
          { start: '11:40', end: '12:25', subject: 'BIO', subjectLong: 'Biologie', teacher: 'KLE', room: 'NW1', state: 'weird' },
        ],
        homework: [{ subject: 'M', text: 'S. 42 Nr. 3\r\nund 4', givenDate: '2026-10-17', completed: true }, { foo: 1 }],
        exams: [{ subject: 'D', subjectLong: 'Deutsch', name: 'Klassenarbeit 2', start: '10:45', end: '11:30', type: 'Klassenarbeit', text: 'Gedichte' }],
      },
      { date: '2026-10-21', holiday: 'Brückentag', lessons: [] },
      { date: 'gestern', lessons: [] },
    ],
  }, { id: 'x', name: 'Bad' }, { id: 4, name: 'Tom', color: 'red', avatarUrl: 'https://evil.example/a.png', days: [] }],
};

const CHANGES = {
  ok: true,
  changes: [
    { id: 11, studentId: 3, student: 'Lena', date: '2026-10-20', start: '09:50', end: '10:35', period: 3, kind: 'cancelled', subject: 'E', subjectLong: 'Englisch', teacher: 'SCH', room: '104', detectedAt: 1760940000000, pushed: true },
    { id: 12, studentId: 3, student: 'Lena', date: '2026-10-21', start: '08:00', end: '08:45', kind: 'exploded', subject: 'M', detectedAt: 1760950000000 },
    { id: 13, studentId: 4, student: 'Tom', date: '2026-10-22', start: '08:00', end: '08:45', kind: 'extra', subject: 'SP', detectedAt: 1760960000000, pushed: false },
  ],
};

describe('utils/school', () => {
  it('ranges and days', () => {
    assert.deepEqual(school.rangeArgs('2026-10-19', '2026-10-25'), { from: '2026-10-19', to: '2026-10-25' });
    assert.deepEqual(school.rangeArgs('2026-10-19', '2026-11-01'), { from: '2026-10-19', to: '2026-11-01' }); // 14 days
    assert.equal(school.rangeArgs('2026-10-19', '2026-11-02'), null); // 15 days
    assert.equal(school.rangeArgs('2026-10-25', '2026-10-19'), null);
    assert.equal(school.rangeArgs('2026-02-30', '2026-03-01'), null);
    assert.equal(school.rangeArgs('2026-10-19', undefined), null);
    assert.equal(school.daysArg(undefined, school.CHANGES_DAYS), 7);
    assert.equal(school.daysArg('14', school.CHANGES_DAYS), 14);
    assert.equal(school.daysArg(31, school.CHANGES_DAYS), null);
    assert.equal(school.daysArg(0, school.CHANGES_DAYS), null);
    assert.equal(school.daysArg(60, school.ABSENCES_DAYS), 60);
    assert.equal(school.addDays('2026-10-31', 1), '2026-11-01');
  });

  it('messages / absences exist from plugin 1.4.0', () => {
    assert.equal(school.messagesSupported('1.4.0'), true);
    assert.equal(school.messagesSupported('1.10.2'), true);
    assert.equal(school.messagesSupported('1.3.0'), false);
    assert.equal(school.messagesSupported(null), null);
    assert.equal(school.messagesSupported('dev'), null);
  });

  it('cleans the timetable: known fields, valid values, lessons by time', () => {
    const r = school.normalizeTimetable(TIMETABLE);
    assert.equal(r.updatedAt, 1760940000000);
    assert.deepEqual(r.students.map((s) => s.id), [3, 4]);
    const [lena, tom] = r.students;
    assert.equal(lena.color, '#2FBF71');
    assert.equal(lena.avatarUrl, '/avatars/lenaAvatarFile00001.webp');
    assert.equal(tom.color, null);
    assert.equal(tom.avatarUrl, null, 'only /avatars/ of the own server');
    assert.deepEqual(lena.days.map((d) => d.date), ['2026-10-20', '2026-10-21']);
    const day = lena.days[0];
    assert.deepEqual(day.lessons.map((l) => [l.start, l.state]), [['08:00', 'changed'], ['09:50', 'cancelled'], ['11:40', 'normal']]);
    assert.deepEqual(day.lessons[0], {
      start: '08:00', end: '08:45', period: 1, periodEnd: 2, subject: 'M', subjectLong: 'Mathematik', subjectOld: 'D',
      teacher: 'MUE', teacherOld: 'SCH', room: '201', roomOld: '104', state: 'changed', info: null, substText: 'Vertretung', text: null,
    });
    assert.deepEqual(day.homework, [{ subject: 'M', subjectLong: null, text: 'S. 42 Nr. 3\nund 4', givenDate: '2026-10-17', completed: true }]);
    assert.equal(day.exams[0].name, 'Klassenarbeit 2');
    assert.equal(lena.days[1].holiday, 'Brückentag');
    assert.deepEqual(school.normalizeTimetable(null), { updatedAt: null, students: [] });
  });

  it('cleans changes, messages and absences', () => {
    const c = school.normalizeChanges(CHANGES).changes;
    assert.deepEqual(c.map((x) => x.id), [13, 11], 'unknown kinds dropped, newest first');
    assert.equal(c[1].pushed, true);
    assert.equal(c[0].pushed, false);

    const m = school.normalizeMessages({ messages: [
      { id: 5, accountId: 1, studentIds: [3, 'x'], subject: 'Elternabend', preview: 'Liebe Eltern', body: 'Liebe Eltern,\r\nam Montag …', sender: 'Frau Schulz', sentAt: '2026-10-19T08:00:00Z', hasAttachments: true, isNew: true },
      { id: 6, subject: 'Alt', sentAt: 1760000000000 },
      { subject: 'ohne id' },
    ] }).messages;
    assert.deepEqual(m.map((x) => x.id), [5, 6]);
    assert.deepEqual(m[0].studentIds, [3]);
    assert.equal(m[0].body, 'Liebe Eltern,\nam Montag …');
    assert.equal(m[0].sentAt, Date.parse('2026-10-19T08:00:00Z'));
    assert.equal(m[1].isNew, false);

    const a = school.normalizeAbsences({ absences: [
      { id: 1, studentId: 3, date: '2026-10-01', start: null, end: null, reason: 'Krank', excused: true },
      { id: 2, studentId: 3, date: '2026-10-14', start: '08:00', end: '09:30', excused: null, text: 'Arzt' },
      { id: 3, studentId: 3, date: '2026-10-07', endDate: '2026-10-09', excused: false },
      { id: 4, date: 'nie' },
    ] }).absences;
    assert.deepEqual(a.map((x) => [x.id, x.excused]), [[2, null], [3, false], [1, true]]);
    assert.equal(a[1].endDate, '2026-10-09');
  });

  it('push context: topic or route, kind, child, day, message', () => {
    assert.deepEqual(school.pushContext({ topic: 'plugin:gatecontrol-schule:changes', data: { route: 'plg-gatecontrol-schule', schule: { studentId: 3, date: '2026-10-20' } } }),
      { kind: 'changes', studentId: 3, date: '2026-10-20', messageId: null });
    assert.deepEqual(school.pushContext({ topic: 'plugin:gatecontrol-schule:messages', data: { schule: { studentId: 3, messageId: 77 } } }),
      { kind: 'messages', studentId: 3, date: null, messageId: 77 });
    assert.deepEqual(school.pushContext({ topic: 'plugin:gatecontrol-schule:default', data: { route: 'plg-gatecontrol-schule', schule: { kind: 'exams', date: '2026-10-21' } } }),
      { kind: 'exams', studentId: null, date: '2026-10-21', messageId: null });
    assert.equal(school.pushContext({ topic: 'plugin:gatecontrol-familie:rules', data: { schule: { studentId: 3 } } }), null);
    assert.equal(school.pushContext({ topic: 'devices', data: null }), null);
    assert.equal(school.pushContext(null), null);
  });
});

/** Fake transport: GET path → answer or thrown error. */
function fakeApi(routes = {}) {
  const api = { calls: [], routes, scopeValue: 'https://gc\nkey' };
  api.scope = () => api.scopeValue;
  api._call = async (method, path, opts = {}) => {
    api.calls.push([method, path, opts.params || null]);
    const key = path.replace(school.API_BASE, '');
    let r = api.routes[key];
    if (typeof r === 'function') r = r(opts.params);
    if (r instanceof Error) throw r;
    if (r === undefined) throw new MessengerError('HTTP 404', { status: 404, code: 'NOT_FOUND' });
    return JSON.parse(JSON.stringify(r));
  };
  api.avatar = async (url) => { api.calls.push(['AVATAR', url]); return { mime: 'image/webp', data: Buffer.from('RIFF') }; };
  return api;
}

const plugins = (version = '1.4.0', extra = []) => ({ ok: true, plugins: [{ id: 'gatecontrol-messenger', version: '1.4.1', tab: { label: 'Chats' } }, { id: 'gatecontrol-schule', name: 'Schule', version, tab: null }, ...extra] });

function service(routes, opts = {}) {
  let now = opts.now || 1760940000000;
  const api = fakeApi({ '/api/v1/client/plugins': plugins(), 'app/timetable': TIMETABLE, 'app/changes': CHANGES, ...routes });
  const s = new SchoolService({ api, log, timing: { recheckMs: 1e9, retryMinMs: 1e9 }, now: () => now, ...opts.extra });
  const states = [];
  const pushes = [];
  s.on('state', (x) => states.push(x));
  s.on('push', (x) => pushes.push(x));
  return { s, api, states, pushes, setNow: (v) => { now = v; } };
}

describe('SchoolService', () => {
  it('is available while the plugin list names gatecontrol-schule', async () => {
    const { s, api, states } = service();
    assert.equal(s.status().state, 'unknown');
    const st = await s.check();
    assert.equal(st.state, 'available');
    assert.equal(st.version, '1.4.0');
    assert.deepEqual(st.features, { messages: true, absences: true });
    assert.equal(states.length, 1);
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [{ id: 'gatecontrol-messenger', version: '1.4.1' }] };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'not_installed']);
    delete api.routes['/api/v1/client/plugins'];
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'unsupported']);
    assert.equal(states.length, 3);
  });

  it('a network error keeps the page; without it the state is error', async () => {
    const { s, api } = service();
    api.routes['/api/v1/client/plugins'] = new MessengerError('down', { code: 'network' });
    assert.equal((await s.check()).state, 'error');
    api.routes['/api/v1/client/plugins'] = plugins();
    assert.equal((await s.check()).state, 'available');
    api.routes['/api/v1/client/plugins'] = new MessengerError('down', { code: 'network' });
    const st = await s.check();
    assert.deepEqual([st.state, st.reason], ['available', 'network']);
  });

  it('older plugins have no messages / absences', async () => {
    const { s, api } = service({}, {});
    api.routes['/api/v1/client/plugins'] = plugins('1.3.0');
    assert.deepEqual((await s.check()).features, { messages: false, absences: false });
    await assert.rejects(s.messages(), (e) => e.code === 'unsupported');
    assert.ok(!api.calls.some((c) => String(c[1]).includes('app/messages')), 'not even asked');
  });

  it('unknown version: a 404 of the route hides the tab, an answer shows it', async () => {
    const { s, api, states } = service({ 'app/absences': { ok: true, absences: [{ id: 1, studentId: 3, date: '2026-10-01', excused: true }] } });
    api.routes['/api/v1/client/plugins'] = plugins(null);
    assert.deepEqual((await s.check()).features, { messages: null, absences: null });
    await assert.rejects(s.messages({ days: 30 }), (e) => e.code === 'unsupported' && e.status === 404);
    const r = await s.absences({ days: 60 });
    assert.equal(r.absences.length, 1);
    assert.deepEqual(s.status().features, { messages: false, absences: true });
    assert.deepEqual(states.at(-1).features, { messages: false, absences: true });
    assert.deepEqual(api.calls.find((c) => c[1].endsWith('app/absences'))[2], { days: 60 });
  });

  it('timetable: checked range, cleaned answer, cache, refresh', async () => {
    const { s, api, setNow } = service();
    await assert.rejects(s.timetable({ from: '2026-10-19', to: '2026-11-19' }), (e) => e.code === 'invalid');
    const a = await s.timetable({ from: '2026-10-19', to: '2026-10-25' });
    assert.equal(a.ok, true);
    assert.equal(a.stale, false);
    assert.deepEqual(a.students.map((x) => x.id), [3, 4]);
    assert.deepEqual(api.calls.at(-1), ['GET', `${school.API_BASE}app/timetable`, { from: '2026-10-19', to: '2026-10-25' }]);
    const n = api.calls.length;
    await s.timetable({ from: '2026-10-19', to: '2026-10-25' });
    assert.equal(api.calls.length, n, 'served from the cache');
    await s.timetable({ from: '2026-10-19', to: '2026-10-25', refresh: true });
    assert.equal(api.calls.length, n + 1);
    setNow(1760940000000 + 61000);
    await s.timetable({ from: '2026-10-19', to: '2026-10-25' });
    assert.equal(api.calls.length, n + 2, 'older than a minute');
  });

  it('offline: the last copy comes back as stale, refusals are thrown', async () => {
    const { s, api } = service();
    await s.changes({ days: 7 });
    api.routes['app/changes'] = new MessengerError('down', { code: 'network' });
    const r = await s.changes({ days: 7, refresh: true });
    assert.equal(r.stale, true);
    assert.equal(r.changes.length, 2);
    api.routes['app/changes'] = new MessengerError('forbidden', { status: 403, code: 'FORBIDDEN' });
    await assert.rejects(s.changes({ days: 7, refresh: true }), (e) => e.code === 'FORBIDDEN');
    await assert.rejects(s.changes({ days: 99 }), (e) => e.code === 'invalid');
  });

  it('a new server drops answers and asks again', async () => {
    const { s, api } = service();
    s.start();
    await tick();
    await s.timetable({ from: '2026-10-19', to: '2026-10-25' });
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    const st = await s.resetForNewServer();
    assert.equal(st.state, 'unavailable');
    const tt = () => api.calls.filter((c) => String(c[1]).endsWith('app/timetable')).length;
    const n = tt();
    await s.timetable({ from: '2026-10-19', to: '2026-10-25' });
    assert.equal(tt(), n + 1, 'not from the old cache');
    s.stop();
  });

  it('avatars are fetched once', async () => {
    const { s, api } = service();
    await s.avatar('/avatars/lenaAvatarFile00001.webp');
    await s.avatar('/avatars/lenaAvatarFile00001.webp');
    assert.equal(api.calls.filter((c) => c[0] === 'AVATAR').length, 1);
  });
});

function center() {
  class N extends EventEmitter { constructor(o) { super(); this.opts = o; N.created.push(this); } show() {} close() {} static isSupported() { return true; } }
  N.created = [];
  const push = new EventEmitter();
  Object.assign(push, { ack: async () => ({ ok: true }), fetchInbox: async () => ({ ok: true, items: [], unread: 0 }), start() {}, stop() {}, restart() {}, applySettings() {}, status: () => ({ state: 'connected' }) });
  const store = createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } });
  const nc = new NotificationCenter({ store, log, pushClient: push, Notification: N, platform: 'win32', protocol: 'gatecontrol-pro', showWindow() {}, now: () => Date.parse('2026-10-20T06:00:00Z') });
  const navigate = [];
  nc.on('navigate', (x) => navigate.push(x));
  return { nc, N, push, navigate };
}

const schoolPush = (seq, topic, schule) => ({
  seq, id: seq + 500, topic, priority: 'normal', title: 'Lena: Englisch fällt aus', body: '3. Std.', created_at: '2026-10-20T05:59:00Z',
  expires_at: '2026-10-22T05:59:00Z', silent: false, data: { route: 'plg-gatecontrol-schule', schule },
});

describe('SchoolService and the notification center', () => {
  it('a Schule push drops the cache and tells the page', async () => {
    const { nc } = center();
    const { s, api, pushes } = service({}, { extra: { notificationCenter: nc } });
    s.start();
    await tick();
    await s.changes();
    nc.handleNotification(schoolPush(1, 'plugin:gatecontrol-schule:changes', { studentId: 3, date: '2026-10-20' }));
    nc.handleNotification({ ...schoolPush(2, 'devices', null), data: { route: 'gateways' } });
    assert.deepEqual(pushes, [{ kind: 'changes', studentId: 3, date: '2026-10-20', messageId: null, notificationId: 501 }]);
    const n = api.calls.length;
    await s.changes();
    assert.equal(api.calls.length, n + 1, 'asked again');
    s.stop();
  });

  it('toast click opens the page while it exists, else the inbox', async () => {
    const { nc, N, navigate } = center();
    const { s, api } = service({}, { extra: { notificationCenter: nc } });
    s.start();
    await tick();
    nc.handleNotification(schoolPush(1, 'plugin:gatecontrol-schule:exams', { studentId: 3, date: '2026-10-21', kind: 'exams' }));
    N.created[0].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'plg-gatecontrol-schule', id: 501, context: { kind: 'exams', studentId: 3, date: '2026-10-21', messageId: null } });

    // other entries keep opening the inbox
    nc.handleNotification({ ...schoolPush(2, 'devices', null), data: null });
    N.created[1].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 502 });

    // plugin gone → the inbox again
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    await s.check();
    nc.handleNotification(schoolPush(3, 'plugin:gatecontrol-schule:changes', { studentId: 3, date: '2026-10-20' }));
    N.created[2].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 503 });

    // stop() removes the resolver
    s.stop();
    assert.equal(nc.clickTarget(nc.get(501)), null);
  });

  it('addClickRoute: app routes only, a failing resolver means inbox', () => {
    const { nc } = center();
    assert.throws(() => nc.addClickRoute('inbox', () => true), TypeError);
    assert.throws(() => nc.addClickRoute('https://x', () => true), TypeError);
    const off = nc.addClickRoute('plg-demo', () => { throw new Error('boom'); });
    assert.equal(nc.clickTarget({ id: 1, topic: 'x' }), null);
    off();
    nc.addClickRoute('plg-demo', () => true);
    assert.deepEqual(nc.clickTarget({ id: 1 }), { route: 'plg-demo', context: null });
  });
});

describe('school:* IPC', () => {
  function register(s) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', school: s,
    });
    return { handlers, sent };
  }

  it('channels, argument checks and events', async () => {
    const { s } = service();
    const { handlers, sent } = register(s);
    for (const ch of ['school:status', 'school:check', 'school:timetable', 'school:changes', 'school:messages', 'school:absences', 'school:avatar']) assert.ok(handlers[ch], ch);
    assert.equal((await handlers['school:check']()).state, 'available');
    assert.deepEqual(sent.at(-1)[0], 'school:state');
    assert.deepEqual(await handlers['school:timetable'](null, { from: 1 }), { ok: false, code: 'invalid', error: 'invalid argument', status: null });
    const bad = await handlers['school:timetable'](null, { from: '2026-10-01', to: '2026-10-30' });
    assert.equal(bad.code, 'invalid');
    const ok = await handlers['school:timetable'](null, { from: '2026-10-19', to: '2026-10-25' });
    assert.equal(ok.students.length, 2);
    assert.equal((await handlers['school:changes'](null, { days: 7 })).changes.length, 2);
    assert.equal((await handlers['school:avatar'](null, { url: '../etc/passwd' })).code, 'invalid');
    const av = await handlers['school:avatar'](null, { url: '/avatars/lenaAvatarFile00001.webp' });
    assert.ok(av.data instanceof Uint8Array);
    s.emit('push', { kind: 'changes' });
    assert.deepEqual(sent.at(-1), ['school:push', { kind: 'changes' }]);
  });

  it('no school service → no school:* channels', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.ok(!Object.keys(handlers).some((c) => c.startsWith('school:')));
  });
});

describe('i18n school.* (de / en)', () => {
  function flatten(obj, prefix = '', out = {}) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
      else out[key] = String(v);
    }
    return out;
  }
  const placeholders = (s) => [...String(s).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort();

  it('same keys and placeholders, no empty strings', () => {
    const d = flatten(de.school, 'school');
    const e = flatten(en.school, 'school');
    assert.deepEqual(Object.keys(d).filter((k) => !(k in e)), []);
    assert.deepEqual(Object.keys(e).filter((k) => !(k in d)), []);
    for (const k of Object.keys(d)) {
      assert.deepEqual(placeholders(e[k]), placeholders(d[k]), k);
      assert.ok(d[k].trim() && e[k].trim(), k);
    }
    assert.equal(d['school.state.cancelled'], 'Entfällt');
    assert.equal(d['school.state.changed'], 'Vertretung');
  });
});
