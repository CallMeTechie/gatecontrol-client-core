'use strict';

// "Familie" (plugin gatecontrol-familie, "Internet zu Hause"): the pure
// helpers (utils/familie.js — argument checks, cleaned answers, the actions
// of a rule as they are written back, push context), the service
// (services/familie.js — the page only for members of a family, older
// plugins without an error, changes, cache and offline copy, "Internet zu
// Hause" pushes incl. pause_over / extend_over, toast click → page), its IPC
// (familie:*) and the familie.* texts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const familie = require('../src/utils/familie');
const FamilieService = require('../src/services/familie');
const MessengerApi = require('../src/services/messenger-api');
const NotificationCenter = require('../src/services/notification-center');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { createMemoryStore } = require('./fixtures/memory-store');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const { MessengerError } = MessengerApi;
const tick = () => new Promise((r) => setImmediate(r));
const ms = (iso) => Date.parse(iso);

const ME = {
  ok: true,
  me: { userId: 2, name: 'Anna', role: 'parent', age: null, avatarUrl: null, color: 'green', colorHex: '#16A34A', initials: 'AN', presence: null },
  modules: { shopping: true, rules: true, presence: true, dates: false },
  members: [],
  serverTime: '2026-11-11T16:52:10Z',
};

const TIM = {
  userId: 5, name: 'Tim', avatarUrl: '/avatars/timsAvatarFile000001.webp', color: 'orange', colorHex: '#f97316', initials: 'TI',
  presence: { state: 'home', since: '2026-11-11T16:05:00Z', source: 'app' },
  paused: '2026-11-11T18:00:00Z',
  pausedBy: { userId: 2, name: 'Anna', at: '2026-11-11T17:30:00Z', rule: { id: 12, title: 'Abendessen' } },
  extended: null, extendedBy: null, nextSchedule: null, profile: 'Kinder', devices: 2, filtered: true, error: null,
};

const INTERNET = {
  ok: true,
  internet: {
    available: true, manage: true, serverTime: '2026-11-11T16:52:10Z', timezone: 'Europe/Berlin',
    children: [
      {
        userId: 4, name: 'Lena\u0007', avatarUrl: 'https://evil.example/a.png', color: 'amber', colorHex: 'yellow', initials: 'LE',
        presence: { state: 'home', since: '2026-11-11T15:40:00Z', source: 'wifi' },
        paused: null, pausedBy: null, extended: null, extendedBy: null,
        nextSchedule: { from: '2026-11-11T20:00:00Z', to: '2026-11-12T06:00:00Z', block: 'categories', categories: ['social', 'games', 'video', 'porn'], active: false },
        profile: 'Kinder', devices: 2, filtered: true, error: null, mac: 'aa:bb:cc:dd:ee:ff',
      },
      TIM,
      {
        userId: 6, name: 'Mia', avatarUrl: null, color: 'pink', colorHex: '#EC4899', initials: 'MI',
        presence: { state: 'away', since: '2026-11-11T14:10:00Z', source: 'app' },
        paused: null, pausedBy: null, extended: '2026-11-11T20:30:00Z',
        extendedBy: { userId: 3, name: 'Marc', at: '2026-11-11T16:50:00Z', rule: null },
        nextSchedule: { from: '2026-11-11T20:00:00Z', to: '2026-11-12T06:00:00Z', block: 'all', categories: [], active: false },
        profile: 'Kleine', devices: 1, filtered: true, error: null,
      },
      { userId: 7, name: 'Ben', presence: { state: 'not_shared', since: null, source: null }, paused: null, nextSchedule: null, profile: null, devices: 0, filtered: false, error: null },
      { userId: 8, name: 'Kaputt', error: 'boom', devices: -3 },
      { name: 'ohne id' },
      { userId: 4, name: 'doppelt' },
    ],
  },
};

const RULES = {
  ok: true,
  can: { house: true, personal: true },
  log: [{ id: 1 }],
  rules: [
    {
      id: 12, title: 'Abendessen', scope: 'house', active: true, kind: 'reminder',
      trigger: { type: 'schedule', weekdays: [7, 1, 2, 3, 4, 5, 6, 9], time: '18:00' },
      conditions: { time: null, afterSunset: false, device: [], calendar: null },
      actions: [
        { type: 'internet', op: 'pause', userId: 5, name: 'Tim', minutes: 30, until: null, available: true, problem: null },
        { type: 'quick_action', plugin: 'gatecontrol-smarthome', id: 'lamp.kitchen', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on', kind: 'toggle', verb: 'Einschalten', available: true, needsTarget: false },
        { type: 'internet', op: 'pause', userId: 4, name: 'Lena', minutes: null, until: '18:30', available: true, problem: null },
        { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', facts: false, buttons: ['done'] },
        { type: 'messenger', to: 'family', text: null },
        { type: 'kaffee', machine: 3, nested: { strength: 'stark' } },
      ],
      lastRunAt: null, lastResult: null, ownerId: 2, ownerName: 'Anna', editable: true, pausable: true,
    },
    {
      id: 13, title: '', scope: 'house', active: false, trigger: { type: 'person_home', userId: 6 },
      actions: [{ type: 'internet', op: 'pause', userId: 9, name: 'Jonas', minutes: 60, until: null, available: false, problem: 'not_found' }],
      ownerId: 3, ownerName: 'Marc', editable: true, pausable: true,
    },
    { title: 'ohne id' },
  ],
};

const OPTIONS = {
  ok: true,
  triggers: [],
  people: [{ userId: 2, name: 'Anna', role: 'parent' }, { userId: 5, name: 'Tim', role: 'child' }, { name: 'x' }],
  internet: { available: true, reason: null, children: [{ userId: 4, name: 'Lena', colorHex: '#EAB308', initials: 'LE' }, { userId: 5, name: 'Tim', colorHex: '#F97316', initials: 'TI' }] },
};

const PRESENCE = {
  ok: true,
  members: [
    { userId: 2, name: 'Anna', role: 'parent', state: 'home', home: true, since: '2026-11-11T15:40:00Z', source: 'wifi' },
    { userId: 4, name: 'Lena', role: 'child', state: 'away', home: false, since: '2026-11-11T14:10:00Z', source: 'app' },
  ],
  me: { share: true, places: false, wifi: true },
  home: [2],
};

const WIFI = {
  ok: true,
  wifi: {
    available: true, consent: true, since: '2026-11-01T09:12:00Z',
    devices: [
      { id: 41, name: 'Annas Handy', lastSeen: '2026-11-11T16:50:00Z', counts: true, gateway: 'Pi Keller', mac: 'aa:bb' },
      { id: 42, name: 'Annas Laptop', lastSeen: '2026-11-11T12:03:00Z', counts: false, gateway: 'Pi Keller' },
      { name: 'ohne id' },
    ],
  },
};

describe('utils/familie', () => {
  it('me: role and modules; no member object → null', () => {
    assert.deepEqual(familie.normalizeMe(ME), { me: { userId: 2, name: 'Anna', role: 'parent' }, modules: { rules: true, presence: true } });
    assert.equal(familie.normalizeMe({ ok: true }), null);
    assert.equal(familie.normalizeMe({ me: { userId: 2, role: 'boss' } }), null);
  });

  it('internet: cleaned children, times as ms, unknown fields dropped', () => {
    const i = familie.normalizeInternet(INTERNET);
    assert.equal(i.available, true);
    assert.equal(i.supported, true);
    assert.equal(i.manage, true);
    assert.equal(i.serverTime, ms('2026-11-11T16:52:10Z'));
    assert.equal(i.timezone, 'Europe/Berlin');
    assert.deepEqual(i.children.map((c) => c.userId), [4, 5, 6, 7, 8]);
    const [lena, tim, mia, ben, bad] = i.children;
    assert.equal(lena.name, 'Lena');
    assert.equal(lena.avatarUrl, null);
    assert.equal(lena.color, null);
    assert.equal('mac' in lena, false);
    assert.deepEqual(lena.presence, { state: 'home', since: ms('2026-11-11T15:40:00Z'), source: 'wifi' });
    assert.deepEqual(lena.nextSchedule, { from: ms('2026-11-11T20:00:00Z'), to: ms('2026-11-12T06:00:00Z'), block: 'categories', categories: ['social', 'games', 'video'], active: false });
    assert.equal(tim.avatarUrl, '/avatars/timsAvatarFile000001.webp');
    assert.equal(tim.color, '#F97316');
    assert.equal(tim.paused, ms('2026-11-11T18:00:00Z'));
    assert.deepEqual(tim.pausedBy, { userId: 2, name: 'Anna', at: ms('2026-11-11T17:30:00Z'), rule: { id: 12, title: 'Abendessen' } });
    assert.equal(mia.extended, ms('2026-11-11T20:30:00Z'));
    assert.equal(mia.extendedBy.rule, null);
    assert.deepEqual(mia.nextSchedule.categories, []);
    assert.deepEqual([ben.filtered, ben.devices, ben.presence.state, ben.profile], [false, 0, 'not_shared', null]);
    assert.deepEqual([bad.error, bad.devices, bad.presence], ['error', 0, null]);
  });

  it('internet: older plugins (no presence, no rule, no server time) and "not on this server"', () => {
    const old = familie.normalizeInternet({ internet: { available: true, manage: false, children: [{ userId: 5, name: 'Tim', paused: '2026-11-11T18:00:00Z', pausedBy: { userId: 2, name: 'Anna', at: '2026-11-11T17:30:00Z' }, devices: 2, filtered: true }] } });
    assert.deepEqual([old.serverTime, old.timezone, old.manage], [null, null, false]);
    assert.equal(old.children[0].presence, null);
    assert.equal(old.children[0].pausedBy.rule, null);
    const none = familie.normalizeInternet({ ok: true, internet: { available: false, manage: true, children: [{ userId: 1 }], serverTime: '2026-11-11T16:52:10Z', timezone: '../etc' } });
    assert.deepEqual([none.available, none.children, none.timezone], [false, [], null]);
    assert.deepEqual(familie.normalizeInternet(null).children, []);
    assert.equal(familie.NO_INTERNET.supported, false);
  });

  it('pause / extend bodies: exactly one field, limits', () => {
    assert.deepEqual(familie.pauseBody({ minutes: 30 }), { minutes: 30 });
    assert.deepEqual(familie.pauseBody({ minutes: 10080, until: undefined, add: null }), { minutes: 10080 });
    assert.equal(familie.pauseBody({ minutes: 10081 }), null);
    assert.equal(familie.pauseBody({ minutes: 0 }), null);
    assert.equal(familie.pauseBody({ minutes: '30' }), null);
    assert.deepEqual(familie.pauseBody({ until: '18:30' }), { until: '18:30' });
    assert.equal(familie.pauseBody({ until: '25:00' }), null);
    assert.deepEqual(familie.pauseBody({ until: '2026-11-12T06:00:00Z' }), { until: '2026-11-12T06:00:00.000Z' });
    assert.deepEqual(familie.pauseBody({ add: 30 }), { add: 30 });
    assert.equal(familie.pauseBody({ add: 1441 }), null);
    assert.equal(familie.pauseBody({ minutes: 30, add: 30 }), null);
    assert.equal(familie.pauseBody({}), null);
    assert.deepEqual(familie.extendBody({ minutes: 0 }), { minutes: 0 });
    assert.deepEqual(familie.extendBody({ minutes: 30, fromNow: true }), { minutes: 30, fromNow: true });
    assert.deepEqual(familie.extendBody({ minutes: 30, fromNow: 'yes' }), { minutes: 30 });
    assert.equal(familie.extendBody({ minutes: 1441 }), null);
    assert.equal(familie.extendBody({}), null);
    assert.equal(familie.internetPath(5, 'pause'), 'internet/5/pause');
    assert.equal(familie.internetPath('5/../x', 'pause'), null);
    assert.equal(familie.internetPath(5, 'delete'), null);
  });

  it('rules: view and what is written back for each action', () => {
    const { rules, can } = familie.normalizeRules(RULES);
    assert.deepEqual(can, { house: true, personal: true });
    assert.deepEqual(rules.map((r) => r.id), [12, 13]);
    const r = rules[0];
    assert.deepEqual(r.trigger, { type: 'schedule', weekdays: [1, 2, 3, 4, 5, 6, 7], time: '18:00' });
    assert.deepEqual(r.actions.map((a) => a.type), ['internet', 'quick_action', 'internet', 'notify', 'messenger', 'kaffee']);
    assert.deepEqual(r.actions[0], { type: 'internet', input: { type: 'internet', op: 'pause', userId: 5, minutes: 30 }, op: 'pause', userId: 5, name: 'Tim', minutes: 30, until: null, available: true, problem: null });
    assert.deepEqual(r.actions[2].input, { type: 'internet', op: 'pause', userId: 4, until: '18:30' });
    // the other actions go back as the rule API reads them — nothing of the view (kind, verb, available, needsTarget)
    assert.deepEqual(r.actions[1].input, { type: 'quick_action', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on' });
    assert.deepEqual(r.actions[3].input, { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', buttons: ['done'] });
    assert.deepEqual(r.actions[4].input, { type: 'messenger', to: 'family' });
    // a kind this app does not know: unchanged
    assert.deepEqual(r.actions[5].input, { type: 'kaffee', machine: 3, nested: { strength: 'stark' } });
    assert.deepEqual([rules[1].title, rules[1].active, rules[1].trigger], ['', false, { type: 'person_home', userId: 6 }]);
    assert.deepEqual([rules[1].actions[0].available, rules[1].actions[0].problem], [false, 'not_found']);
  });

  it('actionInput: an internet action without its fields is the placeholder the plugin restores', () => {
    assert.deepEqual(familie.actionInput({ type: 'internet' }), { type: 'internet' });
    assert.deepEqual(familie.actionInput({ type: 'internet', op: 'resume', userId: 5, minutes: 30 }), { type: 'internet', op: 'resume', userId: 5 });
    assert.deepEqual(familie.actionInput({ type: 'internet', op: 'pause', userId: 5, minutes: 5000 }), { type: 'internet' });
    assert.deepEqual(familie.actionInput({ type: 'quick_action', plugin: 'gatecontrol-door', id: 'open', title: null, state: null }), { type: 'quick_action', plugin: 'gatecontrol-door', id: 'open' });
    assert.equal(familie.actionInput(null), null);
    assert.equal(familie.actionInput({ op: 'pause' }), null);
  });

  it('actionsBody: 1 … 10 small objects with a type', () => {
    const one = { type: 'internet', op: 'resume', userId: 5 };
    assert.deepEqual(familie.actionsBody([one]), [one]);
    assert.equal(familie.actionsBody([]), null);
    assert.equal(familie.actionsBody(new Array(11).fill(one)), null);
    assert.equal(familie.actionsBody([{ op: 'pause' }]), null);
    assert.equal(familie.actionsBody(['x']), null);
    assert.equal(familie.actionsBody([{ type: 'notify', text: 'x'.repeat(5000) }]), null);
    assert.equal(familie.actionsBody('x'), null);
  });

  it('rule options: the action only when the server offers it', () => {
    const o = familie.normalizeOptions(OPTIONS);
    assert.deepEqual(o.internet.children.map((c) => [c.userId, c.name, c.color]), [[4, 'Lena', '#EAB308'], [5, 'Tim', '#F97316']]);
    assert.deepEqual(o.people, [{ userId: 2, name: 'Anna', role: 'parent' }, { userId: 5, name: 'Tim', role: 'child' }]);
    // plugin < 1.20.0: no `internet`
    assert.deepEqual(familie.normalizeOptions({ people: [] }).internet, { available: false, reason: 'unavailable', children: [] });
    assert.deepEqual(familie.normalizeOptions({ internet: { available: false, reason: 'parents_only', children: [{ userId: 4 }] } }).internet, { available: false, reason: 'parents_only', children: [] });
  });

  it('presence and Wi-Fi: own row, switches, own devices without addresses', () => {
    assert.deepEqual(familie.normalizePresence(PRESENCE, 2), { me: { share: true, wifi: true }, self: { state: 'home', since: ms('2026-11-11T15:40:00Z'), source: 'wifi' } });
    assert.equal(familie.normalizePresence(PRESENCE, 99).self, null);
    // a server without Wi-Fi detection: wifi null (no switch)
    assert.equal(familie.normalizePresence({ me: { share: false, wifi: null }, members: [] }, 2).me.wifi, null);
    assert.equal(familie.normalizePresence({ me: { share: false }, members: [] }, 2).me.wifi, null);
    const w = familie.normalizeWifi(WIFI);
    assert.deepEqual([w.available, w.consent, w.since], [true, true, ms('2026-11-01T09:12:00Z')]);
    assert.deepEqual(w.devices, [
      { id: 41, name: 'Annas Handy', lastSeen: ms('2026-11-11T16:50:00Z'), counts: true, gateway: 'Pi Keller' },
      { id: 42, name: 'Annas Laptop', lastSeen: ms('2026-11-11T12:03:00Z'), counts: false, gateway: 'Pi Keller' },
    ]);
    assert.deepEqual(familie.normalizeWifi({ wifi: { available: false, consent: false, since: null, devices: null } }), { available: false, consent: false, since: null, devices: [] });
    assert.deepEqual(familie.normalizeOwnState({ userId: 2, state: 'away', home: false, since: null, source: 'app' }), { state: 'away', since: null, source: 'app' });
  });

  it('push context: the topic internet with every kind, pause_over / extend_over included', () => {
    const entry = (kind, extra = {}) => ({ topic: 'plugin:gatecontrol-familie:internet', data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind, userId: 5, until: null, by: null, ...extra } } });
    assert.deepEqual(familie.pushContext(entry('pause', { until: '2026-11-11T17:30:00Z', by: 2, ruleId: 12 })), { type: 'internet', kind: 'pause', userId: 5, until: ms('2026-11-11T17:30:00Z'), ruleId: 12 });
    for (const kind of ['resume', 'extend', 'extend_end', 'pause_over', 'extend_over']) assert.equal(familie.pushContext(entry(kind)).kind, kind);
    // an unknown kind is still a message of the topic (the page reloads)
    assert.deepEqual(familie.pushContext(entry('later')), { type: 'internet', kind: null, userId: 5, until: null, ruleId: null });
    // the topic alone is enough; another topic of Familie has no page here
    assert.equal(familie.pushContext({ topic: 'plugin:gatecontrol-familie:internet', data: null }).type, 'internet');
    assert.equal(familie.pushContext({ topic: 'plugin:gatecontrol-familie:tasks', data: { route: 'plg-gatecontrol-familie', familie: { type: 'task' } } }), null);
    assert.equal(familie.pushContext({ topic: 'devices', data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind: 'pause', userId: 5 } } }).kind, 'pause');
    assert.equal(familie.pushContext({ topic: 'plugin:gatecontrol-schule:changes', data: { familie: { type: 'internet' } } }), null);
    assert.equal(familie.pushContext(null), null);
  });
});

/** Fake transport: path → answer, function or thrown error. */
function fakeApi(routes = {}) {
  const api = { calls: [], routes, scopeValue: 'https://gc\nkey' };
  api.scope = () => api.scopeValue;
  api._call = async (method, path, opts = {}) => {
    const key = path.replace(familie.API_BASE, '');
    api.calls.push([method, key, opts.body === undefined ? null : opts.body]);
    let r = api.routes[`${method} ${key}`];
    if (r === undefined && method === 'GET') r = api.routes[key];
    if (typeof r === 'function') r = r(opts.body);
    if (r instanceof Error) throw r;
    if (r === undefined) throw new MessengerError('HTTP 404', { status: 404, code: 'not_found' });
    return JSON.parse(JSON.stringify(r));
  };
  api.avatar = async (url) => { api.calls.push(['AVATAR', url]); return { mime: 'image/webp', data: Buffer.from('RIFF') }; };
  return api;
}

const plugins = (version = '1.20.0') => ({ ok: true, plugins: [{ id: 'gatecontrol-schule', version: '1.7.0' }, { id: 'gatecontrol-familie', name: 'Familie', version, tab: { label: 'Familie' } }] });
const refusal = (status, code, body = {}) => new MessengerError(code, { status, code, body: { ok: false, code, ...body } });

function service(routes, opts = {}) {
  let now = opts.now || ms('2026-11-11T16:52:10Z');
  const api = fakeApi({ '/api/v1/client/plugins': plugins(), me: ME, internet: INTERNET, rules: RULES, 'rules/options': OPTIONS, presence: PRESENCE, 'presence/wifi': WIFI, ...routes });
  const s = new FamilieService({ api, log, timing: { recheckMs: 1e9, retryMinMs: 1e9 }, now: () => now, ...opts.extra });
  const states = [];
  const pushes = [];
  s.on('state', (x) => states.push(x));
  s.on('push', (x) => pushes.push(x));
  return { s, api, states, pushes, setNow: (v) => { now = v; } };
}

describe('FamilieService', () => {
  it('the page exists for a member of a family while the plugin is listed', async () => {
    const { s, api, states } = service();
    assert.equal(s.status().state, 'unknown');
    const st = await s.check();
    assert.deepEqual([st.state, st.version], ['available', '1.20.0']);
    assert.deepEqual(st.me, { userId: 2, name: 'Anna', role: 'parent' });
    assert.deepEqual(st.modules, { rules: true, presence: true });
    assert.equal(states.length, 1);

    // no member of a family: no page, and no error
    api.routes.me = refusal(403, 'not_member');
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason, x.me]), ['unavailable', 'not_member', null]);
    // a wall tablet
    api.routes.me = { ...ME, me: { userId: 9, name: 'Wand', role: 'wall' } };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'forbidden']);
    // the plugin gone
    api.routes['/api/v1/client/plugins'] = { ok: true, plugins: [] };
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'not_installed']);
    // a server without plugins
    delete api.routes['/api/v1/client/plugins'];
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'unsupported']);
  });

  it('a child is a member too; a plugin without the app API is no error', async () => {
    const { s, api } = service({ me: { ...ME, me: { userId: 5, name: 'Tim', role: 'child' }, modules: { rules: false, presence: true } } });
    const st = await s.check();
    assert.deepEqual([st.state, st.me.role, st.modules.rules], ['available', 'child', false]);
    delete api.routes.me;
    assert.deepEqual(await s.check().then((x) => [x.state, x.reason]), ['unavailable', 'unsupported']);
  });

  it('a network error keeps the page; without it the state is error', async () => {
    const { s, api } = service();
    api.routes.me = new MessengerError('down', { code: 'network' });
    assert.equal((await s.check()).state, 'error');
    api.routes.me = ME;
    assert.equal((await s.check()).state, 'available');
    api.routes['/api/v1/client/plugins'] = new MessengerError('down', { code: 'network' });
    const st = await s.check();
    assert.deepEqual([st.state, st.reason, st.me.name], ['available', 'network', 'Anna']);
  });

  it('internet: cached, refreshed, and the last copy when the network is down', async () => {
    const { s, api, setNow } = service();
    await s.check();
    const a = await s.internet();
    assert.deepEqual([a.ok, a.stale, a.internet.children.length, a.internet.manage], [true, false, 5, true]);
    await s.internet();
    const asked = () => api.calls.filter((c) => c[0] === 'GET' && c[1] === 'internet').length;
    assert.equal(asked(), 1);
    await s.internet({ refresh: true });
    assert.equal(asked(), 2);
    setNow(ms('2026-11-11T16:53:00Z'));
    api.routes.internet = new MessengerError('down', { code: 'network' });
    const old = await s.internet();
    assert.deepEqual([old.ok, old.stale, old.error, old.internet.children.length], [true, true, 'network', 5]);
    api.routes.internet = refusal(403, 'parents_only');
    await assert.rejects(s.internet({ refresh: true }), (e) => e.code === 'parents_only');
  });

  it('older servers: no route internet / presence/wifi → "not there", never an error', async () => {
    const { s, api } = service();
    await s.check();
    delete api.routes.internet;
    const i = await s.internet();
    assert.deepEqual([i.ok, i.internet.available, i.internet.supported, i.internet.children], [true, false, false, []]);
    delete api.routes['presence/wifi'];
    const w = await s.wifi();
    assert.deepEqual([w.ok, w.wifi.available, w.wifi.devices], [true, false, []]);
    // "Internet zu Hause" not set up on this server
    api.routes.internet = { ok: true, internet: { available: false, manage: true, children: [], serverTime: '2026-11-11T16:52:10Z', timezone: 'Europe/Berlin' } };
    const none = await s.internet({ refresh: true });
    assert.deepEqual([none.internet.available, none.internet.supported], [false, true]);
    // rule options of a plugin before the rule action
    api.routes['rules/options'] = { ok: true, people: [] };
    assert.equal((await s.ruleOptions()).internet.available, false);
  });

  it('pause, resume, extend: the body, the answer, and the cards are asked again', async () => {
    const { s, api } = service({
      'POST internet/5/pause': (body) => ({ ok: true, child: { ...TIM, paused: '2026-11-11T17:22:10Z', pausedBy: { userId: 2, name: 'Anna', at: '2026-11-11T16:52:10Z', rule: null }, sent: body } }),
      'POST internet/5/resume': { ok: true, child: { ...TIM, paused: null, pausedBy: null } },
      'POST internet/5/extend': { ok: true, child: { ...TIM, paused: null, pausedBy: null, extended: '2026-11-11T20:30:00Z' } },
    });
    await s.check();
    await s.internet();
    const r = await s.pause(5, { minutes: 30 });
    assert.equal(r.child.paused, ms('2026-11-11T17:22:10Z'));
    assert.equal(r.child.pausedBy.rule, null);
    assert.deepEqual(api.calls.at(-1), ['POST', 'internet/5/pause', { minutes: 30 }]);
    await s.pause(5, { until: '18:30' });
    assert.deepEqual(api.calls.at(-1)[2], { until: '18:30' });
    await s.pause(5, { add: 30 });
    assert.deepEqual(api.calls.at(-1)[2], { add: 30 });
    assert.equal((await s.resume(5)).child.paused, null);
    assert.deepEqual(api.calls.at(-1), ['POST', 'internet/5/resume', {}]);
    assert.equal((await s.extend(5, { minutes: 30, fromNow: true })).child.extended, ms('2026-11-11T20:30:00Z'));
    assert.deepEqual(api.calls.at(-1), ['POST', 'internet/5/extend', { minutes: 30, fromNow: true }]);
    await s.extend(5, { minutes: 0 });
    assert.deepEqual(api.calls.at(-1)[2], { minutes: 0 });
    const n = api.calls.length;
    await s.internet();
    assert.equal(api.calls.length, n + 1, 'not from the cache after a change');

    await assert.rejects(s.pause(5, { minutes: 30, add: 5 }), (e) => e.code === 'invalid');
    await assert.rejects(s.pause('x', { minutes: 30 }), (e) => e.code === 'invalid');
    await assert.rejects(s.extend(5, { minutes: 5000 }), (e) => e.code === 'invalid');
    assert.equal(api.calls.length, n + 1, 'invalid arguments never reach the server');
    api.routes['POST internet/5/pause'] = refusal(409, 'unavailable');
    await assert.rejects(s.pause(5, { minutes: 30 }), (e) => e.code === 'unavailable' && e.status === 409);
  });

  it('rules: list, switch, and the actions of a rule replaced as a whole', async () => {
    const patched = [];
    const { s, api } = service({ 'PATCH rules/12': (body) => { patched.push(body); return { ok: true, rule: { ...RULES.rules[0], ...(body.active !== undefined ? { active: body.active } : {}) } }; } });
    await s.check();
    const list = await s.rules();
    assert.equal(list.rules.length, 2);
    assert.equal((await s.setRuleActive(12, false)).rule.active, false);
    assert.deepEqual(patched[0], { active: false });
    // one action changed, the others written back as they came
    const inputs = list.rules[0].actions.map((a) => a.input);
    inputs[0] = { type: 'internet', op: 'pause', userId: 5, minutes: 60 };
    await s.setRuleActions(12, inputs);
    assert.deepEqual(patched[1].actions, [
      { type: 'internet', op: 'pause', userId: 5, minutes: 60 },
      { type: 'quick_action', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on' },
      { type: 'internet', op: 'pause', userId: 4, until: '18:30' },
      { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', buttons: ['done'] },
      { type: 'messenger', to: 'family' },
      { type: 'kaffee', machine: 3, nested: { strength: 'stark' } },
    ]);
    await assert.rejects(s.setRuleActions(12, []), (e) => e.code === 'invalid');
    await assert.rejects(s.setRuleActive(12, 'yes'), (e) => e.code === 'invalid');
    api.routes.rules = refusal(403, 'module_off');
    await assert.rejects(s.rules({ refresh: true }), (e) => e.code === 'module_off');
  });

  it('presence: own state, "Anwesenheit teilen", Wi-Fi detection and devices', async () => {
    const { s, api } = service({
      'PUT presence/consent': (body) => ({ ok: true, consent: { share: body.share, places: false }, state: { userId: 2, state: 'not_shared', home: null, since: null, source: null } }),
      'PUT presence/wifi': (body) => ({ ok: true, wifi: { ...WIFI.wifi, consent: body.enabled } }),
      'PUT presence/wifi/devices/42': (body) => ({ ok: true, wifi: { ...WIFI.wifi, devices: [WIFI.wifi.devices[0], { ...WIFI.wifi.devices[1], counts: body.counts }] } }),
    });
    await s.check();
    const p = await s.presence();
    assert.deepEqual([p.me, p.self.state, p.self.source], [{ share: true, wifi: true }, 'home', 'wifi']);
    assert.deepEqual(await s.setShare(false), { ok: true, share: false, self: { state: 'not_shared', since: null, source: null } });
    assert.deepEqual(api.calls.at(-1), ['PUT', 'presence/consent', { share: false }]);
    assert.equal((await s.setWifi(false)).wifi.consent, false);
    assert.deepEqual(api.calls.at(-1), ['PUT', 'presence/wifi', { enabled: false }]);
    assert.equal((await s.setWifiDevice(42, true)).wifi.devices[1].counts, true);
    assert.deepEqual(api.calls.at(-1), ['PUT', 'presence/wifi/devices/42', { counts: true }]);
    await assert.rejects(s.setWifi('on'), (e) => e.code === 'invalid');
    await assert.rejects(s.setWifiDevice('42/..', true), (e) => e.code === 'invalid');
  });

  it('thrown out of the family: the next refusal asks for the page again', async () => {
    const { s, api } = service();
    await s.check();
    api.routes.internet = refusal(403, 'not_member');
    api.routes.me = refusal(403, 'not_member');
    await assert.rejects(s.internet(), (e) => e.code === 'not_member');
    await tick();
    await tick();
    assert.deepEqual([s.status().state, s.status().reason], ['unavailable', 'not_member']);
  });

  it('a new server drops answers and state', async () => {
    const { s, api, states } = service();
    await s.check();
    await s.internet();
    api.scopeValue = 'https://other\nkey2';
    await s.resetForNewServer();
    assert.equal(states.at(-1).state, 'unknown');
    assert.equal(states.at(-1).me, null);
    const n = api.calls.length;
    await s.internet();
    assert.equal(api.calls.length, n + 1);
  });

  it('avatars are fetched once', async () => {
    const { s, api } = service();
    await s.avatar('/avatars/timsAvatarFile000001.webp');
    await s.avatar('/avatars/timsAvatarFile000001.webp');
    assert.equal(api.calls.filter((c) => c[0] === 'AVATAR').length, 1);
  });
});

function center() {
  class N extends EventEmitter { constructor(o) { super(); this.opts = o; N.created.push(this); } show() {} close() {} static isSupported() { return true; } }
  N.created = [];
  const push = new EventEmitter();
  Object.assign(push, { ack: async () => ({ ok: true }), fetchInbox: async () => ({ ok: true, items: [], unread: 0 }), start() {}, stop() {}, restart() {}, applySettings() {}, status: () => ({ state: 'connected' }) });
  const store = createMemoryStore({ notifications: { enabled: true, toasts: true, criticalBypass: true, mutedTopics: [] } });
  const nc = new NotificationCenter({ store, log, pushClient: push, Notification: N, platform: 'win32', protocol: 'gatecontrol-pro', showWindow() {}, now: () => Date.parse('2026-11-11T17:30:00Z') });
  const navigate = [];
  nc.on('navigate', (x) => navigate.push(x));
  return { nc, N, push, navigate };
}

const internetPush = (seq, kind, extra = {}) => ({
  seq, id: seq + 500, topic: 'plugin:gatecontrol-familie:internet', priority: 'normal', title: kind === 'pause_over' ? 'Pause vorbei' : 'Internet-Pause bis 18:30',
  body: kind === 'pause_over' ? 'Das Internet zu Hause geht wieder.' : 'Die Regel „Abendessen“ (Anna) hat das Internet zu Hause pausiert.',
  created_at: '2026-11-11T17:29:00Z', expires_at: '2026-11-13T17:29:00Z', silent: false,
  data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind, userId: 5, until: null, by: null, ...extra } },
});

describe('FamilieService and the notification center', () => {
  it('an "Internet zu Hause" push drops the cards and tells the page', async () => {
    const { nc } = center();
    const { s, api, pushes } = service({}, { extra: { notificationCenter: nc } });
    s.start();
    await tick();
    await tick();
    await s.internet();
    nc.handleNotification(internetPush(1, 'pause', { until: '2026-11-11T18:00:00Z', by: 2, ruleId: 12 }));
    nc.handleNotification({ ...internetPush(2, 'x'), topic: 'plugin:gatecontrol-familie:tasks', data: { route: 'plg-gatecontrol-familie', familie: { type: 'task' } } });
    nc.handleNotification(internetPush(3, 'pause_over'));
    assert.deepEqual(pushes, [
      { type: 'internet', kind: 'pause', userId: 5, until: ms('2026-11-11T18:00:00Z'), ruleId: 12, notificationId: 501 },
      { type: 'internet', kind: 'pause_over', userId: 5, until: null, ruleId: null, notificationId: 503 },
    ]);
    const n = api.calls.length;
    await s.internet();
    assert.equal(api.calls.length, n + 1, 'asked again');
    s.stop();
  });

  it('toast click opens the page while it exists, else the inbox', async () => {
    const { nc, N, navigate } = center();
    const { s, api } = service({}, { extra: { notificationCenter: nc } });
    s.start();
    await tick();
    await tick();
    nc.handleNotification(internetPush(1, 'extend_over'));
    N.created[0].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'plg-gatecontrol-familie', id: 501, context: { type: 'internet', kind: 'extend_over', userId: 5, until: null, ruleId: null } });

    // another topic of Familie keeps opening the inbox
    nc.handleNotification({ ...internetPush(2, 'x'), topic: 'plugin:gatecontrol-familie:tasks', data: { route: 'plg-gatecontrol-familie', familie: { type: 'task' } } });
    N.created[1].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 502 });

    // no member any more → the inbox again
    api.routes.me = refusal(403, 'not_member');
    await s.check();
    nc.handleNotification(internetPush(3, 'pause_over'));
    N.created[2].emit('click');
    assert.deepEqual(navigate.at(-1), { route: 'inbox', id: 503 });
    s.stop();
    assert.equal(nc.clickTarget(internetPush(4, 'pause')), null, 'stop() gives the route back');
  });
});

describe('familie:* IPC', () => {
  function register(s) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', familie: s,
    });
    return { handlers, sent };
  }
  const INVALID = { ok: false, code: 'invalid', error: 'invalid argument', status: null, field: null };

  it('channels, argument checks and events', async () => {
    const { s, api } = service({
      'POST internet/5/pause': { ok: true, child: TIM },
      'PATCH rules/12': refusal(400, 'invalid', { field: 'actions.0.userId' }),
      'PUT presence/wifi': { ok: true, wifi: WIFI.wifi },
    });
    const { handlers, sent } = register(s);
    for (const ch of ['familie:status', 'familie:check', 'familie:internet', 'familie:internet:pause', 'familie:internet:resume', 'familie:internet:extend',
      'familie:rules', 'familie:rules:options', 'familie:rules:active', 'familie:rules:actions', 'familie:presence', 'familie:presence:share',
      'familie:wifi', 'familie:wifi:set', 'familie:wifi:device', 'familie:avatar']) assert.ok(handlers[ch], ch);
    assert.equal((await handlers['familie:check']()).state, 'available');
    assert.equal(sent.at(-1)[0], 'familie:state');
    assert.equal((await handlers['familie:internet'](null, {})).internet.children.length, 5);
    assert.deepEqual(await handlers['familie:internet:pause'](null, { childId: '5', minutes: 30 }), INVALID);
    assert.equal((await handlers['familie:internet:pause'](null, { childId: 5, minutes: 30, evil: true })).child.userId, 5);
    assert.deepEqual(api.calls.at(-1), ['POST', 'internet/5/pause', { minutes: 30 }]);
    assert.equal((await handlers['familie:internet:pause'](null, { childId: 5 })).code, 'invalid');
    assert.deepEqual(await handlers['familie:internet:resume'](null, null), INVALID);
    assert.deepEqual(await handlers['familie:rules:active'](null, { id: 12, active: 1 }), INVALID);
    assert.deepEqual(await handlers['familie:rules:actions'](null, { id: 12, actions: 'x' }), INVALID);
    // the field of a refused action reaches the page
    const refused = await handlers['familie:rules:actions'](null, { id: 12, actions: [{ type: 'internet', op: 'pause', userId: 99, minutes: 30 }] });
    assert.deepEqual([refused.ok, refused.code, refused.status, refused.field], [false, 'invalid', 400, 'actions.0.userId']);
    assert.deepEqual(await handlers['familie:wifi:set'](null, { enabled: 'yes' }), INVALID);
    assert.equal((await handlers['familie:wifi:set'](null, { enabled: true })).wifi.consent, true);
    assert.deepEqual(await handlers['familie:wifi:device'](null, { id: 42 }), INVALID);
    assert.deepEqual(await handlers['familie:presence:share'](null, {}), INVALID);
    assert.equal((await handlers['familie:avatar'](null, { url: '../etc/passwd' })).code, 'invalid');
    const av = await handlers['familie:avatar'](null, { url: '/avatars/timsAvatarFile000001.webp' });
    assert.ok(av.data instanceof Uint8Array);
    s.emit('push', { type: 'internet', kind: 'pause_over' });
    assert.deepEqual(sent.at(-1), ['familie:push', { type: 'internet', kind: 'pause_over' }]);
  });

  it('no familie service → no familie:* channels', () => {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf',
    });
    assert.ok(!Object.keys(handlers).some((c) => c.startsWith('familie:')));
  });
});

describe('i18n familie.* (de / en)', () => {
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
    const d = flatten(de.familie, 'familie');
    const e = flatten(en.familie, 'familie');
    assert.deepEqual(Object.keys(d).filter((k) => !(k in e)), []);
    assert.deepEqual(Object.keys(e).filter((k) => !(k in d)), []);
    for (const k of Object.keys(d)) {
      assert.deepEqual(placeholders(e[k]), placeholders(d[k]), k);
      assert.ok(d[k].trim() && e[k].trim(), k);
    }
    assert.equal(d['familie.tab.internet'], 'Internet zu Hause');
    assert.equal(d['familie.presence.wifi.title'], 'WLAN-Erkennung verwenden');
    // the spelling the user decided on
    for (const k of Object.keys(d)) assert.ok(!/zuhause/i.test(d[k]), k);
  });

  it('a text for every code and enum the helpers know', () => {
    const d = flatten(de.familie, 'familie');
    for (const c of familie.CATEGORIES) assert.ok(d[`familie.internet.cat.${c}`], c);
    for (const c of ['not_found', 'not_allowed', 'unavailable']) assert.ok(d[`familie.rules.problem.${c}`], c);
    for (const c of ['invalid', 'parents_only', 'not_found', 'unavailable', 'not_person', 'module_off', 'not_member', 'forbidden']) assert.ok(d[`familie.err.${c}`], c);
  });
});
