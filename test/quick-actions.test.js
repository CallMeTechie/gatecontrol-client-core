'use strict';

// Plugin quick actions ("Schnellaktionen", server /api/v1/client/actions,
// fields up to 1.317.1): the checks of utils/quick-actions.js (as strict as
// the host: choice without a selection, disabled controls, the day bar), the
// service (services/quick-actions.js — listing, an older server, the last
// answer while offline, runs and their refusals) and its IPC (quickactions:*).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const qa = require('../src/utils/quick-actions');
const QuickActionsService = require('../src/services/quick-actions');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FLAME = 'M12 2c3 4 6 6 6 11a6 6 0 0 1-12 0c0-3 2-5 3-7';
const SUN = 'M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8';

function heating(over = {}) {
  return {
    plugin: 'gatecontrol-smarthome', pluginName: 'Smart Home', id: 'heat:room:3', kind: 'button', title: 'Wohnzimmer',
    device: { id: 'heat:3', title: 'Wohnzimmer' },
    widget: {
      label: 'Ist', value: 20.5, unit: '°C', status: 'Komfort · nach Plan bis 08:00',
      badge: { icon: FLAME, value: 40, unit: '%', label: 'Ventil' },
      readings: [{ id: 'hum', label: 'Feuchte', value: 48, unit: '%' }, { id: 'bat', label: 'Batterie', value: 80, unit: '%' }],
      controls: [
        { id: 'sp', kind: 'stepper', label: 'Soll', value: 21, min: 5, max: 30, step: 0.5, unit: '°C' },
        { id: 'preset', kind: 'choice', value: 'comfort', options: [{ id: 'comfort', label: 'Komfort', icon: SUN }, { id: 'eco', label: 'Eco' }] },
      ],
      timeline: { now: 6.87, segments: [{ from: 0, to: 6, tone: 'neutral', label: 'Nacht' }, { from: 6, to: 8, color: '#F59E0B', label: 'Komfort' }, { from: 8, to: 24, tone: 'good' }] },
    },
    ...over,
  };
}

describe('utils/quick-actions: checks like the host', () => {
  it('keeps a valid action with widget, badge, readings, controls and timeline', () => {
    const a = qa.sanitizeAction(heating());
    assert.equal(a.kind, 'button');
    assert.deepEqual(a.device, { id: 'heat:3', title: 'Wohnzimmer', subtitle: null, icon: null });
    assert.equal(a.widget.value, 20.5);
    assert.deepEqual(a.widget.badge, { icon: FLAME, value: 40, unit: '%', state: null, label: 'Ventil' });
    assert.equal(a.widget.readings.length, 2);
    assert.deepEqual(a.widget.controls.map((c) => [c.id, c.kind, c.value, c.disabled]), [['sp', 'stepper', 21, false], ['preset', 'choice', 'comfort', false]]);
    assert.equal(a.widget.timeline.from, 0);
    assert.equal(a.widget.timeline.to, 24);
    assert.equal(a.widget.timeline.now, 6.87);
    assert.equal(a.widget.timeline.segments[1].color, '#f59e0b');
  });

  it('choice: null = no option active, an unknown value = the first', () => {
    const opts = [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }];
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: null, options: opts }).value, null);
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: 'zz', options: opts }).value, 'a');
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', options: opts }).value, 'a');
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: 'b', options: opts }).value, 'b');
    // 1 or 9 options, a duplicate id, an option without a label → invalid
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: 'a', options: [opts[0]] }), null);
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: 'a', options: [opts[0], opts[0]] }), null);
    assert.equal(qa.sanitizeControl({ id: 'c', kind: 'choice', value: 'a', options: [opts[0], { id: 'x' }] }), null);
  });

  it('disabled only for a JSON true; a stepper value into its range', () => {
    const s = { id: 's', kind: 'stepper', value: 50, min: 5, max: 30, step: 0.5 };
    assert.equal(qa.sanitizeControl({ ...s, disabled: true }).disabled, true);
    for (const d of ['true', 1, null, undefined]) assert.equal(qa.sanitizeControl({ ...s, disabled: d }).disabled, false);
    assert.equal(qa.sanitizeControl(s).value, 30);
    assert.equal(qa.sanitizeControl({ ...s, step: 0 }), null);
    assert.equal(qa.sanitizeControl({ ...s, min: 30, max: 5 }), null);
  });

  it('an invalid control makes the widget null, the action stays', () => {
    const a = qa.sanitizeAction(heating({ widget: { value: 1, controls: [{ id: 'x', kind: 'knob' }] } }));
    assert.ok(a);
    assert.equal(a.widget, null);
    // more than 4 controls
    const many = Array.from({ length: 5 }, (_, i) => ({ id: `s${i}`, kind: 'slider', value: 1, min: 0, max: 2, step: 1 }));
    assert.equal(qa.sanitizeWidget({ controls: many }), null);
  });

  it('timeline: anything invalid → null, the widget stays', () => {
    const w = (timeline) => qa.sanitizeWidget({ value: 1, timeline });
    const seg = (from, to, extra = {}) => ({ from, to, ...extra });
    assert.ok(w({ segments: [seg(0, 24)] }).timeline);
    assert.deepEqual(w({ from: 6, to: 22, segments: [seg(6, 8), seg(10, 22)] }).timeline.segments.map((s) => [s.from, s.to]), [[6, 8], [10, 22]]);
    const bad = [
      { segments: [] },
      { segments: Array.from({ length: 13 }, (_, i) => seg(i, i + 1)) },
      { segments: [seg(0, 8), seg(6, 10)] },          // overlapping
      { segments: [seg(8, 10), seg(0, 6)] },          // out of order
      { segments: [seg(0, 25)] },                     // past `to`
      { segments: [seg(5, 5)] },                      // empty
      { now: 25, segments: [seg(0, 24)] },
      { now: '6', segments: [seg(0, 24)] },
      { from: 10, to: 10, segments: [seg(10, 11)] },
      { from: 'x', segments: [seg(0, 1)] },
      { segments: [seg(0, 1, { tone: 'blue' })] },
      { segments: [seg(0, 1, { color: 'red' })] },
      { segments: [seg(0, 1, { color: '#12345' })] },
      { segments: [seg(0, 1, { label: '' })] },
      { segments: [seg(0, 1, { label: 'x'.repeat(21) })] },
      { segments: [seg(0, 1, { label: 'a\nb' })] },
      { segments: [null] },
      'today',
    ];
    for (const t of bad) {
      const r = w(t);
      assert.ok(r, JSON.stringify(t));
      assert.equal(r.timeline, null, JSON.stringify(t));
    }
  });

  it('readings are dropped one by one, an invalid badge becomes null', () => {
    const w = qa.sanitizeWidget({
      value: 1,
      readings: [{ id: 'a', label: 'A', value: 1 }, { id: 'a', label: 'A2', value: 2 }, { id: 'b', label: 'B' }, { id: 'c d', label: 'C', value: 1 }, { id: 'e', label: 'E', icon: SUN }],
      badge: { value: 3 },
    });
    assert.deepEqual(w.readings.map((r) => r.id), ['a', 'e']);
    assert.equal(w.badge, null);
    assert.equal(qa.sanitizeBadge({ icon: FLAME, value: 'zu lang!!!', unit: '%' }).value, null);
    assert.equal(qa.sanitizeBadge({ icon: FLAME, unit: '%' }).unit, null);
  });

  it('drops invalid actions and duplicates; toggles keep state, look, verbs', () => {
    const list = qa.sanitizeActions([
      heating(),
      heating(),
      { ...heating(), id: 'bad id' },
      { ...heating(), plugin: 'Bad_Plugin' },
      { ...heating(), title: '' },
      { ...heating(), kind: 'slider' },
      {
        plugin: 'gatecontrol-smarthome', pluginName: 'Smart Home', id: 'heat:away', kind: 'toggle', title: 'Heizung abwesend', state: 'off',
        targets: true, verbs: { on: 'Abwesend', off: 'Zu Hause' }, confirmWhen: 'on', look: { on: { tone: 'warn' } },
      },
      { plugin: 'gatecontrol-smarthome', id: 'heat:boost:3', title: 'Boost', state: 'on', targets: true, confirmWhen: 'on' },
    ]);
    assert.deepEqual(list.map((a) => a.id), ['heat:room:3', 'heat:away', 'heat:boost:3']);
    const t = list[1];
    assert.deepEqual([t.state, t.targets, t.confirmWhen, t.verbs.on, t.look.on.tone, t.look.off], ['off', true, 'on', 'Abwesend', 'warn', null]);
    // a button has no state / targets; pluginName falls back to the id
    assert.deepEqual([list[2].state, list[2].targets, list[2].confirmWhen, list[2].pluginName], [null, false, null, 'gatecontrol-smarthome']);
    assert.deepEqual(qa.sanitizeActions('x'), []);
  });

  it('runBody: a button, a state or a control — never both', () => {
    assert.deepEqual(qa.runBody({}), { source: 'app' });
    assert.deepEqual(qa.runBody({ state: 'on' }), { source: 'app', state: 'on' });
    assert.deepEqual(qa.runBody({ control: 'sp', value: 21.5 }), { source: 'app', control: 'sp', value: 21.5 });
    assert.deepEqual(qa.runBody({ control: 'preset', value: 'eco' }), { source: 'app', control: 'preset', value: 'eco' });
    for (const bad of [{ state: 'maybe' }, { control: 'sp', value: NaN }, { control: 'sp' }, { control: 'a b', value: 1 }, { control: 'sp', value: 1, state: 'on' }, { source: 'tile' }]) {
      assert.equal(qa.runBody(bad), null, JSON.stringify(bad));
    }
  });

  it('failureReason', () => {
    assert.equal(qa.failureReason(409, 'control_disabled'), 'control_disabled');
    assert.equal(qa.failureReason(409, 'state_unknown'), 'state_unknown');
    assert.equal(qa.failureReason(404, 'not_found'), 'gone');
    assert.equal(qa.failureReason(403, 'no_user'), 'no_user');
    assert.equal(qa.failureReason(429, 'rate_limited'), 'busy');
    assert.equal(qa.failureReason(504, 'timeout'), 'timeout');
    assert.equal(qa.failureReason(null, 'timeout'), 'timeout');
    assert.equal(qa.failureReason(null, 'network'), 'network');
    assert.equal(qa.failureReason(400, 'invalid_value'), 'invalid');
    assert.equal(qa.failureReason(502, 'plugin_error'), 'failed');
  });
});

/** An ApiClient-like object whose axios `client` answers from `routes` ('GET /path' → data | fn | error). */
function fakeApi(routes) {
  const calls = [];
  const apiClient = {
    serverUrl: 'https://gc.example.test', apiKey: 'gc_token',
    client: {
      async request(cfg) {
        calls.push(cfg);
        const key = `${cfg.method} ${cfg.url}`;
        let r = routes[key];
        if (typeof r === 'function') r = r(cfg);
        if (r instanceof Error) throw r;
        if (r === undefined) throw httpError(404, { ok: false, error: 'not_found' });
        return { status: 200, data: r };
      },
    },
  };
  return { apiClient, calls };
}

function httpError(status, data) {
  const e = new Error(`HTTP ${status}`);
  e.response = { status, data };
  return e;
}

describe('QuickActionsService', () => {
  const RUN = '/api/v1/client/actions/gatecontrol-smarthome/heat%3Aroom%3A3';

  it('lists the checked actions in the app language', async () => {
    const { apiClient, calls } = fakeApi({ 'GET /api/v1/client/actions': { ok: true, actions: [heating(), { id: 'x' }] } });
    const s = new QuickActionsService({ apiClient, log, getLocale: () => 'en', now: () => 1000 });
    const r = await s.list();
    assert.deepEqual([r.ok, r.supported, r.offline, r.fetchedAt, r.actions.length], [true, true, false, 1000, 1]);
    assert.deepEqual(calls[0].params, { lang: 'en' });
  });

  it('an older server (404): supported false, no error', async () => {
    const { apiClient } = fakeApi({});
    const r = await new QuickActionsService({ apiClient, log }).list();
    assert.deepEqual(r, { ok: true, supported: false, actions: [], fetchedAt: r.fetchedAt, offline: false });
  });

  it('offline: the last answer of the same server, else the reason', async () => {
    let fail = false;
    const { apiClient } = fakeApi({ 'GET /api/v1/client/actions': () => (fail ? Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }) : { ok: true, actions: [heating()] }) });
    const s = new QuickActionsService({ apiClient, log });
    await s.list();
    fail = true;
    const r = await s.list();
    assert.deepEqual([r.ok, r.offline, r.reason, r.actions.length], [true, true, 'network', 1]);
    // another token: the copy is not shown
    apiClient.apiKey = 'other';
    assert.deepEqual(await s.list(), { ok: false, reason: 'network' });
    apiClient.apiKey = 'gc_token';
    s.resetForNewServer();
    assert.deepEqual(await s.list(), { ok: false, reason: 'network' });
  });

  it('not configured', async () => {
    const s = new QuickActionsService({ apiClient: {}, log });
    assert.deepEqual(await s.list(), { ok: false, reason: 'not_configured' });
    assert.equal((await s.run('gatecontrol-smarthome', 'heat:away')).reason, 'not_configured');
  });

  it('runs a control and keeps the new widget for the next offline list', async () => {
    let online = true;
    const { apiClient, calls } = fakeApi({
      'GET /api/v1/client/actions': () => (online ? { ok: true, actions: [heating()] } : Object.assign(new Error('timeout of 15000ms exceeded'), { code: 'ECONNABORTED' })),
      [`POST ${RUN}`]: { ok: true, message: null, state: null, widget: { ...heating().widget, value: 21 }, unchanged: false },
    });
    const s = new QuickActionsService({ apiClient, log });
    await s.list();
    const r = await s.run('gatecontrol-smarthome', 'heat:room:3', { control: 'sp', value: 21.5 });
    assert.deepEqual([r.ok, r.widget.value, r.unchanged], [true, 21, false]);
    assert.deepEqual(calls.at(-1).data, { source: 'app', control: 'sp', value: 21.5 });
    online = false;
    const l = await s.list();
    assert.deepEqual([l.offline, l.reason, l.actions[0].widget.value], [true, 'timeout', 21]);
  });

  it('a toggle with a state; refusals as reasons', async () => {
    const answers = {
      'heat:away': { ok: true, state: 'on', widget: null },
      'heat:plan:3': httpError(409, { ok: false, error: 'control_disabled' }),
      'gone': httpError(404, { ok: false, error: 'not_found' }),
      'busy': httpError(429, { ok: false, error: 'rate_limited' }),
      'slow': httpError(504, { ok: false, error: 'timeout' }),
      'nouser': httpError(403, { ok: false, error: 'no_user' }),
      'says-no': { ok: false, message: 'Fenster offen', state: null, widget: null },
    };
    const routes = {};
    for (const [id, a] of Object.entries(answers)) routes[`POST /api/v1/client/actions/gatecontrol-smarthome/${encodeURIComponent(id)}`] = a;
    const { apiClient, calls } = fakeApi(routes);
    const s = new QuickActionsService({ apiClient, log });
    const on = await s.run('gatecontrol-smarthome', 'heat:away', { state: 'on' });
    assert.deepEqual([on.ok, on.state], [true, 'on']);
    assert.deepEqual(calls.at(-1).data, { source: 'app', state: 'on' });
    assert.equal((await s.run('gatecontrol-smarthome', 'heat:plan:3', { control: 'sp', value: 20 })).reason, 'control_disabled');
    assert.equal((await s.run('gatecontrol-smarthome', 'gone')).reason, 'gone');
    assert.equal((await s.run('gatecontrol-smarthome', 'busy')).reason, 'busy');
    assert.equal((await s.run('gatecontrol-smarthome', 'slow')).reason, 'timeout');
    assert.equal((await s.run('gatecontrol-smarthome', 'nouser')).reason, 'no_user');
    const no = await s.run('gatecontrol-smarthome', 'says-no');
    assert.deepEqual([no.ok, no.reason, no.message], [false, 'failed', 'Fenster offen']);
    // checked before anything is sent
    const n = calls.length;
    assert.equal((await s.run('Bad Plugin', 'x')).reason, 'invalid');
    assert.equal((await s.run('gatecontrol-smarthome', 'heat:away', { state: 'toggle' })).reason, 'invalid');
    assert.equal(calls.length, n);
  });
});

describe('quickactions:* IPC', () => {
  function register(s) {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => null, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', ...(s ? { quickActions: s } : {}),
    });
    return handlers;
  }

  it('list and run; only the known fields reach the service; failures resolve', async () => {
    const seen = [];
    const s = {
      list: async () => ({ ok: true, supported: true, actions: [], fetchedAt: 1, offline: false }),
      run: async (plugin, id, opts) => { seen.push([plugin, id, opts]); return { ok: true }; },
      resetForNewServer() {},
    };
    const h = register(s);
    assert.equal((await h['quickactions:list']()).supported, true);
    await h['quickactions:run'](null, { plugin: 'p-x', id: 'a', control: 'sp', value: 2, extra: 1 });
    await h['quickactions:run'](null, { plugin: 'p-x', id: 'a', state: 'off' });
    await h['quickactions:run'](null, null);
    assert.deepEqual(seen, [['p-x', 'a', { control: 'sp', value: 2 }], ['p-x', 'a', { state: 'off' }], [undefined, undefined, {}]]);
    s.list = async () => { throw new Error('boom'); };
    s.run = async () => { throw new Error('boom'); };
    assert.deepEqual(await h['quickactions:list'](), { ok: false, reason: 'failed' });
    assert.equal((await h['quickactions:run'](null, {})).reason, 'failed');
  });

  it('no service → no quickactions:* channels', () => {
    assert.ok(!Object.keys(register(null)).some((c) => c.startsWith('quickactions:')));
  });
});
