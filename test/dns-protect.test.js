'use strict';

// "DNS-Schutz" (the DNS filter of the VPN devices, plugin gatecontrol-dns,
// server from 1.264.0): the pure helpers (utils/dns-protect.js — what
// permissions says, the cleaned status, the body of a pause, the tray
// entries), the service (services/dns-protect.js — only while the server
// reports a DNS protection, older servers and a missing plugin without an
// error, pause / resume, the last answer while the plugin is in trouble, how
// often it asks, 'outage' when the filter fails), its IPC (dnsprotect:*) and
// the dnsProtect.* texts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const dns = require('../src/utils/dns-protect');
const DnsProtectService = require('../src/services/dns-protect');
const MessengerApi = require('../src/services/messenger-api');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const de = require('../src/i18n/locales/de.json');
const en = require('../src/i18n/locales/en.json');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const { MessengerError } = MessengerApi;
const ms = (iso) => Date.parse(iso);
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);

// Thursday, 12 November 2026, 14:48 in Berlin
const NOW = ms('2026-11-12T13:48:00.000Z');
const PLUGIN = 'gatecontrol-dns';
const BASE = `/api/v1/client/plugins/${PLUGIN}/api/`;
const PERMS = { ok: true, permissions: {}, vpnDns: { plugin: PLUGIN, state: 'filtering' } };

const MAY = { pause: true, resume: false, extend: false, reason: null, durations: [5, 30, 60], maxMinutes: 60, forever: false };
const status = (o = {}) => ({
  ok: true,
  state: 'active',
  enabled: true,
  device: { peerId: 21, name: 'Annas Laptop', platform: 'windows', state: 'filtered', ownDns: null },
  profile: { id: 'p1a2b3c4d', name: 'Standard', safeSearch: false },
  pause: null,
  outage: null,
  counters: { scope: 'device', queries: 2106, blocked: 318, percent: 15.1 },
  top: [{ domain: 'googlesyndication.com', count: 74 }, { domain: 'doubleclick.net', count: 61 }],
  may: { ...MAY },
  today: [],
  devices: [],
  manage: false,
  log: { enabled: true, visible: true },
  serverTime: '2026-11-12T13:48:00.000Z',
  ...o,
});
const PAUSE = { scope: 'peer', until: '2026-11-12T14:12:00.000Z', openEnd: false, since: '2026-11-12T13:42:00.000Z', by: { userId: 2, name: 'Anna' }, byMe: true, remainingSeconds: 1440 };
const paused = (o = {}) => status({ state: 'paused', pause: { ...PAUSE }, may: { ...MAY, pause: false, resume: true, extend: true }, ...o });
const fallback = () => status({ state: 'fallback', outage: { since: '2026-11-12T13:31:00.000Z' }, may: { ...MAY, pause: false, reason: 'fallback' } });

const refusal = (statusCode, code, extra = {}) => new MessengerError(extra.error || code, { status: statusCode, code, body: { ok: false, code, ...extra } });

/** A transport like MessengerApi: routes → answer | Error | function. */
function fakeApi(routes) {
  const api = {
    routes: { [`GET ${dns.PERMISSIONS_PATH}`]: PERMS, ...routes },
    calls: [],
    key: 'https://gc.example\ntoken',
    scope() { return this.key; },
    async _call(method, path, opts = {}) {
      const short = path.startsWith(BASE) ? path.slice(BASE.length) : path;
      this.calls.push([method, short, opts.body, opts.params]);
      let r = this.routes[`${method} ${short}`];
      if (typeof r === 'function') r = r(opts.body);
      if (r === undefined) throw refusal(404, 'not_found');
      if (r instanceof Error) throw r;
      return JSON.parse(JSON.stringify(r));
    },
  };
  return api;
}

function service(routes = {}, opts = {}) {
  const api = fakeApi({ 'GET status': status(), ...routes });
  let clock = NOW;
  const s = new DnsProtectService({ api, log, now: () => clock, getLocale: () => 'de', ...opts });
  return { s, api, tick: (n) => { clock += n; }, asked: (route) => api.calls.filter((c) => `${c[0]} ${c[1]}` === route).length };
}

describe('utils/dns-protect', () => {
  it('permissions: the field missing, null, or the plugin that serves the apps', () => {
    assert.deepEqual(dns.vpnDnsOf({ ok: true, permissions: {} }), { supported: false, plugin: null, filter: null });
    assert.deepEqual(dns.vpnDnsOf({ vpnDns: null }), { supported: true, plugin: null, filter: null });
    assert.deepEqual(dns.vpnDnsOf({ vpnDns: { plugin: PLUGIN, state: 'fallback' } }), { supported: true, plugin: PLUGIN, filter: 'fallback' });
    // an unknown state is "not filtering yet", a plugin id that is no id is "none"
    assert.equal(dns.vpnDnsOf({ vpnDns: { plugin: PLUGIN, state: 'weird' } }).filter, 'starting');
    assert.equal(dns.vpnDnsOf({ vpnDns: { plugin: '../../admin', state: 'filtering' } }).plugin, null);
    assert.equal(dns.vpnDnsOf(null).supported, false);
    assert.equal(dns.apiBase('other-dns'), '/api/v1/client/plugins/other-dns/api/');
    assert.equal(dns.apiBase('a/b'), null);
  });

  it('status: only known fields, times as ms, server text cleaned', () => {
    const s = dns.normalizeStatus(status({
      device: { peerId: 21, name: 'Annas\u0007 Laptop', platform: 'windows', state: 'filtered', ownDns: null, ip: '10.8.0.13' },
      top: [{ domain: 'Ads.Example.com', count: 7 }, { domain: '<img src=x>', count: 3 }, { domain: 'ok.example', count: -1 }, null, ...Array(9).fill({ domain: 'x.example', count: 1 })],
      may: { ...MAY, durations: [240, 5, 5, 17, '30'], maxMinutes: 99999999 },
    }));
    assert.equal(s.state, 'active');
    assert.deepEqual(s.device, { peerId: 21, name: 'Annas  Laptop', state: 'filtered', ownDns: null });
    assert.deepEqual(s.counters, { scope: 'device', queries: 2106, blocked: 318, percent: 15.1 });
    assert.equal(s.top.length, 5);
    assert.deepEqual(s.top.slice(0, 2), [{ domain: 'ads.example.com', count: 7 }, { domain: 'ok.example', count: 0 }]);
    assert.deepEqual(s.may.durations, [5, 240]);
    assert.equal(s.may.maxMinutes, dns.MAX_MINUTES);
    assert.equal(s.serverTime, NOW);
    assert.equal(s.pause, null);
    assert.equal(s.outage, null);
    assert.equal(dns.normalizeStatus({ ok: true, state: 'whatever' }), null);
    assert.equal(dns.normalizeStatus(null), null);
    assert.equal(dns.normalizeStatus(status({ top: null })).top, null);
  });

  it('status: pause, open end, outage, a device with its own DNS server', () => {
    const p = dns.normalizeStatus(paused());
    assert.deepEqual(p.pause, { scope: 'peer', until: ms('2026-11-12T14:12:00Z'), openEnd: false, since: ms('2026-11-12T13:42:00Z'), by: { userId: 2, name: 'Anna' }, byMe: true });
    const open = dns.normalizeStatus(paused({ pause: { scope: 'all', until: null, openEnd: true, since: null, by: null, byMe: false, remainingSeconds: null } }));
    assert.deepEqual(open.pause, { scope: 'all', until: null, openEnd: true, since: null, by: null, byMe: false });
    // a pause only counts while the state says so; one without an end is none
    assert.equal(dns.normalizeStatus(status({ pause: { ...PAUSE } })).pause, null);
    assert.equal(dns.normalizeStatus(paused({ pause: { scope: 'peer', until: 'soon' } })).pause, null);
    assert.deepEqual(dns.normalizeStatus(fallback()).outage, { since: ms('2026-11-12T13:31:00Z') });
    assert.equal(dns.normalizeStatus(fallback()).may.reason, 'fallback');
    const own = dns.normalizeStatus(status({ state: 'unfiltered', device: { peerId: 3, name: 'PC', state: 'ownDns', ownDns: '1.1.1.1' } }));
    assert.deepEqual([own.device.state, own.device.ownDns], ['ownDns', '1.1.1.1']);
    assert.equal(dns.normalizeStatus(status({ device: { peerId: 3, name: 'PC', state: 'ownDns', ownDns: '<b>' } })).device.ownDns, null);
    assert.equal(dns.normalizeStatus(status({ device: null })).device, null);
    assert.equal(dns.normalizeMay({ reason: 'made_up' }).reason, null);
  });

  it('pause body: exactly one of minutes, forever, extend', () => {
    assert.deepEqual(dns.pauseBody({ minutes: 30 }), { minutes: 30 });
    assert.deepEqual(dns.pauseBody({ forever: true, minutes: undefined, extend: null }), { forever: true });
    assert.deepEqual(dns.pauseBody({ extend: 30 }), { extend: 30 });
    for (const bad of [null, {}, { minutes: 30, forever: true }, { minutes: 0 }, { minutes: '30' }, { minutes: 1.5 }, { minutes: dns.MAX_MINUTES + 1 }, { forever: 'yes' }, { extend: -5 }]) {
      assert.equal(dns.pauseBody(bad), null, JSON.stringify(bad));
    }
  });

  it('the server\'s clock decides; a PC clock that is off is corrected', () => {
    const snap = { data: { serverTime: NOW }, fetchedAt: 1000 };
    assert.equal(dns.serverNow(snap, 1000), NOW);
    assert.equal(dns.serverNow(snap, 61000), NOW + 60000);
    assert.equal(dns.serverNow({ data: null }, 5000), 5000);
    const until = ms('2026-11-12T14:12:00Z');
    assert.equal(dns.onLocalClock(until, { data: { serverTime: NOW }, fetchedAt: NOW + 900 }), until);
    assert.equal(dns.onLocalClock(until, { data: { serverTime: NOW }, fetchedAt: NOW + 3600000 }), until + 3600000);
    assert.match(dns.clockText(until, 'de'), /^\d\d:12$/);
  });

  it('tray entries follow the state and what the server allows', () => {
    const calls = [];
    const items = (data, extra = {}) => dns.dnsProtectMenuItems({
      snapshot: { state: 'available', data: data ? dns.normalizeStatus(data) : null, fetchedAt: NOW, ...extra }, t, locale: 'de',
      pause: (how) => calls.push(['pause', how]), resume: () => calls.push(['resume']),
    });
    // active: the state and the submenu with the allowed durations
    const a = items(status());
    assert.deepEqual(a.map((i) => [i.label, i.enabled]), [['dnsProtect.tray.active', false], ['dnsProtect.tray.pause', undefined]]);
    assert.deepEqual(a[1].submenu.map((i) => i.label || i.type), ['dnsProtect.tray.minutes.5', 'dnsProtect.tray.minutes.30', 'dnsProtect.tray.minutes.60', 'separator', 'dnsProtect.forever']);
    assert.equal(a[1].submenu.at(-1).enabled, false);
    a[1].submenu[1].click();
    assert.deepEqual(calls.pop(), ['pause', { minutes: 30 }]);
    const adm = items(status({ may: { ...MAY, durations: [5, 30, 60, 240], forever: true } }));
    assert.equal(adm[1].submenu.length, 6);
    adm[1].submenu.at(-1).click();
    assert.deepEqual(calls.pop(), ['pause', { forever: true }]);
    // not allowed: the state only
    assert.deepEqual(items(status({ may: { ...MAY, pause: false, reason: 'admins_only' } })).map((i) => i.label), ['dnsProtect.tray.active']);
    // paused: until when, and "wieder einschalten" when allowed
    const p = items(paused());
    assert.match(p[0].label, /^dnsProtect\.tray\.pausedUntil\(\d\d:12\)$/);
    assert.equal(p[0].enabled, false);
    p[1].click();
    assert.deepEqual(calls.pop(), ['resume']);
    const all = items(paused({ pause: { scope: 'all', until: null, openEnd: true, since: null, by: null, byMe: false }, may: { ...MAY, pause: false, reason: 'paused_for_all' } }));
    assert.deepEqual(all.map((i) => i.label), ['dnsProtect.tray.paused']);
    // fallback: one line; not filtered: one line; nothing while there is no DNS protection
    assert.deepEqual(items(fallback()).map((i) => [i.label, i.enabled]), [['dnsProtect.tray.fallback', false]]);
    assert.deepEqual(items(status({ state: 'unfiltered' })).map((i) => i.label), ['dnsProtect.tray.unfiltered']);
    assert.deepEqual(items(status({ state: 'starting' })), []);
    assert.deepEqual(items(null), []);
    assert.deepEqual(items(status(), { state: 'unavailable' }), []);
    assert.deepEqual(dns.dnsProtectMenuItems({ snapshot: null, t, pause() {}, resume() {} }), []);
  });
});

describe('DnsProtectService', () => {
  it('older server, no plugin, no token: no DNS protection and no error', async () => {
    for (const [answer, reason] of [
      [{ ok: true, permissions: {} }, 'old_server'],
      [{ ok: true, permissions: {}, vpnDns: null }, 'none'],
      [refusal(401, 'unauthorized'), 'auth'],
      [refusal(404, 'http_404'), 'old_server'],
      [new MessengerError('not configured', { code: 'not_configured' }), 'not_configured'],
    ]) {
      const { s, api } = service({ [`GET ${dns.PERMISSIONS_PATH}`]: answer });
      const snap = await s.check();
      assert.deepEqual([snap.state, snap.reason, snap.plugin, snap.data], ['unavailable', reason, null, null], reason);
      assert.equal(api.calls.length, 1);
      assert.equal(s.available(), false);
      await assert.rejects(s.pause({ minutes: 5 }), (e) => e.code === 'unavailable');
    }
  });

  it('the plugin named by permissions is asked, in the app\'s language', async () => {
    const { s, api } = service({ [`GET ${dns.PERMISSIONS_PATH}`]: { ok: true, vpnDns: { plugin: 'other-dns', state: 'filtering' } } });
    const events = [];
    s.on('change', (x) => events.push(x));
    await s.check();
    // another plugin id → another base: the fake answers 404 → no DNS protection
    assert.deepEqual(api.calls.at(-1).slice(0, 2), ['GET', '/api/v1/client/plugins/other-dns/api/status']);
    assert.deepEqual([s.snapshot().state, s.snapshot().reason], ['unavailable', 'not_found']);

    const ok = service();
    const snap = await ok.s.check();
    assert.deepEqual(ok.api.calls.map((c) => [c[0], c[1], c[3]]), [['GET', dns.PERMISSIONS_PATH, undefined], ['GET', 'status', { lang: 'de' }]]);
    assert.deepEqual([snap.state, snap.plugin, snap.filter, snap.stale, snap.error, snap.fetchedAt], ['available', PLUGIN, 'filtering', false, null, NOW]);
    assert.equal(snap.data.state, 'active');
    assert.equal(snap.data.counters.blocked, 318);
  });

  it('pause, "+30 Min." and resume take the status of the answer', async () => {
    const { s, api, asked } = service({
      'POST pause': (body) => ({ ok: true, pause: PAUSE, status: paused(body.extend ? { pause: { ...PAUSE, until: '2026-11-12T14:42:00.000Z' } } : {}) }),
      'POST resume': { ok: true, resumed: true, status: status() },
    });
    await s.check();
    const changes = [];
    s.on('change', (x) => changes.push(x.data.state));
    const r = await s.pause({ minutes: 30 });
    assert.deepEqual(api.calls.at(-1), ['POST', 'pause', { minutes: 30 }, { lang: 'de' }]);
    assert.deepEqual([r.ok, r.snapshot.data.state, r.snapshot.data.pause.until], [true, 'paused', ms('2026-11-12T14:12:00Z')]);
    assert.equal((await s.pause({ extend: 30 })).snapshot.data.pause.until, ms('2026-11-12T14:42:00Z'));
    const back = await s.resume();
    assert.deepEqual([back.resumed, back.snapshot.data.state], [true, 'active']);
    assert.deepEqual(api.calls.at(-1).slice(0, 3), ['POST', 'resume', {}]);
    assert.deepEqual(changes, ['paused', 'paused', 'active']);
    assert.equal(asked('GET status'), 1); // no second call after a change
    await assert.rejects(s.pause({ minutes: 30, forever: true }), (e) => e.code === 'invalid');
    api.routes['POST resume'] = { ok: true, resumed: false, status: status() };
    assert.equal((await s.resume()).resumed, false);
  });

  it('a refusal carries the plugin\'s sentence and reloads the status', async () => {
    const { s, api, asked } = service({
      'POST pause': refusal(403, 'not_allowed', { reason: 'profile', error: 'Für dein Profil hat der Admin das Unterbrechen gesperrt.' }),
    });
    await s.check();
    api.routes['GET status'] = status({ may: { ...MAY, pause: false, reason: 'profile' } });
    await assert.rejects(s.pause({ minutes: 5 }), (e) => e.code === 'not_allowed' && e.status === 403 && e.body.reason === 'profile' && /Profil/.test(e.message));
    await new Promise((r) => setImmediate(r));
    assert.equal(asked('GET status'), 2);
    assert.equal(s.snapshot().data.may.reason, 'profile');
    api.routes['POST pause'] = refusal(403, 'forever_not_allowed');
    await assert.rejects(s.pause({ forever: true }), (e) => e.code === 'forever_not_allowed');
    // a wrong body is the app's mistake: nothing to reload
    await new Promise((r) => setImmediate(r));
    const before = asked('GET status');
    api.routes['POST pause'] = refusal(400, 'invalid', { detail: 'minutes' });
    await assert.rejects(s.pause({ minutes: 5 }), (e) => e.code === 'invalid');
    await new Promise((r) => setImmediate(r));
    assert.equal(asked('GET status'), before);
  });

  it('the plugin gone or switched off: no card; the plugin in trouble: the last answer', async () => {
    for (const [err, reason] of [
      [refusal(404, 'not_found'), 'not_found'],
      [refusal(501, 'unsupported'), 'unsupported'],
      [refusal(409, 'off'), 'off'],
      [refusal(403, 'no_user'), 'no_user'],
    ]) {
      const { s, api } = service();
      await s.check();
      api.routes['GET status'] = err;
      const snap = await s.refresh();
      assert.deepEqual([snap.state, snap.reason, snap.data, snap.plugin], ['unavailable', reason, null, null], reason);
      // … and a change that meets it says the same
      const c = service({ 'POST pause': err });
      await c.s.check();
      await assert.rejects(c.s.pause({ minutes: 5 }));
      assert.equal(c.s.snapshot().state, 'unavailable');
    }
    for (const err of [refusal(502, 'plugin_error'), refusal(503, 'not_running'), refusal(504, 'timeout'), refusal(503, 'unavailable'), refusal(429, 'rate_limited'), new MessengerError('network error', { code: 'network' })]) {
      const { s, api } = service();
      await s.check();
      api.routes['GET status'] = err;
      const snap = await s.refresh();
      assert.deepEqual([snap.state, snap.stale, snap.error, snap.data.state], ['available', true, err.code, 'active'], err.code);
      api.routes['GET status'] = paused();
      assert.deepEqual([(await s.refresh()).stale, s.snapshot().error, s.snapshot().data.state], [false, null, 'paused']);
    }
    // trouble before the first answer: the card says "not reachable"
    const first = service({ 'GET status': refusal(503, 'not_running') });
    const snap = await first.s.check();
    assert.deepEqual([snap.state, snap.data, snap.stale, snap.error], ['available', null, false, 'not_running']);
    // an answer the app does not understand is trouble, not a state
    const odd = service({ 'GET status': { ok: true, state: 'brand_new' } });
    assert.equal((await odd.s.check()).error, 'bad_response');
  });

  it('no network at the start is an error that is asked again; a card that was there stays', async () => {
    const { s, api } = service({ [`GET ${dns.PERMISSIONS_PATH}`]: new MessengerError('network error', { code: 'network' }) });
    assert.deepEqual([(await s.check()).state, s.snapshot().reason], ['error', 'network']);
    api.routes[`GET ${dns.PERMISSIONS_PATH}`] = PERMS;
    assert.equal((await s.check()).state, 'available');
    api.routes[`GET ${dns.PERMISSIONS_PATH}`] = refusal(502, 'http_502');
    const snap = await s.check();
    assert.deepEqual([snap.state, snap.data.state], ['available', 'active']);
  });

  it('"outage" once when the filter goes from running to the fallback', async () => {
    const { s, api } = service();
    const outages = [];
    s.on('outage', (o) => outages.push(o));
    await s.check();
    api.routes['GET status'] = fallback();
    const snap = await s.refresh();
    assert.deepEqual([snap.filter, snap.data.state], ['fallback', 'fallback']);
    assert.deepEqual(outages, [{ since: ms('2026-11-12T13:31:00Z') }]);
    await s.refresh();
    assert.equal(outages.length, 1);
    api.routes['GET status'] = status();
    await s.refresh();
    api.routes['GET status'] = fallback();
    await s.refresh();
    assert.equal(outages.length, 2);

    // already down when the app starts: shown, not announced
    const down = service({ [`GET ${dns.PERMISSIONS_PATH}`]: { ok: true, vpnDns: { plugin: PLUGIN, state: 'fallback' } }, 'GET status': fallback() });
    const seen = [];
    down.s.on('outage', (o) => seen.push(o));
    assert.equal((await down.s.check()).filter, 'fallback');
    assert.deepEqual(seen, []);
  });

  it('asks again: 45 s while watched, 5 min otherwise, shortly after the end of a pause', async () => {
    const timers = [];
    const realSet = global.setTimeout;
    const realClear = global.clearTimeout;
    global.setTimeout = (fn, delay) => { const h = { fn, delay, unref() {} }; timers.push(h); return h; };
    global.clearTimeout = (h) => { const i = timers.indexOf(h); if (i >= 0) timers.splice(i, 1); };
    try {
      const pc = new EventEmitter();
      const { s, api, asked, tick } = service({}, { pushClient: pc });
      s.start();
      await s.check();
      assert.deepEqual(timers.map((x) => x.delay), [DnsProtectService.DEFAULT_TIMING.idleMs]);
      s.watch(true);
      assert.deepEqual(timers.map((x) => x.delay), [DnsProtectService.DEFAULT_TIMING.pollMs]);
      // a pause that ends before the next question: asked 2 s after its end
      api.routes['GET status'] = paused({ pause: { ...PAUSE, until: '2026-11-12T13:49:00.000Z' } });
      s.watch(false);
      await s.refresh();
      assert.deepEqual(timers.map((x) => x.delay), [60000 + 2000]);
      // one that runs longer: the usual interval
      api.routes['GET status'] = paused();
      await s.refresh();
      assert.deepEqual(timers.map((x) => x.delay), [DnsProtectService.DEFAULT_TIMING.idleMs]);
      // 429 stretches the interval
      api.routes['GET status'] = refusal(429, 'rate_limited');
      s.watch(true);
      tick(60000);
      await s.refresh();
      assert.deepEqual(timers.map((x) => x.delay), [DnsProtectService.DEFAULT_TIMING.pollMs * 2]);
      // the timer asks the status
      api.routes['GET status'] = status();
      const before = asked('GET status');
      await timers[0].fn();
      await new Promise((r) => setImmediate(r));
      assert.equal(asked('GET status'), before + 1);
      // shown again after a while: asked at once
      s.watch(false);
      tick(10 * 60000);
      s.watch(true);
      await new Promise((r) => setImmediate(r));
      assert.equal(asked('GET status'), before + 2);
      // a push reconnect asks permissions again
      const perms = asked(`GET ${dns.PERMISSIONS_PATH}`);
      pc.emit('hello');
      await new Promise((r) => setImmediate(r));
      assert.equal(asked(`GET ${dns.PERMISSIONS_PATH}`), perms + 1);
      // no DNS protection: permissions again after 10 min, no status timer
      api.routes[`GET ${dns.PERMISSIONS_PATH}`] = { ok: true, vpnDns: null };
      await s.check();
      assert.deepEqual(timers.map((x) => x.delay), [DnsProtectService.DEFAULT_TIMING.recheckMs]);
      s.stop();
      assert.deepEqual(timers, []);
      assert.equal(pc.listenerCount('hello'), 0);
    } finally {
      global.setTimeout = realSet;
      global.clearTimeout = realClear;
    }
  });

  it('another server or token: the old state is gone', async () => {
    const { s, api } = service();
    await s.check();
    api.key = 'https://other.example\ntoken';
    api.routes[`GET ${dns.PERMISSIONS_PATH}`] = { ok: true, permissions: {} };
    const changes = [];
    s.on('change', (x) => changes.push(x.state));
    const snap = await s.resetForNewServer();
    assert.deepEqual([snap.state, snap.data], ['unknown', null]);
    assert.deepEqual([(await s.check()).state, s.snapshot().reason], ['unavailable', 'old_server']);
    assert.deepEqual(changes, ['unknown', 'unavailable']);
  });
});

describe('dnsprotect:* IPC', () => {
  function register(s) {
    const handlers = {};
    const sent = [];
    const win = { isDestroyed: () => false, webContents: { send: (ch, p) => sent.push([ch, p]) } };
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0' }, dialog: {}, getMainWindow: () => win, store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {}, log, connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}), wgConfigFile: 'wg.conf', ...(s ? { dnsProtect: s } : {}),
    });
    return { handlers, sent };
  }

  it('channels, argument checks and the event', async () => {
    const { s, api } = service({
      'POST pause': (body) => (body.forever ? refusal(403, 'not_allowed', { reason: 'profile', error: 'Gesperrt.' }) : { ok: true, pause: PAUSE, status: paused() }),
      'POST resume': { ok: true, resumed: true, status: status() },
    });
    const { handlers, sent } = register(s);
    for (const ch of ['dnsprotect:status', 'dnsprotect:check', 'dnsprotect:refresh', 'dnsprotect:pause', 'dnsprotect:resume', 'dnsprotect:watch']) assert.ok(handlers[ch], ch);
    assert.equal(handlers['dnsprotect:status']().state, 'unknown');
    assert.equal((await handlers['dnsprotect:check']()).state, 'available');
    assert.equal(sent.at(-1)[0], 'dnsprotect:change');
    assert.equal((await handlers['dnsprotect:refresh']()).data.state, 'active');
    const p = await handlers['dnsprotect:pause'](null, { minutes: 30, peerId: 99, all: true });
    assert.deepEqual([p.ok, p.snapshot.data.state], [true, 'paused']);
    // only the three ways reach the server — no target
    assert.deepEqual(api.calls.at(-1).slice(0, 3), ['POST', 'pause', { minutes: 30 }]);
    assert.equal(sent.at(-1)[1].data.state, 'paused');
    for (const bad of [null, {}, { minutes: '30' }, { minutes: 5, extend: 30 }]) assert.equal((await handlers['dnsprotect:pause'](null, bad)).code, 'invalid');
    assert.deepEqual(await handlers['dnsprotect:pause'](null, { forever: true }), { ok: false, code: 'not_allowed', error: 'Gesperrt.', status: 403, reason: 'profile' });
    assert.equal((await handlers['dnsprotect:resume']()).resumed, true);
    assert.deepEqual(await handlers['dnsprotect:watch'](null, { on: true }), { ok: true });
  });

  it('no service → no dnsprotect:* channels', () => {
    assert.ok(!Object.keys(register(null).handlers).some((c) => c.startsWith('dnsprotect:')));
  });
});

describe('i18n dnsProtect.* (de / en)', () => {
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
    const d = flatten(de.dnsProtect, 'dnsProtect');
    const e = flatten(en.dnsProtect, 'dnsProtect');
    assert.deepEqual(Object.keys(d).filter((k) => !(k in e)), []);
    assert.deepEqual(Object.keys(e).filter((k) => !(k in d)), []);
    for (const k of Object.keys(d)) {
      assert.deepEqual(placeholders(e[k]), placeholders(d[k]), k);
      assert.ok(d[k].trim() && e[k].trim(), k);
    }
    assert.equal(d['dnsProtect.title'], 'DNS-Schutz');
    assert.equal(d['dnsProtect.tray.fallback'], 'DNS-Schutz: ausgefallen (ungefiltert)');
  });

  it('a text for every duration and every reason the card explains', () => {
    const d = flatten(de.dnsProtect, 'dnsProtect');
    for (const m of dns.DURATIONS) {
      assert.ok(d[`dnsProtect.dur.${m}`], `dur ${m}`);
      assert.ok(d[`dnsProtect.tray.minutes.${m}`], `tray ${m}`);
    }
    for (const r of ['profile', 'admins_only']) assert.ok(d[`dnsProtect.banner.${r}`], r);
    for (const s of ['active', 'paused', 'fallback', 'unfiltered', 'starting']) assert.ok(d[`dnsProtect.chip.${s}`], s);
  });
});
