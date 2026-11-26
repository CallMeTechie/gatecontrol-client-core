'use strict';

// Messenger 1.23 (Brücken Stufe 7a): Signal — a further network `signal` that links by QR code only
// (`networks[].flows`), what of the history it brings (`networks[].history`), the consent „Erkennen“ per service
// (`networks[].recognition`, PUT bridges/recognition { allowed, network }), „Im Portal / Windows-Client fortsetzen“
// (POST/DELETE bridges/:network/handoff, GET bridges → handoff, the live event bridge.handoff → `handoff`).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const PushClient = require('../src/services/push-client');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const PUSH_FAST = { initialDelayMs: 20, maxDelayMs: 100, ackDelayMs: 5, networkDebounceMs: 5, connectTimeoutMs: 1000 };
const FEATURES = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_history: true, chat_people: true };
const SIGNAL = { id: 'signal', state: 'running', allowed: true, lock: null, consent: null, logins: [], flows: ['qr'], history: { maxDays: 30, phoneConfirms: true } };

const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function waitFor(fn, ms = 4000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

async function setup({ push = false } = {}) {
  const srv = await messengerServer({ features: FEATURES });
  cleanups.push(() => srv.close());
  srv.state.bridge.networks.push({ ...SIGNAL });
  const store = createMemoryStore();
  const apiClient = new ApiClient(srv.url, 'gc_token', log);
  let pushClient = null;
  if (push) {
    pushClient = new PushClient({ apiClient, store, log, allowHttp: true, timing: PUSH_FAST });
    cleanups.push(() => pushClient.stop());
    pushClient.start();
  }
  const m = new MessengerService({ apiClient, pushClient, store, log, timing: FAST });
  cleanups.push(() => m.stop());
  return { srv, m };
}

describe('Signal (Messenger 1.23) – normalizing', () => {
  it('reads the ways in, the history and the consent of each service; an older plugin: both ways, nothing else', () => {
    const b = U.normalizeBridges({ available: true, networks: [
      { id: 'whatsapp', state: 'running', logins: [] },
      { ...SIGNAL, flows: ['qr', 'qr', 'sms'], history: { maxDays: 30, phoneConfirms: true }, recognition: { available: true, asked: false, allowed: false } },
    ] });
    assert.deepEqual(b.networks[0].flows, ['phone', 'qr']);
    assert.deepEqual(b.networks[0].history, { maxDays: null, phoneConfirms: false });
    assert.equal(b.networks[0].recognition, null);
    assert.deepEqual(b.networks[1].flows, ['qr']);
    assert.deepEqual(b.networks[1].history, { maxDays: 30, phoneConfirms: true });
    assert.deepEqual(b.networks[1].recognition, { available: true, network: 'signal', asked: false, allowed: false });
    assert.equal(U.bridgeLabel('signal'), 'Signal');
  });

  it('a handoff: only the two targets, a path of the portal; target null means over; nothing in GET bridges then', () => {
    const h = U.normalizeHandoff({ network: 'signal', target: 'windows', expiresAt: '2026-11-16T10:12:00.000Z', portalPath: '/portal#plg-gatecontrol-messenger' });
    assert.deepEqual(h, { network: 'signal', target: 'windows', expiresAt: '2026-11-16T10:12:00.000Z', portalPath: '/portal#plg-gatecontrol-messenger' });
    assert.equal(U.normalizeHandoff({ network: 'signal', target: 'mac' }), null);
    assert.equal(U.normalizeHandoff({ network: 'Signal!', target: 'portal' }), null);
    assert.equal(U.normalizeHandoff({ network: 'signal', target: 'portal', portalPath: 'https://example.invalid/x' }).portalPath, null);
    assert.equal(U.normalizeHandoff({ network: 'signal', target: 'portal', portalPath: '//example.invalid' }).portalPath, null);
    assert.deepEqual(U.normalizeHandoff({ network: 'signal', target: null, expiresAt: null }), { network: 'signal', target: null, expiresAt: null, portalPath: null });
    assert.equal('handoff' in U.normalizeBridges({ available: true, networks: [], handoff: { network: 'signal', target: null } }), false);
    assert.equal(U.normalizeBridges({ available: true, networks: [], handoff: { network: 'signal', target: 'windows', expiresAt: '2026-11-16T10:12:00.000Z' } }).handoff.target, 'windows');
    assert.equal('handoff' in U.normalizeBridges({ available: false, handoff: { network: 'signal', target: 'windows' } }), false);
  });
});

describe('Signal (Messenger 1.23) – the service', () => {
  it('links by QR code; the consent „Erkennen“ of Signal goes with its network, WhatsApp’s without', async () => {
    const { srv, m } = await setup();
    srv.state.recognition = { asked: true, allowed: false };
    srv.state.recognitions.signal = { asked: false, allowed: false };
    await m.check();
    const b = await m.bridges();
    const sg = b.networks.find((n) => n.id === 'signal');
    assert.deepEqual(sg.flows, ['qr']);
    assert.deepEqual(sg.recognition, { available: true, network: 'signal', asked: false, allowed: false });
    assert.deepEqual(await m.bridgeConsent('signal'), { consent: true });
    const start = await m.bridgeLogin('signal', 'qr');
    assert.equal(start.step.type, 'qr');
    const r = await m.setRecognition(true, 'signal');
    assert.deepEqual(r, { available: true, network: 'signal', asked: true, allowed: true });
    const put = srv.state.requests.filter((x) => x.path.endsWith('/bridges/recognition'));
    assert.deepEqual(put.at(-1).body, { allowed: true, network: 'signal' });
    await m.setRecognition(false);
    assert.deepEqual(srv.state.requests.filter((x) => x.path.endsWith('/bridges/recognition')).at(-1).body, { allowed: false });
    await assert.rejects(m.setRecognition(true, 'Bad Net'), (e) => e.code === 'invalid');
  });

  it('„Im Windows-Client fortsetzen“: POST and DELETE …/handoff, GET bridges names it while it runs', async () => {
    const { srv, m } = await setup();
    await m.check();
    const h = await m.bridgeHandoff('signal', 'windows');
    assert.equal(h.network, 'signal');
    assert.equal(h.target, 'windows');
    assert.equal(h.portalPath, '/portal#plg-gatecontrol-messenger');
    assert.equal((await m.bridges()).handoff.target, 'windows');
    assert.equal(await m.bridgeHandoffEnd('signal'), true);
    assert.equal((await m.bridges()).handoff, undefined);
    await assert.rejects(m.bridgeHandoff('signal', 'mac'), (e) => e.code === 'invalid');
    assert.equal(await m.bridgeHandoffEnd('<x>'), false);
    assert.equal(srv.state.handoff, null);
  });

  it('the live event bridge.handoff becomes `handoff` (also its end)', async () => {
    const { srv, m } = await setup({ push: true });
    const seen = [];
    m.on('handoff', (h) => seen.push(h));
    m.start();
    await waitFor(() => m.status().state === 'available');
    await waitFor(() => srv.streams.size > 0, 4000, 'push stream');
    srv.event('bridge.handoff', { network: 'signal', target: 'windows', expiresAt: '2026-11-16T10:12:00.000Z' });
    srv.event('bridge.handoff', { network: 'signal', target: 'printer' });
    srv.event('bridge.handoff', { network: 'signal', target: null, expiresAt: null });
    await waitFor(() => seen.length === 2, 4000, 'two events');
    assert.deepEqual(seen.map((h) => h.target), ['windows', null]);
  });
});

describe('Signal (Messenger 1.23) – IPC', () => {
  it('checks the arguments and passes the network along', async () => {
    const { registerMessengerHandlers, CHAT_EVENTS } = require('../src/ipc/messenger-handlers');
    assert.equal(CHAT_EVENTS.handoff, 'chat:handoff');
    const h = new Map();
    const seen = [];
    const m = new Proxy({ on() {} }, { get: (t, k) => (k in t ? t[k] : (...args) => { seen.push([k, ...args]); return Promise.resolve(k === 'bridgeHandoffEnd' ? true : null); }) });
    registerMessengerHandlers((ch, fn) => h.set(ch, fn), { messenger: m, getMainWindow: () => null, log });
    const call = (ch, a) => h.get(ch)(null, a);
    await call('chat:bridge:recognition', { allowed: true, network: 'signal' });
    await call('chat:bridge:recognition', { allowed: false });
    await call('chat:bridge:handoff', { network: 'signal', target: 'portal' });
    assert.equal((await call('chat:bridge:handoff:end', { network: 'signal' })).ok, true);
    assert.deepEqual(seen, [['setRecognition', true, 'signal'], ['setRecognition', false, 'whatsapp'], ['bridgeHandoff', 'signal', 'portal'], ['bridgeHandoffEnd', 'signal']]);
  });
});
