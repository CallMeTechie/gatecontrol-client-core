'use strict';

// Messenger 1.24 (Brücken Stufe 7b): Telegram — a further network `telegram`; „noch nicht eingerichtet“ while the
// administrator has not entered the application id (`networks[].needs: 'app'`), the QR code or the number, then the
// code from the Telegram app and the password of the two-step verification (step type `secret`, a wrong one asked
// again with `retry`). Code and password pass through once and are never kept, logged or put into an error.
// Names and numbers are made up.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const ApiClient = require('../src/services/api-client');
const MessengerService = require('../src/services/messenger');
const U = require('../src/utils/messenger');
const { messengerServer, FEATURES_14 } = require('./fixtures/messenger-server');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = { recheckMs: 60000, errorRetryMs: [30, 60], pollOpenMs: 80, pollIdleMs: 80, activeEveryMs: 40, convDebounceMs: 5, persistDelayMs: 5, typingEveryMs: 3000, typingValidMs: 6000 };
const FEATURES = { ...FEATURES_14, linked_services: true, bridge_chats: true, bridge_media: true, bridge_history: true, chat_people: true };
const TELEGRAM = { id: 'telegram', state: 'running', allowed: true, lock: null, consent: '2026-11-16T09:00:00.000Z', logins: [], flows: ['qr', 'phone'] };
const PASSWORD = 'Wanderweg-Eifel-7';

const cleanups = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()(); });

async function setup() {
  const srv = await messengerServer({ features: FEATURES });
  cleanups.push(() => srv.close());
  srv.state.bridge.networks.push({ ...TELEGRAM });
  const lines = [];
  const rec = (...a) => lines.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
  const m = new MessengerService({ apiClient: new ApiClient(srv.url, 'gc_token', log), store: createMemoryStore(), log: { info: rec, warn: rec, debug: rec, error: rec }, timing: FAST });
  cleanups.push(() => m.stop());
  return { srv, m, lines };
}

describe('Telegram (Messenger 1.24) – normalizing', () => {
  it('its name, both ways in the order of the server, „needs“ only known values', () => {
    const b = U.normalizeBridges({ available: true, networks: [{ ...TELEGRAM, needs: 'app' }, { ...TELEGRAM, id: 'whatsapp', needs: 'cake' }] });
    assert.equal(U.bridgeLabel('telegram'), 'Telegram');
    assert.deepEqual(b.networks[0].flows, ['qr', 'phone']);
    assert.equal(b.networks[0].needs, 'app');
    assert.equal(b.networks[1].needs, null);
  });

  it('the steps for the code and the password become `secret` (with `retry`); other fields this version cannot show', () => {
    const step = (fields, extra = {}) => U.normalizeBridgeLogin({ processId: 'p1', step: { id: 's1', type: 'user_input', fields, ...extra } }).step;
    assert.deepEqual(step([{ id: 'code', type: '2fa_code' }]), { id: 's1', type: 'secret', kind: 'code', fieldId: 'code', retry: false });
    assert.deepEqual(step([{ id: 'pass', type: 'password' }], { retry: true }), { id: 's1', type: 'secret', kind: 'password', fieldId: 'pass', retry: true });
    assert.deepEqual(step([{ id: 'phone_number', type: 'phone_number' }]), { id: 's1', type: 'phone', fieldId: 'phone_number' });
    assert.equal(step([{ id: 'token', type: 'token' }]).type, 'unsupported');
  });
});

describe('Telegram (Messenger 1.24) – linking', () => {
  it('number, a wrong code, the code, a wrong password, the password — linked; nothing of it logged', async () => {
    const { srv, m, lines } = await setup();
    srv.state.bridge.tgPassword = PASSWORD;
    await m.check();
    const start = await m.bridgeLogin('telegram', 'phone');
    assert.equal(start.step.type, 'phone');
    let s = await m.bridgeStep('telegram', start.processId, start.step.id, { phone: '+49 151 00000000', fieldId: start.step.fieldId });
    assert.deepEqual(s.step, { id: 'code1', type: 'secret', kind: 'code', fieldId: 'code', retry: false });
    s = await m.bridgeStep('telegram', s.processId, s.step.id, { secret: '11111', fieldId: s.step.fieldId });
    assert.equal(s.step.retry, true);
    s = await m.bridgeStep('telegram', s.processId, s.step.id, { secret: '47000', fieldId: s.step.fieldId });
    assert.deepEqual([s.step.kind, s.step.retry], ['password', false]);
    s = await m.bridgeStep('telegram', s.processId, s.step.id, { secret: 'falsch', fieldId: s.step.fieldId });
    assert.deepEqual([s.step.kind, s.step.retry], ['password', true]);
    s = await m.bridgeStep('telegram', s.processId, s.step.id, { secret: PASSWORD, fieldId: s.step.fieldId });
    assert.equal(s.step.type, 'complete');
    assert.deepEqual(srv.state.bridge.calls.filter((c) => c.op === 'input').map((c) => c.field), ['phone_number', 'code', 'code', 'pass', 'pass']);
    assert.doesNotMatch(lines.join('\n'), /Wanderweg|47000|00000000/);
  });

  it('a secret that is empty, too long or without its field never reaches the server', async () => {
    const { srv, m } = await setup();
    await m.check();
    const start = await m.bridgeLogin('telegram', 'phone');
    const before = srv.state.bridge.calls.length;
    for (const o of [{ secret: '', fieldId: 'code' }, { secret: 'x'.repeat(U.BRIDGE_SECRET_MAX + 1), fieldId: 'code' }, { secret: '47000', fieldId: '../x' }, { secret: 47000, fieldId: 'code' }]) {
      await assert.rejects(m.bridgeStep('telegram', start.processId, 'code1', o), (e) => e.code === 'invalid' && !/47000/.test(JSON.stringify(e)));
    }
    assert.equal(srv.state.bridge.calls.length, before);
  });

  it('without two-step verification: number, code — linked', async () => {
    const { m } = await setup();
    await m.check();
    const start = await m.bridgeLogin('telegram', 'phone');
    const c = await m.bridgeStep('telegram', start.processId, start.step.id, { phone: '+49 151 00000000', fieldId: 'phone_number' });
    assert.equal((await m.bridgeStep('telegram', c.processId, c.step.id, { secret: '47000', fieldId: 'code' })).step.type, 'complete');
  });
});
