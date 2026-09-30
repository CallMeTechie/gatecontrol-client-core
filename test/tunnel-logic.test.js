'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { reconnectDelay, shouldOpenPortal } = require('../src/utils/tunnel-logic');

describe('reconnectDelay', () => {
  it('starts at the base delay on the first attempt', () => {
    assert.equal(reconnectDelay(0), 2000);
  });

  it('grows exponentially by the factor', () => {
    assert.equal(reconnectDelay(1), 3000);   // 2000 * 1.5
    assert.equal(reconnectDelay(2), 4500);   // 2000 * 1.5^2
  });

  it('is monotonically non-decreasing', () => {
    let prev = -1;
    for (let i = 0; i < 20; i++) {
      const d = reconnectDelay(i);
      assert.ok(d >= prev, `attempt ${i}: ${d} < ${prev}`);
      prev = d;
    }
  });

  it('caps at 60s for long outages', () => {
    assert.equal(reconnectDelay(50), 60000);
    assert.ok(reconnectDelay(9) <= 60000);
  });

  it('honours custom base/factor/cap', () => {
    assert.equal(reconnectDelay(0, { base: 1000 }), 1000);
    assert.equal(reconnectDelay(1, { base: 1000, factor: 2 }), 2000);
    assert.equal(reconnectDelay(10, { cap: 5000 }), 5000);
  });
});

describe('shouldOpenPortal', () => {
  const base = { portalUrl: 'https://home.example.com', autoOpenPortal: true, connectedSince: 100, lastOpenedSince: null };

  it('opens on a fresh user connect with url + flag', () => {
    assert.equal(shouldOpenPortal(base), true);
  });

  it('does not open without a portal url', () => {
    assert.equal(shouldOpenPortal({ ...base, portalUrl: null }), false);
    assert.equal(shouldOpenPortal({ ...base, portalUrl: '' }), false);
  });

  it('does not open when the server disabled auto-open', () => {
    assert.equal(shouldOpenPortal({ ...base, autoOpenPortal: false }), false);
  });

  it('requires autoOpenPortal to be strictly boolean true', () => {
    // a stale/garbage truthy value must not trigger a launch
    assert.equal(shouldOpenPortal({ ...base, autoOpenPortal: 1 }), false);
    assert.equal(shouldOpenPortal({ ...base, autoOpenPortal: 'true' }), false);
  });

  it('opens once per connect: not again for the same connectedSince', () => {
    // first connect opens, recording lastOpenedSince = connectedSince
    assert.equal(shouldOpenPortal({ ...base, lastOpenedSince: 100 }), false);
  });

  it('opens again on a new connect (new connectedSince)', () => {
    assert.equal(shouldOpenPortal({ ...base, connectedSince: 200, lastOpenedSince: 100 }), true);
  });
});
