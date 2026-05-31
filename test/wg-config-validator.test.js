'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// The shared validator that gates connect() (wireguard-native) and
// enable() (killswitch) before the tunnel / firewall rules are touched.
// Both services require it from this same package, and it is re-exported
// from the public API. We assert the fail-closed contract here; the
// connect()/enable() call sites themselves require koffi DLLs / netsh
// (Windows-only) and cannot run in CI's node --test runner.
// NOTE: ../src/index is intentionally NOT required here — it aggregates
// updater.js which requires the host-provided `electron` module (absent in
// the bare node --test runner). The re-export from index.js is wired in
// step 2 and consumed by the Windows client at runtime.
const { validateWgConfig } = require('@callmetechie/gatecontrol-config-hash');

describe('WG config validator (shared, fail-closed gate)', () => {
  it('exposes the expected callable', () => {
    assert.equal(typeof validateWgConfig, 'function');
  });

  it('rejects an obviously-invalid config (fail-closed)', () => {
    const result = validateWgConfig('not a wireguard config at all');
    assert.equal(result.ok, false);
    assert.ok(Array.isArray(result.errors) && result.errors.length > 0);
    // Contract: ok === (errors.length === 0)
    assert.equal(result.ok, result.errors.length === 0);
  });

  it('accepts a well-formed config with valid 32-byte keys', () => {
    const priv = crypto.randomBytes(32).toString('base64');
    const pub = crypto.randomBytes(32).toString('base64');
    const config = [
      '[Interface]',
      `PrivateKey = ${priv}`,
      'Address = 10.8.0.2/32',
      '',
      '[Peer]',
      `PublicKey = ${pub}`,
      'Endpoint = vpn.example.com:51820',
      'AllowedIPs = 0.0.0.0/0',
    ].join('\n');

    const result = validateWgConfig(config);
    assert.equal(result.ok, true);
    assert.deepEqual(result.errors, []);
  });
});
