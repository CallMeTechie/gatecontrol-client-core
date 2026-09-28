'use strict';

// IPC flow of the setup code (server:setup / config:import-qr) with fake
// Electron context. The private config-hash validator is replaced by a stub
// so this test runs without registry access.

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');

function makeCtx(overrides = {}) {
  const handlers = {};
  const stored = {};
  const written = [];
  const calls = { register: 0, configure: [], dialogs: 0 };
  const ctx = {
    app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
    dialog: { showMessageBox: async () => { calls.dialogs++; return { response: overrides.dialogResponse ?? 0 }; } },
    getMainWindow: () => ({}),
    store: { set: (k, v) => { stored[k] = v; }, get: (k) => stored[k], store: stored },
    wgService: { writeConfig: async (file, content) => { written.push({ file, content }); } },
    apiClient: {
      clientVersion: '1.21.0', clientPlatform: 'windows',
      configure: (url, key) => calls.configure.push({ url, key }),
      setPeerId: () => {},
      register: async () => { calls.register++; return { peerId: 99 }; },
      ping: async () => ({ ok: true }),
    },
    updater: { configure() {} },
    log: { info() {}, warn() {}, error() {} },
    connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState() {},
    wgConfigFile: 'wg.conf',
  };
  const ipcMain = { handle: (ch, fn) => { handlers[ch] = fn; }, on() {} };
  registerBaseHandlers(ipcMain, ctx);
  return { handlers, stored, written, calls };
}

const VALID_CONFIG = '[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y';

describe('server:setup with a setup code', () => {
  let original;
  beforeEach(() => { original = ApiClient.redeemSetupCode; });

  it('redeems the code, stores token and peer and writes the config', async () => {
    ApiClient.redeemSetupCode = async (url, code) => {
      assert.equal(url, 'https://gate.example.com');
      assert.equal(code, 'AB12-CD34-EF56-7890');
      return { ok: true, token: 'gc_minted', peerId: 5, config: VALID_CONFIG };
    };
    try {
      const { handlers, stored, written, calls } = makeCtx();
      const res = await handlers['server:setup']({}, { url: 'https://gate.example.com', apiKey: 'ab12 cd34 ef56 7890' });
      assert.deepEqual(res, { success: true, peerId: 5, enrolled: true });
      assert.equal(stored['server.apiKey'], 'gc_minted');
      assert.equal(stored['server.url'], 'https://gate.example.com');
      assert.equal(stored['server.peerId'], '5');
      assert.equal(calls.register, 0, 'peer came with the code');
      assert.deepEqual(written, [{ file: 'wg.conf', content: VALID_CONFIG }]);
    } finally { ApiClient.redeemSetupCode = original; }
  });

  it('registers afterwards when the code is not bound to a peer', async () => {
    ApiClient.redeemSetupCode = async () => ({ ok: true, token: 'gc_minted', peerId: null, config: null });
    try {
      const { handlers, stored, calls } = makeCtx();
      const res = await handlers['server:setup']({}, { url: 'gate.example.com', apiKey: 'AB12-CD34-EF56-7890' });
      assert.equal(res.success, true);
      assert.equal(calls.register, 1);
      assert.equal(stored['server.peerId'], '99');
    } finally { ApiClient.redeemSetupCode = original; }
  });

  it('keeps the existing setup when the redeem fails', async () => {
    ApiClient.redeemSetupCode = async () => {
      const err = new Error('Request failed'); err.response = { status: 400, data: { ok: false, error: 'invalid_or_expired' } }; throw err;
    };
    try {
      const { handlers, stored } = makeCtx();
      stored['server.apiKey'] = 'gc_old';
      const res = await handlers['server:setup']({}, { url: 'https://gate.example.com', apiKey: 'AB12-CD34-EF56-7890' });
      assert.equal(res.success, false);
      assert.match(res.error, /ungültig|invalid/i);
      assert.equal(stored['server.apiKey'], 'gc_old');
    } finally { ApiClient.redeemSetupCode = original; }
  });

  it('refuses plain http servers', async () => {
    const { handlers } = makeCtx();
    const res = await handlers['server:setup']({}, { url: 'http://gate.example.com', apiKey: 'AB12-CD34-EF56-7890' });
    assert.equal(res.success, false);
  });

  it('a real API key still takes the classic path', async () => {
    const { handlers, stored, calls } = makeCtx();
    const res = await handlers['server:setup']({}, { url: 'https://gate.example.com', apiKey: 'gc_abc' });
    assert.equal(res.success, true);
    assert.equal(stored['server.apiKey'], 'gc_abc');
    assert.equal(calls.register, 1);
  });
});
