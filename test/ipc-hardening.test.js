'use strict';

// Hardening of the shared IPC handlers: client hooks (overrides/skip/getUpdater/
// ApiClientClass/extraWritableKeys), the shell:open-external scheme filter,
// logs:show, https enforcement for API-key setups and the pure URL helpers.
// The private config-hash validator is replaced by a stub (no registry access).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');
const { isSafeExternalUrl } = require('../src/utils/external-url');
const { toServerOrigin } = require('../src/utils/enrollment');

// ipcMain double that behaves like Electron: a second handle() on the same
// channel throws.
function strictIpc() {
  const handlers = {};
  return {
    handlers,
    handle(ch, fn) {
      if (handlers[ch]) throw new Error(`Attempted to register a second handler for '${ch}'`);
      handlers[ch] = fn;
    },
    on() {},
  };
}

function makeCtx(extra = {}) {
  const stored = {};
  const calls = { configure: [], register: 0, opened: [], shown: [], updaterConfigure: [] };
  const ctx = {
    app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
    dialog: { showMessageBox: async () => ({ response: 0 }), showOpenDialog: async () => ({ canceled: true }) },
    getMainWindow: () => ({}),
    store: { set: (k, v) => { stored[k] = v; }, get: (k) => stored[k], store: stored },
    wgService: { writeConfig: async () => {} },
    apiClient: {
      clientVersion: '1.0.0', clientPlatform: 'windows',
      configure: (url, key) => calls.configure.push({ url, key }),
      setPeerId() {},
      register: async () => { calls.register++; return { peerId: 7 }; },
      ping: async () => ({ ok: true }),
    },
    log: {
      info() {}, warn() {}, error() {}, debug() {},
      transports: { file: { getFile: () => ({ path: 'C:\\logs\\main.log' }) } },
    },
    shell: {
      openExternal: async (u) => { calls.opened.push(u); },
      showItemInFolder: (p) => { calls.shown.push(p); },
    },
    connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
    wgConfigFile: 'wg.conf',
    ...extra,
  };
  const ipc = strictIpc();
  const registered = registerBaseHandlers(ipc, ctx);
  return { handlers: ipc.handlers, stored, calls, registered, ctx };
}

describe('registerBaseHandlers hooks', () => {
  it('registers every channel once and returns the list', () => {
    const { handlers, registered } = makeCtx();
    assert.deepEqual([...registered].sort(), Object.keys(handlers).sort());
    assert.equal(new Set(registered).size, registered.length);
    assert.ok(handlers['logs:show']);
  });

  it('overrides replace core handlers and add client-only channels', async () => {
    const { handlers, registered } = makeCtx({
      overrides: { 'autostart:set': async () => 'pro', 'dns:check-system': async () => 'sys' },
    });
    assert.equal(await handlers['autostart:set']({}, true), 'pro');
    assert.equal(await handlers['dns:check-system']({}), 'sys');
    assert.equal(registered.filter((c) => c === 'autostart:set').length, 1);
  });

  it('skip leaves channels unregistered', () => {
    const { handlers } = makeCtx({ skip: ['dns:leak-test'] });
    assert.equal(handlers['dns:leak-test'], undefined);
  });

  it('getUpdater is read lazily (updater created after registration)', async () => {
    let updater = null;
    const { handlers } = makeCtx({ getUpdater: () => updater });
    assert.equal(await handlers['update:check'](), null);
    updater = { getUpdateInfo: () => ({ version: '9.9.9' }), configure() {} };
    assert.deepEqual(await handlers['update:check'](), { version: '9.9.9' });
  });

  it('a setup code configures the late-created updater and uses ApiClientClass', async () => {
    const seen = [];
    let updater = null;
    class ProClient extends ApiClient {}
    const original = ApiClient.redeemSetupCode;
    ApiClient.redeemSetupCode = async (url, code) => { seen.push({ url, code }); return { ok: true, token: 'gc_t', peerId: 3, config: '[Interface]' }; };
    try {
      const { handlers, stored } = makeCtx({ getUpdater: () => updater, ApiClientClass: ProClient });
      const confs = [];
      updater = { configure: (u, k) => confs.push({ u, k }), getUpdateInfo: () => null };
      const res = await handlers['server:setup']({}, { url: 'gate.example.com', apiKey: 'AB12-CD34-EF56-7890' });
      assert.equal(res.success, true);
      assert.deepEqual(seen, [{ url: 'https://gate.example.com', code: 'AB12-CD34-EF56-7890' }]);
      assert.deepEqual(confs, [{ u: 'https://gate.example.com', k: 'gc_t' }]);
      assert.equal(stored['tunnel.configPath'], 'wg.conf');
    } finally { ApiClient.redeemSetupCode = original; }
  });

  it('config:set honours the allowlist plus extraWritableKeys', async () => {
    const { handlers, stored } = makeCtx({ extraWritableKeys: ['rdp.panelPinned'] });
    await handlers['config:set']({}, 'server.apiKey', 'gc_evil');
    await handlers['config:set']({}, 'server.url', 'https://evil.example');
    await handlers['config:set']({}, 'app.theme', 'light');
    await handlers['config:set']({}, 'rdp.panelPinned', true);
    assert.equal(stored['server.apiKey'], undefined);
    assert.equal(stored['server.url'], undefined);
    assert.equal(stored['app.theme'], 'light');
    assert.equal(stored['rdp.panelPinned'], true);
  });
});

describe('shell:open-external', () => {
  it('opens http(s) links only', async () => {
    const { handlers, calls } = makeCtx();
    assert.equal(await handlers['shell:open-external']({}, 'https://svc.example.com/x'), true);
    assert.equal(await handlers['shell:open-external']({}, 'http://10.8.0.5:8080'), true);
    for (const bad of ['file:///C:/Windows/System32/calc.exe', 'FILE://x', 'smb://host/share',
      'ms-settings:network', 'javascript:alert(1)', 'calc.exe', '', null, 42, { href: 'https://x' }]) {
      assert.equal(await handlers['shell:open-external']({}, bad), false, String(bad));
    }
    assert.deepEqual(calls.opened, ['https://svc.example.com/x', 'http://10.8.0.5:8080']);
  });
});

describe('logs:show', () => {
  it('reveals the log file in the folder, ignoring renderer input', async () => {
    const { handlers, calls } = makeCtx();
    assert.equal(await handlers['logs:show']({}, 'C:\\Windows\\evil.exe'), true);
    assert.deepEqual(calls.shown, ['C:\\logs\\main.log']);
  });
});

describe('https for API-key setups', () => {
  it('refuses http:// server URLs', async () => {
    const { handlers, stored, calls } = makeCtx();
    const res = await handlers['server:setup']({}, { url: 'http://gate.example.com', apiKey: 'gc_abc' });
    assert.equal(res.success, false);
    assert.equal(stored['server.apiKey'], undefined);
    assert.equal(calls.configure.length, 0);
  });

  it('defaults a bare host to https and stores the origin', async () => {
    const { handlers, stored } = makeCtx();
    const res = await handlers['server:setup']({}, { url: 'gate.example.com/', apiKey: ' gc_abc ' });
    assert.equal(res.success, true);
    assert.equal(stored['server.url'], 'https://gate.example.com');
    assert.equal(stored['server.apiKey'], 'gc_abc');
  });

  it('server:test refuses http:// before sending the key', async () => {
    const { handlers } = makeCtx();
    const res = await handlers['server:test']({}, { url: 'http://gate.example.com', apiKey: 'gc_abc' });
    assert.equal(res.success, false);
  });
});

describe('isSafeExternalUrl', () => {
  it('accepts http and https with a host', () => {
    assert.equal(isSafeExternalUrl('https://a.example'), true);
    assert.equal(isSafeExternalUrl('HTTP://a.example/p?q=1'), true);
  });
  it('rejects other schemes and junk', () => {
    for (const bad of ['file:///etc/passwd', 'https://', 'mailto:a@b', 'gatecontrol://enroll', 'x'.repeat(5000), undefined]) {
      assert.equal(isSafeExternalUrl(bad), false, String(bad).slice(0, 30));
    }
  });
});

describe('toServerOrigin', () => {
  it('normalises to an https origin', () => {
    assert.equal(toServerOrigin('gate.example.com'), 'https://gate.example.com');
    assert.equal(toServerOrigin('gate.example.com:8443'), 'https://gate.example.com:8443');
    assert.equal(toServerOrigin(' https://gate.example.com/ '), 'https://gate.example.com');
  });
  it('refuses non-https schemes', () => {
    assert.equal(toServerOrigin('http://gate.example.com'), null);
    assert.equal(toServerOrigin('ftp://gate.example.com'), null);
    assert.equal(toServerOrigin(''), null);
  });
});
