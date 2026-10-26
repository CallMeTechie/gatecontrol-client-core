'use strict';

// IPC of the company sign-in (signin:methods / signin:password /
// signin:microsoft / signin:cancel): renderer input is checked, the setup code
// goes through the existing redeem path (ApiClient.redeemSetupCode), the
// client policy's server lock applies, and nothing secret is logged or
// returned to the renderer. The private config-hash validator is replaced
// by a stub (no registry access).

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const { AppSignin, SigninError } = require('../src/services/app-signin');
const { registerBaseHandlers, readSigninCredentials } = require('../src/ipc/base-handlers');
const i18n = require('../src/i18n');

const SECRETS = ['Geheim-Passwort-1', '654321', 'AB12-CD34-EF56-7890', 'AB12CD34EF567890'];

function makeCtx({ appSignin, clientPolicy } = {}) {
  const handlers = {};
  const stored = {};
  const lines = [];
  const logger = (...a) => lines.push(a.map(String).join(' '));
  const calls = { register: 0, configure: [] };
  const ctx = {
    app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
    dialog: {},
    getMainWindow: () => ({}),
    store: { set: (k, v) => { stored[k] = v; }, get: (k) => stored[k], store: stored },
    wgService: { writeConfig: async () => {} },
    apiClient: {
      clientVersion: '1.30.0', clientPlatform: 'windows',
      configure: (url, key) => calls.configure.push({ url, key }),
      setPeerId() {},
      register: async () => { calls.register++; return { peerId: 77 }; },
      ping: async () => ({ ok: true }),
    },
    log: { info: logger, warn: logger, error: logger, debug: logger },
    connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {}, installUpdate() {}, getTunnelState: () => ({}),
    wgConfigFile: 'wg.conf',
    appSignin,
    clientPolicy,
  };
  registerBaseHandlers({ handle: (ch, fn) => { handlers[ch] = fn; }, on() {} }, ctx);
  return { handlers, stored, lines, calls };
}

/** AppSignin double: records calls, answers per method. */
function stubSignin(answers = {}) {
  const calls = [];
  return {
    calls,
    methods: async (url) => { calls.push(['methods', url]); return answers.methods || { available: true, password: { enabled: true, hint: null }, microsoft: [] }; },
    password: async (url, creds) => { calls.push(['password', url, creds]); if (answers.password instanceof Error) throw answers.password; return answers.password || { code: 'AB12-CD34-EF56-7890', expiresAt: null }; },
    microsoft: async (url, id) => { calls.push(['microsoft', url, id]); if (answers.microsoft instanceof Error) throw answers.microsoft; return answers.microsoft || { code: 'AB12-CD34-EF56-7890', expiresAt: null }; },
    cancel: () => { calls.push(['cancel']); return true; },
  };
}

describe('signin IPC', () => {
  let original;
  let redeemed;
  beforeEach(() => {
    i18n.setLocale('de');
    original = ApiClient.redeemSetupCode;
    redeemed = [];
    ApiClient.redeemSetupCode = async (url, code, opts) => {
      redeemed.push({ url, code, opts });
      return { ok: true, token: 'gc_minted', peerId: 5, config: null };
    };
  });
  afterEach(() => { ApiClient.redeemSetupCode = original; });

  it('signin:methods asks the server of the typed URL (https origin)', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    const res = await handlers['signin:methods']({}, { url: 'gate.example.com/some/path' });
    assert.equal(res.available, true);
    assert.deepEqual(s.calls, [['methods', 'https://gate.example.com']]);
  });

  it('signin:methods: http, junk and oversized URLs → not available, no request', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    for (const bad of [{ url: 'http://gate.example.com' }, { url: 42 }, null, 'https://x', { url: `https://${'a'.repeat(3000)}.com` }]) {
      assert.equal((await handlers['signin:methods']({}, bad)).available, false);
    }
    assert.equal(s.calls.length, 0);
  });

  it('signin:password redeems the code through the existing setup-code path', async () => {
    const s = stubSignin();
    const { handlers, stored } = makeCtx({ appSignin: s });
    const res = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: ' anna ', password: 'Geheim-Passwort-1 ' });
    assert.deepEqual(res, { success: true, peerId: 5, enrolled: true });
    assert.deepEqual(s.calls[0], ['password', 'https://gate.example.com', { username: 'anna', password: 'Geheim-Passwort-1 ' }]);
    assert.deepEqual(redeemed, [{ url: 'https://gate.example.com', code: 'AB12-CD34-EF56-7890', opts: { clientVersion: '1.30.0', clientPlatform: 'windows' } }]);
    assert.equal(stored['server.apiKey'], 'gc_minted');
    assert.equal(stored['server.url'], 'https://gate.example.com');
  });

  it('totp_required / totp_invalid ask for the code', async () => {
    for (const code of ['totp_required', 'totp_invalid']) {
      const { handlers } = makeCtx({ appSignin: stubSignin({ password: new SigninError(code, { status: 401 }) }) });
      const res = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'x' });
      assert.equal(res.success, false);
      assert.equal(res.code, code);
      assert.equal(res.totpRequired, true);
      assert.ok(res.error);
    }
    assert.equal(redeemed.length, 0);
  });

  it('passes the 6 digits (spaces dropped) on the second attempt', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'x', totp: '123 456' });
    assert.equal(s.calls[0][2].totp, '123456');
  });

  it('error texts from the contract', async () => {
    const cases = [
      [new SigninError('invalid_credentials'), 'Benutzername oder Passwort stimmt nicht.'],
      [new SigninError('enroll_not_allowed'), 'Dein Konto darf keine Geräte selbst einrichten. Bitte frag deinen Administrator nach einem Einrichtungscode.'],
      [new SigninError('limit_reached'), 'Du hast schon die höchste Zahl an Geräten.'],
      [new SigninError('user_disabled'), 'Dein Konto ist gesperrt.'],
      [new SigninError('locked', { status: 429, retryAfter: 300 }), 'Zu viele Versuche. Bitte warte 5 Minuten.'],
    ];
    for (const [err, text] of cases) {
      const { handlers } = makeCtx({ appSignin: stubSignin({ password: err }) });
      const res = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'x' });
      assert.equal(res.error, text);
      assert.equal(res.totpRequired, false);
    }
  });

  it('refuses bad input before any request', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    const url = 'https://gate.example.com';
    for (const bad of [
      null, 'x', { url }, { url, username: 'a' }, { url, password: 'b' },
      { url, username: '', password: 'b' }, { url, username: '   ', password: 'b' }, { url, username: 'a', password: '' },
      { url, username: 'a'.repeat(257), password: 'b' }, { url, username: 'a', password: 'b'.repeat(1025) },
      { url, username: 'a\nb', password: 'b' }, { url, username: { toString: () => 'a' }, password: 'b' },
      { url, username: 'a', password: 'b', totp: '12345' }, { url, username: 'a', password: 'b', totp: 'abcdef' },
      { url, username: 'a', password: 'b', totp: 123456 },
    ]) {
      const res = await handlers['signin:password']({}, bad);
      assert.equal(res.success, false, JSON.stringify(bad));
    }
    assert.equal((await handlers['signin:password']({}, { url: 'http://gate.example.com', username: 'a', password: 'b' })).success, false);
    assert.equal(s.calls.length, 0);
  });

  it('readSigninCredentials keeps the password as typed', () => {
    assert.deepEqual(readSigninCredentials({ username: ' a ', password: ' p ' }), { username: 'a', password: ' p ' });
    assert.equal(readSigninCredentials({ username: 'a', password: 'p', totp: '1234567' }), null);
  });

  it('signin:microsoft: valid directory id only, then the existing redeem', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    for (const id of [0, -1, '3', 1.5, null, undefined, 2 ** 40]) {
      assert.equal((await handlers['signin:microsoft']({}, { url: 'https://gate.example.com', id })).success, false, String(id));
    }
    assert.equal(s.calls.length, 0);
    const res = await handlers['signin:microsoft']({}, { url: 'https://gate.example.com', id: 3 });
    assert.deepEqual(res, { success: true, peerId: 5, enrolled: true });
    assert.deepEqual(s.calls, [['microsoft', 'https://gate.example.com', 3]]);
    assert.equal(redeemed[0].code, 'AB12-CD34-EF56-7890');
  });

  it('signin:microsoft cancelled → cancelled, no error text', async () => {
    const { handlers } = makeCtx({ appSignin: stubSignin({ microsoft: new SigninError('cancelled') }) });
    assert.deepEqual(await handlers['signin:microsoft']({}, { url: 'https://gate.example.com', id: 3 }), { success: false, cancelled: true, code: 'cancelled' });
  });

  it('signin:cancel ends the waiting browser sign-in', async () => {
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s });
    assert.equal(await handlers['signin:cancel']({}), true);
    assert.deepEqual(s.calls, [['cancel']]);
  });

  it('a failed redeem keeps the existing setup', async () => {
    ApiClient.redeemSetupCode = async () => {
      const err = new Error('Request failed'); err.response = { status: 403, data: { ok: false, error: 'limit_reached' } }; throw err;
    };
    const { handlers, stored } = makeCtx({ appSignin: stubSignin() });
    stored['server.apiKey'] = 'gc_old';
    const res = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'x' });
    assert.equal(res.success, false);
    assert.equal(stored['server.apiKey'], 'gc_old');
  });

  it('the server lock of the client policy blocks sign-in like server:setup', async () => {
    const clientPolicy = { getPolicy: () => ({ lockServer: true }), getState: () => ({}), reset() {}, refresh: async () => {} };
    assert.equal(require('../src/utils/client-policy').locks(clientPolicy.getPolicy()).server, true);
    const s = stubSignin();
    const { handlers } = makeCtx({ appSignin: s, clientPolicy });
    assert.equal((await handlers['signin:methods']({}, { url: 'https://gate.example.com' })).available, false);
    const res = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'a', password: 'b' });
    assert.equal(res.policyLocked, true);
    assert.equal((await handlers['signin:microsoft']({}, { url: 'https://gate.example.com', id: 1 })).policyLocked, true);
    assert.equal(s.calls.length, 0);
  });

  it('logs and answers contain no password, TOTP or setup code (real AppSignin, fake server)', async () => {
    const posts = [];
    const httpFake = {
      get: async () => ({ data: { ok: true } }),
      post: async (url, body) => {
        posts.push(body);
        if (!body.totp) {
          const err = new Error('Request failed with status code 401');
          err.response = { status: 401, data: { ok: false, error: 'totp_required' }, headers: {} };
          err.config = { data: JSON.stringify(body) };
          throw err;
        }
        return { data: { ok: true, code: 'AB12CD34EF567890' } };
      },
    };
    const { handlers, lines } = makeCtx({ appSignin: new AppSignin({ http: httpFake }) });
    const first = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'Geheim-Passwort-1' });
    assert.equal(first.totpRequired, true);
    const second = await handlers['signin:password']({}, { url: 'https://gate.example.com', username: 'anna', password: 'Geheim-Passwort-1', totp: '654321' });
    assert.equal(second.success, true);
    assert.equal(posts.length, 2);
    const out = lines.join('\n') + JSON.stringify([first, second]);
    for (const secret of SECRETS) assert.ok(!out.includes(secret), `leaked ${secret}: ${out}`);
  });
});

describe('signin IPC registration', () => {
  it('registers the four channels', () => {
    const { handlers } = makeCtx({ appSignin: stubSignin() });
    for (const ch of ['signin:methods', 'signin:password', 'signin:microsoft', 'signin:cancel']) assert.equal(typeof handlers[ch], 'function', ch);
  });

  it('creates its own AppSignin when the app passes none', async () => {
    const { handlers } = makeCtx();
    assert.equal(await handlers['signin:cancel']({}), false);
  });
});
