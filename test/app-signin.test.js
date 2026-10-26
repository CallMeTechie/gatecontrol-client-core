'use strict';

// Company sign-in ("Mit Firmenkonto anmelden"): PKCE, start URL, methods
// answer, error texts (utils/app-signin.js), the loopback receiver
// (services/signin-loopback.js) and the sign-in client (services/app-signin.js).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const os = require('node:os');

const util = require('../src/utils/app-signin');
const { startLoopbackListener, PAGE_DONE } = require('../src/services/signin-loopback');
const { AppSignin, SigninError } = require('../src/services/app-signin');
const i18n = require('../src/i18n');

const SERVER = 'https://gate.example.com';

/** GET on the loopback receiver; resolves { status, body, headers } or rejects (e.g. ECONNREFUSED). */
function get(url, { host } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      host: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET', agent: false,
      headers: host ? { Host: host } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

function withParams(redirectUri, params) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

const STATE = util.createState();

describe('PKCE and state', () => {
  it('RFC 7636 appendix B: S256 challenge of the example verifier', () => {
    assert.equal(util.challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('verifier: 43 characters of the allowed alphabet, fresh every time; challenge is base64url(sha256)', () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
      const { verifier, challenge } = util.createPkce();
      assert.match(verifier, /^[A-Za-z0-9\-._~]{43,128}$/);
      assert.equal(verifier.length, 43);
      assert.equal(challenge, crypto.createHash('sha256').update(verifier).digest('base64url'));
      assert.ok(!seen.has(verifier));
      seen.add(verifier);
    }
  });

  it('refuses invalid verifiers', () => {
    for (const bad of ['short', 'a'.repeat(129), `${'a'.repeat(43)}+`, null, 42]) {
      assert.equal(util.isValidVerifier(bad), false);
      assert.throws(() => util.challengeFor(bad));
    }
  });

  it('state: random, URL-safe, compared in constant time', () => {
    const a = util.createState();
    const b = util.createState();
    assert.notEqual(a, b);
    assert.match(a, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(util.sameSecret(a, a), true);
    assert.equal(util.sameSecret(a, b), false);
    assert.equal(util.sameSecret(a, a.slice(1)), false);
    assert.equal(util.sameSecret('', ''), false);
    assert.equal(util.sameSecret(null, a), false);
  });
});

describe('start URL and methods answer', () => {
  it('builds the start URL of the server with client=app, redirect_uri, state and challenge', () => {
    const url = new URL(util.buildStartUrl(SERVER, 3, { redirectUri: 'http://127.0.0.1:50123/signin', state: 'st', challenge: 'ch' }));
    assert.equal(url.origin, SERVER);
    assert.equal(url.pathname, '/auth/oidc/3/start');
    assert.deepEqual(Object.fromEntries(url.searchParams), { client: 'app', redirect_uri: 'http://127.0.0.1:50123/signin', state: 'st', challenge: 'ch' });
  });

  it('refuses a non-https server and invalid directory ids', () => {
    assert.throws(() => util.buildStartUrl('http://gate.example.com', 1, { redirectUri: 'x', state: 's', challenge: 'c' }));
    for (const id of [0, -1, 1.5, '1', null, 2 ** 31]) {
      assert.throws(() => util.buildStartUrl(SERVER, id, { redirectUri: 'x', state: 's', challenge: 'c' }), String(id));
    }
  });

  it('loopback redirect URI on 127.0.0.1', () => {
    assert.equal(util.loopbackRedirectUri(50123), 'http://127.0.0.1:50123/signin');
    assert.throws(() => util.loopbackRedirectUri(0));
  });

  it('normalizes the methods answer (contract §1)', () => {
    assert.deepEqual(util.normalizeMethods({
      ok: true, version: 1,
      password: { enabled: true, hint: 'Firmenkonto (corp.local): mit dem Windows-Passwort anmelden' },
      microsoft: [{ id: 2, label: 'Contoso' }, { id: 2, label: 'dup' }, { id: 'x', label: 'bad' }, { id: 5, label: '\u0000 Fabrikam\n' }],
    }), {
      available: true,
      password: { enabled: true, hint: 'Firmenkonto (corp.local): mit dem Windows-Passwort anmelden' },
      microsoft: [{ id: 2, label: 'Contoso' }, { id: 5, label: 'Fabrikam' }],
    });
    assert.deepEqual(util.normalizeMethods({ ok: true, password: { enabled: false, hint: 'x' }, microsoft: [] }),
      { available: false, password: { enabled: false, hint: null }, microsoft: [] });
    assert.equal(util.normalizeMethods({ ok: true, password: { enabled: false }, microsoft: [{ id: 1, label: '' }] }).available, true);
    for (const junk of [null, 'x', { ok: false }, { password: { enabled: true } }]) {
      assert.equal(util.normalizeMethods(junk).available, false);
    }
    const many = util.normalizeMethods({ ok: true, microsoft: Array.from({ length: 30 }, (_, i) => ({ id: i + 1, label: 'x'.repeat(500) })) });
    assert.equal(many.microsoft.length, 10);
    assert.ok(many.microsoft[0].label.length <= 80);
  });
});

describe('error texts', () => {
  const t = i18n.t;
  it('uses the wording of the contract (German)', () => {
    i18n.setLocale('de');
    assert.equal(util.signinErrorMessage(t, { code: 'invalid_credentials' }), 'Benutzername oder Passwort stimmt nicht.');
    assert.equal(util.signinErrorMessage(t, { code: 'enroll_not_allowed' }), 'Dein Konto darf keine Geräte selbst einrichten. Bitte frag deinen Administrator nach einem Einrichtungscode.');
    assert.equal(util.signinErrorMessage(t, { code: 'limit_reached' }), 'Du hast schon die höchste Zahl an Geräten.');
    assert.equal(util.signinErrorMessage(t, { code: 'user_disabled' }), 'Dein Konto ist gesperrt.');
    assert.equal(util.signinErrorMessage(t, { code: 'locked', retryAfter: 900 }), 'Zu viele Versuche. Bitte warte 15 Minuten.');
    assert.equal(util.signinErrorMessage(t, { code: 'rate_limited', retryAfter: 61 }), 'Zu viele Versuche. Bitte warte 2 Minuten.');
    assert.equal(util.signinErrorMessage(t, { code: 'rate_limited', retryAfter: 30 }), 'Zu viele Versuche. Bitte warte 1 Minute.');
    assert.match(util.signinErrorMessage(t, { code: 'rate_limited' }), /ein paar Minuten/);
    assert.match(util.signinErrorMessage(t, { code: 'http_500' }), /\(http_500\)/);
    assert.match(util.signinErrorMessage(t, { code: '<script>' }), /\(unknown\)/);
    assert.match(util.signinErrorMessage(t, { code: 'constructor' }), /\(constructor\)/);
  });

  it('has English texts', () => {
    i18n.setLocale('en');
    try {
      assert.equal(util.signinErrorMessage(t, { code: 'invalid_credentials' }), 'Username or password is incorrect.');
      assert.equal(util.signinErrorMessage(t, { code: 'locked', retryAfter: 120 }), 'Too many attempts. Please wait 2 minutes.');
    } finally { i18n.setLocale('de'); }
  });

  it('browser error codes outside the contract become failed', () => {
    for (const c of ['access_denied', 'not_linked', 'enroll_not_allowed', 'user_disabled', 'failed']) assert.equal(util.browserErrorCode(c), c);
    assert.equal(util.browserErrorCode('<x>'), 'failed');
    assert.equal(util.browserErrorCode(null), 'failed');
  });
});

describe('loopback receiver', () => {
  it('listens on 127.0.0.1, takes the answer with the right state, shows the page and closes', async () => {
    const r = await startLoopbackListener({ state: STATE });
    assert.match(r.redirectUri, /^http:\/\/127\.0\.0\.1:\d+\/signin$/);
    const res = await get(withParams(r.redirectUri, { handoff: 'hand-off_1.2~3', state: STATE }));
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html; charset=utf-8/);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
    assert.ok(res.body.includes(PAGE_DONE));
    assert.ok(res.body.includes('Anmeldung abgeschlossen – du kannst dieses Fenster schließen.'));
    assert.ok(!res.body.includes('hand-off_1.2~3'), 'the page does not echo the handoff');
    assert.deepEqual(await r.result, { handoff: 'hand-off_1.2~3' });
  });

  it('a second request after the answer is refused (single request)', async () => {
    const r = await startLoopbackListener({ state: STATE });
    await get(withParams(r.redirectUri, { handoff: 'first', state: STATE }));
    await assert.rejects(get(withParams(r.redirectUri, { handoff: 'second', state: STATE })), /ECONNREFUSED|ECONNRESET|socket hang up/);
    assert.deepEqual(await r.result, { handoff: 'first' });
  });

  it('a wrong state ends the sign-in with state_mismatch, no handoff', async () => {
    const r = await startLoopbackListener({ state: STATE });
    const res = await get(withParams(r.redirectUri, { handoff: 'h', state: util.createState() }));
    assert.equal(res.status, 400);
    assert.ok(!res.body.includes('Anmeldung abgeschlossen'));
    assert.deepEqual(await r.result, { error: 'state_mismatch' });
    await assert.rejects(get(withParams(r.redirectUri, { handoff: 'h', state: STATE })));
  });

  it('a missing state is a mismatch too', async () => {
    const r = await startLoopbackListener({ state: STATE });
    await get(withParams(r.redirectUri, { handoff: 'h' }));
    assert.deepEqual(await r.result, { error: 'state_mismatch' });
  });

  it('passes the error code of the server redirect (unknown codes → failed)', async () => {
    const r = await startLoopbackListener({ state: STATE });
    await get(withParams(r.redirectUri, { error: 'not_linked', state: STATE }));
    assert.deepEqual(await r.result, { error: 'not_linked' });
    const r2 = await startLoopbackListener({ state: STATE });
    await get(withParams(r2.redirectUri, { error: 'evil<script>', state: STATE }));
    assert.deepEqual(await r2.result, { error: 'failed' });
  });

  it('a malformed handoff is invalid_response', async () => {
    const r = await startLoopbackListener({ state: STATE });
    await get(withParams(r.redirectUri, { handoff: 'a b<c>', state: STATE }));
    assert.deepEqual(await r.result, { error: 'invalid_response' });
  });

  it('other paths and foreign Host headers get 404 and do not count', async () => {
    const r = await startLoopbackListener({ state: STATE });
    const base = new URL(r.redirectUri);
    assert.equal((await get(`${base.origin}/favicon.ico`)).status, 404);
    assert.equal((await get(withParams(r.redirectUri, { handoff: 'h', state: STATE }), { host: `evil.example:${base.port}` })).status, 404);
    // still waiting: the real answer arrives afterwards
    const ok = await get(withParams(r.redirectUri, { handoff: 'real', state: STATE }));
    assert.equal(ok.status, 200);
    assert.deepEqual(await r.result, { handoff: 'real' });
  });

  it('times out (and closes) without an answer', async () => {
    const r = await startLoopbackListener({ state: STATE, timeoutMs: 60 });
    assert.deepEqual(await r.result, { error: 'timeout' });
    await assert.rejects(get(withParams(r.redirectUri, { handoff: 'late', state: STATE })));
  });

  it('defaults to 5 minutes', () => {
    assert.equal(require('../src/services/signin-loopback').DEFAULT_TIMEOUT_MS, 5 * 60 * 1000);
  });

  it('close() cancels and frees the port', async () => {
    const r = await startLoopbackListener({ state: STATE });
    r.close();
    assert.deepEqual(await r.result, { error: 'cancelled' });
    await assert.rejects(get(withParams(r.redirectUri, { handoff: 'h', state: STATE })));
  });

  it('is not reachable on other interfaces', async (t) => {
    const ext = Object.values(os.networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal);
    if (!ext) { t.skip('no non-loopback IPv4 address'); return; }
    const r = await startLoopbackListener({ state: STATE });
    try {
      const port = new URL(r.redirectUri).port;
      await assert.rejects(get(`http://${ext.address}:${port}/signin?handoff=h&state=${STATE}`));
    } finally { r.close(); }
  });

  it('requires a state', async () => {
    await assert.rejects(startLoopbackListener({}), /state/);
  });

  it('logs neither handoff nor state', async () => {
    const lines = [];
    const log = { info: (...a) => lines.push(a.join(' ')), warn: (...a) => lines.push(a.join(' ')), debug: (...a) => lines.push(a.join(' ')) };
    const r = await startLoopbackListener({ state: STATE, log });
    await get(withParams(r.redirectUri, { handoff: 'secret-handoff', state: STATE }));
    await r.result;
    const all = lines.join('\n');
    assert.ok(!all.includes('secret-handoff') && !all.includes(STATE), all);
  });
});

// ── Sign-in client ────────────────────────────────────────────

function httpError(status, data, headers = {}) {
  const err = new Error(`Request failed with status code ${status}`);
  err.response = { status, data, headers };
  err.config = { data: JSON.stringify({ password: 'never-leak' }) };
  return err;
}

function fakeHttp(routes) {
  const calls = [];
  const run = (method) => async (url, body, opts) => {
    if (method === 'GET') { opts = body; body = undefined; }
    calls.push({ method, url, body, opts });
    const fn = routes[`${method} ${new URL(url).pathname}`];
    if (!fn) throw httpError(404, { ok: false });
    return { status: 200, data: await fn(body, opts) };
  };
  return { calls, get: run('GET'), post: run('POST') };
}

describe('AppSignin.methods', () => {
  it('returns the normalized methods', async () => {
    const h = fakeHttp({ 'GET /api/v1/client/signin': () => ({ ok: true, version: 1, password: { enabled: true, hint: null }, microsoft: [{ id: 1, label: 'Contoso' }] }) });
    const s = new AppSignin({ http: h });
    assert.deepEqual(await s.methods(SERVER), { available: true, password: { enabled: true, hint: null }, microsoft: [{ id: 1, label: 'Contoso' }] });
    assert.equal(h.calls[0].url, 'https://gate.example.com/api/v1/client/signin');
    assert.equal(h.calls[0].opts.maxRedirects, 0);
    assert.equal(h.calls[0].opts.headers['X-Client-Platform'], 'windows');
  });

  it('older server (404), errors and junk → not available, never throws', async () => {
    for (const fn of [null, () => { throw httpError(500, {}); }, () => { const e = new Error('ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; }, () => 'junk']) {
      const h = fakeHttp(fn ? { 'GET /api/v1/client/signin': fn } : {});
      const res = await new AppSignin({ http: h }).methods(SERVER);
      assert.equal(res.available, false);
    }
  });
});

describe('AppSignin.password', () => {
  it('sends username, password, hostname, platform (totp only when given) and returns the setup code', async () => {
    const h = fakeHttp({ 'POST /api/v1/client/signin/password': () => ({ ok: true, code: 'ab12cd34ef567890', expiresAt: '2026-10-26T10:00:00Z' }) });
    const s = new AppSignin({ http: h });
    assert.deepEqual(await s.password(SERVER, { username: 'anna', password: 'pw' }), { code: 'AB12-CD34-EF56-7890', expiresAt: '2026-10-26T10:00:00Z' });
    const { body, opts } = h.calls[0];
    assert.deepEqual(Object.keys(body).sort(), ['hostname', 'password', 'platform', 'username']);
    assert.equal(body.hostname, os.hostname());
    assert.equal(opts.maxRedirects, 0, 'the password is never re-sent to a redirect target');
    await s.password(SERVER, { username: 'anna', password: 'pw', totp: '123456' });
    assert.equal(h.calls[1].body.totp, '123456');
  });

  it('maps the server errors (contract §2) without carrying the request along', async () => {
    const cases = [
      [401, { ok: false, error: 'invalid_credentials' }, 'invalid_credentials'],
      [401, { ok: false, error: 'totp_required' }, 'totp_required'],
      [401, { ok: false, error: 'totp_invalid' }, 'totp_invalid'],
      [403, { ok: false, error: 'enroll_not_allowed' }, 'enroll_not_allowed'],
      [403, { ok: false, error: 'user_disabled' }, 'user_disabled'],
      [403, { ok: false, error: 'limit_reached' }, 'limit_reached'],
      [429, { ok: false, error: 'locked', retryAfter: 600 }, 'locked'],
      [429, { ok: false, error: 'rate_limited', retryAfter: 60 }, 'rate_limited'],
      [404, { ok: false }, 'not_supported'],
      [500, 'Internal Server Error', 'http_500'],
    ];
    for (const [status, data, code] of cases) {
      const h = fakeHttp({ 'POST /api/v1/client/signin/password': () => { throw httpError(status, data); } });
      const err = await new AppSignin({ http: h }).password(SERVER, { username: 'anna', password: 'never-leak' }).catch((e) => e);
      assert.ok(err instanceof SigninError, code);
      assert.equal(err.code, code);
      assert.equal(err.message, code);
      assert.equal(err.config, undefined);
      assert.ok(!JSON.stringify({ ...err, message: err.message, stack: err.stack }).includes('never-leak'));
      if (status === 429) assert.equal(err.retryAfter, data.retryAfter);
    }
  });

  it('takes Retry-After from the header and reports network errors as unreachable', async () => {
    const h = fakeHttp({ 'POST /api/v1/client/signin/password': () => { throw httpError(429, { ok: false, error: 'rate_limited' }, { 'retry-after': '120' }); } });
    const err = await new AppSignin({ http: h }).password(SERVER, { username: 'a', password: 'b' }).catch((e) => e);
    assert.equal(err.retryAfter, 120);
    const h2 = { post: async () => { const e = new Error('connect ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; } };
    assert.equal((await new AppSignin({ http: h2 }).password(SERVER, { username: 'a', password: 'b' }).catch((e) => e)).code, 'unreachable');
  });

  it('refuses an answer without a valid setup code', async () => {
    const h = fakeHttp({ 'POST /api/v1/client/signin/password': () => ({ ok: true, code: 'gc_token' }) });
    assert.equal((await new AppSignin({ http: h }).password(SERVER, { username: 'a', password: 'b' }).catch((e) => e)).code, 'bad_response');
  });
});

describe('AppSignin.microsoft (PKCE + loopback + handoff)', () => {
  // Plays the browser: follows the start URL "through the server" back to the loopback receiver.
  function browser({ answer = (q) => ({ handoff: 'HO-1', state: q.state }), ok = true } = {}) {
    const seen = [];
    const open = async (url) => {
      seen.push(url);
      if (!ok) return false;
      const q = Object.fromEntries(new URL(url).searchParams);
      setImmediate(() => { get(withParams(q.redirect_uri, answer(q))).catch(() => {}); });
      return true;
    };
    return { seen, open };
  }

  it('opens the start URL, checks state, exchanges the handoff with the verifier', async () => {
    const b = browser();
    let challenge;
    const h = fakeHttp({
      'POST /api/v1/client/signin/handoff': (body) => {
        assert.equal(body.handoff, 'HO-1');
        assert.equal(crypto.createHash('sha256').update(body.verifier).digest('base64url'), challenge, 'S256 binding');
        return { ok: true, code: 'AB12CD34EF567890', expiresAt: null };
      },
    });
    const s = new AppSignin({ http: h, openExternal: async (url) => { challenge = new URL(url).searchParams.get('challenge'); return b.open(url); } });
    assert.deepEqual(await s.microsoft(SERVER, 7), { code: 'AB12-CD34-EF56-7890', expiresAt: null });
    const start = new URL(b.seen[0]);
    assert.equal(start.origin + start.pathname, 'https://gate.example.com/auth/oidc/7/start');
    assert.equal(start.searchParams.get('client'), 'app');
    assert.match(start.searchParams.get('redirect_uri'), /^http:\/\/127\.0\.0\.1:\d+\/signin$/);
    assert.match(start.searchParams.get('state'), /^[A-Za-z0-9_-]{43}$/);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].opts.maxRedirects, 0);
  });

  it('a wrong state never reaches the server', async () => {
    const b = browser({ answer: () => ({ handoff: 'HO-1', state: 'forged-state-forged-state' }) });
    const h = fakeHttp({});
    const err = await new AppSignin({ http: h, openExternal: b.open }).microsoft(SERVER, 1).catch((e) => e);
    assert.equal(err.code, 'state_mismatch');
    assert.equal(h.calls.length, 0);
  });

  it('passes the browser error code (not_linked)', async () => {
    const b = browser({ answer: (q) => ({ error: 'not_linked', state: q.state }) });
    const err = await new AppSignin({ http: fakeHttp({}), openExternal: b.open }).microsoft(SERVER, 1).catch((e) => e);
    assert.equal(err.code, 'not_linked');
  });

  it('browser could not be opened → browser_failed, receiver closed', async () => {
    const b = browser({ ok: false });
    const err = await new AppSignin({ http: fakeHttp({}), openExternal: b.open }).microsoft(SERVER, 1).catch((e) => e);
    assert.equal(err.code, 'browser_failed');
    const redirect = new URL(b.seen[0]).searchParams.get('redirect_uri');
    await assert.rejects(get(withParams(redirect, { handoff: 'x', state: 'y' })));
  });

  it('times out after timeoutMs', async () => {
    const s = new AppSignin({ http: fakeHttp({}), openExternal: async () => true, timeoutMs: 50 });
    assert.equal((await s.microsoft(SERVER, 1).catch((e) => e)).code, 'timeout');
  });

  it('cancel() ends a waiting sign-in; a new one cancels the old', async () => {
    const s = new AppSignin({ http: fakeHttp({}), openExternal: async () => true });
    const first = s.microsoft(SERVER, 1).catch((e) => e);
    await new Promise((r) => setTimeout(r, 20));
    const second = s.microsoft(SERVER, 2).catch((e) => e);
    assert.equal((await first).code, 'cancelled');
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(s.cancel(), true);
    assert.equal((await second).code, 'cancelled');
    assert.equal(s.cancel(), false);
  });

  it('expired handoff (invalid_or_expired)', async () => {
    const b = browser();
    const h = fakeHttp({ 'POST /api/v1/client/signin/handoff': () => { throw httpError(400, { ok: false, error: 'invalid_or_expired' }); } });
    assert.equal((await new AppSignin({ http: h, openExternal: b.open }).microsoft(SERVER, 1).catch((e) => e)).code, 'invalid_or_expired');
  });

  it('refuses invalid directory ids before opening anything', async () => {
    const b = browser();
    for (const id of [0, '1', null, 1.5]) {
      assert.equal((await new AppSignin({ http: fakeHttp({}), openExternal: b.open }).microsoft(SERVER, id).catch((e) => e)).code, 'invalid_input');
    }
    assert.equal(b.seen.length, 0);
  });
});

describe('openExternalSafely (the browser of the sign-in)', () => {
  const { openExternalSafely } = require('../src/utils/external-url');
  it('hands only http(s) URLs to the shell, settings pages only with allowSettings', async () => {
    const opened = [];
    const shell = { openExternal: async (u) => { opened.push(u); } };
    assert.equal(await openExternalSafely(shell, ' https://gate.example.com/auth/oidc/1/start?x=1 '), true);
    for (const bad of ['file:///C:/x', 'gatecontrol://signin', 'javascript:alert(1)', 'ms-settings:privacy-location', null, 42]) {
      assert.equal(await openExternalSafely(shell, bad), false, String(bad));
    }
    assert.equal(await openExternalSafely(shell, 'ms-settings:privacy-location', { allowSettings: true }), true);
    assert.deepEqual(opened, ['https://gate.example.com/auth/oidc/1/start?x=1', 'ms-settings:privacy-location']);
  });

  it('a failing shell → false, never throws', async () => {
    const shell = { openExternal: async () => { throw new Error('no browser'); } };
    assert.equal(await openExternalSafely(shell, 'https://x.example'), false);
  });
});
