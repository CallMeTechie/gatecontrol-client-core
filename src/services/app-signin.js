/**
 * GateControl – Company sign-in (Core)
 *
 * "Mit Firmenkonto anmelden" in the setup flow (GateControl ≥ 1.201.0, see
 * utils/app-signin.js for the endpoints). Every path ends with an ordinary
 * one-shot setup code; the caller redeems it through the existing setup-code
 * path (ApiClient.redeemSetupCode via base-handlers enrollWithCode), so
 * token, peer, WireGuard config and machine binding work exactly as before.
 *
 *   methods(server)            → { available, password: { enabled, hint }, microsoft: [{ id, label }] }
 *                                (404 / older server / unreachable → available: false)
 *   password(server, creds)    → { code, expiresAt }
 *   microsoft(server, id)      → { code, expiresAt }: PKCE S256 + state, loopback
 *                                receiver, default browser, handoff
 *   cancel()                   → ends a waiting browser sign-in
 *
 * Failures throw SigninError { code, status?, retryAfter? }. Its message is
 * the code only: passwords, TOTP codes, setup codes, handoffs and verifiers
 * never reach an error, a log line or the renderer.
 */

'use strict';

const os = require('os');
const axios = require('axios');
const { normalizeCode } = require('../utils/enrollment');
const signinUtil = require('../utils/app-signin');
const { startLoopbackListener, DEFAULT_TIMEOUT_MS } = require('./signin-loopback');

const REQUEST_TIMEOUT_MS = 15000;
const METHODS_TIMEOUT_MS = 8000;

class SigninError extends Error {
  /**
   * @param {string} code - server error code or flow code (timeout, cancelled, …)
   * @param {{ status?: number, retryAfter?: number }} [info]
   */
  constructor(code, { status, retryAfter } = {}) {
    super(code);
    this.name = 'SigninError';
    this.code = code;
    if (status) this.status = status;
    if (retryAfter !== undefined && retryAfter !== null) this.retryAfter = retryAfter;
  }
}

function retryAfterOf(res) {
  const body = res && res.data;
  if (body && Number.isFinite(Number(body.retryAfter)) && Number(body.retryAfter) > 0) return Number(body.retryAfter);
  const header = res && res.headers && res.headers['retry-after'];
  if (header && /^\d+$/.test(String(header).trim())) return Number(header);
  return undefined;
}

/**
 * Turns an axios failure into a SigninError without carrying the request
 * (its body holds the password) along.
 */
function toSigninError(err) {
  if (err instanceof SigninError) return err;
  const res = err && err.response;
  if (!res) return new SigninError('unreachable');
  const status = res.status;
  const code = res.data && typeof res.data.error === 'string' && /^[a-z0-9_]{1,40}$/.test(res.data.error) ? res.data.error : null;
  if (status === 429) return new SigninError(code === 'locked' ? 'locked' : 'rate_limited', { status, retryAfter: retryAfterOf(res) });
  if (status === 404 || status === 405) return new SigninError('not_supported', { status });
  return new SigninError(code || `http_${status}`, { status });
}

function codeFrom(data) {
  const code = data && data.ok === true ? normalizeCode(data.code) : null;
  if (!code) throw new SigninError('bad_response');
  return { code, expiresAt: typeof data.expiresAt === 'string' ? data.expiresAt : null };
}

class AppSignin {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log] - electron-log compatible logger
   * @param {(url: string) => Promise<boolean>} [opts.openExternal] - opens the
   *   default browser (the http(s)-only helper of utils/external-url.js)
   * @param {string|(() => string)} [opts.clientPlatform='windows'] - X-Client-Platform
   * @param {object} [opts.http] - axios (injectable for tests)
   * @param {Function} [opts.listen] - startLoopbackListener (injectable for tests)
   * @param {number} [opts.timeoutMs] - browser sign-in timeout (default 5 min)
   */
  constructor({ log = null, openExternal = null, clientPlatform = 'windows', http = axios, listen = startLoopbackListener, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.log = log;
    this.openExternal = openExternal;
    this.clientPlatform = clientPlatform;
    this.http = http;
    this.listen = listen;
    this.timeoutMs = timeoutMs;
    this._pending = null; // loopback receiver of the running browser sign-in
  }

  _headers() {
    const platform = typeof this.clientPlatform === 'function' ? this.clientPlatform() : this.clientPlatform;
    return { 'Content-Type': 'application/json', 'X-Client-Platform': platform || 'windows' };
  }

  _url(serverOrigin, path) {
    return `${String(serverOrigin).replace(/\/+$/, '')}${path}`;
  }

  // POST without following redirects: the body (password, verifier) must
  // not be re-sent to another location.
  async _post(serverOrigin, path, body) {
    try {
      const res = await this.http.post(this._url(serverOrigin, path), body, {
        timeout: REQUEST_TIMEOUT_MS,
        maxRedirects: 0,
        headers: this._headers(),
      });
      return res.data;
    } catch (err) {
      throw toSigninError(err);
    }
  }

  /**
   * Sign-in methods of the server. Never throws: a server without the
   * feature (404), an error or an unusable answer → available: false.
   * @param {string} serverOrigin - https origin
   */
  async methods(serverOrigin) {
    try {
      const res = await this.http.get(this._url(serverOrigin, signinUtil.SIGNIN_PATH), {
        timeout: METHODS_TIMEOUT_MS,
        maxRedirects: 0,
        headers: this._headers(),
      });
      return signinUtil.normalizeMethods(res.data);
    } catch (err) {
      const status = err && err.response && err.response.status;
      if (this.log) this.log.debug(`Company sign-in not offered: ${status || (err && err.code) || 'error'}`);
      return signinUtil.normalizeMethods(null);
    }
  }

  /**
   * Username + password (+ the 6 digits on totp_required).
   * @returns {Promise<{ code: string, expiresAt: string|null }>}
   */
  async password(serverOrigin, { username, password, totp } = {}) {
    const body = {
      username,
      password,
      hostname: os.hostname(),
      platform: `${os.platform()} ${os.release()}`,
    };
    if (totp) body.totp = totp;
    const data = await this._post(serverOrigin, '/api/v1/client/signin/password', body);
    return codeFrom(data);
  }

  /**
   * "Mit Microsoft anmelden": opens the default browser at the server's
   * start URL and waits (max. timeoutMs) for the answer on the loopback
   * receiver; then exchanges the handoff (with the PKCE verifier) for a
   * setup code. A second call ends the first one (cancelled).
   * @returns {Promise<{ code: string, expiresAt: string|null }>}
   */
  async microsoft(serverOrigin, directoryId) {
    if (!signinUtil.isDirectoryId(directoryId)) throw new SigninError('invalid_input');
    if (typeof this.openExternal !== 'function') throw new SigninError('browser_failed');
    this.cancel();

    const { verifier, challenge } = signinUtil.createPkce();
    const state = signinUtil.createState();
    const receiver = await this.listen({ state, timeoutMs: this.timeoutMs, log: this.log });
    this._pending = receiver;
    try {
      const startUrl = signinUtil.buildStartUrl(serverOrigin, directoryId, { redirectUri: receiver.redirectUri, state, challenge });
      let opened = false;
      try {
        opened = (await this.openExternal(startUrl)) === true;
      } catch {
        opened = false;
      }
      if (!opened) {
        receiver.close('browser_failed');
        throw new SigninError('browser_failed');
      }
      if (this.log) this.log.info('Company sign-in: waiting for the browser (Microsoft)');

      const outcome = await receiver.result;
      if (outcome.error) throw new SigninError(outcome.error);
      const data = await this._post(serverOrigin, '/api/v1/client/signin/handoff', { handoff: outcome.handoff, verifier });
      return codeFrom(data);
    } finally {
      receiver.close('cancelled');
      if (this._pending === receiver) this._pending = null;
    }
  }

  /** Ends a waiting browser sign-in (its microsoft() call fails with 'cancelled'). */
  cancel() {
    const pending = this._pending;
    this._pending = null;
    if (pending) pending.close('cancelled');
    return !!pending;
  }
}

module.exports = { AppSignin, SigninError, toSigninError };
