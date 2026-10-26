/**
 * GateControl – Company sign-in, pure helpers (Core)
 *
 * "Mit Firmenkonto anmelden" (GateControl ≥ 1.201.0): instead of a setup
 * code from the admin, the person signs in with their account and the server
 * answers with an ordinary one-shot setup code, which the client redeems
 * through the existing POST /api/v1/client/enroll path.
 *
 *   GET  /api/v1/client/signin            → which methods the server offers
 *   POST /api/v1/client/signin/password   → { username, password, totp? } → { code }
 *   GET  {server}/auth/oidc/{id}/start    → Microsoft (Entra) in the browser,
 *        back to http://127.0.0.1:<port>/signin?handoff=…&state=…
 *   POST /api/v1/client/signin/handoff    → { handoff, verifier } → { code }
 *
 * PKCE (RFC 7636, S256), state, the browser start URL, the answer of the
 * methods endpoint and the server's error codes. No Electron, no network.
 */

'use strict';

const crypto = require('crypto');

const SIGNIN_PATH = '/api/v1/client/signin';
const LOOPBACK_PATH = '/signin';

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
// One-time values from the server (handoff): URL-safe, bounded.
const TOKEN_RE = /^[A-Za-z0-9\-._~]{1,512}$/;

// Error codes the server may put into the browser redirect (contract §3).
const BROWSER_ERRORS = new Set(['access_denied', 'not_linked', 'enroll_not_allowed', 'user_disabled', 'failed']);

const MAX_MICROSOFT = 10;
const MAX_LABEL = 80;
const MAX_HINT = 300;

/** base64url without padding (RFC 4648 §5). */
function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** PKCE code verifier: 32 random bytes → 43 characters of [A-Za-z0-9-_]. */
function createVerifier() {
  return base64url(crypto.randomBytes(32));
}

/** PKCE S256 challenge: base64url(sha256(verifier)). */
function challengeFor(verifier) {
  if (!isValidVerifier(verifier)) throw new Error('invalid verifier');
  return base64url(crypto.createHash('sha256').update(verifier, 'ascii').digest());
}

function isValidVerifier(v) {
  return typeof v === 'string' && VERIFIER_RE.test(v);
}

/** { verifier, challenge } for one sign-in. */
function createPkce() {
  const verifier = createVerifier();
  return { verifier, challenge: challengeFor(verifier) };
}

/** Random state of one browser sign-in (32 bytes, base64url). */
function createState() {
  return base64url(crypto.randomBytes(32));
}

/** Constant-time comparison of two strings (false for non-strings / other length). */
function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length || ba.length === 0) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function isValidHandoff(v) {
  return typeof v === 'string' && TOKEN_RE.test(v);
}

/** Loopback redirect URI (RFC 8252 §7.3) for a port the client listens on. */
function loopbackRedirectUri(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid port');
  return `http://127.0.0.1:${port}${LOOPBACK_PATH}`;
}

/**
 * Start URL of the Microsoft sign-in in the browser:
 * {server}/auth/oidc/{id}/start?client=app&redirect_uri=…&state=…&challenge=…
 *
 * @param {string} serverOrigin - https origin (utils/enrollment toServerOrigin)
 * @param {number} id - directory id from the methods answer
 */
function buildStartUrl(serverOrigin, id, { redirectUri, state, challenge }) {
  if (!isDirectoryId(id)) throw new Error('invalid directory id');
  const base = new URL(serverOrigin);
  if (base.protocol !== 'https:') throw new Error('https required');
  const url = new URL(`/auth/oidc/${id}/start`, base.origin);
  url.searchParams.set('client', 'app');
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('challenge', challenge);
  return url.toString();
}

function isDirectoryId(id) {
  return Number.isSafeInteger(id) && id > 0 && id <= 2147483647;
}

function cleanText(v, max) {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/**
 * Answer of GET /api/v1/client/signin → what the setup screen shows.
 * { available, password: { enabled, hint }, microsoft: [{ id, label }] };
 * available is false when the answer is not usable or offers nothing.
 */
function normalizeMethods(data) {
  const none = { available: false, password: { enabled: false, hint: null }, microsoft: [] };
  if (!data || typeof data !== 'object' || data.ok !== true) return none;
  const pw = data.password && typeof data.password === 'object' ? data.password : {};
  const password = { enabled: pw.enabled === true, hint: pw.enabled === true ? cleanText(pw.hint, MAX_HINT) : null };
  const seen = new Set();
  const microsoft = [];
  for (const m of Array.isArray(data.microsoft) ? data.microsoft : []) {
    if (!m || typeof m !== 'object' || !isDirectoryId(m.id) || seen.has(m.id)) continue;
    seen.add(m.id);
    microsoft.push({ id: m.id, label: cleanText(m.label, MAX_LABEL) || '' });
    if (microsoft.length >= MAX_MICROSOFT) break;
  }
  return { available: password.enabled || microsoft.length > 0, password, microsoft };
}

/** Error code of the browser redirect (unknown codes → 'failed'). */
function browserErrorCode(raw) {
  return typeof raw === 'string' && BROWSER_ERRORS.has(raw) ? raw : 'failed';
}

/**
 * Minutes to wait after 429 (rounded up, at least 1), or null when the
 * server did not say.
 */
function waitMinutes(retryAfter) {
  const n = Number(retryAfter);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.max(1, Math.ceil(n / 60));
}

// Server / flow error code → core i18n key (server.signin.*).
const ERROR_KEYS = {
  invalid_credentials: 'server.signin.invalidCredentials',
  totp_required: 'server.signin.totpRequired',
  totp_invalid: 'server.signin.totpInvalid',
  enroll_not_allowed: 'server.signin.enrollNotAllowed',
  user_disabled: 'server.signin.userDisabled',
  limit_reached: 'server.signin.limitReached',
  password_change_required: 'server.signin.passwordChangeRequired',
  directory_unavailable: 'server.signin.directoryUnavailable',
  access_denied: 'server.signin.accessDenied',
  not_linked: 'server.signin.notLinked',
  failed: 'server.signin.microsoftFailed',
  invalid_or_expired: 'server.signin.expired',
  timeout: 'server.signin.timeout',
  state_mismatch: 'server.signin.stateMismatch',
  browser_failed: 'server.signin.browserFailed',
  not_supported: 'server.signin.notSupported',
  unreachable: 'server.signin.unreachable',
};

/**
 * Text for a sign-in error.
 * @param {Function} t - i18n t()
 * @param {{ code?: string, retryAfter?: number }} err
 */
function signinErrorMessage(t, err) {
  const code = err && err.code;
  if (code === 'rate_limited' || code === 'locked') {
    const n = waitMinutes(err.retryAfter);
    if (n === null) return t('server.signin.rateLimitedSoon');
    return n === 1 ? t('server.signin.rateLimitedOne') : t('server.signin.rateLimited', { n });
  }
  if (typeof code === 'string' && Object.prototype.hasOwnProperty.call(ERROR_KEYS, code)) return t(ERROR_KEYS[code]);
  return t('server.signin.failedCode', { error: typeof code === 'string' && /^[a-z0-9_]{1,40}$/.test(code) ? code : 'unknown' });
}

module.exports = {
  SIGNIN_PATH,
  LOOPBACK_PATH,
  base64url,
  createVerifier,
  challengeFor,
  isValidVerifier,
  createPkce,
  createState,
  sameSecret,
  isValidHandoff,
  isDirectoryId,
  loopbackRedirectUri,
  buildStartUrl,
  normalizeMethods,
  browserErrorCode,
  waitMinutes,
  signinErrorMessage,
};
