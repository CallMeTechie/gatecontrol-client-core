/**
 * GateControl – Loopback receiver of the Microsoft sign-in of Mail (Core)
 *
 * "Mit Microsoft anmelden" (Mail › Konto hinzufügen) runs in the person's
 * default browser (authorization code with PKCE, RFC 8252 §7.3). Microsoft
 * sends the browser back to
 *
 *   http://localhost:<free port>/?code=<code>&state=<state>
 *   http://localhost:<free port>/?error=<code>&error_description=…&state=<state>
 *
 * startCodeListener() listens on the loopback addresses only (127.0.0.1 and,
 * when it can, ::1 on the same port — browsers resolve "localhost" to either),
 * takes exactly ONE answer on "/", checks the state (constant time), answers
 * the browser with a small page in the app's language and closes. After
 * 5 minutes without an answer it closes with { error: 'timeout' }.
 *
 * Other paths (/favicon.ico, …) and requests with a foreign Host header (DNS
 * rebinding) get 404 and do not count. Nothing secret (code, state) is ever
 * logged.
 */

'use strict';

const http = require('http');
const crypto = require('crypto');

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

const TEXTS = {
  de: { done: 'Anmeldung abgeschlossen – du kannst dieses Fenster schließen und zu GateControl zurückkehren.', failed: 'Anmeldung nicht abgeschlossen – bitte kehre zur GateControl-App zurück.' },
  en: { done: 'Signed in – you can close this window and return to GateControl.', failed: 'Sign-in not completed – please return to the GateControl app.' },
};

function page(text, lang) {
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8">`
    + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>GateControl</title>'
    + '<style>body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;min-height:90vh;'
    + 'align-items:center;justify-content:center;margin:0;padding:24px;color:#1f2a24;background:#f6f7f5}'
    + '@media (prefers-color-scheme:dark){body{color:#e8ece9;background:#141816}}'
    + 'p{font-size:18px;max-width:32em;text-align:center;line-height:1.5}</style>'
    + `</head><body><p>${text}</p></body></html>`;
}

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'Pragma': 'no-cache',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Connection': 'close',
};

function send(res, status, body, type = 'text/html; charset=utf-8') {
  const buf = Buffer.from(body, 'utf8');
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': buf.length });
  res.end(buf);
}

function sameSecret(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y) && String(a).length === String(b).length;
}

/** Microsoft's error → a short code of ours. */
function errorCodeOf(raw) {
  const e = String(raw || '');
  if (e === 'access_denied') return 'access_denied';
  if (e === 'consent_required' || e === 'interaction_required') return 'consent_required';
  if (e === 'invalid_client' || e === 'unauthorized_client' || e === 'invalid_request') return 'ms_not_configured';
  return 'failed';
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { server.removeListener('listening', onListening); reject(err); };
    const onListening = () => { server.removeListener('error', onError); resolve(server.address().port); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen({ port, host, exclusive: true });
  });
}

/**
 * @param {object} opts
 * @param {string} opts.state - expected state of this sign-in (≥ 16 characters)
 * @param {number} [opts.timeoutMs=300000]
 * @param {() => string} [opts.getLang]
 * @param {object} [opts.log]
 * @returns {Promise<{ port: number, redirectUri: string,
 *   result: Promise<{ code: string } | { error: string }>, close: (reason?: string) => void }>}
 *   result never rejects; error: access_denied | consent_required | ms_not_configured | failed |
 *   state_mismatch | invalid_response | timeout | cancelled.
 */
async function startCodeListener({ state, timeoutMs = DEFAULT_TIMEOUT_MS, getLang = null, log = null } = {}) {
  if (typeof state !== 'string' || state.length < 16) throw new Error('state required');
  const lang = () => {
    let l = null;
    try { l = typeof getLang === 'function' ? getLang() : null; } catch { l = null; }
    return l === 'en' ? 'en' : 'de';
  };

  let settled = false;
  let resolveResult;
  const result = new Promise((r) => { resolveResult = r; });
  let timer = null;
  let port = 0;
  const servers = [];

  function shutdown() {
    clearTimeout(timer);
    for (const s of servers) {
      try { s.close(); } catch { /* closed */ }
      if (typeof s.closeIdleConnections === 'function') s.closeIdleConnections();
    }
  }

  function settle(outcome) {
    if (settled) return;
    settled = true;
    resolveResult(outcome);
    if (log) log.info(`Mail Microsoft sign-in: browser answer ${outcome.code ? 'received' : `(${outcome.error})`}`);
  }

  function onRequest(req, res) {
    const l = lang();
    if (settled) { send(res, 410, page(TEXTS[l].failed, l)); return; }
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { send(res, 400, 'Bad Request', 'text/plain; charset=utf-8'); return; }
    const host = String(req.headers.host || '').toLowerCase();
    const hostOk = [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`].includes(host);
    if (!hostOk || req.method !== 'GET' || url.pathname !== '/' || (!url.searchParams.has('code') && !url.searchParams.has('error'))) {
      send(res, 404, 'Not Found', 'text/plain; charset=utf-8');
      return;
    }
    const p = url.searchParams;
    let outcome;
    if (!sameSecret(p.get('state') || '', state)) outcome = { error: 'state_mismatch' };
    else if (p.has('error')) outcome = { error: errorCodeOf(p.get('error')) };
    else if (/^[A-Za-z0-9._~*!$'()+,;=:@/-]{10,4096}$/.test(p.get('code') || '')) outcome = { code: p.get('code') };
    else outcome = { error: 'invalid_response' };
    settle(outcome);
    res.on('finish', shutdown);
    res.on('close', shutdown);
    send(res, outcome.code ? 200 : 400, page(outcome.code ? TEXTS[l].done : TEXTS[l].failed, l));
  }

  const make = () => {
    const s = http.createServer(onRequest);
    s.headersTimeout = 10000;
    s.requestTimeout = 10000;
    s.keepAliveTimeout = 1;
    s.maxHeadersCount = 50;
    s.on('clientError', (_err, socket) => { try { socket.destroy(); } catch { /* gone */ } });
    s.on('error', (err) => { if (log) log.warn(`Mail Microsoft sign-in: loopback receiver failed: ${err.code || err.message}`); });
    return s;
  };

  const v4 = make();
  port = await listen(v4, 0, '127.0.0.1');
  servers.push(v4);
  // "localhost" may be ::1 for the browser: the same port there too (no IPv6 → only 127.0.0.1)
  const v6 = make();
  try {
    await listen(v6, port, '::1');
    servers.push(v6);
  } catch {
    try { v6.close(); } catch { /* never listened */ }
  }
  timer = setTimeout(() => { settle({ error: 'timeout' }); shutdown(); }, timeoutMs);
  if (typeof timer.unref === 'function') timer.unref();
  return {
    port,
    redirectUri: `http://localhost:${port}`,
    result,
    close(reason = 'cancelled') {
      settle({ error: reason });
      shutdown();
    },
  };
}

module.exports = { startCodeListener, DEFAULT_TIMEOUT_MS };
