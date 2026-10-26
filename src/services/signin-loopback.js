/**
 * GateControl – Loopback receiver of the browser sign-in (Core)
 *
 * "Mit Microsoft anmelden" runs in the person's default browser. The server
 * sends the browser back to a loopback redirect URI (RFC 8252 §7.3):
 *
 *   http://127.0.0.1:<random port>/signin?handoff=<one-time value>&state=<state>
 *   http://127.0.0.1:<random port>/signin?error=<code>&state=<state>
 *
 * startLoopbackListener() listens on 127.0.0.1 only (never on all
 * interfaces) on a port the OS picks, takes exactly ONE answer on /signin,
 * checks the state (constant time), answers the browser with a small German
 * page and closes. After 5 minutes without an answer it closes with
 * { error: 'timeout' }.
 *
 * Other paths (the browser's /favicon.ico, …) and requests with a foreign
 * Host header (DNS rebinding) get 404 and do not count. Nothing secret
 * (handoff, state) is ever logged.
 */

'use strict';

const http = require('http');
const { LOOPBACK_PATH, sameSecret, isValidHandoff, browserErrorCode, loopbackRedirectUri } = require('../utils/app-signin');

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const HOST = '127.0.0.1';

const PAGE_DONE = 'Anmeldung abgeschlossen – du kannst dieses Fenster schließen.';
const PAGE_FAILED = 'Anmeldung nicht abgeschlossen – bitte kehre zur GateControl-App zurück.';

function page(text) {
  return '<!doctype html><html lang="de"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>GateControl</title>'
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

/**
 * @param {object} opts
 * @param {string} opts.state - expected state of this sign-in
 * @param {number} [opts.timeoutMs=300000]
 * @param {object} [opts.log] - electron-log compatible
 * @returns {Promise<{ port: number, redirectUri: string,
 *   result: Promise<{ handoff: string } | { error: string }>,
 *   close: (reason?: string) => void }>}
 *   result never rejects. error is a browser error code (access_denied,
 *   not_linked, enroll_not_allowed, user_disabled, failed) or
 *   state_mismatch | invalid_response | timeout | cancelled.
 */
function startLoopbackListener({ state, timeoutMs = DEFAULT_TIMEOUT_MS, log = null } = {}) {
  if (typeof state !== 'string' || state.length < 16) {
    return Promise.reject(new Error('state required'));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let resolveResult;
    const result = new Promise((r) => { resolveResult = r; });
    let timer = null;
    let port = 0;

    const server = http.createServer();
    // Small, slow or idle clients cannot hold the receiver open.
    server.headersTimeout = 10000;
    server.requestTimeout = 10000;
    server.keepAliveTimeout = 1;
    server.maxHeadersCount = 50;

    function shutdown() {
      clearTimeout(timer);
      try { server.close(); } catch { /* already closed */ }
      // Ends idle keep-alive sockets; a request in flight finishes first.
      if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
    }

    function settle(outcome) {
      if (settled) return;
      settled = true;
      resolveResult(outcome);
      if (log) log.info(`Company sign-in: browser answer ${outcome.handoff ? 'received' : `(${outcome.error})`}`);
    }

    server.on('request', (req, res) => {
      if (settled) {
        send(res, 410, page(PAGE_FAILED));
        return;
      }
      let url;
      try {
        url = new URL(req.url, `http://${HOST}`);
      } catch {
        send(res, 400, 'Bad Request', 'text/plain; charset=utf-8');
        return;
      }
      const hostOk = req.headers.host === `${HOST}:${port}`;
      if (!hostOk || req.method !== 'GET' || url.pathname !== LOOPBACK_PATH) {
        send(res, 404, 'Not Found', 'text/plain; charset=utf-8');
        return;
      }

      // The one answer of this sign-in, whatever it says.
      const params = url.searchParams;
      let outcome;
      if (!sameSecret(params.get('state') || '', state)) {
        outcome = { error: 'state_mismatch' };
      } else if (params.has('error')) {
        outcome = { error: browserErrorCode(params.get('error')) };
      } else if (isValidHandoff(params.get('handoff'))) {
        outcome = { handoff: params.get('handoff') };
      } else {
        outcome = { error: 'invalid_response' };
      }
      settle(outcome);
      res.on('finish', shutdown);
      res.on('close', shutdown);
      send(res, outcome.handoff ? 200 : 400, page(outcome.handoff ? PAGE_DONE : PAGE_FAILED));
    });

    server.on('clientError', (_err, socket) => {
      try { socket.destroy(); } catch { /* gone */ }
    });

    server.on('error', (err) => {
      if (!port) reject(err);
      else if (log) log.warn(`Company sign-in: loopback receiver failed: ${err.code || err.message}`);
    });

    server.listen({ port: 0, host: HOST, exclusive: true }, () => {
      port = server.address().port;
      timer = setTimeout(() => {
        settle({ error: 'timeout' });
        shutdown();
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
      resolve({
        port,
        redirectUri: loopbackRedirectUri(port),
        result,
        close(reason = 'cancelled') {
          settle({ error: reason });
          shutdown();
        },
      });
    });
  });
}

module.exports = { startLoopbackListener, DEFAULT_TIMEOUT_MS, PAGE_DONE, PAGE_FAILED };
