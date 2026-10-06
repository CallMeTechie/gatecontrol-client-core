'use strict';

// One-time portal login link: ApiClient.getPortalLink() against a local HTTP
// server (POST /api/v1/client/portal-link), the shared portal opener and the
// portal:open IPC channel. The ticket in the link is a secret and must never
// reach the log.

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');

const realResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === '@callmetechie/gatecontrol-config-hash') return require.resolve('./fixtures/config-hash-stub');
  return realResolve.call(this, request, ...rest);
};

const ApiClient = require('../src/services/api-client');
const { createPortalOpener, resolvePortalUrl } = require('../src/utils/portal');
const { registerBaseHandlers } = require('../src/ipc/base-handlers');

const TICKET = 'tkt_SECRET_0123456789abcdef';

// Logger double that records every argument of every call.
function recordingLog() {
  const lines = [];
  const rec = (level) => (...args) => { lines.push([level, ...args.map((a) => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === 'string' ? a : JSON.stringify(a)))].join(' ')); };
  return { lines, info: rec('info'), warn: rec('warn'), error: rec('error'), debug: rec('debug') };
}

describe('ApiClient.getPortalLink', () => {
  let server;
  let origin;
  let reply; // (req, res) => void, set per test
  let requests;

  before(async () => {
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, headers: req.headers, body });
        reply(req, res);
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    origin = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => {
    server.closeAllConnections();
    return new Promise((r) => server.close(r));
  });

  beforeEach(() => { requests = []; });

  const json = (status, data) => (_req, res) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  };

  function makeClient(log = recordingLog()) {
    const c = new ApiClient(origin, 'gc_token_x', log, 7, { clientType: 'pro' });
    c.portalUrl = `${origin}/`;
    return { c, log };
  }

  it('returns the link on success and sends the usual auth headers', async () => {
    const link = `${origin}/auto?t=${TICKET}`;
    reply = json(200, { ok: true, url: link, expiresIn: 60 });
    const { c } = makeClient();
    assert.equal(await c.getPortalLink(), link);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/api/v1/client/portal-link');
    assert.equal(requests[0].headers['x-api-token'], 'gc_token_x');
    assert.ok(requests[0].headers['x-machine-fingerprint']);
  });

  it('fetches a fresh link on every call (no caching)', async () => {
    let n = 0;
    reply = (_req, res) => { n++; json(200, { ok: true, url: `${origin}/auto?t=${TICKET}${n}`, expiresIn: 60 })(_req, res); };
    const { c } = makeClient();
    assert.equal(await c.getPortalLink(), `${origin}/auto?t=${TICKET}1`);
    assert.equal(await c.getPortalLink(), `${origin}/auto?t=${TICKET}2`);
    assert.equal(requests.length, 2);
  });

  it('returns null on 404 (older server)', async () => {
    reply = json(404, { error: 'not_found' });
    const { c } = makeClient();
    assert.equal(await c.getPortalLink(), null);
  });

  it('returns null on any other non-2xx answer', async () => {
    reply = json(500, { ok: true, url: `${origin}/auto?t=${TICKET}` });
    const { c } = makeClient();
    assert.equal(await c.getPortalLink(), null);
  });

  it('returns null when the server does not answer within the timeout', async () => {
    reply = () => { /* never answers */ };
    const { c } = makeClient();
    assert.equal(c.portalLinkTimeoutMs, 5000);
    c.portalLinkTimeoutMs = 150;
    const t0 = Date.now();
    assert.equal(await c.getPortalLink(), null);
    assert.ok(Date.now() - t0 < 3000, 'gave up close to the timeout');
  });

  it('returns null on a network error', async () => {
    const dead = http.createServer();
    await new Promise((r) => dead.listen(0, '127.0.0.1', r));
    const port = dead.address().port;
    await new Promise((r) => dead.close(r));
    const c = new ApiClient(`http://127.0.0.1:${port}`, 'gc_token_x', recordingLog(), 7);
    c.portalUrl = `http://127.0.0.1:${port}/`;
    assert.equal(await c.getPortalLink(), null);
  });

  it('rejects a link whose origin differs from the portal URL', async () => {
    const { c, log } = makeClient();
    for (const url of [
      `https://evil.example.com/auto?t=${TICKET}`,
      `${origin.replace('http:', 'https:')}/auto?t=${TICKET}`, // other scheme
      `http://127.0.0.1:1/auto?t=${TICKET}`,                    // other port
    ]) {
      reply = json(200, { ok: true, url, expiresIn: 60 });
      assert.equal(await c.getPortalLink(), null, url);
    }
    assert.ok(log.lines.some((l) => l.includes('origin')));
  });

  it('returns null without a url, with a non-http url, or without a portal URL', async () => {
    const { c } = makeClient();
    reply = json(200, { ok: true, expiresIn: 60 });
    assert.equal(await c.getPortalLink(), null);
    reply = json(200, { ok: true, url: 'javascript:alert(1)' });
    assert.equal(await c.getPortalLink(), null);
    reply = json(200, { ok: true, url: 42 });
    assert.equal(await c.getPortalLink(), null);
    c.portalUrl = null;
    reply = json(200, { ok: true, url: `${origin}/auto?t=${TICKET}` });
    requests = [];
    assert.equal(await c.getPortalLink(), null);
    assert.equal(requests.length, 0, 'no request without a portal URL');
  });

  it('checks against an explicitly passed portal URL', async () => {
    reply = json(200, { ok: true, url: `${origin}/auto?t=${TICKET}` });
    const { c } = makeClient();
    c.portalUrl = null;
    assert.equal(await c.getPortalLink(`${origin}/portal`), `${origin}/auto?t=${TICKET}`);
    assert.equal(await c.getPortalLink('https://other.example.com'), null);
  });

  it('never logs the ticket, whatever happens', async () => {
    const log = recordingLog();
    const { c } = makeClient(log);
    const answers = [
      json(200, { ok: true, url: `${origin}/auto?t=${TICKET}`, expiresIn: 60 }),
      json(200, { ok: true, url: `https://evil.example.com/auto?t=${TICKET}` }),
      json(403, { ok: false, url: `${origin}/auto?t=${TICKET}` }),
      json(500, { error: TICKET }),
    ];
    for (const a of answers) { reply = a; await c.getPortalLink(); }
    reply = () => {};
    c.portalLinkTimeoutMs = 100;
    await c.getPortalLink();
    assert.ok(log.lines.length > 0, 'failures were logged');
    for (const line of log.lines) assert.ok(!line.includes(TICKET), `ticket leaked into log: ${line}`);
    assert.ok(!JSON.stringify(c).includes(TICKET), 'ticket not stored on the client');
  });
});

describe('portal opener', () => {
  const PORTAL = 'https://home.example.com/';
  const LINK = `https://home.example.com/auto?t=${TICKET}`;

  function setup({ link = LINK, portalUrl = PORTAL, getPortalLink } = {}) {
    const opened = [];
    const calls = [];
    const apiClient = {
      getPortalLink: getPortalLink || (async (p) => { calls.push(p); return link; }),
    };
    const opener = createPortalOpener({
      apiClient,
      getPortalUrl: () => portalUrl,
      getShell: () => ({ openExternal: async (u) => { opened.push(u); } }),
      log: recordingLog(),
    });
    return { opener, opened, calls };
  }

  it('opens the one-time link and asks for a fresh one every time', async () => {
    const { opener, opened, calls } = setup();
    assert.equal(await opener.open(), true);
    assert.equal(await opener.open(), true);
    assert.deepEqual(opened, [LINK, LINK]);
    assert.deepEqual(calls, [PORTAL, PORTAL]);
  });

  it('falls back to the portal URL without a link', async () => {
    const { opener, opened } = setup({ link: null });
    assert.equal(await opener.open(), true);
    assert.deepEqual(opened, [PORTAL]);
  });

  it('falls back to the portal URL when getPortalLink throws', async () => {
    const { opener, opened } = setup({ getPortalLink: async () => { throw new Error('boom'); } });
    assert.equal(await opener.open(), true);
    assert.deepEqual(opened, [PORTAL]);
  });

  it('never opens a non-https link', async () => {
    const { opener, opened } = setup({ link: `http://home.example.com/auto?t=${TICKET}` });
    await opener.open();
    assert.deepEqual(opened, [PORTAL]);
  });

  it('opens nothing without an https portal URL', async () => {
    for (const portalUrl of [null, '', 'http://home.example.com', 'file:///C:/x']) {
      const { opener, opened, calls } = setup({ portalUrl });
      assert.equal(await opener.open(), false);
      assert.deepEqual(opened, []);
      assert.deepEqual(calls, []);
    }
  });

  it('resolvePortalUrl works with clients without getPortalLink', async () => {
    assert.equal(await resolvePortalUrl({ apiClient: {}, portalUrl: PORTAL }), PORTAL);
    assert.equal(await resolvePortalUrl({ apiClient: null, portalUrl: null }), null);
  });
});

describe('portal:open IPC channel', () => {
  function register(extra) {
    const handlers = {};
    registerBaseHandlers({ handle: (c, fn) => { handlers[c] = fn; }, on() {} }, {
      app: { getVersion: () => '1.0.0', setLoginItemSettings() {} },
      dialog: {}, getMainWindow: () => null,
      store: { get() {}, set() {}, store: {} },
      wgService: {}, apiClient: {}, killSwitch: {},
      log: recordingLog(),
      connectTunnel() {}, disconnectTunnel() {}, toggleKillSwitch() {},
      installUpdate() {}, getTunnelState: () => ({}),
      wgConfigFile: 'wg.conf',
      ...extra,
    });
    return handlers;
  }

  it('is only registered when the client provides openPortal', () => {
    assert.equal(register({}).hasOwnProperty('portal:open'), false);
  });

  it('calls openPortal and answers with a boolean only', async () => {
    let n = 0;
    const handlers = register({ openPortal: async () => { n++; return true; } });
    assert.equal(await handlers['portal:open']({}), true);
    assert.equal(n, 1);
    const failing = register({ openPortal: async () => { throw new Error('x'); } });
    assert.equal(await failing['portal:open']({}), false);
  });
});
