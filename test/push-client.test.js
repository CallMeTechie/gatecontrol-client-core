'use strict';

// Push client (services/push-client.js) against a local HTTP server that
// plays the GateControl push endpoint: headers, hello/notification/read/
// revoke handling, Last-Event-ID resume, delivered acks, reconnect backoff,
// every error answer of the contract, keepalive watchdog, device settings.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const PushClient = require('../src/services/push-client');
const ApiClient = require('../src/services/api-client');
const { createMemoryStore } = require('./fixtures/memory-store');

const log = { info() {}, warn() {}, debug() {}, error() {} };
const FAST = {
  initialDelayMs: 20, maxDelayMs: 160, disabledRetryMs: 300, rateLimitMs: 400,
  connectTimeoutMs: 1000, defaultKeepaliveS: 25, stableAfterMs: 60000, ackDelayMs: 5, networkDebounceMs: 5,
};

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

async function waitFor(fn, ms = 3000, what = 'condition') {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Local push server; handler(req, res, n) answers request n (0-based). */
async function pushServer(handler) {
  const requests = [];
  const open = new Set();
  const server = http.createServer((req, res) => {
    const n = requests.length;
    requests.push({ at: Date.now(), headers: req.headers, url: req.url, method: req.method });
    open.add(res);
    res.on('close', () => open.delete(res));
    handler(req, res, n);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((r) => {
    for (const res of open) res.destroy();
    server.close(() => r());
  });
  cleanups.push(close);
  return { url, requests, open, close };
}

const ev = (event, data, id) => `${id != null ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
const HELLO = { server_time: '2026-10-10T21:42:03.120Z', keepalive_s: 25, retention_h: 72, via: 'direct', unread: 2,
  topics: [{ id: 'devices', label: 'Geräte & Gateways' }, { id: 'system', label: 'System' }] };
const note = (seq, extra = {}) => ({ seq, id: seq + 100, event_id: 'gateway_state', topic: 'devices', priority: 'critical',
  title: `Message ${seq}`, body: 'b', created_at: '2026-10-10T21:42:03Z', expires_at: '2099-01-01T00:00:00Z',
  collapse_key: 'gateway:3', silent: false, data: { route: 'gateways' }, ...extra });

function sse(res, chunks = [], { keepOpen = true } = {}) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
  for (const c of chunks) res.write(c);
  if (!keepOpen) res.end();
}
function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function fakeApi(url, overrides = {}) {
  const calls = { acks: [], prefs: [], inbox: [], test: 0 };
  return {
    calls,
    serverUrl: url,
    apiKey: 'gc_token',
    buildHeaders: () => ({
      'X-API-Token': 'gc_token', 'X-Client-Version': '1.9.3', 'X-Client-Platform': 'windows',
      'X-Client-Type': 'pro', 'X-Machine-Fingerprint': 'fp123',
    }),
    pushAck: async (b) => { calls.acks.push(b); return { ok: true }; },
    pushPrefs: async (p) => { calls.prefs.push(p); return { ok: true }; },
    pushInbox: async (o) => { calls.inbox.push(o); return { ok: true, items: [], unread: 0 }; },
    pushTest: async () => { calls.test++; return { ok: true, seq: 130 }; },
    ...overrides,
  };
}

function makeClient(url, opts = {}) {
  const store = opts.store || createMemoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
  const api = opts.api || fakeApi(url);
  const client = new PushClient({ apiClient: api, store, log, allowHttp: true, random: () => 1, timing: { ...FAST, ...(opts.timing || {}) }, ...opts.extra });
  cleanups.push(async () => client.stop());
  return { client, store, api };
}

describe('PushClient stream', () => {
  it('connects with the api-client headers and handles hello, notification, read, revoke', async () => {
    const srv = await pushServer((req, res) => sse(res, [
      ev('hello', HELLO), ev('notification', note(5), 5), ': ping\n\n', ev('notification', note(6), 6),
      ev('read', { ids: [105] }), ev('revoke', { ids: [106] }), ev('policy', { version: 'abc' }),
    ]));
    const { client, store, api } = makeClient(srv.url);
    const got = { hello: [], notification: [], read: [], revoke: [], event: [], status: [] };
    for (const k of Object.keys(got)) client.on(k, (x) => got[k].push(x));
    client.start();

    await waitFor(() => got.revoke.length && api.calls.acks.length, 3000, 'events');
    const h = srv.requests[0].headers;
    assert.equal(srv.requests[0].url, '/api/v1/client/push');
    assert.equal(h['x-api-token'], 'gc_token');
    assert.equal(h['x-client-type'], 'pro');
    assert.equal(h['x-client-platform'], 'windows');
    assert.equal(h['x-client-version'], '1.9.3');
    assert.equal(h['x-machine-fingerprint'], 'fp123');
    assert.equal(h.accept, 'text/event-stream');
    assert.equal(h['last-event-id'], undefined);

    assert.equal(got.hello[0].via, 'direct');
    assert.deepEqual(got.notification.map((n) => n.seq), [5, 6]);
    assert.equal(got.notification[0].via, 'direct');
    assert.ok(got.notification[0].received_at);
    assert.deepEqual(got.read, [{ ids: [105] }]);
    assert.deepEqual(got.revoke, [{ ids: [106] }]);
    assert.deepEqual(got.event, [{ event: 'policy', data: { version: 'abc' }, id: '6' }]);
    assert.equal(store.get('notifications.lastSeq'), 6);

    const st = client.status();
    assert.equal(st.state, 'connected');
    assert.equal(st.via, 'direct');
    assert.equal(st.unread, 2);
    assert.deepEqual(st.topics.map((x) => x.id), ['devices', 'system']);
    assert.equal(st.keepaliveS, 25);
    assert.ok(st.since);
    assert.equal(st.serverHost, srv.url.replace('http://', ''));
    // delivered confirmations are batched
    await waitFor(() => api.calls.acks.flatMap((a) => a.seqs).length === 2, 2000, 'acks');
    assert.deepEqual(api.calls.acks, [{ seqs: [5, 6], state: 'delivered', action: undefined }]);
    // device settings are sent once after hello
    await waitFor(() => api.calls.prefs.length === 1);
    assert.deepEqual(api.calls.prefs[0], { enabled: true, mode: 'always', muted_topics: [] });
    assert.ok(got.status.some((s) => s.state === 'connecting'));
  });

  it('resumes with Last-Event-ID after the server closed the stream', async () => {
    const srv = await pushServer((req, res, n) => {
      if (n === 0) return sse(res, [ev('hello', HELLO), ev('notification', note(41), 41)], { keepOpen: false });
      return sse(res, [ev('hello', HELLO), ev('notification', note(41), 41), ev('notification', note(42), 42)]);
    });
    const { client, api } = makeClient(srv.url);
    const seen = [];
    client.on('notification', (n) => seen.push(n.seq));
    client.start();
    await waitFor(() => seen.includes(42), 3000, 'second stream');
    assert.equal(srv.requests[1].headers['last-event-id'], '41');
    // the replayed 41 is confirmed again but not shown twice
    assert.deepEqual(seen, [41, 42]);
    await waitFor(() => api.calls.acks.flatMap((a) => a.seqs).includes(42));
  });

  it('starts without resume position for another server or token and emits reset', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO)]));
    const store = createMemoryStore({ notifications: { lastSeq: 900, seqScope: 'old-scope' } });
    const { client } = makeClient(srv.url, { store });
    let resets = 0;
    client.on('reset', () => resets++);
    client.start();
    await waitFor(() => client.status().state === 'connected');
    assert.equal(srv.requests[0].headers['last-event-id'], undefined);
    assert.equal(resets, 1);
    assert.equal(store.get('notifications.lastSeq'), 0);
    assert.match(store.get('notifications.seqScope'), /^[0-9a-f]{16}$/);
    // same scope next time: resume position is used
    store.set('notifications.lastSeq', 77);
    client.restart();
    await waitFor(() => srv.requests.length === 2);
    assert.equal(srv.requests[1].headers['last-event-id'], '77');
    assert.equal(resets, 1);
    client.restart({ resetSeq: true });
    await waitFor(() => srv.requests.length === 3);
    assert.equal(srv.requests[2].headers['last-event-id'], undefined);
  });

  it('retries failed delivered acks after the next hello', async () => {
    const srv = await pushServer((req, res, n) => {
      if (n === 0) return sse(res, [ev('hello', HELLO), ev('notification', note(8), 8)]);
      return sse(res, [ev('hello', HELLO)]);
    });
    let fail = true;
    const api = fakeApi(srv.url, {});
    api.pushAck = async (b) => { api.calls.acks.push(b); if (fail) throw Object.assign(new Error('x'), { code: 'ECONNRESET' }); return { ok: true }; };
    const { client } = makeClient(srv.url, { api });
    client.start();
    await waitFor(() => api.calls.acks.length === 1);
    fail = false;
    client.networkChanged(); // reconnect → hello → retry
    await waitFor(() => api.calls.acks.length === 2, 3000, 'ack retry');
    assert.deepEqual(api.calls.acks[1].seqs, [8]);
  });

  it('stop() closes the stream and does not reconnect', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO)]));
    const { client } = makeClient(srv.url);
    client.start();
    await waitFor(() => client.status().state === 'connected');
    client.stop();
    await waitFor(() => srv.open.size === 0, 2000, 'server side close');
    await sleep(100);
    assert.equal(srv.requests.length, 1);
    assert.equal(client.status().state, 'stopped');
  });
});

describe('PushClient reconnect and errors', () => {
  it('backs off exponentially with jitter up to the ceiling', async () => {
    const srv = await pushServer((req, res) => json(res, 500, { ok: false, error: 'internal' }));
    const { client } = makeClient(srv.url);
    client.start();
    await waitFor(() => srv.requests.length >= 6, 4000, 'six attempts');
    client.stop();
    const gaps = srv.requests.slice(1, 6).map((r, i) => r.at - srv.requests[i].at);
    // random() = 1 → full base: 20, 40, 80, 160, 160 (ceiling)
    const expected = [20, 40, 80, 160, 160];
    gaps.forEach((g, i) => assert.ok(g >= expected[i] - 5 && g < expected[i] + 150, `gap ${i}: ${g} vs ${expected[i]}`));
  });

  it('jitter spreads the delay between half and full base', () => {
    const c = new PushClient({ apiClient: fakeApi('http://x'), store: createMemoryStore(), log, random: () => 0, timing: FAST });
    assert.deepEqual([c._nextDelay(), c._nextDelay(), c._nextDelay()], [10, 20, 40]);
    const d = new PushClient({ apiClient: fakeApi('http://x'), store: createMemoryStore(), log, random: () => 0.5, timing: { initialDelayMs: 1000, maxDelayMs: 300000 } });
    const seq = Array.from({ length: 12 }, () => d._nextDelay());
    assert.equal(seq[0], 750);
    assert.equal(seq[11], 225000); // 300000 ceiling × 0.75
  });

  it('reports the error state with retryAt and attempt', async () => {
    const srv = await pushServer((req, res) => json(res, 503, { ok: false, error: 'too_many_streams' }));
    const { client } = makeClient(srv.url, { timing: { initialDelayMs: 200 } });
    client.start();
    await waitFor(() => client.status().state === 'error');
    const st = client.status();
    assert.equal(st.reason, 'too_many_streams');
    assert.equal(st.attempt, 1);
    assert.ok(Date.parse(st.retryAt) > Date.now());
  });

  it('404 (old server) and 503 push_disabled → disabled, hourly retry', async () => {
    for (const [status, body, reason] of [[404, { error: 'not_found' }, 'unsupported'], [503, { ok: false, error: 'push_disabled' }, 'push_disabled']]) {
      const srv = await pushServer((req, res) => json(res, status, body));
      const { client } = makeClient(srv.url);
      client.start();
      await waitFor(() => client.status().state === 'disabled');
      assert.equal(client.status().reason, reason);
      await sleep(200);
      assert.equal(srv.requests.length, 1, 'no quick retry');
      await waitFor(() => srv.requests.length === 2, 1000, 'retry after disabledRetryMs');
      assert.ok(srv.requests[1].at - srv.requests[0].at >= 290);
      client.stop();
    }
  });

  it('403 direct_not_allowed waits for the tunnel; networkChanged() connects at once', async () => {
    let tunnel = false;
    const srv = await pushServer((req, res, n) => (n === 0 ? json(res, 403, { ok: false, error: 'direct_not_allowed' }) : sse(res, [ev('hello', { ...HELLO, via: 'tunnel' })])));
    const { client } = makeClient(srv.url, { extra: { isTunnelUp: () => tunnel }, timing: { disabledRetryMs: 60000 } });
    client.start();
    await waitFor(() => client.status().reason === 'direct_not_allowed');
    assert.equal(client.status().state, 'disabled');
    tunnel = true;
    client.networkChanged();
    await waitFor(() => client.status().state === 'connected');
    assert.equal(client.status().via, 'tunnel');
  });

  for (const [status, code] of [[401, 'unauthorized'], [403, 'token_required'], [403, 'scope_required'], [403, 'machine_mismatch']]) {
    it(`${status} ${code} stops until restart()`, async () => {
      let n0 = 0;
      const srv = await pushServer((req, res, n) => { n0 = n; return n === 0 ? json(res, status, { ok: false, error: code }) : sse(res, [ev('hello', HELLO)]); });
      const { client } = makeClient(srv.url);
      client.start();
      await waitFor(() => client.status().state === 'error');
      assert.equal(client.status().reason, 'auth');
      assert.equal(client.status().code, code);
      assert.equal(client.status().retryAt, null);
      client.networkChanged();
      await sleep(150);
      assert.equal(srv.requests.length, 1);
      client.restart();
      await waitFor(() => client.status().state === 'connected');
      assert.equal(n0, 1);
    });
  }

  it('429 waits at least the rate-limit window (or Retry-After when longer)', async () => {
    const srv = await pushServer((req, res, n) => (n === 0 ? json(res, 429, { ok: false, error: 'rate_limited' }, { 'Retry-After': '1' }) : sse(res, [ev('hello', HELLO)])));
    const { client } = makeClient(srv.url);
    client.start();
    await waitFor(() => client.status().reason === 'rate_limited');
    const wait = Date.parse(client.status().retryAt) - Date.now();
    assert.ok(wait > 800 && wait <= 1000, `retry in ${wait} ms`);
    client.networkChanged(); // does not shorten the wait
    await sleep(100);
    assert.equal(srv.requests.length, 1);
    await waitFor(() => client.status().state === 'connected', 2000);
    assert.ok(srv.requests[1].at - srv.requests[0].at >= 950);
  });

  it('429 without Retry-After uses the 15-min floor (rateLimitMs)', async () => {
    const srv = await pushServer((req, res) => json(res, 429, { ok: false, error: 'rate_limited' }));
    const { client } = makeClient(srv.url, { timing: { rateLimitMs: 15 * 60 * 1000 } });
    client.start();
    await waitFor(() => client.status().reason === 'rate_limited');
    const wait = Date.parse(client.status().retryAt) - Date.now();
    assert.ok(wait > 14.9 * 60 * 1000, `retry in ${wait} ms`);
  });

  it('a non event-stream 200 is an error with backoff', async () => {
    const srv = await pushServer((req, res) => json(res, 200, { ok: true }));
    const { client } = makeClient(srv.url);
    const reasons = [];
    client.on('status', (s) => reasons.push(`${s.state}:${s.reason}`));
    client.start();
    await waitFor(() => srv.requests.length >= 2);
    assert.ok(reasons.includes('error:bad_response'), reasons.join(','));
  });

  it('the keepalive watchdog reconnects a silent stream, pings keep it open', async () => {
    const srv = await pushServer((req, res, n) => {
      sse(res, [ev('hello', { ...HELLO, keepalive_s: 1 })]);
      if (n === 0) {
        const t = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* closed */ } }, 300);
        setTimeout(() => clearInterval(t), 2600); // then silence
        res.on('close', () => clearInterval(t));
      }
    });
    const { client } = makeClient(srv.url);
    client.start();
    await waitFor(() => client.status().state === 'connected');
    await sleep(2400);
    assert.equal(srv.requests.length, 1, 'pings keep the stream');
    await waitFor(() => srv.requests.length === 2, 3000, 'watchdog reconnect');
    // last ping at ~2.4 s, watchdog = 2 × keepalive_s = 2 s after it
    assert.ok(srv.requests[1].at - srv.requests[0].at >= 2400 + 1900);
  });

  it('a connect timeout counts as error', async () => {
    const srv = await pushServer(() => { /* never answers */ });
    const { client } = makeClient(srv.url, { timing: { connectTimeoutMs: 100 } });
    client.start();
    await waitFor(() => client.status().reason === 'timeout');
  });

  it('network errors back off', async () => {
    const srv = await pushServer(() => {});
    await srv.close();
    const { client } = makeClient(srv.url);
    client.start();
    await waitFor(() => client.status().reason === 'network');
    assert.equal(client.status().state, 'error');
  });
});

describe('PushClient settings', () => {
  it('does not connect when switched off or not configured; refuses http without allowHttp', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO)]));
    const off = makeClient(srv.url, { store: createMemoryStore({ notifications: { enabled: false } }) }).client;
    off.start();
    assert.deepEqual([off.status().state, off.status().reason], ['disabled', 'off']);
    const none = makeClient(srv.url, { api: { ...fakeApi(srv.url), serverUrl: '' } }).client;
    none.start();
    assert.equal(none.status().reason, 'not_configured');
    const strict = new PushClient({ apiClient: fakeApi(srv.url), store: createMemoryStore(), log, timing: FAST });
    strict.start();
    assert.equal(strict.status().reason, 'insecure_url');
    strict.stop();
    await sleep(50);
    assert.equal(srv.requests.length, 0);
  });

  it('mode vpn_only (direct=false) connects only while the tunnel is up', async () => {
    let tunnel = false;
    const srv = await pushServer((req, res) => sse(res, [ev('hello', { ...HELLO, via: 'tunnel' })]));
    const store = createMemoryStore({ notifications: { direct: false } });
    const { client, api } = makeClient(srv.url, { store, extra: { isTunnelUp: () => tunnel } });
    client.start();
    assert.equal(client.status().reason, 'vpn_only');
    tunnel = true;
    client.networkChanged();
    await waitFor(() => client.status().state === 'connected');
    await waitFor(() => api.calls.prefs.length === 1);
    assert.equal(api.calls.prefs[0].mode, 'vpn_only');
    tunnel = false;
    client.networkChanged();
    await waitFor(() => client.status().reason === 'vpn_only');
    await waitFor(() => srv.open.size === 0);
  });

  it('applySettings(): off tells the server and disconnects, on reconnects', async () => {
    const srv = await pushServer((req, res) => sse(res, [ev('hello', HELLO)]));
    const { client, store, api } = makeClient(srv.url);
    client.start();
    await waitFor(() => client.status().state === 'connected');
    store.set('notifications.enabled', false);
    client.applySettings();
    assert.equal(client.status().reason, 'off');
    await waitFor(() => api.calls.prefs.some((p) => p.enabled === false));
    store.set('notifications.enabled', true);
    store.set('notifications.mutedTopics', ['system', 'not a topic']);
    client.applySettings();
    await waitFor(() => client.status().state === 'connected' && srv.requests.length === 2);
    await waitFor(() => api.calls.prefs.some((p) => p.enabled === true && p.muted_topics.length === 1));
  });
});

describe('PushClient REST helpers', () => {
  it('ack() validates, chunks by 200 and maps errors', async () => {
    const api = fakeApi('http://x');
    const c = new PushClient({ apiClient: api, store: createMemoryStore(), log, timing: FAST });
    assert.deepEqual(await c.ack([], 'read'), { ok: true, count: 0 });
    assert.deepEqual(await c.ack([1], 'opened'), { ok: false, error: 'invalid_state' });
    assert.deepEqual(await c.ack([1], 'read', 'bad action!'), { ok: false, error: 'invalid_action' });
    const seqs = Array.from({ length: 450 }, (_, i) => i + 1);
    assert.deepEqual(await c.ack([...seqs, 3, -1, 'x'], 'read', 'details'), { ok: true, count: 450 });
    assert.deepEqual(api.calls.acks.map((a) => a.seqs.length), [200, 200, 50]);
    assert.equal(api.calls.acks[0].action, 'details');
    api.pushAck = async () => { throw Object.assign(new Error('Request failed'), { response: { status: 400, data: { ok: false, error: 'invalid_seqs' } } }); };
    assert.deepEqual(await c.ack([1], 'read'), { ok: false, error: 'invalid_seqs' });
  });

  it('fetchInbox / setPrefs / requestTest normalise answers', async () => {
    const api = fakeApi('http://x', { pushInbox: async (o) => ({ ok: true, items: [{ seq: 1 }], unread: 1, o }) });
    const c = new PushClient({ apiClient: api, store: createMemoryStore(), log, timing: FAST });
    assert.deepEqual(await c.fetchInbox({ limit: 50 }), { ok: true, items: [{ seq: 1 }], unread: 1 });
    assert.deepEqual(await c.setPrefs({ direct: false, mutedTopics: ['devices', 'plugin:skoda:charging', '../x'] }), { ok: true });
    assert.deepEqual(api.calls.prefs[0], { mode: 'vpn_only', muted_topics: ['devices', 'plugin:skoda:charging'] });
    assert.deepEqual(await c.setPrefs({ muted_topics: 'devices' }), { ok: false, error: 'invalid_topics' });
    assert.deepEqual(await c.requestTest(), { ok: true, seq: 130 });
    api.pushTest = async () => { throw Object.assign(new Error('x'), { response: { status: 429, data: { ok: false, error: 'rate_limited' } } }); };
    assert.deepEqual(await c.requestTest(), { ok: false, error: 'rate_limited' });
    api.pushInbox = async () => { throw Object.assign(new Error('x'), { response: { status: 503, data: {} } }); };
    assert.deepEqual(await c.fetchInbox(), { ok: false, error: 'http_503' });
  });

  it('ApiClient sends the push REST calls to the contract paths with its headers', async () => {
    const seen = [];
    const srv = await pushServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null, headers: req.headers });
        if (req.url.startsWith('/api/v1/client/push/inbox')) return json(res, 200, { ok: true, items: [], unread: 0 });
        if (req.url === '/api/v1/client/push/test') return json(res, 200, { ok: true, seq: 130 });
        return json(res, 200, { ok: true });
      });
    });
    const api = new ApiClient(srv.url, 'gc_live', log, 4, { clientVersion: '2.0.0', clientType: 'community' });
    const c = new PushClient({ apiClient: api, store: createMemoryStore(), log, timing: FAST });
    assert.equal((await c.ack([3, 4], 'read', 'mute_1h')).ok, true);
    assert.equal((await c.fetchInbox({ limit: 20, before: 99 })).ok, true);
    assert.equal((await c.setPrefs({ enabled: true, mode: 'always', muted_topics: [] })).ok, true);
    assert.deepEqual(await c.requestTest(), { ok: true, seq: 130 });
    assert.deepEqual(seen.map((s) => `${s.method} ${s.url}`), [
      'POST /api/v1/client/push/ack',
      'GET /api/v1/client/push/inbox?limit=20&before=99',
      'PUT /api/v1/client/push/prefs',
      'POST /api/v1/client/push/test',
    ]);
    assert.deepEqual(seen[0].body, { seqs: [3, 4], state: 'read', action: 'mute_1h' });
    assert.deepEqual(seen[2].body, { enabled: true, mode: 'always', muted_topics: [] });
    for (const s of seen) {
      assert.equal(s.headers['x-api-token'], 'gc_live');
      assert.equal(s.headers['x-client-type'], 'community');
    }
    // buildHeaders() is what the stream sends as well
    const h = api.buildHeaders();
    assert.deepEqual(Object.keys(h).sort(), ['X-API-Token', 'X-Client-Platform', 'X-Client-Type', 'X-Client-Version', 'X-Machine-Fingerprint']);
  });
});

describe('PushClient kill-switch awareness', () => {
  const WG = (endpoint) => `[Interface]\nAddress = 10.8.0.5/32\n[Peer]\nEndpoint = ${endpoint}\n`;
  const lookup = (map) => async (host) => (map[host] || []).map((address) => ({ address, family: 4 }));

  it('flags tunnel-only push when the kill switch is on and the hosts differ', async () => {
    const c = new PushClient({
      apiClient: fakeApi('https://gc.example.com'), store: createMemoryStore(), log, timing: FAST,
      isKillSwitchActive: () => true, getWgConfig: async () => WG('vpn.example.com:51820'),
      lookup: lookup({ 'gc.example.com': ['203.0.113.10'], 'vpn.example.com': ['198.51.100.7'] }),
    });
    await c.refreshPath();
    const ks = c.status().killSwitch;
    assert.equal(ks.active, true);
    assert.equal(ks.tunnelOnly, true);
    assert.equal(ks.path.coveredByKillSwitch, false);
  });

  it('is fine when the server URL resolves to the endpoint IP on 443, or the kill switch is off', async () => {
    let active = true;
    const c = new PushClient({
      apiClient: fakeApi('https://gc.example.com'), store: createMemoryStore(), log, timing: FAST,
      isKillSwitchActive: () => active, getWgConfig: () => WG('203.0.113.10:51820'),
      lookup: lookup({ 'gc.example.com': ['203.0.113.10'] }),
    });
    await c.refreshPath();
    assert.equal(c.status().killSwitch.tunnelOnly, false);
    assert.equal(c.status().killSwitch.path.coveredByKillSwitch, true);
    const d = new PushClient({
      apiClient: fakeApi('https://gc.example.com:8443'), store: createMemoryStore(), log, timing: FAST,
      isKillSwitchActive: () => active, getWgConfig: () => WG('gc.example.com:51820'),
      lookup: lookup({ 'gc.example.com': ['203.0.113.10'] }),
    });
    await d.refreshPath();
    assert.equal(d.status().killSwitch.tunnelOnly, true, 'port 8443 is not covered');
    active = false;
    assert.equal(d.status().killSwitch.tunnelOnly, false);
  });
});
