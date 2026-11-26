'use strict';

// A fake HTTP(S) server for the Medien tests, as OkHttp's MockWebServer in Android's tests: answers queued with
// enqueue(), every request recorded (method, path, query, headers, body, the client's address).

const http = require('node:http');
const https = require('node:https');

function createMediaServer({ tls = null, host = '127.0.0.1' } = {}) {
  const queue = [];
  const requests = [];
  const waiting = [];
  const handler = (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const r = {
        method: req.method, path: u.pathname, query: u.searchParams, url: req.url, headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'), remoteAddress: req.socket.remoteAddress,
      };
      requests.push(r);
      const w = waiting.shift();
      if (w) w(r);
      const next = queue.shift() || { status: 404, body: '' };
      if (typeof next === 'function') { next(req, res, r); return; }
      res.writeHead(next.status || 200, next.headers || {});
      res.end(next.body === undefined ? '' : next.body);
    });
  };
  const server = tls ? https.createServer({ key: tls.key, cert: tls.cert }, handler) : http.createServer(handler);
  const api = {
    server,
    requests,
    enqueue(a) { queue.push(a); return api; },
    json(body, status = 200, headers = {}) { return api.enqueue({ status, headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) }); },
    take() { return requests.length > api._taken ? requests[api._taken++] : null; },
    _taken: 0,
    async start() {
      await new Promise((r) => server.listen(0, host, r));
      api.port = server.address().port;
      api.base = `${tls ? 'https' : 'http'}://${host}:${api.port}`;
      // a name of the home network (one label) for what only takes those (utils/media-address)
      api.homeBase = `${tls ? 'https' : 'http'}://localhost:${api.port}`;
      return api;
    },
    close() { return new Promise((r) => { server.closeAllConnections && server.closeAllConnections(); server.close(() => r()); }); },
  };
  return api;
}

module.exports = { createMediaServer };
