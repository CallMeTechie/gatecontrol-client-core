'use strict';

/**
 * GateDrop direct transfer – the client side of protocol C:
 *
 *   pushTo(): we send to a listening device
 *     POST http://<candidate>/gatedrop/v1/transfer/<transferId>  (one request per item)
 *   pullFrom(): we fetch from a listening device
 *     GET  http://<candidate>/gatedrop/v1/transfer/<transferId>/<index>
 *
 * Candidates are tried in order; each gets 2 s to accept the connection
 * (then the next one, after the last the caller falls back to the server).
 * Once connected, 30 s without progress end the request. Only private IPv4
 * candidates are used (utils/gatedrop.parseCandidate).
 */

const http = require('http');
const fs = require('fs');
const { pipeline } = require('stream/promises');
const gd = require('../utils/gatedrop');
const { EncryptStream, DecryptStream } = require('../utils/gatedrop-crypto');

const IDLE_MS = 30000;

class DirectError extends Error {
  constructor(message, code, { connected = false, status = null } = {}) {
    super(message);
    this.code = code;
    this.connected = connected;
    this.status = status;
  }
}

/**
 * One HTTP request with a connect timeout. Resolves with the response once
 * headers arrived; `body` (a readable) is piped into the request.
 */
function request({ host, port, method, path, headers, body = null, connectTimeoutMs, idleMs = IDLE_MS, agentFactory = null }) {
  return new Promise((resolve, reject) => {
    let connected = false;
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; fn(v); } };
    const req = http.request({ host, port, method, path, headers, agent: agentFactory ? agentFactory() : false });
    const timer = setTimeout(() => {
      if (!connected) { req.destroy(new DirectError('connect timeout', 'connect_timeout')); }
    }, connectTimeoutMs);
    req.on('socket', (sock) => {
      const onConnect = () => {
        connected = true;
        clearTimeout(timer);
        sock.setTimeout(idleMs, () => req.destroy(new DirectError('stalled', 'timeout', { connected: true })));
      };
      if (sock.connecting === false && !sock.pending) onConnect();
      else sock.once('connect', onConnect);
    });
    req.on('response', (res) => { clearTimeout(timer); done(resolve, res); });
    req.on('error', (err) => {
      clearTimeout(timer);
      done(reject, err instanceof DirectError ? err : new DirectError(err.message, connected ? 'broken' : 'unreachable', { connected }));
    });
    if (body) {
      body.on('error', (err) => req.destroy(err));
      body.pipe(req);
    } else {
      req.end();
    }
  });
}

async function readSmall(res, max = 4096) {
  const parts = [];
  let n = 0;
  for await (const c of res) { n += c.length; if (n <= max) parts.push(c); }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { return null; }
}

/**
 * Send every item to the first candidate that accepts the connection.
 * @param {object} o
 * @param {string[]} o.candidates - 'ip:port'
 * @param {string} o.transferId
 * @param {string} o.ticket
 * @param {Buffer} o.key
 * @param {Array<{ path, name, size }>} o.files
 * @param {(sent: number, total: number) => void} [o.onProgress]
 * @returns {Promise<{ bytes: number, candidate: string }>}
 */
async function pushTo({ candidates, transferId, ticket, key, files, onProgress, connectTimeoutMs = gd.CONNECT_TIMEOUT_MS, idleMs = IDLE_MS, agentFactory = null, resolveCandidate = gd.parseCandidate }) {
  const total = files.reduce((s, f) => s + f.size, 0);
  let lastErr = new DirectError('no candidate', 'no_candidate');
  for (const c of candidates || []) {
    const addr = resolveCandidate(c);
    if (!addr) continue;
    let sent = 0;
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const src = fs.createReadStream(f.path);
        const enc = new EncryptStream({ key, transferId });
        src.on('error', (e) => enc.destroy(e));
        src.on('data', (chunk) => { sent += chunk.length; if (onProgress) { try { onProgress(sent, total); } catch { /* UI */ } } });
        const res = await request({
          host: addr.host, port: addr.port, method: 'POST', path: `/gatedrop/v1/transfer/${transferId}`,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(gd.encryptedSize(f.size)),
            'X-GD-Ticket': ticket,
            'X-GD-Item': String(i),
            'X-GD-Name': gd.encodeName(f.name),
            'X-GD-Size': String(f.size),
          },
          body: src.pipe(enc),
          connectTimeoutMs, idleMs, agentFactory,
        });
        const answer = await readSmall(res);
        if (res.statusCode !== 200) {
          throw new DirectError(`listener answered ${res.statusCode}`, (answer && answer.error) || `http_${res.statusCode}`, { connected: true, status: res.statusCode });
        }
      }
      return { bytes: total, candidate: c };
    } catch (err) {
      lastErr = err instanceof DirectError ? err : new DirectError(err.message, 'broken', { connected: true });
      // Connected and refused / broken off mid-way: another address of the
      // same device will not do better.
      if (lastErr.connected) break;
    }
  }
  throw lastErr;
}

/**
 * Fetch every item from the first candidate that answers.
 * @param {object} o
 * @param {Array<{ index, name, bytes }>} o.items
 * @param {(meta) => Promise<{ stream, commit(): Promise<string>, abort(): Promise<void> }>} o.sink
 * @returns {Promise<{ items: Array<{ index, name, path, bytes }>, bytes: number, candidate: string }>}
 */
async function pullFrom({ candidates, transferId, ticket, key, items, sink, maxBytes = gd.MAX_FILE_BYTES, onProgress, connectTimeoutMs = gd.CONNECT_TIMEOUT_MS, idleMs = IDLE_MS, agentFactory = null, resolveCandidate = gd.parseCandidate }) {
  const total = items.reduce((s, it) => s + (it.bytes || 0), 0);
  let lastErr = new DirectError('no candidate', 'no_candidate');
  for (const c of candidates || []) {
    const addr = resolveCandidate(c);
    if (!addr) continue;
    const saved = [];
    let got = 0;
    try {
      for (const it of items) {
        const res = await request({
          host: addr.host, port: addr.port, method: 'GET', path: `/gatedrop/v1/transfer/${transferId}/${it.index}`,
          headers: { 'X-GD-Ticket': ticket }, connectTimeoutMs, idleMs, agentFactory,
        });
        if (res.statusCode !== 200) {
          const answer = await readSmall(res);
          throw new DirectError(`listener answered ${res.statusCode}`, (answer && answer.error) || `http_${res.statusCode}`, { connected: true, status: res.statusCode });
        }
        const size = gd.nonNegInt(res.headers['x-gd-size']);
        const expected = it.bytes !== null && it.bytes !== undefined ? it.bytes : size;
        if (expected === null || expected > maxBytes || (size !== null && size !== expected)) {
          res.resume();
          throw new DirectError('size mismatch', 'bad_size', { connected: true });
        }
        const headerName = gd.decodeName(res.headers['x-gd-name']);
        const name = gd.safeFileName(it.name || (headerName && !gd.isTraversalName(headerName) ? headerName : null), `datei-${it.index + 1}`);
        const target = await sink({ index: it.index, name, bytes: expected });
        try {
          res.on('data', (chunk) => { got += chunk.length; if (onProgress) { try { onProgress(got, total); } catch { /* UI */ } } });
          await pipeline(res, new DecryptStream({ key, transferId, expectedSize: expected, maxBytes }), target.stream);
          saved.push({ index: it.index, name, path: await target.commit(), bytes: expected });
        } catch (err) {
          try { await target.abort(); } catch { /* best effort */ }
          throw new DirectError(err.message, err.code === 'auth' ? 'auth_failed' : err.code === 'size' ? 'cut_off' : 'broken', { connected: true });
        }
      }
      return { items: saved, bytes: saved.reduce((s, x) => s + x.bytes, 0), candidate: c };
    } catch (err) {
      lastErr = err instanceof DirectError ? err : new DirectError(err.message, 'broken', { connected: true });
      lastErr.saved = saved;
      if (lastErr.connected) break;
    }
  }
  throw lastErr;
}

module.exports = { pushTo, pullFrom, request, DirectError };
