'use strict';

/**
 * GateControl – GateDrop LAN listener (Core service, contract C "Direktübertragung im WLAN")
 *
 * A plain Node http server on TCP 47731, bound to the private LAN addresses
 * of this PC only (one server per address: never 0.0.0.0, never the VPN
 * adapter). The installer opens the port for the private firewall profile.
 *
 *   POST /gatedrop/v1/transfer/<transferId>           push: a device sends us item X-GD-Item
 *        X-GD-Ticket, X-GD-Item, X-GD-Name (base64url UTF-8), X-GD-Size; body = sealed blocks
 *   GET  /gatedrop/v1/transfer/<transferId>/<index>   pull: a device fetches an item we offer
 *        X-GD-Ticket; answer = sealed blocks (+ X-GD-Name, X-GD-Size)
 *
 * Only transfers the plugin announced are accepted: incoming ones from the
 * silent push (expectIncoming) or — when a sender is faster than the push —
 * from GET transfers/<id> (resolveIncoming), outgoing ones from POST sends
 * (offerOutgoing). The ticket is compared in constant time, is valid for 10
 * minutes and ends with the transfer (each item once). Unknown transfer and
 * wrong ticket get the same 403.
 *
 * Limits: private IPv4 peers only, ≤ 2 GB per item, body length must match
 * the announced size, names with path parts are refused (400), at most 4
 * transfers at once, 10 s for the headers, 30 s without a byte → closed.
 *
 * Events: 'incoming-item' ({ transferId, index, name, path, bytes }),
 * 'incoming-done' ({ transferId, items }), 'incoming-failed' ({ transferId, error }),
 * 'outgoing-item' ({ transferId, index, bytes }), 'outgoing-done' ({ transferId }),
 * 'state' (status()).
 */

const EventEmitter = require('events');
const http = require('http');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const gd = require('../utils/gatedrop');
const { EncryptStream, DecryptStream } = require('../utils/gatedrop-crypto');

const ROUTE_RE = /^\/gatedrop\/v1\/transfer\/([A-Za-z0-9_-]{4,100})(?:\/(\d{1,3}))?\/?$/;

const DEFAULT_TIMING = {
  headersTimeoutMs: 10000,
  idleTimeoutMs: 30000,
  ticketTtlMs: gd.TICKET_TTL_MS,
  sweepMs: 30000,
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const digest = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest();
const sameTicket = (a, b) => typeof a === 'string' && typeof b === 'string' && crypto.timingSafeEqual(digest(a), digest(b));

class ListenerError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

class GateDropListener extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log]
   * @param {number} [opts.port=47731] - 0 picks a free port (tests)
   * @param {() => object} [opts.getInterfaces] - os.networkInterfaces
   * @param {string[]} [opts.bindAddresses] - fixed addresses instead of the LAN ones (tests)
   * @param {(ip: string) => boolean} [opts.isAllowedPeer] - default: private IPv4
   * @param {number} [opts.maxBytes] - per item (2 GB)
   * @param {number} [opts.maxActive=4]
   * @param {(transferId: string) => Promise<object|null>} [opts.resolveIncoming]
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   */
  constructor({
    log, port = gd.PORT, getInterfaces = () => os.networkInterfaces(), bindAddresses = null,
    isAllowedPeer = null, maxBytes = gd.MAX_FILE_BYTES, maxActive = 4, resolveIncoming = null,
    timing = {}, now = Date.now,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.port = port;
    this.getInterfaces = getInterfaces;
    this.bindAddresses = bindAddresses;
    this.isAllowedPeer = isAllowedPeer || ((ip) => gd.isPrivateIPv4(ip));
    this.maxBytes = maxBytes;
    this.maxActive = maxActive;
    this.resolveIncoming = resolveIncoming;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.now = now;

    this._servers = new Map();  // ip → { server, port, prefix }
    this._incoming = new Map(); // transferId → transfer
    this._outgoing = new Map();
    this._active = 0;
    this._sweep = null;
    this._started = false;
    this._refreshing = null;
  }

  // ── Lifecycle ────────────────────────────────────────────

  async start() {
    this._started = true;
    if (!this._sweep) {
      this._sweep = setInterval(() => this.sweep(), this.timing.sweepMs);
      if (this._sweep.unref) this._sweep.unref();
    }
    return this.refresh();
  }

  async stop() {
    this._started = false;
    clearInterval(this._sweep);
    this._sweep = null;
    const all = [...this._servers.values()];
    this._servers.clear();
    await Promise.all(all.map((s) => new Promise((r) => { try { s.server.close(() => r()); s.server.closeAllConnections?.(); } catch { r(); } })));
    for (const id of [...this._incoming.keys()]) this._failIncoming(id, 'stopped');
    this._outgoing.clear();
    this.emit('state', this.status());
  }

  /** The addresses to listen on now: [{ ip, prefix }]. */
  wantedAddresses() {
    if (Array.isArray(this.bindAddresses)) return this.bindAddresses.map((ip) => ({ ip, prefix: 24 }));
    try { return gd.lanAddresses(this.getInterfaces()); } catch { return []; }
  }

  /** Bind new LAN addresses, close vanished ones (network change). → status() */
  refresh() {
    if (this._refreshing) return this._refreshing;
    this._refreshing = this._refresh().finally(() => { this._refreshing = null; });
    return this._refreshing;
  }

  async _refresh() {
    if (!this._started) return this.status();
    const wanted = this.wantedAddresses();
    const ips = new Set(wanted.map((a) => a.ip));
    for (const [ip, s] of [...this._servers]) {
      if (ips.has(ip)) continue;
      this._servers.delete(ip);
      try { s.server.close(); s.server.closeAllConnections?.(); } catch { /* gone */ }
    }
    for (const a of wanted) {
      if (this._servers.has(a.ip)) { this._servers.get(a.ip).prefix = a.prefix; continue; }
      try {
        const s = await this._listen(a.ip);
        this._servers.set(a.ip, { ...s, prefix: a.prefix });
        this.log.info(`GateDrop listener on ${a.ip}:${s.port}`);
      } catch (err) {
        this.log.warn(`GateDrop listener on ${a.ip} failed: ${err.code || err.message}`);
      }
    }
    this.emit('state', this.status());
    return this.status();
  }

  _listen(ip) {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => this._onRequest(req, res));
      server.headersTimeout = this.timing.headersTimeoutMs;
      server.requestTimeout = 0;          // large files: the idle timeout below guards stalls
      server.keepAliveTimeout = 5000;
      server.maxHeadersCount = 30;
      server.on('connection', (sock) => {
        sock.setTimeout(this.timing.idleTimeoutMs, () => sock.destroy());
      });
      server.on('clientError', (_e, sock) => { try { sock.destroy(); } catch { /* gone */ } });
      server.once('error', reject);
      server.listen({ host: ip, port: this.port, exclusive: true }, () => {
        server.removeListener('error', reject);
        server.on('error', (err) => this.log.warn(`GateDrop listener ${ip}: ${err.message}`));
        resolve({ server, port: server.address().port });
      });
    });
  }

  /** { listening, port, addresses: [{ ip, prefix, port }] } */
  status() {
    const addresses = [...this._servers.entries()].map(([ip, s]) => ({ ip, prefix: s.prefix, port: s.port }));
    return { listening: addresses.length > 0, port: addresses.length ? addresses[0].port : this.port, addresses };
  }

  get listening() {
    return this._servers.size > 0;
  }

  // ── Transfers ────────────────────────────────────────────

  /**
   * Accept a push transfer to us.
   * @param {object} t
   * @param {string} t.transferId
   * @param {string} t.ticket
   * @param {Buffer} t.key
   * @param {Array<{ index, name, bytes }>} t.items - announced by the plugin (may be empty: then the headers count)
   * @param {(meta: { index, name, bytes }) => Promise<{ stream, commit(): Promise<string>, abort(): Promise<void> }>} t.sink
   * @param {number} [t.expiresAt]
   */
  expectIncoming({ transferId, ticket, key, items = [], sink, expiresAt = null }) {
    if (!gd.isTransferId(transferId) || !gd.isTicket(ticket) || !Buffer.isBuffer(key) || key.length !== 32 || typeof sink !== 'function') {
      throw new TypeError('expectIncoming: transferId, ticket, key and sink required');
    }
    if (this._incoming.has(transferId)) return this._incoming.get(transferId).done;
    let resolve;
    let reject;
    const done = new Promise((res, rej) => { resolve = res; reject = rej; });
    done.catch(() => {});
    const t = {
      transferId, ticket, key, sink, resolve, reject, done,
      items: new Map(items.map((it) => [it.index, it])),
      count: items.length || null,
      received: new Map(),   // index → { name, path, bytes }
      busy: new Set(),
      expiresAt: Math.min(expiresAt || Infinity, this.now() + this.timing.ticketTtlMs),
    };
    this._incoming.set(transferId, t);
    return done;
  }

  /** Offer items of ours to a device that pulls them. Promise resolves when every item was fetched. */
  offerOutgoing({ transferId, ticket, key, items }) {
    if (!gd.isTransferId(transferId) || !gd.isTicket(ticket) || !Buffer.isBuffer(key) || key.length !== 32 || !Array.isArray(items) || !items.length) {
      throw new TypeError('offerOutgoing: transferId, ticket, key and items required');
    }
    let resolve;
    let reject;
    const done = new Promise((res, rej) => { resolve = res; reject = rej; });
    done.catch(() => {});
    const t = {
      transferId, ticket, key, resolve, reject, done,
      items: items.map((it, i) => ({ index: i, path: it.path, name: it.name, size: it.size })),
      sent: new Set(),
      started: false,
      expiresAt: this.now() + this.timing.ticketTtlMs,
    };
    this._outgoing.set(transferId, t);
    return { done, started: () => t.started };
  }

  cancelOutgoing(transferId, reason = 'cancelled') {
    const t = this._outgoing.get(transferId);
    if (!t) return;
    this._outgoing.delete(transferId);
    t.reject(Object.assign(new Error(reason), { code: reason }));
  }

  cancelIncoming(transferId, reason = 'cancelled') {
    this._failIncoming(transferId, reason);
  }

  hasIncoming(transferId) { return this._incoming.has(transferId); }

  /** Drop expired transfers (tickets live 10 min). */
  sweep() {
    const now = this.now();
    for (const [id, t] of [...this._incoming]) if (t.expiresAt <= now && !t.busy.size) this._failIncoming(id, 'expired');
    for (const [id, t] of [...this._outgoing]) if (t.expiresAt <= now && !t.started) this.cancelOutgoing(id, 'expired');
  }

  _failIncoming(id, reason) {
    const t = this._incoming.get(id);
    if (!t) return;
    this._incoming.delete(id);
    const err = Object.assign(new Error(reason), { code: reason, received: [...t.received.values()] });
    t.reject(err);
    this.emit('incoming-failed', { transferId: id, error: reason });
  }

  // ── HTTP ─────────────────────────────────────────────────

  _reply(res, status, body) {
    if (res.headersSent) { res.destroy(); return; }
    const data = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': data.length, Connection: 'close' });
    res.end(data);
  }

  async _onRequest(req, res) {
    const peer = gd.plainIPv4(req.socket.remoteAddress);
    if (!this.isAllowedPeer(peer)) {
      this._reply(res, 403, { error: 'forbidden' });
      req.resume();
      return;
    }
    const m = ROUTE_RE.exec(String(req.url || '').split('?')[0]);
    if (!m) { req.resume(); this._reply(res, 404, { error: 'not_found' }); return; }
    if (this._active >= this.maxActive) { req.resume(); this._reply(res, 503, { error: 'busy' }); return; }
    this._active++;
    try {
      if (req.method === 'POST' && m[2] === undefined) await this._receive(req, res, m[1]);
      else if (req.method === 'GET' && m[2] !== undefined) await this._serve(req, res, m[1], Number(m[2]));
      else { req.resume(); this._reply(res, 405, { error: 'method_not_allowed' }); }
    } catch (err) {
      const status = err instanceof ListenerError ? err.status : 500;
      if (!(err instanceof ListenerError)) this.log.warn(`GateDrop listener: ${err.code || err.message}`);
      req.resume();
      this._reply(res, status, { error: err.code || 'failed' });
    } finally {
      this._active--;
    }
  }

  async _incomingFor(transferId, ticket) {
    let t = this._incoming.get(transferId);
    if (!t && this.resolveIncoming && gd.isTicket(ticket)) {
      // The sender came before the silent push: ask the plugin (authenticated).
      try { await this.resolveIncoming(transferId); } catch (err) { this.log.debug(`GateDrop transfer lookup failed: ${err.message}`); }
      t = this._incoming.get(transferId);
    }
    if (!t || t.expiresAt <= this.now() || !sameTicket(ticket, t.ticket)) throw new ListenerError(403, 'forbidden');
    return t;
  }

  async _receive(req, res, transferId) {
    const ticket = req.headers['x-gd-ticket'];
    const t = await this._incomingFor(transferId, ticket);

    const index = gd.nonNegInt(req.headers['x-gd-item']);
    if (index === null || index >= gd.MAX_ITEMS || (t.count !== null && index >= t.count)) throw new ListenerError(400, 'bad_item');
    if (t.received.has(index) || t.busy.has(index)) throw new ListenerError(409, 'duplicate_item');

    const rawName = gd.decodeName(req.headers['x-gd-name']);
    if (rawName === null || gd.isTraversalName(rawName)) throw new ListenerError(400, 'bad_name');
    const size = gd.nonNegInt(req.headers['x-gd-size']);
    if (size === null) throw new ListenerError(400, 'bad_size');
    if (size > this.maxBytes) throw new ListenerError(413, 'too_large');
    const announced = t.items.get(index);
    if (announced && announced.bytes !== null && announced.bytes !== undefined && announced.bytes !== size) throw new ListenerError(400, 'size_mismatch');
    const len = req.headers['content-length'] !== undefined ? gd.nonNegInt(req.headers['content-length']) : null;
    if (req.headers['content-length'] !== undefined && len !== gd.encryptedSize(size)) {
      throw new ListenerError(len !== null && len > gd.encryptedSize(this.maxBytes) ? 413 : 400, 'bad_length');
    }

    const name = gd.safeFileName((announced && announced.name) || rawName, `datei-${index + 1}`);
    t.busy.add(index);
    let target = null;
    try {
      target = await t.sink({ index, name, bytes: size });
      const dec = new DecryptStream({ key: t.key, transferId, expectedSize: size, maxBytes: this.maxBytes });
      await pipeline(req, dec, target.stream);
      const savedPath = await target.commit();
      t.received.set(index, { index, name, path: savedPath, bytes: size });
      this.emit('incoming-item', { transferId, index, name, path: savedPath, bytes: size });
    } catch (err) {
      if (target) { try { await target.abort(); } catch { /* best effort */ } }
      t.busy.delete(index);
      if (err instanceof ListenerError) throw err;
      throw new ListenerError(err && (err.code === 'auth' || err.code === 'size' || err.code === 'truncated') ? 400 : 500, err && err.code === 'auth' ? 'auth_failed' : 'receive_failed');
    }
    t.busy.delete(index);
    this._reply(res, 200, { ok: true, bytes: size });

    if (t.count !== null && t.received.size >= t.count && this._incoming.get(transferId) === t) {
      this._incoming.delete(transferId); // ticket used up
      const items = [...t.received.values()].sort((a, b) => a.index - b.index);
      t.resolve(items);
      this.emit('incoming-done', { transferId, items });
    }
  }

  /** The device announced how many items it sends with the push; without a count the service ends it. */
  finishIncoming(transferId) {
    const t = this._incoming.get(transferId);
    if (!t || t.busy.size) return null;
    this._incoming.delete(transferId);
    const items = [...t.received.values()].sort((a, b) => a.index - b.index);
    t.resolve(items);
    this.emit('incoming-done', { transferId, items });
    return items;
  }

  async _serve(req, res, transferId, index) {
    req.resume();
    const ticket = req.headers['x-gd-ticket'];
    const t = this._outgoing.get(transferId);
    if (!t || t.expiresAt <= this.now() || !sameTicket(ticket, t.ticket)) throw new ListenerError(403, 'forbidden');
    const item = t.items[index];
    if (!item) throw new ListenerError(404, 'bad_item');
    if (t.sent.has(index)) throw new ListenerError(409, 'duplicate_item');
    let stat;
    try { stat = await fs.promises.stat(item.path); } catch { throw new ListenerError(410, 'gone'); }
    if (!stat.isFile() || stat.size !== item.size) throw new ListenerError(410, 'changed');
    t.started = true;
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': gd.encryptedSize(item.size),
      'X-GD-Name': gd.encodeName(item.name),
      'X-GD-Size': String(item.size),
      'X-GD-Item': String(index),
      'Cache-Control': 'no-store',
    });
    try {
      await pipeline(fs.createReadStream(item.path), new EncryptStream({ key: t.key, transferId }), res);
    } catch (err) {
      this.log.warn(`GateDrop pull of item ${index} broke off: ${err.code || err.message}`);
      res.destroy();
      return;
    }
    t.sent.add(index);
    this.emit('outgoing-item', { transferId, index, bytes: item.size });
    if (t.sent.size >= t.items.length && this._outgoing.get(transferId) === t) {
      this._outgoing.delete(transferId);
      t.resolve({ bytes: t.items.reduce((s, it) => s + it.size, 0) });
      this.emit('outgoing-done', { transferId });
    }
  }
}

GateDropListener.DEFAULT_TIMING = DEFAULT_TIMING;
GateDropListener.ROUTE_RE = ROUTE_RE;

module.exports = GateDropListener;
