'use strict';

/**
 * Medien (Stufe 4e): the connections of the main process to a media server or share — axios as Drive, with
 *
 *   - the LAN binding: at home each socket is bound to the LAN adapter's own address (`localAddress`, utils/media-lan.js)
 *     so it does not go through the VPN when the tunnel carries the home network too (spike, docs/media.md);
 *   - a pinned certificate: a NAS's self-signed certificate (Synology's WebDAV, a Jellyfin on HTTPS) confirmed once by
 *     the person ("einmal bestätigen") is trusted by its SHA-256 over the DER alone — as the home cache does
 *     (services/home-cache.js): the socket goes to the request only after the fingerprint matched, before a byte of the
 *     request (path, access) is sent. Without a pin the usual chain and name check of Node applies.
 *   - no proxy, no redirects (the access never goes to another host), nothing decompressed for streams.
 *
 * request(opts) → the axios answer (validateStatus: any status); failures are MediaNetError with code 'offline',
 * 'timeout', 'cert_untrusted' (a certificate Node does not trust: the page asks the person, certificate()),
 * 'cert_changed' (not the pinned one any more) or 'failed'.
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const tls = require('tls');
const axios = require('axios');
const { normalizeFingerprint } = require('../utils/home-cache');

const CONNECT_TIMEOUT_MS = 8000;
const UNTRUSTED_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_UNTRUSTED',
  'CERT_SIGNATURE_FAILURE', 'CERT_REJECTED',
]);
const OFFLINE_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'EPIPE', 'EADDRNOTAVAIL', 'ENETDOWN', 'EHOSTDOWN', 'ERR_SOCKET_CONNECTION_TIMEOUT']);

class MediaNetError extends Error {
  constructor(message, code, extra = {}) {
    super(message);
    this.name = 'MediaNetError';
    this.code = code;
    Object.assign(this, extra);
  }
}

function fingerprintOf(cert) {
  const raw = cert && Buffer.isBuffer(cert.raw) && cert.raw.length ? cert.raw : null;
  return raw ? crypto.createHash('sha256').update(raw).digest('hex') : null;
}

/**
 * https.Agent that trusts exactly the certificate with SHA-256 `pin` (chain and name are not checked — the pin
 * replaces them and is bound to every connection: the socket reaches the request only after the comparison).
 * Keep-alive is fine (a socket checked once stays that server's), TLS sessions are not resumed (the certificate
 * would be missing to compare).
 */
class PinnedMediaAgent extends https.Agent {
  constructor({ pin, localAddress = null, connectTimeoutMs = CONNECT_TIMEOUT_MS }) {
    const fp = normalizeFingerprint(pin);
    if (!fp) throw new MediaNetError('invalid pin', 'failed');
    super({ keepAlive: true, maxSockets: 8, maxCachedSessions: 0, rejectUnauthorized: false, ...(localAddress ? { localAddress } : {}) });
    this.pin = fp;
    this.connectTimeoutMs = connectTimeoutMs;
  }

  createConnection(options, cb) {
    const socket = super.createConnection(options);
    if (typeof cb !== 'function') {
      socket.once('secureConnect', () => {
        const err = this.verify(socket);
        if (err) socket.destroy(err);
      });
      return socket;
    }
    let settled = false;
    const settle = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) { socket.destroy(); cb(err); } else cb(null, socket);
    };
    const timer = setTimeout(() => settle(new MediaNetError('TLS handshake timed out', 'timeout')), this.connectTimeoutMs);
    socket.once('secureConnect', () => settle(this.verify(socket)));
    socket.once('error', settle);
    return undefined;
  }

  verify(socket) {
    let cert = null;
    try { cert = socket.getPeerCertificate(); } catch { cert = null; }
    const seen = fingerprintOf(cert);
    if (seen && crypto.timingSafeEqual(Buffer.from(seen), Buffer.from(this.pin))) return null;
    return new MediaNetError('certificate does not match the pin', 'cert_changed', { fingerprint: seen });
  }
}

function toError(err) {
  if (err instanceof MediaNetError) return err;
  const cause = err && err.cause instanceof MediaNetError ? err.cause : null;
  if (cause) return cause;
  const c = (err && err.code) || '';
  if (UNTRUSTED_CODES.has(c)) return new MediaNetError('certificate not trusted', 'cert_untrusted', { tlsCode: c });
  if (c === 'ECONNABORTED' || c === 'ETIMEDOUT' || c === 'ESOCKETTIMEDOUT') return new MediaNetError('timed out', 'timeout');
  if (c === 'ERR_CANCELED') return new MediaNetError('cancelled', 'cancelled');
  if (OFFLINE_CODES.has(c)) return new MediaNetError('not reachable', 'offline');
  return new MediaNetError((err && err.message) || 'network error', 'failed');
}

class MediaNet {
  /**
   * @param {object} [opts]
   * @param {object} [opts.log]
   * @param {Function} [opts.axios] - axios (tests)
   */
  constructor({ log = null, axios: ax = axios } = {}) {
    this.log = log || { debug() {}, info() {}, warn() {} };
    this.axios = ax;
    this._agents = new Map();
  }

  /** The agent of one way: protocol, LAN address (null: the system's way — away the tunnel), pin. */
  agent(protocol, localAddress = null, pin = null) {
    const key = `${protocol}|${localAddress || ''}|${pin || ''}`;
    let a = this._agents.get(key);
    if (!a) {
      const bind = localAddress ? { localAddress } : {};
      if (protocol === 'https:') a = pin ? new PinnedMediaAgent({ pin, localAddress }) : new https.Agent({ keepAlive: true, maxSockets: 8, ...bind });
      else a = new http.Agent({ keepAlive: true, maxSockets: 8, ...bind });
      this._agents.set(key, a);
    }
    return a;
  }

  /**
   * One request. opts: { method, url, headers, data, responseType ('json' | 'stream' | 'text' | 'arraybuffer'),
   * localAddress, pin, timeout, signal, maxBytes }. → the axios answer (any status).
   */
  async request({ method = 'GET', url, headers = {}, data, responseType = 'json', localAddress = null, pin = null, timeout = 15000, signal, maxBytes } = {}) {
    let u;
    try { u = new URL(url); } catch { throw new MediaNetError('bad url', 'failed'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new MediaNetError('bad url', 'failed');
    const agent = this.agent(u.protocol, localAddress, u.protocol === 'https:' ? pin : null);
    try {
      return await this.axios.request({
        method,
        url: u.toString(),
        headers: { 'Accept-Encoding': responseType === 'stream' ? 'identity' : 'gzip, deflate', ...headers },
        data,
        responseType,
        timeout,
        signal,
        proxy: false,
        maxRedirects: 0,
        decompress: responseType !== 'stream',
        validateStatus: () => true,
        httpAgent: u.protocol === 'http:' ? agent : undefined,
        httpsAgent: u.protocol === 'https:' ? agent : undefined,
        ...(Number.isSafeInteger(maxBytes) ? { maxContentLength: maxBytes, maxBodyLength: maxBytes } : {}),
        transitional: { silentJSONParsing: true, forcedJSONParsing: responseType === 'json' },
      });
    } catch (err) {
      throw toError(err);
    }
  }

  /**
   * The certificate a server shows (before anything is sent): { fingerprint, subject, issuer, validFrom, validTo,
   * selfSigned, trusted } — for "Zertifikat der NAS einmal bestätigen". Never throws but MediaNetError 'offline'.
   */
  certificate(url, { localAddress = null, timeoutMs = CONNECT_TIMEOUT_MS } = {}) {
    let u;
    try { u = new URL(url); } catch { return Promise.reject(new MediaNetError('bad url', 'failed')); }
    if (u.protocol !== 'https:') return Promise.reject(new MediaNetError('not https', 'failed'));
    return new Promise((resolve, reject) => {
      const host = u.hostname.replace(/^\[|\]$/g, '');
      const socket = tls.connect({
        host,
        port: Number(u.port) || 443,
        servername: /^[\d.]+$/.test(host) || host.includes(':') ? undefined : host,
        rejectUnauthorized: false,
        ...(localAddress ? { localAddress } : {}),
      });
      const timer = setTimeout(() => { socket.destroy(); reject(new MediaNetError('timed out', 'timeout')); }, timeoutMs);
      socket.once('secureConnect', () => {
        clearTimeout(timer);
        let cert = null;
        try { cert = socket.getPeerCertificate(); } catch { cert = null; }
        const authorized = socket.authorized === true;
        socket.end();
        if (!cert || !cert.raw) { reject(new MediaNetError('no certificate', 'failed')); return; }
        const name = (o) => (o && typeof o === 'object' ? String(o.CN || o.O || '').slice(0, 120) || null : null);
        resolve({
          fingerprint: fingerprintOf(cert),
          subject: name(cert.subject),
          issuer: name(cert.issuer),
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          selfSigned: !!cert.issuer && !!cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject),
          trusted: authorized,
        });
      });
      socket.once('error', (err) => { clearTimeout(timer); reject(toError(err)); });
    });
  }

  /** Can `host:port` be reached this way (bound to `localAddress`)? A TCP connect only, nothing sent. */
  reachable(host, port, { localAddress = null, timeoutMs = 1500 } = {}) {
    const net = require('net');
    return new Promise((resolve) => {
      const s = net.connect({ host, port, ...(localAddress ? { localAddress } : {}) });
      const done = (ok) => { clearTimeout(timer); s.destroy(); resolve(ok); };
      const timer = setTimeout(() => done(false), timeoutMs);
      s.once('connect', () => done(true));
      s.once('error', () => done(false));
    });
  }

  /** The way changed (home ↔ away, another LAN address): the kept sockets go. */
  reset() {
    for (const a of this._agents.values()) { try { a.destroy(); } catch { /* ignore */ } }
    this._agents.clear();
  }
}

MediaNet.MediaNetError = MediaNetError;
MediaNet.PinnedMediaAgent = PinnedMediaAgent;
MediaNet.toError = toError;
MediaNet.fingerprintOf = fingerprintOf;

module.exports = MediaNet;
