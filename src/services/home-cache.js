'use strict';

/**
 * GateControl – Laden aus dem Zwischenspeicher im Heimnetz (Gateways Phase 3b).
 *
 * fetchLan(lan, file, opts) lädt `lan.url` (utils/home-cache.js normalizeLan)
 * vom HTTPS-Endpunkt des Heim-Gateways in `file`:
 *
 *   - Zertifikats-Pinning: Das Gateway hat ein selbstsigniertes Zertifikat
 *     ohne Namen; vertraut wird genau dem Zertifikat, dessen SHA-256 (über das
 *     DER) `lan.tlsSha256` ist. Der Pin ersetzt die Prüfung von Aussteller und
 *     Namen, ist aber Pflicht: PinnedAgent gibt den Socket erst an die Anfrage
 *     weiter, wenn der Fingerabdruck stimmt – vorher wird kein Byte der
 *     Anfrage (Pfad samt Signatur) gesendet. Keine Keep-Alive-Sockets, keine
 *     TLS-Sitzungswiederaufnahme (sonst fehlte das Zertifikat zum Vergleich).
 *     Kein Proxy: das Gateway ist im LAN.
 *   - Größe: höchstens `maxBytes` bzw. genau `size`, wenn bekannt.
 *   - Inhalt: SHA-256 der Bytes muss `lan.sha256` sein.
 *   - Kurze Fristen (Verbindung 4 s, ohne Daten 30 s): ist das Gateway nicht
 *     erreichbar (Gastnetz, VPN ohne LAN-Zugriff), geht es schnell weiter.
 *
 * Bei jedem Fehler wird `file` gelöscht und ein HomeCacheError geworfen; die
 * Aufrufer (DriveApi.downloadTo, Updater) laden dann still vom Server.
 */

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const HC = require('../utils/home-cache');

const CONNECT_TIMEOUT_MS = 4000;
const IDLE_TIMEOUT_MS = 30000;

class HomeCacheError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'HomeCacheError';
    this.code = code;
  }
}

/**
 * https.Agent, der nur das Zertifikat mit dem SHA-256 `pin` akzeptiert. Die
 * übliche Kettenprüfung entfällt (selbstsigniert, ohne Namen) – der Vergleich
 * des Fingerabdrucks ersetzt sie und ist an jede Verbindung dieses Agenten
 * gebunden: createConnection gibt nichts zurück und ruft `cb` erst nach dem
 * Vergleich; bei Abweichung wird der Socket zerstört und die Anfrage bekommt
 * nie einen Socket.
 */
class PinnedAgent extends https.Agent {
  constructor({ pin, connectTimeoutMs = CONNECT_TIMEOUT_MS }) {
    const fingerprint = HC.normalizeFingerprint(pin);
    if (!fingerprint) throw new HomeCacheError('invalid pin', 'tls_pin');
    super({ keepAlive: false, maxCachedSessions: 0, rejectUnauthorized: false });
    this.pin = fingerprint;
    this.connectTimeoutMs = connectTimeoutMs;
  }

  createConnection(options, cb) {
    const socket = super.createConnection(options);
    if (typeof cb !== 'function') {
      // Kein Weg, den http.Agent nimmt – trotzdem nie ohne Pin.
      socket.once('secureConnect', () => {
        const err = this.verify(socket);
        if (err) socket.destroy(err);
      });
      return socket;
    }
    let settled = false;
    const timer = setTimeout(() => settle(new HomeCacheError('TLS handshake timed out', 'timeout')), this.connectTimeoutMs);
    const settle = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        socket.destroy();
        cb(err);
      } else {
        cb(null, socket);
      }
    };
    socket.once('secureConnect', () => settle(this.verify(socket)));
    socket.once('error', settle);
    return undefined;
  }

  /** null, wenn das Zertifikat des Gateways den Pin hat, sonst ein Fehler. */
  verify(socket) {
    let cert = null;
    try { cert = socket.getPeerCertificate(); } catch { cert = null; }
    const raw = cert && Buffer.isBuffer(cert.raw) && cert.raw.length ? cert.raw : null;
    const seen = raw ? crypto.createHash('sha256').update(raw).digest('hex') : null;
    if (seen && crypto.timingSafeEqual(Buffer.from(seen), Buffer.from(this.pin))) return null;
    return new HomeCacheError('certificate does not match the pin', 'tls_pin');
  }
}

function toError(err) {
  if (err instanceof HomeCacheError) return err;
  const c = err && err.code;
  if (c === 'ETIMEDOUT' || c === 'ESOCKETTIMEDOUT') return new HomeCacheError(err.message, 'timeout');
  return new HomeCacheError((err && err.message) || 'network error', 'network');
}

function request(lan, { agent, idleTimeoutMs }) {
  return new Promise((resolve, reject) => {
    const req = https.request(lan.url, { method: 'GET', agent, headers: { Accept: 'application/octet-stream' } });
    req.setTimeout(idleTimeoutMs, () => req.destroy(new HomeCacheError('no answer', 'timeout')));
    req.once('error', (err) => reject(toError(err)));
    req.once('response', resolve);
    req.end();
  });
}

/**
 * `lan` (normalizeLan) → `file`. → { bytes, sha256 }; wirft HomeCacheError
 * (tls_pin, http_<status>, too_large, size_mismatch, sha256_mismatch,
 * timeout, network) und löscht `file` dann.
 * @param {object} lan
 * @param {string} file
 * @param {object} [opts]
 * @param {number} [opts.size] - erwartete Größe (bekannt aus Manifest / Drive)
 * @param {number} [opts.maxBytes]
 * @param {(got: number, total: number|null) => void} [opts.onProgress]
 * @param {() => import('stream').Transform|null} [opts.throttle] - Download-Grenze (Drive „Ordner sichern“)
 */
async function fetchLan(lan, file, { size = null, maxBytes = Number.MAX_SAFE_INTEGER, onProgress = null, throttle = null, connectTimeoutMs = CONNECT_TIMEOUT_MS, idleTimeoutMs = IDLE_TIMEOUT_MS } = {}) {
  if (!lan || typeof lan.url !== 'string' || !/^[0-9a-f]{64}$/.test(lan.sha256 || '')) throw new HomeCacheError('no lan hint', 'invalid');
  const limit = Number.isSafeInteger(size) && size >= 0 ? Math.min(size, maxBytes) : maxBytes;
  const agent = new PinnedAgent({ pin: lan.tlsSha256, connectTimeoutMs });
  let res = null;
  try {
    res = await request(lan, { agent, idleTimeoutMs });
    if (res.statusCode !== 200) throw new HomeCacheError(`gateway answered ${res.statusCode}`, `http_${res.statusCode}`);
    const len = res.headers['content-length'] !== undefined ? Number(res.headers['content-length']) : null;
    const total = Number.isSafeInteger(len) && len >= 0 ? len : null;
    if (total !== null && total > limit) throw new HomeCacheError('too large', 'too_large');
    if (total !== null && Number.isSafeInteger(size) && total !== size) throw new HomeCacheError('wrong size', 'size_mismatch');
    const hash = crypto.createHash('sha256');
    let got = 0;
    const tap = new Transform({
      transform(chunk, _enc, done) {
        got += chunk.length;
        if (got > limit) { done(new HomeCacheError('too large', 'too_large')); return; }
        hash.update(chunk);
        if (typeof onProgress === 'function') {
          try { onProgress(got, total); } catch { /* Anzeige */ }
        }
        done(null, chunk);
      },
    });
    const out = fs.createWriteStream(file);
    const slow = typeof throttle === 'function' ? throttle() : null;
    await (slow ? pipeline(res, slow, tap, out) : pipeline(res, tap, out));
    if (Number.isSafeInteger(size) && got !== size) throw new HomeCacheError('wrong size', 'size_mismatch');
    const sha256 = hash.digest('hex');
    if (sha256 !== lan.sha256) throw new HomeCacheError('content does not match', 'sha256_mismatch');
    return { bytes: got, sha256 };
  } catch (err) {
    if (res && !res.destroyed) res.destroy();
    await fs.promises.rm(file, { force: true }).catch(() => {});
    throw toError(err);
  } finally {
    agent.destroy();
  }
}

module.exports = { fetchLan, PinnedAgent, HomeCacheError, CONNECT_TIMEOUT_MS, IDLE_TIMEOUT_MS };
