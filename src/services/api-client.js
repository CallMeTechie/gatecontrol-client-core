/**
 * GateControl – API Client (Core)
 *
 * Kommuniziert mit dem GateControl-Server:
 * - Config abrufen & aktualisieren
 * - Peer registrieren
 * - Heartbeat senden
 * - Status melden
 */

const axios = require('axios');
const os = require('os');
const zlib = require('zlib');
const { getMachineFingerprint } = require('../utils/machine-id');
const { isSafeExternalUrl } = require('../utils/external-url');

// The one-time portal login link must arrive quickly; otherwise the client
// opens the plain portal URL instead of keeping the user waiting.
const PORTAL_LINK_TIMEOUT_MS = 5000;

class ApiClient {
  /**
   * @param {string} serverUrl
   * @param {string} apiKey
   * @param {object} log - electron-log compatible logger
   * @param {string|null} peerId
   * @param {object} [options]
   * @param {string} [options.clientVersion] - Client version string (defaults to core package version)
   * @param {string} [options.clientPlatform] - Client platform (defaults to 'windows')
   * @param {'pro'|'community'} [options.clientType] - Edition; sent as
   *   X-Client-Type so the server knows the product of the reported version
   */
  constructor(serverUrl, apiKey, log, peerId = null, options = {}) {
    this.log = log;
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
    this.peerId = peerId;
    this.configHash = null;
    this.portalUrl = null;
    this.autoOpenPortal = false;
    this.client = null;
    this.clientVersion = options.clientVersion || require('../../package.json').version;
    this.clientPlatform = options.clientPlatform || 'windows';
    this.clientType = ['pro', 'community'].includes(options.clientType) ? options.clientType : null;
    // Client policy version seen in the last server answer (heartbeat /
    // permissions). onPolicyVersion(version) lets ClientPolicyService refresh.
    this.policyVersion = null;
    this.onPolicyVersion = null;
    // Admin asked for a support bundle (peer-info / heartbeat answer):
    // request timestamp, true for servers without a timestamp, or null.
    this.supportBundleRequest = null;
    this.portalLinkTimeoutMs = PORTAL_LINK_TIMEOUT_MS;

    if (serverUrl) {
      this._createClient();
    }
  }

  /**
   * Konfiguration aktualisieren
   */
  configure(url, apiKey, peerId = null) {
    this.serverUrl = url;
    this.apiKey = apiKey;
    if (peerId) this.peerId = peerId;
    this._createClient();
  }

  /**
   * Peer-ID setzen (nach Registrierung)
   */
  setPeerId(peerId) {
    this.peerId = peerId;
  }

  /**
   * Identification headers of every device request (token, version,
   * platform, edition, machine binding). Shared with the push stream
   * (services/push-client.js), which talks to the server without axios.
   * @returns {Object<string, string>}
   */
  buildHeaders() {
    return {
      'X-API-Token': this.apiKey,
      'X-Client-Version': this.clientVersion,
      'X-Client-Platform': this.clientPlatform,
      ...(this.clientType ? { 'X-Client-Type': this.clientType } : {}),
      'X-Machine-Fingerprint': getMachineFingerprint(),
    };
  }

  /**
   * Axios-Client erstellen
   */
  _createClient() {
    this.client = axios.create({
      baseURL: this.serverUrl.replace(/\/+$/, ''),
      timeout: 15000,
      headers: {
        'Content-Type': 'application/json',
        ...this.buildHeaders(),
      },
    });

    // Response Interceptor für Logging
    this.client.interceptors.response.use(
      (res) => res,
      (err) => {
        if (err.response) {
          this.log.warn(`API ${err.response.status}: ${err.config?.url}`);
        } else {
          this.log.warn(`API Error: ${err.message}`);
        }
        throw err;
      }
    );
  }

  /**
   * Server-Erreichbarkeit prüfen
   */
  async ping() {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.get('/api/v1/client/ping');
    return data;
  }

  /**
   * Client beim Server registrieren
   * Gibt Peer-ID und initiale Config zurück
   */
  async register() {
    if (!this.client) throw new Error('Server nicht konfiguriert');

    const hostname = os.hostname();
    const platform = `${os.platform()} ${os.release()}`;

    const { data } = await this.client.post('/api/v1/client/register', {
      hostname,
      platform,
      clientVersion: this.clientVersion,
      peerId: this.peerId || null,
    });

    this.peerId = data.peerId;
    this.configHash = data.hash || null;
    this.log.info(`Registered as peer: ${data.peerId}`);
    return data;
  }

  /**
   * WireGuard-Config vom Server abrufen
   */
  async fetchConfig() {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    if (!this.peerId) throw new Error('Nicht registriert (keine Peer-ID)');

    const { data } = await this.client.get('/api/v1/client/config', {
      params: { peerId: this.peerId },
    });

    if (data.config) {
      this.configHash = data.hash || null;
      return data.config;
    }

    return null;
  }

  /**
   * Prüft ob eine neue Config verfügbar ist
   * Gibt die Config nur zurück wenn sich der Hash geändert hat
   */
  async checkConfigUpdate() {
    if (!this.client || !this.peerId) return null;

    try {
      const params = { peerId: this.peerId };
      if (this.configHash) params.hash = this.configHash;
      const { data } = await this.client.get('/api/v1/client/config/check', { params });

      if (data.updated && data.config) {
        this.configHash = data.hash;
        this.log.info('New configuration available');
        return data.config;
      }

      return null;
    } catch (err) {
      if (err.response?.status === 304) return null;
      throw err;
    }
  }

  /**
   * Heartbeat an Server senden
   */
  async sendHeartbeat(stats) {
    if (!this.client || !this.peerId) return null;

    try {
      const { data } = await this.client.post('/api/v1/client/heartbeat', {
        peerId: this.peerId,
        connected: stats?.connected || false,
        rxBytes: stats?.rxBytes || 0,
        txBytes: stats?.txBytes || 0,
        uptime: stats?.uptime || 0,
        // Pre-sanitize so the server's strict RFC-1123 validator accepts
        // it on the opportunistic internal_dns capture path (heartbeat
        // handler). Raw os.hostname() on macOS / domain-joined Windows
        // often contains '.' or uppercase that would fail validation.
        hostname: ApiClient.sanitizeHostnameForDns(os.hostname()) || os.hostname(),
      });
      this._notePolicyVersion(data);
      this._rememberSupportRequest(data);
      return data || null;
    } catch (err) {
      this.log.debug('Heartbeat failed:', err.message);
      return null;
    }
  }

  /**
   * Setup-Code einlösen (öffentlicher Endpunkt, noch kein Token nötig).
   * Liefert { kind, token, peerId, peerName, config, hash, scopes } —
   * peerId/config sind null, wenn der Code an keinen Peer gebunden ist;
   * dann registriert sich der Client danach mit dem neuen Token.
   *
   * @param {string} serverUrl - https://host[:port]
   * @param {string} code - XXXX-XXXX-XXXX-XXXX
   * @param {object} [options] - { clientVersion, clientPlatform, timeout }
   */
  static async redeemSetupCode(serverUrl, code, options = {}) {
    const { data } = await axios.post(
      `${serverUrl.replace(/\/+$/, '')}/api/v1/client/enroll`,
      {
        code,
        hostname: os.hostname(),
        platform: `${os.platform()} ${os.release()}`,
        clientVersion: options.clientVersion || require('../../package.json').version,
      },
      {
        timeout: options.timeout || 15000,
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Platform': options.clientPlatform || 'windows',
          'X-Machine-Fingerprint': getMachineFingerprint(),
        },
      },
    );
    if (!data || data.ok !== true || !data.token) {
      const err = new Error((data && data.error) || 'enroll_failed');
      err.code = (data && data.error) || 'enroll_failed';
      throw err;
    }
    return data;
  }

  /**
   * Sanitize a raw OS hostname into a DNS-label-safe form matching the
   * server's strict validator (RFC-1123: a-z0-9 and hyphen, max 63,
   * no leading/trailing hyphen). Lowercases, strips any dotted suffix
   * (Mac's "Marc's-MBP.local" -> "marcs-mbp"), replaces invalid chars
   * with hyphens, collapses repeats, and truncates. Returns null if
   * nothing usable remains.
   */
  static sanitizeHostnameForDns(raw) {
    if (raw == null) return null;
    let s = String(raw).trim().toLowerCase();
    if (!s) return null;
    s = s.split('.')[0];
    s = s.replace(/[^a-z0-9-]/g, '-');
    s = s.replace(/-+/g, '-');
    s = s.replace(/^-+|-+$/g, '');
    if (s.length > 63) s = s.slice(0, 63).replace(/-+$/, '');
    return s || null;
  }

  /**
   * Report the OS hostname for internal DNS resolution.
   *
   * Server-side: rate-limited (3/min/token), license-gated
   * (internal_dns), respects sticky admin source. Best-effort — a
   * failure here never blocks connection flow.
   *
   * Returns { ok, assigned, changed } on success, or null on failure /
   * when the feature isn't licensed on the server (403). Caller may
   * stop re-reporting after a non-changed response to save bandwidth.
   */
  async reportHostname(hostname) {
    if (!this.client || !this.peerId) return null;
    if (typeof hostname !== 'string' || !hostname.trim()) return null;

    try {
      const { data } = await this.client.post('/api/v1/client/peer/hostname', {
        hostname: hostname.trim(),
      });
      return data || null;
    } catch (err) {
      const status = err.response?.status;
      if (status === 403 || status === 429 || status === 400) {
        // Feature-gated, rate-limited, or rejected — silent (debug only).
        this.log.debug('Hostname report not accepted:', status, err.response?.data?.error);
      } else {
        this.log.warn('Hostname report failed:', err.message);
      }
      return null;
    }
  }

  /**
   * Status-Update an Server melden
   */
  async reportStatus(status, details = {}) {
    if (!this.client || !this.peerId) return;

    try {
      await this.client.post('/api/v1/client/status', {
        peerId: this.peerId,
        status,
        ...details,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      this.log.debug('Status report failed:', err.message);
    }
  }

  /**
   * Erreichbare Dienste vom Server abrufen
   */
  async getServices() {
    if (!this.client) return [];

    try {
      const res = await this.client.get('/api/v1/client/services');
      return res.data?.services || [];
    } catch (err) {
      this.log.debug('Services query failed:', err.message);
      return [];
    }
  }

  /**
   * DNS-Check Endpunkt abfragen
   */
  async dnsCheck() {
    if (!this.client) return null;

    try {
      const res = await this.client.get('/api/v1/client/dns-check');
      return res.data;
    } catch (err) {
      this.log.debug('DNS check failed:', err.message);
      return null;
    }
  }

  /**
   * Berechtigungen des Tokens abfragen
   */
  async getPermissions() {
    if (!this.client) return null;

    try {
      const res = await this.client.get('/api/v1/client/permissions');
      this.portalUrl = res.data?.portalUrl || null;
      this.autoOpenPortal = res.data?.autoOpenPortal === true;
      this._notePolicyVersion(res.data);
      return res.data?.permissions || null;
    } catch (err) {
      this.log.debug('Permissions query failed:', err.message);
      return null;
    }
  }

  /**
   * Ask the server for a one-time portal login link
   * (POST /api/v1/client/portal-link → { ok, url: "<portal>/auto?t=<ticket>", expiresIn }).
   *
   * Returns the link only when it is an http(s) URL on the same origin as the
   * configured portal URL; otherwise (no portal URL, non-2xx, network error,
   * timeout after 5 s, missing/foreign url) null, and the caller opens the
   * plain portal URL. The link carries a secret ticket: it is never logged
   * or stored, and a fresh one is fetched for every open.
   *
   * @param {string|null} [portalUrl] - configured portal URL (default: this.portalUrl)
   * @returns {Promise<string|null>}
   */
  async getPortalLink(portalUrl = this.portalUrl) {
    if (!this.client || !portalUrl) return null;

    let expectedOrigin;
    try {
      expectedOrigin = new URL(portalUrl).origin;
    } catch {
      return null;
    }

    const timeout = this.portalLinkTimeoutMs;
    let data;
    try {
      const res = await this.client.post('/api/v1/client/portal-link', {}, {
        timeout,
        signal: AbortSignal.timeout(timeout),
      });
      data = res.data;
    } catch (err) {
      // Only status / error message — never the response body (ticket).
      this.log.debug('Portal link unavailable:', err.response?.status || err.code || err.message);
      return null;
    }

    const url = data && typeof data.url === 'string' ? data.url.trim() : '';
    if (!url || !isSafeExternalUrl(url)) {
      this.log.debug('Portal link unavailable: no valid url in answer');
      return null;
    }
    if (new URL(url).origin !== expectedOrigin) {
      this.log.warn('Portal link rejected: origin differs from the portal URL');
      return null;
    }
    return url;
  }

  /**
   * Remember a policyVersion from a server answer and tell the listener.
   */
  _notePolicyVersion(data) {
    const v = data && typeof data.policyVersion === 'string' ? data.policyVersion : null;
    if (!v) return;
    this.policyVersion = v;
    if (typeof this.onPolicyVersion === 'function') {
      try { this.onPolicyVersion(v); } catch (err) { this.log.debug('onPolicyVersion failed:', err.message); }
    }
  }

  /**
   * Effektive Client-Richtlinie abrufen (GET /api/v1/client/policy).
   * Mit der bekannten Version als If-None-Match: 304 → { notModified: true }.
   * Liefert { notModified: false, data } oder wirft bei Netzwerk-/HTTP-Fehlern
   * (der Aufrufer behält dann die zuletzt bekannte Richtlinie).
   *
   * @param {string|null} [knownVersion]
   */
  async getClientPolicy(knownVersion = null) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const headers = {};
    if (knownVersion) headers['If-None-Match'] = `"${knownVersion}"`;
    const res = await this.client.get('/api/v1/client/policy', {
      headers,
      validateStatus: (s) => (s >= 200 && s < 300) || s === 304,
    });
    if (res.status === 304) return { notModified: true, data: null };
    return { notModified: false, data: res.data };
  }

  // ── Push (notification center, see services/push-client.js) ─────────
  // All four throw the axios error on failure; PushClient maps it.

  /**
   * Confirm deliveries: POST /api/v1/client/push/ack → { ok }.
   * @param {{ seqs: number[], state: 'delivered'|'read'|'dismissed', action?: string }} body
   */
  async pushAck({ seqs, state, action } = {}) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const body = { seqs, state };
    if (action) body.action = action;
    const { data } = await this.client.post('/api/v1/client/push/ack', body);
    return data;
  }

  /**
   * Server inbox of this device: GET /api/v1/client/push/inbox → { ok, items, unread }.
   * @param {{ limit?: number, before?: number }} [opts]
   */
  async pushInbox({ limit, before } = {}) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const params = {};
    if (Number.isSafeInteger(limit) && limit > 0) params.limit = limit;
    if (Number.isSafeInteger(before) && before > 0) params.before = before;
    const { data } = await this.client.get('/api/v1/client/push/inbox', { params });
    return data;
  }

  /**
   * Device push preferences: PUT /api/v1/client/push/prefs → { ok }.
   * @param {{ enabled?: boolean, mode?: 'always'|'vpn_only', muted_topics?: string[] }} prefs
   */
  async pushPrefs(prefs = {}) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.put('/api/v1/client/push/prefs', prefs);
    return data;
  }

  /** Test message to this device: POST /api/v1/client/push/test → { ok, seq }. */
  async pushTest() {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.post('/api/v1/client/push/test', {});
    return data;
  }

  /**
   * Traffic-Verbrauch vom Server abrufen
   */
  async getTraffic() {
    if (!this.client || !this.peerId) return null;

    try {
      const res = await this.client.get('/api/v1/client/traffic', {
        params: { peerId: this.peerId },
      });
      return res.data?.traffic || null;
    } catch (err) {
      this.log.debug('Traffic query failed:', err.message);
      return null;
    }
  }

  /**
   * Peer-Info vom Server abrufen (inkl. Ablaufdatum)
   */
  async getPeerInfo() {
    if (!this.client || !this.peerId) return null;

    try {
      const res = await this.client.get('/api/v1/client/peer-info', {
        params: { peerId: this.peerId },
      });
      this._rememberSupportRequest(res.data);
      return res.data?.peer || null;
    } catch (err) {
      this.log.debug('Peer info failed:', err.message);
      return null;
    }
  }

  _rememberSupportRequest(data) {
    if (!data || typeof data !== 'object' || !('supportBundleRequested' in data)) return;
    this.supportBundleRequest = data.supportBundleRequested === true
      ? (typeof data.supportBundleRequestedAt === 'string' && data.supportBundleRequestedAt) || true
      : null;
  }

  /**
   * Upload a (redacted) support bundle, gzip-compressed.
   * POST /api/v1/client/support-bundle?peerId=… — see src/support/.
   * Throws the axios error on failure (caller maps status codes).
   * @param {object} bundle - result of collectSupportBundle()
   * @returns {Promise<{ ok: boolean, bundle: { id, created_at, size_bytes } }>}
   */
  async uploadSupportBundle(bundle) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    if (!this.peerId) throw new Error('Nicht registriert (keine Peer-ID)');
    const body = zlib.gzipSync(Buffer.from(JSON.stringify(bundle), 'utf8'));
    const { data } = await this.client.post('/api/v1/client/support-bundle', body, {
      params: { peerId: this.peerId },
      headers: { 'Content-Type': 'application/gzip' },
      timeout: 60000,
      maxBodyLength: 6 * 1024 * 1024,
      transformRequest: [(d) => d],
    });
    if (this.supportBundleRequest) this.supportBundleRequest = null;
    return data;
  }
}

module.exports = ApiClient;
