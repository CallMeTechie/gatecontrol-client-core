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
const { getMachineFingerprint } = require('../utils/machine-id');

class ApiClient {
  /**
   * @param {string} serverUrl
   * @param {string} apiKey
   * @param {object} log - electron-log compatible logger
   * @param {string|null} peerId
   * @param {object} [options]
   * @param {string} [options.clientVersion] - Client version string (defaults to core package version)
   * @param {string} [options.clientPlatform] - Client platform (defaults to 'windows')
   */
  constructor(serverUrl, apiKey, log, peerId = null, options = {}) {
    this.log = log;
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
    this.peerId = peerId;
    this.configHash = null;
    this.client = null;
    this.clientVersion = options.clientVersion || require('../../package.json').version;
    this.clientPlatform = options.clientPlatform || 'windows';

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
   * Axios-Client erstellen
   */
  _createClient() {
    this.client = axios.create({
      baseURL: this.serverUrl.replace(/\/+$/, ''),
      timeout: 15000,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Token': this.apiKey,
        'X-Client-Version': this.clientVersion,
        'X-Client-Platform': this.clientPlatform,
        'X-Machine-Fingerprint': getMachineFingerprint(),
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
        hostname: os.hostname(),
      });
      return data || null;
    } catch (err) {
      this.log.debug('Heartbeat failed:', err.message);
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
      return res.data?.permissions || null;
    } catch (err) {
      this.log.debug('Permissions query failed:', err.message);
      return null;
    }
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
      return res.data?.peer || null;
    } catch (err) {
      this.log.debug('Peer info failed:', err.message);
      return null;
    }
  }
}

module.exports = ApiClient;
