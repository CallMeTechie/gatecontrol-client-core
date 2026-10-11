/**
 * GateControl – Connection Monitor (Core)
 *
 * Überwacht die WireGuard-Verbindung:
 * - Regelmäßige Handshake-Prüfung
 * - Erkennung von Verbindungsabbrüchen
 * - Traffic-Statistiken sammeln
 * - Automatischer Reconnect-Trigger
 *
 * The peer status (GET peer-info: peer disabled, support bundle requested)
 * is asked every `_peerCheckEveryN`-th cycle. While the push stream delivers
 * these changes (services/push-control.js), setPeerCheckInterval(15 min)
 * stretches that to a time-based check; the WireGuard stats check stays at
 * `interval`. peerDisabled() / supportBundleRequest() are the handlers both
 * paths use.
 */

class ConnectionMonitor {
  constructor({ interval, onDisconnect, onPeerDisabled, onStats, onSupportBundleRequest, wgService, apiClient, log }) {
    this.interval = interval || 30000;
    this.onDisconnect = onDisconnect;
    this.onPeerDisabled = onPeerDisabled;
    this.onStats = onStats;
    // (request) => void — the server reported an admin request for a
    // support bundle (ApiClient.supportBundleRequest, see src/support/).
    this.onSupportBundleRequest = onSupportBundleRequest;
    this.wgService = wgService;
    this.apiClient = apiClient || null;
    this.log = log;

    this.timer = null;
    this.running = false;
    this.failCount = 0;
    this.maxFailures = 3;
    this.lastHandshake = null;
    this.handshakeTimeout = 180; // Sekunden
    this._peerCheckCounter = 0;
    this._peerCheckEveryN = 2; // Check peer status every Nth cycle
    this._peerCheckMinMs = null; // set while push delivers the peer state
    this._lastPeerCheck = 0;
  }

  /**
   * Time-based peer-info check (ms) instead of every Nth cycle, or null to
   * go back. Going back makes the next cycle check right away (events may
   * have been missed while the push stream was down).
   */
  setPeerCheckInterval(ms) {
    const next = Number.isFinite(ms) && ms > 0 ? ms : null;
    if (next === this._peerCheckMinMs) return;
    this._peerCheckMinMs = next;
    if (next) {
      this._lastPeerCheck = Date.now();
    } else {
      this._peerCheckCounter = this._peerCheckEveryN - 1;
    }
  }

  /** Effective peer-info cadence (for logs / tests). */
  peerCheckMode() {
    return this._peerCheckMinMs
      ? { mode: 'interval', ms: this._peerCheckMinMs }
      : { mode: 'cycles', every: this._peerCheckEveryN, ms: this._peerCheckEveryN * this.interval };
  }

  /**
   * The server disabled this peer (peer-info or push). Stops monitoring and
   * calls onPeerDisabled once — only while the tunnel is monitored.
   * @returns {boolean} true when the handler ran
   */
  peerDisabled(peerInfo = {}) {
    if (!this.running || !this.onPeerDisabled) return false;
    this.log.warn('Peer is disabled on server — triggering disconnect');
    this.stop();
    try {
      Promise.resolve(this.onPeerDisabled(peerInfo))
        .catch((err) => this.log.warn(`Peer disabled handling failed: ${err.message}`));
    } catch (err) {
      this.log.warn(`Peer disabled handling failed: ${err.message}`);
    }
    return true;
  }

  /**
   * Admin request for a support bundle (request timestamp, true, or null =
   * no request). Hands it to onSupportBundleRequest; never throws.
   */
  supportBundleRequest(request) {
    if (!this.onSupportBundleRequest) return;
    try {
      Promise.resolve(this.onSupportBundleRequest(request || null))
        .catch((err) => this.log.debug('Support bundle request handling failed:', err.message));
    } catch (err) {
      this.log.debug('Support bundle request handling failed:', err.message);
    }
  }

  /**
   * Monitoring starten
   */
  start() {
    if (this.running) return;

    this.running = true;
    this.failCount = 0;

    this.log.info(`Connection monitor started (interval: ${this.interval / 1000}s)`);

    // Sofort ersten Check
    this._check();

    this.timer = setInterval(() => this._check(), this.interval);
  }

  /**
   * Monitoring stoppen
   */
  stop() {
    this.running = false;

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    this.failCount = 0;
    this.log.info('Connection monitor stopped');
  }

  /**
   * Einzelner Verbindungscheck
   */
  async _check() {
    if (!this.running) return;

    try {
      const stats = await this.wgService.getStats();

      if (!stats) {
        this._handleFailure('No WireGuard statistics available');
        return;
      }

      // Handshake-Alter prüfen
      if (stats.handshakeTimestamp) {
        const age = Math.floor(Date.now() / 1000) - stats.handshakeTimestamp;

        if (age > this.handshakeTimeout) {
          this._handleFailure(`Handshake too old: ${age}s`);
          return;
        }

        this.lastHandshake = stats.handshakeTimestamp;
      } else if (!stats.connected) {
        this._handleFailure('No active connection');
        return;
      }

      // Alles OK
      this.failCount = 0;

      if (this.onStats) {
        this.onStats({
          connected: stats.connected,
          endpoint: stats.endpoint,
          handshake: stats.handshake,
          handshakeTimestamp: stats.handshakeTimestamp,
          rxBytes: stats.rxBytes,
          txBytes: stats.txBytes,
        });
      }

      // Periodischer Peer-Status-Check via API
      await this._checkPeerStatus();

    } catch (err) {
      this._handleFailure(`Check error: ${err.message}`);
    }
  }

  /**
   * Peer-Status beim Server prüfen (alle N Zyklen).
   * Löst onPeerDisabled aus wenn Peer deaktiviert wurde.
   */
  async _checkPeerStatus() {
    if (!this.apiClient || (!this.onPeerDisabled && !this.onSupportBundleRequest)) return;

    if (this._peerCheckMinMs) {
      if (Date.now() - this._lastPeerCheck < this._peerCheckMinMs) return;
    } else {
      this._peerCheckCounter++;
      if (this._peerCheckCounter < this._peerCheckEveryN) return;
    }
    this._peerCheckCounter = 0;
    this._lastPeerCheck = Date.now();

    try {
      const peerInfo = await this.apiClient.getPeerInfo();
      this.supportBundleRequest(this.apiClient.supportBundleRequest || null);
      if (peerInfo && peerInfo.enabled === false) {
        this.peerDisabled(peerInfo);
        return;
      }
    } catch (err) {
      this.log.debug('Peer status check failed:', err.message);
    }
  }

  /**
   * Fehler behandeln
   */
  _handleFailure(reason) {
    this.failCount++;
    this.log.warn(`Connection check failed (${this.failCount}/${this.maxFailures}): ${reason}`);

    if (this.onStats) {
      this.onStats({ connected: false });
    }

    if (this.failCount >= this.maxFailures) {
      this.log.error('Max failures reached, triggering reconnect');
      this.stop();

      if (this.onDisconnect) {
        this.onDisconnect();
      }
    }
  }
}

module.exports = ConnectionMonitor;
