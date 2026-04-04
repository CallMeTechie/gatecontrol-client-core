/**
 * GateControl – Connection Monitor (Core)
 *
 * Überwacht die WireGuard-Verbindung:
 * - Regelmäßige Handshake-Prüfung
 * - Erkennung von Verbindungsabbrüchen
 * - Traffic-Statistiken sammeln
 * - Automatischer Reconnect-Trigger
 */

class ConnectionMonitor {
  constructor({ interval, onDisconnect, onStats, wgService, log }) {
    this.interval = interval || 30000;
    this.onDisconnect = onDisconnect;
    this.onStats = onStats;
    this.wgService = wgService;
    this.log = log;

    this.timer = null;
    this.running = false;
    this.failCount = 0;
    this.maxFailures = 3;
    this.lastHandshake = null;
    this.handshakeTimeout = 180; // Sekunden
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

    } catch (err) {
      this._handleFailure(`Check error: ${err.message}`);
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
