/**
 * GateControl – Auto-Update Service (Core)
 *
 * Prüft den GateControl-Server auf neue Versionen,
 * lädt Updates im Hintergrund herunter und bietet
 * Installation per Dialog an.
 */

const { app, shell } = require('electron');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CHECK_DELAY = 10000;       // 10s nach App-Start
const CHECK_INTERVAL = 21600000; // 6 Stunden

class Updater {
  constructor({ serverUrl, apiKey, log, clientType = 'community' }) {
    this.log = log;
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
    this.clientType = clientType;
    this.currentVersion = app.getVersion();
    this.downloadPath = null;
    this.latestRelease = null;
    this.checkTimer = null;
    this.onUpdateReady = null;
  }

  /**
   * Server-Konfiguration aktualisieren
   */
  configure(serverUrl, apiKey) {
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
  }

  /**
   * Auto-Update starten (Timer)
   */
  start(onUpdateReady) {
    this.onUpdateReady = onUpdateReady;

    setTimeout(() => this._check(), CHECK_DELAY);

    this.checkTimer = setInterval(() => this._check(), CHECK_INTERVAL);

    this.log.info('Auto-Update gestartet');
  }

  /**
   * Manueller Update-Check (öffentlich)
   */
  async check() {
    await this._check();
    return this.getUpdateInfo();
  }

  /**
   * Timer stoppen
   */
  stop() {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
  }

  /**
   * Update-Check durchführen
   */
  async _check() {
    if (!this.serverUrl || !this.apiKey) {
      this.log.debug('Update-Check übersprungen: Server oder API-Key nicht konfiguriert');
      return;
    }

    try {
      const url = `${this.serverUrl.replace(/\/+$/, '')}/api/v1/client/update/check`;
      this.log.info(`Update-Check: ${url} (aktuelle Version: ${this.currentVersion})`);

      const res = await axios.get(url, {
        params: { version: this.currentVersion, platform: 'windows', client: this.clientType },
        headers: {
          'X-API-Token': this.apiKey,
          'X-Client-Platform': 'windows',
          'X-Client-Type': this.clientType,
        },
        timeout: 15000,
      });

      this.log.info(`Update-Check Antwort: ${JSON.stringify(res.data)}`);

      if (!res.data?.ok || !res.data?.available) {
        this.log.info(`Kein Update verfügbar (aktuell: ${this.currentVersion})`);
        return;
      }

      const { version, downloadUrl, fileName, fileSize, releaseNotes } = res.data;
      this.log.info(`Update verfügbar: ${this.currentVersion} -> ${version}`);

      this.latestRelease = { version, downloadUrl, fileName, fileSize, releaseNotes };

      await this._download();
    } catch (err) {
      this.log.warn(`Update-Check fehlgeschlagen: ${err.message}`);
    }
  }

  /**
   * Installer herunterladen
   */
  async _download() {
    if (!this.latestRelease?.downloadUrl) {
      this.log.warn('Kein Download-URL vorhanden');
      return;
    }

    const { downloadUrl, fileName, version } = this.latestRelease;
    const tmpDir = path.join(os.tmpdir(), 'gatecontrol-update');

    try {
      fs.mkdirSync(tmpDir, { recursive: true });
    } catch {}

    const filePath = path.join(tmpDir, fileName || `GateControl-Setup-${version}.exe`);

    if (fs.existsSync(filePath)) {
      this.log.info(`Update bereits heruntergeladen: ${filePath}`);
      this.downloadPath = filePath;
      this._notifyReady();
      return;
    }

    this.log.info(`Lade Update herunter: ${downloadUrl}`);

    try {
      const res = await axios.get(downloadUrl, {
        responseType: 'stream',
        headers: {
          'X-API-Token': this.apiKey,
        },
        timeout: 300000,
      });

      const writer = fs.createWriteStream(filePath);
      res.data.pipe(writer);

      await new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
      });

      if (this.latestRelease.fileSize) {
        const stat = fs.statSync(filePath);
        if (stat.size !== this.latestRelease.fileSize) {
          this.log.error(`Integrity-Check fehlgeschlagen: erwartet ${this.latestRelease.fileSize}, bekam ${stat.size}`);
          try { fs.unlinkSync(filePath); } catch {}
          return;
        }
        this.log.info(`Integrity-Check bestanden (${stat.size} Bytes)`);
      }

      this.downloadPath = filePath;
      this.log.info(`Update heruntergeladen: ${filePath}`);
      this._notifyReady();
    } catch (err) {
      this.log.warn(`Update-Download fehlgeschlagen: ${err.message}`);
      try { fs.unlinkSync(filePath); } catch {}
    }
  }

  /**
   * Callback aufrufen wenn Update bereit
   */
  _notifyReady() {
    if (this.onUpdateReady && this.latestRelease && this.downloadPath) {
      this.onUpdateReady({
        version: this.latestRelease.version,
        releaseNotes: this.latestRelease.releaseNotes,
        installerPath: this.downloadPath,
      });
    }
  }

  /**
   * Update installieren (Installer starten, App beenden)
   */
  install() {
    if (!this.downloadPath || !fs.existsSync(this.downloadPath)) {
      this.log.error('Kein heruntergeladenes Update gefunden');
      return false;
    }

    this.log.info(`Starte Installer: ${this.downloadPath}`);
    shell.openPath(this.downloadPath);
    return true;
  }

  /**
   * Gibt zurück ob ein Update bereit zur Installation ist
   */
  isUpdateReady() {
    return !!(this.downloadPath && fs.existsSync(this.downloadPath) && this.latestRelease);
  }

  /**
   * Release-Info des bereitstehenden Updates
   */
  getUpdateInfo() {
    if (!this.isUpdateReady()) return null;
    return {
      version: this.latestRelease.version,
      releaseNotes: this.latestRelease.releaseNotes,
    };
  }
}

module.exports = Updater;
