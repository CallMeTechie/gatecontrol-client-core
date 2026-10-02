/**
 * GateControl – Auto-Update Service (Core)
 *
 * Prüft den GateControl-Server auf neue Versionen, lädt Updates im
 * Hintergrund herunter und bietet Installation per Dialog an.
 *
 * Signierte Updates: Die Clients haben kein Authenticode-Zertifikat. Jedes
 * Release trägt deshalb ein Manifest (update-manifest.json) mit Produkt,
 * Version, Dateiname, SHA-256 und Größe des Installers, signiert mit einem
 * Ed25519-Schlüssel, der nur als GitHub-Actions-Secret existiert. Der Server
 * reicht Manifest und Signatur unverändert durch. Dieser Updater
 *   - läuft nur mit einem gültigen Ed25519-Public-Key (sonst deaktiviert),
 *   - prüft die Signatur über die exakten Manifest-Bytes,
 *   - akzeptiert nur Produkt, Version, Dateiname, Hash und Größe aus dem
 *     signierten Manifest (nie aus den unsignierten Feldern der Antwort),
 *   - lädt nur über https und schickt den API-Token nur an den eigenen Server,
 *   - verwirft Downloads mit falscher Größe oder falschem Hash und
 *   - hasht den Installer direkt vor dem Start erneut.
 * Einen Rückfall auf unsignierte Updates gibt es nicht.
 *
 * Server-Richtlinie (Update-Kanal stable/beta, Mindestversion, Pflicht-Update):
 * Die Felder channel, minVersion und mandatory der Check-Antwort sind NICHT
 * signiert. Sie dienen nur der Anzeige (Kanal im Info-Bereich, nicht
 * ausblendbarer Hinweis „Update erforderlich“). Sie ändern nichts an der
 * Prüfung: Signatur, Produkt, Version (strikt neuer), Größe und Hash werden
 * immer geprüft, ein Pflicht-Update erlaubt kein Downgrade und gilt erst als
 * Pflicht, wenn ein geprüftes, neueres Update bereitliegt.
 */

const { app, shell } = require('electron');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CHECK_DELAY = 10000;       // 10s nach App-Start
const CHECK_INTERVAL = 21600000; // 6 Stunden

const MANIFEST_SCHEMA = 1;
const MAX_MANIFEST_LENGTH = 16 * 1024;
const FILE_NAME_RE = /^[A-Za-z0-9._ -]{1,200}\.exe$/;
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const PUBLIC_KEY_PLACEHOLDER = 'REPLACE_WITH_UPDATE_PUBLIC_KEY';
const REJECT_MSG = 'Update nicht signiert/ungültig – abgelehnt';
const CHANNELS = ['stable', 'beta'];

/**
 * PEM → Ed25519-KeyObject, sonst null (Platzhalter, leer, anderer Typ, kaputt).
 */
function parsePublicKey(pem) {
  if (typeof pem !== 'string' || !pem.trim() || pem.includes(PUBLIC_KEY_PLACEHOLDER)) return null;
  try {
    const key = crypto.createPublicKey(pem);
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(v || ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** true, wenn a strikt neuer als b ist; bei unlesbaren Versionen false. */
function isNewerVersion(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return false;
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return true;
    if (pa[i] < pb[i]) return false;
  }
  return false;
}

/**
 * Prüft Signatur und Inhalt eines Update-Manifests.
 * @returns {{ok: true, manifest: object} | {ok: false, reason: string}}
 */
function verifyUpdateManifest({ manifest, signature, publicKey, product, offeredVersion, currentVersion }) {
  const fail = (reason) => ({ ok: false, reason });
  const key = publicKey && typeof publicKey === 'object' ? publicKey : parsePublicKey(publicKey);
  if (!key) return fail('kein gültiger Public Key');
  if (typeof manifest !== 'string' || !manifest || manifest.length > MAX_MANIFEST_LENGTH) return fail('Manifest fehlt');
  if (typeof signature !== 'string' || !signature.trim()) return fail('Signatur fehlt');

  const sig = Buffer.from(signature.trim(), 'base64');
  if (sig.length !== 64) return fail('Signatur hat falsche Länge');

  let valid = false;
  try {
    valid = crypto.verify(null, Buffer.from(manifest, 'utf8'), key, sig);
  } catch {
    valid = false;
  }
  if (!valid) return fail('Signatur ungültig');

  let m;
  try {
    m = JSON.parse(manifest);
  } catch {
    return fail('Manifest kein JSON');
  }
  if (!m || typeof m !== 'object' || Array.isArray(m)) return fail('Manifest kein Objekt');
  if (m.schema !== MANIFEST_SCHEMA) return fail(`unbekanntes Schema ${m.schema}`);
  if (m.product !== product) return fail(`falsches Produkt ${m.product}`);
  if (typeof m.version !== 'string' || !VERSION_RE.test(m.version)) return fail('Version ungültig');
  if (m.version !== offeredVersion) return fail(`Version ${m.version} passt nicht zum Angebot ${offeredVersion}`);
  if (!isNewerVersion(m.version, currentVersion)) return fail(`Version ${m.version} ist nicht neuer als ${currentVersion}`);
  if (typeof m.fileName !== 'string' || !FILE_NAME_RE.test(m.fileName)
      || m.fileName !== path.basename(m.fileName) || m.fileName !== path.win32.basename(m.fileName)
      || m.fileName.startsWith('.')) {
    return fail('Dateiname ungültig');
  }
  if (typeof m.sha256 !== 'string' || !SHA256_RE.test(m.sha256)) return fail('SHA-256 ungültig');
  if (!Number.isSafeInteger(m.size) || m.size <= 0) return fail('Größe ungültig');

  return {
    ok: true,
    manifest: { schema: m.schema, product: m.product, version: m.version, fileName: m.fileName, sha256: m.sha256, size: m.size },
  };
}

/**
 * Unsignierte Richtlinien-Felder der Check-Antwort, bereinigt. Unbekannte
 * Kanäle, unlesbare Versionen und alles außer `mandatory === true` fallen weg.
 * @returns {{channel: string|null, minVersion: string|null, mandatory: boolean}}
 */
function sanitizeUpdatePolicy(data) {
  const d = data && typeof data === 'object' ? data : {};
  return {
    channel: CHANNELS.includes(d.channel) ? d.channel : null,
    minVersion: typeof d.minVersion === 'string' && VERSION_RE.test(d.minVersion) ? d.minVersion : null,
    mandatory: d.mandatory === true,
  };
}

/** SHA-256 + Größe einer Datei (synchron, in Blöcken). */
function hashFileSync(filePath) {
  const hash = crypto.createHash('sha256');
  const buf = Buffer.alloc(1024 * 1024);
  let size = 0;
  const fd = fs.openSync(filePath, 'r');
  try {
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      hash.update(buf.subarray(0, n));
      size += n;
    }
  } finally {
    fs.closeSync(fd);
  }
  return { sha256: hash.digest('hex'), size };
}

/** SHA-256 + Größe einer Datei (asynchron). */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    let size = 0;
    fs.createReadStream(filePath)
      .on('data', (chunk) => { hash.update(chunk); size += chunk.length; })
      .on('error', reject)
      .on('end', () => resolve({ sha256: hash.digest('hex'), size }));
  });
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

class Updater {
  /**
   * @param {object} opts
   * @param {string} opts.serverUrl
   * @param {string} opts.apiKey
   * @param {object} opts.log
   * @param {'pro'|'community'} [opts.product] - Produkt im signierten Manifest
   * @param {'pro'|'community'} [opts.clientType] - Alias für product (Altbestand)
   * @param {string} opts.publicKey - Ed25519-Public-Key (SPKI-PEM). Ohne gültigen
   *   Schlüssel bleibt der Updater deaktiviert.
   * @param {string} [opts.downloadDir] - Zielverzeichnis (Standard: tmp/gatecontrol-update)
   */
  constructor({ serverUrl, apiKey, log, clientType, product, publicKey, downloadDir }) {
    this.log = log;
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
    // Auto-detect aus app.name falls nicht explizit gesetzt
    const appName = (app.getName() || '').toLowerCase();
    this.clientType = product || clientType || (appName.includes('pro') ? 'pro' : 'community');
    this.appName = app.getName() || '';
    this.currentVersion = app.getVersion();
    this.downloadDir = path.resolve(downloadDir || path.join(os.tmpdir(), 'gatecontrol-update'));
    this.downloadPath = null;
    this.latestRelease = null;
    this.checkTimer = null;
    this.startTimer = null;
    this.onUpdateReady = null;
    this.onPolicyChange = null;
    // Letzte vom Server gemeldete Richtlinie (unsigniert, nur Anzeige)
    this.policy = { channel: null, minVersion: null, mandatory: false };

    this.publicKey = parsePublicKey(publicKey);
    this.disabled = !this.publicKey;
    if (this.disabled) {
      this.log.warn('Auto-Update deaktiviert: kein gültiger Update-Signaturschlüssel (Ed25519) konfiguriert');
    }
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
   * @param {Function} onUpdateReady - ({version, releaseNotes, installerPath,
   *   mandatory, channel, minVersion}) sobald ein geprüftes Update bereitliegt
   * @param {object} [opts]
   * @param {Function} [opts.onPolicyChange] - (getUpdatePolicy()) wenn sich
   *   Kanal, Mindestversion oder Pflicht-Status ändern
   */
  start(onUpdateReady, { onPolicyChange } = {}) {
    this.onUpdateReady = onUpdateReady;
    if (typeof onPolicyChange === 'function') this.onPolicyChange = onPolicyChange;
    if (this.disabled) {
      this.log.warn('Auto-Update nicht gestartet: kein gültiger Update-Signaturschlüssel');
      return;
    }

    this.startTimer = setTimeout(() => this._check(), CHECK_DELAY);
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
    if (this.startTimer) {
      clearTimeout(this.startTimer);
      this.startTimer = null;
    }
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
  }

  _reject(reason) {
    this.log.error(`${REJECT_MSG}: ${reason}`);
  }

  /**
   * Update-Check durchführen
   */
  async _check() {
    if (this.disabled) {
      this.log.debug('Update-Check übersprungen: Auto-Update deaktiviert (kein Signaturschlüssel)');
      return;
    }
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
          'X-Client-Name': this.appName,
        },
        timeout: 15000,
      });

      const data = res.data || {};
      if (data.ok) this._applyPolicy(data);
      if (!data.ok || !data.available) {
        this.log.info(`Kein Update verfügbar (aktuell: ${this.currentVersion})`);
        return;
      }
      this.log.info(`Update-Check Antwort: Version ${data.version}, signiert: ${!!(data.manifest && data.signature)}`);

      const result = verifyUpdateManifest({
        manifest: data.manifest,
        signature: data.signature,
        publicKey: this.publicKey,
        product: this.clientType,
        offeredVersion: data.version,
        currentVersion: this.currentVersion,
      });
      if (!result.ok) {
        this._reject(result.reason);
        return;
      }
      const m = result.manifest;

      let dl;
      try {
        dl = new URL(data.downloadUrl);
      } catch {
        this._reject('Download-URL fehlt oder ungültig');
        return;
      }
      if (dl.protocol !== 'https:') {
        this._reject(`Download-URL ist nicht https (${dl.protocol})`);
        return;
      }

      this.log.info(`Signiertes Update verfügbar: ${this.currentVersion} -> ${m.version}`
        + `${this.policy.channel ? ` (Kanal ${this.policy.channel})` : ''}${this.policy.mandatory ? ' [Pflicht-Update]' : ''}`);

      // Ein neues Angebot verwirft ein früher geprüftes Download-Ergebnis,
      // außer es ist exakt dieselbe Datei.
      if (!this.latestRelease || this.latestRelease.sha256 !== m.sha256) {
        this.downloadPath = null;
      }
      this.latestRelease = {
        version: m.version,
        downloadUrl: dl.toString(),
        fileName: m.fileName,
        fileSize: m.size,
        sha256: m.sha256,
        releaseNotes: typeof data.releaseNotes === 'string' ? data.releaseNotes : '',
      };

      await this._download();
      this._emitPolicy();
    } catch (err) {
      this.log.warn(`Update-Check fehlgeschlagen: ${err.message}`);
    }
  }

  /**
   * Richtlinie aus der Check-Antwort übernehmen (nur Anzeige, unsigniert).
   */
  _applyPolicy(data) {
    const next = sanitizeUpdatePolicy(data);
    const changed = next.channel !== this.policy.channel
      || next.minVersion !== this.policy.minVersion
      || next.mandatory !== this.policy.mandatory;
    this.policy = next;
    if (changed) {
      this.log.info(`Update-Richtlinie: Kanal ${next.channel || '-'}, Mindestversion ${next.minVersion || '-'}, Pflicht ${next.mandatory}`);
      this._emitPolicy();
    }
  }

  _emitPolicy() {
    if (typeof this.onPolicyChange !== 'function') return;
    const state = JSON.stringify(this.getUpdatePolicy());
    if (state === this._lastEmittedPolicy) return;
    this._lastEmittedPolicy = state;
    try {
      this.onPolicyChange(this.getUpdatePolicy());
    } catch (err) {
      this.log.warn(`onPolicyChange fehlgeschlagen: ${err.message}`);
    }
  }

  /**
   * true, wenn die laufende Version unter der vom Server gemeldeten
   * Mindestversion liegt.
   */
  isBelowMinimum() {
    return !!this.policy.minVersion && isNewerVersion(this.policy.minVersion, this.currentVersion);
  }

  /**
   * Pflicht-Update: Der Server verlangt es (mandatory oder Mindestversion
   * unterschritten) UND ein geprüftes, strikt neueres Update liegt bereit.
   * Ohne bereitliegendes Update gibt es nichts zu erzwingen.
   */
  isMandatory() {
    if (!this.policy.mandatory && !this.isBelowMinimum()) return false;
    return this.isUpdateReady() && isNewerVersion(this.latestRelease.version, this.currentVersion);
  }

  /**
   * Anzeige-Zustand für Info-Bereich und Hinweis (alles unsigniert).
   */
  getUpdatePolicy() {
    return {
      channel: this.policy.channel,
      minVersion: this.policy.minVersion,
      belowMinimum: this.isBelowMinimum(),
      mandatory: this.isMandatory(),
      updateReady: this.isUpdateReady(),
      version: this.isUpdateReady() ? this.latestRelease.version : null,
    };
  }

  /**
   * Installer herunterladen (nur mit geprüftem Manifest)
   */
  async _download() {
    const rel = this.latestRelease;
    if (!rel?.downloadUrl || !rel.sha256 || !rel.fileSize || !FILE_NAME_RE.test(rel.fileName || '')) {
      this.log.warn('Kein geprüftes Update zum Herunterladen');
      return;
    }

    try {
      fs.mkdirSync(this.downloadDir, { recursive: true });
    } catch { /* createWriteStream meldet den Fehler */ }

    const filePath = path.join(this.downloadDir, path.basename(rel.fileName));
    if (path.dirname(filePath) !== this.downloadDir) {
      this._reject('Dateiname verlässt das Download-Verzeichnis');
      return;
    }
    const partPath = `${filePath}.part`;

    // Vorhandene Datei nur nach erneutem Hashen wiederverwenden.
    if (fs.existsSync(filePath)) {
      let accept = false;
      try {
        const actual = await hashFile(filePath);
        accept = actual.size === rel.fileSize && actual.sha256 === rel.sha256;
        if (!accept) this.log.warn(`Zwischengespeichertes Update passt nicht zum Manifest – verwerfe ${filePath}`);
      } catch (err) {
        this.log.warn(`Zwischengespeichertes Update nicht lesbar (${filePath}): ${err.message}`);
      }
      if (accept) {
        this.log.info(`Update bereits heruntergeladen und geprüft: ${filePath}`);
        this.downloadPath = filePath;
        this._notifyReady();
        return;
      }
      try { fs.unlinkSync(filePath); } catch { /* best effort */ }
    }

    // Token nur an den eigenen Server (z. B. Proxy für private Repos), nie an
    // GitHub oder andere Hosts. Mit Token keine Weiterleitungen folgen, damit
    // der Header nicht an ein fremdes Ziel wandert.
    const serverOrigin = originOf(this.serverUrl);
    const sameOrigin = !!serverOrigin && originOf(rel.downloadUrl) === serverOrigin;
    const headers = sameOrigin && this.apiKey ? { 'X-API-Token': this.apiKey } : {};

    this.log.info(`Lade Update herunter: ${rel.downloadUrl}`);

    try { fs.unlinkSync(partPath); } catch { /* nicht vorhanden */ }
    try {
      const res = await axios.get(rel.downloadUrl, {
        responseType: 'stream',
        headers,
        timeout: 300000,
        ...(sameOrigin ? { maxRedirects: 0 } : {}),
      });

      const actual = await this._writeAndHash(res.data, partPath, rel.fileSize);
      if (actual.size !== rel.fileSize || actual.sha256 !== rel.sha256) {
        this._reject(`Download passt nicht zum Manifest (Größe ${actual.size}/${rel.fileSize}, SHA-256 ${actual.sha256})`);
        try { fs.unlinkSync(partPath); } catch { /* best effort */ }
        return;
      }
      fs.renameSync(partPath, filePath);
      this.log.info(`Integrity-Check bestanden (${actual.size} Bytes, SHA-256 ${actual.sha256})`);

      this.downloadPath = filePath;
      this.log.info(`Update heruntergeladen: ${filePath}`);
      this._notifyReady();
    } catch (err) {
      this.log.warn(`Update-Download fehlgeschlagen: ${err.message}`);
      try { fs.unlinkSync(partPath); } catch { /* best effort */ }
    }
  }

  /**
   * Stream in Datei schreiben und dabei hashen; bricht ab, sobald mehr Bytes
   * als erwartet kommen.
   */
  _writeAndHash(stream, filePath, maxBytes) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      let size = 0;
      let done = false;
      const writer = fs.createWriteStream(filePath, { flags: 'wx' });
      const finish = (err) => {
        if (done) return;
        done = true;
        if (err) {
          try { stream.destroy(); } catch { /* ignore */ }
          if (writer.closed) {
            reject(err);
          } else {
            writer.once('close', () => reject(err));
            writer.destroy();
          }
        } else {
          resolve({ size, sha256: hash.digest('hex') });
        }
      };
      stream.on('data', (chunk) => {
        if (done) return;
        size += chunk.length;
        if (size > maxBytes) {
          finish(new Error(`Download größer als erwartet (> ${maxBytes} Bytes)`));
          return;
        }
        hash.update(chunk);
      });
      stream.on('error', finish);
      writer.on('error', finish);
      writer.on('finish', () => finish());
      stream.pipe(writer);
    });
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
        mandatory: this.isMandatory(),
        channel: this.policy.channel,
        minVersion: this.policy.minVersion,
      });
    }
  }

  /**
   * Update installieren (Installer starten, App beenden). Der Installer wird
   * unmittelbar vor dem Start erneut gehasht.
   */
  install() {
    if (this.disabled || !this.latestRelease?.sha256 || !this.downloadPath || !fs.existsSync(this.downloadPath)) {
      this.log.error('Kein geprüftes Update gefunden');
      return false;
    }

    let actual;
    try {
      actual = hashFileSync(this.downloadPath);
    } catch (err) {
      this._reject(`Installer nicht lesbar: ${err.message}`);
      return false;
    }
    if (actual.size !== this.latestRelease.fileSize || actual.sha256 !== this.latestRelease.sha256) {
      this._reject('Installer wurde nach dem Download verändert');
      try { fs.unlinkSync(this.downloadPath); } catch { /* best effort */ }
      this.downloadPath = null;
      return false;
    }

    this.log.info(`Starte Installer: ${this.downloadPath} (SHA-256 ${actual.sha256})`);
    shell.openPath(this.downloadPath);
    return true;
  }

  /**
   * Gibt zurück ob ein Update bereit zur Installation ist
   */
  isUpdateReady() {
    return !!(!this.disabled && this.downloadPath && fs.existsSync(this.downloadPath) && this.latestRelease?.sha256);
  }

  /**
   * Release-Info des bereitstehenden Updates
   */
  getUpdateInfo() {
    if (!this.isUpdateReady()) return null;
    return {
      version: this.latestRelease.version,
      releaseNotes: this.latestRelease.releaseNotes,
      mandatory: this.isMandatory(),
      channel: this.policy.channel,
      minVersion: this.policy.minVersion,
    };
  }
}

Updater.verifyUpdateManifest = verifyUpdateManifest;
Updater.parsePublicKey = parsePublicKey;
Updater.isNewerVersion = isNewerVersion;
Updater.sanitizeUpdatePolicy = sanitizeUpdatePolicy;
Updater.CHANNELS = CHANNELS;
Updater.PUBLIC_KEY_PLACEHOLDER = PUBLIC_KEY_PLACEHOLDER;

module.exports = Updater;
