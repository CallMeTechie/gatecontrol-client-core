'use strict';

/**
 * "Update installieren" for the Pro and Community main processes (tray
 * entry, update card, banner, toast button): one flow, shared here.
 *
 *   1. updater.prepareInstall() – the verified installer is still there and
 *      re-hashes to the signed manifest. Nothing has changed yet: on failure
 *      the VPN stays connected and the caller gets the reason.
 *   2. Tunnel down, firewall (kill switch) lifted – the installer replaces
 *      the files of the running app and its WireGuard adapter.
 *   3. updater.launchInstaller() – starts the installer and watches it for a
 *      moment. On failure the tunnel is connected again (when it was) and
 *      the reason goes back to the window / a notification.
 *   4. Only a running installer ends the app (quit()).
 *
 * Before, the app tore the tunnel down first and then fired the installer
 * off through shell.openPath() without looking at the result, so a failed
 * start left the user offline with nothing happening.
 *
 * No verified update yet (still downloading, never checked, or the file
 * was dropped as changed): the click waits for the running download or
 * checks and downloads now (updater.ensureUpdate()), reports that through
 * onStatus('downloading') and then installs. A file that fails the re-hash
 * is downloaded once more and checked again. Before, such a click only
 * logged "kein geprüftes Update bereit" and did nothing.
 *
 * Result: { ok: true, via } | { ok: false, code, message?, vpnRestored? }
 * (code: not_ready | busy | verify_failed | launch_failed | exited).
 */

function noopLog() { return { info() {}, warn() {}, error() {}, debug() {} }; }

/**
 * @param {object} deps
 * @param {() => object|null} deps.getUpdater - core Updater (or null)
 * @param {object} [deps.log]
 * @param {() => boolean} deps.isConnected - tunnel up?
 * @param {() => Promise<void>} deps.disconnect - tunnel down
 * @param {() => Promise<void>} deps.reconnect - tunnel up again (after a failed start)
 * @param {() => Promise<void>} [deps.liftFirewall] - kill switch off for the installer
 * @param {() => void} deps.quit - end the app (the installer is running)
 * @param {number} [deps.quitDelayMs=300]
 * @param {(state: 'downloading', info: {version: string|null}) => void} [deps.onStatus]
 *   - visible status while the update is fetched first (toast / window)
 * @returns {() => Promise<object>} installUpdate()
 */
function createUpdateInstaller({ getUpdater, log, isConnected, disconnect, reconnect, liftFirewall = async () => {}, quit, quitDelayMs = 300, onStatus = null }) {
  const L = log || noopLog();
  let running = null;

  const status = (state, updater) => {
    if (typeof onStatus !== 'function') return;
    const version = (updater && updater.latestRelease && updater.latestRelease.version) || null;
    try { onStatus(state, { version }); } catch (err) { L.warn(`Update-Status-Anzeige fehlgeschlagen: ${err && err.message}`); }
  };

  // Verified update ready, or fetched now (waits for a running download).
  async function ensureReady(updater, { force = false } = {}) {
    if (!force && updater.isUpdateReady() && !(updater.isDownloading && updater.isDownloading())) return true;
    if (typeof updater.ensureUpdate !== 'function') return updater.isUpdateReady();
    L.info('Update-Installation angefordert – geprüftes Update wird zuerst heruntergeladen');
    status('downloading', updater);
    try {
      return !!(await updater.ensureUpdate());
    } catch (err) {
      L.warn(`Update konnte nicht geladen werden: ${err && err.message}`);
      return false;
    }
  }

  // The verified file is gone or broken: fetch it again in the background.
  const redownload = (updater) => {
    Promise.resolve().then(() => updater.check()).catch((err) => L.warn(`Update erneut laden fehlgeschlagen: ${err && err.message}`));
  };

  async function run() {
    const updater = getUpdater();
    if (!updater || !(await ensureReady(updater))) {
      L.warn('Update-Installation angefordert, aber kein geprüftes Update verfügbar');
      return { ok: false, code: 'not_ready' };
    }
    L.info('Update-Installation gestartet ...');

    let prep = await updater.prepareInstall();
    if (!prep.ok && prep.code === 'verify_failed' && typeof updater.ensureUpdate === 'function') {
      // The file no longer matches the signed manifest (dropped): fetch it once more.
      L.warn('Installer passte nicht zum Manifest – lade das Update neu und prüfe erneut');
      if (await ensureReady(updater, { force: true })) prep = await updater.prepareInstall();
    }
    if (!prep.ok) {
      L.error(`Update-Installation abgebrochen (${prep.code}): ${prep.message || ''} – VPN bleibt verbunden`);
      if (prep.code === 'verify_failed') redownload(updater);
      return prep;
    }

    const wasConnected = !!isConnected();
    if (wasConnected) {
      try {
        await disconnect();
      } catch (err) {
        L.error(`Tunnel konnte vor dem Update nicht getrennt werden: ${err.message}`);
      }
    }
    try {
      await liftFirewall();
    } catch (err) {
      L.error(`Kill-Switch konnte vor dem Update nicht deaktiviert werden: ${err.message}`);
    }

    const launched = await updater.launchInstaller();
    if (!launched.ok) {
      L.error(`Installer nicht gestartet (${launched.code}): ${launched.message || ''}`);
      if (launched.code === 'verify_failed') redownload(updater);
      const result = { ...launched };
      if (wasConnected) {
        try {
          await reconnect();
          result.vpnRestored = true;
          L.info('VPN nach fehlgeschlagenem Update-Start wieder verbunden');
        } catch (err) {
          result.vpnRestored = false;
          L.error(`VPN nach fehlgeschlagenem Update-Start nicht wieder verbunden: ${err.message}`);
        }
      }
      return result;
    }

    L.info(`Installer gestartet (${launched.via}) – App wird beendet`);
    const tm = setTimeout(() => quit(), quitDelayMs);
    if (tm && typeof tm.unref === 'function') tm.unref();
    return { ok: true, via: launched.via };
  }

  return function installUpdate() {
    if (running) return Promise.resolve({ ok: false, code: 'busy' });
    running = run().catch((err) => {
      L.error(`Update-Installation fehlgeschlagen: ${err && err.message}`);
      return { ok: false, code: 'launch_failed', message: String((err && err.message) || err) };
    }).finally(() => { running = null; });
    return running;
  };
}

const INSTALL_ERROR_CODES = Object.freeze(['not_ready', 'busy', 'verify_failed', 'launch_failed', 'exited']);

/**
 * Text for a failed install (notification from the tray / toast button):
 * "Update konnte nicht installiert werden: <reason> (<detail>) <VPN restored>".
 * @param {object} result - installUpdate() result
 * @param {Function} t - i18n t()
 * @returns {string|null} null on success
 */
function installErrorText(result, t) {
  if (result === true || (result && result.ok === true)) return null;
  const r = result && typeof result === 'object' ? result : {};
  const code = INSTALL_ERROR_CODES.includes(r.code) ? r.code : 'launch_failed';
  let text = t(`update.installError.${code}`);
  const detail = typeof r.message === 'string' ? r.message.trim().slice(0, 160) : '';
  if (detail && (code === 'launch_failed' || code === 'exited')) text += ` (${detail})`;
  if (r.vpnRestored === true) text += ` ${t('update.installVpnRestored')}`;
  return text;
}

module.exports = { createUpdateInstaller, installErrorText, INSTALL_ERROR_CODES };
