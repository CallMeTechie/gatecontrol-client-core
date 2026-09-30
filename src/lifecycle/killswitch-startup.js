'use strict';

/**
 * Kill-Switch-Aufräumen beim App-Start (Electron-frei, testbar).
 * Gemeinsam für Pro und Community (vorher je eine Kopie in src/main/).
 *
 * Nach einem Absturz oder harten Beenden bleiben die Firewall-Regeln und
 * die Block-Policy des Kill-Switch stehen — der Rechner hat dann kein
 * Internet. Der Tunnel läuft im App-Prozess (wireguard.dll) und ist nach
 * einem Neustart der App nie mehr aktiv; der Kill-Switch wird deshalb
 * aufgeräumt und beim nächsten Verbinden wieder aktiviert, falls die
 * Einstellung an ist.
 *
 * Nutzt KillSwitch.recoverStaleState() (gesicherte Policy pro Profil).
 * KillSwitch-Objekte ohne diese Methode fallen auf isActive()/disable()
 * zurück.
 *
 * @param {object} ctx
 * @param {object} ctx.killSwitch - KillSwitch-Instanz
 * @param {object} ctx.store - electron-store
 * @param {object} [ctx.wgService] - WireGuard-Service (isConnected())
 * @param {object} ctx.log
 * @returns {Promise<'none'|'kept'|'cleaned'|'failed'>}
 */
async function recoverKillSwitch({ killSwitch, store, wgService, log }) {
  try {
    let tunnelUp = false;
    if (wgService && typeof wgService.isConnected === 'function') {
      try { tunnelUp = (await wgService.isConnected()) === true; } catch { tunnelUp = false; }
    }
    const keepActive = store.get('tunnel.killSwitch', false) === true && tunnelUp;

    if (typeof killSwitch.recoverStaleState === 'function') {
      const result = await killSwitch.recoverStaleState({ keepActive });
      if (result === 'cleaned') log.warn('Verwaiste Kill-Switch-Regeln entfernt und Firewall-Policy wiederhergestellt');
      else if (result === 'kept') log.info('Kill-Switch aus der letzten Sitzung übernommen (Tunnel aktiv)');
      return result;
    }

    // Fallback für ältere Core-Versionen
    if (await killSwitch.isActive()) {
      if (keepActive) {
        killSwitch.enabled = true;
        return 'kept';
      }
      log.warn('Verwaiste Kill-Switch-Regeln gefunden — bereinige...');
      await killSwitch.disable();
      return 'cleaned';
    }
    return 'none';
  } catch (err) {
    log.error('Kill-Switch-Aufräumen beim Start fehlgeschlagen:', err && err.message);
    return 'failed';
  }
}

module.exports = { recoverKillSwitch };
