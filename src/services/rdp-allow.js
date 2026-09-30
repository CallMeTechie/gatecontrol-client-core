/**
 * GateControl – RDP Allow Service (Core)
 *
 * Erstellt eine Windows-Firewall-Regel, die eingehende RDP-Verbindungen
 * (TCP Port 3389) aus dem VPN-Subnetz erlaubt.
 *
 * Implementiert über Windows Firewall (netsh advfirewall).
 *
 * - Die Regel heißt pro Edition anders ("GateControl_Pro_RDP_Allow_In_3389"
 *   bzw. "GateControl_Community_RDP_Allow_In_3389", siehe editions.js).
 *   So löscht eine App beim Deaktivieren, Beenden oder Deinstallieren nie
 *   die Freigabe der anderen, wenn beide installiert sind.
 * - Die alte gemeinsame Regel "GateControl_RDP_Allow_In_3389" (Versionen
 *   vor der Trennung) lässt sich keiner App zuordnen. Sie wird nur
 *   entfernt, wenn keine andere Edition installiert ist oder läuft; im
 *   Zweifel bleibt sie stehen (siehe removeLegacyRule()).
 */

'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;

const execFileAsync = promisify(execFile);

const { validateCidr, IPV4_RE } = require('../utils/validation');
const editions = require('./editions');

const LEGACY_RULE_NAME = editions.LEGACY_RDP_ALLOW_RULE_NAME;

function defaultNetsh(args) {
  return execFileAsync('netsh', args, { windowsHide: true });
}

class RdpAllow {
  /**
   * @param {object} log - electron-log kompatibler Logger
   * @param {object} options
   * @param {'pro'|'community'} options.edition - Edition der App (Pflicht).
   *   Daraus wird der Regelname abgeleitet (editions.rdpAllowRuleName).
   * @param {Function} [options.otherEditionPresent] - async () => boolean;
   *   Standard: editions.isOtherEditionPresent(edition). Entscheidet, ob
   *   die Altregel entfernt werden darf (für Tests).
   * @param {Function} [options.netsh] - async (args[]) => { stdout } (für Tests)
   */
  constructor(log, options = {}) {
    this.log = log;
    this.edition = editions.getEdition(options.edition).id;
    this.ruleName = editions.rdpAllowRuleName(this.edition);
    this._otherEditionPresent = options.otherEditionPresent ||
      (() => editions.isOtherEditionPresent(this.edition));
    this._netsh = options.netsh || defaultNetsh;
    this.enabled = false;
  }

  /**
   * RDP-Firewall-Regel aktivieren.
   * Erlaubt eingehende TCP-Verbindungen auf Port 3389 vom VPN-Subnetz.
   *
   * @param {string} configPath - Pfad zur WireGuard-Konfigurationsdatei
   */
  async enable(configPath) {
    if (this.enabled) {
      this.log.debug('RDP Allow already active');
      return;
    }

    this.log.info('Enabling RDP Allow firewall rule...');

    let vpnSubnet = null;

    try {
      const config = await fs.readFile(configPath, 'utf-8');
      vpnSubnet = this._parseVpnSubnet(config);
    } catch (err) {
      this.log.warn('Config could not be parsed for RDP Allow:', err.message);
    }

    if (!vpnSubnet) {
      this.log.error('RDP Allow aborted: VPN subnet could not be determined');
      throw new Error('RDP Allow: VPN-Subnetz nicht ermittelbar');
    }

    try {
      // Alte Regeln entfernen
      await this._removeAllRules();

      // Eingehende RDP-Verbindungen vom VPN-Subnetz erlauben
      await this._addRule({
        name: this.ruleName,
        dir: 'in',
        action: 'allow',
        protocol: 'tcp',
        localport: '3389',
        remoteip: vpnSubnet,
      });

      this.enabled = true;
      this.log.info(`RDP Allow enabled for VPN subnet ${vpnSubnet}`);

    } catch (err) {
      this.log.error('RDP Allow activation failed:', err);
      await this._removeAllRules();
      throw err;
    }
  }

  /**
   * RDP-Firewall-Regel deaktivieren
   */
  async disable() {
    this.log.info('Disabling RDP Allow firewall rule...');
    await this._removeAllRules();
    this.enabled = false;
    this.log.info('RDP Allow disabled');
  }

  /**
   * Prüft ob die RDP-Allow-Regel dieser Edition existiert
   * (die Altregel und die Regel der anderen Edition zählen nicht).
   */
  async isActive() {
    return this._ruleExists(this.ruleName);
  }

  /**
   * Abgleich beim App-Start mit der gespeicherten Einstellung:
   * - Regel vorhanden, Einstellung aus  → verwaiste Regel entfernen
   * - Regel vorhanden, Einstellung an   → als aktiv übernehmen
   * - Regel fehlt, Einstellung an       → neu anlegen (z.B. nach dem Update
   *   von einer Version mit der gemeinsamen Altregel)
   * Zusätzlich wird eine Altregel entfernt, sofern das sicher ist.
   *
   * @param {object} opts
   * @param {boolean} opts.wanted - gespeicherte Einstellung (tunnel.rdpAllow)
   * @param {string} opts.configPath - Pfad zur WireGuard-Konfigurationsdatei
   * @returns {Promise<boolean>} true, wenn die Freigabe danach aktiv ist
   */
  async reconcile({ wanted, configPath }) {
    const active = await this.isActive();
    if (active && !wanted) {
      this.log.warn('Orphaned RDP Allow rule found — removing');
      await this.disable();
    } else if (active) {
      this.log.info('RDP Allow was active at last exit — rule kept');
      this.enabled = true;
    } else if (wanted) {
      try {
        await this.enable(configPath);
      } catch (err) {
        this.log.warn('RDP Allow could not be restored:', err.message);
      }
    }
    // enable()/disable() haben die Altregel bereits behandelt
    if (!active && !wanted) await this.removeLegacyRule();
    return this.enabled;
  }

  /**
   * Alte gemeinsame Regel "GateControl_RDP_Allow_In_3389" entfernen, aber
   * nur, wenn keine andere Edition installiert ist oder läuft — sonst
   * könnte sie deren aktive RDP-Freigabe (Altversion) sein. Lässt sich das
   * nicht feststellen, bleibt sie stehen.
   *
   * @returns {Promise<boolean>} true, wenn die Altregel gelöscht wurde
   */
  async removeLegacyRule() {
    if (!await this._ruleExists(LEGACY_RULE_NAME)) return false;
    let present;
    try {
      present = await this._otherEditionPresent();
    } catch (err) {
      this.log.warn('RDP Allow: other GateControl edition could not be detected:', err && err.message);
      present = true;
    }
    if (present !== false) {
      this.log.warn(`RDP Allow: legacy rule "${LEGACY_RULE_NAME}" left in place — another GateControl edition is installed or running`);
      return false;
    }
    try {
      await this._netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${LEGACY_RULE_NAME}`]);
      this.log.info(`RDP Allow: legacy rule "${LEGACY_RULE_NAME}" removed`);
      return true;
    } catch (err) {
      this.log.warn(`RDP Allow: legacy rule "${LEGACY_RULE_NAME}" could not be removed:`, err && err.message);
      return false;
    }
  }

  /** true, wenn eine Regel mit genau diesem Anzeigenamen existiert */
  async _ruleExists(name) {
    try {
      const { stdout } = await this._netsh(['advfirewall', 'firewall', 'show', 'rule', `name=${name}`]);
      return String(stdout || '').includes(name);
    } catch {
      // netsh liefert Exit-Code 1, wenn keine Regel passt
      return false;
    }
  }

  /**
   * Firewall-Regel hinzufügen (validiert)
   */
  async _addRule({ name, dir, action, protocol, localport, remoteip }) {
    if (name !== this.ruleName) throw new Error(`Ungültiger Regelname: ${name}`);
    const args = ['advfirewall', 'firewall', 'add', 'rule',
      `name=${name}`,
      `dir=${dir}`,
      `action=${action}`,
      `protocol=${protocol}`,
    ];

    if (localport) args.push(`localport=${localport}`);

    if (remoteip) {
      if (remoteip.includes('/')) validateCidr(remoteip);
      args.push(`remoteip=${remoteip}`);
    }

    args.push('enable=yes');

    this.log.debug(`Firewall rule: netsh ${args.join(' ')}`);
    await this._netsh(args);
  }

  /**
   * RDP-Regel dieser Edition entfernen, dazu die Altregel, sofern sicher.
   * Die Regel der anderen Edition wird nie angefasst.
   */
  async _removeAllRules() {
    await this._netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${this.ruleName}`]).catch(() => {});
    await this.removeLegacyRule().catch(() => false);
  }

  /**
   * VPN-Subnetz aus WireGuard-Config extrahieren
   */
  _parseVpnSubnet(content) {
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      const addrMatch = trimmed.match(/^Address\s*=\s*(.+)$/);
      if (addrMatch) {
        const cidr = addrMatch[1].trim().split(',')[0].trim();
        const parts = cidr.split('/');
        if (parts.length === 2 && IPV4_RE.test(parts[0])) {
          const ip = parts[0].split('.');
          let mask = parseInt(parts[1], 10);
          if (mask >= 0 && mask <= 32) {
            // /32 → /24 (gleiche Logik wie KillSwitch)
            if (mask > 24) mask = 24;
            ip[3] = '0';
            return `${ip.join('.')}/${mask}`;
          }
        }
      }
    }
    return null;
  }
}

module.exports = RdpAllow;
