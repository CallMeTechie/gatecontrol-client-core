/**
 * GateControl – RDP Allow Service (Core)
 *
 * Erstellt eine Windows-Firewall-Regel, die eingehende RDP-Verbindungen
 * (TCP Port 3389) aus dem VPN-Subnetz erlaubt.
 *
 * Implementiert über Windows Firewall (netsh advfirewall).
 */

'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;

const execFileAsync = promisify(execFile);

const { validateCidr, IPV4_RE } = require('../utils/validation');

function netsh(...args) {
  return execFileAsync('netsh', args);
}

const RULE_PREFIX = 'GateControl_RDP';

class RdpAllow {
  constructor(log) {
    this.log = log;
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
        name: `${RULE_PREFIX}_Allow_In_3389`,
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
   * Prüft ob RDP-Allow-Regeln aktiv sind
   */
  async isActive() {
    try {
      const { stdout } = await netsh('advfirewall', 'firewall', 'show', 'rule',
        `name=${RULE_PREFIX}_Allow_In_3389`);
      return stdout.includes(RULE_PREFIX);
    } catch {
      return false;
    }
  }

  /**
   * Firewall-Regel hinzufügen (validiert)
   */
  async _addRule({ name, dir, action, protocol, localport, remoteip }) {
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
    await netsh(...args);
  }

  /**
   * Alle GateControl RDP-Regeln entfernen
   */
  async _removeAllRules() {
    const ruleNames = [
      `${RULE_PREFIX}_Allow_In_3389`,
    ];

    await Promise.all(ruleNames.map(name =>
      netsh('advfirewall', 'firewall', 'delete', 'rule', `name=${name}`).catch(() => {})
    ));
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
