/**
 * GateControl – Kill-Switch Service (Core)
 *
 * Blockiert allen Netzwerkverkehr außer:
 * - WireGuard-Tunnel-Traffic
 * - DNS über VPN
 * - Lokales Netzwerk
 * - GateControl Server-Kommunikation
 *
 * Implementiert über Windows Firewall (netsh advfirewall)
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;

const execFileAsync = promisify(execFile);

const { validateIp, validateCidr, validatePort, IPV4_RE } = require('../utils/validation');

function netsh(...args) {
  return execFileAsync('netsh', args);
}

class KillSwitch {
  constructor(log) {
    this.log = log;
    this.rulePrefix = 'GateControl_KS';
    this.enabled = false;
  }

  /**
   * Kill-Switch aktivieren
   */
  async enable(configPath) {
    if (this.enabled) {
      this.log.debug('Kill-Switch bereits aktiv');
      return;
    }

    this.log.info('Aktiviere Kill-Switch...');

    let endpoint = null;
    let vpnSubnet = null;

    try {
      const config = await fs.readFile(configPath, 'utf-8');
      const parsed = this._parseConfig(config);
      endpoint = parsed.endpoint;
      vpnSubnet = parsed.vpnSubnet;
    } catch (err) {
      this.log.warn('Config konnte nicht geparst werden:', err.message);
    }

    try {
      await this._removeAllRules();

      // 1. ALLOW: Loopback
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback`,
        dir: 'out',
        action: 'allow',
        remoteip: '127.0.0.0/8',
      });

      // 2. ALLOW: Lokales Netzwerk
      for (const subnet of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_${subnet.replace(/[./]/g, '_')}`,
          dir: 'out',
          action: 'allow',
          remoteip: subnet,
        });
      }

      // 3. ALLOW: WireGuard Endpoint
      if (endpoint) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_WG_Endpoint`,
          dir: 'out',
          action: 'allow',
          remoteip: endpoint.host,
          remoteport: endpoint.port,
          protocol: 'udp',
        });
      }

      // 4. ALLOW: VPN-Subnetz
      if (vpnSubnet) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Subnet`,
          dir: 'out',
          action: 'allow',
          remoteip: vpnSubnet,
        });
      }

      // 5. ALLOW: DHCP
      await this._addRule({
        name: `${this.rulePrefix}_Allow_DHCP`,
        dir: 'out',
        action: 'allow',
        protocol: 'udp',
        localport: '68',
        remoteport: '67',
      });

      // 6. BLOCK: Outbound
      await this._addRule({
        name: `${this.rulePrefix}_Block_All_Out`,
        dir: 'out',
        action: 'block',
        remoteip: 'any',
      });

      // 7. BLOCK: Inbound
      await this._addRule({
        name: `${this.rulePrefix}_Block_All_In`,
        dir: 'in',
        action: 'block',
        remoteip: 'any',
      });

      this.enabled = true;
      this.log.info('Kill-Switch aktiviert');

    } catch (err) {
      this.log.error('Kill-Switch Aktivierung fehlgeschlagen:', err);
      await this._removeAllRules();
      throw err;
    }
  }

  /**
   * Kill-Switch deaktivieren
   */
  async disable() {
    this.log.info('Deaktiviere Kill-Switch...');
    await this._removeAllRules();
    this.enabled = false;
    this.log.info('Kill-Switch deaktiviert');
  }

  /**
   * Prüft ob Kill-Switch aktiv ist
   */
  async isActive() {
    try {
      const { stdout } = await netsh('advfirewall', 'firewall', 'show', 'rule',
        `name=${this.rulePrefix}_Block_All_Out`);
      return stdout.includes(this.rulePrefix);
    } catch {
      return false;
    }
  }

  /**
   * Firewall-Regel hinzufügen (alle Werte validiert)
   */
  async _addRule({ name, dir, action, protocol, remoteip, remoteport, localport }) {
    const args = ['advfirewall', 'firewall', 'add', 'rule',
      `name=${name}`,
      `dir=${dir}`,
      `action=${action}`,
      `protocol=${protocol || 'any'}`,
    ];

    if (remoteip) {
      if (remoteip !== 'any') {
        if (remoteip.includes('/')) validateCidr(remoteip);
        else validateIp(remoteip);
      }
      args.push(`remoteip=${remoteip}`);
    }
    if (remoteport) {
      args.push(`remoteport=${validatePort(remoteport)}`);
    }
    if (localport) {
      args.push(`localport=${validatePort(localport)}`);
    }

    args.push('enable=yes');

    this.log.debug(`Firewall-Regel: netsh ${args.join(' ')}`);
    await netsh(...args);
  }

  /**
   * Alle GateControl Kill-Switch Regeln entfernen
   */
  async _removeAllRules() {
    const ruleNames = [
      `${this.rulePrefix}_Block_All_Out`,
      `${this.rulePrefix}_Block_All_In`,
      `${this.rulePrefix}_Allow_Loopback`,
      `${this.rulePrefix}_Allow_WG_Endpoint`,
      `${this.rulePrefix}_Allow_VPN_Subnet`,
      `${this.rulePrefix}_Allow_DHCP`,
      `${this.rulePrefix}_Allow_LAN_10_0_0_0_8`,
      `${this.rulePrefix}_Allow_LAN_172_16_0_0_12`,
      `${this.rulePrefix}_Allow_LAN_192_168_0_0_16`,
    ];

    await Promise.all(ruleNames.map(name =>
      netsh('advfirewall', 'firewall', 'delete', 'rule', `name=${name}`).catch(() => {})
    ));
  }

  /**
   * Config parsen für Endpoint-Extraktion (mit Validierung)
   */
  _parseConfig(content) {
    let endpoint = null;
    let vpnSubnet = null;

    const PORT_RE = /^\d{1,5}$/;

    for (const line of content.split('\n')) {
      const trimmed = line.trim();

      const epMatch = trimmed.match(/^Endpoint\s*=\s*(.+):(\d+)$/);
      if (epMatch) {
        const host = epMatch[1].trim();
        const port = epMatch[2].trim();
        if (IPV4_RE.test(host) && PORT_RE.test(port)) {
          endpoint = { host, port };
        }
      }

      const addrMatch = trimmed.match(/^Address\s*=\s*(.+)$/);
      if (addrMatch) {
        const cidr = addrMatch[1].trim().split(',')[0].trim();
        const parts = cidr.split('/');
        if (parts.length === 2 && IPV4_RE.test(parts[0])) {
          const ip = parts[0].split('.');
          const mask = parseInt(parts[1], 10);
          if (mask >= 0 && mask <= 32) {
            if (mask <= 24) ip[3] = '0';
            vpnSubnet = `${ip.join('.')}/${mask}`;
          }
        }
      }
    }

    return { endpoint, vpnSubnet };
  }
}

module.exports = KillSwitch;
