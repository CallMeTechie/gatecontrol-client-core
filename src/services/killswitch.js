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
 * Verwendet Default-Policy "block" statt expliziter Block-Regeln,
 * damit Allow-Regeln korrekt greifen.
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const os = require('os');

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
    this._savedPolicy = null;
    this._localSubnetRuleNames = [];
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
    let vpnLocalIp = null;

    try {
      const config = await fs.readFile(configPath, 'utf-8');
      const parsed = this._parseConfig(config);
      endpoint = parsed.endpoint;
      vpnSubnet = parsed.vpnSubnet;
      vpnLocalIp = parsed.vpnLocalIp;
    } catch (err) {
      this.log.warn('Config konnte nicht geparst werden:', err.message);
    }

    if (!endpoint) {
      this.log.error('Kill-Switch abgebrochen: WireGuard-Endpoint konnte nicht ermittelt werden');
      throw new Error('Kill-Switch: WireGuard-Endpoint nicht gefunden');
    }

    try {
      await this._removeAllRules();

      // Aktuelle Firewall-Policy speichern, dann auf Block setzen
      this._savedPolicy = await this._getCurrentPolicy();
      await netsh('advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound');
      this.log.info('Firewall Default-Policy auf Block gesetzt');

      // 1. ALLOW: Loopback
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback`,
        dir: 'out',
        action: 'allow',
        remoteip: '127.0.0.0/8',
      });

      // 2. ALLOW: Lokales Netzwerk (private Subnetze)
      for (const subnet of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_${subnet.replace(/[./]/g, '_')}`,
          dir: 'out',
          action: 'allow',
          remoteip: subnet,
        });
      }

      // 2b. ALLOW: Physisches Netzwerk-Subnetz (z.B. öffentliche OVH-IPs)
      const localSubnets = this._getLocalSubnets(vpnLocalIp);
      this._localSubnetRuleNames = [];
      for (const subnet of localSubnets) {
        const ruleSuffix = subnet.replace(/[./]/g, '_');
        const outName = `${this.rulePrefix}_Allow_PhysNet_${ruleSuffix}`;
        const inName = `${this.rulePrefix}_Allow_PhysNet_In_${ruleSuffix}`;
        this._localSubnetRuleNames.push(outName, inName);

        await this._addRule({
          name: outName,
          dir: 'out',
          action: 'allow',
          remoteip: subnet,
        });
        await this._addRule({
          name: inName,
          dir: 'in',
          action: 'allow',
          remoteip: subnet,
        });
        this.log.info(`Physisches Subnetz erlaubt: ${subnet}`);
      }

      // 3. ALLOW: WireGuard Endpoint (UDP zum VPN-Server)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_WG_Endpoint`,
        dir: 'out',
        action: 'allow',
        remoteip: endpoint.host,
        remoteport: endpoint.port,
        protocol: 'udp',
      });

      // 3b. ALLOW: GateControl API (TCP/HTTPS zum Server)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_API`,
        dir: 'out',
        action: 'allow',
        remoteip: endpoint.host,
        remoteport: '443',
        protocol: 'tcp',
      });

      // 4. ALLOW: VPN-Subnetz
      if (vpnSubnet) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Subnet`,
          dir: 'out',
          action: 'allow',
          remoteip: vpnSubnet,
        });
      }

      // 4b. ALLOW: Allen ausgehenden Traffic von der lokalen VPN-IP
      //     (erlaubt Internet-Traffic durch den WireGuard-Tunnel)
      if (vpnLocalIp) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Out`,
          dir: 'out',
          action: 'allow',
          localip: vpnLocalIp,
        });
      }

      // 5. ALLOW: DNS über VPN (UDP/TCP Port 53 im VPN-Subnetz)
      if (vpnSubnet) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_DNS`,
          dir: 'out',
          action: 'allow',
          remoteip: vpnSubnet,
          remoteport: '53',
          protocol: 'udp',
        });
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_DNS_TCP`,
          dir: 'out',
          action: 'allow',
          remoteip: vpnSubnet,
          remoteport: '53',
          protocol: 'tcp',
        });
      }

      // 6. ALLOW: DHCP
      await this._addRule({
        name: `${this.rulePrefix}_Allow_DHCP`,
        dir: 'out',
        action: 'allow',
        protocol: 'udp',
        localport: '68',
        remoteport: '67',
      });

      // 7. ALLOW: Eingehender Traffic vom VPN-Subnetz
      if (vpnSubnet) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_In`,
          dir: 'in',
          action: 'allow',
          remoteip: vpnSubnet,
        });
      }

      // 8. ALLOW: Eingehender Loopback
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback_In`,
        dir: 'in',
        action: 'allow',
        remoteip: '127.0.0.0/8',
      });

      // 9. ALLOW: Eingehender LAN-Traffic
      for (const subnet of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_In_${subnet.replace(/[./]/g, '_')}`,
          dir: 'in',
          action: 'allow',
          remoteip: subnet,
        });
      }

      this.enabled = true;
      this.log.info('Kill-Switch aktiviert');

    } catch (err) {
      this.log.error('Kill-Switch Aktivierung fehlgeschlagen:', err);
      await this._restorePolicy();
      await this._removeAllRules();
      throw err;
    }
  }

  /**
   * Kill-Switch deaktivieren
   */
  async disable() {
    this.log.info('Deaktiviere Kill-Switch...');
    await this._restorePolicy();
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
        `name=${this.rulePrefix}_Allow_WG_Endpoint`);
      return stdout.includes(this.rulePrefix);
    } catch {
      return false;
    }
  }

  /**
   * Aktuelle Firewall-Policy abfragen
   */
  async _getCurrentPolicy() {
    try {
      const { stdout } = await netsh('advfirewall', 'show', 'allprofiles', 'firewallpolicy');
      return stdout;
    } catch {
      return null;
    }
  }

  /**
   * Firewall-Policy auf Standard zurücksetzen
   */
  async _restorePolicy() {
    try {
      await netsh('advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound');
      this.log.info('Firewall Default-Policy wiederhergestellt');
    } catch (err) {
      this.log.error('Firewall-Policy Wiederherstellung fehlgeschlagen:', err.message);
    }
  }

  /**
   * Firewall-Regel hinzufügen (alle Werte validiert)
   */
  async _addRule({ name, dir, action, protocol, remoteip, remoteport, localip, localport }) {
    const args = ['advfirewall', 'firewall', 'add', 'rule',
      `name=${name}`,
      `dir=${dir}`,
      `action=${action}`,
      `protocol=${protocol || 'any'}`,
    ];

    if (localip) {
      validateIp(localip);
      args.push(`localip=${localip}`);
    }
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
      `${this.rulePrefix}_Allow_Loopback`,
      `${this.rulePrefix}_Allow_Loopback_In`,
      `${this.rulePrefix}_Allow_WG_Endpoint`,
      `${this.rulePrefix}_Allow_API`,
      `${this.rulePrefix}_Allow_VPN_Subnet`,
      `${this.rulePrefix}_Allow_VPN_Out`,
      `${this.rulePrefix}_Allow_VPN_DNS`,
      `${this.rulePrefix}_Allow_VPN_DNS_TCP`,
      `${this.rulePrefix}_Allow_VPN_In`,
      `${this.rulePrefix}_Allow_DHCP`,
      `${this.rulePrefix}_Allow_LAN_10_0_0_0_8`,
      `${this.rulePrefix}_Allow_LAN_172_16_0_0_12`,
      `${this.rulePrefix}_Allow_LAN_192_168_0_0_16`,
      `${this.rulePrefix}_Allow_LAN_In_10_0_0_0_8`,
      `${this.rulePrefix}_Allow_LAN_In_172_16_0_0_12`,
      `${this.rulePrefix}_Allow_LAN_In_192_168_0_0_16`,
      ...(this._localSubnetRuleNames || []),
    ];

    await Promise.all(ruleNames.map(name =>
      netsh('advfirewall', 'firewall', 'delete', 'rule', `name=${name}`).catch(() => {})
    ));
  }

  /**
   * Lokale Netzwerk-Subnetze ermitteln (physische Interfaces, nicht VPN)
   * Gibt CIDR-Notationen zurück für alle nicht-internen, nicht-privaten Subnetze
   */
  _getLocalSubnets(vpnLocalIp) {
    const subnets = [];
    const interfaces = os.networkInterfaces();
    const privateRanges = [
      { start: 0x0A000000, end: 0x0AFFFFFF },   // 10.0.0.0/8
      { start: 0xAC100000, end: 0xAC1FFFFF },   // 172.16.0.0/12
      { start: 0xC0A80000, end: 0xC0A8FFFF },   // 192.168.0.0/16
      { start: 0x7F000000, end: 0x7FFFFFFF },   // 127.0.0.0/8
    ];

    for (const [, addrs] of Object.entries(interfaces)) {
      for (const addr of addrs) {
        if (addr.family !== 'IPv4' || addr.internal) continue;
        if (addr.address === vpnLocalIp) continue;

        const ipNum = this._ipToNum(addr.address);
        const isPrivate = privateRanges.some(r => ipNum >= r.start && ipNum <= r.end);
        if (isPrivate) continue; // Already covered by LAN rules

        // Calculate subnet from IP and netmask
        const maskNum = this._ipToNum(addr.netmask);
        const networkNum = ipNum & maskNum;
        const networkIp = this._numToIp(networkNum);
        const prefix = this._maskToPrefix(maskNum);
        const cidr = `${networkIp}/${prefix}`;

        if (!subnets.includes(cidr)) {
          subnets.push(cidr);
        }
      }
    }
    return subnets;
  }

  _ipToNum(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  _numToIp(num) {
    return [(num >>> 24) & 0xFF, (num >>> 16) & 0xFF, (num >>> 8) & 0xFF, num & 0xFF].join('.');
  }

  _maskToPrefix(maskNum) {
    let bits = 0;
    let m = maskNum;
    while (m & 0x80000000) { bits++; m = (m << 1) >>> 0; }
    return bits;
  }

  /**
   * Config parsen für Endpoint-Extraktion (mit Validierung)
   */
  _parseConfig(content) {
    let endpoint = null;
    let vpnSubnet = null;
    let vpnLocalIp = null;

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
          vpnLocalIp = parts[0];
          const ip = parts[0].split('.');
          const mask = parseInt(parts[1], 10);
          if (mask >= 0 && mask <= 32) {
            if (mask <= 24) ip[3] = '0';
            vpnSubnet = `${ip.join('.')}/${mask}`;
          }
        }
      }
    }

    return { endpoint, vpnSubnet, vpnLocalIp };
  }
}

module.exports = KillSwitch;
