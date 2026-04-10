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

const dns = require('dns').promises;
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
      this.log.debug('Kill-switch already active');
      return;
    }

    this.log.info('Enabling kill-switch...');

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
      this.log.warn('Config could not be parsed:', err.message);
    }

    if (!endpoint) {
      this.log.error('Kill-switch aborted: WireGuard endpoint could not be determined');
      throw new Error('Kill-Switch: WireGuard-Endpoint nicht gefunden');
    }

    // Resolve hostname endpoints to IP before creating firewall rules
    if (endpoint.needsResolve) {
      try {
        const { address } = await dns.lookup(endpoint.host, { family: 4 });
        this.log.info(`Kill-switch endpoint resolved: ${endpoint.host} -> ${address}`);
        endpoint.host = address;
        endpoint.needsResolve = false;
      } catch (err) {
        this.log.error(`Kill-switch DNS resolution failed for ${endpoint.host}: ${err.message}`);
        throw new Error(`Kill-Switch: DNS-Auflösung für Endpoint ${endpoint.host} fehlgeschlagen`);
      }
    }

    try {
      await this._removeAllRules();

      // Aktuelle Firewall-Policy speichern
      this._savedPolicy = await this._getCurrentPolicy();

      // WICHTIG: Alle Allow-Regeln ZUERST erstellen, DANN Block-Policy setzen.
      // Verhindert Race Condition: Ohne Regeln würde Block-Policy den
      // WireGuard-Tunnel sofort unterbrechen (Keepalives geblockt → Tunnel stirbt).

      // 1. ALLOW: WireGuard Endpoint (UDP zum VPN-Server) — ZUERST!
      await this._addRule({
        name: `${this.rulePrefix}_Allow_WG_Endpoint`,
        dir: 'out',
        action: 'allow',
        remoteip: endpoint.host,
        remoteport: endpoint.port,
        protocol: 'udp',
      });

      // 1b. ALLOW: Eingehend vom WireGuard Endpoint (UDP-Antworten)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_WG_Endpoint_In`,
        dir: 'in',
        action: 'allow',
        remoteip: endpoint.host,
        remoteport: endpoint.port,
        protocol: 'udp',
      });

      // 2. ALLOW: GateControl API (TCP/HTTPS zum Server)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_API`,
        dir: 'out',
        action: 'allow',
        remoteip: endpoint.host,
        remoteport: '443',
        protocol: 'tcp',
      });

      // 3. ALLOW: Allen ausgehenden Traffic von der lokalen VPN-IP
      //     (erlaubt Internet-Traffic durch den WireGuard-Tunnel)
      if (vpnLocalIp) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Out`,
          dir: 'out',
          action: 'allow',
          localip: vpnLocalIp,
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

      // 6. ALLOW: Eingehender Traffic vom VPN-Subnetz
      if (vpnSubnet) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_In`,
          dir: 'in',
          action: 'allow',
          remoteip: vpnSubnet,
        });
      }

      // 7. ALLOW: Loopback
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback`,
        dir: 'out',
        action: 'allow',
        remoteip: '127.0.0.0/8',
      });
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback_In`,
        dir: 'in',
        action: 'allow',
        remoteip: '127.0.0.0/8',
      });

      // 8. ALLOW: Lokales Netzwerk (private Subnetze)
      for (const subnet of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_${subnet.replace(/[./]/g, '_')}`,
          dir: 'out',
          action: 'allow',
          remoteip: subnet,
        });
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_In_${subnet.replace(/[./]/g, '_')}`,
          dir: 'in',
          action: 'allow',
          remoteip: subnet,
        });
      }

      // 9. ALLOW: Physisches Netzwerk-Subnetz (z.B. andere VMs auf OVH)
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
        this.log.info(`Physical subnet allowed: ${subnet}`);
      }

      // 10. ALLOW: DHCP
      await this._addRule({
        name: `${this.rulePrefix}_Allow_DHCP`,
        dir: 'out',
        action: 'allow',
        protocol: 'udp',
        localport: '68',
        remoteport: '67',
      });

      // JETZT Block-Policy setzen — alle Regeln sind bereits aktiv
      await netsh('advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound');
      this.log.info('Firewall default policy set to block');

      this.enabled = true;
      this.log.info('Kill-switch enabled');

    } catch (err) {
      this.log.error('Kill-switch activation failed:', err);
      await this._restorePolicy();
      await this._removeAllRules();
      throw err;
    }
  }

  /**
   * Kill-Switch deaktivieren
   */
  async disable() {
    this.log.info('Disabling kill-switch...');
    await this._restorePolicy();
    await this._removeAllRules();
    this.enabled = false;
    this.log.info('Kill-switch disabled');
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
      this.log.info('Firewall default policy restored');
    } catch (err) {
      this.log.error('Firewall policy restoration failed:', err.message);
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

    this.log.debug(`Firewall rule: netsh ${args.join(' ')}`);
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
      `${this.rulePrefix}_Allow_WG_Endpoint_In`,
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
        let prefix = this._maskToPrefix(maskNum);

        // Öffentliche Subnetze auf /24 begrenzen.
        // Windows/OVH meldet oft /8 für öffentliche IPs — das würde
        // Millionen von IPs außerhalb des VPN erlauben und den
        // Kill-Switch wirkungslos machen.
        if (prefix < 24) prefix = 24;
        const cappedMask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const networkNum = ipNum & cappedMask;
        const networkIp = this._numToIp(networkNum);
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
        if (PORT_RE.test(port)) {
          // Accept both IP literals and hostnames — hostname resolution
          // happens in enable() before the endpoint is used for firewall rules.
          endpoint = { host, port, needsResolve: !IPV4_RE.test(host) };
        }
      }

      const addrMatch = trimmed.match(/^Address\s*=\s*(.+)$/);
      if (addrMatch) {
        const cidr = addrMatch[1].trim().split(',')[0].trim();
        const parts = cidr.split('/');
        if (parts.length === 2 && IPV4_RE.test(parts[0])) {
          vpnLocalIp = parts[0];
          const ip = parts[0].split('.');
          let mask = parseInt(parts[1], 10);
          if (mask >= 0 && mask <= 32) {
            // /32 ist eine Host-Adresse, nicht das VPN-Subnetz.
            // WireGuard vergibt /32 an Clients, das Subnetz ist aber /24.
            // Ohne Erweiterung würden DNS-Regeln nur die eigene IP abdecken,
            // nicht den DNS-Server (z.B. 10.8.0.1).
            if (mask > 24) mask = 24;
            ip[3] = '0';
            vpnSubnet = `${ip.join('.')}/${mask}`;
          }
        }
      }
    }

    return { endpoint, vpnSubnet, vpnLocalIp };
  }
}

module.exports = KillSwitch;
