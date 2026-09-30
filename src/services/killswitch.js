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
 *
 * Robustheit:
 * - Die Firewall-Policy wird vor dem Aktivieren pro Profil
 *   (Domain/Private/Public) gesichert und beim Deaktivieren exakt so
 *   wiederhergestellt.
 * - Der Zustand "Kill-Switch aktiv + gesicherte Policy" wird in
 *   userData/killswitch-state.json persistiert, BEVOR die Firewall
 *   verändert wird. Nach einem Absturz räumt recoverStaleState() beim
 *   nächsten Start Regeln und Policy wieder auf.
 * - Alle Regeln tragen ein Präfix pro Edition ("GateControl_Pro_KS_" bzw.
 *   "GateControl_Community_KS_", siehe editions.js) und werden beim
 *   Aufräumen per Präfix gefunden und gelöscht. So löscht eine App nie die
 *   Regeln der anderen, wenn beide installiert sind.
 * - Regeln mit dem alten gemeinsamen Präfix "GateControl_KS_" (Versionen
 *   vor der Trennung) tragen kein program= und lassen sich keiner App
 *   zuordnen. Sie werden nur entfernt, wenn keine andere Edition
 *   installiert ist oder läuft (siehe _mayRemoveLegacyRules()).
 * - Alle Werte, die an netsh gehen, werden validiert; netsh-Fehler werden
 *   mit der netsh-Ausgabe weitergereicht statt verschluckt.
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');

const execFileAsync = promisify(execFile);

const dns = require('dns').promises;
const { validateIp, validateCidr, IPV4_RE } = require('../utils/validation');
const { validateWgConfig } = require('@callmetechie/gatecontrol-config-hash');
const editions = require('./editions');

const LEGACY_RULE_PREFIX = editions.LEGACY_KILLSWITCH_RULE_PREFIX;
// Alle Kill-Switch-Regeln aller Editionen und der Altversion:
// GateControl_KS_…, GateControl_Pro_KS_…, GateControl_Community_KS_…
// Die Lookbehind-Grenze verhindert Treffer mitten in fremden Namen.
const ANY_KS_RULE_SCAN_RE = /(?<![A-Za-z0-9_])GateControl_(?:[A-Za-z0-9]+_)?KS_[A-Za-z0-9_]+/g;
const PROFILES = ['domain', 'private', 'public'];
const INBOUND_POLICIES = ['blockinbound', 'blockinboundalways', 'allowinbound', 'notconfigured'];
const OUTBOUND_POLICIES = ['allowoutbound', 'blockoutbound', 'notconfigured'];
const POLICY_RE = /\b(BlockInboundAlways|BlockInbound|AllowInbound|NotConfigured)\s*,\s*(AllowOutbound|BlockOutbound|NotConfigured)\b/i;
const STATE_FILE_NAME = 'killswitch-state.json';
const STATE_VERSION = 1;
const NETSH_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * netsh ausführen. netsh schreibt Fehlermeldungen nach stdout, deshalb
 * wird die Ausgabe an die Fehlermeldung angehängt (sonst steht im Log
 * nur "Command failed").
 */
async function runNetsh(args) {
  try {
    return await execFileAsync('netsh', args, { windowsHide: true, maxBuffer: NETSH_MAX_BUFFER });
  } catch (err) {
    const output = `${err.stdout || ''} ${err.stderr || ''}`.replace(/\s+/g, ' ').trim();
    const wrapped = new Error(
      `netsh ${args.slice(0, 4).join(' ')} fehlgeschlagen: ` +
      (output ? output.slice(0, 500) : err.message)
    );
    wrapped.cause = err;
    wrapped.code = err.code;
    throw wrapped;
  }
}

/**
 * Policy-String aus "netsh advfirewall show <profil> firewallpolicy" lesen.
 * Die Werte (BlockInbound,AllowOutbound …) sind nicht lokalisiert, die
 * Beschriftungen schon — deshalb wird nur nach den Werten gesucht.
 * @returns {string|null} z.B. "blockinbound,allowoutbound"
 */
function parsePolicyOutput(stdout) {
  const m = String(stdout || '').match(POLICY_RE);
  if (!m) return null;
  return `${m[1].toLowerCase()},${m[2].toLowerCase()}`;
}

function isValidPolicyValue(value) {
  if (typeof value !== 'string') return false;
  const [inbound, outbound, rest] = value.split(',');
  return rest === undefined && INBOUND_POLICIES.includes(inbound) && OUTBOUND_POLICIES.includes(outbound);
}

function isValidPolicyMap(policy) {
  return !!policy && typeof policy === 'object' && PROFILES.every(p => isValidPolicyValue(policy[p]));
}

function validatePortStrict(val) {
  const s = String(val);
  if (!/^\d{1,5}$/.test(s)) throw new Error(`Ungültiger Port: ${val}`);
  const n = Number(s);
  if (n < 1 || n > 65535) throw new Error(`Port außerhalb des Bereichs: ${val}`);
  return String(n);
}

/** Regex für genau die Regelnamen "<prefix>_<Name>" */
function ruleNameRe(prefix) {
  if (!/^[A-Za-z0-9_]+$/.test(prefix)) throw new Error(`Ungültiges Regelpräfix: ${prefix}`);
  return new RegExp(`^${prefix}_[A-Za-z0-9_]+$`);
}

function defaultStateFile() {
  try {
    const electron = require('electron');
    if (electron && electron.app && typeof electron.app.getPath === 'function') {
      return path.join(electron.app.getPath('userData'), STATE_FILE_NAME);
    }
  } catch { /* nicht unter Electron (Tests) */ }
  return null;
}

class KillSwitch {
  /**
   * @param {object} log - electron-log kompatibler Logger
   * @param {object} options
   * @param {'pro'|'community'} options.edition - Edition der App (Pflicht).
   *   Daraus wird das Regelpräfix abgeleitet (editions.killSwitchRulePrefix).
   * @param {Function} [options.otherEditionPresent] - async () => boolean;
   *   Standard: editions.isOtherEditionPresent(edition). Entscheidet, ob
   *   Altregeln "GateControl_KS_*" entfernt werden dürfen (für Tests).
   * @param {string|null} [options.stateFile] - Pfad der Zustandsdatei.
   *   Standard: <userData>/killswitch-state.json (unter Electron).
   *   null deaktiviert die Persistenz.
   * @param {Function} [options.netsh] - async (args[]) => { stdout } (für Tests)
   * @param {Function} [options.dnsLookup] - wie dns.promises.lookup (für Tests)
   * @param {Function} [options.networkInterfaces] - wie os.networkInterfaces (für Tests)
   */
  constructor(log, options = {}) {
    this.log = log;
    this.edition = editions.getEdition(options.edition).id;
    this.rulePrefix = editions.killSwitchRulePrefix(this.edition);
    this._ruleNameRe = ruleNameRe(this.rulePrefix);
    this._legacyRuleNameRe = ruleNameRe(LEGACY_RULE_PREFIX);
    this._otherEditionPresent = options.otherEditionPresent ||
      (() => editions.isOtherEditionPresent(this.edition));
    this.enabled = false;
    this._savedPolicy = null;
    this._localSubnetRuleNames = [];
    this._createdRules = [];
    this._netsh = options.netsh || runNetsh;
    this._dnsLookup = options.dnsLookup || ((host, opts) => dns.lookup(host, opts));
    this._networkInterfaces = options.networkInterfaces || (() => os.networkInterfaces());
    this._stateFileOption = options.stateFile;
    this._queue = Promise.resolve();
  }

  // ── Öffentliche API ─────────────────────────────────────────

  /**
   * Kill-Switch aktivieren
   */
  enable(configPath) {
    return this._serialize(() => this._enable(configPath));
  }

  /**
   * Kill-Switch deaktivieren: gesicherte Policy wiederherstellen, alle
   * GateControl-Regeln löschen. Wirft, wenn etwas davon fehlschlägt —
   * der persistierte Zustand bleibt dann erhalten, damit ein späterer
   * Aufruf (oder der nächste App-Start) es erneut versucht.
   */
  disable() {
    return this._serialize(() => this._disable());
  }

  /**
   * Beim App-Start aufrufen: erkennt Reste eines nicht sauber beendeten
   * Kill-Switch (Zustandsdatei oder verwaiste Regeln) und räumt sie auf.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.keepActive=false] - true nur wenn die Einstellung
   *   an ist UND der Tunnel tatsächlich läuft; dann wird der Zustand
   *   übernommen statt aufgeräumt.
   * @returns {Promise<'none'|'kept'|'cleaned'>}
   */
  recoverStaleState({ keepActive = false } = {}) {
    return this._serialize(async () => {
      if (this.enabled) return 'kept';

      const state = await this._loadState();
      let leftovers = [];
      try {
        leftovers = await this._listRemovableRuleNames();
      } catch (err) {
        this.log.error('Kill-switch: firewall rules could not be listed:', err.message);
      }

      if (!state && leftovers.length === 0) return 'none';

      if (keepActive && state && state.savedPolicy) {
        this._savedPolicy = state.savedPolicy;
        this._createdRules = state.rules || [];
        this.enabled = true;
        this.log.info('Kill-switch state from previous session adopted (tunnel is up)');
        return 'kept';
      }

      this.log.warn(`Stale kill-switch state found (state file: ${state ? 'yes' : 'no'}, leftover rules: ${leftovers.length}) — cleaning up`);
      await this._disable({ force: true });
      return 'cleaned';
    });
  }

  /**
   * Prüft ob Kill-Switch aktiv ist (inkl. Reste einer früheren Sitzung)
   */
  async isActive() {
    if (this.enabled) return true;
    if (await this._loadState()) return true;
    try {
      const { stdout } = await this._netsh(['advfirewall', 'firewall', 'show', 'rule',
        `name=${this.rulePrefix}_Allow_WG_Endpoint`]);
      return String(stdout || '').includes(this.rulePrefix);
    } catch {
      return false;
    }
  }

  // ── Ablauf ──────────────────────────────────────────────────

  /** Operationen nacheinander ausführen (Toggle + Connect + Recovery) */
  _serialize(fn) {
    const run = this._queue.then(fn, fn);
    this._queue = run.catch(() => {});
    return run;
  }

  async _enable(configPath) {
    if (this.enabled) {
      this.log.debug('Kill-switch already active');
      return;
    }

    this.log.info('Enabling kill-switch...');

    const config = await fs.readFile(configPath, 'utf-8');

    // Fail-closed: Config validieren, bevor irgendetwas an der Firewall
    // geändert wird.
    const validation = validateWgConfig(config);
    if (!validation.ok) {
      this.log.error('Kill-switch aborted — invalid WireGuard config: ' + validation.errors.join(', '));
      throw new Error('Invalid WireGuard config: ' + validation.errors.join(', '));
    }
    if (validation.warnings && validation.warnings.length > 0) {
      this.log.warn(`WireGuard config warnings: ${validation.warnings.join(', ')}`);
    }

    let endpoint = null;
    let vpnSubnet = null;
    let vpnLocalIp = null;
    try {
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

    const endpointPort = validatePortStrict(endpoint.port);
    const endpointIps = await this._resolveEndpoint(endpoint);
    const endpointRemote = endpointIps.join(',');

    // Gesicherte Policy bestimmen. Liegt noch ein Zustand aus einer
    // abgestürzten Sitzung vor, ist die aktuelle Policy bereits
    // "blockoutbound" — dann gilt die damals gesicherte Policy.
    const staleState = await this._loadState();
    let savedPolicy = staleState && staleState.savedPolicy;
    if (!savedPolicy) {
      savedPolicy = await this._getCurrentPolicy();
      savedPolicy = await this._repairPolicyIfLeftover(savedPolicy);
    }
    this._savedPolicy = savedPolicy;

    try {
      await this._removeAllRules(staleState);

      this._createdRules = [];
      // Zustand VOR jeder Firewall-Änderung persistieren
      await this._writeState({ savedPolicy, rules: [] });

      // WICHTIG: Alle Allow-Regeln ZUERST erstellen, DANN Block-Policy setzen.
      // Verhindert Race Condition: Ohne Regeln würde Block-Policy den
      // WireGuard-Tunnel sofort unterbrechen (Keepalives geblockt → Tunnel stirbt).

      // 1. ALLOW: WireGuard Endpoint (UDP zum VPN-Server) — ZUERST!
      await this._addRule({
        name: `${this.rulePrefix}_Allow_WG_Endpoint`,
        dir: 'out', action: 'allow', protocol: 'udp',
        remoteip: endpointRemote, remoteport: endpointPort,
      });

      // 1b. ALLOW: Eingehend vom WireGuard Endpoint (UDP-Antworten)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_WG_Endpoint_In`,
        dir: 'in', action: 'allow', protocol: 'udp',
        remoteip: endpointRemote, remoteport: endpointPort,
      });

      // 2. ALLOW: GateControl API (TCP/HTTPS zum Server)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_API`,
        dir: 'out', action: 'allow', protocol: 'tcp',
        remoteip: endpointRemote, remoteport: '443',
      });

      // 3. ALLOW: Allen ausgehenden Traffic von der lokalen VPN-IP
      //     (erlaubt Internet-Traffic durch den WireGuard-Tunnel)
      if (vpnLocalIp) {
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Out`,
          dir: 'out', action: 'allow', localip: vpnLocalIp,
        });
      }

      if (vpnSubnet) {
        // 4. ALLOW: VPN-Subnetz
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_Subnet`,
          dir: 'out', action: 'allow', remoteip: vpnSubnet,
        });
        // 5. ALLOW: DNS über VPN (UDP/TCP Port 53 im VPN-Subnetz)
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_DNS`,
          dir: 'out', action: 'allow', protocol: 'udp', remoteip: vpnSubnet, remoteport: '53',
        });
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_DNS_TCP`,
          dir: 'out', action: 'allow', protocol: 'tcp', remoteip: vpnSubnet, remoteport: '53',
        });
        // 6. ALLOW: Eingehender Traffic vom VPN-Subnetz
        await this._addRule({
          name: `${this.rulePrefix}_Allow_VPN_In`,
          dir: 'in', action: 'allow', remoteip: vpnSubnet,
        });
      }

      // 7. ALLOW: Loopback
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback`,
        dir: 'out', action: 'allow', remoteip: '127.0.0.0/8',
      });
      await this._addRule({
        name: `${this.rulePrefix}_Allow_Loopback_In`,
        dir: 'in', action: 'allow', remoteip: '127.0.0.0/8',
      });

      // 8. ALLOW: Lokales Netzwerk (private Subnetze)
      for (const subnet of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
        const suffix = subnet.replace(/[./]/g, '_');
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_${suffix}`,
          dir: 'out', action: 'allow', remoteip: subnet,
        });
        await this._addRule({
          name: `${this.rulePrefix}_Allow_LAN_In_${suffix}`,
          dir: 'in', action: 'allow', remoteip: subnet,
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
        await this._addRule({ name: outName, dir: 'out', action: 'allow', remoteip: subnet });
        await this._addRule({ name: inName, dir: 'in', action: 'allow', remoteip: subnet });
        this.log.info(`Physical subnet allowed: ${subnet}`);
      }

      // 10. ALLOW: DHCP (Anfrage raus, Antwort rein)
      await this._addRule({
        name: `${this.rulePrefix}_Allow_DHCP`,
        dir: 'out', action: 'allow', protocol: 'udp', localport: '68', remoteport: '67',
      });
      await this._addRule({
        name: `${this.rulePrefix}_Allow_DHCP_In`,
        dir: 'in', action: 'allow', protocol: 'udp', localport: '68', remoteport: '67',
      });

      // Regelliste persistieren, bevor die Block-Policy greift
      await this._writeState({ savedPolicy, rules: this._createdRules });

      // JETZT Block-Policy setzen — alle Regeln sind bereits aktiv
      await this._setPolicy(this._blockPolicyFor(savedPolicy));
      this.log.info('Firewall default policy set to block');

      this.enabled = true;
      this.log.info('Kill-switch enabled');
    } catch (err) {
      this.log.error('Kill-switch activation failed:', err.message);
      try {
        await this._disable({ force: true });
      } catch (rollbackErr) {
        this.log.error('Kill-switch rollback failed:', rollbackErr.message);
        err.message += ` (Rollback fehlgeschlagen: ${rollbackErr.message})`;
      }
      throw err;
    }
  }

  async _disable({ force = false } = {}) {
    const state = await this._loadState();
    const savedPolicy = this._savedPolicy || (state && state.savedPolicy) || null;

    if (!force && !this.enabled && !state) {
      // Nichts von uns aktiv — nur evtl. verwaiste Regeln entfernen,
      // die Policy des Benutzers bleibt unangetastet.
      let leftovers = [];
      try { leftovers = await this._listRemovableRuleNames(); } catch (err) {
        this.log.warn('Kill-switch: firewall rules could not be listed:', err.message);
      }
      if (leftovers.length === 0) {
        this.log.debug('Kill-switch not active — nothing to disable');
        return;
      }
    }

    this.log.info('Disabling kill-switch...');
    const errors = [];

    try {
      if (savedPolicy) {
        await this._setPolicy(savedPolicy);
        this.log.info('Firewall default policy restored');
      } else {
        // Keine gesicherte Policy (z.B. Absturz einer alten Version):
        // nur Profile mit "blockoutbound" auf "allowoutbound" zurücksetzen,
        // Eingangs-Policy unverändert lassen.
        const current = await this._getCurrentPolicy();
        const repaired = await this._repairPolicyIfLeftover(current, { assumeLeftover: true });
        if (PROFILES.some(p => repaired[p] !== current[p])) {
          await this._setPolicy(repaired);
          this.log.warn('Firewall policy repaired without saved state (outbound set to allow)');
        }
      }
    } catch (err) {
      errors.push(err);
    }

    try {
      await this._removeAllRules(state);
    } catch (err) {
      errors.push(err);
    }

    if (errors.length > 0) {
      const msg = errors.map(e => e.message).join('; ');
      this.log.error('Kill-switch could not be fully disabled:', msg);
      throw new Error(`Kill-Switch konnte nicht vollständig deaktiviert werden: ${msg}`);
    }

    await this._clearState();
    this.enabled = false;
    this._savedPolicy = null;
    this._createdRules = [];
    this._localSubnetRuleNames = [];
    this.log.info('Kill-switch disabled');
  }

  async _resolveEndpoint(endpoint) {
    let ips;
    if (endpoint.needsResolve) {
      try {
        const res = await this._dnsLookup(endpoint.host, { family: 4, all: true });
        ips = (Array.isArray(res) ? res : [res]).map(r => (typeof r === 'string' ? r : r.address));
        this.log.info(`Kill-switch endpoint resolved: ${endpoint.host} -> ${ips.join(', ')}`);
      } catch (err) {
        this.log.error(`Kill-switch DNS resolution failed for ${endpoint.host}: ${err.message}`);
        throw new Error(`Kill-Switch: DNS-Auflösung für Endpoint ${endpoint.host} fehlgeschlagen`);
      }
    } else {
      ips = [endpoint.host];
    }
    ips = [...new Set(ips)];
    if (ips.length === 0) throw new Error(`Kill-Switch: Endpoint ${endpoint.host} ohne IPv4-Adresse`);
    for (const ip of ips) {
      validateIp(ip);
      if (ip === '0.0.0.0' || ip === '255.255.255.255') {
        throw new Error(`Kill-Switch: ungültige Endpoint-Adresse ${ip}`);
      }
    }
    return ips;
  }

  // ── Firewall-Policy ─────────────────────────────────────────

  /**
   * Aktuelle Firewall-Policy pro Profil abfragen.
   * @returns {Promise<{domain:string, private:string, public:string}>}
   */
  async _getCurrentPolicy() {
    const policy = {};
    for (const profile of PROFILES) {
      const { stdout } = await this._netsh(['advfirewall', 'show', `${profile}profile`, 'firewallpolicy']);
      const value = parsePolicyOutput(stdout);
      if (!value) {
        throw new Error(`Kill-Switch: Firewall-Policy für Profil "${profile}" konnte nicht gelesen werden`);
      }
      policy[profile] = value;
    }
    return policy;
  }

  /**
   * Policy pro Profil setzen. Versucht alle Profile und wirft danach
   * gesammelt, damit ein fehlschlagendes Profil die anderen nicht blockiert.
   */
  async _setPolicy(policy) {
    if (!isValidPolicyMap(policy)) {
      throw new Error('Kill-Switch: ungültige Firewall-Policy');
    }
    const errors = [];
    for (const profile of PROFILES) {
      try {
        await this._netsh(['advfirewall', 'set', `${profile}profile`, 'firewallpolicy', policy[profile]]);
      } catch (err) {
        errors.push(`${profile}: ${err.message}`);
      }
    }
    if (errors.length > 0) {
      throw new Error(`Firewall-Policy konnte nicht gesetzt werden (${errors.join('; ')})`);
    }
  }

  /** Block-Policy ableiten; "blockinboundalways" des Benutzers bleibt erhalten. */
  _blockPolicyFor(savedPolicy) {
    const block = {};
    for (const profile of PROFILES) {
      const inbound = savedPolicy[profile].split(',')[0];
      block[profile] = `${inbound === 'blockinboundalways' ? 'blockinboundalways' : 'blockinbound'},blockoutbound`;
    }
    return block;
  }

  /**
   * Wenn noch GateControl-Kill-Switch-Regeln vorhanden sind (Absturz einer
   * Version ohne Zustandsdatei), stammt ein "blockoutbound" fast sicher von
   * einem GateControl-Kill-Switch — dann gilt für das Profil
   * "allowoutbound" als ursprüngliche Policy. Als Indiz zählen Regeln
   * JEDER Edition und die Altregeln: Ist z.B. der Kill-Switch der anderen
   * Edition aktiv, darf dessen "blockoutbound" nicht als Policy des
   * Benutzers gesichert werden (sonst bliebe der PC nach dem Deaktivieren
   * beider Kill-Switches offline).
   */
  async _repairPolicyIfLeftover(policy, { assumeLeftover = false } = {}) {
    if (!PROFILES.some(p => policy[p].endsWith(',blockoutbound'))) return policy;
    let leftover = assumeLeftover;
    if (!leftover) {
      try {
        leftover = (await this._scanRuleNames()).all.length > 0;
      } catch {
        leftover = false;
      }
    }
    if (!leftover) return policy;
    const repaired = {};
    for (const profile of PROFILES) {
      const [inbound, outbound] = policy[profile].split(',');
      repaired[profile] = outbound === 'blockoutbound' ? `${inbound},allowoutbound` : policy[profile];
    }
    this.log.warn('Leftover kill-switch rules found without saved state — assuming outbound was allowed');
    return repaired;
  }

  // ── Regeln ──────────────────────────────────────────────────

  /**
   * Firewall-Regel hinzufügen (alle Werte validiert)
   */
  async _addRule({ name, dir, action, protocol, remoteip, remoteport, localip, localport }) {
    if (!this._ruleNameRe.test(name)) throw new Error(`Ungültiger Regelname: ${name}`);
    if (!['in', 'out'].includes(dir)) throw new Error(`Ungültige Richtung: ${dir}`);
    if (action !== 'allow') throw new Error(`Ungültige Aktion: ${action}`);
    const proto = protocol || 'any';
    if (!['any', 'tcp', 'udp'].includes(proto)) throw new Error(`Ungültiges Protokoll: ${protocol}`);

    const args = ['advfirewall', 'firewall', 'add', 'rule',
      `name=${name}`,
      `dir=${dir}`,
      `action=${action}`,
      `protocol=${proto}`,
    ];

    if (localip) {
      validateIp(localip);
      args.push(`localip=${localip}`);
    }
    if (remoteip) {
      for (const part of String(remoteip).split(',')) {
        if (part.includes('/')) validateCidr(part);
        else validateIp(part);
      }
      args.push(`remoteip=${remoteip}`);
    }
    if (remoteport) {
      args.push(`remoteport=${validatePortStrict(remoteport)}`);
    }
    if (localport) {
      args.push(`localport=${validatePortStrict(localport)}`);
    }

    args.push('enable=yes');

    this.log.debug(`Firewall rule: netsh ${args.join(' ')}`);
    await this._netsh(args);
    if (!this._createdRules.includes(name)) this._createdRules.push(name);
  }

  /**
   * Alle Kill-Switch-Regeln aufgeteilt nach Herkunft:
   * own = eigenes Präfix, legacy = altes gemeinsames Präfix,
   * all = zusätzlich die Regeln anderer Editionen.
   */
  async _scanRuleNames() {
    const { stdout } = await this._netsh(['advfirewall', 'firewall', 'show', 'rule', 'name=all']);
    const all = [...new Set(String(stdout || '').match(ANY_KS_RULE_SCAN_RE) || [])];
    return {
      all,
      own: all.filter(n => this._ruleNameRe.test(n)),
      legacy: all.filter(n => this._legacyRuleNameRe.test(n)),
    };
  }

  /** Namen der vorhandenen Regeln dieser Edition */
  async _listRuleNames() {
    return (await this._scanRuleNames()).own;
  }

  /**
   * Dürfen Altregeln "GateControl_KS_*" gelöscht werden?
   *
   * Die Altregeln beider Editionen hießen identisch und tragen kein
   * program=, sind also keiner App zuzuordnen. Sie werden deshalb nur
   * gelöscht, wenn keine andere Edition installiert ist oder läuft — dann
   * können sie nur von dieser App stammen. Ist eine andere Edition
   * vorhanden (oder lässt sich das nicht feststellen), bleiben sie stehen:
   * Sie könnten zu deren aktivem Kill-Switch (Altversion) gehören, und
   * ohne sie würde deren Block-Policy den PC komplett vom Netz trennen.
   * Die übrig bleibenden Allow-Regeln sind dagegen harmlos.
   */
  async _mayRemoveLegacyRules() {
    let present;
    try {
      present = await this._otherEditionPresent();
    } catch (err) {
      this.log.warn('Kill-switch: other GateControl edition could not be detected:', err && err.message);
      present = true;
    }
    if (present !== false) {
      this.log.warn(`Kill-switch: legacy rules "${LEGACY_RULE_PREFIX}_*" left in place — another GateControl edition is installed or running`);
      return false;
    }
    return true;
  }

  /** Eigene Regeln plus Altregeln, sofern diese gelöscht werden dürfen */
  async _listRemovableRuleNames() {
    const { own, legacy } = await this._scanRuleNames();
    if (legacy.length > 0 && await this._mayRemoveLegacyRules()) return [...own, ...legacy];
    return own;
  }

  _knownRuleNames() {
    const p = this.rulePrefix;
    return [
      `${p}_Allow_Loopback`, `${p}_Allow_Loopback_In`,
      `${p}_Allow_WG_Endpoint`, `${p}_Allow_WG_Endpoint_In`,
      `${p}_Allow_API`,
      `${p}_Allow_VPN_Subnet`, `${p}_Allow_VPN_Out`,
      `${p}_Allow_VPN_DNS`, `${p}_Allow_VPN_DNS_TCP`, `${p}_Allow_VPN_In`,
      `${p}_Allow_DHCP`, `${p}_Allow_DHCP_In`,
      `${p}_Allow_LAN_10_0_0_0_8`, `${p}_Allow_LAN_172_16_0_0_12`, `${p}_Allow_LAN_192_168_0_0_16`,
      `${p}_Allow_LAN_In_10_0_0_0_8`, `${p}_Allow_LAN_In_172_16_0_0_12`, `${p}_Allow_LAN_In_192_168_0_0_16`,
      // Regeln älterer Versionen
      `${p}_Block_All_Out`, `${p}_Block_All_In`,
    ];
  }

  /**
   * Alle Kill-Switch-Regeln dieser Edition entfernen (per Präfix gefunden),
   * dazu Altregeln, sofern _mayRemoveLegacyRules() es erlaubt.
   * Regeln anderer Editionen werden nie angefasst.
   * Wirft, wenn danach noch zu löschende Regeln vorhanden sind.
   */
  async _removeAllRules(state = null) {
    let listed = null;
    try {
      listed = await this._listRemovableRuleNames();
    } catch (err) {
      this.log.error('Kill-switch: firewall rules could not be listed, deleting known names:', err.message);
    }

    let names;
    if (listed) {
      names = listed;
    } else {
      names = [...new Set([
        ...this._knownRuleNames(),
        ...(this._localSubnetRuleNames || []),
        ...(this._createdRules || []),
        ...((state && state.rules) || []),
      ])];
    }
    const removingLegacy = names.some(n => this._legacyRuleNameRe.test(n));
    names = names.filter(n => this._ruleNameRe.test(n) || (listed && this._legacyRuleNameRe.test(n)));
    if (names.length === 0) return;

    const failures = [];
    for (const name of names) {
      try {
        await this._netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]);
      } catch (err) {
        failures.push({ name, err });
      }
    }

    if (!listed) {
      // Ohne Liste ist "Regel nicht vorhanden" nicht von echten Fehlern zu
      // unterscheiden — nur protokollieren.
      if (failures.length > 0) {
        this.log.debug(`Kill-switch: ${failures.length} rule deletions reported errors (rules may not exist)`);
      }
      return;
    }

    let remaining;
    try {
      const scan = await this._scanRuleNames();
      remaining = removingLegacy ? [...scan.own, ...scan.legacy] : scan.own;
    } catch (err) {
      this.log.error('Kill-switch: rule removal could not be verified:', err.message);
      return;
    }
    if (remaining.length > 0) {
      const detail = failures.map(f => `${f.name}: ${f.err.message}`).join('; ');
      throw new Error(`Firewall-Regeln konnten nicht entfernt werden: ${remaining.join(', ')}${detail ? ` (${detail})` : ''}`);
    }
  }

  // ── Zustandsdatei ───────────────────────────────────────────

  _stateFilePath() {
    if (this._stateFileOption === undefined) this._stateFileOption = defaultStateFile();
    return this._stateFileOption || null;
  }

  /**
   * @returns {Promise<null|{savedPolicy: object|null, rules: string[]}>}
   *   null = keine Zustandsdatei; eine unlesbare Datei gilt als "aktiv,
   *   Policy unbekannt", damit trotzdem aufgeräumt wird.
   */
  async _loadState() {
    const file = this._stateFilePath();
    if (!file) return null;
    let raw;
    try {
      raw = await fs.readFile(file, 'utf-8');
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      this.log.error('Kill-switch state file could not be read:', err.message);
      return { savedPolicy: null, rules: [] };
    }
    try {
      const data = JSON.parse(raw);
      return {
        savedPolicy: isValidPolicyMap(data && data.savedPolicy) ? data.savedPolicy : null,
        rules: Array.isArray(data && data.rules)
          ? data.rules.filter(n => typeof n === 'string' && this._ruleNameRe.test(n))
          : [],
      };
    } catch (err) {
      this.log.error('Kill-switch state file is corrupt:', err.message);
      return { savedPolicy: null, rules: [] };
    }
  }

  async _writeState({ savedPolicy, rules }) {
    const file = this._stateFilePath();
    if (!file) return;
    const data = {
      version: STATE_VERSION,
      engaged: true,
      savedPolicy,
      rules: [...rules],
      updatedAt: new Date().toISOString(),
    };
    await fs.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf-8');
    await fs.rename(tmp, file);
  }

  async _clearState() {
    const file = this._stateFilePath();
    if (!file) return;
    try {
      await fs.unlink(file);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        this.log.warn('Kill-switch state file could not be removed:', err.message);
      }
    }
  }

  // ── Netzwerk-Helfer ─────────────────────────────────────────

  /**
   * Lokale Netzwerk-Subnetze ermitteln (physische Interfaces, nicht VPN)
   * Gibt CIDR-Notationen zurück für alle nicht-internen, nicht-privaten Subnetze
   */
  _getLocalSubnets(vpnLocalIp) {
    const subnets = [];
    const interfaces = this._networkInterfaces ? this._networkInterfaces() : os.networkInterfaces();
    const privateRanges = [
      { start: 0x0A000000, end: 0x0AFFFFFF },   // 10.0.0.0/8
      { start: 0xAC100000, end: 0xAC1FFFFF },   // 172.16.0.0/12
      { start: 0xC0A80000, end: 0xC0A8FFFF },   // 192.168.0.0/16
      { start: 0x7F000000, end: 0x7FFFFFFF },   // 127.0.0.0/8
      { start: 0xA9FE0000, end: 0xA9FEFFFF },   // 169.254.0.0/16 (APIPA)
    ];

    for (const [, addrs] of Object.entries(interfaces || {})) {
      for (const addr of addrs || []) {
        if (addr.family !== 'IPv4' && addr.family !== 4) continue;
        if (addr.internal) continue;
        if (addr.address === vpnLocalIp) continue;
        if (!IPV4_RE.test(addr.address || '') || !IPV4_RE.test(addr.netmask || '')) continue;

        const ipNum = this._ipToNum(addr.address);
        const isPrivate = privateRanges.some(r => ipNum >= r.start && ipNum <= r.end);
        if (isPrivate) continue; // Already covered by LAN rules / not routable

        // Calculate subnet from IP and netmask
        const maskNum = this._ipToNum(addr.netmask);
        let prefix = this._maskToPrefix(maskNum);

        // Öffentliche Subnetze auf /24 begrenzen.
        // Windows/OVH meldet oft /8 für öffentliche IPs — das würde
        // Millionen von IPs außerhalb des VPN erlauben und den
        // Kill-Switch wirkungslos machen.
        if (prefix < 24) prefix = 24;
        const cappedMask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const networkNum = (ipNum & cappedMask) >>> 0;
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
    // Hostname (RFC 1123) oder IPv4-Literal — nichts anderes wird übernommen
    const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;

    for (const line of content.split('\n')) {
      const trimmed = line.trim();

      const epMatch = trimmed.match(/^Endpoint\s*=\s*(.+):(\d+)$/i);
      if (epMatch) {
        const host = epMatch[1].trim();
        const port = epMatch[2].trim();
        if (PORT_RE.test(port) && (IPV4_RE.test(host) || HOST_RE.test(host))) {
          // Accept both IP literals and hostnames — hostname resolution
          // happens in enable() before the endpoint is used for firewall rules.
          endpoint = { host, port, needsResolve: !IPV4_RE.test(host) };
        }
      }

      const addrMatch = trimmed.match(/^Address\s*=\s*(.+)$/i);
      if (addrMatch) {
        const cidr = addrMatch[1].trim().split(',')[0].trim();
        const parts = cidr.split('/');
        if (parts.length === 2 && IPV4_RE.test(parts[0]) && /^\d{1,2}$/.test(parts[1])) {
          vpnLocalIp = parts[0];
          let mask = parseInt(parts[1], 10);
          if (mask >= 0 && mask <= 32) {
            // /32 ist eine Host-Adresse, nicht das VPN-Subnetz.
            // WireGuard vergibt /32 an Clients, das Subnetz ist aber /24.
            // Ohne Erweiterung würden DNS-Regeln nur die eigene IP abdecken,
            // nicht den DNS-Server (z.B. 10.8.0.1).
            if (mask > 24) mask = 24;
            const maskNum = mask === 0 ? 0 : (0xFFFFFFFF << (32 - mask)) >>> 0;
            const network = (this._ipToNum(parts[0]) & maskNum) >>> 0;
            vpnSubnet = `${this._numToIp(network)}/${mask}`;
          }
        }
      }
    }

    return { endpoint, vpnSubnet, vpnLocalIp };
  }
}

KillSwitch.parsePolicyOutput = parsePolicyOutput;
KillSwitch.STATE_FILE_NAME = STATE_FILE_NAME;
KillSwitch.LEGACY_RULE_PREFIX = LEGACY_RULE_PREFIX;
KillSwitch.rulePrefixFor = editions.killSwitchRulePrefix;

module.exports = KillSwitch;
