'use strict';

const { execFile } = require('node:child_process');

/**
 * DnsPolicy — Windows NRPT (Name Resolution Policy Table) helper.
 *
 * Why this exists
 * ---------------
 * WireGuard on Windows sets `DNS = 10.8.0.1` on the wg interface, but
 * Windows fans unqualified queries out to ALL configured DNS servers and
 * uses whichever answers first. A public resolver will (correctly) say
 * NXDOMAIN for "desktop-xxx.gc.internal" before the VPN-side dnsmasq
 * answers, and the negative result gets cached — so the FQDN never
 * resolves. NRPT pins specific namespaces to specific resolvers, which
 * bypasses the race entirely.
 *
 * Behavior
 * --------
 * - sync(rules): the rules of this client become exactly `rules` — one per
 *   zone the server answers (GET /client/config → internalDns.domains).
 *   Missing ones are added, own ones no longer listed are removed. Rules of
 *   other software (no GateControl comment) are never touched.
 * - add(namespace, nameserver): idempotent — removes any pre-existing
 *   GateControl rule for the namespace, then adds the fresh one
 * - remove(namespace): best-effort cleanup of one rule
 * - removeAll(): cleanup on disconnect / quit
 * - All PowerShell calls are wrapped with timeouts so a hung DNS service
 *   can't block the tunnel lifecycle. Errors are logged but never thrown;
 *   NRPT is a best-effort enhancement, not a requirement for the VPN to
 *   come up.
 *
 * Requires Admin rights (Pro/Community run elevated via NSIS).
 */
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
// Only for servers that do not report their zone (GateControl < 1.195); every
// other zone comes from the server.
const LEGACY = { namespace: '.gc.internal', nameServer: '10.8.0.1' };
// The server answers two zones today; anything far beyond that is not a zone list.
const MAX_ZONES = 8;

/** A zone as it may appear in a PowerShell command line: a plain DNS name, lowercased; else null. */
function cleanZone(zone) {
  if (typeof zone !== 'string' || zone.length > 253 || !DOMAIN_RE.test(zone)) return null;
  return zone.toLowerCase();
}


function isIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || ''));
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}

const ipToNum = (ip) => ip.split('.').reduce((n, o) => ((n << 8) | Number(o)) >>> 0, 0);
const numToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

/** Values of `key = a, b` lines in the [Interface] section of a WireGuard config. */
function interfaceValues(wgConfig, key) {
  const out = [];
  let inInterface = false;
  for (const raw of String(wgConfig || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('[')) { inInterface = /^\[interface\]$/i.test(line); continue; }
    if (!inInterface) continue;
    const m = /^([A-Za-z]+)\s*=\s*(.*)$/.exec(line);
    if (m && m[1].toLowerCase() === key) out.push(...m[2].split(',').map((v) => v.trim()).filter(Boolean));
  }
  return out;
}

/**
 * Resolver for a server that does not say which one (GateControl < 1.195):
 * a DNS entry of the tunnel config inside the VPN subnet, else the subnet's
 * first address (the gateway, where the server's dnsmasq listens).
 */
function nameServerFromConfig(wgConfig) {
  const addr = interfaceValues(wgConfig, 'address').map((a) => a.split('/')).find(([ip]) => isIPv4(ip));
  if (!addr) return LEGACY.nameServer;
  // Clients get a /32; the VPN subnet itself is (at least) a /24.
  const mask = Math.min(Number(addr[1] ?? 32), 24);
  const maskNum = mask === 0 ? 0 : (0xFFFFFFFF << (32 - mask)) >>> 0;
  const network = (ipToNum(addr[0]) & maskNum) >>> 0;
  const inSubnet = interfaceValues(wgConfig, 'dns').find((d) => isIPv4(d) && ((ipToNum(d) & maskNum) >>> 0) === network);
  return inSubnet || numToIp(network + 1);
}

class DnsPolicy {
  constructor(log) {
    this.log = log || console;
    // namespace ('.zone') → name server, for the rules this process installed
    this.applied = new Map();
    this._queue = Promise.resolve();
  }

  /** sync() and removeAll() one after the other: a late sync must not re-add what a disconnect removed. */
  _serial(fn) {
    const run = this._queue.then(fn, fn);
    this._queue = run.catch(() => {});
    return run;
  }

  _runPs(script, timeoutMs = 8000) {
    return new Promise((resolve) => {
      execFile('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', script,
      ], { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
        resolve({ err, stdout: String(stdout || '').trim(), stderr: String(stderr || '').trim() });
      });
    });
  }

  /**
   * Ensure Windows routes all queries for *.<namespace> (e.g. ".gc.internal")
   * to the given name server, overriding the default multi-resolver race.
   */
  async add(namespace, nameServer) {
    if (!namespace || !nameServer) return;
    const zone = cleanZone(String(namespace).replace(/^\./, ''));
    // Both end up inside a PowerShell command line.
    if (!zone || !isIPv4(nameServer)) {
      this.log.warn('NRPT rule skipped, invalid namespace or name server');
      return;
    }
    const ns = '.' + zone;
    const comment = 'GateControl:' + ns;

    // Remove any prior rule for this namespace, including:
    //  - exact match on the current comment (re-installs after restart)
    //  - same-namespace rules with any GateControl* comment (catches the
    //    legacy 'GateControl'-without-suffix tag from <=1.16, which
    //    otherwise piles up — one extra row in Get-DnsClientNrptRule per
    //    install)
    await this._runPs(
      "Get-DnsClientNrptRule | Where-Object { $_.Namespace -contains '" + ns + "' -and $_.Comment -like 'GateControl*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
    );

    const addScript = "Add-DnsClientNrptRule -Namespace '" + ns + "' -NameServers '" + nameServer + "' -Comment '" + comment + "'";
    const res = await this._runPs(addScript);
    if (res.err) {
      this.log.warn('NRPT add failed for ' + ns + ': ' + (res.stderr || res.err.message));
      return;
    }
    this.applied.set(ns, nameServer);
    this.log.info('NRPT rule installed: ' + ns + ' -> ' + nameServer);
  }

  /**
   * Remove the NRPT rule for a namespace previously installed by this client.
   * Safe to call even if no rule exists.
   */
  async remove(namespace) {
    if (!namespace) return;
    const zone = cleanZone(String(namespace).replace(/^\./, ''));
    if (!zone) return; // ends up inside a PowerShell command line
    const ns = '.' + zone;
    const comment = 'GateControl:' + ns;
    const res = await this._runPs(
      "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + comment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
    );
    if (res.err) {
      this.log.debug('NRPT remove failed for ' + ns + ': ' + (res.stderr || res.err.message));
      return;
    }
    this.applied.delete(ns);
    this.log.info('NRPT rule removed: ' + ns);
  }

  /**
   * Remove ALL NRPT rules previously installed by this client. Used for
   * crash cleanup and before-quit so leftover rules from a killed process
   * don't silently reroute DNS on the user's next session.
   */
  removeAll() {
    return this._serial(() => this._removeAll());
  }

  async _removeAll() {
    // Match both 'GateControl:*' (current) and bare 'GateControl' (legacy
    // <=1.16) — the bare tag wouldn't match a 'GateControl:*' wildcard
    // and would survive uninstall/quit otherwise.
    const res = await this._runPs(
      "Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'GateControl*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
    );
    if (!res.err) this.applied.clear();
  }

  /**
   * Make the rules of this client exactly `rules` (DnsPolicy.rulesFor): add
   * the missing ones, remove own ones that are no longer listed — the admin
   * can change the zone while the tunnel is up. Only rules with a GateControl
   * comment are looked at.
   *
   * Without `force` nothing is run while the installed rules already match
   * (every config check calls this). `force` on connect: rules left over from
   * a killed process are replaced as well.
   *
   * @param {Array<{ namespace: string, nameServer: string }>} rules
   * @param {{ force?: boolean }} [opts]
   * @returns {Promise<string[]>} namespaces with a rule afterwards
   */
  sync(rules, opts) {
    return this._serial(() => this._sync(rules, opts));
  }

  async _sync(rules, { force = false } = {}) {
    const wanted = new Map();
    for (const rule of Array.isArray(rules) ? rules : []) {
      const zone = cleanZone(String((rule && rule.namespace) || '').replace(/^\./, ''));
      if (!zone || !isIPv4(rule.nameServer)) continue;
      if (wanted.size >= MAX_ZONES) break;
      wanted.set('.' + zone, rule.nameServer);
    }

    const same = wanted.size === this.applied.size
      && [...wanted].every(([ns, server]) => this.applied.get(ns) === server);
    if (same && !force) return [...this.applied.keys()];

    // Own rules for zones that are not wanted any more (also the bare
    // 'GateControl' tag of <=1.16). `keep` holds validated zones only.
    const keep = [...wanted.keys()].map((ns) => "'GateControl:" + ns + "'").join(',');
    const res = await this._runPs(
      '$keep = @(' + keep + "); Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'GateControl*' -and $keep -notcontains $_.Comment } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
    );
    if (res.err) {
      this.log.debug('NRPT cleanup of old zones failed: ' + (res.stderr || res.err.message));
    } else {
      for (const ns of [...this.applied.keys()]) {
        if (!wanted.has(ns)) {
          this.applied.delete(ns);
          this.log.info('NRPT rule removed: ' + ns);
        }
      }
    }

    for (const [ns, server] of wanted) {
      if (force || this.applied.get(ns) !== server) await this.add(ns, server);
    }
    return [...this.applied.keys()];
  }

  /**
   * Whether a rule of this client pins the zone of `name` (a host name such
   * as "laptop.vpn.example.com") to the VPN resolver — only then the name
   * resolves reliably on Windows.
   */
  coversName(name) {
    const host = cleanZone(name);
    if (!host) return false;
    for (const ns of this.applied.keys()) {
      if (host.length > ns.length && host.endsWith(ns)) return true;
    }
    return false;
  }
}

/**
 * Which NRPT rules to install for the peers' hostnames.
 *
 * internalDns is what GET /client/config and /client/config/check reported:
 * { domain, server, domains, primary } from the server's settings, null when
 * its internal DNS is off (no rule), or undefined when unknown (older
 * server, or the config could not be fetched) — then the server default
 * domain and the resolver from the tunnel config.
 *
 * `domains` (GateControl >= 1.271) lists every zone the server answers: one
 * rule each, all to `server`. Without it (older server) the one rule for
 * `domain`, as before. Entries that are not plain DNS names are dropped —
 * they would end up inside a PowerShell command line.
 *
 * @returns {Array<{ namespace: string, nameServer: string }>}
 */
DnsPolicy.rulesFor = function rulesFor({ internalDns, wgConfig } = {}) {
  if (internalDns === null) return [];
  if (internalDns && typeof internalDns === 'object' && isIPv4(internalDns.server)) {
    const zones = [];
    if (Array.isArray(internalDns.domains)) {
      for (const entry of internalDns.domains.slice(0, 4 * MAX_ZONES)) {
        const zone = cleanZone(entry);
        if (zone && !zones.includes(zone)) zones.push(zone);
        if (zones.length >= MAX_ZONES) break;
      }
    }
    if (!zones.length) {
      const zone = cleanZone(internalDns.domain);
      if (zone) zones.push(zone);
    }
    if (zones.length) return zones.map((zone) => ({ namespace: '.' + zone, nameServer: internalDns.server }));
  }
  return [{ namespace: LEGACY.namespace, nameServer: nameServerFromConfig(wgConfig) }];
};

/**
 * The one rule for `internalDns.domain` — what clients installed before the
 * server listed its zones. Kept for callers that have not moved to
 * rulesFor() / sync().
 *
 * @returns {{ namespace: string, nameServer: string } | null}
 */
DnsPolicy.ruleFor = function ruleFor({ internalDns, wgConfig } = {}) {
  if (internalDns === null) return null;
  const single = internalDns && typeof internalDns === 'object'
    ? { domain: internalDns.domain, server: internalDns.server }
    : internalDns;
  return DnsPolicy.rulesFor({ internalDns: single, wgConfig })[0];
};

module.exports = DnsPolicy;
