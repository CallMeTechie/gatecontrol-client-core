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
 * - add(namespace, nameserver): idempotent — removes any pre-existing
 *   GateControl rule for the namespace, then adds the fresh one
 * - remove(namespace): best-effort cleanup on disconnect
 * - All PowerShell calls are wrapped with timeouts so a hung DNS service
 *   can't block the tunnel lifecycle. Errors are logged but never thrown;
 *   NRPT is a best-effort enhancement, not a requirement for the VPN to
 *   come up.
 *
 * Requires Admin rights (Pro/Community run elevated via NSIS).
 */
class DnsPolicy {
  constructor(log) {
    this.log = log || console;
    this.applied = new Set();
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
    const ns = namespace.startsWith('.') ? namespace : '.' + namespace;
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
    this.applied.add(ns);
    this.log.info('NRPT rule installed: ' + ns + ' -> ' + nameServer);
  }

  /**
   * Remove the NRPT rule for a namespace previously installed by this client.
   * Safe to call even if no rule exists.
   */
  async remove(namespace) {
    if (!namespace) return;
    const ns = namespace.startsWith('.') ? namespace : '.' + namespace;
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
  async removeAll() {
    // Match both 'GateControl:*' (current) and bare 'GateControl' (legacy
    // <=1.16) — the bare tag wouldn't match a 'GateControl:*' wildcard
    // and would survive uninstall/quit otherwise.
    const res = await this._runPs(
      "Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'GateControl*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
    );
    if (!res.err) this.applied.clear();
  }
}

module.exports = DnsPolicy;
