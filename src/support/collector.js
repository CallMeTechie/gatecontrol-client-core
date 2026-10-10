'use strict';

/**
 * GateControl – Support bundle collector (Core)
 *
 * Builds the diagnostics bundle (schema 1, see gatecontrol
 * docs/feature-support-bundle.md) for "Support-Paket senden":
 *   client  — product, app/core/electron version, OS, arch, locale
 *   tunnel  — connected, since, last handshake age, endpoint, traffic,
 *             kill switch / RDP allow / split tunnel flags
 *   settings — store snapshot WITHOUT secrets (server.apiKey dropped,
 *             everything else redacted)
 *   wireguardConfig — the tunnel config with PrivateKey/PresharedKey masked
 *   network — interfaces (no MAC addresses), DNS servers, route table
 *   logs    — last MAX_LOG_LINES lines of the electron-log file
 *   errors  — the most recent error/warn lines
 *
 * Every string goes through redact.js; the finished object gets one more
 * full redaction pass. Electron-free and dependency-injected so it can be
 * unit-tested.
 */

const os = require('os');
const fs = require('fs');
const dnsModule = require('dns');
const { execFile } = require('child_process');
const { redactText, redactValue, MASK } = require('./redact');

const SCHEMA_VERSION = 1;
const MAX_LOG_LINES = 2000;
const MAX_LOG_READ = 2 * 1024 * 1024;     // read at most the last 2 MB of the log
const MAX_LINE_LENGTH = 2000;
const MAX_ERROR_LINES = 100;
const MAX_TEXT = 64 * 1024;               // WireGuard config / route table
const ERROR_LINE_RE = /\[(error|warn|warning)\]|\b(error|exception|failed|fatal)\b/i;

function truncate(str, max) {
  if (typeof str !== 'string') return str;
  return str.length > max ? str.slice(0, max) + `… [${str.length - max} chars truncated]` : str;
}

/** Last `maxLines` lines of a file (reads at most MAX_LOG_READ bytes from the end). */
async function readTail(file, maxLines = MAX_LOG_LINES) {
  const stat = await fs.promises.stat(file);
  const start = Math.max(0, stat.size - MAX_LOG_READ);
  const fh = await fs.promises.open(file, 'r');
  try {
    const len = stat.size - start;
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, start);
    let text = buf.toString('utf8');
    if (start > 0) {
      const nl = text.indexOf('\n');
      if (nl >= 0) text = text.slice(nl + 1);
    }
    const all = text.split(/\r?\n/).filter((l) => l.trim());
    return { lines: all.slice(-maxLines), totalLines: all.length, truncated: start > 0 || all.length > maxLines };
  } finally {
    await fh.close();
  }
}

function interfacesSummary(netIfs) {
  const out = [];
  for (const [name, addrs] of Object.entries(netIfs || {})) {
    out.push({
      name,
      addresses: (addrs || []).map((a) => ({
        family: a.family === 4 ? 'IPv4' : a.family === 6 ? 'IPv6' : a.family,
        address: a.address,
        cidr: a.cidr || null,
        internal: !!a.internal,
      })),
    });
  }
  return out;
}

function runCommand(execFileFn, cmd, args, timeout = 5000) {
  return new Promise((resolve) => {
    try {
      execFileFn(cmd, args, { timeout, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout) => {
        if (err) return resolve(null);
        resolve(String(stdout || ''));
      });
    } catch {
      resolve(null);
    }
  });
}

function handshakeAgeSec(state, now) {
  const ts = state.handshakeTimestamp;
  if (typeof ts === 'number' && ts > 0) return Math.max(0, Math.floor(now / 1000) - ts);
  if (state.handshake instanceof Date) return Math.max(0, Math.floor((now - state.handshake.getTime()) / 1000));
  return null;
}

/**
 * Settings snapshot without secrets: server.apiKey is dropped (only whether
 * one is set), all other values pass the redactor.
 */
function settingsSnapshot(storeData) {
  const copy = JSON.parse(JSON.stringify(storeData || {}));
  if (copy.server && typeof copy.server === 'object') {
    copy.server.apiKey = copy.server.apiKey ? MASK : '';
  }
  return redactValue(copy);
}

/**
 * Collect a support bundle.
 *
 * @param {object} ctx
 * @param {object} [ctx.app]               - Electron app (getVersion, getLocale)
 * @param {object} [ctx.store]             - electron-store (store.store, store.get)
 * @param {object} [ctx.log]               - electron-log (transports.file.getFile().path)
 * @param {Function} [ctx.getTunnelState]  - () => tunnelState
 * @param {string} [ctx.wgConfigFile]      - path to the WireGuard config
 * @param {object} [ctx.apiClient]         - ApiClient (clientType, clientVersion, clientPlatform)
 * @param {string} [ctx.edition]           - 'pro' | 'community' (falls back to apiClient.clientType)
 * @param {string} [ctx.locale]
 * @param {object} [opts]
 * @param {'user'|'admin_request'} [opts.reason='user']
 * @param {object} [opts.deps]             - test seams: { os, fs, dns, execFile, now, platform, logFile }
 * @returns {Promise<object>}
 */
async function collectSupportBundle(ctx = {}, opts = {}) {
  const deps = opts.deps || {};
  const osM = deps.os || os;
  const dnsM = deps.dns || dnsModule;
  const execFileFn = deps.execFile || execFile;
  const now = deps.now ? deps.now() : Date.now();
  const platform = deps.platform || process.platform;
  const { app, store, log, apiClient } = ctx;
  const notes = [];

  // ── Client ────────────────────────────────────────────────
  let appVersion = null;
  try { appVersion = app && typeof app.getVersion === 'function' ? app.getVersion() : null; } catch { /* ignore */ }
  const client = {
    product: ctx.edition || (apiClient && apiClient.clientType) || null,
    version: appVersion || (apiClient && apiClient.clientVersion) || null,
    coreVersion: require('../../package.json').version,
    platform: (apiClient && apiClient.clientPlatform) || 'windows',
    os: `${osM.type()} ${osM.release()}${typeof osM.version === 'function' ? ` (${osM.version()})` : ''}`,
    arch: osM.arch(),
    locale: ctx.locale || null,
    electron: process.versions.electron || null,
    node: process.versions.node,
    uptimeSec: Math.round(osM.uptime()),
  };

  // ── Tunnel ────────────────────────────────────────────────
  let tunnel = null;
  try {
    const st = (typeof ctx.getTunnelState === 'function' && ctx.getTunnelState()) || {};
    tunnel = {
      connected: !!st.connected,
      connectedSince: st.connectedSince ? new Date(st.connectedSince).toISOString() : null,
      lastHandshakeAgeSec: handshakeAgeSec(st, now),
      handshake: st.handshake instanceof Date ? st.handshake.toISOString() : (st.handshake != null ? String(st.handshake) : null),
      endpoint: st.endpoint || null,
      interface: st.interface || null,
      rxBytes: Number(st.rxBytes) || 0,
      txBytes: Number(st.txBytes) || 0,
      killSwitch: store ? !!store.get('tunnel.killSwitch', false) : null,
      rdpAllow: store ? !!store.get('tunnel.rdpAllow', false) : null,
      splitTunnel: store ? !!store.get('tunnel.splitTunnel', false) : null,
    };
  } catch (err) {
    notes.push(`tunnel: ${err.message}`);
  }

  // ── Settings ──────────────────────────────────────────────
  let settings = null;
  try {
    settings = settingsSnapshot(store ? store.store : {});
  } catch (err) {
    notes.push(`settings: ${err.message}`);
  }

  // ── WireGuard config (redacted) ──────────────────────────
  let wireguardConfig = null;
  if (ctx.wgConfigFile) {
    try {
      wireguardConfig = truncate(redactText(await (deps.fs || fs).promises.readFile(ctx.wgConfigFile, 'utf8')), MAX_TEXT);
    } catch (err) {
      notes.push(`wireguardConfig: ${err.code || err.message}`);
    }
  }

  // ── Network ───────────────────────────────────────────────
  const network = { interfaces: [], dnsServers: [], routes: null };
  try { network.interfaces = interfacesSummary(osM.networkInterfaces()); } catch (err) { notes.push(`interfaces: ${err.message}`); }
  try { network.dnsServers = dnsM.getServers(); } catch (err) { notes.push(`dns: ${err.message}`); }
  const routeCmd = platform === 'win32' ? ['route', ['print', '-4']] : platform === 'darwin' ? ['netstat', ['-rn']] : ['ip', ['route']];
  const routes = await runCommand(execFileFn, routeCmd[0], routeCmd[1]);
  if (routes != null) network.routes = truncate(redactText(routes), MAX_TEXT);
  else notes.push('routes: unavailable');

  // ── Logs + recent errors ─────────────────────────────────
  let logs = { lines: [], totalLines: 0, truncated: false, file: null };
  let errors = [];
  let logFile = deps.logFile || null;
  if (!logFile) {
    try { logFile = log && log.transports && log.transports.file.getFile().path; } catch { /* ignore */ }
  }
  if (logFile) {
    try {
      const tail = await readTail(logFile);
      const lines = tail.lines.map((l) => truncate(redactText(l), MAX_LINE_LENGTH));
      logs = { lines, totalLines: tail.totalLines, truncated: tail.truncated, file: require('path').basename(logFile) };
      errors = lines.filter((l) => ERROR_LINE_RE.test(l)).slice(-MAX_ERROR_LINES);
    } catch (err) {
      notes.push(`logs: ${err.code || err.message}`);
    }
  }

  const bundle = {
    schema: SCHEMA_VERSION,
    createdAt: new Date(now).toISOString(),
    reason: opts.reason === 'admin_request' ? 'admin_request' : 'user',
    client,
    tunnel,
    settings,
    wireguardConfig,
    network,
    logs,
    errors,
    notes,
    redaction: 'client-core-v1',
  };
  // Belt and braces: one more pass over everything.
  return redactValue(bundle);
}

module.exports = {
  collectSupportBundle,
  settingsSnapshot,
  readTail,
  interfacesSummary,
  SCHEMA_VERSION,
  MAX_LOG_LINES,
};
