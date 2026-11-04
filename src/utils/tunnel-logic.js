'use strict';

/**
 * Pure, Electron-free decision logic for the tunnel/portal state machine.
 *
 * Shared by the Pro and Community main processes (formerly one copy per app
 * in src/main/tunnel-logic.js). Unit-tested in test/tunnel-logic.test.js
 * under `node --test` without an Electron runtime.
 */

/**
 * Exponential backoff delay (ms) for the Nth reconnect attempt (0-based),
 * capped so a long outage doesn't grow the wait unboundedly.
 *
 * @param {number} attempt 0-based attempt index
 * @param {{base?: number, factor?: number, cap?: number}} [opts]
 * @returns {number} delay in milliseconds
 */
function reconnectDelay(attempt, { base = 2000, factor = 1.5, cap = 60000 } = {}) {
  return Math.min(base * Math.pow(factor, attempt), cap);
}

/**
 * Whether the portal should auto-open right now. Opens once per
 * *user-initiated* connect: requires a URL, the server's autoOpen flag, and a
 * connectedSince timestamp we have not already opened for. The reconnect path
 * never reaches this (it does not run the connect sequence), so a reconnect —
 * which mints a fresh connectedSince — cannot re-open the browser.
 * When it says yes, the caller opens the portal via createPortalOpener()
 * (utils/portal.js), which fetches a fresh one-time login link first.
 *
 * @param {{portalUrl: ?string, autoOpenPortal: boolean, connectedSince: number, lastOpenedSince: ?number}} s
 * @returns {boolean}
 */
function shouldOpenPortal({ portalUrl, autoOpenPortal, connectedSince, lastOpenedSince }) {
  return Boolean(portalUrl) && autoOpenPortal === true && connectedSince !== lastOpenedSince;
}

/**
 * Durations of the steps of a connect, for the app log:
 *
 *   const steps = connectSteps();
 *   … steps.done('config', 'server') … steps.done('adapter') …
 *   log.info(steps.summary())   // "Connect steps: config 812 ms (server), adapter 640 ms, … total 2391 ms"
 *
 * @param {() => number} [now=Date.now]
 */
function connectSteps(now = Date.now) {
  const start = now();
  let last = start;
  const list = [];
  return {
    /** Ends step `name` (the time since the previous one); `note` e.g. 'local' / 'timeout'. → its ms */
    done(name, note = null) {
      const t = now();
      const ms = Math.max(0, t - last);
      last = t;
      list.push({ name: String(name), ms, ...(note ? { note: String(note) } : {}) });
      return ms;
    },
    steps: () => list.map((x) => ({ ...x })),
    total: () => Math.max(0, now() - start),
    summary(label = 'Connect steps') {
      const parts = list.map((x) => `${x.name} ${x.ms} ms${x.note ? ` (${x.note})` : ''}`);
      return `${label}: ${parts.join(', ')}${parts.length ? ', ' : ''}total ${Math.max(0, now() - start)} ms`;
    },
  };
}

/**
 * Waits for the first WireGuard handshake: asks `getStats()` every `intervalMs` (was 2 s fixed before the first look)
 * until `timeoutMs` → true when it came. A handshake usually takes well under a second.
 */
async function waitForHandshake(getStats, { timeoutMs = 10000, intervalMs = 250, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = Date.now } = {}) {
  const end = now() + timeoutMs;
  for (;;) {
    let stats = null;
    try { stats = await getStats(); } catch { stats = null; }
    if (stats && stats.handshake) return true;
    if (now() >= end) return false;
    await sleep(Math.min(intervalMs, Math.max(0, end - now())));
  }
}

module.exports = { reconnectDelay, shouldOpenPortal, connectSteps, waitForHandshake };
