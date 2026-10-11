/**
 * GateControl – Push control (Core service, notification center phase 5)
 *
 * Servers with control events tell the device over the push stream what it
 * used to find out by polling (contract: gatecontrol
 * docs/feature-notification-center.md, "Vertrag Gerät ↔ Server"):
 *
 *   event: control  (no id, not stored, not acked)
 *     { type: 'policy_changed', policy_version }      → ClientPolicyService.refresh()
 *     { type: 'support_bundle_requested', requested_at } → the support-bundle handler
 *     { type: 'peer_state', enabled }                 → peer disabled: same as peer-info
 *     { type: 'config_changed' }                      → the app's config check
 *   hello.state (on every connect; catches up what happened while offline)
 *     { policy_version, peer_enabled, support_bundle_requested,
 *       support_bundle_requested_at, config_hash }
 *
 * The reactions reuse the existing paths: ClientPolicyService.refresh() /
 * noteVersion(), ConnectionMonitor.supportBundleRequest() (→ sender
 * onServerRequest, prompts once per request) and ConnectionMonitor
 * .peerDisabled() (→ the app's onPeerDisabled, only while the tunnel is
 * monitored), and the app's onConfigChanged (Community: the config/check
 * poll; Pro: config/check + reconnect).
 *
 * Polling stays as the fallback: while the stream is open and the server
 * sent hello.state (PushClient.controlSupported()), the client policy is
 * polled every 30 min instead of `app.configPollInterval`, and the peer-info
 * check of the connection monitor runs every 15 min instead of every 2nd
 * 30-s cycle (the local WireGuard stats check is unchanged). As soon as the
 * stream drops, the normal intervals apply again. Servers without
 * hello.state: nothing changes.
 *
 * Usage (main process, after PushClient, ClientPolicyService, ConnectionMonitor):
 *   const pushControl = new PushControl({ pushClient, clientPolicy, connectionMonitor,
 *     apiClient, log, onConfigChanged: () => checkConfigNow() });
 *   pushControl.start();   // before or after pushClient.start()
 *
 * Events: 'mode' ({ relaxed }) — polling stretched / back to normal (apps
 * can stretch their own polls, e.g. the Community config poll);
 * 'control' (control) after it was handled.
 */

'use strict';

const EventEmitter = require('events');

const DEFAULTS = Object.freeze({
  policyIntervalMs: 30 * 60 * 1000,  // client policy poll while push delivers changes
  peerInfoIntervalMs: 15 * 60 * 1000, // peer-info check while push delivers changes
  configIntervalMs: 30 * 60 * 1000,  // suggestion for the apps' own config poll (relaxedInterval('config'))
});

const HEX_VERSION_RE = /^[0-9a-f]{1,64}$/i;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

class PushControl extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.pushClient - PushClient ('state', 'control', 'status', controlSupported())
   * @param {object} [opts.clientPolicy] - ClientPolicyService (refresh, noteVersion, setPollInterval)
   * @param {object} [opts.connectionMonitor] - ConnectionMonitor (peerDisabled,
   *   supportBundleRequest, setPeerCheckInterval)
   * @param {object} [opts.apiClient] - ApiClient (supportBundleRequest, configHash)
   * @param {() => (void|Promise<void>)} [opts.onConfigChanged] - the app's config check
   * @param {object} [opts.log]
   * @param {object} [opts.intervals] - overrides of DEFAULTS (ms)
   */
  constructor({ pushClient, clientPolicy = null, connectionMonitor = null, apiClient = null, onConfigChanged = null, log, intervals = {} } = {}) {
    super();
    if (!pushClient) throw new Error('PushControl needs a pushClient');
    this.pushClient = pushClient;
    this.clientPolicy = clientPolicy;
    this.connectionMonitor = connectionMonitor;
    this.apiClient = apiClient;
    this.onConfigChanged = typeof onConfigChanged === 'function' ? onConfigChanged : null;
    this.log = log || noopLog();
    this.intervals = { ...DEFAULTS, ...intervals };
    this._unsub = [];
    this._relaxed = false;
    this._lastPolicyVersion = undefined;
    this._configRun = null;
    this._configAgain = false;
  }

  /** Subscribe to the push client (idempotent). */
  start() {
    if (this._unsub.length) return;
    const on = (ev, fn) => { this.pushClient.on(ev, fn); this._unsub.push(() => this.pushClient.removeListener(ev, fn)); };
    on('state', (state) => this._safe('state', () => this.handleState(state)));
    on('control', (control) => this._safe('control', () => this.handleControl(control)));
    on('status', () => this._safe('status', () => this._syncMode()));
    this._syncMode();
  }

  /** Unsubscribe and go back to the normal polling intervals. */
  stop() {
    for (const off of this._unsub.splice(0)) off();
    this._setRelaxed(false);
  }

  /** True while polling is stretched (push delivers the changes). */
  get relaxed() {
    return this._relaxed;
  }

  /**
   * Interval an app should use for its own poll `name` ('config'):
   * the stretched one while relaxed, otherwise `normalMs`.
   */
  relaxedInterval(name, normalMs) {
    const relaxedMs = this.intervals[`${name}IntervalMs`];
    return this._relaxed && Number.isFinite(relaxedMs) ? Math.max(normalMs, relaxedMs) : normalMs;
  }

  // ── Handlers (public for tests and for apps that feed them directly) ──

  /** hello.state (PushClient.normalizeState) — on every connect. */
  handleState(state) {
    if (!state || typeof state !== 'object') return;
    this._syncMode();

    // Policy: a hash version is compared with the cached one; a counter is
    // compared with the last one seen (first connect: refresh once, 304 is cheap).
    const v = state.policyVersion;
    if (typeof v === 'string' && HEX_VERSION_RE.test(v)) {
      this._lastPolicyVersion = v;
      if (this.clientPolicy) this.clientPolicy.noteVersion(v);
    } else if (v != null && v !== this._lastPolicyVersion) {
      this._lastPolicyVersion = v;
      this._refreshPolicy('hello');
    }

    if (typeof state.supportBundleRequested === 'boolean') {
      this._supportRequest(state.supportBundleRequested ? (state.supportBundleRequestedAt || true) : null);
    }

    if (state.peerEnabled === false) this._peerDisabled('hello');

    const known = this.apiClient && typeof this.apiClient.configHash === 'string' ? this.apiClient.configHash : null;
    if (state.configHash && known && state.configHash !== known) this._configChanged('hello');
  }

  /** `event: control` (PushClient.normalizeControl). */
  handleControl(control) {
    if (!control || typeof control !== 'object') return;
    switch (control.type) {
      case 'policy_changed':
        if (control.policyVersion != null) this._lastPolicyVersion = control.policyVersion;
        this._refreshPolicy('push');
        break;
      case 'support_bundle_requested':
        this._supportRequest(control.requestedAt || true);
        break;
      case 'peer_state':
        if (control.enabled === false) this._peerDisabled('push');
        break;
      case 'config_changed':
        this._configChanged('push');
        break;
      default:
        return;
    }
    this.emit('control', control);
  }

  // ── Reactions ──────────────────────────────────────────

  _refreshPolicy(source) {
    if (!this.clientPolicy || typeof this.clientPolicy.refresh !== 'function') return;
    this.log.info(`Client policy changed on the server (${source}) — refreshing`);
    Promise.resolve(this.clientPolicy.refresh()).catch(() => {});
  }

  _supportRequest(request) {
    // Same state as a peer-info / heartbeat answer would leave.
    if (this.apiClient) this.apiClient.supportBundleRequest = request || null;
    if (this.connectionMonitor && typeof this.connectionMonitor.supportBundleRequest === 'function') {
      this.connectionMonitor.supportBundleRequest(request || null);
    }
  }

  _peerDisabled(source) {
    if (!this.connectionMonitor || typeof this.connectionMonitor.peerDisabled !== 'function') return;
    if (this.connectionMonitor.peerDisabled({ enabled: false, source })) {
      this.log.warn(`Peer disabled on the server (${source})`);
    }
  }

  /** Runs onConfigChanged; calls during a run are coalesced into one more run. */
  _configChanged(source) {
    if (!this.onConfigChanged) return;
    if (this._configRun) { this._configAgain = true; return; }
    this.log.info(`Configuration changed on the server (${source}) — checking`);
    const run = async () => {
      do {
        this._configAgain = false;
        try {
          await this.onConfigChanged();
        } catch (err) {
          this.log.warn(`Config check after push failed: ${err.message}`);
        }
      } while (this._configAgain);
    };
    this._configRun = run().finally(() => { this._configRun = null; });
  }

  /** Promise of a running config check (tests). */
  idle() {
    return this._configRun || Promise.resolve();
  }

  // ── Polling mode ───────────────────────────────────────

  _syncMode() {
    const supported = this._unsub.length > 0 && this._safe('controlSupported', () => this.pushClient.controlSupported() === true, false);
    this._setRelaxed(!!supported);
  }

  _setRelaxed(relaxed) {
    if (relaxed === this._relaxed) return;
    this._relaxed = relaxed;
    const { policyIntervalMs, peerInfoIntervalMs } = this.intervals;
    if (this.clientPolicy && typeof this.clientPolicy.setPollInterval === 'function') {
      this.clientPolicy.setPollInterval(relaxed ? policyIntervalMs : null);
    }
    if (this.connectionMonitor && typeof this.connectionMonitor.setPeerCheckInterval === 'function') {
      this.connectionMonitor.setPeerCheckInterval(relaxed ? peerInfoIntervalMs : null);
    }
    this.log.info(relaxed
      ? 'Push delivers policy/peer/config changes — polling stretched'
      : 'Push control unavailable — normal polling');
    this.emit('mode', { relaxed });
  }

  _safe(what, fn, fallback) {
    try {
      return fn();
    } catch (err) {
      this.log.warn(`Push control (${what}) failed: ${err.message}`);
      return fallback;
    }
  }

  /** EventEmitter: listener errors must not break the push client. */
  emit(event, ...args) {
    try {
      return super.emit(event, ...args);
    } catch (err) {
      this.log.warn(`Push control listener for ${event} failed: ${err.message}`);
      return true;
    }
  }
}

PushControl.DEFAULTS = DEFAULTS;

module.exports = PushControl;
