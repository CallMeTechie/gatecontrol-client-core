'use strict';

/**
 * GateControl – Fernzugriff: the PC's own app API (Core service)
 *
 * REST calls of the plugin `gatecontrol-remote` (1.1, stage 2 "Windows-Schalter") over the
 * device token of the existing ApiClient. GateControl hands the plugin the token's owner and
 * this app installation with its VPN address (req.user.device.vpnIp). Only this file knows the
 * paths:
 *
 *   POST   …/gatecontrol-remote/api/host/register   { name, edition, rdp: { available, enabled, port }, osUser, appVersion, shareMode? }
 *   POST   …/api/host/state                         { rdp: { enabled }, osUser, online } → { shareMode, allowOpen, pending }
 *   PUT    …/api/host/share                         { shareMode: 'code' | 'open' }
 *   DELETE …/api/host                               the switch is off
 *   POST   …/api/host/code                          → { code: '482-913-075', expiresAt }
 *   POST   …/api/host/requests/<id>                 { decision: 'allow' | 'deny', mode? } → { request }
 *   GET    …/api/host/firewall                      → { open: [{ sessionKey, allow, port, until }] }
 *   POST   …/api/host/firewall                      { sessionKey, state: 'open' | 'closed' | 'failed', reason? }
 *
 * Failures: MessengerApi's error class { status, code, message } (`no_share_right`, `home_edition`,
 * `not_found` — also a server without the plugin or with 1.0 —, `network`, `timeout`, `http_<status>`).
 */

const MessengerApi = require('./messenger-api');

const { MessengerError: RemoteHostError } = MessengerApi;

const PLUGIN_ID = 'gatecontrol-remote';
const API_BASE = `/api/v1/client/plugins/${PLUGIN_ID}/api/`;
const REQUEST_RE = /^rq_[A-Za-z0-9_-]{8,40}$/;
const SESSION_KEY_RE = /^fw_[A-Za-z0-9_-]{8,40}$/;

class RemoteHostApi {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (its axios `client`, re-read on every call)
   * @param {object} [opts.log]
   * @param {object} [opts.http] - MessengerApi-compatible transport (tests)
   */
  constructor({ apiClient, log, http = null } = {}) {
    this.http = http || new MessengerApi({ apiClient, log });
  }

  _api(method, p, body) {
    return this.http._call(method, API_BASE + p, body === undefined ? {} : { body });
  }

  register(body) { return this._api('POST', 'host/register', body); }
  state(body) { return this._api('POST', 'host/state', body); }
  share(shareMode) { return this._api('PUT', 'host/share', { shareMode }); }
  unregister() { return this._api('DELETE', 'host'); }
  code() { return this._api('POST', 'host/code', {}); }

  decide(requestId, decision, mode) {
    if (!REQUEST_RE.test(String(requestId || ''))) return Promise.reject(new RemoteHostError('invalid request', { code: 'invalid' }));
    return this._api('POST', 'host/requests/' + encodeURIComponent(requestId), { decision, ...(mode ? { mode } : {}) });
  }

  firewallList() { return this._api('GET', 'host/firewall'); }

  firewallReport(sessionKey, state, reason) {
    if (!SESSION_KEY_RE.test(String(sessionKey || ''))) return Promise.reject(new RemoteHostError('invalid session key', { code: 'invalid' }));
    return this._api('POST', 'host/firewall', { sessionKey, state, ...(reason ? { reason: String(reason).slice(0, 120) } : {}) });
  }
}

RemoteHostApi.RemoteHostError = RemoteHostError;
RemoteHostApi.PLUGIN_ID = PLUGIN_ID;
RemoteHostApi.API_BASE = API_BASE;
RemoteHostApi.REQUEST_RE = REQUEST_RE;
RemoteHostApi.SESSION_KEY_RE = SESSION_KEY_RE;

module.exports = RemoteHostApi;
