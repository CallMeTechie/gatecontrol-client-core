'use strict';

/**
 * GateControl – "Support-Paket senden" flow (Core)
 *
 *   1. ask the user (native dialog: server host + what is included)
 *   2. collect the redacted bundle (collector.js)
 *   3. upload it (ApiClient.uploadSupportBundle → POST /api/v1/client/support-bundle)
 *
 * Used by the support:send IPC handler (Settings → About) and, when the
 * server reports supportBundleRequested (admin asked for a bundle), by the
 * connection monitor — in both cases nothing leaves the machine without the
 * user's confirmation.
 */

const { t } = require('../i18n');
const { collectSupportBundle } = require('./collector');

function serverHost(url) {
  try { return new URL(url).host; } catch { return url || ''; }
}

function errorMessage(err) {
  const status = err && err.response && err.response.status;
  const code = err && err.response && err.response.data && err.response.data.error;
  if (status === 429 || code === 'rate_limited') return t('support.rateLimited');
  if (status === 413 || code === 'too_large') return t('support.tooLarge');
  if (status === 401 || status === 403) return t('support.forbidden');
  if (status === 404) return t('support.unsupported');
  return t('support.failed', { error: code || (err && err.message) || 'unknown' });
}

/**
 * @param {object} ctx - same context as registerBaseHandlers (app, dialog,
 *   getMainWindow, store, apiClient, log, getTunnelState, wgConfigFile) plus
 *   optional `edition` and `getLocale`
 * @param {object} [deps] - test seams: { collect }
 */
function createSupportBundleSender(ctx, deps = {}) {
  const collect = deps.collect || collectSupportBundle;
  let inFlight = null;
  let lastPromptedRequest = null;

  async function confirm(reason) {
    const host = serverHost(ctx.store && ctx.store.get('server.url', ''));
    const detail = [
      reason === 'admin_request' ? t('support.requestedByAdmin') : null,
      t('support.confirmIncludes'),
      t('support.confirmExcludes'),
    ].filter(Boolean).join('\n\n');
    const win = typeof ctx.getMainWindow === 'function' ? ctx.getMainWindow() : null;
    const options = {
      type: 'question',
      buttons: [t('support.send'), t('support.cancel')],
      defaultId: 0,
      cancelId: 1,
      noLink: true,
      title: t('support.title'),
      message: t('support.confirmTitle', { host }),
      detail,
    };
    const { response } = win ? await ctx.dialog.showMessageBox(win, options) : await ctx.dialog.showMessageBox(options);
    return response === 0;
  }

  async function run({ reason = 'user', skipConfirm = false } = {}) {
    const { apiClient, log } = ctx;
    if (!apiClient || !apiClient.client || !apiClient.peerId) {
      return { success: false, error: t('support.notConfigured') };
    }
    if (!skipConfirm && !(await confirm(reason))) {
      return { success: false, cancelled: true };
    }
    try {
      const locale = typeof ctx.getLocale === 'function' ? ctx.getLocale() : require('../i18n').getLocale();
      const bundle = await collect({ ...ctx, locale }, { reason });
      const data = await apiClient.uploadSupportBundle(bundle);
      log && log.info(`Support bundle sent (id ${data && data.bundle && data.bundle.id})`);
      return { success: true, id: data && data.bundle ? data.bundle.id : null };
    } catch (err) {
      log && log.warn(`Support bundle upload failed: ${err.message}`);
      return { success: false, error: errorMessage(err) };
    }
  }

  return {
    /** Ask, collect and upload. Concurrent calls share the running attempt. */
    send(opts) {
      if (!inFlight) inFlight = run(opts).finally(() => { inFlight = null; });
      return inFlight;
    },

    /**
     * Server flag (heartbeat / peer-info): supportBundleRequestedAt (string)
     * or supportBundleRequested (boolean). Prompts once per request — a
     * cancelled prompt is not repeated until the admin asks again (new
     * timestamp) or the request was cleared in between.
     * @param {string|boolean|null} request
     */
    async onServerRequest(request) {
      const key = typeof request === 'string' && request ? request : (request ? 'requested' : null);
      if (!key) { lastPromptedRequest = null; return null; }
      if (key === lastPromptedRequest || inFlight) return null;
      lastPromptedRequest = key;
      const res = await this.send({ reason: 'admin_request' });
      if (typeof ctx.onSupportResult === 'function') ctx.onSupportResult(res);
      return res;
    },

    get busy() { return !!inFlight; },
  };
}

module.exports = { createSupportBundleSender, errorMessage, serverHost };
