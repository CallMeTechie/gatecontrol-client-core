'use strict';

/**
 * Update notice helpers shared by the Pro and Community main processes:
 * tray entries and notification text for a ready (verified) update.
 *
 * A mandatory update (server: below the minimum version) gets a prominent
 * tray entry at the top of the menu and a notification that names the
 * required version. A click on the update toast installs it (updateToast).
 * Installing always goes through the client's
 * installUpdate() (utils/update-install.js: re-hash, then tunnel down, then start);
 * nothing here installs on its own.
 */

/**
 * @param {object} opts
 * @param {{version: string}|null} opts.update - ready update (or null)
 * @param {boolean} opts.mandatory - updater.isMandatory()
 * @param {Function} opts.t - i18n t()
 * @param {Function} opts.install - click handler (installUpdate)
 * @returns {{top: object[], bottom: object[]}} Electron menu template items:
 *   `top` goes right below the status header, `bottom` where the optional
 *   install entry used to be.
 */
function updateMenuItems({ update, mandatory, t, install }) {
  if (!update || !update.version) return { top: [], bottom: [] };
  if (mandatory) {
    return {
      top: [
        { label: t('update.installRequired', { version: update.version }), click: () => install() },
        { type: 'separator' },
      ],
      bottom: [],
    };
  }
  return {
    top: [],
    bottom: [
      { type: 'separator' },
      { label: t('tray.installUpdate', { version: update.version }), click: () => install() },
    ],
  };
}

/**
 * Title/body for the desktop notification of a mandatory update.
 * @param {{version: string, minVersion?: string|null}} info
 * @param {Function} t
 */
function mandatoryNotice(info, t) {
  const body = info.minVersion
    ? t('update.requiredDesc', { minVersion: info.minVersion, version: info.version })
    : t('update.requiredDescNoMin', { version: info.version });
  return { title: t('update.required'), body: `${body} ${t('update.requiredTunnelHint')}` };
}

/**
 * Toast for a ready update ("Version x verfügbar" / "Update erforderlich").
 * A click on the toast — or its "Jetzt installieren" button — runs the same
 * install flow as the tray entry (the client's installUpdate(): it fetches
 * the update first when it is not downloaded and verified yet). Before, a
 * click only dismissed the toast.
 * @param {{version: string, mandatory?: boolean, minVersion?: string|null}} info
 * @param {object} o
 * @param {Function} o.t - i18n t()
 * @param {Function} o.install - click handler (e.g. installUpdateFromTray)
 * @param {string} o.productName - toast title, e.g. 'GateControl Pro'
 * @returns {{body: string, title: string, collapseKey: string, force: boolean,
 *   onClick: Function, actions: Array<{label: string, onClick: Function}>}}
 */
function updateToast(info, { t, install, productName }) {
  const run = () => install();
  const base = { collapseKey: 'update', onClick: run, actions: [{ label: t('update.install'), onClick: run }] };
  if (info && info.mandatory) {
    const notice = mandatoryNotice(info, t);
    // Must be seen: shown during "Nicht stören" and with toasts switched off.
    return { ...base, title: `${productName} - ${notice.title}`, body: notice.body, force: true };
  }
  return { ...base, title: productName, body: t('update.availableToast', { version: info && info.version }), force: false };
}

module.exports = { updateMenuItems, mandatoryNotice, updateToast };
