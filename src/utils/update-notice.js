'use strict';

/**
 * Update notice helpers shared by the Pro and Community main processes:
 * tray entries and notification text for a ready (verified) update.
 *
 * A mandatory update (server: below the minimum version) gets a prominent
 * tray entry at the top of the menu and a notification that names the
 * required version. Installing always goes through the client's
 * installUpdate() → updater.install() (re-hash right before the start);
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

module.exports = { updateMenuItems, mandatoryNotice };
