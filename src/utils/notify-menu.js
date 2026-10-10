'use strict';

/**
 * Tray entries of the notification center, shared by Pro and Community
 * (mockup "Windows – Toast und Tray"): "Mitteilungen · 2 neu" and
 * "Nicht stören für 1 Stunde" / "Nicht stören beenden".
 *
 * Electron-free: returns Electron menu template items.
 *
 * @param {object} opts
 * @param {number} opts.unread - NotificationCenter.unreadCount()
 * @param {{ active: boolean, until: ?number }} opts.dnd - NotificationCenter.dndState()
 * @param {Function} opts.t - i18n t()
 * @param {Function} opts.openInbox - show the window on the inbox
 * @param {Function} opts.setDnd - NotificationCenter.setDnd ({ minutes: 60 } | null)
 * @param {boolean} [opts.enabled=true] - notifications on (off → no entries)
 * @returns {object[]}
 */
function notifyMenuItems({ unread = 0, dnd = { active: false }, t, openInbox, setDnd, enabled = true }) {
  if (!enabled) return [];
  const label = unread > 0
    ? t('push.tray.inboxUnread', { count: unread })
    : t('push.tray.inbox');
  return [
    { label, click: () => openInbox() },
    dnd && dnd.active
      ? { label: t('push.tray.dndOff'), click: () => setDnd(null) }
      : { label: t('push.tray.dnd1h'), click: () => setDnd({ minutes: 60 }) },
  ];
}

module.exports = { notifyMenuItems };
