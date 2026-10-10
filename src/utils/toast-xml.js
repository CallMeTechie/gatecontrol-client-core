'use strict';

/**
 * Windows toast XML for push notifications (Electron Notification `toastXml`).
 *
 *   - Text only: title, body, attribution line; everything XML-escaped.
 *   - Priority → scenario / audio: info is silent, critical uses the
 *     "urgent" scenario (Windows 11; older versions show a normal toast)
 *     with a long duration and the reminder sound.
 *   - Action buttons only when the app registered a protocol (scheme):
 *     Electron reports a click on a Windows toast without telling which
 *     button was pressed, so buttons use protocol activation
 *     (`<scheme>://notify/action?t=<nonce>`): Windows starts the app with
 *     that URL, the running instance receives it in `second-instance` and
 *     hands it to NotificationCenter.handleArgv(). The nonce is random and
 *     single-use — a web page cannot trigger actions by guessing links.
 *
 * Electron-free (unit-testable).
 */

const AUDIO = {
  normal: 'ms-winsoundevent:Notification.Default',
  high: 'ms-winsoundevent:Notification.Default',
  critical: 'ms-winsoundevent:Notification.Reminder',
};

const SCHEME_RE = /^[a-z][a-z0-9+.-]{1,40}$/;

function xmlEscape(v) {
  return String(v == null ? '' : v)
    // XML 1.0 forbids most control characters, even escaped.
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Activation URL of a toast button. */
function actionUrl(scheme, nonce) {
  return `${scheme}://notify/action?t=${encodeURIComponent(nonce)}`;
}

/**
 * @param {object} opts
 * @param {string} opts.title
 * @param {string} [opts.body]
 * @param {string} [opts.attribution] - small third line (e.g. "Sicherheit · 21:42")
 * @param {'info'|'normal'|'high'|'critical'} [opts.priority='normal']
 * @param {boolean} [opts.silent=false] - no sound
 * @param {Array<{ label: string, nonce: string }>} [opts.buttons] - max. 5 (Windows limit)
 * @param {string} [opts.scheme] - protocol for the buttons; none → no buttons
 * @param {string} [opts.launch] - argument of a body click (foreground)
 * @param {string} [opts.imagePath] - app logo override (absolute file path)
 * @returns {string}
 */
function buildToastXml({
  title, body = '', attribution = '', priority = 'normal', silent = false,
  buttons = [], scheme = null, launch = 'gatecontrol-notify', imagePath = null,
} = {}) {
  const critical = priority === 'critical';
  const attrs = [`launch="${xmlEscape(launch)}"`, 'activationType="foreground"'];
  if (critical) attrs.push('scenario="urgent"', 'duration="long"');

  const lines = [
    `<toast ${attrs.join(' ')}>`,
    '<visual><binding template="ToastGeneric">',
    `<text hint-maxLines="2">${xmlEscape(title)}</text>`,
  ];
  if (body) lines.push(`<text>${xmlEscape(body)}</text>`);
  if (attribution) lines.push(`<text placement="attribution">${xmlEscape(attribution)}</text>`);
  if (imagePath) lines.push(`<image placement="appLogoOverride" src="${xmlEscape(imagePath)}"/>`);
  lines.push('</binding></visual>');

  const quiet = silent || priority === 'info';
  lines.push(quiet ? '<audio silent="true"/>' : `<audio src="${AUDIO[priority] || AUDIO.normal}"/>`);

  const usable = scheme && SCHEME_RE.test(scheme)
    ? buttons.filter((b) => b && b.label && b.nonce).slice(0, 5)
    : [];
  if (usable.length) {
    lines.push('<actions>');
    for (const b of usable) {
      lines.push(`<action content="${xmlEscape(b.label)}" activationType="protocol" arguments="${xmlEscape(actionUrl(scheme, b.nonce))}"/>`);
    }
    lines.push('</actions>');
  }
  lines.push('</toast>');
  return lines.join('');
}

/**
 * Nonce from an activation URL (`<scheme>://notify/action?t=…`), or null.
 * Anything else in the URL is ignored.
 */
function parseActionUrl(url, scheme) {
  if (typeof url !== 'string' || !scheme) return null;
  let u;
  try { u = new URL(url.trim()); } catch { return null; }
  if (u.protocol !== `${scheme}:`) return null;
  if (u.hostname !== 'notify' || u.pathname !== '/action') return null;
  const t = u.searchParams.get('t');
  return t && /^[A-Za-z0-9_-]{8,64}$/.test(t) ? t : null;
}

module.exports = { buildToastXml, parseActionUrl, actionUrl, xmlEscape };
