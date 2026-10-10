'use strict';

/**
 * Tray helpers shared by the Pro and Community main processes (formerly a
 * getIcon()/formatBytesShort() copy in each app's main.js).
 *
 * The icon is drawn in code (sun/star design — ring, centre dot, 8 rays) in
 * the colour of the connection state, so no per-state image files are needed.
 * renderTrayIcon() is Electron-free (unit-testable); createTrayIcon() wraps
 * the buffer in a NativeImage.
 */

const TRAY_ICON_SIZE = 32;

const STATE_COLORS = {
  connected: [0x22, 0xC5, 0x5E],   // green
  connecting: [0xF5, 0x9E, 0x0B],  // amber
  disconnected: [0xEF, 0x44, 0x44], // red (also every other state)
};

// Unread push notifications: dot in the top right corner (notification center).
const BADGE_COLOR = [0x3B, 0x82, 0xF6]; // blue
const BADGE = { cx: 25, cy: 7, r: 5.5, gap: 1.5 };

/**
 * @param {string} state - 'connected' | 'connecting' | anything else (red)
 * @param {object} [opts]
 * @param {boolean} [opts.badge=false] - draw the unread dot (top right)
 * @returns {{ buffer: Buffer, width: number, height: number }} raw RGBA
 */
function renderTrayIcon(state, { badge = false } = {}) {
  const color = state === 'connected' ? STATE_COLORS.connected
    : state === 'connecting' ? STATE_COLORS.connecting
    : STATE_COLORS.disconnected;

  const size = TRAY_ICON_SIZE;
  const buf = Buffer.alloc(size * size * 4, 0); // transparent RGBA
  const cx = size / 2;
  const cy = size / 2;

  function setPixel(px, py) {
    const x = Math.round(px);
    const y = Math.round(py);
    if (x < 0 || x >= size || y < 0 || y >= size) return;
    const i = (y * size + x) * 4;
    buf[i] = color[0]; buf[i + 1] = color[1]; buf[i + 2] = color[2]; buf[i + 3] = 255;
  }

  // Ring (outer circle)
  const ringR = 5.0;
  const ringThick = 1.8;
  for (let a = 0; a < 360; a += 1) {
    const rad = a * Math.PI / 180;
    for (let t = -ringThick / 2; t <= ringThick / 2; t += 0.4) {
      setPixel(cx + (ringR + t) * Math.cos(rad), cy + (ringR + t) * Math.sin(rad));
    }
  }

  // Center dot
  for (let dx = -1.5; dx <= 1.5; dx += 0.5) {
    for (let dy = -1.5; dy <= 1.5; dy += 0.5) {
      if (dx * dx + dy * dy <= 2.0) setPixel(cx + dx, cy + dy);
    }
  }

  // 8 rays
  const rayInner = 8.5;
  const rayOuter = 13.5;
  const rayThick = 2.0;
  for (let i = 0; i < 8; i++) {
    const angle = i * 45 * Math.PI / 180;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const perpCos = Math.cos(angle + Math.PI / 2);
    const perpSin = Math.sin(angle + Math.PI / 2);
    for (let d = rayInner; d <= rayOuter; d += 0.3) {
      for (let t = -rayThick / 2; t <= rayThick / 2; t += 0.4) {
        setPixel(cx + d * cos + t * perpCos, cy + d * sin + t * perpSin);
      }
    }
    // Rounded ray ends (inner and outer cap)
    for (let dx = -rayThick / 2; dx <= rayThick / 2; dx += 0.4) {
      for (let dy = -rayThick / 2; dy <= rayThick / 2; dy += 0.4) {
        if (dx * dx + dy * dy <= (rayThick / 2) * (rayThick / 2)) {
          setPixel(cx + rayInner * cos + dx * perpCos + dy * cos, cy + rayInner * sin + dx * perpSin + dy * sin);
          setPixel(cx + rayOuter * cos + dx * perpCos + dy * cos, cy + rayOuter * sin + dx * perpSin + dy * sin);
        }
      }
    }
  }

  if (badge) drawBadge(buf, size);

  return { buffer: buf, width: size, height: size };
}

// Filled dot with a transparent ring around it, so it stays visible on top
// of the rays in every state colour.
function drawBadge(buf, size) {
  const { cx, cy, r, gap } = BADGE;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const d = Math.hypot(x + 0.5 - cx, y + 0.5 - cy);
      if (d > r + gap) continue;
      const i = (y * size + x) * 4;
      if (d <= r) {
        buf[i] = BADGE_COLOR[0]; buf[i + 1] = BADGE_COLOR[1]; buf[i + 2] = BADGE_COLOR[2]; buf[i + 3] = 255;
      } else {
        buf[i] = 0; buf[i + 1] = 0; buf[i + 2] = 0; buf[i + 3] = 0;
      }
    }
  }
}

/**
 * @param {Electron.nativeImage} nativeImage - electron's nativeImage module
 * @param {string} state
 * @param {object} [opts] - { badge } (see renderTrayIcon)
 * @returns {Electron.NativeImage}
 */
function createTrayIcon(nativeImage, state, opts) {
  const { buffer, width, height } = renderTrayIcon(state, opts);
  return nativeImage.createFromBuffer(buffer, { width, height });
}

/**
 * Compact byte count for the tray tooltip ("0 B", "512 B", "1.5 MB").
 * @param {number} bytes
 * @returns {string}
 */
function formatBytesShort(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

module.exports = { renderTrayIcon, createTrayIcon, formatBytesShort, TRAY_ICON_SIZE };
