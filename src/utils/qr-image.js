'use strict';

/**
 * QR codes as pictures for the renderer (Vault's Wi-Fi QR code): the text never has to leave the main process —
 * the page gets an SVG data URL. Encoder: uqr 0.1.2 (Nayuki's QR code generator, MIT), vendored in src/vendor/uqr.js
 * (no npm dependency for the apps to lock). Error correction M, dark modules black on a white square with a quiet
 * zone of 4 modules, so phones read it in any theme.
 */

const { encode } = require('../vendor/uqr');

const QUIET = 4;

/** text → the SVG of its QR code (a string; only numbers and fixed markup in it), or null when it does not fit. */
function qrSvg(text) {
  let q;
  try {
    q = encode(String(text), { ecc: 'M', border: 0 });
  } catch {
    return null;
  }
  const n = q.size + QUIET * 2;
  let d = '';
  for (let y = 0; y < q.size; y++) {
    for (let x = 0; x < q.size; x++) if (q.data[y][x]) d += `M${x + QUIET} ${y + QUIET}h1v1h-1z`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges">`
    + `<rect width="${n}" height="${n}" fill="#ffffff"/><path d="${d}" fill="#000000"/></svg>`;
}

/** text → data:image/svg+xml;base64,… of its QR code, or null. */
function qrDataUrl(text) {
  const svg = qrSvg(text);
  return svg ? `data:image/svg+xml;base64,${Buffer.from(svg, 'utf8').toString('base64')}` : null;
}

module.exports = { qrSvg, qrDataUrl };
