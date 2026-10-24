'use strict';

/**
 * Worker thread of services/totp-qr.js: decodes the QR codes of one bitmap off
 * the main process (jsQR on a 4K screen takes 1–3 s). Gets { data, width,
 * height, bgra } (data transferred), answers { texts } or { error }.
 */

const { parentPort, workerData } = require('worker_threads');
const { decodeQrImage } = require('../utils/totp-qr');

try {
  parentPort.postMessage({ texts: decodeQrImage(workerData) });
} catch (err) {
  parentPort.postMessage({ error: (err && err.name) || 'Error' });
}
