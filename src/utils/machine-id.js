'use strict';

const crypto = require('crypto');
const { execFileSync } = require('child_process');

let cachedFingerprint = null;

/**
 * Read Windows MachineGuid from registry and return SHA256 hash.
 * Falls back to hostname-based ID on non-Windows or if registry read fails.
 */
function getMachineFingerprint() {
  if (cachedFingerprint) return cachedFingerprint;

  let machineGuid = null;

  try {
    const output = execFileSync('reg', [
      'query',
      'HKLM\\SOFTWARE\\Microsoft\\Cryptography',
      '/v', 'MachineGuid',
    ], { encoding: 'utf-8', timeout: 5000 });
    const match = output.match(/MachineGuid\s+REG_SZ\s+(.+)/);
    if (match) machineGuid = match[1].trim();
  } catch {}

  if (!machineGuid) {
    machineGuid = require('os').hostname() + '-fallback';
  }

  cachedFingerprint = crypto.createHash('sha256').update(machineGuid).digest('hex');
  return cachedFingerprint;
}

module.exports = { getMachineFingerprint };
