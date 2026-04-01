/**
 * GateControl – Store Setup (Core)
 *
 * Two-tier encrypted store:
 * 1. keyStore: stores a machine-specific encryption key (bootstrap-encrypted)
 * 2. configStore: stores all app config (encrypted with the machine key)
 *
 * On first launch, a random key is generated and old config files
 * with the previous fixed key are removed.
 */

'use strict';

const crypto = require('crypto');
const path = require('path');
const fsSync = require('fs');
const Store = require('electron-store');

/**
 * Create the two-tier store system.
 *
 * @param {object} options
 * @param {string} options.userDataPath - app.getPath('userData')
 * @param {object} options.log - electron-log instance
 * @returns {{ keyStore: Store, store: Store }}
 */
function createStores({ userDataPath, log }) {
  // Key-Store: speichert den maschinenspezifischen Encryption Key
  const keyStore = new Store({
    name: 'gatecontrol-keyfile',
    encryptionKey: 'gc-bootstrap',
  });

  if (!keyStore.get('machineKey')) {
    // Erstmaliger Start mit neuem Key-System
    const newKey = crypto.randomBytes(32).toString('hex');
    // Alte Config mit festem Key löschen (nicht mehr entschlüsselbar)
    try {
      const configPath = path.join(userDataPath, 'gatecontrol-config.json');
      if (fsSync.existsSync(configPath)) {
        fsSync.unlinkSync(configPath);
        log.info('Alte Config-Datei entfernt (einmalige Key-Migration)');
      }
    } catch {}
    keyStore.set('machineKey', newKey);
  }

  // Config-Store: alle App-Einstellungen
  const store = new Store({
    name: 'gatecontrol-config',
    encryptionKey: keyStore.get('machineKey'),
    schema: {
      server: {
        type: 'object',
        properties: {
          url:    { type: 'string', default: '' },
          apiKey: { type: 'string', default: '' },
          peerId: { type: 'string', default: '' },
        },
        default: {},
      },
      tunnel: {
        type: 'object',
        properties: {
          interfaceName: { type: 'string', default: 'gatecontrol0' },
          autoConnect:   { type: 'boolean', default: true },
          killSwitch:    { type: 'boolean', default: false },
          splitTunnel:   { type: 'boolean', default: false },
          splitRoutes:   { type: 'string', default: '' },
          configPath:    { type: 'string', default: '' },
        },
        default: {},
      },
      app: {
        type: 'object',
        properties: {
          startMinimized: { type: 'boolean', default: true },
          startWithWindows: { type: 'boolean', default: true },
          theme:          { type: 'string', default: 'dark' },
          checkInterval:  { type: 'number', default: 30 },
          configPollInterval: { type: 'number', default: 300 },
        },
        default: {},
      },
    },
  });

  return { keyStore, store };
}

module.exports = { createStores };
