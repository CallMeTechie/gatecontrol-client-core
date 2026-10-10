'use strict';

/**
 * Ed25519-Public-Key für signierte Auto-Updates.
 *
 * Gemeinsam für Pro und Community (vorher je eine Kopie in
 * src/main/update-public-key.js der Apps).
 *
 * Einzige Quelle ist build/update-signing.pub der jeweiligen App (SPKI-PEM).
 * electron-builder legt die Datei per extraResources nach
 * resources/update-signing.pub; die Release-Pipeline (scripts/sign-update.js)
 * prüft ihre Signatur gegen dieselbe Datei. Solange dort der Platzhalter
 * steht, liefert loadUpdatePublicKey() null und der Updater bleibt
 * deaktiviert.
 */

const fs = require('fs');
const path = require('path');

const PLACEHOLDER = 'REPLACE_WITH_UPDATE_PUBLIC_KEY';
const FILE_NAME = 'update-signing.pub';

/**
 * @param {object} [opts]
 * @param {string} [opts.resourcesPath=process.resourcesPath] - installierte App
 * @param {string} [opts.appRoot] - App-Repo-Wurzel (Entwicklung/Tests: build/)
 * @returns {string[]}
 */
function updatePublicKeyPaths({ resourcesPath = process.resourcesPath, appRoot } = {}) {
  const paths = [];
  // Installierte App: <Installationsordner>/resources/update-signing.pub
  if (resourcesPath) paths.push(path.join(resourcesPath, FILE_NAME));
  // Entwicklung (electron .) und Tests: build/update-signing.pub im App-Repo
  if (appRoot) paths.push(path.join(appRoot, 'build', FILE_NAME));
  return paths;
}

/**
 * @param {string[]|{resourcesPath?: string, appRoot?: string}} [pathsOrOpts]
 *   Liste von Kandidaten-Pfaden oder Optionen für updatePublicKeyPaths()
 * @returns {string|null} PEM-Text oder null (fehlt / Platzhalter / kein PEM)
 */
function loadUpdatePublicKey(pathsOrOpts) {
  const paths = Array.isArray(pathsOrOpts) ? pathsOrOpts : updatePublicKeyPaths(pathsOrOpts);
  for (const p of paths) {
    let text;
    try {
      text = fs.readFileSync(p, 'utf8');
    } catch {
      continue;
    }
    if (text.includes(PLACEHOLDER) || !text.includes('-----BEGIN PUBLIC KEY-----')) return null;
    return text;
  }
  return null;
}

module.exports = { loadUpdatePublicKey, updatePublicKeyPaths, PLACEHOLDER, FILE_NAME };
