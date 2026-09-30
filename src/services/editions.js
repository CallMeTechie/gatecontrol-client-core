/**
 * GateControl – Client-Editionen (Pro / Community)
 *
 * Beide Windows-Clients nutzen denselben Core und können gleichzeitig
 * installiert sein. Alles, was systemweit angelegt wird (z.B. Firewall-
 * Regeln des Kill-Switch), muss deshalb pro Edition eindeutig benannt
 * sein, sonst räumt eine App die Regeln der anderen mit auf.
 *
 * Jede App übergibt nur ihre Edition-ID ('pro' | 'community'); Präfixe
 * und Erkennungsmerkmale werden ausschließlich hier abgeleitet.
 *
 * guid = UUID v5 der appId im electron-builder-Namespace
 * (50e065bc-3134-11e6-9bab-38c9862bdaf3). electron-builder legt damit bei
 * der NSIS-Installation den Registry-Schlüssel Software\<guid>
 * (InstallLocation) an. Die Client-Tests prüfen, dass appId, productName
 * und guid mit der package.json der jeweiligen App übereinstimmen.
 */

'use strict';

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');

const execFileAsync = promisify(execFile);

const EDITIONS = Object.freeze({
  pro: Object.freeze({
    id: 'pro',
    name: 'Pro',
    appId: 'com.gatecontrol.client-pro',
    productName: 'GateControl Pro Client',
    guid: 'c2dd862a-ec97-546e-8067-c1923aed53b2',
  }),
  community: Object.freeze({
    id: 'community',
    name: 'Community',
    appId: 'com.gatecontrol.client',
    productName: 'GateControl Community Client',
    guid: 'aa07f3aa-9926-52f3-be30-dbe287d6b2ea',
  }),
});

/** Präfix der Kill-Switch-Regeln vor Einführung der Editions-Präfixe (beide Apps) */
const LEGACY_KILLSWITCH_RULE_PREFIX = 'GateControl_KS';

function getEdition(id) {
  const edition = typeof id === 'string' ? EDITIONS[id.toLowerCase()] : undefined;
  if (!edition) {
    throw new Error(`Unbekannte GateControl-Edition: ${id} (erwartet: ${Object.keys(EDITIONS).join(', ')})`);
  }
  return edition;
}

function otherEditions(id) {
  const own = getEdition(id);
  return Object.values(EDITIONS).filter(e => e.id !== own.id);
}

/** z.B. "GateControl_Pro_KS" – Regelnamen sind "<Präfix>_<Name>" */
function killSwitchRulePrefix(id) {
  return `GateControl_${getEdition(id).name}_KS`;
}

/**
 * Ist die Edition auf diesem Rechner installiert oder läuft sie gerade
 * (z.B. als portable Version)? Im Zweifel (Prüfung nicht möglich) wird
 * true geliefert – Aufrufer nutzen das Ergebnis, um fremde Regeln NICHT
 * anzufassen.
 *
 * @param {object} edition - Eintrag aus EDITIONS
 * @param {object} [deps] - für Tests: { platform, execFile, exists, env }
 * @returns {Promise<boolean>}
 */
async function isEditionPresent(edition, deps = {}) {
  const platform = deps.platform || process.platform;
  if (platform !== 'win32') return false;
  const run = deps.execFile || ((cmd, args) => execFileAsync(cmd, args, { windowsHide: true }));
  const exists = deps.exists || (p => fs.existsSync(p));
  const env = deps.env || process.env;

  // 1. Registry-Eintrag des NSIS-Installers (per-machine bzw. per-user).
  //    reg.exe liefert Exit-Code 1, wenn der Schlüssel fehlt.
  for (const root of ['HKLM', 'HKCU']) {
    try {
      await run('reg', ['query', `${root}\\Software\\${edition.guid}`, '/v', 'InstallLocation', '/reg:64']);
      return true;
    } catch (err) {
      if (err && err.code !== 1) return true;
    }
  }

  // 2. Exe im Standard-Installationsverzeichnis
  const exeName = `${edition.productName}.exe`;
  const bases = [
    env.ProgramW6432,
    env.ProgramFiles,
    env['ProgramFiles(x86)'],
    env.LOCALAPPDATA && path.win32.join(env.LOCALAPPDATA, 'Programs'),
  ].filter(Boolean);
  for (const base of bases) {
    if (exists(path.win32.join(base, edition.productName, exeName))) return true;
  }

  // 3. Läuft gerade (deckt die portable Version ab)
  try {
    const { stdout } = await run('tasklist', ['/FI', `IMAGENAME eq ${exeName}`, '/FO', 'CSV', '/NH']);
    return String(stdout || '').toLowerCase().includes(`"${exeName.toLowerCase()}"`);
  } catch {
    return true;
  }
}

/** true, wenn irgendeine andere Edition installiert ist oder läuft */
async function isOtherEditionPresent(id, deps) {
  for (const edition of otherEditions(id)) {
    if (await isEditionPresent(edition, deps)) return true;
  }
  return false;
}

module.exports = {
  EDITIONS,
  LEGACY_KILLSWITCH_RULE_PREFIX,
  getEdition,
  otherEditions,
  killSwitchRulePrefix,
  isEditionPresent,
  isOtherEditionPresent,
};
