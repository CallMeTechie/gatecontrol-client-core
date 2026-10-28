'use strict';

/**
 * Protection against ransomware on the client side of Drive (Drive 1.6
 * 'guard'): pure helpers of "Ordner sichern" (services/drive-sync.js) and the
 * uploads of the page Drive. The same rules as gc-drive-sync (drive-sync/
 * src/core/guard.rs) and the server's thresholds:
 *
 * - Entropy: Shannon entropy (bits per byte, 0 … 8) of the first 64 KB of a
 *   file. Encrypted bytes are close to 8; text, Office files before 2007,
 *   databases, raw images are far below. Sent with every commit (`entropy`).
 * - A changed file is suspicious when its new content is high-entropy
 *   (> 7.5) although it was not before: the entropy of its last agreed
 *   version is known and below 7.0 — or unknown, and the file type is not
 *   one that is compressed anyway (.docx, .zip, .jpg, .mp4, .pdf …).
 * - A file renamed to a known ransomware extension ("Brief.docx" →
 *   "Brief.docx.locked") is suspicious too.
 * - A run trips the guard when at least 50 changed files are suspicious, or
 *   at least 20 % of the files of a folder with at least 20 files. Then
 *   nothing goes up; the folder waits for the person ("Hochladen" /
 *   "Pausiert lassen"), like the mass-delete guard.
 *
 * Electron-free and side-effect free (unit-tested directly).
 */

const fs = require('fs');

const ENTROPY_BYTES = 64 * 1024;
const ENTROPY_HIGH = 7.5;
const ENTROPY_WAS_LOW = 7.0;
const GUARD_COUNT = 50;
const GUARD_SHARE = 0.2;
const GUARD_DIR_MIN = 20;
const SAMPLE_MAX = 5;

// File types whose content is compressed (or encrypted) by design: high entropy is normal.
const COMPRESSED_EXT = new Set([
  'zip', '7z', 'rar', 'gz', 'tgz', 'bz2', 'xz', 'zst', 'lz', 'lzma', 'cab', 'jar', 'apk', 'aab', 'ipa', 'msi', 'msix', 'appx', 'dmg', 'pkg', 'deb', 'rpm',
  'docx', 'docm', 'xlsx', 'xlsm', 'pptx', 'pptm', 'odt', 'ods', 'odp', 'odg', 'epub', 'pages', 'numbers', 'key', 'vsdx', 'xps', 'oxps', 'pdf',
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'heif', 'avif', 'jxl', 'jp2',
  'mp3', 'm4a', 'aac', 'ogg', 'oga', 'opus', 'flac', 'wma',
  'mp4', 'm4v', 'mov', 'mkv', 'webm', 'avi', 'wmv', '3gp', 'flv', 'mts', 'm2ts',
  'woff', 'woff2', 'kdbx', 'gpg', 'pgp', 'asc', 'p12', 'pfx', 'vhdx', 'vmdk', 'qcow2', 'iso', 'img',
]);

// Extensions known ransomware gives the files it encrypted (lower case, without the dot).
const RANSOM_EXT = new Set([
  'locked', 'locky', 'encrypted', 'enc', 'crypt', 'crypted', 'crypto', 'cryp1', 'crypz', 'cryptolocker', 'encr', 'enciphered',
  'cerber', 'cerber2', 'cerber3', 'zepto', 'odin', 'thor', 'aesir', 'osiris', 'wncry', 'wnry', 'wcry', 'wncryt',
  'ryk', 'ryuk', 'conti', 'lockbit', 'lockbit3', 'djvu', 'djvuu', 'krab', 'gdcb', 'crab', 'sage', 'dharma', 'phobos', 'eking',
  'makop', 'clop', 'cl0p', 'hive', 'avos', 'avos2', 'akira', 'babyk', 'royal_w', 'rhysida', '8base', 'medusa', 'blacksuit', 'basta',
  'xtbl', 'vvv', 'ecc', 'ezz', 'exx', 'zzz', 'ttt', 'xxx', 'ccc', 'r5a', 'r4a', 'crinf', 'lechiffre', 'keybtc', 'kraken', 'nochance',
  'toxcrypt', 'rokku', 'zcrypt', 'rdm', 'rrk', 'kkk', 'btc', 'gws', 'ctbl', 'ctb2', 'cbf', 'good', 'weapologize', 'lol!', 'omg!',
  'petya', 'globe', 'purge', 'darkness', 'payms', 'paymst', 'paybtcs', 'locklock', 'coded', 'payrms', 'ha3', 'nemty', 'sodinokibi',
  'revil', 'maze', 'egregor', 'ragnar', 'mountlocker', 'blackmatter', 'darkside', 'netwalker', 'stop', 'qlkm', 'lokf', 'pcqq',
]);

function extOf(name) {
  const s = String(name || '');
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  const base = s.slice(slash + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

/** Shannon entropy of the bytes (bits per byte, 0 … 8, 3 decimals); null for nothing. */
function entropyOf(buf) {
  if (!buf || !buf.length) return null;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let h = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1000) / 1000;
}

/** Entropy of the first 64 KB of a file → number | null (unreadable, empty). */
async function fileEntropy(p, bytes = ENTROPY_BYTES) {
  let fh;
  try {
    fh = await fs.promises.open(p, 'r');
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await fh.read(buf, 0, bytes, 0);
    return entropyOf(buf.subarray(0, bytesRead));
  } catch {
    return null;
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

const isCompressed = (name) => COMPRESSED_EXT.has(extOf(name));
const isRansomExt = (name) => RANSOM_EXT.has(extOf(name));

/** Is a changed file with this content suspicious? (see the header) */
function suspiciousChange(name, entropy, prevEntropy = null) {
  if (!Number.isFinite(entropy) || entropy <= ENTROPY_HIGH) return false;
  if (Number.isFinite(prevEntropy)) return prevEntropy < ENTROPY_WAS_LOW;
  return !isCompressed(name);
}

/**
 * Was `newName` made from one of the `goneNames` by appending a ransomware extension
 * ("Brief.docx" → "Brief.docx.locked", "Brief.docx.id-1E2D.[mail].eking")? Names in lower case.
 */
function ransomRename(newName, goneNames) {
  const n = String(newName || '').toLowerCase();
  if (!isRansomExt(n)) return false;
  for (const g of goneNames || []) {
    const old = String(g || '').toLowerCase();
    if (old && n !== old && n.startsWith(`${old}.`)) return true;
  }
  return false;
}

/**
 * Does a run trip the guard?
 * @param {Array<{ dir: string, name: string }>} suspicious - suspicious changes (dir: the folder's key)
 * @param {(dir: string) => number} filesIn - files of a folder (its last agreed state)
 * @returns {{ trip: boolean, count: number, sample: string[] }}
 */
function guardTrips(suspicious, filesIn) {
  const list = Array.isArray(suspicious) ? suspicious : [];
  const count = list.length;
  let trip = count >= GUARD_COUNT;
  if (!trip) {
    const byDir = new Map();
    for (const s of list) byDir.set(s.dir, (byDir.get(s.dir) || 0) + 1);
    for (const [dir, n] of byDir) {
      const total = Math.max(Number(filesIn(dir)) || 0, n);
      if (total >= GUARD_DIR_MIN && n >= GUARD_SHARE * total) { trip = true; break; }
    }
  }
  return { trip, count, sample: list.slice(0, SAMPLE_MAX).map((s) => s.name) };
}

module.exports = {
  ENTROPY_BYTES,
  ENTROPY_HIGH,
  ENTROPY_WAS_LOW,
  GUARD_COUNT,
  GUARD_SHARE,
  GUARD_DIR_MIN,
  COMPRESSED_EXT,
  RANSOM_EXT,
  extOf,
  entropyOf,
  fileEntropy,
  isCompressed,
  isRansomExt,
  suspiciousChange,
  ransomRename,
  guardTrips,
};
