'use strict';

/**
 * GateControl – "In Tresor verschieben" (Drive 1.9 vault folders; like the Android app's DriveVaultMove)
 *
 * A file put into a vault from this PC is moved, not copied: once its encrypted upload is committed and the vault's
 * answer is that very ciphertext (verified(): its size, and its SHA-256 when the server gives one), the unencrypted
 * original is deleted from this PC for good (removeOriginal(): fs.unlink — never the recycle bin, which would keep a
 * plaintext copy). Never after an upload that failed, was skipped or did not happen. The original stays, and the
 * person is told, with the reason:
 *
 *   'changed'  it changed while it was read or uploaded (size or mtime), is no plain file any more, or does not lie
 *              where it was found any more (a folder on its way became a link / junction out of the folder picked);
 *   'locked'   read-only (the Windows attribute — unlink would clear it quietly), or Windows does not let it go
 *              (open in a program: EPERM / EACCES / EBUSY);
 *   'verify'   the vault's answer is not the ciphertext sent;
 *   'error'    anything else.
 *
 * A whole folder (a tree: newTree() when it is walked): each file as above; afterwards removeEmptyDirs() removes its
 * folders, the deepest first — only folders whose every entry went into the vault and was deleted (keep(): a folder
 * with something left in it — left out, failed, kept — and every folder above it stays), and only when they are
 * empty (rmdir never removes anything else and never follows a link).
 */

const fs = require('fs');
const path = require('path');

const LOCKED = new Set(['EPERM', 'EACCES', 'EBUSY']);
const REASONS = ['changed', 'locked', 'verify', 'error'];

const kept = (reason) => ({ original: 'kept', reason: REASONS.includes(reason) ? reason : 'error' });
const samePath = (a, b, platform = process.platform) => (platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);

/** `p` is `root` or lies below it (paths as given, no link resolved). */
function inside(root, p) {
  const rel = path.relative(root, p);
  if (rel === '') return true;
  return !path.isAbsolute(rel) && rel.split(path.sep)[0] !== '..';
}

/**
 * The vault's commit answer `node` is the ciphertext sent: `sent` { cipherSize, sha256 } of the encrypted file
 * (sha256 checked only when the server gives one).
 */
function verified(node, sent) {
  if (!node || node.isDir || !sent || !Number.isSafeInteger(sent.cipherSize) || sent.cipherSize <= 0) return false;
  if (node.size !== sent.cipherSize) return false;
  if (!node.sha256) return true;
  return typeof sent.sha256 === 'string' && node.sha256.toLowerCase() === sent.sha256.toLowerCase();
}

/** A dropped folder `root` on its way into a vault (realRoot: its real path, the folders walked in `dirs`). */
function newTree(root, realRoot) {
  return { root, realRoot: realRoot || root, dirs: [], keep: new Set(), complete: false };
}

/** Something stays in folder `dir` of the tree: it and every folder above it (up to the tree's root) stay. */
function keep(tree, dir) {
  if (!tree || typeof dir !== 'string' || !inside(tree.root, dir)) return;
  let d = dir;
  for (let i = 0; i < 10000; i++) {
    tree.keep.add(d);
    if (samePath(d, tree.root)) return;
    const up = path.dirname(d);
    if (up === d) return;
    d = up;
  }
}

/**
 * Deletes the original `file` of a verified vault upload → { original: 'deleted' } | { original: 'kept', reason }.
 * `read` { size, mtimeMs }: the file as it was encrypted; `tree`: the dropped folder it was found in (null: a file
 * picked on its own). A file gone already counts as deleted.
 */
async function removeOriginal(file, read, { tree = null, fsp = fs.promises } = {}) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || !read) return kept('error');
  try {
    if (tree) {
      // still where the walk found it: no folder on its way became a link (junction) out of the folder picked
      if (!inside(tree.root, file)) return kept('changed');
      const dir = path.dirname(file);
      const real = await fsp.realpath(dir);
      if (!samePath(real, path.join(tree.realRoot, path.relative(tree.root, dir)))) return kept('changed');
    }
    const st = await fsp.lstat(file);
    if (!st.isFile() || st.size !== read.size || st.mtimeMs !== read.mtimeMs) return kept('changed');
    // read-only (Windows: the attribute, which unlink would quietly clear): the person's protection stays
    if ((st.mode & 0o222) === 0) return kept('locked');
    await fsp.unlink(file);
    return { original: 'deleted' };
  } catch (err) {
    const code = err && err.code;
    if (code === 'ENOENT') return { original: 'deleted' };
    return kept(LOCKED.has(code) ? 'locked' : 'error');
  }
}

/**
 * After the files of a dropped folder: its folders that are empty now go, the deepest first → { removed, kept }.
 * Nothing when the folder was not walked to its end (tree.complete false).
 */
async function removeEmptyDirs(tree, { fsp = fs.promises } = {}) {
  const out = { removed: 0, kept: 0 };
  if (!tree || !tree.complete) return out;
  for (const d of [...tree.dirs].reverse()) {
    if (tree.keep.has(d) || !inside(tree.root, d)) { out.kept++; continue; }
    try {
      const st = await fsp.lstat(d);
      if (!st.isDirectory()) throw Object.assign(new Error('not a folder'), { code: 'ENOTDIR' });
      await fsp.rmdir(d);
      out.removed++;
    } catch (err) {
      if (err && err.code === 'ENOENT') continue;
      out.kept++;
      keep(tree, path.dirname(d));
    }
  }
  return out;
}

module.exports = { verified, removeOriginal, removeEmptyDirs, newTree, keep, inside, REASONS };
