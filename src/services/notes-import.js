'use strict';

/**
 * GateControl – Notizen & Aufgaben: the move from Synology DS Note (Core)
 *
 * The .nsx export is read ON THIS PC (plugin README "Umzug aus DS Note"): src/vendor/notizen/nsx.js — the plugin's own
 * reader, unchanged — with random access to the file on disk (a ZIP, ZIP64 for large exports; never loaded as a whole,
 * never uploaded as a whole) and Node's zlib for deflated entries. Each attachment goes up on its own (through a
 * temporary file, removed right after), the notes in batches of ten (import/dsnote/<job>/notes, `attnew:<n>` names a
 * picture of the batch), once per `ref` (an import can be repeated).
 *
 * Protected notes: the password the person typed is tried on the first protected note of a notebook (the CryptoJS /
 * OpenSSL passphrase form nsx.js knows). If it opens, those notes go into a new Tresor notebook made here
 * (services/notes-vault.js; its recovery key goes to `onVault` to be shown once) — encrypted here, the server never
 * sees them. Otherwise they are skipped and counted (protectedSkipped).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const NSX = require('../vendor/notizen/nsx');

const inflateRaw = promisify(zlib.inflateRaw);
const BATCH = 10;
const REF_RE = /[^A-Za-z0-9:._-]/g;

class ImportError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

/** Opens an .nsx export on disk → { archive, summary, close() } (summary: nsx.js summary + file name and size). */
async function openNsx(filePath) {
  const fh = await fs.promises.open(filePath, 'r');
  try {
    const size = (await fh.stat()).size;
    const read = async (a, b) => {
      const len = Math.max(0, Math.min(b, size) - a);
      const out = Buffer.alloc(len);
      let got = 0;
      while (got < len) {
        const { bytesRead } = await fh.read(out, got, len - got, a + got);
        if (!bytesRead) break;
        got += bytesRead;
      }
      return new Uint8Array(out.buffer, out.byteOffset, got);
    };
    const archive = await NSX.open(read, size, { inflateRaw: async (b) => new Uint8Array(await inflateRaw(Buffer.from(b))) });
    const summary = await NSX.summary(archive);
    return {
      archive,
      summary: { ...summary, file: path.basename(filePath).slice(0, 200), size },
      close: () => fh.close().catch(() => {}),
    };
  } catch (err) {
    await fh.close().catch(() => {});
    throw new ImportError(err && err.code === 'unsupported' ? 'unsupported' : 'nsx_invalid', err && err.message);
  }
}

/**
 * Runs the import → { notes, skipped, protectedSkipped, notebooks, vaults }.
 * @param {object} o
 * @param {object} o.archive - openNsx().archive
 * @param {object} o.summary - openNsx().summary
 * @param {object} o.api - NotesApi
 * @param {object|null} o.vault - NotesVault (null: protected notes are skipped)
 * @param {string} o.area - 'private' | 'work'
 * @param {string} [o.password] - for protected notes
 * @param {number} o.attachMB - the largest attachment the plugin takes
 * @param {string} o.tmpDir - for the attachments on their way up
 * @param {(p: object) => void} [o.onProgress] - { done, total, notes, skipped, protectedSkipped }
 * @param {(v: { name, recoveryKey, notebookId }) => void} [o.onVault] - a Tresor notebook was made (show its key once)
 * @param {{ aborted: boolean }} [o.signal]
 * @param {(n: object) => string} [o.untitled] - the title of a note without one
 */
async function runImport(o) {
  const { archive, summary, api, vault, area } = o;
  const stats = { notes: 0, skipped: 0, protectedSkipped: 0, notebooks: 0, vaults: 0 };
  let done = 0;
  const total = summary.notes;
  const tick = () => {
    done++;
    if (typeof o.onProgress === 'function') { try { o.onProgress({ done, total, ...stats }); } catch { /* the caller's */ } }
  };
  const aborted = () => !!(o.signal && o.signal.aborted);
  await fs.promises.mkdir(o.tmpDir, { recursive: true });
  const job = await api.dsStart({ file: summary.file, notebooks: summary.notebooks.length, notes: summary.notes, bytes: summary.bytes });

  // every note once, grouped by its notebook (as the portal does it)
  const byBook = new Map();
  for (const id of summary.noteIds) {
    if (aborted()) break;
    let n;
    try { n = await NSX.note(archive, id); } catch { stats.skipped++; tick(); continue; }
    const k = n.notebookId || '_';
    if (!byBook.has(k)) byBook.set(k, []);
    byBook.get(k).push(n);
  }

  for (const nb of summary.notebooks) {
    if (aborted()) break;
    const rows = byBook.get(nb.id) || [];
    if (!rows.length) continue;
    const ref = String(nb.id).replace(REF_RE, '').slice(0, 90) || 'nb';
    const plain = rows.filter((n) => !n.encrypted);
    const prot = rows.filter((n) => n.encrypted);
    if (plain.length) {
      const notebookId = await api.dsNotebook(job.id, { ref, name: nb.title, area });
      stats.notebooks++;
      await sendNotes(o, job.id, notebookId, plain, null, stats, tick, aborted);
    }
    if (prot.length) {
      let opened = false;
      if (o.password && vault) {
        try { await NSX.decrypt(prot[0].html, o.password); opened = true; } catch { opened = false; }
      }
      if (!opened) {
        stats.protectedSkipped += prot.length;
        prot.forEach(tick);
        continue;
      }
      const made = await vault.create(area, `${nb.title} (DS Note)`.slice(0, 80));
      stats.vaults++;
      if (typeof o.onVault === 'function') { try { o.onVault({ name: `${nb.title} (DS Note)`.slice(0, 80), recoveryKey: made.recoveryKey, notebookId: made.notebook.id }); } catch { /* the caller's */ } }
      await sendNotes(o, job.id, made.notebook.id, prot, { vaultId: made.vault.id }, stats, tick, aborted);
    }
  }
  await api.dsFinish(job.id, { skipped: stats.skipped, protectedSkipped: stats.protectedSkipped });
  if (aborted()) throw new ImportError('cancelled');
  return { ...stats, jobId: job.id };
}

/** A temporary file with `bytes`, uploaded and removed → { mediaId }. */
async function uploadBytes(api, tmpDir, bytes, mime) {
  const tmp = path.join(tmpDir, `nsx-${crypto.randomBytes(8).toString('hex')}`);
  await fs.promises.writeFile(tmp, bytes);
  try {
    return await api.upload({ path: tmp, size: bytes.length, mime });
  } finally {
    await fs.promises.rm(tmp, { force: true }).catch(() => {});
  }
}

async function sendNotes(o, job, notebookId, list, vaultInfo, stats, tick, aborted) {
  const { api, archive, vault } = o;
  const NV = vault ? vault.V : null;
  const maxBytes = o.attachMB * 1048576;
  for (let i = 0; i < list.length; i += BATCH) {
    if (aborted()) return;
    const payload = [];
    for (const n of list.slice(i, i + BATCH)) {
      const att = [];
      const byRef = {};
      const cur = vaultInfo ? vault.current(vaultInfo.vaultId) : null;
      for (let k = 0; k < n.attachments.length; k++) {
        const a = n.attachments[k];
        if (!a.entry || a.size > maxBytes) continue;
        try {
          const bytes = Buffer.from(await archive.bytes(a.entry));
          if (vaultInfo) {
            const ct = NV.encryptBuffer(cur.tk, vaultInfo.vaultId, cur.keyVersion, bytes);
            const up = await uploadBytes(api, o.tmpDir, ct, 'application/octet-stream');
            att.push({ n: k, mediaId: up.mediaId, nameCipher: NV.encryptName(cur.tk, vaultInfo.vaultId, cur.keyVersion, a.name) });
          } else {
            const up = await uploadBytes(api, o.tmpDir, bytes, a.mime);
            att.push({ n: k, mediaId: up.mediaId, name: a.name });
            if (a.ref) byRef[a.ref] = k;
          }
        } catch {
          stats.skipped++;
        }
      }
      const refId = String(n.id).replace(REF_RE, '').slice(0, 90);
      let html = n.html;
      if (vaultInfo) {
        try { html = await NSX.decrypt(n.html, o.password); } catch { stats.protectedSkipped++; tick(); continue; }
      }
      const md = NSX.toMarkdown(html, { image: (ref) => (byRef[ref] != null ? `attnew:${byRef[ref]}` : null) });
      if (!vaultInfo) {
        payload.push({ ref: refId, title: n.title, body: md, tags: n.tags, created: n.created, updated: n.updated, attachments: att });
      } else {
        const body = md + (n.tags.length ? `\n\n${n.tags.map((t) => `#${t.replace(/\s+/g, '-')}`).join(' ')}` : '');
        const title = n.title || (typeof o.untitled === 'function' ? o.untitled(n) : 'Notiz');
        payload.push({
          ref: refId, titleCipher: NV.encryptName(cur.tk, vaultInfo.vaultId, cur.keyVersion, title.slice(0, 300)),
          cipher: NV.encryptBuffer(cur.tk, vaultInfo.vaultId, cur.keyVersion, Buffer.from(body, 'utf8')).toString('base64url'),
          keyVersion: cur.keyVersion, created: n.created, updated: n.updated, attachments: att,
        });
      }
      tick();
    }
    if (payload.length) {
      const r = await api.dsNotes(job, notebookId, payload);
      stats.notes += r.imported;
      stats.skipped += r.skipped;
    }
  }
}

module.exports = { openNsx, runImport, ImportError, NSX };
