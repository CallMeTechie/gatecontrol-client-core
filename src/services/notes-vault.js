'use strict';

/**
 * GateControl – Notizen & Aufgaben: the Tresor notebooks (Core)
 *
 * A Tresor notebook is end-to-end encrypted with Drive's vault format byte for byte, every label starting with
 * "gcnotes-v1" (plugin README "Tresor-Notizbücher – Kryptografie"; utils/drive-vault.js withPrefix). The keys and the
 * flows are Drive's (services/drive-vault.js: the device key under DPAPI, open, ask for access, approve after the
 * safety number, the recovery key, a new key, stale keys) — with their own device keys in the store
 * (`notesVault`, one per server) and the notebook in place of Drive's folder node.
 */

const DriveVault = require('./drive-vault');
const V = require('../utils/drive-vault');

const NV = V.withPrefix('gcnotes-v1');
const STORE_KEY = 'notesVault';

class NotesVault extends DriveVault {
  constructor(opts = {}) {
    super({ ...opts, crypto: NV, storeKey: STORE_KEY, label: 'Notizen vault' });
  }

  /** A vault as the page shows it: its notebook, its name when open, this device's state. */
  view(v) {
    const dev = this._device;
    const mine = dev ? v.myDevices.find((d) => d.deviceId === dev.id) : null;
    let name = null;
    const m = this.keysOf(v.id);
    if (m && v.nameCipher) { try { name = NV.decryptName(m, v.id, v.nameCipher); } catch { name = null; } }
    if (v.keyVersion) this._current.set(v.id, Math.max(this._current.get(v.id) || 0, v.keyVersion));
    return {
      id: v.id, notebookId: v.notebookId, area: v.area, name, keyVersion: v.keyVersion, needsRotation: v.needsRotation,
      pending: v.pending, recoveryHolder: v.recoveryHolder, createdAt: v.createdAt,
      state: this.isOpen(v.id) ? 'open' : mine ? (mine.state === 'approved' ? (this.isUnlocked() ? 'approved' : 'locked') : mine.state) : 'none',
    };
  }

  /** The name of a Tresor notebook ({ vault: { id, nameCipher } }) when its keys are here, else null. */
  notebookName(nb) {
    const v = nb && nb.vault;
    if (!v || !v.nameCipher) return null;
    const m = this.keysOf(v.id);
    if (!m) return null;
    if (v.keyVersion) this._current.set(v.id, Math.max(this._current.get(v.id) || 0, v.keyVersion));
    try { return NV.decryptName(m, v.id, v.nameCipher); } catch { return null; }
  }

  /**
   * A new Tresor notebook `name` in `area` → { vault, notebook, recoveryKey } — recoveryKey (text) is shown once; the
   * plugin keeps only its public key and the SHA-256 of its proof.
   */
  async create(area, name) {
    this._ensureScope();
    const dev = await this.device();
    const id = NV.newVaultId();
    const tk = NV.newVaultKey();
    const rec = await NV.newRecoveryKey();
    const rk = NV.recoveryKeyPair(rec.key);
    try {
      const body = {
        id,
        area,
        nameCipher: NV.encryptName(tk, id, 1, name),
        recoveryPub: NV.b64u(rk.publicRaw),
        recoveryAuth: NV.recoveryAuth(rec.key),
        recoveryWrap: NV.wrapKey(tk, rk.publicRaw, id, 1),
        device: { publicKey: dev.publicKey, name: dev.name, platform: 'windows' },
        wrap: NV.wrapKey(tk, this._device.publicRaw, id, 1),
      };
      const r = await this.api.createVault(body);
      this._keys.set(id, new Map([[1, Buffer.from(tk)]]));
      this._current.set(id, 1);
      this._states.set(id, { state: 'open', at: this.now() });
      return { vault: this.view(r.vault), notebook: { ...r.notebook, name }, recoveryKey: rec.text };
    } finally {
      NV.wipe(tk);
      NV.wipe(rec.key);
      NV.wipe(rk.privateRaw);
    }
  }
}

NotesVault.STORE_KEY = STORE_KEY;
NotesVault.crypto = NV;

module.exports = NotesVault;
