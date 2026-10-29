'use strict';

/**
 * GateControl – Drive: jobs for many files and folders at once (Core, Drive 1.12 "Mehrfachauswahl")
 *
 * The selection of the page goes to Drive as one job (`bulk`): move, copy, into the trash (and restore / purge).
 *   - check(): what would happen → { files, folders, bytes, conflicts, blocked } (`ops/check`, changes nothing).
 *     Conflicts are the names the target has already: the page asks once for all of them ("Als neue Version
 *     speichern" / "Beide behalten" / "Überspringen"; the same content counts as done, nothing is stored twice;
 *     folders of the same name are merged by Drive). Blocked are the nodes that cannot go ('forbidden', 'into_itself',
 *     'encrypted', 'locked', 'root', 'same_folder', …) — the rest goes.
 *   - start(): the job (`POST ops`); small ones come back done, larger ones run on the server — on in the background
 *     when the app ends; their progress shows as a row of the transfer list (dir 'op': files done of total, bytes),
 *     asked every second while one runs and taken from the live event `op`; on the next start the person's running
 *     jobs are picked up again (`GET ops?state=running`). "Abbrechen": what is done stays. When a job ends the event
 *     'op' (the row) lets the page show "N Elemente nach „Ziel“ verschoben · Rückgängig" (until `undoUntil`:
 *     `POST ops/<id>/undo` — moved back, out of the trash again, copies into the trash).
 *   - Copying only with 'copyServer' (GateControl copies the media itself); this app never brings the bytes of a copy
 *     (the transfer routes of Drive 1.12 are not used).
 *   - Without `bulk` (an older Drive): move and trash run here as a loop of the single calls (a taken name: "Beide
 *     behalten" or "Überspringen", a new version is not possible without Drive 1.12); copy and undo are not offered.
 *   - Vault folders (Drive 1.9): never across the vault's border (`encrypted`); inside the same vault moving runs here
 *     (Drive only knows the encrypted names: the conflicts are found by the names decrypted on this PC, a free name is
 *     encrypted for "Beide behalten"); into the trash as any job; copying in a vault is not offered.
 *
 * Rows of jobs: { id: 'o<job>', dir: 'op', opId, kind, state: running | done | failed | cancelled, name, count,
 * targetId, targetName, total, done, bytesTotal, bytesDone, results, undoUntil, undoable, local, undo, code, at }.
 */

const MessengerApi = require('./messenger-api');
const drive = require('../utils/drive');
const S = require('../utils/drive-sync');

const { MessengerError: DriveError } = MessengerApi;

const CHECK_OPS = Object.freeze(['move', 'copy', 'trash']);
const LOCAL_MAX = 1000;        // nodes a loop of single calls handles (older Drives, vaults)
const PARALLEL = 4;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Runs `fn` over `list` with at most `n` at a time (in order of the list) → results. */
async function mapLimit(list, n, fn) {
  const out = new Array(list.length);
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const i = next++;
      out[i] = await fn(list[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, list.length) }, worker));
  return out;
}

const label = (v, max = 255) => (typeof v === 'string' && v.trim() ? v.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, max) : null);

class DriveOps {
  /**
   * @param {object} o
   * @param {object} o.api - DriveApi
   * @param {object} o.vault - DriveVault (names of vault nodes)
   * @param {Function} o.row - DriveService._row(row): a new row of the transfer list
   * @param {Function} o.set - DriveService._set(id, patch, { progress })
   * @param {Function} o.emit - DriveService.emit(event, payload)
   * @param {Function} o.siblings - DriveService._vaultSiblings(folderId, vaultId) → [{ node, name }]
   * @param {() => number} [o.now]
   * @param {object} [o.timing] - { opPollMs }
   * @param {object} [o.log]
   */
  constructor({ api, vault, row, set, emit, siblings, now = Date.now, timing = {}, log = null }) {
    this.api = api;
    this.vault = vault;
    this._rowFn = row;
    this._setFn = set;
    this._emit = emit;
    this._siblings = siblings;
    this.now = now;
    this.timing = { opPollMs: 1000, ...timing };
    this.log = log || noopLog();
    this._ops = new Map();       // job id → { row, meta, local, cancel }
    this._poll = null;
    this._polling = false;
    this._nextLocal = 0;
  }

  stop() {
    clearTimeout(this._poll);
    this._poll = null;
  }

  /** server:setup: the jobs of the old server are not followed any more. */
  reset() {
    this.stop();
    for (const j of this._ops.values()) j.cancel = true;
    this._ops.clear();
  }

  // ── What would happen ───────────────────────────────────

  _ids(ids) {
    const list = drive.idList(ids);
    if (!list) throw new DriveError('invalid ids', { code: 'invalid' });
    return list;
  }

  /**
   * Whether this job runs here (a loop of single calls) or on the server, and the nodes it needs to know:
   * { bulk, local, vaultId, nodes?, target? }. `encrypted`: across a vault's border (or copying in a vault).
   */
  async _plan(op, ids, target) {
    const bulk = await this.api.has('bulk').catch(() => false);
    const vaultOn = await this.api.has('vault').catch(() => false);
    let first = null;
    let tgt = null;
    if (vaultOn) {
      first = await this.api.node(ids[0]);
      if (target) tgt = await this.api.node(target);
    }
    const vaultId = first && first.encrypted ? first.vaultId : null;
    const tgtVault = tgt && tgt.encrypted ? tgt.vaultId : null;
    if ((op === 'move' || op === 'copy') && (vaultId || tgtVault) && (vaultId !== tgtVault || op === 'copy')) {
      return { bulk, local: true, vaultId, blockedAll: 'encrypted' };
    }
    // copying needs Drive 1.12 and GateControl's media copy ('copyServer'; the bytes are never brought by this app)
    if (op === 'copy' && !(bulk && await this.api.has('copyServer').catch(() => false))) throw new DriveError('Drive cannot copy', { code: 'unsupported' });
    // a vault's move runs here (Drive knows only the encrypted names); everything else on the server when it can
    const local = !bulk || (op === 'move' && !!vaultId);
    return { bulk, local, vaultId };
  }

  /** The nodes of `ids` (here only: older Drives, vaults) → [node | null] */
  _nodes(ids) {
    return mapLimit(ids, PARALLEL, (id) => this.api.node(id).catch(() => null));
  }

  /** The names in the target folder → Map(keyOf(name) → node), decrypted in a vault. */
  async _taken(target, vaultId) {
    const map = new Map();
    if (vaultId) {
      for (const x of await this._siblings(target, vaultId)) map.set(S.keyOf(x.name), { ...x.node, name: x.name });
    } else {
      for (const n of await this.api.childrenAll(target)) if (!n.deleted && !n.encrypted) map.set(S.keyOf(n.name), n);
    }
    return map;
  }

  /** The name of a node as the person knows it (decrypted in a vault). */
  _nameOf(n) {
    if (!n) return null;
    if (!n.encrypted) return n.name;
    return this.vault.nameOf(n) || null;
  }

  /**
   * → { ok, bulk, local, files, folders, bytes, conflicts, blocked } — nothing changes. A loop here (older Drive,
   * vault) finds the same: blocked 'into_itself' / 'here' (already in that folder) / 'not_found', conflicts by name.
   */
  async check({ op, ids, target = null }) {
    if (!CHECK_OPS.includes(op)) throw new DriveError('invalid job', { code: 'invalid' });
    const list = this._ids(ids);
    const tgt = op === 'trash' ? null : drive.posId(target);
    if (op !== 'trash' && !tgt) throw new DriveError('invalid target', { code: 'invalid' });
    const plan = await this._plan(op, list, tgt);
    if (plan.blockedAll) {
      return { ok: true, bulk: plan.bulk, local: true, files: 0, folders: 0, bytes: 0, conflicts: [], blocked: list.map((id) => ({ id, reason: plan.blockedAll })) };
    }
    if (!plan.local) return { ok: true, bulk: true, local: false, ...(await this.api.opsCheck({ op, ids: list, target: tgt })) };
    if (list.length > LOCAL_MAX) throw new DriveError('too many', { code: 'too_many' });
    return { ok: true, bulk: plan.bulk, local: true, ...(await this._checkHere(op, list, tgt, plan.vaultId)) };
  }

  async _checkHere(op, list, tgt, vaultId) {
    const nodes = await this._nodes(list);
    const out = { files: 0, folders: 0, bytes: 0, conflicts: [], blocked: [] };
    let crumbs = [];
    let taken = new Map();
    if (op !== 'trash') {
      const f = await this.api.folder(tgt, { limit: 1 });
      crumbs = (f.crumbs || []).map((c) => c.id).concat(f.node.id);
      taken = await this._taken(tgt, vaultId);
    }
    for (let i = 0; i < list.length; i++) {
      const n = nodes[i];
      const id = list[i];
      if (!n || n.deleted) { out.blocked.push({ id, reason: 'not_found' }); continue; }
      if (vaultId && n.vaultId !== vaultId) { out.blocked.push({ id, reason: 'encrypted' }); continue; }
      if (op !== 'trash') {
        if (n.id === tgt || (n.isDir && crumbs.includes(n.id))) { out.blocked.push({ id, reason: 'into_itself' }); continue; }
        if (n.parentId === tgt) { out.blocked.push({ id, reason: 'same_folder' }); continue; }
        const name = this._nameOf(n);
        const have = name ? taken.get(S.keyOf(name)) : null;
        if (have) {
          out.conflicts.push({
            id, name, isDir: n.isDir, size: n.isDir ? null : n.size, mtime: n.mtime,
            existing: { id: have.id, size: have.isDir ? null : have.size, mtime: have.mtime, isDir: have.isDir },
            same: !n.isDir && !have.isDir && !!n.sha256 && n.sha256 === have.sha256,
          });
        }
      }
      if (n.isDir) out.folders++;
      else { out.files++; out.bytes += n.size || 0; }
    }
    return out;
  }

  // ── Doing it ────────────────────────────────────────────

  /**
   * Starts the job → { ok, op: row }. `meta` (what the page names it): { name: the first node's name, count, target:
   * the target folder's name, parents: [folder ids the nodes come from] }.
   */
  async start({ op, ids, target = null, onConflict = null, meta = {} }) {
    if (!drive.OP_KINDS.includes(op)) throw new DriveError('invalid job', { code: 'invalid' });
    const list = this._ids(ids);
    const tgt = op === 'move' || op === 'copy' ? drive.posId(target) : null;
    if ((op === 'move' || op === 'copy') && !tgt) throw new DriveError('invalid target', { code: 'invalid' });
    if (onConflict !== null && !drive.OP_CONFLICT.includes(onConflict)) throw new DriveError('invalid choice', { code: 'invalid' });
    const m = {
      name: label(meta.name),
      count: drive.count(meta.count) || list.length,
      target: label(meta.target),
      parents: (Array.isArray(meta.parents) ? meta.parents : []).map(drive.posId).filter(Boolean).slice(0, 100),
      ids: list,
      op,
      targetId: tgt,
    };
    // restore / purge (out of the trash) only as a job of Drive 1.12
    const plan = CHECK_OPS.includes(op) ? await this._plan(op, list, tgt) : { bulk: await this.api.has('bulk').catch(() => false), local: false };
    if (plan.blockedAll) throw new DriveError('across a vault', { code: 'encrypted' });
    if (!plan.local) {
      if (!plan.bulk) throw new DriveError('Drive cannot do this', { code: 'unsupported' });
      const job = await this.api.opsStart({ op, ids: list, target: tgt, onConflict });
      return { ok: true, op: this._track(job, m) };
    }
    if (list.length > LOCAL_MAX) throw new DriveError('too many', { code: 'too_many' });
    return { ok: true, op: this._runHere({ op, list, tgt, onConflict, vaultId: plan.vaultId, meta: m }) };
  }

  /** A row for the job `job` of the server, followed until it ends. */
  _track(job, meta) {
    const have = this._ops.get(job.id);
    if (have) { this._update(job); return { ...have.row }; }
    const undo = !!meta.undo || job.kind === 'undo';
    const row = {
      id: `o${job.id}`, dir: 'op', opId: job.id, kind: job.kind && job.kind !== 'undo' ? job.kind : meta.op || null, state: 'running',
      name: meta.name || job.name || null, count: meta.count || job.count || job.total || 0,
      targetId: job.targetId || meta.targetId || null, targetName: meta.target || job.targetName || job.targetPath || null,
      total: 0, done: 0, bytesTotal: 0, bytesDone: 0, results: null, undoUntil: null, undoable: false,
      local: false, undo, code: null, at: this.now(),
    };
    this._ops.set(job.id, { row, meta, local: false, cancel: false });
    this._rowFn(row);
    this._update(job);
    return { ...row };
  }

  /** A job's state from the server (answer, poll, live event). */
  _update(job) {
    const j = this._ops.get(job.id);
    if (!j || j.row.state !== 'running') return;
    const patch = {
      total: job.total, done: Math.min(job.done, job.total || job.done), bytesTotal: job.bytesTotal, bytesDone: job.bytesDone,
      ...((job.targetName || job.targetPath) && !j.row.targetName ? { targetName: job.targetName || job.targetPath } : {}),
      ...(job.targetId && !j.row.targetId ? { targetId: job.targetId } : {}),
    };
    if (job.state === 'running') {
      this._setFn(j.row.id, patch, { progress: true });
      this._schedule();
      return;
    }
    this._finish(j, { ...patch, state: job.state, results: job.results, undoUntil: job.undoUntil, code: job.code });
  }

  _finish(j, patch) {
    const undoable = patch.state === 'done' && !j.local && !j.row.undo && Number.isFinite(patch.undoUntil) && patch.undoUntil > this.now();
    this._setFn(j.row.id, { ...patch, undoable });
    Object.assign(j.row, patch, { undoable });
    if (j.local) this._ops.delete(j.row.opId);
    // jobs that ended are kept for "Rückgängig" (the newest 50)
    const ended = [...this._ops].filter(([, x]) => x.row.state !== 'running');
    for (const [id] of ended.slice(0, Math.max(0, ended.length - 50))) this._ops.delete(id);
    const folders = new Set([j.row.targetId, ...(j.meta.parents || [])].filter(Boolean));
    for (const folderId of folders) this._emit('changed', { folderId });
    this._emit('op', { ...j.row });
  }

  _schedule() {
    if (this._poll) return;
    if (![...this._ops.values()].some((j) => !j.local && j.row.state === 'running')) return;
    this._poll = setTimeout(() => { this._poll = null; this._pollNow().catch(() => {}); }, this.timing.opPollMs);
    if (this._poll.unref) this._poll.unref();
  }

  async _pollNow() {
    if (this._polling) return;
    this._polling = true;
    try {
      for (const [id, j] of [...this._ops]) {
        if (j.local || j.row.state !== 'running') continue;
        try {
          this._update(await this.api.op(id));
        } catch (err) {
          if (err && err.status === 404) this._finish(j, { state: 'failed', code: 'not_found' });
        }
      }
    } finally {
      this._polling = false;
      this._schedule();
    }
  }

  /** The live event `op` of the plugin (progress, throttled; the end). */
  onEvent(data) {
    const job = drive.normalizeOp(data);
    if (job && this._ops.has(job.id)) this._update(job);
  }

  /** The person's jobs still running on the server (after a restart) → followed again. */
  async resume() {
    if (!(await this.api.has('bulk').catch(() => false))) return [];
    const jobs = await this.api.ops({ state: 'running' });
    return jobs.filter((job) => !this._ops.has(job.id)).map((job) => this._track(job, { op: job.kind === 'undo' ? null : job.kind }));
  }

  /** "Abbrechen": what is done stays → { ok, op } */
  async cancel(opId) {
    const id = drive.opIdOf(opId);
    const j = id && this._ops.get(id);
    if (!j) throw new DriveError('no such job', { code: 'not_found' });
    if (j.local) { j.cancel = true; return { ok: true, op: { ...j.row } }; }
    // Drive stops it at the next step: the row ends with its report (answer or the next poll)
    this._update(await this.api.opCancel(id));
    return { ok: true, op: { ...j.row } };
  }

  /** "Rückgängig" (until undoUntil) → { ok, op: the row of the job that undoes it } */
  async undo(opId) {
    const id = drive.opIdOf(opId);
    const j = id && this._ops.get(id);
    if (j && j.local) throw new DriveError('cannot undo', { code: 'unsupported' });
    const job = await this.api.opUndo(id || opId);
    if (j) this._setFn(j.row.id, { undoable: false, undone: true });
    const meta = j ? { ...j.meta, undo: true, op: j.meta.op, parents: [...(j.meta.parents || []), j.row.targetId].filter(Boolean) } : { undo: true };
    return { ok: true, op: this._track(job, meta) };
  }

  // ── A loop of single calls (older Drives, vaults) ───────

  _runHere({ op, list, tgt, onConflict, vaultId, meta }) {
    const opId = `l${++this._nextLocal}`;
    const row = {
      id: `o${opId}`, dir: 'op', opId, kind: op, state: 'running', name: meta.name, count: meta.count,
      targetId: tgt, targetName: meta.target, total: list.length, done: 0, bytesTotal: 0, bytesDone: 0,
      results: null, undoUntil: null, undoable: false, local: true, undo: false, code: null, at: this.now(),
    };
    const j = { row, meta, local: true, cancel: false };
    this._ops.set(opId, j);
    this._rowFn(row);
    this._loop(j, { op, list, tgt, onConflict, vaultId }).catch((err) => {
      this.log.info(`Drive job here failed: ${drive.errorCode(err)}`);
      this._finish(j, { state: 'failed', code: drive.errorCode(err) });
    });
    return { ...row };
  }

  async _loop(j, { op, list, tgt, onConflict, vaultId }) {
    const res = { done: 0, skipped: 0, failed: [], failedCount: 0, resultIds: [] };
    let taken = new Map();
    if (op === 'move') taken = await this._taken(tgt, vaultId);
    const keys = new Set(taken.keys());
    let done = 0;
    for (const id of list) {
      if (j.cancel) break;
      try {
        if (op === 'trash') {
          await this.api.trash(id);
          res.done++;
        } else {
          const n = await this.api.node(id);
          if (n.parentId === tgt) { res.skipped++; continue; }
          if (vaultId && n.vaultId !== vaultId) throw new DriveError('across a vault', { code: 'encrypted' });
          const name = this._nameOf(n);
          if (!name) throw new DriveError('vault locked', { code: 'vault_locked' });
          const k = S.keyOf(name);
          const have = taken.get(k);
          if (have && (onConflict === 'skip' || (have.sha256 && have.sha256 === n.sha256 && !n.isDir && !have.isDir))) {
            res.skipped++;
          } else if (have) {
            // "Beide behalten" (a new version is only possible with Drive 1.12)
            const free = freeName(name, keys, n.isDir);
            await this._moveTo(n, tgt, free, vaultId);
            keys.add(S.keyOf(free));
            res.done++;
            res.resultIds.push(n.id);
          } else {
            await this._moveTo(n, tgt, null, vaultId);
            keys.add(k);
            res.done++;
            res.resultIds.push(n.id);
          }
        }
      } catch (err) {
        res.failed.push({ id, reason: drive.errorCode(err) });
      } finally {
        done++;
        this._setFn(j.row.id, { done }, { progress: true });
      }
    }
    res.failedCount = res.failed.length;
    this._finish(j, { state: j.cancel ? 'cancelled' : (res.failed.length && !res.done ? 'failed' : 'done'), done, results: res, code: res.failed.length ? res.failed[0].reason : null });
  }

  async _moveTo(n, tgt, newName, vaultId) {
    if (!vaultId) {
      await this.api.place(n.id, { parentId: tgt, ...(newName ? { name: newName } : {}) });
      return;
    }
    await this.api.move(n.id, tgt);
    if (newName) await this.vault.withCurrent(vaultId, (cur) => this.api.renameEncrypted(n.id, this.vault.encryptName(vaultId, newName, cur).nameCipher));
  }
}

/** "Brief.pdf" → "Brief (2).pdf" while its key is taken; a folder without the extension rule. */
function freeName(name, taken, dir = false) {
  if (!taken.has(S.keyOf(name))) return name;
  const dot = dir ? -1 : name.lastIndexOf('.');
  const base = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  for (let i = 2; i < 10000; i++) {
    const c = `${base} (${i})${ext}`;
    if (!taken.has(S.keyOf(c))) return c;
  }
  return `${base} (${Date.now()})${ext}`;
}

DriveOps.LOCAL_MAX = LOCAL_MAX;
DriveOps.freeName = freeName;

module.exports = DriveOps;
