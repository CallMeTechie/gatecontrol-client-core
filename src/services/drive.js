'use strict';

/**
 * GateControl – Drive (Core service)
 *
 * The data side of the page "Drive" in the Windows Pro app: the files of the
 * person, the family, the children and the team on the own storage (plugin
 * `gatecontrol-drive`, README "API"), over the device token of the existing
 * ApiClient (services/drive-api.js):
 *
 * - Availability: the page exists only while GET /api/v1/client/plugins lists
 *   `gatecontrol-drive` (like Schule / GateDrop / Vault). Asked at start,
 *   every 30 min, after a push reconnect and on check(); network errors are
 *   retried (5 s … 5 min). Seat and licence come with `me()` (the page tells
 *   "not switched on" / "no licence").
 * - Browse: areas, folders (crumbs, role, content), search (name and the
 *   recognised text of scans), trash, versions, links — every answer cleaned
 *   by utils/drive.js.
 * - Change: new folder, rename, move, into the trash, restore, purge, restore
 *   a version, create / end links.
 * - Upload: files from disk, one after the other in the background: SHA-256
 *   (≤ 2 GB) → `uploads/check` (the same file there already: skipped; the
 *   name taken: the person chooses "Neue Version" / "Beide behalten" /
 *   "Überspringen") → media upload (resumable above 8 MiB, GateDropApi) →
 *   `uploads/commit`. The list of transfers goes to the page ('transfers').
 * - Open / save: `nodes/<id>/content` → the file streamed into
 *   %TEMP%\gatecontrol-drive\<node>-<rev>\<name> and opened with the default
 *   program (executables only "Speichern unter …"), or into a path the person
 *   picks ("Speichern unter …"; a version too).
 * - Previews: the small / large picture of a file by mediaId (cached in memory).
 * - The folder last picked in "In Drive speichern" (chat, GateDrop, Schule) is
 *   remembered per server (store key `driveLastFolder`).
 *
 * - Whole folders (dropped, or "Ordner hochladen"): the structure is made
 *   first (a taken top name gets a free one, "Fotos (2)"), the files go into
 *   the queue; temporary files, node_modules / .git and names Drive does not
 *   take are left out (like "Ordner sichern"); empty files only on Drives
 *   with 'emptyFiles'.
 * - PDFs with a text layer: their text goes with the commit (`text`, for the
 *   search; utils/pdf-text.js, at most 50 MB / 10 s, failures ignored).
 * - Drive 1.6 'links': "Im Portal öffnen" of a file / folder opens
 *   `me.links.node` with its id – only https and only on the server's or the
 *   portal's host.
 * - Drive 1.6 'guard': the entropy of the first 64 KB goes with every commit;
 *   a write refused with 423 `device_locked` (Drive stopped this device after
 *   unusual changes), the live event `guard` and `me.guard` give the state
 *   (guard()); "Rückgängig machen" / "War ich – freigeben" decide it
 *   (guardDecide()).
 * - Live: the plugin's push event `changed { areas, seq }` is passed on
 *   ('remote'); the page reloads what it shows.
 * - Drive 1.7 'takenAt': pictures and videos carry the time they were taken
 *   (EXIF / the video's header, utils/taken-at.js) with the commit.
 * - Drive 1.7 'timeTravel': a folder back to how it was at a time (preview
 *   first; "Rückgängig" is a time travel to `before`). After it the event
 *   'timetravel' { folderId, at, before } lets "Ordner sichern" run the
 *   folders of this PC that lie there.
 * - Drive 1.7 'photos' / 'albums' / 'frame' / 'storage': the timeline of
 *   pictures, "Vor einem Jahr", albums (also for the photo frame) and the
 *   storage overview (largest files, duplicates); the previews of photos
 *   whose answer names no mediaId are loaded by the node.
 *
 * - Drive 1.8 'docAi': what Drive recognised in a document (kind, title, date,
 *   sender, amount, a suggested name / folder to take, its deadlines with the
 *   person's reminder), "Erneut erkennen", the deadlines of all files, the
 *   switch per area. A click on a deadline reminder (push topic `deadline`)
 *   opens the file on the page (NotificationCenter.addClickRoute).
 * - Drive 1.8 'cloudImport': the import runs in the portal only — its page
 *   `/portal?drive=import#plg-gatecontrol-drive` opens in the browser.
 * - Drive 1.9 'office': "Im Browser bearbeiten / ansehen" — POST
 *   nodes/<id>/office, its https address goes to the default browser.
 * - Drive 1.9 'vault' (services/drive-vault.js): vault folders, end-to-end
 *   encrypted on this PC. Listings show their names decrypted (when this device
 *   has the key, else `locked`); uploads into a vault are encrypted chunk by
 *   chunk into a temporary file (ciphertext only) and go up as
 *   application/octet-stream with nameCipher / keyVersion; opening decrypts into
 *   %TEMP%\gatecontrol-drive\vault\<random>\<name>, removed again after
 *   VAULT_OPEN_KEEP_MS (later while the file is in use), at stop and at the next
 *   start; renaming and new folders send the encrypted name. No previews, text,
 *   takenAt, entropy, links, office or AI for them.
 * - Drive 1.11 (the menu): the folder tree of the menu (tree(): folders only, `hasDirs`; with 'vaultsApart' the
 *   server's `children?dirs=1`, else the plain children filtered here); vault folders are left out of every folder
 *   listing and the search (only the menu's "Tresore" shows them, from vaults()); a new vault always goes into the
 *   top folder of the area picked. The vault lock (services/drive-vault-lock.js): the vault keys are unwrapped only
 *   after Windows Hello (vaultUnlock()); after a time without use, when the window is hidden, when Windows locks or
 *   sleeps the keys are wiped, the decrypted names forgotten and the decrypted copies removed (event 'vaultLock').
 *   The cache on this PC (opened files, previews; never vault keys or uploads still running): cacheInfo() /
 *   clearCache().
 *
 * - Drive 1.12 'bulk' / 'zip' / 'multiLink' (the selection of many files and folders, services/drive-ops.js): what
 *   a job would do (conflicts, what cannot go), the job itself (move, copy, into the trash) as a row of the transfer
 *   list that runs on in the server, "Abbrechen", "Rückgängig"; older Drives: move and trash as a loop of single
 *   calls. "Herunterladen (ZIP)" of a selection into a path the person picks, one link for several files.
 *
 * - Drive 1.14 (only with the features `me` reports): 'deadlineCalendar' — a deadline into the family calendar
 *   (POST deadlines/<id>/calendar); 'docAsk' — a question to the person's documents (POST ask: the answer only from
 *   their files, with the sources and quotes); 'photoSearch' — photos by what is on them (GET photos?q=, the labels
 *   come from the phones); 'scanDocs' — "In Dokument umwandeln" of pictures: scans/classify (with the text of the
 *   pages first, read on this PC), then the document: printed text becomes a searchable PDF made here (Windows OCR,
 *   services/windows-ocr.js + utils/searchable-pdf.js; no AI); else Drive makes the document's bytes (scans/convert —
 *   with smaller copies of the pictures for a PDF's pages, a whiteboard's photo, a handwritten page; Drive writes no
 *   file itself), this PC uploads them and files them with scans/save (with the recognised text; "Original-Scan
 *   behalten" off: the first picture into the trash by Drive, the other pages here). 'deadlineCalendar' also: per area
 *   new deadlines into the calendar on their own (PATCH areas/<id> { deadlinesToCalendar }).
 *
 * - Drive 1.17 'deadlineMailCalendar': deadlines into a calendar of the mail plugin too — the calendars to choose
 *   (deadlines/calendars), the person's own target per area (deadlines/targets), "In Kalender eintragen" with a target.
 *
 * - Drive 1.18 'overview': the page's "Übersicht" (overview()) in one call; an older Drive's overview is built here from
 *   what it has (deadlines, photos/memories, people, photos/places, photos/classes, the storage of the areas), without
 *   "Zuletzt geöffnet" and "Neu in …" (utils/drive-overview.js).
 *
 * - Drive 1.16 (only with the features `me` reports): 'photoPlaces' — pictures and videos carry where they were taken
 *   (EXIF GPS / the video's ©xyz, utils/taken-at.js) with the commit unless the person switched keepGeo off; the
 *   places, the map's clusters (the tiles come from services/map-service.js like the chats' maps), photos of a place,
 *   a box of the map, the settings (keepGeo, stripGeoOnShare) and "Orte löschen" (DELETE photos/geo).
 *   'photoPeople' — the people the phones recognised (the faces are found on the devices only; this PC finds none):
 *   people, a person with "Ist das auch …?" (uncertain faces), "Zusammen mit", naming (a name taken merges both),
 *   hiding, merging, "Sieht aus wie …", a face to another person, photos of people; `people: false` deletes all face
 *   data. Both: suggestions while typing (photos/suggest) and the marks of a search (people, places).
 *
 * Events: 'state' (status()), 'transfers' (list of uploads / downloads),
 * 'changed' ({ folderId }) after an upload landed in a folder, 'remote'
 * ({ areas, seq }) Drive changed elsewhere, 'guard' (guard state),
 * 'timetravel' ({ folderId, at, before }) after a time travel, 'vault'
 * ({ vault, event, device, keyVersion }) a request / approval / new key of a
 * vault folder (live event `vault`), 'vaultLock' ({ locked, reason }) the vaults
 * locked / unlocked (Drive 1.11), 'op' (the row of a job that ended, Drive 1.12).
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const DriveApi = require('./drive-api');
const DriveVault = require('./drive-vault');
const DriveVaultLock = require('./drive-vault-lock');
const DriveOps = require('./drive-ops');
const V = require('../utils/drive-vault');
const MessengerApi = require('./messenger-api');
const drive = require('../utils/drive');
const OV = require('../utils/drive-overview');
const S = require('../utils/drive-sync');
const G = require('../utils/drive-guard');
const { pdfText, isPdf } = require('../utils/pdf-text');
const { shot: readShot, isMediaName } = require('../utils/taken-at');
const { unsafeToOpen, safeFileName } = require('../utils/messenger');
const { guessMime } = require('../utils/gatedrop');
const { openExternalSafely } = require('../utils/external-url');
const { buildSearchablePdf, pagesText } = require('../utils/searchable-pdf');

const { MessengerError: DriveError } = MessengerApi;

const DEFAULT_TIMING = {
  recheckMs: 30 * 60 * 1000,
  retryMinMs: 5000,
  retryMaxMs: 5 * 60 * 1000,
  progressMs: 250,         // transfer list updates at most every 250 ms while bytes move
  previewCache: 300,       // pictures kept in memory
  keepTransfers: 50,       // finished rows kept in the list
  minuteMs: 60 * 1000,     // Drive 1.11: the vault lock's minutes
  opPollMs: 1000,          // Drive 1.12: a running job is asked every second
};
const STORE_KEY = 'driveLastFolder';
const MAX_PATHS = 200;
const FOLDER_MAX_FILES = 20000;   // a dropped folder: at most this many files …
const FOLDER_MAX_DIRS = 5000;     // … and folders
const ME_MAX_AGE = 10 * 60 * 1000;
const VAULT_OPEN_KEEP_MS = 10 * 60 * 1000;   // a decrypted file opened from a vault is removed after this …
const VAULT_OPEN_RETRY_MS = 5 * 60 * 1000;   // … or later while a program still holds it
const DEADLINE_TOPIC = `plugin:${drive.PLUGIN_ID}:deadline`;
const VAULT_TOPIC = `plugin:${drive.PLUGIN_ID}:vault`;
const SCAN_KEEP_MS = 30 * 60 * 1000;          // a prepared scan (its pictures on this PC) is dropped after this
const SCAN_IMAGE_MAX = 40 * 1024 * 1024;      // a picture larger than this is not read on this PC
const SCAN_MIME_RE = /^image\/(jpeg|png)$/i;  // what this PC can read (Electron's decoder) …
const SCAN_ANY_RE = /^image\/(jpeg|png|webp|heic|heif|tiff|bmp)$/i;   // … and what Drive takes as a scan
const SCAN_EXT = { pdf: 'pdf', docx: 'docx', xlsx: 'xlsx' };

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

const SCAN_NAME_EXT_RE = /\.(jpe?g|png|webp|hei[cf]|tiff?|bmp|pdf|docx|xlsx)$/i;

/** `name` with the extension `ext` (a picture's or document's extension already there is replaced). */
function withExt(name, ext) {
  const base = String(name || '').trim().replace(SCAN_NAME_EXT_RE, '');
  return ext ? `${base}.${ext}` : base;
}

class DriveService extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
   * @param {object} [opts.log]
   * @param {object} [opts.api] - DriveApi (tests)
   * @param {object} [opts.store] - electron-store (the folder last picked)
   * @param {object} [opts.shell] - Electron shell (open, show in folder)
   * @param {object} [opts.dialog] - Electron dialog (pick files, save as)
   * @param {Function} [opts.getMainWindow]
   * @param {() => string} [opts.tempDir] - folder for opened files (%TEMP%\gatecontrol-drive)
   * @param {() => string} [opts.getLang] - 'de' | 'en'
   * @param {object} [opts.pushClient] - PushClient: a reconnect ('hello') asks for the plugin again
   * @param {object} [opts.timing]
   * @param {() => number} [opts.now]
   * @param {() => string[]} [opts.allowedHosts] - hosts "Im Portal öffnen" may open (default: the server's and the portal's)
   * @param {(file: string, o: object) => Promise<string|null>} [opts.readPdfText] - text layer of a PDF (tests)
   * @param {object} [opts.protect] - Drive 1.9 vaults: { available, encrypt, decrypt } of Electron safeStorage (DPAPI) —
   *   without it this PC cannot keep a device key (DriveService.safeStorageProtect(safeStorage))
   * @param {object} [opts.notificationCenter] - a click on a deadline / vault push opens the page
   * @param {() => string} [opts.deviceName] - this PC's name for vault requests
   * @param {object|null} [opts.consent] - Drive 1.11: Windows Hello as the confirmation before the vaults unlock
   *   (windowsHello.createConsentVerifier()); null: none here (the vaults open only with "Mit Windows Hello öffnen"
   *   switched off); left out: not enforced (as before Drive 1.11)
   * @param {object} [opts.powerMonitor] - Electron powerMonitor: the vaults lock when Windows locks or sleeps
   * @param {object|null} [opts.ocr] - Drive 1.14: the text recognition of Windows (windowsOcr.createWindowsOcr()) for
   *   searchable PDFs made on this PC; null: Drive makes them (scans/convert)
   */
  constructor({
    apiClient, log, api = null, store = null, shell = null, dialog = null, getMainWindow = null,
    tempDir = null, getLang = null, pushClient = null, timing = {}, now = Date.now, allowedHosts = null, readPdfText = null,
    protect = null, notificationCenter = null, deviceName = null, consent, powerMonitor = null, ocr = null,
  } = {}) {
    super();
    this.log = log || noopLog();
    this.apiClient = apiClient || null;
    this.allowedHosts = typeof allowedHosts === 'function' ? allowedHosts : () => this._defaultHosts();
    this.readPdfText = typeof readPdfText === 'function' ? readPdfText : (file, o) => pdfText(file, { ...o, log: this.log });
    this._meCache = null;          // { links, guard, incidents, features, at } of the last GET me
    this._guardKey = '';
    this.api = api || new DriveApi({ apiClient, log: this.log, getLang });
    this.store = store;
    this.shell = shell;
    this.dialog = dialog;
    this.getMainWindow = typeof getMainWindow === 'function' ? getMainWindow : () => null;
    this.tempDir = typeof tempDir === 'function' ? tempDir : () => path.join(os.tmpdir(), 'gatecontrol-drive');
    this.pushClient = pushClient;
    this.notificationCenter = notificationCenter;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    // Drive 1.11: the vault lock (Windows Hello first; locks after a time without use, when hidden, when Windows locks)
    this.vaultLock = new DriveVaultLock({
      consent, store, powerMonitor, getLang, log: this.log, timing: { minuteMs: this.timing.minuteMs },
      getWindow: () => {
        const w = this.getMainWindow();
        return w && !(typeof w.isDestroyed === 'function' && w.isDestroyed()) && typeof w.getNativeWindowHandle === 'function' ? w.getNativeWindowHandle() : null;
      },
      busy: () => this._vaultActive > 0 || [...this._jobs.values()].some((j) => j.vault && !j.waiting),
      hasKeys: () => this.vault.hasKeys(),
    });
    this.vaultLock.on('lock', (e) => this._onVaultLock(e));
    this.vaultLock.on('unlock', () => this.emit('vaultLock', { locked: false, reason: null }));
    this._vaultActive = 0;          // vault uploads / downloads running (the lock's time without use waits)
    this.vault = new DriveVault({ api: this.api, store, protect, scope: () => this._scopeNow(), deviceName, log: this.log, now, isUnlocked: () => this.vaultLock.isUnlocked() });
    this._vaultOpened = new Map();  // a decrypted file's folder → its removal timer
    this._vaultSweep = null;        // the running sweep of the vault's temp folders (_sweepVaultTemp)
    this._vaultRoots = new Map();   // vault id → the node id of its folder
    this.now = now;
    // Drive 1.12: jobs for many nodes at once (services/drive-ops.js); their rows are part of the transfer list
    this.ops = new DriveOps({
      api: this.api, vault: this.vault, now, log: this.log, timing: { opPollMs: this.timing.opPollMs },
      row: (r) => this._row(r), set: (id, patch, o) => this._set(id, patch, o), emit: (ev, payload) => this.emit(ev, payload),
      siblings: (folderId, vaultId) => this._vaultSiblings(folderId, vaultId),
    });
    this._opsResumed = false;
    // Drive 1.14: the OCR of Windows and the scans prepared for "In Dokument umwandeln" (scanId → session)
    this.ocr = ocr && typeof ocr.recognize === 'function' ? ocr : null;
    this._scans = new Map();

    this._state = { state: 'unknown', reason: null, version: null, checkedAt: null };
    this._timer = null;
    this._retry = 0;
    this._checking = null;
    this._started = false;
    this._unsub = [];
    this._scope = this._scopeNow();
    this._previews = new Map();     // `${mediaId}|${size}` → { mime, data }
    this._mediaOf = new Map();      // node id → mediaId (photos without a mediaId in the answer)
    this._inflight = new Map();
    this._transfers = [];           // rows of the transfer list (see _row)
    this._jobs = new Map();         // upload id → job (queued / waiting for a choice)
    this._queue = [];
    this._pumping = false;
    this._nextId = 0;
    this._emitTimer = null;
    this._lastEmit = 0;
  }

  // ── Lifecycle ────────────────────────────────────────────

  start() {
    if (this._started) return;
    this._started = true;
    const pc = this.pushClient;
    if (pc && typeof pc.on === 'function') {
      const onHello = () => { if (this._state.state !== 'available') this.check().catch(() => {}); };
      // the plugin's live events: `changed { areas, seq }` (the page reloads), `guard { incident }`
      const onEvent = (ev) => {
        if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== drive.PLUGIN_ID) return;
        const d = ev.data.data && typeof ev.data.data === 'object' ? ev.data.data : ev.data;
        if (ev.data.type === 'changed') {
          const areas = Array.isArray(d.areas) ? d.areas.map(drive.areaIdOf).filter(Boolean).slice(0, 100) : null;
          this.emit('remote', { areas, seq: drive.count(d.seq) });
        } else if (ev.data.type === 'guard') {
          this.guard({ fresh: true }).catch(() => {});
        } else if (ev.data.type === 'op') {
          // Drive 1.12: a job's progress / its end
          this.ops.onEvent(d);
        } else if (ev.data.type === 'vault') {
          // Drive 1.9: a request, an approval, a new key of a vault folder
          this.vault.onEvent(d);
          this.emit('vault', vaultEvent(d));
        }
      };
      pc.on('hello', onHello);
      pc.on('event', onEvent);
      this._unsub.push(() => { pc.removeListener('hello', onHello); pc.removeListener('event', onEvent); });
    }
    const nc = this.notificationCenter;
    if (nc && typeof nc.addClickRoute === 'function') {
      // Drive 1.8 / 1.9: a deadline reminder opens its file, a vault request the vault on the page
      this._unsub.push(nc.addClickRoute(drive.APP_ROUTE, (entry) => this.clickContext(entry)));
    }
    this.vaultLock.start();
    // decrypted files a crash left behind
    this._sweepVaultTemp().catch(() => {});
    this.check().catch(() => {});
  }

  stop() {
    this._started = false;
    clearTimeout(this._timer);
    this._timer = null;
    clearTimeout(this._emitTimer);
    this._emitTimer = null;
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    this.vaultLock.stop();
    this.ops.stop();
    this.vault.clear();
    for (const t of this._vaultOpened.values()) clearTimeout(t);
    this._vaultOpened.clear();
    this._sweepVaultTemp().catch(() => {});
    for (const id of [...this._scans.keys()]) this.scanDiscard(id);
  }

  /**
   * A click on a Drive push while the page exists → { kind: 'deadline', nodeId, deadlineId, areaId } |
   * { kind: 'vault', vaultId, nodeId, event } | null (the inbox opens).
   */
  clickContext(entry) {
    if (!this.available() || !entry || typeof entry !== 'object') return null;
    const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {};
    const d = data.drive && typeof data.drive === 'object' && !Array.isArray(data.drive) ? data.drive : null;
    if (!d) return null;
    if (entry.topic === DEADLINE_TOPIC && drive.posId(d.node)) {
      return { kind: 'deadline', nodeId: drive.posId(d.node), deadlineId: drive.posId(d.deadline), areaId: drive.areaIdOf(d.area) };
    }
    if (entry.topic === VAULT_TOPIC && drive.vaultIdOf(d.vault)) {
      return { kind: 'vault', vaultId: d.vault, nodeId: drive.posId(d.node), areaId: drive.areaIdOf(d.area), event: typeof d.event === 'string' ? d.event.slice(0, 20) : null };
    }
    return null;
  }

  /** server:setup: the old server's state goes (queued uploads are dropped), the new one is asked. */
  resetForNewServer() {
    this._meCache = null;
    this._guardKey = '';
    this._previews.clear();
    this._mediaOf.clear();
    this._inflight.clear();
    this.vaultLock.lock('server');
    this.vault.clear();
    this._vaultRoots.clear();
    this.ops.reset();
    this._opsResumed = false;
    this._transfers = this._transfers.filter((r) => r.dir !== 'op');
    for (const job of this._queue.splice(0)) this._set(job.id, { state: 'skipped' });
    for (const [id, job] of this._jobs) if (job.waiting) this._set(id, { state: 'skipped' });
    this._jobs.clear();
    this._retry = 0;
    this._scope = this._scopeNow();
    this._setState({ state: 'unknown', reason: null, version: null, checkedAt: null });
    if (this._started) return this.check().catch(() => this.status());
    return Promise.resolve(this.status());
  }

  // ── Availability ─────────────────────────────────────────

  /** { state: 'unknown'|'available'|'unavailable'|'error', reason, version, checkedAt } */
  status() {
    return { ...this._state };
  }

  available() {
    return this._state.state === 'available';
  }

  check() {
    if (this._checking) return this._checking;
    this._checking = this._check().finally(() => { this._checking = null; });
    return this._checking;
  }

  async _check() {
    this._ensureScope();
    clearTimeout(this._timer);
    this._timer = null;
    let next = this.timing.recheckMs;
    try {
      const p = await this.api.plugin();
      this._retry = 0;
      if (!p) this._setState({ state: 'unavailable', reason: 'not_installed', version: null, checkedAt: this.now() });
      else {
        this._setState({ state: 'available', reason: null, version: typeof p.version === 'string' ? p.version.slice(0, 40) : null, checkedAt: this.now() });
        // Drive 1.12: jobs of the person still running on the server (the app was closed meanwhile) show again
        if (this._started && !this._opsResumed) {
          this._opsResumed = true;
          this.ops.resume().catch((err) => { this._opsResumed = false; this.log.debug(`Drive jobs not resumed: ${drive.errorCode(err)}`); });
        }
      }
    } catch (err) {
      if (err && err.status === 404) {
        this._retry = 0;
        this._setState({ state: 'unavailable', reason: 'unsupported', version: null, checkedAt: this.now() });
      } else if (err && (err.status === 401 || err.status === 403)) {
        this._setState({ state: 'unavailable', reason: err.status === 401 ? 'auth' : 'forbidden', version: null, checkedAt: this.now() });
      } else if (err && err.code === 'not_configured') {
        this._setState({ state: 'unavailable', reason: 'not_configured', version: null, checkedAt: this.now() });
      } else {
        // Network / 5xx: keep "available" (the page stays and says it is offline).
        const keep = this._state.state === 'available';
        this._setState({ ...this._state, state: keep ? 'available' : 'error', reason: (err && err.code) || 'network', checkedAt: this.now() });
        next = Math.min(this.timing.retryMaxMs, this.timing.retryMinMs * (2 ** this._retry));
        this._retry = Math.min(this._retry + 1, 10);
      }
    }
    if (this._started) {
      this._timer = setTimeout(() => this.check().catch(() => {}), next);
      if (this._timer.unref) this._timer.unref();
    }
    return this.status();
  }

  _setState(s) {
    const key = () => JSON.stringify([this._state.state, this._state.reason, this._state.version]);
    const before = key();
    this._state = { state: s.state, reason: s.reason || null, version: s.version || null, checkedAt: s.checkedAt || null };
    if (key() !== before) this.emit('state', this.status());
  }

  _scopeNow() {
    return typeof this.api.scope === 'function' ? this.api.scope() : '';
  }

  _ensureScope() {
    const s = this._scopeNow();
    if (s === this._scope) return;
    this._scope = s;
    this._previews.clear();
    this._mediaOf.clear();
  }

  /** Drive is not listed (any more): the call fails like the plugin would. */
  _need() {
    if (this._state.state === 'unavailable') throw new DriveError('Drive is not available', { code: 'drive_unavailable' });
  }

  /** A 404 of the plugin's base or a refusal of the token: ask for the plugin again. */
  async _run(fn) {
    this._need();
    this._ensureScope();
    try {
      return await fn();
    } catch (err) {
      const e = err instanceof DriveError ? err : MessengerApi.toMessengerError(err);
      if (e.status === 404 && /^http_/.test(e.code)) this.check().catch(() => {});
      this._onWriteError(e);
      throw e;
    }
  }

  // ── Browse ───────────────────────────────────────────────

  /** GET me → { ok, me, licence, areas, settings, limits, people, usable, features, links, guard, incidents } */
  async me() {
    return this._run(async () => {
      const m = await this.api.me();
      this._remember(m);
      return { ok: true, ...m, usable: m.licence.valid && !!m.me.seat };
    });
  }

  /** Keeps links / guard of a GET me; a change of the guard goes out as 'guard'. */
  _remember(m) {
    this._meCache = { features: m.features || [], links: m.links || null, guard: m.guard || null, incidents: m.incidents || [], at: this.now() };
    const g = this._guardView();
    const key = JSON.stringify([g.locked, g.incident && g.incident.id, g.incidents.map((i) => i.id)]);
    if (key !== this._guardKey) {
      this._guardKey = key;
      this.emit('guard', g);
    }
  }

  async _meFresh(fresh = false) {
    if (!fresh && this._meCache && this.now() - this._meCache.at < ME_MAX_AGE) return this._meCache;
    this._remember(await this.api.me());
    return this._meCache;
  }

  // ── Guard (Drive 1.6, 'guard') ───────────────────────────

  _guardView() {
    const c = this._meCache || {};
    const g = c.guard || { locked: false, incident: null };
    return {
      ok: true,
      supported: (c.features || []).includes('guard'),
      locked: !!g.locked,
      incident: g.incident || null,
      incidents: (c.incidents || []).slice(),
      portal: !!(c.links && c.links.drive),
    };
  }

  /**
   * The guard of this device → { ok, supported, locked, incident, incidents, portal }.
   * `fresh`: ask the server now (live event `guard`, a 423 of a write).
   */
  async guard({ fresh = false } = {}) {
    return this._run(async () => {
      await this._meFresh(fresh);
      return this._guardView();
    });
  }

  /** "Rückgängig machen" ('undo') / "War ich – freigeben" ('release') → { ok, decision, incident, restored, trashed, guard } */
  async guardDecide(incidentId, decision) {
    if (!drive.incidentIdOf(incidentId) || (decision !== 'undo' && decision !== 'release')) throw new DriveError('invalid', { code: 'invalid' });
    return this._run(async () => {
      const r = await this.api.guardDecide(incidentId, decision);
      await this._meFresh(true).catch(() => null);
      const g = this._guardView();
      // "Ordner sichern" goes on (after an undo: the PC's files come back from Drive)
      this.emit('guard', { ...g, decided: decision, decidedId: drive.incidentIdOf(incidentId) });
      return { ok: true, decision, incident: r.incident, restored: r.restored, trashed: r.trashed, guard: g };
    });
  }

  /** A write refused because Drive stopped this device: the guard is asked again. */
  _onWriteError(err) {
    if (err && err.status === 423 && err.code === 'device_locked') this.guard({ fresh: true }).catch(() => {});
  }

  // ── Portal links (Drive 1.6, 'links') ────────────────────

  _defaultHosts() {
    const out = [];
    const a = this.apiClient || {};
    for (const u of [a.serverUrl, a.portalUrl]) {
      try { if (u) out.push(new URL(u).hostname.toLowerCase()); } catch { /* not a URL */ }
    }
    return out;
  }

  _hosts() {
    let h = [];
    try { h = this.allowedHosts() || []; } catch { h = []; }
    return h.filter((x) => typeof x === 'string' && x);
  }

  /** The portal link of a node (or of Drive with id null) → { ok, url } | { ok: false, code: 'unsupported' }. */
  async portalLink(nodeId = null) {
    return this._run(async () => {
      const c = await this._meFresh(false);
      const links = c.links;
      if (!links) return { ok: false, code: 'unsupported', error: 'no portal links' };
      if (nodeId === null || nodeId === undefined) {
        const url = drive.allowedLink(links.drive, this._hosts());
        return url ? { ok: true, url } : { ok: false, code: 'unsupported', error: 'no portal link' };
      }
      const url = drive.nodeLink(links.node, nodeId, this._hosts());
      return url ? { ok: true, url } : { ok: false, code: 'unsupported', error: 'no portal link' };
    });
  }

  /** "Im Portal öffnen": the node's page in the portal in the browser → { ok } | { ok: false, code }. */
  async openInPortal(nodeId = null) {
    const r = await this.portalLink(nodeId);
    if (!r.ok) return r;
    if (!this.shell || typeof this.shell.openExternal !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    const ok = await openExternalSafely(this.shell, r.url, { log: this.log, label: 'Drive portal link' });
    return ok ? { ok: true } : { ok: false, code: 'open_failed', error: 'not opened' };
  }

  /** GET areas → { ok, areas } (sorted: mine, family, children, teams). */
  async areas() {
    return this._run(async () => ({ ok: true, ...(await this.api.areas()) }));
  }

  /**
   * A folder: { ok, node, crumbs, role, writable, items, total, next, vault } — vault (Drive 1.9): the vault the folder
   * lies in { id, state, name, needsRotation } (null outside one); vault nodes carry their decrypted name, or
   * `locked: true` while this device has no key.
   */
  async folder(id, query = {}) {
    return this._run(async () => {
      const f = await this.api.folder(id, query);
      // Drive 1.11: vault folders only in the menu ("Tresore"); an older Drive lists them, they are left out here
      if (!f.node.encrypted) {
        const before = f.items.length;
        f.items = drive.withoutVaults(f.items);
        if (f.items.length !== before && Number.isFinite(f.total)) f.total = Math.max(f.items.length, f.total - (before - f.items.length));
      }
      await this._vaultDecorate(f.items, { inVault: f.node.encrypted });
      if (f.node.encrypted) this.vaultLock.touch();
      let vault = null;
      if (f.node.encrypted && f.node.vaultId) {
        await this.vault.tryOpen(f.node.vaultId);
        f.node = this._vaultNode(f.node);
        if (f.node.vaultRoot === undefined) f.node.vaultRoot = false;
        vault = { id: f.node.vaultId, state: this.vault.stateOf(f.node.vaultId) };
        await this._vaultCrumbs(f).catch(() => {});
      }
      return { ok: true, ...f, vault };
    });
  }

  // ── Vault folders (Drive 1.9, 'vault') ───────────────────

  /** A vault node with its decrypted name (else locked: true and the opaque name). */
  _vaultNode(n) {
    if (!n || !n.encrypted) return n;
    const name = this.vault.nameOf(n);
    return name ? { ...n, name, opaqueName: n.name, locked: false } : { ...n, opaqueName: n.name, locked: true };
  }

  /** Names of the vault nodes of a list (vaults with a key here are opened quietly first). */
  async _vaultDecorate(items, { inVault = false } = {}) {
    if (!Array.isArray(items) || !items.some((n) => n.encrypted)) return items;
    for (const vid of new Set(items.filter((n) => n.encrypted && n.vaultId).map((n) => n.vaultId))) await this.vault.tryOpen(vid);
    for (let i = 0; i < items.length; i++) {
      const n = items[i];
      if (!n.encrypted) continue;
      items[i] = { ...this._vaultNode(n), vaultRoot: !inVault && n.isDir, vaultState: this.vault.stateOf(n.vaultId) };
      if (!inVault && n.isDir && n.vaultId) this._vaultRoots.set(n.vaultId, n.id);
    }
    return items;
  }

  /** The breadcrumbs inside a vault get their names (from the names decrypted before, else the nodes). */
  async _vaultCrumbs(f) {
    const vid = f.node.vaultId;
    let rootId = this._vaultRoots.get(vid);
    if (!rootId) {
      rootId = (await this.api.vault(vid)).nodeId;
      this._vaultRoots.set(vid, rootId);
    }
    const at = f.crumbs.findIndex((c) => c.id === rootId);
    if (at < 0) return;
    for (let i = at; i < f.crumbs.length; i++) {
      const c = f.crumbs[i];
      let name = c.id === f.node.id && !f.node.locked ? f.node.name : this.vault.knownName(c.id);
      if (!name && this.vault.isOpen(vid)) name = this.vault.nameOf(await this.api.node(c.id).catch(() => null));
      f.crumbs[i] = name ? { ...c, name } : { ...c, locked: true };
    }
  }

  /** The node `id` when it lies in a vault (feature on), else null. */
  async _vaultNodeOf(id) {
    if (!(await this.api.has('vault').catch(() => false))) return null;
    const n = await this.api.node(id);
    return n.encrypted && n.vaultId ? n : null;
  }

  /** The decrypted names of the children of the vault folder `folderId` → [{ node, name }] (locked ones left out). */
  async _vaultSiblings(folderId, vaultId) {
    const out = [];
    for (const n of await this.api.childrenAll(folderId)) {
      if (n.deleted || !n.encrypted || n.vaultId !== vaultId) continue;
      const name = this.vault.nameOf(n);
      if (name) out.push({ node: n, name });
    }
    return out;
  }

  /** { ok, supported, device: { id, safetyNumber, name } | null } — this PC for vaults (no key made here). */
  async vaultStatus() {
    return this._run(async () => {
      const supported = this.vault.supported() && await this.api.has('vault').catch(() => false);
      const device = supported ? await this.vault.device({ create: false }) : null;
      return { ok: true, supported, protect: this.vault.supported(), device: device ? { id: device.id, safetyNumber: device.safetyNumber, name: device.name } : null };
    });
  }

  async vaults() {
    return this._run(async () => {
      await this._feature('vault');
      const vaults = await this.vault.list();
      for (const v of vaults) this._vaultRoots.set(v.id, v.nodeId);
      return { ok: true, vaults };
    });
  }

  /**
   * A new vault folder → { ok, vault, node, recoveryKey } (recoveryKey: shown once). Drive 1.11: it always goes into
   * the top folder of an area — `areaId` (the area picked in "Wer darf ihn öffnen?") or the area of `parentId`
   * (older callers); a Drive with 'vaultsApart' does the same itself.
   */
  async vaultCreate(parentId, name, { areaId = null } = {}) {
    const n = this._name(name);
    return this._run(async () => {
      await this._feature('vault');
      const { areas } = await this.api.areas();
      let area = areaId ? areas.find((a) => a.id === areaId) : null;
      if (!area && !areaId && drive.posId(parentId)) {
        const p = await this.api.node(parentId);
        area = areas.find((a) => a.id === p.areaId) || null;
      }
      if (!area) throw new DriveError('no such area', { code: 'not_found' });
      if (!area.writable) throw new DriveError('read only', { code: 'forbidden' });
      const r = await this.vault.create(area.rootId, n);
      // its key stays until the next lock (time without use, window hidden, Windows locked)
      this.vaultLock.touch();
      this._vaultRoots.set(r.vault.id, r.node.id);
      this.emit('changed', { folderId: area.rootId });
      return { ok: true, ...r };
    });
  }

  // ── Vault lock (Drive 1.11) ──────────────────────────────

  /** { ok, enforced, unlocked, settings: { hello, autoLockMinutes, lockOnLeave }, hello: { available, reason }, choices, lastLock } */
  async vaultLockStatus() {
    return { ok: true, ...(await this.vaultLock.status()) };
  }

  /**
   * Windows Hello, then the vaults of this PC unlock → { ok, unlocked, state? } — with `vaultId` that vault is opened
   * right away (its state). Refused: { ok: false, code: 'hello_cancelled' | 'hello_not_set_up' | … }.
   */
  async vaultUnlock(vaultId = null) {
    return this._run(async () => {
      await this.vaultLock.unlock();
      const out = { ok: true, unlocked: true };
      if (vaultId) out.state = (await this.vault.open(vaultId, { fresh: true })).state;
      return out;
    });
  }

  /** "Jetzt sperren" → { ok, unlocked: false } */
  vaultLockNow() {
    this.vaultLock.lock('manual');
    return { ok: true, unlocked: false };
  }

  /** { hello?, autoLockMinutes?, lockOnLeave? } → the lock's status (switching Hello off asks Windows Hello first). */
  async vaultLockSettings(patch) {
    return { ok: true, ...(await this.vaultLock.setSettings(patch)) };
  }

  /** Activity on the page while a vault is open: its time without use starts again. */
  vaultTouch() {
    this.vaultLock.touch();
    return { ok: true };
  }

  /** The main window was minimized / hidden into the tray ("Beim Verlassen sperren"). */
  windowHidden() {
    this.vaultLock.windowHidden();
  }

  /** Windows' sign-in options (to set up Windows Hello). */
  async openHelloSettings() {
    if (!this.shell || typeof this.shell.openExternal !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    await this.shell.openExternal('ms-settings:signinoptions');
    return { ok: true };
  }

  /** The vaults locked: keys wiped, names forgotten, the decrypted copies removed (later while a program holds one). */
  _onVaultLock({ reason = 'manual' } = {}) {
    this.vault.forget();
    for (const t of this._vaultOpened.values()) clearTimeout(t);
    this._vaultOpened.clear();
    const dir = path.join(this.tempDir(), 'vault');
    fs.promises.readdir(dir).then((names) => {
      for (const n of names) {
        const d = path.join(dir, n);
        fs.promises.rm(d, { recursive: true, force: true }).catch(() => this._forgetOpened(d, VAULT_OPEN_RETRY_MS));
      }
    }).catch(() => {});
    this.emit('vaultLock', { locked: true, reason });
  }

  /** Opens a vault on this PC → { ok, state: 'open' | 'pending' | 'none' | 'revoked' } */
  async vaultOpen(vaultId) {
    return this._run(async () => {
      await this._feature('vault');
      return { ok: true, ...(await this.vault.open(vaultId, { fresh: true })) };
    });
  }

  /** This PC asks for access → { ok, state, safetyNumber } (the number the approving device compares). */
  async vaultRequest(vaultId) {
    return this._run(async () => {
      await this._feature('vault');
      const r = await this.vault.request(vaultId);
      return { ok: true, state: r.state, safetyNumber: r.safetyNumber, deviceId: r.device.deviceId };
    });
  }

  /** The devices of a vault with their safety numbers → { ok, devices, vault } */
  async vaultDevices(vaultId) {
    return this._run(async () => {
      await this._feature('vault');
      const [devices, vault] = await Promise.all([this.vault.devices(vaultId), this.vault.get(vaultId)]);
      return { ok: true, devices, vault };
    });
  }

  /** Approves a request after the safety number was compared → { ok, device } */
  async vaultApprove(vaultId, deviceId, safetyNumber) {
    return this._run(async () => {
      await this._feature('vault');
      return { ok: true, device: await this.vault.approve(vaultId, deviceId, safetyNumber) };
    });
  }

  async vaultDecline(vaultId, deviceId) {
    return this._run(async () => {
      await this._feature('vault');
      return { ok: true, device: await this.vault.decline(vaultId, deviceId) };
    });
  }

  /** Opens the vault with its recovery key → { ok, state: 'open' } */
  async vaultRecover(vaultId, text) {
    return this._run(async () => {
      await this._feature('vault');
      const r = await this.vault.recover(vaultId, text);
      this.vaultLock.touch();
      return { ok: true, ...r };
    });
  }

  /** A new vault key (needsRotation) → { ok, vault, recoveryKey } (recoveryKey only when Drive asked for a new one) */
  async vaultRotate(vaultId) {
    return this._run(async () => {
      await this._feature('vault');
      return { ok: true, ...(await this.vault.rotate(vaultId)) };
    });
  }

  /** A folder in a vault (the top one of an uploaded folder: a free name) → node with its name. */
  async _vaultMkdir(vaultId, parentId, name, { free = false } = {}) {
    let n = name;
    if (free) {
      const taken = new Set((await this._vaultSiblings(parentId, vaultId)).map((x) => S.keyOf(x.name)));
      n = freeFileName(name, taken, true);
    }
    const node = await this.vault.withCurrent(vaultId, (cur) => this.api.mkdirEncrypted(parentId, this.vault.encryptName(vaultId, n, cur)));
    this.vault.nameOf(node);
    return { ...node, name: n, opaqueName: node.name, locked: false };
  }

  /**
   * Removes the folders of decrypted files (all of them: at stop / start). What writes there next waits for it
   * (_vaultTempReady): an upload or opening right after start() would else lose its file to the sweep.
   */
  _sweepVaultTemp() {
    const run = async () => {
      for (const d of ['vault', 'vault-dl', 'vault-up']) {
        await fs.promises.rm(path.join(this.tempDir(), d), { recursive: true, force: true, maxRetries: 2 }).catch(() => {});
      }
    };
    this._vaultSweep = Promise.resolve(this._vaultSweep).then(run, run);
    return this._vaultSweep;
  }

  /** Resolves once no sweep of the vault's temp folders runs. */
  async _vaultTempReady() {
    await Promise.resolve(this._vaultSweep).catch(() => {});
  }

  /** The decrypted copy in `dir` goes after VAULT_OPEN_KEEP_MS — later while a program still holds it. */
  _forgetOpened(dir, delay = VAULT_OPEN_KEEP_MS) {
    clearTimeout(this._vaultOpened.get(dir));
    const t = setTimeout(async () => {
      this._vaultOpened.delete(dir);
      try {
        await fs.promises.rm(dir, { recursive: true, force: true });
      } catch {
        this._forgetOpened(dir, VAULT_OPEN_RETRY_MS);
      }
    }, delay);
    if (t.unref) t.unref();
    this._vaultOpened.set(dir, t);
  }

  /** The ciphertext of a vault file (or a version) decrypted into `file` → node content info. */
  async _vaultFetchTo(node, versionId, file, row) {
    this._vaultActive++;
    try {
      return await this._vaultFetch(node, versionId, file, row);
    } finally {
      this._vaultActive--;
      this.vaultLock.touch();
    }
  }

  async _vaultFetch(node, versionId, file, row) {
    const keys = this.vault.keys(node.vaultId);
    const c = await this.api.content(node.id, versionId);
    if (c.empty || !c.mediaId) throw new DriveError('no content', { code: 'invalid' });
    await this._vaultTempReady();
    const tmpDir = path.join(this.tempDir(), 'vault-dl');
    await fs.promises.mkdir(tmpDir, { recursive: true });
    const enc = path.join(tmpDir, `${crypto.randomBytes(8).toString('hex')}.enc`);
    const part = `${file}.${crypto.randomBytes(4).toString('hex')}.part`;
    try {
      const out = fs.createWriteStream(enc);
      try {
        await this.api.download(c.mediaId, out, { onProgress: (got, total) => this._set(row.id, { sent: Math.round(got / 2), ...(total ? { total } : {}) }, { progress: true }) });
      } catch (err) { out.destroy(); throw err; }
      await fs.promises.mkdir(path.dirname(file), { recursive: true });
      let total = null;
      try {
        await V.decryptFile(keys, node.vaultId, enc, part, { onProgress: (done, size) => { total = size; this._set(row.id, { sent: done, total: size }, { progress: true }); } });
      } catch (err) {
        if (err instanceof V.DriveVaultError) throw new DriveError(err.message, { code: err.code === 'decrypt' ? 'vault_decrypt' : 'vault_invalid' });
        throw err;
      }
      await fs.promises.rm(file, { force: true });
      await fs.promises.rename(part, file);
      return { size: total };
    } finally {
      await fs.promises.rm(enc, { force: true }).catch(() => {});
      await fs.promises.rm(part, { force: true }).catch(() => {});
    }
  }

  // ── The menu's folder tree (Drive 1.11) ──────────────────

  /**
   * The subfolders of folder `id` for the menu → { ok, items: [{ id, name, hasDirs }], more } — never a vault folder;
   * hasDirs null: an older Drive does not say (known once that folder is opened). At most 5000.
   */
  async tree(id) {
    return this._run(async () => {
      const apart = await this.api.has('vaultsApart').catch(() => false);
      const items = [];
      let offset = 0;
      let more = false;
      for (;;) {
        const page = await this.api.dirs(id, { offset, limit: 1000, apart });
        items.push(...page.items);
        if (page.next === null || page.next <= offset) break;
        if (items.length >= 5000) { more = true; break; }
        offset = page.next;
      }
      return { ok: true, items, more };
    });
  }

  // ── The cache on this PC (Drive 1.11 settings) ───────────

  /** What a clear removes: the opened files' copies, previews in memory → { ok, bytes, files }. */
  async cacheInfo() {
    let bytes = 0;
    let files = 0;
    const walk = async (d, depth) => {
      let entries;
      try { entries = await fs.promises.readdir(d, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) { if (depth < 6) await walk(p, depth + 1); continue; }
        try { const st = await fs.promises.stat(p); bytes += st.size; files++; } catch { /* gone */ }
      }
    };
    for (const e of await this._cacheEntries()) {
      if (e.dir) await walk(e.path, 0);
      else { bytes += e.size; files++; }
    }
    for (const p of this._previews.values()) if (p && p.data) bytes += p.data.length;
    return { ok: true, bytes, files, previews: this._previews.size };
  }

  /** The cached entries of the temp folder: never uploads in progress (vault-up / vault-dl), never a file being loaded. */
  async _cacheEntries() {
    const root = this.tempDir();
    let entries;
    try { entries = await fs.promises.readdir(root, { withFileTypes: true }); } catch { return []; }
    const out = [];
    for (const e of entries) {
      if (e.name === 'vault-up' || e.name === 'vault-dl') continue;
      const p = path.join(root, e.name);
      if (e.isDirectory()) out.push({ path: p, dir: true });
      else { try { out.push({ path: p, dir: false, size: (await fs.promises.stat(p)).size }); } catch { /* gone */ } }
    }
    return out;
  }

  /** "Zwischenspeicher leeren" → { ok, removed, kept } (kept: copies a program still holds open). */
  async clearCache() {
    this._previews.clear();
    this._mediaOf.clear();
    let removed = 0;
    let kept = 0;
    const running = this._transfers.some((r) => r.dir === 'down' && r.state === 'running');
    for (const e of await this._cacheEntries()) {
      // a download running right now writes its .part there: that folder stays until it is done
      if (running && e.dir && (await fs.promises.readdir(e.path).catch(() => [])).some((n) => n.endsWith('.part'))) { kept++; continue; }
      try {
        await fs.promises.rm(e.path, { recursive: true, force: true, maxRetries: 1 });
        removed++;
      } catch {
        kept++;
      }
    }
    return { ok: true, removed, kept };
  }

  async search(q, area = null) {
    const text = typeof q === 'string' ? q.trim() : '';
    if (text.length < 2 || text.length > 100) throw new DriveError('search needs 2 to 100 characters', { code: 'invalid' });
    // Drive 1.11: never a vault's node (the plugin leaves them out already; an older one, too — checked here again)
    return this._run(async () => ({ ok: true, items: drive.withoutVaults(await this.api.search(text, area)) }));
  }

  async trashList(area = null) {
    return this._run(async () => ({ ok: true, items: await this._vaultDecorate(await this.api.trashList(area), { inVault: true }) }));
  }

  async versions(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.versions(id)) }));
  }

  async links(nodeId = null) {
    return this._run(async () => ({ ok: true, ...(await this.api.links(nodeId)) }));
  }

  // ── Change ───────────────────────────────────────────────

  _name(name) {
    if (!drive.validName(name)) throw new DriveError('name not allowed', { code: 'invalid_name' });
    return name.trim();
  }

  async mkdir(parentId, name) {
    const n = this._name(name);
    return this._run(async () => {
      // Drive 1.9: a folder in a vault gets an encrypted name
      const parent = await this._vaultNodeOf(parentId);
      if (parent) return { ok: true, node: await this._vaultMkdir(parent.vaultId, parent.id, n, { free: true }) };
      return { ok: true, node: await this.api.mkdir(parentId, n) };
    });
  }

  async rename(id, name) {
    const n = this._name(name);
    return this._run(async () => {
      const node = await this._vaultNodeOf(id);
      if (node) {
        const r = await this.vault.withCurrent(node.vaultId, (cur) => this.api.renameEncrypted(node.id, this.vault.encryptName(node.vaultId, n, cur).nameCipher));
        return { ok: true, node: this._vaultNode(r) };
      }
      return { ok: true, node: await this.api.rename(id, n) };
    });
  }

  async move(id, parentId) {
    return this._run(async () => ({ ok: true, node: await this.api.move(id, parentId) }));
  }

  async remove(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.trash(id)) }));
  }

  async restore(id) {
    return this._run(async () => ({ ok: true, node: await this.api.restore(id) }));
  }

  async purge(id) {
    return this._run(async () => ({ ok: true, ...(await this.api.purge(id)) }));
  }

  async restoreVersion(id, versionId) {
    return this._run(async () => ({ ok: true, node: await this.api.restoreVersion(id, versionId) }));
  }

  /** A link of one node, or (`ids`, Drive 1.12 'multiLink') one link for several (with folders: 400 invalid { reason: 'mixed' }). */
  async createLink(opts) {
    return this._run(async () => {
      if (opts && Array.isArray(opts.ids)) await this._feature('multiLink');
      return { ok: true, link: await this.api.createLink(opts) };
    });
  }

  // ── Jobs for many nodes (Drive 1.12, services/drive-ops.js) ──

  /** What a job would do → { ok, bulk, local, files, folders, bytes, conflicts, blocked } (changes nothing) */
  async opsCheck({ op, ids, target = null } = {}) {
    return this._run(() => this.ops.check({ op, ids, target }));
  }

  /** Starts a job → { ok, op } (its row of the transfer list; the event 'op' when it ends) */
  async opsStart({ op, ids, target = null, onConflict = null, meta = {} } = {}) {
    return this._run(() => this.ops.start({ op, ids, target, onConflict, meta }));
  }

  /** "Abbrechen" of a running job → { ok, op } */
  async opCancel(opId) {
    return this._run(() => this.ops.cancel(opId));
  }

  /** "Rückgängig" of a job that ended (until undoUntil) → { ok, op } */
  async opUndo(opId) {
    return this._run(async () => {
      await this._feature('bulk');
      return this.ops.undo(opId);
    });
  }

  /**
   * "Herunterladen (ZIP)" (Drive 1.12 'zip'): "Speichern unter …" first (name: the page's suggestion), then Drive
   * makes the ZIP of the nodes (never a vault's) and it streams into that path → { ok, path } | { ok: false, cancelled }.
   */
  async zip(ids, { name = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    const list = drive.idList(ids);
    if (!list) throw new DriveError('invalid ids', { code: 'invalid' });
    return this._run(async () => {
      await this._feature('zip');
      const base = drive.safeName(typeof name === 'string' ? name : '') || 'Drive';
      const fileName = /\.zip$/i.test(base) ? base : `${base}.zip`;
      const win = this.getMainWindow();
      const opts = { defaultPath: fileName, filters: [{ name: 'ZIP', extensions: ['zip'] }] };
      const res = win ? await this.dialog.showSaveDialog(win, opts) : await this.dialog.showSaveDialog(opts);
      if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true, code: 'cancelled' };
      const row = this._downloadRow(path.basename(res.filePath), 0);
      const part = `${res.filePath}.${crypto.randomBytes(4).toString('hex')}.part`;
      let bytes = 0;
      try {
        const z = await this.api.zip(list, { name: typeof name === 'string' && name ? base.replace(/\.zip$/i, '') : null });
        const out = fs.createWriteStream(part);
        try {
          const r = await this.api.downloadZip(z.url, out, { onProgress: (got, total) => this._set(row.id, { sent: got, ...(total ? { total } : {}) }, { progress: true }) });
          bytes = r.bytes;
        } catch (err) { out.destroy(); throw err; }
        await fs.promises.rm(res.filePath, { force: true });
        await fs.promises.rename(part, res.filePath);
      } catch (err) {
        await fs.promises.rm(part, { force: true }).catch(() => {});
        this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
        throw err;
      }
      this._set(row.id, { state: 'done', sent: bytes, total: bytes, path: res.filePath });
      return { ok: true, path: res.filePath };
    });
  }

  async endLink(token) {
    return this._run(async () => ({ ok: true, ...(await this.api.endLink(token)) }));
  }

  // ── Drive 1.7: time travel, photos, albums, storage ──────

  /** Throws 'unsupported' when this Drive does not report `name` in me.features. */
  async _feature(name) {
    if (!(await this.api.has(name).catch(() => false))) throw new DriveError(`Drive cannot do ${name}`, { code: 'unsupported' });
  }

  /** What a time travel of the folder `id` back to `at` would do → { ok, at, historySince, restore, revert, trash, move, total, sample, limited } */
  async timeTravelPreview(id, at) {
    return this._run(async () => {
      await this._feature('timeTravel');
      return { ok: true, ...(await this.api.timeTravelPreview(id, at)) };
    });
  }

  /**
   * The folder `id` back to how it was at `at` → { ok, at, before, restored, reverted, trashed, moved, failed }.
   * Nothing is lost: new files go into the trash, replaced contents become older versions.
   * "Rückgängig" is another time travel to `before`.
   */
  async timeTravel(id, at) {
    return this._run(async () => {
      await this._feature('timeTravel');
      const folderId = drive.posId(id);
      const r = await this.api.timeTravel(folderId, at);
      this.emit('timetravel', { folderId, at: r.at, before: r.before });
      this.emit('changed', { folderId });
      return { ok: true, ...r };
    });
  }

  /**
   * GET photos → { ok, items, next } — Drive 1.14 'photoSearch': with `q` the photos by what is on them (+ terms,
   * total); Drive 1.16: `q` also matches names of people and places (→ marks), photos of a place (`place`, with
   * `districts` its districts) or a box of the map (`bbox`) need 'photoPlaces', of people (`person`, one id or
   * several) and `withPeople` (the people on each photo) 'photoPeople'.
   */
  async photos({ area = null, before = null, limit = 100, q = null, place = null, bbox = null, person = null, districts = false, withPeople = false } = {}) {
    return this._run(async () => {
      await this._feature('photos');
      if (q) await this._searchFeature();
      if (place || bbox) await this._feature('photoPlaces');
      if (person || withPeople) await this._feature('photoPeople');
      const r = await this.api.photos({ area, before, limit, q, place, bbox, person, districts, withPeople });
      for (const p of r.items) if (p.mediaId) this._mediaOf.set(p.id, p.mediaId);
      return { ok: true, ...r };
    });
  }

  /** A search of photos needs 'photoSearch' (labels) or, Drive 1.16, 'photoPlaces' / 'photoPeople' (names). */
  async _searchFeature() {
    for (const f of ['photoSearch', 'photoPlaces', 'photoPeople']) if (await this.api.has(f).catch(() => false)) return;
    throw new DriveError('Drive cannot do photoSearch', { code: 'unsupported' });
  }

  /** photos/months → { ok, months } — Drive 1.16 with the filters of photos (q, place, person) */
  async photoMonths(area = null, { q = null, place = null, person = null } = {}) {
    return this._run(async () => {
      await this._feature('photos');
      if (q) await this._searchFeature();
      if (place) await this._feature('photoPlaces');
      if (person) await this._feature('photoPeople');
      return { ok: true, ...(await this.api.photoMonths(area, q || place || person ? { q, place, person } : null)) };
    });
  }

  /** "Vor einem Jahr": photos of this day (± 1) of earlier years → { ok, groups } */
  async memories(date = null) {
    return this._run(async () => {
      await this._feature('photos');
      return { ok: true, ...(await this.api.memories(date)) };
    });
  }

  // ── Drive 1.18: the overview ───────────────────────────

  /**
   * The page "Übersicht" → { ok, overview, view } (utils/drive-overview.js; view: the tiles and their texts). With 'overview' GET overview; else built from
   * the endpoints this Drive has (a part that fails is left out, like one whose feature is off).
   */
  async overview() {
    return this._run(async () => {
      const f = (await this._meFresh()).features || [];
      if (f.includes('overview')) {
        const overview = await this.api.overview();
        return { ok: true, overview, view: OV.overviewView(overview, this.now()) };
      }
      const soft = (on, fn) => (on ? fn().catch(() => null) : Promise.resolve(null));
      const now = this.now();
      const d = new Date(now);
      const today = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      const [deadlines, classes, memories, people, places, areas] = await Promise.all([
        soft(f.includes('docAi'), () => this.api.deadlines({ from: today })),
        soft(f.includes('photoClasses'), () => this.api.photoClasses()),
        soft(f.includes('photos'), () => this.api.memories(today)),
        soft(f.includes('photoPeople'), () => this.api.people()),
        soft(f.includes('photoPlaces'), () => this.api.photoPlaces({})),
        soft(true, () => this.api.areas()),
      ]);
      const overview = OV.assembleOverview({ now, deadlines, classes, memories, people, places, areas: areas && areas.areas });
      return { ok: true, overview, view: OV.overviewView(overview, now) };
    });
  }

  // ── Drive 1.16: places and people ────────────────────────

  /** The places of the photos (most first) → { ok, places } */
  async photoPlaces(filter = {}) {
    return this._run(async () => {
      await this._feature('photoPlaces');
      if (filter && filter.person) await this._feature('photoPeople');
      return { ok: true, ...(await this.api.photoPlaces(filter || {})) };
    });
  }

  /** The clusters of photos in a box of the map at a zoom → { ok, clusters } */
  async photoMap({ bbox, zoom, ...filter } = {}) {
    return this._run(async () => {
      await this._feature('photoPlaces');
      return { ok: true, ...(await this.api.photoMap({ bbox, zoom, ...filter })) };
    });
  }

  /** Suggestions while typing: people, places, labels → { ok, people, places, labels } */
  async photoSuggest(q) {
    return this._run(async () => {
      if (!(await this.api.has('photoPlaces').catch(() => false)) && !(await this.api.has('photoPeople').catch(() => false))) {
        throw new DriveError('Drive cannot do photoPlaces / photoPeople', { code: 'unsupported' });
      }
      return { ok: true, ...(await this.api.photoSuggest(q)) };
    });
  }

  async _placesOrPeople() {
    const [places, people] = await Promise.all([this.api.has('photoPlaces').catch(() => false), this.api.has('photoPeople').catch(() => false)]);
    if (!places && !people) throw new DriveError('Drive cannot do photoPlaces / photoPeople', { code: 'unsupported' });
    return { places, people };
  }

  /** The person's settings of places and people → { ok, keepGeo, stripGeoOnShare, people, peopleKids } */
  async photoSettings() {
    return this._run(async () => {
      await this._placesOrPeople();
      return { ok: true, ...(await this.api.photoSettings()) };
    });
  }

  /**
   * Changes them ({ keepGeo?, stripGeoOnShare?, people?, peopleKids? }); `people: false` deletes all face data
   * ("Alle Gesichtsdaten löschen") → { ok, …settings, deleted }.
   */
  async setPhotoSettings(patch = {}) {
    return this._run(async () => {
      const f = await this._placesOrPeople();
      const p = patch || {};
      if ((p.keepGeo !== undefined || p.stripGeoOnShare !== undefined) && !f.places) throw new DriveError('Drive cannot do photoPlaces', { code: 'unsupported' });
      if ((p.people !== undefined || p.peopleKids !== undefined) && !f.people) throw new DriveError('Drive cannot do photoPeople', { code: 'unsupported' });
      return { ok: true, ...(await this.api.setPhotoSettings(p)) };
    });
  }

  /** "Orte löschen": the places of every photo this person uploaded → { ok, deleted } */
  async deletePhotoGeo() {
    return this._run(async () => {
      await this._feature('photoPlaces');
      return { ok: true, ...(await this.api.deletePhotoGeo()) };
    });
  }

  async people() {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.people()) };
    });
  }

  async person(id) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.person(id)) };
    });
  }

  /** Name ("" removes it; a name taken merges both → mergedInto), hide / show, link with a family member or contact. */
  async updatePerson(id, patch = {}) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.updatePerson(id, patch || {})) };
    });
  }

  async mergePerson(id, into) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.mergePerson(id, into)) };
    });
  }

  async similarPeople(id) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.similarPeople(id)) };
    });
  }

  async uncertainFaces(id, limit = 50) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.uncertainFaces(id, limit)) };
    });
  }

  async confirmFaces(id, faceIds, yes) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.confirmFaces(id, faceIds, yes)) };
    });
  }

  async moveFace(faceId, person = null) {
    return this._run(async () => {
      await this._feature('photoPeople');
      return { ok: true, ...(await this.api.moveFace(faceId, person)) };
    });
  }

  async albums() {
    return this._run(async () => {
      await this._feature('albums');
      return { ok: true, ...(await this.api.albums()) };
    });
  }

  async album(id, { before = null, limit = 100 } = {}) {
    return this._run(async () => {
      await this._feature('albums');
      const r = await this.api.album(id, { before, limit });
      for (const p of r.items) if (p.mediaId) this._mediaOf.set(p.id, p.mediaId);
      return { ok: true, ...r };
    });
  }

  async createAlbum({ name, areaId = null } = {}) {
    return this._run(async () => {
      await this._feature('albums');
      return { ok: true, album: await this.api.createAlbum({ name, areaId }) };
    });
  }

  /** { name?, coverId?, frame? } – `frame` only on Drives with 'frame' (and albums with canFrame; else 403 { field: 'frame' }) */
  async updateAlbum(id, patch = {}) {
    return this._run(async () => {
      await this._feature('albums');
      if (patch && patch.frame !== undefined) await this._feature('frame');
      return { ok: true, album: await this.api.updateAlbum(id, patch || {}) };
    });
  }

  async deleteAlbum(id) {
    return this._run(async () => {
      await this._feature('albums');
      return this.api.deleteAlbum(id);
    });
  }

  /** Photos into an album (remove: out of it) → { ok, album } */
  async albumItems(id, ids, { remove = false } = {}) {
    return this._run(async () => {
      await this._feature('albums');
      return { ok: true, album: await this.api.albumItems(id, ids, { remove }) };
    });
  }

  /** The storage overview → { ok, total, limit, areas, people, largest, duplicates } (`all`: administrators) */
  async storage({ all = false } = {}) {
    return this._run(async () => {
      await this._feature('storage');
      return { ok: true, ...(await this.api.storage({ all })) };
    });
  }

  async pruneVersions({ areaId, keep } = {}) {
    return this._run(async () => {
      await this._feature('storage');
      return { ok: true, ...(await this.api.pruneVersions({ areaId, keep })) };
    });
  }

  // ── Drive 1.8: AI for documents, deadlines, the import ───

  /** What Drive recognised in a file → { ok, insight } */
  async insight(id) {
    return this._run(async () => {
      await this._feature('docAi');
      return { ok: true, insight: await this.api.insight(id) };
    });
  }

  /** "Erneut erkennen" → { ok, insight } (422 unsupported { reason: no_text | media_disabled }) */
  async recognize(id) {
    return this._run(async () => {
      await this._feature('docAi');
      return { ok: true, insight: await this.api.recognize(id) };
    });
  }

  /** The suggestion taken (name and / or folder) → { ok, node, insight } */
  async applyInsight(id, { name = false, folder = false } = {}) {
    return this._run(async () => {
      await this._feature('docAi');
      const before = await this.api.node(id).catch(() => null);
      const r = await this.api.applyInsight(id, { name, folder });
      if (before && before.parentId) this.emit('changed', { folderId: before.parentId });
      if (r.node.parentId && (!before || before.parentId !== r.node.parentId)) this.emit('changed', { folderId: r.node.parentId });
      return { ok: true, ...r };
    });
  }

  /** The deadlines of the files the person reads → { ok, deadlines } (from / to: YYYY-MM-DD) */
  async deadlines({ from = null, to = null } = {}) {
    return this._run(async () => {
      await this._feature('docAi');
      return { ok: true, ...(await this.api.deadlines({ from, to })) };
    });
  }

  /** "Erinnern N Tage vorher" (daysBefore null: no reminder) → { ok, deadline } */
  async remind(deadlineId, daysBefore) {
    return this._run(async () => {
      await this._feature('docAi');
      const deadline = daysBefore === null || daysBefore === undefined ? await this.api.unremind(deadlineId) : await this.api.remind(deadlineId, daysBefore);
      return { ok: true, deadline };
    });
  }

  /** AI for documents on / off in an area (write right) → { ok, area: { id, docAi } } */
  async setDocAi(areaId, on) {
    return this._run(async () => {
      await this._feature('docAi');
      return { ok: true, area: await this.api.setDocAi(areaId, on) };
    });
  }

  /** "Aus Google Drive / OneDrive importieren": the portal's import page in the browser (Drive 1.8 'cloudImport'). */
  async openImport() {
    return this._run(async () => {
      await this._feature('cloudImport');
      const c = await this._meFresh(false);
      const a = this.apiClient || {};
      const url = drive.allowedLink(drive.importLink((c.links && c.links.drive) || a.portalUrl || a.serverUrl), this._hosts());
      if (!url) return { ok: false, code: 'unsupported', error: 'no portal address' };
      if (!this.shell || typeof this.shell.openExternal !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
      const ok = await openExternalSafely(this.shell, url, { log: this.log, label: 'Drive import link' });
      return ok ? { ok: true } : { ok: false, code: 'open_failed', error: 'not opened' };
    });
  }

  // ── Drive 1.9: office in the browser ─────────────────────

  /** "Im Browser bearbeiten / ansehen": the office address in the default browser → { ok, mode, expiresAt } */
  async office(id) {
    return this._run(async () => {
      await this._feature('office');
      if (!this.shell || typeof this.shell.openExternal !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
      const r = await this.api.office(id);
      const ok = await openExternalSafely(this.shell, r.url, { log: this.log, label: 'Drive office link' });
      return ok ? { ok: true, mode: r.mode, expiresAt: r.expiresAt } : { ok: false, code: 'open_failed', error: 'not opened' };
    });
  }

  // ── Drive 1.14: the family calendar, questions, scans become documents ──

  /**
   * "In den Familienkalender" of a deadline → { ok, deadline } (409 familie_unavailable: Familie not there / refused);
   * Drive 1.17 "In Kalender eintragen": target { kind: 'mail', calendarId } (409 mail_unavailable { reason }).
   */
  async calendar(deadlineId, target = null) {
    return this._run(async () => {
      const mail = !!(target && target.kind === 'mail');
      await this._feature(mail ? 'deadlineMailCalendar' : 'deadlineCalendar');
      return { ok: true, deadline: await this.api.calendar(deadlineId, mail ? target : null) };
    });
  }

  /** Drive 1.17: the calendars a deadline can go to → { ok, family, mail: [{ id, name, account, color }] } */
  async deadlineCalendars() {
    return this._run(async () => {
      await this._feature('deadlineMailCalendar');
      return { ok: true, ...(await this.api.deadlineCalendars()) };
    });
  }

  /** Drive 1.17: the person's target per area for new deadlines → { ok, targets: [{ areaId, label, target }] } */
  async deadlineTargets() {
    return this._run(async () => {
      await this._feature('deadlineMailCalendar');
      return { ok: true, ...(await this.api.deadlineTargets()) };
    });
  }

  /** Drive 1.17: "Fristen aus <Bereich>" → { ok, targets } (target null: off, { kind: 'family' }, { kind: 'mail', calendarId, label }) */
  async setDeadlineTarget(areaId, target) {
    return this._run(async () => {
      await this._feature('deadlineMailCalendar');
      return { ok: true, ...(await this.api.setDeadlineTarget(areaId, target)) };
    });
  }

  /** New deadlines of an area into the family calendar on their own (write right) → { ok, area: { id, docAi, deadlinesToCalendar } } */
  async setDeadlinesToCalendar(areaId, on) {
    return this._run(async () => {
      await this._feature('deadlineCalendar');
      return { ok: true, area: await this.api.setDeadlinesToCalendar(areaId, on) };
    });
  }

  /** A question to the person's documents (3 … 300 characters) → { ok, status, answer, sources, terms, areas, deadline } (429 rate_limited) */
  async ask(q, area = null) {
    return this._run(async () => {
      await this._feature('docAsk');
      return { ok: true, ...(await this.api.ask(q, { area })) };
    });
  }

  /** Can this PC make the searchable PDF itself? → { ok, supported, local, reason } */
  async scanStatus() {
    const supported = await this.api.has('scanDocs').catch(() => false);
    if (!this.ocr) return { ok: true, supported, local: false, reason: 'no_ocr' };
    const a = await Promise.resolve(this.ocr.available()).catch(() => ({ available: false, reason: 'error' }));
    return { ok: true, supported, local: !!(a && a.available), reason: a && a.available ? null : (a && a.reason) || 'error' };
  }

  _scanDir() {
    return path.join(this.tempDir(), 'scan', crypto.randomBytes(8).toString('hex'));
  }

  /**
   * "In Dokument umwandeln" of the pictures `ids` (one scan, its pages in this order, ≤ 8): their media; the pictures
   * this PC reads (JPEG / PNG) are loaded — the text of the pages is read here when Windows has an OCR language (the
   * text goes to the AI first, the picture only when it is needed); then scans/classify → { ok, scanId, pages, kind,
   * confidence, summary, classified, local, words, folderId, areaId, name, suggestion: { name, folderId, folderPath } |
   * null }. local: the searchable PDF is made here.
   */
  async scanPrepare(ids) {
    return this._run(async () => {
      await this._feature('scanDocs');
      const list = [...new Set((Array.isArray(ids) ? ids : []).map(drive.posId).filter(Boolean))];
      if (!list.length || list.length > drive.SCAN_PAGES_MAX) throw new DriveError('invalid pages', { code: 'invalid' });
      const nodes = [];
      for (const id of list) {
        const n = await this.api.node(id);
        if (n.isDir || n.encrypted) throw new DriveError('not a picture', { code: n.encrypted ? 'encrypted' : 'invalid' });
        if (!SCAN_ANY_RE.test(n.mime || guessMime(n.name))) throw new DriveError('not a picture', { code: 'not_picture' });
        nodes.push(n);
      }
      const contents = [];
      for (const n of nodes) contents.push(await this.api.content(n.id));
      const mediaIds = contents.map((c) => c.mediaId);
      // the pictures on this PC (smaller copies go to Drive for a PDF / a Word file; with an OCR language: their text)
      let pages = null;
      let dir = null;
      const readable = !!this.ocr && contents.every((c, i) => SCAN_MIME_RE.test(c.mime || nodes[i].mime || '') && (!c.size || c.size <= SCAN_IMAGE_MAX));
      if (readable) {
        dir = this._scanDir();
        try {
          await fs.promises.mkdir(dir, { recursive: true });
          pages = [];
          for (let i = 0; i < contents.length; i++) {
            const file = path.join(dir, `page-${i + 1}`);
            const out = fs.createWriteStream(file);
            try {
              await this.api.download(contents[i].mediaId, out, { maxBytes: SCAN_IMAGE_MAX });
            } catch (err) { out.destroy(); throw err; }
            pages.push({ file, width: null, height: null, lines: null });
          }
        } catch (err) {
          this.log.warn(`Drive scan: pictures not loaded (${drive.errorCode(err)})`);
          pages = null;
          await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
          dir = null;
        }
      }
      let local = false;
      if (pages && (await Promise.resolve(this.ocr.available()).catch(() => null) || {}).available) {
        try {
          for (const p of pages) {
            const r = await this.ocr.recognize(await fs.promises.readFile(p.file));
            Object.assign(p, { width: r.width, height: r.height, lines: r.lines });
          }
          local = true;
        } catch (err) {
          this.log.warn(`Drive scan: no text on this PC (${drive.errorCode(err)})`);
          for (const p of pages) Object.assign(p, { width: null, height: null, lines: null });
        }
      }
      const text = local ? pagesText(pages) : '';
      const words = local ? pages.reduce((a, p) => a + p.lines.reduce((b, l) => b + l.words.length, 0), 0) : 0;
      let cls = null;
      let classifyError = null;
      try {
        cls = await this.api.scanClassify({ mediaIds, text: text || null });
      } catch (err) {
        // without AI for it (budget, pictures not allowed …) the PDF made here and "Nur Bild" still work
        if (!(err instanceof DriveError) || ['network', 'timeout', 'drive_unavailable'].includes(err.code)) throw err;
        classifyError = drive.errorCode(err);
      }
      let suggestion = null;
      if (await this.api.has('docAi').catch(() => false)) {
        const ins = await this.api.insight(nodes[0].id).catch(() => null);
        if (ins && ins.status === 'ready' && ins.suggestion) suggestion = ins.suggestion;
      }
      const kind = cls ? cls.kind : (words ? 'printed' : 'other');
      const scanId = crypto.randomBytes(12).toString('hex');
      const timer = setTimeout(() => this.scanDiscard(scanId), SCAN_KEEP_MS);
      if (timer.unref) timer.unref();
      this._scans.set(scanId, { ids: list, nodes, mediaIds, pages, local, text, dir, kind, timer, scope: this._scopeNow() });
      return {
        ok: true,
        scanId,
        pages: list.length,
        kind,
        confidence: cls ? cls.confidence : null,
        summary: cls ? cls.summary : null,
        classified: !!cls,
        classifyError,
        local,
        // a PDF needs this PC's text or its pictures for Drive (without them Drive makes no PDF)
        pdf: local || !!pages,
        words,
        folderId: nodes[0].parentId,
        areaId: nodes[0].areaId,
        name: withExt(nodes[0].name, null),
        suggestion,
      };
    });
  }

  /** A prepared scan is not needed any more (its pictures on this PC go). */
  scanDiscard(scanId) {
    const sc = this._scans.get(scanId);
    if (!sc) return { ok: true };
    this._scans.delete(scanId);
    clearTimeout(sc.timer);
    if (sc.dir) fs.promises.rm(sc.dir, { recursive: true, force: true }).catch(() => {});
    return { ok: true };
  }

  /**
   * "Als PDF / Word-Datei / Excel-Datei speichern" (target 'pdf' | 'docx' | 'xlsx') or "Bild speichern" ('image': the
   * picture stays, renamed / moved when asked) of a prepared scan into `folderId` as `name` → { ok, node, target, local }.
   * A PDF with this PC's text is made here; else Drive makes the bytes (scans/convert — with smaller copies of the
   * pictures for a PDF's pages, a whiteboard's photo, a handwritten page) and this PC uploads them; scans/save files
   * either. keepOriginal false: the scan's pictures go into the trash once the document is there (the first by Drive).
   * Drive gave no file (a PDF without pictures): code 'scan_no_file'.
   */
  async scanSave(scanId, { target, folderId = null, name = null, keepOriginal = true } = {}) {
    return this._run(async () => {
      await this._feature('scanDocs');
      const sc = this._scans.get(scanId);
      if (!sc || sc.scope !== this._scopeNow()) throw new DriveError('scan gone', { code: 'not_found' });
      if (this._locked()) throw new DriveError('device locked', { code: 'device_locked' });
      const parentId = drive.posId(folderId) || sc.nodes[0].parentId;
      if (target === 'image') {
        if (sc.nodes.length !== 1) throw new DriveError('one picture only', { code: 'invalid' });
        const n = sc.nodes[0];
        const ext = (/\.([A-Za-z0-9]{1,5})$/.exec(n.name) || [])[1] || null;
        const want = name ? this._name(withExt(name, ext)) : n.name;
        const node = want !== n.name || parentId !== n.parentId ? await this.api.place(n.id, { name: want !== n.name ? want : null, parentId: parentId !== n.parentId ? parentId : null }) : n;
        this.scanDiscard(scanId);
        if (n.parentId) this.emit('changed', { folderId: n.parentId });
        if (parentId !== n.parentId) this.emit('changed', { folderId: parentId });
        return { ok: true, node, target, local: false };
      }
      if (!SCAN_EXT[target]) throw new DriveError('invalid target', { code: 'invalid' });
      const fileName = this._name(withExt(name || sc.nodes[0].name, SCAN_EXT[target]));
      const local = target === 'pdf' && sc.local;
      let doc;   // { data, mime, name, text, folderId }
      if (local) {
        doc = await this._scanPdfHere(sc, fileName);
      } else {
        const images = await this._scanImages(sc, target);
        const ask = (imgs) => this.api.scanConvert({ mediaIds: sc.mediaIds, text: sc.text || null, target, kind: sc.kind, folderId: parentId, name: fileName, images: imgs });
        let r;
        try {
          r = await ask(images);
        } catch (err) {
          // the pictures too large for Drive: once more without them
          if (!(images && err && err.code === 'too_large')) throw err;
          r = await ask(null);
        }
        if (!r.file) throw new DriveError('no document', { code: 'scan_no_file' });
        doc = { data: r.file.data, mime: r.file.mime, name: r.file.name, text: r.text, folderId: r.folderId || parentId };
      }
      const file = path.join(sc.dir || this._scanDir(), `doc.${SCAN_EXT[target]}`);
      await fs.promises.mkdir(path.dirname(file), { recursive: true });
      await fs.promises.writeFile(file, doc.data);
      let saved;
      try {
        const up = await this.api.upload({ path: file, size: doc.data.length, mime: doc.mime || guessMime(doc.name) }, {});
        saved = await this.api.scanSave({ mediaId: up.mediaId, folderId: doc.folderId || parentId, name: doc.name, text: doc.text || null, sourceId: sc.nodes[0].id, keepOriginal: keepOriginal !== false });
      } finally {
        if (!sc.dir) fs.promises.rm(path.dirname(file), { recursive: true, force: true }).catch(() => {});
      }
      this.scanDiscard(scanId);
      if (keepOriginal === false) {
        // the first picture Drive put into the trash (when one may); the other pages here
        for (const n of sc.nodes.slice(1)) await this.api.trash(n.id).catch((err) => this.log.warn(`Drive scan: original not removed (${drive.errorCode(err)})`));
        for (const f of new Set(sc.nodes.map((n) => n.parentId).filter(Boolean))) if (f !== saved.node.parentId) this.emit('changed', { folderId: f });
      }
      this.emit('changed', { folderId: saved.node.parentId || doc.folderId || parentId });
      return { ok: true, node: saved.node, target, local };
    });
  }

  /** The searchable PDF of a scan made on this PC → { data, mime, name, text, folderId: null }. */
  async _scanPdfHere(sc, fileName) {
    const pages = [];
    for (const p of sc.pages) {
      const img = this.ocr.image(await fs.promises.readFile(p.file));
      pages.push({ jpeg: img.jpeg, width: img.width, height: img.height, lines: p.lines });
    }
    const data = buildSearchablePdf(pages, { title: fileName.replace(/\.pdf$/i, ''), now: this.now() });
    return { data, mime: 'application/pdf', name: fileName, text: pagesText(sc.pages) || null, folderId: null };
  }

  /**
   * Smaller JPEGs of the pages for scans/convert (≤ 600 KB together): every page for a PDF, the first for the Word file
   * of a whiteboard / handwriting; null when not needed or not possible (Drive then works with the text alone).
   */
  async _scanImages(sc, target) {
    const want = target === 'pdf' ? sc.pages : target === 'docx' && (sc.kind === 'whiteboard' || sc.kind === 'handwriting') && sc.pages ? sc.pages.slice(0, 1) : null;
    if (!want || !want.length || !this.ocr || typeof this.ocr.jpeg !== 'function') return null;
    const raw = [];
    for (const p of want) raw.push(await fs.promises.readFile(p.file));
    for (const [maxSide, quality] of [[1700, 72], [1400, 62], [1100, 55], [850, 50]]) {
      try {
        const out = raw.map((b) => this.ocr.jpeg(b, { maxSide, quality }));
        if (out.reduce((a, b) => a + b.length, 0) <= drive.SCAN_IMAGES_MAX_BYTES - 8 * 1024) return out;
      } catch (err) {
        this.log.warn(`Drive scan: pictures not made smaller (${drive.errorCode(err)})`);
        return null;
      }
    }
    return null;
  }

  /**
   * The preview of a photo by its node (Drive 1.7 photo answers without a mediaId): the node is
   * asked once (GET nodes/<id>, it tells no one), then the preview of its media → { ok, mime, data }.
   */
  async previewOf(nodeId, { large = false } = {}) {
    const id = drive.posId(nodeId);
    if (!id) throw new DriveError('invalid id', { code: 'invalid' });
    this._ensureScope();
    let mediaId = this._mediaOf.get(id);
    if (!mediaId) {
      const node = await this._run(() => this.api.node(id));
      if (!node.mediaId || node.isDir) throw new DriveError('no picture', { code: 'not_found' });
      mediaId = node.mediaId;
      this._mediaOf.set(id, mediaId);
      while (this._mediaOf.size > 5000) this._mediaOf.delete(this._mediaOf.keys().next().value);
    }
    return this.preview(mediaId, { large });
  }

  // ── Previews ─────────────────────────────────────────────

  /** The preview of `mediaId` → { ok, mime, data } (cached; a new version is a new mediaId). */
  async preview(mediaId, { large = false } = {}) {
    if (!drive.isMediaId(mediaId)) throw new DriveError('invalid media id', { code: 'invalid' });
    this._ensureScope();
    const key = `${mediaId}|${large ? 'l' : 's'}`;
    const hit = this._previews.get(key);
    if (hit) return { ok: true, ...hit };
    if (this._inflight.has(key)) return this._inflight.get(key);
    const run = this.api.preview(mediaId, { large }).then((r) => {
      this._previews.set(key, r);
      while (this._previews.size > this.timing.previewCache) this._previews.delete(this._previews.keys().next().value);
      return { ok: true, ...r };
    }).finally(() => this._inflight.delete(key));
    this._inflight.set(key, run);
    return run;
  }

  // ── The folder last picked ("In Drive speichern") ────────

  _scopeKey() {
    return crypto.createHash('sha256').update(this._scopeNow()).digest('hex').slice(0, 16);
  }

  /** → { ok, folderId } of this server, or folderId null. */
  lastFolder() {
    let v = null;
    try { v = this.store && this.store.get(STORE_KEY); } catch { v = null; }
    const ok = v && typeof v === 'object' && v.scope === this._scopeKey();
    return { ok: true, folderId: ok ? drive.posId(v.folderId) : null };
  }

  rememberFolder(folderId) {
    const id = drive.posId(folderId);
    if (!id) throw new DriveError('invalid folder', { code: 'invalid' });
    try { if (this.store) this.store.set(STORE_KEY, { v: 1, scope: this._scopeKey(), folderId: id }); } catch (err) { this.log.warn(`Drive folder not remembered: ${err.message}`); }
    return { ok: true, folderId: id };
  }

  // ── Transfers (the list on the page) ─────────────────────

  transfers() {
    return this._transfers.map((r) => ({ ...r }));
  }

  _row(row) {
    this._transfers.push(row);
    const done = (r) => !['queued', 'running', 'conflict'].includes(r.state);
    let extra = this._transfers.filter(done).length - this.timing.keepTransfers;
    if (extra > 0) this._transfers = this._transfers.filter((r) => !(done(r) && extra-- > 0));
    this._emitTransfers(true);
  }

  _set(id, patch, { progress = false } = {}) {
    const r = this._transfers.find((x) => x.id === id);
    if (!r) return;
    Object.assign(r, patch);
    this._emitTransfers(!progress);
  }

  _emitTransfers(now) {
    const fire = () => {
      this._emitTimer = null;
      this._lastEmit = Date.now();
      this.emit('transfers', this.transfers());
    };
    if (now) {
      clearTimeout(this._emitTimer);
      fire();
      return;
    }
    if (this._emitTimer) return;
    const wait = Math.max(0, this.timing.progressMs - (Date.now() - this._lastEmit));
    this._emitTimer = setTimeout(fire, wait);
    if (this._emitTimer.unref) this._emitTimer.unref();
  }

  /** Removes finished rows. */
  clearTransfers() {
    this._transfers = this._transfers.filter((r) => ['queued', 'running', 'conflict'].includes(r.state));
    this._emitTransfers(true);
    return { ok: true, transfers: this.transfers() };
  }

  // ── Upload ───────────────────────────────────────────────

  /** File dialog → { ok, paths } | { ok: false, code: 'cancelled' } */
  async pickFiles() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const opts = { properties: ['openFile', 'multiSelections'] };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, paths: r.filePaths.slice(0, MAX_PATHS) };
  }

  /** Folder dialog ("Ordner hochladen") → { ok, paths } | { ok: false, code: 'cancelled' } */
  async pickFolders() {
    if (!this.dialog || typeof this.dialog.showOpenDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    const win = this.getMainWindow();
    const opts = { properties: ['openDirectory', 'multiSelections', 'dontAddToRecent'] };
    const r = win ? await this.dialog.showOpenDialog(win, opts) : await this.dialog.showOpenDialog(opts);
    if (!r || r.canceled || !Array.isArray(r.filePaths) || !r.filePaths.length) return { ok: false, code: 'cancelled', error: 'cancelled' };
    return { ok: true, paths: r.filePaths.slice(0, MAX_PATHS) };
  }

  /**
   * Queues files (and whole folders) from disk for the folder `parentId`
   * → { ok, queued, rejected, folders, skipped }. Unreadable paths are rejected ({ name, code });
   * a folder is made in Drive with its structure (folders: how many), what is left out counts in skipped.
   */
  async upload(parentId, paths) {
    const folderId = drive.posId(parentId);
    if (!folderId) throw new DriveError('invalid folder', { code: 'invalid' });
    this._need();
    // Drive 1.9: into a vault only encrypted (this PC needs its key)
    const parent = await this._run(() => this._vaultNodeOf(folderId));
    const vaultId = parent ? parent.vaultId : null;
    if (vaultId) {
      await this.vault.tryOpen(vaultId);
      this.vault.keys(vaultId);
    }
    const list = Array.isArray(paths) ? paths.slice(0, MAX_PATHS) : [];
    const out = { queued: [], rejected: [], folders: 0, skipped: 0 };
    for (const p of list) {
      if (typeof p !== 'string' || !p || p.length > 4096 || !path.isAbsolute(p)) continue;
      const base = path.basename(p);
      let st;
      try { st = await fs.promises.lstat(p); } catch { out.rejected.push({ name: base, code: 'missing' }); continue; }
      if (st.isDirectory()) { await this._queueFolder(folderId, p, out, vaultId); continue; }
      if (!st.isFile()) { out.rejected.push({ name: base, code: 'missing' }); continue; }
      this._queueFile(folderId, p, base, st, out, vaultId);
    }
    this._pump();
    return { ok: true, ...out };
  }

  _queueFile(folderId, p, base, st, out, vaultId = null) {
    if (st.size > drive.MAX_FILE_BYTES) { out.rejected.push({ name: base, code: 'too_large' }); return; }
    const name = drive.safeName(base);
    if (!name) { out.rejected.push({ name: base, code: 'invalid_name' }); return; }
    const id = `u${++this._nextId}`;
    const job = { id, path: p, name, size: st.size, mtime: st.mtimeMs, folderId, choice: null, waiting: false, scope: this._scopeNow(), vault: vaultId };
    this._jobs.set(id, job);
    this._queue.push(job);
    this._row({ id, dir: 'up', name, folderId, total: st.size, sent: 0, state: 'queued', code: null, at: this.now() });
    out.queued.push(id);
  }

  /**
   * A whole folder: its structure in Drive first (the top folder gets a free name when taken),
   * then its files into the queue. Left out like "Ordner sichern": temporary files,
   * node_modules / .git, names Drive does not take, links.
   */
  async _queueFolder(parentId, abs, out, vaultId = null) {
    const base = path.basename(abs);
    const top = drive.safeName(base);
    if (!top) { out.rejected.push({ name: base, code: 'invalid_name' }); return; }
    const row = { id: `f${++this._nextId}`, dir: 'up', name: top, folderId: parentId, total: 0, sent: 0, state: 'running', code: null, at: this.now(), folder: true };
    this._row(row);
    const settings = { ...S.DEFAULT_SETTINGS, maxFileBytes: 0 };
    let files = 0;
    let dirs = 0;
    try {
      const made = await this._run(() => (vaultId ? this._vaultMkdir(vaultId, parentId, top, { free: true }) : this.api.mkdir(parentId, top, { rename: true })));
      dirs++;
      const walk = async (dirAbs, nodeId, rel) => {
        let entries;
        try { entries = await fs.promises.readdir(dirAbs, { withFileTypes: true }); } catch { out.skipped++; return; }
        entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        for (const e of entries) {
          const name = e.name.normalize('NFC');
          const r = S.joinRel(rel, name);
          const p = path.join(dirAbs, e.name);
          if (e.isSymbolicLink()) { out.skipped++; continue; }
          if (e.isDirectory()) {
            if (S.excluded(r, { dir: true }, settings) || dirs >= FOLDER_MAX_DIRS) { out.skipped++; continue; }
            const child = vaultId ? await this._run(() => this._vaultMkdir(vaultId, nodeId, name)) : await this._run(() => this.api.mkdir(nodeId, name, { rename: false })).catch(async (err) => {
              if (!(err && err.status === 409)) throw err;
              const kids = await this.api.childrenAll(nodeId);
              const have = kids.find((k) => k.isDir && !k.encrypted && S.keyOf(k.name) === S.keyOf(name));
              if (!have) throw err;
              return have;
            });
            dirs++;
            await walk(p, child.id, r);
          } else if (e.isFile()) {
            let st;
            try { st = await fs.promises.stat(p); } catch { out.skipped++; continue; }
            const why = S.excluded(r, { dir: false, size: st.size }, settings);
            if (why) { if (why !== 'temp') out.skipped++; continue; }
            // an empty file only goes to Drives that take them (1.5 'emptyFiles'; a vault's file always has its header)
            if (!st.size && !vaultId && !(await this.api.has('emptyFiles').catch(() => false))) { out.skipped++; continue; }
            if (files >= FOLDER_MAX_FILES) { out.skipped++; continue; }
            files++;
            this._queueFile(nodeId, p, name, st, out, vaultId);
          }
        }
      };
      await walk(abs, made.id, '');
      out.folders += dirs;
      this._set(row.id, { state: 'done', nodeId: made.id, name: made.name, files });
      this.emit('changed', { folderId: parentId });
    } catch (err) {
      out.folders += dirs;
      this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
      this.log.info(`Drive upload of a folder failed: ${drive.errorCode(err)}`);
    }
  }

  /** Drive stopped this device (guard): nothing goes up until it is decided. */
  _locked() {
    return !!(this._meCache && this._meCache.guard && this._meCache.guard.locked);
  }

  /**
   * What goes with a commit: the text layer of a PDF, the entropy (Drive 1.6 'guard'), when a photo was taken
   * (1.7 'takenAt') and where (1.16 'photoPlaces', not with keepGeo off).
   */
  async _commitExtra(file, name, size) {
    const extra = {};
    if (size > 0 && isMediaName(name)) {
      const wantAt = await this.api.has('takenAt').catch(() => false);
      const wantGeo = typeof this.api.geoAllowed === 'function' && await this.api.geoAllowed().catch(() => false);
      if (wantAt || wantGeo) {
        const r = await readShot(file, { name, geo: wantGeo }).catch(() => ({ takenAt: null, geo: null }));
        if (wantAt && r.takenAt) extra.takenAt = r.takenAt;
        if (wantGeo && r.geo) extra.geo = r.geo;
      }
    }
    if (size > 0 && isPdf(name)) {
      const text = await Promise.resolve(this.readPdfText(file, { size })).catch(() => null);
      if (text) extra.text = text;
    }
    if (size > 0 && await this.api.has('guard').catch(() => false)) {
      const e = await G.fileEntropy(file);
      if (e !== null) extra.entropy = e;
    }
    return extra;
  }

  /** The person's answer to a taken name: 'version' | 'rename' (keep both) | null (skip). */
  resolve(id, choice) {
    const job = this._jobs.get(id);
    if (!job || !job.waiting) throw new DriveError('no such upload', { code: 'not_found' });
    job.waiting = false;
    if (choice !== 'version' && choice !== 'rename') {
      this._jobs.delete(id);
      this._set(id, { state: 'skipped' });
      return { ok: true };
    }
    job.choice = choice;
    this._set(id, { state: 'queued' });
    this._queue.unshift(job);
    this._pump();
    return { ok: true };
  }

  async _pump() {
    if (this._pumping) return;
    this._pumping = true;
    try {
      while (this._queue.length) {
        const job = this._queue.shift();
        try {
          await this._runUpload(job);
        } catch (err) {
          const code = drive.errorCode(err);
          this._onWriteError(err);
          this.log.info(`Drive upload of a file failed: ${code}`);
          this._jobs.delete(job.id);
          this._set(job.id, { state: 'failed', code });
        }
      }
    } finally {
      this._pumping = false;
    }
  }

  async _runUpload(job) {
    if (job.scope !== this._scopeNow()) throw new DriveError('server changed', { code: 'drive_unavailable' });
    if (this._locked()) throw new DriveError('device locked', { code: 'device_locked' });
    this._set(job.id, { state: 'running', sent: 0 });
    let st;
    try { st = await fs.promises.stat(job.path); } catch { throw new DriveError('file gone', { code: 'missing' }); }
    if (!st.isFile()) throw new DriveError('file gone', { code: 'missing' });
    if (st.size !== job.size) {
      job.size = st.size;
      this._set(job.id, { total: st.size });
    }
    if (job.vault) { await this._runVaultUpload(job); return; }
    if (!job.choice) {
      const sha = job.size <= drive.SHA_MAX_BYTES ? await sha256File(job.path).catch(() => null) : null;
      const c = await this.api.check({ parentId: job.folderId, name: job.name, sha256: sha, size: job.size });
      if (c.same) {
        this._jobs.delete(job.id);
        this._set(job.id, { state: 'same', sent: job.size, nodeId: c.node ? c.node.id : null });
        return;
      }
      if (c.exists) {
        job.waiting = true;
        this._set(job.id, { state: 'conflict' });
        return;
      }
    }
    let r;
    if (!job.size) {
      // GateControl takes no empty media; Drive 1.5 ('emptyFiles') makes an empty file without one
      if (!(await this.api.has('emptyFiles').catch(() => false))) throw new DriveError('empty file', { code: 'empty_file' });
      r = await this.api.commit({ empty: true, parentId: job.folderId, name: job.name, mtime: job.mtime, onConflict: job.choice || 'rename' });
    } else {
      const up = await this.api.upload({ path: job.path, size: job.size, mime: guessMime(job.name) }, {
        onProgress: (sent) => this._set(job.id, { sent }, { progress: true }),
      });
      const extra = await this._commitExtra(job.path, job.name, job.size);
      r = await this.api.commit({ mediaId: up.mediaId, parentId: job.folderId, name: job.name, mtime: job.mtime, onConflict: job.choice || 'rename', ...extra });
    }
    this._jobs.delete(job.id);
    this._set(job.id, { state: 'done', sent: job.size, nodeId: r.node.id, name: r.node.name });
    this.emit('changed', { folderId: job.folderId });
  }

  /**
   * A file into a vault: a taken name asks like any upload (by the decrypted names of the folder) → the file encrypted
   * chunk by chunk into a temporary file (ciphertext only) → media upload → commit with nameCipher / keyVersion
   * (a new version: the file's opaque name with onConflict 'version'). A stale key: the keys again, once.
   */
  async _runVaultUpload(job) {
    this._vaultActive++;
    try {
      return await this._vaultUpload(job);
    } finally {
      this._vaultActive--;
      this.vaultLock.touch();
    }
  }

  async _vaultUpload(job) {
    const vaultId = job.vault;
    this.vault.keys(vaultId);
    const siblings = await this._vaultSiblings(job.folderId, vaultId);
    const same = (x) => S.keyOf(x.name) === S.keyOf(job.name);
    let name = job.name;
    let opaque = null;
    if (!job.choice) {
      const hit = siblings.find((x) => same(x) && !x.node.isDir);
      if (hit) {
        job.waiting = true;
        this._set(job.id, { state: 'conflict' });
        return;
      }
    }
    if (job.choice === 'version') {
      const hit = siblings.find((x) => same(x) && !x.node.isDir);
      if (hit) opaque = hit.node.name;
    }
    if (!opaque && siblings.some(same)) name = freeFileName(job.name, new Set(siblings.map((x) => S.keyOf(x.name))));
    await this._vaultTempReady();
    const dir = path.join(this.tempDir(), 'vault-up');
    await fs.promises.mkdir(dir, { recursive: true });
    const tmp = path.join(dir, `${job.id}-${crypto.randomBytes(6).toString('hex')}.enc`);
    let r;
    try {
      r = await this.vault.withCurrent(vaultId, async (cur) => {
        let enc;
        try {
          enc = await V.encryptFile(cur.tk, vaultId, cur.keyVersion, job.path, tmp);
        } catch (err) {
          if (err instanceof V.DriveVaultError) throw new DriveError(err.message, { code: err.code === 'changed' ? 'missing' : 'invalid' });
          throw err;
        }
        const up = await this.api.upload({ path: tmp, size: enc.cipherSize, mime: 'application/octet-stream' }, {
          onProgress: (sent) => this._set(job.id, { sent: Math.min(job.size, Math.round(sent * job.size / Math.max(1, enc.cipherSize))) }, { progress: true }),
        });
        const { nameCipher } = this.vault.encryptName(vaultId, name, cur);
        return this.api.commit({ mediaId: up.mediaId, parentId: job.folderId, mtime: job.mtime, encrypted: { nameCipher, keyVersion: cur.keyVersion, name: opaque, onConflict: opaque ? 'version' : 'rename' } });
      });
    } finally {
      await fs.promises.rm(tmp, { force: true }).catch(() => {});
    }
    this.vault.nameOf(r.node);
    this._jobs.delete(job.id);
    this._set(job.id, { state: 'done', sent: job.size, nodeId: r.node.id, name });
    this.emit('changed', { folderId: job.folderId });
  }

  // ── Download: open / save as ─────────────────────────────

  async _fetchTo(nodeId, versionId, file, row) {
    const c = await this.api.content(nodeId, versionId);
    const part = `${file}.${crypto.randomBytes(4).toString('hex')}.part`;
    await fs.promises.mkdir(path.dirname(file), { recursive: true });
    const out = fs.createWriteStream(part);
    try {
      // Drive 1.5: an empty file has no media
      if (c.empty) await new Promise((resolve, reject) => { out.on('error', reject); out.end(resolve); });
      else await this.api.download(c.mediaId, out, { onProgress: (got, total) => this._set(row.id, { sent: got, ...(total ? { total } : {}) }, { progress: true }) });
      await fs.promises.rm(file, { force: true });
      await fs.promises.rename(part, file);
    } catch (err) {
      out.destroy();
      await fs.promises.rm(part, { force: true }).catch(() => {});
      throw err;
    }
    return c;
  }

  _downloadRow(name, size) {
    const row = { id: `d${++this._nextId}`, dir: 'down', name, folderId: null, total: size || 0, sent: 0, state: 'running', code: null, at: this.now() };
    this._row(row);
    return row;
  }

  /**
   * Loads the file (or a version) into the temp folder and opens it with the
   * default program → { ok, path } | { ok: false, code: 'unsafe' } (executables:
   * "Speichern unter …" only).
   */
  async open(nodeId, { versionId = null } = {}) {
    if (!this.shell || typeof this.shell.openPath !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    return this._run(async () => {
      const node = await this.api.node(nodeId);
      if (node.isDir) throw new DriveError('a folder', { code: 'invalid' });
      if (node.encrypted && node.vaultId) return this._openVaultFile(node, versionId);
      const name = drive.safeName(node.name) || 'Datei';
      if (unsafeToOpen(name, node.mime)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
      const dir = path.join(this.tempDir(), `${node.id}-${versionId ? `v${drive.posId(versionId)}` : node.rev}`);
      // Windows device names (CON, NUL, COM1 …) cannot be files: open a renamed local copy.
      const file = path.join(dir, safeFileName(name, 'Datei'));
      let have = false;
      if (!versionId) {
        try { have = (await fs.promises.stat(file)).size === node.size && node.size > 0; } catch { have = false; }
      }
      if (have) {
        // Already loaded this revision: the server still learns that it was opened (a child's folder).
        await this.api.content(node.id).catch(() => {});
      } else {
        const row = this._downloadRow(name, node.size);
        try {
          await this._fetchTo(node.id, versionId, file, row);
          this._set(row.id, { state: 'done', sent: row.total, path: file });
        } catch (err) {
          this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
          throw err;
        }
      }
      const err = await this.shell.openPath(file);
      if (err) {
        this.log.warn(`Opening a Drive file failed: ${err}`);
        return { ok: false, code: 'open_failed', error: String(err) };
      }
      return { ok: true, path: file };
    });
  }

  /**
   * A vault file decrypted into %TEMP%\gatecontrol-drive\vault\<random>\<name> and opened; the copy goes again
   * after VAULT_OPEN_KEEP_MS (later while in use), at stop and at the next start.
   */
  async _openVaultFile(node, versionId) {
    await this.vault.tryOpen(node.vaultId);
    this.vault.keys(node.vaultId);
    const name = drive.safeName(this.vault.nameOf(node) || '') || 'Datei';
    if (unsafeToOpen(name, null)) return { ok: false, code: 'unsafe', error: 'file type is not opened directly' };
    const dir = path.join(this.tempDir(), 'vault', crypto.randomBytes(8).toString('hex'));
    const file = path.join(dir, safeFileName(name, 'Datei'));
    const row = this._downloadRow(name, node.size);
    try {
      await this._vaultFetchTo(node, versionId, file, row);
      this._set(row.id, { state: 'done', sent: row.total });
    } catch (err) {
      this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
      await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
      throw err;
    }
    this._forgetOpened(dir);
    const err = await this.shell.openPath(file);
    if (err) {
      this.log.warn(`Opening a Drive vault file failed: ${err}`);
      return { ok: false, code: 'open_failed', error: String(err) };
    }
    return { ok: true, path: file };
  }

  /** "Speichern unter …": the file (or a version) into a path the person picks → { ok, path } | { ok: false, cancelled }. */
  async saveAs(nodeId, { versionId = null } = {}) {
    if (!this.dialog || typeof this.dialog.showSaveDialog !== 'function') throw new DriveError('no dialog', { code: 'unsupported' });
    return this._run(async () => {
      const node = await this.api.node(nodeId);
      if (node.isDir) throw new DriveError('a folder', { code: 'invalid' });
      const vault = node.encrypted && node.vaultId ? node.vaultId : null;
      if (vault) {
        await this.vault.tryOpen(vault);
        this.vault.keys(vault);
      }
      const name = drive.safeName(vault ? this.vault.nameOf(node) || '' : node.name) || 'Datei';
      const win = this.getMainWindow();
      const res = win ? await this.dialog.showSaveDialog(win, { defaultPath: name }) : await this.dialog.showSaveDialog({ defaultPath: name });
      if (!res || res.canceled || !res.filePath) return { ok: false, cancelled: true, code: 'cancelled' };
      const row = this._downloadRow(path.basename(res.filePath), node.size);
      try {
        // a vault's file: decrypted into the path picked (the person asked for a plain copy there)
        if (vault) await this._vaultFetchTo(node, versionId, res.filePath, row);
        else await this._fetchTo(node.id, versionId, res.filePath, row);
      } catch (err) {
        this._set(row.id, { state: 'failed', code: drive.errorCode(err) });
        throw err;
      }
      this._set(row.id, { state: 'done', sent: row.total, path: res.filePath });
      return { ok: true, path: res.filePath };
    });
  }

  /** Shows a file this app saved / opened in the Explorer (rows of the transfer list only). */
  showItem(p) {
    if (!this.shell || typeof this.shell.showItemInFolder !== 'function') throw new DriveError('no shell', { code: 'unsupported' });
    if (!this._transfers.some((r) => r.path && r.path === p)) throw new DriveError('unknown file', { code: 'invalid' });
    this.shell.showItemInFolder(p);
    return { ok: true };
  }
}

/** The live event / push data `vault` → { vault, event, device, keyVersion } */
function vaultEvent(d) {
  const o = d && typeof d === 'object' ? d : {};
  return {
    vault: drive.vaultIdOf(o.vault),
    event: typeof o.event === 'string' ? o.event.slice(0, 20) : null,
    device: drive.vaultDeviceIdOf(o.device),
    keyVersion: drive.posId(o.keyVersion),
  };
}

/** "Brief.pdf" → "Brief (2).pdf" while taken (keys of S.keyOf); a folder (`dir`) without the extension rule. */
function freeFileName(name, taken, dir = false) {
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

/**
 * safeStorage (Windows: DPAPI, bound to the Windows user) as the `protect` of the vault folders' device key:
 * DriveService.safeStorageProtect(require('electron').safeStorage).
 */
function safeStorageProtect(safeStorage) {
  return {
    available: () => !!(safeStorage && safeStorage.isEncryptionAvailable()),
    encrypt: (b) => safeStorage.encryptString(Buffer.from(b).toString('base64')),
    decrypt: (b) => Buffer.from(safeStorage.decryptString(Buffer.from(b)), 'base64'),
  };
}

/** SHA-256 of a file (hex), streamed. */
function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(p);
    s.on('error', reject);
    s.on('data', (c) => h.update(c));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

DriveService.DEFAULT_TIMING = DEFAULT_TIMING;
DriveService.STORE_KEY = STORE_KEY;
DriveService.sha256File = sha256File;
DriveService.FOLDER_MAX_FILES = FOLDER_MAX_FILES;
DriveService.safeStorageProtect = safeStorageProtect;
DriveService.freeFileName = freeFileName;
DriveService.VAULT_OPEN_KEEP_MS = VAULT_OPEN_KEEP_MS;

module.exports = DriveService;
