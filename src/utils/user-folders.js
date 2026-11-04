'use strict';

/**
 * The Windows folders of the person signed in (Downloads, Dokumente, Bilder …)
 * — also when the app runs as another Windows user.
 *
 * The apps need administrator rights (requireAdministrator). A person without
 * them answers the UAC prompt with another (admin) account: the app then runs
 * as that account (utils/session-user.js runAs().differs) and
 * app.getPath('downloads') is C:\Users\<admin>\Downloads. Received GateDrop
 * files, the log export and the save dialogs would land there, where the
 * person signed in neither looks nor (as a standard user) may look.
 *
 * userPath(key) is the folder to use instead of app.getPath(key):
 *   - the app runs as the person signed in: app.getPath(key), as always;
 *   - it runs as another user: that person's folder, read from the registry —
 *       session (WTSUserName + WTSDomainName) → SID (LookupAccountNameW; else
 *       the loaded hive whose `Volatile Environment` names that account)
 *       → HKLM\…\ProfileList\<SID>\ProfileImagePath (the profile)
 *       → HKU\<SID>\…\Explorer\User Shell Folders (e.g. Downloads moved to
 *         OneDrive or a network drive), its %USERPROFILE% … filled in with the
 *         values of that person (profile, HKU\<SID>\Volatile Environment and
 *         Environment) — never with this process's environment;
 *       a value that cannot be filled in: `Shell Folders` (what Explorer
 *       wrote, already filled in); nothing usable: <profile>\Downloads.
 *       A folder this process cannot reach (a network drive mapped only for
 *       the person, a share the admin account may not open) is checked once
 *       in the background; then <profile>\Downloads is used, said in the log.
 *   - nothing known (no session, registry not readable): app.getPath(key),
 *     said once in the log.
 * Registry and SID through koffi (advapi32, UTF-16: names like „Jürgen“ come
 * through unchanged — reg.exe answers in the console's code page). Resolved
 * once per process and cached.
 *
 *   const { userPath, dialogPath } = require('./user-folders');
 *   userPath('downloads')                 // C:\Users\max\Downloads
 *   dialogPath('downloads', 'Liste.zip')  // defaultPath of a save dialog
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { runAs: defaultRunAs, sessionAccount: defaultSessionAccount } = require('./session-user');

const W = path.win32;

/** Known folders: value in `User Shell Folders`, folder below the profile when there is none. */
const FOLDERS = {
  downloads: { value: '{374DE290-123F-4565-9164-39C4925E467B}', dir: 'Downloads' },
  documents: { value: 'Personal', dir: 'Documents' },
  pictures: { value: 'My Pictures', dir: 'Pictures' },
  desktop: { value: 'Desktop', dir: 'Desktop' },
  videos: { value: 'My Video', dir: 'Videos' },
  music: { value: 'My Music', dir: 'Music' },
  appData: { value: 'AppData', dir: 'AppData\\Roaming' },
};
/** Keys besides FOLDERS: the profile itself. */
const HOME = 'home';

const HKEY_LOCAL_MACHINE = -2147483646; // (HKEY)(LONG)0x80000002, sign-extended like Windows does
const HKEY_USERS = -2147483645;         // (HKEY)(LONG)0x80000003
const KEY_PROFILES = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList';
const KEY_USER_SHELL_FOLDERS = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders';
const KEY_SHELL_FOLDERS = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders';
const KEY_VOLATILE = 'Volatile Environment';
const KEY_ENVIRONMENT = 'Environment';
/** Variables that are the same for every user of the PC (taken from this process). */
const MACHINE_VARS = ['SYSTEMDRIVE', 'SYSTEMROOT', 'WINDIR', 'PROGRAMDATA', 'ALLUSERSPROFILE', 'PUBLIC', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)'];
/** Loaded user hives: local / domain accounts (S-1-5-21-…), Entra ID accounts (S-1-12-1-…). */
const USER_SID_RE = /^S-1-(?:5-21|12-1)(?:-\d+)+$/;
/** A full path: C:\… or \\server\share\… */
const FULL_RE = /^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)/;

const ERROR_MORE_DATA = 234;
const ERROR_NO_MORE_ITEMS = 259;
const RRF_RT_REG_SZ = 0x00000002;
const RRF_RT_REG_EXPAND_SZ = 0x00000004;
const RRF_NOEXPAND = 0x10000000;

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Binary SID → "S-1-5-21-…" (null when it is no SID). */
function sidToString(buf) {
  if (!buf || buf.length < 8 || buf[0] !== 1) return null;
  const count = buf[1];
  if (buf.length < 8 + 4 * count) return null;
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + buf[i];
  const parts = ['S', '1', String(auth)];
  for (let i = 0; i < count; i++) parts.push(String(buf.readUInt32LE(8 + 4 * i)));
  return parts.join('-');
}

/**
 * Fills in %NAME% from lookup(NAME) (names without case; values may hold
 * variables themselves, two levels deep) → the string, or null when a
 * variable is unknown.
 */
function expandVars(value, lookup, depth = 0) {
  if (typeof value !== 'string') return null;
  let unknown = false;
  const out = value.replace(/%([^%\\]+)%/g, (all, name) => {
    let v = null;
    try { v = lookup(String(name).toUpperCase()); } catch { v = null; }
    if (typeof v !== 'string' || !v) { unknown = true; return all; }
    if (v.includes('%')) {
      if (depth >= 2) { unknown = true; return all; }
      const inner = expandVars(v, lookup, depth + 1);
      if (inner === null) { unknown = true; return all; }
      return inner;
    }
    return v;
  });
  return unknown ? null : out;
}

/** A process variable that is the same for every user, else null. */
function machineVar(env, name) {
  const up = String(name).toUpperCase();
  if (!MACHINE_VARS.includes(up)) return null;
  for (const [k, v] of Object.entries(env || {})) if (k.toUpperCase() === up && typeof v === 'string' && v) return v;
  return null;
}

// ── Windows (koffi) ──────────────────────────────────────

let winApi;

/**
 * advapi32 through koffi → { lookupSid(domain, user), regGet(hive, subKey, name), subKeys(hive) }
 * (Windows only, loaded once); null when it cannot be.
 */
function loadWinApi(koffi = null) {
  if (winApi !== undefined && !koffi) return winApi;
  let api = null;
  try {
    const k = koffi || require('koffi');
    const adv = k.load('advapi32.dll');
    const lookup = adv.func('bool __stdcall LookupAccountNameW(const char16_t *lpSystemName, const char16_t *lpAccountName, void *Sid, _Inout_ uint32_t *cbSid, void *ReferencedDomainName, _Inout_ uint32_t *cchReferencedDomainName, _Out_ int *peUse)');
    const getValue = adv.func('long __stdcall RegGetValueW(intptr_t hkey, const char16_t *lpSubKey, const char16_t *lpValue, uint32_t dwFlags, _Out_ uint32_t *pdwType, void *pvData, _Inout_ uint32_t *pcbData)');
    const enumKey = adv.func('long __stdcall RegEnumKeyExW(intptr_t hKey, uint32_t dwIndex, void *lpName, _Inout_ uint32_t *lpcchName, void *lpReserved, void *lpClass, void *lpcchClass, void *lpftLastWriteTime)');
    api = {
      lookupSid(domain, user) {
        const sid = Buffer.alloc(68);            // SECURITY_MAX_SID_SIZE
        const cbSid = [sid.length];
        const dom = Buffer.alloc(1024);          // 512 UTF-16 units
        const cchDom = [512];
        const use = [0];
        const name = domain ? `${domain}\\${user}` : user;
        if (!lookup(null, name, sid, cbSid, dom, cchDom, use)) return null;
        return sidToString(sid.subarray(0, Math.min(cbSid[0], sid.length)));
      },
      // REG_SZ / REG_EXPAND_SZ as stored (RRF_NOEXPAND: never filled in with this process's variables)
      regGet(hive, subKey, name) {
        let size = 1024;
        for (let i = 0; i < 4; i++) {
          const buf = Buffer.alloc(size);
          const type = [0];
          const cb = [size];
          const rc = getValue(hive, subKey, name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, type, buf, cb);
          if (rc === 0) return buf.subarray(0, Math.min(cb[0], size)).toString('utf16le').replace(/\0[\s\S]*$/, '');
          if (rc !== ERROR_MORE_DATA || cb[0] > 1 << 20) return null;
          size = Math.max(cb[0] + 2, size * 2);
        }
        return null;
      },
      subKeys(hive) {
        const out = [];
        for (let i = 0; i < 4096; i++) {
          const buf = Buffer.alloc(1024);
          const n = [512];
          const rc = enumKey(hive, i, buf, n, null, null, null, null);
          if (rc === ERROR_NO_MORE_ITEMS) break;
          if (rc !== 0) continue;
          out.push(buf.subarray(0, Math.min(n[0], 512) * 2).toString('utf16le'));
        }
        return out;
      },
    };
  } catch {
    api = null;
  }
  if (!koffi) winApi = api;
  return api;
}

// ── Resolution ───────────────────────────────────────────

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

/** The loaded hive whose `Volatile Environment` is this account's → SID, or null. */
function sidFromLoadedHives(api, account) {
  let keys;
  try { keys = api.subKeys(HKEY_USERS) || []; } catch { keys = []; }
  for (const sid of keys.filter((k) => USER_SID_RE.test(k))) {
    let user;
    let domain;
    try {
      user = api.regGet(HKEY_USERS, `${sid}\\${KEY_VOLATILE}`, 'USERNAME');
      domain = api.regGet(HKEY_USERS, `${sid}\\${KEY_VOLATILE}`, 'USERDOMAIN');
    } catch { continue; }
    if (same(user, account.user) && (!account.domain || !domain || same(domain, account.domain))) return sid;
  }
  return null;
}

/**
 * The folders of `account` from the registry (no reachability check)
 * → { sid, profile, folders: { key: { path, source } } } or null.
 * source: 'registry' (User Shell Folders), 'shell-folders' (Explorer's filled-in
 * copy), 'profile' (<profile>\<folder>).
 * @param {object} o
 * @param {{ user: string, domain?: string }} o.account
 * @param {object} o.api - loadWinApi() (tests: a fake)
 * @param {object} [o.env=process.env] - only the machine-wide variables are used
 * @param {object} [o.log]
 */
function resolveFolders({ account, api, env = process.env, log = noopLog() }) {
  if (!account || !account.user || !api) return null;
  const get = (hive, key, name) => { try { return api.regGet(hive, key, name) || null; } catch { return null; } };
  let sid = null;
  try { sid = api.lookupSid(account.domain || null, account.user); } catch { sid = null; }
  if (!sid) sid = sidFromLoadedHives(api, account);
  if (!sid) {
    log.warn(`User folders: no SID for "${account.domain ? `${account.domain}\\` : ''}${account.user}"`);
    return null;
  }
  const machine = (name) => machineVar(env, name);
  let profile = expandVars(get(HKEY_LOCAL_MACHINE, `${KEY_PROFILES}\\${sid}`, 'ProfileImagePath'), machine);
  if (!profile || !FULL_RE.test(profile)) profile = expandVars(get(HKEY_USERS, `${sid}\\${KEY_VOLATILE}`, 'USERPROFILE'), machine);
  if (!profile || !FULL_RE.test(profile)) {
    log.warn(`User folders: no profile for ${sid}`);
    return null;
  }
  profile = W.normalize(profile).replace(/\\+$/, '');

  // The person's variables: profile, Volatile Environment, Environment, derived ones, then the machine's.
  const base = (name) => {
    if (name === 'USERPROFILE') return profile;
    if (name === 'USERNAME') return account.user;
    if (name === 'USERDOMAIN' && account.domain) return account.domain;
    return null;
  };
  const derived = (name) => {
    if (name === 'APPDATA') return W.join(profile, 'AppData', 'Roaming');
    if (name === 'LOCALAPPDATA') return W.join(profile, 'AppData', 'Local');
    if (name === 'HOMEDRIVE' && /^[A-Za-z]:/.test(profile)) return profile.slice(0, 2);
    if (name === 'HOMEPATH' && /^[A-Za-z]:/.test(profile)) return profile.slice(2) || '\\';
    return null;
  };
  const lookup = (name) => base(name)
    || get(HKEY_USERS, `${sid}\\${KEY_VOLATILE}`, name)
    || get(HKEY_USERS, `${sid}\\${KEY_ENVIRONMENT}`, name)
    || derived(name)
    || machine(name);

  const folders = {};
  for (const [key, f] of Object.entries(FOLDERS)) {
    const fallback = { path: W.join(profile, f.dir), source: 'profile' };
    const raw = get(HKEY_USERS, `${sid}\\${KEY_USER_SHELL_FOLDERS}`, f.value);
    let p = raw ? expandVars(raw, lookup) : null;
    let source = 'registry';
    if (raw && !p) {
      log.warn(`User folders: ${key} "${raw}" cannot be filled in – Explorer's copy instead`);
      p = get(HKEY_USERS, `${sid}\\${KEY_SHELL_FOLDERS}`, f.value);
      source = 'shell-folders';
    }
    folders[key] = p && FULL_RE.test(p) ? { path: W.normalize(p).replace(/\\+$/, ''), source } : fallback;
  }
  return { sid, profile, folders };
}

// ── The app's view ───────────────────────────────────────

function defaultGetPath(key) {
  const { app } = require('electron');
  return app.getPath(key);
}

function defaultLog() {
  try { return require('electron-log'); } catch { return noopLog(); }
}

const sharedCache = {};

/**
 * @param {object} [o]
 * @param {(key: string) => string} [o.getPath] - app.getPath (the folders of this process)
 * @param {object} [o.log]
 * @param {() => object} [o.runAs] - session-user runAs()
 * @param {() => ({ user, domain }|null)} [o.account] - session-user sessionAccount()
 * @param {object|null} [o.api] - loadWinApi() (tests: a fake)
 * @param {object} [o.env=process.env]
 * @param {(p: string) => Promise<object>} [o.stat] - fs.promises.stat (reachability check)
 * @param {number} [o.checkTimeoutMs=5000] - a folder that does not answer in time counts as unreachable
 */
function createUserFolders({
  getPath = defaultGetPath, log = null, runAs = null, account = null, api = undefined, env = process.env,
  stat = (p) => fs.promises.stat(p), checkTimeoutMs = 5000,
} = {}) {
  const injected = !!(runAs || account || api !== undefined);
  const cache = injected ? {} : sharedCache;
  const logger = () => log || (log = defaultLog());

  function who() {
    if (!cache.ra) {
      let ra;
      try { ra = (runAs || defaultRunAs)(); } catch { ra = null; }
      cache.ra = ra || { processUser: null, sessionUser: null, differs: false, profile: null };
    }
    return cache.ra;
  }

  /** Background check: a folder this process cannot open → <profile>\<folder> (said in the log). */
  function check(res) {
    const keys = Object.keys(res.folders).filter((k) => res.folders[k].source !== 'profile');
    cache.checked = Promise.all(keys.map(async (key) => {
      const f = res.folders[key];
      let timer;
      const ok = await Promise.race([
        Promise.resolve().then(() => stat(f.path)).then((st) => !!st && st.isDirectory(), () => false),
        new Promise((r) => { timer = setTimeout(() => r(false), checkTimeoutMs); if (timer.unref) timer.unref(); }),
      ]);
      clearTimeout(timer);
      if (ok) return;
      const fallback = W.join(res.profile, FOLDERS[key].dir);
      logger().warn(`User folders: ${key} "${f.path}" is not reachable for this process – "${fallback}" instead`);
      res.folders[key] = { path: fallback, source: 'profile', unreachable: f.path };
    })).catch(() => {});
  }

  /** The folders of the person signed in, when the app runs as another user (once); else null. */
  function resolved() {
    if (cache.res !== undefined) return cache.res;
    const ra = who();
    let res = null;
    if (ra.differs) {
      let acc = null;
      try { acc = (account || defaultSessionAccount)(); } catch { acc = null; }
      if (!acc && ra.sessionUser) acc = { user: ra.sessionUser, domain: null };
      const a = api === undefined ? loadWinApi() : api;
      try { res = resolveFolders({ account: acc, api: a, env, log: logger() }); } catch (err) { logger().warn(`User folders: ${err.message}`); res = null; }
      if (res) {
        logger().info(`User folders: app runs as "${ra.processUser}", folders of "${ra.sessionUser}" (${res.profile}): downloads ${res.folders.downloads.path} (${res.folders.downloads.source})`);
        check(res);
      } else {
        logger().warn(`User folders: app runs as "${ra.processUser}", signed in is "${ra.sessionUser}" – their folders are unknown, those of "${ra.processUser}" are used`);
      }
    }
    cache.res = res;
    return res;
  }

  function own(key) {
    if (key === HOME) {
      try { return getPath('home'); } catch { return os.homedir(); }
    }
    try {
      const p = getPath(key);
      if (p) return p;
    } catch { /* below */ }
    const f = FOLDERS[key];
    return f ? path.join(os.homedir(), ...f.dir.split('\\')) : os.homedir();
  }

  /** The folder `key` (downloads, documents, pictures, desktop, videos, music, appData, home) of the person signed in. */
  function userPath(key) {
    const res = resolved();
    if (res) {
      if (key === HOME) return res.profile;
      if (res.folders[key]) return res.folders[key].path;
    }
    return own(key);
  }

  /**
   * defaultPath of a dialog: the app runs as another user → that person's
   * folder (with `name` for a save dialog); else `name` alone (save: Windows
   * opens the folder used last) or undefined (open: likewise).
   */
  function dialogPath(key, name = null) {
    const n = typeof name === 'string' && name ? name : null;
    if (!resolved()) return n || undefined;
    const dir = userPath(key);
    return n ? (FULL_RE.test(dir) ? W : path).join(dir, n) : dir;
  }

  /** → { processUser, sessionUser, differs, profile, sessionProfile, downloads, downloadsSource, unreachable } */
  function info() {
    const ra = who();
    const res = resolved();
    const d = res && res.folders.downloads;
    return {
      ...ra,
      sessionProfile: res ? res.profile : null,
      downloads: userPath('downloads'),
      downloadsSource: d ? d.source : 'app',
      unreachable: d && d.unreachable ? d.unreachable : null,
    };
  }

  /** Resolves when the background check is done (tests, startup). */
  function checked() {
    resolved();
    return cache.checked || Promise.resolve();
  }

  return { userPath, dialogPath, info, checked };
}

let shared = null;
const sharedFolders = () => shared || (shared = createUserFolders());

/** The folder `key` of the person signed in — use instead of app.getPath(key). */
function userPath(key) { return sharedFolders().userPath(key); }
/** defaultPath of a save / open dialog (see createUserFolders). */
function dialogPath(key, name) { return sharedFolders().dialogPath(key, name); }
/** Who runs the app and whose folders are used (system:run-as). */
function userFolders() { return sharedFolders().info(); }

module.exports = {
  userPath, dialogPath, userFolders, createUserFolders, resolveFolders, expandVars, sidToString, loadWinApi,
  FOLDERS, HKEY_LOCAL_MACHINE, HKEY_USERS,
};
