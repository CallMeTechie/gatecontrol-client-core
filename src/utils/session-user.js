'use strict';

/**
 * Who runs the app, who is signed in to Windows.
 *
 * The apps need administrator rights (requireAdministrator). A person without
 * them types the password of another (admin) account at the UAC prompt: the
 * app then runs as that other Windows user. Its Downloads, %APPDATA% and
 * %TEMP% are the other user's — GateDrop's received files, the log file and
 * Drive's opened files land in C:\Users\<other>\…, the Explorer of the person
 * signed in cannot show them, and Windows refuses the toasts (E_ACCESSDENIED).
 * runAs() finds that out, so the app can say where the files are and why.
 *
 *   runAs() → { processUser, sessionUser, differs, profile } (sessionUser null: unknown)
 */

const os = require('os');

const WTS_CURRENT_SERVER_HANDLE = null;
const WTS_CURRENT_SESSION = 0xffffffff;
const WTS_USER_NAME = 5;
const WTS_DOMAIN_NAME = 7;

let wts;

/** wtsapi32 through koffi (Windows only), loaded once; null when it cannot be. */
function loadWts(koffi) {
  if (wts !== undefined) return wts;
  try {
    const k = koffi || require('koffi');
    const lib = k.load('wtsapi32.dll');
    wts = {
      k,
      query: lib.func('bool __stdcall WTSQuerySessionInformationW(void *hServer, uint32_t SessionId, int WTSInfoClass, _Out_ void **ppBuffer, _Out_ uint32_t *pBytesReturned)'),
      free: lib.func('void __stdcall WTSFreeMemory(void *pMemory)'),
    };
  } catch {
    wts = null;
  }
  return wts;
}

/** One string of this process's Windows session (WTS_INFO_CLASS `cls`), or null. */
function sessionString(cls, { koffi = null } = {}) {
  const w = loadWts(koffi);
  if (!w) return null;
  const buf = [null];
  const len = [0];
  try {
    if (!w.query(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, cls, buf, len) || !buf[0]) return null;
    const n = Math.min(len[0], 1024);
    const bytes = n > 0 ? Buffer.from(w.k.decode(buf[0], 'uint8_t', n)) : Buffer.alloc(0);
    const name = bytes.toString('utf16le').replace(/\0[\s\S]*$/, '').trim();
    return name || null;
  } catch {
    return null;
  } finally {
    if (buf[0]) { try { w.free(buf[0]); } catch { /* freed */ } }
  }
}

/** The user name of this process's Windows session (the person signed in), or null. */
function sessionUserName(o = {}) {
  return sessionString(WTS_USER_NAME, o);
}

/**
 * The account of the person signed in → { user, domain } (domain: the
 * computer's name for a local account), or null when it is not known.
 */
function sessionAccount(o = {}) {
  const user = sessionString(WTS_USER_NAME, o);
  if (!user) return null;
  return { user, domain: sessionString(WTS_DOMAIN_NAME, o) || null };
}

/**
 * → { processUser, sessionUser, differs, profile }. `differs`: the app runs as
 * another Windows user than the one signed in (only known on Windows).
 * @param {object} [o]
 * @param {string} [o.platform=process.platform]
 * @param {() => string|null} [o.getSessionUser] - tests
 * @param {() => { username: string, homedir: string }} [o.userInfo] - tests
 */
function runAs({ platform = process.platform, getSessionUser = null, userInfo = null } = {}) {
  let info = null;
  try { info = userInfo ? userInfo() : os.userInfo(); } catch { info = null; }
  const processUser = info && info.username ? String(info.username) : null;
  const profile = info && info.homedir ? String(info.homedir) : null;
  let sessionUser = null;
  if (platform === 'win32' || getSessionUser) {
    try { sessionUser = getSessionUser ? getSessionUser() : sessionUserName(); } catch { sessionUser = null; }
  }
  const differs = !!(processUser && sessionUser && processUser.toLowerCase() !== String(sessionUser).toLowerCase());
  return { processUser, sessionUser: sessionUser || null, differs, profile };
}

module.exports = { runAs, sessionUserName, sessionAccount };
