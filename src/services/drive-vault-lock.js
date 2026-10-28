'use strict';

/**
 * GateControl – Drive: the lock of the vault folders (Core, Drive 1.11 "Tresor-Sperre")
 *
 * Like OneDrive's Personal Vault: the keys of the vault folders (services/drive-vault.js) are only unwrapped with this
 * PC's device key after a confirmation with Windows Hello (face, fingerprint or the Windows Hello PIN;
 * services/windows-hello.js createConsentVerifier — UserConsentVerifier over WinRT, no new native dependency), and
 * the vaults lock again
 *   - after a time without use (default 3 minutes; 1 / 3 / 5 / 15 minutes or never),
 *   - when the window is minimized or closed into the tray ("Beim Verlassen sperren", on by default),
 *   - always when Windows locks the session or goes to sleep (powerMonitor 'lock-screen' / 'suspend'),
 *   - on a server change and when the app ends.
 * Locking is the event 'lock' { reason }: DriveService then wipes the vault keys, forgets the decrypted names and
 * removes the decrypted copies (services/drive.js _onVaultLock).
 *
 * "Mit Windows Hello öffnen" can be switched off (then only the device key under DPAPI protects the vaults, the page
 * warns); switching it off needs a Windows Hello confirmation itself while Hello is set up. Without Windows Hello
 * (not set up, a remote desktop, no provider) the vaults cannot be unlocked while the switch is on — the page says
 * why and offers Windows' sign-in options. A confirmation with the Windows password instead of Hello is not offered
 * (it would mean reading the password into this process and checking it with LogonUser).
 * Without a `consent` option at all (an app that does not wire Windows Hello) the vaults behave as before Drive 1.11:
 * no confirmation, nothing enforced (status().enforced false); the timers still wipe the keys.
 *
 * Settings live on this PC only (store key `driveVaultLock`): { hello, autoLockMinutes, lockOnLeave }.
 */

const EventEmitter = require('events');
const MessengerApi = require('./messenger-api');

const { MessengerError: DriveError } = MessengerApi;

const STORE_KEY = 'driveVaultLock';
const AUTO_LOCK_CHOICES = Object.freeze([1, 3, 5, 15, 0]);   // minutes; 0 = never
const DEFAULT_SETTINGS = Object.freeze({ hello: true, autoLockMinutes: 3, lockOnLeave: true });
const DEFAULT_TIMING = { minuteMs: 60 * 1000 };
const REASONS = Object.freeze(['manual', 'timeout', 'hidden', 'system', 'server', 'stop', 'settings']);

// what the confirmation answered → the code the page shows
const HELLO_CODES = {
  cancelled: 'hello_cancelled',
  retries_exhausted: 'hello_retries',
  device_busy: 'hello_busy',
  not_set_up: 'hello_not_set_up',
  device_not_present: 'hello_not_set_up',
  disabled_by_policy: 'hello_policy',
  unavailable: 'hello_unavailable',
  unsupported_os: 'hello_unavailable',
  remote_session: 'hello_unavailable',
};

function noopLog() { return { info() {}, warn() {}, debug() {}, error() {} }; }

/** Settings from the store, every field checked → { hello, autoLockMinutes, lockOnLeave } */
function cleanSettings(v) {
  const o = v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  return {
    hello: typeof o.hello === 'boolean' ? o.hello : DEFAULT_SETTINGS.hello,
    autoLockMinutes: AUTO_LOCK_CHOICES.includes(o.autoLockMinutes) ? o.autoLockMinutes : DEFAULT_SETTINGS.autoLockMinutes,
    lockOnLeave: typeof o.lockOnLeave === 'boolean' ? o.lockOnLeave : DEFAULT_SETTINGS.lockOnLeave,
  };
}

class DriveVaultLock extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object|null} [opts.consent] - createConsentVerifier() (Windows Hello); null: no confirmation possible here;
   *   undefined: not wired (nothing enforced)
   * @param {object} [opts.store] - electron-store (the settings)
   * @param {object} [opts.powerMonitor] - Electron powerMonitor: locks on 'lock-screen' / 'suspend'
   * @param {() => any} [opts.getWindow] - the owner window of the dialog (BrowserWindow.getNativeWindowHandle())
   * @param {() => string} [opts.getLang] - 'de' | 'en' (the dialog's text)
   * @param {() => boolean} [opts.busy] - vault transfers running: the time without use waits for them
   * @param {object} [opts.timing] - { minuteMs }
   * @param {object} [opts.log]
   */
  constructor({ consent, store = null, powerMonitor = null, getWindow = null, getLang = null, busy = null, timing = {}, log = null } = {}) {
    super();
    this.enforced = consent !== undefined;
    this.consent = consent || null;
    this.store = store;
    this.powerMonitor = powerMonitor;
    this.getWindow = typeof getWindow === 'function' ? getWindow : () => null;
    this.getLang = typeof getLang === 'function' ? getLang : () => 'de';
    this.busy = typeof busy === 'function' ? busy : () => false;
    this.timing = { ...DEFAULT_TIMING, ...timing };
    this.log = log || noopLog();
    this._unlocked = false;
    this._timer = null;
    this._unsub = [];
    this._unlocking = null;
    this._lastLock = null;
  }

  start() {
    const pm = this.powerMonitor;
    if (pm && typeof pm.on === 'function' && !this._unsub.length) {
      const onSystem = () => this.lock('system');
      for (const ev of ['lock-screen', 'suspend']) {
        pm.on(ev, onSystem);
        this._unsub.push(() => pm.removeListener(ev, onSystem));
      }
    }
  }

  stop() {
    for (const off of this._unsub.splice(0)) { try { off(); } catch { /* gone */ } }
    this.lock('stop');
  }

  // ── settings ─────────────────────────────────────────────

  settings() {
    let v = null;
    try { v = this.store && this.store.get(STORE_KEY); } catch { v = null; }
    return cleanSettings(v);
  }

  _save(next) {
    try { if (this.store) this.store.set(STORE_KEY, next); } catch (err) { this.log.warn(`Drive vault lock: settings not stored: ${err.message}`); }
  }

  /** Is a confirmation with Windows Hello possible here → { available, reason } (no prompt). */
  async hello() {
    if (!this.consent || typeof this.consent.available !== 'function') return { available: false, reason: 'unsupported_os' };
    try {
      const a = await this.consent.available();
      return { available: !!(a && a.available), reason: a && a.available ? null : ((a && a.reason) || 'error') };
    } catch {
      return { available: false, reason: 'error' };
    }
  }

  /**
   * { autoLockMinutes?, lockOnLeave?, hello? } → status(). Switching "Mit Windows Hello öffnen" off asks Windows
   * Hello first (while it is set up here); a refused confirmation keeps it on ('hello_cancelled' …).
   */
  async setSettings(patch = {}) {
    const p = patch && typeof patch === 'object' ? patch : {};
    const cur = this.settings();
    const next = { ...cur };
    if (p.autoLockMinutes !== undefined) {
      if (!AUTO_LOCK_CHOICES.includes(p.autoLockMinutes)) throw new DriveError('invalid auto-lock', { code: 'invalid' });
      next.autoLockMinutes = p.autoLockMinutes;
    }
    if (p.lockOnLeave !== undefined) {
      if (typeof p.lockOnLeave !== 'boolean') throw new DriveError('invalid', { code: 'invalid' });
      next.lockOnLeave = p.lockOnLeave;
    }
    if (p.hello !== undefined) {
      if (typeof p.hello !== 'boolean') throw new DriveError('invalid', { code: 'invalid' });
      if (cur.hello && !p.hello) {
        const h = await this.hello();
        if (h.available) {
          const r = await this._confirm('settings');
          if (r.status !== 'verified') throw new DriveError('not confirmed', { code: HELLO_CODES[r.status] || 'hello_failed' });
        }
      }
      next.hello = p.hello;
    }
    this._save(next);
    // switched on again: what was opened without it closes
    if (!cur.hello && next.hello) this.lock('settings');
    else this.touch();
    return this.status();
  }

  // ── state ────────────────────────────────────────────────

  /** May vault keys be unwrapped now? */
  isUnlocked() {
    return this._unlocked || !this.enforced;
  }

  /** { enforced, unlocked, settings, hello: { available, reason }, choices, lastLock } */
  async status() {
    return { enforced: this.enforced, unlocked: this.isUnlocked(), settings: this.settings(), hello: await this.hello(), choices: [...AUTO_LOCK_CHOICES], lastLock: this._lastLock };
  }

  _message(why) {
    const de = this.getLang() !== 'en';
    if (why === 'settings') return de ? 'GateControl Drive: Tresore ohne Windows Hello öffnen' : 'GateControl Drive: open vaults without Windows Hello';
    return de ? 'GateControl Drive: Tresore entsperren' : 'GateControl Drive: unlock vaults';
  }

  async _confirm(why) {
    let win = null;
    try { win = this.getWindow(); } catch { win = null; }
    try {
      return (await this.consent.verify(this._message(why), { window: win })) || { status: 'failed' };
    } catch (err) {
      this.log.warn(`Drive vault lock: confirmation failed: ${err.message}`);
      return { status: 'failed' };
    }
  }

  /**
   * Unlocks the vaults of this PC → { unlocked: true } or throws DriveError 'hello_cancelled' | 'hello_not_set_up' |
   * 'hello_unavailable' | 'hello_policy' | 'hello_busy' | 'hello_retries' | 'hello_failed' (the reason: { hello }).
   */
  async unlock() {
    if (this._unlocked) { this.touch(); return { unlocked: true, confirmed: false }; }
    if (this._unlocking) return this._unlocking;
    this._unlocking = (async () => {
      const s = this.settings();
      if (!s.hello || !this.enforced) {
        this._open();
        return { unlocked: true, confirmed: false };
      }
      const h = await this.hello();
      if (!h.available) throw new DriveError('Windows Hello is not available', { code: HELLO_CODES[h.reason] || 'hello_unavailable' });
      const r = await this._confirm('unlock');
      if (r.status !== 'verified') throw new DriveError('not confirmed', { code: HELLO_CODES[r.status] || 'hello_failed' });
      this._open();
      this.log.info('Drive vaults unlocked (Windows Hello)');
      return { unlocked: true, confirmed: true };
    })().finally(() => { this._unlocking = null; });
    return this._unlocking;
  }

  _open() {
    this._unlocked = true;
    this._lastLock = null;
    this.touch();
    this.emit('unlock');
  }

  /** Use of a vault: the time without use starts again. */
  touch() {
    clearTimeout(this._timer);
    this._timer = null;
    const m = this.settings().autoLockMinutes;
    if (!this._unlocked || !(m > 0)) return;
    const arm = (ms) => {
      this._timer = setTimeout(() => {
        // a vault upload / download still running waits (it is use, too)
        if (this.busy()) { arm(Math.min(ms, this.timing.minuteMs)); return; }
        this.lock('timeout');
      }, ms);
      if (this._timer.unref) this._timer.unref();
    };
    arm(m * this.timing.minuteMs);
  }

  /** The window was minimized / hidden into the tray: "Beim Verlassen sperren" locks now. */
  windowHidden() {
    if (this._unlocked && this.settings().lockOnLeave) this.lock('hidden');
  }

  /** Locks (also when locked already: what an unlock without Hello left behind goes, too). */
  lock(reason = 'manual') {
    clearTimeout(this._timer);
    this._timer = null;
    const was = this._unlocked;
    this._unlocked = false;
    const r = REASONS.includes(reason) ? reason : 'manual';
    if (was) {
      this._lastLock = { reason: r, at: Date.now() };
      this.log.info(`Drive vaults locked (${r})`);
    }
    this.emit('lock', { reason: r, was });
  }
}

DriveVaultLock.STORE_KEY = STORE_KEY;
DriveVaultLock.AUTO_LOCK_CHOICES = AUTO_LOCK_CHOICES;
DriveVaultLock.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
DriveVaultLock.cleanSettings = cleanSettings;

module.exports = DriveVaultLock;
