'use strict';

/**
 * IPC of "Vault" (opt-in: registerBaseHandlers(…, { vault })).
 * Arguments from the renderer are checked here and again in VaultService.
 * Every handler resolves (except vault:status, which answers status()):
 * success { ok: true, … }, failure { ok: false, code, error, status }.
 * Every call except vault:status counts as activity (auto-lock starts again).
 *
 * Secrets reach the renderer only on explicit request: vault:entry (detail),
 * vault:history, vault:copy (main writes the clipboard). Lists carry titles,
 * user names and metadata.
 *
 *   vault:status           () → status()
 *   vault:check            () → { ok, status }
 *   vault:setup            ({ password, personalName? }) → { ok, recoveryKey }   (nothing sent yet)
 *   vault:setup:confirm    () → { ok, status }                                  (POST account, unlocked)
 *   vault:setup:cancel     () → { ok }
 *   vault:unlock           ({ password }) → { ok, status }
 *   vault:unlockRemembered () → { ok, status }
 *   vault:unlockHello      () → { ok, status }                                  (Windows Hello prompt; codes hello_off,
 *                          hello_blocked, hello_cancelled, hello_locked, hello_unavailable, hello_failed, hello_invalid)
 *   vault:hello:check      () → { ok, available, reason }                       (asks Windows again, no prompt)
 *   vault:hello:set        ({ on: true, password } | { on: false }) → { ok, …settings }   (on: unlocked, then the prompt)
 *   vault:lock             () → { ok, status }
 *   vault:recover          ({ recoveryKey }) → { ok, status }                   (then completeRecovery)
 *   vault:completeRecovery ({ password }) → { ok, recoveryKey }
 *   vault:changePassword   ({ current, password }) → { ok, status }
 *   vault:deleteAccount    ({ confirm: 'DELETE' }) → { ok, status }
 *   vault:sync             () → { ok, sync: { state, code } } | { ok: false, code } (offline / error)
 *   vault:entries          ({ vaultId?, trash? }) → { ok, entries: [summary], vaults: [view], unreadable }
 *   vault:entry            ({ id, emergencyId? }) → { ok, entry: { …summary, data } }
 *   vault:match            ({ domain? , app? }) → { ok, entries: [summary] }   (same site / app, favourites first)
 *   vault:save             ({ id?, vaultId, data }) → { ok, id }
 *   vault:trash / vault:restore / vault:purge ({ id }) → { ok }
 *   vault:history          ({ id }) → { ok, history: [{ rev, updatedAt, updatedBy, device, data }] }
 *   vault:vaults           () → { ok, vaults: [view] }
 *   vault:createVault      ({ name }) → { ok, vault }
 *   vault:renameVault      ({ id, name }) → { ok, vault }
 *   vault:deleteVault      ({ id }) → { ok }
 *   vault:people           () → { ok, people: [{ id, name, hasVault, safetyNumber }] }
 *   vault:addMember        ({ vaultId, userId, role }) → { ok, vault }
 *   vault:setRole          ({ vaultId, userId, role }) → { ok, vault }
 *   vault:removeMember     ({ vaultId, userId }) → { ok, vault }   (vault null after leaving)
 *   vault:emergency        () → { ok, granted, received }
 *   vault:emergencyAdd     ({ userId, waitHours }) → { ok, emergency }
 *   vault:emergencyRemove  ({ id }) → { ok }
 *   vault:emergencyStep    ({ id, step: 'request'|'deny'|'approve' }) → { ok, emergency }
 *   vault:emergencyOpen    ({ id }) → { ok, grantor, vaults, entries }
 *   vault:import:parse     ({ text, vaultId? }) → { ok, source, counts, duplicates, preview }
 *   vault:import:save      ({ vaultId, skipDuplicates? }) → { ok, saved, skipped }
 *   vault:generate         ({ words?, length?, upper?, digits?, symbols?, avoidAmbiguous?, wordCount? }) → { ok, password, strength, bits }
 *   vault:strength         ({ password }) → { ok, strength, bits, good, words }
 *   vault:totp             ({ id, emergencyId? } | { uri }) → { ok, code, secondsLeft, period, digits }
 *   vault:settings:get     () → { ok, autoLockMinutes, choices, remember, rememberAvailable, hello, helloAvailable,
 *                          helloReason, helloBlocked }
 *   vault:settings:set     ({ autoLockMinutes?, remember? }) → same
 *   vault:copy             ({ id, field, emergencyId? } | { text }) → { ok, clearsInMs }
 *   vault:wifi-scan        () → { ok, networks: [{ ssid, security, signal, connected }] }   (unlocked; Windows, takes ~4 s;
 *                          codes no_adapter, service_off, radio_off, location_denied, failed)
 *   vault:totp-qr          ({ source: 'screen'|'clipboard'|'file' }) → { ok, uris: ['otpauth://totp/…'] }   (unlocked;
 *                          codes none_found, hotp, invalid_code, no_image, unsupported, cancelled, failed)
 *   vault:wifi-shares      ({ id }) → { ok, shares: [{ id, target, expiresAt, createdBy, canEnd, current }], targets: { wall, portal } }
 *                          (a Wi-Fi entry's running shares — never the password; current: false → offer "Aktualisieren")
 *   vault:wifi-share       ({ id, target: 'wall'|'portal', duration: '5m'|'1h'|'24h'|'forever'|'keep' }) → { ok, share }
 *                          (main decrypts the entry and sends the copy; codes forbidden, conflict, no_wall, unavailable,
 *                          limit, rate_limited)
 *   vault:wifi-share-end   ({ shareId }) → { ok }
 *   vault:wifi-qr          ({ id, emergencyId? }) → { ok, image: 'data:image/svg+xml;base64,…', ssid, hidden }
 *                          (the Wi-Fi QR code as a picture built in main — never its text, which holds the password)
 *   vault:touch            () → { ok }
 *   vault:notices:clear    () → { ok }
 *
 * Events to the main window: vault:state (status()), vault:push (context of
 * a Vault push message: { topic, event, vaultId, emergencyId, page, notificationId }).
 */

const vault = require('../utils/vault');

const VAULT_EVENTS = {
  state: 'vault:state',
  push: 'vault:push',
};

const MAX_SECRET = 1024;              // passwords, recovery key
const MAX_IMPORT = 20 * 1024 * 1024;  // text of an export file
const QR_SOURCES = ['screen', 'clipboard', 'file'];

function fail(err) {
  return { ok: false, code: (err && err.code) || 'failed', error: (err && err.message) || 'failed', status: (err && err.status) || null };
}

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const secret = (v) => typeof v === 'string' && v.length > 0 && v.length <= MAX_SECRET;
const name = (v) => typeof v === 'string' && v.trim().length > 0 && v.length <= 200;
const userId = (v) => Number.isSafeInteger(v) && v > 0;
const emergencyId = (v) => typeof v === 'string' && vault.EMERGENCY_ID_RE.test(v);
const optEmergency = (v) => v === undefined || v === null || emergencyId(v);

/**
 * @param {Function} handle - registerBaseHandlers' handle(channel, fn)
 * @param {object} deps
 * @param {object} deps.vault - VaultService
 * @param {Function} deps.getMainWindow
 * @param {object} deps.log
 */
function registerVaultHandlers(handle, { vault: s, getMainWindow, log }) {
  const invalid = () => ({ ok: false, code: 'invalid', error: 'invalid argument', status: null });
  // Only what a person does counts as activity for the auto-lock: the page's own refreshes (lists after
  // vault:state, the 2FA countdown, background syncs) go through `passive` and never keep the vault open.
  const wrap = (fn, { passive = false } = {}) => async (_e, arg) => {
    try {
      if (!passive) s.touch();
      const r = await fn(obj(arg));
      return r && r.ok === false ? r : { ok: true, ...(r || {}) };
    } catch (err) {
      return fail(err);
    }
  };
  const withStatus = (fn, opts) => wrap(async (a) => { const r = await fn(a); if (r && r.ok === false) return r; return { status: s.status() }; }, opts);
  const passive = { passive: true };

  handle('vault:status', () => s.status());
  handle('vault:check', withStatus(() => s.check(), passive));

  handle('vault:setup', wrap(async (a) => {
    if (!secret(a.password) || (a.personalName != null && !name(a.personalName))) return invalid();
    return s.setup({ password: a.password, personalName: a.personalName || null });
  }));
  handle('vault:setup:confirm', withStatus(() => s.confirmSetup()));
  handle('vault:setup:cancel', wrap(async () => { s.cancelSetup(); }));
  handle('vault:unlock', withStatus(async (a) => (secret(a.password) ? s.unlock({ password: a.password }) : invalid())));
  handle('vault:unlockRemembered', withStatus(() => s.unlockRemembered()));
  handle('vault:unlockHello', withStatus(() => s.unlockHello()));
  handle('vault:hello:check', wrap(() => s.checkHello(), passive));
  handle('vault:hello:set', wrap(async (a) => {
    if (a.on === false) return s.setHello({ on: false });
    if (a.on !== true || !secret(a.password)) return invalid();
    return s.setHello({ on: true, password: a.password });
  }));
  handle('vault:lock', withStatus(async () => s.lock('manual')));
  handle('vault:recover', withStatus(async (a) => (typeof a.recoveryKey === 'string' && a.recoveryKey.length <= 200 ? s.recover({ recoveryKey: a.recoveryKey }) : invalid())));
  handle('vault:completeRecovery', wrap(async (a) => (secret(a.password) ? s.completeRecovery({ password: a.password }) : invalid())));
  handle('vault:changePassword', withStatus(async (a) => (secret(a.current) && secret(a.password) ? s.changePassword({ current: a.current, password: a.password }) : invalid())));
  handle('vault:deleteAccount', withStatus(async (a) => (a.confirm === 'DELETE' ? s.deleteAccount({ confirm: 'DELETE' }) : invalid())));
  handle('vault:sync', wrap(async () => {
    const r = await s.sync();
    return r.state === 'done' ? { sync: r } : { ok: false, code: r.code || r.state, error: r.state, status: null };
  }, passive));

  // entries
  handle('vault:entries', wrap(async (a) => {
    if (a.vaultId != null && !vault.isId(a.vaultId)) return invalid();
    return s.entries({ vaultId: a.vaultId || null, trash: a.trash === true });
  }, passive));
  handle('vault:entry', wrap(async (a) => {
    if (!vault.isId(a.id) || !optEmergency(a.emergencyId)) return invalid();
    return { entry: await s.entry(a.id, { emergencyId: a.emergencyId || null }) };
  }));
  handle('vault:match', wrap(async (a) => {
    const ok = (x) => x === undefined || x === null || (typeof x === 'string' && x.length <= 2048);
    if (!ok(a.domain) || !ok(a.app)) return invalid();
    return { entries: await s.match({ domain: a.domain || null, app: a.app || null }) };
  }));
  handle('vault:save', wrap(async (a) => {
    if ((a.id != null && !vault.isId(a.id)) || !vault.isId(a.vaultId) || !vault.normalizeEntry(a.data)) return invalid();
    return s.save({ id: a.id || null, vaultId: a.vaultId, data: a.data });
  }));
  for (const op of ['trash', 'restore', 'purge']) {
    handle(`vault:${op}`, wrap(async (a) => (vault.isId(a.id) ? s[op](a.id) : invalid())));
  }
  handle('vault:history', wrap(async (a) => (vault.isId(a.id) ? { history: await s.history(a.id) } : invalid())));

  // vaults and members
  handle('vault:vaults', wrap(() => s.vaults(), passive));
  handle('vault:createVault', wrap(async (a) => (name(a.name) ? { vault: await s.createVault(a.name) } : invalid())));
  handle('vault:renameVault', wrap(async (a) => (vault.isId(a.id) && name(a.name) ? { vault: await s.renameVault(a.id, a.name) } : invalid())));
  handle('vault:deleteVault', wrap(async (a) => (vault.isId(a.id) ? s.deleteVault(a.id) : invalid())));
  handle('vault:people', wrap(async () => ({ people: await s.people() }), passive));
  handle('vault:addMember', wrap(async (a) => (vault.isId(a.vaultId) && userId(a.userId) && vault.ROLES.includes(a.role)
    ? { vault: await s.addMember(a.vaultId, a.userId, a.role) } : invalid())));
  handle('vault:setRole', wrap(async (a) => (vault.isId(a.vaultId) && userId(a.userId) && vault.ROLES.includes(a.role)
    ? { vault: await s.setRole(a.vaultId, a.userId, a.role) } : invalid())));
  handle('vault:removeMember', wrap(async (a) => (vault.isId(a.vaultId) && userId(a.userId) ? { vault: await s.removeMember(a.vaultId, a.userId) } : invalid())));

  // emergency access
  handle('vault:emergency', wrap(() => s.emergency(), passive));
  handle('vault:emergencyAdd', wrap(async (a) => (userId(a.userId) && Number.isSafeInteger(a.waitHours) && a.waitHours >= 1 && a.waitHours <= 720
    ? { emergency: await s.emergencyAdd(a.userId, a.waitHours) } : invalid())));
  handle('vault:emergencyRemove', wrap(async (a) => (emergencyId(a.id) ? s.emergencyRemove(a.id) : invalid())));
  handle('vault:emergencyStep', wrap(async (a) => (emergencyId(a.id) && vault.EMERGENCY_STEPS.includes(a.step)
    ? { emergency: await s.emergencyStep(a.id, a.step) } : invalid())));
  handle('vault:emergencyOpen', wrap(async (a) => (emergencyId(a.id) ? s.emergencyOpen(a.id) : invalid())));

  // import
  handle('vault:import:parse', wrap(async (a) => {
    if (typeof a.text !== 'string' || !a.text || a.text.length > MAX_IMPORT || (a.vaultId != null && !vault.isId(a.vaultId))) return invalid();
    return s.importParse(a.text, { vaultId: a.vaultId || null });
  }));
  handle('vault:import:save', wrap(async (a) => (vault.isId(a.vaultId) ? s.importSave(a.vaultId, { skipDuplicates: a.skipDuplicates !== false }) : invalid())));

  // generator, codes, clipboard, settings
  handle('vault:generate', wrap(async (a) => s.generate(a)));
  handle('vault:strength', wrap(async (a) => (typeof a.password === 'string' && a.password.length <= MAX_SECRET ? s.strength(a.password) : invalid())));
  handle('vault:totp', wrap(async (a) => {
    if (a.id != null) return vault.isId(a.id) && optEmergency(a.emergencyId) ? s.totp({ id: a.id, emergencyId: a.emergencyId || null }) : invalid();
    return typeof a.uri === 'string' && a.uri.length <= 2048 ? s.totp({ uri: a.uri }) : invalid();
  }, passive));
  handle('vault:copy', wrap(async (a) => {
    if (a.id != null) {
      return vault.isId(a.id) && typeof a.field === 'string' && a.field.length <= 64 && optEmergency(a.emergencyId)
        ? s.copy({ id: a.id, field: a.field, emergencyId: a.emergencyId || null }) : invalid();
    }
    return typeof a.text === 'string' && a.text.length <= 4096 ? s.copy({ text: a.text }) : invalid();
  }));
  handle('vault:settings:get', wrap(async () => s.settings(), passive));
  handle('vault:settings:set', wrap(async (a) => {
    const patch = {};
    if (a.autoLockMinutes !== undefined) {
      if (!vault.AUTO_LOCK_CHOICES.includes(a.autoLockMinutes)) return invalid();
      patch.autoLockMinutes = a.autoLockMinutes;
    }
    if (a.remember !== undefined) {
      if (typeof a.remember !== 'boolean') return invalid();
      patch.remember = a.remember;
    }
    return s.setSettings(patch);
  }));
  // Wi-Fi networks nearby for a Wi-Fi entry: the person asked for it (activity), needs the vault unlocked
  handle('vault:wifi-scan', wrap(() => s.wifiScan()));
  // Wi-Fi shares (plugin 1.4.0): the renderer names the entry, main builds the copy from the decrypted entry
  handle('vault:wifi-shares', wrap(async (a) => (vault.isId(a.id) ? s.wifiShares(a.id) : invalid()), passive));
  handle('vault:wifi-share', wrap(async (a) => (vault.isId(a.id) && vault.SHARE_TARGETS.includes(a.target)
    && (vault.SHARE_DURATIONS.includes(a.duration) || a.duration === 'keep') ? s.wifiShare(a.id, a.target, a.duration) : invalid())));
  handle('vault:wifi-qr', wrap(async (a) => (vault.isId(a.id) && optEmergency(a.emergencyId) ? s.wifiQr(a.id, { emergencyId: a.emergencyId || null }) : invalid()), passive));
  handle('vault:wifi-share-end', wrap(async (a) => (emergencyId(a.shareId) ? s.wifiShareEnd(a.shareId) : invalid())));
  // 2FA key from a QR code (screen, clipboard image, image file): activity, needs the vault unlocked
  handle('vault:totp-qr', wrap(async (a) => (QR_SOURCES.includes(a.source)
    ? s.totpQr({ source: a.source, getWindow: getMainWindow }) : invalid())));
  handle('vault:touch', wrap(async () => {}));
  handle('vault:notices:clear', wrap(async () => { s.clearNotices(); }));

  const send = (channel, payload) => {
    const win = getMainWindow && getMainWindow();
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed()) || !win.webContents) return;
    try { win.webContents.send(channel, payload); } catch (err) { log.debug(`${channel} not delivered: ${err.message}`); }
  };
  for (const [event, channel] of Object.entries(VAULT_EVENTS)) s.on(event, (payload) => send(channel, payload));
}

module.exports = { registerVaultHandlers, VAULT_EVENTS };
