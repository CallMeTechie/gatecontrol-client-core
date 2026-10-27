'use strict';

/**
 * Renderer bridge shared by the Pro and Community preload scripts.
 *
 * createBridgeApi() builds the `window.gatecontrol` object with every channel
 * both editions expose; the app preload adds its edition-specific parts
 * (e.g. Pro: rdp.*, dns.checkSystem; Community: window.toggleMaximize) and
 * hands the result to contextBridge.exposeInMainWorld('gatecontrol', api).
 *
 * Electron-free: ipcRenderer and the i18n module are passed in, so the
 * channel list can be unit-tested with a fake ipcRenderer.
 *
 * @param {Electron.IpcRenderer} ipcRenderer
 * @param {object} i18n - core i18n module (t, setLocale, getLocale, …)
 * @param {object} [opts]
 * @param {string} [opts.updateReadyChannel='update-ready'] - event channel the
 *   main process uses to announce a downloaded update (Pro: 'update:ready')
 * @param {object} [opts.webUtils] - Electron webUtils (paths of dropped files, GateDrop)
 * @returns {object} bridge API
 */
function createBridgeApi(ipcRenderer, i18n, { updateReadyChannel = 'update-ready', webUtils = null } = {}) {
  const { t, setLocale, getLocale, onLocaleChange, getSupportedLocales } = i18n;

  // Subscribe to a main → renderer event; returns an unsubscribe function.
  const subscribe = createSubscriber(ipcRenderer);

  return {
    // ── App ──────────────────────────────────────────────
    getVersion: () => ipcRenderer.invoke('app:version'),

    // ── Tunnel ───────────────────────────────────────────
    tunnel: {
      connect:    () => ipcRenderer.invoke('tunnel:connect'),
      disconnect: () => ipcRenderer.invoke('tunnel:disconnect'),
      reconnect:  () => ipcRenderer.invoke('tunnel:reconnect'),
      getStatus:  () => ipcRenderer.invoke('tunnel:status'),
      onState:    (cb) => subscribe('tunnel-state', cb),
    },

    // ── Server ───────────────────────────────────────────
    server: {
      setup: (opts) => ipcRenderer.invoke('server:setup', opts),
      test:  (opts) => ipcRenderer.invoke('server:test', opts),
    },

    // ── Company sign-in ("Mit Firmenkonto anmelden") ────────
    // methods(url) → { available, password: { enabled, hint }, microsoft: [{ id, label }] }
    // password({ url, username, password, totp? }) / microsoft({ url, id })
    //   → like server.setup: { success, peerId, enrolled } | { success: false, error, code?, totpRequired?, cancelled? }
    signin: {
      methods:   (url) => ipcRenderer.invoke('signin:methods', { url }),
      password:  ({ url, username, password, totp } = {}) => ipcRenderer.invoke('signin:password', { url, username, password, totp }),
      microsoft: ({ url, id } = {}) => ipcRenderer.invoke('signin:microsoft', { url, id }),
      cancel:    () => ipcRenderer.invoke('signin:cancel'),
    },

    // ── Config ───────────────────────────────────────────
    config: {
      get:        (key)        => ipcRenderer.invoke('config:get', key),
      set:        (key, value) => ipcRenderer.invoke('config:set', key, value),
      getAll:     ()           => ipcRenderer.invoke('config:getAll'),
      importFile: ()           => ipcRenderer.invoke('config:import-file'),
      importQR:   (imageData)  => ipcRenderer.invoke('config:import-qr', imageData),
    },

    // ── WireGuard ────────────────────────────────────────
    wireguard: {
      check: () => ipcRenderer.invoke('wireguard:check'),
    },

    // ── Kill-Switch ──────────────────────────────────────
    killSwitch: {
      toggle: (enabled) => ipcRenderer.invoke('killswitch:toggle', enabled),
    },

    // ── RDP Allow ────────────────────────────────────────
    rdpAllow: {
      toggle: (enabled) => ipcRenderer.invoke('rdp-allow:toggle', enabled),
    },

    // ── Autostart ────────────────────────────────────────
    autostart: {
      set: (enabled) => ipcRenderer.invoke('autostart:set', enabled),
    },

    // ── Logs ─────────────────────────────────────────────
    logs: {
      get: (opts) => ipcRenderer.invoke('logs:get', opts),
      export: () => ipcRenderer.invoke('logs:export'),
      show: () => ipcRenderer.invoke('logs:show'),
    },

    // ── Support bundle ───────────────────────────────────
    // → { success, id } | { success: false, cancelled } | { success: false, error }
    support: {
      send: () => ipcRenderer.invoke('support:send'),
    },

    // ── Peer ─────────────────────────────────────────────
    peer: {
      onExpiry: (cb) => subscribe('peer-expiry', cb),
    },

    // ── Permissions ──────────────────────────────────────
    permissions: {
      get: () => ipcRenderer.invoke('permissions:get'),
    },

    // ── Traffic ──────────────────────────────────────────
    traffic: {
      stats: () => ipcRenderer.invoke('traffic:stats'),
    },

    // ── Services ─────────────────────────────────────────
    services: {
      list: () => ipcRenderer.invoke('services:list'),
    },

    // ── DNS ──────────────────────────────────────────────
    dns: {
      leakTest: () => ipcRenderer.invoke('dns:leak-test'),
    },

    // ── Update ───────────────────────────────────────────
    update: {
      check:   () => ipcRenderer.invoke('update:check'),
      install: () => ipcRenderer.invoke('update:install'),
      onReady: (cb) => subscribe(updateReadyChannel, cb),
      // { channel, minVersion, belowMinimum, mandatory, updateReady, version }
      policy:   () => ipcRenderer.invoke('update:policy'),
      onPolicy: (cb) => subscribe('update:policy', cb),
    },

    // ── Client-Richtlinie (vom Server) ───────────────────
    // State: { fetched, version, managed, policy, locks, splitModes }
    policy: {
      get:      () => ipcRenderer.invoke('policy:get'),
      refresh:  () => ipcRenderer.invoke('policy:refresh'),
      onChange: (cb) => subscribe('policy:changed', cb),
    },

    // ── Benachrichtigungen (notification center) ─────────
    // Served when the app passes a NotificationCenter to registerBaseHandlers.
    notify: {
      // { filter: 'all'|'unread'|<topic>, limit, before, refresh } → { items, unread, topics }
      list:     (opts) => ipcRenderer.invoke('notify:list', opts),
      // ids (notification ids) or 'all' → { ok, updated, unread }
      read:     (ids) => ipcRenderer.invoke('notify:read', ids === 'all' ? { all: true } : { ids: Array.isArray(ids) ? ids : [ids] }),
      action:   (id, action) => ipcRenderer.invoke('notify:action', { id, action }),
      getPrefs: () => ipcRenderer.invoke('notify:prefs:get'),
      setPrefs: (patch) => ipcRenderer.invoke('notify:prefs:set', patch),
      test:     () => ipcRenderer.invoke('notify:test'),
      status:   () => ipcRenderer.invoke('notify:status'),
      // { minutes } | { until } | null (off); no argument = query
      dnd:      (...args) => ipcRenderer.invoke('notify:dnd', ...args),
      // Quiet hours of the person (read-only; set in the portal):
      // { refresh } → { ok, known, quiet: { from, to, tz, criticalBypass } | null, source, at }
      quiet:     (opts) => ipcRenderer.invoke('notify:quiet', opts),
      // "Im Portal ändern" → portal tab "Meine Benachrichtigungen" (auto-login)
      openQuietHours: () => ipcRenderer.invoke('notify:quiet:open'),
      // Where each kind of notification appears (core 1.191): GateControl,
      // the family chat or an own chat → { ok, routes } | { ok: false, error };
      // setRoute also gives `chat` (the own chat on 'own', else null)
      routes:   () => ipcRenderer.invoke('notify:routes'),
      setRoute: (topic, dest) => ipcRenderer.invoke('notify:routes:set', { topic, dest }),
      // A notice card's link (Messenger 1.6): open what a click on that
      // notification would ({ route, topic, data }) → { ok } (ok false: open the route yourself)
      open:     (target) => ipcRenderer.invoke('notify:open', target || {}),
      onNew:      (cb) => subscribe('notify:new', cb),
      onUpdate:   (cb) => subscribe('notify:update', cb),
      onStatus:   (cb) => subscribe('notify:status', cb),
      onNavigate: (cb) => subscribe('notify:navigate', cb),
    },

    // ── Chats (messenger) ────────────────────────────────
    // Served when the app passes a MessengerService to registerBaseHandlers
    // (ipc/messenger-handlers.js lists arguments and answers).
    chat: {
      status:        () => ipcRenderer.invoke('chat:status'),
      check:         () => ipcRenderer.invoke('chat:check'),
      conversations: (opts) => ipcRenderer.invoke('chat:conversations', opts),
      conversation:  (id, opts) => ipcRenderer.invoke('chat:conversation', { ...(opts || {}), id }),
      messages:      (id, opts) => ipcRenderer.invoke('chat:messages', { ...(opts || {}), id }),
      send:          (msg) => ipcRenderer.invoke('chat:send', msg),
      retry:         (clientId) => ipcRenderer.invoke('chat:outbox:retry', { clientId }),
      discard:       (clientId) => ipcRenderer.invoke('chat:outbox:discard', { clientId }),
      edit:          (id, text) => ipcRenderer.invoke('chat:edit', { id, text }),
      remove:        (id, scope) => ipcRenderer.invoke('chat:delete', { id, scope }),
      react:         (id, emoji) => ipcRenderer.invoke('chat:react', { id, emoji }),
      read:          (id, upTo) => ipcRenderer.invoke('chat:read', { id, upTo }),
      typing:        (id, stop) => ipcRenderer.invoke('chat:typing', { id, stop: stop === true }),
      open:          (id, visible) => ipcRenderer.invoke('chat:open', { id, visible: visible === true }),
      view:          (open) => ipcRenderer.invoke('chat:view', { open: open === true }),
      people:        (opts) => ipcRenderer.invoke('chat:people', opts),
      create:        (opts) => ipcRenderer.invoke('chat:create', opts),
      update:        (id, patch, avatar) => ipcRenderer.invoke('chat:update', { id, patch, avatar }),
      prefs:         (patch) => ipcRenderer.invoke('chat:prefs', patch),
      search:        (id, q) => ipcRenderer.invoke('chat:search', { id, q }),
      mediaList:     (id, opts) => ipcRenderer.invoke('chat:media:list', { ...(opts || {}), id }),
      media:         (mediaId) => ipcRenderer.invoke('chat:media', { mediaId }),
      avatar:        (url) => ipcRenderer.invoke('chat:avatar', { url }),
      saveMedia:     (mediaId, fileName) => ipcRenderer.invoke('chat:media:save', { mediaId, fileName }),
      openMedia:     (mediaId, fileName) => ipcRenderer.invoke('chat:media:open', { mediaId, fileName }),
      // Map of the location dialog / previews: OpenStreetMap tile bytes,
      // address search and the address of a point (main process, Nominatim).
      mapTile:       (z, x, y) => ipcRenderer.invoke('chat:map:tile', { z, x, y }),
      mapSearch:     (q, lang) => ipcRenderer.invoke('chat:map:search', { q, lang }),
      mapReverse:    (lat, lon, lang) => ipcRenderer.invoke('chat:map:reverse', { lat, lon, lang }),
      // status().updateHint: the server has chat functions this version lacks
      dismissUpdateHint: () => ipcRenderer.invoke('chat:update-hint:dismiss'),
      // Messenger 1.4.0 (status().me.features decides what the page shows)
      statusFeed:    (opts) => ipcRenderer.invoke('chat:status:feed', opts),
      setStatus:     (s) => ipcRenderer.invoke('chat:status:set', s),
      clearStatus:   () => ipcRenderer.invoke('chat:status:clear'),
      createStory:   (s) => ipcRenderer.invoke('chat:story:create', s),
      deleteStory:   (id) => ipcRenderer.invoke('chat:story:delete', { id }),
      storySeen:     (id) => ipcRenderer.invoke('chat:story:seen', { id }),
      storyViewers:  (id) => ipcRenderer.invoke('chat:story:viewers', { id }),
      storyReact:    (id, emoji) => ipcRenderer.invoke('chat:story:react', { id, emoji }),
      blocks:        () => ipcRenderer.invoke('chat:blocks'),
      block:         (userId, blocked) => ipcRenderer.invoke('chat:block', { userId, blocked: blocked !== false }),
      archive:       (id, archived) => ipcRenderer.invoke('chat:archive', { id, archived: archived === true }),
      pin:           (id, messageId, pinned) => ipcRenderer.invoke('chat:pin', { id, messageId, pinned: pinned !== false }),
      lists:         (opts) => ipcRenderer.invoke('chat:lists', opts),
      saveLists:     (lists) => ipcRenderer.invoke('chat:lists:save', { lists }),
      exportChat:    (id) => ipcRenderer.invoke('chat:export', { id }),
      remind:        (id, at) => ipcRenderer.invoke('chat:remind', { id, at }),
      reminders:     () => ipcRenderer.invoke('chat:reminders'),
      deleteReminder: (id) => ipcRenderer.invoke('chat:reminder:delete', { id }),
      suggest:       (id) => ipcRenderer.invoke('chat:suggest', { id }),
      toList:        (id, items, list) => ipcRenderer.invoke('chat:to-list', { id, items, list }),
      toCalendar:    (id, ev) => ipcRenderer.invoke('chat:to-calendar', { ...(ev || {}), id }),
      // Messenger 1.10: the file of a message into Drive (folderId: a folder picked, else Meine Dateien › Messenger)
      toDrive:       (id, folderId) => ipcRenderer.invoke('chat:to-drive', { id, folderId: folderId || null }),
      places:        () => ipcRenderer.invoke('chat:places'),
      poll:          (id, op, args) => ipcRenderer.invoke('chat:poll', { ...(args || {}), id, op }),
      event:         (id, op, args) => ipcRenderer.invoke('chat:event', { ...(args || {}), id, op }),
      stopArrival:   (id) => ipcRenderer.invoke('chat:arrival:stop', { id }),
      actions:       (opts) => ipcRenderer.invoke('chat:actions', opts),
      action:        (id, op, args) => ipcRenderer.invoke('chat:action', { ...(args || {}), id, op }),
      cardImage:     (id) => ipcRenderer.invoke('chat:card:image', { id }),
      // Messenger 1.6 notice cards: the notification's picture (/notify-media/… of the own server)
      noticeImage:   (path) => ipcRenderer.invoke('chat:notice:image', { path }),
      storage:       () => ipcRenderer.invoke('chat:storage'),
      clearCache:    () => ipcRenderer.invoke('chat:cache:clear'),
      onFeed:          (cb) => subscribe('chat:feed', cb),
      onLists:         (cb) => subscribe('chat:lists', cb),
      onReminders:     (cb) => subscribe('chat:reminders', cb),
      onState:         (cb) => subscribe('chat:state', cb),
      onConversations: (cb) => subscribe('chat:conversations', cb),
      onMessages:      (cb) => subscribe('chat:messages', cb),
      onTyping:        (cb) => subscribe('chat:typing', cb),
      onUnread:        (cb) => subscribe('chat:unread', cb),
      onOutbox:        (cb) => subscribe('chat:outbox', cb),
      onNavigate:      (cb) => subscribe('chat:navigate', cb),
    },

    // ── Schule (plugin gatecontrol-schule, WebUntis) ─────
    // Served when the app passes a SchoolService to registerBaseHandlers.
    school: {
      status:    () => ipcRenderer.invoke('school:status'),
      check:     () => ipcRenderer.invoke('school:check'),
      // from / to: 'YYYY-MM-DD' (≤ 14 days); opts: { refresh }
      timetable: (from, to, opts) => ipcRenderer.invoke('school:timetable', { from, to, refresh: !!(opts && opts.refresh) }),
      changes:   (days, opts) => ipcRenderer.invoke('school:changes', { days, refresh: !!(opts && opts.refresh) }),
      messages:  (days, opts) => ipcRenderer.invoke('school:messages', { days, refresh: !!(opts && opts.refresh) }),
      absences:  (days, opts) => ipcRenderer.invoke('school:absences', { days, refresh: !!(opts && opts.refresh) }),
      avatar:    (url) => ipcRenderer.invoke('school:avatar', { url }),
      // Schule 1.7: an attachment into Drive (folderId: a folder picked, else the family area › Schule)
      attachmentToDrive: (messageId, attachmentId, folderId) => ipcRenderer.invoke('school:attachment:drive', { messageId, attachmentId, folderId: folderId || null }),
      onState:   (cb) => subscribe('school:state', cb),
      onPush:    (cb) => subscribe('school:push', cb),
    },

    // ── GateDrop (plugin gatecontrol-gatedrop) ───────────
    // Served when the app passes a GateDropService to registerBaseHandlers
    // (ipc/gatedrop-handlers.js lists arguments and answers).
    gatedrop: {
      status:      () => ipcRenderer.invoke('gatedrop:status'),
      check:       () => ipcRenderer.invoke('gatedrop:check'),
      targets:     (opts) => ipcRenderer.invoke('gatedrop:targets', { refresh: !!(opts && opts.refresh) }),
      // file dialog → { ok, files: [{ id, name, size, mime }], rejected }
      pick:        () => ipcRenderer.invoke('gatedrop:pick'),
      // dropped File objects (drag & drop) → { ok, files, rejected }
      prepareDropped: (fileList) => {
        const paths = [];
        for (const f of Array.from(fileList || [])) {
          let p = '';
          try { p = webUtils && typeof webUtils.getPathForFile === 'function' ? webUtils.getPathForFile(f) : (f && f.path) || ''; } catch { p = ''; }
          if (p) paths.push(p);
        }
        return ipcRenderer.invoke('gatedrop:prepare', { paths });
      },
      takeCompose: () => ipcRenderer.invoke('gatedrop:compose:take'),
      // { files: [ids], text?, link?, note?, to: { people, devices, nas, link: { expires, pin } } }
      send:        (msg) => ipcRenderer.invoke('gatedrop:send', msg),
      inbox:       (kind, opts) => ipcRenderer.invoke('gatedrop:inbox', { kind, refresh: !!(opts && opts.refresh) }),
      sendDetails: (id) => ipcRenderer.invoke('gatedrop:send:get', { id }),
      saveSend:    (id) => ipcRenderer.invoke('gatedrop:send:save', { id }),
      endLink:     (token) => ipcRenderer.invoke('gatedrop:link:end', { token }),
      openFolder:  () => ipcRenderer.invoke('gatedrop:folder'),
      showItem:    (path) => ipcRenderer.invoke('gatedrop:show', { path }),
      openItem:    (path) => ipcRenderer.invoke('gatedrop:open', { path }),
      copy:        (text) => ipcRenderer.invoke('gatedrop:copy', { text }),
      openLink:    (url) => ipcRenderer.invoke('gatedrop:open-link', { url }),
      // "Senden an → GateDrop" in the Explorer: () → state, (true|false) → set
      explorer:    (enabled) => ipcRenderer.invoke('gatedrop:explorer', typeof enabled === 'boolean' ? { enabled } : {}),
      // Who may send to this PC (GateDrop 1.2.0) → { ok, supported, receiveFrom: 'self' | 'everyone' }
      access:      () => ipcRenderer.invoke('gatedrop:access'),
      setAccess:   (receiveFrom) => ipcRenderer.invoke('gatedrop:access:set', { receiveFrom }),
      onState:     (cb) => subscribe('gatedrop:state', cb),
      onCompose:   (cb) => subscribe('gatedrop:compose', cb),
      onProgress:  (cb) => subscribe('gatedrop:progress', cb),
      onReceived:  (cb) => subscribe('gatedrop:received', cb),
      onChanged:   (cb) => subscribe('gatedrop:changed', cb),
      onNavigate:  (cb) => subscribe('gatedrop:navigate', cb),
    },

    // ── Vault (plugin gatecontrol-vault, password manager) ─
    // Served when the app passes a VaultService to registerBaseHandlers
    // (ipc/vault-handlers.js lists arguments and answers). Lists carry no
    // secrets; entry() / history() / copy() are the explicit requests.
    vault: {
      status:           () => ipcRenderer.invoke('vault:status'),
      check:            () => ipcRenderer.invoke('vault:check'),
      // setup in two steps: setup → { recoveryKey } (show it), confirmSetup once kept
      setup:            (password, personalName) => ipcRenderer.invoke('vault:setup', { password, personalName }),
      confirmSetup:     () => ipcRenderer.invoke('vault:setup:confirm'),
      cancelSetup:      () => ipcRenderer.invoke('vault:setup:cancel'),
      unlock:           (password) => ipcRenderer.invoke('vault:unlock', { password }),
      unlockRemembered: () => ipcRenderer.invoke('vault:unlockRemembered'),
      // Windows Hello: unlock (prompt), check (no prompt), on (master password, then the prompt) / off
      unlockHello:      () => ipcRenderer.invoke('vault:unlockHello'),
      helloCheck:       () => ipcRenderer.invoke('vault:hello:check'),
      setHello:         (on, password) => ipcRenderer.invoke('vault:hello:set', on === true ? { on: true, password } : { on: false }),
      lock:             () => ipcRenderer.invoke('vault:lock'),
      recover:          (recoveryKey) => ipcRenderer.invoke('vault:recover', { recoveryKey }),
      completeRecovery: (password) => ipcRenderer.invoke('vault:completeRecovery', { password }),
      changePassword:   (current, password) => ipcRenderer.invoke('vault:changePassword', { current, password }),
      deleteAccount:    (confirm) => ipcRenderer.invoke('vault:deleteAccount', { confirm }),
      sync:             () => ipcRenderer.invoke('vault:sync'),
      // opts: { vaultId?, trash? }
      entries:          (opts) => ipcRenderer.invoke('vault:entries', opts && typeof opts === 'object' ? { vaultId: opts.vaultId, trash: opts.trash === true } : {}),
      entry:            (id, opts) => ipcRenderer.invoke('vault:entry', { id, emergencyId: opts && opts.emergencyId }),
      // { domain } (web address) or { app } → entries of that site, favourites first
      match:            (opts) => ipcRenderer.invoke('vault:match', opts && typeof opts === 'object' ? { domain: opts.domain, app: opts.app } : {}),
      // { id?, vaultId, data: { type, title, fields, … } }
      save:             (entry) => ipcRenderer.invoke('vault:save', entry && typeof entry === 'object' ? { id: entry.id, vaultId: entry.vaultId, data: entry.data } : {}),
      trash:            (id) => ipcRenderer.invoke('vault:trash', { id }),
      restore:          (id) => ipcRenderer.invoke('vault:restore', { id }),
      purge:            (id) => ipcRenderer.invoke('vault:purge', { id }),
      history:          (id) => ipcRenderer.invoke('vault:history', { id }),
      vaults:           () => ipcRenderer.invoke('vault:vaults'),
      createVault:      (name) => ipcRenderer.invoke('vault:createVault', { name }),
      renameVault:      (id, name) => ipcRenderer.invoke('vault:renameVault', { id, name }),
      deleteVault:      (id) => ipcRenderer.invoke('vault:deleteVault', { id }),
      people:           () => ipcRenderer.invoke('vault:people'),
      addMember:        (vaultId, userId, role) => ipcRenderer.invoke('vault:addMember', { vaultId, userId, role }),
      setRole:          (vaultId, userId, role) => ipcRenderer.invoke('vault:setRole', { vaultId, userId, role }),
      removeMember:     (vaultId, userId) => ipcRenderer.invoke('vault:removeMember', { vaultId, userId }),
      emergency:        () => ipcRenderer.invoke('vault:emergency'),
      emergencyAdd:     (userId, waitHours) => ipcRenderer.invoke('vault:emergencyAdd', { userId, waitHours }),
      emergencyRemove:  (id) => ipcRenderer.invoke('vault:emergencyRemove', { id }),
      // step: 'request' | 'deny' | 'approve'
      emergencyStep:    (id, step) => ipcRenderer.invoke('vault:emergencyStep', { id, step }),
      emergencyOpen:    (id) => ipcRenderer.invoke('vault:emergencyOpen', { id }),
      importParse:      (text, opts) => ipcRenderer.invoke('vault:import:parse', { text, vaultId: opts && opts.vaultId }),
      importSave:       (vaultId, opts) => ipcRenderer.invoke('vault:import:save', { vaultId, skipDuplicates: !(opts && opts.skipDuplicates === false) }),
      generate:         (opts) => ipcRenderer.invoke('vault:generate', opts && typeof opts === 'object' ? opts : {}),
      strength:         (password) => ipcRenderer.invoke('vault:strength', { password }),
      // { id, emergencyId? } of an entry, or { uri } (otpauth:// or a base32 secret)
      totp:             (arg) => ipcRenderer.invoke('vault:totp', arg && typeof arg === 'object' ? arg : {}),
      // { id, field, emergencyId? } or { text }; cleared after 30 s when unchanged
      copy:             (arg) => ipcRenderer.invoke('vault:copy', arg && typeof arg === 'object' ? arg : {}),
      settings:         () => ipcRenderer.invoke('vault:settings:get'),
      // { autoLockMinutes?: 0|1|5|15|60, remember?: boolean }
      setSettings:      (patch) => ipcRenderer.invoke('vault:settings:set', patch && typeof patch === 'object' ? patch : {}),
      // Wi-Fi networks nearby (Windows): { ok, networks: [{ ssid, security, signal, connected }] } | { ok: false, code }
      wifiScan:         () => ipcRenderer.invoke('vault:wifi-scan'),
      // Wi-Fi shares (plugin 1.4.0): a Wi-Fi entry on the wall tablet / the portal's start page — main sends the copy
      wifiShares:       (id) => ipcRenderer.invoke('vault:wifi-shares', { id }),
      // target: 'wall' | 'portal'; duration: '5m' | '1h' | '24h' | 'forever' | 'keep'
      wifiShare:        (id, target, duration) => ipcRenderer.invoke('vault:wifi-share', { id, target, duration }),
      wifiShareEnd:     (shareId) => ipcRenderer.invoke('vault:wifi-share-end', { shareId }),
      // the Wi-Fi QR code as a picture (built in main): { id, emergencyId? } → { ok, image, ssid, hidden }
      wifiQr:           (arg) => ipcRenderer.invoke('vault:wifi-qr', arg && typeof arg === 'object' ? arg : {}),
      // 2FA key from a QR code: 'screen' | 'clipboard' | 'file' → { ok, uris: ['otpauth://totp/…'] } | { ok: false, code }
      totpQr:           (source) => ipcRenderer.invoke('vault:totp-qr', { source: typeof source === 'string' ? source : '' }),
      touch:            () => ipcRenderer.invoke('vault:touch'),
      clearNotices:     () => ipcRenderer.invoke('vault:notices:clear'),
      onState:          (cb) => subscribe('vault:state', cb),
      onPush:           (cb) => subscribe('vault:push', cb),
    },

    // ── Drive (plugin gatecontrol-drive) ─────────────────
    // Served when the app passes a DriveService to registerBaseHandlers
    // (ipc/drive-handlers.js lists arguments and answers).
    drive: {
      status:       () => ipcRenderer.invoke('drive:status'),
      check:        () => ipcRenderer.invoke('drive:check'),
      me:           () => ipcRenderer.invoke('drive:me'),
      areas:        () => ipcRenderer.invoke('drive:areas'),
      // opts: { sort: 'name' | 'mtime' | 'size' | 'updated', order: 'asc' | 'desc', offset, limit }
      folder:       (id, opts) => ipcRenderer.invoke('drive:folder', { ...(opts || {}), id }),
      search:       (q, area) => ipcRenderer.invoke('drive:search', { q, area: area || null }),
      mkdir:        (parentId, name) => ipcRenderer.invoke('drive:mkdir', { parentId, name }),
      rename:       (id, name) => ipcRenderer.invoke('drive:rename', { id, name }),
      move:         (id, parentId) => ipcRenderer.invoke('drive:move', { id, parentId }),
      remove:       (id) => ipcRenderer.invoke('drive:remove', { id }),
      trash:        (area) => ipcRenderer.invoke('drive:trash', { area: area || null }),
      restore:      (id) => ipcRenderer.invoke('drive:restore', { id }),
      purge:        (id) => ipcRenderer.invoke('drive:purge', { id }),
      versions:     (id) => ipcRenderer.invoke('drive:versions', { id }),
      restoreVersion: (id, versionId) => ipcRenderer.invoke('drive:version:restore', { id, versionId }),
      links:        (nodeId) => ipcRenderer.invoke('drive:links', { nodeId: nodeId || null }),
      // { nodeId, mode: 'view' | 'download' | 'upload', expires: '1d' | '7d' | '30d' | 'never', pin? }
      createLink:   (opts) => ipcRenderer.invoke('drive:link:create', { ...(opts || {}) }),
      endLink:      (token) => ipcRenderer.invoke('drive:link:end', { token }),
      preview:      (mediaId, opts) => ipcRenderer.invoke('drive:preview', { mediaId, large: !!(opts && opts.large) }),
      // file dialog → { ok, paths }; then upload(parentId, paths)
      pick:         () => ipcRenderer.invoke('drive:pick'),
      upload:       (parentId, paths) => ipcRenderer.invoke('drive:upload', { parentId, paths }),
      // dropped File objects (drag & drop) → the same as upload()
      uploadDropped: (parentId, fileList) => {
        const paths = [];
        for (const f of Array.from(fileList || [])) {
          let p = '';
          try { p = webUtils && typeof webUtils.getPathForFile === 'function' ? webUtils.getPathForFile(f) : (f && f.path) || ''; } catch { p = ''; }
          if (p) paths.push(p);
        }
        return ipcRenderer.invoke('drive:upload', { parentId, paths });
      },
      // a taken name: 'version' | 'rename' (keep both) | null (skip)
      resolve:      (id, choice) => ipcRenderer.invoke('drive:upload:resolve', { id, choice: choice || null }),
      transfers:    () => ipcRenderer.invoke('drive:transfers'),
      clearTransfers: () => ipcRenderer.invoke('drive:transfers:clear'),
      open:         (id, versionId) => ipcRenderer.invoke('drive:open', { id, versionId: versionId || null }),
      saveAs:       (id, versionId) => ipcRenderer.invoke('drive:save-as', { id, versionId: versionId || null }),
      showItem:     (path) => ipcRenderer.invoke('drive:show', { path }),
      // the folder last picked in "In Drive speichern"
      lastFolder:   () => ipcRenderer.invoke('drive:last-folder'),
      setLastFolder: (folderId) => ipcRenderer.invoke('drive:last-folder:set', { folderId }),
      onState:      (cb) => subscribe('drive:state', cb),
      onTransfers:  (cb) => subscribe('drive:transfers', cb),
      onChanged:    (cb) => subscribe('drive:changed', cb),
    },

    // ── Shell ────────────────────────────────────────────
    shell: {
      openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
    },

    // ── Portal ───────────────────────────────────────────
    onPortalUrl: (cb) => ipcRenderer.on('portal-url', (_e, url) => cb(url)),
    // Opens the portal with a fresh one-time login link (fallback: portal URL).
    portal: {
      // Optional { next: '/portal#<tab>' } → lands on that portal tab.
      open: (opts) => ipcRenderer.invoke('portal:open', opts && typeof opts === 'object' ? { next: opts.next } : undefined),
    },

    // ── Fenster ──────────────────────────────────────────
    window: {
      minimize: () => ipcRenderer.send('window:minimize'),
      close:    () => ipcRenderer.send('window:close'),
    },

    // ── Navigation ───────────────────────────────────────
    onNavigate: (cb) => subscribe('navigate', cb),

    // ── i18n ─────────────────────────────────────────────
    i18n: {
      t: (key, params) => t(key, params),
      getLocale: () => getLocale(),
      getSupportedLocales: () => getSupportedLocales(),
    },

    // ── Locale ───────────────────────────────────────────
    locale: {
      set: (locale) => {
        setLocale(locale);
        ipcRenderer.invoke('locale:set', locale);
      },
      get: () => ipcRenderer.invoke('locale:get'),
      onChange: (cb) => {
        const ipcHandler = (_, loc) => {
          setLocale(loc);
          cb(loc);
        };
        ipcRenderer.on('locale:changed', ipcHandler);
        const unsub = onLocaleChange((loc) => cb(loc));
        return () => {
          ipcRenderer.removeListener('locale:changed', ipcHandler);
          unsub();
        };
      },
    },
  };
}

/**
 * Helper for edition-specific event subscriptions in the app preload.
 * @returns {(channel: string, cb: Function) => Function} subscribe(channel, cb) → unsubscribe
 */
function createSubscriber(ipcRenderer) {
  return (channel, cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on(channel, handler);
    return () => ipcRenderer.removeListener(channel, handler);
  };
}

module.exports = { createBridgeApi, createSubscriber };
