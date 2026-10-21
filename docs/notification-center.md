# Notification center: push client for the Windows apps

The core ships the shared push layer of the GateControl notification center
(server contract: `gatecontrol/docs/feature-notification-center.md`,
section "Vertrag Gerät ↔ Server"). The apps (Pro, Community) wire it up and
build the UI ("Mitteilungen", settings tab "Benachrichtigungen", tray).

| Module | Purpose |
|---|---|
| `PushClient` (`src/services/push-client.js`) | SSE stream `GET /api/v1/client/push` over Node `https`, resume, backoff, acks, prefs, test |
| `NotificationCenter` (`src/services/notification-center.js`) | Toasts (Electron `Notification`, Windows `toastXml`), inbox cache, unread count, DND, actions, quiet hours (read-only) |
| `PushControl` (`src/services/push-control.js`) | Control events + `hello.state` → policy refresh, support bundle, peer disabled, config check; stretches polling while push delivers |
| `createPortalOpener()` / `portalNext()` (`src/utils/portal.js`) | Portal with one-time login link, optionally on a portal tab (`next`) |
| `notificationsSchema` (`src/utils/notify-schema.js`) | Store schema fragment `notifications{}` |
| `registerBaseHandlers(…, { notificationCenter })` | IPC `notify:*` (opt-in) and renderer events |
| `createBridgeApi()` → `window.gatecontrol.notify` | Renderer API |
| `notifyMenuItems()` | Tray entries "Mitteilungen · 2 neu" and "Nicht stören für 1 Stunde" |
| `createTrayIcon(nativeImage, state, { badge })` | Tray icon with the unread dot |
| `checkPushPath()` / `isTunnelOnly()` | Kill-switch check ("Push nur durch den Tunnel") |

No new dependency: the stream uses Node `http`/`https`, REST calls go through
the existing axios `ApiClient`.

## Wiring an app (Pro and Community)

### 1. Store schema

`createStores()` (Community) already contains the fragment. Pro has its own
schema and merges it:

```js
const { notificationsSchema } = require('@gatecontrol/client-core');
const store = new Store({ name: 'gatecontrol-config', encryptionKey, schema: { ...proSchema, ...notificationsSchema } });
```

Keys (`notifications.*`): `enabled` (true), `direct` (true = also without VPN,
server mode `always`; false = `vpn_only`), `toasts` (true), `criticalBypass`
(true), `mutedTopics` ([]), `dndUntil` (null, epoch ms), plus main-process
keys `muteUntil` ({topic: epoch ms}), `lastSeq` (0), `seqScope` ('').
The inbox cache lives in the same encrypted store under `notificationsInbox`.
`config:set` accepts `NOTIFICATION_WRITABLE_KEYS` (the first six) and the
change reaches the push client through the store watcher.

### 2. Instantiate after `ClientPolicyService`

One instance of each for the app's lifetime (`apiClient.configure()` changes
URL/token in place; the push client reads them on every connect).

```js
const { PushClient, NotificationCenter } = require('@gatecontrol/client-core');

const pushClient = new PushClient({
  apiClient,                                   // ApiClient / ApiClientPro instance
  store,
  log,
  isTunnelUp: () => tunnelState.connected,     // mode vpn_only + reconnect on change
  isKillSwitchActive: () => killSwitch.enabled,
  getWgConfig: () => fs.promises.readFile(store.get('tunnel.configPath') || WG_CONFIG_FILE, 'utf8').catch(() => null),
});

const notificationCenter = new NotificationCenter({
  store,
  log,
  pushClient,
  protocol: 'gatecontrol-pro',                 // Community: 'gatecontrol-community' (see 5.)
  toastImagePath: path.join(__dirname, 'assets', 'icon.png'),
  showWindow: () => showWindow(),
  openPortal: (portalPath) => portalOpener.open({ path: portalPath }),  // target → `next` (see 8.)
});

notificationCenter.start();                    // opens the stream (no-op when switched off)
```

Toasts on Windows need the AppUserModelID (`app.setAppUserModelId(...)`),
which both apps already set for their notifications.

### 3. IPC and renderer

Pass the center to the shared handlers (opt-in — without it no `notify:*`
channel is registered):

```js
registerBaseHandlers(ipcMain, { ...ctx, notificationCenter });
```

After a successful `server:setup` (also via setup code / QR) the handlers call
`notificationCenter.resetForNewServer()`: the old inbox is dropped and the
stream reconnects without resume position. If an app overrides
`server:setup`, it must call that itself. The resume position is additionally
scoped to server + token, so a changed setup never resumes a foreign `seq`.

Tunnel changes: call `pushClient.networkChanged()` whenever the tunnel goes up
or down (same place that sends `tunnel-state` to the renderer). The stream
reconnects so the server sees the new path (`via`), and mode `vpn_only`
connects/disconnects.

### 4. Shutdown

Stop it in the app's `performCleanShutdown` (the core helper does it when
`ctx.notificationCenter` is given):

```js
notificationCenter.stop();   // closes the stream, flushes delivery acks
```

### 5. Toast buttons (protocol activation)

Electron reports a click on a Windows toast without telling which button was
pressed. Buttons therefore use protocol activation
(`<protocol>://notify/action?t=<nonce>`, random single-use nonce). The app
registers the scheme and forwards the URL:

```js
app.setAsDefaultProtocolClient('gatecontrol-pro');
app.on('second-instance', (_e, argv) => {
  if (notificationCenter.handleArgv(argv)) return;  // toast button
  showWindow();
});
```

Without `protocol` the toasts have no buttons; a click on the toast still
opens the entry (event `navigate`). Unknown/stale nonces only open the inbox.

### 6. Tray

```js
const { createTrayIcon, notifyMenuItems, i18n } = require('@gatecontrol/client-core');

function refreshTray() {
  tray.setImage(createTrayIcon(nativeImage, trayState, { badge: notificationCenter.unreadCount() > 0 }));
  const items = notifyMenuItems({
    unread: notificationCenter.unreadCount(),
    dnd: notificationCenter.dndState(),
    enabled: notificationCenter.getPrefs().enabled,
    t: i18n.t,
    openInbox: () => notificationCenter.openInbox(),   // window + notify:navigate { route: 'inbox' }
    setDnd: (arg) => notificationCenter.setDnd(arg),
  });
  // insert `items` into the tray menu template
}
notificationCenter.on('unread', refreshTray);
notificationCenter.on('status', refreshTray);   // DND on/off, DND expiry
```

### 7. Local notifications (Pro)

Replace the inline `new Notification({ title, body }).show()` calls with
`notificationCenter.notify({ title, body, priority, collapseKey })`. It uses the
same toast code and respects "Nicht stören" and the toast setting
(`force: true` for messages that must always show).

### 8. Push control (phase 5): control events instead of polling

Create it next to the push client once `ClientPolicyService` and
`ConnectionMonitor` exist (both apps keep one of each for the app's lifetime):

```js
const { PushControl } = require('@gatecontrol/client-core');

const pushControl = new PushControl({
  pushClient,
  clientPolicy,                   // ClientPolicyService
  connectionMonitor,              // ConnectionMonitor (its onPeerDisabled / onSupportBundleRequest)
  apiClient,                      // supportBundleRequest / configHash
  log,
  onConfigChanged: () => checkConfigNow(),   // the app's config/check (+ apply / reconnect)
});
pushControl.start();
```

What arrives and what happens:

| Server sends | Reaction (same path as the poll) |
|---|---|
| `control` `policy_changed` | `clientPolicy.noteVersion(policy_version)`: fetches `GET /client/policy` only when the version differs from the cached one (without a usable version: `refresh()`, If-None-Match) |
| `control` `support_bundle_requested` | `apiClient.supportBundleRequest = requested_at` (`YYYY-MM-DD HH:MM:SS` UTC, the same value as peer-info `supportBundleRequestedAt`, so both paths prompt once) → `connectionMonitor.supportBundleRequest()` → sender `onServerRequest` (asks once per request) |
| `control` `peer_state` `enabled:false` | `connectionMonitor.peerDisabled()` → the app's `onPeerDisabled` (disconnect + notice); only while the tunnel is monitored and the device has a peer (`apiClient.peerId`) |
| `control` `config_changed` | `onConfigChanged()` (coalesced while one runs) |
| `hello.state` (every connect) | catches up: policy (`noteVersion`), support request set/cleared, `peer_enabled:false` (ignored for a token without a peer, which always gets `false`), `config_hash` (= the `hash` of `GET /client/config` / `config/check`) ≠ `apiClient.configHash` → `onConfigChanged()` |

`policy_version` is an opaque string (16 hex characters, the same value as
heartbeat / peer-info `policyVersion` and the policy ETag): compared for
equality, never parsed. Unknown control types are ignored.

Control events carry no `id`: they are not stored by the server, never acked
and do not move the resume position. Anything missed while offline comes
with the next `hello.state`.

**Polling as the fallback.** While the stream is open and its hello had
`state` (`pushClient.controlSupported()`):

| Poll | Normal | While push delivers |
|---|---|---|
| Client policy (`ClientPolicyService`) | `app.configPollInterval` (300 s) | 30 min (`setPollInterval`) |
| Peer info (`ConnectionMonitor`, peer disabled + support request) | every 2nd 30-s cycle | every 15 min (`setPeerCheckInterval`) |
| WireGuard stats / handshake (`ConnectionMonitor`) | 30 s | 30 s (unchanged) |
| App's own polls, e.g. Community config/check | app setting | `pushControl.relaxedInterval('config', normalMs)` → 30 min |

When the stream drops (any state other than `connected`) the normal intervals
apply at once and the next monitor cycle asks peer-info right away. Longer
user intervals are never shortened. Servers without `hello.state` (and
servers without push): nothing changes. Event `mode` `{ relaxed }` tells the
app when the mode changes.

### 9. Quiet hours and portal tabs

The person's quiet hours ("Ruhezeiten") are set in the portal and applied by
the server (`silent:true`); the apps only show them. The center takes them
from `hello.quiet`, or asks `GET …/push/prefs` when the server's hello has no
`quiet` (`refreshQuiet()`; the settings page calls `notify:quiet` with
`refresh: true` when it opens). `status().quiet` →
`{ from: 'HH:MM', to: 'HH:MM', tz, criticalBypass } | null`, `status().quietKnown`.

"Im Portal ändern" (`notify:quiet:open`) and push actions `open_portal` use the
portal opener with `next`: a portal tab (`/portal`, `/portal#<tab>`, `/#<tab>`;
tabs `start`, `dienste`, `zuhause`, `fahrzeug`, `netzwerk`, `geraete`,
`mitteilungen`, `benachrichtigungen`, `plg-<id>` — `portalNext()`, same rule as
the server) is requested as `POST /api/v1/client/portal-link {"next": …}` and
the user lands there signed in. Servers before 1.156 return a link without
`next`; the opener appends it (they ignore it and open the portal home). A
target that is no portal tab, or no link at all, opens the page directly on
the portal origin as before. `portal:open` accepts `{ next }` as well
(validated with `portalNext`, anything else opens the portal home); apps pass
it on: `openPortal: (opts) => portalOpener.open(opts)`.

### 10. Where notifications appear (core 1.191, Messenger 1.6)

With a sink plugin (the messenger) each kind of notification (push topic) can
appear in the pinned chat **GateControl** (the inbox, default), in the
**family chat** (the Familie group, for the whole household — only admins and
parents may choose it, `canFamily`) or in an **own chat** of its source
("Schule", only for the person). `routes()` / `setRoute(topic, dest)` (IPC
`notify:routes` / `notify:routes:set`) use `GET/PUT /api/v1/client/push/routes`
with the device token; the answer `{ sink, canFamily, groups: [{ source,
label, topics: [{ id, label, dest, locked, familySetBy }] }] }` is cleaned by
`utils/notify-routes.js` (`security` and `admin_notice` are always locked to
GateControl). Refusals come as their codes (`family_not_allowed`, `locked`,
`no_sink`, `unknown_topic`, `no_user`, `push_disabled`, `invalid_*`); a server
without the route answers `unsupported` — the apps hide the entries then.
The apps show the page "Wo Mitteilungen erscheinen" in Einstellungen ›
Benachrichtigungen and in the chat settings.

On `dest: "own"` GateControl 1.192 makes sure the source's own chat exists
and names it in the PUT answer; `setRoute()` passes it on as `chat: { source,
label, conversationId (string), created }` (`created`: newly created, false:
an existing chat is used) — null for inbox / family, on older servers or when
it failed (`normalizeChat()`). The apps then say "Chat „Schule“ angelegt" /
"Erscheint im vorhandenen Chat „Schule“" (`push.routes.chatCreated` /
`chatExisting`) and reload the chat list.

A notice card in a chat carries its notification (`card.notice { topic, data
}`); its link (`card.link.route`, may name a plugin screen after a `/`) opens
what a click on that notification would: `openTarget({ route, topic, data })`
(IPC `notify:open`) asks the click routes (`addClickRoute`, e.g. Schule on the
school message) and emits `navigate` `{ route, id: null, context }` when one
claims it (`{ ok: true }`); otherwise `{ ok: false }` and the app opens the
route itself (its page, or the plugin's portal tab).

## API reference

### PushClient

`new PushClient({ apiClient, store, log, storeKey?, isTunnelUp?, isKillSwitchActive?, getWgConfig?, agent?, timing? , onHello?, onNotification?, onRead?, onRevoke?, onStatus?, onEvent? })`

| Method | Result |
|---|---|
| `start()` / `stop()` | open / close the stream (stop flushes pending `delivered` acks) |
| `restart({ resetSeq })` | stop + start; `resetSeq` forgets the resume position |
| `networkChanged()` | tunnel/network changed → reconnect (debounced) |
| `applySettings()` | re-read `notifications.*` (on/off, direct, muted topics) and tell the server |
| `ack(seqs, state, action?)` | `POST …/push/ack` (state `delivered`/`read`/`dismissed`, ≤ 200 per request) → `{ ok, count }` / `{ ok:false, error }` |
| `fetchInbox({ limit, before })` | `GET …/push/inbox` → `{ ok, items, unread }` |
| `setPrefs({ enabled, mode \| direct, muted_topics \| mutedTopics })` | `PUT …/push/prefs` → `{ ok }` |
| `requestTest()` | `POST …/push/test` → `{ ok, seq }` (server: 5/min) |
| `fetchPrefs()` | `GET …/push/prefs` → `{ ok, quiet, hasQuiet }` (quiet hours, read-only) |
| `controlSupported()` | stream open and its hello carried `state` (server with control events) |
| `refreshPath()` | re-run the kill-switch check |
| `status()` | see below |

Events: `hello` (payload + normalized `quiet` — `undefined` when the server
does not send it — and `state`), `notification` (contract payload +
`received_at`, `via`), `read` `{ids}`, `revoke` `{ids}`, `state` (normalized
`hello.state`: `{ policyVersion, peerEnabled, supportBundleRequested,
supportBundleRequestedAt, configHash }`, only from servers that send it),
`control` (`{ type: 'policy_changed', policyVersion }`,
`{ type: 'support_bundle_requested', requestedAt }`,
`{ type: 'peer_state', enabled }`, `{ type: 'config_changed' }`; unknown types
and malformed payloads are dropped), `status`, `event` (other stream events),
`reset` (server/token changed). Normalizers: `PushClient.normalizeQuiet`,
`normalizeState`, `normalizeControl`.

`status()` →
`{ state: 'stopped'|'connecting'|'connected'|'disabled'|'error', reason, code,
via: 'direct'|'tunnel'|null, since, retryAt, attempt, unread, topics, keepaliveS,
serverTime, lastEventAt, lastSeq, control, serverHost, killSwitch: { active, tunnelOnly, path } }`

| Server answer | state / reason | Next attempt |
|---|---|---|
| 200 `text/event-stream` | `connecting` → `connected` after `hello` | — |
| stream ends / watchdog (no byte for 2 × `keepalive_s`) | `connecting`/`reconnecting`, `error`/`keepalive_timeout` | backoff |
| network error, timeout (15 s), 5xx, `503 too_many_streams` | `error` / `network`, `timeout`, `http_500`, `too_many_streams` | backoff 1 s → 5 min, jitter (½…1 × base); reset after a stream lived ≥ 30 s |
| `404` | `disabled` / `unsupported` | hourly |
| `503 push_disabled` | `disabled` / `push_disabled` | hourly |
| `403 direct_not_allowed` | `disabled` / `direct_not_allowed` | `networkChanged()` or hourly |
| `429 rate_limited` | `error` / `rate_limited` | ≥ 15 min (or `Retry-After`) |
| `401`, other `403` (`token_required`, `scope_required`, machine binding) | `error` / `auth` | none — until `restart()` (server:setup) |
| switched off locally | `disabled` / `off` | on `applySettings()` |
| `direct:false` and tunnel down | `disabled` / `vpn_only` | on `networkChanged()` |
| no URL/token, http URL | `disabled` / `not_configured`, `insecure_url` | — |

Proxy: `ApiClient` uses no explicit agent (axios defaults). The stream
accepts an optional `agent` (e.g. a proxy agent) if an app ever needs one.

### NotificationCenter

| Method | Result |
|---|---|
| `start()` / `stop()` / `dispose()` | push client on/off; dispose also drops listeners |
| `list({ filter: 'all'\|'unread'\|<topic>, limit, before })` | `{ items, unread, topics }` (items carry `actions`) |
| `get(id)` | one entry |
| `refresh()` | replace the cache with the server inbox (also runs after every `hello`) |
| `markRead(ids \| 'all')` | local + `ack read`; failed acks are retried after the next `hello` |
| `performAction(id, actionId)` | `open_app_route` → `navigate`; `open_portal` → `openPortal(target)` (portal tab via the login link with `next`, or event `portal`); `mute_1h` → local topic mute 1 h; `done` → `dismissed`; `ack`; always acks with `action` |
| `getPrefs()` / `setPrefs(patch)` | `{ enabled, direct, toasts, criticalBypass, mutedTopics, dndUntil, topics }` |
| `setDnd({ minutes } \| { until } \| null)` / `dndState()` | "Nicht stören bis" |
| `muteTopic(topic, ms)` | local mute |
| `unreadCount()`, `topics()`, `status()` | status = push status + `unread`, `dnd`, `toasts`, `enabled`, `quiet`, `quietKnown` |
| `quietState()` / `refreshQuiet()` | `{ known, quiet, source: 'hello'\|'prefs', at }`; refresh asks `GET …/push/prefs` |
| `openQuietHoursInPortal()` | portal tab `/portal#benachrichtigungen` (auto-login) |
| `routes()` / `setRoute(topic, dest)` | where each kind of notification appears (`PushClient.fetchRoutes()` / `setRoute()`): `{ ok, routes }` / `{ ok: false, error }` |
| `openTarget({ route, topic, data })` | a notice card's link: `navigate` `{ route, id: null, context }` when a click route claims the notification → `{ ok: true, route }`, else `{ ok: false }` |
| `notify({ title, body, priority, collapseKey, force, onClick })` | local app notification through the same wrapper |
| `handleArgv(argv)` / `handleProtocolUrl(url)` | toast button activation |
| `openInbox(id?)` | show the window on the inbox (event `navigate`) |
| `addClickRoute(route, resolve)` / `clickTarget(entry)` | an app page claims its entries: a toast click opens `route` (event `navigate` `{ route, id, context }`, context = `resolve(entry)`) instead of the inbox while `resolve` answers; used by `SchoolService` (`plg-gatecontrol-schule`) |
| `resetForNewServer()` / `clear()` | drop cache (+ reconnect without seq) |

Events: `new` (entry + `toast`, `updated`), `update` `{ reason, ids, unread }`
(`read`/`revoke`/`sync`/`clear`), `unread` (count), `status`, `navigate`
`{ route, id }`, `portal` `{ path }`, `action` `{ id, seq, action, type }`.

Toast rules (`NotificationCenter.toastDecision`): no toast when switched off,
`toasts:false`, `silent:true` (inbox only), topic muted, "Nicht stören" — the
last two unless `priority:'critical'` and `criticalBypass`. Expired messages
are dropped; messages older than 6 h (replay after a long offline phase) and
more than 5 toasts in 10 s go to the inbox only. Same `collapse_key` (or the
same message id, bundling) replaces the toast; `read`/`revoke` close it.
Priority: `info` silent, `normal`/`high` default sound, `critical` urgent
scenario with the reminder sound; `high`/`critical` prefix the body with
"Hoch ·"/"Kritisch ·".

### IPC (`registerBaseHandlers`, opt-in) and bridge (`window.gatecontrol.notify`)

| Channel | Bridge | Argument → result |
|---|---|---|
| `notify:list` | `list(opts)` | `{ filter, limit, before, refresh }` → `{ items, unread, topics }` |
| `notify:read` | `read(ids \| 'all')` | `{ ids }` / `{ all: true }` → `{ ok, updated, unread }` |
| `notify:action` | `action(id, actionId)` | → `{ ok, error? }` |
| `notify:prefs:get` | `getPrefs()` | → prefs |
| `notify:prefs:set` | `setPrefs(patch)` | → `{ ok, prefs }` / `{ ok:false, error }` |
| `notify:test` | `test()` | → `{ ok, seq }` / `{ ok:false, error }` |
| `notify:status` | `status()` | → `NotificationCenter.status()` |
| `notify:dnd` | `dnd(arg?)` | `{ minutes }` / `{ until }` / `null` (off) / no argument (query) → `{ ok, active, until }` |
| `notify:quiet` | `quiet(opts)` | `{ refresh }` → `{ ok, known, quiet, source, at }` |
| `notify:quiet:open` | `openQuietHours()` | → boolean (portal tab "Meine Benachrichtigungen") |
| `notify:routes` | `routes()` | → `{ ok, routes: { sink, canFamily, groups } }` / `{ ok:false, error }` (`unsupported`: older server) |
| `notify:routes:set` | `setRoute(topic, dest)` | `'inbox'\|'own'\|'family'` → `{ ok, routes }` / `{ ok:false, error }` |
| `notify:open` | `open({ route, topic, data })` | notice card link → `{ ok, route? }` (ok false: the app opens the route) |
| `portal:open` | `window.gatecontrol.portal.open(opts)` | `{ next: '/portal#<tab>' }` optional → boolean |
| event `notify:new` | `onNew(cb)` | entry |
| event `notify:update` | `onUpdate(cb)` | `{ reason, ids, unread }` |
| event `notify:status` | `onStatus(cb)` | status |
| event `notify:navigate` | `onNavigate(cb)` | `{ route, id, context? }` — `route` is `inbox` (+ `id`) or an app route of the contract (`vpn`, `services`, `gateways`, `plg-<id>`); `context` from `addClickRoute` |

i18n: `push.*` in `src/i18n/locales/{de,en}.json` (states, reasons per
`status().reason`, `via`, `tunnelOnly` warning, priorities, tray entries,
`push.routes.*` for "Wo Mitteilungen erscheinen").

## Kill switch

Outside the tunnel the kill switch allows only TCP 443 to the WireGuard
endpoint IP. `status().killSwitch.tunnelOnly` is true when the kill switch is
on and the server URL resolves to other IPs or uses another port: push then
only works while the tunnel is up. The settings page shows `push.tunnelOnly`
in that case, otherwise `push.killSwitchOk`.

## Known limits

* `open_portal` targets that are not a portal tab open directly on the portal
  origin without auto-login (the server's `next` only accepts tabs).
* Quiet hours are read-only on the device; they change in the portal and
  reach the app with the next hello (reconnect) or when the settings page
  opens (`notify:quiet` with refresh).
* Control events need the push stream. With push switched off, `vpn_only`
  without tunnel, or an older server, the polls run at their normal intervals.
