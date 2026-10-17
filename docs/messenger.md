# Messenger: "Chats" for the Windows apps

The core holds the data side of the GateControl Messenger (plugin
`gatecontrol-messenger`, contract: `gatecontrol-plugins/plugins/gatecontrol-messenger/README.md`
"App-API"; server: GateControl ≥ 1.177.0 — plugin media, realtime events,
chat notifications). The apps (Pro, Community) draw the page "Chats".

| Module | Purpose |
|---|---|
| `MessengerApi` (`src/services/messenger-api.js`) | REST of the plugin over the device token (`ApiClient`'s axios), raw media upload / download, `/avatars/…`, availability via `GET /api/v1/client/plugins` |
| `MessengerOutbox` (`src/services/messenger-outbox.js`) | Offline outbox: persisted, ordered, clientId idempotency, uploads before sending, backoff, failed / retry / discard |
| `MessengerService` (`src/services/messenger.js`) | Availability, cache (also offline), live plugin events from the push stream, catch-up after reconnects, polling fallback, read marks, "active", typing, groups, search, media cache |
| `ChatNotifier` (`src/services/chat-notifier.js`) | Chat pushes (`kind: "message"`) as Windows toasts with reply field / "Gelesen", acks, closing on read / revoke |
| `registerBaseHandlers(…, { messenger, chatNotifier })` | IPC `chat:*` (`src/ipc/messenger-handlers.js`) and renderer events |
| `createBridgeApi()` → `window.gatecontrol.chat` | Renderer API |
| `messengerUtil` (`src/utils/messenger.js`) | Pure helpers (status ticks, send bodies, chat push parsing, safe file names, unsafe types) |
| i18n `chat.*` | Texts of the page, the toasts and the errors (DE/EN) |

No new dependency.

## Wiring an app

Create the messenger after the notification center (it uses the same push
client) and keep one instance for the app's lifetime:

```js
const { MessengerService, ChatNotifier } = require('@gatecontrol/client-core');

const messenger = new MessengerService({
  apiClient,                                   // configure() changes it in place
  pushClient: notifications.pushClient,        // live events + reconnects (optional: polling only)
  store,                                       // encrypted store: cache `messengerCache`, outbox `messengerOutbox`
  dataDir: app.getPath('userData'),            // files waiting in the outbox
  log,
  isWindowVisible: () => !!mainWindow && mainWindow.isVisible() && !mainWindow.isMinimized(),
});
const chatNotifier = new ChatNotifier({
  messenger,
  notificationCenter: notifications.notificationCenter,
  log,
  protocol: 'gatecontrol-pro',                 // fallback "Gelesen" button (see below)
  toastImagePath: path.join(RESOURCES_PATH, 'icons', 'app-icon.png'),
  tmpDir: app.getPath('temp'),                 // sender pictures for the toasts
  showWindow: () => showWindow(),
});

registerBaseHandlers(ipcMain, { ...ctx, notificationCenter, messenger, chatNotifier });
chatNotifier.start();
messenger.start();
// quit: messenger.stop() (performCleanShutdown does it with ctx.messenger), chatNotifier.stop()
```

`server:setup` (core handler) calls `messenger.resetForNewServer()`: cache,
outbox and availability of the old server are dropped, the new one is asked.

The renderer reports the page and the open conversation:
`chat.view(true|false)` when the page is shown / left, and
`chat.open(id, visible)` when a chat is opened or closed and when the window
is hidden / shown (`document.visibilityState`, focus). Visible → `POST …/active`
every 20 s (the server sends no push for it), read up to the newest message,
the chat's toasts are closed and acked.

### Renderer CSP

Pictures and voice messages arrive as bytes over IPC (`chat.media(id)` →
`{ mime, data: Uint8Array }`) and are shown as `blob:` URLs: the page needs
`img-src 'self' data: blob:` and `media-src 'self' blob: mediastream:`
(recording). The renderer never talks to the server itself.

## Availability ("only when the server has the plugin")

| Server | `status().state` / `reason` |
|---|---|
| plugin usable, app tab visible, `GET me` answers | `available` |
| no `GET /api/v1/client/plugins` (older server) | `unavailable` / `unsupported` |
| plugin not installed / not usable for this token | `unavailable` / `not_installed` |
| `appVisible` hides the tab for this person | `unavailable` / `hidden` |
| kiosk device, token without owner (`403`) | `unavailable` / `forbidden`, `no_user` |
| network error, 5xx | `error` (or `available` + `stale` with a cache) — retried 5 s … 5 min |

`unavailable` is asked again every 30 min, after a push reconnect and on
`chat.check()`; a plugin event on the stream triggers a check as well. The
apps hide the nav entry unless `available`.

## Live updates

Plugin events arrive on the existing push stream as `event: plugin`
(`PushClient` 'event'). The service handles every type of the README:
`message.new` (→ `messages?after=`), `message.update` (→ `changedSince=`),
`message.delete` (tombstone for `deleted`, removed otherwise), `reaction`,
`read` (others → `GET conversations/:id` for the ticks; `self` → unread,
event `read-self`), `typing` ("schreibt …" until `until`),
`conversation.update`, `conversation.remove`. There is no replay: after every
`hello` it asks `conversations?since=<serverTime>`, the newer messages of the
loaded chats and `changedSince` for the open one. Without a connected stream
(notifications off on this PC, `vpn_only` without tunnel, old server) it
polls: 30 s while the page is open, 2 min otherwise.

## Sending, outbox

`chat.send({ conversationId, kind, text, replyTo, meta, file, thumb })`
validates against the `GET me` limits (`maxBytes`, `types`, `textMax`,
`thumbMaxBytes`) and queues the message. Files are uploaded first (raw `PUT
…/media`), the media ids are kept, `media_invalid` uploads once more. Network
errors / 5xx / 429 → retried (2 s … 5 min, at once after a reconnect);
refusals → `failed` with the code (`chat.retry(clientId)` /
`chat.discard(clientId)`). Pending entries come with `chat.messages()` in
`pending`; the server's message replaces them (same `clientId`). The renderer
scales pictures before sending (long side `imageMaxSide`, WebP, plus a
320 px preview ≤ 64 KB) — the server converts nothing.

## Chat notifications on Windows

`NotificationCenter.setChatHandler()` (set by `ChatNotifier.start()`) takes
every push with `kind: "message"` away from the inbox (the server keeps them
out of `…/push/inbox` as well). One toast per chat (`Tag` `chat-<id>`,
`Group` `chats`): header = group title or sender, text = message (group:
"Anna: …"), the sender's picture as round logo.

| Electron | Buttons |
|---|---|
| `Notification.handleActivation` (Electron ≥ 39, Windows) | reply field + "Senden" + "Gelesen" (foreground activation; also after a restart) |
| older, app protocol registered | "Gelesen" as protocol button (`<protocol>://notify/action?t=<nonce>`, through `NotificationCenter.handleArgv`) |
| neither | none — a click opens the chat |

Reply: `messenger.send({ kind: 'text', text, source: 'notification' })`
(outbox, clientId), then like `mark_read`: `POST …/read { upTo }` and `ack`
`read` (action `reply` / `mark_read`) for every shown `seq` of the chat. A
reply the server refuses shows a local notice ("Antwort nicht gesendet").
Toast rules as for every message (on/off, Windows toasts, topic muted,
"Nicht stören", quiet hours = `silent` → no banner, replay/burst caps); no
toast while the chat is open and visible. `read`/`revoke` on the stream and
the messenger's own `read` event close the toast.

## Files

`chat.saveMedia(id, name)` → save dialog; the file gets the Windows "Mark of
the Web" (`Zone.Identifier`, internet zone). `chat.openMedia(id, name)` → a
copy in `%TEMP%\gatecontrol-chat\…` opened with the default program — refused
(`code: 'unsafe'`) for executables, scripts, shortcuts, HTML/SVG and Office
macro formats (`messengerUtil.unsafeToOpen`); those can only be saved.

## API reference

### MessengerService

| Method | Result |
|---|---|
| `start()` / `stop()` | check + live / timers off, cache saved |
| `check({ force })` / `status()` / `available()` | availability (above); status: `{ state, reason, stale, version, label, me: { user, prefs, features, limits, license }, unread, live, outbox }` |
| `listConversations()` / `getConversation(id)` / `refreshConversations({ full })` | conversations with `typing` (user ids) and `outbox` (pending count) |
| `getMessages(id, { before })` / `messagesView(id)` | `{ conversationId, messages, pending, hasMore, offline }` |
| `send(req)` / `retrySend(clientId)` / `discardSend(clientId)` | outbox |
| `edit(id, text)`, `remove(id, 'me'\|'all')`, `react(id, emoji\|null)` | |
| `markRead(id, upTo?)`, `typing(id, { stop })`, `setOpen({ id, visible })`, `setViewOpen(open)` | |
| `people()`, `createConversation(…)`, `updateConversation(id, patch, { avatar })`, `setPrefs(patch)`, `search(id, q)`, `mediaList(id, opts)` | |
| `media(mediaId)`, `avatar(path)` | `{ mime, data }` (memory LRU 48 MB / 8 MB) |
| `unreadTotal()` | unread messages of the chats that are not muted (nav badge, tray) |
| `resetForNewServer()` | |

Events: `state`, `conversations` `{ ids, removed }`, `messages`
`{ conversationId, reason }`, `typing` `{ conversationId, userIds }`,
`unread` (total), `outbox` `{ conversationId }`, `read-local`, `read-self`,
`send-failed` `{ conversationId, clientId, error, source }`.

### IPC / bridge

`window.gatecontrol.chat`: `status`, `check`, `conversations`, `conversation`,
`messages`, `send`, `retry`, `discard`, `edit`, `remove`, `react`, `read`,
`typing`, `open`, `view`, `people`, `create`, `update`, `prefs`, `search`,
`mediaList`, `media`, `avatar`, `saveMedia`, `openMedia`; events `onState`,
`onConversations`, `onMessages`, `onTyping`, `onUnread`, `onOutbox`,
`onNavigate` (`{ conversationId }`, toast click). Arguments and answers:
`src/ipc/messenger-handlers.js`. Every call resolves; failures are
`{ ok: false, code, error }` — `chat.error.<code>` has the text.

## Known limits

* Location messages are shown (map link) but not sent from Windows (no
  position source on the PC).
* Disappearing chats are shown and switchable in the chat info; the server
  deletes the messages and the client drops them on `message.delete`
  (`expired`).
* The toast reply field needs Electron's `Notification.handleActivation`
  (Electron 44 in both apps) and the app's start-menu shortcut (AUMID), like
  every Windows toast; the portable build shows no toasts.
* Bridges (WhatsApp, Signal, …) and end-to-end encryption are not part of V1.
