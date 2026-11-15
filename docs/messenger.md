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
| `MapService` (`src/services/map-service.js`) | Map of "Standort senden" and the location previews: OpenStreetMap tiles and address search / reverse geocoding (Nominatim) from the main process |
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
(recording). Map tiles come the same way (`chat.mapTile(z, x, y)`). The
renderer never talks to the server or the internet itself.

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
`read` (Messenger ≥ 1.1.0: `readUpTo` / `deliveredUpTo` of the event set the
chat's values and the reader's receipt → the ticks, no GET; older plugins:
`GET conversations/:id`; `self` → unread, event `read-self`), `typing`
("schreibt …" until `until`), `conversation.update` (every reason, also
`released` — a managed group became a normal group — → `GET
conversations/:id`), `conversation.remove`. There is no replay: after every
`hello` it asks `conversations?since=<serverTime>`, the newer messages of the
loaded chats and `changedSince` for the open one — `changedSince` is the
`serverTime` of the chat's last messages answer (1.1.0; older plugins: the
one of the conversation list).

### Jumping to a message (`around`)

A search hit or a quoted message that is not loaded: `chat.messages(id, {
around: messageId })` → `messages?around=` (Messenger ≥ 1.1.0, half older,
the message, the newer ones). While there is a gap to the cached newest
messages the answer is a window of its own (`detached: true`, `hasMore` =
older ones exist, `hasMoreAfter` = newer ones exist); `chat.messages(id, {
before })` / `{ after }` page it, and once it reaches the cached messages
both are joined (`detached: false`). `chat.messages(id)` closes the window
("Zur neuesten Nachricht"). A 1.0.x plugin answers `{ ok: false, code:
'unsupported' }` — the view then loads older pages until it finds the
message. Without a connected stream
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

### Videos and file previews (Messenger 1.3.0)

Videos stay `kind: "file"`. Picking a `video/*` file, the renderer loads it
into a `<video>` element, grabs a frame at ~1 s (canvas, WebP — JPEG when
the engine has no WebP encoder — long side ≤ `limits.thumbMaxSide` (640),
≤ `limits.thumbMaxBytes` (64 KB)) and reads duration and size: `chat.send({
kind: 'file', file, thumb, video: { durationMs, width, height } })`. The core
sends `video` only when `GET me` has `features.video_meta === true` and the
file is `video/*`, and the preview (`thumbMediaId`, uploaded before the file)
only with `features.file_thumbs === true` — older plugins get the plain file
message. Video bubbles show the preview with a play button and the
duration and play in an overlay (`<video>` with the file as `blob:` URL);
files with a preview show it above the file card. The chat info's media list
has "Fotos / Videos / Dateien" (`mediaList(id, { kind: 'video' })` when the
server supports it; `counts.video`). PDF previews are not made (no PDF
renderer in the apps; Chromium's viewer cannot render off-screen).

## Update hint ("newer version of GateControl")

The core knows the `GET me` feature keys of its version
(`messengerUtil.KNOWN_FEATURES`: `direct`, `groups`, `voice`, `files`,
`location`, `reactions`, `edit`, `search`, `disappearing`, `bridges`, `e2e`,
`video_meta`, `file_thumbs`, the 1.4.0 keys `status`, `stories`, `polls`,
`events`, `arrival`, `actions`, `msg_tools`, `privacy2` and the 1.4.1 key
`story_duration`). When the server sets any other key to `true`,
`status().updateHint` is `{ features: [keys], key }` and the Chats view shows
a small banner on top: „Für alle Chat-Funktionen gibt es eine neuere Version
von GateControl“ with "Nach Updates suchen" (the app's update check in
Settings › About) and a close button — `chat.dismissUpdateHint()` hides it
until the set of unknown keys changes (store key `messengerUpdateHint`).
Nothing is blocked; everything this version knows keeps working.

## Messenger 1.4.0

Status and stories, privacy, chat tools, polls, events, live arrival and
home actions (plugin README "App-API → Since 1.4.0"; server GateControl ≥
1.180.0). `GET me` → `features` is an object of the keys that are `true`
(absent = not offered — never `false`); every part is used only when its key
is there, every 1.4.0 call of a server without it answers `{ ok: false, code:
'unsupported' }` without asking the server:

| Key | Core | Apps (Chats page) |
|---|---|---|
| `status` | `statusFeed()`, `setStatus()`, `clearStatus()`; the feed is cached (60 s) and fetched again on `status.update`, `story.new`, `story.remove` and after a reconnect → event `feed` | own avatar in the list head ("Dein Status": text ≤ 60, presets, "Löschen nach", "Sichtbar für"), the status strip under "Angeheftet" (glowing ring while a person has unseen stories) |
| `stories` | `createStory()` (picture / video uploaded first, the preview before the file), `deleteStory()`, `storySeen()` (the cached feed marks it seen), `storyViewers()`, `storyReact()` | story viewer (text, picture, video; progress, ←/→, reply → a direct message with `replyStory`, reactions, viewers of one's own), "Status erstellen" (text with colour / font, picture or video; readable in the light and the dark theme; a failed post stays as an error in the dialog); own active stories: the glowing ring around "Mein Status" and the own avatar in the list head, a click on the avatar shows them (with "Gesehen von"), "+" adds one, the card "Meine Storys" in "Dein Status"; a posted story is shown at once (before the feed is fetched again) |
| `story_duration` (1.4.1, with `stories`) | `createStory({ durationH })` sends `durationH` (1, 3, 6, 12 or 24 — `limits.storyDurationsH`, `messengerUtil.storyDurationsOf()`); another value → `invalid` without asking the server; without the key `durationH` is left out (the server's 24 h) | "Dauer" in "Status erstellen": 1 / 3 / 6 / 12 / 24 Std. (default 24); without the key "24 Std." as plain text |
| `polls` | `send({ kind: 'poll', poll })`, `vote()`, `addPollOption()`, `closePoll()`, `nudgePoll()` | "Abstimmung erstellen" in the attach menu, poll bubble (vote, add an answer, votes, remind, close) |
| `events` | `send({ kind: 'event', event })`, `rsvp()`, `checkItem()`, `editEvent()` (PATCH, also `cancelled: true`) | "Ereignis erstellen" (Familie places when `integrations.familie.places`), event bubble (RSVP with guests, checklist, edit / cancel), the bar of `conversation.nextEvent` |
| `arrival` | `stopArrival()` — **Windows sends no arrivals** (no GPS) | arrival bubble (live / arrived / stopped, ETA, distance, progress, map preview and "Auf Karte"; an own live one can be stopped) |
| `actions` | `actions()` (cached 60 s), `send({ kind: 'action', action })`, `actionOp(id, 'run'\|'approve'\|'deny', { actionId, plugin })`, `cardImage(id)` (base64 → bytes, checked image type, cached) | "Aus deinem Zuhause" in the attach menu (run / request / grant), action bubbles (state `done` only after an approved request), plugin cards (picture, buttons, the `link` route — e.g. the doorbell's "Live-Bild" `plg-gatecontrol-door` — opened as that portal tab) |
| `msg_tools` | `archive()`, `pin()`, `lists()` / `saveLists()` (event `lists`), `setBlocked()`, `blocks()`, `exportChat()` (all parts, oldest first), `remind()`, `reminders()`, `deleteReminder()` (event `reminders`), `suggest()`, `toList()`, `toCalendar()`, `places()` | "Archiviert", pinned messages bar, chips (Alle, Ungelesen, Gruppen, own lists), block / unblock, export (save dialog, UTF-8 text), "Erinnere mich", "Auf Einkaufsliste" / "Termin anlegen" when Familie offers them |
| `privacy2` | `setPrefs({ privacy, notify, chats })` (partial, only known keys and values — `messengerUtil.prefsBody`) | the settings page (below), "online" / "zuletzt online" in direct chats |

`status().me` keeps the whole `prefs` (with `privacy`, `notify`, `chats` when
the server sends them) and `integrations: { familie: { lists, calendar,
places } }`. Archived chats do not count in `unreadTotal()` (nav badge,
tray). Sending checks the bodies like the server (`messengerUtil.buildSendBody`:
poll 2…12 distinct options, event times / reminder minutes, action modes, a
grant needs `toUserId` and `until`) — `poll`, `event` and `action` carry no
text, no meta.

**Live events.** `poll.update`, `event.update`, `action.update`,
`arrival.update` → `messages?changedSince=<updatedAt − 1 ms>` for a cached
message (event `messages`); `event.update` and a changed newest message also
refresh the conversation (`nextEvent`, list preview). `conversation.update`
with `archive` / `pins` / `blocks` → `GET conversations/:id` (blocks: the
people and the feed as well).

**Messages of unknown kinds** (a newer server) are drawn as a neutral bubble
„Diese Nachricht braucht eine neuere App-Version“; the update hint above
covers unknown feature keys.

**Pushes.** Poll, event, arrival and action messages come as chat pushes with
the server's texts ("📊 Umfrage: …", "Bittet um: …" — only to approvers).
Pushes with `data.kind` (`reminder`, `event_reminder`, `event_departure`,
`poll_nudge`, `arrived`, `action_approved`, `action_denied`, `reaction`) are
shown with the server's title and body as they are, in a toast of their own
per kind (`chat-<id>-<kind>`) that a new message of the chat does not
replace; they are acked with the chat (`parseChatNotification` → `pushKind`,
`deepLink`, `reminderId`). The server already respects `dnd`, `notify.*` and
mutes.

### The settings page (apps)

"Chat-Einstellungen" is a page over the chat view (gear in the list head),
sections on the left: **Konto** (profile, status, "Im Portal ändern"),
**Datenschutz** (last seen, picture, status default, place in status, groups,
default disappearing timer, read receipts, "schreibt …", blocked people),
**Benachrichtigungen** (preview, mentions only, reactions, status digest,
event reminder; the sound of this PC), **Chats** (Enter sends, font size,
archived chats stay archived, export), **Listen**, **Erinnerungen**,
**Speicher** (`storage()`: server quota full or not, largest file, retention;
caches of this PC, `clearMediaCache()`), **Haus-Aktionen** (which actions the
attach menu shows — this PC). Without `privacy2` / `msg_tools` / `actions`
the page keeps the 1.0 settings (read receipts, typing, preview). Settings of
this PC are in `localStorage` (`gc.chat.enterSends`, `gc.chat.fontSize`,
`gc.chat.sound`, `gc.chat.hiddenActions`).

## Messenger 1.6: the chat as the place for all notifications

With `GET me` features `notices` / `notice_routes` (both known, no update
hint) GateControl's notifications can arrive in chats (core 1.191 push
routes, see notification-center.md § 10):

- the chat list: "Mein Status" (status strip) above "Angeheftet"; under it
  the "GateControl" entry, then the chats the server pins to the list
  (`listPinned: true`, the family group the Familie plugin keeps), then
  "Chats" with the rest. Filters apply to both; while searching pinned chats
  appear among the results.
- notice channels (`notice: { source, label }`, read only, every `can` flag
  false, `managedBy: 'gatecontrol-messenger'`): tag "Mitteilungen" in the
  list and the chat info (no "kept by a plugin" hint).
- notice cards (`kind: 'card'`, `card.kind: 'notice'`, `card.notice {
  source, sourceLabel, topic, topicLabel, priority, data }`): head line
  "<sourceLabel> · <topicLabel>", the title, the whole text (≤ 4000, line
  breaks kept), the core picture `card.imageUrl` (`/notify-media/…`, loaded
  over the device token: `noticeImage(path)`, memory cache only), actions as
  on other cards and the link (`link.route` may name a plugin screen after a
  `/`, e.g. `plg-gatecontrol-schule/messages/<id>`) that opens what a click on
  the notification would (`notify:open`, see notification-center.md).
- "Wo Mitteilungen erscheinen" in the chat settings (and in Einstellungen ›
  Benachrichtigungen): per source each kind with GateControl / Familien-Chat
  (only with `canFamily`, "Für alle in Familie sichtbar") / Eigener Chat
  „<Quelle>“; locked kinds with a lock ("immer GateControl"), without a sink
  the hint that the Messenger plugin is needed.

## Messenger 1.11: the host's virus scan

With `GET me` features `scan` (known, no update hint; GateControl 1.223.0):
`message.media.scan { state, blocked, finding }` comes as the plugin sends it
(blocked: no `url` / thumbnail, the media route answers 423); utils/scan.js
`view(scan)` says what to show (`checking`, `malware`, `unscannable`,
`warning`, `notCheckable`), the texts are the core's i18n `scan.*` (DE / EN).

- Sending: 422 `infected` { finding } / 423 `scan_blocked` → the outbox entry
  is `failed` with `error` and `finding` (never sent again by itself;
  „Nicht gesendet – Schadsoftware gefunden“). A file still being checked is sent.
- `message.update { scan }` → `changedSince` = editedAt − 1 s (the message's own
  `editedAt` stays: not "edited"); a blocked file's bytes in the memory cache
  are dropped.
- `chat:media` / `chat:media:save` of a blocked file → `{ ok: false, code:
  'scan_pending' | 'quarantined' | 'scan_blocked', scan?, finding?, retryAfter? }`.

## Messenger 1.13 / 1.14: linked services and chats over a bridge

Both parts are detected by feature words of `GET me`, never by a version:

* `linked_services` (1.13) — the server offers a bridge to another messenger
  (today WhatsApp). „Verknüpfte Dienste“ in the chat settings links the
  person's OWN account: `bridges()`, `bridgeConsent(network)`,
  `bridgeLogin(network, 'phone' | 'qr')`, `bridgeStep(network, processId,
  stepId, { phone?, fieldId? })`, `bridgeCancel`, `bridgeUnlink`. A step comes
  back normalized (`utils/messenger.js` `normalizeBridgeLogin`): `phone` (the
  number is asked for), `code` (the pairing code), `qr` (the code's modules
  `matrix: { size, rows }` — the page draws them, there is never a picture
  address), `complete`, `unsupported`, or `{ waiting: true }` (ask again; the
  server waits up to 15 s per call, so these calls get 30 s). The number is
  checked in the main process (`bridgePhone`), sent once and never stored or
  logged; the same holds for the pairing code and the QR content. Refusals:
  `bridge_off`, `consent_required`, `bridge_locked`, `bridge_unsupported`,
  `bridge_failed` (with `reason`, e.g. `timeout`), `bridge_unreachable`,
  `rate_limited`; the IPC answer carries `reason` as well.
* `bridge_chats` (1.14) — set only for a person who HAS a chat over a bridge.
  Such a chat exists only for a client that says so: every call below
  `conversations` and `messages` carries `?bridged=1` (`MessengerApi.bridged`)
  as soon as the server names `linked_services` or `bridge_chats`, or an event
  (`message.new` with `bridge`) or a chat push (`data.bridge`) named such a
  chat (`MessengerService.noteBridge()` — it also reads `GET me` again, since
  the word appears with the first chat). An older plugin never gets the mark;
  its requests are byte for byte what they were.

What a bridged chat looks like to the page: `conversation.bridge` (`network`,
`label`, `state`: ok / unreachable / logged_out / unlinked / locked / off,
`closed`), no `peer`, one member; `typingContacts` (`[{ contactId, name }]`)
next to `typing`; `message.bridge` (`sender` — the contact, `remote`, `state`,
`reason`, `placeholder`). `messageStatus()` answers `failed` / `pending` for
the bridge's word on an own message. Only a text crosses a bridge: `send()`
refuses everything else with `bridge_text_only` before it is queued, and the
outbox does not retry a `bridge_*` refusal (the server keeps no queue for the
other messenger) — the message shows why and can be sent again. A message the
server stored but the bridge did not take (`bridge.state: failed`) goes out
again with `resend(messageId)`.

The push of such a chat reads „Kim Muster · WhatsApp“ (without preview „Neue
Nachricht über WhatsApp“ and no text); a group keeps the service in its title.
Its actions carry `bridged: true` in their body and are sent on unchanged.

### Messenger 1.15: files, pictures and a new chat by number

Again only feature words, set by the server together with `bridge_chats`:

* `bridge_media` — files cross the bridge. Per chat only `conversation.bridge`
  decides: `supports` adds `image`, `video`, `voice`, `file`, `mediaTypes`
  names the types per kind (`null` = any; WhatsApp: no `audio/webm`).
  `send()` lets a picture, voice message or file through when its kind and
  type are named (`bridgeMediaRefusal`: a file of `video/*` is a video) and
  refuses the rest before it is queued — `bridge_text_only`, or
  `bridge_media_type` with `reason` image / voice / video. Should the server
  still refuse the type, the pending message keeps `reason`. A `423
  scan_pending` (the virus scan of the upload is not finished) is not a
  failure: the outbox sends the same entry (same `clientId`, no new upload)
  again after `Retry-After`, for up to about five minutes; this holds for
  every chat. Files coming in arrive as `bridge.placeholder` (`state`
  loading / failed + `reason` / null + `geo`) and, once fetched, as
  `message.update { media: true }` — read like any edit. The chat's picture is
  `conversation.avatarMediaId`, a contact's `message.bridge.sender.avatarMediaId`
  (`media(id)` like a group picture).
* `bridge_new_chat` — a chat by phone number: `bridgeResolve(network, number,
  cc)` → `{ found, name, avatarMediaId, existing: { conversationId } | null }`
  and `bridgeStartChat(network, number, cc)` → `{ conversation, created }`.
  The number is normalized in the main process (`bridgeNumber`: `cc`, default
  +49, for a number without one; a leading 0 goes; 00 and + keep their
  country), sent once per call and never stored or logged. The new chat is
  not in `GET conversations` until something was written in it, so a full
  read of the list keeps it. `GET bridges` names per service `newChat`
  (`available`, `reason`, `limit`; Messenger 1.16) — `null` from a plugin
  without it. Refusals: `invalid_number`, `rate_limited` (with `retryAfterS`
  and, 1.16, `perHour` in the IPC answer), `bridge_unlinked` (`reason`
  unlinked), `bridge_logged_out` (1.16; 1.15: `bridge_unlinked` with `reason`
  logged_out),
  `bridge_locked`, `child_new_chat_off`, `bridge_unreachable`, `bridge_off`,
  `not_found` (`reason: not_on_network`).

### Messenger 1.17: older history, the phone, „Brücke veraltet“

One feature word, `bridge_history` — set only for people who linked a
service, and only when the server can take older messages over (`gc.bridges`
version 5):

* `GET bridges` → `history` `{ available, days, default, options, pending }`
  (`normalizeBridgeHistory`; `null` = the server has none: the row is left
  out). `setBridgeHistory(days)` — `0` (off), `30` (days), `-1` (everything),
  checked before anything is asked — → `PUT bridges/history { days }` → the
  new `history`. The choice holds at the next link (WhatsApp sends the
  history only then); fewer days drop at once what still waits.
* Older messages come at night, without push and without `message.new`, as
  read: per chat and portion one `conversation.update { reason: history }`.
  The chat that is open (`setOpen`) loads its newest messages again
  (`messages` with `reason: 'history'`; the view stays where it is), any other
  chat's cached messages are dropped and loaded when it opens. No toast, no
  sound.
* Files of the history wait for a click: `bridge.placeholder.state` is
  `on_request`; `fetchBridgeFile(id)` → `POST messages/:id/fetch?bridged=1`
  (empty body) → the message, its placeholder then `loading`; the file follows
  like any other (`message.update { media: true }`). `400 invalid` when there
  is nothing to fetch; very old files end as `failed` / `gone`.
* Per service `phone` `{ offline, days, leftDays }` (`normalizePhone`; the
  bridge warns after 12 days, WhatsApp ends the link after about 14) and
  `clientOutdated` (WhatsApp refuses the bridge's version — shown like
  `outdated`). The push of the new topic `bridge`
  (`plugin:gatecontrol-messenger:bridge`, „WhatsApp: Handy seit N Tagen nicht
  gesehen“, data
  `{ deepLink: 'bridges', bridge }`) is an ordinary inbox entry with its toast;
  `ChatNotifier` claims a click on it for the chats' app route
  (`bridgePushContext` → navigate `{ route: 'plg-gatecontrol-messenger',
  context: { type: 'bridges', bridge } }`): the app opens „Verknüpfte Dienste“.

### Messenger 1.18: „Neuer Chat“ with contacts

One feature word, `bridge_contacts` — set only for people who linked a
service, and only when the server has `gc.bridges` version 6. Without it the
new chat by number of 1.15 / 1.16 stays as it was.

* `newChatContacts(network, q)` → `GET contacts/new-chat?network=&q=`
  (`q` ≤ 100 characters, the search as typed) → `normalizeNewChatContacts`:
  `{ network, query, gatecontrol, whatsapp, addressBook, addressBookReason,
  number, numberEntry, limit }`. `gatecontrol` are the accounts as in
  `GET people` (+ `conversationId`), `whatsapp` `null` (left out) or
  `{ state: ok | unreachable | logged_out, total, items }` — the contacts of
  the bridge, by name, with a sealed `ref` and never a number
  (`alsoInAddressBook`, `avatarMediaId`, `conversationId`). `addressBook`
  (`null` without WhatsApp, Mail or numbers) follows the WhatsApp `state`;
  its `phones` are sorted mobile, work, home, other (`key`, `kind`, `number`,
  `e164`, `landline`, `notOnNetwork`). `number` `{ e164, show,
  conversationId }` when the search looks like a number, `numberEntry` =
  offer „Nicht dabei? Nummer eingeben“. Listing and searching ask the
  service nothing.
* `bridgeContactChat(network, contact)` → `POST bridges/:network/chats` with
  `{ ref }` (a WhatsApp contact: started at once, nothing checked or counted)
  or `{ contactId, phoneKind }` (an address book number: checked now, counted
  in the brake of „Nummer eingeben“) → `{ conversation, created }`, kept in
  the list like a chat by number. Refusals: `contact_expired` (the reference
  ran out — load the list again), `not_found` with `reason` `not_on_network`
  (`remembered: true` = from the server's 30-day memory, nothing asked) or
  `contact_gone`, `rate_limited` (`retryAfterS`, `perHour`),
  `bridge_unreachable` / `bridge_off`, `bridge_logged_out`, `mail_missing`,
  and those of 1.15.
* Neither the search nor a name or number is logged or kept in the main
  process.

### Messenger 1.20: channels, read-only groups, format, link previews

One feature word, `bridge_channels` — for the same people as `bridge_chats`, on a server with `gc.bridges` version 7.
Without it everything stays as it was (a channel is then a read-only chat in the list, as in older apps).

* With the word the calls carry `?channels=1` next to `?bridged=1` (and a push button with `bridged: true` in its body
  gets `channels: true`). `GET conversations` has **no channels** then — they are not in `listConversations()`, not in
  `unreadTotal()` (nav badge, tray) — but `channels: { count, unread }` (`normalizeChannelSummary`).
* `refreshChannels()` → `GET channels` (`{ channels, removed, unread }`), read whenever that summary differs from the
  cached channels; `listChannels()` (channels with a post, the newest first), `channelSummary()` → `{ count, unread }` or
  `null` without the word; `status().channels` the same. A live event of a conversation not cached yet fetches it
  (`GET conversations/:id`) — a channel (`isChannel`: `bridge.channel`) goes to the channels. IPC `chat:channels`
  (`{ refresh }` → `{ ok, channels, summary }`), `chat:conversations` also answers `channels`.
* Conversations: `bridge.channel`, `bridge.readOnly`, `bridge.reactions` (`own` | `off`), `can.sendReason`
  (`channel` | `admins_only` | `null`), `can.react`. Sending into one → `409 bridge_read_only` with `reason`; reacting in
  a channel while off → the same with `reason: reactions_off`. The bell is `updateConversation(id, { notify })`.
* Messages: `marks` (bold, italic, strike, code, link — UTF-16 offsets into `text`) and `preview` (`url`, `title`,
  `description`, `site`, `image: { mediaId, mime, w, h, state }`) are passed through as the server sends them; the
  apps draw them (never as HTML). `bridge.channel: true` — a post of the channel (no sender name).
* The push of a channel's post (`data.channel`, only while its bell is on): the server's title „<Kanal> · Kanal über
  WhatsApp“ and the post, only „Als gelesen“ (`parseChatNotification` → `channel`).
* Independent of the word (since 1.19): `fetchBridgeFile(id)` (`POST messages/:id/fetch`) also fetches a file whose
  placeholder `failed` with `retry: true` once more — for every app that shows chats over a bridge.

### Messenger 1.21: persons („Personen zusammenführen“)

One feature word, `chat_people` — for the same people as `bridge_chats`. Without it everything stays as it was: the
ways of a person are separate chats in the list (as for older apps, and as the other person always sees them).

* With the word every call carries `?people=1` next to `?bridged=1` (a push button with `bridged: true` in its body
  gets `people: true`). `GET conversations` has **one entry per person**: the view of its lead conversation (the
  GateControl chat, else the oldest way) with `person` { id, name, nameFrom, userId, conversationId, names, ways, reply }
  — its `id` is the lead's; the other ways come as `folded` and leave the cache (`isPerson`, `personWayIds`).
* `GET conversations/:id` of a way names `person` → the service reads `GET persons/:id` and keeps the entry (a plain
  view never replaces a person's entry); `entryIdOf(id)` maps a way to its entry.
* Messages of an entry: `GET persons/:id/messages` — all ways mixed by time (`createdAt`, a tie by id; `mergeMessages(…,
  { byTime: true })`), `way` on each message, cursors of any way. `setWay(id, way)` (IPC `chat:person:way`) — the
  source chips: a filter loads its own page (`?way=`), is not stored and is never read there; `messagesView().way`.
  The ticks of GateControl messages come from `ways[gatecontrol].readUpTo / deliveredUpTo`.
* `send()` to an entry → the outbox posts `POST persons/:id/messages` (`personId`): the server picks the way (the way of
  the newest incoming message, a tie or none: GateControl; an answer the way of its message). The checks of the
  composer use that way (`replyWay(id)` → { way, label, conversationId, bridge, can }). After sending the entry is read
  again (`person.reply` may change).
* `markRead(entry)` → `POST persons/:id/read { upTo: newest shown }` (only in „Alle“); a way's id (a push's „Gelesen“)
  reads only that way. `setOpen()` pings `active` on every way; `typing()` goes to the way of the answer.
* `updateConversation(entry, { notify, mutedUntil })` → `PATCH persons/:id`; `archive()` → `POST persons/:id/archive`;
  `search()` → `GET persons/:id/search`; `pin()` pins in the message's way.
* Live events come per way → applied to the entry (a message, typing, read marks of the GateControl way);
  `conversation.update { reason: person }` (merged, renamed, split) → the list in full again and the suggestions.
* `suggestions({ refresh })` (`GET persons/suggestions`, at most every 15 min; event `suggestions`),
  `answerSuggestion(id, 'later' | 'never')`, `mergePersons({ conversationIds, userId?, name })` (`POST persons`; 409
  `cannot_merge` with `reason`), `splitPerson(entry, conversationId?)` („Trennen“, `DELETE persons/:id/ways/:cid`, the
  list again), `renamePerson(entry, 'account' | conversationId)`, `personCandidates(id)` (`GET persons/candidates`).
* `bridges()` carries `recognition` { available, network, asked, allowed } when GateControl has the call
  (`gc.bridges` version 9); `setRecognition(allowed)` → `PUT bridges/recognition` — asked once after WhatsApp was linked.
* The push of a way (`data.person` { id, conversationId }): the server's title „Jenny Backes · über WhatsApp“; a click
  opens the entry, the buttons stay on the message's way. A push of the open person shows no toast.

## Locations ("Standort senden")

A location message is `kind: "location"` with `location: { lat, lon,
label?, accuracy? }` (README "Sending"; `chat.send({ conversationId, kind:
'location', location, replyTo })`, outbox like every message). The apps show
a dialog with a map:

* **own position** — `navigator.geolocation` in the renderer, which Electron
  answers from the Windows location service (the apps start Chromium with
  `enable-features=WinrtGeolocationImplementation` on Windows; Electron has
  no key for Google's network location). Denied (Windows Settings ›
  Privacy & security › Location), unavailable or timed out → a notice, the
  map and the address search still work; `accuracy` is sent only for an own
  position that was not moved afterwards;
* **a point on the map** — click (drag moves, wheel / buttons / `+` `-`
  zoom, arrow keys move, Enter picks the centre);
* **an address** — search on Enter / button (`chat.mapSearch(q, lang)`);
  a picked point gets its address as label (`chat.mapReverse(lat, lon,
  lang)`), the label can be changed.

Received locations show a small map with a pin (and the accuracy circle),
label, coordinates and "In OpenStreetMap öffnen".

`MapService` serves the channels `chat:map:tile`, `chat:map:search` and
`chat:map:reverse` (`registerBaseHandlers` creates it with `app.getName()` /
`app.getVersion()` as User-Agent unless `ctx.maps` is passed):

| | |
|---|---|
| Tiles | `https://tile.openstreetmap.org/{z}/{x}/{y}.png`, at most 2 requests at a time (bounded queue → `busy`), one request per tile, memory LRU 32 MB for 24 h, a stale copy when the tile server fails |
| Addresses | `https://nominatim.openstreetmap.org/search` / `/reverse` (`jsonv2`, `accept-language`), one request at a time ≥ 1.1 s apart, the last 64 answers cached, labels shortened to "Straße Nr, PLZ Ort" |
| User-Agent | `<app name>/<version> (+https://github.com/CallMeTechie/gatecontrol)`, e.g. `GateControl-Pro-Client/1.30.0 (+…)` (OSM tile and Nominatim usage policies) |

Why not the server's tile relay (`/plugins/_shared/tiles/<token>/…`): its
token is minted only for the map frames of `ui.maps` plugins; a device token
cannot get one. Like the Android app, the client loads the tiles itself
with its own User-Agent. What leaves the PC: the map area shown and the
searched address / picked point, to OpenStreetMap — not the message.

## The pinned "GateControl" entry

The notification inbox as a chat (renderer, `window.gatecontrol.notify`):
it opens at the oldest unread entry (line "Ungelesene Nachrichten"), and
every entry is marked read once it has been in view (`IntersectionObserver`,
≥ 60 % of it, or half the list for a tall one) while the window is shown
and focused — `notify.read(ids)` → `NotificationCenter.markRead(ids)` →
`POST …/push/ack { seqs, state: "read" }` for just those entries (other
devices follow through the stream's `read`). Entries scrolled past without
being seen stay unread; "Alle als gelesen markieren" in the header reads
the rest.

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
| `listChannels()` / `channelSummary()` / `refreshChannels()` | Messenger 1.20 (`bridge_channels`): the page „Kanäle“ — channels with a post, `{ count, unread }` (null without the word), `GET channels` |
| `getMessages(id, { before, after, around })` / `messagesView(id)` | `{ conversationId, messages, pending, hasMore, hasMoreAfter, detached, offline }` |
| `supports(feature)` | `GET me` `features[feature] === true`, e.g. `video_meta`, `file_thumbs` |
| `updateHint()` / `dismissUpdateHint()` | unknown features switched on → `{ features, key }` / hide the banner for that set |
| `send(req)` / `retrySend(clientId)` / `discardSend(clientId)` | outbox |
| `edit(id, text)`, `remove(id, 'me'\|'all')`, `react(id, emoji\|null)` | |
| `markRead(id, upTo?)`, `typing(id, { stop })`, `setOpen({ id, visible })`, `setViewOpen(open)` | |
| `people()`, `createConversation(…)`, `updateConversation(id, patch, { avatar })`, `setPrefs(patch)`, `search(id, q)`, `mediaList(id, opts)` | |
| `media(mediaId)`, `avatar(path)` | `{ mime, data }` (memory LRU 48 MB / 8 MB) |
| `unreadTotal()` | unread messages of the chats that are neither muted nor archived (nav badge, tray) |
| 1.4.0: `statusFeed({ refresh })`, `setStatus(s)`, `clearStatus()`, `createStory(s)` (1.4.1: `durationH`), `deleteStory(id)`, `storySeen(id)`, `storyViewers(id)`, `storyReact(id, emoji)` | status and stories |
| 1.4.0: `archive(id, archived)`, `pin(id, messageId, pinned)`, `lists()`, `saveLists(lists)`, `blocks()`, `setBlocked(userId, blocked)`, `exportChat(id)`, `remind(messageId, at)`, `reminders()`, `deleteReminder(id)`, `suggest(messageId)`, `toList(messageId, { items, list })`, `toCalendar(messageId, ev)`, `places()` | chat tools, Familie |
| 1.4.0: `vote(id, optionIds)`, `addPollOption(id, text)`, `closePoll(id)`, `nudgePoll(id)`, `rsvp(id, answer, guests)`, `checkItem(id, itemId, done)`, `editEvent(id, patch)`, `stopArrival(id)` | → the changed message (cached one replaced) |
| 1.4.0: `actions({ refresh })`, `actionOp(id, op, { actionId, plugin })`, `cardImage(id)` | home actions, plugin cards |
| 1.6: `noticeImage(path)` | picture of a notice card (`/notify-media/…`, ≤ 1 MiB, image types only) → `{ mime, data }` |
| `storage()` / `clearMediaCache()` | caches of this PC and the server's limits |
| `resetForNewServer()` | |

Events: `state`, `conversations` `{ ids, removed }`, `messages`
`{ conversationId, reason }`, `typing` `{ conversationId, userIds }`,
`unread` (total), `outbox` `{ conversationId }`, `read-local`, `read-self`,
`send-failed` `{ conversationId, clientId, error, source }`; 1.4.0: `feed`
(the status feed), `lists`, `reminders`.

### IPC / bridge

`window.gatecontrol.chat`: `status`, `check`, `conversations`, `conversation`,
`messages`, `send`, `retry`, `discard`, `edit`, `remove`, `react`, `read`,
`typing`, `open`, `view`, `people`, `create`, `update`, `prefs`, `search`,
`mediaList`, `media`, `avatar`, `saveMedia`, `openMedia`, `mapTile`,
`mapSearch`, `mapReverse`, `dismissUpdateHint`; 1.4.0: `statusFeed`,
`setStatus`, `clearStatus`, `createStory`, `deleteStory`, `storySeen`,
`storyViewers`, `storyReact`, `blocks`, `block`, `archive`, `pin`, `lists`,
`saveLists`, `exportChat` (save dialog), `remind`, `reminders`,
`deleteReminder`, `suggest`, `toList`, `toCalendar`, `places`, `poll(id, op,
args)`, `event(id, op, args)`, `stopArrival`, `actions`, `action(id, op,
args)`, `cardImage` (`{ mime, data: Uint8Array }`), 1.6: `noticeImage(path)`
(`{ mime, data: Uint8Array }`), 1.13 / 1.14: `bridges`, `bridgeConsent`,
`bridgeLogin`, `bridgeStep`, `bridgeCancel`, `bridgeUnlink`, `resend`, 1.15:
`bridgeResolve(network, number, cc)`, `bridgeNewChat(network, number, cc)`,
1.17: `bridgeHistory(days)`, `fetchFile(id)`, 1.18: `newChatContacts(network, q)`,
`bridgeContactChat(network, contact)`, `storage`, `clearCache`; events `onState`, `onConversations`, `onMessages`, `onTyping`,
`onUnread`, `onOutbox`, `onNavigate` (`{ conversationId }`, toast click),
`onFeed`, `onLists`, `onReminders`. Arguments and answers:
`src/ipc/messenger-handlers.js`. Every call resolves; failures are
`{ ok: false, code, error }` — `chat.error.<code>` has the text.

## Known limits

* The own position needs the Windows location service (and "Let desktop
  apps access your location"); without it, a point on the map or an
  address is sent.
* Disappearing chats are shown and switchable in the chat info; the server
  deletes the messages and the client drops them on `message.delete`
  (`expired`).
* The toast reply field needs Electron's `Notification.handleActivation`
  (Electron 44 in both apps) and the app's start-menu shortcut (AUMID), like
  every Windows toast; the portable build shows no toasts.
* End-to-end encryption is not part of V1. Chats over a bridge carry text
  only with Messenger 1.14; files, voice messages, pictures of contacts and
  "new chat with a number" come with 1.15 (`bridge_media`, `bridge_new_chat`),
  older history with 1.17 (`bridge_history`), „Neuer Chat“ with contacts with
  1.18 (`bridge_contacts`).
* Live arrival is shown, not sent: Windows PCs have no reliable GPS. The
  departure hint push of an event opens the chat.
* Server storage: the server reports only whether the chat file quota is
  full and the largest file (`limits.quotaFull`, `maxBytes`), not the bytes
  used.
