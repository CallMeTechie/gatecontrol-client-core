# Notizen & Aufgaben in the Windows apps

The page "Notizen & Aufgaben" of the Pro app is the client of the plugin `gatecontrol-notizen` (1.0.0, plugin README
"API"). Core holds the data side; the Pro app builds the page (notes-view.js).

| Part | File | What |
|---|---|---|
| API | `src/services/notes-api.js` | every route of the plugin (`/api/v1/client/plugins/gatecontrol-notizen/api/…`), media up (`PUT …/media`, resumable) and down (`/plugin-media/<token>`, the signed `url` of an attachment) |
| Answers, arguments | `src/utils/notes.js` | Task, Item, List, Notebook, NoteSummary, Attachment, the views and the menu cleaned; what the renderer may send; push targets; a check box of the Markdown (Tresor notes) |
| Service | `src/services/notes.js` | availability (plugin listed — a plugin without licence is not — and `GET me` lets the person in; `status().features` = `me.features`), live events (`changed`, `vault`), push clicks, attachments (open, save, a picture's bytes, the recognised text of a picture via Windows.Media.Ocr), the moves |
| Tresor | `src/services/notes-vault.js` | Drive's vault flows (`services/drive-vault.js`) with Drive's format and every label `gcnotes-v1` (`utils/drive-vault.js withPrefix`), the device key under DPAPI (store `notesVault`), the lock (`services/drive-vault-lock.js`, store `notesVaultLock`: Windows Hello, 15 minutes, when the window is left, Windows locked) |
| DS Note | `src/services/notes-import.js` | the `.nsx` export read on this PC with the plugin's own reader (`src/vendor/notizen/nsx.js`), protected notes with the password into a new Tresor made here |
| Shopping lists | `src/utils/notes-shopping.js` | plugin 1.4.0: the lists and items as the server said last (`since`, tombstones), the queue of operations on top |
| IPC | `src/ipc/notes-handlers.js` | `notes:*` channels (arguments checked), events `notes:state`, `notes:changed`, `notes:vault`, `notes:vault-lock`, `notes:import`; bridge `window.gatecontrol.notes` |

`src/vendor/notizen/` holds the plugin's `ui/quickparse.js`, `ui/repeat.js` and `ui/nsx.js` unchanged (the Pro app's
renderer loads its own copies of the first two; a Pro test checks they are the same files). Tests:
`test/notes-places.test.js` (plugin 1.5.0), `test/notes-shopping.test.js` (plugin 1.4.0), `test/notes.test.js` (the plugin's frozen vectors of the quick entry, the repeat rules and the Tresor format; the service
against `test/fixtures/notes-server.js`, which the Pro app's e2e runs use too).

Opening an item of another plugin (contract § 5): the Pro app maps Mail `message/<id>`, Drive `node/<id>` and Schule to
its own pages; everything else opens the plugin's portal tab (the portal link cannot carry the route).

## Plugin 1.3.0: reminders with buttons, „Gestern offen geblieben“, the calendar

Told by `me.features` only (never by a version): `reminderActions`, `yesterdayOpen`, `taskCalendar`. An older plugin
sends none of the fields, and the service refuses the new calls with `unsupported` before the server is asked.

| What | Where |
|---|---|
| A task's `reminder` ({ tag, at, atMs, mine, snoozed }), `snoozed`, `missedReminder`, `calendar` ({ state, eventId, calendarId, mine }), `canEdit` | `normalizeTask` |
| `me.calendar` ({ available, enabled, mine, name } — the calendar shows only when all three are true), `me.yesterday` ({ push, at }) | `normalizeMe` |
| The card: `view.yesterday` of `views/myday` ({ day, title, count, items, moveOptions }), `GET yesterday`, `POST yesterday` | `normalizeYesterday`, `yesterday()`, `decideYesterday()` — IPC `notes:yesterday`, `notes:yesterday:decide` |
| A row to another day: `POST tasks/<id>/move { to }` (`today`, `tomorrow`, `weekend`, a date) | `moveTask()` — IPC `notes:task:move` |

Pushes (topic `reminders`): the buttons of a reminder (Erledigt, In 1 Std., Heute Abend) are `callback` actions — the
notification center shows them on the toast and answers them with the ack, nothing of the service is needed. The
morning hint (`data.notizen.kind === 'yesterday'`) opens „Mein Tag“ with the card: `pushTarget()` answers
`{ kind: 'yesterday', day, taskIds, action }`; its buttons „Erledigt“ (several tasks, `done_ask`) and „Verschieben“
(`move`) arrive as links to the plugin's portal tab (the plugin has no app tab) and open the page instead
(`NotificationCenter.addClickRoute`: the resolver gets the pressed button, `context.action`).

The Windows apps set **no alarm of their own** (`GET reminders`, `POST tasks/<id>/snooze` are not called): the app
holds the push stream while it runs, and a closed app has no background alarm on Windows that would be worth the same.

## Plugin 1.4.0: shopping lists, a list at a task

Told by `me.features` only (never by a version): `shoppingLists`, `taskList`, `familyShopping`. An older plugin sends
none of the fields; the service refuses the new calls — and a task body with `attachedListId`, `attachedListUid` or
`attach`, which an older plugin would pass over in silence — with `unsupported` before the server is asked.

| What | Where |
|---|---|
| A shopping list ({ id — the text id the device made, listId — the list's number, name, icon, area, role, canEdit, canManage, owner, members, shared, family, open, total, assignee, going, tasks }), an item ({ id, listId, text, qty, checked, checkedBy }) | `normalizeShopList`, `normalizeShopItem`, `normalizeShopping` |
| The menu's `shopping` (not part of `lists`), `me.shopping.family` ({ available, bound, parent }), `me.listIcons` | `normalizeNav`, `normalizeMe` |
| A task's `attachedList` ({ id, uid, name, icon, open, total, done, family } or null) | `normalizeTask` (`attachedListOf`) |
| Writing it: `attachedListId` (a number, null takes it off) or `attachedListUid`; POST tasks also `attach: 'auto'` | `taskPatch`, `taskCreate` |
| The suggestion of the quick entry: `attach` of POST parse and POST tasks ({ via: tag / name / word, word, list, lists }) | `normalizeAttach`, `parse()` → `{ parsed, attach }`, `createTask()` → `{ task, parsed, attach }` |
| The operations of POST shopping/ops as the renderer may send them (list_add, list_rename, list_delete, item_add, item_edit, item_check, item_delete, clear_checked; ≤ 200) | `shopOp`, `shopOps` — IPC `notes:shopping:ops` |
| The lists between two calls: `since`, tombstones, the queue | `utils/notes-shopping.js` |

`NotesService.shopping()` answers `{ lists, items, pending, stale, completed }`: the first call asks `GET shopping`,
every later one `GET shopping?since=<serverTime>` (`lists` is always complete — a list that is missing is gone with its
items; a list the device did not know is fetched once without `since`; `{ full: true }` asks without `since`).
`shoppingOps(ops)` shows the change at once and puts it into a queue: sent in order, 200 a call, stored
(`notesShopQueue`, for this server and person only) and sent again unchanged after a network error, a 5xx or a
reconnect of the push stream — the ids of new lists and items are made on the device (the IPC makes them with
`crypto.randomUUID()` when the renderer names none), so a repeated batch never makes anything twice. What the server
rejects (`rejected: [{ op, id, listId, code }]`) is dropped and never sent again; the next answer is then taken whole,
so the page is put right. `completed` names the tasks the server completed because the last open item of their list
was ticked („Alles abgehakt“); „Rückgängig“ is `completeTask(id, false)` and unticks nothing.

A shopping list is renamed and deleted with the ops (`list_rename`, `list_delete`: `canManage`); shared and left
through the list routes with its number (`notes:list:members`, `notes:list:delete` with `listId`); a deleted list
comes back with `shoppingRestore(listId)` (`POST lists/<n>/restore`: its owner, within 30 days). Family lists
(`familyShopping`, `me.shopping.family.available`): `shoppingFamily(uid, on)`, `shoppingGoing(uid)`,
`shoppingAssign(uid, { userId, dueAt?, notify? })` — handed to Familie by the hub.

Live: `changed { what: ['shopping'] }` (the numbers of `attachedList` may have changed too; `tasks` comes with it when
a list completed a task). Push: a reminder of a task with a list carries `data.notizen.attachedList` and the button
`open_list` („Liste öffnen“, `open_app_route` → `plg-gatecontrol-notizen`); `pushTarget()` answers
`{ kind: 'shopping', uid, listId, taskId }` for that button, the Pro app opens the list to tick off. A click on the
message itself, the other buttons and an older plugin stay what they were (`{ kind: 'task' }`).

The Windows apps have no shopping list of the Familie plugin (the page „Familie“ shows „Internet zu Hause“, the rules
and the presence), so there is nothing to move over on this side; the family's lists show under „Notizen & Aufgaben“
once the hub owns them.

## Plugin 1.5.0: a task at a place

Told by `me.features` only (never by a version): `places`, `placeSearch`. An older plugin sends none of the fields; the
service refuses the new calls — and a task body with `place`, a prefs patch with `places`, which an older plugin would
pass over in silence — with `unsupported` before the server is asked.

**A Windows PC watches no place.** The phone of the person the task belongs to holds the geofences and shows the
reminder; `POST places/watch`, `POST places/fired`, `POST tasks/<id>/place/skip` and `…/later` are the phone's and are
not called from here (there is no method for them). A PC shows the place and the trigger and lets both be changed.

| What | Where |
|---|---|
| A task's `place` ({ mode: `place` / `any`, id, name, address, lat, lon, radius, ref, own, trigger: `enter` / `exit`, key, label, by, consent, watch, nearby, skipped, later } or null) | `normalizeTask` (`taskPlaceOf`) |
| Writing it: `place` of `PATCH tasks/<id>` and `POST tasks` — null (take it off), `{ placeId }`, `{ familyId }`, a search hit unchanged (`{ ref, name, address, lat, lon }`; without `ref` a point), `{ any: true, key }` („Jeder Lidl“), `{ trigger }` alone; with `trigger?`, `key?`, `label?`, `remember?`. `POST tasks` also `place: 'auto'` | `placeArg`, `taskPatch`, `taskCreate` |
| The suggestion of the quick entry: `place` of POST parse and POST tasks ({ via: own / family / kind / address / name, word, query, key, label, title, certain, trigger, place, uses, options, search }) | `normalizePlaceSuggest`, `parse()` → `{ parsed, attach, place }`, `createTask()` → `{ task, parsed, attach, place }` |
| „Meine Orte“: `GET places` ({ places, family, favs }), `POST places`, `PATCH` / `DELETE places/<id>`, `PUT places/favs` | `normalizePlaces`, `normalizePlace`, `placeCreate`, `placePatch`, `favArg` — `places()`, `createPlace()`, `updatePlace()`, `deletePlace()`, `setPlaceFav()`; IPC `notes:places`, `notes:place:create` / `:update` / `:delete` / `:fav` |
| The search: `POST places/search` | `placeSearchArg`, `normalizePlaceSearch` — `searchPlaces()`; IPC `notes:place:search` |
| The consent for a place someone else set: `POST tasks/<id>/place/consent { accept }` | `placeConsent()`; IPC `notes:task:place:consent` |
| `me.places` ({ search: { state, enabled, mine, service, radiusKm, attribution }, nearby, quiet, perTask, radius, family }), `prefs.places` ({ search, nearby, quiet }) | `normalizeMe`, `normalizePrefs`, `placePrefsArg` (IPC `notes:prefs:set { patch: { places } }`) |

The parser on the PC (`src/vendor/notizen/quickparse.js`) and its frozen vectors are **unchanged**: the place of a typed
line comes from the server (`POST parse`), not from the parser.

The search and the position. A PC has no position of its own, so — as the plugin's portal does — a search is made near
one of the person's places: `nearPlaceId` (one of „Meine Orte“) or `nearFamilyId` („Zuhause“, a rule place of
Familie). `placeSearchArg` lets nothing else through: `near { lat, lon }` from the renderer is dropped, a search without
a place to search near is refused (only an address may be searched without one). So no coordinates of a position ever
leave this PC; the server rounds the place's point as it rounds every position, and `distanceM` / `minutes` of a hit
are counted from that place („zunächst aus der Entfernung geschätzt“ — no real travel time). The answer's `cell` (the
rounded point) is not handed to the page. `searchPlaces()` is only ever called because the person asked for it (a
button, Enter) — never per key stroke, never on a timer; while `me.places.search.state` is not `on` (the administrator
or the person switched it off, an own service is not set up) the server is not asked at all (`module_off` /
`unavailable`). The server's own answers arrive with their code: `module_off` (403, `reason: admin | self`),
`unavailable` (503), `busy` (429, `retryAfter` seconds in the IPC's failure), `invalid`, `not_found`. No map service is
ever asked directly. `attribution` („© OpenStreetMap“ with its link, https only) is to be shown wherever hits are shown.

Consent. The place of a task is watched by the phone of the person the task belongs to (assigned, else who made it). A
place someone else set is `consent: 'pending'` and `watch: false` until that person agrees: in the page with
`placeConsent(id, true | false)`, or on the push „… möchte dich erinnern“ (topic `shared`,
`data.notizen.kind === 'place_consent'`) — its buttons „Annehmen“ / „Ablehnen“ are `callback` actions the notification
center shows on the toast and answers itself; a click on the message opens the task (`pushTarget()` →
`{ kind: 'task', taskId }`).

Live: `changed { what: [..., 'places'] }` (a task with a place made, changed or done, the consent, own places, the
switches) — the page fetches again; there is nothing to re-register on a PC.

## Plugin 1.6.0: whose turn, stars, the family's list

Told by `me.features` only (never by a version): `taskTurns`, `taskStars`, `familyTasks`, `doneFeedback`, `placeMine`.
An older plugin sends none of the fields; the service refuses what an older plugin would pass over in silence — a task
body with `turn`, `people` or `stars`, `completeTask(id, done, userId)`, `familySeen()`, a prefs patch with `feedback` —
with `unsupported` before the server is asked.

| What | Where |
|---|---|
| A task's `turn` (`rotate` „reihum“: `assignee` is who is on now / `first` „wer zuerst“: nobody is assigned, the task is for everybody in `people` / null), `people` ([{ id, name }], [] without a turn), `stars` (0: none), `doneBy` (who it was ticked off for), `family` (a task of the family's list) | `normalizeTask` |
| Writing them: `turn` (null / `rotate` / `first`), `people` (ids, in order), `stars` (0…10) of `POST tasks` and `PATCH tasks/<id>`; with `rotate` `assigneeId` says who starts | `taskPatch`, `taskCreate`, `peopleArg` |
| What the typed line says: `parsed.people`, `parsed.turn`, `parsed.stars` (and the cleaned `title`) of POST parse and POST tasks; `listId` of POST parse — the list the line is typed in, only there the server reads stars | `normalizeParsed`, `parse({ text, area, listId })`; IPC `notes:parse ({ text, area, listId? })` |
| The family's list: `List.family` (at most one), `me.familyTasks` ({ available, bound, listId, parent, stars, starsMax, moved: { at, tasks, places, seen } / null }) | `normalizeList`, `normalizeMe` |
| A parent ticks off for a member of the family: `POST tasks/<id>/complete { done, userId }` | `completeTask(id, done, userId)`; IPC `notes:task:complete ({ id, done, userId? })` |
| The note „Umzug abgeschlossen“ was read: `POST family/seen` | `familySeen()`; IPC `notes:family:seen` |
| The message to a parent when a child ticks off: `prefs.feedback` (`all` / `stars` / `off`) | `normalizePrefs`; IPC `notes:prefs:set { patch: { feedback } }` |
| Who may accept a place: `place.mine`, `place.canConsent` (only when the server sends them — without `placeMine` the page decides as before) | `normalizeTask` (`taskPlaceOf`) |

Whose turn from the typed line. The parser (`src/vendor/notizen/quickparse.js`) and its frozen vectors are **unchanged**
(a test holds their checksums). Several people („@Mia @Jonas“), „reihum“ / „wer zuerst“ and „2 Sterne“ are read by a
second small module **after** the parser: `src/vendor/notizen/turnwords.js` — the plugin's own `ui/turnwords.js`,
unchanged, with its vectors `test/fixtures/notes/turnwords-vectors.json` (16 cases, all of them checked in
`test/notes-family.test.js`). `TW.apply(parsed, { people, stars }) → { title, people, turn, stars }`; `stars: true` is
passed only when the person may give stars and the task goes into the family's list (`me.familyTasks.bound && parent &&
stars`, the list is `familyTasks.listId`). The server reads the line the same way (`POST parse`, `POST tasks { text }`);
what does not fit there (somebody is no member of the list, stars without the right) is dropped in silence.

What a child may is enforced by the server; the page follows `canEdit` / `canComplete` of a task and
`me.familyTasks.parent`. The server's answers arrive with their code and — in the IPC's failure — `reason` / `field`:
`invalid` (`field: turn | people | stars | userId`; `reason: family` for stars outside the family's list),
`not_member` (409, `field: people`), `forbidden` (403, `reason: parents_only` — a child gives stars, changes a task of
the parents or ticks off for somebody else; `reason: family` — the family's list is deleted, left or shared: that is
decided by the Familie plugin). The stars are counted and settled in the Familie plugin; the hub only carries the number
at the task.

Pushes. „… hat ‚…‘ erledigt“ (topic `shared`, `data.notizen.kind === 'done_feedback'`) carries two buttons: „Ansehen“
(`open_app_route`) opens the task like a click on the message (`pushTarget()` → `{ kind: 'task', taskId }`), „Noch nicht
fertig“ is a `callback` action the notification center shows on the toast and in the inbox and answers itself — the
server opens the task again and takes the stars back; the same is reached with `completeTask(id, false)`. „Erledigt von
…“ (topic `reminders`, kind `reminder_done`, no buttons) comes with the collapse key of the reminder (`task:<id>`) and so
replaces the reminder of a task „wer zuerst“ somebody else did; a click opens the task (it names it as `taskId`).

The test server (`test/fixtures/notes-server.js`) has the 1.6.0 routes and fields only with these words in `features`
(`STAGE4`); its default stays an older plugin. `srv.addFamily()` makes the family's list; `state.user` decides who asks.

## Plugin 1.7.0: the reminders of Drive's deadlines ring from here

Told by words only (never by a version): `driveDeadlines` in the hub's `me.features`, `deadlineHub` in Drive's (there
only while the hub rings). An older plugin sends none of the fields; nothing new is asked — there is **no new route
and no new kind of push**. Such a reminder is an ordinary task of the hub with an ordinary reminder: it is completed,
put off, changed and deleted with the calls of every task.

| What | Where |
|---|---|
| A task's `deadline` ({ date, kind: `payment` / `cancellation` / `objection` / `warranty` / `renewal` / null, file, daysBefore (0…90, 0: on the day itself), open: { plugin, route } / null } or null — every other task, an older plugin) | `normalizeTask` (`deadlineOf`) |
| `me.driveDeadlines` ({ available, active } or null — a hint for a line of help, the same for everybody) | `normalizeMe` |
| Who rings a reminder of a deadline in Drive: `Deadline.reminder.by` (`notizen` / `drive`; an older Drive names nobody: `drive`) | `utils/drive.js normalizeDeadline` |
| The file of the button „Datei öffnen“ of the reminder's push (`data.notizen.deadline.open`) | `pushFile(topic, data, actionId)` |

„Datei öffnen“. `deadline.open` is the same form as an item's `open` (contract § 5): the Pro app opens Drive's
`node/<id>` on its Drive page. The reminder's push carries four buttons — „Erledigt“, „In 1 Std.“, „Heute Abend“
(the `callback` actions of every reminder) and „Datei öffnen“ (`open_file`), which the server sends as a link to the
portal (`open_portal`, `/portal?drive=<id>#plg-gatecontrol-drive`). `DriveService.clickContext(entry, action)` claims
that button while Drive is available and the push names a file of Drive: the notification center then opens the Drive
page with `{ kind: 'deadline', nodeId, deadlineId: null, areaId: null, action: 'open_file' }` — the context of a click
on Drive's own deadline message — instead of the portal (`NotificationCenter.performAction`: an `open_portal` button
whose path leads to the claiming page's own portal tab, `utils/portal.js portalTab`, the query does not matter).
`NotesService.clickContext` leaves that button alone; without a Drive page it stays the link to the portal the server
sent. A click on the message itself opens the task, as with every reminder.

No alarm of its own, still: the Windows apps do not call `GET reminders`, so there is no local alarm to add a button
to, and the Drive page sets no alarm for a deadline either — for a reminder `by: 'notizen'` Drive sends no message of
its own, the hub's push is the one message. The page says „über Notizen & Aufgaben“ at such a reminder.

Deleting such a task means „no reminder of this deadline“ (neither the hub nor Drive rings until another reminder is
set in Drive); the deadline stays in Drive. The page says so where the task is deleted.

The own role in a list and a notebook is `owner` / `write` / `read` as the plugin names it (`normalizeList`,
`normalizeNotebook`; `member` of the first versions reads as `write`), with `canEdit` (false for somebody who only
reads; a plugin that names none: true). Before, every role but `owner` arrived as null and `canEdit` not at all.

The test server (`test/fixtures/notes-server.js`) has `Task.deadline` and `me.driveDeadlines` only with the word
(`STAGE5`); its default stays an older plugin. `srv.addDeadline()` makes such a task, `srv.reminderPush(taskId)` its
push. `test/fixtures/drive-server.js` names `reminder.by` with `deadlineHub` (or `srv.remindBy`). Tests:
`test/notes-deadlines.test.js`.

## Plugin 1.8.0: „Meine Orte“ live in the profile

With the word `profilePlaces` the places of „Meine Orte“ are those of GateControl's profile (docs/places.md): every id
is the profile's, `ref` is `profile:<id>`, a place has `icon`, `visibility` and `usedBy`, `GET places` adds `profile:
true` and `notMoved` (what the move could not take), `me.places.profile` says that POST / PATCH / DELETE change the
profile. `notes:place:create` / `:update` take `icon` and `visibility`; `notes:place:delete` answers code `in_use` with
`usedBy` and `ref` while another plugin uses the place, `{ force: true }` deletes it all the same. A task's place may be
`{ ref: 'profile:<id>' }`.
