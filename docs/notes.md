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
`test/notes-shopping.test.js` (plugin 1.4.0), `test/notes.test.js` (the plugin's frozen vectors of the quick entry, the repeat rules and the Tresor format; the service
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
