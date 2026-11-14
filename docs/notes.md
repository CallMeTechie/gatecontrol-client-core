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
| IPC | `src/ipc/notes-handlers.js` | `notes:*` channels (arguments checked), events `notes:state`, `notes:changed`, `notes:vault`, `notes:vault-lock`, `notes:import`; bridge `window.gatecontrol.notes` |

`src/vendor/notizen/` holds the plugin's `ui/quickparse.js`, `ui/repeat.js` and `ui/nsx.js` unchanged (the Pro app's
renderer loads its own copies of the first two; a Pro test checks they are the same files). Tests:
`test/notes.test.js` (the plugin's frozen vectors of the quick entry, the repeat rules and the Tresor format; the service
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
