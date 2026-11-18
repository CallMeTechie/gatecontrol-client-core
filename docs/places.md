# Meine Orte (Mein Profil › Meine Orte)

GateControl 1.299.0 keeps a person's places in the user profile: name, symbol, point (required), radius 50–2000 m,
address (optional) and who sees the place (`self` | `family` | `all`), at most 100 per person. Plugins read them through
`gc.places`; the apps keep only references (`profile:<id>`). Windows shows and changes them — it watches no place (the
phone does).

## Core pieces

| Piece | What it does |
|---|---|
| `src/utils/places.js` | the contract: normalizing answers, bodies (only the known keys, `lat` and `lon` together, never 0/0, an emptied address `null`), `diffBody(old, draft)`, the search argument (3–120 characters, `near` rounded to two places ≈ 1 km on this PC) |
| `src/services/places.js` | `PlacesService`: `list`, `get`, `create`, `update`, `remove({ force })`, `markUsed`, `search`; a short cache with the last copy on network errors (`stale`); `unsupported` on a server before 1.299.0 |
| `src/ipc/places-handlers.js` | `places:*` (opt-in: `registerBaseHandlers(…, { places })`), events `places:changed` / `places:state` |
| `src/preload/bridge.js` | `window.gatecontrol.places` |

The app creates the service and hands it to the IPC:

```js
const places = new PlacesService({ apiClient, log, pushClient: notifications?.pushClient, getLang: () => getLocale() });
places.start();
registerBaseHandlers(ipcMain, { …, places });   // gets the core map service for the search fallback
```

## REST (device token)

| Call | Route |
|---|---|
| `list()` | `GET /api/v1/client/me/profile/places` → `places`, `family`, `limits`, `options`, `search: osm \| own \| off` |
| `create(place)` | `POST …/profile/places` |
| `update(id, patch)` | `PATCH …/profile/places/:id` (only the fields given; an empty patch asks nothing) |
| `remove(id, { force })` | `DELETE …/profile/places/:id[?force=1]` — in use: code `in_use` with `usedBy` |
| `markUsed(id)` | `POST …/profile/places/:id/used` |
| `search({ q, near })` | `GET /api/v1/client/me/places/search` |

Refusals keep the server's code in lower case (`invalid` + `field`, `duplicate`, `limit`, `not_found`, `in_use`,
`rate_limited` + `retryAfter`, `search_off`, `search_unavailable`, `no_user`); `unsupported` is a server without the
route (404 without a code).

## Address search

Only when the person asks („Suchen“ / Enter), never while typing, from 3 characters. While the administrator switched
GateControl's search off (`search: 'off'` in the list, or `403 SEARCH_OFF`), the map service of this PC answers
(`services/map-service.js`, OpenStreetMap Nominatim with its own rate limit); the answer says `via: 'device'`. Show the
attribution (`© OpenStreetMap`) under the hits.

## Changes

- A change made here updates the copy at once and emits `changed` (`origin: 'local'`) — GateControl tells the person's
  other devices, never the one that made the change.
- The push stream's control event `places` (`{ ids, deleted }`, never a name or a point) and a reconnect drop the copy
  and emit `changed` (`origin: 'push'` / `'reconnect'`). The pages load again; nothing else happens on Windows.

## The forms

| Form | Source of the choice | What is sent |
|---|---|---|
| Chats: event place | `chat.pickPlaces()` → `chat:places { all: true }`: Messenger 1.28 (`profilePlaces`) `GET places` — own profile places and Familie's, each with `ref`, most used first; older Messenger: Familie's places (`source: 'familie'`) | a profile place as `{ label, lat, lon }` (an event keeps a copy), a Familie place as before with `familiePlaceId` |
| Notizen: a task's place, „Meine Orte“ | Notizen 1.8.0 (`profilePlaces`): `notes.places()` — the ids are the profile's, `ref` `profile:<id>`, `icon`, `visibility`, `usedBy`, `notMoved` | `place: { ref: 'profile:<id>' }` or `{ placeId }`; `deletePlace(id, { force })` (code `in_use` with `usedBy`) |
| Familie rules | Windows does not edit rules' places (only „aktiv“ and the actions) | — |

Without the feature words everything stays as before.
