# Medien (Stufe 4e: Windows Medien-Kern)

Films and series from the NAS on the PC: Jellyfin first, SMB and WebDAV shares beside it. This core holds the services
only; the pages come in the Pro client (4f pages, 4g player, 4h folders). Decisions 21–29 a: Pro only, every device signs
in on its own (own Jellyfin device id, "Gerät anmelden" confirms the Quick Connect code of another device), the access
encrypted on this PC (DPAPI), nothing of it to the GateControl server or the page. The logic and the test cases follow
Android's `:core:media`.

## Core pieces

| Piece | What it does |
|---|---|
| `src/utils/media-address.js` | addresses as typed: Jellyfin (`192.168.1.20` → `http://192.168.1.20:8096`), `\\nas\filme` / `smb://…`, WebDAV (HTTPS by default); plain HTTP and SMB only in the home network |
| `src/utils/media-jellyfin.js` | the pure Jellyfin parts: `Authorization: MediaBrowser …`, URLs under the base, the JSON, the device profile of Chromium (`capsOf`, `profile`), `playbackBody`, `plan`, `progressBody`, the UDP answers |
| `src/utils/media-quality.js` / `media-tracks.js` | quality by bandwidth (decision 10) / sound and subtitles (labels, `fate`: decoded or converted, per series) |
| `src/utils/media-sources.js` | the stored list: replacing a source signed in again, the SMB ↔ WebDAV pair, `shareFor(atHome)`, `publicSource` (no secrets) |
| `src/utils/media-share.js` | share paths, UNC paths (no ADS, no devices), Range, Basic/Digest (RFC 7616), a small XML reader for `207 Multi-Status` (no DTD, no entities) |
| `src/utils/media-playable.js` | "can Chromium play this NAS file?": `sniff` (Matroska CodecIDs, MP4 sample entries, moov at the end) and `verdict` (yes / partial / no / unknown, `external` → "In VLC öffnen", 4h) |
| `src/utils/media-share-names.js` | 4h: what a file name says (film / episode, title, year, `S01E02`, a season folder), `key` / `sortKey` to compare and sort titles of different sources (Android's `ShareNames`) |
| `src/utils/media-share-index.js` | 4h: the films and series of a share from its folders with the pictures beside the videos (`poster.jpg`, `<film>-poster.png`, `fanart.jpg`), ids `f:<path>` / `s:<key>` / `s:<key>:<n>` (Android's `ShareIndex`) |
| `src/utils/media-lan.js` | the LAN adapter to bind to (`lanBinding`, never the VPN), the tunnel address away, the route verdict |
| `src/services/media-net.js` | axios with the LAN binding (`localAddress`), pinned self-signed certificates, `certificate()` for "einmal bestätigen", no proxy, no redirects |
| `src/services/media-jellyfin.js` | `JellyfinClient`, `JellyfinLibrary` (rows, detail, PlaybackInfo, progress, played, bandwidth, `authorize` code), `JellyfinSignIn` (Quick Connect, name and password) |
| `src/services/media-discovery.js` | Jellyfin search: UDP 7359, one socket per real LAN address |
| `src/services/media-share.js` | `SmbShare` (UNC + `WNetAddConnection2W` via koffi, no drive letter, 1219 → `smb_conflict`, `useExisting`), `WebDavShare` (PROPFIND, GET with Range, Basic/Digest, pin) |
| `src/services/media-share-library.js` | 4h: a share as a library: rows, grids (A–Z, added, year; unwatched), seasons, episodes, search, detail; the progress on this PC (90 % = gesehen, under 30 s no place, read again after 10 minutes) |
| `src/services/media-external.js` | 4h: "In VLC öffnen" (VLC from the registry or the usual folders, a loopback address `http://127.0.0.1:<port>/<token>/<name>` — only that Host, only tokens made for it, Range — never the access), "In anderer App öffnen" (Windows' app with the UNC path of an SMB file) |
| `src/services/media-lan-route.js` | Windows: `GetBestRoute2` diagnosis, Plan B host route (`netsh … <nas>/32 … metric=1 store=active`), removed again |
| `src/services/media-store.js` | electron-store: sources as one safeStorage blob, device id, track choice per series, share progress (newest 500), quality |
| `src/services/media-stream.js` | the scheme `gcmedia:` (token only in the page, HLS playlists without `api_key`, Range, CORS only for the app page) |
| `src/services/media.js` | `MediaService`: the way (home/away), setup, rows, play, report, shares; `.stream` is the protocol handler |
| `src/ipc/media-handlers.js` | `media:*` (opt-in: `registerBaseHandlers(…, { media })`), events `media:state`, `media:link` |
| `src/preload/bridge.js` | `createMediaBridge(ipcRenderer)` → `window.gatecontrol.media` (the Pro preload adds it) |

## In the Pro client (4f/4g/4h)

```js
const store = new MediaStore({ store, protect: DriveService.safeStorageProtect(safeStorage) });
const media = new MediaService({ store, client: 'GateControl Pro', version: app.getVersion(), log });
// before app ready, together with the other schemes:
schemes.push({ scheme: MediaStreamService.SCHEME, privileges: { ...MediaStreamService.SCHEME_PRIVILEGES } });
// after ready:
protocol.handle(MediaStreamService.SCHEME, (req) => media.stream.handleProtocol(req));
registerBaseHandlers(ipcMain, { …, media });
app.on('before-quit', () => media.close());          // host routes and SMB connections go
// tunnel up/down, another Wi-Fi: media.networkChanged()
```

The page's CSP needs `gcmedia:` in `img-src`, `media-src` and `connect-src` (hls.js loads by fetch/XHR). The player tells
the core what Chromium plays: `media.setCaps({ hevc, av1, vp9, mkv, hdr, ac3, eac3, maxAudioChannels })` from
`canPlayType` / `MediaCapabilities.decodingInfo` / `matchMedia('(dynamic-range: high)')`.

## The folders of a share (4h)

- The rows and grids of Medien take a share's id like a Jellyfin one: `media:resume`, `media:latest`, `media:movies`,
  `media:series`, `media:seasons`, `media:episodes`, `media:search`, `media:detail`, `media:play`, `media:played`. Every
  title (Jellyfin's too) carries `key` and `sortKey`: the page shows a title that Jellyfin and a share both have once
  (Jellyfin wins) and mixes the sources A–Z — as Android's `MediaLogic`.
- `media:share:list` gives each video its title from the name and the picture beside it (`gcmedia://image/<token>/<path>`,
  one token per share, jpg/png/webp up to 4 MB), and its `itemId` for detail and play.
- „Im Ordner suchen“ (as Android): `media:share:search` ({ id, dir, q }) finds the videos below the folder whose file
  name holds every word (any case, accents, without the extension; `N.matches`) in the share's index — entries as
  `media:share:list` gives them, with `folder` (where each lies), A–Z, at most 60. In a Jellyfin library or folder
  `media:library:search` ({ id, parentId, q }) asks Jellyfin's search below it (`parentId`, recursive).
  „Als gesehen markieren“ of a file is `media:played` (kept on this PC, as before).
- Before a file plays its start is read once (`check`, kept per size): `media:share:check` for the detail column,
  `media:play` / `media:share:open` carry it as well. `check.external`: "In VLC öffnen" (`media:share:external`, app
  `vlc`) when `media:external:info` finds VLC, else "In anderer App öffnen" (app `default`, SMB only: WebDAV has no path
  Windows' apps could open).
- A play given up before it started (another one asked meanwhile, 'stop' at 0) does not overwrite the place of a file.

```js
const media = new MediaService({ store, client: 'GateControl Pro', version, log, openPath: (p) => shell.openPath(p) });
```

## The way to the NAS with the VPN on (spike, Risiko 6)

**Question:** can a connection to the NAS at home be forced through the LAN adapter by `localAddress` while the tunnel
carries the home network (split routes with `192.168.1.0/24`)?

**Answer:** yes for our own sockets (Jellyfin, WebDAV, the UDP search). Windows uses the strong host model for IPv4 by
default (send and receive since Vista): a socket bound to the LAN address only takes routes of the adapter that owns
that address — its on-link subnet, else its default gateway — whatever the tunnel claims, also a more specific route.
`test/media.win.test.js` proves it on a Windows runner with a real wireguard-nt adapter (the app's driver): the network
of a target routed into the tunnel, unbound the TCP connection dies in the tunnel, bound to the LAN address it arrives
(also HTTP through `MediaNet`), `GetBestRoute2` with and without the source address agrees.

**Not with binding:** SMB goes through Windows' own redirector (UNC paths, the Explorer) — there is no socket of ours.
**Plan B** (implemented, `MediaLanRoute`): when the diagnosis says the unbound way is the tunnel, a host route for the
NAS's address alone through the LAN adapter (`/32`, metric 1, `store=active`: in memory only), set by `check()` at home
for SMB (and for HTTP if the binding should not hold, e.g. `weakhostsend` on the LAN adapter), removed by `close()` /
`forgetAll()`. The `/32` wins over the tunnel's `/24` by the longer prefix (tested on the runner as well). The app runs
elevated (it creates the WireGuard adapter), so netsh may change routes.

**Away:** connections are bound to the tunnel's own address, so a hotel network with the same private addresses never
gets the access token.

**Home or away:** a source is "at home" when its host lies in the subnet of a real LAN adapter and answers there bound to
that adapter — Jellyfin with its server id checked (a hotel's `192.168.1.20` is not taken for home); shares by a TCP
connect only (no identity: SMB answers with a challenge-response, WebDAV over HTTPS keeps its pin).

**To test on a real PC (Nutzer):**

1. At home, VPN on with split routes that include the home network: Jellyfin plays, the status bar says "Zuhause,
   direkt"; Resource Monitor › Network shows the connection to the NAS on the LAN adapter, not on `gatecontrol0`.
2. Same with an SMB share: `route print` shows `<NAS>/32` via the LAN while Medien is open; gone after quitting.
3. Full tunnel (0.0.0.0/0) at home: still direct (on-link `/24` beats `0/0`), no host route needed.
4. Kill switch on: the LAN rules let the NAS through (10/8, 172.16/12, 192.168/16).
5. A NAS in another subnet than the PC (routed by the home router): the bound way takes the LAN gateway.
6. SMB with the Explorer already connected to the NAS under another user → message 1219 and "Mit dem Explorer-Zugang
   verwenden".
7. Away (mobile hotspot): Jellyfin through the tunnel with the measured bandwidth; WebDAV instead of SMB for a pair.

## The sources from the server (Medien-Plugin, Teilstufe W1)

Since the plugin `gatecontrol-medien` (app API v1, its README "App-API v1") the sources are set up once in the
GateControl server — nothing on the PC. `MediaServerSources` (`src/services/media-server-sources.js`, pure parts in
`src/utils/media-server.js`) asks `GET …/gatecontrol-medien/api/v1/sources[?since=rev]` at start, after a push
reconnect, after the event `media.changed`, after the signal `media.revoke`, when Medien is opened
(`media:sources:refresh`) and else every 15 minutes, and merges the list into MediaStore (`managed: true`, the
plugin's ids `jf-<n>` / `sh-<n>`; a share's WebDAV half is `sh-<n>_w`).

| What | How |
|---|---|
| Entry "Medien" | only while `GET /api/v1/client/plugins` gives the plugin's `tab` (`status().server.visible`) |
| Jellyfin access | made on this PC: Quick Connect with `device.id` / `device.name` of the list (header values URL-encoded), the code to `v1/jellyfin/pair` (never shown), then Connect / AuthenticateWithQuickConnect, `v1/jellyfin/paired`; Jellyfin's 401 or another linked user → again without asking; `code_invalid` / `device_mismatch` once more |
| A share's password | `v1/sources/{id}/secret` when `secretRev` is newer; the first SMB sign-in → `v1/shares/{id}/checked` |
| Kept | the list and the plugin's last answer encrypted (safeStorage / DPAPI, `serverCache`); without the server the last list counts |
| Offline | 30 days without the list → `offline.hint`; 90 days (`maxOfflineDays`) → the NAS passwords are deleted |
| Widerruf | `media.revoke` (silent, topic `plugin:gatecontrol-medien:media_signal`) or 403 `no_access` → access and passwords of those sources go, then the whole list |
| Plugin gone | 404 `plugin_unavailable` / 403 `license_required`: hidden at once, the server's sources deleted after 24 h |
| Taken over | a source set up on this PC with the same Jellyfin `serverId` / the same share address → the server's (progress of share files moved, the old Jellyfin access signed out); the rest removed, named in `status().server.notice` |
| SMB 1219 | the WebDAV half at once, no question |

**The network rule (binding):** at home — GateControl's own home-network detection says so (the server's
`GET /api/v1/client/home-network?local=<the PC's LAN addresses>`, services/homeNetwork.js on the server: the same as
the trusted network, Familie's presence and the home cache): `same_lan: true` with a site — its own LAN only for a
request through the tunnel (the peer's WireGuard endpoint in the server's LAN), a gateway site also directly (the PC's
public address is an online gateway's and a LAN address lies in a subnet it reports). With the VPN off only a gateway
site can be confirmed; otherwise the source counts as away, opening it starts the tunnel and the server is asked again
through it. A private address alone is no proof, the plugin's `network.home.probes` never decide it (a `tcp` probe
least of all); an error or an old server: away. At home every connection goes straight to the home address bound to
the LAN, never through the tunnel, also with the VPN on. Away with `away.mode = vpn` only through the own tunnel: opening or playing a title
starts it (`tunnel.connect()` of the app, event `media:vpn`: connecting / up / failed); without it nothing is sent
(`vpn_required`, MediaNet refuses before a byte leaves). Away with `away.mode = direct` (the admin's exception) over the
source's `https://` address with the usual TLS check. `link.way` per source: `home` | `vpn` | `direct` | `blocked`; a
failure of the way goes to the plugin once per change (`v1/sources/{id}/report`, e.g. `tunnel_unreachable`).

IPC (read only): `media:sources:status`, `media:sources:refresh`; events `media:sources:state`, `media:vpn`. The
channels of the old setup (`media:discover`, `media:server`, `media:trust`, `media:qc:*`, `media:signin`,
`media:authorize`, `media:share:add`, `media:source:remove`) are gone; the core's methods stay (tests).

```js
const media = new MediaService({ store, client: 'GateControl Pro', version, log,
  tunnel: { up: () => tunnelState.connected, connect: async () => { await connectTunnel(); return tunnelState.connected; } } });
const mediaSources = new MediaServerSources({ media, apiClient, pushClient, notificationCenter, log });
mediaSources.start();
```

## „Videos umwandeln“: the hint before playing (gatecontrol-medien 1.6.0)

The plugin converts overnight the files that do not play everywhere (contract „umwandeln-apps-vertrag“).
`MediaConvert` (`src/services/media-convert.js`, `mediaSources.convert`; pure parts in `src/utils/media-convert.js`)
asks `GET …/v1/convert/status?items=<id>,…` (up to 100 ids, what comes within 20 ms in one question, kept 3 min) and
sends `POST …/v1/convert/request { itemId }` („Für heute Nacht vormerken“: only onto the list, the admin queues it).
Only for Jellyfin sources of the server's list, only while the plugin is visible and at least 1.6.0. 404 (older plugin),
403 `no_access` / `license_required`: no hint, not asked again for 30 min. A network error: no hint, asked next time.

**The picture on this PC** (`videoProblem`, with the caps of the page): Chromium in the app plays H.264 in every form —
High 10 (10 bit), 4:2:2 and 4:4:4 too (checked with the Electron of the Pro client: D3D11 takes 8-bit H.264, the rest
falls back to Chromium's software decoder; 1080p50 in 10 bit runs smoothly). So the plugin's most common finding
(`h264_10bit`) plays here directly: no hint. Converted on the NAS here are HEVC without the hardware decoder, AV1
without a decoder, MPEG-2 / VC-1 / MPEG-4 ASP / WMV and other old codecs, Dolby Vision without a fallback and HDR on an
SDR screen.

**The hint** (`hintOf`): only when the picture is converted here and the plugin knows the file — `queued` (place, start),
`running` (percent), `requested` („vorgemerkt“), the offer only for files the plugin rates `convert` (the NAS does not
convert them smoothly while playing) with `available: true`; `done` and `hint` / `info` files nothing. Playing stays.

IPC: `media:convert:hint ({ id, itemId, versionId? })` (after `media:detail`), `media:convert:prefetch ({ id, itemIds })`
(a season's episodes in one question), `media:convert:request ({ id, itemId })`.

## "Auf TV/PC abspielen": this PC as the receiver

The phone sends a title to "GateControl für Windows" as it does to GateControl TV: the same cast contract version 1
(plugin README "Cast"), the same plugin routes. Nothing is set up for it: the plugin lists this PC in the phone's
`GET v1/cast/targets` as `kind: "pc"` (every own Windows device, `platform: 'windows'`, online first).
`MediaCastReceiver` (`src/services/media-cast.js`, pure parts in `src/utils/media-cast.js`, the logic of Android's
`CastWire` / `CastInbox` / `CastReceiverRules` / `TvCast`):

| What | How |
|---|---|
| In | the push stream's event `plugin` (`type: 'media.cast'`) and the silent signal (topic `media_signal`, `data.kind: 'media.cast'`); each message once (sender, session, seq). The signal goes to this PC alone: its `to` is this PC's GateControl id (kept in MediaStore `castSelf`); an event counts only with `to` == that id (before: only for the own session, never a start). |
| Start | not older than 120 s; the own source with the plugin's id (`jf-<n>`, a share by its SMB half) → `MediaService.detail` (the network rule: home directly, away only through the VPN, started here; the sign-in) → event `play` to the page. A share's file Chromium cannot play at all (`verdict: 'no'`) → `unsupported`. |
| Refusals | `source_missing`, `signed_out`, `not_found`, `offline` (also `vpn_required`), `unsupported`, `blocked` (the page did not open it within 15 s), `taken_over` (a new start, from any own device), `closed` (closed on this PC) |
| Commands | only of the session's controller, newer seq, not older than 60 s → event `command` (`play`, `pause`, `seek`, `seekBy`, `audio` / `subtitle` as Jellyfin's stream index, `stop`, `status`; `volume` { volume 0–100, muted } is a proposal beyond version 1: the plugin forwards only the commands it knows) |
| States | `cast.state` to the controller on a change of the phase, a track or the volume, a jump of more than 4 s, and every 5 minutes while it plays; `device` = this PC's name. Track ids `a<index>`, `s<index>`, `off`. The last state of a session that was rate limited goes once more after 61 s. |

```js
const mediaCast = new MediaCastReceiver({ media, apiClient, log,
  pushClient: notifications.pushClient, notificationCenter: notifications.notificationCenter });
mediaCast.start();
registerBaseHandlers(ipcMain, { …, media, mediaCast });
```
