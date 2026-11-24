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
| `src/utils/media-lan.js` | the LAN adapter to bind to (`lanBinding`, never the VPN), the tunnel address away, the route verdict |
| `src/services/media-net.js` | axios with the LAN binding (`localAddress`), pinned self-signed certificates, `certificate()` for "einmal bestätigen", no proxy, no redirects |
| `src/services/media-jellyfin.js` | `JellyfinClient`, `JellyfinLibrary` (rows, detail, PlaybackInfo, progress, played, bandwidth, `authorize` code), `JellyfinSignIn` (Quick Connect, name and password) |
| `src/services/media-discovery.js` | Jellyfin search: UDP 7359, one socket per real LAN address |
| `src/services/media-share.js` | `SmbShare` (UNC + `WNetAddConnection2W` via koffi, no drive letter, 1219 → `smb_conflict`, `useExisting`), `WebDavShare` (PROPFIND, GET with Range, Basic/Digest, pin) |
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
