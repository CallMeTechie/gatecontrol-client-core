# Vault: the password manager for the Windows apps

The core holds the data side of "Vault" (plugin `gatecontrol-vault` ≥ 1.0.0,
contract: `gatecontrol-plugins/plugins/gatecontrol-vault/README.md` "App-API"
and "Kryptoformat"; reference implementation: the Android app's
`vault/VaultRepository.kt`). The apps (Pro, Community) draw the page "Vault".
Everything is end-to-end encrypted: the server only ever sees ciphertext.

| Module | Purpose |
|---|---|
| `vaultCrypto` (`src/utils/vault-crypto.js`) | The crypto format (libsodium): Argon2id master key, user key, X25519 key pair, sealed vault keys, entries bound by AD; fixed test vectors shared with Android |
| `VaultService` (`src/services/vault.js`) | Availability via `GET /api/v1/client/plugins`, account (setup, unlock, recovery, new password, delete), sync with an offline outbox, entries, vaults / members / roles, key changes, emergency access, import, auto-lock, "remember unlock", clipboard, pushes |
| `registerBaseHandlers(…, { vault })` | IPC `vault:*` (`src/ipc/vault-handlers.js` lists arguments and answers) and the events `vault:state`, `vault:push` |
| `createBridgeApi()` → `window.gatecontrol.vault` | Renderer API |
| `vaultUtil` (`src/utils/vault.js`) | Pure helpers: server JSON, merge of the offline copy, entry JSON v1, TOTP (RFC 6238), password generator / strength, matching by web address, import (Bitwarden JSON; CSV of Chrome / Edge, Bitwarden, 1Password, KeePass, Firefox), push context |
| `wifiScan` (`src/services/wifi-scan.js`) | Wi-Fi networks nearby for Wi-Fi entries (Windows Native Wifi API via koffi), see below |
| `totpQr` (`src/services/totp-qr.js`), `totpQrUtil` (`src/utils/totp-qr.js`) | 2FA keys from QR codes (screen, clipboard, image file) for the entry editor, see below |
| i18n `vault.*` | The personal vault's default name, the suffix of conflict copies, the file dialog of "QR-Code scannen" |

No new runtime dependency (libsodium-wrappers-sumo is already there for `vaultCrypto`, jsQR — pinned to 1.4.0 — for the QR codes); `qrcode-generator` 1.4.4 (MIT) draws the QR codes of the tests (dev only).

## What stays where

- **Keys** (user key, key pair, vault keys) and **decrypted entries**: main
  process memory only, only while unlocked. `lock()` zeroes the keys.
- **Offline copy**: the server's encrypted records (account, vaults, entries)
  and the outbox of unsent saves in `<dir>/vault-<owner>.json` (owner: a hash of
  server URL + device token), written atomically. Never plaintext, never a key.
- **Remember unlock**: only when the person turns it on — the user key
  protected by DPAPI (Electron `safeStorage`) in `<dir>/remember-<owner>.bin`.
- **Settings** (auto-lock minutes): `<dir>/settings.json`.
- **Renderer**: lists get titles, user names and metadata; secrets only through
  `entry()`, `history()` and `copy()` (main writes the clipboard and clears it
  after 30 s when it still holds the value).

## Wiring an app

```js
const { app, clipboard, safeStorage, powerMonitor } = require('electron');
const path = require('path');
const { VaultService } = require('@gatecontrol/client-core');

const vault = new VaultService({
  apiClient,                                           // configure() changes it in place
  dir: path.join(app.getPath('userData'), 'vault'),    // offline copy, settings, remembered key
  protect: VaultService.safeStorageProtect(safeStorage), // "remember unlock" (DPAPI)
  clipboard,                                           // copy() + clear after 30 s
  notificationCenter: notifications.notificationCenter, // pushes → sync + vault:push, toast click → page
  pushClient: notifications.pushClient,                // reconnect → ask again, sync
  powerMonitor,                                        // lock on lock-screen / suspend
  log,
});
vault.start();
mainWindow.on('hide', () => vault.windowHidden());     // auto-lock "immediately" (0)
mainWindow.on('minimize', () => vault.windowHidden());

registerBaseHandlers(ipcMain, { /* … */, vault });     // vault:* channels, reset on server:setup
app.on('before-quit', () => { vault.lock('quit'); vault.stop(); });
```

The page exists while `status().state === 'available'`. Route of the page and of
its toasts: `plg-gatecontrol-vault` (NotificationCenter `navigate` carries the
context `{ topic, event, vaultId, emergencyId, page: 'home' | 'emergency' }`).

Argon2id (64 MiB, 3 passes) runs in the main process for setup, unlock, recovery
and a new password and takes about 0.3–1 s; show a busy state.

## Wi-Fi networks nearby (Wi-Fi entries)

The edit form of a Wi-Fi entry offers "WLAN in der Nähe suchen": IPC
`vault:wifi-scan` → `window.gatecontrol.vault.wifiScan()` →
`{ ok, networks: [{ ssid, security, signal, connected }] }`.

- Needs the vault **unlocked** (`locked` otherwise) and counts as activity
  (the person asked for it).
- Windows only, through the Native Wifi API of `wlanapi.dll` (koffi, loaded on
  the first scan; no `netsh`, so it does not depend on the Windows language):
  `WlanOpenHandle` → `WlanEnumInterfaces` → `WlanScan` on every interface →
  about 3.5 s for the drivers → `WlanGetAvailableNetworkList` (+
  `WlanGetNetworkBssList` for the security of each access point) →
  `WlanFreeMemory` / `WlanCloseHandle`. A scan takes about 4 s; calls while one
  runs share it.
- `ssid`: UTF-8 (latin1 when the bytes are not UTF-8); hidden networks are left
  out. One row per SSID (the strongest), connected first, then by signal
  (0–100), at most 100.
- `security` uses the strings of Vault's Wi-Fi entries (the portal derives the
  QR code type from them): `WPA3` (SAE), `WPA2/WPA3` (SAE and PSK, transition
  mode), `WPA2` (RSNA-PSK), `WPA` (WPA-PSK), `WEP`, `Offen` (open, OWE), `''`
  when unknown. Enterprise networks map to `WPA2` / `WPA3` / `WPA` as well.
- Codes: `no_adapter` (not Windows, no WLAN service / adapter), `service_off`
  (WLAN AutoConfig not running), `radio_off` (WLAN switched off),
  `location_denied` (`ERROR_ACCESS_DENIED`: since Windows 11 24H2 scan results
  need "Standortdienste" and "Desktop-Apps Zugriff auf Ihren Standort
  erlauben"), `failed`.
- For `location_denied` the page opens `ms-settings:privacy-location` through
  `shell:open-external`, which allows exactly that settings page besides
  http(s) links (`isAllowedSettingsUri`, `src/utils/external-url.js`).

## 2FA key from a QR code ("QR-Code scannen")

Next to "2FA-Schlüssel" (entries of type login and 2FA code) the edit form offers
"QR-Code scannen" with three sources: IPC `vault:totp-qr` →
`window.gatecontrol.vault.totpQr(source)` →
`{ ok, uris: ['otpauth://totp/…'] }` (at least one), else `{ ok: false, code }`.

- Needs the vault **unlocked** (`locked` otherwise, also when it locked while the
  scan ran) and counts as activity. One scan at a time (a second call waits).
- `source: 'screen'`: every display through Electron's `desktopCapturer`
  (`types: ['screen']`) at its native resolution (`thumbnailSize`: the largest
  display size × scale factor). When nothing is found and the main window is
  visible, the window is made fully transparent (`setOpacity(0)`, ~250 ms for
  the compositor) for one more capture and restored right after: it may cover
  the website's QR code. Windows / macOS only; elsewhere there is one capture.
- `source: 'clipboard'`: `clipboard.readImage()` (e.g. after Windows + Shift + S).
- `source: 'file'`: `dialog.showOpenDialog` (PNG, JPG, GIF, BMP, WebP, ≤ 30 MB).
  PNG / JPG through `nativeImage`; GIF, BMP and WebP through the Windows shell's
  thumbnail (`nativeImage.createThumbnailFromPath`, 2048 px), elsewhere
  `unsupported`.
- Decoding: [jsQR](https://github.com/cozmo/jsQR) 1.4.0 (Apache-2.0, pure
  JavaScript, no native build) in a worker thread
  (`src/services/totp-qr-worker.js`; in the main process when the worker cannot
  start). Bitmaps (BGRA from `toBitmap()`) never reach the renderer. Images
  ≥ 2000 px wide are searched at half size first (normal and light-on-dark
  codes; ~0.4 s for a 4K screen), then at full size (small codes); smaller
  ones at full size. A found code is painted white and the image searched
  again (several codes); when nothing is found, four overlapping tiles are
  searched (jsQR mixes up two codes of the same size).
- Only `otpauth://totp/…` URIs that the vault's own parser accepts
  (`parseTotp`: SHA1 / SHA256 / SHA512, 6–8 digits) are returned, deduplicated.
  `otpauth-migration://offline?data=…` (Google Authenticator's "Konten
  exportieren"; protobuf `MigrationPayload` with `OtpParameters { secret,
  name, issuer, algorithm, digits, type }`) becomes one `otpauth://totp/Issuer:Account?secret=…&issuer=…`
  URI per TOTP account (HOTP and MD5 accounts are left out).
- Codes: `none_found` (no QR code with a 2FA key), `hotp` (only
  `otpauth://hotp` codes: "HOTP wird nicht unterstützt"), `invalid_code`
  (an otpauth code without a usable key), `no_image` (no image in the
  clipboard), `unsupported` (image format, or no screen capture), `cancelled`
  (file dialog closed), `failed`.
- The page puts the chosen URI into the 2FA field (digits, period and algorithm
  stay in it), fills the title from the issuer / account while it is empty and,
  for logins, the user name from the account when it is empty and looks like an
  e-mail address or user name. Several codes: the person picks one.
- Neither images nor URIs are logged (only the source, the number of codes or
  the code).
