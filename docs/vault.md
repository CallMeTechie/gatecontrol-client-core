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
| i18n `vault.*` | The personal vault's default name, the suffix of conflict copies |

No new dependency (libsodium-wrappers-sumo is already there for `vaultCrypto`).

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
