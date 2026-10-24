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
| `windowsHello` (`src/services/windows-hello.js`), `src/utils/vault-hello.js` | "Mit Windows Hello entsperren": a Windows Hello key (WinRT KeyCredentialManager via koffi) and the user key wrapped under its signature, see below |
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
- **Windows Hello unlock**: only when the person turns it on — the user key
  wrapped by a key only a Windows Hello signature gives, the record
  DPAPI-protected in `<dir>/hello-<owner>.bin` (see below).
- **Settings** (auto-lock minutes): `<dir>/settings.json`.
- **Renderer**: lists get titles, user names and metadata; secrets only through
  `entry()`, `history()` and `copy()` (main writes the clipboard and clears it
  after 30 s when it still holds the value).

## Wiring an app

```js
const { app, clipboard, safeStorage, powerMonitor } = require('electron');
const path = require('path');
const { VaultService, windowsHello } = require('@gatecontrol/client-core');

const vault = new VaultService({
  apiClient,                                           // configure() changes it in place
  dir: path.join(app.getPath('userData'), 'vault'),    // offline copy, settings, remembered key
  protect: VaultService.safeStorageProtect(safeStorage), // "remember unlock" (DPAPI)
  clipboard,                                           // copy() + clear after 30 s
  notificationCenter: notifications.notificationCenter, // pushes → sync + vault:push, toast click → page
  pushClient: notifications.pushClient,                // reconnect → ask again, sync
  powerMonitor,                                        // lock on lock-screen / suspend
  hello: windowsHello.createWindowsHello({ log }),     // "Mit Windows Hello entsperren" (Windows; elsewhere unavailable)
  helloName: 'GateControl Pro Vault',                  // the Hello key's name: one per app and login
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

## Unlock with Windows Hello ("Mit Windows Hello entsperren")

Like the Android app's fingerprint unlock (the user key under a Keystore key
that only a strong biometric releases), the Windows apps can open Vault with
Windows Hello — face, fingerprint or PIN. Hello gates real key material: the
key that unwraps the user key exists only as a signature Windows makes after
the person confirmed. The master password is never stored.

### Approach

- **Windows Hello key** (`Windows.Security.Credentials.KeyCredentialManager`):
  `RequestCreateAsync(name, ReplaceExisting)` makes a per-user RSA 2048 key in
  the Microsoft Passport key storage provider (in the TPM when there is one;
  the private key never leaves Windows). Name: `<helloName> <owner>` — one key
  per app and login.
- **Stable key material**: the key signs a 32-byte random challenge with
  `RequestSignAsync` (one prompt). RSA PKCS#1 v1.5 / SHA-256 signatures are
  deterministic, so the same key signs the same challenge to the same bytes
  every time (the scheme of KeePassXC's Windows Hello quick unlock). Turning Hello on
  checks this: the signature must verify as PKCS#1 v1.5 under the key's public
  key (`check: 'pkcs1'`, verified again before every unwrap); otherwise a second
  signature must be byte-equal (`check: 'repeat'`), else Hello is not turned on.
- **Wrapping**: wrapping key = HKDF-SHA256(ikm = signature, salt = challenge,
  info = `gcv1:hello-wrap-key`); the user key is wrapped with vault-crypto's
  `wrap()` (XChaCha20-Poly1305, AD `gcv1:user-key:hello:<key name>`).
- **On disk**: `hello-<owner>.bin` = DPAPI (`safeStorage`) of the JSON record
  `{ v, keyName, challenge, publicKey, check, wrapped }`. Never the signature,
  the wrapping key or the user key. Local only: not part of the plugin's
  crypto format, nothing goes to the server.
- **Calling WinRT**: directly through koffi (already a dependency, like
  `wifi-scan.js`): `RoGetActivationFactory` → the statics' COM vtables,
  `IAsyncInfo.Status` polled with `setTimeout` (Electron's main thread keeps
  pumping messages while the dialog is open; its STA apartment is kept, plain
  Node gets `RoInitialize(MTA)`), `CryptographicBuffer` for `IBuffer`s. No
  PowerShell, no native addon, nothing unsigned shipped. The Hello dialog can
  open behind a desktop app's window: its window (`Credential Dialog Xaml
  Host`) is brought to the front. A CryptographicBuffer round trip checks the
  vtable layout before Hello is offered. One Hello call at a time.

Rejected alternatives:

- **WebAuthn PRF / hmac-secret in the renderer**: the pages are `file://`
  (opaque origin, no valid RP ID; a custom scheme is not accepted as a
  WebAuthn origin), Electron has no passkey UI of its own, and Windows Hello
  supports PRF only on recent Windows 11 builds — Windows 10 and most current
  Windows 11 machines would get nothing.
- **A PowerShell 5.1 helper with the WinRT projections**: 0.5–1.5 s start per
  call, blocked by Constrained Language Mode / AppLocker in managed
  environments, a separate (background) process that cannot bring the Hello
  dialog to the front, and the signature would cross a process boundary.
- **UserConsentVerifier** (a yes/no prompt in front of a DPAPI key): gates no
  key material — any process of the user could read the DPAPI key without the
  prompt.

### Flows

- **Turn on** (`setHello({ on: true, password })`, vault settings): the vault
  must be unlocked and the master password is entered again (checked with
  Argon2id; the key Hello will guard is the one this password opens). Then
  Windows asks — creating the key and signing may be two prompts. Turning it
  on replaces "remember unlock" (that would open without the person);
  "remember unlock" cannot be turned on while Hello is on (`hello_on`).
  Already on: nothing happens (a new key would void the record).
- **Unlock** (`unlockHello()`): one prompt (a second call shares it), the user
  key is unwrapped and checked against the account (`keysFrom`: the private key
  must open and match the public key). Auto-lock, lock screen and suspend lock
  as always; the keys are only in memory while unlocked.
- **Failed / cancelled**: `hello_cancelled`, `hello_locked` (Windows Hello is
  locked: too many wrong PINs), `hello_failed` count; after `MAX_FAILS` (3) in
  a row `helloBlocked` is true and only the master password (or the recovery
  key) opens — that resets the count. "Use the password instead" in the
  dialog (`UserPrefersPassword`) goes to the password at once.
- **Hello key gone or changed** (Hello reset, PIN removed, the key made again
  elsewhere, a record of another account): `hello_invalid` — record and key
  are removed, the master password opens.
- **Turn off** (`setHello({ on: false })`, also while locked): record and
  Windows Hello key (`DeleteAsync`, no prompt) go.
- **Master password changed, recovery**: the user key stays, so Hello keeps
  working (the record wraps the user key, not a password-derived key).
- **Account deleted** (here or on another device) / another login: the record
  and the key of that login go (`deleteAccount`, account gone); each login has
  its own record and key.
- **Not available** (`status().helloAvailable` false, `helloReason`):
  `unsupported_os` (not Windows, no KeyCredentialManager), `remote_session`
  (Remote Desktop — Hello does not work there), `not_set_up` (no Windows
  Hello / PIN for this user), `no_protect` (DPAPI unavailable), `error`. The
  apps hide the option or disable it with the reason (for `not_set_up` with a
  button to Windows' sign-in options: `shell:open-external` allows exactly
  `ms-settings:signinoptions`); a Hello unlock that is already on keeps its
  record and offers the master password meanwhile.
- Logged: statuses, codes and HRESULTs only — never a signature, key or the
  challenge.

### Threat model

| Attacker | Can | Cannot |
|---|---|---|
| Has the disk / a backup, not the Windows login | — | read `hello-*.bin` (DPAPI needs the user's Windows credentials); even with it, unwrap without the Hello key's signature (TPM-bound private key) |
| Another Windows user on the PC | — | open the user's DPAPI data or use their Hello key |
| Malware running as the user, vault locked | read the DPAPI record; ask Windows for a signature — Windows shows the Hello dialog and the person must confirm | get the signature without the person confirming (unlike "remember unlock", where any process of the user opens the DPAPI key silently) |
| Malware running as the user, vault unlocked / while the person types | read the main process' memory, log keys — as with the master password | — (out of scope for every password manager) |
| Knows the Windows PIN and has the logged-in PC | open the vault with Hello (the PIN is a Hello factor) | — : turning Hello on makes the Windows Hello credentials an alternative to the master password; the settings text says so |
| Admin / SYSTEM, kernel | everything | — (out of scope) |
| The server | — | nothing about Hello reaches it |

Without a TPM, Windows keeps Hello keys in software (protected by the user's
Hello credentials) — weaker against an offline attacker who also breaks DPAPI.
Hello's own anti-hammering (TPM lockout of PIN tries) is the brute-force
limit; the app's `MAX_FAILS` only moves the person to the master password.

### Tests

- `test/vault-hello.test.js`: wrapping (fixed HKDF vector, wrong key / record /
  AD fail, no key material in the record), VaultService's state machine with a
  fake provider, IPC, and end to end through the real WinRT code on fake COM
  objects.
- `test/windows-hello.test.js`: the COM layer against fake COM objects (koffi
  callbacks as vtables): slots, statuses, async errors and timeouts, the dialog
  to the front, every object released, every HSTRING deleted, every CoTaskMem
  copy wiped.
- `test/windows-hello.win.test.js` (CI job "Windows Hello", `windows-latest`):
  the real WinRT without a prompt — availability answers, buffers round trip,
  KeyCredentialManager activation, `IsSupportedAsync`, `OpenAsync` of a missing
  key.
- On a real Windows PC (manual): turn on (both prompts in front of the app),
  unlock, cancel ×3 → master password, Hello reset / PIN removed →
  `hello_invalid`, Remote Desktop → unavailable, quick search (Strg+Alt+P).
