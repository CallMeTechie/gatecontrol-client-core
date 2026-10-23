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
