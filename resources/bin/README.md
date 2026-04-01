# WireGuard Native DLLs

These DLLs are bundled with the core package and shared across all GateControl clients.

- `wireguard.dll` — wireguard-nt library for tunnel management via FFI
- `wintun.dll` — WinTUN virtual network adapter driver

## Usage by consuming clients

Clients use electron-builder's `extraResources` to copy these files into the app bundle:

```json
{
  "extraResources": [
    {
      "from": "node_modules/@gatecontrol/client-core/resources/",
      "to": "resources/",
      "filter": ["**/*"]
    },
    {
      "from": "resources/",
      "to": "resources/",
      "filter": ["**/*"]
    }
  ]
}
```

The second entry allows clients to override or add client-specific resources.
