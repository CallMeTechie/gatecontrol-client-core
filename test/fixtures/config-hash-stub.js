'use strict';
// Test stand-in for the private @callmetechie/gatecontrol-config-hash package:
// only validateWgConfig is used by the IPC handlers under test.
module.exports = {
  validateWgConfig: (text) => ({ ok: /\[Interface\]/.test(String(text)), errors: [], warnings: [] }),
};
