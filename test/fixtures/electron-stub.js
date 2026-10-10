'use strict';

// Minimal electron double for the node --test runner (electron is provided
// by the host app at runtime and is not a core dependency).
const state = { name: 'GateControl Pro Client', version: '1.0.0', opened: [] };

module.exports = {
  __state: state,
  app: {
    getName: () => state.name,
    getVersion: () => state.version,
  },
  shell: {
    openPath: async (p) => { state.opened.push(p); return ''; },
  },
};
