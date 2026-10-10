'use strict';

// electron-store stand-in: dot-path get/set, `store` snapshot and
// onDidChange(key, cb) → unsubscribe, like the real store.

function createMemoryStore(initial = {}) {
  let data = JSON.parse(JSON.stringify(initial));
  const watchers = new Set();
  const writes = [];

  const getPath = (obj, key) => key.split('.').reduce((o, k) => (o != null && typeof o === 'object' ? o[k] : undefined), obj);
  const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

  return {
    writes,
    get(key, def) {
      const v = getPath(data, key);
      return v === undefined ? def : clone(v);
    },
    set(key, value) {
      const before = watchers.size ? [...watchers].map((w) => clone(getPath(data, w.key))) : [];
      const parts = key.split('.');
      let o = data;
      for (const p of parts.slice(0, -1)) {
        if (o[p] == null || typeof o[p] !== 'object') o[p] = {};
        o = o[p];
      }
      o[parts[parts.length - 1]] = clone(value);
      writes.push(key);
      [...watchers].forEach((w, i) => {
        const now = getPath(data, w.key);
        if (JSON.stringify(now) !== JSON.stringify(before[i])) w.cb(clone(now), before[i]);
      });
    },
    delete(key) {
      const parts = key.split('.');
      const parent = parts.length > 1 ? getPath(data, parts.slice(0, -1).join('.')) : data;
      if (parent) delete parent[parts[parts.length - 1]];
    },
    onDidChange(key, cb) {
      const w = { key, cb };
      watchers.add(w);
      return () => watchers.delete(w);
    },
    get store() { return clone(data); },
    reset(next = {}) { data = clone(next); },
  };
}

module.exports = { createMemoryStore };
