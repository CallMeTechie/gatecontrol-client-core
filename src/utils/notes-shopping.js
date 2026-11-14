'use strict';

/**
 * Notizen & Aufgaben — the shopping lists of the hub (plugin gatecontrol-notizen 1.4.0, feature `shoppingLists`) as the
 * Windows apps hold them between two calls. Pure: no network, no clock.
 *
 * - `base` is what the server said last: every list the person sees and their items (GET shopping). `merge()` takes
 *   an answer in: `lists` is always complete — a list that is missing is gone (left, no longer shared, deleted), with
 *   its items; with `since` only the items changed since come, tombstones (`deleted: true`) included. A list the device
 *   did not know needs one answer without `since` for its items (`needFull`).
 * - `queue` holds the operations of POST shopping/ops that were not confirmed yet, in the order they were made. Their
 *   ids are made by the device, so sending the same batch again never duplicates anything.
 * - `view()` is base with the queue applied on top — what the page shows while a batch is on its way or the server
 *   cannot be reached. The numbers of a list (`open`, `total`) are counted from its items.
 */

const N = require('./notes');

const QUEUE_MAX = 2000;

function newState() {
  return { lists: new Map(), items: new Map(), since: null, loaded: false };
}

/**
 * An answer of GET shopping into `st`. `full`: asked without `since` (the items are complete).
 * @returns {{ needFull: boolean }} needFull: a list came that the device did not know — ask once without `since`
 */
function merge(st, answer, { full = false } = {}) {
  const a = answer || {};
  const known = new Set(st.lists.keys());
  const lists = new Map();
  let needFull = false;
  for (const l of a.lists || []) {
    if (!l || l.deleted) continue;
    lists.set(l.id, l);
    if (!full && st.loaded && !known.has(l.id)) needFull = true;
  }
  const items = full ? new Map() : st.items;
  for (const i of a.items || []) {
    if (!i) continue;
    if (i.deleted) items.delete(i.id);
    else items.set(i.id, i);
  }
  // what belongs to a list that is gone goes with it
  for (const [id, i] of items) if (!lists.has(i.listId)) items.delete(id);
  st.lists = lists;
  st.items = items;
  if (a.serverTime && !(needFull && !full)) st.since = a.serverTime;
  st.loaded = true;
  return { needFull };
}

/** One operation onto the maps `lists` / `items` (the rules of POST shopping/ops, as far as the device can tell). */
function applyOp(lists, items, op, { userId = null, pending = false } = {}) {
  switch (op.op) {
    case 'list_add':
      if (lists.has(op.id)) break;
      lists.set(op.id, {
        id: op.id, listId: null, name: op.name, icon: op.icon || 'cart', area: op.area || 'private', sort: 0, updatedAt: null, deleted: false,
        role: 'owner', canEdit: true, canManage: true, owner: userId ? { id: userId, name: null } : null, shared: !!op.family, members: [],
        family: !!op.family, open: 0, total: 0, assignee: null, dueAt: null, going: [], tasks: [], ...(pending ? { pending: true } : {}),
      });
      break;
    case 'list_rename': {
      const l = lists.get(op.id);
      if (l) lists.set(op.id, { ...l, name: op.name, ...(op.icon ? { icon: op.icon } : {}) });
      break;
    }
    case 'list_delete':
      if (lists.delete(op.id)) for (const [id, i] of items) if (i.listId === op.id) items.delete(id);
      break;
    case 'item_add':
      if (items.has(op.id) || !lists.has(op.listId)) break;
      items.set(op.id, { id: op.id, listId: op.listId, text: op.text, qty: op.qty || null, checked: false, checkedBy: null, updatedAt: null, deleted: false, ...(pending ? { pending: true } : {}) });
      break;
    case 'item_edit': {
      const i = items.get(op.id);
      if (i) items.set(op.id, { ...i, ...(op.text !== undefined ? { text: op.text } : {}), ...(op.qty !== undefined ? { qty: op.qty } : {}) });
      break;
    }
    case 'item_check': {
      const i = items.get(op.id);
      if (i && i.checked !== op.checked) items.set(op.id, { ...i, checked: op.checked, checkedBy: op.checked ? userId : null });
      break;
    }
    case 'item_delete':
      items.delete(op.id);
      break;
    case 'clear_checked':
      for (const [id, i] of items) if (i.listId === op.listId && i.checked) items.delete(id);
      break;
    default:
      break;
  }
}

/** Operations the server took (all of `ops` but the rejected indexes) into base. */
function confirm(st, ops, rejected, ctx) {
  const no = new Set((rejected || []).map((r) => r.index));
  ops.forEach((op, i) => { if (!no.has(i)) applyOp(st.lists, st.items, op, ctx); });
}

/** base with the queue on top → { lists: [ShopList], items: [ShopItem] } (lists in the server's order, new ones last). */
function view(st, queue, ctx) {
  const lists = new Map(st.lists);
  const items = new Map(st.items);
  for (const op of queue || []) applyOp(lists, items, op, { ...(ctx || {}), pending: true });
  const n = new Map();
  for (const i of items.values()) {
    const c = n.get(i.listId) || { open: 0, total: 0 };
    c.total++;
    if (!i.checked) c.open++;
    n.set(i.listId, c);
  }
  return {
    lists: [...lists.values()].map((l) => ({ ...l, ...(n.get(l.id) || { open: 0, total: 0 }) })),
    items: [...items.values()],
  };
}

/** The queue as it was stored ({ scope, ops }) for this server and person → the ops (cleaned again), else []. */
function storedQueue(v, scope) {
  if (!v || typeof v !== 'object' || v.scope !== scope || !Array.isArray(v.ops)) return [];
  return v.ops.slice(0, QUEUE_MAX).map((o) => N.shopOp(o)).filter(Boolean);
}

module.exports = { QUEUE_MAX, newState, merge, applyOp, confirm, view, storedQueue };
