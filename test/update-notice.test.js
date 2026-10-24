'use strict';

// Tray entries / notification text for ready updates (shared by Pro and
// Community): a mandatory update sits at the top of the tray menu, an
// optional one at its old place; both install via the client's handler.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const i18n = require('../src/i18n');
const { updateMenuItems, mandatoryNotice, updateToast } = require('../src/utils/update-notice');

i18n.setLocale('de');
const t = i18n.t;

describe('updateMenuItems', () => {
  it('no update → no entries', () => {
    assert.deepEqual(updateMenuItems({ update: null, mandatory: true, t, install() {} }), { top: [], bottom: [] });
  });

  it('optional update → entry at the bottom', () => {
    let clicked = 0;
    const r = updateMenuItems({ update: { version: '1.2.3' }, mandatory: false, t, install: () => clicked++ });
    assert.equal(r.top.length, 0);
    assert.equal(r.bottom[1].label, 'Update 1.2.3 installieren');
    r.bottom[1].click();
    assert.equal(clicked, 1);
  });

  it('mandatory update → prominent entry at the top', () => {
    let clicked = 0;
    const r = updateMenuItems({ update: { version: '1.2.3' }, mandatory: true, t, install: () => clicked++ });
    assert.equal(r.bottom.length, 0);
    assert.equal(r.top[0].label, 'Update erforderlich: v1.2.3 installieren');
    r.top[0].click();
    assert.equal(clicked, 1);
  });
});

describe('mandatoryNotice', () => {
  it('names the minimum and the offered version (de/en)', () => {
    const de = mandatoryNotice({ version: '1.2.3', minVersion: '1.2.0' }, t);
    assert.equal(de.title, 'Update erforderlich');
    assert.match(de.body, /mindestens Version 1\.2\.0/);
    assert.match(de.body, /Version 1\.2\.3/);
    i18n.setLocale('en');
    const en = mandatoryNotice({ version: '1.2.3', minVersion: null }, i18n.t);
    assert.equal(en.title, 'Update required');
    assert.match(en.body, /requires this update/);
    i18n.setLocale('de');
  });
});

describe('updateToast', () => {
  it('optional update: click and "Jetzt installieren" both install', () => {
    let installs = 0;
    const o = updateToast({ version: '1.43.1' }, { t, install: () => installs++, productName: 'GateControl Pro' });
    assert.equal(o.title, 'GateControl Pro');
    assert.equal(o.body, 'Version 1.43.1 verfügbar – zum Installieren klicken.');
    assert.equal(o.collapseKey, 'update');
    assert.equal(o.force, false);
    assert.deepEqual(o.actions.map((a) => a.label), ['Jetzt installieren']);
    o.onClick();
    o.actions[0].onClick();
    assert.equal(installs, 2);
  });

  it('mandatory update: forced, names the required version, click installs', () => {
    let installs = 0;
    const o = updateToast({ version: '2.0.0', minVersion: '1.9.0', mandatory: true }, { t, install: () => installs++, productName: 'GateControl' });
    assert.equal(o.title, 'GateControl - Update erforderlich');
    assert.match(o.body, /1\.9\.0/);
    assert.equal(o.force, true);
    o.onClick();
    assert.equal(installs, 1);
  });
});
