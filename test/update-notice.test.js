'use strict';

// Tray entries / notification text for ready updates (shared by Pro and
// Community): a mandatory update sits at the top of the tray menu, an
// optional one at its old place; both install via the client's handler.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const i18n = require('../src/i18n');
const { updateMenuItems, mandatoryNotice } = require('../src/utils/update-notice');

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
