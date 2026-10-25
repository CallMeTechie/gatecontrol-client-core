'use strict';

// Autostart task against the real Task Scheduler (Windows only, needs admin
// rights for RunLevel HighestAvailable; GitHub's Windows runners have them).
// Registers a task with a random name pointing at node.exe (logon trigger, it
// never runs here), reads it back with schtasks /Query /XML and removes it.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const { registerAutostartTask, currentUserId, schtasksDeleteArgs } = require('../src/utils/autostart-task');

const win = process.platform === 'win32';
const run = promisify(execFile);
const TASK = `GateControlCoreTest-${crypto.randomBytes(4).toString('hex')}`;

function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}(?: [^>]*)?>([^<]*)</${name}>`));
  return m ? m[1] : null;
}

describe('autostart task on Windows (schtasks)', { skip: win ? false : 'Windows only' }, () => {
  after(async () => {
    try { await run('schtasks', schtasksDeleteArgs(TASK), { windowsHide: true }); } catch { /* not created */ }
  });

  it('registers from XML with the corrected settings, twice (idempotent)', async () => {
    const log = { warn: (m) => console.log(`warn: ${m}`) };
    const opts = {
      taskName: TASK,
      command: process.execPath,
      userId: currentUserId(),
      description: 'GateControl core test (removed after the test)',
      dir: process.env.ProgramData || os.tmpdir(),
      execFile: (f, a) => run(f, a, { windowsHide: true }),
      log,
    };
    assert.equal(await registerAutostartTask(opts), 'xml');
    assert.equal(await registerAutostartTask(opts), 'xml');

    const { stdout } = await run('schtasks', ['/Query', '/TN', TASK, '/XML'], { windowsHide: true });
    assert.equal(tag(stdout, 'ExecutionTimeLimit'), 'PT0S');
    assert.equal(tag(stdout, 'DisallowStartIfOnBatteries'), 'false');
    assert.equal(tag(stdout, 'StopIfGoingOnBatteries'), 'false');
    assert.equal(tag(stdout, 'Priority'), '4');
    assert.equal(tag(stdout, 'MultipleInstancesPolicy'), 'IgnoreNew');
    assert.equal(tag(stdout, 'RunLevel'), 'HighestAvailable');
    assert.equal(tag(stdout, 'LogonType'), 'InteractiveToken');
    assert.equal(tag(stdout, 'Delay'), 'PT10S');
    assert.equal(tag(stdout, 'Command').toLowerCase(), process.execPath.toLowerCase());
    assert.match(stdout, /<LogonTrigger>/);
  });
});
