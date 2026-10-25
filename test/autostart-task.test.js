'use strict';

// Autostart task (Task Scheduler): the task XML must not keep the defaults
// meant for short jobs (3-day limit, no start / stop on battery, low
// priority), and registerAutostartTask replaces the task idempotently with
// fallbacks. Pure parts and fakes; the real schtasks runs in
// autostart-task.win.test.js (Windows only).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  AUTOSTART_TASK_SETTINGS, buildAutostartTaskXml, encodeTaskXml, currentUserId, joinArgs,
  schtasksXmlArgs, schtasksLegacyArgs, schtasksDeleteArgs, registerAutostartTask,
} = require('../src/utils/autostart-task');

const EXE = 'C:\\Program Files\\GateControl Pro Client\\GateControl Pro Client.exe';

/** Text of the first <tag> element (no XML parser in the core: plain match). */
function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}(?: [^>]*)?>([^<]*)</${name}>`));
  return m ? m[1] : null;
}

describe('buildAutostartTaskXml', () => {
  const xml = buildAutostartTaskXml({ command: EXE, userId: 'PC01\\maria', description: 'GateControl Pro autostart' });

  it('no 3-day limit, runs on battery, normal priority', () => {
    assert.equal(tag(xml, 'ExecutionTimeLimit'), 'PT0S');
    assert.equal(tag(xml, 'DisallowStartIfOnBatteries'), 'false');
    assert.equal(tag(xml, 'StopIfGoingOnBatteries'), 'false');
    assert.equal(tag(xml, 'Priority'), '4');
    assert.equal(tag(xml, 'MultipleInstancesPolicy'), 'IgnoreNew');
    assert.equal(tag(xml, 'StartWhenAvailable'), 'false');
    assert.equal(tag(xml, 'RunOnlyIfIdle'), 'false');
    assert.equal(tag(xml, 'RunOnlyIfNetworkAvailable'), 'false');
    assert.equal(tag(xml, 'StopOnIdleEnd'), 'false');
    assert.equal(tag(xml, 'Enabled'), 'true');
    assert.equal(AUTOSTART_TASK_SETTINGS.ExecutionTimeLimit, 'PT0S');
    assert.ok(Object.isFrozen(AUTOSTART_TASK_SETTINGS));
  });

  it('logon trigger for this user, elevated, 10 s delay, the exe as action', () => {
    assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-16"\?>\r\n<Task version="1\.2" xmlns="http:\/\/schemas\.microsoft\.com\/windows\/2004\/02\/mit\/task">/);
    assert.match(xml, /<LogonTrigger>\r\n\s*<Enabled>true<\/Enabled>\r\n\s*<UserId>PC01\\maria<\/UserId>\r\n\s*<Delay>PT10S<\/Delay>/);
    assert.match(xml, /<Principal id="Author">\r\n\s*<UserId>PC01\\maria<\/UserId>\r\n\s*<LogonType>InteractiveToken<\/LogonType>\r\n\s*<RunLevel>HighestAvailable<\/RunLevel>/);
    assert.equal(tag(xml, 'Command'), EXE);
    assert.equal(tag(xml, 'Arguments'), null);
    assert.equal(tag(xml, 'Description'), 'GateControl Pro autostart');
    assert.match(xml, /<Actions Context="Author">/);
    // one of each block
    for (const t of ['Triggers', 'Principals', 'Settings', 'Actions']) assert.equal(xml.split(`<${t}`).length, 2, t);
  });

  it('without a user: trigger at any logon, principal without account', () => {
    const x = buildAutostartTaskXml({ command: EXE });
    assert.equal(x.includes('<UserId>'), false);
    assert.equal(tag(x, 'Description'), null);
    assert.equal(tag(x, 'ExecutionTimeLimit'), 'PT0S');
  });

  it('escapes XML in path, user and arguments', () => {
    const x = buildAutostartTaskXml({ command: 'C:\\A&B <x>\\app.exe', userId: 'R&D\\o\'neil', args: ['--hidden', 'a "b"'] });
    assert.equal(tag(x, 'Command'), 'C:\\A&amp;B &lt;x&gt;\\app.exe');
    assert.match(x, /<UserId>R&amp;D\\o&apos;neil<\/UserId>/);
    assert.equal(tag(x, 'Arguments'), '--hidden &quot;a \\&quot;b\\&quot;&quot;');
  });

  it('delay: valid durations, anything else falls back to PT10S', () => {
    assert.equal(tag(buildAutostartTaskXml({ command: EXE, delay: 'PT30S' }), 'Delay'), 'PT30S');
    assert.equal(tag(buildAutostartTaskXml({ command: EXE, delay: 'PT1M' }), 'Delay'), 'PT1M');
    for (const d of ['PT', '10', 'P1D', '<x/>', null]) assert.equal(tag(buildAutostartTaskXml({ command: EXE, delay: d }), 'Delay'), 'PT10S', String(d));
  });

  it('needs a command', () => {
    assert.throws(() => buildAutostartTaskXml({}), /command missing/);
    assert.throws(() => buildAutostartTaskXml({ command: '  ' }), /command missing/);
    assert.throws(() => buildAutostartTaskXml(), /command missing/);
  });
});

describe('helpers', () => {
  it('encodeTaskXml: UTF-16 LE with BOM', () => {
    const b = encodeTaskXml('<a>ä</a>');
    assert.deepEqual([...b.subarray(0, 2)], [0xff, 0xfe]);
    assert.equal(b.subarray(2).toString('utf16le'), '<a>ä</a>');
  });

  it('currentUserId: DOMAIN\\user, user alone, os fallback', () => {
    assert.equal(currentUserId({ USERDOMAIN: 'PC01', USERNAME: 'maria' }), 'PC01\\maria');
    assert.equal(currentUserId({ USERNAME: 'maria' }), 'maria');
    assert.equal(currentUserId({}, { userInfo: () => ({ username: 'bob' }) }), 'bob');
    assert.equal(currentUserId({}, { userInfo: () => { throw new Error('x'); } }), null);
  });

  it('joinArgs quotes blanks and quotes', () => {
    assert.equal(joinArgs(['--hidden', 'a b', '']), '--hidden "a b" ""');
    assert.equal(joinArgs(undefined), '');
  });

  it('schtasks arguments', () => {
    assert.deepEqual(schtasksXmlArgs('GateControlProAutostart', 'C:\\x\\task.xml'), ['/Create', '/F', '/TN', 'GateControlProAutostart', '/XML', 'C:\\x\\task.xml']);
    assert.deepEqual(schtasksLegacyArgs('T', EXE), ['/Create', '/F', '/TN', 'T', '/TR', `"${EXE}"`, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/DELAY', '0000:10']);
    assert.deepEqual(schtasksDeleteArgs('T'), ['/Delete', '/F', '/TN', 'T']);
  });
});

describe('registerAutostartTask', () => {
  function tmp() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'gc-autostart-test-'));
  }
  function logDouble() {
    const lines = [];
    return { lines, warn: (m) => lines.push(`warn ${m}`), info: (m) => lines.push(`info ${m}`) };
  }

  it('writes the XML (UTF-16) into a fresh folder, runs schtasks /XML, cleans up', async () => {
    const dir = tmp();
    const calls = [];
    const res = await registerAutostartTask({
      taskName: 'GateControlProAutostart',
      command: EXE,
      userId: 'PC01\\maria',
      dir,
      execFile: async (file, args) => {
        const xmlPath = args[args.indexOf('/XML') + 1];
        assert.equal(path.dirname(path.dirname(xmlPath)), dir);
        assert.match(path.basename(path.dirname(xmlPath)), /^gc-autostart-/);
        const buf = fs.readFileSync(xmlPath);
        calls.push({ file, args, xml: buf.subarray(2).toString('utf16le'), bom: [...buf.subarray(0, 2)] });
      },
    });
    assert.equal(res, 'xml');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, 'schtasks');
    assert.deepEqual(calls[0].args.slice(0, 5), ['/Create', '/F', '/TN', 'GateControlProAutostart', '/XML']);
    assert.deepEqual(calls[0].bom, [0xff, 0xfe]);
    assert.equal(tag(calls[0].xml, 'ExecutionTimeLimit'), 'PT0S');
    assert.match(calls[0].xml, /<UserId>PC01\\maria<\/UserId>/);
    assert.deepEqual(fs.readdirSync(dir), [], 'temporary folder removed');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('idempotent: a second call replaces the task again (/F)', async () => {
    const dir = tmp();
    const calls = [];
    const o = { taskName: 'T', command: EXE, dir, execFile: async (f, a) => { calls.push(a); } };
    assert.equal(await registerAutostartTask(o), 'xml-any-user');
    assert.equal(await registerAutostartTask(o), 'xml-any-user');
    assert.equal(calls.length, 2);
    assert.ok(calls.every((a) => a[0] === '/Create' && a[1] === '/F'));
    assert.deepEqual(fs.readdirSync(dir), []);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('falls back: XML without user, then the old schtasks arguments', async () => {
    const dir = tmp();
    const log = logDouble();
    const calls = [];
    const res = await registerAutostartTask({
      taskName: 'T', command: EXE, userId: 'X\\y', dir, log,
      execFile: async (f, a) => {
        const xml = a.includes('/XML') ? fs.readFileSync(a[a.indexOf('/XML') + 1]).subarray(2).toString('utf16le') : null;
        calls.push({ a, xml });
        if (a.includes('/XML')) throw new Error('ERROR: The task XML is malformed.');
      },
    });
    assert.equal(res, 'legacy');
    assert.equal(calls.length, 3);
    assert.match(calls[0].xml, /<UserId>X\\y<\/UserId>/);
    assert.equal(calls[1].xml.includes('<UserId>'), false);
    assert.deepEqual(calls[2].a, schtasksLegacyArgs('T', EXE));
    assert.ok(log.lines.some((l) => l.includes('malformed')));
    assert.ok(log.lines.some((l) => l.includes('Task Scheduler defaults')));
    assert.deepEqual(fs.readdirSync(dir), []);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('second attempt succeeds: XML for any user', async () => {
    const dir = tmp();
    let n = 0;
    const res = await registerAutostartTask({
      taskName: 'T', command: EXE, userId: 'X\\y', dir,
      execFile: async () => { n += 1; if (n === 1) throw new Error('No mapping between account names and security IDs was done.'); },
    });
    assert.equal(res, 'xml-any-user');
    assert.equal(n, 2);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('everything fails → the error of the last attempt', async () => {
    const dir = tmp();
    await assert.rejects(
      registerAutostartTask({ taskName: 'T', command: EXE, dir, execFile: async (f, a) => { throw new Error(a.includes('/XML') ? 'xml' : 'Access is denied.'); } }),
      /Access is denied/,
    );
    assert.deepEqual(fs.readdirSync(dir), []);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a folder that cannot be created → still the old registration', async () => {
    const calls = [];
    const res = await registerAutostartTask({
      taskName: 'T', command: EXE, dir: path.join(os.tmpdir(), 'gc-does-not-exist', 'nested'),
      execFile: async (f, a) => { calls.push(a); },
    });
    assert.equal(res, 'legacy');
    assert.deepEqual(calls, [schtasksLegacyArgs('T', EXE)]);
  });
});
