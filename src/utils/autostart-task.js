/**
 * GateControl – Autostart task for the Windows Task Scheduler (Core)
 *
 * An app that runs with requireAdministrator cannot autostart through the
 * Run key (login items): Windows does not start elevated programs from there.
 * It registers a task with a logon trigger instead.
 *
 * `schtasks /Create /SC ONLOGON …` leaves every other setting at the Task
 * Scheduler defaults, and those are meant for short jobs, not for an app that
 * runs for weeks:
 *   - ExecutionTimeLimit PT72H: Windows ends the app after 3 days.
 *   - DisallowStartIfOnBatteries / StopIfGoingOnBatteries: a laptop on battery
 *     does not start the app, or ends it when the charger is unplugged.
 *   - Priority 7: below-normal CPU priority and low I/O and memory priority,
 *     inherited by everything the app starts.
 * schtasks has no switches for these, so the task is registered from a task
 * XML (`schtasks /Create /F /XML`). /F replaces an existing task, so calling
 * this on every start brings older installations up to date.
 *
 * buildAutostartTaskXml / schtasksXmlArgs are pure (unit-tested);
 * registerAutostartTask takes its side effects (execFile, fs) as parameters.
 */

'use strict';

const TASK_NS = 'http://schemas.microsoft.com/windows/2004/02/mit/task';

/**
 * Settings of the autostart task (Task Scheduler schema 1.2, Windows 7+).
 * Keys are the XML element names under <Settings>.
 */
const AUTOSTART_TASK_SETTINGS = Object.freeze({
  // The app is single-instance; a second start while it runs is not needed.
  MultipleInstancesPolicy: 'IgnoreNew',
  // Start and keep running on battery (laptops).
  DisallowStartIfOnBatteries: false,
  StopIfGoingOnBatteries: false,
  AllowHardTerminate: true,
  // Logon trigger: there is no missed run to catch up on. A late start would
  // only bring the window of an already running app to the front.
  StartWhenAvailable: false,
  RunOnlyIfNetworkAvailable: false,
  AllowStartOnDemand: true,
  Enabled: true,
  Hidden: false,
  RunOnlyIfIdle: false,
  WakeToRun: false,
  // No limit (default PT72H: the app would be ended after 3 days).
  ExecutionTimeLimit: 'PT0S',
  // 4 = normal priority class with normal I/O and memory priority, like a
  // program started from the desktop (default 7 = below normal, low I/O).
  Priority: 4,
});

/** Default start delay after logon (as before: /DELAY 0000:10). */
const DEFAULT_DELAY = 'PT10S';

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Command line arguments as Windows expects them (quoted when they contain blanks or quotes). */
function joinArgs(args) {
  return (Array.isArray(args) ? args : [])
    .map((a) => String(a))
    .map((a) => (a === '' || /[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a))
    .join(' ');
}

/**
 * The account the task is registered for, "DOMAIN\user" (or null).
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{ userInfo?: () => { username: string } }} [os]
 * @returns {string|null}
 */
function currentUserId(env = process.env, os = require('os')) {
  let name = env && env.USERNAME;
  if (!name) {
    try { name = os.userInfo().username; } catch { name = null; }
  }
  if (!name) return null;
  const domain = env && env.USERDOMAIN;
  return domain ? `${domain}\\${name}` : name;
}

/**
 * Task XML of the autostart task.
 *
 * @param {object} o
 * @param {string} o.command - full path of the exe
 * @param {string[]} [o.args]
 * @param {string|null} [o.userId] - "DOMAIN\user": logon trigger and principal
 *   for this account only; without it the trigger fires at any logon and the
 *   task runs as the account that registers it.
 * @param {string} [o.delay] - ISO 8601 duration after logon (default PT10S)
 * @param {string} [o.description]
 * @param {Partial<typeof AUTOSTART_TASK_SETTINGS>} [o.settings] - overrides (tests)
 * @returns {string}
 */
function buildAutostartTaskXml(o) {
  if (!o || typeof o.command !== 'string' || !o.command.trim()) throw new Error('autostart task: command missing');
  const userId = typeof o.userId === 'string' && o.userId.trim() ? o.userId.trim() : null;
  const delay = typeof o.delay === 'string' && /^PT(?:\d+H)?(?:\d+M)?(?:\d+S)?$/.test(o.delay) && o.delay !== 'PT' ? o.delay : DEFAULT_DELAY;
  const settings = { ...AUTOSTART_TASK_SETTINGS, ...(o.settings || {}) };
  const args = joinArgs(o.args);
  const userLine = userId ? `\n      <UserId>${xmlEscape(userId)}</UserId>` : '';

  const settingLines = Object.entries(settings)
    .map(([k, v]) => `    <${k}>${xmlEscape(typeof v === 'boolean' ? String(v) : v)}</${k}>`);
  // Only relevant with RunOnlyIfIdle; explicit so the defaults (stop when the user returns) never apply.
  settingLines.push('    <IdleSettings>\n      <StopOnIdleEnd>false</StopOnIdleEnd>\n      <RestartOnIdle>false</RestartOnIdle>\n    </IdleSettings>');

  return [
    '<?xml version="1.0" encoding="UTF-16"?>',
    `<Task version="1.2" xmlns="${TASK_NS}">`,
    '  <RegistrationInfo>',
    o.description ? `    <Description>${xmlEscape(o.description)}</Description>` : null,
    '  </RegistrationInfo>',
    '  <Triggers>',
    '    <LogonTrigger>',
    `      <Enabled>true</Enabled>${userLine}`,
    `      <Delay>${delay}</Delay>`,
    '    </LogonTrigger>',
    '  </Triggers>',
    '  <Principals>',
    `    <Principal id="Author">${userLine}`,
    '      <LogonType>InteractiveToken</LogonType>',
    '      <RunLevel>HighestAvailable</RunLevel>',
    '    </Principal>',
    '  </Principals>',
    '  <Settings>',
    ...settingLines,
    '  </Settings>',
    '  <Actions Context="Author">',
    '    <Exec>',
    `      <Command>${xmlEscape(o.command)}</Command>`,
    args ? `      <Arguments>${xmlEscape(args)}</Arguments>` : null,
    '    </Exec>',
    '  </Actions>',
    '</Task>',
    '',
  ].filter((l) => l !== null).join('\n').replace(/\r?\n/g, '\r\n');
}

/** UTF-16 LE with BOM: the encoding schtasks /XML reads reliably. */
function encodeTaskXml(xml) {
  return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(xml, 'utf16le')]);
}

/** schtasks arguments: create or replace the task from a task XML file. */
function schtasksXmlArgs(taskName, xmlPath) {
  return ['/Create', '/F', '/TN', taskName, '/XML', xmlPath];
}

/** schtasks arguments of the old registration (fallback only: Task Scheduler defaults). */
function schtasksLegacyArgs(taskName, command) {
  return ['/Create', '/F', '/TN', taskName, '/TR', `"${command}"`, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/DELAY', '0000:10'];
}

/**
 * Create or replace the autostart task (idempotent).
 *
 * The task XML goes into a fresh directory (mkdtemp) under `dir` and is
 * removed afterwards. For an elevated app `dir` should be a place a normal
 * process of the same user cannot change (e.g. %ProgramData%: a new folder
 * there belongs to the administrators), otherwise the file could be swapped
 * before schtasks reads it.
 *
 * Order: XML for this account → XML without account → old schtasks
 * arguments (the app still autostarts, with the Task Scheduler defaults).
 *
 * @param {object} o
 * @param {string} o.taskName
 * @param {string} o.command
 * @param {string[]} [o.args]
 * @param {(file: string, args: string[]) => Promise<any>} o.execFile
 * @param {string} o.dir
 * @param {string|null} [o.userId]
 * @param {string} [o.description]
 * @param {object} [o.fs] - node:fs (tests)
 * @param {object} [o.path] - node:path (tests)
 * @param {object} [o.log]
 * @returns {Promise<'xml'|'xml-any-user'|'legacy'>}
 */
async function registerAutostartTask(o) {
  const fs = o.fs || require('fs');
  const path = o.path || require('path');
  const log = o.log || null;
  const attempts = o.userId ? [o.userId, null] : [null];

  for (const userId of attempts) {
    let dir = null;
    try {
      dir = fs.mkdtempSync(path.join(o.dir, 'gc-autostart-'));
      const file = path.join(dir, 'task.xml');
      const xml = buildAutostartTaskXml({ command: o.command, args: o.args, userId, description: o.description });
      fs.writeFileSync(file, encodeTaskXml(xml), { flag: 'wx' });
      await o.execFile('schtasks', schtasksXmlArgs(o.taskName, file));
      return userId ? 'xml' : 'xml-any-user';
    } catch (err) {
      log?.warn(`Autostart task from XML failed${userId ? '' : ' (any user)'}: ${err && err.message}`);
    } finally {
      if (dir) {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
      }
    }
  }

  // Last resort: the old registration, so the app still starts with Windows.
  await o.execFile('schtasks', schtasksLegacyArgs(o.taskName, o.command));
  log?.warn('Autostart task registered with the Task Scheduler defaults (3-day limit, not on battery)');
  return 'legacy';
}

/** schtasks arguments: remove the task. */
function schtasksDeleteArgs(taskName) {
  return ['/Delete', '/F', '/TN', taskName];
}

module.exports = {
  AUTOSTART_TASK_SETTINGS,
  DEFAULT_DELAY,
  buildAutostartTaskXml,
  encodeTaskXml,
  currentUserId,
  joinArgs,
  schtasksXmlArgs,
  schtasksLegacyArgs,
  schtasksDeleteArgs,
  registerAutostartTask,
};
