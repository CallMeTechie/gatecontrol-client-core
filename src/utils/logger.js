/**
 * GateControl – Logger Setup (Core)
 *
 * Configures electron-log with standard settings:
 * - File transport: info level, 5 MB max
 * - Console transport: debug level
 */

'use strict';

const log = require('electron-log');

/**
 * Create and configure the logger.
 *
 * @param {object} [options]
 * @param {string} [options.fileLevel='info'] - Log level for file transport
 * @param {string} [options.consoleLevel='debug'] - Log level for console transport
 * @param {number} [options.maxFileSize=5242880] - Max log file size in bytes (default 5 MB)
 * @returns {object} Configured electron-log instance
 */
function createLogger(options = {}) {
  const {
    fileLevel = 'info',
    consoleLevel = 'debug',
    maxFileSize = 5 * 1024 * 1024,
  } = options;

  log.transports.file.level = fileLevel;
  log.transports.file.maxSize = maxFileSize;
  log.transports.console.level = consoleLevel;

  return log;
}

module.exports = { createLogger };
