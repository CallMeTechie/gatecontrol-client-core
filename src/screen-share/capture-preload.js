'use strict';

/**
 * GateControl – Fernzugriff stage 7: the preload of the hidden capture window (src/screen-share/capture.html).
 * Two channels, nothing else: commands from the main process in, the encoder's output out. No Node in the page.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gcCapture', {
  /** cb({ t: 'start' | 'keyframe' | 'bitrate' | 'stop', … }) */
  onCommand: (cb) => { ipcRenderer.on('gc-capture:cmd', (_e, m) => cb(m)); },
  /** { t: 'started' | 'config' | 'chunk' | 'error' | 'stopped', … } */
  post: (m) => ipcRenderer.send('gc-capture:event', m),
});
