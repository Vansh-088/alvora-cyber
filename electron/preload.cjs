'use strict';

/**
 * Alvora Cyber — Electron Preload / Context Bridge
 *
 * Exposes a secure, minimal API surface from the main process to the renderer.
 * All communication goes through ipcRenderer.invoke() — no direct Node access.
 */

const { contextBridge, ipcRenderer } = require('electron');

// Extract the per-install API token passed via additionalArguments.
const tokenArg = process.argv.find(a => a.startsWith('--alvora-api-token='));
const API_TOKEN = tokenArg ? tokenArg.split('=')[1] : '';

contextBridge.exposeInMainWorld('alvoraBridge', {
  // ── Identity ────────────────────────────────────────────────────────────────
  isElectron: true,
  platform:   process.platform,
  apiToken:   API_TOKEN,   // renderer attaches this to backend requests
  getVersion: () => ipcRenderer.invoke('app:version'),

  // ── Window controls ─────────────────────────────────────────────────────────
  window: {
    minimize:        () => ipcRenderer.invoke('window:minimize'),
    maximize:        () => ipcRenderer.invoke('window:maximize'),
    close:           () => ipcRenderer.invoke('window:close'),
    minimizeToTray:  () => ipcRenderer.invoke('window:minimizeToTray'),
  },

  // ── Navigation (from tray menu) ──────────────────────────────────────────────
  onNavigate: (callback) => {
    ipcRenderer.on('navigate', (_, tab) => callback(tab));
    return () => ipcRenderer.removeAllListeners('navigate');
  },

  // ── Shell ────────────────────────────────────────────────────────────────────
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  // Opens a named System Settings page (allowlisted in the main process)
  openSystemSettings: (pane) => ipcRenderer.invoke('systemsettings:open', pane),

  // ── Downloads scanner actions (restricted to ~/Downloads in the main process) ──
  downloads: {
    reveal: (p) => ipcRenderer.invoke('downloads:reveal', p),
    trash:  (p) => ipcRenderer.invoke('downloads:trash', p),
  },

  // ── Notifications ────────────────────────────────────────────────────────────
  notify: (title, body, urgency = 'normal') =>
    ipcRenderer.invoke('notification:send', { title, body, urgency }),

  // ── License (native file persistence) ────────────────────────────────────────
  license: {
    read:  () => ipcRenderer.invoke('license:read'),
    write: (data) => ipcRenderer.invoke('license:write', data),
    clear: () => ipcRenderer.invoke('license:clear'),
  },

  // ── Settings ─────────────────────────────────────────────────────────────────
  settings: {
    read:  () => ipcRenderer.invoke('settings:read'),
    write: (data) => ipcRenderer.invoke('settings:write', data),
  },

  // ── Encrypted API keys (Keychain-backed; values never returned) ────────────────
  apiKeys: {
    list:   () => ipcRenderer.invoke('apikeys:list'),
    set:    (name, value) => ipcRenderer.invoke('apikeys:set', { name, value }),
    remove: (name) => ipcRenderer.invoke('apikeys:delete', name),
  },

  // ── System info ──────────────────────────────────────────────────────────────
  getSystemInfo: () => ipcRenderer.invoke('system:info'),

  // ── Reports ──────────────────────────────────────────────────────────────────
  exportReport: (content) => ipcRenderer.invoke('report:export', content),
});
