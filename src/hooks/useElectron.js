/**
 * useElectron — Electron context bridge hook
 *
 * Provides a safe abstraction over window.alvoraBridge.
 * When running in a browser (not Electron), returns stubs so the
 * app still works as a web app without crashes.
 */

import { useEffect, useState, useCallback } from 'react';

const bridge = typeof window !== 'undefined' ? window.alvoraBridge : null;

// ─── Public Hook ──────────────────────────────────────────────────────────────

export function useElectron() {
  const isElectron = !!bridge;
  const [version,  setVersion]  = useState('1.0.0');
  const [platform, setPlatform] = useState('web');

  useEffect(() => {
    if (!bridge) return;
    bridge.getVersion().then(setVersion).catch(() => {});
    setPlatform(bridge.platform ?? 'unknown');
  }, []);

  // ── Window controls ─────────────────────────────────────────────────────────
  const minimizeWindow    = useCallback(() => bridge?.window.minimize(),       []);
  const maximizeWindow    = useCallback(() => bridge?.window.maximize(),       []);
  const closeWindow       = useCallback(() => bridge?.window.close(),          []);
  const minimizeToTray    = useCallback(() => bridge?.window.minimizeToTray(), []);

  // ── Notifications ───────────────────────────────────────────────────────────
  const sendNotification = useCallback((title, body, urgency = 'normal') => {
    if (bridge) return bridge.notify(title, body, urgency);
    // Web fallback: browser Notification API
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, { body });
    }
  }, []);

  // ── Shell ───────────────────────────────────────────────────────────────────
  const openExternal = useCallback((url) => {
    if (bridge) return bridge.openExternal(url);
    window.open(url, '_blank', 'noopener,noreferrer');
  }, []);

  // ── License ─────────────────────────────────────────────────────────────────
  const readLicense  = useCallback(async () => {
    if (bridge) return bridge.license.read();
    // Web fallback: localStorage
    try { return JSON.parse(localStorage.getItem('alvora_license') ?? 'null'); } catch { return null; }
  }, []);

  const writeLicense = useCallback(async (data) => {
    if (bridge) return bridge.license.write(data);
    localStorage.setItem('alvora_license', JSON.stringify(data));
    return { success: true };
  }, []);

  const clearLicense = useCallback(async () => {
    if (bridge) return bridge.license.clear();
    localStorage.removeItem('alvora_license');
    return { success: true };
  }, []);

  // ── Settings ────────────────────────────────────────────────────────────────
  const readSettings  = useCallback(async () => {
    if (bridge) return bridge.settings.read();
    try { return JSON.parse(localStorage.getItem('alvora_settings') ?? 'null'); } catch { return null; }
  }, []);

  const writeSettings = useCallback(async (data) => {
    if (bridge) return bridge.settings.write(data);
    localStorage.setItem('alvora_settings', JSON.stringify(data));
    return { success: true };
  }, []);

  // ── Reports ─────────────────────────────────────────────────────────────────
  const exportReport = useCallback(async (content) => {
    if (bridge) return bridge.exportReport(content);
    // Web fallback: download as JSON file
    const blob = new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `alvora-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    return { success: true };
  }, []);

  // ── Navigation from tray ────────────────────────────────────────────────────
  const onNavigate = useCallback((cb) => {
    if (!bridge) return () => {};
    return bridge.onNavigate(cb);
  }, []);

  // ── Encrypted API keys (Electron only) ────────────────────────────────────────
  const listApiKeys = useCallback(async () => {
    if (bridge) return bridge.apiKeys.list();
    return [];
  }, []);
  const setApiKey = useCallback(async (name, value) => {
    if (bridge) return bridge.apiKeys.set(name, value);
    return { success: false, error: 'API keys require the desktop app' };
  }, []);
  const removeApiKey = useCallback(async (name) => {
    if (bridge) return bridge.apiKeys.remove(name);
    return { success: false };
  }, []);

  // ── Downloads scanner actions (Electron only; main process restricts to ~/Downloads) ──
  const revealDownload = useCallback(async (p) => bridge?.downloads?.reveal(p) ?? { error: 'Desktop app only' }, []);
  const trashDownload  = useCallback(async (p) => bridge?.downloads?.trash(p)  ?? { error: 'Desktop app only' }, []);

  // ── System Settings shortcut (Electron on macOS only; panes allowlisted in main) ──
  const openSystemSettings = bridge?.openSystemSettings
    ? (pane) => bridge.openSystemSettings(pane)
    : null;

  return {
    isElectron,
    version,
    platform,
    minimizeWindow,
    maximizeWindow,
    closeWindow,
    minimizeToTray,
    sendNotification,
    openExternal,
    readLicense,
    writeLicense,
    clearLicense,
    readSettings,
    writeSettings,
    exportReport,
    onNavigate,
    listApiKeys,
    setApiKey,
    removeApiKey,
    revealDownload,
    trashDownload,
    openSystemSettings,
  };
}
