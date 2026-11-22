'use strict';

/**
 * Alvora Cyber — Electron Main Process
 *
 * Handles app lifecycle, system tray, window management, IPC,
 * and backend process spawning for the desktop application.
 */

const {
  app,
  BrowserWindow,
  Tray,
  Menu,
  nativeImage,
  shell,
  ipcMain,
  Notification,
  dialog,
  nativeTheme,
  utilityProcess,
  safeStorage,
  session,
} = require('electron');

const path   = require('path');
const { spawn, exec } = require('child_process');
const fs     = require('fs');
const os     = require('os');
const crypto = require('crypto');

// ── Environment ──────────────────────────────────────────────────────────────

const isDev         = process.env.NODE_ENV === 'development';
const BACKEND_PORT  = parseInt(process.env.PORT || '3001', 10);
const VITE_PORT     = 5173;

// nvm node path (needed when spawning the backend)
const NODE_BINARY = (() => {
  const nvmNode = '/Users/vanshdudhagra/.nvm/versions/node/v24.14.0/bin/node';
  if (fs.existsSync(nvmNode)) return nvmNode;
  return process.execPath; // fallback to Electron's bundled node
})();

// ── State ────────────────────────────────────────────────────────────────────

let mainWindow    = null;
let tray          = null;
let backendChild  = null;   // utilityProcess handle
let isQuitting    = false;

// ── API access token ─────────────────────────────────────────────────────────
// A random per-install secret. The renderer and backend share it; the backend
// rejects any /api request without it — so other local processes / curl can't
// drive the security backend. Persisted so it's stable across launches.
const tokenFile = path.join(app.getPath('userData'), 'api-token');
function getApiToken() {
  try {
    return fs.readFileSync(tokenFile, 'utf8').trim();
  } catch {
    const t = crypto.randomBytes(32).toString('hex');
    try { fs.writeFileSync(tokenFile, t, { mode: 0o600 }); } catch {}
    return t;
  }
}
const API_TOKEN = getApiToken();

// ── Encrypted API-key store (macOS Keychain via safeStorage) ──────────────────
// Third-party API keys (AbuseIPDB, Anthropic, …) are encrypted at rest with an
// OS-managed key — never written as plaintext .env. Stored as a single encrypted
// blob; decrypted only in memory and handed to the backend at spawn time.
const apiKeysFile = path.join(app.getPath('userData'), 'api-keys.enc');

function readApiKeys() {
  try {
    const blob = fs.readFileSync(apiKeysFile);
    if (!safeStorage.isEncryptionAvailable()) return {};
    return JSON.parse(safeStorage.decryptString(blob));
  } catch {
    return {};
  }
}

function writeApiKeys(keys) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage unavailable — cannot store API keys safely');
  }
  const enc = safeStorage.encryptString(JSON.stringify(keys));
  fs.writeFileSync(apiKeysFile, enc, { mode: 0o600 });
}

// License state (persisted in userData)
const licenseFile = path.join(app.getPath('userData'), 'license.json');

function readLicense() {
  try {
    return JSON.parse(fs.readFileSync(licenseFile, 'utf8'));
  } catch {
    return null;
  }
}

function writeLicense(data) {
  fs.writeFileSync(licenseFile, JSON.stringify(data, null, 2), 'utf8');
}

// Settings state
const settingsFile = path.join(app.getPath('userData'), 'settings.json');

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  } catch {
    return {
      autoLaunch: true,      // background security service — start on login by default
      notifications: true,
      scanInterval: 10,
      minimizeToTray: true,
      theme: 'dark',
    };
  }
}

function writeSettings(data) {
  fs.writeFileSync(settingsFile, JSON.stringify(data, null, 2), 'utf8');
}

// ── Launch at login ─────────────────────────────────────────────────────────
// Uses the OS-sanctioned login-item API (macOS SMAppService / Windows registry).
// This is deliberately chosen over a hand-written LaunchAgent plist: a manual
// plist hard-codes the .app path and silently breaks whenever the app is moved
// or updated, whereas setLoginItemSettings is managed by the OS and survives
// app moves. Defaults to ON (Alvora is a background security service).
function applyLoginItem() {
  // Never register a dev build (node_modules/electron) as a login item — only
  // the installed app should launch at login.
  if (isDev || !app.isPackaged) return;
  try {
    const settings = readSettings();
    const enabled  = settings.autoLaunch !== false; // default true
    app.setLoginItemSettings({
      openAtLogin:  enabled,
      openAsHidden: true,             // start in the background (tray only)
      name:         'Alvora Cyber',
    });
  } catch (e) {
    console.error('[Electron] applyLoginItem failed:', e.message);
  }
}

// ── Backend Spawn ─────────────────────────────────────────────────────────────

function startBackend() {
  if (isDev) {
    console.log('[Electron] Dev mode — backend runs via npm run dev');
    return Promise.resolve();
  }

  const serverPath = path.join(process.resourcesPath, 'backend', 'server.js');

  if (!fs.existsSync(serverPath)) {
    console.error('[Electron] Backend not found at:', serverPath);
    return Promise.resolve();
  }

  // utilityProcess uses Electron's built-in Node — no external binary needed
  backendChild = utilityProcess.fork(serverPath, [], {
    stdio: 'pipe',
    env: {
      ...process.env,
      NODE_ENV:        'production',
      PORT:            String(BACKEND_PORT),
      ELECTRON_APP:    '1',
      ALVORA_VERSION:  app.getVersion(),
      // Persistent storage location for vault, SQLite DB, and geo cache.
      // Lives in the OS user-data dir so it survives app updates/reinstalls.
      ALVORA_DATA_DIR: app.getPath('userData'),
      // Shared secret — backend requires this on sensitive /api routes.
      ALVORA_API_TOKEN: API_TOKEN,
      // Decrypted third-party keys, in-memory only (encrypted at rest via Keychain).
      ABUSEIPDB_KEY:  readApiKeys().abuseipdb || '',
      ANTHROPIC_KEY:  readApiKeys().anthropic || '',
      NVIDIA_NIM_KEY: readApiKeys().nvidia || '',
      ABUSECH_KEY:    readApiKeys().abusech || '',   // optional MalwareBazaar hash lookups
      OPENROUTER_KEY: readApiKeys().openrouter || '', // optional "Explain with AI" via OpenRouter
    },
    cwd: path.dirname(serverPath),
  });

  backendChild.stdout?.on('data', d => console.log('[Backend]', d.toString().trim()));
  backendChild.stderr?.on('data', d => console.error('[Backend]', d.toString().trim()));
  backendChild.on('exit', (code) => {
    if (!isQuitting) console.warn('[Electron] Backend exited with code:', code);
  });

  // Give backend ~1.5 s to bind port before window loads
  return new Promise(resolve => setTimeout(resolve, 1500));
}

// ── Window ────────────────────────────────────────────────────────────────────

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1200,
    minHeight: 720,
    backgroundColor: '#0a0f1a',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
    frame: process.platform !== 'darwin',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,            // renderer cannot touch Node internals
      nodeIntegration:  false,           // no require() in the renderer
      sandbox:          true,            // run renderer in OS sandbox
      webSecurity:      true,
      devTools:         isDev,           // DevTools disabled in production builds
      // Hand the per-install API token to the renderer via argv (read in preload)
      additionalArguments: [`--alvora-api-token=${API_TOKEN}`],
    },
    show: false, // Show after load to avoid white flash
  });

  if (!isDev) {
    // Start backend first (non-blocking after 1.5s grace)
    startBackend();
  }

  if (isDev) {
    // Dev: load from Vite dev server
    mainWindow.loadURL(`http://localhost:${VITE_PORT}`).catch(err => {
      console.error('[Electron] Failed to load dev URL:', err.message);
    });
  } else {
    // Production: load built React from file:// — no HTTP dependency
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html')).catch(err => {
      console.error('[Electron] Failed to load app:', err.message);
    });
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // DevTools in development
  if (isDev) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  // Minimize to tray instead of closing (if setting enabled)
  mainWindow.on('close', (e) => {
    if (!isQuitting && readSettings().minimizeToTray) {
      e.preventDefault();
      mainWindow.hide();
      if (process.platform === 'darwin') app.dock?.hide();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ── Tray ──────────────────────────────────────────────────────────────────────

function createTray() {
  // Create a simple programmatic icon (16x16 cyan shield)
  const iconData = createTrayIcon();
  const icon = nativeImage.createFromBuffer(iconData).resize({ width: 16, height: 16 });

  tray = new Tray(icon);

  const updateTrayMenu = (status = 'Active') => {
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Alvora Cyber',
        enabled: false,
        icon: nativeImage.createFromBuffer(iconData).resize({ width: 16, height: 16 }),
      },
      { type: 'separator' },
      {
        label: `AI Security: ${status}`,
        enabled: false,
      },
      { type: 'separator' },
      {
        label: 'Open Dashboard',
        accelerator: 'CmdOrCtrl+Shift+A',
        click: () => {
          mainWindow?.show();
          mainWindow?.focus();
          if (process.platform === 'darwin') app.dock?.show();
        },
      },
      {
        label: 'Scan Prompt Now',
        click: () => {
          mainWindow?.show();
          mainWindow?.focus();
          mainWindow?.webContents.send('navigate', 'ai-monitor');
        },
      },
      { type: 'separator' },
      {
        label: 'Settings',
        click: () => {
          mainWindow?.show();
          mainWindow?.webContents.send('navigate', 'settings');
        },
      },
      { type: 'separator' },
      {
        label: 'Quit Alvora Cyber',
        click: () => {
          isQuitting = true;
          app.quit();
        },
      },
    ]);

    tray.setContextMenu(contextMenu);
  };

  tray.setToolTip('Alvora Cyber — AI Security Active');
  updateTrayMenu();

  tray.on('double-click', () => {
    mainWindow?.show();
    mainWindow?.focus();
    if (process.platform === 'darwin') app.dock?.show();
  });
}

/**
 * Creates a tiny PNG buffer for the tray icon (programmatic, no file needed)
 * In production, replace with a real .icns / .ico file via electron-builder
 */
function createTrayIcon() {
  // 16x16 minimal PNG — a simple square
  // Real app: use electron/assets/tray.png
  const { nativeImage: ni } = require('electron');
  const img = ni.createEmpty();
  return img.isEmpty()
    ? Buffer.alloc(0)
    : img.toPNG();
}

// ── IPC Handlers ──────────────────────────────────────────────────────────────

function setupIPC() {
  // ── App info ────────────────────────────────────────────────────────────────
  ipcMain.handle('app:version', () => app.getVersion());
  ipcMain.handle('app:platform', () => process.platform);
  ipcMain.handle('app:isElectron', () => true);

  // ── Window controls ─────────────────────────────────────────────────────────
  ipcMain.handle('window:minimize', () => mainWindow?.minimize());
  ipcMain.handle('window:maximize', () => {
    if (mainWindow?.isMaximized()) mainWindow.unmaximize();
    else mainWindow?.maximize();
  });
  ipcMain.handle('window:close', () => mainWindow?.close());
  ipcMain.handle('window:minimizeToTray', () => {
    mainWindow?.hide();
    if (process.platform === 'darwin') app.dock?.hide();
  });

  // ── Shell ────────────────────────────────────────────────────────────────────
  ipcMain.handle('shell:openExternal', async (_, url) => {
    // Web links only — never file://, custom app schemes, etc.
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return { error: 'Only web links can be opened' };
    await shell.openExternal(url);
  });

  // ── System Settings shortcuts for the Security Check guide ───────────────────
  // Fixed allowlist: the renderer names a pane, never supplies a URL.
  const SETTINGS_PANES = {
    filevault:  'x-apple.systempreferences:com.apple.preference.security?FileVault',
    firewall:   'x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall',
    security:   'x-apple.systempreferences:com.apple.preference.security?General',
    updates:    'x-apple.systempreferences:com.apple.Software-Update-Settings.extension',
    lockscreen: 'x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension',
    sharing:    'x-apple.systempreferences:com.apple.Sharing-Settings.extension',
    users:      'x-apple.systempreferences:com.apple.Users-Groups-Settings.extension',
  };
  ipcMain.handle('systemsettings:open', async (_, pane) => {
    const url = Object.hasOwn(SETTINGS_PANES, pane) ? SETTINGS_PANES[pane] : null;
    if (!url || process.platform !== 'darwin') return { error: 'Unknown settings page' };
    await shell.openExternal(url);
    return { success: true };
  });

  // ── Downloads scanner actions ────────────────────────────────────────────────
  // Only files directly inside the user's Downloads folder (what the scanner
  // watches) — the renderer can't point these at arbitrary paths.
  const downloadsDir = app.getPath('downloads');
  const inDownloads = (p) => {
    if (typeof p !== 'string') return null;
    const resolved = path.resolve(p);
    return resolved.startsWith(downloadsDir + path.sep) && fs.existsSync(resolved) ? resolved : null;
  };
  ipcMain.handle('downloads:reveal', (_, p) => {
    const file = inDownloads(p);
    if (!file) return { error: 'Not a file in your Downloads folder' };
    shell.showItemInFolder(file);
    return { success: true };
  });
  ipcMain.handle('downloads:trash', async (_, p) => {
    const file = inDownloads(p);
    if (!file) return { error: 'Not a file in your Downloads folder' };
    await shell.trashItem(file);   // recoverable from the Trash
    return { success: true };
  });

  // ── Notifications ────────────────────────────────────────────────────────────
  ipcMain.handle('notification:send', async (_, { title, body, urgency = 'normal' }) => {
    if (readSettings().notifications === false) return;   // the user turned alerts off
    if (Notification.isSupported()) {
      const notif = new Notification({
        title,
        body,
        urgency,
        silent: urgency !== 'critical',
      });
      notif.show();
      notif.on('click', () => {
        mainWindow?.show();
        mainWindow?.focus();
      });
    }
  });

  // ── License ──────────────────────────────────────────────────────────────────
  ipcMain.handle('license:read', () => readLicense());
  ipcMain.handle('license:write', (_, data) => {
    writeLicense(data);
    return { success: true };
  });
  ipcMain.handle('license:clear', () => {
    try { fs.unlinkSync(licenseFile); } catch {}
    return { success: true };
  });

  // ── Encrypted API keys (Keychain-backed) ──────────────────────────────────────
  ipcMain.handle('apikeys:list', () => Object.keys(readApiKeys()));   // names only, never values
  const API_KEY_NAMES = new Set(['abuseipdb', 'anthropic', 'nvidia', 'abusech', 'openrouter']);
  ipcMain.handle('apikeys:set', (_, { name, value }) => {
    if (!API_KEY_NAMES.has(name) || typeof value !== 'string' || !value.trim()) return { error: 'Unknown key name or empty value' };
    const keys = readApiKeys();
    keys[name] = value;
    writeApiKeys(keys);
    return { success: true, note: 'Restart required for the security engine to use the new key.' };
  });
  ipcMain.handle('apikeys:delete', (_, name) => {
    const keys = readApiKeys();
    delete keys[name];
    writeApiKeys(keys);
    return { success: true };
  });

  // ── Settings ─────────────────────────────────────────────────────────────────
  ipcMain.handle('settings:read', () => readSettings());
  ipcMain.handle('settings:write', (_, data) => {
    writeSettings(data);
    applyLoginItem();   // re-apply login-at-startup if the toggle changed
    return { success: true };
  });

  // ── System info (native) ─────────────────────────────────────────────────────
  ipcMain.handle('system:info', () => ({
    platform:     os.platform(),
    arch:         os.arch(),
    hostname:     os.hostname(),
    totalMem:     os.totalmem(),
    freeMem:      os.freemem(),
    uptime:       os.uptime(),
    cpuCount:     os.cpus().length,
    nodeVersion:  process.versions.node,
    electronVer:  process.versions.electron,
  }));

  // ── Export report ─────────────────────────────────────────────────────────────
  ipcMain.handle('report:export', async (_, content) => {
    const { filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Alvora Cyber Report',
      defaultPath: path.join(os.homedir(), `alvora-report-${Date.now()}.json`),
      filters: [
        { name: 'JSON Report', extensions: ['json'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });
    if (filePath) {
      fs.writeFileSync(filePath, JSON.stringify(content, null, 2), 'utf8');
      return { success: true, filePath };
    }
    return { success: false };
  });
}

// ── App Lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  nativeTheme.themeSource = 'dark';

  // Content Security Policy (defense in depth, alongside the index.html meta tag).
  // Allows the app's own assets + the local backend; blocks remote script origins.
  session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
    cb({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self' 'unsafe-inline' http://localhost:* ws://localhost:*; " +
          "img-src 'self' data:; " +
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
          "font-src 'self' https://fonts.gstatic.com; " +
          "connect-src 'self' http://localhost:* ws://localhost:*; " +
          "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        ],
      },
    });
  });

  setupIPC();
  await createWindow();
  createTray();
  applyLoginItem();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    } else {
      mainWindow?.show();
      if (process.platform === 'darwin') app.dock?.show();
    }
  });
});

app.on('window-all-closed', () => {
  // On macOS: keep app running in tray even with no windows
  if (process.platform !== 'darwin') {
    isQuitting = true;
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  if (backendChild) {
    backendChild.kill();
    backendChild = null;
  }
});

function revealMainWindow() {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
}

// alvora:// links (the extension's "Open Dashboard" button) bring the app forward.
// Only the packaged app registers the scheme — a dev run would point it into node_modules.
if (!isDev && app.isPackaged) app.setAsDefaultProtocolClient('alvora');
app.on('open-url', (event, url) => {
  event.preventDefault();
  if (url.startsWith('alvora://')) revealMainWindow();   // no other actions are accepted from links
});

// Single-instance lock
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', revealMainWindow);
}
