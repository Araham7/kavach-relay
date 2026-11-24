// Kavach desktop: a window that opens your Kavach server.
// First launch asks for the server address and remembers it (menu: Kavach → Change server).
const { app, BrowserWindow, Menu, ipcMain, shell, systemPreferences } = require('electron');
const fs = require('fs');
const path = require('path');

const cfgFile = () => path.join(app.getPath('userData'), 'server.json');
const readUrl = () => { try { return JSON.parse(fs.readFileSync(cfgFile(), 'utf8')).url || ''; } catch { return ''; } };
const saveUrl = (u) => fs.writeFileSync(cfgFile(), JSON.stringify({ url: u }));
let win;

function serverOrigin() { try { return new URL(readUrl()).origin; } catch { return null; } }

function openSetup() {
  win.loadFile(path.join(__dirname, 'setup.html'), { query: { url: readUrl() } });
}

function openServer() {
  const u = readUrl();
  if (!u) return openSetup();
  win.loadURL(u).catch(() => openSetup());
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100, height: 760, minWidth: 360, minHeight: 520,
    backgroundColor: '#070027', title: 'Kavach', autoHideMenuBar: true,
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      contextIsolation: true, sandbox: true, nodeIntegration: false,
      preload: path.join(__dirname, 'setup-preload.js'),
    },
  });
  // Windows and Mac: the window shows black in screenshots and screen recordings.
  win.setContentProtection(true);

  const ses = win.webContents.session;
  // Camera, mic, notifications and clipboard only for your own Kavach server.
  const allowed = new Set(['media', 'notifications', 'clipboard-sanitized-write', 'clipboard-read', 'fullscreen']);
  ses.setPermissionRequestHandler((wc, perm, cb, details) => {
    const origin = (() => { try { return new URL(details.requestingUrl || wc.getURL()).origin; } catch { return null; } })();
    cb(allowed.has(perm) && origin === serverOrigin());
  });
  ses.setPermissionCheckHandler((wc, perm, origin) => allowed.has(perm) && origin === serverOrigin());

  // Never navigate away from the server; external links open in the normal browser.
  win.webContents.on('will-navigate', (e, url) => {
    const o = (() => { try { return new URL(url).origin; } catch { return null; } })();
    if (url.startsWith('file:') || o === serverOrigin()) return;
    e.preventDefault(); if (/^https?:/.test(url)) shell.openExternal(url);
  });
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https?:/.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('did-fail-load', (e, code, desc, url, isMain) => { if (isMain && code !== -3) openSetup(); });

  openServer();
}

ipcMain.handle('kavach:save-url', (e, u) => {
  let url;
  try { url = new URL(u); } catch { return 'Address is not valid'; }
  if (url.protocol !== 'https:') return 'Address must start with https://';
  saveUrl(url.origin + '/');
  openServer();
  return '';
});

const menu = Menu.buildFromTemplate([
  { label: 'Kavach', submenu: [
    { label: 'Change server…', click: () => openSetup() },
    { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: () => openServer() },
    { type: 'separator' }, { role: 'quit' },
  ] },
  { role: 'editMenu' },
  { label: 'View', submenu: [{ role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'resetZoom' }, { role: 'togglefullscreen' }] },
]);

app.whenReady().then(async () => {
  Menu.setApplicationMenu(menu);
  if (process.platform === 'darwin') {
    try { await systemPreferences.askForMediaAccess('microphone'); await systemPreferences.askForMediaAccess('camera'); } catch {}
  }
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
