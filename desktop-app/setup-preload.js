// Only the local setup page gets this one function; the Kavach page itself gets nothing.
const { contextBridge, ipcRenderer } = require('electron');
if (location.protocol === 'file:') {
  contextBridge.exposeInMainWorld('kavachDesktop', { saveUrl: (u) => ipcRenderer.invoke('kavach:save-url', u) });
}
