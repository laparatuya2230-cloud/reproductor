const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('srDesktop', {
  printTicket(options = {}) {
    return ipcRenderer.invoke('print-ticket', options || {});
  },
});
