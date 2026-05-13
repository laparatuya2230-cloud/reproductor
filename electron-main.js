const { app: electronApp, BrowserWindow, Menu, dialog, screen, ipcMain } = require('electron');
const http = require('http');
const path = require('path');

let mainWindow;
let httpServer;

function createMainWindow() {
  const display = screen.getPrimaryDisplay();
  const area = display.workAreaSize || { width: 1366, height: 768 };
  const scaleFactor = display.scaleFactor || 1;
  const compactDisplay = area.width <= 1366 || area.height <= 768;

  const width = Math.max(1100, Math.floor(area.width * 0.92));
  const height = Math.max(680, Math.floor(area.height * 0.92));

  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 1024,
    minHeight: 640,
    useContentSize: true,
    title: 'Santiago Reparaciones',
    autoHideMenuBar: true,
    backgroundColor: '#0e0e0e',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // Ajuste de zoom para mantener proporciones similares en 1366x768 y DPI altos.
  const targetZoom = compactDisplay
    ? (scaleFactor > 1 ? Math.max(0.82, 1 / scaleFactor) : 0.92)
    : 1;

  // Mantener un zoom controlado evita diferencias por DPI/zoom accidental.
  const resetZoom = () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.webContents.setZoomLevel(0);
    mainWindow.webContents.setZoomFactor(targetZoom);
  };

  mainWindow.webContents.on('did-finish-load', resetZoom);
  mainWindow.once('ready-to-show', () => {
    // En pantallas bajas o estrechas, arrancar maximizada evita recortes.
    if (area.width <= 1366 || area.height <= 820) {
      mainWindow.maximize();
    }
  });

  return mainWindow;
}

ipcMain.handle('print-ticket', async (event, requested = {}) => {
  const contents = event.sender;
  let printers = [];
  try {
    printers = await contents.getPrintersAsync();
  } catch (_) {}

  const hint = String(requested.deviceHint || '4BARCODE').toLowerCase();
  const targetPrinter = printers.find((printer) => {
    const name = String(printer.name || '').toLowerCase();
    const displayName = String(printer.displayName || '').toLowerCase();
    return name.includes(hint) || displayName.includes(hint);
  });

  const printOptions = {
    silent: true,
    printBackground: true,
    landscape: true,
    margins: { marginType: 'none' },
    pageSize: { width: 101600, height: 50800 },
    scaleFactor: 100,
    copies: 1,
  };
  if (targetPrinter && targetPrinter.name) {
    printOptions.deviceName = targetPrinter.name;
  }

  return new Promise((resolve) => {
    contents.print(printOptions, (success, failureReason) => {
      resolve({
        success,
        failureReason: failureReason || null,
        deviceName: printOptions.deviceName || null,
      });
    });
  });
});

function waitForServer(port, maxAttempts) {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    function check() {
      const req = http.get(`http://127.0.0.1:${port}/`, (res) => {
        res.resume();
        resolve();
      });
      req.setTimeout(500, () => req.destroy());
      req.on('error', () => {
        if (++attempts < maxAttempts) {
          setTimeout(check, 250);
        } else {
          reject(new Error('El servidor no respondió en el puerto ' + port + '.\nVerifica que no haya otro programa usando ese puerto.'));
        }
      });
    }
    check();
  });
}

electronApp.on('ready', async () => {
  // Apuntar la base de datos a la carpeta de usuario (funciona con install "para todos")
  process.env.SR_DATA_DIR = electronApp.getPath('userData');

  Menu.setApplicationMenu(null);

  // Abrir ventana con tama�o adaptado a la pantalla actual
  mainWindow = createMainWindow();

  mainWindow.loadFile(path.join(__dirname, 'loading.html'));
  mainWindow.on('closed', () => { mainWindow = null; });

  // Cargar la aplicación Express
  let expressApp, PORT;
  try {
    const mod = require('./app');
    expressApp = mod.app;
    PORT = mod.PORT;
  } catch (err) {
    dialog.showErrorBox(
      'Error al cargar la aplicación',
      'No se pudo iniciar el sistema.\n\nDetalle técnico:\n' + (err.stack || err.message)
    );
    electronApp.quit();
    return;
  }

  // Iniciar el servidor HTTP en el puerto configurado
  try {
    await new Promise((resolve, reject) => {
      httpServer = expressApp.listen(PORT, '127.0.0.1', resolve);
      httpServer.on('error', reject);
    });
  } catch (err) {
    const msg = err.code === 'EADDRINUSE'
      ? 'El puerto ' + PORT + ' ya está en uso.\nCierra otras aplicaciones e intenta de nuevo.'
      : 'No se pudo iniciar el servidor.\n\n' + err.message;
    dialog.showErrorBox('Error al iniciar servidor', msg);
    electronApp.quit();
    return;
  }

  // Confirmar que el servidor responde
  try {
    await waitForServer(PORT, 60);
  } catch (e) {
    dialog.showErrorBox('Tiempo de espera agotado', e.message);
    electronApp.quit();
    return;
  }

  // Todo OK — cargar el dashboard
  if (mainWindow) {
    mainWindow.loadURL('http://127.0.0.1:' + PORT + '/admin/dashboard');
  }
});

electronApp.on('window-all-closed', () => {
  if (httpServer) httpServer.close();
  electronApp.quit();
});
