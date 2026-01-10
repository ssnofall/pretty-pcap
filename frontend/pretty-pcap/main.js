import { app, BrowserWindow, ipcMain, dialog } from "electron";
import path from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let executableProcess = null;

function getExecutablePath() {
  // In development, use local executable
  // In production, use bundled executable from resources
  if (process.env.NODE_ENV === 'development') {
    return path.join(__dirname, 'executable', 'pretty-pcap-backend');
  } else {
    // For production builds - adjust based on your platform
    if (process.platform === 'win32') {
      return path.join(process.resourcesPath, 'executable', 'pretty-pcap-backend.exe');
    } else {
      return path.join(process.resourcesPath, 'executable', 'pretty-pcap-backend');
    }
  }
}

function startExecutable() {
  const execPath = getExecutablePath();
  
  executableProcess = spawn(execPath, [], {
    // Add any arguments or options your executable needs
  });

  executableProcess.stdout.on('data', (data) => {
    console.log(`Executable stdout: ${data}`);
  });

  executableProcess.stderr.on('data', (data) => {
    console.error(`Executable stderr: ${data}`);
  });

  executableProcess.on('close', (code) => {
    console.log(`Executable process exited with code ${code}`);
  });
}

function stopExecutable() {
  if (executableProcess) {
    executableProcess.kill();
    executableProcess = null;
  }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 700,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  // Load from dev server in development, from dist in production
  if (process.env.NODE_ENV === 'development') {
    win.loadURL("http://localhost:5173");
  } else {
    win.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }
}

app.whenReady().then(() => {
  startExecutable();
  createWindow();
});

app.on('before-quit', () => {
  stopExecutable();
});

app.on('window-all-closed', () => {
  stopExecutable();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// File dialog IPC
ipcMain.handle("dialog:openFile", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ["openFile"],
    filters: [{ name: "PCAP Files", extensions: ["pcap", "pcapng"] }],
  });
  if (canceled) {
    return null;
  } else {
    return filePaths[0];
  }
});