import { app, BrowserWindow, ipcMain, dialog } from "electron";
import path from "path";
import { fileURLToPath } from "url";
import { spawn, exec } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let executableProcess = null;

function getExecutablePath() {
  if (process.env.NODE_ENV === "development") {
    return path.join(__dirname, "executable", "pretty-pcap-backend");
  } else {
    if (process.platform === "win32") {
      return path.join(process.resourcesPath, "executable", "pretty-pcap-backend.exe");
    } else {
      return path.join(process.resourcesPath, "executable", "pretty-pcap-backend");
    }
  }
}

function startExecutable() {
  const execPath = getExecutablePath();

  // detached:true ensures a separate process group for proper termination
  executableProcess = spawn(execPath, [], {
    detached: true,
    stdio: "inherit", // optional: pipe stdout/stderr to Electron console
  });

  executableProcess.on("close", (code) => {
    console.log(`Executable process exited with code ${code}`);
  });

  executableProcess.on("error", (err) => {
    console.error("Failed to start backend:", err);
  });
}

function stopExecutable() {
  if (!executableProcess) return;

  const pid = executableProcess.pid;

  if (process.platform === "win32") {
    // Windows: kill process tree
    exec(`taskkill /PID ${pid} /T /F`, (err) => {
      if (err) console.error("Failed to kill backend:", err);
    });
  } else {
    // Unix/macOS: kill entire process group
    try {
      process.kill(-pid, "SIGTERM");
    } catch (err) {
      console.error("Failed to kill backend:", err);
    }
  }

  executableProcess = null;
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

  if (process.env.NODE_ENV === "development") {
    win.loadURL("http://localhost:5173");
  } else {
    win.loadFile(path.join(__dirname, "dist", "index.html"));
  }
}

// Start backend and window
app.whenReady().then(() => {
  startExecutable();
  createWindow();
});

// Cleanly stop backend on quit
app.on("will-quit", () => {
  stopExecutable();
});

// File dialog IPC
ipcMain.handle("dialog:openFile", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ["openFile"],
    filters: [{ name: "PCAP Files", extensions: ["pcap", "pcapng"] }],
  });

  return canceled ? null : filePaths[0];
});

// Optional: macOS behavior for re-opening app
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
