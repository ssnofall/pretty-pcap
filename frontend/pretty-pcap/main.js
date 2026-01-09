import { app, BrowserWindow, ipcMain, dialog } from "electron";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  win.loadURL("http://localhost:5173");
}

app.whenReady().then(() => {
  createWindow();
});

// ------------------------
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
