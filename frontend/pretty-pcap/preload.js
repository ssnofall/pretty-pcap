// preload.js
const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {});
