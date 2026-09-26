// 通过 contextBridge 向渲染进程暴露后端地址等基本信息。
const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('gofind', {
  apiBase: 'http://127.0.0.1:18525',
  platform: process.platform,
  electron: process.versions.electron || '',
});
