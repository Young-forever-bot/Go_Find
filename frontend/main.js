// Young@Asset Collection Electron 主进程：拉起/守护 Go 后端，创建窗口。
const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const BACKEND_ADDR = '127.0.0.1:18525';
const HEALTH_URL = `http://${BACKEND_ADDR}/api/health`;

let backendChild = null;
let mainWindow = null;

// 后端二进制位置：环境变量 GOFIND_BACKEND > ../bin/gofind(.exe)（打包后为 extraResources/bin）
function backendBinary() {
  if (process.env.GOFIND_BACKEND) return process.env.GOFIND_BACKEND;
  const exe = process.platform === 'win32' ? 'gofind.exe' : 'gofind';
  const candidates = [
    path.join(process.resourcesPath || '', 'bin', exe),
    path.join(__dirname, '..', 'bin', exe),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function waitHealthy(tries = 50, intervalMs = 200) {
  return new Promise(resolve => {
    let n = 0;
    const timer = setInterval(() => {
      const req = http.get(HEALTH_URL, res => {
        res.resume();
        clearInterval(timer);
        resolve(true);
      });
      req.on('error', () => {});
      if (++n >= tries) {
        clearInterval(timer);
        resolve(false);
      }
    }, intervalMs);
  });
}

// 确保后端可用：已有实例在运行则直接复用，否则拉起后端二进制。
async function ensureBackend() {
  if (await waitHealthy(3, 150)) {
    console.log('[Young@Asset Collection] 检测到后端已在运行，直接复用:', HEALTH_URL);
    return { reused: true };
  }
  const bin = backendBinary();
  if (!bin) {
    console.warn('[Young@Asset Collection] 未找到后端二进制，请先构建 (go build -o bin/gofind.exe ./cmd/gofind)，' +
      '或通过环境变量 GOFIND_BACKEND 指定已运行后端。');
    return { reused: false, missing: true };
  }
  console.log('[Young@Asset Collection] 启动后端:', bin);
  const child = spawn(bin, ['-addr', BACKEND_ADDR], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', d => console.log('[gofind]', d.toString().trim()));
  child.stderr.on('data', d => console.error('[gofind]', d.toString().trim()));
  child.on('exit', code => {
    backendChild = null;
    console.log('[Young@Asset Collection] 后端已退出, code =', code);
  });
  backendChild = child;
  const ok = await waitHealthy();
  return { reused: false, ok };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 640,
    title: 'Young@Asset Collection',
    backgroundColor: '#0d1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(async () => {
  const result = await ensureBackend();
  if (result.missing) {
    dialog.showMessageBox({
      type: 'warning',
      message: `未找到后端二进制。\n请先在项目根目录执行: go build -o bin/gofind.exe ./cmd/gofind\n窗口仍会打开（需要后端就绪后才能执行任务）。`,
    });
  } else if (!result.reused && !result.ok) {
    dialog.showMessageBox({
      type: 'warning',
      message: `后端在 10 秒内未就绪 (${HEALTH_URL})。\n窗口仍会打开，可检查后端是否被防火墙拦截。`,
    });
  }
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// 终止后端子进程：Windows 下用 taskkill 按进程树强杀，确保不残留。
function stopBackend() {
  if (!backendChild) return;
  const pid = backendChild.pid;
  backendChild = null;
  try {
    if (process.platform === 'win32' && pid) {
      spawn('taskkill', ['/F', '/T', '/PID', String(pid)], { stdio: 'ignore' });
    } else if (pid) {
      backendChildKilled(pid);
    }
  } catch { /* ignore */ }
}

function backendChildKilled(pid) {
  try {
    process.kill(pid);
  } catch { /* ignore */ }
}

app.on('window-all-closed', () => {
  stopBackend();
  app.quit();
});

app.on('before-quit', () => {
  stopBackend();
});
