@echo off
chcp 65001 >nul
title Go_Find
cd /d "%~dp0frontend"
if not exist node_modules (
  echo 首次运行，正在安装依赖（约 1-2 分钟）...
  call npm install --registry=https://registry.npmmirror.com
)
echo 正在启动 Go_Find 桌面应用...
call npm start
