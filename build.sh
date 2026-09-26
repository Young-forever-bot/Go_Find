#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo "[1/2] 构建后端 gofind ..."
go build -ldflags "-s -w" -o bin/gofind.exe ./cmd/gofind
echo "后端构建完成: bin/gofind.exe"
if [ ! -d frontend/node_modules ]; then
  echo "[2/2] 安装前端依赖 ..."
  (cd frontend && npm install --registry=https://registry.npmmirror.com)
fi
echo
echo "完成！启动方式:"
echo "  桌面应用:  cd frontend && npm start"
echo "  浏览器:    ./bin/gofind.exe -web frontend"
